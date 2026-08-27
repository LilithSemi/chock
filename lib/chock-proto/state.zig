//! The fold that turns a session log into the state of a session. The log is
//! the truth, and a session's state, the context the model reads included, is a
//! view built by folding the log forward one event at a time. `Session.apply`
//! does that folding. It never reads storage itself, so this file does not
//! depend on `storage.zig`. A caller can drive it from any source of envelopes:
//! a live `Storage.Replay`, a plain `log.Replay`, or a test that builds
//! envelopes by hand.
//!
//! That gives this file its two most important rules:
//!
//! * Compaction is an event in the log, not an edit to the log. Applying it
//!   shortens `Session.context`, the model's view, but the log itself, and any
//!   fresh replay of it, still holds every event that was ever appended.
//! * A `session.spawn` event records that a child session exists. It never pulls
//!   the child's own events into the parent: the parent receives the result of
//!   a child, never its transcript, and the child keeps its own log for that.
//!
//! A session mixes models freely: the roster maps `main`, `subagent`, and
//! `compact` to different aliases. `Message.model_alias` names which alias
//! wrote a given turn, and `Session.apply` carries that alias into the matching
//! `ContextEntry`, so a later reader can say which model produced which part of
//! the context.
//!
//! `apply` takes an `Envelope` by value and does not keep a reference into it. A
//! caller is free to `deinit` the envelope right after the call returns, for
//! example a `Replay` result freed at the end of a loop body. Almost everything
//! this file keeps past the call is copied into `Session`'s own arena first. The
//! one exception is the raw JSON of an unrecognized content part: `apply` keeps
//! the field name but drops the value. See `dupeContentParts` for why.

const std = @import("std");
const event = @import("event.zig");
const log = @import("log.zig");

/// A `Message`, deep copied into `Session`'s own arena so it survives past the
/// envelope `apply` was given.
pub const OwnedMessage = struct {
    role: event.Role,
    content: []const event.ContentPart,
};

/// What one entry of the model context holds. A compaction replaces a run of
/// `.message` entries with one `.summary` entry. Nothing else changes the shape
/// of an entry once `apply` has added it.
pub const ContextData = union(enum) {
    message: OwnedMessage,
    /// The text of a compaction's summary, standing in for every entry it
    /// folded.
    summary: []const u8,
};

/// One entry of the model context. `id` is the id of the event this entry came
/// from, kept so a later compaction can find which entries its
/// `[from_id, through_id]` range covers.
pub const ContextEntry = struct {
    id: u64,
    data: ContextData,
    /// The alias of the model that produced this entry. Copied from
    /// `Message.model_alias` for a `.message` entry, and from
    /// `Compaction.model_alias` for a `.summary` entry. Empty when no model
    /// wrote the turn, for example a user message.
    model_alias: []const u8 = "",
};

/// A child session this session spawned. Holds only what `SessionSpawn` records:
/// the child's id, its agent kind, and the reason given for the spawn. Never the
/// child's own events. See this file's top comment.
pub const Child = struct {
    session: []const u8,
    agent_kind: []const u8,
    reason: []const u8,
    /// The slice of the parent's budget this child was given when it started.
    /// Zero for a child that was given no cap, which is what a parent with no
    /// cap of its own hands out. See `event.SessionSpawn.budget_max_cost`.
    budget_max_cost: f64 = 0,
    budget_currency: []const u8 = "",
};

/// The workspace one attempt at a session opened, folded from `workspace.open`.
/// Holds only what the event records. See `event.WorkspaceOpen`.
pub const Workspace = struct {
    kind: event.WorkspaceKind,
    attempt: []const u8,
    path: []const u8,
    /// Empty for the overlay kind, which has no commit of its own. A reader
    /// must never treat that empty string as a commit.
    base_commit: []const u8,
};

/// The state of one session, folded from its log one event at a time.
/// What a session has spent, folded from its `usage` events. A cap is enforced
/// against this, and only against this: ai&'s own analytics API is rate limited
/// and cached for 120 seconds, and a cap checked against a number that can be
/// two minutes stale is not a cap.
pub const Spend = struct {
    input_tokens: u64 = 0,
    output_tokens: u64 = 0,
    cache_creation_input_tokens: u64 = 0,
    cache_read_input_tokens: u64 = 0,
    /// The money, summed over every turn that could be priced. Meaningless on
    /// its own: read `enforceable` first.
    amount: f64 = 0,
    /// The currency of `amount`. Empty when no priced turn has landed yet.
    currency: []const u8 = "",
    /// How many `usage` events folded in. Zero means nothing has been
    /// counted, which is not the same as a session that cost nothing.
    turns: u64 = 0,
    /// Turns whose cost was `unknown`. **A total with one of these in it is
    /// not a total**, and a cap over an unknown cost cannot be enforced: it
    /// warns once and runs.
    unpriced_turns: u64 = 0,
    /// Turns whose cost was `free`. **Counted apart from `unpriced_turns`,
    /// because free and unknown are different facts**: a local llama.cpp server
    /// costs nothing, and a model with no price entry costs a number nobody
    /// knows. A reader that had only `unpriced_turns` could tell a free turn
    /// from a priced one, since both leave `amount` where it was, only by
    /// reading the log again. The two are reported apart, and `chock usage` is
    /// what reports them.
    free_turns: u64 = 0,
    /// Two turns reported money in different currencies. Adding those gives a
    /// number in no currency at all, so the total stops being enforceable
    /// rather than quietly becoming wrong.
    mixed_currency: bool = false,

    /// Whether `amount` is a total a cap can be compared against. False as
    /// soon as one turn could not be priced, or two turns disagreed about the
    /// currency.
    pub fn enforceable(self: Spend) bool {
        return self.unpriced_turns == 0 and !self.mixed_currency;
    }

    /// Fold one turn's usage in. `free` adds nothing and leaves the total
    /// enforceable, which is what makes a session against a local model
    /// runnable under a cap. `unknown` adds nothing either, but records that
    /// the total is no longer complete.
    pub fn add(self: *Spend, usage: event.Usage) void {
        self.turns += 1;
        self.input_tokens += usage.input_tokens;
        self.output_tokens += usage.output_tokens;
        self.cache_creation_input_tokens += usage.cache_creation_input_tokens;
        self.cache_read_input_tokens += usage.cache_read_input_tokens;
        switch (usage.cost) {
            .free => self.free_turns += 1,
            .known => |money| {
                if (self.currency.len == 0) {
                    self.currency = money.currency;
                } else if (!std.mem.eql(u8, self.currency, money.currency)) {
                    self.mixed_currency = true;
                }
                self.amount += money.value;
            },
            // An unrecognized state came from a writer this reader is older
            // than. It is not free and it is not a number, so it counts as
            // unknown, which is the answer that refuses to enforce a cap
            // rather than the one that enforces a wrong one.
            .unknown, .unrecognized => self.unpriced_turns += 1,
        }
    }

    /// Turns that were priced: the ones that put money into `amount`. The
    /// three states of `Cost` together make up every turn, so this is what is
    /// left after the free ones and the unknown ones are taken out.
    ///
    /// Saturating, so a `Spend` a caller built by hand with numbers that do
    /// not add up gives a wrong answer rather than a panic in a release
    /// build. `add` and `merge` can never produce one: each of them counts a
    /// turn once and raises at most one of the two counters with it.
    pub fn pricedTurns(self: Spend) u64 {
        return self.turns -| self.free_turns -| self.unpriced_turns;
    }

    /// Fold another `Spend` into this one: the totals of two sessions, added.
    ///
    /// **The currency rule is the one `add` keeps, and it is written once.**
    /// Two sessions billed in different currencies add up to a number in no
    /// currency at all, so the result stops being enforceable rather than
    /// quietly becoming wrong, which is the same answer one session with two
    /// currencies in it already gets.
    ///
    /// `currency` is borrowed from `other`, exactly as `add` borrows it from
    /// the usage event. A caller that keeps the result past the lifetime of
    /// `other` owns making that string live long enough, which for
    /// `chock usage` is one arena holding both.
    pub fn merge(self: *Spend, other: Spend) void {
        self.turns += other.turns;
        self.input_tokens += other.input_tokens;
        self.output_tokens += other.output_tokens;
        self.cache_creation_input_tokens += other.cache_creation_input_tokens;
        self.cache_read_input_tokens += other.cache_read_input_tokens;
        self.unpriced_turns += other.unpriced_turns;
        self.free_turns += other.free_turns;
        if (other.mixed_currency) self.mixed_currency = true;
        if (other.currency.len != 0) {
            if (self.currency.len == 0) {
                self.currency = other.currency;
            } else if (!std.mem.eql(u8, self.currency, other.currency)) {
                self.mixed_currency = true;
            }
        }
        self.amount += other.amount;
    }
};

/// The agent's own task list, folded from every `plan.update` event.
///
/// **Nothing is ever removed from this list.** A step is merged in by its
/// identifier: an identifier seen before changes that step, and one seen for
/// the first time is added at the end. An agent that simply stops naming a
/// step therefore does not make it disappear, and the reader still sees it
/// sitting at whatever status it last had.
///
/// That rule is the design and not an implementation detail. A list where a
/// step vanishes in silence reads as finished when it is not, so the only way
/// to take a step off the list is `PlanStatus.abandoned`, which is a thing the
/// agent says out loud. See `chock_proto.event.PlanUpdate`.
///
/// **Order is first seen order**, so a replay of the log rebuilds the same
/// list in the same order, whatever order a later update named the steps in.
pub const Plan = struct {
    /// One step, with every string owned by the arena of the `Session` that
    /// holds it.
    pub const Step = struct {
        id: []const u8,
        subject: []const u8,
        status: event.PlanStatus,
        blocked_by: []const u8 = "",
    };

    /// How many steps are at each status. What a one line report is built
    /// from, by `chock run` and by `chock plan`.
    pub const Counts = struct {
        pending: usize = 0,
        in_progress: usize = 0,
        done: usize = 0,
        abandoned: usize = 0,
        /// Steps whose status this reader has no member for, from a newer
        /// writer. **Counted apart and never folded into `done`**: an
        /// unrecognized status is not finished work.
        unrecognized: usize = 0,

        pub fn total(self: Counts) usize {
            return self.pending + self.in_progress + self.done +
                self.abandoned + self.unrecognized;
        }

        /// Steps that are neither finished nor given up. What is left to do.
        pub fn left(self: Counts) usize {
            return self.pending + self.in_progress + self.unrecognized;
        }
    };

    steps: std.ArrayList(Step) = .empty,

    /// True for a session whose agent never wrote a plan. Every such session
    /// holds no `plan.update` event at all: see `event.PlanUpdate`.
    pub fn isEmpty(self: Plan) bool {
        return self.steps.items.len == 0;
    }

    /// The step with this identifier, or null when the plan has none.
    pub fn find(self: Plan, id: []const u8) ?*Step {
        for (self.steps.items) |*step| {
            if (std.mem.eql(u8, step.id, id)) return step;
        }
        return null;
    }

    pub fn counts(self: Plan) Counts {
        var out = Counts{};
        for (self.steps.items) |step| {
            switch (step.status) {
                .pending => out.pending += 1,
                .in_progress => out.in_progress += 1,
                .done => out.done += 1,
                .abandoned => out.abandoned += 1,
                .unknown => out.unrecognized += 1,
            }
        }
        return out;
    }

    /// Merge one `plan.update` in. `allocator` owns every string this keeps,
    /// which for a `Session` is its own arena.
    pub fn apply(
        self: *Plan,
        allocator: std.mem.Allocator,
        update: event.PlanUpdate,
    ) std.mem.Allocator.Error!void {
        for (update.steps) |given| {
            // A step with no identifier cannot be merged and cannot be found
            // again, so it is dropped rather than added as a step nothing can
            // ever change. `Loop` refuses such a call before it reaches the
            // log; this is the answer for a log written by something else.
            if (given.id.len == 0) continue;

            const status = try dupePlanStatus(allocator, given.status);
            const blocked_by = try allocator.dupe(u8, given.blocked_by);
            if (self.find(given.id)) |step| {
                step.status = status;
                step.blocked_by = blocked_by;
                // An update may reword a step. An empty subject leaves the
                // wording alone, so a caller that only changes a status does
                // not have to repeat the words to keep them.
                if (given.subject.len != 0) step.subject = try allocator.dupe(u8, given.subject);
                continue;
            }
            try self.steps.append(allocator, .{
                .id = try allocator.dupe(u8, given.id),
                .subject = try allocator.dupe(u8, given.subject),
                .status = status,
                .blocked_by = blocked_by,
            });
        }
    }
};

/// What the agent has promised about itself, folded from every `policy.self`
/// event. See `chock_policy.ratchet`, which holds the rule, and
/// `chock_proto.event.PolicySelf`, which is what writes one.
///
/// **Nothing is ever removed from this list, and there is no event that could
/// remove one.** The ceiling for one act is the narrowest promise that covers
/// it, so a list that only grows is a session's own word that only ever gets
/// narrower. That is the ratchet, and it is a property of this fold rather
/// than of a check anybody remembers to write: a promise cannot be lifted
/// because there is nothing to lift it with.
///
/// **Order is the order the promises were made in**, so a replay of the log
/// rebuilds the same list. Nothing reads the order, because the answer is a
/// minimum, and a reader is a person who wants to see what was promised when.
pub const SelfPolicy = struct {
    /// Every promise, in the order they were made. Empty for a session whose
    /// agent promised nothing, which is every session that had no use for a
    /// promise: such a session holds no `policy.self` event at all.
    ///
    /// **There is no `isEmpty` beside this, and no other reader either.** The
    /// list is what `chock_policy.ratchet.ceilingFor` folds, and a session
    /// that promised nothing folds to `allow`, which is already the answer a
    /// caller wants. `Plan` has an `isEmpty` because `chock plan` asks that
    /// question of a session it is about to print; nothing asks it here.
    restrictions: std.ArrayList(event.SelfRestriction) = .empty,

    /// Merge one `policy.self` in. `allocator` owns every string this keeps,
    /// which for a `Session` is its own arena.
    ///
    /// **An authorised update replaces by exact name, and every other one only
    /// appends.** See `event.PolicySelf.authorised`: an agent cannot write that
    /// flag, because `chock_core.Loop` only sets it after a broker outside the
    /// agent's reach permitted the widening, and the broker holds the policy
    /// table the agent cannot read.
    ///
    /// The strings of a dropped promise are not freed. A `Session` folds into
    /// one arena that is released whole, the same way every other list here is
    /// kept, and a fold that freed piece by piece would have to know which
    /// allocator each string came from.
    pub fn apply(
        self: *SelfPolicy,
        allocator: std.mem.Allocator,
        update: event.PolicySelf,
    ) std.mem.Allocator.Error!void {
        if (update.authorised) {
            for (update.restrictions) |given| {
                if (given.action.len == 0) continue;
                var index: usize = 0;
                while (index < self.restrictions.items.len) {
                    if (std.mem.eql(u8, self.restrictions.items[index].action, given.action)) {
                        // Ordered, so the promises that are left read in the
                        // order they were made, which is what a person reading
                        // the record the next morning expects.
                        _ = self.restrictions.orderedRemove(index);
                        continue;
                    }
                    index += 1;
                }
            }
        }
        for (update.restrictions) |given| {
            // A restriction that names no action covers no act, so it binds
            // nothing and a reader could never say what was promised.
            // `chock_core.Loop` refuses one before it reaches the log; this is
            // the answer for a log written by something else. Dropping it is
            // the same treatment `Plan.apply` gives a step with no identifier.
            if (given.action.len == 0) continue;
            try self.restrictions.append(allocator, .{
                .action = try allocator.dupe(u8, given.action),
                .ceiling = try dupePolicyCeiling(allocator, given.ceiling),
                .reason = try allocator.dupe(u8, given.reason),
            });
        }
    }
};

pub const Session = struct {
    /// Owns every slice this struct or its entries hold. One arena for the
    /// whole session's lifetime keeps `apply` simple: nothing here is freed
    /// piece by piece, only all at once in `deinit`.
    arena: std.heap.ArenaAllocator,

    agent_kind: []const u8 = "",
    model_alias: []const u8 = "",
    parent_session: []const u8 = "",

    ended: bool = false,
    end_reason: event.SessionEndReason = .{ .unknown = "" },
    end_detail: []const u8 = "",

    /// The model's view. Shrinks only when a compaction folds a run of entries
    /// into one summary entry. Every other event that touches this list only
    /// grows it.
    context: std.ArrayList(ContextEntry) = .empty,

    /// Every child this session spawned, in `session.spawn` order.
    children: std.ArrayList(Child) = .empty,

    /// The workspace the last attempt at this session opened, or null for a
    /// session that never opened one.
    ///
    /// **A process that takes over a session reads the log, and reads nothing
    /// else.** The path carries an attempt identifier that `chock run` mints
    /// for each invocation, so no other process can compute it. A workspace
    /// the new owner cannot name is a workspace it has to build again out of
    /// committed state, and that throws away everything the last owner did not
    /// commit. The base commit is here for the same reason: it is what the
    /// work of the session is measured against, and a new owner that read
    /// `HEAD` again would measure against a commit the session made itself.
    workspace: ?Workspace = null,

    /// The agent's own task list. Empty for a session whose agent never wrote
    /// one, which is every session that had no use for one. See `Plan`.
    plan: Plan = .{},

    /// What the agent promised about itself. Empty for a session whose agent
    /// promised nothing. See `SelfPolicy`, and `chock_policy.ratchet` for what
    /// a promise means once it is here.
    self_policy: SelfPolicy = .{},

    /// What the session has spent so far, folded from every `usage` event.
    /// See `Spend`: the log is the truth, so a replay of the same log reaches
    /// the same total, which is the guarantee the context fold already gives.
    spend: Spend = .{},

    /// How many input tokens the last request of this session actually
    /// carried, from the newest `usage` event. **Zero means nobody knows
    /// yet**, which is true of a session before its first reply and of one
    /// right after a compaction, and it is never a claim that the context is
    /// empty.
    ///
    /// Folded here rather than counted in the loop so that a resumed session,
    /// or one a `/daemonize` handed over, knows how full its context is
    /// before it sends anything. The state is a fold over the log, and this
    /// number is in the log already.
    last_input_tokens: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) Session {
        return .{ .arena = std.heap.ArenaAllocator.init(allocator) };
    }

    pub fn deinit(self: *Session) void {
        self.arena.deinit();
    }

    /// Fold one more event into the state.
    pub fn apply(self: *Session, envelope: event.Envelope) std.mem.Allocator.Error!void {
        const allocator = self.arena.allocator();
        switch (envelope.event) {
            .session_start => |start| {
                self.agent_kind = try allocator.dupe(u8, start.agent_kind);
                self.model_alias = try allocator.dupe(u8, start.model_alias);
                self.parent_session = try allocator.dupe(u8, start.parent_session);
            },
            .session_end => |end| {
                self.ended = true;
                self.end_reason = try dupeSessionEndReason(allocator, end.reason);
                self.end_detail = try allocator.dupe(u8, end.detail);
            },
            .session_spawn => |spawn| {
                // Record that the child exists. Do not touch the child's log:
                // the parent context gets the child's result later, through a
                // different event, never the child's own transcript.
                try self.children.append(allocator, .{
                    .session = try allocator.dupe(u8, spawn.child_session),
                    .agent_kind = try allocator.dupe(u8, spawn.child_agent_kind),
                    .reason = try allocator.dupe(u8, spawn.reason),
                    // What this child was allowed to spend. Folded here, and
                    // not counted in the loop, so a parent that resumed knows
                    // what it has already handed out. See
                    // `chock_core.subagent.budgetSlice`: a slice a resumed
                    // parent forgot would be a slice it could hand out twice.
                    .budget_max_cost = spawn.budget_max_cost,
                    .budget_currency = try allocator.dupe(u8, spawn.budget_currency),
                });
            },
            .workspace_open => |opened| {
                // **The last one wins.** Each attempt at a session opens one
                // workspace, so the newest `workspace.open` in the log names
                // the one that is on disk now. A fold that kept the first
                // would send the next owner to a path an earlier attempt
                // already removed.
                self.workspace = .{
                    .kind = try dupeWorkspaceKind(allocator, opened.kind),
                    .attempt = try allocator.dupe(u8, opened.attempt),
                    .path = try allocator.dupe(u8, opened.path),
                    .base_commit = try allocator.dupe(u8, opened.base_commit),
                };
            },
            .message => |message| {
                try self.context.append(allocator, .{
                    .id = envelope.id,
                    .data = .{ .message = .{
                        .role = try dupeRole(allocator, message.role),
                        .content = try dupeContentParts(allocator, message.content),
                    } },
                    .model_alias = try allocator.dupe(u8, message.model_alias),
                });
            },
            .usage => |usage| {
                // The currency is borrowed from the envelope, which the
                // caller of `apply` owns and may release, so the arena keeps
                // a copy the way every other field here does.
                var owned = usage;
                if (usage.cost == .known) {
                    owned.cost = .{ .known = .{
                        .value = usage.cost.known.value,
                        .currency = try allocator.dupe(u8, usage.cost.known.currency),
                    } };
                }
                self.spend.add(owned);
                self.last_input_tokens = usage.input_tokens +
                    usage.cache_creation_input_tokens + usage.cache_read_input_tokens;
            },
            .plan_update => |update| try self.plan.apply(allocator, update),
            .policy_self => |update| try self.self_policy.apply(allocator, update),
            .compaction => |compaction| {
                try self.applyCompaction(allocator, compaction);
                // The context this number measured no longer exists, and the
                // size of the shorter one is not known until the next reply
                // says so. A reader that kept the old number would compact
                // again on the next turn, and then again, on a context that
                // already has room.
                self.last_input_tokens = 0;
            },
            // Every other kind changes state this fold does not track yet:
            // tool calls, approvals, prompts, and diffs. Folding those belongs
            // with the agent loop, and adding fields nothing reads yet would be
            // untested code, not state.
            else => {},
        }
    }

    /// Replace every context entry inside `[from_id, through_id]` with one
    /// summary entry, except an entry inside one of `kept_ranges`, which stays
    /// as it was. This is the only operation that shortens `context`. The log
    /// itself is never touched, so a fresh replay of it still returns every
    /// event this session ever applied.
    ///
    /// A summary entry is always added, even when no context entry falls
    /// inside `[from_id, through_id]`, for example a range that covers only
    /// `tool.call` events, which this fold does not put in the context. A
    /// compaction is an event in the log, and a reader must be able to see
    /// that it ran, not just its effect when it had one. The summary lands at
    /// the point in `context` where a folded entry would have sat, so the
    /// order of `context` still matches the order of the log.
    fn applyCompaction(
        self: *Session,
        allocator: std.mem.Allocator,
        compaction: event.Compaction,
    ) std.mem.Allocator.Error!void {
        var folded: std.ArrayList(ContextEntry) = .empty;
        var summary_written = false;

        for (self.context.items) |entry| {
            const in_range = entry.id >= compaction.from_id and entry.id <= compaction.through_id;
            if (in_range) {
                if (!summary_written) {
                    try folded.append(allocator, try summaryEntry(allocator, compaction));
                    summary_written = true;
                }
                if (isKept(compaction.kept_ranges, entry.id)) try folded.append(allocator, entry);
                continue;
            }
            // An entry past the compacted range, with no entry ever falling
            // inside it: the summary belongs here, in the range's own place
            // in the id order, not tacked onto the end of the list.
            if (!summary_written and entry.id > compaction.through_id) {
                try folded.append(allocator, try summaryEntry(allocator, compaction));
                summary_written = true;
            }
            try folded.append(allocator, entry);
        }
        if (!summary_written) try folded.append(allocator, try summaryEntry(allocator, compaction));

        // The old backing array is arena memory: nothing needs an explicit free
        // here, the whole arena goes away together in Session.deinit.
        self.context = folded;
    }
};

/// Build the one context entry a compaction ever adds: its summary text, with
/// `id` set to `from_id`, and `model_alias` carried over from the compaction
/// event instead of discarded.
///
/// **`from_id`, because the summary sits where the span started and the ids of
/// `context` must stay in ascending order.** This used to be `through_id`, and
/// a real session on 2026-08-21 showed what that costs as soon as a compaction
/// keeps a tail: the summary landed ahead of the entries `kept_ranges` had
/// kept, while carrying an id larger than all of them. The list was then out of
/// id order, so the next compaction's own range test, which reads an id, did
/// not match the entries it meant to fold. **It folded nothing and the context
/// went on growing.** With `from_id` the summary is never larger than what
/// follows it, because everything the fold keeps came later in the log.
fn summaryEntry(allocator: std.mem.Allocator, compaction: event.Compaction) std.mem.Allocator.Error!ContextEntry {
    return .{
        .id = compaction.from_id,
        .data = .{ .summary = try allocator.dupe(u8, compaction.summary) },
        .model_alias = try allocator.dupe(u8, compaction.model_alias),
    };
}

fn isKept(ranges: []const event.EventRange, id: u64) bool {
    for (ranges) |range| {
        if (id >= range.from_id and id <= range.through_id) return true;
    }
    return false;
}

fn dupeRole(allocator: std.mem.Allocator, role: event.Role) std.mem.Allocator.Error!event.Role {
    return switch (role) {
        .unknown => |name| .{ .unknown = try allocator.dupe(u8, name) },
        else => role,
    };
}

fn dupePlanStatus(
    allocator: std.mem.Allocator,
    status: event.PlanStatus,
) std.mem.Allocator.Error!event.PlanStatus {
    return switch (status) {
        .unknown => |name| .{ .unknown = try allocator.dupe(u8, name) },
        else => status,
    };
}

fn dupePolicyCeiling(
    allocator: std.mem.Allocator,
    ceiling: event.PolicyCeiling,
) std.mem.Allocator.Error!event.PolicyCeiling {
    return switch (ceiling) {
        .unknown => |name| .{ .unknown = try allocator.dupe(u8, name) },
        else => ceiling,
    };
}

fn dupeWorkspaceKind(
    allocator: std.mem.Allocator,
    kind: event.WorkspaceKind,
) std.mem.Allocator.Error!event.WorkspaceKind {
    return switch (kind) {
        .unknown => |name| .{ .unknown = try allocator.dupe(u8, name) },
        else => kind,
    };
}

fn dupeSessionEndReason(
    allocator: std.mem.Allocator,
    reason: event.SessionEndReason,
) std.mem.Allocator.Error!event.SessionEndReason {
    return switch (reason) {
        .unknown => |name| .{ .unknown = try allocator.dupe(u8, name) },
        else => reason,
    };
}

/// Deep copy a message's content parts into `allocator`. Every plain string
/// field is duplicated. `.unknown`'s raw JSON tree is not: `context` is a view
/// built for the model, not the record of truth, and the log, not this struct,
/// is what must keep every byte of an unrecognized part. A caller that later
/// needs the raw value of an unknown part in the context can add that copy here
/// once something actually reads it.
fn dupeContentParts(
    allocator: std.mem.Allocator,
    parts: []const event.ContentPart,
) std.mem.Allocator.Error![]event.ContentPart {
    const copy = try allocator.alloc(event.ContentPart, parts.len);
    for (parts, 0..) |part, i| {
        copy[i] = switch (part) {
            .text => |text| .{ .text = try allocator.dupe(u8, text) },
            .reasoning => |reasoning| .{ .reasoning = .{
                .text = try allocator.dupe(u8, reasoning.text),
                .signature = try allocator.dupe(u8, reasoning.signature),
            } },
            .tool_use => |tool_use| .{ .tool_use = .{
                .call_id = try allocator.dupe(u8, tool_use.call_id),
                .tool = try allocator.dupe(u8, tool_use.tool),
                .arguments = try allocator.dupe(u8, tool_use.arguments),
            } },
            .tool_result => |tool_result| .{ .tool_result = .{
                .call_id = try allocator.dupe(u8, tool_result.call_id),
                .output = try allocator.dupe(u8, tool_result.output),
                .is_error = tool_result.is_error,
            } },
            .unknown => |unknown| .{ .unknown = .{
                .name = try allocator.dupe(u8, unknown.name),
                .raw = .null,
            } },
        };
    }
    return copy;
}

test "a session that replays a start and two messages holds both messages in order" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{
        .session_start = .{ .agent_kind = "coder", .model_alias = "main", .parent_session = "" },
    } });
    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{
        .message = .{ .role = .user, .content = &.{.{ .text = "first" }} },
    } });
    try session.apply(.{ .id = 3, .session = "01S", .time_ms = 3, .event = .{
        .message = .{ .role = .assistant, .content = &.{.{ .text = "second" }} },
    } });

    try std.testing.expectEqualStrings("coder", session.agent_kind);
    try std.testing.expectEqual(@as(usize, 2), session.context.items.len);
    try std.testing.expectEqual(event.Role.user, std.meta.activeTag(session.context.items[0].data.message.role));
    try std.testing.expectEqualStrings("first", session.context.items[0].data.message.content[0].text);
    try std.testing.expectEqualStrings("second", session.context.items[1].data.message.content[0].text);
}

test "a compaction event replaces the events before it in the context, and the log keeps them" {
    // This is the property everything else rests on. The context is a view.
    // The history stays complete. A real log.Log proves the second half: a
    // fresh replay after the fold still returns every event that was ever
    // appended, compaction event included, even though the fold shortened the
    // session's own context.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try log.absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/compaction", .{dir_path});

    var chock_log = try log.Log.open(io, path, "01COMPACT");
    defer chock_log.close(io);
    var locked = try chock_log.lock(io);

    const first_id = try locked.append(allocator, io, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);
    const second_id = try locked.append(allocator, io, .{ .message = .{ .role = .assistant, .content = &.{.{ .text = "two" }} } }, 2);
    _ = try locked.append(allocator, io, .{ .compaction = .{
        .summary = "one and two, summarized",
        .from_id = first_id,
        .through_id = second_id,
        .kept_ranges = &.{},
        .model_alias = "compact",
    } }, 3);
    _ = try locked.append(allocator, io, .{ .message = .{ .role = .user, .content = &.{.{ .text = "three" }} } }, 4);

    var session = Session.init(allocator);
    defer session.deinit();
    {
        var replay = try chock_log.replayFrom(allocator, io, 0);
        defer replay.deinit();
        while (try replay.next(io)) |envelope| {
            defer envelope.deinit();
            try session.apply(envelope.value);
        }
    }

    // The context is shorter: "one" and "two" collapse into one summary entry,
    // leaving the summary and "three", not three separate entries.
    try std.testing.expectEqual(@as(usize, 2), session.context.items.len);
    try std.testing.expectEqualStrings("one and two, summarized", session.context.items[0].data.summary);
    // The compaction named "compact" as the alias that wrote the summary.
    // The fold must not discard that fact.
    try std.testing.expectEqualStrings("compact", session.context.items[0].model_alias);
    try std.testing.expectEqualStrings("three", session.context.items[1].data.message.content[0].text);

    // The log itself is untouched by the fold: a fresh replay still returns
    // every event that was ever appended.
    var full_replay = try chock_log.replayFrom(allocator, io, 0);
    defer full_replay.deinit();
    var count: usize = 0;
    while (try full_replay.next(io)) |envelope| {
        defer envelope.deinit();
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 4), count);
}

test "a compaction's kept_ranges survive verbatim inside the folded range" {
    // Suspicious case: a compaction can keep part of what it folds, so a reader
    // can see exactly what was dropped. This pins that the kept entry survives
    // in its original place, between the summary and whatever comes after.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 10, .session = "01S", .time_ms = 1, .event = .{
        .message = .{ .role = .user, .content = &.{.{ .text = "a" }} },
    } });
    try session.apply(.{ .id = 20, .session = "01S", .time_ms = 2, .event = .{
        .message = .{ .role = .user, .content = &.{.{ .text = "b, kept" }} },
    } });
    try session.apply(.{ .id = 30, .session = "01S", .time_ms = 3, .event = .{
        .message = .{ .role = .user, .content = &.{.{ .text = "c" }} },
    } });
    try session.apply(.{ .id = 40, .session = "01S", .time_ms = 4, .event = .{
        .compaction = .{
            .summary = "a and c, folded",
            .from_id = 10,
            .through_id = 30,
            .kept_ranges = &.{.{ .from_id = 20, .through_id = 20 }},
            .model_alias = "compact",
        },
    } });
    try session.apply(.{ .id = 50, .session = "01S", .time_ms = 5, .event = .{
        .message = .{ .role = .user, .content = &.{.{ .text = "d" }} },
    } });

    try std.testing.expectEqual(@as(usize, 3), session.context.items.len);
    try std.testing.expectEqualStrings("a and c, folded", session.context.items[0].data.summary);
    try std.testing.expectEqualStrings("b, kept", session.context.items[1].data.message.content[0].text);
    try std.testing.expectEqualStrings("d", session.context.items[2].data.message.content[0].text);
}

test "a second compaction over a context that already holds a summary still shortens it" {
    // **Measured on a real session, 2026-08-21.** The summary entry used to
    // carry `through_id`, so after one compaction that kept a tail the
    // context read [head][summary id 7490][kept ids 2999..7490]: out of id
    // order. The next compaction's range test reads an id, so it matched
    // almost nothing, folded almost nothing, and the context went on growing
    // while the log said a compaction had happened. Every other test in this
    // file passed throughout, because none of them compacts twice.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    for (1..7) |i| {
        try session.apply(.{ .id = i * 10, .session = "01S", .time_ms = 1, .event = .{
            .message = .{ .role = .user, .content = &.{.{ .text = "turn" }} },
        } });
    }
    // Fold ids 20 through 60, keeping 50 and 60. Six entries become three:
    // the head, the summary, and the two kept.
    try session.apply(.{ .id = 70, .session = "01S", .time_ms = 2, .event = .{
        .compaction = .{
            .summary = "the first summary",
            .from_id = 20,
            .through_id = 60,
            .kept_ranges = &.{.{ .from_id = 50, .through_id = 60 }},
            .model_alias = "compact",
        },
    } });
    try std.testing.expectEqual(@as(usize, 4), session.context.items.len);

    // The ids are still ascending, which is what the next fold depends on.
    for (session.context.items[1..], session.context.items[0 .. session.context.items.len - 1]) |after, before| {
        try std.testing.expect(before.id <= after.id);
    }

    // Now fold everything after the head again, keeping only the last entry.
    try session.apply(.{ .id = 80, .session = "01S", .time_ms = 3, .event = .{
        .compaction = .{
            .summary = "the second summary",
            .from_id = 20,
            .through_id = 60,
            .kept_ranges = &.{.{ .from_id = 60, .through_id = 60 }},
            .model_alias = "compact",
        },
    } });

    // The head, the second summary, and the one kept entry. Three, not four:
    // the fold really did shorten the context a second time.
    try std.testing.expectEqual(@as(usize, 3), session.context.items.len);
    try std.testing.expectEqualStrings("the second summary", session.context.items[1].data.summary);
    try std.testing.expectEqual(@as(u64, 60), session.context.items[2].id);
}

test "the fold says which model alias produced which turn, when two aliases wrote in one session" {
    // A session can mix models freely, a cheap alias for the routine work and
    // an expensive one for the hard part. This proves the state can answer
    // "which was which" after the fact, not just while the turn is fresh.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{
        .message = .{ .role = .user, .content = &.{.{ .text = "what should I do" }} },
    } });
    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{
        .message = .{
            .role = .assistant,
            .content = &.{.{ .text = "let me check something routine" }},
            .model_alias = "cheap",
        },
    } });
    try session.apply(.{ .id = 3, .session = "01S", .time_ms = 3, .event = .{
        .message = .{
            .role = .assistant,
            .content = &.{.{ .text = "here is the hard answer" }},
            .model_alias = "expensive",
        },
    } });

    try std.testing.expectEqual(@as(usize, 3), session.context.items.len);
    // A user turn names no model.
    try std.testing.expectEqualStrings("", session.context.items[0].model_alias);
    try std.testing.expectEqualStrings("cheap", session.context.items[1].model_alias);
    try std.testing.expectEqualStrings("expensive", session.context.items[2].model_alias);
}

test "a compaction whose range covers no context entry still leaves a summary behind" {
    // A reviewer found this real case: a compaction range that covers only
    // tool.call events, which this fold never puts in the context, folded
    // nothing and left no trace. The log is the complete history, so a
    // compaction that changed nothing in the context must still be visible as
    // an event that ran.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 10, .session = "01S", .time_ms = 1, .event = .{
        .message = .{ .role = .user, .content = &.{.{ .text = "before" }} },
    } });
    // ids 20 through 30 stand in for tool.call and tool.result events: never
    // folded into context, so nothing in context falls inside this range.
    try session.apply(.{ .id = 40, .session = "01S", .time_ms = 4, .event = .{
        .compaction = .{
            .summary = "nothing to fold here",
            .from_id = 20,
            .through_id = 30,
            .kept_ranges = &.{},
            .model_alias = "compact",
        },
    } });
    try session.apply(.{ .id = 50, .session = "01S", .time_ms = 5, .event = .{
        .message = .{ .role = .user, .content = &.{.{ .text = "after" }} },
    } });

    try std.testing.expectEqual(@as(usize, 3), session.context.items.len);
    try std.testing.expectEqualStrings("before", session.context.items[0].data.message.content[0].text);
    try std.testing.expectEqualStrings("nothing to fold here", session.context.items[1].data.summary);
    try std.testing.expectEqualStrings("compact", session.context.items[1].model_alias);
    try std.testing.expectEqualStrings("after", session.context.items[2].data.message.content[0].text);
}

test "a session.spawn event records the child session and not its transcript" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01PARENT", .time_ms = 1, .event = .{
        .session_spawn = .{ .child_session = "01CHILD", .child_agent_kind = "reviewer", .reason = "review the diff" },
    } });

    try std.testing.expectEqual(@as(usize, 1), session.children.items.len);
    try std.testing.expectEqualStrings("01CHILD", session.children.items[0].session);
    try std.testing.expectEqualStrings("reviewer", session.children.items[0].agent_kind);
    try std.testing.expectEqualStrings("review the diff", session.children.items[0].reason);

    // A parent gets the result of a child, never its transcript: a spawn adds
    // nothing to the context at all.
    try std.testing.expectEqual(@as(usize, 0), session.context.items.len);
}

test "a session with no plan.update event has no plan at all" {
    // **Not mandatory is a property of the fold as well as of the tool.** A
    // one step task with a task list is noise, so a session that never wrote
    // one holds nothing here, and every reader can tell that from an empty
    // list rather than from a list of nothing.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{
        .session_start = .{ .agent_kind = "coder", .model_alias = "main", .parent_session = "" },
    } });
    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{
        .message = .{ .role = .user, .content = &.{.{ .text = "rename one field" }} },
    } });

    try std.testing.expect(session.plan.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), session.plan.counts().total());
}

test "a step the agent stopped naming is still in the fold, at the status it last had" {
    // **The fault this design exists to stop.** A task quietly dropped from a
    // list reads as a task that was finished, and a reader in the morning
    // cannot see the difference. The fold merges by identifier and removes
    // nothing, so the only way off the list is to say `abandoned`.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .plan_update = .{ .steps = &.{
        .{ .id = "s1", .subject = "read the fold", .status = .in_progress },
        .{ .id = "s2", .subject = "measure it on Darwin", .status = .pending },
        .{ .id = "s3", .subject = "write the command", .status = .pending },
    } } } });
    // The second update names s1 and s3 and says nothing about s2.
    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{ .plan_update = .{ .steps = &.{
        .{ .id = "s1", .subject = "read the fold", .status = .done },
        .{ .id = "s3", .subject = "write the command", .status = .abandoned },
    } } } });

    // Three steps, still, and in the order they were first named.
    try std.testing.expectEqual(@as(usize, 3), session.plan.steps.items.len);
    try std.testing.expectEqualStrings("s1", session.plan.steps.items[0].id);
    try std.testing.expectEqualStrings("s2", session.plan.steps.items[1].id);
    try std.testing.expectEqualStrings("s3", session.plan.steps.items[2].id);

    // The step nobody mentioned again kept the status it had. It did not
    // vanish, and it did not become done.
    const forgotten = session.plan.find("s2").?;
    try std.testing.expectEqual(event.PlanStatus.pending, std.meta.activeTag(forgotten.status));
    try std.testing.expectEqualStrings("measure it on Darwin", forgotten.subject);

    // And the step that was given up is visible as given up, not as gone.
    const dropped = session.plan.find("s3").?;
    try std.testing.expectEqual(event.PlanStatus.abandoned, std.meta.activeTag(dropped.status));
    try std.testing.expect(dropped.status != .done);

    const counts = session.plan.counts();
    try std.testing.expectEqual(@as(usize, 1), counts.done);
    try std.testing.expectEqual(@as(usize, 1), counts.abandoned);
    try std.testing.expectEqual(@as(usize, 1), counts.pending);
    try std.testing.expectEqual(@as(usize, 3), counts.total());
    // One step left to do: the abandoned one is not work and the done one is
    // not work either.
    try std.testing.expectEqual(@as(usize, 1), counts.left());
}

test "an update that only changes a status keeps the words, and one that rewords replaces them" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .plan_update = .{ .steps = &.{
        .{ .id = "s1", .subject = "port the driver", .status = .pending, .blocked_by = "the Darwin box is offline" },
    } } } });
    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{ .plan_update = .{ .steps = &.{
        .{ .id = "s1", .subject = "", .status = .in_progress },
    } } } });

    const step = session.plan.find("s1").?;
    try std.testing.expectEqualStrings("port the driver", step.subject);
    try std.testing.expectEqual(event.PlanStatus.in_progress, std.meta.activeTag(step.status));
    // What held it up is gone, because the update said nothing holds it up.
    try std.testing.expectEqualStrings("", step.blocked_by);

    try session.apply(.{ .id = 3, .session = "01S", .time_ms = 3, .event = .{ .plan_update = .{ .steps = &.{
        .{ .id = "s1", .subject = "port the driver and its probe", .status = .done },
    } } } });
    try std.testing.expectEqualStrings("port the driver and its probe", session.plan.find("s1").?.subject);
    try std.testing.expectEqual(@as(usize, 1), session.plan.steps.items.len);
}

test "a status this reader does not know is counted apart, and never as done" {
    // A plan written by a newer Chock. Reading an unrecognized status as
    // finished would report work nobody did.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .plan_update = .{ .steps = &.{
        .{ .id = "s1", .subject = "ship it", .status = .{ .unknown = "deferred" } },
    } } } });

    const counts = session.plan.counts();
    try std.testing.expectEqual(@as(usize, 0), counts.done);
    try std.testing.expectEqual(@as(usize, 1), counts.unrecognized);
    // It counts as work that is left, which is the answer that understates
    // nothing.
    try std.testing.expectEqual(@as(usize, 1), counts.left());
    try std.testing.expectEqualStrings("deferred", session.plan.find("s1").?.status.wireName());
}

test "the plan folds from the log, and a fresh replay of the same log gives the same list" {
    // **The property the whole design rests on.** The list is in the log, so a
    // session that was compacted, handed to the daemon, or attached to from a
    // phone rebuilds exactly the list the terminal had. A plan kept anywhere
    // but the log would pass every other test in this file and fail this one.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try log.absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/plan", .{dir_path});

    var chock_log = try log.Log.open(io, path, "01PLAN");
    defer chock_log.close(io);
    var locked = try chock_log.lock(io);

    // The live session: it folds each event as it appends it, which is what
    // `Loop.appendAndApply` does.
    var live = Session.init(allocator);
    defer live.deinit();

    const written = [_]event.Event{
        .{ .plan_update = .{ .steps = &.{
            .{ .id = "a", .subject = "read the driver", .status = .in_progress },
            .{ .id = "b", .subject = "write the test", .status = .pending },
        } } },
        .{ .message = .{ .role = .assistant, .content = &.{.{ .text = "starting" }} } },
        .{ .plan_update = .{ .steps = &.{
            .{ .id = "a", .subject = "read the driver", .status = .done },
            .{ .id = "c", .subject = "measure it on Darwin", .status = .pending, .blocked_by = "b" },
        } } },
        .{ .plan_update = .{ .steps = &.{
            .{ .id = "b", .subject = "write the test", .status = .abandoned },
        } } },
    };
    for (written, 1..) |one, time| {
        const id = try locked.append(allocator, io, one, @intCast(time));
        try live.apply(.{ .id = id, .session = "01PLAN", .time_ms = @intCast(time), .event = one });
    }

    // The replay: a reader that has only the file.
    var replayed = Session.init(allocator);
    defer replayed.deinit();
    var replay = try chock_log.replayFrom(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |envelope| {
        defer envelope.deinit();
        try replayed.apply(envelope.value);
    }

    try std.testing.expectEqual(live.plan.steps.items.len, replayed.plan.steps.items.len);
    try std.testing.expectEqual(@as(usize, 3), replayed.plan.steps.items.len);
    for (live.plan.steps.items, replayed.plan.steps.items) |from_live, from_file| {
        try std.testing.expectEqualStrings(from_live.id, from_file.id);
        try std.testing.expectEqualStrings(from_live.subject, from_file.subject);
        try std.testing.expectEqualStrings(from_live.status.wireName(), from_file.status.wireName());
        try std.testing.expectEqualStrings(from_live.blocked_by, from_file.blocked_by);
    }

    // And the list really says what happened: one finished, one given up, one
    // still waiting on the one that was given up.
    const counts = replayed.plan.counts();
    try std.testing.expectEqual(@as(usize, 1), counts.done);
    try std.testing.expectEqual(@as(usize, 1), counts.abandoned);
    try std.testing.expectEqual(@as(usize, 1), counts.pending);
    try std.testing.expectEqualStrings("b", replayed.plan.find("c").?.blocked_by);
}

test "a promise the agent made survives a resume, because it is folded from the log" {
    // **The property the ratchet rests on.** A promise held in the model's
    // attention is lost to a compaction, to a resume, and to a handover to the
    // daemon. This one is written down, so a reader that has only the file
    // rebuilds exactly what the live session held, which is what makes
    // `src/run.zig` able to enforce it after `Loop.run` has ended and the
    // live state is gone.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try log.absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/promise", .{dir_path});

    var chock_log = try log.Log.open(io, path, "01PROMISE");
    defer chock_log.close(io);
    var locked = try chock_log.lock(io);

    var live = Session.init(allocator);
    defer live.deinit();
    try std.testing.expectEqual(@as(usize, 0), live.self_policy.restrictions.items.len);

    const written = [_]event.Event{
        .{ .policy_self = .{ .restrictions = &.{
            .{ .action = "net.fetch", .ceiling = .deny, .reason = "this task reads local files only" },
        } } },
        // A compaction between the two, which is the event that would take a
        // promise away from a model that only remembered it.
        .{ .compaction = .{
            .from_id = 0,
            .through_id = 0,
            .summary = "the work so far",
            .kept_ranges = &.{},
            .model_alias = "compact",
        } },
        .{ .message = .{ .role = .assistant, .content = &.{.{ .text = "carrying on" }} } },
        .{ .policy_self = .{ .restrictions = &.{
            .{ .action = "git.*", .ceiling = .ask, .reason = "no git without a person" },
        } } },
    };
    for (written, 1..) |one, time| {
        const id = try locked.append(allocator, io, one, @intCast(time));
        try live.apply(.{ .id = id, .session = "01PROMISE", .time_ms = @intCast(time), .event = one });
    }

    var replayed = Session.init(allocator);
    defer replayed.deinit();
    var replay = try chock_log.replayFrom(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |envelope| {
        defer envelope.deinit();
        try replayed.apply(envelope.value);
    }

    // The reader with only the file holds what the live session held, in the
    // order the promises were made in.
    try std.testing.expectEqual(
        live.self_policy.restrictions.items.len,
        replayed.self_policy.restrictions.items.len,
    );
    try std.testing.expectEqual(@as(usize, 2), replayed.self_policy.restrictions.items.len);
    for (live.self_policy.restrictions.items, replayed.self_policy.restrictions.items) |from_live, from_file| {
        try std.testing.expectEqualStrings(from_live.action, from_file.action);
        try std.testing.expectEqualStrings(from_live.ceiling.wireName(), from_file.ceiling.wireName());
        try std.testing.expectEqualStrings(from_live.reason, from_file.reason);
    }
    try std.testing.expectEqualStrings("net.fetch", replayed.self_policy.restrictions.items[0].action);
    try std.testing.expectEqualStrings("deny", replayed.self_policy.restrictions.items[0].ceiling.wireName());
    try std.testing.expectEqualStrings("git.*", replayed.self_policy.restrictions.items[1].action);
    try std.testing.expectEqualStrings("ask", replayed.self_policy.restrictions.items[1].ceiling.wireName());

    // The compaction shortened the model's own view, and it took nothing off
    // this list. That is the difference between a promise and a message.
    try std.testing.expect(replayed.context.items.len < written.len);
}

test "a promise from a newer writer keeps its own spelling, and one that binds nothing is dropped" {
    // Two rules of this fold, and they fail in opposite directions on purpose.
    // A ceiling this build has no member for is kept exactly as written, so
    // `chock_policy.ratchet.ceilingFromLog` can read it as the narrowest thing
    // there is rather than as one of the five it knows. An action that names
    // nothing covers no act at all, so nothing could ever be measured against
    // it and a reader could never say what was promised.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .policy_self = .{
        .restrictions = &.{
            .{ .action = "", .ceiling = .deny, .reason = "a promise about nothing" },
            .{ .action = "nix.build", .ceiling = .{ .unknown = "ask_two_people" }, .reason = "from a newer Chock" },
        },
    } } });

    try std.testing.expectEqual(@as(usize, 1), session.self_policy.restrictions.items.len);
    const kept = session.self_policy.restrictions.items[0];
    try std.testing.expectEqualStrings("nix.build", kept.action);
    try std.testing.expectEqualStrings("ask_two_people", kept.ceiling.wireName());
}

test "a plan step with no identifier is dropped, because nothing could ever change it" {
    // A line written by something that is not this loop. A step nothing can
    // name again is a step that can never be crossed off, so it is refused at
    // the fold rather than sitting on the list forever.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .plan_update = .{ .steps = &.{
        .{ .id = "", .subject = "something nobody can name", .status = .pending },
        .{ .id = "s1", .subject = "something they can", .status = .pending },
    } } } });

    try std.testing.expectEqual(@as(usize, 1), session.plan.steps.items.len);
    try std.testing.expectEqualStrings("s1", session.plan.steps.items[0].id);
}

test "a free turn and an unknown turn are counted apart, and neither adds money" {
    // The fault the three state `Cost` exists to stop. Both of these leave
    // `amount` at zero, so a reader with only a total cannot tell them apart,
    // and they mean opposite things: the free one is a measured fact and the
    // unknown one is an absence.
    var spend = Spend{};
    spend.add(.{ .input_tokens = 10, .cost = .free });
    spend.add(.{ .input_tokens = 20, .cost = .unknown });
    spend.add(.{ .input_tokens = 30, .cost = .{ .known = .{ .value = 0.25, .currency = "USD" } } });

    try std.testing.expectEqual(@as(u64, 3), spend.turns);
    try std.testing.expectEqual(@as(u64, 1), spend.free_turns);
    try std.testing.expectEqual(@as(u64, 1), spend.unpriced_turns);
    try std.testing.expectEqual(@as(u64, 1), spend.pricedTurns());
    try std.testing.expectEqual(@as(u64, 60), spend.input_tokens);
    // Only the priced turn put money in. The free one is not a discount and
    // the unknown one is not a zero.
    try std.testing.expectApproxEqAbs(@as(f64, 0.25), spend.amount, 1e-12);
    // And the unknown one alone is what stops a cap being enforced.
    try std.testing.expect(!spend.enforceable());

    var free_only = Spend{};
    free_only.add(.{ .input_tokens = 10, .cost = .free });
    free_only.add(.{ .input_tokens = 10, .cost = .free });
    try std.testing.expectEqual(@as(u64, 2), free_only.free_turns);
    try std.testing.expectEqual(@as(u64, 0), free_only.unpriced_turns);
    try std.testing.expectEqual(@as(u64, 0), free_only.pricedTurns());
    // A session against a local model runs under a cap without trouble.
    try std.testing.expect(free_only.enforceable());
}

test "a state a newer writer used counts as unknown and never as free" {
    // An `unrecognized` cost came from a Chock this reader is older than. It
    // is not a number and it is not a measured zero, so it takes the answer
    // that refuses to enforce a cap rather than the one that enforces a wrong
    // one.
    var spend = Spend{};
    spend.add(.{ .cost = .{ .unrecognized = .{ .name = "metered", .raw = .null } } });
    try std.testing.expectEqual(@as(u64, 1), spend.unpriced_turns);
    try std.testing.expectEqual(@as(u64, 0), spend.free_turns);
    try std.testing.expect(!spend.enforceable());
}

test "two sessions add up, and two currencies stop the total being one" {
    // What `chock usage` does across a project. Adding a euro to a dollar
    // gives a number in no currency at all, so the sum says it is not a sum
    // rather than printing a figure nobody can check.
    var first = Spend{};
    first.add(.{ .input_tokens = 100, .cost = .{ .known = .{ .value = 1.50, .currency = "USD" } } });
    first.add(.{ .input_tokens = 100, .cost = .free });

    var second = Spend{};
    second.add(.{ .output_tokens = 40, .cost = .{ .known = .{ .value = 2.25, .currency = "USD" } } });

    var total = Spend{};
    total.merge(first);
    total.merge(second);
    try std.testing.expectEqual(@as(u64, 3), total.turns);
    try std.testing.expectEqual(@as(u64, 200), total.input_tokens);
    try std.testing.expectEqual(@as(u64, 40), total.output_tokens);
    try std.testing.expectEqual(@as(u64, 1), total.free_turns);
    try std.testing.expectEqual(@as(u64, 2), total.pricedTurns());
    try std.testing.expectApproxEqAbs(@as(f64, 3.75), total.amount, 1e-12);
    try std.testing.expectEqualStrings("USD", total.currency);
    try std.testing.expect(total.enforceable());

    var euros = Spend{};
    euros.add(.{ .cost = .{ .known = .{ .value = 1.00, .currency = "EUR" } } });
    total.merge(euros);
    try std.testing.expect(total.mixed_currency);
    try std.testing.expect(!total.enforceable());

    // And a session that was already mixed carries that across the merge,
    // rather than the flag being lost because this session's own currency
    // matched.
    var already_mixed = Spend{ .mixed_currency = true };
    var fresh = Spend{};
    fresh.merge(already_mixed);
    try std.testing.expect(fresh.mixed_currency);
    already_mixed = .{};
}

test "the newest workspace.open is the workspace, because each attempt opens one" {
    // The fact this pins: the fold overwrites, and it does not append or keep
    // the first. Each attempt at a session mints its own identifier and opens
    // its own workspace, so only the newest one is on disk. A next owner sent
    // to an earlier path would find a directory an earlier attempt removed.
    // Change `apply` to keep the first value and this test stops holding.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    // A session that opened nothing names no path, so nothing can invent one.
    try std.testing.expectEqual(@as(?Workspace, null), session.workspace);

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .workspace_open = .{
        .kind = .worktree,
        .attempt = "01FIRST",
        .path = "/work/01FIRST",
        .base_commit = "aaaa1111",
    } } });
    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{ .workspace_open = .{
        .kind = .overlay,
        .attempt = "01SECOND",
        .path = "/work/01SECOND/upper",
        .base_commit = "",
    } } });

    const workspace = session.workspace.?;
    try std.testing.expectEqualStrings("01SECOND", workspace.attempt);
    try std.testing.expectEqualStrings("/work/01SECOND/upper", workspace.path);
    try std.testing.expectEqualStrings("overlay", workspace.kind.wireName());
    // An overlay has no commit of its own, and the fold does not carry the
    // commit of the attempt before it.
    try std.testing.expectEqualStrings("", workspace.base_commit);
}

test "the fold copies the workspace strings, so a released envelope leaves them whole" {
    // The fact this pins: `apply` keeps no reference into the envelope it was
    // given. The next owner of a session reads these strings long after the
    // replay that produced them freed its line. Change the `.workspace_open`
    // arm to assign the slices instead of duplicating them and this test stops
    // holding, under the testing allocator or under a sanitizer.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    const attempt = try allocator.dupe(u8, "01ATTEMPT");
    const path = try allocator.dupe(u8, "/work/01ATTEMPT");
    const commit = try allocator.dupe(u8, "9f2c1ab4d5e6f708");
    const kind_name = try allocator.dupe(u8, "btrfs_subvolume");

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .workspace_open = .{
        .kind = .{ .unknown = kind_name },
        .attempt = attempt,
        .path = path,
        .base_commit = commit,
    } } });

    allocator.free(attempt);
    allocator.free(path);
    allocator.free(commit);
    allocator.free(kind_name);

    const workspace = session.workspace.?;
    try std.testing.expectEqualStrings("01ATTEMPT", workspace.attempt);
    try std.testing.expectEqualStrings("/work/01ATTEMPT", workspace.path);
    try std.testing.expectEqualStrings("9f2c1ab4d5e6f708", workspace.base_commit);
    // A backing a newer writer used keeps its spelling here too, so a person
    // reading the state sees what the log said.
    try std.testing.expectEqualStrings("btrfs_subvolume", workspace.kind.wireName());
}

test "a handed over session ends, and the workspace it names is still the one on disk" {
    // The fact this pins: the two halves of a live handover reach the state
    // together. The end reason says the session stopped for a new owner, and
    // the fold still names the workspace and the commit that owner has to
    // adopt. Change `session.end` to clear `workspace` and this test stops
    // holding.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .workspace_open = .{
        .kind = .worktree,
        .attempt = "01ATTEMPT",
        .path = "/work/01ATTEMPT",
        .base_commit = "aaaa1111",
    } } });
    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{
        .session_end = .{ .reason = .handed_over, .detail = "" },
    } });

    try std.testing.expect(session.ended);
    try std.testing.expectEqual(
        event.SessionEndReason.handed_over,
        std.meta.activeTag(session.end_reason),
    );
    // Not a cancel: a cancel takes the workspace away, and a handover hands it
    // on. See `event.SessionEndReason.handed_over`.
    try std.testing.expect(std.meta.activeTag(session.end_reason) != .canceled_by_user);
    try std.testing.expectEqualStrings("/work/01ATTEMPT", session.workspace.?.path);
    try std.testing.expectEqualStrings("aaaa1111", session.workspace.?.base_commit);
}
