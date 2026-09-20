//! The fold that turns a session log into the state of a session. It never
//! reads storage itself. Compaction is an event in the log, not an edit to it:
//! applying one shortens the model's view and never the log.

const std = @import("std");
const event = @import("event.zig");
const log = @import("log.zig");

pub const OwnedMessage = struct {
    role: event.Role,
    content: []const event.ContentPart,
};

pub const ContextData = union(enum) {
    message: OwnedMessage,
    summary: []const u8,
};

pub const ContextEntry = struct {
    id: u64,
    data: ContextData,
    model_alias: []const u8 = "",
};

pub const Child = struct {
    session: []const u8,
    agent_kind: []const u8,
    reason: []const u8,
    budget_max_cost: f64 = 0,
    budget_currency: []const u8 = "",
};

pub const Workspace = struct {
    kind: event.WorkspaceKind,
    attempt: []const u8,
    path: []const u8,
    /// Empty for the overlay kind. Never treat that empty string as a commit.
    base_commit: []const u8,
};

/// A cap is enforced against this and only against this: ai&'s analytics API is
/// rate limited and cached for 120 seconds, so a cap checked against it is not
/// a cap.
pub const Spend = struct {
    input_tokens: u64 = 0,
    output_tokens: u64 = 0,
    cache_creation_input_tokens: u64 = 0,
    cache_read_input_tokens: u64 = 0,
    amount: f64 = 0,
    currency: []const u8 = "",
    turns: u64 = 0,
    /// A total with one of these in it is not a total.
    unpriced_turns: u64 = 0,
    /// Apart from `unpriced_turns`: free and unknown are different facts.
    free_turns: u64 = 0,
    /// Two currencies add up to a number in no currency at all, so the total
    /// stops being enforceable rather than quietly becoming wrong.
    mixed_currency: bool = false,

    pub fn enforceable(self: Spend) bool {
        return self.unpriced_turns == 0 and !self.mixed_currency;
    }

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
            .unknown, .unrecognized => self.unpriced_turns += 1,
        }
    }

    /// Saturating, so numbers that do not add up give a wrong answer, no panic.
    pub fn pricedTurns(self: Spend) u64 {
        return self.turns -| self.free_turns -| self.unpriced_turns;
    }

    /// `currency` is borrowed from `other`: a caller that keeps the result must
    /// keep that string alive too.
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

/// Nothing is ever removed from this list. A step is merged in by identifier,
/// so an agent that stops naming a step does not make it disappear: the only
/// way off the list is `PlanStatus.abandoned`.
pub const Plan = struct {
    pub const Step = struct {
        id: []const u8,
        subject: []const u8,
        status: event.PlanStatus,
        blocked_by: []const u8 = "",
    };

    pub const Counts = struct {
        pending: usize = 0,
        in_progress: usize = 0,
        done: usize = 0,
        abandoned: usize = 0,
        unrecognized: usize = 0,

        pub fn total(self: Counts) usize {
            return self.pending + self.in_progress + self.done +
                self.abandoned + self.unrecognized;
        }

        pub fn left(self: Counts) usize {
            return self.pending + self.in_progress + self.unrecognized;
        }
    };

    steps: std.ArrayList(Step) = .empty,

    pub fn isEmpty(self: Plan) bool {
        return self.steps.items.len == 0;
    }

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

    pub fn apply(
        self: *Plan,
        allocator: std.mem.Allocator,
        update: event.PlanUpdate,
    ) std.mem.Allocator.Error!void {
        for (update.steps) |given| {
            if (given.id.len == 0) continue;

            const status = try dupePlanStatus(allocator, given.status);
            const blocked_by = try allocator.dupe(u8, given.blocked_by);
            if (self.find(given.id)) |step| {
                step.status = status;
                step.blocked_by = blocked_by;
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

/// Nothing is ever removed from this list, and no event can remove one. The
/// ceiling for an act is the narrowest promise that covers it, so a list that
/// only grows can only narrow.
pub const SelfPolicy = struct {
    restrictions: std.ArrayList(event.SelfRestriction) = .empty,

    /// An authorised update replaces by exact name, every other one appends. An
    /// agent cannot write that flag: `chock_core.Loop` sets it only after a
    /// broker outside the agent's reach permitted the widening.
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
                        _ = self.restrictions.orderedRemove(index);
                        continue;
                    }
                    index += 1;
                }
            }
        }
        for (update.restrictions) |given| {
            if (given.action.len == 0) continue;
            try self.restrictions.append(allocator, .{
                .action = try allocator.dupe(u8, given.action),
                .ceiling = try dupePolicyCeiling(allocator, given.ceiling),
                .reason = try allocator.dupe(u8, given.reason),
            });
        }
    }
};

/// A memory of an answer, never a permission of its own. The type cannot
/// enforce that a grant never outlives a narrowing, and it cannot detect one:
/// `apply` folds `approval.response` events only.
pub const SessionGrants = struct {
    granted: std.StringHashMapUnmanaged(void) = .empty,

    /// The match is exact equality, never an `else`: a decision this fold does
    /// not recognise must not fall through into a grant. `request_id` zero is
    /// refused too, because a response the table answered on its own carries
    /// zero, and so does the record of a grant that served an act.
    pub fn apply(
        self: *SessionGrants,
        allocator: std.mem.Allocator,
        response: event.ApprovalResponse,
    ) std.mem.Allocator.Error!void {
        if (response.decision != .approved_by_user_for_session) return;
        if (response.action.len == 0 or response.request_id == 0) return;
        if (self.granted.contains(response.action)) return;
        const owned = try allocator.dupe(u8, response.action);
        try self.granted.put(allocator, owned, {});
    }

    /// `fresh_decision_is_ask` must be true only when the table's answer for
    /// this same action was exactly `ask`. The caller proves it with a flag
    /// because `chock_proto` cannot import `chock_policy`.
    pub fn get(self: SessionGrants, action: []const u8, fresh_decision_is_ask: bool) ?bool {
        if (!fresh_decision_is_ask) return null;
        if (self.granted.contains(action)) return true;
        return null;
    }

    /// Only a ceiling stricter than `ask` invalidates: a grant given while the
    /// table said `ask` still answers a fresh `ask`. An `unknown` ceiling is
    /// read the narrowest way there is, so it invalidates.
    pub fn invalidate(
        self: *SessionGrants,
        allocator: std.mem.Allocator,
        restriction: event.SelfRestriction,
    ) std.mem.Allocator.Error!void {
        const narrows = switch (restriction.ceiling) {
            .deny, .agent_then_human, .unknown => true,
            .ask, .agent_review, .allow => false,
        };
        if (!narrows or restriction.action.len == 0) return;

        var doomed: std.ArrayListUnmanaged([]const u8) = .empty;
        defer doomed.deinit(allocator);
        var it = self.granted.keyIterator();
        while (it.next()) |key| {
            if (matchesPattern(restriction.action, key.*)) try doomed.append(allocator, key.*);
        }
        for (doomed.items) |key| _ = self.granted.remove(key);
    }
};

/// `git.*` matches `git.push` and does not match `git` itself.
fn matchesPattern(pattern: []const u8, key: []const u8) bool {
    if (std.mem.endsWith(u8, pattern, ".*")) {
        const prefix = pattern[0 .. pattern.len - 2];
        return key.len > prefix.len + 1 and
            std.mem.startsWith(u8, key, prefix) and
            key[prefix.len] == '.';
    }
    return std.mem.eql(u8, pattern, key);
}

pub const Session = struct {
    arena: std.heap.ArenaAllocator,

    agent_kind: []const u8 = "",
    model_alias: []const u8 = "",
    parent_session: []const u8 = "",

    ended: bool = false,
    end_reason: event.SessionEndReason = .{ .unknown = "" },
    end_detail: []const u8 = "",

    context: std.ArrayList(ContextEntry) = .empty,

    children: std.ArrayList(Child) = .empty,

    /// A process that takes a session over reads the log and nothing else. A
    /// new owner that read `HEAD` again would compare the work against a
    /// commit the session made itself.
    workspace: ?Workspace = null,

    plan: Plan = .{},

    self_policy: SelfPolicy = .{},

    grants: SessionGrants = .{},

    spend: Spend = .{},

    /// Zero means nobody knows yet, never that the context is empty.
    last_input_tokens: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) Session {
        return .{ .arena = std.heap.ArenaAllocator.init(allocator) };
    }

    pub fn deinit(self: *Session) void {
        self.arena.deinit();
    }

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
                try self.children.append(allocator, try childFrom(allocator, spawn));
            },
            .workspace_open => |opened| {
                // The last one wins. Keeping the first would send the next
                // owner to a path an earlier attempt removed.
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
                self.spend.add(try ownedUsage(allocator, usage));
                self.last_input_tokens = usage.input_tokens +
                    usage.cache_creation_input_tokens + usage.cache_read_input_tokens;
            },
            .plan_update => |update| try self.plan.apply(allocator, update),
            .policy_self => |update| {
                for (update.restrictions) |restriction| {
                    try self.grants.invalidate(allocator, restriction);
                }
                try self.self_policy.apply(allocator, update);
            },
            .approval_response => |response| try self.grants.apply(allocator, response),
            .compaction => |compaction| {
                try self.applyCompaction(allocator, compaction);
                // A reader that kept this number would compact again at once.
                self.last_input_tokens = 0;
            },
            else => {},
        }
    }

    /// A summary entry is always added, even when the range holds no context
    /// entry, so a reader can see that the compaction ran.
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
            if (!summary_written and entry.id > compaction.through_id) {
                try folded.append(allocator, try summaryEntry(allocator, compaction));
                summary_written = true;
            }
            try folded.append(allocator, entry);
        }
        if (!summary_written) try folded.append(allocator, try summaryEntry(allocator, compaction));

        self.context = folded;
    }
};

fn childFrom(allocator: std.mem.Allocator, spawn: event.SessionSpawn) std.mem.Allocator.Error!Child {
    return .{
        .session = try allocator.dupe(u8, spawn.child_session),
        .agent_kind = try allocator.dupe(u8, spawn.child_agent_kind),
        .reason = try allocator.dupe(u8, spawn.reason),
        // A budget slice a resumed parent forgot is one it hands out twice.
        .budget_max_cost = spawn.budget_max_cost,
        .budget_currency = try allocator.dupe(u8, spawn.budget_currency),
    };
}

fn ownedUsage(allocator: std.mem.Allocator, usage: event.Usage) std.mem.Allocator.Error!event.Usage {
    var owned = usage;
    if (usage.cost == .known) {
        owned.cost = .{ .known = .{
            .value = usage.cost.known.value,
            .currency = try allocator.dupe(u8, usage.cost.known.currency),
        } };
    }
    return owned;
}

/// This holds no `context` field and must never grow one: a caller that writes
/// `.context` then gets a compile error rather than a stale value.
pub const PolicyFold = struct {
    arena: std.heap.ArenaAllocator,

    children: std.ArrayList(Child) = .empty,
    self_policy: SelfPolicy = .{},
    grants: SessionGrants = .{},
    spend: Spend = .{},

    pub fn init(allocator: std.mem.Allocator) PolicyFold {
        return .{ .arena = std.heap.ArenaAllocator.init(allocator) };
    }

    pub fn deinit(self: *PolicyFold) void {
        self.arena.deinit();
    }

    pub fn apply(self: *PolicyFold, envelope: event.Envelope) std.mem.Allocator.Error!void {
        const allocator = self.arena.allocator();
        switch (envelope.event) {
            .session_spawn => |spawn| try self.children.append(allocator, try childFrom(allocator, spawn)),
            .usage => |usage| self.spend.add(try ownedUsage(allocator, usage)),
            .policy_self => |update| {
                for (update.restrictions) |restriction| {
                    try self.grants.invalidate(allocator, restriction);
                }
                try self.self_policy.apply(allocator, update);
            },
            .approval_response => |response| try self.grants.apply(allocator, response),
            else => {},
        }
    }
};

/// `from_id`, because the ids of `context` must stay in ascending order. With
/// `through_id` the summary carried an id larger than the entries a tail kept,
/// so the next compaction folded nothing and the context went on growing.
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

/// `.unknown`'s raw JSON tree is not copied: the log keeps those bytes.
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
            .image => |image| .{ .image = .{
                .call_id = try allocator.dupe(u8, image.call_id),
                .media_type = try allocator.dupe(u8, image.media_type),
                .data = try allocator.dupe(u8, image.data),
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

    try std.testing.expectEqual(@as(usize, 2), session.context.items.len);
    try std.testing.expectEqualStrings("one and two, summarized", session.context.items[0].data.summary);
    try std.testing.expectEqualStrings("compact", session.context.items[0].model_alias);
    try std.testing.expectEqualStrings("three", session.context.items[1].data.message.content[0].text);

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
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    for (1..7) |i| {
        try session.apply(.{ .id = i * 10, .session = "01S", .time_ms = 1, .event = .{
            .message = .{ .role = .user, .content = &.{.{ .text = "turn" }} },
        } });
    }
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

    for (session.context.items[1..], session.context.items[0 .. session.context.items.len - 1]) |after, before| {
        try std.testing.expect(before.id <= after.id);
    }

    try session.apply(.{ .id = 80, .session = "01S", .time_ms = 3, .event = .{
        .compaction = .{
            .summary = "the second summary",
            .from_id = 20,
            .through_id = 60,
            .kept_ranges = &.{.{ .from_id = 60, .through_id = 60 }},
            .model_alias = "compact",
        },
    } });

    try std.testing.expectEqual(@as(usize, 3), session.context.items.len);
    try std.testing.expectEqualStrings("the second summary", session.context.items[1].data.summary);
    try std.testing.expectEqual(@as(u64, 60), session.context.items[2].id);
}

test "the fold says which model alias produced which turn, when two aliases wrote in one session" {
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
    try std.testing.expectEqualStrings("", session.context.items[0].model_alias);
    try std.testing.expectEqualStrings("cheap", session.context.items[1].model_alias);
    try std.testing.expectEqualStrings("expensive", session.context.items[2].model_alias);
}

test "a compaction whose range covers no context entry still leaves a summary behind" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 10, .session = "01S", .time_ms = 1, .event = .{
        .message = .{ .role = .user, .content = &.{.{ .text = "before" }} },
    } });
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

    try std.testing.expectEqual(@as(usize, 0), session.context.items.len);
}

test "a session with no plan.update event has no plan at all" {
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
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .plan_update = .{ .steps = &.{
        .{ .id = "s1", .subject = "read the fold", .status = .in_progress },
        .{ .id = "s2", .subject = "measure it on Darwin", .status = .pending },
        .{ .id = "s3", .subject = "write the command", .status = .pending },
    } } } });
    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{ .plan_update = .{ .steps = &.{
        .{ .id = "s1", .subject = "read the fold", .status = .done },
        .{ .id = "s3", .subject = "write the command", .status = .abandoned },
    } } } });

    try std.testing.expectEqual(@as(usize, 3), session.plan.steps.items.len);
    try std.testing.expectEqualStrings("s1", session.plan.steps.items[0].id);
    try std.testing.expectEqualStrings("s2", session.plan.steps.items[1].id);
    try std.testing.expectEqualStrings("s3", session.plan.steps.items[2].id);

    const forgotten = session.plan.find("s2").?;
    try std.testing.expectEqual(event.PlanStatus.pending, std.meta.activeTag(forgotten.status));
    try std.testing.expectEqualStrings("measure it on Darwin", forgotten.subject);

    const dropped = session.plan.find("s3").?;
    try std.testing.expectEqual(event.PlanStatus.abandoned, std.meta.activeTag(dropped.status));
    try std.testing.expect(dropped.status != .done);

    const counts = session.plan.counts();
    try std.testing.expectEqual(@as(usize, 1), counts.done);
    try std.testing.expectEqual(@as(usize, 1), counts.abandoned);
    try std.testing.expectEqual(@as(usize, 1), counts.pending);
    try std.testing.expectEqual(@as(usize, 3), counts.total());
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
    try std.testing.expectEqualStrings("", step.blocked_by);

    try session.apply(.{ .id = 3, .session = "01S", .time_ms = 3, .event = .{ .plan_update = .{ .steps = &.{
        .{ .id = "s1", .subject = "port the driver and its probe", .status = .done },
    } } } });
    try std.testing.expectEqualStrings("port the driver and its probe", session.plan.find("s1").?.subject);
    try std.testing.expectEqual(@as(usize, 1), session.plan.steps.items.len);
}

test "a status this reader does not know is counted apart, and never as done" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .plan_update = .{ .steps = &.{
        .{ .id = "s1", .subject = "ship it", .status = .{ .unknown = "deferred" } },
    } } } });

    const counts = session.plan.counts();
    try std.testing.expectEqual(@as(usize, 0), counts.done);
    try std.testing.expectEqual(@as(usize, 1), counts.unrecognized);
    try std.testing.expectEqual(@as(usize, 1), counts.left());
    try std.testing.expectEqualStrings("deferred", session.plan.find("s1").?.status.wireName());
}

test "the plan folds from the log, and a fresh replay of the same log gives the same list" {
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

    const counts = replayed.plan.counts();
    try std.testing.expectEqual(@as(usize, 1), counts.done);
    try std.testing.expectEqual(@as(usize, 1), counts.abandoned);
    try std.testing.expectEqual(@as(usize, 1), counts.pending);
    try std.testing.expectEqualStrings("b", replayed.plan.find("c").?.blocked_by);
}

test "a promise the agent made survives a resume, because it is folded from the log" {
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

    try std.testing.expect(replayed.context.items.len < written.len);
}

test "a promise from a newer writer keeps its own spelling, and one that binds nothing is dropped" {
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

test "a grant for the rest of the session survives a resume, because it is folded from the log" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try log.absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/grants", .{dir_path});

    var chock_log = try log.Log.open(io, path, "01GRANTS");
    defer chock_log.close(io);
    var locked = try chock_log.lock(io);

    var live = Session.init(allocator);
    defer live.deinit();

    const granted_request: event.Event = .{ .approval_request = .{
        .action = "git.push",
        .summary = "push to origin",
        .detail = "a1b2c3 fix the parser",
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } };
    const granted_request_id = try locked.append(allocator, io, granted_request, 1);
    try live.apply(.{ .id = granted_request_id, .session = "01GRANTS", .time_ms = 1, .event = granted_request });

    const granted_response: event.Event = .{ .approval_response = .{
        .request_id = granted_request_id,
        .decision = .approved_by_user_for_session,
        .responder = "terminal",
        .action = "git.push",
        .tool_call_id = "call1",
    } };
    const granted_response_id = try locked.append(allocator, io, granted_response, 2);
    try live.apply(.{ .id = granted_response_id, .session = "01GRANTS", .time_ms = 2, .event = granted_response });

    const plain_request: event.Event = .{ .approval_request = .{
        .action = "git.commit",
        .summary = "commit the fix",
        .detail = "a1b2c3 fix the parser",
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call2",
    } };
    const plain_request_id = try locked.append(allocator, io, plain_request, 3);
    try live.apply(.{ .id = plain_request_id, .session = "01GRANTS", .time_ms = 3, .event = plain_request });

    const plain_response: event.Event = .{ .approval_response = .{
        .request_id = plain_request_id,
        .decision = .approved_by_user,
        .responder = "terminal",
        .action = "git.commit",
        .tool_call_id = "call2",
    } };
    const plain_response_id = try locked.append(allocator, io, plain_response, 4);
    try live.apply(.{ .id = plain_response_id, .session = "01GRANTS", .time_ms = 4, .event = plain_response });

    try std.testing.expectEqual(true, live.grants.get("git.push", true).?);
    try std.testing.expectEqual(@as(?bool, null), live.grants.get("git.commit", true));
    try std.testing.expectEqual(@as(?bool, null), live.grants.get("git.fetch", true));

    var replayed = Session.init(allocator);
    defer replayed.deinit();
    var replay = try chock_log.replayFrom(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |envelope| {
        defer envelope.deinit();
        try replayed.apply(envelope.value);
    }

    try std.testing.expectEqual(true, replayed.grants.get("git.push", true).?);
    try std.testing.expectEqual(@as(?bool, null), replayed.grants.get("git.commit", true));
    try std.testing.expectEqual(@as(?bool, null), replayed.grants.get("git.fetch", true));
}

test "the overlay is read only where a question was actually asked" {
    // `request_id` is zero when the table decided on its own, so no question
    // was written and nobody could have answered one.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .approval_response = .{
        .request_id = 0,
        .decision = .approved_by_user_for_session,
        .responder = "terminal",
        .action = "git.push",
    } } });
    try std.testing.expectEqual(@as(?bool, null), session.grants.get("git.push", true));

    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{ .approval_response = .{
        .request_id = 1,
        .decision = .approved_by_user_for_session,
        .responder = "terminal",
        .action = "git.push",
    } } });
    try std.testing.expectEqual(true, session.grants.get("git.push", true).?);
}

test "every decision but the one exact yes leaves the overlay untouched, a deny included" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    const others = [_]event.ApprovalDecision{
        .allowed_by_policy,
        .denied_by_policy,
        .approved_by_user,
        .refused_by_user,
        .expired,
        .approved_by_review,
        .refused_by_review,
        .review_unavailable,
        .{ .unknown = "approved_with_edits" },
    };
    for (others, 1..) |decision, id| {
        try session.apply(.{
            .id = @intCast(id),
            .session = "01S",
            .time_ms = @intCast(id),
            .event = .{ .approval_response = .{
                .request_id = @intCast(id),
                .decision = decision,
                .responder = "terminal",
                .action = "git.push",
            } },
        });
    }
    try std.testing.expectEqual(@as(?bool, null), session.grants.get("git.push", true));
}

test "a policy.self narrowing the exact action clears the grant it names" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .approval_response = .{
        .request_id = 1,
        .decision = .approved_by_user_for_session,
        .responder = "terminal",
        .action = "git.push",
    } } });
    try std.testing.expectEqual(true, session.grants.get("git.push", true).?);

    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{ .policy_self = .{
        .restrictions = &.{
            .{ .action = "git.push", .ceiling = .agent_then_human, .reason = "restrict_self" },
        },
    } } });
    try std.testing.expectEqual(@as(?bool, null), session.grants.get("git.push", true));
}

test "a policy.self narrowing through a class pattern clears every grant it covers" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .approval_response = .{
        .request_id = 1,
        .decision = .approved_by_user_for_session,
        .responder = "terminal",
        .action = "git.push",
    } } });
    try std.testing.expectEqual(true, session.grants.get("git.push", true).?);

    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{ .policy_self = .{
        .restrictions = &.{
            .{ .action = "git.*", .ceiling = .deny, .reason = "restrict_self" },
        },
    } } });
    try std.testing.expectEqual(@as(?bool, null), session.grants.get("git.push", true));
}

test "a policy.self narrowing an unrelated action leaves another grant alone" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .approval_response = .{
        .request_id = 1,
        .decision = .approved_by_user_for_session,
        .responder = "terminal",
        .action = "git.push",
    } } });

    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{ .policy_self = .{
        .restrictions = &.{
            .{ .action = "net.fetch", .ceiling = .deny, .reason = "restrict_self" },
        },
    } } });
    try std.testing.expectEqual(true, session.grants.get("git.push", true).?);
}

test "a ceiling of ask or wider never clears a grant" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .approval_response = .{
        .request_id = 1,
        .decision = .approved_by_user_for_session,
        .responder = "terminal",
        .action = "git.push",
    } } });

    const wide = [_]event.PolicyCeiling{ .ask, .agent_review, .allow };
    for (wide, 2..) |ceiling, id| {
        try session.apply(.{
            .id = @intCast(id),
            .session = "01S",
            .time_ms = @intCast(id),
            .event = .{ .policy_self = .{
                .restrictions = &.{
                    .{ .action = "git.push", .ceiling = ceiling, .reason = "restrict_self" },
                },
            } },
        });
    }
    try std.testing.expectEqual(true, session.grants.get("git.push", true).?);
}

test "get returns the grant only where the fresh decision is exactly ask" {
    // `Broker.request` routes both `.ask` and `.agent_then_human` through
    // `askTheHuman`, so a caller must prove which one it had.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{ .approval_response = .{
        .request_id = 1,
        .decision = .approved_by_user_for_session,
        .responder = "terminal",
        .action = "git.push",
    } } });

    try std.testing.expectEqual(true, session.grants.get("git.push", true).?);
    try std.testing.expectEqual(@as(?bool, null), session.grants.get("git.push", false));
}

test "a plan step with no identifier is dropped, because nothing could ever change it" {
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
    var spend = Spend{};
    spend.add(.{ .input_tokens = 10, .cost = .free });
    spend.add(.{ .input_tokens = 20, .cost = .unknown });
    spend.add(.{ .input_tokens = 30, .cost = .{ .known = .{ .value = 0.25, .currency = "USD" } } });

    try std.testing.expectEqual(@as(u64, 3), spend.turns);
    try std.testing.expectEqual(@as(u64, 1), spend.free_turns);
    try std.testing.expectEqual(@as(u64, 1), spend.unpriced_turns);
    try std.testing.expectEqual(@as(u64, 1), spend.pricedTurns());
    try std.testing.expectEqual(@as(u64, 60), spend.input_tokens);
    try std.testing.expectApproxEqAbs(@as(f64, 0.25), spend.amount, 1e-12);
    try std.testing.expect(!spend.enforceable());

    var free_only = Spend{};
    free_only.add(.{ .input_tokens = 10, .cost = .free });
    free_only.add(.{ .input_tokens = 10, .cost = .free });
    try std.testing.expectEqual(@as(u64, 2), free_only.free_turns);
    try std.testing.expectEqual(@as(u64, 0), free_only.unpriced_turns);
    try std.testing.expectEqual(@as(u64, 0), free_only.pricedTurns());
    try std.testing.expect(free_only.enforceable());
}

test "a state a newer writer used counts as unknown and never as free" {
    var spend = Spend{};
    spend.add(.{ .cost = .{ .unrecognized = .{ .name = "metered", .raw = .null } } });
    try std.testing.expectEqual(@as(u64, 1), spend.unpriced_turns);
    try std.testing.expectEqual(@as(u64, 0), spend.free_turns);
    try std.testing.expect(!spend.enforceable());
}

test "two sessions add up, and two currencies stop the total being one" {
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

    var already_mixed = Spend{ .mixed_currency = true };
    var fresh = Spend{};
    fresh.merge(already_mixed);
    try std.testing.expect(fresh.mixed_currency);
    already_mixed = .{};
}

test "the newest workspace.open is the workspace, because each attempt opens one" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

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
    try std.testing.expectEqualStrings("", workspace.base_commit);
}

test "the fold copies the workspace strings, so a released envelope leaves them whole" {
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
    try std.testing.expectEqualStrings("btrfs_subvolume", workspace.kind.wireName());
}

test "a handed over session ends, and the workspace it names is still the one on disk" {
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
    try std.testing.expect(std.meta.activeTag(session.end_reason) != .canceled_by_user);
    try std.testing.expectEqualStrings("/work/01ATTEMPT", session.workspace.?.path);
    try std.testing.expectEqualStrings("aaaa1111", session.workspace.?.base_commit);
}
