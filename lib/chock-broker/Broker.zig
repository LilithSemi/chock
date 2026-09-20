//! The broker: it evaluates policy and asks for approval. The privileged work
//! is `lib/chock-broker/actions.zig`. An approval travels as two log events,
//! `approval.request` and `approval.response`, not on a channel of its own.

const std = @import("std");
const chock_proto = @import("chock-proto");
const chock_policy = @import("chock-policy");
const secrets_mod = @import("secrets.zig");
const review_mod = @import("review.zig");
const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;

const event = chock_proto.event;
const table = chock_policy.table;

const Broker = @This();

policy: *const table.Table,
waiter: Waiter,
/// A null reviewer is a refusal and never an allow.
reviewer: ?review_mod.Reviewer = null,
secrets: secrets_mod.Store = .{},
/// Values, and never a name: a name is a route to the value it protects. Short
/// values match inside ordinary words, so `src/run.zig` applies a length floor.
redaction: []const []const u8 = &.{},

grants: ?Grants = null,

/// `std.StringHashMapUnmanaged` grow frees the old array with the allocator of
/// the current call, so `allocator` must be the one that filled `memory`.
pub const Grants = struct {
    memory: *chock_proto.state.SessionGrants,
    allocator: std.mem.Allocator,
};

pub const default_timeout_ms: i64 = 5 * std.time.ms_per_min;

/// An open request holds the session lock, so a longer ask is reduced to this.
pub const max_timeout_ms: i64 = 60 * std.time.ms_per_min;

pub const poll_interval_ms: u64 = 50;

pub const Request = struct {
    action: []const u8,
    summary: []const u8,
    /// Show the effect, for example the diff, and never the command string.
    detail: []const u8,
    reason: []const u8,
    agent_kind: []const u8,
    model_alias: []const u8,
    tool: []const u8,
    tool_call_id: []const u8,
    source: []const u8 = "",
    /// Every parent of the asking agent, root first. The asking agent itself is
    /// not a link.
    spawn_chain: []const event.SpawnLink = &.{},
    timeout_ms: i64 = default_timeout_ms,
    self_policy: []const chock_policy.ratchet.Restriction = &.{},
};

pub const Outcome = enum {
    allowed_by_policy,
    denied_by_policy,
    approved_by_user,
    refused_by_user,
    expired,
    unknown_decision,
    mismatched_answer,
    approved_by_review,
    refused_by_review,
    /// A refusal. Every way a review can fail lands here.
    review_unavailable,

    pub fn permits(self: Outcome) bool {
        return switch (self) {
            .allowed_by_policy, .approved_by_user, .approved_by_review => true,
            .denied_by_policy,
            .refused_by_user,
            .expired,
            .unknown_decision,
            .mismatched_answer,
            .refused_by_review,
            .review_unavailable,
            => false,
        };
    }

    /// Coarse on purpose. The asking agent never learns which way a review was
    /// unavailable.
    pub fn reviewOutcome(self: Outcome) ?review_mod.ReviewOutcome {
        return switch (self) {
            .approved_by_review => .approved,
            .refused_by_review => .refused,
            .review_unavailable => .unavailable,
            .allowed_by_policy,
            .denied_by_policy,
            .approved_by_user,
            .refused_by_user,
            .expired,
            .unknown_decision,
            .mismatched_answer,
            => null,
        };
    }
};

pub const Error =
    std.mem.Allocator.Error ||
    chock_proto.storage.ReplayError ||
    std.Io.Cancelable;

/// `nowMs` must move forward as real time does. A clock that never moves makes
/// the wait in `request` run forever, and this file cannot recover from that.
pub const Waiter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Wake = enum {
        slept,
        /// The open `approval.request` stays in the log, the same state a crash
        /// leaves. A client that reconnects can still answer it.
        canceled,
    };

    pub const VTable = struct {
        /// Milliseconds since the epoch, the scale `timeout_at_ms` uses.
        nowMs: *const fn (ptr: *anyopaque, io: std.Io) i64,
        wait: *const fn (ptr: *anyopaque, io: std.Io, budget_ms: u64) Wake,
    };

    pub fn nowMs(self: Waiter, io: std.Io) i64 {
        return self.vtable.nowMs(self.ptr, io);
    }

    pub fn wait(self: Waiter, io: std.Io, budget_ms: u64) Wake {
        return self.vtable.wait(self.ptr, io, budget_ms);
    }
};

/// The clock is `.real`, because `timeout_at_ms` is a unix time every client
/// reads. The sleep is `.awake`, the monotonic clock, because it is a length.
pub const SystemWaiter = struct {
    var anchor: u8 = 0;

    pub fn waiter() Waiter {
        return .{ .ptr = &anchor, .vtable = &vtable };
    }

    const vtable = Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = ptr;
        return std.Io.Timestamp.now(io, .real).toMilliseconds();
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Waiter.Wake {
        _ = ptr;
        std.Io.sleep(io, .fromMilliseconds(@intCast(budget_ms)), .awake) catch |err| switch (err) {
            error.Canceled => return .canceled,
        };
        return .slept;
    }
};

/// `locked` is `anytype` because `chock_proto.storage.Locked` is not `pub`. A
/// generation check inside the backend is what proves the handle is real.
pub fn request(
    self: *const Broker,
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    locked: anytype,
    given: Request,
    diag: ?*?Diagnostic,
) Error!Outcome {
    std.debug.assert(given.action.len > 0);
    std.debug.assert(given.agent_kind.len > 0);
    std.debug.assert(given.model_alias.len > 0);
    std.debug.assert(given.tool.len > 0);

    var scrub_arena = std.heap.ArenaAllocator.init(gpa);
    defer scrub_arena.deinit();
    const ask = try self.scrubbed(scrub_arena.allocator(), given);

    const chain = try policyChain(gpa, ask);
    defer gpa.free(chain);

    const key = table.Key{
        .agent_kind = ask.agent_kind,
        .model = ask.model_alias,
        .tool = ask.tool,
        .action = ask.action,
    };

    // One evaluation, over the whole chain. A second evaluation of the asking
    // kind alone would let a reviewer be consulted about a denied key.
    const decision = chock_policy.ratchet.narrow(
        self.policy.evaluateChain(chain, key, null),
        ask.self_policy,
        key.action,
    );
    switch (decision) {
        .allow => {
            _ = try appendAnswer(gpa, io, locked, ask, 0, .allowed_by_policy, "", self.waiter.nowMs(io), .{});
            return .allowed_by_policy;
        },
        .deny => {
            _ = try appendAnswer(gpa, io, locked, ask, 0, .denied_by_policy, "", self.waiter.nowMs(io), .{});
            return .denied_by_policy;
        },
        .ask => {
            // `SessionGrants.apply` refuses to fold a zero `request_id` back
            // into a grant, so this response cannot become a second source of it.
            if (self.grants) |grants| {
                if (grants.memory.get(ask.action, true) != null) {
                    _ = try appendAnswer(
                        gpa,
                        io,
                        locked,
                        ask,
                        0,
                        .approved_by_user_for_session,
                        "",
                        self.waiter.nowMs(io),
                        .{},
                    );
                    return .approved_by_user;
                }
            }
            return self.askTheHuman(gpa, io, storage, locked, ask, .{}, diag);
        },
        .agent_review, .agent_then_human => {},
    }

    return self.reviewed(gpa, io, storage, locked, ask, chain, decision, diag);
}

/// A review that could not run is a refusal, because the cheapest attack on a
/// review is to make it fail.
fn reviewed(
    self: *const Broker,
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    locked: anytype,
    ask: Request,
    chain: []const []const u8,
    decision: chock_policy.table.Decision,
    diag: ?*?Diagnostic,
) Error!Outcome {
    std.debug.assert(decision.needsReview());

    if (decision.needsHuman() and ask.timeout_ms <= 0) {
        _ = diagnostic.note(diag, .{ .cannot_wait_for_a_person = .{
            .decision = decision,
            .action = ask.action,
        } });
        _ = try appendAnswer(gpa, io, locked, ask, 0, .expired, "", self.waiter.nowMs(io), .{});
        return .expired;
    }

    const report = self.runReview(gpa, io, ask, chain, decision, diag) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ReviewNotRun => {
            _ = try appendAnswer(gpa, io, locked, ask, 0, .review_unavailable, "", self.waiter.nowMs(io), .{});
            return .review_unavailable;
        },
    };
    defer review_mod.freeReport(gpa, report);

    const clean_note = try self.scrubText(gpa, report.note);
    defer if (clean_note) |note| gpa.free(note);
    const record = Record{ .verdict = report.verdict, .note = clean_note orelse report.note };

    switch (review_mod.resolve(decision, report.verdict)) {
        .permit => {
            _ = try appendAnswer(
                gpa,
                io,
                locked,
                ask,
                0,
                .approved_by_review,
                self.reviewer.?.kind,
                self.waiter.nowMs(io),
                record,
            );
            return .approved_by_review;
        },
        .refuse => {
            _ = try appendAnswer(
                gpa,
                io,
                locked,
                ask,
                0,
                .refused_by_review,
                self.reviewer.?.kind,
                self.waiter.nowMs(io),
                record,
            );
            return .refused_by_review;
        },
        .ask_the_human => return self.askTheHuman(gpa, io, storage, locked, ask, record, diag),
        .not_a_review => {
            _ = diagnostic.note(diag, .{ .review_for_a_decision_that_asks_for_none = .{
                .decision = decision,
                .action = ask.action,
            } });
            _ = try appendAnswer(gpa, io, locked, ask, 0, .review_unavailable, "", self.waiter.nowMs(io), .{});
            return .review_unavailable;
        },
    }
}

fn runReview(
    self: *const Broker,
    gpa: std.mem.Allocator,
    io: std.Io,
    ask: Request,
    chain: []const []const u8,
    decision: chock_policy.table.Decision,
    diag: ?*?Diagnostic,
) review_mod.ReviewError!review_mod.Report {
    const reviewer = self.reviewer orelse {
        _ = diagnostic.note(diag, .{ .no_reviewer = .{
            .decision = decision,
            .action = ask.action,
        } });
        return error.ReviewNotRun;
    };

    if (review_mod.reviewsItself(chain, reviewer.kind)) {
        _ = diagnostic.note(diag, .{ .reviewer_reviews_itself = .{
            .reviewer_kind = reviewer.kind,
            .action = ask.action,
        } });
        return error.ReviewNotRun;
    }

    return reviewer.review(gpa, io, .{
        .action = ask.action,
        .summary = ask.summary,
        .detail = ask.detail,
        .reason = ask.reason,
        .chain = chain,
        .decision = decision,
    });
}

fn askTheHuman(
    self: *const Broker,
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    locked: anytype,
    ask: Request,
    record: Record,
    diag: ?*?Diagnostic,
) Error!Outcome {
    const asked_at_ms = self.waiter.nowMs(io);
    const timeout_ms = @min(ask.timeout_ms, max_timeout_ms);
    const deadline_ms = asked_at_ms +| timeout_ms;

    // The question is on disk before the wait starts, so a crash leaves it
    // there for whoever reconnects.
    const request_id = try locked.append(gpa, io, .{
        .approval_request = .{
            .action = ask.action,
            .summary = ask.summary,
            .detail = ask.detail,
            .reason = ask.reason,
            .agent_kind = ask.agent_kind,
            .spawn_chain = ask.spawn_chain,
            .timeout_at_ms = deadline_ms,
            .tool_call_id = ask.tool_call_id,
            .source = ask.source,
            .review = record.verdict,
            .review_note = record.note,
        },
    }, asked_at_ms);

    var last_look_ms = asked_at_ms;
    while (true) {
        if (try findAnswer(
            gpa,
            io,
            storage,
            request_id,
            ask,
            self.grants,
            diag,
        )) |outcome| return outcome;

        const now_ms = self.waiter.nowMs(io);
        std.debug.assert(now_ms >= last_look_ms);
        last_look_ms = now_ms;

        if (now_ms >= deadline_ms) {
            _ = try appendAnswer(gpa, io, locked, ask, request_id, .expired, "", now_ms, record);
            return .expired;
        }

        const left_ms: u64 = @intCast(deadline_ms - now_ms);
        switch (self.waiter.wait(io, @min(left_ms, poll_interval_ms))) {
            .slept => {},
            .canceled => return error.Canceled,
        }
    }
}

/// The asking kind is added at the end. Stop doing that and a child can be
/// stronger than its parent. The caller frees the array, and not the names.
fn policyChain(gpa: std.mem.Allocator, ask: Request) Error![]const []const u8 {
    const chain = try gpa.alloc([]const u8, ask.spawn_chain.len + 1);
    for (ask.spawn_chain, chain[0..ask.spawn_chain.len]) |link, *slot| slot.* = link.agent_kind;
    chain[ask.spawn_chain.len] = ask.agent_kind;
    return chain;
}

/// The result is borrowed from `arena` and from `ask`.
fn scrubbed(self: *const Broker, arena: std.mem.Allocator, ask: Request) Error!Request {
    if (self.redaction.len == 0) return ask;

    var clean = ask;
    clean.summary = (try self.scrubText(arena, ask.summary)).?;
    clean.detail = (try self.scrubText(arena, ask.detail)).?;
    clean.reason = (try self.scrubText(arena, ask.reason)).?;

    if (ask.spawn_chain.len > 0) {
        const links = try arena.alloc(event.SpawnLink, ask.spawn_chain.len);
        for (ask.spawn_chain, links) |link, *slot| {
            slot.* = link;
            slot.reason = (try self.scrubText(arena, link.reason)).?;
        }
        clean.spawn_chain = links;
    }
    return clean;
}

// Every field of `Request` is replaced above or named here as one that holds no
// bytes an agent, a workspace or a model supplied. A new field fails the build.
comptime {
    const replaced = [_][]const u8{ "summary", "detail", "reason", "spawn_chain" };
    const chock_wrote_it = [_][]const u8{
        "action",       "agent_kind", "model_alias", "tool",
        "tool_call_id", "timeout_ms", "self_policy", "source",
    };
    for (@typeInfo(Request).@"struct".fields) |field| {
        var listed = false;
        for (replaced ++ chock_wrote_it) |name| {
            if (std.mem.eql(u8, field.name, name)) listed = true;
        }
        if (!listed) {
            @compileError("this field of Request is neither replaced nor named as Chock's own: " ++ field.name);
        }
    }
}

fn scrubText(
    self: *const Broker,
    gpa: std.mem.Allocator,
    said: []const u8,
) std.mem.Allocator.Error!?[]u8 {
    if (self.redaction.len == 0) return null;
    var scan = try secrets_mod.Redactor.initValues(gpa, self.redaction);
    defer scan.deinit(gpa);
    try scan.push(gpa, said);
    return try scan.finish(gpa);
}

/// The note goes nowhere but the log. The agent that asked reads
/// `review.requesterText`.
const Record = struct {
    verdict: event.ReviewVerdict = .none,
    note: []const u8 = "",
};

/// `request_id` is zero when no question was written.
fn appendAnswer(
    gpa: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    ask: Request,
    request_id: u64,
    decision: event.ApprovalDecision,
    responder: []const u8,
    time_ms: i64,
    record: Record,
) Error!u64 {
    return locked.append(gpa, io, .{ .approval_response = .{
        .request_id = request_id,
        .decision = decision,
        .responder = responder,
        .action = ask.action,
        .tool_call_id = ask.tool_call_id,
        .review = record.verdict,
        .review_note = record.note,
    } }, time_ms);
}

/// The newest open question, and only while it has no answer. Every waiter must
/// read it the same way, or one answers a question another is showing.
pub fn openRequest(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
) Error!?u64 {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();

    var newest: ?u64 = null;
    var answered = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .approval_request => {
                newest = parsed.value.id;
                answered = false;
            },
            .approval_response => |response| {
                if (newest) |id| {
                    if (response.request_id == id) answered = true;
                }
            },
            else => {},
        }
    }
    if (answered) return null;
    return newest;
}

/// A waiter holds no `Request`, so it reads the action back rather than guess it.
pub fn requestAction(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    request_id: u64,
) Error!?[]u8 {
    var replay = try storage.replay(gpa, io, request_id);
    defer replay.deinit();

    const parsed = try replay.next(io) orelse return null;
    defer parsed.deinit();
    if (parsed.value.event != .approval_request) return null;

    return try gpa.dupe(u8, parsed.value.event.approval_request.action);
}

/// More than one request can be open at once, so an answer must name the request
/// it answers. The replay starts at that request's own id, because an id is a
/// byte offset and another session's log can hold the same number.
fn findAnswer(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    request_id: u64,
    ask: Request,
    grants: ?Grants,
    diag: ?*?Diagnostic,
) Error!?Outcome {
    var replay = try storage.replay(gpa, io, request_id);
    defer replay.deinit();

    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .approval_response) continue;
        const answer = parsed.value.event.approval_response;
        if (answer.request_id != request_id) continue;
        if (disagrees(answer.action, ask.action) or
            disagrees(answer.tool_call_id, ask.tool_call_id))
        {
            if (diagnostic.wants(diag)) {
                var owned: Diagnostic = .{ .answer_is_about_another_request = .{
                    .request_id = request_id,
                    .answer_action = "",
                    .answer_tool_call_id = "",
                    .ask_action = ask.action,
                    .ask_tool_call_id = ask.tool_call_id,
                } };
                errdefer owned.deinit(gpa);
                const names = &owned.answer_is_about_another_request;
                names.answer_action = try gpa.dupe(u8, answer.action);
                names.answer_tool_call_id = try gpa.dupe(u8, answer.tool_call_id);
                _ = diagnostic.note(diag, owned);
            }
            return .mismatched_answer;
        }

        return switch (answer.decision) {
            .allowed_by_policy => .allowed_by_policy,
            .denied_by_policy => .denied_by_policy,
            .approved_by_user => .approved_by_user,
            .approved_by_user_for_session => blk: {
                if (grants) |g| try g.memory.apply(g.allocator, answer);
                break :blk .approved_by_user;
            },
            .refused_by_user => .refused_by_user,
            .expired => .expired,
            // This broker writes these three itself and never reads one back,
            // so one found here cannot be true of this request.
            inline .approved_by_review, .refused_by_review, .review_unavailable => |_, tag| claimed: {
                // A `ReviewDecision` and not `@tagName`: the name was a pointer
                // into `.rodata` and `Diagnostic.deinit` freed it.
                _ = diagnostic.note(diag, .{ .answer_claims_a_review = .{
                    .request_id = request_id,
                    .decision = @field(Diagnostic.ReviewDecision, @tagName(tag)),
                } });
                break :claimed .mismatched_answer;
            },
            .unknown => |name| unknown: {
                if (diagnostic.wants(diag)) {
                    _ = diagnostic.note(diag, .{ .answer_names_an_unknown_decision = .{
                        .request_id = request_id,
                        .name = try gpa.dupe(u8, name),
                    } });
                }
                break :unknown .unknown_decision;
            },
        };
    }
    return null;
}

/// This is not the seam a live session's tool results go through. `chock-core`
/// imports no `chock-broker`, so the loop cannot reach it, and nothing fills
/// `secrets` today. The loop's own seam is `chock_core.Loop.appendAndApply`.
pub fn appendToolResult(
    self: *const Broker,
    gpa: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    result: event.ToolResult,
    time_ms: i64,
) secrets_mod.AppendError!u64 {
    const clean = try self.scrubText(gpa, result.output);
    defer if (clean) |output| gpa.free(output);

    var scanned = result;
    if (clean) |output| scanned.output = output;
    return secrets_mod.appendToolResult(self.secrets, gpa, io, locked, scanned, time_ms);
}

/// Call this where the sandbox launcher builds the environment and nowhere else.
/// Release the result with `secrets.freeEnv`.
pub fn resolveEnv(
    self: *const Broker,
    gpa: std.mem.Allocator,
    entries: []const []const u8,
    diag: ?*?Diagnostic,
) secrets_mod.ResolveError![][]u8 {
    return secrets_mod.resolveEnv(self.secrets, gpa, entries, diag);
}

pub fn redactor(self: *const Broker, gpa: std.mem.Allocator) std.mem.Allocator.Error!secrets_mod.Redactor {
    const values = try gpa.alloc([]const u8, self.secrets.entries.len + self.redaction.len);
    defer gpa.free(values);
    for (self.secrets.entries, values[0..self.secrets.entries.len]) |entry, *slot| slot.* = entry.value;
    @memcpy(values[self.secrets.entries.len..], self.redaction);
    return secrets_mod.Redactor.initValues(gpa, values);
}

/// Empty means the writer did not say, and never "not applicable".
fn disagrees(said: []const u8, expected: []const u8) bool {
    return said.len > 0 and !std.mem.eql(u8, said, expected);
}

const testing = std.testing;

/// `chock_proto.storage.Locked` is not `pub`, so this reaches the same type
/// through the public return type of `Storage.lock`.
const LockedHandle = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

const OnWait = *const fn (ctx: ?*anyopaque, io: std.Io, waits: usize) anyerror!void;

const TestWaiter = struct {
    now_ms: i64 = 1_700_000_000_000,
    waits: usize = 0,
    frozen: bool = false,
    ctx: ?*anyopaque = null,
    on_wait: ?OnWait = null,
    /// A `Waiter` cannot report an error to the broker, so the test checks this.
    failed: ?anyerror = null,
    cancel_at_wait: ?usize = null,

    fn waiter(self: *TestWaiter) Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = io;
        const self: *TestWaiter = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Waiter.Wake {
        const self: *TestWaiter = @ptrCast(@alignCast(ptr));
        self.waits += 1;
        if (self.on_wait) |answer| {
            answer(self.ctx, io, self.waits) catch |err| {
                if (self.failed == null) self.failed = err;
            };
        }
        if (!self.frozen) self.now_ms += @intCast(budget_ms);
        if (self.cancel_at_wait) |at| {
            if (self.waits >= at) return .canceled;
        }
        return .slept;
    }
};

fn testRequest(action: []const u8) Request {
    return .{
        .action = action,
        .summary = "push the branch to origin",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the task asked for the change to be published",
        .agent_kind = "coder",
        .model_alias = "main",
        .tool = "git",
        .tool_call_id = "call1",
    };
}

fn testBroker(gpa: std.mem.Allocator, source: [:0]const u8, waiter: *TestWaiter) !Broker {
    return .{ .policy = try table.Table.parse(gpa, source, null), .waiter = waiter.waiter() };
}

fn findRequestId(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    action: []const u8,
) !?u64 {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .approval_request) continue;
        if (!std.mem.eql(u8, parsed.value.event.approval_request.action, action)) continue;
        return parsed.value.id;
    }
    return null;
}

/// `freeAnswer` releases it.
const LoggedAnswer = struct {
    id: u64,
    request_id: u64,
    decision_name: []const u8,
    responder: []const u8,
    action: []const u8,
    tool_call_id: []const u8,
    review_name: []const u8,
    review_note: []const u8,
};

fn countKind(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    kind: event.Kind,
) !usize {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    var count: usize = 0;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (std.meta.activeTag(parsed.value.event) == kind) count += 1;
    }
    return count;
}

fn theAnswer(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    request_id: u64,
) !LoggedAnswer {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();

    var found: ?LoggedAnswer = null;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .approval_response) continue;
        const answer = parsed.value.event.approval_response;
        if (answer.request_id != request_id) continue;
        if (found != null) return error.MoreThanOneAnswer;
        found = .{
            .id = parsed.value.id,
            .request_id = answer.request_id,
            .decision_name = try gpa.dupe(u8, answer.decision.wireName()),
            .responder = try gpa.dupe(u8, answer.responder),
            .action = try gpa.dupe(u8, answer.action),
            .tool_call_id = try gpa.dupe(u8, answer.tool_call_id),
            .review_name = try gpa.dupe(u8, answer.review.wireName()),
            .review_note = try gpa.dupe(u8, answer.review_note),
        };
    }
    return found orelse error.NoAnswer;
}

fn freeAnswer(gpa: std.mem.Allocator, answer: LoggedAnswer) void {
    gpa.free(answer.decision_name);
    gpa.free(answer.responder);
    gpa.free(answer.action);
    gpa.free(answer.tool_call_id);
    gpa.free(answer.review_name);
    gpa.free(answer.review_note);
}

/// This fills in neither `action` nor `tool_call_id` on purpose: a writer that
/// does not know those two fields must still be able to answer.
fn answerAsUser(
    gpa: std.mem.Allocator,
    io: std.Io,
    locked: *LockedHandle,
    request_id: u64,
    decision: event.ApprovalDecision,
    responder: []const u8,
) !u64 {
    return locked.append(gpa, io, .{ .approval_response = .{
        .request_id = request_id,
        .decision = decision,
        .responder = responder,
    } }, 1_700_000_000_000);
}

fn answerAbout(
    gpa: std.mem.Allocator,
    io: std.Io,
    locked: *LockedHandle,
    request_id: u64,
    decision: event.ApprovalDecision,
    action: []const u8,
    tool_call_id: []const u8,
) !u64 {
    return locked.append(gpa, io, .{ .approval_response = .{
        .request_id = request_id,
        .decision = decision,
        .responder = "ross",
        .action = action,
        .tool_call_id = tool_call_id,
    } }, 1_700_000_000_000);
}

const poison_width: usize = 24;

/// The line is the same number of bytes whatever `request_id` holds. An event id
/// is a byte offset, so the padding keeps the offsets after the line still.
fn stalePoison(
    gpa: std.mem.Allocator,
    io: std.Io,
    locked: *LockedHandle,
    request_id: u64,
) !void {
    var digits: [20]u8 = undefined;
    const printed = try std.fmt.bufPrint(&digits, "{d}", .{request_id});
    const padding: [poison_width]u8 = @splat('p');
    _ = try locked.append(gpa, io, .{ .approval_response = .{
        .request_id = request_id,
        .decision = .approved_by_user,
        .responder = padding[0 .. poison_width - printed.len],
    } }, 1_700_000_000_000);
}

/// It counts its calls, because an outcome alone cannot tell a review that
/// refused from one that never ran.
const TestReviewer = struct {
    kind: []const u8 = "arbiter",
    says: ?review_mod.Verdict = .approved,
    note: []const u8 = "the change is the one the task asked for",
    calls: usize = 0,
    /// A `Case` is borrowed for the length of the call, and `Case.chain` is an
    /// array `request` frees, so the case is taken apart rather than kept whole.
    saw_action: []const u8 = "",
    saw_detail: []const u8 = "",
    saw_decision: ?chock_policy.table.Decision = null,
    saw_chain_len: usize = 0,
    saw_first_kind: []const u8 = "",
    never: []const u8 = "",
    saw_never: bool = false,

    fn reviewer(self: *TestReviewer) review_mod.Reviewer {
        return .{ .ptr = self, .vtable = &vtable, .kind = self.kind };
    }

    const vtable = review_mod.Reviewer.VTable{ .review = reviewFn };

    fn reviewFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        case: review_mod.Case,
    ) review_mod.ReviewError!review_mod.Report {
        _ = io;
        const self: *TestReviewer = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        self.saw_action = case.action;
        self.saw_detail = case.detail;
        self.saw_decision = case.decision;
        self.saw_chain_len = case.chain.len;
        self.saw_first_kind = if (case.chain.len == 0) "" else case.chain[0];
        if (self.never.len > 0 and std.mem.indexOf(u8, case.detail, self.never) != null) {
            self.saw_never = true;
        }
        const verdict = self.says orelse return error.ReviewNotRun;
        return .{ .verdict = verdict, .note = try gpa.dupe(u8, self.note) };
    }
};

const LoggedQuestion = struct {
    id: u64,
    review_name: []const u8,
    review_note: []const u8,

    fn free(self: LoggedQuestion, gpa: std.mem.Allocator) void {
        gpa.free(self.review_name);
        gpa.free(self.review_note);
    }
};

fn theQuestion(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    action: []const u8,
) !LoggedQuestion {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .approval_request) continue;
        const question = parsed.value.event.approval_request;
        if (!std.mem.eql(u8, question.action, action)) continue;
        return .{
            .id = parsed.value.id,
            .review_name = try gpa.dupe(u8, question.review.wireName()),
            .review_note = try gpa.dupe(u8, question.review_note),
        };
    }
    return error.NoQuestion;
}

fn theOnlyAnswer(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
) !LoggedAnswer {
    return theAnswer(gpa, io, storage, 0);
}

const ask_every_action: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "git.push", .decision = .ask },
    \\            .{ .action = "git.commit", .decision = .ask },
    \\        },
    \\    },
    \\}
;

test "a request appears in the log before the broker waits for an answer" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,
        saw_request_at: ?u64 = null,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            self.saw_request_at = try findRequestId(self.gpa, io_inner, self.store, "git.push");
            const id = self.saw_request_at orelse return;
            _ = try answerAsUser(self.gpa, io_inner, self.locked, id, .approved_by_user, "ross");
        }
    };

    var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked };
    var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };

    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    if (waiter.failed) |err| return err;

    try testing.expect(answerer.saw_request_at != null);
    try testing.expectEqual(Outcome.approved_by_user, outcome);
    try testing.expect(outcome.permits());

    const answer = try theAnswer(gpa, io, store, answerer.saw_request_at.?);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("approved_by_user", answer.decision_name);
    try testing.expectEqualStrings("ross", answer.responder);
    try testing.expect(answerer.saw_request_at.? < answer.id);
}

test "a policy of allow never appends a request, and the log says the policy allowed it" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const allow_the_push: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const broker = try testBroker(gpa, allow_the_push, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    try testing.expectEqual(Outcome.allowed_by_policy, outcome);
    try testing.expect(outcome.permits());

    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
    try testing.expectEqual(@as(usize, 0), waiter.waits);

    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_response));
    const answer = try theAnswer(gpa, io, store, 0);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("allowed_by_policy", answer.decision_name);
    try testing.expectEqualStrings("git.push", answer.action);
    try testing.expectEqualStrings("call1", answer.tool_call_id);
    try testing.expectEqualStrings("", answer.responder);

    // Byte zero of every log is inside the header line, so no appended event
    // ever sits there and zero cannot be read as a real event id.
    try testing.expectEqual(@as(u64, 0), answer.request_id);
    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    var events: usize = 0;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        events += 1;
        try testing.expect(parsed.value.id > 0);
    }
    try testing.expectEqual(@as(usize, 1), events);
}

test "a policy of deny never appends a request either" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const deny_the_push: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.push", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const broker = try testBroker(gpa, deny_the_push, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    try testing.expectEqual(Outcome.denied_by_policy, outcome);
    try testing.expect(!outcome.permits());

    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
    try testing.expectEqual(@as(usize, 0), waiter.waits);
    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_response));

    const answer = try theAnswer(gpa, io, store, 0);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("denied_by_policy", answer.decision_name);
    try testing.expectEqualStrings("git.push", answer.action);
    try testing.expectEqualStrings("call1", answer.tool_call_id);
    try testing.expectEqualStrings("", answer.responder);
    try testing.expectEqual(@as(u64, 0), answer.request_id);
}

test "a request that expires is a refusal, and says expired rather than refused" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const started_at_ms = waiter.now_ms;

    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.timeout_ms = 500;

    const outcome = try broker.request(gpa, io, store, &locked, ask, null);
    try testing.expectEqual(Outcome.expired, outcome);
    try testing.expect(!outcome.permits());
    try testing.expect(outcome != .refused_by_user);
    try testing.expectEqual(@as(usize, 10), waiter.waits);

    const request_id = (try findRequestId(gpa, io, store, "git.push")).?;
    var replay = try store.replay(gpa, io, request_id);
    defer replay.deinit();
    const question = (try replay.next(io)).?;
    defer question.deinit();
    try testing.expectEqual(
        started_at_ms + ask.timeout_ms,
        question.value.event.approval_request.timeout_at_ms,
    );

    const answer = try theAnswer(gpa, io, store, request_id);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("expired", answer.decision_name);
    try testing.expect(!std.mem.eql(u8, "refused_by_user", answer.decision_name));
    try testing.expectEqualStrings("", answer.responder);
}

test "an answer to a different request does not answer this one" {
    // Both action names must be in the table this test parses, because
    // `lib/chock-policy/defaults.zig` ships `.allow` for `git.commit`.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    const Nested = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,
        broker: *const Broker,
        inner_outcome: ?Outcome = null,
        outer_id: ?u64 = null,
        inner_id: ?u64 = null,
        looks_while_only_the_other_was_answered: usize = 0,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            switch (waits) {
                1 => {
                    self.outer_id = try findRequestId(self.gpa, io_inner, self.store, "git.push");
                    var inner = testRequest("git.commit");
                    inner.tool_call_id = "call2";
                    // The inner request shares this waiter, so `waits` counts on.
                    self.inner_outcome = try self.broker.request(
                        self.gpa,
                        io_inner,
                        self.store,
                        self.locked,
                        inner,
                        null,
                    );
                },
                2 => {
                    self.inner_id = try findRequestId(self.gpa, io_inner, self.store, "git.commit");
                    _ = try answerAsUser(
                        self.gpa,
                        io_inner,
                        self.locked,
                        self.inner_id.?,
                        .approved_by_user,
                        "ross",
                    );
                },
                3 => self.looks_while_only_the_other_was_answered += 1,
                else => _ = try answerAsUser(
                    self.gpa,
                    io_inner,
                    self.locked,
                    self.outer_id.?,
                    .refused_by_user,
                    "ross",
                ),
            }
        }
    };

    var nested = Nested{ .gpa = gpa, .store = store, .locked = &locked, .broker = &broker };
    waiter.ctx = &nested;
    waiter.on_wait = Nested.onWait;

    const outer = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    if (waiter.failed) |err| return err;

    try testing.expect(nested.outer_id != null);
    try testing.expect(nested.inner_id != null);
    try testing.expect(nested.outer_id.? < nested.inner_id.?);

    try testing.expect(nested.looks_while_only_the_other_was_answered > 0);

    try testing.expectEqual(Outcome.approved_by_user, nested.inner_outcome.?);
    try testing.expectEqual(Outcome.refused_by_user, outer);
    try testing.expect(nested.inner_outcome.?.permits());
    try testing.expect(!outer.permits());

    const inner_answer = try theAnswer(gpa, io, store, nested.inner_id.?);
    defer freeAnswer(gpa, inner_answer);
    try testing.expectEqualStrings("approved_by_user", inner_answer.decision_name);

    const outer_answer = try theAnswer(gpa, io, store, nested.outer_id.?);
    defer freeAnswer(gpa, outer_answer);
    try testing.expectEqualStrings("refused_by_user", outer_answer.decision_name);

    // The inner yes came first, so this catches a broker that takes the first
    // answer it finds.
    try testing.expect(inner_answer.id < outer_answer.id);
}

test "the spawn chain reaches the request, with a reason at every level" {
    const gpa = testing.allocator;
    const io = testing.io;

    const chain = [_]event.SpawnLink{
        .{ .agent_kind = "main", .reason = "the user asked for the bug to be fixed" },
        .{ .agent_kind = "reviewer", .reason = "read the change before it is published" },
    };

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);

        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        const Answerer = struct {
            gpa: std.mem.Allocator,
            store: chock_proto.storage.Storage,
            locked: *LockedHandle,

            fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
                const self: *@This() = @ptrCast(@alignCast(ctx.?));
                if (waits != 1) return;
                const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
                _ = try answerAsUser(self.gpa, io_inner, self.locked, id, .approved_by_user, "ross");
            }
        };
        var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };

        const broker = try testBroker(gpa, ask_every_action, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        ask.agent_kind = "fixer";
        ask.spawn_chain = &chain;

        const outcome = try broker.request(gpa, io, store, &locked, ask, null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.approved_by_user, outcome);

        const request_id = (try findRequestId(gpa, io, store, "git.push")).?;
        var replay = try store.replay(gpa, io, request_id);
        defer replay.deinit();
        const question = (try replay.next(io)).?;
        defer question.deinit();
        const logged = question.value.event.approval_request;

        try testing.expectEqual(@as(usize, 2), logged.spawn_chain.len);
        try testing.expectEqualStrings("main", logged.spawn_chain[0].agent_kind);
        try testing.expectEqualStrings(
            "the user asked for the bug to be fixed",
            logged.spawn_chain[0].reason,
        );
        try testing.expectEqualStrings("reviewer", logged.spawn_chain[1].agent_kind);
        try testing.expectEqualStrings(
            "read the change before it is published",
            logged.spawn_chain[1].reason,
        );
        try testing.expectEqualStrings("fixer", logged.agent_kind);
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);

        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        const the_root_denies: [:0]const u8 =
            \\.{
            \\    .policy = .{
            \\        .rules = .{
            \\            .{ .agent_kind = "main", .action = "git.push", .decision = .deny },
            \\            .{ .agent_kind = "reviewer", .action = "git.push", .decision = .allow },
            \\            .{ .agent_kind = "fixer", .action = "git.push", .decision = .allow },
            \\        },
            \\    },
            \\}
        ;
        const broker = try testBroker(gpa, the_root_denies, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        ask.agent_kind = "fixer";
        ask.spawn_chain = &chain;

        try testing.expectEqual(
            Outcome.denied_by_policy,
            try broker.request(gpa, io, store, &locked, ask, null),
        );

        var alone = testRequest("git.push");
        alone.agent_kind = "fixer";
        try testing.expectEqual(
            Outcome.allowed_by_policy,
            try broker.request(gpa, io, store, &locked, alone, null),
        );
    }
}

test "a decision this broker does not know is not permission" {
    // `event.ApprovalDecision` keeps a name it does not know, so an old reader
    // can read a new log. That rule is about reading and is not a licence to act.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
            _ = try answerAsUser(
                self.gpa,
                io_inner,
                self.locked,
                id,
                .{ .unknown = "approved_with_edits" },
                "ross",
            );
        }
    };
    var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked };
    var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };

    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    if (waiter.failed) |err| return err;

    try testing.expectEqual(Outcome.unknown_decision, outcome);
    try testing.expect(!outcome.permits());

    const request_id = (try findRequestId(gpa, io, store, "git.push")).?;
    const answer = try theAnswer(gpa, io, store, request_id);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("approved_with_edits", answer.decision_name);
}

test "a wait that reports a cancellation stops the request and leaves the question open" {
    // A wait that swallows a cancellation makes a busy loop that runs until the
    // deadline, which can be an hour, while `Loop.run` holds the session lock.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{ .cancel_at_wait = 1 };
    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    try testing.expectError(
        error.Canceled,
        broker.request(gpa, io, store, &locked, testRequest("git.push"), null),
    );

    try testing.expectEqual(@as(usize, 1), waiter.waits);

    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_request));
    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_response));
}

test "a timeout longer than the broker's bound expires at the bound" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const started_at_ms = waiter.now_ms;

    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.timeout_ms = max_timeout_ms * 3;

    try testing.expectEqual(
        Outcome.expired,
        try broker.request(gpa, io, store, &locked, ask, null),
    );

    const request_id = (try findRequestId(gpa, io, store, "git.push")).?;
    var replay = try store.replay(gpa, io, request_id);
    defer replay.deinit();
    const question = (try replay.next(io)).?;
    defer question.deinit();
    try testing.expectEqual(
        started_at_ms + max_timeout_ms,
        question.value.event.approval_request.timeout_at_ms,
    );

    try testing.expectEqual(
        @as(usize, @intCast(max_timeout_ms)) / poll_interval_ms,
        waiter.waits,
    );
}

test "a timeout of zero expires on the first look and never waits at all" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.timeout_ms = 0;

    try testing.expectEqual(
        Outcome.expired,
        try broker.request(gpa, io, store, &locked, ask, null),
    );
    try testing.expectEqual(@as(usize, 0), waiter.waits);
    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_request));

    const request_id = (try findRequestId(gpa, io, store, "git.push")).?;
    const answer = try theAnswer(gpa, io, store, request_id);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("expired", answer.decision_name);
}

test "an answer that names this request and a different action is not permission" {
    // When the two statements in one answer disagree, neither can be trusted.
    const gpa = testing.allocator;
    const io = testing.io;

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,
        says_action: []const u8,
        says_call: []const u8,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
            _ = try answerAbout(
                self.gpa,
                io_inner,
                self.locked,
                id,
                .approved_by_user,
                self.says_action,
                self.says_call,
            );
        }
    };

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var answerer = Answerer{
            .gpa = gpa,
            .store = store,
            .locked = &locked,
            .says_action = "git.commit",
            .says_call = "call1",
        };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        const broker = try testBroker(gpa, ask_every_action, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.mismatched_answer, outcome);
        try testing.expect(!outcome.permits());
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var answerer = Answerer{
            .gpa = gpa,
            .store = store,
            .locked = &locked,
            .says_action = "git.push",
            .says_call = "call9",
        };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        const broker = try testBroker(gpa, ask_every_action, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.mismatched_answer, outcome);
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var answerer = Answerer{
            .gpa = gpa,
            .store = store,
            .locked = &locked,
            .says_action = "git.push",
            .says_call = "call1",
        };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        const broker = try testBroker(gpa, ask_every_action, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.approved_by_user, outcome);
        try testing.expect(outcome.permits());
    }
}

test "an answer written before its own request does not answer it" {
    // Two passes: the first finds the offset, the second poisons it.
    const gpa = testing.allocator;
    const io = testing.io;

    const measured: u64 = measure: {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        try stalePoison(gpa, io, &locked, 0);

        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, ask_every_action, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        ask.timeout_ms = 100;
        _ = try broker.request(gpa, io, store, &locked, ask, null);
        break :measure (try findRequestId(gpa, io, store, "git.push")).?;
    };

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    try stalePoison(gpa, io, &locked, measured);

    var waiter = TestWaiter{};
    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.timeout_ms = 100;
    const outcome = try broker.request(gpa, io, store, &locked, ask, null);

    const request_id = (try findRequestId(gpa, io, store, "git.push")).?;
    try testing.expectEqual(measured, request_id);

    try testing.expectEqual(Outcome.expired, outcome);
    try testing.expect(!outcome.permits());
}

test "a caller holding only a broker can redact and can resolve, and never holds a credential" {
    // Nothing below names `secrets.Store`, because a caller that had to name one
    // would be a caller holding credentials.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const broker = Broker{
        .policy = try table.Table.parse(gpa, ask_every_action, null),
        .waiter = waiter.waiter(),
        .secrets = .{ .entries = &.{.{ .name = "aiand", .value = "sk-live-9f2c4a7b1d3e" }} },
    };
    defer table.Table.destroy(gpa, broker.policy);

    const child_env = try broker.resolveEnv(gpa, &.{"AIAND_TOKEN={{secret:aiand}}"}, null);
    defer secrets_mod.freeEnv(gpa, child_env);
    try testing.expectEqualStrings("AIAND_TOKEN=sk-live-9f2c4a7b1d3e", child_env[0]);

    _ = try broker.appendToolResult(gpa, io, &locked, .{
        .call_id = "call1",
        .output = "AIAND_TOKEN=sk-live-9f2c4a7b1d3e\n",
        .is_error = false,
        .truncated = false,
    }, waiter.now_ms);

    var pieces = try broker.redactor(gpa);
    defer pieces.deinit(gpa);
    try pieces.push(gpa, "half is sk-live-9f2c");
    try pieces.push(gpa, "4a7b1d3e and that was all");
    const streamed = try pieces.finish(gpa);
    defer gpa.free(streamed);
    try testing.expectEqualStrings("half is [redacted] and that was all", streamed);

    _ = try broker.appendToolResult(gpa, io, &locked, .{
        .call_id = "call2",
        .output = streamed,
        .is_error = false,
        .truncated = false,
    }, waiter.now_ms);

    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, "sk-live-9f2c4a7b1d3e") == null);
    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, "[redacted]") != null);
}

const the_parent_denies_and_the_child_would_review: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .agent_kind = "main", .action = "git.push", .decision = .deny },
    \\            .{ .agent_kind = "coder", .action = "git.push", .decision = .agent_review },
    \\        },
    \\    },
    \\}
;

const review_the_push: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "git.push", .decision = .agent_review },
    \\        },
    \\    },
    \\}
;

const review_then_ask_about_the_push: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "git.push", .decision = .agent_then_human },
    \\        },
    \\    },
    \\}
;

test "a reviewer cannot approve what its requester was denied" {
    // `evaluateChain` alone does not give this. It bounds what a reviewer may do
    // with its own tool calls, and a verdict is not a tool call.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    var arbiter = TestReviewer{ .says = .approved };
    const broker = Broker{
        .policy = try table.Table.parse(gpa, the_parent_denies_and_the_child_would_review, null),
        .waiter = waiter.waiter(),
        .reviewer = arbiter.reviewer(),
    };
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.spawn_chain = &.{.{ .agent_kind = "main", .reason = "the user asked for the fix" }};

    const outcome = try broker.request(gpa, io, store, &locked, ask, null);

    // A broker that paid for a review and threw the answer away gives the same
    // outcome, so the call count is what separates the two.
    try testing.expectEqual(Outcome.denied_by_policy, outcome);
    try testing.expect(!outcome.permits());
    try testing.expectEqual(@as(usize, 0), arbiter.calls);

    try testing.expectEqual(
        chock_policy.table.Decision.agent_review,
        broker.policy.evaluateKindAlone(.{
            .agent_kind = "coder",
            .model = "main",
            .tool = "git",
            .action = "git.push",
        }),
    );

    const alone = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    try testing.expectEqual(Outcome.approved_by_review, alone);
    try testing.expectEqual(@as(usize, 1), arbiter.calls);
}

test "a reviewer cannot review its own request, and pays nothing to find out" {
    const gpa = testing.allocator;
    const io = testing.io;

    const cases = [_]struct { asker: []const u8, parent: []const u8 }{
        .{ .asker = "arbiter", .parent = "main" },
        .{ .asker = "worker", .parent = "arbiter" },
    };

    for (cases) |one| {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        var arbiter = TestReviewer{ .kind = "arbiter", .says = .approved };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        ask.agent_kind = one.asker;
        ask.spawn_chain = &.{.{ .agent_kind = one.parent, .reason = "started it" }};

        const outcome = try broker.request(gpa, io, store, &locked, ask, null);
        try testing.expectEqual(Outcome.review_unavailable, outcome);
        try testing.expect(!outcome.permits());
        try testing.expectEqual(@as(usize, 0), arbiter.calls);

        const answer = try theOnlyAnswer(gpa, io, store);
        defer freeAnswer(gpa, answer);
        try testing.expectEqualStrings("review_unavailable", answer.decision_name);
        try testing.expectEqualStrings("none", answer.review_name);
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        var arbiter = TestReviewer{ .kind = "arbiter", .says = .approved };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        ask.spawn_chain = &.{.{ .agent_kind = "main", .reason = "started it" }};
        try testing.expectEqual(
            Outcome.approved_by_review,
            try broker.request(gpa, io, store, &locked, ask, null),
        );
        try testing.expectEqual(@as(usize, 1), arbiter.calls);
    }
}

test "a review that could not run refuses, and never allows" {
    const gpa = testing.allocator;
    const io = testing.io;

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, review_the_push, &waiter);
        defer table.Table.destroy(gpa, broker.policy);
        try testing.expect(broker.reviewer == null);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        try testing.expectEqual(Outcome.review_unavailable, outcome);
        try testing.expect(!outcome.permits());
        try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
        try testing.expectEqual(@as(usize, 0), waiter.waits);
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        var arbiter = TestReviewer{ .says = null };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        try testing.expectEqual(Outcome.review_unavailable, outcome);
        try testing.expect(!outcome.permits());
        try testing.expectEqual(@as(usize, 1), arbiter.calls);
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        var arbiter = TestReviewer{ .says = .none };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        try testing.expectEqual(Outcome.refused_by_review, outcome);
        try testing.expect(!outcome.permits());
    }
}

test "a reviewer that says yes permits, and the record says who and why" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    var arbiter = TestReviewer{
        .kind = "arbiter",
        .says = .approved,
        .note = "the push carries only the parser fix the task named",
    };
    const broker = Broker{
        .policy = try table.Table.parse(gpa, review_the_push, null),
        .waiter = waiter.waiter(),
        .reviewer = arbiter.reviewer(),
    };
    defer table.Table.destroy(gpa, broker.policy);

    const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    try testing.expectEqual(Outcome.approved_by_review, outcome);
    try testing.expect(outcome.permits());

    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
    try testing.expectEqual(@as(usize, 0), waiter.waits);

    const answer = try theOnlyAnswer(gpa, io, store);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("approved_by_review", answer.decision_name);
    try testing.expectEqualStrings("arbiter", answer.responder);
    try testing.expectEqualStrings("approved", answer.review_name);
    try testing.expectEqualStrings("the push carries only the parser fix the task named", answer.review_note);
    try testing.expectEqualStrings("git.push", answer.action);

    try testing.expectEqualStrings("git.push", arbiter.saw_action);
    try testing.expectEqualStrings("a1b2c3 fix the parser\n", arbiter.saw_detail);
    try testing.expectEqual(chock_policy.table.Decision.agent_review, arbiter.saw_decision.?);
    try testing.expectEqual(@as(usize, 1), arbiter.saw_chain_len);
    try testing.expectEqualStrings("coder", arbiter.saw_first_kind);
}

test "a reviewer that says no is its own refusal, and the reason stays in the log" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    var arbiter = TestReviewer{
        .says = .rejected,
        .note = "the diff rewrites chock.zon, which is the file the policy is in",
    };
    const broker = Broker{
        .policy = try table.Table.parse(gpa, review_the_push, null),
        .waiter = waiter.waiter(),
        .reviewer = arbiter.reviewer(),
    };
    defer table.Table.destroy(gpa, broker.policy);

    const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    try testing.expectEqual(Outcome.refused_by_review, outcome);
    try testing.expect(!outcome.permits());
    try testing.expect(outcome != .review_unavailable);

    const answer = try theOnlyAnswer(gpa, io, store);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("refused_by_review", answer.decision_name);
    try testing.expectEqualStrings("rejected", answer.review_name);
    try testing.expect(std.mem.indexOf(u8, answer.review_note, "chock.zon") != null);

    // The reviewer's own words stay in the log. The agent that asked reads
    // `review.requesterText` instead.
    const said = review_mod.requesterText(outcome.reviewOutcome().?);
    try testing.expect(std.mem.indexOf(u8, said, "chock.zon") == null);
    try testing.expect(std.mem.indexOf(u8, said, answer.review_note) == null);
}

test "agent_then_human puts the review in front of the person and still needs a yes" {
    const gpa = testing.allocator;
    const io = testing.io;

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,
        decision: event.ApprovalDecision,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
            _ = try answerAsUser(self.gpa, io_inner, self.locked, id, self.decision, "ross");
        }
    };

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var answerer = Answerer{
            .gpa = gpa,
            .store = store,
            .locked = &locked,
            .decision = .approved_by_user,
        };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        var arbiter = TestReviewer{
            .says = .approved,
            .note = "the diff is the parser fix and nothing else",
        };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_then_ask_about_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.approved_by_user, outcome);
        try testing.expect(outcome.permits());
        try testing.expectEqual(@as(usize, 1), arbiter.calls);

        const question = try theQuestion(gpa, io, store, "git.push");
        defer question.free(gpa);
        try testing.expectEqualStrings("approved", question.review_name);
        try testing.expectEqualStrings(
            "the diff is the parser fix and nothing else",
            question.review_note,
        );
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var answerer = Answerer{
            .gpa = gpa,
            .store = store,
            .locked = &locked,
            .decision = .refused_by_user,
        };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        var arbiter = TestReviewer{ .says = .approved };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_then_ask_about_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.refused_by_user, outcome);
        try testing.expect(!outcome.permits());
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        var arbiter = TestReviewer{ .says = .rejected };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_then_ask_about_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        try testing.expectEqual(Outcome.refused_by_review, outcome);
        try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
        try testing.expectEqual(@as(usize, 0), waiter.waits);
    }
}

test "agent_then_human pays for no review when nobody can answer the second half" {
    // `Loop.run` holds the exclusive lock on the session log for the whole
    // session, so nothing can append an `approval.response` while a turn runs.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    var arbiter = TestReviewer{ .says = .approved };
    const broker = Broker{
        .policy = try table.Table.parse(gpa, review_then_ask_about_the_push, null),
        .waiter = waiter.waiter(),
        .reviewer = arbiter.reviewer(),
    };
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.timeout_ms = 0;

    const outcome = try broker.request(gpa, io, store, &locked, ask, null);
    try testing.expectEqual(Outcome.expired, outcome);
    try testing.expect(!outcome.permits());
    try testing.expectEqual(@as(usize, 0), arbiter.calls);
    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));

    {
        var review_backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const review_store = review_backing.storage();
        defer review_store.close(io);
        var review_locked = try review_store.lock(io);
        defer review_locked.unlock(io) catch {};

        var review_waiter = TestWaiter{};
        var review_arbiter = TestReviewer{ .says = .approved };
        const review_broker = Broker{
            .policy = try table.Table.parse(gpa, review_the_push, null),
            .waiter = review_waiter.waiter(),
            .reviewer = review_arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, review_broker.policy);

        var no_wait = testRequest("git.push");
        no_wait.timeout_ms = 0;
        try testing.expectEqual(
            Outcome.approved_by_review,
            try review_broker.request(gpa, io, review_store, &review_locked, no_wait, null),
        );
        try testing.expectEqual(@as(usize, 1), review_arbiter.calls);
    }
}

test "a remembered grant answers with no question and still writes a compact record" {
    // An act a grant serves must still leave a line in the log, or the log is
    // not the evidence for any act after the first.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01GRANTSERVED0000000000000");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const ask_the_push: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.push", .decision = .ask },
        \\        },
        \\    },
        \\}
    ;

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = try findRequestId(self.gpa, io_inner, self.store, "git.push") orelse return;
            _ = try answerAbout(self.gpa, io_inner, self.locked, id, .approved_by_user_for_session, "git.push", "call1");
        }
    };
    var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked };
    var first_waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
    var first_broker = try testBroker(gpa, ask_the_push, &first_waiter);
    defer table.Table.destroy(gpa, first_broker.policy);

    const first_outcome = try first_broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    if (first_waiter.failed) |err| return err;
    try testing.expectEqual(Outcome.approved_by_user, first_outcome);
    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_request));

    var folded = chock_proto.state.Session.init(gpa);
    defer folded.deinit();
    {
        var replay = try store.replay(gpa, io, 0);
        defer replay.deinit();
        while (try replay.next(io)) |parsed| {
            defer parsed.deinit();
            try folded.apply(parsed.value);
        }
    }
    try testing.expect(folded.grants.granted.contains("git.push"));

    var second_waiter = TestWaiter{};
    var second_broker = try testBroker(gpa, ask_the_push, &second_waiter);
    defer table.Table.destroy(gpa, second_broker.policy);
    second_broker.grants = .{ .memory = &folded.grants, .allocator = folded.arena.allocator() };

    const second_outcome = try second_broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    try testing.expectEqual(Outcome.approved_by_user, second_outcome);
    try testing.expect(second_outcome.permits());

    try testing.expectEqual(@as(usize, 0), second_waiter.waits);
    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_request));

    try testing.expectEqual(@as(usize, 2), try countKind(gpa, io, store, .approval_response));
    const answer = try theAnswer(gpa, io, store, 0);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("approved_by_user_for_session", answer.decision_name);
    try testing.expectEqualStrings("git.push", answer.action);
    try testing.expectEqualStrings("call1", answer.tool_call_id);
    try testing.expectEqualStrings("", answer.responder);

    // `SessionGrants.apply` refuses a zero `request_id`, so a fresh fold of the
    // whole log still holds exactly one grant.
    var refolded = chock_proto.state.Session.init(gpa);
    defer refolded.deinit();
    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try refolded.apply(parsed.value);
    }
    try testing.expect(refolded.grants.granted.contains("git.push"));
    try testing.expectEqual(@as(u32, 1), refolded.grants.granted.count());
}

test "a live grant past the map's first capacity grows through the same allocator that built it, with no invalid free" {
    // `std.StringHashMapUnmanaged` has a minimal capacity of 8 slots at an 80
    // percent load factor, so the sixth put fits and the seventh grows the map.
    // A test with fewer grants reaches no grow. A wrong allocator pairing does
    // not reliably crash, because that depends on arena chunk boundaries, so the
    // assertions below pin the correct answer instead.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01GRANTGROW00000000000000000");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const ask_every_grant: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "grant.*", .decision = .ask },
        \\        },
        \\    },
        \\}
    ;

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,
        action: []const u8,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = try findRequestId(self.gpa, io_inner, self.store, self.action) orelse return;
            _ = try answerAbout(self.gpa, io_inner, self.locked, id, .approved_by_user_for_session, self.action, "call1");
        }
    };

    var action_buf: [6][]const u8 = undefined;
    for (0..6) |i| {
        action_buf[i] = try std.fmt.allocPrint(gpa, "grant.{d}", .{i});
    }
    defer for (action_buf) |a| gpa.free(a);

    for (action_buf) |action| {
        var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked, .action = action };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        var broker = try testBroker(gpa, ask_every_grant, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest(action), null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.approved_by_user, outcome);
    }

    var folded = chock_proto.state.Session.init(gpa);
    defer folded.deinit();
    {
        var replay = try store.replay(gpa, io, 0);
        defer replay.deinit();
        while (try replay.next(io)) |parsed| {
            defer parsed.deinit();
            try folded.apply(parsed.value);
        }
    }
    try testing.expectEqual(@as(u32, 6), folded.grants.granted.count());
    try testing.expectEqual(@as(u32, 8), folded.grants.granted.capacity());

    // A live grant, recorded through `Broker.Grants.allocator` and not a fold.
    const seventh = "grant.6";
    var seventh_answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked, .action = seventh };
    var seventh_waiter = TestWaiter{ .ctx = &seventh_answerer, .on_wait = Answerer.onWait };
    var live_broker = try testBroker(gpa, ask_every_grant, &seventh_waiter);
    defer table.Table.destroy(gpa, live_broker.policy);
    live_broker.grants = .{ .memory = &folded.grants, .allocator = folded.arena.allocator() };

    const outcome = try live_broker.request(gpa, io, store, &locked, testRequest(seventh), null);
    if (seventh_waiter.failed) |err| return err;
    try testing.expectEqual(Outcome.approved_by_user, outcome);

    try testing.expectEqual(@as(u32, 7), folded.grants.granted.count());
    try testing.expect(folded.grants.granted.capacity() > 8);
    for (action_buf) |action| try testing.expect(folded.grants.granted.contains(action));
    try testing.expect(folded.grants.granted.contains(seventh));
}

test "a promise the session made narrows the answer, and never widens it" {
    const gpa = testing.allocator;
    const io = testing.io;

    const allow_the_push: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, allow_the_push, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        try testing.expectEqual(Outcome.allowed_by_policy, outcome);
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, allow_the_push, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        const promised = [_]chock_policy.ratchet.Restriction{
            .{ .action = "git.*", .ceiling = .deny, .reason = "this task changes nothing remote" },
        };
        ask.self_policy = &promised;

        const outcome = try broker.request(gpa, io, store, &locked, ask, null);
        try testing.expectEqual(Outcome.denied_by_policy, outcome);
        try testing.expect(!outcome.permits());
        try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
        try testing.expectEqual(@as(usize, 0), waiter.waits);
    }

    // A promise is a ceiling and never a floor, so it cannot lift a `deny`.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        const deny_the_push: [:0]const u8 =
            \\.{
            \\    .policy = .{
            \\        .rules = .{
            \\            .{ .action = "git.push", .decision = .deny },
            \\        },
            \\    },
            \\}
        ;
        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, deny_the_push, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        const promised = [_]chock_policy.ratchet.Restriction{
            .{ .action = "git.push", .ceiling = .allow, .reason = "I would like to push" },
        };
        ask.self_policy = &promised;

        const outcome = try broker.request(gpa, io, store, &locked, ask, null);
        try testing.expectEqual(Outcome.denied_by_policy, outcome);
        try testing.expect(!outcome.permits());
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, allow_the_push, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        const promised = [_]chock_policy.ratchet.Restriction{
            .{ .action = "net.fetch", .ceiling = .deny, .reason = "this task needs no network" },
        };
        ask.self_policy = &promised;

        try testing.expectEqual(
            Outcome.allowed_by_policy,
            try broker.request(gpa, io, store, &locked, ask, null),
        );
    }
}

test "a promise can turn an allow into a review, so the acceptance modes carry it too" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const allow_the_push: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    var waiter = TestWaiter{};
    var arbiter = TestReviewer{ .says = .approved, .note = "the push is what the task asked for" };
    const broker = Broker{
        .policy = try table.Table.parse(gpa, allow_the_push, null),
        .waiter = waiter.waiter(),
        .reviewer = arbiter.reviewer(),
    };
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    const promised = [_]chock_policy.ratchet.Restriction{
        .{ .action = "git.push", .ceiling = .agent_review, .reason = "somebody should read this first" },
    };
    ask.self_policy = &promised;

    const outcome = try broker.request(gpa, io, store, &locked, ask, null);
    try testing.expectEqual(Outcome.approved_by_review, outcome);
    try testing.expectEqual(@as(usize, 1), arbiter.calls);
    try testing.expectEqual(chock_policy.table.Decision.agent_review, arbiter.saw_decision.?);

    {
        var second_backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const second = second_backing.storage();
        defer second.close(io);
        var second_locked = try second.lock(io);
        defer second_locked.unlock(io) catch {};

        var plain_waiter = TestWaiter{};
        const no_reviewer = try testBroker(gpa, allow_the_push, &plain_waiter);
        defer table.Table.destroy(gpa, no_reviewer.policy);

        const refused = try no_reviewer.request(gpa, io, second, &second_locked, ask, null);
        try testing.expectEqual(Outcome.review_unavailable, refused);
        try testing.expect(!refused.permits());
    }
}

test "a request to widen a promise is judged like any other act, by the acceptance modes" {
    const gpa = testing.allocator;
    const io = testing.io;

    const widen_needs_both: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "policy.widen", .decision = .agent_then_human },
        \\        },
        \\    },
        \\}
    ;

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        const Answerer = struct {
            gpa: std.mem.Allocator,
            store: chock_proto.storage.Storage,
            locked: *LockedHandle,

            fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
                const self: *@This() = @ptrCast(@alignCast(ctx.?));
                if (waits != 1) return;
                const id = (try findRequestId(
                    self.gpa,
                    io_inner,
                    self.store,
                    chock_policy.ratchet.widen_action,
                )).?;
                _ = try answerAsUser(self.gpa, io_inner, self.locked, id, .approved_by_user, "ross");
            }
        };

        var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        var arbiter = TestReviewer{
            .says = .approved,
            .note = "the task really does need the network the agent gave up",
        };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, widen_needs_both, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest(chock_policy.ratchet.widen_action);
        ask.summary = "raise the promise about net.fetch from deny to ask";
        ask.tool = "restrict_self";
        const promised = [_]chock_policy.ratchet.Restriction{
            .{ .action = "net.fetch", .ceiling = .deny, .reason = "the plan said no network" },
        };
        ask.self_policy = &promised;

        const outcome = try broker.request(gpa, io, store, &locked, ask, null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.approved_by_user, outcome);
        try testing.expectEqual(@as(usize, 1), arbiter.calls);

        const question = try theQuestion(gpa, io, store, chock_policy.ratchet.widen_action);
        defer question.free(gpa);
        try testing.expectEqualStrings("approved", question.review_name);
        try testing.expect(std.mem.indexOf(u8, question.review_note, "really does need") != null);
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, ".{}", &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest(chock_policy.ratchet.widen_action);
        ask.timeout_ms = 0;

        const outcome = try broker.request(gpa, io, store, &locked, ask, null);
        try testing.expectEqual(Outcome.expired, outcome);
        try testing.expect(!outcome.permits());
    }
}

test "a decision only the broker's own review writes is not an answer a client can give" {
    // A request a reviewer settled has no open question, so one of these found
    // as the answer to a person's question is something else claiming a review.
    const gpa = testing.allocator;
    const io = testing.io;

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,
        decision: event.ApprovalDecision,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
            _ = try answerAsUser(self.gpa, io_inner, self.locked, id, self.decision, "ross");
        }
    };

    for ([_]event.ApprovalDecision{ .approved_by_review, .refused_by_review, .review_unavailable }) |claimed| {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked, .decision = claimed };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        const broker = try testBroker(gpa, ask_every_action, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.mismatched_answer, outcome);
        try testing.expect(!outcome.permits());
    }
}

/// Long enough to pass the length floor `src/run.zig` applies.
const fake_key = "sk-broker-test-000000000000";

test "a value this broker keeps out is in none of the log's own bytes" {
    // The log is append only and hash chained, so a value written here stays
    // here. There is no cleanup, only prevention.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
            _ = try answerAsUser(self.gpa, io_inner, self.locked, id, .approved_by_user, "ross");
        }
    };

    var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked };
    var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };

    const broker = Broker{
        .policy = try table.Table.parse(gpa, ask_every_action, null),
        .waiter = waiter.waiter(),
        .redaction = &.{fake_key},
    };
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.summary = "push the client that reads " ++ fake_key;
    ask.detail = "a1b2c3 add the client\n+const token = \"" ++ fake_key ++ "\";\n";
    ask.reason = "the task named " ++ fake_key;
    ask.spawn_chain = &.{.{ .agent_kind = "main", .reason = "the user pasted " ++ fake_key }};

    const outcome = try broker.request(gpa, io, store, &locked, ask, null);
    if (waiter.failed) |err| return err;
    try testing.expectEqual(Outcome.approved_by_user, outcome);

    // The log's own bytes, and not a parsed field.
    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, fake_key) == null);

    try testing.expectEqual(
        @as(usize, 4),
        std.mem.count(u8, backing.bytes.items, secrets_mod.redacted_marker),
    );

    const question_id = (try findRequestId(gpa, io, store, "git.push")).?;
    var replay = try store.replay(gpa, io, question_id);
    defer replay.deinit();
    const parsed = (try replay.next(io)).?;
    defer parsed.deinit();
    const question = parsed.value.event.approval_request;
    try testing.expect(std.mem.indexOf(u8, question.detail, "a1b2c3 add the client") != null);
    try testing.expect(std.mem.indexOf(u8, question.detail, "+const token = ") != null);
    try testing.expectEqualStrings("git.push", question.action);
    try testing.expectEqualStrings("main", question.spawn_chain[0].agent_kind);

    const report = try chock_proto.storage.verify(store, gpa, io);
    try testing.expectEqual(chock_proto.chain.Verdict.intact, report.verdict);
    try testing.expect(report.events > 0);
    try testing.expectEqual(report.events, report.chained);

    // This block must stay last, because it spoils the log.
    const marker_at = std.mem.indexOf(u8, backing.bytes.items, secrets_mod.redacted_marker).?;
    backing.bytes.items[marker_at + 1] = 'X';
    const forged = try chock_proto.storage.verify(store, gpa, io);
    try testing.expectEqual(chock_proto.chain.Verdict.broken, forged.verdict);
}

test "a reviewer reads a clean case, and the note it writes is scanned again" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
            _ = try answerAsUser(self.gpa, io_inner, self.locked, id, .approved_by_user, "ross");
        }
    };

    var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked };
    var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
    var arbiter = TestReviewer{
        .kind = "arbiter",
        .says = .approved,
        .note = "the commit adds " ++ fake_key ++ " and the task asked for it",
        .never = fake_key,
    };

    const broker = Broker{
        .policy = try table.Table.parse(gpa, review_then_ask_about_the_push, null),
        .waiter = waiter.waiter(),
        .reviewer = arbiter.reviewer(),
        .redaction = &.{fake_key},
    };
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.detail = "a1b2c3 add the client\n+const token = \"" ++ fake_key ++ "\";\n";

    const outcome = try broker.request(gpa, io, store, &locked, ask, null);
    if (waiter.failed) |err| return err;
    try testing.expectEqual(Outcome.approved_by_user, outcome);

    try testing.expectEqual(@as(usize, 1), arbiter.calls);
    try testing.expect(!arbiter.saw_never);

    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, fake_key) == null);

    const question = try theQuestion(gpa, io, store, "git.push");
    defer question.free(gpa);
    try testing.expect(std.mem.indexOf(u8, question.review_note, secrets_mod.redacted_marker) != null);
    try testing.expect(std.mem.indexOf(u8, question.review_note, "the task asked for it") != null);

    // `agent_review` is where the broker writes the note into the answer itself.
    var review_backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const review_store = review_backing.storage();
    defer review_store.close(io);
    var review_locked = try review_store.lock(io);
    defer review_locked.unlock(io) catch {};

    var quiet = TestWaiter{};
    const review_only = Broker{
        .policy = try table.Table.parse(gpa, review_the_push, null),
        .waiter = quiet.waiter(),
        .reviewer = arbiter.reviewer(),
        .redaction = &.{fake_key},
    };
    defer table.Table.destroy(gpa, review_only.policy);

    try testing.expectEqual(
        Outcome.approved_by_review,
        try review_only.request(gpa, io, review_store, &review_locked, ask, null),
    );
    try testing.expect(std.mem.indexOf(u8, review_backing.bytes.items, fake_key) == null);

    const answer = try theOnlyAnswer(gpa, io, review_store);
    defer freeAnswer(gpa, answer);
    try testing.expect(std.mem.indexOf(u8, answer.review_note, secrets_mod.redacted_marker) != null);
    try testing.expect(std.mem.indexOf(u8, answer.review_note, "the task asked for it") != null);
}

test "a broker with nothing to keep out copies nothing" {
    // Pointers, because a clean string comes back equal either way.
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var waiter = TestWaiter{};
    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.spawn_chain = &.{.{ .agent_kind = "main", .reason = "the user asked for the fix" }};

    const same = try broker.scrubbed(arena_state.allocator(), ask);
    try testing.expectEqual(ask.summary.ptr, same.summary.ptr);
    try testing.expectEqual(ask.detail.ptr, same.detail.ptr);
    try testing.expectEqual(ask.reason.ptr, same.reason.ptr);
    try testing.expectEqual(ask.spawn_chain.ptr, same.spawn_chain.ptr);
}

test "a value with no name is kept out of a tool result, whole or in pieces" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const broker = Broker{
        .policy = try table.Table.parse(gpa, ask_every_action, null),
        .waiter = waiter.waiter(),
        .redaction = &.{fake_key},
    };
    defer table.Table.destroy(gpa, broker.policy);

    _ = try broker.appendToolResult(gpa, io, &locked, .{
        .call_id = "call1",
        .output = "TOKEN=" ++ fake_key ++ "\nHOME=/home/ross\n",
        .is_error = false,
        .truncated = false,
    }, waiter.now_ms);

    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, fake_key) == null);
    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, "HOME=/home/ross") != null);

    // A cut through the middle of the value, so neither piece holds it.
    var pieces = try broker.redactor(gpa);
    defer pieces.deinit(gpa);
    try pieces.push(gpa, "half is " ++ fake_key[0..9]);
    try pieces.push(gpa, fake_key[9..] ++ " and that was all");
    const streamed = try pieces.finish(gpa);
    defer gpa.free(streamed);
    try testing.expect(std.mem.indexOf(u8, streamed, fake_key) == null);
    try testing.expect(std.mem.indexOf(u8, streamed, secrets_mod.redacted_marker) != null);
}
