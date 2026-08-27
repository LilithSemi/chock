//! Compaction: folding the middle of a session's context into one summary so
//! the session can keep going.
//!
//! **The log is the truth and the context is a view of it.** A compaction
//! summarises the view and deletes nothing from the log. It is one more event
//! appended, `compaction`, and `chock_proto.state.Session.applyCompaction`
//! already knows how to fold it. So a replay of the same log builds the same
//! shorter context, and a user can still read every turn the model can no
//! longer see. Nothing in this file writes to storage or removes anything.
//!
//! This file does no I/O at all. `lib/chock-core/Loop.zig` is what sends the
//! request and appends the event.
//!
//! ## Why this exists, measured
//!
//! Two sessions on 2026-08-21. The first grew from 2323 to 19534 input tokens
//! and its turns went from about 2 seconds to about 20, monotonically, until
//! one took nineteen minutes. The second died outright on `request (77857
//! tokens) exceeds the available context size (65536 tokens)`, with a full log
//! of work that had nothing wrong with it. `compaction` was already one of the
//! eleven event kinds and the loop never wrote one.
//!
//! ## What is protected, and what is kept verbatim
//!
//! Two parts of the context never become a summary, and they are protected in
//! two different ways because they mean two different things.
//!
//! **The head is never in the folded span at all.** `Policy.protect_head_entries`
//! keeps the first entries of the context out of `[from_id, through_id]`, and
//! the first entry of a `chock run` session is the user's own message. **A
//! session that forgets what it was asked is worse than one that runs out of
//! context**, and a summary of the task is not the task. Because the head sits
//! before the span, the fold leaves it where it is, so the shorter context
//! still reads task first, summary second.
//!
//! **The tail is inside the span and named in `kept_ranges`.** That is what
//! the field is for: a range inside the folded span that was kept as it was,
//! so a reader can show the user exactly what a compaction dropped and exactly
//! what it did not. The recent turns are the obvious thing to keep, because
//! they hold the state the next turn works from: the file just read, the error
//! the last command printed.

const std = @import("std");
const chock_proto = @import("chock-proto");

const event = chock_proto.event;
const state = chock_proto.state;

pub const Error = std.mem.Allocator.Error;

/// When to compact, how much to keep, and how large the summary request may
/// be.
///
/// **The default `context_limit_tokens` is null, which means Chock does not
/// know the limit**, and an unknown limit is never a guess: with null, only
/// the overflow backstop can fire: an absent answer is never a permissive one.
pub const Policy = struct {
    /// How many tokens the model behind this session can hold, request and
    /// reply together. Null when nothing told Chock.
    context_limit_tokens: ?u64 = null,
    /// The share of `context_limit_tokens` at which a turn compacts before it
    /// sends anything.
    ///
    /// **Three quarters, because the reply needs room too.** The number the
    /// threshold is measured against is the input tokens of the last request,
    /// and the request that follows is larger than the one before it by a
    /// whole turn: an assistant message and the tool output it asked for. A
    /// threshold near the limit therefore overflows on the very turn it was
    /// meant to prevent.
    compact_at: f64 = 0.75,
    /// The share of `context_limit_tokens` at which the agent is told a
    /// compaction is coming, so it can save what it would not want to work
    /// out again. See `noticeText`.
    ///
    /// **Below `compact_at` on purpose, and the gap is the whole point.** The
    /// notice is useless if it arrives with the compaction, because the agent
    /// needs a turn to act on it. See `chock-plan-15-memory`: memory survives
    /// a compaction and context does not.
    warn_at: f64 = 0.6,
    /// How many context entries at the end are kept verbatim. See this file's
    /// own top comment: these are named in the event's `kept_ranges`.
    keep_recent_entries: usize = 6,
    /// How many bytes those entries may hold altogether, whichever bound is
    /// reached first. One entry is always kept, however large it is, so the
    /// model still sees the turn it just took.
    ///
    /// **A count alone is not a bound, and a real session proved it.** A
    /// `run_command` result is capped at 64 KiB, so six recent entries can be
    /// most of a 65536 token context on their own. Measured on 2026-08-21: a
    /// session reading large files compacted, kept six entries worth about
    /// fifty thousand tokens, and overflowed again on the very next turn. It
    /// went forward each time, and it paid a summary call every turn to do
    /// it. With a byte bound the same session keeps the last turn and drops
    /// back to a context with room in it.
    keep_recent_max_bytes: usize = 16 * 1024,
    /// How many context entries at the start are kept out of the folded span
    /// altogether. One, which is the user's own first message.
    protect_head_entries: usize = 1,
    /// The largest transcript this sends a model to summarise.
    ///
    /// **Bounded because the reason to compact is that the context is full.**
    /// A summary request that carried the whole span would meet the same
    /// refusal the turn just met, so the span is rendered and cut to this,
    /// keeping the most recent bytes.
    summary_max_bytes: usize = 16 * 1024,
    /// The largest one part of one message contributes to that transcript. A
    /// single `run_command` that printed a megabyte would otherwise fill the
    /// whole budget and hide every other turn in the span.
    part_max_bytes: usize = 2 * 1024,
};

/// The number of tokens at which `fraction` of the limit is reached, or null
/// when the limit is unknown.
pub fn thresholdTokens(policy: Policy, fraction: f64) ?u64 {
    const limit = policy.context_limit_tokens orelse return null;
    if (limit == 0) return null;
    const scaled = @as(f64, @floatFromInt(limit)) * fraction;
    if (scaled <= 0) return null;
    return @intFromFloat(scaled);
}

/// True when a request of `input_tokens` has reached the compaction
/// threshold. False whenever the limit is unknown: the backstop in
/// `Loop.runTurn` is what covers that case, and a guessed limit would compact
/// a session that had room.
pub fn shouldCompact(policy: Policy, input_tokens: u64) bool {
    const at = thresholdTokens(policy, policy.compact_at) orelse return false;
    return input_tokens >= at;
}

/// True when a request of `input_tokens` has reached the warning threshold.
pub fn shouldWarn(policy: Policy, input_tokens: u64) bool {
    const at = thresholdTokens(policy, policy.warn_at) orelse return false;
    return input_tokens >= at;
}

/// Which span of the context a compaction folds, and which part of it stays.
/// Every slice is owned by the allocator `plan` was given.
pub const Plan = struct {
    /// The first event id inside the folded span.
    from_id: u64,
    /// The last event id inside the folded span. The kept tail is inside this
    /// range: see this file's own top comment.
    through_id: u64,
    /// The ranges inside the span that stay verbatim.
    kept_ranges: []const event.EventRange,
    /// The entries the summary stands in for, in order. Borrowed from the
    /// session, so it is only valid while the session is not folded again.
    folded: []const state.ContextEntry,
};

/// Decide what to fold, or null when there is nothing worth folding.
///
/// **Null is a real answer and the caller must handle it.** A context of a
/// task, one summary and a kept tail cannot be made shorter by folding it
/// again, and a caller that treated null as "try once more" would compact in
/// a circle. `Loop.runTurn` ends the session on it, with the log intact, which
/// is the honest outcome: the tail alone is too large for this model.
pub fn plan(allocator: std.mem.Allocator, session: *const state.Session, policy: Policy) Error!?Plan {
    const entries = session.context.items;
    // Every range test below reads an id, so the ids have to ascend with the
    // list. `chock_proto.state.summaryEntry` is what keeps that true after a
    // compaction, and it did not always: see its own doc comment for the
    // session where it did not and the fold quietly stopped folding.
    if (entries.len > 1) {
        for (entries[1..], entries[0 .. entries.len - 1]) |after, before| {
            std.debug.assert(before.id <= after.id);
        }
    }

    const head = @min(policy.protect_head_entries, entries.len);
    if (entries.len <= head) return null;

    // Build the kept tail by walking back from the end, under both bounds at
    // once: a count of entries and a count of bytes. The first entry is taken
    // whatever its size, so the model always still sees the turn it just took.
    var tail_start = entries.len;
    var kept_bytes: usize = 0;
    while (tail_start > head and entries.len - tail_start < policy.keep_recent_entries) {
        const size = entryBytes(entries[tail_start - 1]);
        const first = tail_start == entries.len;
        if (!first and kept_bytes + size > policy.keep_recent_max_bytes) break;
        kept_bytes += size;
        tail_start -= 1;
    }

    // Never cut a tool answer off the assistant turn that asked for it. The
    // boundary only ever moves earlier, so the kept tail grows and the folded
    // span shrinks, which cannot make this loop forever. The bound on
    // `entries.len` is for a policy that keeps no recent entries at all, where
    // the boundary starts one past the end.
    while (tail_start > head and tail_start < entries.len and isToolAnswer(entries[tail_start])) : (tail_start -= 1) {}

    // One entry folded into one summary entry shortens nothing, and a summary
    // of a summary shortens nothing either. Two is the smallest fold that is
    // worth an event.
    if (tail_start < head + 2) return null;

    var ranges: std.ArrayList(event.EventRange) = .empty;
    errdefer ranges.deinit(allocator);
    if (tail_start < entries.len) {
        try ranges.append(allocator, .{
            .from_id = entries[tail_start].id,
            .through_id = entries[entries.len - 1].id,
        });
    }

    return .{
        .from_id = entries[head].id,
        .through_id = entries[entries.len - 1].id,
        .kept_ranges = try ranges.toOwnedSlice(allocator),
        .folded = entries[head..tail_start],
    };
}

/// Roughly what one context entry costs, in bytes of content. Not tokens:
/// nothing here can tokenize, and a byte count of the same text is
/// proportional enough to bound a tail with. See `Policy.keep_recent_max_bytes`.
fn entryBytes(entry: state.ContextEntry) usize {
    return switch (entry.data) {
        .summary => |text| text.len,
        .message => |m| bytes: {
            var total: usize = 0;
            for (m.content) |part| total += switch (part) {
                .text => |text| text.len,
                .reasoning => |reasoning| reasoning.text.len,
                .tool_use => |use| use.tool.len + use.arguments.len,
                .tool_result => |result| result.output.len,
                .unknown => 0,
            };
            break :bytes total;
        },
    };
}

fn isToolAnswer(entry: state.ContextEntry) bool {
    return switch (entry.data) {
        .message => |m| m.role == .tool,
        .summary => false,
    };
}

/// A transcript of `entries` as plain text, cut to `policy.summary_max_bytes`.
///
/// **One user message, never a replayed conversation.** Sending the folded
/// span back as real messages would need every `tool_use` part to still have
/// its answer beside it, and a span cut anywhere breaks that pairing, which
/// providers refuse outright. Text has no pairing rule.
///
/// The cut keeps the **end** of the span. The start of the session is not
/// lost by that: `Policy.protect_head_entries` keeps the user's own task out
/// of the span altogether.
pub fn transcript(allocator: std.mem.Allocator, entries: []const state.ContextEntry, policy: Policy) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    for (entries) |entry| {
        switch (entry.data) {
            .summary => |text| {
                try out.appendSlice(allocator, "[a summary of even earlier turns]\n");
                try appendCut(allocator, &out, text, policy.part_max_bytes);
            },
            .message => |m| {
                for (m.content) |part| switch (part) {
                    .text => |text| {
                        if (text.len == 0) continue;
                        try out.print(allocator, "[{s}]\n", .{roleName(m.role)});
                        try appendCut(allocator, &out, text, policy.part_max_bytes);
                    },
                    .tool_use => |use| {
                        try out.print(allocator, "[a call to {s}] ", .{use.tool});
                        try appendCut(allocator, &out, use.arguments, policy.part_max_bytes);
                    },
                    .tool_result => |result| {
                        const word = if (result.is_error) "a tool failed" else "a tool answered";
                        try out.print(allocator, "[{s}]\n", .{word});
                        try appendCut(allocator, &out, result.output, policy.part_max_bytes);
                    },
                    // Reasoning is left out on purpose: it is the model's own
                    // working, it is the largest part of a turn on a
                    // reasoning model, and what it worked out is already in
                    // the text and the tool calls beside it.
                    .reasoning, .unknown => {},
                };
            },
        }
    }

    const text = try out.toOwnedSlice(allocator);
    if (text.len <= policy.summary_max_bytes) return text;

    defer allocator.free(text);
    const tail = text[text.len - policy.summary_max_bytes ..];
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ cut_note, tail });
}

/// The line that says a transcript starts partway through, so a model does not
/// read the first sentence it sees as the start of the span.
pub const cut_note = "[chock: the earlier part of this span is not shown here.]\n";

/// The marker left where one part of one message was cut.
pub const part_cut_note = " [chock: cut]\n";

fn appendCut(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    text: []const u8,
    max_bytes: usize,
) Error!void {
    if (text.len <= max_bytes) {
        try out.appendSlice(allocator, text);
        if (text.len == 0 or text[text.len - 1] != '\n') try out.append(allocator, '\n');
        return;
    }
    try out.appendSlice(allocator, text[0..max_bytes]);
    try out.appendSlice(allocator, part_cut_note);
}

fn roleName(role: event.Role) []const u8 {
    return switch (role) {
        .user => "the user",
        .assistant => "you",
        .system => "the harness",
        .tool => "a tool",
        .unknown => |name| name,
    };
}

/// What a model is told when it is asked to write a summary.
///
/// **The dead ends are named first and named explicitly.** An agent that ruled
/// something out, was compacted, and tried it again pays the whole detour a
/// second time and reaches the same answer. That is the single most expensive
/// thing a summary can leave out, and a model asked only for "a summary"
/// writes what worked and drops what did not.
pub const summary_system =
    \\You are summarising the middle of a coding session, so the session can go
    \\on with a shorter context. What you write replaces those turns. Anything
    \\you leave out is gone.
    \\
    \\Write one summary of at most 300 words, in these three parts:
    \\
    \\1. What was done, and what now works. Name the files, the functions and
    \\   the commands exactly.
    \\2. What was tried and did not work, and why it did not. Never leave this
    \\   out. An approach that was ruled out and then tried again costs the
    \\   whole detour a second time.
    \\3. What is still open, and what the next step is.
    \\
    \\Write only the summary. Do not give advice and do not address the reader.
;

/// The one user message a summary request carries: the transcript, then the
/// instruction. Owned by the caller.
pub fn summaryPrompt(allocator: std.mem.Allocator, rendered: []const u8) Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "Here is the part of the session to summarise.\n\n{s}\n\nWrite the summary now.",
        .{rendered},
    );
}

/// The summary Chock writes when no model wrote one: the request failed, or
/// the reply held no text.
///
/// **Worse than a model's and better than nothing.** It cannot say what was
/// learned, so it says what happened: how many turns were folded, which tools
/// ran and how often, and the last thing the model itself said. A session that
/// ended because a summary call failed would lose every one of those.
///
/// The first line says who wrote it, so a reader is never left to guess
/// whether a thin summary is a model's poor work or the harness standing in.
pub fn harnessSummary(
    allocator: std.mem.Allocator,
    entries: []const state.ContextEntry,
    policy: Policy,
) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, harness_summary_first_line);

    var calls: std.ArrayList(Counted) = .empty;
    defer calls.deinit(allocator);
    var last_text: []const u8 = "";
    for (entries) |entry| {
        const m = switch (entry.data) {
            .message => |value| value,
            .summary => continue,
        };
        for (m.content) |part| switch (part) {
            .tool_use => |use| try count(allocator, &calls, use.tool),
            .text => |text| if (m.role == .assistant and text.len != 0) {
                last_text = text;
            },
            else => {},
        };
    }

    try out.print(allocator, "{d} earlier messages were folded away here.\n", .{entries.len});
    if (calls.items.len != 0) {
        try out.appendSlice(allocator, "The tool calls in them were:");
        for (calls.items, 0..) |entry, i| {
            const separator: []const u8 = if (i == 0) " " else ", ";
            try out.print(allocator, "{s}{s} ({d})", .{ separator, entry.name, entry.times });
        }
        try out.appendSlice(allocator, ".\n");
    }
    if (last_text.len != 0) {
        try out.appendSlice(allocator, "The last thing you said before this point was:\n");
        try appendCut(allocator, &out, last_text, policy.part_max_bytes);
    }

    return out.toOwnedSlice(allocator);
}

/// How `harnessSummary` starts. Exported so a reader that shows this to a
/// person, and the test that pins it, do not carry a second copy of a
/// sentence written here.
pub const harness_summary_first_line =
    "[chock wrote this summary. No model answered, so it says what happened and not what was learned.]\n";

const Counted = struct { name: []const u8, times: usize };

fn count(allocator: std.mem.Allocator, list: *std.ArrayList(Counted), name: []const u8) Error!void {
    for (list.items) |*entry| {
        if (std.mem.eql(u8, entry.name, name)) {
            entry.times += 1;
            return;
        }
    }
    try list.append(allocator, .{ .name = name, .times = 1 });
}

/// What the agent is told when its context is approaching the threshold.
///
/// **The threshold is named, in tokens, because a warning without a number is
/// a warning nobody can act on.** The agent cannot see how full its context
/// is; the harness holds that number exactly, which is what makes this one of
/// the facts only the harness knows.
///
/// `offer_memory` is false for a session with no knowledgebase, and the text
/// then never names `write_memory`. **A tool that is not offered is never
/// named**, the same rule the prompt keeps: naming one costs a turn to find
/// out it does not exist.
pub fn noticeText(
    allocator: std.mem.Allocator,
    used_tokens: u64,
    compact_at_tokens: u64,
    limit_tokens: u64,
    offer_memory: bool,
) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.print(
        allocator,
        "[chock] Your context holds {d} tokens of the {d} this model can take, and chock folds the " ++
            "middle of it into a short summary at {d}. What is folded away is gone from your context.\n",
        .{ used_tokens, limit_tokens, compact_at_tokens },
    );
    if (offer_memory) {
        try out.appendSlice(
            allocator,
            "Your notes are not: they outlive a compaction and this session. Call write_memory now " ++
                "for anything a fresh agent would waste time working out again, and write the dead " ++
                "ends first. An approach you ruled out and then tried again costs the whole detour " ++
                "a second time.\n",
        );
    } else {
        try out.appendSlice(
            allocator,
            "Finish what you are in the middle of, and say in your next message anything you would " ++
                "otherwise have to work out again.\n",
        );
    }
    return out.toOwnedSlice(allocator);
}

const testing = std.testing;

/// Build a session whose context holds one plain message per entry of
/// `roles`, with ids 1, 2, 3 and so on, so a test can name a span by number.
fn sessionOf(allocator: std.mem.Allocator, roles: []const event.Role) !state.Session {
    var session = state.Session.init(allocator);
    errdefer session.deinit();
    for (roles, 0..) |role, i| {
        try session.apply(.{ .id = i + 1, .session = "01S", .time_ms = 1, .event = .{
            .message = .{ .role = role, .content = &.{.{ .text = "x" }} },
        } });
    }
    return session;
}

test "the plan folds the middle, protects the head, and names the tail in kept_ranges" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const many = [_]event.Role{.user} ** 10;
    var session = try sessionOf(allocator, &many);
    defer session.deinit();

    const policy = Policy{ .protect_head_entries = 1, .keep_recent_entries = 3 };
    const p = (try plan(arena_state.allocator(), &session, policy)).?;

    // The head, id 1, is not in the span at all.
    try testing.expectEqual(@as(u64, 2), p.from_id);
    try testing.expectEqual(@as(u64, 10), p.through_id);
    // The tail, ids 8 through 10, is in the span and kept.
    try testing.expectEqual(@as(usize, 1), p.kept_ranges.len);
    try testing.expectEqual(@as(u64, 8), p.kept_ranges[0].from_id);
    try testing.expectEqual(@as(u64, 10), p.kept_ranges[0].through_id);
    // Six entries are folded, ids 2 through 7.
    try testing.expectEqual(@as(usize, 6), p.folded.len);
}

test "the tail never begins on a tool answer, so a call is never separated from its result" {
    // **The fault this rule exists for is a provider refusal, not a bad
    // summary.** A `tool` role message answers a `tool_use` part in the
    // assistant turn before it. A boundary that kept the answer and folded
    // the call away builds a request that Anthropic refuses outright, so the
    // compaction that was meant to save the session would end it instead.
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const roles = [_]event.Role{
        .user, .assistant, .tool, .assistant, .tool, .tool, .assistant,
    };
    var session = try sessionOf(allocator, &roles);
    defer session.deinit();

    // Three kept entries would begin at index 4, which is a tool answer, and
    // index 5 is another. The boundary walks back to index 3, the assistant
    // turn that asked.
    const policy = Policy{ .protect_head_entries = 1, .keep_recent_entries = 3 };
    const p = (try plan(arena_state.allocator(), &session, policy)).?;
    try testing.expectEqual(@as(u64, 4), p.kept_ranges[0].from_id);
    try testing.expectEqual(@as(usize, 2), p.folded.len);
}

test "a context with nothing worth folding plans nothing, rather than folding in a circle" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const four = [_]event.Role{.user} ** 4;
    var session = try sessionOf(allocator, &four);
    defer session.deinit();

    const policy = Policy{ .protect_head_entries = 1, .keep_recent_entries = 3 };
    try testing.expect(try plan(arena_state.allocator(), &session, policy) == null);

    var tiny = try sessionOf(allocator, &.{.user});
    defer tiny.deinit();
    try testing.expect(try plan(arena_state.allocator(), &tiny, policy) == null);
}

test "a tail of huge turns is cut by its bytes, so a compaction really does make room" {
    // **Measured on a real session, 2026-08-21.** A count alone is not a
    // bound. A `run_command` result is capped at 64 KiB, so six recent
    // entries were about fifty thousand tokens of a sixty five thousand token
    // context: the session compacted, kept all six, and overflowed again on
    // the very next turn. It went forward each time and paid a summary call
    // every turn to do it.
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    var session = state.Session.init(allocator);
    defer session.deinit();

    const huge = "H" ** 40_000;
    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{
        .message = .{ .role = .user, .content = &.{.{ .text = "TASK" }} },
    } });
    for (2..11) |id| {
        try session.apply(.{ .id = id, .session = "01S", .time_ms = 1, .event = .{
            .message = .{ .role = .assistant, .content = &.{.{ .text = huge }} },
        } });
    }

    const policy = Policy{
        .protect_head_entries = 1,
        .keep_recent_entries = 6,
        .keep_recent_max_bytes = 16 * 1024,
    };
    const p = (try plan(arena_state.allocator(), &session, policy)).?;

    // One kept entry, not six: every one of them is larger than the whole
    // byte bound on its own, and the last turn is kept whatever its size.
    try testing.expectEqual(@as(u64, 10), p.kept_ranges[0].from_id);
    try testing.expectEqual(@as(usize, 8), p.folded.len);

    // And the same context under a bound large enough for all six keeps all
    // six, so the count is still the bound when the turns are ordinary.
    const roomy = Policy{
        .protect_head_entries = 1,
        .keep_recent_entries = 6,
        .keep_recent_max_bytes = 1024 * 1024,
    };
    const wide = (try plan(arena_state.allocator(), &session, roomy)).?;
    try testing.expectEqual(@as(u64, 5), wide.kept_ranges[0].from_id);
    try testing.expectEqual(@as(usize, 3), wide.folded.len);
}

test "a policy that keeps no recent entries at all still plans without reading past the context" {
    // `keep_recent_entries = 0` puts the tail boundary one past the last
    // entry, which the walk that keeps a tool answer with its call must not
    // read.
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const five = [_]event.Role{.user} ** 5;
    var session = try sessionOf(allocator, &five);
    defer session.deinit();

    const policy = Policy{ .protect_head_entries = 1, .keep_recent_entries = 0 };
    const p = (try plan(arena_state.allocator(), &session, policy)).?;
    try testing.expectEqual(@as(usize, 0), p.kept_ranges.len);
    try testing.expectEqual(@as(usize, 4), p.folded.len);
}

test "a second plan over a context that already holds a summary keeps its kept range inside its span" {
    // **The invariant a real session broke on 2026-08-21.** A `kept_ranges`
    // entry outside `[from_id, through_id]` is not merely untidy: the fold
    // tests every entry against that span, so entries the plan meant to fold
    // fall outside it, survive, and the context goes on growing while the log
    // says a compaction ran.
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const many = [_]event.Role{.user} ** 10;
    var session = try sessionOf(allocator, &many);
    defer session.deinit();

    const policy = Policy{ .protect_head_entries = 1, .keep_recent_entries = 3 };
    const first = (try plan(arena, &session, policy)).?;
    try session.apply(.{ .id = 11, .session = "01S", .time_ms = 1, .event = .{ .compaction = .{
        .summary = "the first summary",
        .from_id = first.from_id,
        .through_id = first.through_id,
        .kept_ranges = first.kept_ranges,
        .model_alias = "compact",
    } } });

    // The head, the summary and three kept entries.
    try testing.expectEqual(@as(usize, 5), session.context.items.len);

    // Then the session goes on and the context grows again, which is the
    // state a second compaction actually meets.
    for (12..18) |id| {
        try session.apply(.{ .id = id, .session = "01S", .time_ms = 1, .event = .{
            .message = .{ .role = .assistant, .content = &.{.{ .text = "more" }} },
        } });
    }

    const second = (try plan(arena, &session, policy)).?;
    for (second.kept_ranges) |range| {
        try testing.expect(range.from_id >= second.from_id);
        try testing.expect(range.through_id <= second.through_id);
    }
}

test "the threshold is read from the model's own limit, and an unknown limit fires nothing" {
    const known = Policy{ .context_limit_tokens = 65536, .compact_at = 0.75, .warn_at = 0.6 };
    try testing.expectEqual(@as(?u64, 49152), thresholdTokens(known, known.compact_at));
    try testing.expect(!shouldCompact(known, 49151));
    try testing.expect(shouldCompact(known, 49152));
    try testing.expect(shouldWarn(known, 39322));
    // The warning comes first. A notice that arrived with the compaction
    // would give the agent no turn to act on it.
    try testing.expect(shouldWarn(known, 40000) and !shouldCompact(known, 40000));

    const unknown = Policy{};
    try testing.expect(thresholdTokens(unknown, 0.75) == null);
    try testing.expect(!shouldCompact(unknown, 1_000_000));
    try testing.expect(!shouldWarn(unknown, 1_000_000));
}

test "a transcript holds each turn once and cuts one huge part rather than the whole span" {
    const allocator = testing.allocator;
    var session = state.Session.init(allocator);
    defer session.deinit();

    const big = "B" ** 8000;
    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{
        .message = .{ .role = .assistant, .content = &.{
            .{ .text = "reading the file" },
            .{ .tool_use = .{ .call_id = "c1", .tool = "read_file", .arguments = "{\"path\":\"x.zig\"}" } },
        } },
    } });
    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{
        .message = .{ .role = .tool, .content = &.{
            .{ .tool_result = .{ .call_id = "c1", .output = big, .is_error = false } },
        } },
    } });

    const policy = Policy{ .part_max_bytes = 100 };
    const text = try transcript(allocator, session.context.items, policy);
    defer allocator.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "reading the file") != null);
    try testing.expect(std.mem.indexOf(u8, text, "read_file") != null);
    try testing.expect(std.mem.indexOf(u8, text, "x.zig") != null);
    try testing.expect(std.mem.indexOf(u8, text, part_cut_note) != null);
    try testing.expect(text.len < big.len);
}

test "a transcript larger than the budget keeps its end and says the front is missing" {
    const allocator = testing.allocator;
    var session = state.Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{
        .message = .{ .role = .assistant, .content = &.{.{ .text = "THE OLDEST THING" }} },
    } });
    for (2..40) |i| {
        try session.apply(.{ .id = i, .session = "01S", .time_ms = 1, .event = .{
            .message = .{ .role = .assistant, .content = &.{.{ .text = "M" ** 200 }} },
        } });
    }
    try session.apply(.{ .id = 40, .session = "01S", .time_ms = 1, .event = .{
        .message = .{ .role = .assistant, .content = &.{.{ .text = "THE NEWEST THING" }} },
    } });

    const policy = Policy{ .summary_max_bytes = 1024, .part_max_bytes = 1024 };
    const text = try transcript(allocator, session.context.items, policy);
    defer allocator.free(text);

    try testing.expect(std.mem.startsWith(u8, text, cut_note));
    try testing.expect(std.mem.indexOf(u8, text, "THE NEWEST THING") != null);
    try testing.expect(std.mem.indexOf(u8, text, "THE OLDEST THING") == null);
}

test "the harness summary says who wrote it, counts the tool calls, and keeps the last thing said" {
    const allocator = testing.allocator;
    var session = state.Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{
        .message = .{ .role = .assistant, .content = &.{
            .{ .tool_use = .{ .call_id = "c1", .tool = "read_file", .arguments = "{}" } },
        } },
    } });
    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{
        .message = .{ .role = .assistant, .content = &.{
            .{ .tool_use = .{ .call_id = "c2", .tool = "read_file", .arguments = "{}" } },
            .{ .text = "the parser is in src/parse.zig" },
        } },
    } });

    const text = try harnessSummary(allocator, session.context.items, .{});
    defer allocator.free(text);

    try testing.expect(std.mem.startsWith(u8, text, harness_summary_first_line));
    try testing.expect(std.mem.indexOf(u8, text, "read_file (2)") != null);
    try testing.expect(std.mem.indexOf(u8, text, "src/parse.zig") != null);
}

test "the notice names the threshold and asks for the dead ends first" {
    const allocator = testing.allocator;
    const text = try noticeText(allocator, 40000, 49152, 65536, true);
    defer allocator.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "40000") != null);
    try testing.expect(std.mem.indexOf(u8, text, "49152") != null);
    try testing.expect(std.mem.indexOf(u8, text, "65536") != null);
    try testing.expect(std.mem.indexOf(u8, text, "write_memory") != null);
    try testing.expect(std.mem.indexOf(u8, text, "dead ends") != null);
}

test "a session with no knowledgebase is never told to call write_memory" {
    const allocator = testing.allocator;
    const text = try noticeText(allocator, 40000, 49152, 65536, false);
    defer allocator.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "write_memory") == null);
    try testing.expect(std.mem.indexOf(u8, text, "49152") != null);
}

test "the summary instruction asks for what did not work, not only for what did" {
    try testing.expect(std.mem.indexOf(u8, summary_system, "did not work") != null);
    try testing.expect(std.mem.indexOf(u8, summary_system, "detour") != null);
}
