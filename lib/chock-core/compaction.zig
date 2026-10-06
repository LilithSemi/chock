//! Compaction folds the middle of a session's context into one summary
//! so the session can keep going. The log keeps every event; only the
//! model's view gets shorter.

const std = @import("std");
const chock_proto = @import("chock-proto");

const event = chock_proto.event;
const state = chock_proto.state;

pub const Error = std.mem.Allocator.Error;

pub const Policy = struct {
    context_limit_tokens: ?u64 = null,
    compact_at: f64 = 0.75,
    warn_at: f64 = 0.6,
    keep_recent_entries: usize = 6,
    keep_recent_max_bytes: usize = 16 * 1024,
    protect_head_entries: usize = 1,
    summary_max_bytes: usize = 16 * 1024,
    part_max_bytes: usize = 2 * 1024,
};

pub fn thresholdTokens(policy: Policy, fraction: f64) ?u64 {
    const limit = policy.context_limit_tokens orelse return null;
    if (limit == 0) return null;
    const scaled = @as(f64, @floatFromInt(limit)) * fraction;
    if (scaled <= 0) return null;
    return @intFromFloat(scaled);
}

pub fn shouldCompact(policy: Policy, input_tokens: u64) bool {
    const at = thresholdTokens(policy, policy.compact_at) orelse return false;
    return input_tokens >= at;
}

pub fn shouldWarn(policy: Policy, input_tokens: u64) bool {
    const at = thresholdTokens(policy, policy.warn_at) orelse return false;
    return input_tokens >= at;
}

pub const Plan = struct {
    from_id: u64,
    through_id: u64,
    kept_ranges: []const event.EventRange,
    folded: []const state.ContextEntry,
};

pub fn plan(allocator: std.mem.Allocator, session: *const state.Session, policy: Policy) Error!?Plan {
    const entries = session.context.items;
    if (entries.len > 1) {
        for (entries[1..], entries[0 .. entries.len - 1]) |after, before| {
            std.debug.assert(before.id <= after.id);
        }
    }

    const head = @min(policy.protect_head_entries, entries.len);
    if (entries.len <= head) return null;

    var tail_start = entries.len;
    var kept_bytes: usize = 0;
    while (tail_start > head and entries.len - tail_start < policy.keep_recent_entries) {
        const size = entryBytes(entries[tail_start - 1]);
        const first = tail_start == entries.len;
        if (!first and kept_bytes + size > policy.keep_recent_max_bytes) break;
        kept_bytes += size;
        tail_start -= 1;
    }

    while (tail_start > head and tail_start < entries.len and isToolAnswer(entries[tail_start])) : (tail_start -= 1) {}

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
                .image => |image| image.data.len,
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
                    .image => |image| {
                        try out.print(allocator, "[an image, {s}, which is no longer shown]\n", .{
                            image.media_type,
                        });
                    },
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

pub const cut_note = "[chock: the earlier part of this span is not shown here.]\n";

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

pub fn summaryPrompt(allocator: std.mem.Allocator, rendered: []const u8) Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "Here is the part of the session to summarise.\n\n{s}\n\nWrite the summary now.",
        .{rendered},
    );
}

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

    try testing.expectEqual(@as(u64, 2), p.from_id);
    try testing.expectEqual(@as(u64, 10), p.through_id);
    try testing.expectEqual(@as(usize, 1), p.kept_ranges.len);
    try testing.expectEqual(@as(u64, 8), p.kept_ranges[0].from_id);
    try testing.expectEqual(@as(u64, 10), p.kept_ranges[0].through_id);
    try testing.expectEqual(@as(usize, 6), p.folded.len);
}

test "the tail never begins on a tool answer, so a call is never separated from its result" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const roles = [_]event.Role{
        .user, .assistant, .tool, .assistant, .tool, .tool, .assistant,
    };
    var session = try sessionOf(allocator, &roles);
    defer session.deinit();

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

    try testing.expectEqual(@as(u64, 10), p.kept_ranges[0].from_id);
    try testing.expectEqual(@as(usize, 8), p.folded.len);

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

    try testing.expectEqual(@as(usize, 5), session.context.items.len);

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
