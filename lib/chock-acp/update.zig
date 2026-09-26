//! What Chock has to say during a turn, and how each protocol version says it.
//!
//! ## One model, two encodings
//!
//! A session's own events are Chock's, and neither protocol version is shaped
//! like them. So a caller builds one of these and asks for the `session/update`
//! parameters in the version it negotiated. Version 2 rebuilt this stream, and
//! the differences are real rather than cosmetic:
//!
//! * A tool call opens as `tool_call` in version 1. Version 2 has no such
//!   variant and opens it as `tool_call_update`, whose shape is identical.
//! * A plan is `plan` in version 1 and `plan_update` in version 2.
//! * An abandoned plan step is `cancelled` in version 2. Version 1 cannot say
//!   it, so the step is left out of the plan rather than reported as finished.
//!
//! ## What this does not know
//!
//! It imports no other Chock library, so it holds no event type and no session.
//! The command that speaks ACP is the one place that knows both a log event and
//! one of these, which keeps the translation in one file that can be read.
//!
//! ## A plan is sent whole
//!
//! ACP's plan entries carry no identifier, so a client cannot merge one entry
//! into a plan it already has. Chock's own plan updates are a delta keyed by
//! identifier. The caller therefore holds the merged plan and passes all of it,
//! every time.

const std = @import("std");

const common = @import("common.zig");

pub const Version = common.Version;
pub const ToolKind = common.ToolKind;

/// Where a plan step has got to, in Chock's own terms.
pub const StepStatus = enum {
    pending,
    in_progress,
    done,
    /// Given up rather than finished, which version 1 has no word for.
    abandoned,
};

pub const PlanStep = struct {
    subject: []const u8,
    status: StepStatus,
};

/// What a tool call is doing. Split from the protocol's own status because
/// `started` has to become a different variant in each version.
pub const ToolPhase = enum { started, finished, failed };

pub const Chunk = struct { text: []const u8 };

pub const Tool = struct {
    id: []const u8,
    /// What a person reads. Required by both versions when a call opens.
    title: []const u8,
    /// The tool's own name, which stays the same for the life of the call.
    name: []const u8 = "",
    kind: ToolKind = .other,
    phase: ToolPhase,
    /// What the call produced, for a call that has finished. Empty otherwise.
    output: []const u8 = "",
};

pub const Usage = struct {
    input_tokens: u64 = 0,
    output_tokens: u64 = 0,
    /// Null when the cost is unknown, which is not the same as free. See
    /// `lib/chock-cost`.
    cost: ?f64 = null,
};

/// One thing to tell the client.
pub const Update = union(enum) {
    agent_message: Chunk,
    agent_thought: Chunk,
    user_message: Chunk,
    tool: Tool,
    /// The whole plan, not a change to it. See this file's own note.
    plan: []const PlanStep,
    usage: Usage,
};

/// The `params` of a `session/update` notification, in `version`'s spelling.
///
/// Null when this version cannot carry this update at all. A caller that treats
/// null as an error would refuse a turn over something the client never needed.
pub fn encode(
    arena: std.mem.Allocator,
    version: Version,
    session_id: []const u8,
    update: Update,
) std.mem.Allocator.Error!?[]u8 {
    return switch (update) {
        .agent_message => |one| try chunk(arena, version, session_id, "agent_message_chunk", one),
        .agent_thought => |one| try chunk(arena, version, session_id, "agent_thought_chunk", one),
        .user_message => |one| try chunk(arena, version, session_id, "user_message_chunk", one),
        .tool => |one| try tool(arena, version, session_id, one),
        .plan => |steps| try plan(arena, version, session_id, steps),
        .usage => |one| try usage(arena, version, session_id, one),
    };
}

fn chunk(
    arena: std.mem.Allocator,
    version: Version,
    session_id: []const u8,
    kind: []const u8,
    one: Chunk,
) std.mem.Allocator.Error![]u8 {
    _ = version;
    // Both versions spell a chunk the same way, and both carry it as a content
    // block rather than a bare string.
    return std.json.Stringify.valueAlloc(arena, .{
        .sessionId = session_id,
        .update = .{
            .sessionUpdate = kind,
            .content = .{ .type = "text", .text = one.text },
        },
    }, .{});
}

fn tool(
    arena: std.mem.Allocator,
    version: Version,
    session_id: []const u8,
    one: Tool,
) std.mem.Allocator.Error![]u8 {
    const status: []const u8 = switch (one.phase) {
        .started => "in_progress",
        .finished => "completed",
        .failed => "failed",
    };

    // Version 1 opens a call with `tool_call`; version 2 has no such variant and
    // opens it with the update, whose fields are the same in both.
    const kind: []const u8 = switch (one.phase) {
        .started => switch (version) {
            .v1 => "tool_call",
            .v2 => "tool_call_update",
        },
        .finished, .failed => "tool_call_update",
    };

    if (one.phase == .started) {
        return std.json.Stringify.valueAlloc(arena, .{
            .sessionId = session_id,
            .update = .{
                .sessionUpdate = kind,
                .toolCallId = one.id,
                .title = one.title,
                .name = one.name,
                .kind = one.kind.wireName(),
                .status = status,
            },
        }, .{});
    }

    // An update carries only what changed, so the title and the kind are not
    // repeated. The output goes in a content block, which is where a client
    // looks for what a call produced.
    if (one.output.len == 0) {
        return std.json.Stringify.valueAlloc(arena, .{
            .sessionId = session_id,
            .update = .{
                .sessionUpdate = kind,
                .toolCallId = one.id,
                .status = status,
            },
        }, .{});
    }

    return std.json.Stringify.valueAlloc(arena, .{
        .sessionId = session_id,
        .update = .{
            .sessionUpdate = kind,
            .toolCallId = one.id,
            .status = status,
            .content = .{.{
                .type = "content",
                .content = .{ .type = "text", .text = one.output },
            }},
        },
    }, .{});
}

fn plan(
    arena: std.mem.Allocator,
    version: Version,
    session_id: []const u8,
    steps: []const PlanStep,
) std.mem.Allocator.Error![]u8 {
    const Entry = struct {
        content: []const u8,
        /// Chock's plan has no priority and ACP requires one, so every step is
        /// the middle value. Inventing an order nobody wrote would be worse.
        priority: []const u8 = "medium",
        status: []const u8,
    };

    var entries: std.ArrayList(Entry) = .empty;
    for (steps) |step| {
        const status: []const u8 = switch (step.status) {
            .pending => "pending",
            .in_progress => "in_progress",
            .done => "completed",
            // Version 1 has no word for a step that was given up. Leaving it out
            // says it is no longer in the plan, which is true; calling it
            // completed would not be.
            .abandoned => switch (version) {
                .v1 => continue,
                .v2 => "cancelled",
            },
        };
        try entries.append(arena, .{ .content = step.subject, .status = status });
    }

    return std.json.Stringify.valueAlloc(arena, .{
        .sessionId = session_id,
        .update = .{
            .sessionUpdate = switch (version) {
                .v1 => "plan",
                .v2 => "plan_update",
            },
            .entries = entries.items,
        },
    }, .{});
}

fn usage(
    arena: std.mem.Allocator,
    version: Version,
    session_id: []const u8,
    one: Usage,
) std.mem.Allocator.Error![]u8 {
    _ = version;
    return std.json.Stringify.valueAlloc(arena, .{
        .sessionId = session_id,
        .update = .{
            .sessionUpdate = "usage_update",
            .inputTokens = one.input_tokens,
            .outputTokens = one.output_tokens,
            .cost = one.cost,
        },
    }, .{});
}

const testing = std.testing;

fn encoded(arena: std.mem.Allocator, version: Version, update: Update) ![]u8 {
    return (try encode(arena, version, "sess-1", update)).?;
}

fn field(arena: std.mem.Allocator, body: []const u8, path: []const []const u8) ![]const u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, arena, body, .{});
    var at = parsed.value;
    for (path) |name| at = at.object.get(name) orelse return error.NoSuchField;
    return switch (at) {
        .string => |text| text,
        .integer => |number| try std.fmt.allocPrint(arena, "{d}", .{number}),
        else => error.NotAString,
    };
}

test "a message chunk is the same in both versions, and carries a content block" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    for ([_]Version{ .v1, .v2 }) |version| {
        const body = try encoded(arena, version, .{ .agent_message = .{ .text = "hello" } });
        try testing.expectEqualStrings("sess-1", try field(arena, body, &.{"sessionId"}));
        try testing.expectEqualStrings(
            "agent_message_chunk",
            try field(arena, body, &.{ "update", "sessionUpdate" }),
        );
        try testing.expectEqualStrings("text", try field(arena, body, &.{ "update", "content", "type" }));
        try testing.expectEqualStrings("hello", try field(arena, body, &.{ "update", "content", "text" }));
    }

    // A thought is its own variant, so a client can hide reasoning without
    // hiding the answer.
    const thought = try encoded(arena, .v1, .{ .agent_thought = .{ .text = "thinking" } });
    try testing.expectEqualStrings(
        "agent_thought_chunk",
        try field(arena, thought, &.{ "update", "sessionUpdate" }),
    );
}

test "a tool call opens as tool_call in version 1 and as an update in version 2" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    const started = Update{ .tool = .{
        .id = "call-1",
        .title = "run gh issue list",
        .name = "run_command",
        .kind = .execute,
        .phase = .started,
    } };

    const one = try encoded(arena, .v1, started);
    try testing.expectEqualStrings("tool_call", try field(arena, one, &.{ "update", "sessionUpdate" }));
    try testing.expectEqualStrings("call-1", try field(arena, one, &.{ "update", "toolCallId" }));
    try testing.expectEqualStrings("execute", try field(arena, one, &.{ "update", "kind" }));
    try testing.expectEqualStrings("in_progress", try field(arena, one, &.{ "update", "status" }));

    // Version 2 has no `tool_call` variant at all, so sending one would be a
    // variant no client reads.
    const two = try encoded(arena, .v2, started);
    try testing.expectEqualStrings("tool_call_update", try field(arena, two, &.{ "update", "sessionUpdate" }));
    try testing.expectEqualStrings("run gh issue list", try field(arena, two, &.{ "update", "title" }));
}

test "a finished call reports its output as content, and a failed one says so" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    const done = try encoded(arena, .v1, .{ .tool = .{
        .id = "call-1",
        .title = "",
        .phase = .finished,
        .output = "issue 1 open",
    } });
    try testing.expectEqualStrings("tool_call_update", try field(arena, done, &.{ "update", "sessionUpdate" }));
    try testing.expectEqualStrings("completed", try field(arena, done, &.{ "update", "status" }));

    var parsed = try std.json.parseFromSlice(std.json.Value, arena, done, .{});
    const content = parsed.value.object.get("update").?.object.get("content").?.array;
    try testing.expectEqual(@as(usize, 1), content.items.len);
    try testing.expectEqualStrings("content", content.items[0].object.get("type").?.string);
    try testing.expectEqualStrings(
        "issue 1 open",
        content.items[0].object.get("content").?.object.get("text").?.string,
    );

    const failed = try encoded(arena, .v1, .{ .tool = .{
        .id = "call-1",
        .title = "",
        .phase = .failed,
        .output = "no such thing",
    } });
    try testing.expectEqualStrings("failed", try field(arena, failed, &.{ "update", "status" }));

    // A call that produced nothing carries no content member rather than an
    // empty one, which a client would draw as an empty result.
    const quiet = try encoded(arena, .v1, .{ .tool = .{ .id = "c", .title = "", .phase = .finished } });
    var quiet_parsed = try std.json.parseFromSlice(std.json.Value, arena, quiet, .{});
    try testing.expect(quiet_parsed.value.object.get("update").?.object.get("content") == null);
}

test "an abandoned step is cancelled in version 2 and absent from version 1" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    const steps = [_]PlanStep{
        .{ .subject = "read the schema", .status = .done },
        .{ .subject = "write the encoder", .status = .in_progress },
        .{ .subject = "ask the vendor", .status = .abandoned },
        .{ .subject = "write the docs", .status = .pending },
    };

    const one = try encoded(arena, .v1, .{ .plan = &steps });
    try testing.expectEqualStrings("plan", try field(arena, one, &.{ "update", "sessionUpdate" }));
    var one_parsed = try std.json.parseFromSlice(std.json.Value, arena, one, .{});
    const one_entries = one_parsed.value.object.get("update").?.object.get("entries").?.array;
    // Three, not four: version 1 cannot say a step was given up, so it is left
    // out rather than reported as finished.
    try testing.expectEqual(@as(usize, 3), one_entries.items.len);
    try testing.expectEqualStrings("completed", one_entries.items[0].object.get("status").?.string);
    for (one_entries.items) |entry| {
        try testing.expect(!std.mem.eql(u8, entry.object.get("content").?.string, "ask the vendor"));
        // Every entry carries a priority, which ACP requires and Chock has no
        // word for.
        try testing.expectEqualStrings("medium", entry.object.get("priority").?.string);
    }

    const two = try encoded(arena, .v2, .{ .plan = &steps });
    try testing.expectEqualStrings("plan_update", try field(arena, two, &.{ "update", "sessionUpdate" }));
    var two_parsed = try std.json.parseFromSlice(std.json.Value, arena, two, .{});
    const two_entries = two_parsed.value.object.get("update").?.object.get("entries").?.array;
    try testing.expectEqual(@as(usize, 4), two_entries.items.len);
    try testing.expectEqualStrings("cancelled", two_entries.items[2].object.get("status").?.string);
}

test "usage carries the tokens, and an unknown cost is null rather than zero" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    const known = try encoded(arena, .v1, .{ .usage = .{
        .input_tokens = 120,
        .output_tokens = 34,
        .cost = 0.0021,
    } });
    try testing.expectEqualStrings("usage_update", try field(arena, known, &.{ "update", "sessionUpdate" }));
    try testing.expectEqualStrings("120", try field(arena, known, &.{ "update", "inputTokens" }));

    // Free and unknown are different, and `lib/chock-cost` exists because
    // collapsing them is wrong in both directions. Null is what carries that.
    const unknown = try encoded(arena, .v1, .{ .usage = .{ .input_tokens = 1 } });
    var parsed = try std.json.parseFromSlice(std.json.Value, arena, unknown, .{});
    try testing.expectEqual(std.json.Value.null, parsed.value.object.get("update").?.object.get("cost").?);
}

test "every update is something both versions can be asked for" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    const every = [_]Update{
        .{ .agent_message = .{ .text = "a" } },
        .{ .agent_thought = .{ .text = "a" } },
        .{ .user_message = .{ .text = "a" } },
        .{ .tool = .{ .id = "c", .title = "t", .phase = .started } },
        .{ .tool = .{ .id = "c", .title = "t", .phase = .finished } },
        .{ .plan = &.{} },
        .{ .usage = .{} },
    };

    var seen = std.EnumSet(std.meta.Tag(Update)).initEmpty();
    for (every) |one| {
        seen.insert(std.meta.activeTag(one));
        for ([_]Version{ .v1, .v2 }) |version| {
            const body = (try encode(arena, version, "s", one)) orelse continue;
            // Every one is a whole JSON object with the two members the
            // notification requires.
            var parsed = try std.json.parseFromSlice(std.json.Value, arena, body, .{});
            try testing.expect(parsed.value.object.get("sessionId") != null);
            try testing.expect(parsed.value.object.get("update").?.object.get("sessionUpdate") != null);
            // And it frames: the transport cannot carry an embedded newline.
            try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, body, '\n'));
        }
    }
    try testing.expectEqual(@typeInfo(Update).@"union".fields.len, seen.count());
}

test "a newline in what the model said survives as an escape, not as a frame" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    const body = try encoded(arena, .v1, .{ .agent_message = .{ .text = "one\ntwo" } });
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, body, '\n'));
    try testing.expectEqualStrings("one\ntwo", try field(arena, body, &.{ "update", "content", "text" }));
}
