//! What Chock has to say during a turn, encoded for whichever ACP version
//! negotiated. It holds no event type or session; the command that speaks ACP
//! is the only place that knows both, and sends each plan whole, since ACP's own plan entries carry no identifier to merge by.

const std = @import("std");

const common = @import("common.zig");

pub const Version = common.Version;
pub const ToolKind = common.ToolKind;

pub const StepStatus = enum {
    pending,
    in_progress,
    done,
    /// Given up, not finished; version 1 has no word for it.
    abandoned,
};

pub const PlanStep = struct {
    subject: []const u8,
    status: StepStatus,
};

/// Split out: `started` becomes a different variant per version.
pub const ToolPhase = enum { started, finished, failed };

pub const Chunk = struct { text: []const u8 };

pub const Tool = struct {
    id: []const u8,
    /// Required by both versions when a call opens.
    title: []const u8,
    name: []const u8 = "",
    kind: ToolKind = .other,
    phase: ToolPhase,
    /// Empty until the call finishes.
    output: []const u8 = "",
};

/// A file change made in Chock's isolated session workspace. Version 2 can
/// carry the logged Git patch directly. Version 1's diff requires complete
/// old and new file contents, which an audit-log patch cannot safely invent.
pub const DiffOperation = enum { add, delete, modify };

pub const Diff = struct {
    id: []const u8,
    path: []const u8,
    patch: []const u8,
    operation: DiffOperation = .modify,
};

pub const SubagentState = enum { running, idle };

pub const Subagent = struct {
    session_id: []const u8,
    title: []const u8,
    description: []const u8,
    cwd: []const u8,
    state: SubagentState,
    stop_reason: []const u8 = "",
};

pub const Compaction = struct {
    id: []const u8,
    summary: []const u8,
};

pub const SessionState = struct {
    state: enum { running, requires_action, idle },
    stop_reason: []const u8 = "",
};

/// ACP's `usage_update` gauge, not a bill: `used`/`size` show window fullness.
pub const Usage = struct {
    used: u64,
    size: u64,
    /// Null when unknown, not the same as free. See `lib/chock-cost`.
    cost: ?f64 = null,
    currency: []const u8 = "USD",
};

pub const Update = union(enum) {
    agent_message: Chunk,
    agent_thought: Chunk,
    user_message: Chunk,
    tool: Tool,
    diff: Diff,
    subagent: Subagent,
    compaction: Compaction,
    state: SessionState,
    /// The whole plan, not a change to it.
    plan: []const PlanStep,
    usage: Usage,
    /// Untrusted: a client cuts it to length and strips terminal-driving bytes.
    title: []const u8,
};

/// Null when this version can't carry it, never an error.
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
        .diff => |one| try diff(arena, version, session_id, one),
        .subagent => |one| try subagent(arena, version, session_id, one),
        .compaction => |one| try compaction(arena, version, session_id, one),
        .state => |one| try sessionState(arena, version, session_id, one),
        .plan => |steps| try plan(arena, version, session_id, steps),
        .usage => |one| try usage(arena, version, session_id, one),
        .title => |text| try title(arena, version, session_id, text),
    };
}

/// Adds the audit-log cursor without making it part of any ACP update entity.
/// The key is namespaced because ACP reserves `_meta` for extensions.
pub fn encodeAt(
    arena: std.mem.Allocator,
    version: Version,
    session_id: []const u8,
    update: Update,
    log_offset: u64,
) std.mem.Allocator.Error!?[]u8 {
    const body = (try encode(arena, version, session_id, update)) orelse return null;
    std.debug.assert(body.len != 0 and body[body.len - 1] == '}');
    return try std.fmt.allocPrint(
        arena,
        "{s},\"_meta\":{{\"dev.lilithsemi.chock/logOffset\":{d}}}}}",
        .{ body[0 .. body.len - 1], log_offset },
    );
}

fn subagent(
    arena: std.mem.Allocator,
    version: Version,
    session_id: []const u8,
    one: Subagent,
) std.mem.Allocator.Error![]u8 {
    _ = version;
    if (one.state == .running) {
        return std.json.Stringify.valueAlloc(arena, .{
            .sessionId = session_id,
            .update = .{
                .sessionUpdate = "subagent_update",
                .sessionId = one.session_id,
                .title = one.title,
                .description = one.description,
                .cwd = one.cwd,
                .state = .{ .state = "running" },
            },
        }, .{});
    }
    return std.json.Stringify.valueAlloc(arena, .{
        .sessionId = session_id,
        .update = .{
            .sessionUpdate = "subagent_update",
            .sessionId = one.session_id,
            .title = one.title,
            .description = one.description,
            .cwd = one.cwd,
            .state = .{ .state = "idle", .stopReason = one.stop_reason },
        },
    }, .{});
}

fn compaction(
    arena: std.mem.Allocator,
    version: Version,
    session_id: []const u8,
    one: Compaction,
) std.mem.Allocator.Error![]u8 {
    _ = version;
    return std.json.Stringify.valueAlloc(arena, .{
        .sessionId = session_id,
        .update = .{
            .sessionUpdate = "compaction_update",
            .compactionId = one.id,
            .status = "completed",
            .summary = .{.{ .type = "text", .text = one.summary }},
        },
    }, .{});
}

fn sessionState(
    arena: std.mem.Allocator,
    version: Version,
    session_id: []const u8,
    one: SessionState,
) std.mem.Allocator.Error!?[]u8 {
    if (version == .v1) return null;
    if (one.state != .idle or one.stop_reason.len == 0) {
        return try std.json.Stringify.valueAlloc(arena, .{
            .sessionId = session_id,
            .update = .{ .sessionUpdate = "state_update", .state = @tagName(one.state) },
        }, .{});
    }
    return try std.json.Stringify.valueAlloc(arena, .{
        .sessionId = session_id,
        .update = .{
            .sessionUpdate = "state_update",
            .state = "idle",
            .stopReason = one.stop_reason,
        },
    }, .{});
}

fn diff(
    arena: std.mem.Allocator,
    version: Version,
    session_id: []const u8,
    one: Diff,
) std.mem.Allocator.Error![]u8 {
    const diff_title = try std.fmt.allocPrint(arena, "Isolated workspace diff: {s}", .{one.path});

    if (version == .v1) {
        return std.json.Stringify.valueAlloc(arena, .{
            .sessionId = session_id,
            .update = .{
                .sessionUpdate = "tool_call",
                .toolCallId = one.id,
                .title = diff_title,
                .name = "workspace_diff",
                .kind = "edit",
                .status = "completed",
                .content = .{.{
                    .type = "content",
                    .content = .{ .type = "text", .text = one.patch },
                }},
            },
        }, .{});
    }

    const Change = struct {
        operation: []const u8,
        path: []const u8,
        fileType: []const u8 = "text",
    };
    const change = Change{ .operation = @tagName(one.operation), .path = one.path };

    // ACP v2 calls this format `git_patch`. A provider may log a useful patch
    // fragment instead; keep the structured file change native and carry that
    // fragment as text rather than lying about its format.
    if (!std.mem.startsWith(u8, one.patch, "diff --git ")) {
        return std.json.Stringify.valueAlloc(arena, .{
            .sessionId = session_id,
            .update = .{
                .sessionUpdate = "tool_call_update",
                .toolCallId = one.id,
                .title = diff_title,
                .name = "workspace_diff",
                .kind = "edit",
                .status = "completed",
                .content = .{
                    .{ .type = "diff", .changes = .{change} },
                    .{ .type = "content", .content = .{ .type = "text", .text = one.patch } },
                },
            },
        }, .{});
    }

    return std.json.Stringify.valueAlloc(arena, .{
        .sessionId = session_id,
        .update = .{
            .sessionUpdate = "tool_call_update",
            .toolCallId = one.id,
            .title = diff_title,
            .name = "workspace_diff",
            .kind = "edit",
            .status = "completed",
            .content = .{.{
                .type = "diff",
                .changes = .{change},
                .patch = .{ .format = "git_patch", .text = one.patch },
            }},
        },
    }, .{});
}

fn chunk(
    arena: std.mem.Allocator,
    version: Version,
    session_id: []const u8,
    kind: []const u8,
    one: Chunk,
) std.mem.Allocator.Error![]u8 {
    _ = version;
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

    // Version 1 opens a call with `tool_call`; version 2 has no such variant.
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

    // An update carries only what changed: no repeated title or kind.
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
        /// No priority in Chock's plan; every step gets ACP's required middle value.
        priority: []const u8 = "medium",
        status: []const u8,
    };

    var entries: std.ArrayList(Entry) = .empty;
    for (steps) |step| {
        const status: []const u8 = switch (step.status) {
            .pending => "pending",
            .in_progress => "in_progress",
            .done => "completed",
            // Left out here, not called completed.
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
    // Null when nobody priced it; a zero would say free, a different fact.
    const Money = struct { amount: f64, currency: []const u8 };
    return std.json.Stringify.valueAlloc(arena, .{
        .sessionId = session_id,
        .update = .{
            .sessionUpdate = "usage_update",
            .used = one.used,
            .size = one.size,
            .cost = if (one.cost) |money| Money{
                .amount = money,
                .currency = one.currency,
            } else null,
        },
    }, .{});
}

fn title(
    arena: std.mem.Allocator,
    version: Version,
    session_id: []const u8,
    text: []const u8,
) std.mem.Allocator.Error![]u8 {
    _ = version;
    return std.json.Stringify.valueAlloc(arena, .{
        .sessionId = session_id,
        .update = .{
            .sessionUpdate = "session_info_update",
            .title = text,
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

    // Omits content, rather than an empty array a client would read as a result.
    const quiet = try encoded(arena, .v1, .{ .tool = .{ .id = "c", .title = "", .phase = .finished } });
    var quiet_parsed = try std.json.parseFromSlice(std.json.Value, arena, quiet, .{});
    try testing.expect(quiet_parsed.value.object.get("update").?.object.get("content") == null);
}

test "workspace diffs are native in version 2 and honest text in version 1" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    const patch = "diff --git a/src/main.zig b/src/main.zig\n--- a/src/main.zig\n+++ b/src/main.zig\n";
    const update = Update{ .diff = .{
        .id = "diff-42",
        .path = "/tmp/chock-worktree/src/main.zig",
        .patch = patch,
    } };

    const one = try encoded(arena, .v1, update);
    var one_parsed = try std.json.parseFromSlice(std.json.Value, arena, one, .{});
    const one_update = one_parsed.value.object.get("update").?.object;
    try testing.expectEqualStrings("tool_call", one_update.get("sessionUpdate").?.string);
    try testing.expectEqualStrings("completed", one_update.get("status").?.string);
    try testing.expectEqualStrings("content", one_update.get("content").?.array.items[0].object.get("type").?.string);

    const two = try encoded(arena, .v2, update);
    var parsed = try std.json.parseFromSlice(std.json.Value, arena, two, .{});
    const sent = parsed.value.object.get("update").?.object;
    try testing.expectEqualStrings("tool_call_update", sent.get("sessionUpdate").?.string);
    try testing.expectEqualStrings("Isolated workspace diff: /tmp/chock-worktree/src/main.zig", sent.get("title").?.string);
    const native = sent.get("content").?.array.items[0].object;
    try testing.expectEqualStrings("diff", native.get("type").?.string);
    try testing.expectEqualStrings("git_patch", native.get("patch").?.object.get("format").?.string);
    try testing.expectEqualStrings(patch, native.get("patch").?.object.get("text").?.string);
    const change = native.get("changes").?.array.items[0].object;
    try testing.expectEqualStrings("modify", change.get("operation").?.string);
    try testing.expectEqualStrings("/tmp/chock-worktree/src/main.zig", change.get("path").?.string);

    const fragment = try encoded(arena, .v2, .{ .diff = .{
        .id = "diff-43",
        .path = "/tmp/chock-worktree/new.zig",
        .patch = "+new\n",
        .operation = .add,
    } });
    var fragment_parsed = try std.json.parseFromSlice(std.json.Value, arena, fragment, .{});
    const content = fragment_parsed.value.object.get("update").?.object.get("content").?.array;
    try testing.expectEqual(@as(usize, 2), content.items.len);
    try testing.expect(content.items[0].object.get("patch") == null);
    try testing.expectEqualStrings("add", content.items[0].object.get("changes").?.array.items[0].object.get("operation").?.string);
    try testing.expectEqualStrings("content", content.items[1].object.get("type").?.string);
}

test "subagents, compactions, state, and log offsets remain structured" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    const child = try encoded(arena, .v1, .{ .subagent = .{
        .session_id = "child-1",
        .title = "reviewer",
        .description = "review the patch",
        .cwd = "/tmp/worktree",
        .state = .running,
    } });
    try testing.expectEqualStrings("subagent_update", try field(arena, child, &.{ "update", "sessionUpdate" }));
    try testing.expectEqualStrings("child-1", try field(arena, child, &.{ "update", "sessionId" }));
    try testing.expectEqualStrings("running", try field(arena, child, &.{ "update", "state", "state" }));

    const compacted = try encoded(arena, .v2, .{ .compaction = .{
        .id = "compact-9",
        .summary = "kept context",
    } });
    try testing.expectEqualStrings("compaction_update", try field(arena, compacted, &.{ "update", "sessionUpdate" }));
    try testing.expectEqualStrings("completed", try field(arena, compacted, &.{ "update", "status" }));

    try testing.expect((try encode(arena, .v1, "s", .{ .state = .{ .state = .running } })) == null);
    const idle = try encoded(arena, .v2, .{ .state = .{ .state = .idle, .stop_reason = "cancelled" } });
    try testing.expectEqualStrings("state_update", try field(arena, idle, &.{ "update", "sessionUpdate" }));
    try testing.expectEqualStrings("cancelled", try field(arena, idle, &.{ "update", "stopReason" }));

    const offset = (try encodeAt(arena, .v2, "s", .{ .title = "replay" }, 4096)).?;
    try testing.expectEqualStrings(
        "4096",
        try field(arena, offset, &.{ "_meta", "dev.lilithsemi.chock/logOffset" }),
    );
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
    try testing.expectEqual(@as(usize, 3), one_entries.items.len);
    try testing.expectEqualStrings("completed", one_entries.items[0].object.get("status").?.string);
    for (one_entries.items) |entry| {
        try testing.expect(!std.mem.eql(u8, entry.object.get("content").?.string, "ask the vendor"));
        try testing.expectEqualStrings("medium", entry.object.get("priority").?.string);
    }

    const two = try encoded(arena, .v2, .{ .plan = &steps });
    try testing.expectEqualStrings("plan_update", try field(arena, two, &.{ "update", "sessionUpdate" }));
    var two_parsed = try std.json.parseFromSlice(std.json.Value, arena, two, .{});
    const two_entries = two_parsed.value.object.get("update").?.object.get("entries").?.array;
    try testing.expectEqual(@as(usize, 4), two_entries.items.len);
    try testing.expectEqualStrings("cancelled", two_entries.items[2].object.get("status").?.string);
}

test "usage is a context gauge, and an unknown cost is null rather than zero" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    const known = try encoded(arena, .v1, .{ .usage = .{
        .used = 12000,
        .size = 65536,
        .cost = 0.0021,
    } });
    try testing.expectEqualStrings("usage_update", try field(arena, known, &.{ "update", "sessionUpdate" }));
    // Not a token bill: a draft doing that was refused by a real client.
    try testing.expectEqualStrings("12000", try field(arena, known, &.{ "update", "used" }));
    try testing.expectEqualStrings("65536", try field(arena, known, &.{ "update", "size" }));
    try testing.expectEqualStrings("USD", try field(arena, known, &.{ "update", "cost", "currency" }));

    const unknown = try encoded(arena, .v1, .{ .usage = .{ .used = 1, .size = 2 } });
    const parsed = try std.json.parseFromSlice(std.json.Value, arena, unknown, .{});
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
        .{ .diff = .{ .id = "d", .path = "/tmp/file", .patch = "+change" } },
        .{ .subagent = .{ .session_id = "child", .title = "reviewer", .description = "review", .cwd = "/tmp", .state = .running } },
        .{ .compaction = .{ .id = "compact-1", .summary = "earlier work" } },
        .{ .state = .{ .state = .running } },
        .{ .plan = &.{} },
        .{ .usage = .{ .used = 1, .size = 2 } },
        .{ .title = "what this session is about" },
    };

    var seen = std.EnumSet(std.meta.Tag(Update)).empty;
    for (every) |one| {
        seen.insert(std.meta.activeTag(one));
        for ([_]Version{ .v1, .v2 }) |version| {
            const body = (try encode(arena, version, "s", one)) orelse continue;
            var parsed = try std.json.parseFromSlice(std.json.Value, arena, body, .{});
            try testing.expect(parsed.value.object.get("sessionId") != null);
            try testing.expect(parsed.value.object.get("update").?.object.get("sessionUpdate") != null);
            // The transport cannot carry an embedded newline.
            try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, body, '\n'));
        }
    }
    try testing.expectEqual(@typeInfo(Update).@"union".field_names.len, seen.count());
}

test "a newline in what the model said survives as an escape, not as a frame" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    const body = try encoded(arena, .v1, .{ .agent_message = .{ .text = "one\ntwo" } });
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, body, '\n'));
    try testing.expectEqualStrings("one\ntwo", try field(arena, body, &.{ "update", "content", "text" }));
}

test "a session's title reaches the client as its own update" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    for ([_]Version{ .v1, .v2 }) |version| {
        const body = try encoded(arena, version, .{ .title = "fix the parser" });
        try testing.expectEqualStrings(
            "session_info_update",
            try field(arena, body, &.{ "update", "sessionUpdate" }),
        );
        try testing.expectEqualStrings("fix the parser", try field(arena, body, &.{ "update", "title" }));
    }
}
