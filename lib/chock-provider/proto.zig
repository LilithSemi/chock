//! Converts between provider-neutral records and Chock's durable log records.

const std = @import("std");
const provider = @import("llm-provider").message;
const chock_proto = @import("chock-proto");
const event = chock_proto.event;

pub fn fromOwnedMessage(
    arena: std.mem.Allocator,
    source: chock_proto.state.OwnedMessage,
) std.mem.Allocator.Error!provider.Message {
    const content = try arena.alloc(provider.ContentPart, source.content.len);
    for (source.content, content) |part, *slot| slot.* = try fromEventPart(arena, part);
    return .{
        .role = fromEventRole(source.role),
        .content = content,
    };
}

pub fn fromEventMessage(
    arena: std.mem.Allocator,
    source: event.Message,
) std.mem.Allocator.Error!provider.Message {
    const content = try arena.alloc(provider.ContentPart, source.content.len);
    for (source.content, content) |part, *slot| slot.* = try fromEventPart(arena, part);
    return .{
        .role = fromEventRole(source.role),
        .content = content,
        .model_alias = source.model_alias,
        .extra = try fromEventExtra(arena, source.extra),
    };
}

pub fn toEventMessage(
    arena: std.mem.Allocator,
    source: provider.Message,
) std.mem.Allocator.Error!event.Message {
    const content = try arena.alloc(event.ContentPart, source.content.len);
    for (source.content, content) |part, *slot| slot.* = try toEventPart(arena, part);
    return .{
        .role = toEventRole(source.role),
        .content = content,
        .model_alias = source.model_alias,
        .extra = try toEventExtra(arena, source.extra),
    };
}

pub fn toEventUsage(
    arena: std.mem.Allocator,
    source: provider.Usage,
) std.mem.Allocator.Error!event.Usage {
    return .{
        .input_tokens = source.input_tokens,
        .output_tokens = source.output_tokens,
        .cache_creation_input_tokens = source.cache_creation_input_tokens,
        .cache_read_input_tokens = source.cache_read_input_tokens,
        .cost = try toEventCost(arena, source.cost),
        .price_table_version = source.price_table_version,
        .model = source.model,
        .model_alias = source.model_alias,
        .request_id = source.request_id,
        .inference_ms = source.inference_ms,
        .reasoning_effort_applied = source.reasoning_effort_applied,
        .extra = try toEventExtra(arena, source.extra),
    };
}

fn fromEventRole(source: event.Role) provider.Role {
    return switch (source) {
        .user => .user,
        .assistant => .assistant,
        .system => .system,
        .tool => .tool,
        .unknown => |name| .{ .unknown = name },
    };
}

fn toEventRole(source: provider.Role) event.Role {
    return switch (source) {
        .user => .user,
        .assistant => .assistant,
        .system => .system,
        .tool => .tool,
        .unknown => |name| .{ .unknown = name },
    };
}

fn fromEventPart(
    arena: std.mem.Allocator,
    source: event.ContentPart,
) std.mem.Allocator.Error!provider.ContentPart {
    return switch (source) {
        .text => |text| .{ .text = text },
        .reasoning => |one| .{ .reasoning = .{
            .text = one.text,
            .signature = one.signature,
            .extra = try fromEventExtra(arena, one.extra),
        } },
        .tool_use => |one| .{ .tool_use = .{
            .call_id = one.call_id,
            .tool = one.tool,
            .arguments = one.arguments,
            .extra = try fromEventExtra(arena, one.extra),
        } },
        .tool_result => |one| .{ .tool_result = .{
            .call_id = one.call_id,
            .output = one.output,
            .is_error = one.is_error,
            .extra = try fromEventExtra(arena, one.extra),
        } },
        .image => |one| .{ .image = .{
            .call_id = one.call_id,
            .media_type = one.media_type,
            .data = one.data,
            .extra = try fromEventExtra(arena, one.extra),
        } },
        .unknown => |one| .{ .unknown = .{ .name = one.name, .raw = one.raw } },
    };
}

fn toEventPart(
    arena: std.mem.Allocator,
    source: provider.ContentPart,
) std.mem.Allocator.Error!event.ContentPart {
    return switch (source) {
        .text => |text| .{ .text = text },
        .reasoning => |one| .{ .reasoning = .{
            .text = one.text,
            .signature = one.signature,
            .extra = try toEventExtra(arena, one.extra),
        } },
        .tool_use => |one| .{ .tool_use = .{
            .call_id = one.call_id,
            .tool = one.tool,
            .arguments = one.arguments,
            .extra = try toEventExtra(arena, one.extra),
        } },
        .tool_result => |one| .{ .tool_result = .{
            .call_id = one.call_id,
            .output = one.output,
            .is_error = one.is_error,
            .extra = try toEventExtra(arena, one.extra),
        } },
        .image => |one| .{ .image = .{
            .call_id = one.call_id,
            .media_type = one.media_type,
            .data = one.data,
            .extra = try toEventExtra(arena, one.extra),
        } },
        .unknown => |one| .{ .unknown = .{ .name = one.name, .raw = one.raw } },
    };
}

fn toEventCost(
    arena: std.mem.Allocator,
    source: provider.Cost,
) std.mem.Allocator.Error!event.Cost {
    return switch (source) {
        .known => |amount| .{ .known = .{
            .value = amount.value,
            .currency = amount.currency,
            .extra = try toEventExtra(arena, amount.extra),
        } },
        .free => .free,
        .unknown => .unknown,
        .unrecognized => |one| .{ .unrecognized = .{ .name = one.name, .raw = one.raw } },
    };
}

fn fromEventExtra(
    arena: std.mem.Allocator,
    source: event.Extra,
) std.mem.Allocator.Error!provider.Extra {
    const members = try arena.alloc(provider.ExtraMember, source.members.len);
    for (source.members, members) |member, *slot| slot.* = .{
        .name = member.name,
        .value = member.value,
    };
    return .{ .members = members };
}

fn toEventExtra(
    arena: std.mem.Allocator,
    source: provider.Extra,
) std.mem.Allocator.Error!event.Extra {
    const members = try arena.alloc(event.ExtraMember, source.members.len);
    for (source.members, members) |member, *slot| slot.* = .{
        .name = member.name,
        .value = member.value,
    };
    return .{ .members = members };
}

test "a message crosses the provider boundary without losing future fields" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const extras = [_]event.ExtraMember{.{
        .name = "future",
        .value = .{ .integer = 7 },
    }};
    const content = [_]event.ContentPart{
        .{ .reasoning = .{
            .text = "thinking",
            .signature = "signed",
            .extra = .{ .members = &extras },
        } },
        .{ .unknown = .{ .name = "future_part", .raw = .{ .bool = true } } },
    };
    const original = event.Message{
        .role = .{ .unknown = "future_role" },
        .content = &content,
        .model_alias = "work",
        .extra = .{ .members = &extras },
    };

    const neutral = try fromEventMessage(arena, original);
    const restored = try toEventMessage(arena, neutral);
    const before = try std.json.Stringify.valueAlloc(arena, original, .{});
    const after = try std.json.Stringify.valueAlloc(arena, restored, .{});
    try std.testing.expectEqualStrings(before, after);
}
