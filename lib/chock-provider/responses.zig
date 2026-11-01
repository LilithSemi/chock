//! The OpenAI Responses API adapter used by Sign in with ChatGPT.

const std = @import("std");
const message = @import("message.zig");

pub const path = "/responses";

pub const Request = struct {
    model: []const u8,
    system: []const u8,
    messages: []const message.Message,
    tools: []const message.ToolDefinition = &.{},
    provider_search: ?message.ProviderSearch = null,
};

pub fn buildRequest(allocator: std.mem.Allocator, request: Request) std.mem.Allocator.Error![]u8 {
    var arena_state: std.heap.ArenaAllocator = .init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var input: std.ArrayList(std.json.Value) = .empty;
    for (request.messages) |one| try appendMessage(arena, &input, one);

    var tools: std.ArrayList(std.json.Value) = .empty;
    for (request.tools) |tool| {
        var object: std.json.ObjectMap = .empty;
        try object.put(arena, "type", .{ .string = "function" });
        try object.put(arena, "name", .{ .string = tool.name });
        try object.put(arena, "description", .{ .string = tool.description });
        try object.put(arena, "parameters", tool.parameters);
        try tools.append(arena, .{ .object = object });
    }
    if (request.provider_search) |search| {
        var filters: std.json.ObjectMap = .empty;
        var domains = std.json.Array.init(arena);
        for (search.allowed_domains) |domain| {
            try domains.append(.{ .string = domain });
        }
        try filters.put(arena, "allowed_domains", .{ .array = domains });

        var object: std.json.ObjectMap = .empty;
        try object.put(arena, "type", .{ .string = "web_search" });
        try object.put(arena, "filters", .{ .object = filters });
        try tools.append(arena, .{ .object = object });
    }

    const wire = .{
        .model = request.model,
        .instructions = if (request.system.len == 0) null else request.system,
        .input = input.items,
        .tools = if (tools.items.len == 0) null else tools.items,
        .store = false,
        .stream = true,
    };
    return std.json.Stringify.valueAlloc(allocator, wire, .{ .emit_null_optional_fields = false });
}

fn appendMessage(arena: std.mem.Allocator, input: *std.ArrayList(std.json.Value), one: message.Message) std.mem.Allocator.Error!void {
    for (one.content) |part| switch (part) {
        .reasoning => |reasoning| {
            if (reasoning.signature.len == 0) continue;
            var object: std.json.ObjectMap = .empty;
            try object.put(arena, "type", .{ .string = "reasoning" });
            try object.put(arena, "encrypted_content", .{ .string = reasoning.signature });
            try input.append(arena, .{ .object = object });
        },
        .text, .tool_use, .tool_result, .image, .unknown => {},
    };

    var texts: std.ArrayList(u8) = .empty;
    for (one.content) |part| if (part == .text) {
        if (texts.items.len != 0) try texts.append(arena, '\n');
        try texts.appendSlice(arena, part.text);
    };
    if (texts.items.len != 0) {
        var object: std.json.ObjectMap = .empty;
        try object.put(arena, "type", .{ .string = "message" });
        try object.put(arena, "role", .{ .string = switch (one.role) {
            .user => "user",
            .assistant => "assistant",
            .system => "developer",
            .tool => "user",
            .unknown => "user",
        } });
        try object.put(arena, "content", .{ .string = texts.items });
        try input.append(arena, .{ .object = object });
    }

    for (one.content) |part| switch (part) {
        .tool_use => |call| {
            var object: std.json.ObjectMap = .empty;
            try object.put(arena, "type", .{ .string = "function_call" });
            try object.put(arena, "call_id", .{ .string = call.call_id });
            try object.put(arena, "name", .{ .string = call.tool });
            try object.put(arena, "arguments", .{ .string = call.arguments });
            try input.append(arena, .{ .object = object });
        },
        .tool_result => |result| {
            var object: std.json.ObjectMap = .empty;
            try object.put(arena, "type", .{ .string = "function_call_output" });
            try object.put(arena, "call_id", .{ .string = result.call_id });
            try object.put(arena, "output", .{ .string = result.output });
            try input.append(arena, .{ .object = object });
        },
        .text, .reasoning, .image, .unknown => {},
    };
}

pub const Piece = union(enum) {
    none,
    text: []const u8,
    reasoning: []const u8,
    tool_call: message.ToolCallFragment,
    usage: message.Usage,
    completed: ?message.Usage,
    failed,

    pub fn deinit(self: Piece, allocator: std.mem.Allocator) void {
        switch (self) {
            .text, .reasoning => |value| allocator.free(value),
            .tool_call => |fragment| {
                if (fragment.id) |value| allocator.free(value);
                if (fragment.name) |value| allocator.free(value);
                if (fragment.arguments) |value| allocator.free(value);
            },
            .none, .usage, .completed, .failed => {},
        }
    }
};

pub const DecodeError = std.json.ParseError(std.json.Scanner) || error{BodyNotObject};

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) DecodeError!Piece {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.BodyNotObject;
    const object = parsed.value.object;
    const kind_value = object.get("type") orelse return .none;
    if (kind_value != .string) return .none;
    const kind = kind_value.string;

    if (std.mem.eql(u8, kind, "response.output_text.delta")) return stringPiece(allocator, object, "delta", .text);
    if (std.mem.eql(u8, kind, "response.output_text.annotation.added")) {
        const annotation = object.get("annotation") orelse return .none;
        if (annotation != .object or
            !std.mem.eql(u8, string(annotation.object, "type") orelse "", "url_citation")) return .none;
        const url = string(annotation.object, "url") orelse return .none;
        const title = string(annotation.object, "title") orelse url;
        return .{ .text = try std.fmt.allocPrint(allocator, " ([{s}]({s}))", .{ title, url }) };
    }
    if (std.mem.eql(u8, kind, "response.reasoning_text.delta") or
        std.mem.eql(u8, kind, "response.reasoning_summary_text.delta")) return stringPiece(allocator, object, "delta", .reasoning);
    if (std.mem.eql(u8, kind, "response.function_call_arguments.delta")) {
        return .{ .tool_call = .{
            .index = nonNegative(object, "output_index") orelse 0,
            .arguments = try allocator.dupe(u8, string(object, "delta") orelse ""),
        } };
    }
    if (std.mem.eql(u8, kind, "response.output_item.added")) {
        const item = object.get("item") orelse return .none;
        if (item != .object or !std.mem.eql(u8, string(item.object, "type") orelse "", "function_call")) return .none;
        return .{ .tool_call = .{
            .index = nonNegative(object, "output_index") orelse 0,
            .id = try allocator.dupe(u8, string(item.object, "call_id") orelse string(item.object, "id") orelse ""),
            .name = try allocator.dupe(u8, string(item.object, "name") orelse ""),
            .arguments = try allocator.dupe(u8, string(item.object, "arguments") orelse ""),
        } };
    }
    if (std.mem.eql(u8, kind, "response.completed")) {
        const response = object.get("response") orelse return .{ .completed = null };
        if (response != .object) return .{ .completed = null };
        const usage_value = response.object.get("usage") orelse return .{ .completed = null };
        if (usage_value != .object) return .{ .completed = null };
        var usage: message.Usage = .{};
        usage.input_tokens = nonNegative(usage_value.object, "input_tokens") orelse 0;
        usage.output_tokens = nonNegative(usage_value.object, "output_tokens") orelse 0;
        if (usage_value.object.get("input_tokens_details")) |details| if (details == .object) {
            usage.cache_read_input_tokens = nonNegative(details.object, "cached_tokens") orelse 0;
        };
        return .{ .completed = usage };
    }
    if (std.mem.eql(u8, kind, "response.failed") or std.mem.eql(u8, kind, "response.incomplete") or
        std.mem.eql(u8, kind, "error")) return .failed;
    return .none;
}

fn stringPiece(allocator: std.mem.Allocator, object: std.json.ObjectMap, name: []const u8, comptime tag: std.meta.Tag(Piece)) std.mem.Allocator.Error!Piece {
    const value = string(object, name) orelse "";
    return @unionInit(Piece, @tagName(tag), try allocator.dupe(u8, value));
}

fn string(object: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = object.get(name) orelse return null;
    return if (value == .string) value.string else null;
}

fn nonNegative(object: std.json.ObjectMap, name: []const u8) ?u64 {
    const value = object.get(name) orelse return null;
    if (value != .integer or value.integer < 0) return null;
    return @intCast(value.integer);
}

test "request uses Responses history and disables storage" {
    const content = [_]message.ContentPart{.{ .text = "hello" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &content }};
    const body = try buildRequest(std.testing.allocator, .{
        .model = "gpt-test",
        .system = "be careful",
        .messages = &messages,
    });
    defer std.testing.allocator.free(body);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(false, parsed.value.object.get("store").?.bool);
    try std.testing.expectEqual(true, parsed.value.object.get("stream").?.bool);
    try std.testing.expectEqualStrings("hello", parsed.value.object.get("input").?.array.items[0].object.get("content").?.string);
}

test "provider search is constrained to the supplied domains" {
    const domains = [_][]const u8{ "example.com", "docs.ziglang.org" };
    const body = try buildRequest(std.testing.allocator, .{
        .model = "gpt-test",
        .system = "",
        .messages = &.{},
        .provider_search = .{ .allowed_domains = &domains },
    });
    defer std.testing.allocator.free(body);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();
    const tool = parsed.value.object.get("tools").?.array.items[0].object;
    try std.testing.expectEqualStrings("web_search", tool.get("type").?.string);
    const allowed = tool.get("filters").?.object.get("allowed_domains").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), allowed.len);
    try std.testing.expectEqualStrings("example.com", allowed[0].string);
    try std.testing.expectEqualStrings("docs.ziglang.org", allowed[1].string);
}

test "a search citation becomes a visible clickable markdown link" {
    const piece = try decode(std.testing.allocator,
        \\{"type":"response.output_text.annotation.added","annotation":{"type":"url_citation","url":"https://example.com/a","title":"Example"}}
    );
    defer piece.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(" ([Example](https://example.com/a))", piece.text);
}

test "stream text and function arguments become neutral deltas" {
    const text = try decode(std.testing.allocator, "{\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}");
    defer text.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("hi", text.text);
    const call = try decode(std.testing.allocator, "{\"type\":\"response.function_call_arguments.delta\",\"output_index\":2,\"delta\":\"{}\"}");
    defer call.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), call.tool_call.index);
    try std.testing.expectEqualStrings("{}", call.tool_call.arguments.?);
}
