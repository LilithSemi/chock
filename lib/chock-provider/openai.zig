//! The OpenAI compatible adapter. It covers ai& and a local llama.cpp

const std = @import("std");
const message = @import("message.zig");

pub const ToolDefinition = message.ToolDefinition;

pub const Request = struct {
    model: []const u8,
    system: []const u8,
    messages: []const message.Message,
    tools: []const ToolDefinition = &.{},
    stream: bool = false,
};

pub const WireFunctionCall = struct {
    name: []const u8,
    arguments: []const u8,
};

pub const WireToolCall = struct {
    id: []const u8,
    type: []const u8 = "function",
    function: WireFunctionCall,
};

pub const WireTextPart = struct {
    type: []const u8 = "text",
    text: []const u8,
};

pub const WireImagePart = struct {
    type: []const u8 = "image_url",
    image_url: Url,

    pub const Url = struct {
        url: []const u8,
    };
};

pub const WireContent = union(enum) {
    text: []const u8,
    parts: []const WireTextPart,
    images: []const WireImagePart,

    pub fn jsonStringify(self: WireContent, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        switch (self) {
            .text => |text| try jw.write(text),
            .parts => |parts| try jw.write(parts),
            .images => |parts| try jw.write(parts),
        }
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!WireContent {
        const value = try std.json.innerParse(std.json.Value, allocator, source, options);
        switch (value) {
            .string => |text| return .{ .text = text },
            .array => |items| {
                var parts: std.ArrayList(WireTextPart) = .empty;
                errdefer parts.deinit(allocator);
                for (items.items) |item| {
                    if (item != .object) continue;
                    const kind = item.object.get("type") orelse continue;
                    if (kind != .string or !std.mem.eql(u8, kind.string, "text")) continue;
                    const text_value = item.object.get("text") orelse continue;
                    if (text_value != .string) continue;
                    try parts.append(allocator, .{ .text = text_value.string });
                }
                return .{ .parts = try parts.toOwnedSlice(allocator) };
            },
            else => return error.UnexpectedToken,
        }
    }
};

pub const WireReasoning = struct {
    text: []const u8,
    signature: []const u8,
};

pub const WireUnknownPart = struct {
    name: []const u8,
    raw: std.json.Value,
};

pub const WireMessage = struct {
    role: []const u8,
    content: ?WireContent = null,
    tool_calls: ?[]const WireToolCall = null,
    tool_call_id: ?[]const u8 = null,
    is_error: ?bool = null,
    reasoning_content: ?[]const u8 = null,
    reasoning_signature: ?[]const u8 = null,
    reasoning_blocks: ?[]const WireReasoning = null,
    model_alias: ?[]const u8 = null,
    unknown_parts: ?[]const WireUnknownPart = null,
};

const WireFunctionDef = struct {
    name: []const u8,
    description: []const u8,
    parameters: std.json.Value,
};

const WireTool = struct {
    type: []const u8 = "function",
    function: WireFunctionDef,
};

pub const WireStreamOptions = struct {
    include_usage: bool = true,
};

const WireRequest = struct {
    model: []const u8,
    messages: []const WireMessage,
    tools: ?[]const WireTool = null,
    stream: ?bool = null,
    stream_options: ?WireStreamOptions = null,
};

pub const BuildError = std.mem.Allocator.Error;

fn base64Encode(allocator: std.mem.Allocator, bytes: []const u8) BuildError![]const u8 {
    const encoder = std.base64.standard.Encoder;
    const buf = try allocator.alloc(u8, encoder.calcSize(bytes.len));
    return encoder.encode(buf, bytes);
}

fn base64Decode(allocator: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]const u8 {
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(text) catch return text;
    const buf = try allocator.alloc(u8, size);
    decoder.decode(buf, text) catch {
        allocator.free(buf);
        return text;
    };
    return buf;
}

fn toWireMessages(allocator: std.mem.Allocator, msg: message.Message) BuildError![]const WireMessage {
    var texts: std.ArrayList([]const u8) = .empty;
    var reasoning_parts: std.ArrayList(WireReasoning) = .empty;
    var tool_calls: std.ArrayList(WireToolCall) = .empty;
    var unknown_parts: std.ArrayList(WireUnknownPart) = .empty;
    var tool_messages: std.ArrayList(WireMessage) = .empty;
    var images: std.ArrayList(WireImagePart) = .empty;

    for (msg.content) |part| {
        switch (part) {
            .text => |text_part| try texts.append(allocator, text_part),
            .reasoning => |reasoning| try reasoning_parts.append(allocator, .{
                .text = reasoning.text,
                .signature = try base64Encode(allocator, reasoning.signature),
            }),
            .tool_use => |tool_use| try tool_calls.append(allocator, .{
                .id = tool_use.call_id,
                .function = .{ .name = tool_use.tool, .arguments = tool_use.arguments },
            }),
            .tool_result => |tool_result| try tool_messages.append(allocator, .{
                .role = "tool",
                .content = .{ .text = tool_result.output },
                .tool_call_id = tool_result.call_id,
                .is_error = tool_result.is_error,
            }),
            .image => |image| try images.append(allocator, .{ .image_url = .{
                .url = try dataUrl(allocator, image.media_type, image.data),
            } }),
            .unknown => |unknown_part| try unknown_parts.append(allocator, .{
                .name = unknown_part.name,
                .raw = unknown_part.raw,
            }),
        }
    }

    const content: ?WireContent = switch (texts.items.len) {
        0 => null,
        1 => .{ .text = texts.items[0] },
        else => blk: {
            var parts: std.ArrayList(WireTextPart) = .empty;
            for (texts.items) |text| try parts.append(allocator, .{ .text = text });
            break :blk .{ .parts = try parts.toOwnedSlice(allocator) };
        },
    };

    var reasoning_content: ?[]const u8 = null;
    var reasoning_signature: ?[]const u8 = null;
    var reasoning_blocks: ?[]const WireReasoning = null;
    switch (reasoning_parts.items.len) {
        0 => {},
        1 => {
            reasoning_content = reasoning_parts.items[0].text;
            reasoning_signature = reasoning_parts.items[0].signature;
        },
        else => reasoning_blocks = reasoning_parts.items,
    }

    const primary_has_content = content != null or tool_calls.items.len != 0 or
        reasoning_content != null or reasoning_blocks != null or
        unknown_parts.items.len != 0 or msg.model_alias.len != 0;

    var result: std.ArrayList(WireMessage) = .empty;
    if (primary_has_content) {
        try result.append(allocator, .{
            .role = msg.role.wireName(),
            .content = content,
            .tool_calls = if (tool_calls.items.len == 0) null else tool_calls.items,
            .reasoning_content = reasoning_content,
            .reasoning_signature = reasoning_signature,
            .reasoning_blocks = reasoning_blocks,
            .model_alias = if (msg.model_alias.len == 0) null else msg.model_alias,
            .unknown_parts = if (unknown_parts.items.len == 0) null else unknown_parts.items,
        });
    }
    try result.appendSlice(allocator, tool_messages.items);

    // A message with role tool on this wire carries text only, so an image from a tool cannot ride in the message that answers the call. It follows as a user turn of its own instead.
    if (images.items.len != 0) {
        try result.append(allocator, .{
            .role = "user",
            .content = .{ .images = images.items },
        });
    }

    return result.toOwnedSlice(allocator);
}

fn dataUrl(
    allocator: std.mem.Allocator,
    media_type: []const u8,
    data: []const u8,
) BuildError![]const u8 {
    return std.fmt.allocPrint(allocator, "data:{s};base64,{s}", .{ media_type, data });
}

pub fn buildRequest(allocator: std.mem.Allocator, request: Request) BuildError![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var messages: std.ArrayList(WireMessage) = .empty;
    if (request.system.len != 0) {
        try messages.append(arena, .{ .role = "system", .content = .{ .text = request.system } });
    }
    for (request.messages) |msg| {
        if (request.system.len != 0 and std.meta.activeTag(msg.role) == .system) continue;
        try messages.appendSlice(arena, try toWireMessages(arena, msg));
    }

    var tools: std.ArrayList(WireTool) = .empty;
    for (request.tools) |tool| {
        try tools.append(arena, .{ .function = .{
            .name = tool.name,
            .description = tool.description,
            .parameters = tool.parameters,
        } });
    }

    const wire = WireRequest{
        .model = request.model,
        .messages = messages.items,
        .tools = if (tools.items.len == 0) null else tools.items,
        .stream = if (request.stream) true else null,
        .stream_options = if (request.stream) .{} else null,
    };
    return std.json.Stringify.valueAlloc(allocator, wire, .{ .emit_null_optional_fields = false });
}

pub const Choice = struct {
    message: WireMessage,
};

pub const Response = struct {
    choices: []const Choice,
};

pub const ParseError = std.json.ParseError(std.json.Scanner);

pub fn parseResponse(allocator: std.mem.Allocator, text: []const u8) ParseError!std.json.Parsed(Response) {
    return std.json.parseFromSlice(Response, allocator, text, .{ .ignore_unknown_fields = true });
}

fn roleFromWire(text: []const u8) message.Role {
    if (std.mem.eql(u8, text, "user")) return .user;
    if (std.mem.eql(u8, text, "assistant")) return .assistant;
    if (std.mem.eql(u8, text, "system")) return .system;
    if (std.mem.eql(u8, text, "tool")) return .tool;
    return .{ .unknown = text };
}

fn toolOutputText(allocator: std.mem.Allocator, content: ?WireContent) std.mem.Allocator.Error![]const u8 {
    const wire_content = content orelse return "";
    return switch (wire_content) {
        .text => |text| text,
        .images => "",
        .parts => |parts| blk: {
            var out: std.ArrayList(u8) = .empty;
            for (parts, 0..) |part, i| {
                if (i != 0) try out.appendSlice(allocator, "\n");
                try out.appendSlice(allocator, part.text);
            }
            break :blk try out.toOwnedSlice(allocator);
        },
    };
}

pub fn toMessage(allocator: std.mem.Allocator, wire: WireMessage) std.mem.Allocator.Error!message.Message {
    var parts: std.ArrayList(message.ContentPart) = .empty;
    errdefer parts.deinit(allocator);

    if (wire.reasoning_blocks) |blocks| {
        for (blocks) |block| {
            try parts.append(allocator, .{ .reasoning = .{
                .text = block.text,
                .signature = try base64Decode(allocator, block.signature),
            } });
        }
    } else if (wire.reasoning_content) |text| {
        try parts.append(allocator, .{ .reasoning = .{
            .text = text,
            .signature = try base64Decode(allocator, wire.reasoning_signature orelse ""),
        } });
    }

    if (wire.unknown_parts) |extras| {
        for (extras) |extra| {
            try parts.append(allocator, .{ .unknown = .{ .name = extra.name, .raw = extra.raw } });
        }
    }

    if (wire.tool_call_id) |call_id| {
        try parts.append(allocator, .{ .tool_result = .{
            .call_id = call_id,
            .output = try toolOutputText(allocator, wire.content),
            .is_error = wire.is_error orelse false,
        } });
    } else if (wire.content) |content| {
        switch (content) {
            .text => |text| if (text.len != 0) try parts.append(allocator, .{ .text = text }),
            .parts => |wire_parts| for (wire_parts) |part| {
                if (part.text.len != 0) try parts.append(allocator, .{ .text = part.text });
            },
            .images => {},
        }
    }

    if (wire.tool_calls) |calls| {
        for (calls) |call| {
            try parts.append(allocator, .{ .tool_use = .{
                .call_id = call.id,
                .tool = call.function.name,
                .arguments = call.function.arguments,
            } });
        }
    }

    return .{
        .role = roleFromWire(wire.role),
        .content = try parts.toOwnedSlice(allocator),
        .model_alias = wire.model_alias orelse "",
    };
}

comptime {
    // Request must hold no field that could carry a credential, so a caller cannot pass an API key into buildRequest even by mistake: the key belongs in the Authorization header, set outside this function and never in the body chockd logs.
    for (@typeInfo(Request).@"struct".fields) |field| {
        const suspect = std.mem.indexOf(u8, field.name, "key") != null or
            std.mem.indexOf(u8, field.name, "token") != null or
            std.mem.indexOf(u8, field.name, "secret") != null or
            std.mem.indexOf(u8, field.name, "auth") != null or
            std.mem.indexOf(u8, field.name, "credential") != null;
        if (suspect) @compileError("Request must not hold a credential field: " ++ field.name);
    }
}

fn parseWireRequest(allocator: std.mem.Allocator, body: []const u8) !std.json.Parsed(WireRequest) {
    return std.json.parseFromSlice(WireRequest, allocator, body, .{ .ignore_unknown_fields = true });
}

test "a request holds the system prompt, the messages, and the tools, in the shape the wire expects" {
    const allocator = std.testing.allocator;

    const schema_text =
        \\{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}
    ;
    const schema = try std.json.parseFromSlice(std.json.Value, allocator, schema_text, .{});
    defer schema.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "list the files" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};
    const tools = [_]ToolDefinition{.{
        .name = "list_files",
        .description = "List files in the workspace",
        .parameters = schema.value,
    }};

    const body = try buildRequest(allocator, .{
        .model = "glm4.7-flash:A3B",
        .system = "You are a careful coding agent.",
        .messages = &messages,
        .tools = &tools,
    });
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("glm4.7-flash:A3B", parsed.value.object.get("model").?.string);

    const wire_messages = parsed.value.object.get("messages").?.array;
    try std.testing.expectEqual(@as(usize, 2), wire_messages.items.len);
    try std.testing.expectEqualStrings("system", wire_messages.items[0].object.get("role").?.string);
    try std.testing.expectEqualStrings(
        "You are a careful coding agent.",
        wire_messages.items[0].object.get("content").?.string,
    );
    try std.testing.expectEqualStrings("user", wire_messages.items[1].object.get("role").?.string);
    try std.testing.expectEqualStrings("list the files", wire_messages.items[1].object.get("content").?.string);

    const wire_tools = parsed.value.object.get("tools").?.array;
    try std.testing.expectEqual(@as(usize, 1), wire_tools.items.len);
    const function = wire_tools.items[0].object.get("function").?.object;
    try std.testing.expectEqualStrings("list_files", function.get("name").?.string);
    try std.testing.expectEqualStrings("object", function.get("parameters").?.object.get("type").?.string);
}

test "a reasoning block with a signature survives neutral to wire to neutral, through buildRequest" {
    const allocator = std.testing.allocator;
    const signature = "EqoBCkYIARgCIkAy9f3KX+j2rAStub8vQ==";
    const content = [_]message.ContentPart{
        .{ .reasoning = .{ .text = "considering the approach", .signature = signature } },
    };
    const messages = [_]message.Message{.{ .role = .assistant, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "glm4.7-flash:A3B", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseWireRequest(allocator, body);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 1), parsed.value.messages.len);
    const round_tripped = try toMessage(allocator, parsed.value.messages[0]);
    defer allocator.free(round_tripped.content);
    defer allocator.free(round_tripped.content[0].reasoning.signature);

    try std.testing.expectEqual(@as(usize, 1), round_tripped.content.len);
    try std.testing.expectEqualStrings(signature, round_tripped.content[0].reasoning.signature);
    try std.testing.expectEqualStrings("considering the approach", round_tripped.content[0].reasoning.text);
}

test "a tool call in a response becomes a neutral tool call with its arguments intact" {
    const allocator = std.testing.allocator;
    const text =
        \\{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"finish_reason":"tool_calls",
        \\"message":{"role":"assistant","content":null,"tool_calls":[
        \\{"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"README.md\"}"}}
        \\]}}]}
    ;
    const parsed = try parseResponse(allocator, text);
    defer parsed.deinit();

    const neutral = try toMessage(allocator, parsed.value.choices[0].message);
    defer allocator.free(neutral.content);

    try std.testing.expectEqual(@as(usize, 1), neutral.content.len);
    const call: message.ToolCall = neutral.content[0].tool_use;
    try std.testing.expectEqualStrings("call_1", call.call_id);
    try std.testing.expectEqualStrings("read_file", call.tool);
    try std.testing.expectEqualStrings("{\"path\":\"README.md\"}", call.arguments);
}

test "an unknown field in a response does not fail the parse" {
    const allocator = std.testing.allocator;
    const text =
        \\{"id":"chatcmpl-2","object":"chat.completion","model":"glm4.7-flash:A3B",
        \\"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12},
        \\"choices":[{"index":0,"finish_reason":"stop",
        \\"message":{"role":"assistant","content":"done","from_a_future_field":{"nested":true}}}]}
    ;
    const parsed = try parseResponse(allocator, text);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("done", parsed.value.choices[0].message.content.?.text);
}

test "the request never holds the API key" {
    const allocator = std.testing.allocator;
    const content = [_]message.ContentPart{.{ .text = "hello" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &content }};

    const body = try buildRequest(allocator, .{
        .model = "glm4.7-flash:A3B",
        .system = "",
        .messages = &messages,
    });
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    var field_count: usize = 0;
    var it = parsed.value.object.iterator();
    while (it.next()) |_| field_count += 1;
    try std.testing.expectEqual(@as(usize, 2), field_count);
    try std.testing.expect(parsed.value.object.get("model") != null);
    try std.testing.expect(parsed.value.object.get("messages") != null);
    try std.testing.expect(parsed.value.object.get("tools") == null);
    try std.testing.expect(parsed.value.object.get("api_key") == null);
    try std.testing.expect(parsed.value.object.get("authorization") == null);
}

test "a tool result becomes its own wire message, not glued onto the text of the same message" {
    const allocator = std.testing.allocator;
    const content = [_]message.ContentPart{
        .{ .text = "here is the answer" },
        .{ .tool_result = .{ .call_id = "call_9", .output = "FILE BODY", .is_error = false } },
    };
    const messages = [_]message.Message{.{ .role = .assistant, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "glm4.7-flash:A3B", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseWireRequest(allocator, body);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 2), parsed.value.messages.len);

    const text_msg = parsed.value.messages[0];
    try std.testing.expectEqualStrings("assistant", text_msg.role);
    try std.testing.expectEqualStrings("here is the answer", text_msg.content.?.text);
    try std.testing.expectEqual(@as(?[]const u8, null), text_msg.tool_call_id);

    const tool_msg = parsed.value.messages[1];
    try std.testing.expectEqualStrings("tool", tool_msg.role);
    try std.testing.expectEqualStrings("FILE BODY", tool_msg.content.?.text);
    try std.testing.expectEqualStrings("call_9", tool_msg.tool_call_id.?);

    const round_text = try toMessage(allocator, text_msg);
    defer allocator.free(round_text.content);
    try std.testing.expectEqual(@as(usize, 1), round_text.content.len);
    try std.testing.expectEqualStrings("here is the answer", round_text.content[0].text);

    const round_tool = try toMessage(allocator, tool_msg);
    defer allocator.free(round_tool.content);
    try std.testing.expectEqual(@as(usize, 1), round_tool.content.len);
    try std.testing.expectEqualStrings("FILE BODY", round_tool.content[0].tool_result.output);
}

test "a failed tool result's is_error survives neutral to wire to neutral" {
    const allocator = std.testing.allocator;
    const content = [_]message.ContentPart{
        .{ .tool_result = .{ .call_id = "call_1", .output = "not found", .is_error = true } },
    };
    const messages = [_]message.Message{.{ .role = .tool, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "glm4.7-flash:A3B", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseWireRequest(allocator, body);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 1), parsed.value.messages.len);
    try std.testing.expectEqual(true, parsed.value.messages[0].is_error.?);

    const round_tripped = try toMessage(allocator, parsed.value.messages[0]);
    defer allocator.free(round_tripped.content);
    try std.testing.expectEqual(true, round_tripped.content[0].tool_result.is_error);
}

test "multiple text parts keep their order and stay distinct, with no separator concatenation" {
    const allocator = std.testing.allocator;
    const content = [_]message.ContentPart{
        .{ .text = "first" },
        .{ .text = "second" },
        .{ .text = "third" },
    };
    const messages = [_]message.Message{.{ .role = .user, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "glm4.7-flash:A3B", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseWireRequest(allocator, body);
    defer parsed.deinit();

    const wire_parts = parsed.value.messages[0].content.?.parts;
    try std.testing.expectEqual(@as(usize, 3), wire_parts.len);
    try std.testing.expectEqualStrings("first", wire_parts[0].text);
    try std.testing.expectEqualStrings("second", wire_parts[1].text);
    try std.testing.expectEqualStrings("third", wire_parts[2].text);

    const round_tripped = try toMessage(allocator, parsed.value.messages[0]);
    defer allocator.free(round_tripped.content);
    try std.testing.expectEqual(@as(usize, 3), round_tripped.content.len);
    try std.testing.expectEqualStrings("first", round_tripped.content[0].text);
    try std.testing.expectEqualStrings("second", round_tripped.content[1].text);
    try std.testing.expectEqualStrings("third", round_tripped.content[2].text);
}

test "two tool results in one message become two separate wire tool messages, not one glued output" {
    const allocator = std.testing.allocator;
    const content = [_]message.ContentPart{
        .{ .tool_result = .{ .call_id = "call_a", .output = "result A", .is_error = false } },
        .{ .tool_result = .{ .call_id = "call_b", .output = "result B", .is_error = true } },
    };
    const messages = [_]message.Message{.{ .role = .assistant, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "glm4.7-flash:A3B", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseWireRequest(allocator, body);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 2), parsed.value.messages.len);
    try std.testing.expectEqualStrings("call_a", parsed.value.messages[0].tool_call_id.?);
    try std.testing.expectEqualStrings("result A", parsed.value.messages[0].content.?.text);
    try std.testing.expectEqual(false, parsed.value.messages[0].is_error.?);
    try std.testing.expectEqualStrings("call_b", parsed.value.messages[1].tool_call_id.?);
    try std.testing.expectEqualStrings("result B", parsed.value.messages[1].content.?.text);
    try std.testing.expectEqual(true, parsed.value.messages[1].is_error.?);
}

test "two reasoning blocks each keep their own signature, not collapsed to the last one" {
    const allocator = std.testing.allocator;
    const content = [_]message.ContentPart{
        .{ .reasoning = .{ .text = "step one", .signature = "sig-one" } },
        .{ .reasoning = .{ .text = "step two", .signature = "sig-two" } },
    };
    const messages = [_]message.Message{.{ .role = .assistant, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "glm4.7-flash:A3B", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseWireRequest(allocator, body);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(?[]const u8, null), parsed.value.messages[0].reasoning_content);
    try std.testing.expectEqual(@as(usize, 2), parsed.value.messages[0].reasoning_blocks.?.len);

    const round_tripped = try toMessage(allocator, parsed.value.messages[0]);
    defer allocator.free(round_tripped.content);
    defer allocator.free(round_tripped.content[0].reasoning.signature);
    defer allocator.free(round_tripped.content[1].reasoning.signature);
    try std.testing.expectEqual(@as(usize, 2), round_tripped.content.len);
    try std.testing.expectEqualStrings("step one", round_tripped.content[0].reasoning.text);
    try std.testing.expectEqualStrings("sig-one", round_tripped.content[0].reasoning.signature);
    try std.testing.expectEqualStrings("step two", round_tripped.content[1].reasoning.text);
    try std.testing.expectEqualStrings("sig-two", round_tripped.content[1].reasoning.signature);
}

test "an unknown content part survives the wire round trip instead of being dropped" {
    const allocator = std.testing.allocator;
    const raw = try std.json.parseFromSlice(std.json.Value, allocator, "{\"note\":\"from a future kind\"}", .{});
    defer raw.deinit();
    const content = [_]message.ContentPart{
        .{ .unknown = .{ .name = "citation", .raw = raw.value } },
    };
    const messages = [_]message.Message{.{ .role = .assistant, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "glm4.7-flash:A3B", .system = "", .messages = &messages });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"role\":\"assistant\",\"unknown_parts\"") != null);

    const parsed = try parseWireRequest(allocator, body);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.messages.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.messages[0].unknown_parts.?.len);
    try std.testing.expectEqualStrings("citation", parsed.value.messages[0].unknown_parts.?[0].name);

    const round_tripped = try toMessage(allocator, parsed.value.messages[0]);
    defer allocator.free(round_tripped.content);
    try std.testing.expectEqual(@as(usize, 1), round_tripped.content.len);
    try std.testing.expectEqualStrings("citation", round_tripped.content[0].unknown.name);
    try std.testing.expectEqualStrings(
        "from a future kind",
        round_tripped.content[0].unknown.raw.object.get("note").?.string,
    );
}

test "model_alias reaches the wire and comes back on the round trip" {
    const allocator = std.testing.allocator;
    const content = [_]message.ContentPart{.{ .text = "considering options" }};
    const messages = [_]message.Message{.{ .role = .assistant, .content = &content, .model_alias = "coder-local" }};

    const body = try buildRequest(allocator, .{ .model = "glm4.7-flash:A3B", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseWireRequest(allocator, body);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("coder-local", parsed.value.messages[0].model_alias.?);

    const round_tripped = try toMessage(allocator, parsed.value.messages[0]);
    defer allocator.free(round_tripped.content);
    try std.testing.expectEqualStrings("coder-local", round_tripped.model_alias);
}

test "a reasoning signature with invalid UTF-8 bytes serializes as a JSON string, not an array of numbers" {
    const allocator = std.testing.allocator;
    const raw_signature = [_]u8{ 'S', 'I', 'G', 1, 0xFF };
    const content = [_]message.ContentPart{
        .{ .reasoning = .{ .text = "thinking", .signature = &raw_signature } },
    };
    const messages = [_]message.Message{.{ .role = .assistant, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "glm4.7-flash:A3B", .system = "", .messages = &messages });
    defer allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"reasoning_signature\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"reasoning_signature\":[") == null);

    const parsed = try parseWireRequest(allocator, body);
    defer parsed.deinit();
    const round_tripped = try toMessage(allocator, parsed.value.messages[0]);
    defer allocator.free(round_tripped.content);
    defer allocator.free(round_tripped.content[0].reasoning.signature);
    try std.testing.expectEqualSlices(u8, &raw_signature, round_tripped.content[0].reasoning.signature);
}

test "a system value and a system role message do not both reach the wire" {
    const allocator = std.testing.allocator;
    const system_content = [_]message.ContentPart{.{ .text = "legacy system text" }};
    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{
        .{ .role = .system, .content = &system_content },
        .{ .role = .user, .content = &user_content },
    };

    const body = try buildRequest(allocator, .{
        .model = "glm4.7-flash:A3B",
        .system = "You are helpful.",
        .messages = &messages,
    });
    defer allocator.free(body);

    const parsed = try parseWireRequest(allocator, body);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 2), parsed.value.messages.len);
    try std.testing.expectEqualStrings("system", parsed.value.messages[0].role);
    try std.testing.expectEqualStrings("You are helpful.", parsed.value.messages[0].content.?.text);
    try std.testing.expectEqualStrings("user", parsed.value.messages[1].role);
}

test "a system role message still reaches the wire when the request carries no system prompt of its own" {
    const allocator = std.testing.allocator;
    const system_content = [_]message.ContentPart{.{ .text = "only system source" }};
    const messages = [_]message.Message{.{ .role = .system, .content = &system_content }};

    const body = try buildRequest(allocator, .{ .model = "glm4.7-flash:A3B", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseWireRequest(allocator, body);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.messages.len);
    try std.testing.expectEqualStrings("system", parsed.value.messages[0].role);
    try std.testing.expectEqualStrings("only system source", parsed.value.messages[0].content.?.text);
}

test "a tool's image follows the tool message as a user turn holding a data URL" {
    const allocator = std.testing.allocator;
    const data = "iVBORw0KGgoAAAANSUhEUg==";
    const content = [_]message.ContentPart{
        .{ .tool_result = .{ .call_id = "call_1", .output = "read it", .is_error = false } },
        .{ .image = .{ .call_id = "call_1", .media_type = "image/png", .data = data } },
    };
    const messages = [_]message.Message{.{ .role = .tool, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "m", .system = "", .messages = &messages });
    defer allocator.free(body);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const wire_messages = parsed.value.object.get("messages").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), wire_messages.len);

    try std.testing.expectEqualStrings("tool", wire_messages[0].object.get("role").?.string);
    try std.testing.expectEqualStrings("read it", wire_messages[0].object.get("content").?.string);
    try std.testing.expectEqualStrings("user", wire_messages[1].object.get("role").?.string);

    const parts = wire_messages[1].object.get("content").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), parts.len);
    try std.testing.expectEqualStrings("image_url", parts[0].object.get("type").?.string);
    const url = parts[0].object.get("image_url").?.object.get("url").?.string;
    try std.testing.expectEqualStrings("data:image/png;base64," ++ data, url);
}

test "a response whose content is an array of text parts degrades to the text instead of failing to parse" {
    const allocator = std.testing.allocator;
    const text =
        \\{"choices":[{"message":{"role":"assistant","content":[
        \\{"type":"text","text":"first"},
        \\{"type":"image_url","image_url":{"url":"https://example.com/x.png"}},
        \\{"type":"text","text":"second"}
        \\]}}]}
    ;
    const parsed = try parseResponse(allocator, text);
    defer parsed.deinit();

    const neutral = try toMessage(allocator, parsed.value.choices[0].message);
    defer allocator.free(neutral.content);

    try std.testing.expectEqual(@as(usize, 2), neutral.content.len);
    try std.testing.expectEqualStrings("first", neutral.content[0].text);
    try std.testing.expectEqualStrings("second", neutral.content[1].text);
}
