//! The Anthropic native adapter, one of the two wire formats Chock speaks.

const std = @import("std");
const message = @import("message.zig");
const sse = @import("sse.zig");

pub const ToolDefinition = message.ToolDefinition;

pub const Usage = message.Usage;

pub const path = "/messages";

pub const key_header = "x-api-key";

pub const version_header = "anthropic-version";
pub const version = "2023-06-01";

pub const default_max_tokens: u32 = 8192;

pub const Request = struct {
    model: []const u8,
    system: []const u8,
    messages: []const message.Message,
    tools: []const ToolDefinition = &.{},
    max_tokens: u32 = default_max_tokens,
    stream: bool = false,
};

pub const WireBlock = union(enum) {
    text: Text,
    thinking: Thinking,
    tool_use: ToolUse,
    tool_result: ToolResult,
    image: Image,
    unknown: Unknown,

    pub const Text = struct {
        text: []const u8,
    };

    pub const Thinking = struct {
        thinking: []const u8,
        signature: []const u8,
    };

    pub const ToolUse = struct {
        id: []const u8,
        name: []const u8,
        input: std.json.Value,
    };

    pub const ToolResult = struct {
        tool_use_id: []const u8,
        content: []const u8,
        is_error: bool,
    };

    pub const Image = struct {
        media_type: []const u8,
        data: []const u8,
    };

    pub const Unknown = struct {
        name: []const u8,
        raw: std.json.Value,
    };

    pub fn jsonStringify(self: WireBlock, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        switch (self) {
            .text => |block| try jw.write(.{ .type = "text", .text = block.text }),
            .thinking => |block| try jw.write(.{
                .type = "thinking",
                .thinking = block.thinking,
                .signature = block.signature,
            }),
            .tool_use => |block| try jw.write(.{
                .type = "tool_use",
                .id = block.id,
                .name = block.name,
                .input = block.input,
            }),
            .tool_result => |block| try jw.write(.{
                .type = "tool_result",
                .tool_use_id = block.tool_use_id,
                .content = block.content,
                .is_error = block.is_error,
            }),
            .image => |block| try jw.write(.{
                .type = "image",
                .source = .{
                    .type = "base64",
                    .media_type = block.media_type,
                    .data = block.data,
                },
            }),
            .unknown => |block| try jw.write(block.raw),
        }
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!WireBlock {
        const value = try std.json.innerParse(std.json.Value, allocator, source, options);
        return fromValue(allocator, value);
    }

    pub fn fromValue(
        allocator: std.mem.Allocator,
        value: std.json.Value,
    ) std.mem.Allocator.Error!WireBlock {
        if (value != .object) return unknownBlock(allocator, "", value);
        const object = value.object;
        const kind = object.get("type") orelse return unknownBlock(allocator, "", value);
        if (kind != .string) return unknownBlock(allocator, "", value);

        if (std.mem.eql(u8, kind.string, "text")) {
            return .{ .text = .{ .text = stringField(object, "text") } };
        }
        if (std.mem.eql(u8, kind.string, "thinking")) {
            return .{ .thinking = .{
                .thinking = stringField(object, "thinking"),
                .signature = stringField(object, "signature"),
            } };
        }
        if (std.mem.eql(u8, kind.string, "tool_use")) {
            return .{ .tool_use = .{
                .id = stringField(object, "id"),
                .name = stringField(object, "name"),
                .input = object.get("input") orelse .{ .object = .empty },
            } };
        }
        if (std.mem.eql(u8, kind.string, "tool_result")) {
            const is_error = object.get("is_error") orelse std.json.Value{ .bool = false };
            return .{ .tool_result = .{
                .tool_use_id = stringField(object, "tool_use_id"),
                .content = toolResultText(object.get("content")),
                .is_error = is_error == .bool and is_error.bool,
            } };
        }
        if (std.mem.eql(u8, kind.string, "image")) {
            const source = object.get("source") orelse return unknownBlock(allocator, kind.string, value);
            if (source != .object) return unknownBlock(allocator, kind.string, value);
            return .{ .image = .{
                .media_type = stringField(source.object, "media_type"),
                .data = stringField(source.object, "data"),
            } };
        }
        return unknownBlock(allocator, kind.string, value);
    }

    fn unknownBlock(
        allocator: std.mem.Allocator,
        name: []const u8,
        value: std.json.Value,
    ) std.mem.Allocator.Error!WireBlock {
        _ = allocator;
        return .{ .unknown = .{ .name = name, .raw = value } };
    }
};

fn stringField(object: std.json.ObjectMap, name: []const u8) []const u8 {
    const value = object.get(name) orelse return "";
    return if (value == .string) value.string else "";
}

fn toolResultText(content: ?std.json.Value) []const u8 {
    const value = content orelse return "";
    switch (value) {
        .string => |text| return text,
        .array => |items| {
            for (items.items) |item| {
                if (item != .object) continue;
                const kind = item.object.get("type") orelse continue;
                if (kind != .string or !std.mem.eql(u8, kind.string, "text")) continue;
                return stringField(item.object, "text");
            }
            return "";
        },
        else => return "",
    }
}

pub const WireMessage = struct {
    role: []const u8,
    content: []const WireBlock,
};

const WireTool = struct {
    name: []const u8,
    description: []const u8,
    input_schema: std.json.Value,
};

const WireRequest = struct {
    model: []const u8,
    max_tokens: u32,
    messages: []const WireMessage,
    system: ?[]const u8 = null,
    tools: ?[]const WireTool = null,
    stream: ?bool = null,
};

pub const BuildError = std.mem.Allocator.Error;

fn parseArguments(
    arena: std.mem.Allocator,
    arguments: []const u8,
) std.mem.Allocator.Error!std.json.Value {
    const empty = std.json.Value{ .object = .empty };
    if (arguments.len == 0) return empty;
    const parsed = std.json.parseFromSliceLeaky(
        std.json.Value,
        arena,
        arguments,
        .{},
    ) catch return empty;
    return if (parsed == .object) parsed else empty;
}

fn toWireMessages(
    arena: std.mem.Allocator,
    msg: message.Message,
) BuildError![]const WireMessage {
    var own: std.ArrayList(WireBlock) = .empty;
    var results: std.ArrayList(WireBlock) = .empty;

    for (msg.content) |part| {
        switch (part) {
            .text => |text| {
                if (text.len != 0) try own.append(arena, .{ .text = .{ .text = text } });
            },
            .reasoning => |reasoning| try own.append(arena, .{ .thinking = .{
                .thinking = reasoning.text,
                .signature = reasoning.signature,
            } }),
            .tool_use => |tool_use| try own.append(arena, .{ .tool_use = .{
                .id = tool_use.call_id,
                .name = tool_use.tool,
                .input = try parseArguments(arena, tool_use.arguments),
            } }),
            .tool_result => |tool_result| try results.append(arena, .{ .tool_result = .{
                .tool_use_id = tool_result.call_id,
                .content = tool_result.output,
                .is_error = tool_result.is_error,
            } }),
            .image => |image| try own.append(arena, .{ .image = .{
                .media_type = image.media_type,
                .data = image.data,
            } }),
            .unknown => |unknown| try own.append(arena, .{ .unknown = .{
                .name = unknown.name,
                .raw = unknown.raw,
            } }),
        }
    }

    var out: std.ArrayList(WireMessage) = .empty;
    const assistant = std.meta.activeTag(msg.role) == .assistant;
    if (assistant) {
        if (own.items.len != 0) {
            try out.append(arena, .{ .role = "assistant", .content = own.items });
        }
        if (results.items.len != 0) {
            try out.append(arena, .{ .role = "user", .content = results.items });
        }
        return out.toOwnedSlice(arena);
    }

    try results.appendSlice(arena, own.items);
    if (results.items.len != 0) {
        try out.append(arena, .{ .role = "user", .content = results.items });
    }
    return out.toOwnedSlice(arena);
}

fn joinText(arena: std.mem.Allocator, msg: message.Message) BuildError![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (msg.content) |part| {
        if (part != .text) continue;
        if (out.items.len != 0) try out.append(arena, '\n');
        try out.appendSlice(arena, part.text);
    }
    return out.toOwnedSlice(arena);
}

fn holdsToolResult(wire_message: WireMessage) bool {
    for (wire_message.content) |block| {
        if (block == .tool_result) return true;
    }
    return false;
}

pub fn buildRequest(allocator: std.mem.Allocator, request: Request) BuildError![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var system: []const u8 = request.system;
    var messages: std.ArrayList(WireMessage) = .empty;
    for (request.messages) |msg| {
        if (std.meta.activeTag(msg.role) == .system) {
            if (system.len == 0) system = try joinText(arena, msg);
            continue;
        }
        for (try toWireMessages(arena, msg)) |wire_message| {
            if (messages.items.len != 0 and !holdsToolResult(wire_message)) {
                const last = &messages.items[messages.items.len - 1];
                if (std.mem.eql(u8, last.role, wire_message.role)) {
                    last.content = try std.mem.concat(
                        arena,
                        WireBlock,
                        &.{ last.content, wire_message.content },
                    );
                    continue;
                }
            }
            try messages.append(arena, wire_message);
        }
    }

    var tools: std.ArrayList(WireTool) = .empty;
    for (request.tools) |tool| {
        try tools.append(arena, .{
            .name = tool.name,
            .description = tool.description,
            .input_schema = tool.parameters,
        });
    }

    const wire = WireRequest{
        .model = request.model,
        .max_tokens = request.max_tokens,
        .messages = messages.items,
        .system = if (system.len == 0) null else system,
        .tools = if (tools.items.len == 0) null else tools.items,
        .stream = if (request.stream) true else null,
    };
    return std.json.Stringify.valueAlloc(allocator, wire, .{ .emit_null_optional_fields = false });
}

pub const WireUsage = struct {
    input_tokens: ?u64 = null,
    output_tokens: ?u64 = null,
    cache_creation_input_tokens: ?u64 = null,
    cache_read_input_tokens: ?u64 = null,
};

pub const Response = struct {
    role: []const u8 = "assistant",
    content: []const WireBlock = &.{},
    model: []const u8 = "",
    stop_reason: ?[]const u8 = null,
    usage: WireUsage = .{},
};

pub const ParseError = std.json.ParseError(std.json.Scanner);

pub fn parseResponse(
    allocator: std.mem.Allocator,
    text: []const u8,
) ParseError!std.json.Parsed(Response) {
    return std.json.parseFromSlice(Response, allocator, text, .{ .ignore_unknown_fields = true });
}

fn roleFromWire(text: []const u8) message.Role {
    if (std.mem.eql(u8, text, "assistant")) return .assistant;
    if (std.mem.eql(u8, text, "user")) return .user;
    return .{ .unknown = text };
}

pub fn toContent(
    allocator: std.mem.Allocator,
    blocks: []const WireBlock,
) std.mem.Allocator.Error![]message.ContentPart {
    var parts: std.ArrayList(message.ContentPart) = .empty;
    errdefer parts.deinit(allocator);

    for (blocks) |block| {
        switch (block) {
            .text => |text| try parts.append(allocator, .{ .text = text.text }),
            .thinking => |thinking| try parts.append(allocator, .{
                .reasoning = .{
                    .text = thinking.thinking,
                    .signature = thinking.signature,
                },
            }),
            .tool_use => |tool_use| try parts.append(allocator, .{ .tool_use = .{
                .call_id = tool_use.id,
                .tool = tool_use.name,
                .arguments = try std.json.Stringify.valueAlloc(allocator, tool_use.input, .{}),
            } }),
            .image => |image| try parts.append(allocator, .{ .image = .{
                .call_id = "",
                .media_type = image.media_type,
                .data = image.data,
            } }),
            .tool_result => |tool_result| try parts.append(allocator, .{ .tool_result = .{
                .call_id = tool_result.tool_use_id,
                .output = tool_result.content,
                .is_error = tool_result.is_error,
            } }),
            .unknown => |unknown| try parts.append(allocator, .{ .unknown = .{
                .name = unknown.name,
                .raw = unknown.raw,
            } }),
        }
    }
    return parts.toOwnedSlice(allocator);
}

pub fn toMessage(
    allocator: std.mem.Allocator,
    response: Response,
) std.mem.Allocator.Error!message.Message {
    return .{
        .role = roleFromWire(response.role),
        .content = try toContent(allocator, response.content),
        .model_alias = "",
    };
}

pub const StreamError = struct {
    kind: []const u8,
    text: []const u8,
};

pub const Piece = union(enum) {
    none,
    text: []const u8,
    reasoning: []const u8,
    reasoning_signature: []const u8,
    tool_call: message.ToolCallFragment,
    usage: Usage,
    stream_error: StreamError,
};

const BlockKind = enum { text, thinking, tool_use, other };

pub const DecodeError = std.mem.Allocator.Error || std.json.ParseError(std.json.Scanner) || error{
    BodyNotObject,
    MissingEventType,
    BlockIndexInvalid,
};

pub const StopDetails = struct {
    category: []const u8 = "",
    explanation: []const u8 = "",
};

pub const max_stop_category: usize = 64;

pub const max_stop_explanation: usize = 512;

fn stopDetailsOf(delta: std.json.ObjectMap) StopDetails {
    const value = delta.get("stop_details") orelse return .{};
    if (value != .object) return .{};
    return .{
        .category = stringField(value.object, "category"),
        .explanation = stringField(value.object, "explanation"),
    };
}

fn keepCut(buffer: []u8, text: []const u8) usize {
    const kept = @min(text.len, buffer.len);
    @memcpy(buffer[0..kept], text[0..kept]);
    return kept;
}

pub const Decoder = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    kinds: std.AutoArrayHashMapUnmanaged(usize, BlockKind) = .empty,
    usage: Usage = .{},
    saw_usage: bool = false,
    stop_reason_text: std.ArrayList(u8) = .empty,
    stop_category_buffer: [max_stop_category]u8 = @splat(0),
    stop_category_len: usize = 0,
    stop_explanation_buffer: [max_stop_explanation]u8 = @splat(0),
    stop_explanation_len: usize = 0,
    saw_message_stop: bool = false,

    pub fn init(allocator: std.mem.Allocator) Decoder {
        return .{ .allocator = allocator, .arena = std.heap.ArenaAllocator.init(allocator) };
    }

    pub fn deinit(self: *Decoder) void {
        self.stop_reason_text.deinit(self.allocator);
        self.kinds.deinit(self.allocator);
        self.arena.deinit();
    }

    pub fn stopReason(self: *const Decoder) []const u8 {
        return self.stop_reason_text.items;
    }

    pub fn stopDetails(self: *const Decoder) StopDetails {
        return .{
            .category = self.stop_category_buffer[0..self.stop_category_len],
            .explanation = self.stop_explanation_buffer[0..self.stop_explanation_len],
        };
    }

    pub fn feed(self: *Decoder, json_text: []const u8) DecodeError!Piece {
        _ = self.arena.reset(.retain_capacity);
        const value = try std.json.parseFromSliceLeaky(
            std.json.Value,
            self.arena.allocator(),
            json_text,
            .{},
        );
        return self.feedValue(value);
    }

    fn feedValue(self: *Decoder, value: std.json.Value) DecodeError!Piece {
        if (value != .object) return error.BodyNotObject;
        const body = value.object;
        const kind_value = body.get("type") orelse return error.MissingEventType;
        if (kind_value != .string) return error.MissingEventType;
        const kind = kind_value.string;

        if (std.mem.eql(u8, kind, "error")) {
            const detail = body.get("error");
            if (detail != null and detail.? == .object) {
                return .{ .stream_error = .{
                    .kind = stringField(detail.?.object, "type"),
                    .text = stringField(detail.?.object, "message"),
                } };
            }
            return .{ .stream_error = .{ .kind = "error", .text = "" } };
        }

        if (std.mem.eql(u8, kind, "message_start")) {
            const msg = body.get("message") orelse return .none;
            if (msg != .object) return .none;
            if (msg.object.get("usage")) |usage_value| {
                self.applyUsage(usage_value);
                return .{ .usage = self.usage };
            }
            return .none;
        }

        if (std.mem.eql(u8, kind, "message_delta")) {
            if (body.get("delta")) |delta| {
                if (delta == .object) {
                    const reason = stringField(delta.object, "stop_reason");
                    if (reason.len != 0) {
                        self.stop_reason_text.clearRetainingCapacity();
                        try self.stop_reason_text.appendSlice(self.allocator, reason);
                        const details = stopDetailsOf(delta.object);
                        self.stop_category_len = keepCut(
                            &self.stop_category_buffer,
                            details.category,
                        );
                        self.stop_explanation_len = keepCut(
                            &self.stop_explanation_buffer,
                            details.explanation,
                        );
                    }
                }
            }
            if (body.get("usage")) |usage_value| {
                self.applyUsage(usage_value);
                return .{ .usage = self.usage };
            }
            return .none;
        }

        if (std.mem.eql(u8, kind, "content_block_start")) {
            const index = try blockIndex(body);
            const block_value = body.get("content_block") orelse return .none;
            const block = try WireBlock.fromValue(self.allocator, block_value);
            try self.kinds.put(self.allocator, index, switch (block) {
                .text => .text,
                .thinking => .thinking,
                .tool_use => .tool_use,
                else => .other,
            });
            switch (block) {
                .tool_use => |tool_use| return .{ .tool_call = .{
                    .index = index,
                    .id = tool_use.id,
                    .name = tool_use.name,
                } },
                .text => |text| return if (text.text.len == 0) .none else .{ .text = text.text },
                .thinking => |thinking| return if (thinking.thinking.len == 0)
                    .none
                else
                    .{ .reasoning = thinking.thinking },
                else => return .none,
            }
        }

        if (std.mem.eql(u8, kind, "content_block_delta")) {
            const index = try blockIndex(body);
            const delta_value = body.get("delta") orelse return .none;
            if (delta_value != .object) return .none;
            const delta = delta_value.object;
            const delta_kind = stringField(delta, "type");

            if (std.mem.eql(u8, delta_kind, "text_delta")) {
                return .{ .text = stringField(delta, "text") };
            }
            if (std.mem.eql(u8, delta_kind, "thinking_delta")) {
                return .{ .reasoning = stringField(delta, "thinking") };
            }
            if (std.mem.eql(u8, delta_kind, "signature_delta")) {
                return .{ .reasoning_signature = stringField(delta, "signature") };
            }
            if (std.mem.eql(u8, delta_kind, "input_json_delta")) {
                return .{ .tool_call = .{
                    .index = index,
                    .arguments = stringField(delta, "partial_json"),
                } };
            }
            const block_kind = self.kinds.get(index) orelse return .none;
            return switch (block_kind) {
                .text => .{ .text = stringField(delta, "text") },
                .thinking => .{ .reasoning = stringField(delta, "thinking") },
                .tool_use => .{ .tool_call = .{
                    .index = index,
                    .arguments = stringField(delta, "partial_json"),
                } },
                .other => .none,
            };
        }

        if (std.mem.eql(u8, kind, "message_stop")) {
            self.saw_message_stop = true;
            return .none;
        }

        return .none;
    }

    fn applyUsage(self: *Decoder, value: std.json.Value) void {
        if (value != .object) return;
        const object = value.object;
        self.saw_usage = true;
        if (countField(object, "input_tokens")) |count| self.usage.input_tokens = count;
        if (countField(object, "output_tokens")) |count| self.usage.output_tokens = count;
        if (countField(object, "cache_creation_input_tokens")) |count| {
            self.usage.cache_creation_input_tokens = count;
        }
        if (countField(object, "cache_read_input_tokens")) |count| {
            self.usage.cache_read_input_tokens = count;
        }
    }

    fn countField(object: std.json.ObjectMap, name: []const u8) ?u64 {
        const value = object.get(name) orelse return null;
        if (value != .integer) return null;
        if (value.integer < 0) return null;
        return @intCast(value.integer);
    }

    fn blockIndex(body: std.json.ObjectMap) DecodeError!usize {
        const value = body.get("index") orelse return error.BlockIndexInvalid;
        if (value != .integer or value.integer < 0) return error.BlockIndexInvalid;
        return @intCast(value.integer);
    }
};

comptime {
    // Request has nowhere to put a credential, so this guard stops a caller from passing one into buildRequest by mistake. The key goes in the x-api-key header instead, set outside this file and never logged.
    for (@typeInfo(Request).@"struct".fields) |field| {
        if (std.mem.eql(u8, field.name, "max_tokens")) continue;
        const suspect = std.mem.indexOf(u8, field.name, "key") != null or
            std.mem.indexOf(u8, field.name, "token") != null or
            std.mem.indexOf(u8, field.name, "secret") != null or
            std.mem.indexOf(u8, field.name, "auth") != null or
            std.mem.indexOf(u8, field.name, "credential") != null;
        if (suspect) @compileError("Request must not hold a credential field: " ++ field.name);
    }
}

const testing = std.testing;

fn parseBody(allocator: std.mem.Allocator, body: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, allocator, body, .{});
}

test "the system prompt is a top level field and never a message" {
    const allocator = testing.allocator;
    const user_content = [_]message.ContentPart{.{ .text = "list the files" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const body = try buildRequest(allocator, .{
        .model = "claude-opus-5",
        .system = "You are a careful coding agent.",
        .messages = &messages,
    });
    defer allocator.free(body);

    const parsed = try parseBody(allocator, body);
    defer parsed.deinit();

    try testing.expectEqualStrings(
        "You are a careful coding agent.",
        parsed.value.object.get("system").?.string,
    );
    const wire_messages = parsed.value.object.get("messages").?.array;
    try testing.expectEqual(@as(usize, 1), wire_messages.items.len);
    try testing.expectEqualStrings("user", wire_messages.items[0].object.get("role").?.string);
    for (wire_messages.items) |wire_message| {
        try testing.expect(!std.mem.eql(u8, wire_message.object.get("role").?.string, "system"));
    }
}

test "a system role message folds into the top level field instead of being dropped" {
    const allocator = testing.allocator;
    const system_content = [_]message.ContentPart{.{ .text = "from an older history" }};
    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{
        .{ .role = .system, .content = &system_content },
        .{ .role = .user, .content = &user_content },
    };

    const body = try buildRequest(allocator, .{ .model = "claude-opus-5", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseBody(allocator, body);
    defer parsed.deinit();
    try testing.expectEqualStrings("from an older history", parsed.value.object.get("system").?.string);
    try testing.expectEqual(@as(usize, 1), parsed.value.object.get("messages").?.array.items.len);
}

test "a harness notice after a tool result joins that turn, and never makes two user turns" {
    const allocator = testing.allocator;
    const asked = [_]message.ContentPart{.{ .tool_use = .{
        .call_id = "call_1",
        .tool = "read_file",
        .arguments = "{\"path\":\"a.zig\"}",
    } }};
    const answered = [_]message.ContentPart{.{ .tool_result = .{
        .call_id = "call_1",
        .output = "the file",
        .is_error = false,
    } }};
    const notice = [_]message.ContentPart{.{ .text = "[chock] You read a.zig again." }};
    const messages = [_]message.Message{
        .{ .role = .assistant, .content = &asked },
        .{ .role = .tool, .content = &answered },
        .{ .role = .user, .content = &notice },
    };

    const body = try buildRequest(allocator, .{ .model = "claude-opus-5", .system = "s", .messages = &messages });
    defer allocator.free(body);
    const parsed = try parseBody(allocator, body);
    defer parsed.deinit();

    const wire_messages = parsed.value.object.get("messages").?.array.items;
    try testing.expectEqual(@as(usize, 2), wire_messages.len);
    try testing.expectEqualStrings("assistant", wire_messages[0].object.get("role").?.string);
    try testing.expectEqualStrings("user", wire_messages[1].object.get("role").?.string);

    const blocks = wire_messages[1].object.get("content").?.array.items;
    try testing.expectEqual(@as(usize, 2), blocks.len);
    try testing.expectEqualStrings("tool_result", blocks[0].object.get("type").?.string);
    try testing.expectEqualStrings("text", blocks[1].object.get("type").?.string);

    var previous: []const u8 = "";
    for (wire_messages) |wire_message| {
        const role = wire_message.object.get("role").?.string;
        try testing.expect(!std.mem.eql(u8, role, previous));
        previous = role;
    }
}

test "two turns that both carry a tool result keep their own turns" {
    const allocator = testing.allocator;
    const first_result = [_]message.ContentPart{.{ .tool_result = .{
        .call_id = "call_1",
        .output = "one",
        .is_error = false,
    } }};
    const notice = [_]message.ContentPart{.{ .text = "[chock] a notice" }};
    const second_result = [_]message.ContentPart{.{ .tool_result = .{
        .call_id = "call_2",
        .output = "two",
        .is_error = false,
    } }};
    const messages = [_]message.Message{
        .{ .role = .tool, .content = &first_result },
        .{ .role = .user, .content = &notice },
        .{ .role = .tool, .content = &second_result },
    };

    const body = try buildRequest(allocator, .{ .model = "claude-opus-5", .system = "s", .messages = &messages });
    defer allocator.free(body);
    const parsed = try parseBody(allocator, body);
    defer parsed.deinit();

    const wire_messages = parsed.value.object.get("messages").?.array.items;
    try testing.expectEqual(@as(usize, 2), wire_messages.len);
    try testing.expectEqual(@as(usize, 2), wire_messages[0].object.get("content").?.array.items.len);
    try testing.expectEqual(@as(usize, 1), wire_messages[1].object.get("content").?.array.items.len);
}

test "a tool's image rides after its result, in the same user turn" {
    const allocator = testing.allocator;
    const data = "iVBORw0KGgoAAAANSUhEUg==";
    const content = [_]message.ContentPart{
        .{ .tool_result = .{ .call_id = "toolu_1", .output = "read it", .is_error = false } },
        .{ .image = .{ .call_id = "toolu_1", .media_type = "image/png", .data = data } },
    };
    const messages = [_]message.Message{.{ .role = .tool, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "claude-opus-5", .system = "s", .messages = &messages });
    defer allocator.free(body);
    const parsed = try parseBody(allocator, body);
    defer parsed.deinit();

    const wire_messages = parsed.value.object.get("messages").?.array.items;
    try testing.expectEqual(@as(usize, 1), wire_messages.len);
    try testing.expectEqualStrings("user", wire_messages[0].object.get("role").?.string);

    const blocks = wire_messages[0].object.get("content").?.array.items;
    try testing.expectEqual(@as(usize, 2), blocks.len);
    try testing.expectEqualStrings("tool_result", blocks[0].object.get("type").?.string);
    try testing.expectEqualStrings("image", blocks[1].object.get("type").?.string);

    const source = blocks[1].object.get("source").?.object;
    try testing.expectEqualStrings("base64", source.get("type").?.string);
    try testing.expectEqualStrings("image/png", source.get("media_type").?.string);
    try testing.expectEqualStrings(data, source.get("data").?.string);

    const reversed = [_]message.ContentPart{
        .{ .image = .{ .call_id = "toolu_1", .media_type = "image/png", .data = data } },
        .{ .tool_result = .{ .call_id = "toolu_1", .output = "read it", .is_error = false } },
    };
    const reversed_messages = [_]message.Message{.{ .role = .tool, .content = &reversed }};
    const reversed_body = try buildRequest(allocator, .{
        .model = "claude-opus-5",
        .system = "s",
        .messages = &reversed_messages,
    });
    defer allocator.free(reversed_body);
    const reversed_parsed = try parseBody(allocator, reversed_body);
    defer reversed_parsed.deinit();

    const reversed_blocks = reversed_parsed.value.object.get("messages").?.array
        .items[0].object.get("content").?.array.items;
    try testing.expectEqual(@as(usize, 2), reversed_blocks.len);
    try testing.expectEqualStrings("tool_result", reversed_blocks[0].object.get("type").?.string);
    try testing.expectEqualStrings("image", reversed_blocks[1].object.get("type").?.string);
}

test "an image block read off this wire keeps its media type and its bytes" {
    const allocator = testing.allocator;
    const body =
        \\{"role":"user","content":[{"type":"image","source":
        \\{"type":"base64","media_type":"image/webp","data":"UklGRg=="}}]}
    ;
    const parsed = try std.json.parseFromSlice(WireMessage, allocator, body, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    const parts = try toContent(allocator, parsed.value.content);
    defer allocator.free(parts);
    try testing.expectEqual(@as(usize, 1), parts.len);
    try testing.expectEqualStrings("image/webp", parts[0].image.media_type);
    try testing.expectEqualStrings("UklGRg==", parts[0].image.data);
}

test "max_tokens is always on the wire, because this provider requires it" {
    const allocator = testing.allocator;
    const content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "claude-opus-5", .system = "", .messages = &messages });
    defer allocator.free(body);
    const parsed = try parseBody(allocator, body);
    defer parsed.deinit();
    try testing.expectEqual(@as(i64, default_max_tokens), parsed.value.object.get("max_tokens").?.integer);

    const bigger = try buildRequest(allocator, .{
        .model = "claude-opus-5",
        .system = "",
        .messages = &messages,
        .max_tokens = 64000,
    });
    defer allocator.free(bigger);
    const parsed_bigger = try parseBody(allocator, bigger);
    defer parsed_bigger.deinit();
    try testing.expectEqual(@as(i64, 64000), parsed_bigger.value.object.get("max_tokens").?.integer);
}

test "a tool result is a content block in a user message, and no message carries a tool role" {
    const allocator = testing.allocator;
    const content = [_]message.ContentPart{
        .{ .tool_result = .{ .call_id = "toolu_1", .output = "FILE BODY", .is_error = false } },
    };
    const messages = [_]message.Message{.{ .role = .tool, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "claude-opus-5", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseBody(allocator, body);
    defer parsed.deinit();

    const wire_messages = parsed.value.object.get("messages").?.array;
    try testing.expectEqual(@as(usize, 1), wire_messages.items.len);
    try testing.expectEqualStrings("user", wire_messages.items[0].object.get("role").?.string);

    const blocks = wire_messages.items[0].object.get("content").?.array;
    try testing.expectEqual(@as(usize, 1), blocks.items.len);
    try testing.expectEqualStrings("tool_result", blocks.items[0].object.get("type").?.string);
    try testing.expectEqualStrings("toolu_1", blocks.items[0].object.get("tool_use_id").?.string);
    try testing.expectEqualStrings("FILE BODY", blocks.items[0].object.get("content").?.string);

    try testing.expect(std.mem.indexOf(u8, body, "\"role\":\"tool\"") == null);
}

test "a tool result block comes before the text of the same user turn" {
    const allocator = testing.allocator;
    const content = [_]message.ContentPart{
        .{ .text = "and here is what I found" },
        .{ .tool_result = .{ .call_id = "toolu_1", .output = "ok", .is_error = false } },
    };
    const messages = [_]message.Message{.{ .role = .user, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "claude-opus-5", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseBody(allocator, body);
    defer parsed.deinit();
    const blocks = parsed.value.object.get("messages").?.array.items[0].object.get("content").?.array;
    try testing.expectEqual(@as(usize, 2), blocks.items.len);
    try testing.expectEqualStrings("tool_result", blocks.items[0].object.get("type").?.string);
    try testing.expectEqualStrings("text", blocks.items[1].object.get("type").?.string);
}

test "a thinking block returns with the same signature it arrived with" {
    const allocator = testing.allocator;
    const signature = "EqoBCkYIARgCIkAy9f3KX+j2rAStub8vQ==";
    const content = [_]message.ContentPart{
        .{ .reasoning = .{ .text = "considering the approach", .signature = signature } },
    };
    const messages = [_]message.Message{.{ .role = .assistant, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "claude-opus-5", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseBody(allocator, body);
    defer parsed.deinit();
    const block = parsed.value.object.get("messages").?.array.items[0].object.get("content").?.array.items[0];
    try testing.expectEqualStrings("thinking", block.object.get("type").?.string);
    try testing.expectEqualStrings(signature, block.object.get("signature").?.string);

    const reply_text =
        \\{"role":"assistant","content":[
        \\{"type":"thinking","thinking":"considering the approach","signature":"EqoBCkYIARgCIkAy9f3KX+j2rAStub8vQ=="}
        \\]}
    ;
    const reply = try parseResponse(allocator, reply_text);
    defer reply.deinit();
    const neutral = try toMessage(allocator, reply.value);
    defer allocator.free(neutral.content);
    try testing.expectEqual(@as(usize, 1), neutral.content.len);
    try testing.expectEqualStrings(signature, neutral.content[0].reasoning.signature);
    try testing.expectEqualStrings("considering the approach", neutral.content[0].reasoning.text);
}

test "a tool call's arguments nest as an object here and come back as JSON text" {
    const allocator = testing.allocator;
    const content = [_]message.ContentPart{
        .{ .tool_use = .{
            .call_id = "toolu_1",
            .tool = "read_file",
            .arguments = "{\"path\":\"README.md\"}",
        } },
    };
    const messages = [_]message.Message{.{ .role = .assistant, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "claude-opus-5", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseBody(allocator, body);
    defer parsed.deinit();
    const block = parsed.value.object.get("messages").?.array.items[0].object.get("content").?.array.items[0];
    try testing.expectEqualStrings("tool_use", block.object.get("type").?.string);
    try testing.expectEqual(std.json.Value.object, std.meta.activeTag(block.object.get("input").?));
    try testing.expectEqualStrings("README.md", block.object.get("input").?.object.get("path").?.string);

    const reply_text =
        \\{"role":"assistant","content":[
        \\{"type":"tool_use","id":"toolu_1","name":"read_file","input":{"path":"README.md"}}
        \\]}
    ;
    const reply = try parseResponse(allocator, reply_text);
    defer reply.deinit();
    const neutral = try toMessage(allocator, reply.value);
    defer allocator.free(neutral.content);
    defer allocator.free(neutral.content[0].tool_use.arguments);
    try testing.expectEqualStrings("toolu_1", neutral.content[0].tool_use.call_id);
    try testing.expectEqualStrings("read_file", neutral.content[0].tool_use.tool);
    try testing.expectEqualStrings("{\"path\":\"README.md\"}", neutral.content[0].tool_use.arguments);
}

test "arguments that are not valid JSON become an empty object rather than malformed wire text" {
    const allocator = testing.allocator;
    const content = [_]message.ContentPart{
        .{ .tool_use = .{ .call_id = "toolu_1", .tool = "read_file", .arguments = "{\"path\":" } },
    };
    const messages = [_]message.Message{.{ .role = .assistant, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "claude-opus-5", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseBody(allocator, body);
    defer parsed.deinit();
    const block = parsed.value.object.get("messages").?.array.items[0].object.get("content").?.array.items[0];
    const input = block.object.get("input").?;
    try testing.expectEqual(std.json.Value.object, std.meta.activeTag(input));
    try testing.expectEqual(@as(usize, 0), input.object.count());
}

test "the request never holds the API key" {
    const allocator = testing.allocator;
    const content = [_]message.ContentPart{.{ .text = "hello" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &content }};

    const body = try buildRequest(allocator, .{ .model = "claude-opus-5", .system = "", .messages = &messages });
    defer allocator.free(body);

    const parsed = try parseBody(allocator, body);
    defer parsed.deinit();

    var field_count: usize = 0;
    var it = parsed.value.object.iterator();
    while (it.next()) |_| field_count += 1;
    try testing.expectEqual(@as(usize, 3), field_count);
    try testing.expect(parsed.value.object.get("model") != null);
    try testing.expect(parsed.value.object.get("max_tokens") != null);
    try testing.expect(parsed.value.object.get("messages") != null);
    try testing.expect(parsed.value.object.get("api_key") == null);
    try testing.expect(parsed.value.object.get("x-api-key") == null);
}

test "a content block type this reader does not know survives the round trip whole" {
    const allocator = testing.allocator;
    const reply_text =
        \\{"role":"assistant","content":[
        \\{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{"query":"zig"}}
        \\]}
    ;
    const reply = try parseResponse(allocator, reply_text);
    defer reply.deinit();

    const neutral = try toMessage(allocator, reply.value);
    defer allocator.free(neutral.content);
    try testing.expectEqual(@as(usize, 1), neutral.content.len);
    try testing.expectEqualStrings("server_tool_use", neutral.content[0].unknown.name);

    const messages = [_]message.Message{.{ .role = .assistant, .content = neutral.content }};
    const body = try buildRequest(allocator, .{ .model = "claude-opus-5", .system = "", .messages = &messages });
    defer allocator.free(body);
    try testing.expect(std.mem.indexOf(u8, body, "\"server_tool_use\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "srvtoolu_1") != null);
}

fn feedEvent(decoder: *Decoder, json_text: []const u8) !Piece {
    return decoder.feed(json_text);
}

test "the pieces of a streamed reply come out as text, reasoning, a signature, and a tool call" {
    const allocator = testing.allocator;
    var decoder = Decoder.init(allocator);
    defer decoder.deinit();

    try testing.expectEqual(Piece.none, try feedEvent(&decoder,
        \\{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}
    ));
    const reasoning = try feedEvent(&decoder,
        \\{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"weighing it"}}
    );
    try testing.expectEqualStrings("weighing it", reasoning.reasoning);
    const signature = try feedEvent(&decoder,
        \\{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"SIG=="}}
    );
    try testing.expectEqualStrings("SIG==", signature.reasoning_signature);

    const text = try feedEvent(&decoder,
        \\{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"I will read it."}}
    );
    try testing.expectEqualStrings("I will read it.", text.text);

    const call_start = try feedEvent(&decoder,
        \\{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_1","name":"read_file","input":{}}}
    );
    try testing.expectEqual(@as(usize, 2), call_start.tool_call.index);
    try testing.expectEqualStrings("toolu_1", call_start.tool_call.id.?);
    try testing.expectEqualStrings("read_file", call_start.tool_call.name.?);
    try testing.expectEqual(@as(?[]const u8, null), call_start.tool_call.arguments);

    const call_delta = try feedEvent(&decoder,
        \\{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"path\":"}}
    );
    try testing.expectEqualStrings("{\"path\":", call_delta.tool_call.arguments.?);

    try testing.expectEqual(Piece.none, try feedEvent(&decoder,
        \\{"type":"ping"}
    ));
    try testing.expectEqual(Piece.none, try feedEvent(&decoder,
        \\{"type":"content_block_stop","index":2}
    ));
    try testing.expectEqual(Piece.none, try feedEvent(&decoder,
        \\{"type":"message_stop"}
    ));
}

test "a tool call's partial JSON assembles through the one assembler both adapters share" {
    const allocator = testing.allocator;
    var decoder = Decoder.init(allocator);
    defer decoder.deinit();
    var assembler = sse.ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    const events = [_][]const u8{
        \\{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"read_file","input":{}}}
        ,
        \\{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"pa"}}
        ,
        \\{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"th\":\"REA"}}
        ,
        \\{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"DME.md\"}"}}
        ,
    };
    for (events) |body| {
        const piece = try feedEvent(&decoder, body);
        if (piece == .tool_call) try assembler.feed(piece.tool_call);
    }

    const calls = try assembler.finished();
    defer sse.freeFinished(allocator, calls);
    try testing.expectEqual(@as(usize, 1), calls.len);
    try testing.expect(calls[0].complete);
    try testing.expectEqualStrings("toolu_1", calls[0].id);
    try testing.expectEqualStrings("read_file", calls[0].name);
    try testing.expectEqualStrings("{\"path\":\"README.md\"}", calls[0].arguments);
}

test "cumulative message_delta usage gives the last value and not the sum" {
    // The counts in message_delta events are cumulative, not incremental: summing them instead of keeping the latest value overcounts every turn with more than one delta.
    const allocator = testing.allocator;
    var decoder = Decoder.init(allocator);
    defer decoder.deinit();

    const start = try feedEvent(&decoder,
        \\{"type":"message_start","message":{"id":"msg_1","role":"assistant","usage":{"input_tokens":1200,"output_tokens":1,"cache_read_input_tokens":800}}}
    );
    try testing.expectEqual(@as(u64, 1200), start.usage.input_tokens);
    try testing.expectEqual(@as(u64, 1), start.usage.output_tokens);

    const rising = [_][]const u8{
        \\{"type":"message_delta","delta":{"stop_reason":null},"usage":{"output_tokens":40}}
        ,
        \\{"type":"message_delta","delta":{"stop_reason":null},"usage":{"output_tokens":90}}
        ,
        \\{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":150}}
        ,
    };
    for (rising) |body| _ = try feedEvent(&decoder, body);

    try testing.expectEqual(@as(u64, 150), decoder.usage.output_tokens);
    try testing.expectEqual(@as(u64, 1200), decoder.usage.input_tokens);
    try testing.expectEqual(@as(u64, 800), decoder.usage.cache_read_input_tokens);
    try testing.expectEqualStrings("tool_use", decoder.stopReason());
    try testing.expect(decoder.saw_usage);
    try testing.expectEqual(@as(u64, 2150), decoder.usage.totalTokens());
    try testing.expectEqualStrings("", decoder.stopDetails().category);
    try testing.expectEqualStrings("", decoder.stopDetails().explanation);
}

test "a refusal keeps the category and the explanation the wire sent with it" {
    const allocator = testing.allocator;
    var decoder = Decoder.init(allocator);
    defer decoder.deinit();

    _ = try feedEvent(&decoder,
        \\{"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber","explanation":"This request was declined because it could enable cyber harm."}},"usage":{"output_tokens":12}}
    );

    try testing.expectEqualStrings("refusal", decoder.stopReason());
    try testing.expectEqualStrings("cyber", decoder.stopDetails().category);
    try testing.expectEqualStrings(
        "This request was declined because it could enable cyber harm.",
        decoder.stopDetails().explanation,
    );
}

test "a refusal with both details null keeps neither, and invents neither" {
    const allocator = testing.allocator;
    var decoder = Decoder.init(allocator);
    defer decoder.deinit();

    _ = try feedEvent(&decoder,
        \\{"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"type":"refusal","category":null,"explanation":null}},"usage":{"output_tokens":3}}
    );

    try testing.expectEqualStrings("refusal", decoder.stopReason());
    try testing.expectEqualStrings("", decoder.stopDetails().category);
    try testing.expectEqualStrings("", decoder.stopDetails().explanation);
}

test "a refusal with one detail null keeps the other one" {
    const allocator = testing.allocator;
    var decoder = Decoder.init(allocator);
    defer decoder.deinit();

    _ = try feedEvent(&decoder,
        \\{"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"type":"refusal","category":null,"explanation":"This request was declined."}},"usage":{"output_tokens":3}}
    );
    try testing.expectEqualStrings("", decoder.stopDetails().category);
    try testing.expectEqualStrings("This request was declined.", decoder.stopDetails().explanation);

    _ = try feedEvent(&decoder,
        \\{"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber","explanation":null}},"usage":{"output_tokens":4}}
    );
    try testing.expectEqualStrings("cyber", decoder.stopDetails().category);
    try testing.expectEqualStrings("", decoder.stopDetails().explanation);
}

test "an explanation longer than the bound is cut, and never dropped" {
    const allocator = testing.allocator;
    var decoder = Decoder.init(allocator);
    defer decoder.deinit();

    const long = "n" ** (max_stop_explanation + 200);
    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"refusal\"," ++
            "\"stop_details\":{{\"type\":\"refusal\",\"category\":\"{s}\"," ++
            "\"explanation\":\"{s}\"}}}}}}",
        .{ "c" ** (max_stop_category + 8), long },
    );
    defer allocator.free(body);
    _ = try feedEvent(&decoder, body);

    const details = decoder.stopDetails();
    try testing.expectEqual(max_stop_category, details.category.len);
    try testing.expectEqual(max_stop_explanation, details.explanation.len);
    try testing.expectEqualStrings(long[0..max_stop_explanation], details.explanation);
}

test "a provider that reports no usage leaves saw_usage false, so zero is not read as free" {
    const allocator = testing.allocator;
    var decoder = Decoder.init(allocator);
    defer decoder.deinit();

    _ = try feedEvent(&decoder,
        \\{"type":"message_start","message":{"id":"msg_1","role":"assistant"}}
    );
    _ = try feedEvent(&decoder,
        \\{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}
    );
    try testing.expect(!decoder.saw_usage);
    try testing.expectEqual(@as(u64, 0), decoder.usage.totalTokens());
    try testing.expectEqual(message.Cost.unknown, std.meta.activeTag(decoder.usage.cost));
}

test "an error event inside the stream is a stream error and not another delta" {
    const allocator = testing.allocator;
    var decoder = Decoder.init(allocator);
    defer decoder.deinit();

    const piece = try feedEvent(&decoder,
        \\{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}
    );
    try testing.expectEqualStrings("overloaded_error", piece.stream_error.kind);
    try testing.expectEqualStrings("Overloaded", piece.stream_error.text);
}

test "a delta of an unknown type still reaches the buffer its block opened with" {
    const allocator = testing.allocator;
    var decoder = Decoder.init(allocator);
    defer decoder.deinit();

    _ = try feedEvent(&decoder,
        \\{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}
    );
    const piece = try feedEvent(&decoder,
        \\{"type":"content_block_delta","index":0,"delta":{"type":"text_delta_v2","text":"still text"}}
    );
    try testing.expectEqualStrings("still text", piece.text);
}

test "an event body with no type is refused rather than read as an empty delta" {
    const allocator = testing.allocator;
    var decoder = Decoder.init(allocator);
    defer decoder.deinit();
    try testing.expectError(error.MissingEventType, decoder.feed("{}"));
    try testing.expectError(error.BodyNotObject, decoder.feed("[]"));
    try testing.expectError(
        error.BlockIndexInvalid,
        decoder.feed("{\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"x\"}}"),
    );
}
