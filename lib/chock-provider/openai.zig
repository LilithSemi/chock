//! The OpenAI compatible adapter. It covers ai& and a local llama.cpp
//! server. It translates the neutral
//! message type in `message.zig` to and from the JSON body an OpenAI
//! compatible chat completion endpoint expects.
//!
//! The adapter never sees a credential. `Request` has no field that could
//! hold one, and a caller sends the returned body with the key in the
//! `Authorization` header of the HTTP request, never in this text. That
//! matters because the body is exactly what a session log ends up holding,
//! and `chockd` re-serves that log to other clients.
//!
//! A tool result is its own message on the wire, with role "tool" and its
//! own `tool_call_id`. It is never folded into another message's `content`:
//! a neutral message that carries a tool result becomes a separate wire
//! message for that result, in the shape a real OpenAI compatible server
//! expects, so the result reads back the same way it went out.

const std = @import("std");
const message = @import("message.zig");

/// See `message.ToolDefinition`'s own doc comment: the canonical definition
/// lives there, neutral, so `Client`'s interface never has to import this
/// file to name a tool's shape. Aliased, not copied, for the reason
/// `message.zig`'s own top comment gives.
pub const ToolDefinition = message.ToolDefinition;

/// Everything one call to the model needs, in the shape `buildRequest` reads
/// to build the wire body. `Client.HttpClient` is the only caller that builds
/// one of these: it converts from `message.Request`, the neutral shape
/// `Client`'s own interface carries, adding the one field, `stream`, that
/// only matters once a request is about to become wire bytes. `Request`
/// holds no field for the endpoint, the model backend, or a credential,
/// because none of those belong in a value that a caller might pass to
/// `buildRequest` and then write into the session log.
pub const Request = struct {
    model: []const u8,
    /// Becomes the first message, with role "system", when not empty. A
    /// message in `messages` that already has role "system" is not
    /// duplicated on top of this: see `buildRequest`.
    system: []const u8,
    messages: []const message.Message,
    tools: []const ToolDefinition = &.{},
    /// Ask the server for a server sent event stream instead of one whole
    /// JSON body. `Client.HttpClient` always sets this itself before it
    /// builds a request, so a caller of `Client.send` never has to set it.
    /// The field stays here, not private to `Client.zig`, because
    /// `buildRequest` is the one place that knows how to put it on the
    /// wire, the same reasoning `tools` already follows.
    stream: bool = false,
};

/// One function call inside a wire message's `tool_calls` array.
pub const WireFunctionCall = struct {
    name: []const u8,
    /// The call's arguments, already serialized to JSON text. OpenAI's
    /// schema carries this as a JSON string, not a nested object, and
    /// `message.ToolCall.arguments` already keeps the same shape, so no
    /// re-encoding happens at this boundary.
    arguments: []const u8,
};

pub const WireToolCall = struct {
    id: []const u8,
    type: []const u8 = "function",
    function: WireFunctionCall,
};

/// One entry of a `content` array, the shape a server uses for a multi-part
/// message. Real servers add other part types, such as `image_url`; this
/// adapter reads only `text` and skips the rest instead of failing to parse.
/// See `WireContent.jsonParse`.
pub const WireTextPart = struct {
    type: []const u8 = "text",
    text: []const u8,
};

/// A message's `content` field. An OpenAI compatible server accepts either a
/// plain string or an array of typed parts, and some servers send the array
/// shape back in a response. Both directions go through this type so a
/// caller never has to guess which shape a given message used.
pub const WireContent = union(enum) {
    text: []const u8,
    parts: []const WireTextPart,

    pub fn jsonStringify(self: WireContent, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        switch (self) {
            .text => |text| try jw.write(text),
            .parts => |parts| try jw.write(parts),
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
                // A part with no "type":"text" pair, such as an image_url
                // entry, has no field this adapter can carry: skip it rather
                // than fail the whole response over one part it cannot read.
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

/// One reasoning block inside `WireMessage.reasoning_blocks`: present only
/// when a message holds more than one reasoning part. See the field's doc
/// comment on `WireMessage`.
pub const WireReasoning = struct {
    text: []const u8,
    /// Base64 of the raw signature bytes, not the raw bytes themselves. See
    /// `WireMessage.reasoning_signature`.
    signature: []const u8,
};

/// A content part this adapter has no dedicated wire field for, kept by
/// field name and raw JSON so nothing `message.ContentPart` can hold is
/// silently dropped at this boundary. Mirrors `message.ContentPart.unknown`.
pub const WireUnknownPart = struct {
    name: []const u8,
    raw: std.json.Value,
};

/// One message in the shape the wire expects, whether written into a
/// request or read back out of a response. The two directions share one
/// type because the OpenAI schema uses the same message shape for both.
pub const WireMessage = struct {
    role: []const u8,
    content: ?WireContent = null,
    tool_calls: ?[]const WireToolCall = null,
    /// Set only on a message with role "tool": the id of the call this
    /// message answers.
    tool_call_id: ?[]const u8 = null,
    /// Set only on a message with role "tool": whether the call failed.
    /// Not part of the standard OpenAI schema, same as the reasoning fields
    /// below: a server that has never heard of this field ignores it.
    is_error: ?bool = null,
    /// A signed reasoning block. Not part of the standard OpenAI schema: a
    /// server that has never heard of these two fields ignores them, and a
    /// server that keeps reasoning across turns reads them back on the next
    /// request. Keeping the signature in its own field, next to the text and
    /// not inside it, is what lets it survive a round trip unchanged: nothing
    /// has to parse it back out of prose.
    reasoning_content: ?[]const u8 = null,
    /// Base64 of the raw signature bytes. A signature is opaque bytes a
    /// provider signs over, not guaranteed to be valid UTF-8, and
    /// `std.json.Stringify` falls back to writing an invalid `[]const u8` as
    /// a JSON array of numbers rather than a string. No real server reads
    /// `[83,73,71]` as a string, so this field is always base64 text,
    /// whether the underlying bytes were valid UTF-8 or not, and always
    /// decoded back on the way in.
    reasoning_signature: ?[]const u8 = null,
    /// More than one reasoning block in one turn, each with its own
    /// signature, for example several thinking steps. Set only when a
    /// message holds more than one reasoning part; a single one still uses
    /// the two fields above, which a plain reasoning capable server already
    /// reads.
    reasoning_blocks: ?[]const WireReasoning = null,
    /// The alias of the model that wrote this turn. A backend can hold one
    /// model at a time, so knowing which alias produced which turn matters
    /// even inside one session. Not part of the standard OpenAI schema.
    model_alias: ?[]const u8 = null,
    /// See `WireUnknownPart`.
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

/// Asks a streaming server to send a final chunk carrying the token counts.
/// **Without this a streaming request reports no usage at all**, and usage is
/// an event of its own, so a session that streams would have nothing to
/// write.
pub const WireStreamOptions = struct {
    include_usage: bool = true,
};

const WireRequest = struct {
    model: []const u8,
    messages: []const WireMessage,
    tools: ?[]const WireTool = null,
    /// Omitted, not written as `false`, when the request does not stream:
    /// `emit_null_optional_fields = false` on the `Stringify` call below
    /// drops a `null` field, and every non-streaming test in this file
    /// asserts an exact field count that a spurious `"stream":false` would
    /// break.
    stream: ?bool = null,
    /// Written only alongside `stream`, for the same reason: a server that
    /// is not streaming has no final chunk to put usage in, and the field
    /// would be one more thing for a strict endpoint to refuse.
    stream_options: ?WireStreamOptions = null,
};

/// `buildRequest` only allocates. `std.json.Stringify.valueAlloc` writes
/// into memory it owns, so no other error can reach the caller.
pub const BuildError = std.mem.Allocator.Error;

fn base64Encode(allocator: std.mem.Allocator, bytes: []const u8) BuildError![]const u8 {
    const encoder = std.base64.standard.Encoder;
    const buf = try allocator.alloc(u8, encoder.calcSize(bytes.len));
    return encoder.encode(buf, bytes);
}

/// Decode a base64 wire signature back to raw bytes. `text` may not be
/// valid base64: a hand-written or older peer could send anything in this
/// non-standard extension field. Rather than fail the whole message over
/// one malformed field, keep `text` unchanged, so the caller still gets a
/// signature value, just not a decoded one.
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

/// Convert one neutral message into the wire message or messages that
/// represent it. A tool result is its own wire message, with role "tool",
/// never folded into another message's `content`: a neutral message with N
/// tool result parts becomes N wire "tool" messages, in the order the
/// results appeared, plus one more wire message for everything else the
/// neutral message carried (text, reasoning, tool calls, an unknown part),
/// if it carried anything else. Scratch allocations come from `allocator`;
/// `buildRequest` gives this an arena so the caller of `buildRequest` never
/// has to free them one by one.
fn toWireMessages(allocator: std.mem.Allocator, msg: message.Message) BuildError![]const WireMessage {
    var texts: std.ArrayList([]const u8) = .empty;
    var reasoning_parts: std.ArrayList(WireReasoning) = .empty;
    var tool_calls: std.ArrayList(WireToolCall) = .empty;
    var unknown_parts: std.ArrayList(WireUnknownPart) = .empty;
    var tool_messages: std.ArrayList(WireMessage) = .empty;

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
            .unknown => |unknown_part| try unknown_parts.append(allocator, .{
                .name = unknown_part.name,
                .raw = unknown_part.raw,
            }),
        }
    }

    // Multiple text parts keep their order and stay distinct as a content
    // array instead of being concatenated into one string with nothing
    // between them. A single text part still serializes as a plain string,
    // the shape every OpenAI compatible server accepts.
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
        // Two or more reasoning blocks each keep their own signature instead
        // of collapsing to the last one.
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
    // A neutral message that holds only tool results has nothing left for
    // the primary message to carry: `primary_has_content` is false and only
    // the "tool" messages below are emitted, matching what a real OpenAI
    // compatible history looks like for a tool's answer.
    try result.appendSlice(allocator, tool_messages.items);

    return result.toOwnedSlice(allocator);
}

/// Build the JSON body for a chat completion request. The key never enters
/// this text: `request` has no field that could hold one, so a caller adds
/// the key to the HTTP request as an `Authorization` header, outside this
/// body, outside anything a session log will ever hold.
pub fn buildRequest(allocator: std.mem.Allocator, request: Request) BuildError![]u8 {
    // Scratch allocations, the wire messages toWireMessages builds and the
    // arrays it builds them from, live in the arena and die with it. Only
    // the final JSON text below is the caller's to free.
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var messages: std.ArrayList(WireMessage) = .empty;
    if (request.system.len != 0) {
        try messages.append(arena, .{ .role = "system", .content = .{ .text = request.system } });
    }
    for (request.messages) |msg| {
        // request.system, above, is already the system message when it is
        // not empty. A message that also carries role "system" would
        // otherwise ride along as a second one.
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

/// One choice in a chat completion response. Real servers add more fields,
/// such as `index` and `finish_reason`. `ignore_unknown_fields` on
/// `parseResponse` means adding one more never breaks this reader.
pub const Choice = struct {
    message: WireMessage,
};

/// A chat completion response. Real servers add fields such as `id`,
/// `object`, `model`, and `usage`. None of them are named here, and
/// `ignore_unknown_fields` is what lets that be true without a parse error.
pub const Response = struct {
    choices: []const Choice,
};

pub const ParseError = std.json.ParseError(std.json.Scanner);

/// Parse a chat completion response body. `ignore_unknown_fields` is set:
/// without it, a field this reader has never heard of, anywhere in the
/// object, makes `std.json` reject the whole response, and a provider that
/// adds one field would break every reader that has not been rebuilt yet.
pub fn parseResponse(allocator: std.mem.Allocator, text: []const u8) ParseError!std.json.Parsed(Response) {
    return std.json.parseFromSlice(Response, allocator, text, .{ .ignore_unknown_fields = true });
}

fn roleFromWire(text: []const u8) message.Role {
    if (std.mem.eql(u8, text, "user")) return .user;
    if (std.mem.eql(u8, text, "assistant")) return .assistant;
    if (std.mem.eql(u8, text, "system")) return .system;
    if (std.mem.eql(u8, text, "tool")) return .tool;
    // A role a future provider adds. The escape hatch argument for an enum on
    // the wire applies here too: keep the name instead of refusing the
    // message.
    return .{ .unknown = text };
}

/// Join the parts of an array-shaped `content` into the single string a
/// tool result's `output` field holds. A newline separates parts that came
/// in as distinct array entries: still lossy versus keeping each part
/// separate, but not the no-separator concatenation Finding 3 reported,
/// and this shape is not one a real tool message is expected to use.
fn toolOutputText(allocator: std.mem.Allocator, content: ?WireContent) std.mem.Allocator.Error![]const u8 {
    const wire_content = content orelse return "";
    return switch (wire_content) {
        .text => |text| text,
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

/// Convert one wire message, such as `Response.choices[0].message`, into the
/// neutral message type. Most strings the result holds are slices into
/// `wire`, not a copy: the caller keeps the `std.json.Parsed` value that
/// produced `wire` alive for as long as the returned `Message` is in use.
/// Two exceptions allocate through `allocator` and are the caller's to free
/// on top of the returned `content` slice itself: a reasoning signature,
/// decoded from base64, on every `.reasoning` content part, and a tool
/// result's `output`, when the wire content was an array of parts joined
/// back into one string.
pub fn toMessage(allocator: std.mem.Allocator, wire: WireMessage) std.mem.Allocator.Error!message.Message {
    var parts: std.ArrayList(message.ContentPart) = .empty;
    errdefer parts.deinit(allocator);

    if (wire.reasoning_blocks) |blocks| {
        // Each block keeps its own signature: reading reasoning_blocks
        // instead of the singular fields below is what stops two blocks
        // from collapsing into one.
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
        // A message with role "tool" answers a previous call: its content is
        // the tool's output, not a remark from the assistant.
        try parts.append(allocator, .{ .tool_result = .{
            .call_id = call_id,
            .output = try toolOutputText(allocator, wire.content),
            .is_error = wire.is_error orelse false,
        } });
    } else if (wire.content) |content| {
        switch (content) {
            .text => |text| if (text.len != 0) try parts.append(allocator, .{ .text = text }),
            // Each array entry stays its own text part: no entry is
            // concatenated onto another.
            .parts => |wire_parts| for (wire_parts) |part| {
                if (part.text.len != 0) try parts.append(allocator, .{ .text = part.text });
            },
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
    // Request must hold no field that could carry a credential. A caller
    // cannot pass an API key into buildRequest even by mistake, because
    // Request has nowhere to put one: the key belongs in the Authorization
    // header a caller sets outside this function, never in the body that
    // chockd logs. Verified by temporarily renaming `model` to `api_key`,
    // and separately to `credential_handle`, during development and
    // confirming this block failed the build with the message below, before
    // renaming it back.
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
    // A signature that changes is worthless, so this is byte for byte.
    // Goes through the public buildRequest, not the private toWireMessages
    // helper, so this pins the path a caller actually takes.
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
    // toMessage decodes the base64 signature into fresh memory: see the
    // ownership note on toMessage's doc comment.
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
    // A provider adds fields. A reader that refuses them breaks on a Tuesday.
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
    // The key belongs in a header, not the body. This is the test that stops a key
    // reaching the log, because the body is what gets logged.
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

    // The body has exactly the fields buildRequest can write: model and
    // messages, with tools omitted because none were given. There is no
    // fourth field for a key to ride along in, and the comptime check above
    // proves Request never had a place to put one before this point either.
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
    // Finding 1. Before the fix, a text part and a tool_result part in one
    // neutral message shared one `content` string, and toMessage read the
    // whole joined string back as the tool result's output.
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

    // The round trip must recover the same two facts, not one joined string.
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
    // Finding 2. Before the fix, toWire never wrote is_error and toMessage
    // hardcoded false, so a failed tool call re-served as a successful one.
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

    // No primary message: the neutral message carried nothing but the two
    // tool results, so only the two "tool" messages are emitted.
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

    // The singular fields stay empty: reasoning_blocks is the one source of
    // truth once there is more than one block, so a reader cannot read both
    // and double count.
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
    // Finding 3: a message holding only one unknown part used to serialize
    // to {"role":"assistant"} with no content at all.
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
    // Finding 3: a session can mix models across turns, so a reader needs to
    // know which alias produced a turn.
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
    // Finding 4. std.json falls back to a JSON array of numbers for a byte
    // slice that fails UTF-8 validation. No real server reads that as a
    // string, so the signature is always base64 on the wire.
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

test "a response whose content is an array of text parts degrades to the text instead of failing to parse" {
    // Finding 5: some servers send content as an array of typed parts. The
    // non-text image_url entry is skipped rather than failing the parse.
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
