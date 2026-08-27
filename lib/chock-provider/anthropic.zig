//! The Anthropic native adapter. Chock has two wire formats, and this is the
//! second one. It exists rather than translating through the OpenAI shape
//! because **a thinking block with its signature, and cache control, do not
//! survive that conversion**, and a lossy conversion is permanent: `chockd`
//! re-serves the session log to other clients, so what is lost here is lost
//! for everyone.
//!
//! `openai.zig` is the model this file follows, field for field where the two
//! wires agree, because the parallel shape is what lets a reader compare them.
//! Four differences break a naive port, and each one has a test below:
//!
//! 1. **`system` is a top level field, not a message with a system role.**
//! 2. **`max_tokens` is required.** See `default_max_tokens`.
//! 3. **A tool result is a content block inside a `user` message. There is no
//!    `tool` role at all.** This is the difference most likely to be got
//!    wrong, because the neutral type has a `tool` role and the OpenAI wire
//!    has one too.
//! 4. **A thinking block goes back with its `signature` intact.** Dropping it
//!    makes the provider treat the block as forged on the next turn, and it
//!    is the whole reason this adapter exists.
//!
//! The adapter never sees a credential, the same as `openai.zig`: `Request`
//! has no field that could hold one, and the comptime block at the end of
//! this file fails the build if anyone adds one. The key travels in the
//! `x-api-key` header, which is the second difference from the OpenAI wire's
//! `Authorization: Bearer`, and `Client.zig` is the file that sets it.
//!
//! ## The stream
//!
//! ```
//! message_start
//!   content_block_start
//!   content_block_delta   (repeats)
//!   content_block_stop
//!   ... one group per content block ...
//! message_delta
//! message_stop
//! ```
//!
//! `ping` may arrive at any point and means nothing. **An `error` event may
//! arrive inside the stream**, for example `overloaded_error`, which is a 529
//! in a non-streaming call: a reader that only checks the HTTP status misses
//! it entirely, because the status was 200 and stayed 200.
//!
//! `Decoder` reads one event's JSON body at a time and answers with one
//! `Piece`. It does not frame the stream: `sse.zig` already does that, and
//! this file writes no second parser. `sse.ToolCallAssembler` already
//! assembles a tool call from fragments keyed by index, and this adapter
//! feeds it the same neutral `message.ToolCallFragment` the OpenAI path does,
//! so nothing above either adapter has to know which wire it came off.
//!
//! ## The usage trap
//!
//! `message_start` carries the initial `usage`, and `message_delta` carries
//! `usage` again. **Those counts are cumulative, not incremental.** A parser
//! that adds them up over counts, and adding them up is what a reasonable
//! implementation does. `Decoder` replaces each field it is told about and
//! never adds, so the last value wins. See the test named for it.

const std = @import("std");
const message = @import("message.zig");
const sse = @import("sse.zig");

/// See `message.ToolDefinition`: the canonical definition is neutral and
/// lives there, so `Client`'s interface never imports a wire format to name a
/// tool's shape. Aliased, not copied, the same as `openai.zig` does it.
pub const ToolDefinition = message.ToolDefinition;

/// What a turn cost. See `message.Usage`.
pub const Usage = message.Usage;

/// The path this adapter appends to a provider's base URL. The OpenAI
/// compatible adapter uses `/chat/completions`; ai& serves both on one host.
pub const path = "/messages";

/// The header the key travels in. **Not `Authorization: Bearer`**, which is
/// what the OpenAI compatible wire uses.
pub const key_header = "x-api-key";

/// The version header every request must carry, and its one value Chock
/// sends. Anthropic dates its wire format instead of numbering it.
pub const version_header = "anthropic-version";
pub const version = "2023-06-01";

/// `max_tokens` is required on this wire, and the OpenAI wire treats it as
/// optional, so a caller that never set one still needs a number here. 8192
/// is generous for a coding turn's answer and small enough that a runaway
/// generation stops rather than filling a context window. A caller that wants
/// a different ceiling sets `Request.max_tokens` itself.
pub const default_max_tokens: u32 = 8192;

/// Everything one call to the model needs, in the shape `buildRequest` reads.
/// `Client.HttpClient` is the only caller that builds one: it converts from
/// `message.Request`, the neutral shape, adding the two fields that only
/// matter once a request is about to become wire bytes.
pub const Request = struct {
    model: []const u8,
    /// The top level `system` field. **Not a message.** A message in
    /// `messages` that carries the system role is folded in here instead when
    /// this is empty, and dropped when it is not: see `buildRequest`.
    system: []const u8,
    messages: []const message.Message,
    tools: []const ToolDefinition = &.{},
    max_tokens: u32 = default_max_tokens,
    stream: bool = false,
};

/// One content block on the wire. Anthropic's content is always an array of
/// typed blocks, in both directions, unlike the OpenAI wire where a message's
/// content is usually one string.
pub const WireBlock = union(enum) {
    text: Text,
    thinking: Thinking,
    tool_use: ToolUse,
    tool_result: ToolResult,
    /// A block type this reader has no case for, kept whole so it can be
    /// written back out unchanged. Mirrors `message.ContentPart.unknown`.
    unknown: Unknown,

    pub const Text = struct {
        text: []const u8,
    };

    /// `signature` is opaque bytes the provider signs over. Keep it exactly
    /// as given: see `chock_proto.event.Reasoning`.
    pub const Thinking = struct {
        thinking: []const u8,
        signature: []const u8,
    };

    /// `input` is a JSON **object**, not a string. The OpenAI wire carries a
    /// tool call's arguments as a JSON string; this one nests them.
    pub const ToolUse = struct {
        id: []const u8,
        name: []const u8,
        input: std.json.Value,
    };

    /// Lives in a `user` message. There is no `tool` role.
    pub const ToolResult = struct {
        tool_use_id: []const u8,
        content: []const u8,
        is_error: bool,
    };

    pub const Unknown = struct {
        /// The `type` this reader did not recognize.
        name: []const u8,
        /// The whole block, kept verbatim.
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
            // The raw value already carries its own `type`, because it is the
            // block exactly as it arrived. Writing it verbatim is what makes
            // the round trip exact.
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

    /// Read one block out of an already parsed JSON value. `Decoder` needs
    /// this too, because a `content_block_start` event carries the block
    /// nested inside an event body it has already parsed.
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

/// The value of `object[name]` when it is a string, and an empty string
/// otherwise. Every caller is reading bytes off a wire it does not control,
/// so a field of the wrong type is a runtime fault to absorb, not a reason to
/// refuse a whole message.
fn stringField(object: std.json.ObjectMap, name: []const u8) []const u8 {
    const value = object.get(name) orelse return "";
    return if (value == .string) value.string else "";
}

/// A `tool_result` block's `content` is either a plain string or an array of
/// content blocks. Chock's neutral `ToolResultPart.output` is one string, so
/// the array shape takes the first text block it finds. Chock itself always
/// writes the string shape, so this only ever runs on a history some other
/// client wrote.
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

/// One message on the wire. **The role is only ever `user` or `assistant`.**
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

/// `buildRequest` only allocates. `std.json.Stringify.valueAlloc` writes into
/// memory it owns, so no other error can reach the caller.
pub const BuildError = std.mem.Allocator.Error;

/// Parse a neutral tool call's `arguments`, which is JSON text, into the
/// object this wire nests under `input`.
///
/// **Arguments that are not valid JSON cannot be represented on this wire at
/// all**, because `input` is an object and not a string. An empty object goes
/// out instead of malformed text, which is the same answer the provider would
/// give: it refuses the request rather than guessing. A call whose arguments
/// never parsed was already broken before it reached this function.
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

/// Convert one neutral message into the wire message or messages that
/// represent it. See difference 3 in this file's own top comment: a tool
/// result never rides in a message of its own with a `tool` role, because
/// this wire has no such role. It becomes a `tool_result` block inside a
/// `user` message, and those blocks come first in that message, which is the
/// order the provider expects.
///
/// A neutral assistant message that also carries tool results, which nothing
/// in Chock builds but a foreign history could, becomes two wire messages:
/// the assistant turn, then the user turn holding the results.
fn toWireMessages(
    arena: std.mem.Allocator,
    msg: message.Message,
) BuildError![]const WireMessage {
    var own: std.ArrayList(WireBlock) = .empty;
    var results: std.ArrayList(WireBlock) = .empty;

    for (msg.content) |part| {
        switch (part) {
            .text => |text| {
                // An empty text block is refused by the provider, and a
                // neutral message can hold one after a truncated stream.
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

    // Everything else, user and tool alike, is a user turn. The results come
    // first: a `tool_result` block after ordinary text is refused.
    try results.appendSlice(arena, own.items);
    if (results.items.len != 0) {
        try out.append(arena, .{ .role = "user", .content = results.items });
    }
    return out.toOwnedSlice(arena);
}

/// The text of a neutral message, joined with newlines. Used only to fold a
/// system role message into the top level `system` field.
fn joinText(arena: std.mem.Allocator, msg: message.Message) BuildError![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (msg.content) |part| {
        if (part != .text) continue;
        if (out.items.len != 0) try out.append(arena, '\n');
        try out.appendSlice(arena, part.text);
    }
    return out.toOwnedSlice(arena);
}

/// True when this wire message carries a tool result. See `buildRequest`: a
/// message with one keeps its own turn, because the blocks of one turn put
/// every result before any text.
fn holdsToolResult(wire_message: WireMessage) bool {
    for (wire_message.content) |block| {
        if (block == .tool_result) return true;
    }
    return false;
}

/// Build the JSON body for a `/messages` request. The key never enters this
/// text: `Request` has no field that could hold one, and the caller puts the
/// key in the `x-api-key` header, outside anything a session log will hold.
pub fn buildRequest(allocator: std.mem.Allocator, request: Request) BuildError![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var system: []const u8 = request.system;
    var messages: std.ArrayList(WireMessage) = .empty;
    for (request.messages) |msg| {
        if (std.meta.activeTag(msg.role) == .system) {
            // Difference 1: there is no system message on this wire. A
            // history that carries one, for example a session started
            // against an OpenAI compatible provider and continued here,
            // folds into the top level field rather than being dropped.
            if (system.len == 0) system = try joinText(arena, msg);
            continue;
        }
        for (try toWireMessages(arena, msg)) |wire_message| {
            // Difference 5, and the one a trailing harness notice runs into.
            // This wire has no `tool` role, so a tool result is already a
            // `user` turn: see `toWireMessages`. A `user` message after one,
            // which is what `chock_core.Loop`'s notice is, would be two
            // `user` turns in a row, and this wire wants alternating roles.
            // Joining them says the same thing in the shape the wire takes.
            //
            // **Only a message with no tool result in it is joined on.** A
            // `tool_result` block after ordinary text is refused, so a message
            // that carries one keeps its own turn, where its results are
            // already first.
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
        // Difference 2: always written, never omitted, because the provider
        // refuses a request without it.
        .max_tokens = request.max_tokens,
        .messages = messages.items,
        .system = if (system.len == 0) null else system,
        .tools = if (tools.items.len == 0) null else tools.items,
        .stream = if (request.stream) true else null,
    };
    return std.json.Stringify.valueAlloc(allocator, wire, .{ .emit_null_optional_fields = false });
}

/// The usage object, in both the non-streaming response and the streaming
/// `message_start` and `message_delta` events. Every field is optional
/// because the provider sends only the ones that changed: see `applyUsage`.
pub const WireUsage = struct {
    input_tokens: ?u64 = null,
    output_tokens: ?u64 = null,
    cache_creation_input_tokens: ?u64 = null,
    cache_read_input_tokens: ?u64 = null,
};

/// A whole non-streaming reply. Real servers add more fields; `ignore_unknown_fields`
/// on `parseResponse` is what lets that be true without a parse error.
pub const Response = struct {
    role: []const u8 = "assistant",
    content: []const WireBlock = &.{},
    model: []const u8 = "",
    stop_reason: ?[]const u8 = null,
    usage: WireUsage = .{},
};

pub const ParseError = std.json.ParseError(std.json.Scanner);

/// Parse a `/messages` response body.
pub fn parseResponse(
    allocator: std.mem.Allocator,
    text: []const u8,
) ParseError!std.json.Parsed(Response) {
    return std.json.parseFromSlice(Response, allocator, text, .{ .ignore_unknown_fields = true });
}

fn roleFromWire(text: []const u8) message.Role {
    if (std.mem.eql(u8, text, "assistant")) return .assistant;
    if (std.mem.eql(u8, text, "user")) return .user;
    // A role a future provider adds. Keep the name rather than refusing the
    // message: the escape hatch argument for an unknown name.
    return .{ .unknown = text };
}

/// Convert wire blocks into the neutral content parts. Every string is a
/// slice into whatever `std.json.Parsed` value produced `blocks`, except a
/// tool call's `arguments`, which is serialized fresh because this wire
/// carries the input as an object and the neutral type carries it as text.
/// The caller frees the returned slice, and each `arguments` string in it.
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
                    // Difference 4: byte for byte, never regenerated.
                    .signature = thinking.signature,
                },
            }),
            .tool_use => |tool_use| try parts.append(allocator, .{ .tool_use = .{
                .call_id = tool_use.id,
                .tool = tool_use.name,
                .arguments = try std.json.Stringify.valueAlloc(allocator, tool_use.input, .{}),
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

/// Convert a whole non-streaming response into the neutral message type. See
/// `toContent` for what the caller owns.
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

/// An `error` event that arrived inside a 200 stream. See this file's own top
/// comment: a reader that only checks the HTTP status never sees this.
pub const StreamError = struct {
    /// For example "overloaded_error", which is a 529 in a non-streaming call.
    kind: []const u8,
    text: []const u8,
};

/// One event's worth of meaning. `Decoder.feed` answers with exactly one of
/// these per server sent event, so a caller drives it in a plain loop.
pub const Piece = union(enum) {
    /// A `ping`, a `content_block_stop`, a `message_stop`, or an event this
    /// reader has no case for. Nothing to do.
    none,
    text: []const u8,
    reasoning: []const u8,
    /// A `signature_delta`: the thinking block's signature, which arrives
    /// after its text and must be kept with it.
    reasoning_signature: []const u8,
    tool_call: message.ToolCallFragment,
    /// The counts so far, **cumulative and not incremental**. A caller keeps
    /// the last one it was given and never adds them up.
    usage: Usage,
    stream_error: StreamError,
};

/// What one content block index is carrying, so a `content_block_delta` for
/// that index knows which kind of delta it is reading. The delta's own `type`
/// says this too, and `Decoder` reads that first; this is the fallback for a
/// delta whose type a future provider spells differently.
const BlockKind = enum { text, thinking, tool_use, other };

pub const DecodeError = std.mem.Allocator.Error || std.json.ParseError(std.json.Scanner) || error{
    /// The event body parsed but was not a JSON object.
    BodyNotObject,
    /// The event body carried no `type` field, or one that was not a string.
    /// Every real event on this wire has one.
    MissingEventType,
    /// A `content_block_start` or `content_block_delta` with no usable
    /// `index`. Every real one carries a non negative integer.
    BlockIndexInvalid,
};

/// What the `stop_details` beside a `stop_reason` said. **This wire sends
/// `stop_details` for one stop reason only, `refusal`, and sends null for
/// every other one.**
///
/// **Both fields can be null even on a real refusal**, so an empty one here
/// means the provider said nothing, and a reader that fills that gap with a
/// reason of its own throws away the only explanation anybody has and puts an
/// invented one in its place. A refusal with neither field is a different fact
/// from a refusal with them, and whatever reports this must keep the two
/// different.
pub const StopDetails = struct {
    /// A short token naming the class of the refusal, for example
    /// `cyber_harm`. Empty when the provider sent none.
    category: []const u8 = "",
    /// The provider's own sentence about the refusal, for example "This
    /// request was declined because it could enable cyber harm." Empty when
    /// the provider sent none.
    explanation: []const u8 = "",
};

/// The longest `category` this reader keeps. It is one short token, the same
/// shape a stop reason is, so it gets the length `Client.max_stop_reason`
/// gives that one, and for the same reason: a cut token still names the class
/// of the refusal, and an empty one names nothing at all. Written out here
/// rather than read from there, because an adapter that imported `Client.zig`
/// would close an import cycle.
pub const max_stop_category: usize = 64;

/// The longest `explanation` this reader keeps. This one is prose and not a
/// token, so it needs a bound of its own: the longest the platform documents
/// is 61 bytes, "This request was declined because it could enable cyber
/// harm.", and this holds several sentences of that size. It is a fixed buffer
/// in every `Decoder` and in every `Client.AssembledReply`, both of which are
/// passed by value, which is what makes a bound necessary at all: the provider
/// chooses this length, and Chock does not let it choose how big those structs
/// get. A longer explanation is cut and not dropped, for the same reason a
/// stop reason is.
pub const max_stop_explanation: usize = 512;

/// Read the `stop_details` object beside a `stop_reason`. An absent one, a
/// null one, and one of the wrong type all read as "the provider said
/// nothing", which is what an empty field means everywhere else in this
/// reader.
fn stopDetailsOf(delta: std.json.ObjectMap) StopDetails {
    const value = delta.get("stop_details") orelse return .{};
    if (value != .object) return .{};
    return .{
        .category = stringField(value.object, "category"),
        .explanation = stringField(value.object, "explanation"),
    };
}

/// Copy as much of `text` as `buffer` holds, and answer how much that was.
fn keepCut(buffer: []u8, text: []const u8) usize {
    const kept = @min(text.len, buffer.len);
    @memcpy(buffer[0..kept], text[0..kept]);
    return kept;
}

/// Reads the events of one `/messages` stream. Holds the small amount of
/// state the wire forces a reader to keep: which content block index is
/// carrying what, and the running usage counts.
///
/// It does not frame the stream. `sse.Parser` does that, and this file writes
/// no second parser: see this file's own top comment.
pub const Decoder = struct {
    allocator: std.mem.Allocator,
    /// Holds one event's parsed JSON tree, and nothing older. Reset at the
    /// top of every `feed`, which is what makes the lifetime rule in `feed`'s
    /// own doc comment true: a `Piece` is a view of the event it came from.
    arena: std.heap.ArenaAllocator,
    /// Keyed by content block index. A hash map for the same reason
    /// `sse.ToolCallAssembler` uses one: the provider chooses how many blocks
    /// a reply has, and a scan per event is quadratic in that count.
    kinds: std.AutoArrayHashMapUnmanaged(usize, BlockKind) = .empty,
    /// The counts so far. **Replaced field by field, never added to.** See
    /// the usage trap in this file's own top comment.
    usage: Usage = .{},
    /// Whether any event carried usage at all. A provider that reports none
    /// leaves this false, and a caller then knows the zeros are absence and
    /// not a free turn.
    saw_usage: bool = false,
    /// The `stop_reason` from `message_delta`, for example "tool_use" or
    /// "end_turn". A copy, not a slice into `arena`, because it outlives the
    /// event it arrived on: read it with `stopReason`.
    stop_reason_text: std.ArrayList(u8) = .empty,
    /// What the `stop_details` beside that `stop_reason` said, cut to
    /// `max_stop_category` and `max_stop_explanation`. Copies, not slices into
    /// `arena`, for the reason `stop_reason_text` gives, and fixed buffers
    /// rather than a second and third `std.ArrayList` because the explanation
    /// is prose whose length the provider chooses. Read them with
    /// `stopDetails`.
    stop_category_buffer: [max_stop_category]u8 = @splat(0),
    /// How much of `stop_category_buffer` the provider filled.
    stop_category_len: usize = 0,
    stop_explanation_buffer: [max_stop_explanation]u8 = @splat(0),
    /// How much of `stop_explanation_buffer` the provider filled.
    stop_explanation_len: usize = 0,
    /// Whether `message_stop` has arrived. **This wire never sends the
    /// `[DONE]` line the OpenAI compatible wire ends with**, so a caller that
    /// waits for one calls every complete reply truncated. This is the fact
    /// to check instead.
    saw_message_stop: bool = false,

    pub fn init(allocator: std.mem.Allocator) Decoder {
        return .{ .allocator = allocator, .arena = std.heap.ArenaAllocator.init(allocator) };
    }

    pub fn deinit(self: *Decoder) void {
        self.stop_reason_text.deinit(self.allocator);
        self.kinds.deinit(self.allocator);
        self.arena.deinit();
    }

    /// Why the model stopped, for example "tool_use" or "end_turn". Empty
    /// until a `message_delta` says.
    pub fn stopReason(self: *const Decoder) []const u8 {
        return self.stop_reason_text.items;
    }

    /// What the provider said about the reason `stopReason` names. Both
    /// fields stay empty until a `message_delta` carries a `stop_details` that
    /// fills them, which this wire does for a refusal and for nothing else.
    /// See `StopDetails`: empty means the provider said nothing, and never
    /// that it said there was no reason.
    pub fn stopDetails(self: *const Decoder) StopDetails {
        return .{
            .category = self.stop_category_buffer[0..self.stop_category_len],
            .explanation = self.stop_explanation_buffer[0..self.stop_explanation_len],
        };
    }

    /// Read one event's JSON body. **Every string in the returned `Piece` is
    /// a view of that one event and is valid only until the next `feed`**,
    /// the same rule `Client.Delta` already states: a caller that wants to
    /// keep the bytes copies them before it asks for the next event.
    ///
    /// The body is untrusted: a provider can be compromised and a proxy can
    /// sit in the way. A field of the wrong type is skipped rather than
    /// asserted on, and only a body with no event type at all, or a content
    /// block with no index, is refused outright, because neither can be
    /// attributed to anything.
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

    /// The body of `feed`, split out so a test can hand it an already parsed
    /// value. **Every slice in the answer points into `value`.**
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
                        // **Replaced with the reason they belong to, always,
                        // even when the event carried none.** The details of
                        // an earlier stop reason describe that word and not
                        // this one, and keeping them would report a refusal's
                        // explanation beside the reason that replaced it. See
                        // `StopDetails`.
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
                // The tool call's id and name arrive here, once, and every
                // fragment after this carries only a piece of the arguments.
                // That is the same shape the OpenAI wire has, which is why
                // one `sse.ToolCallAssembler` serves both.
                .tool_use => |tool_use| return .{ .tool_call = .{
                    .index = index,
                    .id = tool_use.id,
                    .name = tool_use.name,
                } },
                // A block can open with text already in it. Every capture
                // this adapter has read opens empty, but nothing on the wire
                // promises that, and dropping it would lose a whole answer.
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
            // A delta type this reader has no case for. The block's own kind
            // is the fallback, so a renamed delta on a known block still
            // reaches the right buffer rather than being dropped.
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

        // ping, content_block_stop, and anything a later version of this
        // wire adds.
        return .none;
    }

    /// **Replace, never add.** The counts on this wire are cumulative: an
    /// implementation that adds each `message_delta` to the running total
    /// over counts, and adding is the reasonable looking thing to do. A
    /// field the event does not carry keeps whatever `message_start` set.
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
    // The same guard `openai.Request` carries: a caller cannot pass a
    // credential into `buildRequest` even by mistake, because `Request` has
    // nowhere to put one. The key belongs in the `x-api-key` header, set
    // outside this file, never in the body `chockd` logs.
    for (@typeInfo(Request).@"struct".fields) |field| {
        // `max_tokens` is this wire's required output ceiling, not a
        // credential, and it is the one field name here that contains
        // "token". Named exactly rather than loosening the substring list,
        // so `refresh_token` or `token_file` would still fail the build.
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
    // Difference 1. A port from openai.zig writes a message with role
    // "system" here, which this wire refuses outright.
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
    // Difference 5. `chock_core.Loop` puts what the harness knows at the end
    // of the context, as a `user` message, and the message before it is the
    // tool's own answer, which this wire already carries as a `user` turn. Two
    // `user` turns in a row is what this wire will not take.
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

    // The result first and the notice after it: a `tool_result` block that
    // follows ordinary text is refused, which is why the order is not free.
    const blocks = wire_messages[1].object.get("content").?.array.items;
    try testing.expectEqual(@as(usize, 2), blocks.len);
    try testing.expectEqualStrings("tool_result", blocks[0].object.get("type").?.string);
    try testing.expectEqualStrings("text", blocks[1].object.get("type").?.string);

    // And the roles really do alternate now, which is the fact this pins.
    var previous: []const u8 = "";
    for (wire_messages) |wire_message| {
        const role = wire_message.object.get("role").?.string;
        try testing.expect(!std.mem.eql(u8, role, previous));
        previous = role;
    }
}

test "two turns that both carry a tool result keep their own turns" {
    // The negative half of the join above. Joining these would put a
    // `tool_result` block after another turn's text, which this provider
    // refuses, so a message holding one is never joined on.
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
    // The first two joined; the third kept its own turn because it holds a
    // result.
    try testing.expectEqual(@as(usize, 2), wire_messages[0].object.get("content").?.array.items.len);
    try testing.expectEqual(@as(usize, 1), wire_messages[1].object.get("content").?.array.items.len);
}

test "max_tokens is always on the wire, because this provider requires it" {
    // Difference 2. openai.zig omits it entirely, and a request without it is
    // refused here.
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
    // Difference 3, and the one most likely to be got wrong: the neutral type
    // has a `tool` role and the OpenAI wire has one, and this wire has none.
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

    // Not "the role happened to be user this time": no message anywhere in
    // the body names the role this wire does not have.
    try testing.expect(std.mem.indexOf(u8, body, "\"role\":\"tool\"") == null);
}

test "a tool result block comes before the text of the same user turn" {
    // The provider refuses a user turn whose tool_result blocks are not
    // first, so the order here is a wire rule and not a preference.
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
    // Difference 4, and the reason this adapter exists rather than a
    // translation through the OpenAI shape. A signature that changes is
    // worthless, so this is byte for byte, through the public functions a
    // caller actually uses.
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

    // And back the other way: a reply that carries a thinking block gives the
    // same signature to the neutral type.
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
    // The OpenAI wire carries arguments as a JSON string; this one nests
    // them. A port that writes the string straight into `input` sends a
    // string where an object belongs.
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
    // An object, not a string: this is the assertion a naive port fails.
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
    // The slice last, the string it points into first: a defer runs in
    // reverse, so freeing `content` before reading a field of it would read
    // memory this test just returned.
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
    // The body is what a session log holds, and chockd re-serves that log.
    // The comptime block above proves Request has nowhere to put a key; this
    // proves the text that leaves this file has no room for one either.
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

/// Feed one event body to `decoder` and give back the piece. Only the tests
/// below use this.
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
    // sse.ToolCallAssembler is not re-implemented here: the fragments this
    // decoder produces are the same neutral shape the OpenAI path produces,
    // which is what lets one assembler serve both wires.
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
    // The trap this whole decoder is careful about. The counts rise, so a
    // parser that adds them reports 1 + 40 + 90 + 150 = 281 output tokens
    // where the truth is 150. Rising counts are what tells the two apart: a
    // single message_delta cannot.
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
    // The input count came from message_start and no message_delta repeated
    // it, so it must still be there: replacing a field the event did not
    // carry would zero it.
    try testing.expectEqual(@as(u64, 1200), decoder.usage.input_tokens);
    try testing.expectEqual(@as(u64, 800), decoder.usage.cache_read_input_tokens);
    try testing.expectEqualStrings("tool_use", decoder.stopReason());
    try testing.expect(decoder.saw_usage);
    // 1200 + 150 + 800, once each. A summing parser reports more.
    try testing.expectEqual(@as(u64, 2150), decoder.usage.totalTokens());
    // A stop reason that is not a refusal comes with `stop_details: null`, so
    // there is nothing to keep beside the word. See `StopDetails`.
    try testing.expectEqualStrings("", decoder.stopDetails().category);
    try testing.expectEqualStrings("", decoder.stopDetails().explanation);
}

test "a refusal keeps the category and the explanation the wire sent with it" {
    // The whole reason `stop_details` is read. "It stopped because of refusal"
    // says nothing a person can act on, and the sentence that does say
    // something arrives in the same event.
    const allocator = testing.allocator;
    var decoder = Decoder.init(allocator);
    defer decoder.deinit();

    _ = try feedEvent(&decoder,
        \\{"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber_harm","explanation":"This request was declined because it could enable cyber harm."}},"usage":{"output_tokens":12}}
    );

    try testing.expectEqualStrings("refusal", decoder.stopReason());
    try testing.expectEqualStrings("cyber_harm", decoder.stopDetails().category);
    try testing.expectEqualStrings(
        "This request was declined because it could enable cyber harm.",
        decoder.stopDetails().explanation,
    );
}

test "a refusal with both details null keeps neither, and invents neither" {
    // **A real shape, not a defensive one.** Both fields are nullable even on
    // a refusal, and a reader that filled the gap here would put an invented
    // reason in the log of the one turn nobody can explain any other way.
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
        \\{"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber_harm","explanation":null}},"usage":{"output_tokens":4}}
    );
    try testing.expectEqualStrings("cyber_harm", decoder.stopDetails().category);
    // **Cleared with the reason it belonged to.** The explanation above
    // described the first refusal, and reporting it beside the second one
    // would attach a reason to a word that never carried it.
    try testing.expectEqualStrings("", decoder.stopDetails().explanation);
}

test "an explanation longer than the bound is cut, and never dropped" {
    // A cut sentence still says why. An empty one says nothing at all, which
    // is the fault this reader exists to fix. See `max_stop_explanation`.
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
    // The HTTP status was 200 and stays 200. A reader that only checks the
    // status reports a short, successful answer for a request the provider
    // refused.
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
