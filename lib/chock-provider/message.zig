//! The neutral message type Chock's provider adapters read and write.
//!
//! This is not a new type. `lib/chock-proto/event.zig` already has a message
//! type with ordered content parts. An early review put it there for one
//! reason: flattening a model turn to plain text loses a reasoning block and
//! its signature, and
//! `chockd` re-serves a session to other clients, so that loss is permanent.
//!
//! This file re-exports that type instead of copying its shape. A copy is
//! how the mount list once quietly stopped matching the mounts it
//! described: two definitions of the same idea drift the moment one of them
//! changes and the other does not. An alias cannot drift, because there is
//! only ever one definition to change.

const std = @import("std");
const chock_proto = @import("chock-proto");

/// One model turn, or one user turn. See `lib/chock-proto/event.zig`.
pub const Message = chock_proto.event.Message;

/// One piece of the ordered content of a turn: text, a signed reasoning
/// block, a tool call, a tool result, or a part this reader does not
/// recognize.
pub const ContentPart = chock_proto.event.ContentPart;

/// The speaker of a message.
pub const Role = chock_proto.event.Role;

/// A block of model reasoning the provider marks opaque, with the signature
/// that proves it was not edited.
pub const Reasoning = chock_proto.event.Reasoning;

/// A tool's answer, carried back to the model as part of a turn.
pub const ToolResultPart = chock_proto.event.ToolResultPart;

/// The model asked, inside its own turn, to run a tool. `chock-proto` calls
/// this shape `ToolUse`, because there it names one content part of a
/// `message` event. The adapter code in this library calls the same shape
/// `ToolCall`, because that is the name a caller building a request or
/// reading a response reaches for. Same fields, same type, one alias: the
/// two names describe the same data from two angles and can never drift into
/// two shapes, because there is only one.
pub const ToolCall = chock_proto.event.ToolUse;

/// What one call to a model cost, in tokens and in money. See
/// `lib/chock-proto/event.zig`: this is the payload of the `usage` event, and
/// an adapter fills in whatever its provider reported. Aliased, not copied,
/// for the reason this file's own top comment gives: a second definition
/// would drift from the one the log writes.
pub const Usage = chock_proto.event.Usage;

/// Known, free, or unknown, and never an optional that a caller reads as a
/// zero. See `lib/chock-proto/event.zig`.
pub const Cost = chock_proto.event.Cost;

/// A sum of money, for `Cost.known`.
pub const Amount = chock_proto.event.Amount;

/// One thing a tool may need before anybody may offer it to a model.
///
/// **This is a property of the wire format, not of a tool.** A tool names
/// which member it needs, `Client.Adapter.carries` says whether an adapter can
/// express it at all, and the provider instance's own capability record says
/// whether that instance does it. Both answers must be yes: see
/// `lib/chock-core/tools.zig`'s own `Support`.
///
/// A tool the model cannot use is worse than a tool that is missing, because
/// the model spends one turn calling it and one turn reading the failure, and
/// a small model may never recover from that.
pub const Capability = enum {
    /// The model can be given tool definitions and can answer with a tool
    /// call. Every adapter Chock has carries this, and every provider Chock
    /// talks to is expected to: a provider that does not would leave the
    /// agent with nothing to do at all.
    tool_calls,
    /// A tool result can carry an image rather than text. **No adapter
    /// carries this today**: `ContentPart` has text, reasoning, a tool call
    /// and a tool result, and no image part, so there is nothing for an
    /// adapter to encode. The member exists so the gate that will hold
    /// `read_image` back is built and tested before the tool is, rather than
    /// after.
    image_results,
};

/// A JSON schema for one tool's parameters, and the name and description the
/// model reads to decide whether to call it. Neutral: every provider adapter
/// builds its own wire shaped tool listing from this one. `parameters` is a
/// parsed value rather than pre-serialized text, so the schema nests
/// directly into whatever request body an adapter builds instead of arriving
/// as one long escaped string.
pub const ToolDefinition = struct {
    name: []const u8,
    description: []const u8,
    parameters: std.json.Value,
};

/// Everything one call to the model needs, independent of which adapter ends
/// up putting it on a wire. The internal type stays neutral so `Client`'s
/// interface, in `Client.zig`, can be implemented
/// by more than one adapter. `Client.HttpClient` is the OpenAI compatible one
/// this milestone builds. A native Anthropic adapter, promised for version 1,
/// reads this same type instead of needing `openai.zig`'s wire shapes.
pub const Request = struct {
    model: []const u8,
    system: []const u8,
    messages: []const Message,
    tools: []const ToolDefinition = &.{},
};

/// One piece of one tool call as it streams off the wire, keyed by `index`
/// the same way every provider's streaming shape tells two calls in one
/// response apart, whatever it calls the field internally. `id` and `name`
/// are set only on a call's first fragment. Every fragment after it, on
/// every real stream this library has read, carries only a piece of
/// `arguments`. Neutral, like `Request`: `Client.Delta.tool_call` carries
/// this type, not an OpenAI compatible adapter's own wire fragment shape, so
/// a second adapter's `Client.send` can produce one without importing
/// `sse.zig`.
pub const ToolCallFragment = struct {
    index: usize,
    id: ?[]const u8 = null,
    name: ?[]const u8 = null,
    arguments: ?[]const u8 = null,
};
