//! The neutral message type Chock's provider adapters read and write.

const std = @import("std");
const chock_proto = @import("chock-proto");

pub const Message = chock_proto.event.Message;

pub const ContentPart = chock_proto.event.ContentPart;

pub const Role = chock_proto.event.Role;

pub const Reasoning = chock_proto.event.Reasoning;

pub const ToolResultPart = chock_proto.event.ToolResultPart;

pub const ToolCall = chock_proto.event.ToolUse;

pub const Usage = chock_proto.event.Usage;

pub const Cost = chock_proto.event.Cost;

pub const Amount = chock_proto.event.Amount;

pub const Capability = enum {
    tool_calls,
    image_results,
};

pub const ToolDefinition = struct {
    name: []const u8,
    description: []const u8,
    parameters: std.json.Value,
};

pub const Request = struct {
    model: []const u8,
    system: []const u8,
    messages: []const Message,
    tools: []const ToolDefinition = &.{},
};

pub const ToolCallFragment = struct {
    index: usize,
    id: ?[]const u8 = null,
    name: ?[]const u8 = null,
    arguments: ?[]const u8 = null,
};
