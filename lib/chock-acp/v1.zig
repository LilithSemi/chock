//! ACP version 1: the methods, who answers each one, and the values its enums
//! take. Chock speaks version 1, since version 2 is still alpha, and never
//! calls the client's file or terminal methods, running a tool call in its own sandbox instead.

const std = @import("std");

const common = @import("common.zig");

pub const StopReason = common.StopReason;
pub const ToolKind = common.ToolKind;
pub const PermissionKind = common.PermissionKind;

/// Bumped only for a breaking change; everything else negotiates by capability.
pub const protocol_version: u16 = 1;

pub const Method = enum {
    initialize,
    authenticate,
    logout,
    session_new,
    session_load,
    session_prompt,
    session_cancel,
    session_set_mode,
    session_set_config_option,
    session_list,
    session_delete,
    session_resume,
    session_close,
    session_update,
    session_request_permission,
    fs_read_text_file,
    fs_write_text_file,
    terminal_create,
    terminal_output,
    terminal_release,
    terminal_wait_for_exit,
    terminal_kill,
    elicitation_create,
    elicitation_complete,
    cancel_request,

    /// A client sending a client method is confused; answering would be worse than refusing.
    pub const Side = enum { agent, client, protocol };

    pub fn side(self: Method) Side {
        return switch (self) {
            .initialize,
            .authenticate,
            .logout,
            .session_new,
            .session_load,
            .session_prompt,
            .session_cancel,
            .session_set_mode,
            .session_set_config_option,
            .session_list,
            .session_delete,
            .session_resume,
            .session_close,
            => .agent,
            .session_update,
            .session_request_permission,
            .fs_read_text_file,
            .fs_write_text_file,
            .terminal_create,
            .terminal_output,
            .terminal_release,
            .terminal_wait_for_exit,
            .terminal_kill,
            .elicitation_create,
            .elicitation_complete,
            => .client,
            .cancel_request => .protocol,
        };
    }

    /// Spells a slash as underscore, like the schema's table.
    pub fn wireName(self: Method) []const u8 {
        return switch (self) {
            .initialize => "initialize",
            .authenticate => "authenticate",
            .logout => "logout",
            .session_new => "session/new",
            .session_load => "session/load",
            .session_prompt => "session/prompt",
            .session_cancel => "session/cancel",
            .session_set_mode => "session/set_mode",
            .session_set_config_option => "session/set_config_option",
            .session_list => "session/list",
            .session_delete => "session/delete",
            .session_resume => "session/resume",
            .session_close => "session/close",
            .session_update => "session/update",
            .session_request_permission => "session/request_permission",
            .fs_read_text_file => "fs/read_text_file",
            .fs_write_text_file => "fs/write_text_file",
            .terminal_create => "terminal/create",
            .terminal_output => "terminal/output",
            .terminal_release => "terminal/release",
            .terminal_wait_for_exit => "terminal/wait_for_exit",
            .terminal_kill => "terminal/kill",
            .elicitation_create => "elicitation/create",
            .elicitation_complete => "elicitation/complete",
            .cancel_request => "$/cancel_request",
        };
    }

    pub fn fromWireName(name: []const u8) ?Method {
        inline for (@typeInfo(Method).@"enum".fields) |field| {
            const one: Method = @enumFromInt(field.value);
            if (std.mem.eql(u8, one.wireName(), name)) return one;
        }
        return null;
    }

    pub fn isNotification(self: Method) bool {
        return switch (self) {
            .session_cancel, .session_update, .elicitation_complete, .cancel_request => true,
            else => false,
        };
    }
};

/// Says which variant a `session/update`'s `sessionUpdate` object is.
pub const UpdateKind = enum {
    user_message_chunk,
    agent_message_chunk,
    agent_thought_chunk,
    tool_call,
    tool_call_update,
    plan,
    available_commands_update,
    current_mode_update,
    config_option_update,
    session_info_update,
    usage_update,

    pub fn wireName(self: UpdateKind) []const u8 {
        return @tagName(self);
    }
};

/// Version 2 adds `cancelled` to this.
pub const ToolCallStatus = enum {
    pending,
    in_progress,
    completed,
    failed,

    pub fn wireName(self: ToolCallStatus) []const u8 {
        return @tagName(self);
    }
};

const testing = std.testing;

test "every method has a wire name and reads back as itself" {
    // Catches a method added but forgotten in the name table.
    inline for (@typeInfo(Method).@"enum".fields) |field| {
        const one: Method = @enumFromInt(field.value);
        const name = one.wireName();
        try testing.expect(name.len != 0);
        try testing.expectEqual(one, Method.fromWireName(name).?);
    }
    try testing.expectEqual(@as(?Method, null), Method.fromWireName("session/nothing"));
}

test "the methods this agent answers are the ones the schema puts on the agent" {
    // Copied from the schema's own `x-side` tags.
    const agent_side = [_][]const u8{
        "initialize",     "authenticate",     "logout",
        "session/new",    "session/load",     "session/prompt",
        "session/cancel", "session/set_mode", "session/set_config_option",
        "session/list",   "session/delete",   "session/resume",
        "session/close",
    };
    for (agent_side) |name| {
        const one = Method.fromWireName(name).?;
        try testing.expectEqual(Method.Side.agent, one.side());
    }

    const client_side = [_][]const u8{
        "session/update",     "session/request_permission", "fs/read_text_file",
        "fs/write_text_file", "terminal/create",            "terminal/output",
        "terminal/release",   "terminal/wait_for_exit",     "terminal/kill",
        "elicitation/create", "elicitation/complete",
    };
    for (client_side) |name| {
        try testing.expectEqual(Method.Side.client, Method.fromWireName(name).?.side());
    }

    try testing.expectEqual(Method.Side.protocol, Method.cancel_request.side());
}

test "a notification takes no reply, and a request does" {
    try testing.expect(Method.session_cancel.isNotification());
    try testing.expect(Method.session_update.isNotification());
    try testing.expect(Method.cancel_request.isNotification());

    // `session/prompt`'s reply carries the stop reason for the whole turn.
    try testing.expect(!Method.session_prompt.isNotification());
    try testing.expect(!Method.initialize.isNotification());
    try testing.expect(!Method.session_request_permission.isNotification());
}

test "version 1's own enums spell themselves the way its schema does" {
    try testing.expectEqualStrings("agent_message_chunk", UpdateKind.agent_message_chunk.wireName());
    try testing.expectEqualStrings("tool_call_update", UpdateKind.tool_call_update.wireName());
    try testing.expectEqualStrings("in_progress", ToolCallStatus.in_progress.wireName());

    inline for (.{ UpdateKind, ToolCallStatus }) |Kind| {
        inline for (@typeInfo(Kind).@"enum".fields) |field| {
            const one: Kind = @enumFromInt(field.value);
            try testing.expectEqualStrings(field.name, one.wireName());
        }
    }

    // Reading v2's set as v1's would misread a status.
    try testing.expectEqual(@as(usize, 4), @typeInfo(ToolCallStatus).@"enum".fields.len);
    // `tool_call` is v1 only; v2 has no such variant.
    try testing.expect(std.mem.indexOf(u8, UpdateKind.tool_call.wireName(), "tool_call") != null);
    try testing.expectEqual(@as(usize, 11), @typeInfo(UpdateKind).@"enum".fields.len);
}
