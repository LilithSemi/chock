//! ACP version 2: the methods, who answers each one, and what it renamed.
//! It is `2.0.0-alpha.5`, so `common.negotiate` never chooses it over a
//! version the client offered.

const std = @import("std");

const common = @import("common.zig");

pub const StopReason = common.StopReason;
pub const ToolKind = common.ToolKind;
pub const PermissionKind = common.PermissionKind;

pub const protocol_version: u16 = 2;

pub const Method = enum {
    initialize,
    auth_login,
    auth_logout,
    session_new,
    session_prompt,
    session_cancel,
    session_set_config_option,
    session_list,
    session_delete,
    session_resume,
    session_close,
    session_update,
    session_request_permission,
    elicitation_create,
    elicitation_complete,
    cancel_request,

    pub const Side = enum { agent, client, protocol };

    pub fn side(self: Method) Side {
        return switch (self) {
            .initialize,
            .auth_login,
            .auth_logout,
            .session_new,
            .session_prompt,
            .session_cancel,
            .session_set_config_option,
            .session_list,
            .session_delete,
            .session_resume,
            .session_close,
            => .agent,
            .session_update,
            .session_request_permission,
            .elicitation_create,
            .elicitation_complete,
            => .client,
            .cancel_request => .protocol,
        };
    }

    pub fn wireName(self: Method) []const u8 {
        return switch (self) {
            .initialize => "initialize",
            .auth_login => "auth/login",
            .auth_logout => "auth/logout",
            .session_new => "session/new",
            .session_prompt => "session/prompt",
            .session_cancel => "session/cancel",
            .session_set_config_option => "session/set_config_option",
            .session_list => "session/list",
            .session_delete => "session/delete",
            .session_resume => "session/resume",
            .session_close => "session/close",
            .session_update => "session/update",
            .session_request_permission => "session/request_permission",
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

pub const UpdateKind = enum {
    user_message_chunk,
    user_message,
    agent_message_chunk,
    agent_message,
    agent_thought_chunk,
    agent_thought,
    state_update,
    tool_call_content_chunk,
    tool_call_update,
    terminal_update,
    terminal_output_chunk,
    plan_update,
    available_commands_update,
    config_option_update,
    session_info_update,
    usage_update,

    pub fn wireName(self: UpdateKind) []const u8 {
        return @tagName(self);
    }
};

/// Version 1 has the first four of these.
pub const ToolCallStatus = enum {
    pending,
    in_progress,
    completed,
    failed,
    cancelled,

    pub fn wireName(self: ToolCallStatus) []const u8 {
        return @tagName(self);
    }
};

const testing = std.testing;

test "every method has a wire name and reads back as itself" {
    inline for (@typeInfo(Method).@"enum".fields) |field| {
        const one: Method = @enumFromInt(field.value);
        const name = one.wireName();
        try testing.expect(name.len != 0);
        try testing.expectEqual(one, Method.fromWireName(name).?);
    }
    try testing.expectEqual(@as(?Method, null), Method.fromWireName("session/nothing"));
}

test "the methods this agent answers are the ones the schema puts on the agent" {
    // Copied from the version 2 schema's own method table.
    const agent_side = [_][]const u8{
        "initialize",     "auth/login",                "auth/logout",
        "session/new",    "session/prompt",            "session/cancel",
        "session/list",   "session/set_config_option", "session/delete",
        "session/resume", "session/close",
    };
    for (agent_side) |name| {
        try testing.expectEqual(Method.Side.agent, Method.fromWireName(name).?.side());
    }

    const client_side = [_][]const u8{
        "session/update", "session/request_permission", "elicitation/create", "elicitation/complete",
    };
    for (client_side) |name| {
        try testing.expectEqual(Method.Side.client, Method.fromWireName(name).?.side());
    }
}

test "what version 2 dropped is absent here, not renamed" {
    // The client no longer reads files or runs terminals.
    for ([_][]const u8{
        "fs/read_text_file", "fs/write_text_file", "terminal/create",
        "terminal/output",   "terminal/release",   "terminal/wait_for_exit",
        "terminal/kill",
    }) |gone| {
        try testing.expectEqual(@as(?Method, null), Method.fromWireName(gone));
    }

    // And these three were renamed rather than dropped.
    try testing.expectEqual(@as(?Method, null), Method.fromWireName("authenticate"));
    try testing.expectEqual(@as(?Method, null), Method.fromWireName("logout"));
    try testing.expectEqual(@as(?Method, null), Method.fromWireName("session/load"));
    try testing.expect(Method.fromWireName("auth/login") != null);
    try testing.expect(Method.fromWireName("auth/logout") != null);
    try testing.expect(Method.fromWireName("session/resume") != null);

    // A mode is a config option in v2; no method for one.
    try testing.expectEqual(@as(?Method, null), Method.fromWireName("session/set_mode"));
}

test "version 2's own enums spell themselves the way its schema does" {
    inline for (.{ UpdateKind, ToolCallStatus }) |Kind| {
        inline for (@typeInfo(Kind).@"enum".fields) |field| {
            const one: Kind = @enumFromInt(field.value);
            try testing.expectEqualStrings(field.name, one.wireName());
        }
    }

    // Two differences from version 1 a caller must know.
    try testing.expectEqualStrings("cancelled", ToolCallStatus.cancelled.wireName());
    try testing.expectEqual(@as(usize, 5), @typeInfo(ToolCallStatus).@"enum".fields.len);
    try testing.expectEqualStrings("plan_update", UpdateKind.plan_update.wireName());
    try testing.expectEqual(@as(usize, 16), @typeInfo(UpdateKind).@"enum".fields.len);
}

test "a tool call is reported without a tool_call variant" {
    // Version 2 has only `tool_call_update`; reaching for `tool_call` wouldn't compile.
    inline for (@typeInfo(UpdateKind).@"enum".fields) |field| {
        try testing.expect(!std.mem.eql(u8, field.name, "tool_call"));
        try testing.expect(!std.mem.eql(u8, field.name, "plan"));
        try testing.expect(!std.mem.eql(u8, field.name, "current_mode_update"));
    }
}
