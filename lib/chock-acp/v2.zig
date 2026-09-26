//! ACP version 2: the methods, who answers each one, and what it renamed.
//!
//! ## An alpha, and spoken only when a client asks for it
//!
//! Version 2 was `2.0.0-alpha.5` when this was written, and its own fields moved
//! between alphas: a diff payload was renamed, semantic string types were added,
//! and a `cancelled` status appeared. So `common.negotiate` never chooses it over
//! a version the client offered. It is here so a client that already speaks it
//! is answered rather than refused, and so the difference from version 1 is
//! written down in one place.
//!
//! ## What it changed, against version 1
//!
//! * **The client no longer reads files or runs terminals.** `fs/*` and
//!   `terminal/*` are gone from the client's side. Chock never called them, so
//!   this costs it nothing and is the direction it already wanted.
//! * **The capability tree collapsed.** Version 1 has `loadSession`,
//!   `promptCapabilities`, `mcpCapabilities` and `sessionCapabilities` beside
//!   each other. Version 2 has `auth` and `session`.
//! * **`session/load` became `session/resume`**, and `session/set_mode` is gone:
//!   a mode is a config option now.
//! * **`authenticate` and `logout` became `auth/login` and `auth/logout`.**
//! * **The update stream was rebuilt.** A whole message can be sent as well as a
//!   chunk of one, a tool call's content arrives as its own chunk, a terminal has
//!   its own updates, and `plan` became `plan_update`. There is no `tool_call`
//!   variant: a call is reported through `tool_call_update` from the start.
//! * **A tool call may be `cancelled`**, which version 1 cannot say.
//! * **`initialize` requires client info**, which version 1 leaves optional, and
//!   `clientCapabilities` is called `capabilities`.

const std = @import("std");

const common = @import("common.zig");

pub const StopReason = common.StopReason;
pub const ToolKind = common.ToolKind;
pub const PermissionKind = common.PermissionKind;

/// The version this speaks.
pub const protocol_version: u16 = 2;

/// A method this agent answers, or a method it calls on the client.
pub const Method = enum {
    // Answered here, by the agent.
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
    // Called on the client.
    session_update,
    session_request_permission,
    elicitation_create,
    elicitation_complete,
    // Either side.
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

/// The `sessionUpdate` member of a `session/update` notification.
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

/// Where a tool call has got to. Version 1 has the first four.
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
    // The client no longer reads files or runs terminals for the agent. A method
    // table that still held these would let a caller reach for one and be
    // refused by a client rather than by this.
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

    // A mode is a config option in version 2, so there is no method for one.
    try testing.expectEqual(@as(?Method, null), Method.fromWireName("session/set_mode"));
}

test "version 2's own enums spell themselves the way its schema does" {
    inline for (.{ UpdateKind, ToolCallStatus }) |Kind| {
        inline for (@typeInfo(Kind).@"enum".fields) |field| {
            const one: Kind = @enumFromInt(field.value);
            try testing.expectEqualStrings(field.name, one.wireName());
        }
    }

    // The two differences from version 1 that a caller has to know about.
    try testing.expectEqualStrings("cancelled", ToolCallStatus.cancelled.wireName());
    try testing.expectEqual(@as(usize, 5), @typeInfo(ToolCallStatus).@"enum".fields.len);
    try testing.expectEqualStrings("plan_update", UpdateKind.plan_update.wireName());
    try testing.expectEqual(@as(usize, 16), @typeInfo(UpdateKind).@"enum".fields.len);
}

test "a tool call is reported without a tool_call variant" {
    // Version 1 opens a call with `tool_call` and follows it with
    // `tool_call_update`. Version 2 has only the update, so an encoder that
    // reached for a `tool_call` here would not compile rather than send a
    // variant no client reads.
    inline for (@typeInfo(UpdateKind).@"enum".fields) |field| {
        try testing.expect(!std.mem.eql(u8, field.name, "tool_call"));
        try testing.expect(!std.mem.eql(u8, field.name, "plan"));
        try testing.expect(!std.mem.eql(u8, field.name, "current_mode_update"));
    }
}
