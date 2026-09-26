//! ACP version 1: the methods, who answers each one, and the values its enums
//! take.
//!
//! ## Version 1 and not version 2
//!
//! The schema ships both. Version 1 is released, at 1.9.1 when this was written,
//! and version 2 is `2.0.0-alpha.5` with its own fields still being renamed
//! between alphas. So this speaks 1, and `initialize` negotiates: a client
//! offering a higher version is answered with this one, which the protocol says
//! is how an agent declines a version it does not have.
//!
//! Version 2 drops `fs/*` and `terminal/*` from the client side, which is the
//! direction Chock already wants. Nothing here depends on their absence, so
//! adding 2 later is a second table beside this one.
//!
//! ## Chock never calls the client's file or terminal methods
//!
//! In version 1 a client may offer to read and write files and to run terminals
//! for the agent. Both are optional and the protocol says an agent must not call
//! one a client did not declare. Chock declares it needs neither and never calls
//! them: a tool call runs in Chock's own sandbox, which is the thing Chock is
//! for, and handing the work to the editor would put it outside every layer.
//!
//! What that costs is real and worth naming: an editor's unsaved buffer is not
//! visible to Chock, and the editor is not told which files changed as they
//! change. Chock works in its own workspace and hands the work back at the end,
//! which is the model it already has.

const std = @import("std");

/// The version this speaks. `initialize` carries an integer, bumped only for a
/// breaking change; everything else is negotiated by capability.
pub const protocol_version: u16 = 1;

/// A method this agent answers, or a method it calls on the client.
pub const Method = enum {
    // Answered here, by the agent.
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
    // Called on the client.
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
    // Either side.
    cancel_request,

    /// Which side answers this method. Read before dispatching one: a client
    /// that sent a client method is confused, and answering it would be worse
    /// than refusing it.
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

    /// The name on the wire. The enum spells a slash as an underscore, the way
    /// the schema's own method table does.
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

    /// Whether this method is a notification, which takes no reply. Answering
    /// one, or failing to answer a request, is the fault a peer notices first.
    pub fn isNotification(self: Method) bool {
        return switch (self) {
            .session_cancel, .session_update, .elicitation_complete, .cancel_request => true,
            else => false,
        };
    }
};

/// Why a prompt turn ended. Returned from `session/prompt`.
pub const StopReason = enum {
    end_turn,
    max_tokens,
    max_turn_requests,
    refusal,
    cancelled,

    pub fn wireName(self: StopReason) []const u8 {
        return @tagName(self);
    }
};

/// The `sessionUpdate` member of a `session/update` notification, which is what
/// says which variant the rest of the object is.
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

/// What a tool call is, for a client choosing how to draw it. `other` is the
/// default, so a tool that fits none of the rest still reports something.
pub const ToolKind = enum {
    read,
    edit,
    delete,
    move,
    search,
    fetch,
    execute,
    think,
    switch_mode,
    other,

    pub fn wireName(self: ToolKind) []const u8 {
        return @tagName(self);
    }
};

/// Where a tool call has got to.
pub const ToolStatus = enum {
    pending,
    in_progress,
    completed,
    failed,

    pub fn wireName(self: ToolStatus) []const u8 {
        return @tagName(self);
    }
};

/// What one answer to `session/request_permission` means. `always` is a standing
/// permission and not one answer, which is why Chock treats it as a policy
/// change and not as a reply.
pub const PermissionKind = enum {
    allow_once,
    allow_always,
    reject_once,
    reject_always,

    pub fn wireName(self: PermissionKind) []const u8 {
        return @tagName(self);
    }

    pub fn fromWireName(name: []const u8) ?PermissionKind {
        inline for (@typeInfo(PermissionKind).@"enum".fields) |field| {
            if (std.mem.eql(u8, field.name, name)) return @enumFromInt(field.value);
        }
        return null;
    }

    pub fn permits(self: PermissionKind) bool {
        return switch (self) {
            .allow_once, .allow_always => true,
            .reject_once, .reject_always => false,
        };
    }

    /// Whether this answer is meant to bind later calls as well as this one.
    pub fn isStanding(self: PermissionKind) bool {
        return switch (self) {
            .allow_always, .reject_always => true,
            .allow_once, .reject_once => false,
        };
    }
};

const testing = std.testing;

test "every method has a wire name and reads back as itself" {
    // The guard that stops a method being added to the enum and forgotten in
    // the name table, which is the same one `chock_proto.event` keeps.
    inline for (@typeInfo(Method).@"enum".fields) |field| {
        const one: Method = @enumFromInt(field.value);
        const name = one.wireName();
        try testing.expect(name.len != 0);
        try testing.expectEqual(one, Method.fromWireName(name).?);
    }
    try testing.expectEqual(@as(?Method, null), Method.fromWireName("session/nothing"));
}

test "the methods this agent answers are the ones the schema puts on the agent" {
    // Copied from the schema's own `x-side` tags, so a method that moved sides
    // between versions is caught here rather than at a client.
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

    // `session/prompt` is the one that must not be answered early: its reply
    // carries the stop reason for the whole turn.
    try testing.expect(!Method.session_prompt.isNotification());
    try testing.expect(!Method.initialize.isNotification());
    try testing.expect(!Method.session_request_permission.isNotification());
}

test "an always answer is a standing one, and a once answer is not" {
    try testing.expect(PermissionKind.allow_always.isStanding());
    try testing.expect(PermissionKind.reject_always.isStanding());
    try testing.expect(!PermissionKind.allow_once.isStanding());
    try testing.expect(!PermissionKind.reject_once.isStanding());

    try testing.expect(PermissionKind.allow_once.permits());
    try testing.expect(PermissionKind.allow_always.permits());
    try testing.expect(!PermissionKind.reject_once.permits());
    try testing.expect(!PermissionKind.reject_always.permits());

    // All four, because the docs page lists three and the schema lists four,
    // and a client may send the one the page left out.
    for ([_][]const u8{ "allow_once", "allow_always", "reject_once", "reject_always" }) |name| {
        try testing.expect(PermissionKind.fromWireName(name) != null);
    }
    try testing.expectEqual(@as(?PermissionKind, null), PermissionKind.fromWireName("maybe"));
}

test "every enum on the wire spells itself the way the schema does" {
    // The schema's values are snake case and so are these tags, so `@tagName`
    // is the wire name. This is what says so, rather than a comment.
    try testing.expectEqualStrings("end_turn", StopReason.end_turn.wireName());
    try testing.expectEqualStrings("agent_message_chunk", UpdateKind.agent_message_chunk.wireName());
    try testing.expectEqualStrings("tool_call_update", UpdateKind.tool_call_update.wireName());
    try testing.expectEqualStrings("switch_mode", ToolKind.switch_mode.wireName());
    try testing.expectEqualStrings("in_progress", ToolStatus.in_progress.wireName());

    inline for (.{ StopReason, UpdateKind, ToolKind, ToolStatus, PermissionKind }) |Kind| {
        inline for (@typeInfo(Kind).@"enum".fields) |field| {
            const one: Kind = @enumFromInt(field.value);
            try testing.expectEqualStrings(field.name, one.wireName());
        }
    }
}
