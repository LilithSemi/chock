//! The events that make up a session log.
//!
//! Wire rule: a reader keeps what it does not know and writes it back out. An
//! unknown field goes to `extra`. An unknown event kind or enum member becomes
//! `unknown` and keeps its raw name. A writer never removes or renames a field.

const std = @import("std");

pub const ExtraMember = struct {
    name: []const u8,
    value: std.json.Value,
};

pub const Extra = struct {
    members: []const ExtraMember = &.{},
};

fn hasExtraField(comptime T: type) bool {
    for (@typeInfo(T).@"struct".fields) |field| {
        if (std.mem.eql(u8, field.name, "extra")) return true;
    }
    return false;
}

fn ForwardCompatible(comptime T: type) type {
    comptime std.debug.assert(hasExtraField(T));
    const fields = @typeInfo(T).@"struct".fields;

    return struct {
        pub fn jsonStringify(self: T, jw: *std.json.Stringify) std.json.Stringify.Error!void {
            try jw.beginObject();
            inline for (fields) |field| {
                if (comptime !std.mem.eql(u8, field.name, "extra")) {
                    try jw.objectField(field.name);
                    try jw.write(@field(self, field.name));
                }
            }
            // Unknown members go after the known fields, never before them.
            for (self.extra.members) |member| {
                try jw.objectField(member.name);
                try jw.write(member.value);
            }
            try jw.endObject();
        }

        pub fn jsonParse(
            allocator: std.mem.Allocator,
            source: anytype,
            options: std.json.ParseOptions,
        ) std.json.ParseError(@TypeOf(source.*))!T {
            if (.object_begin != try source.next()) return error.UnexpectedToken;

            const max_len = options.max_value_len orelse std.json.default_max_value_len;
            var result: T = undefined;
            var seen = [_]bool{false} ** fields.len;
            var extras: std.ArrayList(ExtraMember) = .empty;

            while (true) {
                const name_token = try source.nextAllocMax(allocator, .alloc_if_needed, max_len);
                const name = switch (name_token) {
                    .object_end => break,
                    .string, .allocated_string => |slice| slice,
                    else => return error.UnexpectedToken,
                };

                var matched = false;
                inline for (fields, 0..) |field, i| {
                    if (comptime !std.mem.eql(u8, field.name, "extra")) {
                        if (!matched and std.mem.eql(u8, field.name, name)) {
                            @field(result, field.name) =
                                try std.json.innerParse(field.type, allocator, source, options);
                            seen[i] = true;
                            matched = true;
                        }
                    }
                }
                if (matched) continue;

                // `alloc_if_needed` can give a slice into the scanner buffer,
                // which the next token overwrites, so copy the name.
                try extras.append(allocator, .{
                    .name = try allocator.dupe(u8, name),
                    .value = try std.json.innerParse(std.json.Value, allocator, source, options),
                });
            }

            inline for (fields, 0..) |field, i| {
                if (comptime std.mem.eql(u8, field.name, "extra")) {
                    result.extra = .{ .members = try extras.toOwnedSlice(allocator) };
                } else if (!seen[i]) {
                    const default = field.default_value_ptr orelse return error.MissingField;
                    @field(result, field.name) = @as(*const field.type, @ptrCast(@alignCast(default))).*;
                }
            }
            return result;
        }
    };
}

pub const Kind = enum {
    session_start,
    session_config,
    session_end,
    session_spawn,
    session_title,
    session_imported,
    message,
    tool_call,
    tool_result,
    approval_request,
    approval_response,
    prompt_password,
    diff,
    compaction,
    usage,
    task_complete,
    agent_complete,
    plan_update,
    policy_self,
    workspace_open,
    workspace_integrate,
    workspace_adopt,
    sandbox_open,
    sandbox_supervisor,
    sandbox_syscalls,
    device_exposed,
    network_summary,
    unknown,

    pub fn wireName(self: Kind) []const u8 {
        std.debug.assert(self != .unknown);
        return wire_names.get(self);
    }

    pub fn fromWireName(name: []const u8) ?Kind {
        inline for (@typeInfo(Kind).@"enum".fields) |field| {
            const kind: Kind = @enumFromInt(field.value);
            if (kind == .unknown) continue;
            if (std.mem.eql(u8, wire_names.get(kind), name)) return kind;
        }
        return null;
    }
};

const wire_names = std.EnumArray(Kind, []const u8).init(.{
    .session_start = "session.start",
    .session_config = "session.config",
    .session_end = "session.end",
    .session_spawn = "session.spawn",
    .session_title = "session.title",
    .session_imported = "session.imported",
    .message = "message",
    .tool_call = "tool.call",
    .tool_result = "tool.result",
    .approval_request = "approval.request",
    .approval_response = "approval.response",
    .prompt_password = "prompt.password",
    .diff = "diff",
    .compaction = "compaction",
    .usage = "usage",
    .task_complete = "task.complete",
    .agent_complete = "agent.complete",
    .plan_update = "plan.update",
    .policy_self = "policy.self",
    .workspace_open = "workspace.open",
    .workspace_integrate = "workspace.integrate",
    .workspace_adopt = "workspace.adopt",
    .sandbox_open = "sandbox.open",
    .sandbox_supervisor = "sandbox.supervisor",
    .sandbox_syscalls = "sandbox.syscalls",
    .device_exposed = "device.exposed",
    .network_summary = "network.summary",
    .unknown = "unknown",
});

fn WireString(comptime T: type) type {
    return struct {
        pub fn wireName(self: T) []const u8 {
            return switch (self) {
                .unknown => |name| name,
                inline else => |_, tag| @tagName(tag),
            };
        }

        pub fn jsonStringify(self: T, jw: *std.json.Stringify) std.json.Stringify.Error!void {
            try jw.write(wireName(self));
        }

        pub fn jsonParse(
            allocator: std.mem.Allocator,
            source: anytype,
            options: std.json.ParseOptions,
        ) std.json.ParseError(@TypeOf(source.*))!T {
            const max_len = options.max_value_len orelse std.json.default_max_value_len;
            const token = try source.nextAllocMax(allocator, .alloc_if_needed, max_len);
            const text = switch (token) {
                .string, .allocated_string => |slice| slice,
                else => return error.UnexpectedToken,
            };
            inline for (@typeInfo(T).@"union".fields) |field| {
                if (comptime std.mem.eql(u8, field.name, "unknown")) continue;
                if (std.mem.eql(u8, field.name, text)) return @unionInit(T, field.name, {});
            }
            return @unionInit(T, "unknown", try allocator.dupe(u8, text));
        }
    };
}

pub const Role = union(enum) {
    user,
    assistant,
    system,
    tool,
    unknown: []const u8,

    pub const wireName = WireString(Role).wireName;
    pub const jsonStringify = WireString(Role).jsonStringify;
    pub const jsonParse = WireString(Role).jsonParse;
};

pub const SessionStart = struct {
    agent_kind: []const u8,
    model_alias: []const u8,
    parent_session: []const u8,
    spawn_chain: []const SpawnLink = &.{},
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// What a person put on the command line, and the content of the file the
/// session read its policy from. Together these are the part of a session's
/// configuration that its own log would not otherwise hold: a flag leaves no
/// trace in `chock.zon`, and a `chock.zon` that is edited but never committed
/// leaves none in git.
///
/// A field nobody set is left out, so a reader sees what the session had and
/// never a list of what it did not. `config_hash` is the one exception: it is
/// always written, because its absence is the fact worth recording.
pub const SessionConfig = struct {
    /// SHA-256 of `chock.zon`, lower case hex. Null means the project has no
    /// `chock.zon`, so the session ran under the built in rules alone.
    config_hash: ?[]const u8 = null,
    /// SHA-256 over what the sandbox of this run lets a tool call reach: its
    /// mounts, its rules, its scratch areas, its limits, its network mode and
    /// its devices. Two runs of one session that differ here did not run the
    /// same sandbox, which is the alteration this event exists to show.
    sandbox_hash: []const u8 = "",
    /// Every file `--instructions` named, in the order given.
    instructions: []const []const u8 = &.{},
    /// Every `--policy-rule`, as the person wrote it.
    policy_rules: []const []const u8 = &.{},
    /// The `devShells` attribute this session read, from `--dev-shell` or
    /// from the `nix` block.
    dev_shell: []const u8 = "",
    /// True when `--allow-dirty` put uncommitted work in the workspace.
    allow_dirty: bool = false,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonParse = forward.jsonParse;

    /// Not `ForwardCompatible.jsonStringify`, which writes every field. A
    /// reader of this event asks what the session was given, and a row of
    /// empty strings answers a question nobody asked.
    pub fn jsonStringify(self: SessionConfig, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        try jw.beginObject();

        try jw.objectField("config_hash");
        try jw.write(self.config_hash);

        if (self.sandbox_hash.len != 0) {
            try jw.objectField("sandbox_hash");
            try jw.write(self.sandbox_hash);
        }
        if (self.instructions.len != 0) {
            try jw.objectField("instructions");
            try jw.write(self.instructions);
        }
        if (self.policy_rules.len != 0) {
            try jw.objectField("policy_rules");
            try jw.write(self.policy_rules);
        }
        if (self.dev_shell.len != 0) {
            try jw.objectField("dev_shell");
            try jw.write(self.dev_shell);
        }
        if (self.allow_dirty) {
            try jw.objectField("allow_dirty");
            try jw.write(true);
        }

        for (self.extra.members) |member| {
            try jw.objectField(member.name);
            try jw.write(member.value);
        }
        try jw.endObject();
    }
};

pub const SessionEndReason = union(enum) {
    finished,
    canceled_by_user,
    errored,
    budget_reached,
    no_progress,
    turn_limit,
    handed_over,
    empty_response,
    /// The provider answered with `stop_reason` `refusal`. A retry gets the
    /// same refusal: the platform refuses again unless the session is reset.
    /// Chock does not retry, change model, or reword what the provider said.
    refused_by_model,
    rate_limited,
    unknown: []const u8,

    pub const wireName = WireString(SessionEndReason).wireName;
    pub const jsonStringify = WireString(SessionEndReason).jsonStringify;
    pub const jsonParse = WireString(SessionEndReason).jsonParse;
};

pub const SessionEnd = struct {
    reason: SessionEndReason,
    detail: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const SessionSpawn = struct {
    child_session: []const u8,
    child_agent_kind: []const u8,
    reason: []const u8,
    budget_max_cost: f64 = 0,
    budget_currency: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const SessionTitle = struct {
    /// Untrusted text put in front of a person. A reader must cut it to length
    /// and take out the bytes that drive a terminal.
    title: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// A new session log records that a transcript from another harness was
/// brought in as context. It never claims Chock witnessed the imported work,
/// only that on this date this machine read these bytes from that source. The
/// imported turns are not written as `message` events; this row and its hash
/// are the whole record.
///
/// `from`, `source_path`, `content_hash` and `imported_ms` are always written,
/// because an import missing any of them is not a record of anything. A field
/// nobody set is left out.
pub const SessionImported = struct {
    /// The harness it came from, as this build names it.
    from: []const u8,
    /// Where it was read on the machine that ran the import.
    source_path: []const u8,
    /// SHA-256 of the imported bytes, lower case hex. The chain covers this
    /// event, so this is what ties it to exactly what was read.
    content_hash: []const u8,
    /// When the import ran. Not when the work happened.
    imported_ms: i64,
    /// The time range the source claims for the work. The source's word, not
    /// this machine's observation. Zero when the source stated none.
    source_started_ms: i64 = 0,
    source_ended_ms: i64 = 0,
    /// How many turns the transcript held.
    messages: usize = 0,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonParse = forward.jsonParse;

    /// Not `ForwardCompatible.jsonStringify`. `from`, `source_path`,
    /// `content_hash` and `imported_ms` are always written; the rest appear
    /// only when the import set them.
    pub fn jsonStringify(self: SessionImported, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        try jw.beginObject();

        try jw.objectField("from");
        try jw.write(self.from);
        try jw.objectField("source_path");
        try jw.write(self.source_path);
        try jw.objectField("content_hash");
        try jw.write(self.content_hash);
        try jw.objectField("imported_ms");
        try jw.write(self.imported_ms);

        if (self.source_started_ms != 0) {
            try jw.objectField("source_started_ms");
            try jw.write(self.source_started_ms);
        }
        if (self.source_ended_ms != 0) {
            try jw.objectField("source_ended_ms");
            try jw.write(self.source_ended_ms);
        }
        if (self.messages != 0) {
            try jw.objectField("messages");
            try jw.write(self.messages);
        }

        for (self.extra.members) |member| {
            try jw.objectField(member.name);
            try jw.write(member.value);
        }
        try jw.endObject();
    }
};

/// `signature` must be kept exactly as given. A changed or dropped signature
/// makes the provider treat the block as forged on the next turn.
pub const Reasoning = struct {
    text: []const u8,
    signature: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const ToolUse = struct {
    call_id: []const u8,
    tool: []const u8,
    arguments: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const ToolResultPart = struct {
    call_id: []const u8,
    output: []const u8,
    is_error: bool,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const ImagePart = struct {
    call_id: []const u8,
    media_type: []const u8,
    /// Base64, padded, with no line breaks. `std.json.Stringify` writes a
    /// `[]const u8` that is not valid UTF-8 as an array of integers, and image
    /// bytes are never valid UTF-8.
    data: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const UnknownPart = struct {
    name: []const u8,
    raw: std.json.Value,
};

pub const ContentPart = union(enum) {
    text: []const u8,
    reasoning: Reasoning,
    tool_use: ToolUse,
    tool_result: ToolResultPart,
    image: ImagePart,
    unknown: UnknownPart,

    pub fn jsonStringify(self: ContentPart, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        try jw.beginObject();
        switch (self) {
            .unknown => |part| {
                try jw.objectField(part.name);
                try jw.write(part.raw);
            },
            inline else => |payload, tag| {
                try jw.objectField(@tagName(tag));
                try jw.write(payload);
            },
        }
        try jw.endObject();
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!ContentPart {
        if (.object_begin != try source.next()) return error.UnexpectedToken;

        const max_len = options.max_value_len orelse std.json.default_max_value_len;
        const name_token = try source.nextAllocMax(allocator, .alloc_if_needed, max_len);
        const field_name = switch (name_token) {
            .string, .allocated_string => |slice| slice,
            else => return error.UnexpectedToken,
        };

        var result: ContentPart = undefined;
        if (std.mem.eql(u8, field_name, "text")) {
            result = .{ .text = try std.json.innerParse([]const u8, allocator, source, options) };
        } else if (std.mem.eql(u8, field_name, "reasoning")) {
            result = .{ .reasoning = try std.json.innerParse(Reasoning, allocator, source, options) };
        } else if (std.mem.eql(u8, field_name, "tool_use")) {
            result = .{ .tool_use = try std.json.innerParse(ToolUse, allocator, source, options) };
        } else if (std.mem.eql(u8, field_name, "tool_result")) {
            result = .{ .tool_result = try std.json.innerParse(ToolResultPart, allocator, source, options) };
        } else if (std.mem.eql(u8, field_name, "image")) {
            result = .{ .image = try std.json.innerParse(ImagePart, allocator, source, options) };
        } else {
            result = .{ .unknown = .{
                .name = try allocator.dupe(u8, field_name),
                .raw = try std.json.innerParse(std.json.Value, allocator, source, options),
            } };
        }

        if (.object_end != try source.next()) return error.UnexpectedToken;
        return result;
    }
};

pub const Message = struct {
    role: Role,
    content: []const ContentPart,
    model_alias: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const ToolCall = struct {
    call_id: []const u8,
    tool: []const u8,
    arguments: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const ImageRef = struct {
    media_type: []const u8,
    byte_count: u64,
    content_hash: []const u8,
    /// `jsonStringify` below leaves this out, so it never reaches the log and
    /// a value parsed back from a log is always empty.
    data: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());

    pub fn jsonStringify(self: ImageRef, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        try jw.beginObject();
        try jw.objectField("media_type");
        try jw.write(self.media_type);
        try jw.objectField("byte_count");
        try jw.write(self.byte_count);
        try jw.objectField("content_hash");
        try jw.write(self.content_hash);
        for (self.extra.members) |member| {
            try jw.objectField(member.name);
            try jw.write(member.value);
        }
        try jw.endObject();
    }

    pub const jsonParse = forward.jsonParse;
};

pub const ToolResult = struct {
    call_id: []const u8,
    output: []const u8,
    is_error: bool,
    /// A reader must not treat a truncated `output` as the complete result.
    truncated: bool,
    /// Chock's own sentence to the person watching. It never reaches the
    /// model, which reads `output` alone.
    note: []const u8 = "",
    image: ?ImageRef = null,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const SpawnLink = struct {
    agent_kind: []const u8,
    reason: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const ApprovalRequest = struct {
    action: []const u8,
    summary: []const u8,
    detail: []const u8,
    reason: []const u8,
    agent_kind: []const u8,
    spawn_chain: []const SpawnLink,
    /// A request still unanswered at this time is a refusal.
    timeout_at_ms: i64,
    tool_call_id: []const u8,
    review: ReviewVerdict = .none,
    review_note: []const u8 = "",
    source: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const ApprovalDecision = union(enum) {
    allowed_by_policy,
    denied_by_policy,
    approved_by_user,
    /// Kept only for the life of this process. It can narrow how often a
    /// person is asked, and never widen what the policy table permits.
    approved_by_user_for_session,
    refused_by_user,
    expired,
    approved_by_review,
    refused_by_review,
    /// The policy asked for a review and there was none to be had. It is a
    /// refusal. A review that could not run is never permission.
    review_unavailable,
    unknown: []const u8,

    pub const wireName = WireString(ApprovalDecision).wireName;
    pub const jsonStringify = WireString(ApprovalDecision).jsonStringify;
    pub const jsonParse = WireString(ApprovalDecision).jsonParse;
};

pub const ApprovalResponse = struct {
    /// Zero when the policy table answered on its own. An id is a byte offset,
    /// and byte zero is inside the header line, so no event can have id zero.
    request_id: u64,
    decision: ApprovalDecision,
    responder: []const u8,
    action: []const u8 = "",
    tool_call_id: []const u8 = "",
    review: ReviewVerdict = .none,
    /// It never travels back to the agent that asked, because the reviewer is
    /// told why the policy is what it is.
    review_note: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// Git or SSH asked for a credential. The answer never enters the log. It
/// travels straight to the broker over the control channel.
pub const PromptPassword = struct {
    correlation_id: []const u8,
    prompt: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const ReviewVerdict = union(enum) {
    none,
    approved,
    rejected,
    unknown: []const u8,

    pub const wireName = WireString(ReviewVerdict).wireName;
    pub const jsonStringify = WireString(ReviewVerdict).jsonStringify;
    pub const jsonParse = WireString(ReviewVerdict).jsonParse;
};

pub const Diff = struct {
    path: []const u8,
    patch: []const u8,
    change_set_id: []const u8,
    review: ReviewVerdict,
    review_note: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const EventRange = struct {
    from_id: u64,
    through_id: u64,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// The log keeps every event. Only the context the model sees gets shorter.
pub const Compaction = struct {
    summary: []const u8,
    from_id: u64,
    through_id: u64,
    kept_ranges: []const EventRange,
    model_alias: []const u8,
    stand_in_reason: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const TaskStatus = union(enum) {
    exited,
    signaled,
    timed_out,
    did_not_run,
    unknown: []const u8,

    pub const wireName = WireString(TaskStatus).wireName;
    pub const jsonStringify = WireString(TaskStatus).jsonStringify;
    pub const jsonParse = WireString(TaskStatus).jsonParse;
};

pub const TaskComplete = struct {
    task_id: []const u8,
    command: []const u8,
    status: TaskStatus,
    code: i64,
    /// The path as the agent sees it, and not the host path.
    output_path: []const u8,
    output_bytes: u64,
    truncated: bool,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const AgentOutcome = union(enum) {
    finished,
    no_progress,
    budget,
    refused,
    died,
    rate_limited,
    unknown: []const u8,

    pub const wireName = WireString(AgentOutcome).wireName;
    pub const jsonStringify = WireString(AgentOutcome).jsonStringify;
    pub const jsonParse = WireString(AgentOutcome).jsonParse;
};

pub const AgentComplete = struct {
    child_session: []const u8,
    child_agent_kind: []const u8,
    outcome: AgentOutcome,
    result: []const u8,
    scratchpad_path: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const PlanStatus = union(enum) {
    pending,
    in_progress,
    done,
    /// Not `done`, and not the same as leaving the step out.
    abandoned,
    unknown: []const u8,

    pub const wireName = WireString(PlanStatus).wireName;
    pub const jsonStringify = WireString(PlanStatus).jsonStringify;
    pub const jsonParse = WireString(PlanStatus).jsonParse;
};

pub const PlanStep = struct {
    id: []const u8,
    subject: []const u8,
    status: PlanStatus,
    blocked_by: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// `steps` is what changed, and not always the whole list. A reader merges
/// each step in by identifier.
pub const PlanUpdate = struct {
    steps: []const PlanStep,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// A reader must read a name it does not know as `deny`, which is the
/// narrowest reading there is.
pub const PolicyCeiling = union(enum) {
    deny,
    agent_then_human,
    ask,
    agent_review,
    allow,
    unknown: []const u8,

    pub const wireName = WireString(PolicyCeiling).wireName;
    pub const jsonStringify = WireString(PolicyCeiling).jsonStringify;
    pub const jsonParse = WireString(PolicyCeiling).jsonParse;
};

pub const SelfRestriction = struct {
    action: []const u8,
    ceiling: PolicyCeiling,
    reason: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const PolicySelf = struct {
    restrictions: []const SelfRestriction,
    /// A reader that drops this field folds the older, narrower promise, which
    /// is the safe direction.
    authorised: bool = false,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const WorkspaceKind = union(enum) {
    worktree,
    overlay,
    unknown: []const u8,

    pub const wireName = WireString(WorkspaceKind).wireName;
    pub const jsonStringify = WireString(WorkspaceKind).jsonStringify;
    pub const jsonParse = WireString(WorkspaceKind).jsonParse;
};

pub const WorkspaceOpen = struct {
    kind: WorkspaceKind,
    /// Fresh for each invocation, and never the session identifier.
    attempt: []const u8,
    path: []const u8,
    /// The commit the work is compared to. Empty for the overlay kind. A next
    /// owner that reads `HEAD` again gets a commit the session made itself.
    base_commit: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const WriteExecuteRule = union(enum) {
    strict,
    relaxed,
    unknown: []const u8,

    pub const wireName = WireString(WriteExecuteRule).wireName;
    pub const jsonStringify = WireString(WriteExecuteRule).jsonStringify;
    pub const jsonParse = WireString(WriteExecuteRule).jsonParse;
};

pub const WorkspaceIntegrate = struct {
    ref: []const u8,
    /// A row from a build before 2026-09-14 can carry `ref`, or `ask`, and
    /// neither of those is a landing.
    mode: []const u8,
    decision: []const u8,
    branch: []const u8,
    branch_from: []const u8,
    branch_to: []const u8,
    parked: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const WorkspaceAdopt = struct {
    attempt: []const u8,
    path: []const u8,
    files: u64 = 0,
    deleted: u64 = 0,
    skipped: u64 = 0,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const SandboxOpen = struct {
    attempt: []const u8,
    write_execute: WriteExecuteRule,
    decision: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// The supervisor holds the provider credential, and it goes on without a
/// layer rather than end the caller's program.
pub const SandboxSupervisor = struct {
    process: []const u8,
    layer: []const u8,
    fail_mode: []const u8 = "",
    confined: u64 = 0,
    /// Above zero means a process holding the credential ran without this layer.
    unconfined: u64 = 0,
    unreported: u64 = 0,
    reason: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const SyscallCount = struct {
    name: []const u8,
    count: u64 = 0,
    unverified_paths: ?UnverifiedPaths = null,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// This is telemetry and it is not audit evidence. The supervisor lets the
/// held call run, so a process can write one path and then open another. The
/// counts on `SyscallCount` come from the kernel and cannot be forged.
pub const UnverifiedPaths = struct {
    granted: u64 = 0,
    ungranted: u64 = 0,
    ungranted_unnamed: u64 = 0,
    relative: u64 = 0,
    unread: u64 = 0,
    truncated: u64 = 0,
    ungranted_names: []const []const u8 = &.{},
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const SandboxSyscalls = struct {
    mechanism: []const u8,
    observed: u64 = 0,
    /// Above zero means the rows below are short by a whole tool call.
    unobserved: u64 = 0,
    calls: []const SyscallCount = &.{},
    /// Whether the paths above are what the kernel used. False today.
    paths_verified: bool = false,
    path_readers_unreported: u64 = 0,
    path_readers_absent: u64 = 0,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const DeviceExposed = struct {
    attempt: []const u8,
    action: []const u8,
    decision: []const u8,
    /// Whether this machine's driver can act on `decision` at all. A policy
    /// answer of `allow` does not prove the device was placed.
    enforced: bool = false,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const NetworkSummary = struct {
    granted: u64 = 0,
    refused: u64 = 0,
    diagnostic: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// `value` is a float, because one turn costs less than a currency's minor
/// unit. `currency` is ISO 4217.
pub const Amount = struct {
    value: f64,
    currency: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const Cost = union(enum) {
    known: Amount,
    free,
    /// No price entry, or the provider reported no usage. Never a zero.
    unknown,
    unrecognized: UnknownPart,

    pub fn jsonStringify(self: Cost, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        try jw.beginObject();
        switch (self) {
            .known => |amount| {
                try jw.objectField("known");
                try jw.write(amount);
            },
            .unrecognized => |part| {
                try jw.objectField(part.name);
                try jw.write(part.raw);
            },
            // `true` and not an empty object, because an empty Zig tuple
            // serializes as `[]`.
            inline .free, .unknown => |_, tag| {
                try jw.objectField(@tagName(tag));
                try jw.write(true);
            },
        }
        try jw.endObject();
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!Cost {
        if (.object_begin != try source.next()) return error.UnexpectedToken;

        const max_len = options.max_value_len orelse std.json.default_max_value_len;
        const name_token = try source.nextAllocMax(allocator, .alloc_if_needed, max_len);
        const name = switch (name_token) {
            .string, .allocated_string => |slice| slice,
            else => return error.UnexpectedToken,
        };

        var result: Cost = undefined;
        if (std.mem.eql(u8, name, "known")) {
            result = .{ .known = try std.json.innerParse(Amount, allocator, source, options) };
        } else if (std.mem.eql(u8, name, "free") or std.mem.eql(u8, name, "unknown")) {
            _ = try std.json.innerParse(std.json.Value, allocator, source, options);
            result = if (std.mem.eql(u8, name, "free")) .free else .unknown;
        } else {
            result = .{ .unrecognized = .{
                .name = try allocator.dupe(u8, name),
                .raw = try std.json.innerParse(std.json.Value, allocator, source, options),
            } };
        }

        if (.object_end != try source.next()) return error.UnexpectedToken;
        return result;
    }
};

pub const Usage = struct {
    input_tokens: u64 = 0,
    output_tokens: u64 = 0,
    /// Anthropic reports these apart from `input_tokens` and bills them
    /// differently. A cache write costs more, and a cache read costs less.
    cache_creation_input_tokens: u64 = 0,
    cache_read_input_tokens: u64 = 0,
    cost: Cost = .unknown,
    price_table_version: []const u8 = "",
    model: []const u8 = "",
    model_alias: []const u8 = "",
    request_id: []const u8 = "",
    inference_ms: u64 = 0,
    /// Not always the effort that was asked for. Some models fall back to a
    /// supported level, and the billed reasoning tokens are that level's.
    reasoning_effort_applied: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;

    pub fn totalTokens(self: Usage) u64 {
        return self.input_tokens + self.output_tokens +
            self.cache_creation_input_tokens + self.cache_read_input_tokens;
    }
};

pub const UnknownEvent = struct {
    kind: []const u8,
    payload: std.json.Value,
};

pub const Event = union(Kind) {
    session_start: SessionStart,
    session_config: SessionConfig,
    session_end: SessionEnd,
    session_spawn: SessionSpawn,
    session_title: SessionTitle,
    session_imported: SessionImported,
    message: Message,
    tool_call: ToolCall,
    tool_result: ToolResult,
    approval_request: ApprovalRequest,
    approval_response: ApprovalResponse,
    prompt_password: PromptPassword,
    diff: Diff,
    compaction: Compaction,
    usage: Usage,
    task_complete: TaskComplete,
    agent_complete: AgentComplete,
    plan_update: PlanUpdate,
    policy_self: PolicySelf,
    workspace_open: WorkspaceOpen,
    workspace_integrate: WorkspaceIntegrate,
    workspace_adopt: WorkspaceAdopt,
    sandbox_open: SandboxOpen,
    sandbox_supervisor: SandboxSupervisor,
    sandbox_syscalls: SandboxSyscalls,
    device_exposed: DeviceExposed,
    network_summary: NetworkSummary,
    unknown: UnknownEvent,

    pub fn jsonStringify(self: Event, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        try jw.beginObject();
        switch (self) {
            .unknown => |payload| {
                try jw.objectField(payload.kind);
                try jw.write(payload.payload);
            },
            inline else => |payload, tag| {
                try jw.objectField(tag.wireName());
                try jw.write(payload);
            },
        }
        try jw.endObject();
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!Event {
        if (.object_begin != try source.next()) return error.UnexpectedToken;

        const max_len = options.max_value_len orelse std.json.default_max_value_len;
        const name_token = try source.nextAllocMax(allocator, .alloc_if_needed, max_len);
        const field_name = switch (name_token) {
            .string, .allocated_string => |slice| slice,
            else => return error.UnexpectedToken,
        };

        var result: Event = undefined;
        if (Kind.fromWireName(field_name)) |kind| {
            switch (kind) {
                .unknown => unreachable,
                inline else => |k| {
                    const Payload = @FieldType(Event, @tagName(k));
                    result = @unionInit(Event, @tagName(k), try std.json.innerParse(Payload, allocator, source, options));
                },
            }
        } else {
            result = .{ .unknown = .{
                .kind = try allocator.dupe(u8, field_name),
                .payload = try std.json.innerParse(std.json.Value, allocator, source, options),
            } };
        }

        if (.object_end != try source.next()) return error.UnexpectedToken;
        return result;
    }
};

/// The session log never holds a secret. A tool result is redacted before it
/// reaches this type, because `chockd` serves the log to other clients.
pub const Envelope = struct {
    /// The byte offset of this line in the log. Zero for an event not yet written.
    id: u64,
    session: []const u8,
    time_ms: i64,
    event: Event,
    version: u32 = 1,
    /// The hash of the whole line before this one, in lowercase hexadecimal,
    /// without that line's closing newline. The first event hashes the header
    /// line. Empty means no chain, and a reader must accept that.
    prev: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

pub const EncodeError = std.mem.Allocator.Error;

/// Serialize an envelope to one line of JSON. The result holds no newline,
/// because the log format uses a line break to end an event.
pub fn toJson(allocator: std.mem.Allocator, envelope: Envelope) EncodeError![]u8 {
    return std.json.Stringify.valueAlloc(allocator, envelope, .{});
}

pub const DecodeError = std.json.ParseError(std.json.Scanner);

/// `ignore_unknown_fields` must stay on. Without it, `std.json` rejects the
/// whole line with `error.UnknownField` for one field this reader has not got.
pub fn fromJson(allocator: std.mem.Allocator, text: []const u8) DecodeError!std.json.Parsed(Envelope) {
    return std.json.parseFromSlice(Envelope, allocator, text, .{ .ignore_unknown_fields = true });
}

test "every Kind has a wire name, and every wire name is a Kind" {
    inline for (@typeInfo(Kind).@"enum".fields) |field| {
        const kind: Kind = @enumFromInt(field.value);
        if (kind == .unknown) continue;
        const name = kind.wireName();
        try std.testing.expectEqual(kind, Kind.fromWireName(name).?);
    }
    try std.testing.expectEqual(@as(?Kind, null), Kind.fromWireName("no.such.event"));
}

test "the wire names are the names the rest of the product uses" {
    try std.testing.expectEqualStrings("session.start", Kind.session_start.wireName());
    try std.testing.expectEqualStrings("tool.call", Kind.tool_call.wireName());
    try std.testing.expectEqualStrings("approval.request", Kind.approval_request.wireName());
    try std.testing.expectEqualStrings("prompt.password", Kind.prompt_password.wireName());
}

test "an envelope survives a round trip through JSON" {
    const allocator = std.testing.allocator;
    const content = [_]ContentPart{.{ .text = "hello" }};
    const original = Envelope{
        .id = 4096,
        .session = "01H0",
        .time_ms = 1_700_000_000_000,
        .event = .{ .message = .{ .role = .assistant, .content = &content } },
    };

    const text = try toJson(allocator, original);
    defer allocator.free(text);

    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();

    try std.testing.expectEqual(original.id, parsed.value.id);
    try std.testing.expectEqualStrings(original.session, parsed.value.session);
    try std.testing.expectEqual(original.time_ms, parsed.value.time_ms);
    try std.testing.expectEqual(@as(u32, 1), parsed.value.version);
    try std.testing.expectEqualStrings("hello", parsed.value.event.message.content[0].text);
}

test "a path record survives a round trip, caveat and overflow count included" {
    const allocator = std.testing.allocator;
    const names = [_][]const u8{ "/etc/shadow", "/home/someone/.ssh/id_ed25519" };
    const rows = [_]SyscallCount{
        .{ .name = "openat", .count = 900, .unverified_paths = .{
            .granted = 812,
            .ungranted = 9,
            .ungranted_unnamed = 7,
            .relative = 71,
            .truncated = 1,
            .ungranted_names = &names,
        } },
        .{ .name = "connect", .count = 0 },
    };
    const original = Envelope{
        .id = 8192,
        .session = "01H0",
        .time_ms = 1_700_000_000_000,
        .event = .{ .sandbox_syscalls = .{
            .mechanism = "seccomp_user_notif",
            .observed = 3,
            .calls = &rows,
            .path_readers_unreported = 1,
        } },
    };

    const text = try toJson(allocator, original);
    defer allocator.free(text);

    try std.testing.expect(std.mem.indexOf(u8, text, "\"unverified_paths\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"paths_verified\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"ungranted_unnamed\"") != null);

    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();

    const said = parsed.value.event.sandbox_syscalls;
    try std.testing.expectEqual(false, said.paths_verified);
    try std.testing.expectEqual(@as(u64, 1), said.path_readers_unreported);

    const opens = said.calls[0].unverified_paths.?;
    try std.testing.expectEqual(@as(u64, 812), opens.granted);
    try std.testing.expectEqual(@as(u64, 9), opens.ungranted);
    try std.testing.expectEqual(@as(u64, 7), opens.ungranted_unnamed);
    try std.testing.expectEqual(@as(u64, 71), opens.relative);
    try std.testing.expectEqual(@as(u64, 1), opens.truncated);
    try std.testing.expectEqual(@as(usize, 2), opens.ungranted_names.len);
    try std.testing.expectEqualStrings("/etc/shadow", opens.ungranted_names[0]);
    try std.testing.expectEqualStrings("/home/someone/.ssh/id_ed25519", opens.ungranted_names[1]);

    try std.testing.expectEqual(@as(?UnverifiedPaths, null), said.calls[1].unverified_paths);
}

test "device.exposed carries the policy answer and whether this machine could act on it" {
    const allocator = std.testing.allocator;

    const granted = Envelope{
        .id = 12,
        .session = "01H0",
        .time_ms = 5,
        .event = .{ .device_exposed = .{
            .attempt = "01ATTEMPT",
            .action = "device.usb.1d50.6018",
            .decision = "allow",
            .enforced = true,
        } },
    };
    const text = try toJson(allocator, granted);
    defer allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"device.exposed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"enforced\":true") != null);

    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();
    const exposed = parsed.value.event.device_exposed;
    try std.testing.expectEqual(Kind.device_exposed, std.meta.activeTag(parsed.value.event));
    try std.testing.expectEqualStrings("01ATTEMPT", exposed.attempt);
    try std.testing.expectEqualStrings("device.usb.1d50.6018", exposed.action);
    try std.testing.expectEqualStrings("allow", exposed.decision);
    try std.testing.expectEqual(true, exposed.enforced);

    const refused = Envelope{
        .id = 13,
        .session = "01H0",
        .time_ms = 6,
        .event = .{ .device_exposed = .{
            .attempt = "01ATTEMPT",
            .action = "device.tty.serial.DF62585783282137",
            .decision = "ask",
        } },
    };
    const refused_text = try toJson(allocator, refused);
    defer allocator.free(refused_text);
    const refused_parsed = try fromJson(allocator, refused_text);
    defer refused_parsed.deinit();
    try std.testing.expectEqual(false, refused_parsed.value.event.device_exposed.enforced);
}

test "the log holds the description of an image and never the bytes of one" {
    const allocator = std.testing.allocator;

    const result = ToolResult{
        .call_id = "call1",
        .output = "[chock: image/png, 69 bytes, image_hash 0123456789abcdef] shot.png",
        .is_error = false,
        .truncated = false,
        .image = .{
            .media_type = "image/png",
            .byte_count = 69,
            .content_hash = "0123456789abcdef",
            .data = "iVBORw0KGgoAAAANSUhEUg==",
        },
    };

    const text = try std.json.Stringify.valueAlloc(allocator, result, .{});
    defer allocator.free(text);

    try std.testing.expect(std.mem.indexOf(u8, text, "iVBORw0KGgoAAAANSUhEUg==") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"data\"") == null);

    try std.testing.expect(std.mem.indexOf(u8, text, "\"media_type\":\"image/png\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"byte_count\":69") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"content_hash\":\"0123456789abcdef\"") != null);

    const parsed = try std.json.parseFromSlice(ToolResult, allocator, text, .{});
    defer parsed.deinit();
    const back = parsed.value.image.?;
    try std.testing.expectEqualStrings("image/png", back.media_type);
    try std.testing.expectEqual(@as(u64, 69), back.byte_count);
    try std.testing.expectEqualStrings("0123456789abcdef", back.content_hash);
    try std.testing.expectEqualStrings("", back.data);

    const plain = ToolResult{
        .call_id = "call2",
        .output = "ok",
        .is_error = false,
        .truncated = false,
    };
    const plain_text = try std.json.Stringify.valueAlloc(allocator, plain, .{});
    defer allocator.free(plain_text);
    try std.testing.expect(std.mem.indexOf(u8, plain_text, "\"image\":null") != null);
}

test "an image content part survives a round trip byte for byte" {
    const allocator = std.testing.allocator;

    const data = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1Pe";
    const content = [_]ContentPart{
        .{ .tool_result = .{ .call_id = "call1", .output = "read it", .is_error = false } },
        .{ .image = .{ .call_id = "call1", .media_type = "image/png", .data = data } },
    };
    const envelope = Envelope{
        .id = 7,
        .session = "01S",
        .time_ms = 9,
        .event = .{ .message = .{ .role = .tool, .content = &content } },
    };

    const text = try std.json.Stringify.valueAlloc(allocator, envelope, .{});
    defer allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"image\":{") != null);

    const parsed = try std.json.parseFromSlice(Envelope, allocator, text, .{});
    defer parsed.deinit();

    const back = parsed.value.event.message.content;
    try std.testing.expectEqual(@as(usize, 2), back.len);
    try std.testing.expectEqualStrings("call1", back[0].tool_result.call_id);
    try std.testing.expectEqualStrings("call1", back[1].image.call_id);
    try std.testing.expectEqualStrings("image/png", back[1].image.media_type);
    try std.testing.expectEqualStrings(data, back[1].image.data);
}

test "a reasoning block's signature survives a round trip byte for byte" {
    const allocator = std.testing.allocator;
    const signature = "EqoBCkYIARgCIkAy9f3KX+j2rAStub8vQ==";

    const content = [_]ContentPart{
        .{ .reasoning = .{ .text = "considering the approach", .signature = signature } },
    };
    const original = Envelope{
        .id = 1,
        .session = "01H0",
        .time_ms = 0,
        .event = .{ .message = .{ .role = .assistant, .content = &content } },
    };

    const text = try toJson(allocator, original);
    defer allocator.free(text);

    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();

    try std.testing.expectEqualStrings(signature, parsed.value.event.message.content[0].reasoning.signature);
}

test "a reader survives a payload field it does not know, and keeps the fields it does know" {
    const allocator = std.testing.allocator;
    const text =
        \\{"id":5,"session":"01H0","time_ms":1,"version":1,"event":{"session.start":{"agent_kind":"coder","model_alias":"main","parent_session":"","from_a_future_writer":"ignored"}}}
    ;
    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("coder", parsed.value.event.session_start.agent_kind);
    try std.testing.expectEqualStrings("main", parsed.value.event.session_start.model_alias);
}

test "a reader survives an envelope field it does not know, and keeps the fields it does know" {
    const allocator = std.testing.allocator;
    const text =
        \\{"id":9,"session":"01H0","time_ms":42,"version":1,"from_a_future_client":true,"event":{"prompt.password":{"correlation_id":"c1","prompt":"passphrase?"}}}
    ;
    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u64, 9), parsed.value.id);
    try std.testing.expectEqualStrings("c1", parsed.value.event.prompt_password.correlation_id);
}

test "a reader survives an event kind it does not know, and keeps the raw payload" {
    const allocator = std.testing.allocator;
    const text =
        \\{"id":12,"session":"01H0","time_ms":7,"version":1,"event":{"image.generated":{"note":"a future kind"}}}
    ;
    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();

    try std.testing.expectEqual(Kind.unknown, std.meta.activeTag(parsed.value.event));
    try std.testing.expectEqualStrings("image.generated", parsed.value.event.unknown.kind);
    try std.testing.expectEqualStrings("a future kind", parsed.value.event.unknown.payload.object.get("note").?.string);

    const round = try toJson(allocator, parsed.value);
    defer allocator.free(round);
    try std.testing.expect(std.mem.indexOf(u8, round, "\"image.generated\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, round, "a future kind") != null);
}

test "a reader survives an enum member it does not know, such as a future role" {
    const allocator = std.testing.allocator;
    const text =
        \\{"id":3,"session":"01H0","time_ms":0,"version":1,"event":{"message":{"role":"moderator","content":[{"text":"hi"}]}}}
    ;
    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("moderator", parsed.value.event.message.role.wireName());
    try std.testing.expectEqualStrings("hi", parsed.value.event.message.content[0].text);
}

test "a policy refusal round trips as its own decision, and an older reader keeps it as a name" {
    const allocator = std.testing.allocator;

    const original = Envelope{
        .id = 4096,
        .session = "01H0",
        .time_ms = 5,
        .event = .{ .approval_response = .{
            .request_id = 0,
            .decision = .denied_by_policy,
            .responder = "",
            .action = "git.push",
            .tool_call_id = "call1",
        } },
    };

    const text = try toJson(allocator, original);
    defer allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"denied_by_policy\"") != null);

    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();
    const response = parsed.value.event.approval_response;
    try std.testing.expectEqual(
        ApprovalDecision.denied_by_policy,
        std.meta.activeTag(response.decision),
    );
    try std.testing.expectEqual(@as(u64, 0), response.request_id);
    try std.testing.expectEqualStrings("git.push", response.action);
    try std.testing.expectEqualStrings("call1", response.tool_call_id);

    const from_the_future =
        \\{"id":8,"session":"01H0","time_ms":1,"version":1,"event":{"approval.response":{"request_id":4096,"decision":"approved_with_edits","responder":"ross"}}}
    ;
    const future = try fromJson(allocator, from_the_future);
    defer future.deinit();
    try std.testing.expectEqualStrings(
        "approved_with_edits",
        future.value.event.approval_response.decision.wireName(),
    );
    try std.testing.expectEqualStrings("", future.value.event.approval_response.action);
    try std.testing.expectEqualStrings("", future.value.event.approval_response.tool_call_id);
    try std.testing.expectEqualStrings("ross", future.value.event.approval_response.responder);
}

test "a session grant round trips as its own decision, and an older reader keeps only its name" {
    const allocator = std.testing.allocator;

    const original = Envelope{
        .id = 4096,
        .session = "01H0",
        .time_ms = 5,
        .event = .{ .approval_response = .{
            .request_id = 4096,
            .decision = .approved_by_user_for_session,
            .responder = "terminal",
            .action = "git.push",
            .tool_call_id = "call1",
        } },
    };

    const text = try toJson(allocator, original);
    defer allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"approved_by_user_for_session\"") != null);

    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();
    const response = parsed.value.event.approval_response;
    try std.testing.expectEqual(
        ApprovalDecision.approved_by_user_for_session,
        std.meta.activeTag(response.decision),
    );
    try std.testing.expectEqualStrings("git.push", response.action);
    try std.testing.expectEqualStrings("call1", response.tool_call_id);

    const OldDecision = union(enum) {
        allowed_by_policy,
        denied_by_policy,
        approved_by_user,
        refused_by_user,
        expired,
        approved_by_review,
        refused_by_review,
        review_unavailable,
        unknown: []const u8,

        pub const jsonParse = WireString(@This()).jsonParse;
    };

    var old = try std.json.parseFromSlice(
        OldDecision,
        allocator,
        "\"approved_by_user_for_session\"",
        .{},
    );
    defer old.deinit();
    try std.testing.expectEqual(std.meta.Tag(OldDecision).unknown, std.meta.activeTag(old.value));
    try std.testing.expectEqualStrings("approved_by_user_for_session", old.value.unknown);
}

test "no serialized envelope contains a raw newline, whatever the Kind, and every field round trips" {
    const allocator = std.testing.allocator;

    // A field that skips the standard string encoder leaks a raw newline into
    // the line, which breaks the one event, one line rule that the byte offset
    // ids depend on.
    const nl = "line one\nline two";

    const spawn_chain = [_]SpawnLink{.{ .agent_kind = nl, .reason = nl }};
    const content = [_]ContentPart{
        .{ .text = nl },
        .{ .reasoning = .{ .text = nl, .signature = nl } },
        .{ .tool_use = .{ .call_id = nl, .tool = nl, .arguments = nl } },
        .{ .tool_result = .{ .call_id = nl, .output = nl, .is_error = false } },
        .{ .unknown = .{ .name = nl, .raw = .{ .string = nl } } },
    };
    const kept_ranges = [_]EventRange{.{ .from_id = 1, .through_id = 2 }};
    const plan_steps = [_]PlanStep{.{ .id = nl, .subject = nl, .status = .in_progress, .blocked_by = nl }};

    const events = [_]Event{
        .{ .session_start = .{
            .agent_kind = nl,
            .model_alias = nl,
            .parent_session = nl,
            .spawn_chain = &spawn_chain,
        } },
        .{ .session_end = .{ .reason = .finished, .detail = nl } },
        .{ .session_spawn = .{ .child_session = nl, .child_agent_kind = nl, .reason = nl } },
        .{ .session_title = .{ .title = nl } },
        .{ .message = .{ .role = .assistant, .content = &content, .model_alias = nl } },
        .{ .tool_call = .{ .call_id = nl, .tool = nl, .arguments = nl } },
        .{ .tool_result = .{ .call_id = nl, .output = nl, .is_error = false, .truncated = true } },
        .{ .approval_request = .{
            .action = nl,
            .summary = nl,
            .detail = nl,
            .reason = nl,
            .agent_kind = nl,
            .spawn_chain = &spawn_chain,
            .timeout_at_ms = 1000,
            .tool_call_id = nl,
        } },
        .{ .approval_response = .{ .request_id = 1, .decision = .approved_by_user, .responder = nl } },
        .{ .approval_response = .{
            .request_id = 0,
            .decision = .denied_by_policy,
            .responder = "",
            .action = nl,
            .tool_call_id = nl,
        } },
        .{ .approval_response = .{
            .request_id = 3,
            .decision = .approved_by_review,
            .responder = nl,
            .action = nl,
            .tool_call_id = nl,
            .review = .approved,
            .review_note = nl,
        } },
        .{ .prompt_password = .{ .correlation_id = nl, .prompt = nl } },
        .{ .diff = .{ .path = nl, .patch = nl, .change_set_id = nl, .review = .approved, .review_note = nl } },
        .{ .compaction = .{ .summary = nl, .from_id = 1, .through_id = 9, .kept_ranges = &kept_ranges, .model_alias = nl } },
        .{ .usage = .{
            .input_tokens = 1200,
            .output_tokens = 150,
            .cost = .{ .known = .{ .value = 0.0042, .currency = nl } },
            .price_table_version = nl,
            .model = nl,
            .model_alias = nl,
            .request_id = nl,
            .reasoning_effort_applied = nl,
        } },
        .{ .task_complete = .{
            .task_id = nl,
            .command = nl,
            .status = .exited,
            .code = 2,
            .output_path = nl,
            .output_bytes = 4096,
            .truncated = true,
        } },
        .{ .agent_complete = .{
            .child_session = nl,
            .child_agent_kind = nl,
            .outcome = .died,
            .result = nl,
            .scratchpad_path = nl,
        } },
        .{ .plan_update = .{ .steps = &plan_steps } },
        .{ .workspace_open = .{
            .kind = .worktree,
            .attempt = nl,
            .path = nl,
            .base_commit = nl,
        } },
        .{ .workspace_integrate = .{
            .ref = nl,
            .mode = nl,
            .decision = nl,
            .branch = nl,
            .branch_from = nl,
            .branch_to = nl,
            .parked = nl,
        } },
        .{ .workspace_adopt = .{
            .attempt = nl,
            .path = nl,
        } },
        .{ .sandbox_open = .{
            .attempt = nl,
            .write_execute = .relaxed,
            .decision = nl,
        } },
        .{ .sandbox_supervisor = .{
            .process = nl,
            .layer = nl,
            .fail_mode = nl,
            .confined = 7,
            .unconfined = 1,
            .unreported = 2,
            .reason = nl,
        } },
        .{ .device_exposed = .{ .attempt = nl, .action = nl, .decision = nl } },
        .{ .network_summary = .{ .granted = 3, .refused = 1, .diagnostic = nl } },
        .{ .unknown = .{ .kind = "future.kind", .payload = .{ .string = nl } } },
    };

    for (events) |event| {
        const text = try toJson(allocator, .{
            .id = 0,
            .session = "01H0",
            .time_ms = 0,
            .event = event,
        });
        defer allocator.free(text);

        try std.testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, text, '\n'));

        const parsed = try fromJson(allocator, text);
        defer parsed.deinit();
        try std.testing.expectEqual(std.meta.activeTag(event), std.meta.activeTag(parsed.value.event));
    }
}

test "a session named twice keeps both names in the log, and the later one is later" {
    const allocator = std.testing.allocator;

    const names = [_][]const u8{ "read the parser tests", "port the parser to the new lexer" };
    var written: [names.len][]u8 = undefined;
    for (names, 0..) |name, index| {
        written[index] = try toJson(allocator, .{
            .id = index,
            .session = "01TITLE",
            .time_ms = @intCast(index + 1),
            .event = .{ .session_title = .{ .title = name } },
        });
    }
    defer for (written) |line| allocator.free(line);

    try std.testing.expect(std.mem.indexOf(u8, written[0], "\"session.title\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written[0], "session_title") == null);

    for (names, written) |name, line| {
        const parsed = try fromJson(allocator, line);
        defer parsed.deinit();
        try std.testing.expectEqualStrings(name, parsed.value.event.session_title.title);
    }
}

test "a handed over session gives its own reason, and never the one a cancel gives" {
    const allocator = std.testing.allocator;

    const text = try toJson(allocator, .{
        .id = 0,
        .session = "01H0",
        .time_ms = 0,
        .event = .{ .session_end = .{ .reason = .handed_over, .detail = "chockd asked for it" } },
    });
    defer allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"handed_over\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "canceled_by_user") == null);

    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();
    const end = parsed.value.event.session_end;
    try std.testing.expectEqual(SessionEndReason.handed_over, std.meta.activeTag(end.reason));
    try std.testing.expect(std.meta.activeTag(end.reason) != .canceled_by_user);
    try std.testing.expectEqualStrings("handed_over", end.reason.wireName());
    try std.testing.expectEqualStrings("chockd asked for it", end.detail);
}

test "workspace.open carries the attempt id and the base commit to the next owner" {
    const allocator = std.testing.allocator;

    const text = try toJson(allocator, .{
        .id = 4096,
        .session = "01H0",
        .time_ms = 3,
        .event = .{ .workspace_open = .{
            .kind = .worktree,
            .attempt = "01ATTEMPT",
            .path = "/home/ross/.cache/chock/work/01ATTEMPT",
            .base_commit = "9f2c1ab4d5e6f70819202122232425262728292a",
        } },
    });
    defer allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"workspace.open\"") != null);

    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();
    const opened = parsed.value.event.workspace_open;
    try std.testing.expectEqual(Kind.workspace_open, std.meta.activeTag(parsed.value.event));
    try std.testing.expectEqualStrings("worktree", opened.kind.wireName());
    try std.testing.expectEqualStrings("01ATTEMPT", opened.attempt);
    try std.testing.expectEqualStrings("/home/ross/.cache/chock/work/01ATTEMPT", opened.path);
    try std.testing.expectEqualStrings(
        "9f2c1ab4d5e6f70819202122232425262728292a",
        opened.base_commit,
    );

    const over = try toJson(allocator, .{
        .id = 5,
        .session = "01H0",
        .time_ms = 4,
        .event = .{ .workspace_open = .{
            .kind = .overlay,
            .attempt = "01ATTEMPT",
            .path = "/home/ross/.cache/chock/work/01ATTEMPT/upper",
            .base_commit = "",
        } },
    });
    defer allocator.free(over);
    const overlay = try fromJson(allocator, over);
    defer overlay.deinit();
    try std.testing.expectEqualStrings("overlay", overlay.value.event.workspace_open.kind.wireName());
    try std.testing.expectEqualStrings("", overlay.value.event.workspace_open.base_commit);

    const from_the_future =
        \\{"id":7,"session":"01H0","time_ms":1,"version":1,"event":{"workspace.open":{"kind":"btrfs_subvolume","attempt":"01ATTEMPT","path":"/w","base_commit":""}}}
    ;
    const future = try fromJson(allocator, from_the_future);
    defer future.deinit();
    try std.testing.expectEqualStrings(
        "btrfs_subvolume",
        future.value.event.workspace_open.kind.wireName(),
    );
}

test "a child that died and a child that finished are different outcomes on the wire" {
    const allocator = std.testing.allocator;

    const died = try toJson(allocator, .{
        .id = 0,
        .session = "01H0",
        .time_ms = 0,
        .event = .{ .agent_complete = .{
            .child_session = "01CHILD",
            .child_agent_kind = "reviewer",
            .outcome = .died,
            .result = "the child's log has no session.end",
            .scratchpad_path = "/tmp/chock/01PARENT/agents/01CHILD/scratch",
        } },
    });
    defer allocator.free(died);
    try std.testing.expect(std.mem.indexOf(u8, died, "\"died\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, died, "\"finished\"") == null);

    const read_back = try fromJson(allocator, died);
    defer read_back.deinit();
    const complete = read_back.value.event.agent_complete;
    try std.testing.expectEqualStrings("died", complete.outcome.wireName());
    try std.testing.expectEqualStrings("01CHILD", complete.child_session);
    try std.testing.expectEqualStrings(
        "/tmp/chock/01PARENT/agents/01CHILD/scratch",
        complete.scratchpad_path,
    );

    const from_the_future =
        \\{"id":9,"session":"01H0","time_ms":1,"version":1,"event":{"agent.complete":{"child_session":"01CHILD","child_agent_kind":"reviewer","outcome":"waiting_for_the_card","result":"","scratchpad_path":""}}}
    ;
    const future = try fromJson(allocator, from_the_future);
    defer future.deinit();
    try std.testing.expectEqualStrings(
        "waiting_for_the_card",
        future.value.event.agent_complete.outcome.wireName(),
    );
}

test "a field a newer writer added to a known struct is kept and written back out" {
    const allocator = std.testing.allocator;
    const text =
        \\{"id":5,"session":"01H0","time_ms":1,"version":1,"event":{"session.start":{"agent_kind":"coder","model_alias":"main","parent_session":"","from_a_future_writer":{"nested":[1,2]}}}}
    ;
    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("coder", parsed.value.event.session_start.agent_kind);
    const extra = parsed.value.event.session_start.extra.members;
    try std.testing.expectEqual(@as(usize, 1), extra.len);
    try std.testing.expectEqualStrings("from_a_future_writer", extra[0].name);

    const round = try toJson(allocator, parsed.value);
    defer allocator.free(round);
    try std.testing.expect(std.mem.indexOf(u8, round, "\"from_a_future_writer\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, round, "\"nested\":[1,2]") != null);

    const again = try fromJson(allocator, round);
    defer again.deinit();
    const round_again = try toJson(allocator, again.value);
    defer allocator.free(round_again);
    try std.testing.expectEqualStrings(round, round_again);
}

test "a field a newer writer added to the envelope itself is kept the same way" {
    const allocator = std.testing.allocator;
    const text =
        \\{"id":9,"session":"01H0","time_ms":42,"version":1,"signature":"from-section-21","event":{"prompt.password":{"correlation_id":"c1","prompt":"passphrase?"}}}
    ;
    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u64, 9), parsed.value.id);

    const round = try toJson(allocator, parsed.value);
    defer allocator.free(round);
    try std.testing.expect(std.mem.indexOf(u8, round, "\"signature\":\"from-section-21\"") != null);
}

test "a record that gained nothing serializes with its known fields and no unknown ones" {
    const allocator = std.testing.allocator;
    const content = [_]ContentPart{.{ .text = "hello" }};
    const text = try toJson(allocator, .{
        .id = 4096,
        .session = "01H0",
        .time_ms = 1_700_000_000_000,
        .event = .{ .message = .{ .role = .assistant, .content = &content } },
    });
    defer allocator.free(text);
    try std.testing.expectEqualStrings(
        "{\"id\":4096,\"session\":\"01H0\",\"time_ms\":1700000000000," ++
            "\"event\":{\"message\":{\"role\":\"assistant\",\"content\":[{\"text\":\"hello\"}]," ++
            "\"model_alias\":\"\"}},\"version\":1,\"prev\":\"\"}",
        text,
    );
}

test "an envelope with no prev on the wire reads back as no chain, never as a fault" {
    const allocator = std.testing.allocator;
    const line = "{\"id\":0,\"session\":\"01H0\",\"time_ms\":7," ++
        "\"event\":{\"session.end\":{\"reason\":\"finished\",\"detail\":\"\"}},\"version\":1}";
    const parsed = try fromJson(allocator, line);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("", parsed.value.prev);

    const chained = "{\"id\":0,\"session\":\"01H0\",\"time_ms\":7," ++
        "\"event\":{\"session.end\":{\"reason\":\"finished\",\"detail\":\"\"}},\"version\":1," ++
        "\"prev\":\"" ++ "ab" ** 32 ++ "\"}";
    const second = try fromJson(allocator, chained);
    defer second.deinit();
    try std.testing.expectEqualStrings("ab" ** 32, second.value.prev);
}

test "a usage event round trips in each of the three cost states, and they stay apart" {
    const allocator = std.testing.allocator;

    const states = [_]Cost{
        .{ .known = .{ .value = 0.0042, .currency = "USD" } },
        .free,
        .unknown,
    };
    for (states) |state| {
        const original = Envelope{
            .id = 1,
            .session = "01H0",
            .time_ms = 0,
            .event = .{ .usage = .{
                .input_tokens = 1200,
                .output_tokens = 150,
                .cache_creation_input_tokens = 300,
                .cache_read_input_tokens = 800,
                .cost = state,
                .price_table_version = "2026-08-21",
                .model = "claude-opus-5",
                .model_alias = "work",
                .request_id = "req_01",
                .inference_ms = 734,
                .reasoning_effort_applied = "high",
            } },
        };

        const text = try toJson(allocator, original);
        defer allocator.free(text);
        const parsed = try fromJson(allocator, text);
        defer parsed.deinit();

        const usage = parsed.value.event.usage;
        try std.testing.expectEqual(std.meta.activeTag(state), std.meta.activeTag(usage.cost));
        try std.testing.expectEqual(@as(u64, 1200), usage.input_tokens);
        try std.testing.expectEqual(@as(u64, 150), usage.output_tokens);
        try std.testing.expectEqual(@as(u64, 300), usage.cache_creation_input_tokens);
        try std.testing.expectEqual(@as(u64, 800), usage.cache_read_input_tokens);
        try std.testing.expectEqual(@as(u64, 2450), usage.totalTokens());
        try std.testing.expectEqualStrings("2026-08-21", usage.price_table_version);
        try std.testing.expectEqualStrings("claude-opus-5", usage.model);
        try std.testing.expectEqualStrings("work", usage.model_alias);
        try std.testing.expectEqualStrings("req_01", usage.request_id);
        try std.testing.expectEqual(@as(u64, 734), usage.inference_ms);
        try std.testing.expectEqualStrings("high", usage.reasoning_effort_applied);
        if (state == .known) {
            try std.testing.expectApproxEqAbs(@as(f64, 0.0042), usage.cost.known.value, 1e-12);
            try std.testing.expectEqualStrings("USD", usage.cost.known.currency);
        }
    }
}

test "a usage event with no cost still replays, and reads as unknown rather than free" {
    const allocator = std.testing.allocator;
    const text =
        \\{"id":3,"session":"01H0","time_ms":0,"version":1,"event":{"usage":{"input_tokens":10,"output_tokens":2}}}
    ;
    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();
    const usage = parsed.value.event.usage;
    try std.testing.expectEqual(Cost.unknown, std.meta.activeTag(usage.cost));
    try std.testing.expect(usage.cost != .free);
    try std.testing.expectEqual(@as(u64, 12), usage.totalTokens());
}

test "a cost state from a future writer keeps its name instead of reading as free" {
    const allocator = std.testing.allocator;
    const text =
        \\{"id":3,"session":"01H0","time_ms":0,"version":1,"event":{"usage":{"cost":{"estimated":{"value":1.5}}}}}
    ;
    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();
    const cost = parsed.value.event.usage.cost;
    try std.testing.expectEqual(Cost.unrecognized, std.meta.activeTag(cost));
    try std.testing.expect(cost != .free);
    try std.testing.expectEqualStrings("estimated", cost.unrecognized.name);

    const round = try toJson(allocator, parsed.value);
    defer allocator.free(round);
    try std.testing.expect(std.mem.indexOf(u8, round, "\"estimated\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, round, "1.5") != null);
}

test "a task completion records where the output is and how large, and never the output itself" {
    const allocator = std.testing.allocator;

    const build_output = "warning: unused variable\n" ** 4000;
    const text = try toJson(allocator, .{
        .id = 0,
        .session = "01H0",
        .time_ms = 0,
        .event = .{ .task_complete = .{
            .task_id = "task-01",
            .command = "make -j8",
            .status = .exited,
            .code = 0,
            .output_path = "/run/chock/tasks/task-01.out",
            .output_bytes = build_output.len,
            .truncated = false,
        } },
    });
    defer allocator.free(text);

    try std.testing.expect(text.len < build_output.len);
    try std.testing.expect(std.mem.indexOf(u8, text, "unused variable") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "task.complete") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "/run/chock/tasks/task-01.out") != null);

    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();
    const done = parsed.value.event.task_complete;
    try std.testing.expectEqualStrings("task-01", done.task_id);
    try std.testing.expectEqual(TaskStatus.exited, done.status);
    try std.testing.expectEqual(@as(u64, build_output.len), done.output_bytes);
}

test "a plan step that was abandoned reads as abandoned, and never as done or as absent" {
    const allocator = std.testing.allocator;

    const steps = [_]PlanStep{
        .{ .id = "s1", .subject = "write the fold", .status = .done },
        .{ .id = "s2", .subject = "measure it on Darwin", .status = .abandoned },
        .{ .id = "s3", .subject = "wire the command", .status = .pending, .blocked_by = "s1" },
    };
    const text = try toJson(allocator, .{
        .id = 0,
        .session = "01H0",
        .time_ms = 0,
        .event = .{ .plan_update = .{ .steps = &steps } },
    });
    defer allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "plan.update") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"abandoned\"") != null);

    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();
    const read_back = parsed.value.event.plan_update.steps;
    try std.testing.expectEqual(@as(usize, 3), read_back.len);
    try std.testing.expectEqual(PlanStatus.done, std.meta.activeTag(read_back[0].status));
    try std.testing.expectEqual(PlanStatus.abandoned, std.meta.activeTag(read_back[1].status));
    try std.testing.expect(read_back[1].status != .done);
    try std.testing.expect(read_back[1].status != .pending);
    try std.testing.expectEqualStrings("measure it on Darwin", read_back[1].subject);
    try std.testing.expectEqualStrings("s1", read_back[2].blocked_by);
    try std.testing.expectEqualStrings("", read_back[0].blocked_by);
}

test "a plan status from a future writer keeps its name instead of reading as done" {
    const allocator = std.testing.allocator;
    const text =
        \\{"id":3,"session":"01H0","time_ms":0,"version":1,"event":{"plan.update":{"steps":[{"id":"s1","subject":"ship it","status":"deferred"}]}}}
    ;
    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();
    const step = parsed.value.event.plan_update.steps[0];
    try std.testing.expectEqual(PlanStatus.unknown, std.meta.activeTag(step.status));
    try std.testing.expect(step.status != .done);
    try std.testing.expectEqualStrings("deferred", step.status.wireName());

    const round = try toJson(allocator, parsed.value);
    defer allocator.free(round);
    try std.testing.expect(std.mem.indexOf(u8, round, "\"deferred\"") != null);
}

test "a task that timed out reads as its own status and not as one that died" {
    const allocator = std.testing.allocator;
    const text =
        \\{"id":3,"session":"01H0","time_ms":0,"version":1,"event":{"task.complete":{"task_id":"task-02","command":"make","status":"timed_out","code":0,"output_path":"/run/chock/tasks/task-02.out","output_bytes":12,"truncated":false}}}
    ;
    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();
    const done = parsed.value.event.task_complete;
    try std.testing.expectEqual(TaskStatus.timed_out, done.status);
    try std.testing.expect(done.status != .signaled);
    try std.testing.expect(done.status != .exited);

    const future =
        \\{"id":4,"session":"01H0","time_ms":0,"version":1,"event":{"task.complete":{"task_id":"task-03","command":"make","status":"paused","code":0,"output_path":"p","output_bytes":0,"truncated":false}}}
    ;
    const later = try fromJson(allocator, future);
    defer later.deinit();
    try std.testing.expectEqual(TaskStatus.unknown, std.meta.activeTag(later.value.event.task_complete.status));
    try std.testing.expect(later.value.event.task_complete.status != .exited);
    try std.testing.expectEqualStrings("paused", later.value.event.task_complete.status.unknown);
}

test "a reader can tell a session that moved a branch from one that did not" {
    const allocator = std.testing.allocator;

    const moved = try toJson(allocator, .{
        .id = 1,
        .session = "01S",
        .time_ms = 1,
        .event = .{ .workspace_integrate = .{
            .ref = "refs/chock/01S",
            .mode = "merge",
            .decision = "allow",
            .branch = "refs/heads/main",
            .branch_from = "aaaa1111",
            .branch_to = "bbbb2222",
            .parked = "",
        } },
    });
    defer allocator.free(moved);
    const read_moved = try fromJson(allocator, moved);
    defer read_moved.deinit();
    try std.testing.expectEqualStrings(
        "refs/heads/main",
        read_moved.value.event.workspace_integrate.branch,
    );
    try std.testing.expectEqualStrings("", read_moved.value.event.workspace_integrate.parked);

    const parked = try toJson(allocator, .{
        .id = 2,
        .session = "01S",
        .time_ms = 2,
        .event = .{ .workspace_integrate = .{
            .ref = "refs/chock/01S",
            .mode = "merge",
            .decision = "allow",
            .branch = "",
            .branch_from = "",
            .branch_to = "",
            .parked = "dirty_tree",
        } },
    });
    defer allocator.free(parked);
    const read_parked = try fromJson(allocator, parked);
    defer read_parked.deinit();
    try std.testing.expectEqualStrings("", read_parked.value.event.workspace_integrate.branch);
    try std.testing.expectEqualStrings(
        "dirty_tree",
        read_parked.value.event.workspace_integrate.parked,
    );
    try std.testing.expectEqualStrings("merge", read_parked.value.event.workspace_integrate.mode);
}

test "a resumed run whose sandbox changed writes a different session.config" {
    const gpa = std.testing.allocator;

    const before = Event{ .session_config = .{ .config_hash = "ff00", .sandbox_hash = "aa11" } };
    const after = Event{ .session_config = .{ .config_hash = "ff00", .sandbox_hash = "bb22" } };

    const first = try std.json.Stringify.valueAlloc(gpa, before, .{});
    defer gpa.free(first);
    const second = try std.json.Stringify.valueAlloc(gpa, after, .{});
    defer gpa.free(second);

    // The same chock.zon, a different sandbox. A reader of the log sees the
    // second run was not the first one's sandbox.
    try std.testing.expect(!std.mem.eql(u8, first, second));
    try std.testing.expect(std.mem.indexOf(u8, second, "bb22") != null);
}

test "session.config writes what the session had, and never a row of empty fields" {
    const gpa = std.testing.allocator;

    const bare = Event{ .session_config = .{ .config_hash = "abc123" } };
    const text = try std.json.Stringify.valueAlloc(gpa, bare, .{});
    defer gpa.free(text);
    try std.testing.expectEqualStrings(
        "{\"session.config\":{\"config_hash\":\"abc123\"}}",
        text,
    );

    // A project with no chock.zon says so, rather than leaving the reader to
    // guess between that and a writer too old to hold the field.
    const none = Event{ .session_config = .{} };
    const said = try std.json.Stringify.valueAlloc(gpa, none, .{});
    defer gpa.free(said);
    try std.testing.expectEqualStrings("{\"session.config\":{\"config_hash\":null}}", said);
}

test "every part of a session's configuration reaches the log, and reads back" {
    const gpa = std.testing.allocator;

    const full = Event{ .session_config = .{
        .config_hash = "ff00",
        .sandbox_hash = "aa11",
        .instructions = &.{ "./task.md", "./style.md" },
        .policy_rules = &.{"net.fetch.*=allow"},
        .dev_shell = "ci",
        .allow_dirty = true,
    } };
    const text = try std.json.Stringify.valueAlloc(gpa, full, .{});
    defer gpa.free(text);

    const parsed = try std.json.parseFromSlice(Event, gpa, text, .{});
    defer parsed.deinit();

    const back = parsed.value.session_config;
    try std.testing.expectEqualStrings("ff00", back.config_hash.?);
    try std.testing.expectEqualStrings("aa11", back.sandbox_hash);
    try std.testing.expectEqual(@as(usize, 2), back.instructions.len);
    try std.testing.expectEqualStrings("./style.md", back.instructions[1]);
    try std.testing.expectEqualStrings("net.fetch.*=allow", back.policy_rules[0]);
    try std.testing.expectEqualStrings("ci", back.dev_shell);
    try std.testing.expect(back.allow_dirty);

    // Two sessions given different rules write different bytes, which is what
    // makes the chain over them worth reading.
    const other = Event{ .session_config = .{
        .config_hash = "ff00",
        .sandbox_hash = "aa11",
        .instructions = &.{ "./task.md", "./style.md" },
        .policy_rules = &.{"net.fetch.*=deny"},
        .dev_shell = "ci",
        .allow_dirty = true,
    } };
    const differs = try std.json.Stringify.valueAlloc(gpa, other, .{});
    defer gpa.free(differs);
    try std.testing.expect(!std.mem.eql(u8, text, differs));
}

test "session.imported survives a round trip through JSON" {
    const gpa = std.testing.allocator;

    const original = Event{ .session_imported = .{
        .from = "other-harness",
        .source_path = "/home/someone/.other/sessions/01H0.jsonl",
        .content_hash = "9f2a1c...",
        .imported_ms = 1_700_000_000_000,
        .source_started_ms = 1_699_000_000_000,
        .source_ended_ms = 1_699_100_000_000,
        .messages = 42,
    } };
    const text = try std.json.Stringify.valueAlloc(gpa, original, .{});
    defer gpa.free(text);

    const parsed = try std.json.parseFromSlice(Event, gpa, text, .{});
    defer parsed.deinit();

    const back = parsed.value.session_imported;
    try std.testing.expectEqualStrings("other-harness", back.from);
    try std.testing.expectEqualStrings("/home/someone/.other/sessions/01H0.jsonl", back.source_path);
    try std.testing.expectEqualStrings("9f2a1c...", back.content_hash);
    try std.testing.expectEqual(@as(i64, 1_700_000_000_000), back.imported_ms);
    try std.testing.expectEqual(@as(i64, 1_699_000_000_000), back.source_started_ms);
    try std.testing.expectEqual(@as(i64, 1_699_100_000_000), back.source_ended_ms);
    try std.testing.expectEqual(@as(usize, 42), back.messages);
}

test "session.imported always writes from, source_path, content_hash and imported_ms, and leaves out the rest" {
    const gpa = std.testing.allocator;

    const bare = Event{ .session_imported = .{
        .from = "other-harness",
        .source_path = "/tmp/transcript.json",
        .content_hash = "abc123",
        .imported_ms = 5,
    } };
    const text = try std.json.Stringify.valueAlloc(gpa, bare, .{});
    defer gpa.free(text);
    try std.testing.expectEqualStrings(
        "{\"session.imported\":{\"from\":\"other-harness\",\"source_path\":\"/tmp/transcript.json\"," ++
            "\"content_hash\":\"abc123\",\"imported_ms\":5}}",
        text,
    );
}

test "two imports of different bytes produce different JSON" {
    const gpa = std.testing.allocator;

    const first = Event{ .session_imported = .{
        .from = "other-harness",
        .source_path = "/tmp/transcript.json",
        .content_hash = "aa11",
        .imported_ms = 5,
    } };
    const second = Event{ .session_imported = .{
        .from = "other-harness",
        .source_path = "/tmp/transcript.json",
        .content_hash = "bb22",
        .imported_ms = 5,
    } };

    const first_text = try std.json.Stringify.valueAlloc(gpa, first, .{});
    defer gpa.free(first_text);
    const second_text = try std.json.Stringify.valueAlloc(gpa, second, .{});
    defer gpa.free(second_text);

    // A swapped transcript hashes differently, so the chain over it says so.
    try std.testing.expect(!std.mem.eql(u8, first_text, second_text));
}
