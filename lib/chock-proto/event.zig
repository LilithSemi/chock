//! The events that make up a session log.
//!
//! The log is written once and read forever after. A field, a kind, or an enum
//! member added in a later version must not stop an older reader from reading
//! everything it does understand. Every type that crosses the wire follows that
//! rule: an unrecognized field is **kept** and written back out, an unrecognized
//! `Event.Kind` becomes `.unknown` with its raw payload kept, and an
//! unrecognized member of a string enum such as `Role` becomes `.unknown` with
//! the raw name kept. A security relevant enum is never a boolean, and the same
//! argument applies to keeping an escape hatch on every enum here.
//!
//! ## A known struct that gains a field
//!
//! `UnknownEvent` covers a new event *kind*. Nothing used to cover a new
//! *field* on a known struct: `ignore_unknown_fields` skipped it, and
//! re-serialization could not invent it back, so an older `chockd` relaying a
//! newer record dropped the field silently. The loss was invisible where it
//! happened and appeared as a wrong number on somebody else's screen.
//!
//! Every struct that crosses the wire now carries an `extra` field. `Extra`
//! keeps each member this reader had no field for, by name and by raw JSON
//! value, and writes every one of them back out after the fields it does know.
//! `ForwardCompatible` is the one implementation, so the two directions cannot
//! drift, and its `jsonParse` walks the token stream rather than a
//! `std.json.Value` tree, so each known field still goes through its own
//! `jsonParse` (`Role`, `ContentPart`, `Event` all have one, and a tree walk
//! would have needed a second `jsonParseFromValue` on every one of them).
//!
//! Keeping the raw member beside the parsed struct costs one slice per record.
//! An "unknown members" bag on every struct was the alternative, which is the
//! same cost written twice. Relaying a record with fields silently missing
//! costs more than either.

const std = @import("std");

/// One member of a JSON object that the reader had no field for. `value` is
/// the raw JSON, kept verbatim so it can be written back out unchanged.
pub const ExtraMember = struct {
    name: []const u8,
    value: std.json.Value,
};

/// The members of one record that this reader does not know. Empty for a
/// record written by a peer of the same version, which is the ordinary case.
/// See this file's own top comment.
pub const Extra = struct {
    members: []const ExtraMember = &.{},
};

/// Whether `T` declares a field named `extra`, which is what `ForwardCompatible`
/// fills in and writes back.
fn hasExtraField(comptime T: type) bool {
    for (@typeInfo(T).@"struct".fields) |field| {
        if (std.mem.eql(u8, field.name, "extra")) return true;
    }
    return false;
}

/// The JSON encoding for a struct that keeps the members it does not know.
/// `T` must be a struct with a field `extra: Extra = .{}`. A struct opts in
/// with three lines:
///
/// ```zig
/// const forward = ForwardCompatible(@This());
/// pub const jsonStringify = forward.jsonStringify;
/// pub const jsonParse = forward.jsonParse;
/// ```
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
            // After the fields this reader knows, never before them, so a
            // record that gained nothing serializes byte for byte the way it
            // did before `Extra` existed.
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

                // A member from a newer writer. The name is duplicated because
                // `alloc_if_needed` can hand back a slice into the scanner's
                // own buffer, which the next token overwrites.
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

/// A tag names one kind of event. The enum member has no dot, because a Zig
/// identifier cannot hold one. `wireName` and `fromWireName` translate to and
/// from the dotted name that the wire format uses.
///
/// `unknown` is not a real kind. It is the tag `Event` carries when a line
/// names a kind this reader has never heard of. It has no fixed wire name of
/// its own, because its whole purpose is to carry whatever name it saw.
pub const Kind = enum {
    session_start,
    session_end,
    session_spawn,
    session_title,
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
    sandbox_open,
    sandbox_supervisor,
    sandbox_syscalls,
    network_summary,
    unknown,

    /// Give the dotted wire name for a kind. Never call this with `.unknown`.
    /// An unknown kind has no fixed name, only the raw name `Event` kept from
    /// the line that used it.
    pub fn wireName(self: Kind) []const u8 {
        std.debug.assert(self != .unknown);
        return wire_names.get(self);
    }

    /// Find the kind for a dotted wire name. Null when no kind uses that
    /// name, which is what a caller gets for a name from a future kind. The
    /// caller then falls back to `.unknown` and keeps the raw name itself.
    pub fn fromWireName(name: []const u8) ?Kind {
        inline for (@typeInfo(Kind).@"enum".fields) |field| {
            const kind: Kind = @enumFromInt(field.value);
            if (kind == .unknown) continue;
            if (std.mem.eql(u8, wire_names.get(kind), name)) return kind;
        }
        return null;
    }
};

// The one place that names the wire form of each kind. `wireName` and
// `fromWireName` both read this table, so the two directions cannot drift
// apart from each other. The `.unknown` entry is never read. `wireName`
// asserts before reaching it. It exists only because `EnumArray.init` needs
// every member filled in.
const wire_names = std.EnumArray(Kind, []const u8).init(.{
    .session_start = "session.start",
    .session_end = "session.end",
    .session_spawn = "session.spawn",
    .session_title = "session.title",
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
    .sandbox_open = "sandbox.open",
    .sandbox_supervisor = "sandbox.supervisor",
    .sandbox_syscalls = "sandbox.syscalls",
    .network_summary = "network.summary",
    .unknown = "unknown",
});

/// Build the JSON encoding for a value that travels the wire as one JSON
/// string: a closed, comptime known set of plain names, plus an `unknown`
/// case that keeps whatever spelling a future writer used. `T` must be a
/// `union(enum)` whose non-`unknown` fields all hold `void`, and whose
/// `unknown` field holds `[]const u8`.
///
/// Every enum that crosses the wire needs this shape, not a plain Zig enum.
/// A plain enum forces `fromWireName` to either reject a value it does not
/// know, which is the trap this file's top comment describes, or fall back to
/// `@enumFromInt` on an untrusted integer, which is undefined behaviour for a
/// tag that does not exist. `Role`, `SessionEndReason`, `ApprovalDecision`,
/// and `ReviewVerdict` all use this one implementation, so the fallback logic
/// exists exactly once.
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
            // A name from a future writer. Keep it instead of failing, so
            // the rest of the line, and the rest of the log, still reads.
            return @unionInit(T, "unknown", try allocator.dupe(u8, text));
        }
    };
}

/// The speaker of a message.
pub const Role = union(enum) {
    user,
    assistant,
    system,
    /// The turn is a tool's answer, in the shape an OpenAI compatible
    /// history expects.
    tool,
    unknown: []const u8,

    pub const wireName = WireString(Role).wireName;
    pub const jsonStringify = WireString(Role).jsonStringify;
    pub const jsonParse = WireString(Role).jsonParse;
};

/// A session began. The agent kind selects the policy that governs it.
pub const SessionStart = struct {
    agent_kind: []const u8,
    /// The model alias this session uses. The agent never learns the provider,
    /// the URL, or the key behind the alias.
    model_alias: []const u8,
    /// The session that spawned this one. Empty for a root session.
    parent_session: []const u8,
    /// Every parent between the root of the spawn tree and this agent, root
    /// first, and this agent itself left out. See `SpawnLink`. Empty for a
    /// session a person started.
    ///
    /// **The same chain the `approval.request` carries, and written once at
    /// the start.** A child's permissions are its parents' permissions made
    /// narrower, so `chock_policy.table.Table.evaluateChain` folds every kind
    /// from the root down to the asker. A log that names only
    /// `parent_session` gives a reader an identifier and not the kinds, so
    /// that reader must hold the parent log as well to say what the table
    /// answered. **A log is the record of what an agent did, and it must
    /// stand on its own**: `chock sessions export` copies one log for a
    /// collector to read, and a copy that cannot be judged without its parent
    /// is a gap in the evidence.
    ///
    /// **It is written even when the session asks for no approval.** A session
    /// that asked for nothing writes no `approval.request`, so the request is
    /// not a place a reader can always find the chain in.
    ///
    /// Empty for every log a build before this field wrote. A reader that
    /// finds it empty on a session with a parent knows the chain was not
    /// recorded, which is a different fact from a root session.
    spawn_chain: []const SpawnLink = &.{},
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// Why a session ended. A free string cannot be told apart from a typo, and
/// an enum belongs wherever a reader must act on the value.
pub const SessionEndReason = union(enum) {
    finished,
    canceled_by_user,
    errored,
    /// The session reached the budget in `chock.zon` and stopped rather than
    /// spending past it. **Not `errored`**: nothing went wrong, the cap did
    /// exactly what the user wrote it to do, and everything the session
    /// produced up to here is in the log. A reason of its own rather than a
    /// sentence a reader has to match on, which is the gap `src/main.zig` still
    /// papers over for the turn limit.
    budget_reached,
    /// The same tool was called with the same arguments enough times in a row
    /// that the session had stopped making progress. See
    /// `chock_core.Loop.no_progress_repeats`. **Not `errored`**: nothing
    /// faulted, the model simply stopped getting anywhere, and a script acts
    /// on that differently from a crash.
    no_progress,
    /// The caller asked for at most so many turns, with `--max-turns`, and
    /// the session reached that number with no final answer. Off by default:
    /// a turn count says "this is taking a while", which is fine, and it
    /// cannot say "this has stopped making progress", which is what
    /// `no_progress` is for.
    ///
    /// A member of its own, and not a sentence in `detail`. `src/main.zig`
    /// once matched a prefix of that sentence to give this its own exit code,
    /// which meant a reword in one file quietly changed the exit code a
    /// script read in another.
    turn_limit,
    /// Another process asked for this session, and the session stopped at its
    /// next turn boundary. **Not `canceled_by_user`**: nobody canceled
    /// anything, the workspace stays on disk, and the work goes on under a new
    /// owner. `src/main.zig` maps each reason to an exit code, so a reason of
    /// its own is what stops a script from reading a handover as a refusal and
    /// starting the work again.
    handed_over,
    /// The provider was reached and answered the turn with nothing at all: no
    /// text, no tool call, no content of any kind. **Not `finished`**, which is
    /// what this used to be recorded as.
    ///
    /// A session measured on 2026-08-26 holds the whole argument in three
    /// lines: `usage` counted 7367 input tokens and 0 output tokens, `message`
    /// carried an empty content list, and `session.end` said `finished` with an
    /// empty detail. The process exited 0, so a run that got nothing back read
    /// exactly like a run that did the work and had nothing left to say. That
    /// is the false OK this project refuses everywhere else: a check that was
    /// not made must never count as a check that passed.
    ///
    /// **Not `errored` either.** Nothing faulted. The connection was good, the
    /// request was accepted, and the provider chose to say nothing, which is a
    /// third thing and a different one to act on: a retry is reasonable here
    /// and is not reasonable after a fault. `detail` carries the provider's own
    /// stop reason when it sent one, because the provider usually knows why.
    empty_response,
    /// The provider refused the request: it answered with `stop_reason`
    /// `refusal`, and said so in the same message. Whatever the model had
    /// already written is in the log, because the refusal usually lands part
    /// way through a turn and the words before it were real work.
    ///
    /// **Not `errored`.** Nothing faulted. The connection was good, the
    /// request was accepted, and the status was 200. A refusal is an answer,
    /// and a script that reads it as a crash retries a request that was
    /// already answered.
    ///
    /// **Not `empty_response`, which is the one it is easiest to confuse with,
    /// and the advice is the opposite.** An empty response is the provider
    /// saying nothing, and asking again is reasonable there. Here the provider
    /// said no, and asking again gets the same no: the platform is explicit
    /// that a session which carries on without a reset is refused again and
    /// again. The two look alike on the wire, one turn with no useful content,
    /// and they must never be acted on alike.
    ///
    /// **Not `finished`.** The work did not finish. A session that ends here
    /// answered nothing, and calling that a success is the false OK this
    /// project refuses everywhere else.
    ///
    /// `detail` carries the provider's own words: the category and the
    /// explanation from `stop_details` when it sent them, and nothing invented
    /// when it sent neither. **Chock does not work around this ending**: it
    /// does not retry, change model, reset the context, or reword what the
    /// provider said.
    refused_by_model,
    unknown: []const u8,

    pub const wireName = WireString(SessionEndReason).wireName;
    pub const jsonStringify = WireString(SessionEndReason).jsonStringify;
    pub const jsonParse = WireString(SessionEndReason).jsonParse;
};

/// A session ended.
pub const SessionEnd = struct {
    reason: SessionEndReason,
    /// Free text detail, such as an error message. Empty when the reason
    /// alone says enough.
    detail: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// A parent session started a child session. The child keeps its own log.
/// The parent context receives the result of the child, not its transcript.
pub const SessionSpawn = struct {
    child_session: []const u8,
    /// The agent kind of the child. Its policy is the intersection of this
    /// kind's policy and the parent's.
    child_agent_kind: []const u8,
    /// The reason the parent gave for spawning the child.
    reason: []const u8,
    /// The slice of the parent's budget this child was given, and the currency
    /// it is written in. Zero and empty for a child that was given no cap,
    /// which is what a parent with no cap of its own hands out.
    ///
    /// **Recorded because the parent has to know what it has already handed
    /// out.** The cap covers the whole tree, and the answer taken is a slice
    /// per child, so the sum of the slices is the number that has to hold. A
    /// parent that resumed and counted from zero could hand the same money out
    /// twice. See `chock_core.subagent.budgetSlice`.
    budget_max_cost: f64 = 0,
    budget_currency: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// The agent gave this session a name a person can read.
///
/// **Written by the model and never by a rule over the first message.** A title
/// a heuristic guessed is a title about the opening sentence, and the one thing
/// that knows what the session turned out to be is the agent doing the work. See
/// `chock_core.Loop.runSetTitle`, which is what appends one.
///
/// **A later title supersedes an earlier one, and the fold takes the last.** The
/// log is append only and hash chained, so nothing can edit a title in place: an
/// agent that learns halfway through that the task was something else says so by
/// writing again. The same shape `chock_core.memory` keeps for a note, which
/// adds a version rather than replacing one, so every name a session went by
/// stays readable in the log.
///
/// **The text is untrusted and a reader has to treat it as such.** It is put in
/// front of a person, in a listing beside facts Chock states itself, so a reader
/// keeps it off column zero and takes out the bytes that drive a terminal:
/// `src/sessions.zig` holds both, and its own `titleText` says how.
pub const SessionTitle = struct {
    /// What this session is about, in the agent's own words. One line.
    ///
    /// **Bounded at the writer and cut at the reader.**
    /// `chock_core.Loop.max_title_bytes` refuses a longer one rather than
    /// cutting it, so no title in a log this build wrote is over the bound. A
    /// reader still cuts, because a log is a file on disk and this build is not
    /// the only thing that can write one.
    title: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// A block of model reasoning the provider marks opaque. `signature` proves
/// to the provider that the block was not edited. Keep it exactly as given.
/// A regenerated or dropped signature makes the provider treat the block as
/// forged on the next turn.
pub const Reasoning = struct {
    text: []const u8,
    signature: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// The model asked, inside its own turn, to run a tool. Distinct from the
/// `tool.call` event: this is the content block a provider sent as part of a
/// message, before Chock turns it into a sandboxed call.
pub const ToolUse = struct {
    call_id: []const u8,
    tool: []const u8,
    /// The arguments, already serialized to JSON text.
    arguments: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// A tool's answer, carried back to the model as part of a turn.
pub const ToolResultPart = struct {
    call_id: []const u8,
    output: []const u8,
    is_error: bool,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// A content part this reader does not recognize, for example a citation
/// block a provider adds after this reader was built. `name` is the field
/// name seen on the wire, and `raw` is its value, kept verbatim so nothing
/// a future provider sends is silently dropped.
pub const UnknownPart = struct {
    name: []const u8,
    raw: std.json.Value,
};

/// One piece of the ordered content of a model turn. A provider message is
/// not always plain text: it can carry a reasoning block, a tool call, or a
/// tool result, each with its own shape. Flattening all of that into one
/// `text` field would lose data that `chockd` cannot get back once it has
/// re-served the session to another client.
pub const ContentPart = union(enum) {
    text: []const u8,
    reasoning: Reasoning,
    tool_use: ToolUse,
    tool_result: ToolResultPart,
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
        } else {
            // A content part from a future provider adapter. Keep the name
            // and the raw JSON, so the part survives a replay through this
            // reader instead of being dropped.
            result = .{ .unknown = .{
                .name = try allocator.dupe(u8, field_name),
                .raw = try std.json.innerParse(std.json.Value, allocator, source, options),
            } };
        }

        if (.object_end != try source.next()) return error.UnexpectedToken;
        return result;
    }
};

/// One model turn, or one user turn.
pub const Message = struct {
    role: Role,
    /// The ordered content of the turn. See `ContentPart`.
    content: []const ContentPart,
    /// The alias of the model that wrote this turn. A session can mix models
    /// freely, so this is what lets a later reader say which alias produced
    /// which turn. Empty for a turn no model wrote, for example a user
    /// message.
    model_alias: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// The model asked to run a tool.
pub const ToolCall = struct {
    /// Identifies this call. The matching tool.result carries the same id.
    call_id: []const u8,
    tool: []const u8,
    /// The arguments the tool receives, already serialized to JSON text.
    arguments: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// A tool call finished.
pub const ToolResult = struct {
    call_id: []const u8,
    /// Redacted before this event is built. See the doc comment on Envelope.
    output: []const u8,
    is_error: bool,
    /// True when `output` was cut short before it reached this event. A
    /// reader must not treat `output` as the complete result.
    truncated: bool,
    /// Chock's own sentence to the person watching about this result, or
    /// empty for the ordinary call that needs none.
    ///
    /// **A tool result has two readers, and this is the second one.** The
    /// model reads `output`, and `output` is written for the model: it says
    /// what the agent may do next, which is why a refusal there tells the
    /// agent that a file is the user's to write and not its own. A person who
    /// reads that same paragraph is reading a message about themselves in the
    /// third person, and the project owner did exactly that on 2026-08-25 and
    /// reported a correct refusal as a broken feature.
    ///
    /// **It never reaches the model.** `Loop.runTool` builds the content part
    /// that feeds the next turn out of `output` alone, so this field is in the
    /// log and on the screen and nowhere else. That is what lets it be written
    /// in the second person, and it is why rewording `output` for a person is
    /// the wrong fix: the model needs the paragraph it already gets.
    ///
    /// **In the event, and not on a side channel**, so the two sentences
    /// travel together and cannot drift apart, and so a replay of the log
    /// shows the person what the person was shown at the time.
    note: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// One parent of the agent that asked, and the reason that parent gave for
/// spawning the next agent down the chain. The whole chain is required: "a
/// subagent three levels down wants to push" is the fact the user most needs
/// before answering.
pub const SpawnLink = struct {
    agent_kind: []const u8,
    reason: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// The agent asked the broker to do a privileged action. `detail` holds the
/// full content, for example a diff, and `summary` holds the one line form.
pub const ApprovalRequest = struct {
    /// For example "git.push".
    action: []const u8,
    summary: []const u8,
    detail: []const u8,
    /// The reason the agent gave for wanting to do this.
    reason: []const u8,
    /// The agent kind of the requester. Selects the policy.
    agent_kind: []const u8,
    /// Every parent between the root session and the agent that asked, root
    /// first. See `SpawnLink`.
    spawn_chain: []const SpawnLink,
    /// Unix milliseconds. A request still unanswered at this time counts as
    /// a refusal.
    timeout_at_ms: i64,
    /// The call_id of the tool.call that caused this request, so a reader
    /// can find the call that triggered it.
    tool_call_id: []const u8,
    /// What a reviewer agent already said about this request, for section
    /// 6.5's `agent_then_human`: "the reviewer answers first, and its verdict
    /// goes with the diff". `none` for every request no reviewer saw, which
    /// is every plain `ask`.
    review: ReviewVerdict = .none,
    /// The reviewer's own one line reason, for the person about to answer.
    /// Empty when `review` is `.none`.
    review_note: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// How an approval.request was answered. A security choice is never a boolean,
/// because a wrong boolean value reads as harmless. A boolean also cannot tell
/// an expired request from a refused one, and an expired request must count as
/// a refusal without losing the fact that it expired.
pub const ApprovalDecision = union(enum) {
    /// The static policy table answered `allow` without asking the user.
    allowed_by_policy,
    /// The static policy table answered `deny` without asking the user. A
    /// signature over this record comes later, and a decision with no record
    /// cannot become a signed one, so a refusal that the table made on its
    /// own is written down the same way every other decision is.
    denied_by_policy,
    /// The user answered yes.
    approved_by_user,
    /// The user answered yes, and also asked not to be asked about this exact
    /// action again for the rest of this session. `chock_proto.state.SessionGrants`
    /// is the fold that remembers it, keyed by the exact `action` string this
    /// response names, and it lives only as long as this process does:
    /// nothing this decision causes is ever written to `chock.zon`. See
    /// `SessionGrants`'s own doc for the whole contract, and in particular for
    /// why a memory kept here can only ever narrow how often a person is
    /// asked, never widen what the policy table permits.
    approved_by_user_for_session,
    /// The user answered no.
    refused_by_user,
    /// Nobody answered before the timeout named in the matching request.
    expired,
    /// A reviewer agent read the request and said yes, under `agent_review`.
    /// The matching response carries the verdict and the reviewer's own words
    /// in `review` and `review_note`.
    approved_by_review,
    /// A reviewer agent read the request and said no.
    refused_by_review,
    /// The policy asked for a review and there was none to be had: no
    /// reviewer, a reviewer that would have reviewed its own request, a
    /// reviewer that could not be paid for, or an answer this build cannot
    /// read. **It is a refusal.** A review that could not run must never
    /// become permission, so this is its own decision rather than a silent
    /// fall back to `expired`, which would say nobody was asked.
    review_unavailable,
    unknown: []const u8,

    pub const wireName = WireString(ApprovalDecision).wireName;
    pub const jsonStringify = WireString(ApprovalDecision).jsonStringify;
    pub const jsonParse = WireString(ApprovalDecision).jsonParse;
};

/// An approval request was answered. The user answers most of them. The
/// policy table answers `allowed_by_policy` and `denied_by_policy` on its
/// own, and the broker answers `expired` when the timeout passes first.
pub const ApprovalResponse = struct {
    /// The id of the approval.request envelope this answers.
    ///
    /// Zero when there is no such envelope, which happens when the policy
    /// table answered on its own: nobody is asked, so no request is written.
    /// Zero cannot be confused with a real event id. An id is the byte
    /// offset of the line, `Envelope.id` reserves zero for an event that is
    /// not yet written, and byte zero of every log is inside the header
    /// line, so no appended event can ever sit there. See
    /// `lib/chock-proto/log.zig`'s own `replayFrom`, which says the same.
    request_id: u64,
    decision: ApprovalDecision,
    /// Who decided. Empty for `allowed_by_policy`, `denied_by_policy` and
    /// `expired`, since nobody acted. A signature over this record comes
    /// later, and a record with no identity of the responder cannot become a
    /// signed one.
    responder: []const u8,
    /// The action this answers about, for example "git.push".
    ///
    /// The matching approval.request holds this too. It is repeated here so
    /// that one line says what was decided and what it was decided about. A
    /// response with `request_id` zero has no request to read it from, and a
    /// record of a refusal that names nothing is a record of nothing. Empty
    /// when the writer did not know the action.
    action: []const u8 = "",
    /// The call_id of the tool.call that caused this, so a reader can find
    /// the call without first finding the request. Empty when the writer did
    /// not know it.
    tool_call_id: []const u8 = "",
    /// What a reviewer agent said about this request, for `agent_review` and
    /// `agent_then_human`. `none` when no review ran, which is every decision
    /// the table or a person made on its own.
    review: ReviewVerdict = .none,
    /// The reviewer's own one line reason. Empty when `review` is `.none`.
    ///
    /// **This is written for the person who reads the record the next
    /// morning, and it never travels back to the agent that asked.** See
    /// `lib/chock-broker/review.zig`: the reviewer is told why the policy is
    /// what it is, and telling the asking agent the same thing would be the
    /// leak that whole file exists to prevent.
    review_note: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// Git or SSH asked for a credential and Chock is showing the prompt to the
/// user instead of a terminal. The answer to this prompt never enters the
/// log. It travels straight to the broker over the control channel. Only the
/// fact that Chock asked, and the prompt text, are recorded here.
pub const PromptPassword = struct {
    /// Links this prompt to the client's answer on the control channel.
    correlation_id: []const u8,
    prompt: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// The verdict of the read only reviewer agent, for the `agent_review` and
/// `agent_then_human` policies. `none` when no review ran.
pub const ReviewVerdict = union(enum) {
    none,
    approved,
    rejected,
    unknown: []const u8,

    pub const wireName = WireString(ReviewVerdict).wireName;
    pub const jsonStringify = WireString(ReviewVerdict).jsonStringify;
    pub const jsonParse = WireString(ReviewVerdict).jsonParse;
};

/// A proposed change to a file, not yet applied to the user's tree.
pub const Diff = struct {
    path: []const u8,
    /// A unified diff.
    patch: []const u8,
    /// Groups every diff event that belongs to one proposed change, so a
    /// reader can show them to the user as one unit.
    change_set_id: []const u8,
    review: ReviewVerdict,
    /// The reviewer's own words. Empty when `review` is `.none`.
    review_note: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// One inclusive range of event ids, using the byte offset id from Envelope.
pub const EventRange = struct {
    from_id: u64,
    through_id: u64,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// The model context was folded into a summary. The log itself keeps every
/// event. Only the context that the model sees is shorter after this.
pub const Compaction = struct {
    summary: []const u8,
    /// The first event id folded into the summary.
    from_id: u64,
    /// The last event id folded into the summary.
    through_id: u64,
    /// Ranges inside [from_id, through_id] that were kept verbatim, not
    /// folded, so a reader can show the user exactly what was dropped.
    kept_ranges: []const EventRange,
    /// The model alias that produced the summary. Empty when the harness wrote
    /// it, and `stand_in_reason` then says why.
    model_alias: []const u8,
    /// Why the harness summary stood in for the model's own. Empty when the
    /// model wrote the summary, which is the ordinary case and the one
    /// `model_alias` already names.
    ///
    /// **A compaction happens either way, so without this the failure left no
    /// trace at all.** The model call can be refused, answered with an error
    /// status, cut off partway, or answered with no summary in it. Every one
    /// of those ends with the same shorter context and the same harness
    /// written summary, and a person reading the log saw a compaction that
    /// looked ordinary. The provider's own words go here, including the
    /// category and the explanation of a refusal.
    ///
    /// Empty for every log a build before this field wrote, which is
    /// indistinguishable from a model written summary in those logs and is why
    /// `model_alias` is still the field to read for who wrote it.
    stand_in_reason: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// How a background command ended. An enum and not a free string, because a
/// reader has to act on the value wherever a number or a name decides what
/// happens next.
pub const TaskStatus = union(enum) {
    /// The command ran to its end. `TaskComplete.code` is its exit status.
    exited,
    /// A signal ended the command. `TaskComplete.code` is the signal number.
    signaled,
    /// The command ran past the bound in `chock_core.tasks.default_timeout_ns`
    /// and the harness stopped it. **Not `signaled`**, although a signal is how
    /// it was stopped: "it was still going" and "it died" ask the agent for
    /// different next steps.
    timed_out,
    /// The command produced no exit status at all: either it never started, or
    /// it ended in a way the operating system reported as neither an exit nor a
    /// signal. The output file holds whatever was said about why.
    did_not_run,
    unknown: []const u8,

    pub const wireName = WireString(TaskStatus).wireName;
    pub const jsonStringify = WireString(TaskStatus).jsonStringify;
    pub const jsonParse = WireString(TaskStatus).jsonParse;
};

/// A background command finished. See `lib/chock-core/tasks.zig`.
///
/// **The contents of the output are not here, and that is the point.** A build
/// writes megabytes and the session log is the one file a session cannot afford
/// to bloat. This records that the task ran, how it ended, where the output is,
/// and how large it was, which is everything a replay needs to know that the
/// output existed and everything a later reader needs to tell whether the file
/// in front of them is the one the agent read.
pub const TaskComplete = struct {
    /// The identifier the agent was given when it started the task.
    task_id: []const u8,
    /// The command, joined with single spaces, so a person reading the log
    /// knows what ran without matching this event to the `tool.call` beside it.
    command: []const u8,
    status: TaskStatus,
    /// The exit status, or the signal number when `status` is `signaled`. Zero
    /// when the status names neither.
    code: i64,
    /// Where the output is, as the agent sees it: a path inside the read only
    /// mount. **Not the host path**, which names a temp directory that is gone
    /// by the time anybody replays this log.
    output_path: []const u8,
    /// How many bytes landed in that file.
    output_bytes: u64,
    /// True when the command wrote more than the file kept. A reader must not
    /// treat the file as the complete output, the same warning `ToolResult`
    /// carries for the same reason.
    truncated: bool,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// How a subagent ended, as the parent reads it out of the child's own log.
/// See `chock_core.subagent`.
///
/// **A member and not a sentence**: a parent branches on this, and a code read
/// out of a message is a code a reword can change.
pub const AgentOutcome = union(enum) {
    /// The child answered, and the answer is the shape the parent asked for.
    finished,
    /// The child stopped repeating itself. See
    /// `chock_core.Loop.no_progress_repeats`.
    no_progress,
    /// The child used the whole slice of the budget it was given at spawn.
    /// **Not `refused`**: nothing went wrong, and the parent can decide to
    /// give a larger slice or to do the work itself.
    budget,
    /// The child ran and gave the parent nothing it could use: it was stopped,
    /// it faulted, it reached a turn limit, or its answer was not the shape
    /// the parent asked for.
    refused,
    /// **The child's log has no `session.end` at all.** The process was killed
    /// or it died before it could say why. A parent is told that plainly here
    /// rather than left to read a truncated log as a finished one.
    died,
    unknown: []const u8,

    pub const wireName = WireString(AgentOutcome).wireName;
    pub const jsonStringify = WireString(AgentOutcome).jsonStringify;
    pub const jsonParse = WireString(AgentOutcome).jsonParse;
};

/// A subagent this session started has finished, and this session was told.
///
/// **The parent appends this, and the child cannot.** The parent holds the
/// exclusive lock on its own log for the whole session, which is the one
/// writer rule the rest of the design keeps, and the parent is the process
/// that started the child, so the parent is what sees it end.
///
/// **Being told is therefore in the record.** A parent that acts on a child's
/// answer leaves a trace of having been told, and a replay reads the same
/// thing in the same order. A completion that lived only in the parent's
/// memory would be the one part of a session nobody could reconstruct.
///
/// **It points at three places rather than carrying them.** The child's own
/// log holds every turn, the scratchpad holds the bulk of what the child
/// wrote, and only the answer itself is here. The same discipline
/// `TaskComplete` keeps: record that it happened and where it is.
pub const AgentComplete = struct {
    /// The child's own session identifier, which is how the parent, or anybody
    /// replaying this log, reads the child's log.
    child_session: []const u8,
    /// The kind the child ran as. Already in the `session.spawn` beside this
    /// one, and repeated here so a reader of one event needs no second lookup.
    child_agent_kind: []const u8,
    outcome: AgentOutcome,
    /// The child's answer: prose, or the JSON object the parent asked for. A
    /// sentence naming what went wrong when the outcome is anything but
    /// `finished`.
    result: []const u8,
    /// The child's own scratchpad, on the host. Empty for a session that had
    /// none. **Where the bulk is**: a child answers with a verdict and a path,
    /// so a parent with six children does not spend its whole context reading.
    scratchpad_path: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// Where one step of the agent's own plan has got to.
///
/// **`abandoned` is a member and not an absence, and that is the whole point
/// of the type.** An agent that drops a step has to say so, because a list
/// where a step vanishes in silence reads as finished when it is not. The same
/// principle as `session.end` always being appended: the thing that did not
/// happen is written down too.
///
/// A union and not a plain enum, the rule every wire enum in this file keeps:
/// a status a later writer invents keeps its own spelling instead of reading
/// as one of the four this reader knows.
pub const PlanStatus = union(enum) {
    /// Named, and not started.
    pending,
    /// Being worked on now. **At most one step is ordinarily here**, and
    /// nothing enforces that: the list is the agent's own statement of intent,
    /// not a plan the harness holds it to.
    in_progress,
    /// Finished.
    done,
    /// The agent dropped this step on purpose. **Not the same as `done`, and
    /// not the same as leaving the step out**: a reader has to be able to tell
    /// work that was finished from work that was given up.
    abandoned,
    unknown: []const u8,

    pub const wireName = WireString(PlanStatus).wireName;
    pub const jsonStringify = WireString(PlanStatus).jsonStringify;
    pub const jsonParse = WireString(PlanStatus).jsonParse;
};

/// One step of the agent's own plan. Small on purpose, in the shape the events
/// beside it use: an identifier, the subject, a status, and what holds it up.
pub const PlanStep = struct {
    /// Stable for the life of the session. A later `plan.update` that names
    /// this identifier again changes this step rather than adding a second
    /// one. See `chock_proto.state.Plan`.
    id: []const u8,
    /// What the step is, in the imperative: "read the fold", not "reading the
    /// fold" and not "the fold was read".
    subject: []const u8,
    status: PlanStatus,
    /// What this step waits on, in the agent's own words. Empty when nothing
    /// holds it up, which is the ordinary case.
    blocked_by: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// The agent changed its own task list. See `chock_proto.state.Plan` for the
/// fold, and `chock_core.tools.Tool.update_plan` for what writes one.
///
/// **"Plan" and not "task", although a task list is what this is.** `task` is
/// already taken on this wire: `task.complete` is a background command,
/// `TaskComplete.task_id` is `task-01`, and `chock_core.tasks` runs them. Two
/// meanings of one word in one log is a log a reader has to disambiguate line
/// by line, so the second thing takes the other word, and `chock plan` is the
/// command that reads it back.
///
/// **The list is in the log because the log is the truth of a session**, and
/// a task list is a claim about the work. Three things follow, and the second
/// is the one that decided the design:
///
/// * It replays, so a reader sees the plan as it was at every point.
/// * **A step the agent stopped naming is still visible.** The fold keeps
///   every identifier it has ever seen, so the only way to take a step off the
///   list is to mark it `abandoned`, which is a thing the agent says rather
///   than a thing it omits.
/// * It survives compaction and a handover, because a phone that attaches and
///   the terminal fold the same log.
///
/// **`steps` is what changed, and not always the whole list.** A reader merges
/// each step into the plan it already has, by identifier. A whole list is
/// therefore a correct event too, and it says the same thing at more cost.
///
/// **Nothing appends one of these unless the agent asked.** A session that
/// never writes a plan holds no `plan.update` at all, which is what keeps a
/// one step task from carrying a task list nobody wanted.
pub const PlanUpdate = struct {
    steps: []const PlanStep,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// The most an agent has promised to hold for one action. The five names of
/// `chock_policy.table.Decision`, which is what the policy table answers with,
/// so a promise and a rule are written in one vocabulary.
///
/// A union and not a plain enum, the rule every wire enum in this file keeps.
/// The reader that acts on this is `chock_policy.ratchet.ceilingFromLog`, and
/// **it reads a name it does not know as `deny`**: a promise written by a
/// later Chock is still a promise, and the only safe reading of one this build
/// cannot measure is the narrowest there is.
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

/// One thing an agent has promised not to do, or not to do unasked.
///
/// **Three members, and the shape is `chock_policy.ratchet.Restriction`'s.**
/// That file's own comptime block allows no fourth, and the reason is written
/// there in full: a member naming a clause of the constitution would make a
/// tier that enforces nothing the warrant for a rule the broker enforces.
pub const SelfRestriction = struct {
    /// The action, or the class of actions, this covers. The same pattern
    /// language a policy rule uses: `git.*` covers every action below `git`.
    action: []const u8,
    ceiling: PolicyCeiling,
    /// Why, in the agent's own words, for the person who reads the record.
    reason: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// The agent bound itself. See `chock_proto.state.SelfPolicy` for the fold,
/// `chock_policy.ratchet` for the rule, and `chock_core.Loop` for what writes
/// one.
///
/// **The promise is in the log because a promise held only in the model's
/// attention is not a promise.** It has to survive a compaction, a resume, and
/// a handover to the daemon, and the log is the one thing that does. The same
/// reason `plan.update` is an event.
///
/// **An ordinary one never lifts a restriction.** The fold appends, and the
/// ceiling for one act is the narrowest promise that covers it, so a session's
/// own word can only ever get narrower by writing. A request to widen is
/// measured against `chock_policy.ratchet.widen_action` like any other act, and
/// it writes nothing at all unless it is authorised: see `authorised`.
pub const PolicySelf = struct {
    restrictions: []const SelfRestriction,
    /// True only for a widening that somebody other than the agent permitted.
    /// The review policy answers that question, through
    /// `chock_policy.ratchet.widen_action`, and `chock_core.Loop` is what
    /// writes this after `Broker.request` said yes.
    ///
    /// **It is on the event and never on a restriction.** The authorisation is
    /// a fact about one decision somebody made, not a property a promise
    /// carries around, and keeping it here is what lets
    /// `chock_policy.ratchet.Restriction` stay the three members its own
    /// comptime guard allows.
    ///
    /// **The fold treats it as a replacement, by exact name.**
    /// `chock_proto.state.SelfPolicy.apply` drops every promise already held
    /// whose `action` is the same string, then appends these. Exact and never a
    /// pattern: lifting a promise means naming exactly what was promised, which
    /// is the rule `chock_policy.ratchet.ceilingFor` already keeps for the
    /// question it answers.
    ///
    /// **A reader that does not know this field folds the older, narrower
    /// promise**, because `ignore_unknown_fields` drops it and the fold is then
    /// a plain append over a minimum. That is the safe direction: an older
    /// Chock reading a newer log holds the agent to more than it has to, and
    /// never to less.
    authorised: bool = false,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// What holds the files of a workspace. A member and not a free string: a
/// reader acts on this value, because a checkout has a commit of its own and
/// an overlay has none.
pub const WorkspaceKind = union(enum) {
    /// A `git worktree` checkout of the project. See
    /// `chock_workspace.worktree`.
    worktree,
    /// One overlay mount over a project that git does not track. See
    /// `chock_workspace.overlay`.
    overlay,
    unknown: []const u8,

    pub const wireName = WireString(WorkspaceKind).wireName;
    pub const jsonStringify = WireString(WorkspaceKind).jsonStringify;
    pub const jsonParse = WireString(WorkspaceKind).jsonParse;
};

/// The workspace one attempt at a session opened.
///
/// **A process that takes over a session reads the log, and reads nothing
/// else.** `chock run` mints a fresh attempt identifier for each invocation,
/// and every scratch path of the workspace carries that identifier, so no
/// second process can compute the path for itself. Without this event the next
/// owner has to build a new workspace out of committed state, which throws
/// away everything the last owner did not commit.
pub const WorkspaceOpen = struct {
    kind: WorkspaceKind,
    /// The identifier every scratch path of this workspace is named after.
    /// **Fresh for each invocation, and never the session identifier**: a
    /// session that continues would otherwise ask git for a path an earlier
    /// run already holds, and a run that died before its own teardown would
    /// then break every later `--continue`.
    attempt: []const u8,
    /// Absolute host path of the checkout, or of an overlay's upper layer.
    path: []const u8,
    /// The commit the checkout started at. Empty for the overlay kind, which
    /// has no commit of its own.
    ///
    /// **This is what the work of the session is measured against**, see
    /// `chock_workspace.worktree.Worktree.headMoved`. A next owner that read
    /// `HEAD` again would measure against a commit the session made itself,
    /// and would then report that nothing changed.
    base_commit: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// Whether the write and execute rule was on for one attempt at a session.
///
/// **A member and not a boolean**, the rule this file's own top comment gives:
/// a security relevant enum is never a boolean. A reader acts on the value, and
/// `unknown` is what an older reader gives a spelling a later Chock writes.
pub const WriteExecuteRule = union(enum) {
    /// A page may not be writable and executable at the same time. The default,
    /// and what every session gets that did not ask for anything else.
    strict,
    /// The rule was off, because this project's policy answered `allow` for
    /// `sandbox.jit`. See `lib/chock-policy/hardening.zig`.
    relaxed,
    unknown: []const u8,

    pub const wireName = WireString(WriteExecuteRule).wireName;
    pub const jsonStringify = WireString(WriteExecuteRule).jsonStringify;
    pub const jsonParse = WireString(WriteExecuteRule).jsonParse;
};

/// **What one `workspace.apply` did to the branch the user has checked out.**
///
/// This exists so that a session is distinguishable afterwards by what happened
/// to the branch. Before `chock_policy.apply` existed the answer was always
/// "nothing", and the work waited at `refs/chock/<session>` until a person ran
/// the merge. A project can now ask for `merge`, `rebase` or `squash`, and a
/// control that moved somebody's branch quietly would be the wrong shape
/// whatever it was written in. `SandboxOpen` is the same fact about the
/// sandbox, written for the same reason.
///
/// **The reason and not only the outcome.** `mode` and `decision` together say
/// why this apply was allowed to move a branch at all, so a reader can tell a
/// project that asked for a merge from an installation whose organisation
/// permitted one, and can tell a project that asked for nothing from one whose
/// merge was refused. `parked` says why a branch that was going to move did
/// not.
///
/// **Written once per apply**, whichever way it went, including the applies
/// where no branch was ever going to move. A fact recorded only when it is
/// interesting is missing whenever somebody disagrees about what is
/// interesting.
pub const WorkspaceIntegrate = struct {
    /// The ref the work is parked at. Set in every mode, because every mode
    /// parks the work there first.
    ref: []const u8,
    /// The mode this project configured, after the policy row bounded it, by
    /// the name `chock_policy.apply.Mode` gives it. `ref` for a project that
    /// configured nothing.
    mode: []const u8,
    /// The policy answer for `workspace.integrate`, by the name
    /// `chock_policy.table.Decision` gives it. Only `allow` keeps `mode`.
    decision: []const u8,
    /// The branch that moved. **Empty when no branch moved**, which is the
    /// one field a reader looking for "did somebody's branch move" reads.
    branch: []const u8,
    /// Where that branch was. Empty when none moved.
    branch_from: []const u8,
    /// Where that branch is now. Empty when none moved.
    branch_to: []const u8,
    /// Why no branch moved, by the name `chock_broker.integrate.Reason` gives
    /// it. Empty when one did.
    parked: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// The sandbox one attempt at a session ran under.
///
/// **This exists so that a session which gave up hardening is distinguishable
/// afterwards from one that did not.** `lib/chock-policy/hardening.zig` holds
/// the one row a project can write to give a piece of it up, and a control that
/// weakened a layer quietly would be the wrong shape whatever it was written
/// in. So the fact is in the log, beside `workspace.open`, which is the other
/// thing one attempt records about the machinery it built.
///
/// **Per attempt and not per session**, for the reason `WorkspaceOpen.attempt`
/// gives. A session can be continued by a later process, that process reads
/// `chock.zon` again, and the answer it gets is the answer that binds the tool
/// calls it makes. One `session.start` at the beginning of time cannot state
/// that.
pub const SandboxOpen = struct {
    /// The identifier of this attempt, the same one `WorkspaceOpen.attempt`
    /// carries, so the two lines of one run read together.
    attempt: []const u8,
    /// Whether a page could be writable and executable at the same time.
    write_execute: WriteExecuteRule,
    /// The policy answer that decided it, by the name `table.Decision` gives
    /// it. **The reason and not only the outcome**: a reader of the log can
    /// otherwise not tell a project that asked for this from an installation
    /// whose organisation permitted it.
    decision: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// Whether the supervisor process could put one layer on itself, counted over
/// the whole session.
///
/// **The supervisor holds the provider credential.** `Sandbox.spawn` forks
/// twice. The first child waits for the second and relays its outcome, and it
/// holds this program's own memory while it waits, which on the `chock run`
/// path includes the credential. It puts a Landlock ruleset and a seccomp
/// filter on itself for that reason alone.
///
/// **That install is best effort, and the degradation used to be invisible.**
/// The supervisor cannot be killed for a layer that guards nothing of the
/// caller's: the caller's program is already running by then, and ending the
/// supervisor ends it. So the supervisor prints and goes on. The printed line
/// reaches a terminal and dies with it, and the supervisor cannot write the
/// log itself, because the sandbox revoked that descriptor before it got
/// there. So nothing in the log could answer "did the credential holding
/// process run unfiltered in this session". This event is that answer.
///
/// **Written once per session and whichever way it went**, for the reason
/// `SandboxOpen` is written on every attempt: a fact recorded only when it is
/// interesting is missing whenever somebody disagrees about what is
/// interesting, and an absent event would leave a reader unable to tell a
/// session with nothing to report from a session written by an older build.
///
/// **A count and not a line per call.** The answer is a property of the
/// machine, so it is the same for every tool call of one session, and a line
/// per call would repeat one fact a thousand times. `NetworkSummary` is the
/// same shape for the same reason.
pub const SandboxSupervisor = struct {
    /// The process these counts are about, by the name the driver gives it.
    process: []const u8,
    /// The layer these counts are about, by the name of the mechanism that
    /// carries it. **A field and not part of the kind**, so a second layer of
    /// the same process is a second event of this kind rather than a second
    /// kind.
    layer: []const u8,
    /// Calls whose supervisor said the layer went on.
    confined: u64 = 0,
    /// Calls whose supervisor said it did not. **This is the field an audit
    /// reads.** Anything above zero means a process holding the credential ran
    /// without this layer.
    unconfined: u64 = 0,
    /// Calls whose supervisor said nothing at all, because it was killed
    /// before it reached the point where it puts the layer on. A cancelled
    /// tool call and one that ran past its deadline both land here.
    unreported: u64 = 0,
    /// Why the first unconfined supervisor went without the layer, by the name
    /// the driver's own fault type gives it. Empty when `unconfined` is zero.
    ///
    /// **The specific fault and never a bare "failed".** A refused
    /// `no_new_privs` flag, a missing privilege, a filter the kernel would not
    /// read, and a kernel with no seccomp at all are four different faults with
    /// four different repairs.
    reason: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// How many times the sandboxed programs of one session made one system call.
///
/// **A field and not a kind for each call.** A member added to the trap set is
/// another row here, and never another event kind, so a reader written today
/// reads a log written by a build that watches more calls.
pub const SyscallCount = struct {
    /// The call, by the name the sandbox's own trap set gives it.
    name: []const u8,
    /// How many times the sandboxed programs of this session made it.
    count: u64 = 0,
    /// **This is where a path list joins, and it joins here.** Counting is
    /// what this event carries today. The call a program made is known, and
    /// the path it named is not. When the supervisor reads the path too, it
    /// becomes another field on this struct, beside `count`, and every reader
    /// of this kind keeps working: a reader with no field for it keeps it in
    /// `extra` and writes it back out, which is what this file's own top
    /// comment promises for a struct that gains a field. No new kind, no new
    /// wire name, and no reader anywhere has to learn anything to keep
    /// reading the counts.
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// What the sandboxed programs of one session asked the kernel for.
///
/// **Chock's log could say which program an agent ran, and not what that
/// program then opened.** `tool.call` carries the argument vector, and nothing
/// after it says a word about the calls the program made. This is the answer,
/// taken at the one level a program cannot talk its way around: the kernel
/// holds the call, gives the supervisor the call number, and the supervisor
/// counts it. The number comes from the kernel, so the count cannot be forged
/// by the program it is about.
///
/// **A count and not a line for each call.** One tool call makes thousands of
/// opens, and a session makes thousands of tool calls. A record for each one
/// would grow the log without bound, which is a cost this project has already
/// paid once. `SandboxSupervisor` and `NetworkSummary` have the same shape for
/// the same reason.
///
/// **Written once per session and whichever way it went**, the same rule
/// `SandboxSupervisor` follows: a reader that found nothing could not tell a
/// session that watched nothing from a session written by a build that could
/// not watch at all.
///
/// **`observed` and `unobserved` are what make a row of zeros readable.** A
/// histogram of zeros is the honest record of a session that asked for no
/// observation, and it is also what a session whose supervisor never got the
/// notification descriptor leaves behind. Those are different facts with
/// different repairs, so they are counted apart and neither one reads as "the
/// program opened nothing".
pub const SandboxSyscalls = struct {
    /// What produced these counts, by the name the sandbox gives it. **A field
    /// and not part of the kind**, the same choice `SandboxSupervisor.layer`
    /// makes, so a second mechanism is a second event of this kind rather than
    /// a second kind.
    mechanism: []const u8,
    /// Tool calls whose supervisor watched them, so the rows below are about
    /// them.
    observed: u64 = 0,
    /// Tool calls that asked to be watched and were not. **This is the field
    /// an audit reads.** Anything above zero means the rows below are short by
    /// a whole tool call.
    unobserved: u64 = 0,
    /// One row for each call the sandbox can watch. A call nobody made still
    /// gets a row, so a reader can tell a call that was watched and never made
    /// from a call this build does not watch at all.
    calls: []const SyscallCount = &.{},
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// A tool call's own network use over the whole session, one line rather than
/// one per connection.
///
/// **A count, and never a per-connection record.** `net.connect` is allowed
/// or denied by policy alone for the ordinary case, with no question asked
/// and no `approval.request` written: see `lib/chock-broker/network.zig`'s
/// own top comment. Before this event, that decision reached a terminal line
/// and nothing else, so `SECURITY.md`'s own claim that the log is the
/// evidence was false for a tool call's own network. Written once, when the
/// session ends, because the cost of this event does not grow with the
/// number of connections and a line per connection's does: see
/// `src/run.zig`'s `ToolNetwork.deinit` for the count measured against a
/// line per connection.
pub const NetworkSummary = struct {
    /// How many connections a tool call's own sandbox reached.
    granted: u64 = 0,
    /// How many were refused.
    refused: u64 = 0,
    /// The first refusal's own diagnostic, already formatted to text. Empty
    /// when `refused` is zero.
    diagnostic: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// A sum of money. `value` is a float rather than an integer of minor units
/// because a single turn on a cheap model costs a fraction of a cent, and a
/// currency's minor unit cannot hold that.
pub const Amount = struct {
    value: f64,
    /// ISO 4217, for example "USD".
    currency: []const u8,
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// What a turn cost. **Three states, not two.**
///
/// Collapsing `free` and `unknown` is wrong in both directions. Calling
/// unknown free lets a cap be passed with nobody noticing, which is the same
/// class of fault as a policy resolving an unnamed action to allow, section
/// 8.1. Calling free unknown makes a local llama.cpp server, the cheapest way
/// to work, look like the risky one.
///
/// This is a union and not an optional for exactly that reason: an optional
/// that a caller reads as a zero has already collapsed the distinction. A
/// reader must name the case it is handling.
pub const Cost = union(enum) {
    /// The provider said, or Chock computed it from token counts and a price
    /// table. `Usage.price_table_version` names the table when Chock computed
    /// it, and is empty when the provider said.
    known: Amount,
    /// This model costs nothing to run. A fact, not an absence: a session
    /// against a local server runs under a cap without trouble.
    free,
    /// No price entry for this model, or the provider reports no usage at
    /// all. **Never treat this as a zero.**
    unknown,
    /// A state a future writer used that this reader has no case for. The raw
    /// value is kept so the record relays unchanged, the same way
    /// `UnknownEvent` and `ContentPart.unknown` already work.
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
            // `true` rather than an empty object: an empty Zig tuple
            // serializes as `[]`, and a state that reads as an empty array is
            // a shape nobody expects.
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
            // The value carries nothing; the name is the whole answer.
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

/// What one call to a model cost, in tokens and in money. **Cost that lives
/// only in the running process is lost on a `/daemonize`, on a reconnect, and
/// on a replay**, and a phone attached to a session must see the same total the
/// terminal sees. So usage is an event, like everything else that is true about
/// a session.
pub const Usage = struct {
    input_tokens: u64 = 0,
    output_tokens: u64 = 0,
    /// Anthropic reports these two apart from `input_tokens` and bills them
    /// differently: a cache write costs more than an ordinary input token and
    /// a cache read costs far less.
    cache_creation_input_tokens: u64 = 0,
    cache_read_input_tokens: u64 = 0,
    /// See `Cost`. Defaults to `unknown`, which is the honest answer for a
    /// provider that said nothing.
    cost: Cost = .unknown,
    /// Which price table produced a computed `cost`. Empty when the provider
    /// reported the number itself, or when the cost is not `known`. A wrong
    /// price is then a fact somebody can find, rather than a number nobody
    /// can explain.
    price_table_version: []const u8 = "",
    /// The model on the wire, and its alias on the roster. A session mixes
    /// models across turns, so a total that does not say which model spent
    /// what cannot be checked.
    model: []const u8 = "",
    model_alias: []const u8 = "",
    /// The provider's own correlation handle, for example ai&'s
    /// `X-Request-ID`. A user reporting a bad turn then has something the
    /// provider can look up.
    request_id: []const u8 = "",
    /// Server side time, separate from time on the wire.
    inference_ms: u64 = 0,
    /// **Not always the effort that was asked for.** Some models fall back to
    /// a supported level, and the billed reasoning tokens are the applied
    /// level's. Empty when the provider did not say.
    reasoning_effort_applied: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;

    /// Every token this call was billed for, however it was billed. The plain
    /// sum: a caller that wants the three classes priced apart reads the
    /// fields themselves.
    pub fn totalTokens(self: Usage) u64 {
        return self.input_tokens + self.output_tokens +
            self.cache_creation_input_tokens + self.cache_read_input_tokens;
    }
};

/// An event whose payload for kind `kind` was not folded into the summary.
pub const UnknownEvent = struct {
    /// The dotted wire name this reader did not recognize, kept so the
    /// event can be shown to the user and written back out unchanged.
    kind: []const u8,
    /// The raw payload for that kind, kept verbatim.
    payload: std.json.Value,
};

/// One event. The active field names the kind. `jsonStringify` and
/// `jsonParse` write and read the dotted wire name instead of the Zig field
/// name, because a Zig field name cannot hold the dot that the wire form
/// uses.
pub const Event = union(Kind) {
    session_start: SessionStart,
    session_end: SessionEnd,
    session_spawn: SessionSpawn,
    session_title: SessionTitle,
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
    sandbox_open: SandboxOpen,
    sandbox_supervisor: SandboxSupervisor,
    sandbox_syscalls: SandboxSyscalls,
    network_summary: NetworkSummary,
    /// A kind this reader does not recognize. See `UnknownEvent`.
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
                // fromWireName never returns .unknown. It is filtered out above.
                .unknown => unreachable,
                inline else => |k| {
                    const Payload = @FieldType(Event, @tagName(k));
                    result = @unionInit(Event, @tagName(k), try std.json.innerParse(Payload, allocator, source, options));
                },
            }
        } else {
            // A kind from a future writer. Keep the raw name and the raw
            // payload, so this event replays as opaque data instead of
            // taking the rest of the log down with it.
            result = .{ .unknown = .{
                .kind = try allocator.dupe(u8, field_name),
                .payload = try std.json.innerParse(std.json.Value, allocator, source, options),
            } };
        }

        if (.object_end != try source.next()) return error.UnexpectedToken;
        return result;
    }
};

/// One line of the session log. The log is the truth for a session, and the
/// session log never holds a secret: a tool result is redacted before it
/// reaches this type, because `chockd` serves the log to other clients and a
/// redaction applied later would already be too late.
pub const Envelope = struct {
    /// The byte offset of this line in the log. Zero for an event not yet written.
    id: u64,
    /// The session identifier.
    session: []const u8,
    /// Milliseconds since the epoch. The caller supplies this.
    time_ms: i64,
    event: Event,
    /// The wire format version of this envelope. The log gets a header version
    /// of its own, but this same envelope is the frame for server sent events
    /// and for the unix socket, and neither of those has a header. The envelope
    /// must carry its own version so a remote client that reconnects can tell
    /// which shape it is reading.
    version: u32 = 1,
    /// The hash of the whole line written before this one, in lowercase
    /// hexadecimal. This is what makes a log evidence against an edit: change
    /// one line and the line after it names bytes that are no longer there.
    /// See `lib/chock-proto/chain.zig`, which holds the hash, the reader, and
    /// an honest account of what a chain does not defeat.
    ///
    /// **Empty means no chain, and that is read rather than refused.** Every
    /// log written before this field existed carries an empty `prev` on every
    /// event, and those sessions must stay readable forever.
    ///
    /// The bytes hashed are the previous line exactly as it sits on disk,
    /// without its closing newline. The first event of a log carries the hash
    /// of the log's header line. `log.Locked.append` fills this in, and a
    /// caller never sets it.
    prev: []const u8 = "",
    extra: Extra = .{},

    const forward = ForwardCompatible(@This());
    pub const jsonStringify = forward.jsonStringify;
    pub const jsonParse = forward.jsonParse;
};

/// `toJson` only ever fails to allocate. `std.json.Stringify.valueAlloc`
/// writes into memory it owns, so no other error can reach the caller.
pub const EncodeError = std.mem.Allocator.Error;

/// Serialize an envelope to one line of JSON. The result holds no newline,
/// because the log format uses a line break to mark where the next event
/// starts.
pub fn toJson(allocator: std.mem.Allocator, envelope: Envelope) EncodeError![]u8 {
    return std.json.Stringify.valueAlloc(allocator, envelope, .{});
}

pub const DecodeError = std.json.ParseError(std.json.Scanner);

/// Parse one line of the session log back into an envelope.
///
/// `ignore_unknown_fields` is on. Without it, a field this reader does not
/// know, on the envelope or on any payload, makes `std.json` reject the
/// whole line with `error.UnknownField`. That turns every format growth into
/// a break for every reader that has not been rebuilt yet, which is exactly
/// what a wire format and an on disk format must not do.
pub fn fromJson(allocator: std.mem.Allocator, text: []const u8) DecodeError!std.json.Parsed(Envelope) {
    return std.json.parseFromSlice(Envelope, allocator, text, .{ .ignore_unknown_fields = true });
}

test "every Kind has a wire name, and every wire name is a Kind" {
    // A mapping in two places drifts. This proves the two directions agree.
    inline for (@typeInfo(Kind).@"enum".fields) |field| {
        const kind: Kind = @enumFromInt(field.value);
        // unknown has no fixed wire name. Its name comes from the event
        // that used it, not from this table.
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

test "a reasoning block's signature survives a round trip byte for byte" {
    const allocator = std.testing.allocator;
    // A real signature is opaque bytes the provider signs over. Any change,
    // even in whitespace, makes the provider treat the block as forged on
    // the next turn, so an exact match is the only fact that matters here.
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
    // Stands in for a newer writer that added a field to session.start.
    // An older reader must not reject the whole line over one field it has
    // never heard of.
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
    // Stands in for a future envelope field, for example one a remote
    // transport frame adds that the log format never needed.
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
    // Stands in for a kind added in a later version, for example
    // "image.generated". The old reader cannot interpret it, but it must
    // not drop it or die on it either.
    const allocator = std.testing.allocator;
    const text =
        \\{"id":12,"session":"01H0","time_ms":7,"version":1,"event":{"image.generated":{"note":"a future kind"}}}
    ;
    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();

    try std.testing.expectEqual(Kind.unknown, std.meta.activeTag(parsed.value.event));
    try std.testing.expectEqualStrings("image.generated", parsed.value.event.unknown.kind);
    try std.testing.expectEqualStrings("a future kind", parsed.value.event.unknown.payload.object.get("note").?.string);

    // Writing it back out keeps the same kind name and payload, so a reader
    // that does not understand image.generated still relays it correctly to
    // a client that does.
    const round = try toJson(allocator, parsed.value);
    defer allocator.free(round);
    try std.testing.expect(std.mem.indexOf(u8, round, "\"image.generated\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, round, "a future kind") != null);
}

test "a reader survives an enum member it does not know, such as a future role" {
    // Stands in for a role a later provider adapter adds, for example one
    // OpenAI compatible history uses that Chock has not modeled yet.
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
    // An approval has four outcomes and a signature over the record of each
    // one comes later. `denied_by_policy` is the fourth, and it was added
    // after `allowed_by_policy`, `approved_by_user`, `refused_by_user` and
    // `expired`. This pins both halves of that: a reader that knows the name
    // gives the member, and a reader that does not keeps the spelling.
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

    // A decision name from a future writer, which is what `denied_by_policy`
    // itself looks like to a reader built before it existed. The line still
    // reads, and the spelling survives.
    const from_the_future =
        \\{"id":8,"session":"01H0","time_ms":1,"version":1,"event":{"approval.response":{"request_id":4096,"decision":"approved_with_edits","responder":"ross"}}}
    ;
    const future = try fromJson(allocator, from_the_future);
    defer future.deinit();
    try std.testing.expectEqualStrings(
        "approved_with_edits",
        future.value.event.approval_response.decision.wireName(),
    );
    // The two fields added beside the decision carry a default, so a line
    // written before they existed still reads, with both of them empty.
    try std.testing.expectEqualStrings("", future.value.event.approval_response.action);
    try std.testing.expectEqualStrings("", future.value.event.approval_response.tool_call_id);
    try std.testing.expectEqualStrings("ross", future.value.event.approval_response.responder);
}

test "a session grant round trips as its own decision, and an older reader keeps only its name" {
    // `approved_by_user_for_session` is a wire format change the same way
    // `denied_by_policy` was, tested the same two ways just above: a reader
    // that knows the name gives the member, and a reader that does not keeps
    // the spelling instead of failing the line.
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

    // The exact member set `ApprovalDecision` had the moment before this one
    // was added, built over the same `WireString` every decision in this file
    // shares, so what runs below is the very code path a real older binary
    // would run and not a hand rolled stand-in for it. Fed the wire name
    // above, it has no case for it, so the fallback gives a name and nothing
    // that reads as a yes: `lib/chock-broker/Broker.zig`'s own
    // "a decision this broker does not know is not permission" is what says
    // that a decision landing here is never permission, whichever build
    // could not read it or why.
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

    // Stands in for every text field below. If any field, in any Kind,
    // skips the standard string encoder, this exact text leaks a raw
    // newline into the line and breaks the one event, one line rule that
    // the log's byte offset ids depend on.
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
        // A second one, for the two fields that carry a default: a response
        // the policy table answered on its own names no request envelope,
        // and it must still say what it decided about.
        .{ .approval_response = .{
            .request_id = 0,
            .decision = .denied_by_policy,
            .responder = "",
            .action = nl,
            .tool_call_id = nl,
        } },
        // A third one, for the two fields a review fills in. A reviewer agent
        // decided this, and the record says what it said.
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
        .{ .sandbox_open = .{
            .attempt = nl,
            .write_execute = .relaxed,
            .decision = nl,
        } },
        .{ .sandbox_supervisor = .{
            .process = nl,
            .layer = nl,
            .confined = 7,
            .unconfined = 1,
            .unreported = 2,
            .reason = nl,
        } },
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
    // **The log cannot edit a title, so a rename is a second event.** This is
    // what makes "set it early and correct it later" work at all: an agent that
    // named the session after its first message, and then found out what the
    // task really was, writes again. A reader takes the last, and the name the
    // session went by before is still there for anybody reading the record.
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

    // The kind is on the wire under the dotted name, and not under the Zig one.
    try std.testing.expect(std.mem.indexOf(u8, written[0], "\"session.title\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written[0], "session_title") == null);

    for (names, written) |name, line| {
        const parsed = try fromJson(allocator, line);
        defer parsed.deinit();
        try std.testing.expectEqualStrings(name, parsed.value.event.session_title.title);
    }

    // Mutation check: spell the wire name `session_title` in `wire_names`, and
    // the first two `expect` lines fail.
}

test "a handed over session gives its own reason, and never the one a cancel gives" {
    // The fact this pins: `handed_over` is a member of its own on the wire, and
    // it is not `canceled_by_user`. A handover leaves the workspace on disk for
    // the next owner, and a cancel does not, so a script that read the two as
    // one name would start again from committed state and drop the work.
    // Change `handed_over` to write `canceled_by_user`, or delete the member,
    // and this test stops holding.
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
    // The fact this pins: the two things a new owner cannot work out for
    // itself survive the log. The attempt id is fresh for each invocation, so
    // nobody can compute the workspace path from the session id; the base
    // commit is what `headMoved` measures the work against, and a new owner
    // that read HEAD again would measure against a commit the session made.
    // Change either field name, or drop one of them from `WorkspaceOpen`, and
    // this test stops holding.
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

    // An overlay has no commit of its own, so the field is empty and stays
    // empty. Nothing may read that empty string as a commit.
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

    // A backing a later version of Chock adds keeps its spelling, the rule
    // every other wire enum in this file follows.
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
    // The fact this pins: a parent reads "the child died" as its own answer,
    // never as a finished child with an empty result. `chock_core.subagent`
    // decides which one a log means; this is the half that has to survive
    // being written down and read back.
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

    // An outcome a later version of Chock adds keeps its spelling rather than
    // reading as one of the five this version knows, the same rule every other
    // wire enum in this file follows.
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
    // The fault this file's `Extra` exists to close. Before it,
    // `ignore_unknown_fields` skipped the field and re-serialization could not
    // invent it back, so an older `chockd` relaying a newer record dropped it
    // in silence: invisible where it happened, and a wrong number on somebody
    // else's screen later.
    const allocator = std.testing.allocator;
    const text =
        \\{"id":5,"session":"01H0","time_ms":1,"version":1,"event":{"session.start":{"agent_kind":"coder","model_alias":"main","parent_session":"","from_a_future_writer":{"nested":[1,2]}}}}
    ;
    const parsed = try fromJson(allocator, text);
    defer parsed.deinit();

    // The fields this reader knows still read back.
    try std.testing.expectEqualStrings("coder", parsed.value.event.session_start.agent_kind);
    // And the one it does not know is kept, by name and by raw value.
    const extra = parsed.value.event.session_start.extra.members;
    try std.testing.expectEqual(@as(usize, 1), extra.len);
    try std.testing.expectEqualStrings("from_a_future_writer", extra[0].name);

    // Writing it back out is the half that actually matters: a reader that
    // kept the field in memory and dropped it on the way out would still
    // lose it for the client on the other side of the relay.
    const round = try toJson(allocator, parsed.value);
    defer allocator.free(round);
    try std.testing.expect(std.mem.indexOf(u8, round, "\"from_a_future_writer\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, round, "\"nested\":[1,2]") != null);

    // Twice through, byte for byte: a relay chain of two old readers must
    // not lose it on the second hop either.
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
    // The other side of the bargain: keeping unknown members must not add
    // anything of its own to a record that has none. `extra` is written after
    // the fields this build knows, so a record with an empty `extra` is
    // exactly the fields of `Envelope` and nothing else.
    //
    // **`prev` is one of those fields now**, and it is here empty because
    // nothing but `log.Locked.append` fills it in. That is the wire change the
    // hash chain made, written out in full so a later change to the shape is a
    // change to this line as well: see `lib/chock-proto/chain.zig`.
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
    // Every log written before the chain existed holds lines of exactly this
    // shape, and they must keep parsing forever. A missing member has to reach
    // the reader as an empty `prev`, which `chain.Verifier` counts and passes
    // over, and never as `error.MissingField`.
    const allocator = std.testing.allocator;
    const line = "{\"id\":0,\"session\":\"01H0\",\"time_ms\":7," ++
        "\"event\":{\"session.end\":{\"reason\":\"finished\",\"detail\":\"\"}},\"version\":1}";
    const parsed = try fromJson(allocator, line);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("", parsed.value.prev);

    // And a line that does carry one keeps it byte for byte, since the digest
    // is compared as text and a reader that reshaped it would compare nothing.
    const chained = "{\"id\":0,\"session\":\"01H0\",\"time_ms\":7," ++
        "\"event\":{\"session.end\":{\"reason\":\"finished\",\"detail\":\"\"}},\"version\":1," ++
        "\"prev\":\"" ++ "ab" ** 32 ++ "\"}";
    const second = try fromJson(allocator, chained);
    defer second.deinit();
    try std.testing.expectEqualStrings("ab" ** 32, second.value.prev);
}

test "a usage event round trips in each of the three cost states, and they stay apart" {
    // Known, free, and unknown are three different facts. A wire shape that
    // could not tell free from unknown would let a cap be passed with nobody
    // noticing, or make a local model look like the risky one.
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
    // The same escape hatch every other enum on this wire has, and the same
    // reason: an unrecognized state must never collapse into the most
    // permissive one, which for a budget is "this turn cost nothing."
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
    // The rule this event exists to keep. A build writes megabytes, and the
    // session log is the one file a session cannot afford to bloat, so the
    // record names the file and the size and stops there.
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

    // The whole line is shorter than one line of what the command printed.
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
    // The one distinction the whole type exists for. A list where a step
    // vanishes in silence reads as finished when it is not, so "the agent gave
    // this up" has to survive being written down and read back as its own
    // fact, apart from "the agent finished this".
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
    // Not done, and not pending: those are the two answers a reader would
    // reach for if the status were a boolean or a missing entry.
    try std.testing.expect(read_back[1].status != .done);
    try std.testing.expect(read_back[1].status != .pending);
    try std.testing.expectEqualStrings("measure it on Darwin", read_back[1].subject);
    try std.testing.expectEqualStrings("s1", read_back[2].blocked_by);
    // A step that nothing holds up says so by carrying nothing, which is what
    // lets an older writer's line read without the field at all.
    try std.testing.expectEqualStrings("", read_back[0].blocked_by);
}

test "a plan status from a future writer keeps its name instead of reading as done" {
    // The same escape hatch every other enum on this wire has. Reading an
    // unrecognized status as `done` would report finished work that nobody
    // did, which is the one wrong answer a task list must never give.
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

    // And it relays unchanged, so an older reader between two newer ones does
    // not turn a deferred step into something else.
    const round = try toJson(allocator, parsed.value);
    defer allocator.free(round);
    try std.testing.expect(std.mem.indexOf(u8, round, "\"deferred\"") != null);
}

test "a task that timed out reads as its own status and not as one that died" {
    // "It was still going" and "it died" ask the agent for different next
    // steps, so a wait that ran out must not arrive as a signal.
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

    // And a status from a future writer keeps its own name instead of
    // collapsing into the most reassuring one.
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
    // **The one field that answers "did somebody's branch move".** `branch` is
    // empty for every apply that parked the work, and never empty for one that
    // moved a branch, so a reader looking for the fact reads one field and not
    // a combination of three.
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
    // **The reason and not only the outcome.** "Nothing moved" and "nothing
    // moved because the working tree was dirty" are different facts about a
    // session, and only the second one tells a person what to change.
    try std.testing.expectEqualStrings(
        "dirty_tree",
        read_parked.value.event.workspace_integrate.parked,
    );
    try std.testing.expectEqualStrings("merge", read_parked.value.event.workspace_integrate.mode);
}
