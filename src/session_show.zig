//! A deterministic, read-only view of one session log.

const std = @import("std");
const chock_core = @import("chock-core");
const chock_proto = @import("chock-proto");

const tty = @import("tty.zig");

const chain = chock_proto.chain;
const event = chock_proto.event;

const preview_bytes: usize = 512;

pub const Format = enum {
    human,
    compact,
    json,

    pub fn parse(text: []const u8) ?Format {
        return std.meta.stringToEnum(Format, text);
    }
};

pub const Filters = struct {
    lifecycle: bool = true,
    messages: bool = true,
    tools: bool = true,
    approvals: bool = true,
    policy: bool = true,
    diffs: bool = true,
    subagents: bool = true,
    usage: bool = true,
    workspace: bool = true,
    sandbox: bool = true,
    network: bool = true,

    pub fn parse(text: []const u8) ?Filters {
        if (std.mem.eql(u8, text, "all")) return .{};
        if (text.len == 0) return null;

        var out = Filters{
            .lifecycle = false,
            .messages = false,
            .tools = false,
            .approvals = false,
            .policy = false,
            .diffs = false,
            .subagents = false,
            .usage = false,
            .workspace = false,
            .sandbox = false,
            .network = false,
        };
        var names = std.mem.splitScalar(u8, text, ',');
        while (names.next()) |name| {
            if (name.len == 0) return null;
            if (std.mem.eql(u8, name, "lifecycle")) out.lifecycle = true else if (std.mem.eql(u8, name, "messages")) out.messages = true else if (std.mem.eql(u8, name, "tools")) out.tools = true else if (std.mem.eql(u8, name, "approvals")) out.approvals = true else if (std.mem.eql(u8, name, "policy")) out.policy = true else if (std.mem.eql(u8, name, "diffs")) out.diffs = true else if (std.mem.eql(u8, name, "subagents")) out.subagents = true else if (std.mem.eql(u8, name, "usage")) out.usage = true else if (std.mem.eql(u8, name, "workspace")) out.workspace = true else if (std.mem.eql(u8, name, "sandbox")) out.sandbox = true else if (std.mem.eql(u8, name, "network")) out.network = true else return null;
        }
        return out;
    }

    fn includes(self: Filters, one: event.Event) bool {
        return switch (one) {
            .message => self.messages,
            .tool_call, .tool_result, .task_complete => self.tools,
            .approval_request, .approval_response, .prompt_password => self.approvals,
            .policy_self => self.policy,
            .diff => self.diffs,
            .session_spawn, .agent_complete => self.subagents,
            .usage => self.usage,
            .workspace_open, .workspace_integrate, .workspace_adopt => self.workspace,
            .sandbox_open,
            .sandbox_supervisor,
            .sandbox_syscalls,
            .device_exposed,
            .secret_used,
            => self.sandbox,
            .network_summary => self.network,
            // Forward-compatible events must never disappear behind a filter the
            // installed Chock cannot name.
            .unknown => true,
            // A newly typed event starts in the lifecycle view until this command
            // gives it a narrower category. This also lets session.fork land on
            // its own branch without breaking this renderer's exhaustive switch.
            else => self.lifecycle,
        };
    }
};

pub const Options = struct {
    format: Format = .human,
    filters: Filters = .{},
    full: bool = false,
};

pub const Outcome = enum {
    shown,
    not_found,
    invalid,
};

pub fn show(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    options: Options,
) !Outcome {
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, id }, 0);
    const flags: std.posix.O = .{ .ACCMODE = .RDONLY };
    const fd = std.posix.openatZ(std.posix.AT.FDCWD, path, flags, 0) catch |err| switch (err) {
        error.FileNotFound => return .not_found,
        else => {
            try writeDiagnostic(arena, options.format, 0, "unreadable", @errorName(err));
            return .invalid;
        },
    };
    var log = chock_proto.log.Log{
        .file = .{ .handle = fd, .flags = .{ .nonblocking = false } },
        .session = id,
    };
    defer log.close(io);

    const header = log.headerDigest(io) catch |err| {
        try writeDiagnostic(arena, options.format, 0, "bad header", @errorName(err));
        return .invalid;
    };
    var verifier = chain.Verifier.init(header);
    var replay = try log.replayFrom(gpa, io, 0);
    defer replay.deinit();

    var scratch_state = std.heap.ArenaAllocator.init(gpa);
    defer scratch_state.deinit();

    if (options.format == .human) {
        tty.out(.plain, "session {s}\n{s}\n\n", .{ id, path });
    }

    var ending: chain.Ending = .complete;
    var ending_at: u64 = 0;
    var first_unknown: ?u64 = null;
    var shown_events: u64 = 0;
    while (true) {
        _ = scratch_state.reset(.retain_capacity);
        const scratch = scratch_state.allocator();
        const at = replay.pos;
        const parsed = replay.next(io) catch |err| {
            ending = .undecodable;
            ending_at = at;
            try writeDiagnostic(scratch, options.format, at, "undecodable event", @errorName(err));
            break;
        } orelse {
            if (replay.truncated) {
                ending = .torn;
                ending_at = replay.truncated_at;
                try writeDiagnostic(scratch, options.format, ending_at, "torn event", "the final line is unfinished");
            }
            break;
        };
        defer parsed.deinit();

        verifier.take(parsed.value.id, replay.line(), parsed.value.prev);
        if (parsed.value.event == .unknown and first_unknown == null) first_unknown = parsed.value.id;
        if (!options.filters.includes(parsed.value.event)) continue;
        shown_events += 1;

        switch (options.format) {
            .json => {
                const text = try event.toJson(scratch, parsed.value);
                tty.out(.plain, "{s}\n", .{text});
            },
            .compact => try writeCompact(scratch, parsed.value),
            .human => try writeHuman(scratch, parsed.value, options.full),
        }
    }

    const report = verifier.finish(ending, ending_at);
    if (report.verdict == .broken) {
        const scratch = scratch_state.allocator();
        const detail = try std.fmt.allocPrint(
            scratch,
            "the hash chain breaks after event {d}",
            .{report.after},
        );
        try writeDiagnostic(scratch, options.format, report.at, "edited log", detail);
        return .invalid;
    }
    if (report.verdict == .torn or report.verdict == .undecodable) return .invalid;

    if (first_unknown) |at| {
        try writeDiagnostic(
            scratch_state.allocator(),
            options.format,
            at,
            "unknown event",
            "this Chock cannot validate that event kind",
        );
    }

    if (options.format == .human) {
        if (shown_events == report.events) {
            tty.out(.dim, "\n{d} events; hash chain: {s}\n", .{ report.events, @tagName(report.verdict) });
        } else {
            tty.out(.dim, "\n{d} events in the log; {d} shown; hash chain: {s}\n", .{
                report.events, shown_events, @tagName(report.verdict),
            });
        }
    }
    return if (first_unknown != null) .invalid else .shown;
}

fn kindName(one: event.Event) []const u8 {
    return switch (one) {
        .unknown => |unknown| unknown.kind,
        inline else => |_, tag| tag.wireName(),
    };
}

fn writeCompact(arena: std.mem.Allocator, envelope: event.Envelope) !void {
    tty.out(.plain, "{d} {d} {s}", .{
        envelope.id, envelope.time_ms, try inlineText(arena, kindName(envelope.event)),
    });
    switch (envelope.event) {
        .session_start => |one| tty.out(.plain, " agent={s} model={s} parent={s}", .{
            try inlineText(arena, one.agent_kind),
            try inlineText(arena, one.model_alias),
            try inlineText(arena, one.parent_session),
        }),
        .session_end => |one| tty.out(.plain, " reason={s}", .{try inlineText(arena, one.reason.wireName())}),
        .session_spawn => |one| tty.out(.plain, " child={s} agent={s}", .{
            try inlineText(arena, one.child_session),
            try inlineText(arena, one.child_agent_kind),
        }),
        .session_fork => |one| tty.out(.plain, " source={s} event={d}", .{
            try inlineText(arena, one.source_session), one.source_event,
        }),
        .session_title => |one| tty.out(.plain, " {s}", .{try inlineText(arena, one.title)}),
        .message => |one| tty.out(.plain, " role={s} parts={d}", .{
            try inlineText(arena, one.role.wireName()), one.content.len,
        }),
        .tool_call => |one| tty.out(.plain, " tool={s} call={s}", .{
            try inlineText(arena, one.tool),
            try inlineText(arena, one.call_id),
        }),
        .tool_result => |one| tty.out(.plain, " call={s} bytes={d} error={}", .{
            try inlineText(arena, one.call_id), one.output.len, one.is_error,
        }),
        .approval_request => |one| tty.out(.plain, " action={s}", .{try inlineText(arena, one.action)}),
        .approval_response => |one| tty.out(.plain, " request={d} decision={s}", .{
            one.request_id, try inlineText(arena, one.decision.wireName()),
        }),
        .diff => |one| tty.out(.plain, " path={s} bytes={d}", .{
            try inlineText(arena, one.path), one.patch.len,
        }),
        .usage => |one| tty.out(.plain, " model={s} input={d} output={d}", .{
            try inlineText(arena, one.model), one.input_tokens, one.output_tokens,
        }),
        .agent_complete => |one| tty.out(.plain, " child={s} outcome={s}", .{
            try inlineText(arena, one.child_session), try inlineText(arena, one.outcome.wireName()),
        }),
        .workspace_open => |one| tty.out(.plain, " kind={s} path={s}", .{
            try inlineText(arena, one.kind.wireName()), try inlineText(arena, one.path),
        }),
        .workspace_integrate => |one| tty.out(.plain, " mode={s} ref={s}", .{
            try inlineText(arena, one.mode), try inlineText(arena, one.ref),
        }),
        .network_summary => |one| tty.out(.plain, " granted={d} refused={d}", .{ one.granted, one.refused }),
        .unknown => |one| tty.out(.warn, " unknown={s}", .{try inlineText(arena, one.kind)}),
        inline else => |payload| {
            const raw = try std.json.Stringify.valueAlloc(arena, payload, .{});
            tty.out(.plain, " {s}", .{try inlineText(arena, raw)});
        },
    }
    tty.out(.plain, "\n", .{});
}

fn writeHuman(arena: std.mem.Allocator, envelope: event.Envelope, full: bool) !void {
    tty.out(.dim, "[{d}] {d}  {s}\n", .{
        envelope.id, envelope.time_ms, try inlineText(arena, kindName(envelope.event)),
    });
    switch (envelope.event) {
        .session_start => |one| {
            try field(arena, "agent", one.agent_kind, true);
            try field(arena, "model alias", one.model_alias, true);
            if (one.parent_session.len != 0) try field(arena, "parent session", one.parent_session, true);
            for (one.spawn_chain) |link| {
                tty.out(.plain, "  via {s}: {s}\n", .{
                    try inlineText(arena, link.agent_kind), try inlineText(arena, link.reason),
                });
            }
        },
        .session_config => |one| tty.out(.plain, "  config={s} sandbox={s}, {d} instructions, {d} policy rules\n", .{
            try inlineText(arena, one.config_hash orelse "built in"),
            try inlineText(arena, one.sandbox_hash),
            one.instructions.len,
            one.policy_rules.len,
        }),
        .session_end => |one| {
            tty.out(.plain, "  {s}\n", .{try inlineText(arena, one.reason.wireName())});
            if (one.detail.len != 0) try field(arena, "detail", one.detail, full);
        },
        .session_spawn => |one| {
            try field(arena, "child session", one.child_session, true);
            try field(arena, "child agent", one.child_agent_kind, true);
            try field(arena, "reason", one.reason, full);
        },
        .session_fork => |one| {
            try field(arena, "source session", one.source_session, true);
            tty.out(.plain, "  source event: {d}\n", .{one.source_event});
            try field(arena, "source head", one.source_head, true);
        },
        .session_title => |one| try field(arena, "title", one.title, full),
        .session_imported => |one| tty.out(.plain, "  {s}: {d} messages from {s}\n", .{
            try inlineText(arena, one.from), one.messages, try inlineText(arena, one.source_path),
        }),
        .message => |one| {
            tty.out(.plain, "  {s}\n", .{try inlineText(arena, one.role.wireName())});
            for (one.content) |part| switch (part) {
                .text => |text| try field(arena, "text", text, full),
                .reasoning => |reasoning| try field(arena, "reasoning", reasoning.text, full),
                .tool_use => |tool| {
                    tty.out(.plain, "  tool use {s} ({s})\n", .{
                        try inlineText(arena, tool.tool), try inlineText(arena, tool.call_id),
                    });
                    try field(arena, "arguments", tool.arguments, full);
                },
                .tool_result => |result| try field(arena, if (result.is_error) "tool error" else "tool result", result.output, full),
                .image => |image| tty.out(.plain, "  image {s}, {d} encoded bytes\n", .{
                    try inlineText(arena, image.media_type), image.data.len,
                }),
                .unknown => |unknown| tty.out(.warn, "  unknown content part: {s}\n", .{try inlineText(arena, unknown.name)}),
            };
        },
        .tool_call => |one| {
            tty.out(.plain, "  {s} ({s})\n", .{ try inlineText(arena, one.tool), try inlineText(arena, one.call_id) });
            try field(arena, "arguments", one.arguments, full);
        },
        .tool_result => |one| {
            tty.out(.plain, "  call {s}: {s}{s}\n", .{
                try inlineText(arena, one.call_id),
                if (one.is_error) "error" else "ok",
                if (one.truncated) ", recorded output is truncated" else "",
            });
            try field(arena, "output", one.output, full);
            if (one.note.len != 0) try field(arena, "note", one.note, full);
        },
        .approval_request => |one| {
            try field(arena, "action", one.action, true);
            try field(arena, "summary", one.summary, full);
            try field(arena, "reason", one.reason, full);
        },
        .approval_response => |one| tty.out(.plain, "  request {d}: {s}, responder {s}\n", .{
            one.request_id, try inlineText(arena, one.decision.wireName()), try inlineText(arena, one.responder),
        }),
        .prompt_password => |one| try field(arena, "credential prompt", one.prompt, full),
        .diff => |one| {
            try field(arena, "path", one.path, true);
            tty.out(.plain, "  review: {s}\n", .{try inlineText(arena, one.review.wireName())});
            try field(arena, "patch", one.patch, full);
        },
        .compaction => |one| {
            tty.out(.plain, "  events {d} through {d}, model {s}\n", .{
                one.from_id, one.through_id, try inlineText(arena, one.model_alias),
            });
            try field(arena, "summary", one.summary, full);
        },
        .usage => |one| tty.out(.plain, "  {s}: input {d}, output {d}, cache write {d}, cache read {d}\n", .{
            try inlineText(arena, one.model),
            one.input_tokens,
            one.output_tokens,
            one.cache_creation_input_tokens,
            one.cache_read_input_tokens,
        }),
        .task_complete => |one| tty.out(.plain, "  task {s}: {s} ({d}), {d} output bytes{s}\n", .{
            try inlineText(arena, one.task_id),       try inlineText(arena, one.status.wireName()), one.code, one.output_bytes,
            if (one.truncated) ", truncated" else "",
        }),
        .agent_complete => |one| {
            tty.out(.plain, "  child {s} ({s}): {s}\n", .{
                try inlineText(arena, one.child_session),
                try inlineText(arena, one.child_agent_kind),
                try inlineText(arena, one.outcome.wireName()),
            });
            try field(arena, "result", one.result, full);
        },
        .plan_update => |one| for (one.steps) |step| tty.out(.plain, "  {s}: {s} — {s}\n", .{
            try inlineText(arena, step.id), try inlineText(arena, step.status.wireName()), try inlineText(arena, step.subject),
        }),
        .policy_self => |one| {
            tty.out(.plain, "  authorised: {}\n", .{one.authorised});
            for (one.restrictions) |restriction| tty.out(.plain, "  {s}: {s}\n", .{
                try inlineText(arena, restriction.action), try inlineText(arena, restriction.ceiling.wireName()),
            });
        },
        .workspace_open => |one| tty.out(.plain, "  {s} at {s}, base {s}, attempt {s}\n", .{
            try inlineText(arena, one.kind.wireName()), try inlineText(arena, one.path), try inlineText(arena, one.base_commit),
            try inlineText(arena, one.attempt),
        }),
        .workspace_integrate => |one| tty.out(.plain, "  {s}: {s}, branch {s}, ref {s}\n", .{
            try inlineText(arena, one.mode),   try inlineText(arena, one.decision),
            try inlineText(arena, one.branch), try inlineText(arena, one.ref),
        }),
        .workspace_adopt => |one| tty.out(.plain, "  {s}: {d} files, {d} deleted, {d} skipped\n", .{
            try inlineText(arena, one.path), one.files, one.deleted, one.skipped,
        }),
        .sandbox_open => |one| tty.out(.plain, "  attempt {s}: {s}, write/execute {s}\n", .{
            try inlineText(arena, one.attempt), try inlineText(arena, one.decision), try inlineText(arena, one.write_execute.wireName()),
        }),
        .sandbox_supervisor => |one| tty.out(.plain, "  {s}: layer {s}, confined {d}, unconfined {d}, unreported {d}\n", .{
            try inlineText(arena, one.process), try inlineText(arena, one.layer),
            one.confined,                       one.unconfined,
            one.unreported,
        }),
        .device_exposed => |one| tty.out(.plain, "  {s}: {s}, decision {s}, enforced {}\n", .{
            try inlineText(arena, one.attempt),  try inlineText(arena, one.action),
            try inlineText(arena, one.decision), one.enforced,
        }),
        .secret_used => |one| tty.out(.plain, "  {s} for {s}, bound by {s}\n", .{
            try inlineText(arena, one.name), try inlineText(arena, one.action), try inlineText(arena, one.bind),
        }),
        .network_summary => |one| {
            tty.out(.plain, "  granted {d}, refused {d}\n", .{ one.granted, one.refused });
            if (one.diagnostic.len != 0) try field(arena, "diagnostic", one.diagnostic, full);
        },
        .unknown => |one| {
            const raw = try std.json.Stringify.valueAlloc(arena, one.payload, .{});
            try field(arena, "unknown payload", raw, full);
        },
        inline else => |payload, tag| {
            const raw = try std.json.Stringify.valueAlloc(arena, payload, .{});
            try field(arena, tag.wireName(), raw, full);
        },
    }
    tty.out(.plain, "\n", .{});
}

fn field(arena: std.mem.Allocator, name: []const u8, raw: []const u8, full: bool) !void {
    const shown = try displayText(arena, raw, if (full) std.math.maxInt(usize) else preview_bytes, true);
    tty.out(.plain, "  {s}: {s}\n", .{ name, shown });
}

fn inlineText(arena: std.mem.Allocator, raw: []const u8) ![]const u8 {
    return displayText(arena, raw, preview_bytes, false);
}

fn displayText(
    arena: std.mem.Allocator,
    raw: []const u8,
    limit: usize,
    multiline: bool,
) ![]const u8 {
    if (!std.unicode.utf8ValidateSlice(raw)) {
        return std.fmt.allocPrint(arena, "[{d} bytes that are not UTF-8]", .{raw.len});
    }
    const cut = chock_core.notices.cutToCharacter(raw, @min(limit, raw.len));
    var out: std.ArrayList(u8) = .empty;
    for (cut) |byte| switch (byte) {
        '\n' => if (multiline) try out.appendSlice(arena, "\n    ") else try out.append(arena, ' '),
        '\t' => try out.append(arena, if (multiline) '\t' else ' '),
        else => try out.append(arena, if (byte < 0x20 or byte == 0x7f) '?' else byte),
    };
    if (cut.len != raw.len) try out.print(arena, " … ({d} bytes total)", .{raw.len});
    return out.toOwnedSlice(arena);
}

const Diagnostic = struct {
    chock_show: u32 = 1,
    offset: u64,
    error_name: []const u8,
    detail: []const u8,
};

fn writeDiagnostic(
    arena: std.mem.Allocator,
    format: Format,
    offset: u64,
    name: []const u8,
    detail: []const u8,
) !void {
    if (format == .json) {
        const text = try std.json.Stringify.valueAlloc(arena, Diagnostic{
            .offset = offset,
            .error_name = name,
            .detail = detail,
        }, .{});
        tty.out(.plain, "{s}\n", .{text});
        return;
    }
    tty.out(.err, "[{d}] {s}: {s}\n", .{
        offset,
        try inlineText(arena, name),
        try inlineText(arena, detail),
    });
}

test "filters name every documented group and unknown events always remain visible" {
    const only_tools = Filters.parse("tools").?;
    try std.testing.expect(only_tools.includes(.{ .tool_call = .{
        .call_id = "1",
        .tool = "shell",
        .arguments = "{}",
    } }));
    try std.testing.expect(!only_tools.includes(.{ .message = .{ .role = .user, .content = &.{} } }));
    try std.testing.expect(only_tools.includes(.{ .unknown = .{
        .kind = "future.event",
        .payload = .null,
    } }));

    try std.testing.expect(Filters.parse("messages,tools,approvals,policy,diffs,subagents,usage,sandbox,network") != null);
    try std.testing.expect(Filters.parse("messages,no-such-group") == null);
    try std.testing.expect(Filters.parse("") == null);
}

test "display text cannot drive a terminal and cuts only at a UTF-8 boundary" {
    const arena = std.testing.allocator;
    const shown = try displayText(arena, "first\n\x1b[31msecond €", 19, true);
    defer arena.free(shown);
    try std.testing.expect(std.mem.indexOfScalar(u8, shown, 0x1b) == null);
    try std.testing.expect(std.unicode.utf8ValidateSlice(shown));
    try std.testing.expect(std.mem.indexOf(u8, shown, "\n    ") != null);
    try std.testing.expect(std.mem.indexOf(u8, shown, "bytes total") != null);
}

fn testLog(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    events: []const event.Event,
) ![:0]const u8 {
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, id }, 0);
    var log = try chock_proto.log.Log.open(io, path, id);
    defer log.close(io);
    var locked = try log.lock(io);
    defer locked.unlock(io) catch {};
    for (events, 0..) |one, index| {
        _ = try locked.append(arena, io, one, @intCast(1000 + index));
    }
    return path;
}

test "human inspection links sessions, sanitizes text, and previews large results" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buffer);
    const dir = root_buffer[0..root_len];
    const id = "01JQ" ++ @as([22]u8, @splat('S'));
    const parent = "01JQ" ++ @as([22]u8, @splat('P'));
    const child = "01JQ" ++ @as([22]u8, @splat('C'));
    const content = [_]event.ContentPart{.{ .text = "hello\n\x1b[31mworld" }};
    const large: [700]u8 = @splat('x');
    _ = try testLog(arena, io, dir, id, &.{
        .{ .session_start = .{ .agent_kind = "main", .model_alias = "fast", .parent_session = parent } },
        .{ .session_fork = .{ .source_session = parent, .source_event = 123, .source_head = "0123456789abcdef" } },
        .{ .message = .{ .role = .user, .content = &content } },
        .{ .session_spawn = .{ .child_session = child, .child_agent_kind = "reviewer", .reason = "review" } },
        .{ .tool_result = .{ .call_id = "call-1", .output = &large, .is_error = false, .truncated = false } },
    });

    var capture: tty.Capture = undefined;
    capture.start(io, gpa);
    defer capture.stop(io);

    try std.testing.expectEqual(Outcome.shown, try show(arena, gpa, io, dir, id, .{}));
    try std.testing.expect(std.mem.indexOf(u8, capture.out(), parent) != null);
    try std.testing.expect(std.mem.indexOf(u8, capture.out(), "source event: 123") != null);
    try std.testing.expect(std.mem.indexOf(u8, capture.out(), child) != null);
    try std.testing.expect(std.mem.indexOf(u8, capture.out(), "bytes total") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, capture.out(), 0x1b) == null);
    try std.testing.expect(std.mem.indexOf(u8, capture.out(), "hash chain: intact") != null);
}

test "JSON inspection emits filtered envelopes with their real offsets" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buffer);
    const dir = root_buffer[0..root_len];
    const id = "01JQ" ++ @as([22]u8, @splat('J'));
    const content = [_]event.ContentPart{.{ .text = "only this event" }};
    _ = try testLog(arena, io, dir, id, &.{
        .{ .session_start = .{ .agent_kind = "main", .model_alias = "m", .parent_session = "" } },
        .{ .message = .{ .role = .assistant, .content = &content } },
        .{ .session_end = .{ .reason = .finished, .detail = "" } },
    });

    var capture: tty.Capture = undefined;
    capture.start(io, gpa);
    defer capture.stop(io);
    try std.testing.expectEqual(Outcome.shown, try show(arena, gpa, io, dir, id, .{
        .format = .json,
        .filters = Filters.parse("messages").?,
    }));

    const line = std.mem.trimEnd(u8, capture.out(), "\n");
    try std.testing.expect(std.mem.indexOfScalar(u8, line, '\n') == null);
    var parsed = try event.fromJson(gpa, line);
    defer parsed.deinit();
    try std.testing.expect(parsed.value.id != 0);
    try std.testing.expectEqual(event.Kind.message, std.meta.activeTag(parsed.value.event));
}

test "unknown and undecodable events are visible audit gaps" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buffer);
    const dir = root_buffer[0..root_len];
    const unknown_id = "01JQ" ++ @as([22]u8, @splat('U'));
    _ = try testLog(arena, io, dir, unknown_id, &.{.{ .unknown = .{
        .kind = "future.event",
        .payload = .null,
    } }});

    var capture: tty.Capture = undefined;
    capture.start(io, gpa);
    defer capture.stop(io);
    try std.testing.expectEqual(Outcome.invalid, try show(arena, gpa, io, dir, unknown_id, .{}));
    try std.testing.expect(std.mem.indexOf(u8, capture.out(), "future.event") != null);

    capture.clear();
    const corrupt_id = "01JQ" ++ @as([22]u8, @splat('X'));
    const path = try testLog(arena, io, dir, corrupt_id, &.{});
    const before = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1024));
    const corrupt = try std.mem.concat(arena, u8, &.{ before, "not json\n" });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = corrupt });

    try std.testing.expectEqual(Outcome.invalid, try show(arena, gpa, io, dir, corrupt_id, .{}));
    try std.testing.expect(std.mem.indexOf(u8, capture.out(), "undecodable event") != null);
    try std.testing.expect(std.mem.indexOf(u8, capture.out(), "[") != null);

    capture.clear();
    const torn_id = "01JQ" ++ @as([22]u8, @splat('T'));
    const torn_path = try testLog(arena, io, dir, torn_id, &.{});
    const header = try std.Io.Dir.cwd().readFileAlloc(io, torn_path, arena, .limited(1024));
    const torn = try std.mem.concat(arena, u8, &.{ header, "{" });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = torn_path, .data = torn });
    try std.testing.expectEqual(Outcome.invalid, try show(arena, gpa, io, dir, torn_id, .{}));
    try std.testing.expect(std.mem.indexOf(u8, capture.out(), "torn event") != null);

    capture.clear();
    const edited_id = "01JQ" ++ @as([22]u8, @splat('E'));
    const edited_path = try testLog(arena, io, dir, edited_id, &.{
        .{ .session_title = .{ .title = "safe" } },
        .{ .session_end = .{ .reason = .finished, .detail = "" } },
    });
    const edited = try std.Io.Dir.cwd().readFileAlloc(io, edited_path, arena, .limited(4096));
    const title_at = std.mem.indexOf(u8, edited, "\"title\":\"safe\"").? + "\"title\":\"".len;
    @memcpy(edited[title_at .. title_at + 4], "evil");
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = edited_path, .data = edited });
    try std.testing.expectEqual(Outcome.invalid, try show(arena, gpa, io, dir, edited_id, .{}));
    try std.testing.expect(std.mem.indexOf(u8, capture.out(), "edited log") != null);
}

test "inspection never repairs or otherwise writes an invalid log" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buffer);
    const dir = root_buffer[0..root_len];
    const id = "01JQ" ++ @as([22]u8, @splat('R'));
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, id }, 0);
    var empty = try std.Io.Dir.createFileAbsolute(io, path, .{});
    empty.close(io);

    var capture: tty.Capture = undefined;
    capture.start(io, gpa);
    defer capture.stop(io);
    try std.testing.expectEqual(Outcome.invalid, try show(arena, gpa, io, dir, id, .{}));
    try std.testing.expect(std.mem.indexOf(u8, capture.out(), "bad header") != null);
    try std.testing.expectEqual(@as(u64, 0), (try std.Io.Dir.cwd().statFile(io, path, .{})).size);
}
