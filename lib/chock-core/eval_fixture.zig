//! Integrity-checked provider and tool exchanges for deterministic evaluations.

const std = @import("std");
const chock_provider = @import("chock-provider");
const chock_proto = @import("chock-proto");
const Loop = @import("Loop.zig");
const redact = @import("redact.zig");

const Client = chock_provider.Client;
const event = chock_proto.event;
const message = chock_provider.message;

pub const max_bytes: usize = 256 * 1024 * 1024;

pub const ProviderResult = union(enum) {
    ok,
    status_error: struct {
        status: u16,
        body: []const u8,
        retry_after_s: ?u64 = null,
    },
};

pub const ProviderExchange = struct {
    request_sha256: []const u8,
    deltas: []const Client.Delta,
    result: ProviderResult,
    training: ?TrainingTrace = null,
};

pub const TrainingTrace = Client.TrainingTrace;

pub const ToolExchange = struct {
    request_sha256: []const u8,
    result: event.ToolResult,
};

pub const Payload = struct {
    providers: []const ProviderExchange = &.{},
    tools: []const ToolExchange = &.{},
};

const File = struct {
    schema: []const u8 = "chock.eval-fixture",
    version: u32 = 1,
    payload_sha256: []const u8,
    payload: Payload,
};

pub const DecodeError = std.mem.Allocator.Error || std.json.ParseError(std.json.Scanner) || error{
    BadSchema,
    BadDigest,
};

pub fn encode(arena: std.mem.Allocator, payload: Payload) ![]const u8 {
    const payload_json = try std.json.Stringify.valueAlloc(arena, payload, .{});
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload_json, &digest, .{});
    const digest_hex = try arena.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
    return std.json.Stringify.valueAlloc(arena, File{
        .payload_sha256 = digest_hex,
        .payload = payload,
    }, .{});
}

pub fn decode(arena: std.mem.Allocator, bytes: []const u8) DecodeError!Payload {
    const file = try std.json.parseFromSliceLeaky(File, arena, bytes, .{ .ignore_unknown_fields = true });
    if (!std.mem.eql(u8, file.schema, "chock.eval-fixture") or file.version != 1) return error.BadSchema;
    const payload_json = try std.json.Stringify.valueAlloc(arena, file.payload, .{});
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload_json, &digest, .{});
    const actual = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, file.payload_sha256, &actual)) return error.BadDigest;
    return file.payload;
}

pub fn load(arena: std.mem.Allocator, io: std.Io, path: []const u8) !Payload {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_bytes));
    return decode(arena, bytes);
}

pub fn save(arena: std.mem.Allocator, io: std.Io, path: []const u8, payload: Payload) !void {
    const bytes = try encode(arena, payload);
    var file = if (std.fs.path.isAbsolute(path))
        try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true })
    else
        try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    try file.sync(io);
}

pub fn requestDigest(arena: std.mem.Allocator, request: message.Request) ![64]u8 {
    const json = try std.json.Stringify.valueAlloc(arena, request, .{});
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(json, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn toolDigest(call: event.ToolCall, action: []const u8) [64]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for ([_][]const u8{ call.tool, "\x00", call.arguments, "\x00", action }) |part| hasher.update(part);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

pub const Recorder = struct {
    arena: std.mem.Allocator,
    policy: redact.Policy,
    provider_exchanges: std.ArrayList(ProviderExchange) = .empty,
    tool_exchanges: std.ArrayList(ToolExchange) = .empty,

    pub fn payload(self: *const Recorder) Payload {
        return .{ .providers = self.provider_exchanges.items, .tools = self.tool_exchanges.items };
    }

    pub fn provider(self: *Recorder, inner: Client.Client) RecordingProvider {
        return .{ .recorder = self, .inner = inner };
    }

    pub fn tools(self: *Recorder, inner: Loop.ToolRunner) RecordingTools {
        return .{ .recorder = self, .inner = inner };
    }
};

pub const RecordingProvider = struct {
    recorder: *Recorder,
    inner: Client.Client,

    pub fn client(self: *RecordingProvider) Client.Client {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Client.Client.VTable{ .send = send };

    const Forward = struct {
        recorder: *Recorder,
        deltas: std.ArrayList(Client.Delta) = .empty,
        training: ?TrainingTrace = null,
        on_delta: Client.OnDelta,
        ctx: ?*anyopaque,

        fn take(raw: ?*anyopaque, delta: Client.Delta) Client.OnDeltaError!void {
            const self: *Forward = @ptrCast(@alignCast(raw.?));
            if (delta == .training_trace) {
                self.training = try cloneTrainingTrace(self.recorder, delta.training_trace);
                return;
            }
            try self.deltas.append(self.recorder.arena, try cloneDelta(self.recorder, delta));
            try self.on_delta(self.ctx, delta);
        }
    };

    fn send(
        raw: *anyopaque,
        allocator: std.mem.Allocator,
        request: message.Request,
        on_delta: Client.OnDelta,
        ctx: ?*anyopaque,
    ) Client.SendError!Client.SendResult {
        const self: *RecordingProvider = @ptrCast(@alignCast(raw));
        const digest = try requestDigest(allocator, request);
        var forward = Forward{ .recorder = self.recorder, .on_delta = on_delta, .ctx = ctx };
        const result = try self.inner.send(allocator, request, Forward.take, &forward);
        const captured: ProviderResult = switch (result) {
            .ok => .ok,
            .status_error => |failure| .{ .status_error = .{
                .status = @backingInt(failure.status),
                .body = try clean(self.recorder, failure.body),
                .retry_after_s = failure.retry_after_s,
            } },
        };
        try self.recorder.provider_exchanges.append(self.recorder.arena, .{
            .request_sha256 = try self.recorder.arena.dupe(u8, &digest),
            .deltas = forward.deltas.items,
            .result = captured,
            .training = forward.training,
        });
        return result;
    }
};

pub const RecordingTools = struct {
    recorder: *Recorder,
    inner: Loop.ToolRunner,

    pub fn runner(self: *RecordingTools) Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Loop.ToolRunner.VTable{ .dispatch = dispatch };

    fn dispatch(raw: *anyopaque, allocator: std.mem.Allocator, io: std.Io, call: event.ToolCall, action: []const u8) Loop.DispatchError!event.ToolResult {
        const self: *RecordingTools = @ptrCast(@alignCast(raw));
        const result = try self.inner.dispatch(allocator, io, call, action);
        const digest = toolDigest(call, action);
        self.recorder.tool_exchanges.append(self.recorder.arena, .{
            .request_sha256 = try self.recorder.arena.dupe(u8, &digest),
            .result = try cloneResult(self.recorder, result),
        }) catch |err| {
            freeToolResult(allocator, result);
            return err;
        };
        return result;
    }
};

pub const Replay = struct {
    payload: Payload,
    provider_at: usize = 0,
    tool_at: usize = 0,
    mismatch: []const u8 = "",

    pub fn client(self: *Replay) Client.Client {
        return .{ .ptr = self, .vtable = &provider_vtable };
    }

    pub fn runner(self: *Replay) Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &tool_vtable };
    }

    pub fn complete(self: *const Replay) bool {
        return self.mismatch.len == 0 and self.provider_at == self.payload.providers.len and self.tool_at == self.payload.tools.len;
    }

    const provider_vtable = Client.Client.VTable{ .send = send };
    const tool_vtable = Loop.ToolRunner.VTable{ .dispatch = dispatch };

    fn send(raw: *anyopaque, allocator: std.mem.Allocator, request: message.Request, on_delta: Client.OnDelta, ctx: ?*anyopaque) Client.SendError!Client.SendResult {
        const self: *Replay = @ptrCast(@alignCast(raw));
        if (self.provider_at >= self.payload.providers.len) {
            self.mismatch = "the provider fixture is exhausted";
            return error.ReplayExhausted;
        }
        const expected = self.payload.providers[self.provider_at];
        const digest = try requestDigest(allocator, request);
        if (!std.mem.eql(u8, expected.request_sha256, &digest)) {
            self.mismatch = "the provider request differs from its fixture";
            return error.ReplayMismatch;
        }
        self.provider_at += 1;
        for (expected.deltas) |delta| try on_delta(ctx, delta);
        return switch (expected.result) {
            .ok => .ok,
            .status_error => |failure| .{ .status_error = .{
                .status = @fromBackingInt(@intCast(failure.status)),
                .body = try allocator.dupe(u8, failure.body),
                .retry_after_s = failure.retry_after_s,
            } },
        };
    }

    fn dispatch(raw: *anyopaque, allocator: std.mem.Allocator, io: std.Io, call: event.ToolCall, action: []const u8) Loop.DispatchError!event.ToolResult {
        _ = io;
        const self: *Replay = @ptrCast(@alignCast(raw));
        if (self.tool_at >= self.payload.tools.len) {
            self.mismatch = "the tool fixture is exhausted";
            return error.Unexpected;
        }
        const expected = self.payload.tools[self.tool_at];
        const digest = toolDigest(call, action);
        if (!std.mem.eql(u8, expected.request_sha256, &digest)) {
            self.mismatch = "the tool request differs from its fixture";
            return error.Unexpected;
        }
        self.tool_at += 1;
        return dupeResult(allocator, expected.result);
    }
};

fn clean(recorder: *Recorder, source: []const u8) ![]const u8 {
    const redacted = try redact.text(recorder.arena, recorder.policy, source);
    return recorder.arena.dupe(u8, redacted);
}

fn cloneDelta(recorder: *Recorder, delta: Client.Delta) !Client.Delta {
    return switch (delta) {
        .text => |one| .{ .text = try clean(recorder, one) },
        .reasoning => |one| .{ .reasoning = try clean(recorder, one) },
        .reasoning_signature => |one| .{ .reasoning_signature = try clean(recorder, one) },
        .tool_call => |one| .{ .tool_call = .{
            .index = one.index,
            .id = if (one.id) |value| try clean(recorder, value) else null,
            .name = if (one.name) |value| try clean(recorder, value) else null,
            .arguments = if (one.arguments) |value| try clean(recorder, value) else null,
        } },
        .usage => |one| .{ .usage = try cloneUsage(recorder, one) },
        .stop_reason => |one| .{ .stop_reason = .{
            .reason = try clean(recorder, one.reason),
            .category = try clean(recorder, one.category),
            .explanation = try clean(recorder, one.explanation),
        } },
        .training_trace => |one| .{ .training_trace = try cloneTrainingTrace(recorder, one) },
    };
}

fn cloneTrainingTrace(recorder: *Recorder, trace: TrainingTrace) !TrainingTrace {
    return .{
        .prompt_token_ids = try recorder.arena.dupe(u32, trace.prompt_token_ids),
        .response_token_ids = try recorder.arena.dupe(u32, trace.response_token_ids),
        .response_mask = try recorder.arena.dupe(u8, trace.response_mask),
        .old_logprobs = try recorder.arena.dupe(f32, trace.old_logprobs),
    };
}

fn cloneUsage(recorder: *Recorder, usage: message.Usage) !message.Usage {
    var out = usage;
    out.price_table_version = try clean(recorder, usage.price_table_version);
    out.model = try clean(recorder, usage.model);
    out.model_alias = try clean(recorder, usage.model_alias);
    out.request_id = try clean(recorder, usage.request_id);
    out.reasoning_effort_applied = try clean(recorder, usage.reasoning_effort_applied);
    if (usage.cost == .known) out.cost = .{ .known = .{
        .value = usage.cost.known.value,
        .currency = try clean(recorder, usage.cost.known.currency),
    } };
    return out;
}

fn cloneResult(recorder: *Recorder, result: event.ToolResult) !event.ToolResult {
    var out = result;
    out.call_id = try clean(recorder, result.call_id);
    out.output = try clean(recorder, result.output);
    out.note = try clean(recorder, result.note);
    if (result.image) |image| out.image = .{
        .media_type = try clean(recorder, image.media_type),
        .byte_count = image.byte_count,
        .content_hash = try clean(recorder, image.content_hash),
        .data = try recorder.arena.dupe(u8, image.data),
    };
    return out;
}

fn dupeResult(allocator: std.mem.Allocator, result: event.ToolResult) !event.ToolResult {
    var out = result;
    out.call_id = try allocator.dupe(u8, result.call_id);
    errdefer allocator.free(out.call_id);
    out.output = try allocator.dupe(u8, result.output);
    errdefer allocator.free(out.output);
    out.note = try allocator.dupe(u8, result.note);
    errdefer allocator.free(out.note);
    if (result.image) |image| out.image = .{
        .media_type = try allocator.dupe(u8, image.media_type),
        .byte_count = image.byte_count,
        .content_hash = try allocator.dupe(u8, image.content_hash),
        .data = try allocator.dupe(u8, image.data),
    };
    return out;
}

fn freeToolResult(allocator: std.mem.Allocator, result: event.ToolResult) void {
    allocator.free(result.call_id);
    allocator.free(result.output);
    if (result.note.len != 0) allocator.free(result.note);
    if (result.image) |image| {
        allocator.free(image.media_type);
        allocator.free(image.content_hash);
        allocator.free(image.data);
    }
}

test "an encoded fixture verifies its payload" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const encoded = try encode(arena, .{ .providers = &.{.{
        .request_sha256 = &@as([64]u8, @splat('a')),
        .deltas = &.{ .{ .text = "hello" }, .{ .stop_reason = .{ .reason = "stop" } } },
        .result = .ok,
        .training = .{
            .prompt_token_ids = &.{ 1, 2 },
            .response_token_ids = &.{3},
            .response_mask = &.{1},
            .old_logprobs = &.{-0.25},
        },
    }} });
    const decoded = try decode(arena, encoded);
    try std.testing.expectEqual(@as(usize, 1), decoded.providers.len);
    try std.testing.expectEqualStrings("hello", decoded.providers[0].deltas[0].text);
    try std.testing.expectEqual(@as(u32, 3), decoded.providers[0].training.?.response_token_ids[0]);

    var damaged = try arena.dupe(u8, encoded);
    const text_at = std.mem.indexOf(u8, damaged, "hello") orelse unreachable;
    damaged[text_at] = 'j';
    try std.testing.expectError(error.BadDigest, decode(arena, damaged));
}

const FakeProvider = struct {
    fn send(_: *anyopaque, _: std.mem.Allocator, _: message.Request, on_delta: Client.OnDelta, ctx: ?*anyopaque) Client.SendError!Client.SendResult {
        try on_delta(ctx, .{ .text = "the token is supersecret" });
        try on_delta(ctx, .{ .training_trace = .{
            .prompt_token_ids = &.{ 1, 2 },
            .response_token_ids = &.{3},
            .response_mask = &.{1},
            .old_logprobs = &.{-0.25},
        } });
        try on_delta(ctx, .{ .stop_reason = .{ .reason = "stop" } });
        return .ok;
    }

    fn client(self: *FakeProvider) Client.Client {
        return .{ .ptr = self, .vtable = &.{ .send = send } };
    }
};

const SeenDeltas = struct {
    count: usize = 0,
    text: []const u8 = "",

    fn take(raw: ?*anyopaque, delta: Client.Delta) Client.OnDeltaError!void {
        const self: *SeenDeltas = @ptrCast(@alignCast(raw.?));
        self.count += 1;
        if (delta == .text) self.text = delta.text;
    }
};

test "provider recording redacts and replay requires the same request" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var recorder = Recorder{
        .arena = arena,
        .policy = .{ .secrets = &.{.{ .value = "supersecret" }} },
    };
    var fake = FakeProvider{};
    var recording = recorder.provider(fake.client());
    const request = message.Request{ .model = "model", .system = "system", .messages = &.{} };
    var live = SeenDeltas{};
    try std.testing.expectEqual(Client.SendResult.ok, try recording.client().send(arena, request, SeenDeltas.take, &live));
    try std.testing.expectEqual(@as(usize, 2), live.count);
    try std.testing.expectEqualStrings("the token is supersecret", live.text);
    try std.testing.expectEqual(@as(usize, 1), recorder.payload().providers.len);
    try std.testing.expect(std.mem.indexOf(u8, recorder.payload().providers[0].deltas[0].text, "supersecret") == null);
    try std.testing.expectEqualSlices(u32, &.{3}, recorder.payload().providers[0].training.?.response_token_ids);

    const bytes = try encode(arena, recorder.payload());
    var replay = Replay{ .payload = try decode(arena, bytes) };
    var repeated = SeenDeltas{};
    try std.testing.expectEqual(Client.SendResult.ok, try replay.client().send(arena, request, SeenDeltas.take, &repeated));
    try std.testing.expectEqual(@as(usize, 2), repeated.count);
    try std.testing.expect(replay.complete());

    var wrong = Replay{ .payload = try decode(arena, bytes) };
    const changed = message.Request{ .model = "other", .system = "system", .messages = &.{} };
    try std.testing.expectError(error.ReplayMismatch, wrong.client().send(arena, changed, SeenDeltas.take, &repeated));
}

const FakeTools = struct {
    fn dispatch(_: *anyopaque, allocator: std.mem.Allocator, _: std.Io, call: event.ToolCall, _: []const u8) Loop.DispatchError!event.ToolResult {
        return .{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try allocator.dupe(u8, "supersecret result"),
            .is_error = false,
            .truncated = false,
        };
    }

    fn runner(self: *FakeTools) Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &.{ .dispatch = dispatch } };
    }
};

test "tool recording redacts and replay never calls the live runner" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var recorder = Recorder{
        .arena = arena,
        .policy = .{ .secrets = &.{.{ .value = "supersecret" }} },
    };
    var fake = FakeTools{};
    var recording = recorder.tools(fake.runner());
    const call = event.ToolCall{ .call_id = "call-1", .tool = "read_file", .arguments = "{\"path\":\"a\"}" };
    const live = try recording.runner().dispatch(std.testing.allocator, std.testing.io, call, "file.read");
    defer freeToolResult(std.testing.allocator, live);
    try std.testing.expectEqualStrings("supersecret result", live.output);
    try std.testing.expect(std.mem.indexOf(u8, recorder.payload().tools[0].result.output, "supersecret") == null);

    var replay = Replay{ .payload = recorder.payload() };
    const repeated = try replay.runner().dispatch(std.testing.allocator, std.testing.io, call, "file.read");
    defer freeToolResult(std.testing.allocator, repeated);
    try std.testing.expect(std.mem.indexOf(u8, repeated.output, "supersecret") == null);
    try std.testing.expect(replay.complete());
}
