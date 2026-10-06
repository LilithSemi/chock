//! Interface to hide which provider answers a model request.

const std = @import("std");
const message = @import("message.zig");
const anthropic = @import("anthropic.zig");
const openai = @import("openai.zig");
const sse = @import("sse.zig");
const retry = @import("retry.zig");

pub const Adapter = enum {
    openai_compatible,
    anthropic,

    pub fn carries(self: Adapter, capability: message.Capability) bool {
        return switch (self) {
            .openai_compatible => switch (capability) {
                .tool_calls => true,
                .image_results => true,
            },
            .anthropic => switch (capability) {
                .tool_calls => true,
                .image_results => true,
            },
        };
    }
};

pub const Stop = struct {
    reason: []const u8,
    category: []const u8 = "",
    explanation: []const u8 = "",

    pub fn isRefusal(self: Stop) bool {
        return std.mem.eql(u8, self.reason, "refusal");
    }
};

pub const Delta = union(enum) {
    text: []const u8,
    reasoning: []const u8,
    reasoning_signature: []const u8,
    tool_call: message.ToolCallFragment,
    usage: message.Usage,
    stop_reason: Stop,
};

pub const OnDeltaError = std.mem.Allocator.Error;

pub const OnDelta = *const fn (ctx: ?*anyopaque, delta: Delta) OnDeltaError!void;

pub const StatusError = struct {
    status: std.http.Status,
    body: []u8,
    retry_after_s: ?u64 = null,
};

pub const SendResult = union(enum) {
    ok,
    status_error: StatusError,
};

pub const DeltaShapeError = error{
    BodyNotObject,
    MissingChoices,
    ChoicesNotArray,
    NoChoices,
    ChoiceNotObject,
    MissingDelta,
    DeltaNotObject,
    ToolCallsNotArray,
    ToolCallNotObject,
    ToolCallMissingIndex,
    ToolCallIndexNotInteger,
    ToolCallIndexNegative,
    ToolCallFunctionNotObject,
    MissingEventType,
    BlockIndexInvalid,
};

pub const SendError =
    std.mem.Allocator.Error ||
    std.json.ParseError(std.json.Scanner) ||
    DeltaShapeError ||
    sse.Parser.Error ||
    sse.ToolCallAssembler.Error ||
    error{
        TransportFailed,
        BodyCompressed,
        StreamStalled,
        StreamTruncated,
    };

pub const Client = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            request: message.Request,
            on_delta: OnDelta,
            ctx: ?*anyopaque,
        ) SendError!SendResult,
        transportReason: ?*const fn (ptr: *anyopaque) []const u8 = null,
    };

    pub fn send(
        self: Client,
        allocator: std.mem.Allocator,
        request: message.Request,
        on_delta: OnDelta,
        ctx: ?*anyopaque,
    ) SendError!SendResult {
        return self.vtable.send(self.ptr, allocator, request, on_delta, ctx);
    }

    pub fn transportReason(self: Client) []const u8 {
        const ask = self.vtable.transportReason orelse return "";
        return ask(self.ptr);
    }
};

pub const HttpClient = struct {
    http: std.http.Client,
    io: std.Io,
    adapter: Adapter,
    base_url: []const u8,
    key: []const u8,
    last_transport_error: []const u8 = "",
    last_transport_stage: Stage = .open,
    reason_buffer: [128]u8 = undefined,
    gap_ns: u64 = default_gap_ns,
    wire: ?Wire = null,
    idle: ?Idle = null,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, base_url: []const u8, key: []const u8) HttpClient {
        return initAdapter(allocator, io, .openai_compatible, base_url, key);
    }

    pub fn initAnthropic(
        allocator: std.mem.Allocator,
        io: std.Io,
        base_url: []const u8,
        key: []const u8,
    ) HttpClient {
        return initAdapter(allocator, io, .anthropic, base_url, key);
    }

    fn initAdapter(
        allocator: std.mem.Allocator,
        io: std.Io,
        adapter: Adapter,
        base_url: []const u8,
        key: []const u8,
    ) HttpClient {
        return .{
            .http = .{ .allocator = allocator, .io = io },
            .io = io,
            .adapter = adapter,
            .base_url = base_url,
            .key = key,
        };
    }

    pub fn deinit(self: *HttpClient) void {
        self.http.deinit();
    }

    pub fn client(self: *HttpClient) Client {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Client.VTable{ .send = sendVtable, .transportReason = transportReasonVtable };

    fn transportReasonVtable(ptr: *anyopaque) []const u8 {
        const self: *HttpClient = @ptrCast(@alignCast(ptr));
        if (self.last_transport_error.len == 0) return "";
        return std.fmt.bufPrint(&self.reason_buffer, "{s}, {s}", .{
            self.last_transport_stage.text(),
            self.last_transport_error,
        }) catch self.last_transport_error;
    }

    fn sendVtable(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: message.Request,
        on_delta: OnDelta,
        ctx: ?*anyopaque,
    ) SendError!SendResult {
        const self: *HttpClient = @ptrCast(@alignCast(ptr));
        return self.send(allocator, request, on_delta, ctx);
    }

    fn transportFailed(self: *HttpClient, stage: Stage, err: anytype) SendError {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        self.last_transport_error = @errorName(err);
        self.last_transport_stage = stage;
        return error.TransportFailed;
    }

    pub const Stage = enum {
        url,
        open,
        send_body,
        receive_head,

        pub fn text(self: Stage) []const u8 {
            return switch (self) {
                .url => "parsing the base url",
                .open => "opening the connection",
                .send_body => "sending the request",
                .receive_head => "waiting for the response",
            };
        }
    };

    fn send(
        self: *HttpClient,
        allocator: std.mem.Allocator,
        request: message.Request,
        on_delta: OnDelta,
        ctx: ?*anyopaque,
    ) SendError!SendResult {
        const body = switch (self.adapter) {
            .openai_compatible => try openai.buildRequest(allocator, .{
                .model = request.model,
                .system = request.system,
                .messages = request.messages,
                .tools = request.tools,
                .stream = true,
            }),
            .anthropic => try anthropic.buildRequest(allocator, .{
                .model = request.model,
                .system = request.system,
                .messages = request.messages,
                .tools = request.tools,
                .stream = true,
            }),
        };
        defer allocator.free(body);

        const url = try std.fmt.allocPrint(allocator, "{s}{s}", .{
            self.base_url,
            switch (self.adapter) {
                .openai_compatible => openai_path,
                .anthropic => anthropic.path,
            },
        });
        defer allocator.free(url);
        const uri = std.Uri.parse(url) catch |err| return self.transportFailed(.url, err);

        const auth_value = if (self.key.len == 0 or self.adapter != .openai_compatible)
            try allocator.dupe(u8, "")
        else
            try std.fmt.allocPrint(allocator, "Bearer {s}", .{self.key});
        defer {
            // A credential sitting freed but unzeroed in the heap is still readable in a crash dump, a swapped page, or a reused allocation, so this is zeroed before freeing.
            std.crypto.secureZero(u8, @volatileCast(auth_value));
            allocator.free(auth_value);
        }
        const authorization: std.http.Client.Request.Headers.Value =
            if (auth_value.len == 0) .omit else .{ .override = auth_value };

        var header_storage: [3]std.http.Header = undefined;
        var header_count: usize = 0;
        header_storage[header_count] = .{ .name = "Accept", .value = "text/event-stream" };
        header_count += 1;
        switch (self.adapter) {
            .openai_compatible => {
                header_storage[header_count] = .{ .name = aiand_metrics_header, .value = "true" };
                header_count += 1;
            },
            .anthropic => {
                header_storage[header_count] = .{
                    .name = anthropic.version_header,
                    .value = anthropic.version,
                };
                header_count += 1;
                if (self.key.len != 0) {
                    header_storage[header_count] = .{ .name = anthropic.key_header, .value = self.key };
                    header_count += 1;
                }
            },
        }

        var req = self.http.request(.POST, uri, .{
            .keep_alive = false,
            // No redirect is followed: a chat completion response that tries to redirect is refused rather than followed.
            .redirect_behavior = .not_allowed,
            .headers = .{
                .authorization = authorization,
                .content_type = .{ .override = "application/json" },
                .accept_encoding = .{ .override = identity_encoding },
            },
            .extra_headers = header_storage[0..header_count],
        }) catch |err| return self.transportFailed(.open, err);
        defer req.deinit();

        req.sendBodyComplete(body) catch |err| return self.transportFailed(.send_body, err);

        var redirect_buf: [4 * 1024]u8 = undefined;
        var response = req.receiveHead(&redirect_buf) catch |err| return self.transportFailed(.receive_head, err);

        if (response.head.content_encoding != .identity) return error.BodyCompressed;

        if (response.head.status.class() != .success) {
            // Retry-After is read before the response reader is touched, because reading the body invalidates every pointer the head holds.
            const retry_after = retryAfterOf(response.head);
            var transfer_buf: [4 * 1024]u8 = undefined;
            const body_reader = response.reader(&transfer_buf);
            const error_body = try readErrorBody(allocator, body_reader);
            return .{ .status_error = .{
                .status = response.head.status,
                .body = error_body,
                .retry_after_s = retry_after,
            } };
        }

        var transfer_buf: [4 * 1024]u8 = undefined;
        const body_reader = response.reader(&transfer_buf);
        const gap: ?Gap = if (req.connection) |connection| .{
            .io = self.io,
            .stream = connection.stream_reader.stream,
            .in_hand = connection.reader(),
            .gap_ns = self.gap_ns,
            .wire = self.wire,
            .idle = self.idle,
        } else null;
        return streamBody(allocator, self.adapter, response.head.status, body_reader, gap, on_delta, ctx);
    }
};

const openai_path = "/chat/completions";

const aiand_metrics_header = "X-Aiand-Metrics";

const aiand_metrics_event = "metrics";

const max_currency = 8;

const identity_encoding = "identity";

pub const default_gap_ns: u64 = 5 * std.time.ns_per_min;

pub const Wire = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        moreIsComing: *const fn (ptr: *anyopaque, gap_ns: u64) bool,
    };

    pub fn moreIsComing(self: Wire, gap_ns: u64) bool {
        return self.vtable.moreIsComing(self.ptr, gap_ns);
    }
};

pub const Idle = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        step: *const fn (ptr: *anyopaque) void,
    };

    pub fn step(self: Idle) void {
        self.vtable.step(self.ptr);
    }
};

pub const idle_slice_ms: u64 = 100;

pub fn idleSlice(left_ms: i32) i32 {
    std.debug.assert(left_ms > 0);
    return @min(left_ms, @as(i32, @intCast(idle_slice_ms)));
}

const Gap = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    in_hand: *std.Io.Reader,
    gap_ns: u64,
    wire: ?Wire = null,
    idle: ?Idle = null,

    fn eventInHand(self: Gap) bool {
        const buffered = self.in_hand.buffered();
        if (std.mem.indexOf(u8, buffered, "\n\n") != null) return true;
        return std.mem.indexOf(u8, buffered, "\r\n\r\n") != null;
    }

    fn moreIsComing(self: Gap) bool {
        if (self.wire) |scripted| return scripted.moreIsComing(self.gap_ns);
        const ms = self.gap_ns / std.time.ns_per_ms;
        const whole: i32 = if (ms > std.math.maxInt(i32)) std.math.maxInt(i32) else @intCast(ms);

        const filler = self.idle orelse return self.readable(whole);

        var left = whole;
        while (left > 0) {
            const slice = idleSlice(left);
            if (self.readable(slice)) return true;
            left -= slice;
            filler.step();
        }
        return false;
    }

    fn readable(self: Gap, timeout_ms: i32) bool {
        var fds = [_]std.posix.pollfd{.{
            .fd = self.stream.socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&fds, timeout_ms) catch return true;
        return ready != 0;
    }

    fn stopReading(self: Gap) void {
        self.stream.shutdown(self.io, .recv) catch {};
    }
};

const max_error_body_bytes: usize = 8 * 1024 * 1024;

fn retryAfterOf(head: std.http.Client.Response.Head) ?u64 {
    var headers = head.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "retry-after")) continue;
        return retry.retryAfterSeconds(header.value);
    }
    return null;
}

fn readErrorBody(allocator: std.mem.Allocator, body_reader: *std.Io.Reader) std.mem.Allocator.Error![]u8 {
    return body_reader.allocRemaining(allocator, .limited(max_error_body_bytes)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => try std.fmt.allocPrint(
            allocator,
            "[error body exceeded {d} bytes and was discarded]",
            .{max_error_body_bytes},
        ),
        error.ReadFailed => try std.fmt.allocPrint(
            allocator,
            "[error body could not be read: the connection failed partway through]",
            .{},
        ),
    };
}

fn streamBody(
    allocator: std.mem.Allocator,
    adapter: Adapter,
    status: std.http.Status,
    body_reader: *std.Io.Reader,
    gap: ?Gap,
    on_delta: OnDelta,
    ctx: ?*anyopaque,
) SendError!SendResult {
    var parser = sse.Parser.init(allocator);
    defer parser.deinit();
    var decoder = anthropic.Decoder.init(allocator);
    defer decoder.deinit();
    var sent_stop_reason: [max_stop_reason]u8 = @splat(0);
    var sent_len: usize = 0;
    var saw_end = false;
    var stalled = false;

    while (true) {
        if (gap) |watch| {
            if (!stalled and !saw_end and !watch.eventInHand() and !watch.moreIsComing()) {
                watch.stopReading();
                stalled = true;
            }
        }

        body_reader.fillMore() catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed => {
                if (saw_end) break;
                return if (stalled) error.StreamStalled else error.StreamTruncated;
            },
        };

        const available = body_reader.buffered();
        if (available.len == 0) continue;

        try parser.feed(available);
        body_reader.toss(available.len);

        while (parser.next()) |event| {
            defer event.deinit(allocator);
            switch (event) {
                .done => saw_end = true,
                .data => |data| switch (adapter) {
                    .openai_compatible => if (std.mem.eql(u8, data.name, aiand_metrics_event))
                        // ai&'s metrics event is identified by the name the server gave it, never by sniffing the JSON shape.
                        try deliverAiandMetrics(allocator, data.body, on_delta, ctx)
                    else
                        try deliverDelta(allocator, data.body, on_delta, ctx),
                    .anthropic => {
                        if (try deliverAnthropic(allocator, &decoder, data.body, status, on_delta, ctx)) |refusal| {
                            return .{ .status_error = refusal };
                        }
                        const reason = decoder.stopReason();
                        if (reason.len != 0 and !std.mem.eql(u8, reason, sent_stop_reason[0..sent_len])) {
                            sent_len = keepCut(&sent_stop_reason, reason);
                            const details = decoder.stopDetails();
                            try on_delta(ctx, .{ .stop_reason = .{
                                .reason = reason,
                                .category = details.category,
                                .explanation = details.explanation,
                            } });
                        }
                        saw_end = saw_end or decoder.saw_message_stop;
                    },
                },
            }
        }
    }

    // A reply whose own end marker already arrived finishes as complete even when the connection drops right after: the end marker proves the reply is whole, and a half read event that arrives after it belongs to no part of this reply.
    if (!saw_end) {
        return if (stalled) error.StreamStalled else error.StreamTruncated;
    }
    return .ok;
}

fn deliverAnthropic(
    allocator: std.mem.Allocator,
    decoder: *anthropic.Decoder,
    json_text: []const u8,
    status: std.http.Status,
    on_delta: OnDelta,
    ctx: ?*anyopaque,
) SendError!?StatusError {
    const piece = try decoder.feed(json_text);
    switch (piece) {
        .none => {},
        .text => |text| if (text.len != 0) try on_delta(ctx, .{ .text = text }),
        .reasoning => |text| if (text.len != 0) try on_delta(ctx, .{ .reasoning = text }),
        .reasoning_signature => |text| if (text.len != 0) {
            try on_delta(ctx, .{ .reasoning_signature = text });
        },
        .tool_call => |fragment| try on_delta(ctx, .{ .tool_call = fragment }),
        .usage => |usage| try on_delta(ctx, .{ .usage = usage }),
        .stream_error => return StatusError{
            .status = status,
            .body = try allocator.dupe(u8, json_text),
        },
    }
    return null;
}

fn deliverDelta(
    allocator: std.mem.Allocator,
    json_text: []const u8,
    on_delta: OnDelta,
    ctx: ?*anyopaque,
) SendError!void {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.BodyNotObject;

    const reported_usage = openAiUsage(parsed.value.object);
    if (reported_usage) |usage| try on_delta(ctx, .{ .usage = usage });

    const choices_value = parsed.value.object.get("choices") orelse {
        if (reported_usage != null) return;
        return error.MissingChoices;
    };
    if (choices_value != .array) return error.ChoicesNotArray;
    if (choices_value.array.items.len == 0) {
        if (reported_usage != null) return;
        return error.NoChoices;
    }

    const choice_value = choices_value.array.items[0];
    if (choice_value != .object) return error.ChoiceNotObject;

    if (choice_value.object.get("finish_reason")) |v| {
        if (v == .string and v.string.len != 0) {
            try on_delta(ctx, .{ .stop_reason = .{ .reason = v.string } });
        }
    }

    const delta_value = choice_value.object.get("delta") orelse return error.MissingDelta;
    if (delta_value != .object) return error.DeltaNotObject;
    const delta = delta_value.object;

    if (delta.get("content")) |v| {
        if (v == .string and v.string.len != 0) try on_delta(ctx, .{ .text = v.string });
    }
    if (delta.get("reasoning_content")) |v| {
        if (v == .string and v.string.len != 0) try on_delta(ctx, .{ .reasoning = v.string });
    }

    if (delta.get("tool_calls")) |tool_calls_value| {
        if (tool_calls_value != .array) return error.ToolCallsNotArray;
        for (tool_calls_value.array.items) |call_value| {
            if (call_value != .object) return error.ToolCallNotObject;
            const call = call_value.object;

            const index_value = call.get("index") orelse return error.ToolCallMissingIndex;
            if (index_value != .integer) return error.ToolCallIndexNotInteger;
            if (index_value.integer < 0) return error.ToolCallIndexNegative;
            var fragment = message.ToolCallFragment{ .index = @intCast(index_value.integer) };

            if (call.get("id")) |id_value| {
                if (id_value == .string) fragment.id = id_value.string;
            }
            if (call.get("function")) |function_value| {
                if (function_value != .object) return error.ToolCallFunctionNotObject;
                const function = function_value.object;
                if (function.get("name")) |name_value| {
                    if (name_value == .string) fragment.name = name_value.string;
                }
                if (function.get("arguments")) |arguments_value| {
                    if (arguments_value == .string) fragment.arguments = arguments_value.string;
                }
            }
            try on_delta(ctx, .{ .tool_call = fragment });
        }
    }
}

fn firstOf(object: std.json.ObjectMap, names: []const []const u8) ?std.json.Value {
    for (names) |name| {
        if (object.get(name)) |value| return value;
    }
    return null;
}

fn countOf(object: std.json.ObjectMap, names: []const []const u8) ?u64 {
    const value = firstOf(object, names) orelse return null;
    if (value != .integer or value.integer < 0) return null;
    return @intCast(value.integer);
}

fn textOf(object: std.json.ObjectMap, names: []const []const u8) ?[]const u8 {
    const value = firstOf(object, names) orelse return null;
    return if (value == .string) value.string else null;
}

fn numberOf(object: std.json.ObjectMap, names: []const []const u8) ?f64 {
    const value = firstOf(object, names) orelse return null;
    return switch (value) {
        .float => |amount| amount,
        .integer => |amount| @floatFromInt(amount),
        .number_string => |text| std.fmt.parseFloat(f64, text) catch null,
        else => null,
    };
}

fn iso4217(text: []const u8, buf: []u8) []const u8 {
    if (text.len == 0 or text.len > buf.len) return text;
    return std.ascii.upperString(buf[0..text.len], text);
}

fn deliverAiandMetrics(
    allocator: std.mem.Allocator,
    json_text: []const u8,
    on_delta: OnDelta,
    ctx: ?*anyopaque,
) SendError!void {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return,
    };
    defer parsed.deinit();
    if (parsed.value != .object) return;

    var currency_buf: [max_currency]u8 = undefined;
    const usage = aiandMetrics(parsed.value.object, &currency_buf) orelse return;
    try on_delta(ctx, .{ .usage = usage });
}

fn aiandMetrics(object: std.json.ObjectMap, currency_buf: []u8) ?message.Usage {
    var usage = message.Usage{};
    var said_anything = false;

    if (object.get("tokens")) |tokens_value| {
        if (tokens_value == .object) {
            const tokens = tokens_value.object;
            said_anything = true;
            if (countOf(tokens, &.{"input"})) |count| usage.input_tokens = count;
            if (countOf(tokens, &.{"output"})) |count| usage.output_tokens = count;
            // Cached prompt tokens are counted apart from fresh ones here too, because a cached token is billed at a fraction of a fresh one and folding them together would hide the discount.
            if (countOf(tokens, &.{"cached"})) |count| usage.cache_read_input_tokens = count;
        }
    }

    if (numberOf(object, &.{"cost"})) |amount| {
        said_anything = true;
        usage.cost = .{ .known = .{
            .value = amount,
            .currency = iso4217(textOf(object, &.{"currency"}) orelse "", currency_buf),
        } };
    }
    if (countOf(object, &.{"inference_ms"})) |count| {
        said_anything = true;
        usage.inference_ms = count;
    }

    return if (said_anything) usage else null;
}

fn openAiUsage(object: std.json.ObjectMap) ?message.Usage {
    var usage = message.Usage{};
    var said_anything = false;

    if (object.get("usage")) |usage_value| {
        if (usage_value == .object) {
            const counts = usage_value.object;
            said_anything = true;
            if (countOf(counts, &.{ "prompt_tokens", "input_tokens" })) |count| {
                usage.input_tokens = count;
            }
            if (countOf(counts, &.{ "completion_tokens", "output_tokens" })) |count| {
                usage.output_tokens = count;
            }
            if (counts.get("prompt_tokens_details")) |details| {
                if (details == .object) {
                    if (countOf(details.object, &.{"cached_tokens"})) |count| {
                        usage.cache_read_input_tokens = count;
                    }
                }
            }
        }
    }

    if (numberOf(object, &.{ "X-Cost", "x_cost", "cost" })) |amount| {
        said_anything = true;
        usage.cost = .{ .known = .{
            .value = amount,
            .currency = textOf(object, &.{ "X-Cost-Currency", "x_cost_currency", "cost_currency" }) orelse "",
        } };
    }
    if (textOf(object, &.{ "X-Request-ID", "x_request_id", "request_id", "id" })) |text| {
        usage.request_id = text;
    }
    if (countOf(object, &.{ "X-Inference-Ms", "x_inference_ms", "inference_ms" })) |count| {
        said_anything = true;
        usage.inference_ms = count;
    }
    if (textOf(object, &.{ "X-Reasoning-Effort", "x_reasoning_effort", "reasoning_effort" })) |text| {
        said_anything = true;
        usage.reasoning_effort_applied = text;
    }

    return if (said_anything) usage else null;
}

pub const AssembledReply = struct {
    outcome: Outcome,
    stop_reason_buffer: [max_stop_reason]u8 = @splat(0),
    stop_reason_len: usize = 0,
    stop_category_buffer: [max_stop_category]u8 = @splat(0),
    stop_category_len: usize = 0,
    stop_explanation_buffer: [max_stop_explanation]u8 = @splat(0),
    stop_explanation_len: usize = 0,
    usage: message.Usage,

    pub const Outcome = union(enum) {
        message: message.Message,
        status_error: StatusError,
        failed: struct {
            err: SendError,
            partial: message.Message,
            reason: []const u8 = "",
        },
    };

    pub fn stopReason(self: *const AssembledReply) []const u8 {
        return self.stop_reason_buffer[0..self.stop_reason_len];
    }

    pub fn stop(self: *const AssembledReply) Stop {
        return .{
            .reason = self.stopReason(),
            .category = self.stop_category_buffer[0..self.stop_category_len],
            .explanation = self.stop_explanation_buffer[0..self.stop_explanation_len],
        };
    }
};

pub const max_stop_reason: usize = 64;

pub const max_stop_category: usize = anthropic.max_stop_category;

pub const max_stop_explanation: usize = anthropic.max_stop_explanation;

fn keepCut(buffer: []u8, text: []const u8) usize {
    const kept = @min(text.len, buffer.len);
    @memcpy(buffer[0..kept], text[0..kept]);
    return kept;
}

pub const OnWatchedDelta = *const fn (ctx: ?*anyopaque, delta: Delta) void;

pub const Watcher = struct {
    ctx: ?*anyopaque = null,
    on_delta: OnWatchedDelta,
};

pub fn sendAndAssemble(
    c: Client,
    allocator: std.mem.Allocator,
    request: message.Request,
) SendError!AssembledReply {
    return sendAndAssembleWatching(c, allocator, request, null);
}

pub fn sendAndAssembleWatching(
    c: Client,
    allocator: std.mem.Allocator,
    request: message.Request,
    watcher: ?Watcher,
) SendError!AssembledReply {
    var collector = Collector.init(allocator);
    collector.watcher = watcher;
    defer collector.deinit();

    const result = c.send(allocator, request, Collector.onDelta, &collector) catch |err| {
        return collector.reply(.{ .failed = .{
            .err = err,
            .partial = try collector.toMessage(),
            .reason = c.transportReason(),
        } });
    };
    switch (result) {
        .status_error => |status_error| return collector.reply(.{ .status_error = status_error }),
        .ok => {},
    }
    if (collector.err) |err| {
        return collector.reply(.{ .failed = .{ .err = err, .partial = try collector.toMessage() } });
    }
    return collector.reply(.{ .message = try collector.toMessage() });
}

pub fn freeUsage(allocator: std.mem.Allocator, usage: message.Usage) void {
    if (usage.cost == .known and usage.cost.known.currency.len != 0) {
        allocator.free(usage.cost.known.currency);
    }
    if (usage.request_id.len != 0) allocator.free(usage.request_id);
    if (usage.reasoning_effort_applied.len != 0) allocator.free(usage.reasoning_effort_applied);
    if (usage.model.len != 0) allocator.free(usage.model);
}

pub fn freeAssembledMessage(allocator: std.mem.Allocator, msg: message.Message) void {
    for (msg.content) |part| {
        switch (part) {
            .text => |text| allocator.free(text),
            .reasoning => |reasoning| {
                allocator.free(reasoning.text);
                allocator.free(reasoning.signature);
            },
            .tool_use => |tool_use| {
                allocator.free(tool_use.call_id);
                allocator.free(tool_use.tool);
                allocator.free(tool_use.arguments);
            },
            .tool_result, .image, .unknown => std.debug.panic(
                "freeAssembledMessage received a .{s} content part; sendAndAssemble never builds one",
                .{@tagName(part)},
            ),
        }
    }
    allocator.free(msg.content);
}

const Collector = struct {
    allocator: std.mem.Allocator,
    text: std.ArrayList(u8) = .empty,
    reasoning: std.ArrayList(u8) = .empty,
    assembler: sse.ToolCallAssembler,
    order: std.ArrayList(Kind) = .empty,
    seen_tool_indices: std.AutoArrayHashMapUnmanaged(usize, void) = .empty,
    reasoning_signature: std.ArrayList(u8) = .empty,
    usage: message.Usage = .{},
    saw_usage: bool = false,
    err: ?sse.ToolCallAssembler.Error = null,
    stop_reason_buffer: [max_stop_reason]u8 = @splat(0),
    stop_reason_len: usize = 0,
    stop_category_buffer: [max_stop_category]u8 = @splat(0),
    stop_category_len: usize = 0,
    stop_explanation_buffer: [max_stop_explanation]u8 = @splat(0),
    stop_explanation_len: usize = 0,
    watcher: ?Watcher = null,

    const Kind = union(enum) {
        text,
        reasoning,
        tool_call: usize,
    };

    fn init(allocator: std.mem.Allocator) Collector {
        return .{ .allocator = allocator, .assembler = sse.ToolCallAssembler.init(allocator) };
    }

    fn deinit(self: *Collector) void {
        self.text.deinit(self.allocator);
        self.reasoning.deinit(self.allocator);
        self.reasoning_signature.deinit(self.allocator);
        self.order.deinit(self.allocator);
        self.seen_tool_indices.deinit(self.allocator);
        self.assembler.deinit();
        freeUsage(self.allocator, self.usage);
    }

    fn reply(self: *Collector, outcome: AssembledReply.Outcome) std.mem.Allocator.Error!AssembledReply {
        return .{
            .outcome = outcome,
            .usage = try self.takeUsage(),
            .stop_reason_buffer = self.stop_reason_buffer,
            .stop_reason_len = self.stop_reason_len,
            .stop_category_buffer = self.stop_category_buffer,
            .stop_category_len = self.stop_category_len,
            .stop_explanation_buffer = self.stop_explanation_buffer,
            .stop_explanation_len = self.stop_explanation_len,
        };
    }

    fn takeUsage(self: *Collector) std.mem.Allocator.Error!message.Usage {
        const usage = self.usage;
        self.usage = .{};
        return usage;
    }

    fn replaceUsage(self: *Collector, incoming: message.Usage) OnDeltaError!void {
        var copy = incoming;
        copy.request_id = if (incoming.request_id.len == 0)
            ""
        else
            try self.allocator.dupe(u8, incoming.request_id);
        errdefer if (copy.request_id.len != 0) self.allocator.free(copy.request_id);

        copy.reasoning_effort_applied = if (incoming.reasoning_effort_applied.len == 0)
            ""
        else
            try self.allocator.dupe(u8, incoming.reasoning_effort_applied);
        errdefer if (copy.reasoning_effort_applied.len != 0) {
            self.allocator.free(copy.reasoning_effort_applied);
        };

        copy.model = if (incoming.model.len == 0) "" else try self.allocator.dupe(u8, incoming.model);
        errdefer if (copy.model.len != 0) self.allocator.free(copy.model);

        if (incoming.cost == .known and incoming.cost.known.currency.len != 0) {
            copy.cost = .{ .known = .{
                .value = incoming.cost.known.value,
                .currency = try self.allocator.dupe(u8, incoming.cost.known.currency),
            } };
        }

        freeUsage(self.allocator, self.usage);
        self.usage = copy;
        self.saw_usage = true;
    }

    fn onDelta(ctx: ?*anyopaque, delta: Delta) OnDeltaError!void {
        const self: *Collector = @ptrCast(@alignCast(ctx.?));
        if (self.watcher) |watching| watching.on_delta(watching.ctx, delta);
        switch (delta) {
            .text => |text| {
                if (self.text.items.len == 0) try self.order.append(self.allocator, .text);
                try self.text.appendSlice(self.allocator, text);
            },
            .reasoning => |text| {
                if (self.reasoning.items.len == 0) try self.order.append(self.allocator, .reasoning);
                try self.reasoning.appendSlice(self.allocator, text);
            },
            .reasoning_signature => |text| {
                if (self.reasoning.items.len == 0 and self.reasoning_signature.items.len == 0) {
                    try self.order.append(self.allocator, .reasoning);
                }
                try self.reasoning_signature.appendSlice(self.allocator, text);
            },
            .usage => |usage| try self.replaceUsage(usage),
            .stop_reason => |stopped| {
                self.stop_reason_len = keepCut(&self.stop_reason_buffer, stopped.reason);
                self.stop_category_len = keepCut(&self.stop_category_buffer, stopped.category);
                self.stop_explanation_len = keepCut(
                    &self.stop_explanation_buffer,
                    stopped.explanation,
                );
            },
            .tool_call => |fragment| {
                if (!self.seen_tool_indices.contains(fragment.index)) {
                    try self.seen_tool_indices.put(self.allocator, fragment.index, {});
                    try self.order.append(self.allocator, .{ .tool_call = fragment.index });
                }
                self.assembler.feed(fragment) catch |err| {
                    self.err = err;
                };
            },
        }
    }

    fn findCall(calls: []const sse.ToolCall, index: usize) ?sse.ToolCall {
        for (calls) |call| {
            if (call.index == index) return call;
        }
        return null;
    }

    fn toMessage(self: *Collector) std.mem.Allocator.Error!message.Message {
        var parts: std.ArrayList(message.ContentPart) = .empty;
        errdefer parts.deinit(self.allocator);

        const calls = try self.assembler.finished();
        defer sse.freeFinished(self.allocator, calls);

        for (self.order.items) |kind| {
            switch (kind) {
                .text => try parts.append(self.allocator, .{ .text = try self.text.toOwnedSlice(self.allocator) }),
                .reasoning => try parts.append(self.allocator, .{
                    .reasoning = .{
                        .text = try self.reasoning.toOwnedSlice(self.allocator),
                        .signature = try self.reasoning_signature.toOwnedSlice(self.allocator),
                    },
                }),
                .tool_call => |index| {
                    const call = findCall(calls, index) orelse continue;
                    if (!call.complete) continue;
                    try parts.append(self.allocator, .{ .tool_use = .{
                        .call_id = try self.allocator.dupe(u8, call.id),
                        .tool = try self.allocator.dupe(u8, call.name),
                        .arguments = try self.allocator.dupe(u8, call.arguments),
                    } });
                },
            }
        }

        return .{
            .role = .assistant,
            .content = try parts.toOwnedSlice(self.allocator),
            .model_alias = "",
        };
    }
};

// This file's own tests live in test/core/client.zig instead: they need a real socket server, and Zig 0.16 refuses a relative @import that reaches outside this file's own module.

test "a transport fault carries the transport's own name for it, not only TransportFailed" {
    const Stub = struct {
        reason: []const u8,

        fn sendVtable(
            _: *anyopaque,
            _: std.mem.Allocator,
            _: message.Request,
            _: OnDelta,
            _: ?*anyopaque,
        ) SendError!SendResult {
            return error.TransportFailed;
        }

        fn reasonVtable(ptr: *anyopaque) []const u8 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.reason;
        }

        const table = Client.VTable{ .send = sendVtable, .transportReason = reasonVtable };

        fn client(self: *@This()) Client {
            return .{ .ptr = self, .vtable = &table };
        }
    };

    var stub = Stub{ .reason = "ConnectionResetByPeer" };
    const reply = try sendAndAssembleWatching(stub.client(), std.testing.allocator, .{
        .model = "m",
        .system = "",
        .messages = &.{},
        .tools = &.{},
    }, null);
    defer freeUsage(std.testing.allocator, reply.usage);
    defer freeAssembledMessage(std.testing.allocator, reply.outcome.failed.partial);

    try std.testing.expectEqual(SendError.TransportFailed, reply.outcome.failed.err);
    try std.testing.expectEqualStrings("ConnectionResetByPeer", reply.outcome.failed.reason);
}

test "a client that keeps no reason answers empty rather than refusing to build" {
    const Bare = struct {
        fn sendVtable(
            _: *anyopaque,
            _: std.mem.Allocator,
            _: message.Request,
            _: OnDelta,
            _: ?*anyopaque,
        ) SendError!SendResult {
            return error.TransportFailed;
        }

        const table = Client.VTable{ .send = sendVtable };
    };

    var nothing: u8 = 0;
    const bare = Client{ .ptr = &nothing, .vtable = &Bare.table };
    try std.testing.expectEqualStrings("", bare.transportReason());
}
