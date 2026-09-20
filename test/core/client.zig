//! Tests for `lib/chock-provider/Client.zig`. They live here because Zig 0.16
//! refuses a relative `@import` outside a module's root directory, so
//! `Client.zig` cannot import `fake_provider.zig` under `test/`.

const std = @import("std");
const provider = @import("chock-provider");
const fake_provider = @import("fake_provider.zig");

const Client = provider.Client.Client;
const HttpClient = provider.Client.HttpClient;
const Delta = provider.Client.Delta;
const OnDelta = provider.Client.OnDelta;
const OnDeltaError = provider.Client.OnDeltaError;
const SendError = provider.Client.SendError;
const SendResult = provider.Client.SendResult;
const sendAndAssemble = provider.Client.sendAndAssemble;
const freeAssembledMessage = provider.Client.freeAssembledMessage;
const freeUsage = provider.Client.freeUsage;
const message = provider.message;

fn noopOnDelta(ctx: ?*anyopaque, delta: Delta) OnDeltaError!void {
    _ = ctx;
    _ = delta;
}

fn testRequest(messages: []const message.Message) message.Request {
    return .{ .model = "glm4.7-flash:A3B", .system = "", .messages = messages };
}

/// A wire that answers from a script and lets one more piece of the reply out
/// for each answer. This takes the clock out of the gap bound tests: a piece
/// goes out because the client asked, so a test pins an order. The rest is real.
const ScriptedWire = struct {
    gate: *fake_provider.Gate,
    /// One answer per question. The last stands for every question after it.
    answers: []const bool,
    /// A client that never asked would get no piece of the reply at all.
    asked: usize = 0,

    fn wire(self: *ScriptedWire) provider.Client.Wire {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = provider.Client.Wire.VTable{ .moreIsComing = moreIsComingFn };

    fn moreIsComingFn(ptr: *anyopaque, gap_ns: u64) bool {
        _ = gap_ns;
        const self: *ScriptedWire = @ptrCast(@alignCast(ptr));
        const live = self.answers[@min(self.asked, self.answers.len - 1)];
        self.asked += 1;
        if (live) self.gate.release();
        return live;
    }
};

test "a complete streamed reply arrives as one assembled message" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // One event is split mid JSON, which breaks a client that reads whole events.
    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello\"}}]}\n\n",
            ) },
            .{
                .bytes = fake_provider.httpChunk("data: {\"choices\":[{\"index\":0,\"del"),
                .delay = .fromMilliseconds(5),
            },
            .{
                .bytes = fake_provider.httpChunk("ta\":{\"content\":\", world\"}}]}\n\n"),
                .delay = .fromMilliseconds(5),
            },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: [DONE]\n\n") },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();

    defer freeUsage(allocator, reply.usage);
    switch (reply.outcome) {
        .status_error, .failed => return error.TestUnexpectedResult,
        .message => |msg| {
            defer freeAssembledMessage(allocator, msg);
            try std.testing.expectEqual(message.Role.assistant, msg.role);
            try std.testing.expectEqual(@as(usize, 1), msg.content.len);
            try std.testing.expectEqualStrings("Hello, world", msg.content[0].text);
        },
    }
}

test "a stream that stops in the middle is an error and not a short message" {
    // The chunked encoding ends cleanly with its own zero length chunk, so the
    // transport sees nothing wrong. Only a missing `[DONE]` catches this.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"}}]}\n\n",
            ) },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();

    defer freeUsage(allocator, reply.usage);
    switch (reply.outcome) {
        .message, .status_error => return error.TestUnexpectedResult,
        .failed => |failed| {
            defer freeAssembledMessage(allocator, failed.partial);
            try std.testing.expect(failed.err == error.StreamTruncated);
            try std.testing.expectEqual(@as(usize, 1), failed.partial.content.len);
            try std.testing.expectEqualStrings("Hello", failed.partial.content[0].text);
        },
    }
}

test "a provider that stops sending mid reply is stopped, and says so, rather than hanging the session" {
    // The silence is scripted and never timed. The second question gets nothing.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var gate = fake_provider.Gate{};
    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"}}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\", world\"}}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: [DONE]\n\n") },
            .{ .bytes = fake_provider.last_chunk },
        },
        .gate = &gate,
    });

    var wire = ScriptedWire{ .gate = &gate, .answers = &.{ true, false } };
    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();
    http_client.wire = wire.wire();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    // Before the join: the server holds pieces nothing else will let out.
    gate.openAll();
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);

    try std.testing.expectEqual(@as(usize, 2), wire.asked);

    switch (reply.outcome) {
        .message, .status_error => return error.TestUnexpectedResult,
        .failed => |failed| {
            defer freeAssembledMessage(allocator, failed.partial);
            try std.testing.expect(failed.err == error.StreamStalled);
            try std.testing.expect(failed.err != error.StreamTruncated);
            try std.testing.expectEqual(@as(usize, 1), failed.partial.content.len);
            try std.testing.expectEqualStrings("Hello", failed.partial.content[0].text);
        },
    }
}

test "a reply that is merely slow is left alone, because the bound is on the gap and not on the call" {
    // Every answer says "still sending" and lets one more piece out, so the check
    // saw activity at each gap. Nothing here is a duration.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var gate = fake_provider.Gate{};
    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"one \"}}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"two \"}}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"three\"}}]}\n\n",
            ) },
            // The end marker and the last chunk go out as one piece. Split in two
            // they need a fifth question, which the loop never asks.
            .{ .bytes = comptime fake_provider.httpChunk("data: [DONE]\n\n") ++ fake_provider.last_chunk },
        },
        .gate = &gate,
    });

    var wire = ScriptedWire{ .gate = &gate, .answers = &.{true} };
    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();
    http_client.wire = wire.wire();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    gate.openAll();
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);

    try std.testing.expectEqual(@as(usize, 4), wire.asked);

    switch (reply.outcome) {
        .status_error, .failed => return error.TestUnexpectedResult,
        .message => |msg| {
            defer freeAssembledMessage(allocator, msg);
            try std.testing.expectEqualStrings("one two three", msg.content[0].text);
        },
    }
}

test "a non 200 status is reported with what the body said" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const refusal_body = "{\"error\":{\"message\":\"the model refused: disallowed content\"}}";
    const head = std.fmt.comptimePrint(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{refusal_body.len},
    );

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = head,
        .body = &.{.{ .bytes = refusal_body }},
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const result = try http_client.client().send(allocator, testRequest(&messages), noopOnDelta, null);
    fp.join();
    defer fp.deinit();

    switch (result) {
        .ok => return error.TestUnexpectedResult,
        .status_error => |status_error| {
            defer allocator.free(status_error.body);
            try std.testing.expectEqual(std.http.Status.bad_request, status_error.status);
            try std.testing.expectEqualStrings(refusal_body, status_error.body);
        },
    }
}

test "a 429 carries its own Retry-After off the wire, and a refusal without one carries null" {
    // `Retry-After` is read off the head before the body, because reading the body
    // invalidates every pointer the head holds. Only a real `receiveHead` gets that wrong.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const refusal_body = "{\"error\":{\"type\":\"rate_limit_error\",\"message\":\"500,000 input tokens per minute\"}}";
    const limited_head = std.fmt.comptimePrint(
        "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 42\r\nContent-Type: application/json\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n",
        .{refusal_body.len},
    );

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = limited_head,
        .body = &.{.{ .bytes = refusal_body }},
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const result = try http_client.client().send(allocator, testRequest(&messages), noopOnDelta, null);
    fp.join();
    defer fp.deinit();

    switch (result) {
        .ok => return error.TestUnexpectedResult,
        .status_error => |status_error| {
            defer allocator.free(status_error.body);
            try std.testing.expectEqual(std.http.Status.too_many_requests, status_error.status);
            try std.testing.expectEqual(@as(?u64, 42), status_error.retry_after_s);
            try std.testing.expectEqualStrings(refusal_body, status_error.body);
        },
    }

    // Null and never a zero. A zero would be a wait of no time at all.
    const plain_head = std.fmt.comptimePrint(
        "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n",
        .{refusal_body.len},
    );
    var plain_fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = plain_head,
        .body = &.{.{ .bytes = refusal_body }},
    });

    var plain_base_buf: [64]u8 = undefined;
    var plain_client = HttpClient.init(allocator, io, plain_fp.baseUrl(&plain_base_buf), "test-key");
    defer plain_client.deinit();

    const plain_result = try plain_client.client().send(allocator, testRequest(&messages), noopOnDelta, null);
    plain_fp.join();
    defer plain_fp.deinit();

    switch (plain_result) {
        .ok => return error.TestUnexpectedResult,
        .status_error => |status_error| {
            defer allocator.free(status_error.body);
            try std.testing.expectEqual(@as(?u64, null), status_error.retry_after_s);
        },
    }
}

test "the key travels in a header and appears in no log line" {
    // The body is what a session log holds, so the key must be in a header only.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key = "sk-test-only-secret-9f3c";

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: [DONE]\n\n") },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), key);
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "a secret must never ride along with a prompt" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);
    defer switch (reply.outcome) {
        .message => |msg| freeAssembledMessage(allocator, msg),
        .status_error => |status_error| allocator.free(status_error.body),
        .failed => |failed| freeAssembledMessage(allocator, failed.partial),
    };

    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "authorization: Bearer " ++ key) != null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.body, key) == null);
}

test "the fake and the HTTP client produce the same assembled message for the same deltas" {
    // Two implementations, driven through one function written against the
    // interface, agree on one message. Not a proof that nothing can tell them apart.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const StubClient = struct {
        deltas: []const Delta,

        fn send(
            ptr: *anyopaque,
            alloc: std.mem.Allocator,
            request: message.Request,
            on_delta: OnDelta,
            ctx: ?*anyopaque,
        ) SendError!SendResult {
            _ = alloc;
            _ = request;
            const self: *@This() = @ptrCast(@alignCast(ptr));
            for (self.deltas) |delta| try on_delta(ctx, delta);
            return .ok;
        }

        fn client(self: *@This()) Client {
            return .{ .ptr = self, .vtable = &.{ .send = send } };
        }
    };

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};
    const request = testRequest(&messages);

    var stub = StubClient{ .deltas = &.{ .{ .text = "Hello" }, .{ .text = ", world" } } };
    const stub_reply = try sendAndAssemble(stub.client(), allocator, request);
    defer freeUsage(allocator, stub_reply.usage);
    defer switch (stub_reply.outcome) {
        .message => |msg| freeAssembledMessage(allocator, msg),
        .status_error => |status_error| allocator.free(status_error.body),
        .failed => |failed| freeAssembledMessage(allocator, failed.partial),
    };

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"}}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\", world\"},\"finish_reason\":\"stop\"}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: [DONE]\n\n") },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const http_reply = try sendAndAssemble(http_client.client(), allocator, request);
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, http_reply.usage);
    defer switch (http_reply.outcome) {
        .message => |msg| freeAssembledMessage(allocator, msg),
        .status_error => |status_error| allocator.free(status_error.body),
        .failed => |failed| freeAssembledMessage(allocator, failed.partial),
    };

    try std.testing.expect(stub_reply.outcome == .message);
    try std.testing.expect(http_reply.outcome == .message);
    try std.testing.expectEqual(message.Role.assistant, stub_reply.outcome.message.role);
    try std.testing.expectEqual(message.Role.assistant, http_reply.outcome.message.role);
    try std.testing.expectEqualStrings(stub_reply.outcome.message.content[0].text, http_reply.outcome.message.content[0].text);
}

/// How far the reply had got when each text delta was handed on, in pieces let
/// out of the gate. A count and not a clock.
const ArrivalCtx = struct {
    allocator: std.mem.Allocator,
    wire: *const ScriptedWire,
    /// One entry per text delta.
    pieces_out: std.ArrayList(usize) = .empty,
};

fn recordArrival(ctx: ?*anyopaque, delta: Delta) OnDeltaError!void {
    const self: *ArrivalCtx = @ptrCast(@alignCast(ctx.?));
    if (delta != .text) return;
    try self.pieces_out.append(self.allocator, self.wire.asked);
}

test "a delta sent early arrives before a later one is sent" {
    // A fixed size read buffer that reports only once it fills makes every delta
    // arrive together at the end. Reading the response head takes the first pieces
    // of the body with it, so a gap bound that waits with an event in hand does too.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var gate = fake_provider.Gate{};
    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"first\"}}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"second\"},\"finish_reason\":\"stop\"}]}\n\n",
            ) },
            .{ .bytes = comptime fake_provider.httpChunk("data: [DONE]\n\n") ++ fake_provider.last_chunk },
        },
        .gate = &gate,
    });

    var wire = ScriptedWire{ .gate = &gate, .answers = &.{true} };
    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();
    http_client.wire = wire.wire();

    var ctx = ArrivalCtx{ .allocator = allocator, .wire = &wire };
    defer ctx.pieces_out.deinit(allocator);

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const result = try http_client.client().send(allocator, testRequest(&messages), recordArrival, &ctx);
    gate.openAll();
    fp.join();
    defer fp.deinit();
    try std.testing.expect(result == .ok);

    try std.testing.expectEqual(@as(usize, 2), ctx.pieces_out.items.len);
    try std.testing.expectEqual(@as(usize, 1), ctx.pieces_out.items[0]);
    try std.testing.expectEqual(@as(usize, 2), ctx.pieces_out.items[1]);
}

test "an empty key sends no Authorization header at all, not an empty one" {
    // `Authorization: Bearer ` with nothing after it is not the same thing. A real
    // provider answers 401, so the header has to be absent and not merely empty.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: [DONE]\n\n") },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "a local server needs no credential" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);
    defer switch (reply.outcome) {
        .message => |msg| freeAssembledMessage(allocator, msg),
        .status_error => |status_error| allocator.free(status_error.body),
        .failed => |failed| freeAssembledMessage(allocator, failed.partial),
    };

    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "authorization") == null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "Authorization") == null);

    try std.testing.expectEqualStrings("ok", reply.outcome.message.content[0].text);
}

const anthropic_head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
    "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n";

test "the Anthropic wire streams thinking, its signature, text, and a tool call into one message" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = anthropic_head,
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":" ++
                    "{\"id\":\"msg_1\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":1200,\"output_tokens\":1}}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0," ++
                    "\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\",\"signature\":\"\"}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"type\":\"content_block_delta\",\"index\":0," ++
                    "\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"weighing it\"}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"type\":\"content_block_delta\",\"index\":0," ++
                    "\"delta\":{\"type\":\"signature_delta\",\"signature\":\"EqoBCkYIARgCIkAy\"}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: {\"type\":\"ping\"}\n\n") },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"type\":\"content_block_delta\",\"index\":1," ++
                    "\"delta\":{\"type\":\"text_delta\",\"text\":\"I will read it.\"}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":" ++
                    "{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"read_file\",\"input\":{}}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"type\":\"content_block_delta\",\"index\":2," ++
                    "\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\":\"}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"type\":\"content_block_delta\",\"index\":2," ++
                    "\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"README.md\\\"}\"}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}," ++
                    "\"usage\":{\"output_tokens\":150}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: {\"type\":\"message_stop\"}\n\n") },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.initAnthropic(allocator, io, fp.baseUrl(&base_buf), "sk-ant-test");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "read the readme" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);

    switch (reply.outcome) {
        .status_error, .failed => return error.TestUnexpectedResult,
        .message => |msg| {
            defer freeAssembledMessage(allocator, msg);
            try std.testing.expectEqual(@as(usize, 3), msg.content.len);
            // A pipeline that dropped the signature passes every other assertion here.
            try std.testing.expectEqualStrings("weighing it", msg.content[0].reasoning.text);
            try std.testing.expectEqualStrings("EqoBCkYIARgCIkAy", msg.content[0].reasoning.signature);
            try std.testing.expectEqualStrings("I will read it.", msg.content[1].text);
            try std.testing.expectEqualStrings("toolu_1", msg.content[2].tool_use.call_id);
            try std.testing.expectEqualStrings("read_file", msg.content[2].tool_use.tool);
            try std.testing.expectEqualStrings(
                "{\"path\":\"README.md\"}",
                msg.content[2].tool_use.arguments,
            );
        },
    }

    // The counts are cumulative on this wire, so 1 then 150 is 150 and never 151.
    try std.testing.expectEqual(@as(u64, 1200), reply.usage.input_tokens);
    try std.testing.expectEqual(@as(u64, 150), reply.usage.output_tokens);
    try std.testing.expectEqual(message.Cost.unknown, std.meta.activeTag(reply.usage.cost));

    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "POST /messages") != null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "chat/completions") == null);
}

test "the Anthropic key travels in x-api-key, not Authorization, and appears in no log line" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key = "sk-ant-test-only-secret-9f3c";

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = anthropic_head,
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"type\":\"content_block_delta\",\"index\":0," ++
                    "\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: {\"type\":\"message_stop\"}\n\n") },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.initAnthropic(allocator, io, fp.baseUrl(&base_buf), key);
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "a secret must never ride along with a prompt" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);
    defer switch (reply.outcome) {
        .message => |msg| freeAssembledMessage(allocator, msg),
        .status_error => |status_error| allocator.free(status_error.body),
        .failed => |failed| freeAssembledMessage(allocator, failed.partial),
    };

    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "x-api-key: " ++ key) != null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "anthropic-version: 2023-06-01") != null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "Bearer") == null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.body, key) == null);
    // The body carries max_tokens, which this wire requires.
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.body, "\"max_tokens\"") != null);
}

test "an error event inside a 200 stream is reported as an error, with the 200 status" {
    // The status was 200 and stayed 200, so a status check reads a refusal as a reply.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = anthropic_head,
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"type\":\"content_block_delta\",\"index\":0," ++
                    "\"delta\":{\"type\":\"text_delta\",\"text\":\"starting\"}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "event: error\ndata: {\"type\":\"error\",\"error\":" ++
                    "{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n",
            ) },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.initAnthropic(allocator, io, fp.baseUrl(&base_buf), "sk-ant-test");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);

    switch (reply.outcome) {
        .message, .failed => return error.TestUnexpectedResult,
        .status_error => |status_error| {
            defer allocator.free(status_error.body);
            try std.testing.expectEqual(std.http.Status.ok, status_error.status);
            try std.testing.expect(std.mem.indexOf(u8, status_error.body, "overloaded_error") != null);
            try std.testing.expect(std.mem.indexOf(u8, status_error.body, "Overloaded") != null);
        },
    }
}

test "an Anthropic non 200 status is reported with what the body said, and never as a truncated stream" {
    // An error body on this wire is plain JSON and not server sent events, so a
    // reader that hands it to the SSE parser calls the whole reply truncated.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const refusal_body = "{\"type\":\"error\",\"error\":{\"type\":\"not_found_error\"," ++
        "\"message\":\"model: claude-sonnet-5\"}}";
    const head = std.fmt.comptimePrint(
        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n",
        .{refusal_body.len},
    );

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = head,
        .body = &.{.{ .bytes = refusal_body }},
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.initAnthropic(allocator, io, fp.baseUrl(&base_buf), "sk-ant-test");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);

    switch (reply.outcome) {
        .message, .failed => return error.TestUnexpectedResult,
        .status_error => |status_error| {
            defer allocator.free(status_error.body);
            try std.testing.expectEqual(std.http.Status.not_found, status_error.status);
            try std.testing.expectEqualStrings(refusal_body, status_error.body);
        },
    }
}

test "the request asks for the bytes as they are, because a compressed body is not an event stream" {
    // `std.http.Client` offers "gzip, deflate" by itself and `Response.reader` gives
    // back what arrived, so `sse.Parser` finds no `data:` line in a good reply.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = anthropic_head,
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"type\":\"content_block_delta\",\"index\":0," ++
                    "\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: {\"type\":\"message_stop\"}\n\n") },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.initAnthropic(allocator, io, fp.baseUrl(&base_buf), "sk-ant-test");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);
    defer switch (reply.outcome) {
        .message => |msg| freeAssembledMessage(allocator, msg),
        .status_error => |status_error| allocator.free(status_error.body),
        .failed => |failed| freeAssembledMessage(allocator, failed.partial),
    };

    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "accept-encoding: identity") != null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "gzip") == null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "deflate") == null);
    try std.testing.expectEqualStrings("ok", reply.outcome.message.content[0].text);
}

test "a provider that compresses anyway is named as that, and never as a truncated stream" {
    // The body below is never read: `Content-Encoding` in the head is what decides.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        .body = &.{
            .{ .bytes = fake_provider.httpChunk("\x1f\x8b\x08\x00 not really gzip, and never read") },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.initAnthropic(allocator, io, fp.baseUrl(&base_buf), "sk-ant-test");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);

    switch (reply.outcome) {
        .message, .status_error => return error.TestUnexpectedResult,
        .failed => |failed| {
            defer freeAssembledMessage(allocator, failed.partial);
            try std.testing.expect(failed.err == error.BodyCompressed);
        },
    }
}

test "an OpenAI compatible stream's final usage chunk reaches the caller instead of failing the parse" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = anthropic_head,
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1200,\"completion_tokens\":150," ++
                    "\"prompt_tokens_details\":{\"cached_tokens\":800}},\"X-Cost\":0.0042," ++
                    "\"X-Cost-Currency\":\"USD\",\"X-Inference-Ms\":734}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: [DONE]\n\n") },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);
    defer switch (reply.outcome) {
        .message => |msg| freeAssembledMessage(allocator, msg),
        .status_error => |status_error| allocator.free(status_error.body),
        .failed => |failed| freeAssembledMessage(allocator, failed.partial),
    };

    try std.testing.expect(reply.outcome == .message);
    try std.testing.expectEqualStrings("ok", reply.outcome.message.content[0].text);
    try std.testing.expectEqual(@as(u64, 1200), reply.usage.input_tokens);
    try std.testing.expectEqual(@as(u64, 150), reply.usage.output_tokens);
    try std.testing.expectEqual(@as(u64, 800), reply.usage.cache_read_input_tokens);
    try std.testing.expectEqual(@as(u64, 734), reply.usage.inference_ms);
    try std.testing.expectEqual(message.Cost.known, std.meta.activeTag(reply.usage.cost));
    try std.testing.expectEqual(@as(f64, 0.0042), reply.usage.cost.known.value);
    try std.testing.expectEqualStrings("USD", reply.usage.cost.known.currency);

    // The counts and the cost arrive only when these two go out, off by default.
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "X-Aiand-Metrics: true") != null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.body, "\"include_usage\":true") != null);
}

/// The trailer ai& appends after `[DONE]`. A named event and not a chunk.
const aiand_metrics_trailer = "event: metrics\n" ++
    "data: {\"tokens\":{\"input\":7,\"output\":2,\"total\":9,\"cached\":3}," ++
    "\"cost\":0.000018,\"currency\":\"usd\",\"ttft_ms\":120,\"inference_ms\":850}\n\n";

test "ai&'s metrics trailer is the token count and the cost of a turn, and it lands after DONE" {
    // ai& relays a model's SSE unchanged, and qwen and glm send no `usage` at all.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = anthropic_head,
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: [DONE]\n\n") },
            .{ .bytes = fake_provider.httpChunk(aiand_metrics_trailer) },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);
    defer switch (reply.outcome) {
        .message => |msg| freeAssembledMessage(allocator, msg),
        .status_error => |status_error| allocator.free(status_error.body),
        .failed => |failed| freeAssembledMessage(allocator, failed.partial),
    };

    try std.testing.expect(reply.outcome == .message);
    try std.testing.expectEqual(@as(usize, 1), reply.outcome.message.content.len);
    try std.testing.expectEqualStrings("ok", reply.outcome.message.content[0].text);

    try std.testing.expectEqual(@as(u64, 7), reply.usage.input_tokens);
    try std.testing.expectEqual(@as(u64, 2), reply.usage.output_tokens);
    try std.testing.expectEqual(@as(u64, 3), reply.usage.cache_read_input_tokens);
    try std.testing.expectEqual(@as(u64, 850), reply.usage.inference_ms);

    try std.testing.expectEqual(message.Cost.known, std.meta.activeTag(reply.usage.cost));
    try std.testing.expectEqual(@as(f64, 0.000018), reply.usage.cost.known.value);
    try std.testing.expectEqual(@as(usize, 0), reply.usage.price_table_version.len);
    // Uppercase, though ai& writes `usd`. Another spelling counts against no cap.
    try std.testing.expectEqualStrings("USD", reply.usage.cost.known.currency);
}

test "a connection that fails after the reply is whole delivers the reply, and never calls it truncated" {
    // No terminating zero length chunk: the connection dies mid chunk frame.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = anthropic_head,
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"the whole answer\"}," ++
                    "\"finish_reason\":\"stop\"}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: [DONE]\n\n") },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);
    defer switch (reply.outcome) {
        .message => |msg| freeAssembledMessage(allocator, msg),
        .status_error => |status_error| allocator.free(status_error.body),
        .failed => |failed| freeAssembledMessage(allocator, failed.partial),
    };

    try std.testing.expect(reply.outcome == .message);
    try std.testing.expectEqual(@as(usize, 1), reply.outcome.message.content.len);
    try std.testing.expectEqualStrings("the whole answer", reply.outcome.message.content[0].text);
    try std.testing.expectEqualStrings("stop", reply.stopReason());
}

test "a connection that fails before the end marker is still a truncated stream" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = anthropic_head,
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"half an ans\"}}]}\n\n",
            ) },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);

    switch (reply.outcome) {
        .message, .status_error => return error.TestUnexpectedResult,
        .failed => |failed| {
            defer freeAssembledMessage(allocator, failed.partial);
            try std.testing.expect(failed.err == error.StreamTruncated);
            try std.testing.expectEqual(@as(usize, 1), failed.partial.content.len);
            try std.testing.expectEqualStrings("half an ans", failed.partial.content[0].text);
        },
    }
}

test "a malformed metrics trailer costs the cost line and never the reply" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = anthropic_head,
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: [DONE]\n\n") },
            .{ .bytes = fake_provider.httpChunk(
                "event: metrics\ndata: {\"tokens\":{\"input\":7,\n\n",
            ) },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);
    defer switch (reply.outcome) {
        .message => |msg| freeAssembledMessage(allocator, msg),
        .status_error => |status_error| allocator.free(status_error.body),
        .failed => |failed| freeAssembledMessage(allocator, failed.partial),
    };

    try std.testing.expect(reply.outcome == .message);
    try std.testing.expectEqualStrings("ok", reply.outcome.message.content[0].text);
    try std.testing.expectEqual(message.Cost.unknown, std.meta.activeTag(reply.usage.cost));
}

test "a trailer that is still arriving when the connection dies costs nothing but the trailer" {
    // `[DONE]` arrived, then the connection died partway through the trailer.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = anthropic_head,
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"the whole answer\"}," ++
                    "\"finish_reason\":\"stop\"}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: [DONE]\n\n") },
            .{ .bytes = fake_provider.httpChunk("event: metrics\ndata: {\"tokens\":{\"input\":7") },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);
    defer switch (reply.outcome) {
        .message => |msg| freeAssembledMessage(allocator, msg),
        .status_error => |status_error| allocator.free(status_error.body),
        .failed => |failed| freeAssembledMessage(allocator, failed.partial),
    };

    try std.testing.expect(reply.outcome == .message);
    try std.testing.expectEqualStrings("the whole answer", reply.outcome.message.content[0].text);
    try std.testing.expectEqual(message.Cost.unknown, std.meta.activeTag(reply.usage.cost));
}

test "a stream with no trailer at all is read exactly as it was, which is what OpenAI proper sends" {
    // OpenAI proper appends nothing after `[DONE]`, so its usage chunk is the answer.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = anthropic_head,
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":4}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: [DONE]\n\n") },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);
    defer switch (reply.outcome) {
        .message => |msg| freeAssembledMessage(allocator, msg),
        .status_error => |status_error| allocator.free(status_error.body),
        .failed => |failed| freeAssembledMessage(allocator, failed.partial),
    };

    try std.testing.expect(reply.outcome == .message);
    try std.testing.expectEqualStrings("ok", reply.outcome.message.content[0].text);
    try std.testing.expectEqual(@as(u64, 11), reply.usage.input_tokens);
    try std.testing.expectEqual(@as(u64, 4), reply.usage.output_tokens);
    try std.testing.expectEqual(message.Cost.unknown, std.meta.activeTag(reply.usage.cost));
}

test "an OpenAI compatible reply with no content at all assembles to an empty message that names its stop reason" {
    // The provider counts input tokens and answers with no content of any kind.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}," ++
                    "\"finish_reason\":\"content_filter\"}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7367,\"completion_tokens\":0}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: [DONE]\n\n") },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.init(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();

    defer freeUsage(allocator, reply.usage);
    try std.testing.expectEqual(@as(u64, 7367), reply.usage.input_tokens);
    try std.testing.expectEqual(@as(u64, 0), reply.usage.output_tokens);
    try std.testing.expectEqualStrings("content_filter", reply.stopReason());
    switch (reply.outcome) {
        .status_error, .failed => return error.TestUnexpectedResult,
        .message => |msg| {
            defer freeAssembledMessage(allocator, msg);
            try std.testing.expectEqual(@as(usize, 0), msg.content.len);
        },
    }
}

test "an Anthropic reply with no content at all assembles to an empty message that names its stop reason" {
    // The Anthropic wire puts `stop_reason` on `message_delta`.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = anthropic_head,
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":" ++
                    "{\"id\":\"msg_1\",\"role\":\"assistant\"," ++
                    "\"usage\":{\"input_tokens\":7367,\"output_tokens\":0}}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "event: message_delta\ndata: {\"type\":\"message_delta\"," ++
                    "\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            ) },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.initAnthropic(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();

    defer freeUsage(allocator, reply.usage);
    try std.testing.expectEqualStrings("end_turn", reply.stopReason());
    try std.testing.expectEqualStrings("", reply.stop().category);
    try std.testing.expectEqualStrings("", reply.stop().explanation);
    switch (reply.outcome) {
        .status_error, .failed => return error.TestUnexpectedResult,
        .message => |msg| {
            defer freeAssembledMessage(allocator, msg);
            try std.testing.expectEqual(@as(usize, 0), msg.content.len);
        },
    }
}

test "a refused Anthropic reply carries the category and the explanation through the fold" {
    // The value gets out of the decoder, through the fold, and into the reply the
    // agent loop reads. Mechanisms here have shipped green with no caller.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = anthropic_head,
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":" ++
                    "{\"id\":\"msg_1\",\"role\":\"assistant\"," ++
                    "\"usage\":{\"input_tokens\":41,\"output_tokens\":0}}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "event: message_delta\ndata: {\"type\":\"message_delta\"," ++
                    "\"delta\":{\"stop_reason\":\"refusal\",\"stop_details\":" ++
                    "{\"type\":\"refusal\",\"category\":\"cyber\",\"explanation\":" ++
                    "\"This request was declined because it could enable cyber harm.\"}}," ++
                    "\"usage\":{\"output_tokens\":0}}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk(
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            ) },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = HttpClient.initAnthropic(allocator, io, fp.baseUrl(&base_buf), "test-key");
    defer http_client.deinit();

    const user_content = [_]message.ContentPart{.{ .text = "hi" }};
    const messages = [_]message.Message{.{ .role = .user, .content = &user_content }};

    const reply = try sendAndAssemble(http_client.client(), allocator, testRequest(&messages));
    fp.join();
    defer fp.deinit();

    defer freeUsage(allocator, reply.usage);
    const stopped = reply.stop();
    try std.testing.expectEqualStrings("refusal", stopped.reason);
    try std.testing.expectEqualStrings("cyber", stopped.category);
    try std.testing.expectEqualStrings(
        "This request was declined because it could enable cyber harm.",
        stopped.explanation,
    );
    switch (reply.outcome) {
        .status_error, .failed => return error.TestUnexpectedResult,
        .message => |msg| {
            defer freeAssembledMessage(allocator, msg);
            try std.testing.expectEqual(@as(usize, 0), msg.content.len);
        },
    }
}

test "every adapter carries a tool call, and every adapter carries an image result" {
    // `Adapter.carries` stops a tool being offered on a wire that cannot carry it.
    const Adapter = provider.Client.Adapter;

    inline for (@typeInfo(Adapter).@"enum".fields) |field| {
        const adapter: Adapter = @enumFromInt(field.value);
        try std.testing.expect(adapter.carries(.tool_calls));
        try std.testing.expect(adapter.carries(.image_results));
    }
}

test "carries is readable at comptime, which is what makes it a property of the adapter" {
    // The answer is known while the program is built, so a caller may fold it away.
    comptime {
        const Adapter = provider.Client.Adapter;
        if (!Adapter.openai_compatible.carries(.tool_calls)) unreachable;
        if (!Adapter.anthropic.carries(.image_results)) unreachable;
    }
}

test "the slices of a wait for the provider add up to the wait, and none of them is zero" {
    // A reply is cut off after `gap_ns` and never sooner, so the slices add up to it.
    const idleSlice = provider.Client.idleSlice;
    const slice: i32 = @intCast(provider.Client.idle_slice_ms);

    for ([_]i32{ 1, slice - 1, slice, slice + 1, 5 * 60 * 1000 }) |whole| {
        var left = whole;
        var taken: usize = 0;
        while (left > 0) {
            const one = idleSlice(left);
            try std.testing.expect(one > 0);
            try std.testing.expect(one <= slice);
            try std.testing.expect(one <= left);
            left -= one;
            taken += 1;
        }
        try std.testing.expectEqual(@as(i32, 0), left);
        try std.testing.expect(taken != 0);
    }

    try std.testing.expectEqual(@as(i32, 1), idleSlice(1));
    try std.testing.expectEqual(slice, idleSlice(slice + 1));
}
