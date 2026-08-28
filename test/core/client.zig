//! Tests for `lib/chock-provider/Client.zig`. Lives here, not inside
//! `Client.zig` itself, because these tests need `fake_provider.zig`, a real
//! socket server, and Zig 0.16 refuses a relative `@import` that reaches
//! outside a module's own root directory: `lib/chock-provider/Client.zig`
//! cannot import a file under `test/`. `test/proto/lock.zig` hits the same
//! boundary for its own reasons and is built the same way: a standalone test
//! binary, wired up in `build.zig`, that imports the library module by name
//! instead of being part of it.

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

/// A `provider.Client.Wire` that answers from a script the test wrote, and lets
/// one more piece of the reply out for every answer that says the provider is
/// still sending.
///
/// **This is what takes the clock out of the tests of the gap bound.** Each
/// piece goes out **because** the client asked whether more was coming, so the
/// test pins the order the two acts happen in, which is the fact. The old shape
/// scripted real pauses against a real bound and pinned that one number was
/// smaller than another, which is the machine and the load on it: it failed
/// once on a loaded Darwin box and passed on a rerun of the same tree. Three
/// earlier wall clock tests in this project were replaced the same way.
///
/// Every other part of the machinery is real: a real socket, a real buffer read
/// by `Gap.eventInHand`, a real shutdown by `Gap.stopReading`, and real bytes
/// through the real parser.
const ScriptedWire = struct {
    gate: *fake_provider.Gate,
    /// One answer per question, in order. The last answer stands for every
    /// question after it, so a script says only where it changes.
    answers: []const bool,
    /// How many times the client asked. **A client that never asked would get
    /// no piece of the reply at all**, because a piece goes out only on an
    /// answer, so this count and the text that arrived pin the same fact from
    /// two sides.
    asked: usize = 0,

    fn wire(self: *ScriptedWire) provider.Client.Wire {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = provider.Client.Wire.VTable{ .moreIsComing = moreIsComingFn };

    fn moreIsComingFn(ptr: *anyopaque, gap_ns: u64) bool {
        // The bound is not read here, and that is the point of this whole
        // type: nothing in either of these tests measures a length of time.
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

    // Split across pieces on purpose, one event even split mid JSON, each
    // written on its own with a short pause first: the exact shapes, slowly
    // and in small pieces, that break a client which assumes one network read
    // is one whole event.
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
    // A truncated reply that reads as a complete one is how a harness
    // silently loses half of what the model said. This script is the
    // sharpest shape of that trap: the chunked encoding ends cleanly, with
    // its own terminating zero length chunk, so the transport layer sees
    // nothing wrong at all. Only tracking whether a `[DONE]` event ever
    // arrived, which sse.Parser.finish's own doc comment says is the
    // caller's job, catches this.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"}}]}\n\n",
            ) },
            // The body ends here: a clean chunked terminator, but no
            // finish_reason chunk and no [DONE] ever arrives.
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

    // The truncation is still a failure, never a quietly short "Hello": see
    // AssembledReply.failed's own doc comment. What already streamed in,
    // "Hello", is not thrown away with the error: it comes back in
    // `.failed.partial`, so a caller can decide whether a shortened reply is
    // worth keeping instead of losing it outright.
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
    // Before this bound there was none of any kind: a provider that went
    // quiet held the session open for as long as anybody left it running,
    // with nothing at all to tell that apart from a model still generating.
    // The connection here is never closed and never fails: the server simply
    // says nothing after the first piece, which is exactly the shape a real
    // stall takes.
    //
    // **The silence is scripted and never timed.** The wire answers "still
    // sending" for the first question and "nothing at all" for the second, so
    // the second piece is never let out. See `ScriptedWire`.
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
            // The rest of the reply is written, and never let out while the
            // client is reading, so a client that waited for it would look
            // like it was working.
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
    // Before the join, because the server is holding the pieces this client
    // will never ask for and nothing else will let them out.
    gate.openAll();
    fp.join();
    defer fp.deinit();
    defer freeUsage(allocator, reply.usage);

    // Asked twice and no more: the check stops asking once it has stopped
    // reading, so a third question would mean the silence was not acted on.
    try std.testing.expectEqual(@as(usize, 2), wire.asked);

    switch (reply.outcome) {
        .message, .status_error => return error.TestUnexpectedResult,
        .failed => |failed| {
            defer freeAssembledMessage(allocator, failed.partial);
            // Stalled, and not truncated. The two are different facts: a
            // truncated stream ended, and this one never did.
            try std.testing.expect(failed.err == error.StreamStalled);
            try std.testing.expect(failed.err != error.StreamTruncated);
            // And what did arrive before the silence is not thrown away with
            // the error, the same as any other failed stream.
            try std.testing.expectEqual(@as(usize, 1), failed.partial.content.len);
            try std.testing.expectEqualStrings("Hello", failed.partial.content[0].text);
        },
    }
}

test "a reply that is merely slow is left alone, because the bound is on the gap and not on the call" {
    // **The case that must not be killed**, and the reason the bound has the
    // shape it has. A real session spent nineteen minutes on one turn with the
    // model generating the whole time, and any bound on the whole call short
    // enough to catch a stall would have destroyed it.
    //
    // **The fact is that the check saw activity at every gap, never that a
    // pause was short.** The wire answers "still sending" to every question,
    // and every answer lets exactly one more piece out, so each piece of this
    // reply arrives **because** the client asked and got a live answer. The
    // whole reply then completes with the check having run at each gap in it.
    //
    // The shape before this scripted 120 millisecond pauses against a 400
    // millisecond bound and pinned that one number was smaller than the other.
    // That measures the machine: it failed once on a loaded Darwin box and
    // passed on a rerun of the same tree. Widening the margin only moves the
    // day it fails. See `ScriptedWire`.
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
            // The end marker and the last chunk go out together, as the one
            // piece the fourth question lets out. Split in two they would need
            // a fifth question that the loop never asks, because it stops
            // asking the moment it has seen the end.
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

    // One question per piece, and the whole reply arrived, so the check ran at
    // every gap in this stream and cut none of them. Neither half alone says
    // that: a reply that arrived with no question asked would mean the check
    // never ran, and questions with no reply would mean it cut the stream.
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
    // A provider explains a refusal in the body. Throwing it away wastes
    // the user's time.
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
    // **The header that turns the most recoverable error there is into a wait
    // of exactly the right length.** ai& sends this on a 429. It has to be
    // read off the response head before the body is read, because reading the
    // body invalidates every pointer the head holds, so this drives a real
    // socket rather than a fake client: only a real `receiveHead` can get that
    // order wrong.
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
            // The number, not merely that something was read: a wait built
            // from the wrong number is a wait that hammers or a wait that
            // hangs.
            try std.testing.expectEqual(@as(?u64, 42), status_error.retry_after_s);
            // And the body still arrives whole, so nothing about reading the
            // header first cost the words the provider spent explaining
            // itself.
            try std.testing.expectEqualStrings(refusal_body, status_error.body);
        },
    }

    // A refusal with no such header reads as null, never as a zero: a zero
    // would be a wait of no time at all, which is the hammering the retry
    // exists to prevent.
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
    // The body is what gets written to the session log, and chockd serves
    // that log to other clients, and the model context never holds a
    // credential. This proves both directions: the fake server
    // actually saw the key, in the Authorization header, and the request
    // body it captured, the same bytes a log entry would hold, never
    // contains it.
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
    // An earlier version of this test was named "the fake and the HTTP
    // client are interchangeable for a caller" and its own comment claimed
    // that agreement on one crafted
    // scenario proved opacity, that "nothing above this interface could have
    // told them apart." That does not follow: a reviewer mutating code in
    // the shared fold, `sendAndAssemble` and `Collector`, left this test
    // green, and no opacity leak, a new public declaration either
    // implementation added, or a distinguishing error only one of them could
    // raise, could ever fail it, because neither side of the comparison
    // below looks at anything but the one text field both replies happen to
    // share. This test is renamed to say what it actually checks: two
    // different `Client` implementations, driven through the one function
    // written only against the interface, agree on the message they produce
    // for the same input. That is real and worth pinning, since a caller
    // like `sendAndAssemble` is written once, against the interface, and
    // used against whichever implementation it is handed. It is not a proof
    // that a caller can never tell the two apart by some other means.
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

    // The same two deltas, this time carried over a real socket by the
    // fake HTTP server instead of produced in process.
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

/// Records how long after `start` each text `Delta` reached `on_delta`. See
/// `"a delta sent early arrives before a later one is sent"` below.
/// Records how far the reply had got when each text delta was handed on, in
/// pieces let out of the gate rather than in milliseconds.
///
/// **A count and not a clock.** "The first delta arrived while only the first
/// piece had gone out" is the fact, and a duration is only a way of guessing at
/// it that a loaded machine gets wrong.
const ArrivalCtx = struct {
    allocator: std.mem.Allocator,
    wire: *const ScriptedWire,
    /// One entry per text delta: how many pieces of the reply had been let out
    /// when it reached this callback.
    pieces_out: std.ArrayList(usize) = .empty,
};

fn recordArrival(ctx: ?*anyopaque, delta: Delta) OnDeltaError!void {
    const self: *ArrivalCtx = @ptrCast(@alignCast(ctx.?));
    if (delta != .text) return;
    try self.pieces_out.append(self.allocator, self.wire.asked);
}

test "a delta sent early arrives before a later one is sent" {
    // The measured trap this pins: a fixed size read buffer that only
    // reports data once it fills
    // makes every delta arrive together at the end, however far apart the
    // provider actually sent them. Measured against the pre-fix client, three
    // events sent at t=0, t=300ms and t=600ms all reached the callback
    // together at t+906ms, because two short text deltas never come close to
    // filling a 4 KiB buffer.
    //
    // **The fault is an order and never a duration.** A streaming client hands
    // the first delta on while only the first piece has been sent; a buffering
    // one hands both on after the whole reply has been sent. So the gate holds
    // each piece back until the client asks for it, and each arrival records
    // how many pieces had gone out by then. The shape before this compared
    // arrival times against 150 and 300 millisecond margins, which measures the
    // machine: see `ScriptedWire`.
    //
    // **It guards a second thing now, and it caught it.** The gap bound of
    // `provider.Client.default_gap_ns` waits on the socket between one piece
    // and the next, and a first version of that waited even when a whole
    // event was already in hand. Reading the response head takes the first
    // pieces of the body with it, so that held the first delta back until the
    // provider sent the second, which is exactly a first arrival at two pieces
    // out instead of one. See `Gap.eventInHand`.
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
    // The first delta was handed on with one piece sent and the second with
    // two, so each reached the caller off the read that produced it. The
    // buffering client this pins would have both at three, the whole reply,
    // because nothing left its buffer until the connection closed.
    try std.testing.expectEqual(@as(usize, 1), ctx.pieces_out.items[0]);
    try std.testing.expectEqual(@as(usize, 2), ctx.pieces_out.items[1]);
}

test "an empty key sends no Authorization header at all, not an empty one" {
    // An instance that names no credential and has none stored sends none,
    // which is what a local llama.cpp server needs, and there is no
    // placeholder string pretending to be a secret.
    //
    // `Authorization: Bearer ` with nothing after it is not the same thing.
    // A real provider reads that as a credential it cannot parse and answers
    // 401, so the header has to be absent and not merely empty. This reads
    // the raw request head the server saw and proves the word is not in it
    // at all.
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

    // Not "no Bearer" and not "no empty value": the header name itself is
    // absent from the head the server read.
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "authorization") == null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "Authorization") == null);

    // And the reply still arrived, so this is a request the server answered
    // rather than one that never went out.
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
            // The reasoning first, because that is the order the model sent
            // it in, and with the signature it arrived with. A pipeline that
            // dropped the signature would still pass every other assertion
            // here, which is why this one is separate.
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

    // The counts are cumulative on this wire, so 1 then 150 is 150 and never
    // 151. See anthropic.Decoder's own usage note.
    try std.testing.expectEqual(@as(u64, 1200), reply.usage.input_tokens);
    try std.testing.expectEqual(@as(u64, 150), reply.usage.output_tokens);
    // No cost came off the wire, and unknown is not zero.
    try std.testing.expectEqual(message.Cost.unknown, std.meta.activeTag(reply.usage.cost));

    // The path is the adapter's business: this wire lives at /messages, not
    // at the OpenAI compatible /chat/completions.
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "POST /messages") != null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "chat/completions") == null);
}

test "the Anthropic key travels in x-api-key, not Authorization, and appears in no log line" {
    // The same fact the OpenAI suite pins, on the other wire: the body is
    // what a session log holds and chockd re-serves, so the key must be in a
    // header and only in a header. The header is a different one here, which
    // is exactly why the test is repeated rather than assumed.
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
    // Not the OpenAI compatible header, which a provider on this wire would
    // ignore, leaving an unauthenticated request that looks like a bug
    // somewhere else.
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "Bearer") == null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.body, key) == null);
    // The body carries max_tokens, which this wire requires and the OpenAI
    // compatible one leaves out.
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.body, "\"max_tokens\"") != null);
}

test "an error event inside a 200 stream is reported as an error, with the 200 status" {
    // The trap this adapter's top comment names: the HTTP status was 200 and
    // stayed 200, and a reader that only checks the status reports a short,
    // successful answer for a request the provider refused.
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
            // The provider's own words, not a re-worded summary.
            try std.testing.expect(std.mem.indexOf(u8, status_error.body, "overloaded_error") != null);
            try std.testing.expect(std.mem.indexOf(u8, status_error.body, "Overloaded") != null);
        },
    }
}

test "an Anthropic non 200 status is reported with what the body said, and never as a truncated stream" {
    // The same fact the OpenAI suite pins, on the other wire, and the reason
    // it is repeated: an error body on this wire is plain JSON, not server
    // sent events, so a reader that hands the body to the SSE parser whatever
    // the status was gets no events at all and calls the reply truncated.
    // `StreamTruncated` says the connection broke, which is a different fault
    // in a different place, so the real reason, here an unknown model name,
    // never reaches the user and every diagnosis starts in the wrong file.
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
        // `.failed` is the shape this test exists to refuse: a refusal read as
        // a broken connection.
        .message, .failed => return error.TestUnexpectedResult,
        .status_error => |status_error| {
            defer allocator.free(status_error.body);
            try std.testing.expectEqual(std.http.Status.not_found, status_error.status);
            // The provider's own words, whole. A user who reads "model:
            // claude-sonnet-5" fixes the request in one step.
            try std.testing.expectEqualStrings(refusal_body, status_error.body);
        },
    }
}

test "the request asks for the bytes as they are, because a compressed body is not an event stream" {
    // Measured against the live Anthropic API. `std.http.Client` offers
    // "gzip, deflate" by itself, that endpoint takes the offer, and
    // `Response.reader` gives back what arrived rather than unpacking it, so
    // `sse.Parser` was fed gzip and found no `data:` line in a whole good
    // reply. Every live session ended in about two seconds with
    // `StreamTruncated`, naming a broken connection for a body that arrived
    // complete.
    //
    // The header is read off the raw request head the server saw, so this
    // pins what actually goes on the wire and not an intention in a struct.
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
    // Not "identity was named among others": neither coding the client would
    // have offered on its own is in the head at all.
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "gzip") == null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "deflate") == null);
    // And the reply still arrived, so this is a request the server answered.
    try std.testing.expectEqualStrings("ok", reply.outcome.message.content[0].text);
}

test "a provider that compresses anyway is named as that, and never as a truncated stream" {
    // The other half of the fix above. A provider is a peer Chock does not
    // control: it may compress whatever the request asked for. What must not
    // happen is the old answer, `StreamTruncated`, which sends the reader
    // looking for a broken connection when the body arrived whole and only
    // its coding was unreadable.
    //
    // The body below is never read: `Content-Encoding` in the head is what
    // decides, so the bytes after it may be anything.
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
    // The chunk that carries the counts carries no choice at all. A reader
    // that demands a choice first throws the number away and calls the event
    // malformed, which is how a session ends up with nothing to write for
    // its usage event.
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
    // The provider said what it cost, so this is `known` and not computed
    // from a price table: the provider's number is taken as truth.
    try std.testing.expectEqual(message.Cost.known, std.meta.activeTag(reply.usage.cost));
    try std.testing.expectEqual(@as(f64, 0.0042), reply.usage.cost.known.value);
    try std.testing.expectEqualStrings("USD", reply.usage.cost.known.currency);

    // And the request asked for all of it: the counts and the cost arrive
    // only when these two go out, and both are off by default.
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "X-Aiand-Metrics: true") != null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.body, "\"include_usage\":true") != null);
}

/// The trailer ai& appends after `[DONE]` when the request asks for it, in
/// the shape its own documentation gives. **A named event, not a chunk**: the
/// name is what tells it apart from a chat completion, and reading it as one
/// is what ai& tells readers not to do.
const aiand_metrics_trailer = "event: metrics\n" ++
    "data: {\"tokens\":{\"input\":7,\"output\":2,\"total\":9,\"cached\":3}," ++
    "\"cost\":0.000018,\"currency\":\"usd\",\"ttft_ms\":120,\"inference_ms\":850}\n\n";

test "ai&'s metrics trailer is the token count and the cost of a turn, and it lands after DONE" {
    // Measured, not guessed: across three real sessions against ai& every one
    // of 94 usage events held nothing but zeros, because ai& relays a model's
    // SSE events unchanged and qwen and glm send no `usage` object at all.
    // This trailer is the only place the numbers exist on that provider.
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

    // The trailer is read for what it is and never folded into the reply: a
    // reader that took it for a chunk would either fail the whole stream or
    // append its JSON to what the model said.
    try std.testing.expect(reply.outcome == .message);
    try std.testing.expectEqual(@as(usize, 1), reply.outcome.message.content.len);
    try std.testing.expectEqualStrings("ok", reply.outcome.message.content[0].text);

    try std.testing.expectEqual(@as(u64, 7), reply.usage.input_tokens);
    try std.testing.expectEqual(@as(u64, 2), reply.usage.output_tokens);
    // Apart from the fresh input, never folded into it: a cached prompt token
    // is billed at a fraction of a fresh one.
    try std.testing.expectEqual(@as(u64, 3), reply.usage.cache_read_input_tokens);
    try std.testing.expectEqual(@as(u64, 850), reply.usage.inference_ms);

    // The provider's own final figure, so `known` and not an estimate, and
    // `price_table_version` stays empty because no table produced it.
    try std.testing.expectEqual(message.Cost.known, std.meta.activeTag(reply.usage.cost));
    try std.testing.expectEqual(@as(f64, 0.000018), reply.usage.cost.known.value);
    try std.testing.expectEqual(@as(usize, 0), reply.usage.price_table_version.len);
    // Uppercase, though ai& wrote `usd`: a budget's currency is `USD`, and a
    // spend in another spelling counts against no cap at all.
    try std.testing.expectEqualStrings("USD", reply.usage.cost.known.currency);
}

test "a connection that fails after the reply is whole delivers the reply, and never calls it truncated" {
    // What killed 73 turns of real work. Chock asks ai& for the metrics
    // trailer, so it keeps reading after `[DONE]`, and the provider dropped
    // the connection in that window. The reply had arrived in full, the end
    // marker was in hand, and the whole turn was thrown away as truncated.
    //
    // The script writes no terminating zero length chunk: the connection dies
    // mid chunk frame, which is a transport fault and not a clean end of body.
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
    // The half of the pair that must not move. The script above and this one
    // differ in one thing, whether `[DONE]` arrived before the connection
    // died, and that one thing is the whole of what tells a finished turn
    // apart from a lost one. A reply cut off mid sentence is still an error,
    // and the text that did arrive still comes back in `failed.partial`.
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
    // A trailer arrives after the model's answer is already whole, so nothing
    // it says can make the answer worse. Failing the stream over unreadable
    // metadata would throw away a finished turn for the sake of a number
    // nobody can spend.
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
    // Unknown, and never a zero: nothing readable said what this turn cost.
    // See `message.Cost`, where those are different states.
    try std.testing.expectEqual(message.Cost.unknown, std.meta.activeTag(reply.usage.cost));
}

test "a trailer that is still arriving when the connection dies costs nothing but the trailer" {
    // The sharpest shape of the same trap, and the reason the end marker is
    // the whole of the test. `[DONE]` has arrived, the reply is whole, and
    // the connection then dies partway through the metrics trailer, leaving a
    // half read event in the parser. Demanding a clean parser as well as the
    // end marker would call this turn truncated and lose it, over a cost line
    // that arrived late and incomplete.
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
            // No terminating blank line, and no zero length chunk after it:
            // the trailer is cut off mid event and the connection drops.
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
    // The half trailer said nothing this reader can spend, so the cost stays
    // unknown. The turn is kept; only its price is missing.
    try std.testing.expectEqual(message.Cost.unknown, std.meta.activeTag(reply.usage.cost));
}

test "a stream with no trailer at all is read exactly as it was, which is what OpenAI proper sends" {
    // The trailer is one provider's extension, bought with one request
    // header. OpenAI proper names no event and appends nothing after
    // `[DONE]`, so its usage chunk must still be the whole answer, and a
    // reader that started demanding a trailer would report nothing at all
    // for every other provider on this wire.
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
    // The chunk said counts and no cost, so the cost stays unknown rather
    // than becoming a zero somebody could spend against a cap.
    try std.testing.expectEqual(message.Cost.unknown, std.meta.activeTag(reply.usage.cost));
}

test "an OpenAI compatible reply with no content at all assembles to an empty message that names its stop reason" {
    // The cheap deterministic shape of the fault the red team run of
    // 2026-08-26 hit: the provider is reached, it counts input tokens, and it
    // answers with no content of any kind. The stop reason is the only thing
    // that says why, and this reader used to drop it. See
    // `chock_provider.Client.Delta.stop_reason`.
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
    // The counts of the measured session: real input, no output at all.
    try std.testing.expectEqual(@as(u64, 7367), reply.usage.input_tokens);
    try std.testing.expectEqual(@as(u64, 0), reply.usage.output_tokens);
    // **The provider said why, so Chock holds the word.**
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
    // The same shape on the wire the measured session actually used. The
    // Anthropic wire puts `stop_reason` on `message_delta`, and
    // `anthropic.Decoder` has always read it: nothing outside its own tests
    // ever asked for it.
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
    // Not a refusal, so the wire sent no `stop_details` and the fold holds
    // none. See `chock_provider.Client.Stop`.
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
    // `anthropic.Decoder` reads `stop_details`, and its own tests prove that.
    // This one proves the value gets out of the decoder, through `streamBody`,
    // through the fold, and into the reply the agent loop reads: three
    // mechanisms in this project have shipped with green tests and no caller,
    // and no unit test can catch that.
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

test "every adapter carries a tool call, and no adapter carries an image result yet" {
    // `Adapter.carries` is what stops a tool being offered on a wire that
    // cannot express it at all. A tool the
    // model cannot use costs one turn calling it and one turn reading the
    // failure, which is worse than the tool simply not being there.
    const Adapter = provider.Client.Adapter;

    inline for (@typeInfo(Adapter).@"enum".fields) |field| {
        const adapter: Adapter = @enumFromInt(field.value);
        // An agent with no tool call has nothing to do at all, so this must
        // hold for every wire Chock speaks.
        try std.testing.expect(adapter.carries(.tool_calls));
        // `message.ContentPart` has no image part, so neither adapter has
        // anything to encode. This flips to true for one adapter at a time,
        // once that part exists and that adapter learns to write it.
        try std.testing.expect(!adapter.carries(.image_results));
    }
}

test "carries is readable at comptime, which is what makes it a property of the adapter" {
    // Not a runtime question about a host: the wire format either has a
    // shape for the thing or it does not, and that is known while the
    // program is being built. A caller may therefore fold the answer away
    // entirely.
    comptime {
        const Adapter = provider.Client.Adapter;
        if (!Adapter.openai_compatible.carries(.tool_calls)) unreachable;
        if (Adapter.anthropic.carries(.image_results)) unreachable;
    }
}

test "the slices of a wait for the provider add up to the wait, and none of them is zero" {
    // **The gap bound is not what changed when a caller was given something to
    // do while it waits.** A reply is still cut off after `gap_ns` of silence
    // and never sooner, so the slices have to add up to exactly that. A slice
    // of zero would turn the wait into a busy loop; a slice longer than the
    // bound would give a silent provider extra time.
    //
    // Mutation check: change `@min` to `@max` in `idleSlice` and the first
    // loop overruns; drop the `@min` and the last expectation fails.
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

    // A wait shorter than one slice is one slice, and it is the wait itself.
    try std.testing.expectEqual(@as(i32, 1), idleSlice(1));
    try std.testing.expectEqual(slice, idleSlice(slice + 1));
}
