//! The one `Loop.run` test that needs a real HTTP round trip:
//! `test/core/fake_provider.zig`, a real socket server. Lives here, not in
//! `lib/chock-core/Loop.zig` itself, for the same reason `test/core/client.zig`
//! is its own test target: Zig 0.16 refuses a relative `@import` that
//! reaches outside a module's own root directory, so `Loop.zig` cannot
//! import `fake_provider.zig` directly. Every other fact about `Loop.run`
//! is proven inside `Loop.zig` itself, against `FakeClient` and
//! `FakeToolRunner`, two in memory test doubles that need no socket.

const std = @import("std");
const chock_provider = @import("chock-provider");
const chock_proto = @import("chock-proto");
const chock_core = @import("chock-core");
const fake_provider = @import("fake_provider.zig");

const Loop = chock_core.Loop;

/// A `Loop.ToolRunner` that answers every call the same way, without a
/// sandbox: this test only cares about the key, not about what a tool call
/// actually does.
const NoopToolRunner = struct {
    fn dispatch(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) Loop.DispatchError!chock_proto.event.ToolResult {
        _ = ptr;
        _ = io;
        return .{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try allocator.dupe(u8, "ok"),
            .is_error = false,
            .truncated = false,
        };
    }

    fn runner(self: *NoopToolRunner) Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Loop.ToolRunner.VTable{ .dispatch = dispatch };
};

test "the API key is in no event in the log, driven through a real HttpClient" {
    // Extends test/core/client.zig's own "the key travels in a header and
    // appears in no log line" from the HTTP request body to the session
    // log Loop.run builds from the reply. The model context never holds a
    // credential, because chockd re-serves the session log to other
    // clients, and a key in the log is a key given away.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key = "sk-loop-test-only-secret-4b2e";

    var fp = try fake_provider.FakeProvider.start(allocator, io, .{
        .head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        .body = &.{
            .{ .bytes = fake_provider.httpChunk(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"no tools needed\"},\"finish_reason\":\"stop\"}]}\n\n",
            ) },
            .{ .bytes = fake_provider.httpChunk("data: [DONE]\n\n") },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var base_buf: [64]u8 = undefined;
    var http_client = chock_provider.Client.HttpClient.init(allocator, io, fp.baseUrl(&base_buf), key);
    defer http_client.deinit();

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOPKEY");
    const store = backing.storage();
    defer store.close(io);

    var noop_tools = NoopToolRunner{};

    try Loop.run(allocator, io, .{
        .client = http_client.client(),
        .storage = store,
        .tool_runner = noop_tools.runner(),
        .tool_definitions = &.{},
        .model = "glm4.7-flash:A3B",
        .model_alias = "main",
        .agent_kind = "coder",
        .system_prompt = "you are a careful coding agent",
    });
    fp.join();
    defer fp.deinit();

    // The fake server actually saw the key, in the header, over the wire.
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "authorization: Bearer " ++ key) != null);

    // Every event now on the log, byte for byte, holds no trace of it: the
    // whole point of this test.
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var events_seen: usize = 0;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        events_seen += 1;
        const text = try chock_proto.event.toJson(allocator, parsed.value);
        defer allocator.free(text);
        try std.testing.expect(std.mem.indexOf(u8, text, key) == null);
    }
    try std.testing.expect(events_seen > 0);
}
