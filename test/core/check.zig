//! Tests for `lib/chock-auth/check.zig`, the one call `chock login` makes
//! before it stores anything. Lives here, not inside `check.zig` itself,
//! because these tests need `fake_provider.zig`, a real socket server, and
//! Zig 0.16 refuses a relative `@import` that reaches outside a module's own
//! root directory: `lib/chock-auth/check.zig` cannot import a file under
//! `test/`. `test/core/client.zig` sits at the same boundary for the same
//! reason and is built the same way, and this file is in the same directory
//! as `fake_provider.zig` so it can reach it by an in-bounds relative path.

const std = @import("std");
const chock_auth = @import("chock-auth");
const fake_provider = @import("fake_provider.zig");

const catalogue_body = "{\"object\":\"list\",\"data\":[{\"id\":\"claude-sonnet-5\"},{\"id\":\"claude-opus-5\"}]}";

fn catalogueHead(comptime body: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n",
        .{body.len},
    );
}

test "the check asks for the bytes as they are, so a compressed catalogue cannot be counted as none" {
    // The same fault `lib/chock-provider/Client.zig` was measured making
    // against the live Anthropic endpoint, on the other command:
    // `std.http.Client` offers "gzip, deflate" by itself, and the reader this
    // file uses gives back what arrived rather than unpacking it. A compressed
    // catalogue then holds no `data` array this reader can find, so `chock
    // login` reports a provider it could not count, and a compressed refusal
    // is printed to a terminal as bytes that are not text.
    //
    // The header is read off the raw request head the server saw, so this
    // pins what goes on the wire and not an intention in a struct.
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var fp = try fake_provider.FakeProvider.start(gpa, io, .{
        .head = catalogueHead(catalogue_body),
        .body = &.{.{ .bytes = catalogue_body }},
    });

    var base_buf: [64]u8 = undefined;
    var outcome = try chock_auth.check.credential(
        gpa,
        io,
        .anthropic,
        fp.baseUrl(&base_buf),
        "sk-ant-test",
    );
    fp.join();
    defer fp.deinit();
    defer outcome.deinit(gpa);

    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "accept-encoding: identity") != null);
    // Not "identity was named among others": neither coding the client would
    // have offered on its own is in the head at all.
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "gzip") == null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "deflate") == null);

    // And the answer was read as a catalogue, so this is a request the server
    // answered and not one that never went out.
    try std.testing.expectEqual(std.meta.activeTag(outcome), chock_auth.check.Outcome.ok);
    try std.testing.expectEqual(@as(?usize, 2), outcome.ok.model_count);
}

test "the Anthropic check sends x-api-key and its version header, never Authorization" {
    // `chock login` and `chock run` have to agree about which header carries
    // the key, or a credential that logs in cannot run. This file builds its
    // own request rather than going through `chock-provider`, because a model
    // catalogue is not a chat completion, so the agreement is a thing to pin
    // and not a thing to assume.
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const key = "sk-ant-test-only-secret-9f3c";

    var fp = try fake_provider.FakeProvider.start(gpa, io, .{
        .head = catalogueHead(catalogue_body),
        .body = &.{.{ .bytes = catalogue_body }},
    });

    var base_buf: [64]u8 = undefined;
    var outcome = try chock_auth.check.credential(gpa, io, .anthropic, fp.baseUrl(&base_buf), key);
    fp.join();
    defer fp.deinit();
    defer outcome.deinit(gpa);

    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "x-api-key: " ++ key) != null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "anthropic-version: 2023-06-01") != null);
    // The OpenAI compatible header, which a provider on this wire ignores,
    // leaving an unauthenticated request that looks like a wrong key.
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "Bearer") == null);
    // The catalogue lives beside the base URL the instance names.
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "GET /models") != null);
}

test "a refusal comes back with the provider's own words and stores nothing" {
    // A user who mistypes a key learns at login. The words the
    // provider spent explaining the refusal are what make that useful, so
    // they come back whole.
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    const refusal = "{\"type\":\"error\",\"error\":{\"type\":\"authentication_error\"," ++
        "\"message\":\"invalid x-api-key\"}}";
    const head = std.fmt.comptimePrint(
        "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n",
        .{refusal.len},
    );

    var fp = try fake_provider.FakeProvider.start(gpa, io, .{
        .head = head,
        .body = &.{.{ .bytes = refusal }},
    });

    var base_buf: [64]u8 = undefined;
    var outcome = try chock_auth.check.credential(gpa, io, .anthropic, fp.baseUrl(&base_buf), "sk-ant-wrong");
    fp.join();
    defer fp.deinit();
    defer outcome.deinit(gpa);

    try std.testing.expectEqual(std.meta.activeTag(outcome), chock_auth.check.Outcome.rejected);
    try std.testing.expectEqual(std.http.Status.unauthorized, outcome.rejected.status);
    try std.testing.expectEqualStrings(refusal, outcome.rejected.body);
}
