//! Tests for `lib/chock-auth/check.zig`. Zig 0.16 refuses a relative
//! `@import` outside a module root, so these cannot live in `check.zig`.

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
    // `std.http.Client` offers "gzip, deflate" by itself, and the reader here
    // gives back what arrived, so a compressed catalogue holds no `data` array.
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
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "gzip") == null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "deflate") == null);

    try std.testing.expectEqual(std.meta.activeTag(outcome), chock_auth.check.Outcome.ok);
    try std.testing.expectEqual(@as(?usize, 2), outcome.ok.model_count);
}

test "the Anthropic check sends x-api-key and its version header, never Authorization" {
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
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "Bearer") == null);
    try std.testing.expect(std.mem.indexOf(u8, fp.captured.head, "GET /models") != null);
}

test "a refusal comes back with the provider's own words and stores nothing" {
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
