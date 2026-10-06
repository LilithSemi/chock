//! The check before storing. A provider with a model catalogue, such as ai&'s

const std = @import("std");
const config = @import("config.zig");

pub const max_body_bytes: usize = 1024 * 1024;

const identity_encoding = "identity";

pub const Outcome = union(enum) {
    ok: Ok,
    rejected: Rejected,
    not_reached: []const u8,

    pub fn deinit(self: *Outcome, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .rejected => |rejected| gpa.free(rejected.body),
            .ok, .not_reached => {},
        }
        self.* = undefined;
    }
};

pub const Ok = struct {
    model_count: ?usize,
};

pub const Rejected = struct {
    status: std.http.Status,
    body: []u8,
};

pub const Error = std.mem.Allocator.Error;

pub fn credential(
    gpa: std.mem.Allocator,
    io: std.Io,
    kind: config.Kind,
    base_url: []const u8,
    token: []const u8,
) Error!Outcome {
    const url = try std.fmt.allocPrint(gpa, "{s}/models", .{base_url});
    defer gpa.free(url);
    const uri = std.Uri.parse(url) catch |err| return .{ .not_reached = @errorName(err) };

    var http: std.http.Client = .{ .allocator = gpa, .io = io };
    defer http.deinit();

    // Built once and wiped before it is freed: a credential sitting freed but unzeroed in the heap is still readable in a crash dump or a swapped page.
    const header_value = try switch (kind) {
        .anthropic => gpa.dupe(u8, token),
        .aiand, .openai_compat => std.fmt.allocPrint(gpa, "Bearer {s}", .{token}),
    };
    defer {
        std.crypto.secureZero(u8, header_value);
        gpa.free(header_value);
    }

    var extra: [2]std.http.Header = undefined;
    var extra_count: usize = 0;
    var authorization: std.http.Client.Request.Headers.Value = .omit;
    switch (kind) {
        .anthropic => {
            extra[0] = .{ .name = "anthropic-version", .value = "2023-06-01" };
            extra_count = 1;
            if (token.len != 0) {
                extra[1] = .{ .name = "x-api-key", .value = header_value };
                extra_count = 2;
            }
        },
        .aiand, .openai_compat => {
            if (token.len != 0) authorization = .{ .override = header_value };
        },
    }

    var request = http.request(.GET, uri, .{
        .keep_alive = false,
        // A provider that answers a catalogue with a redirect is not followed: a redirect would carry the credential wherever it points.
        .redirect_behavior = .not_allowed,
        .headers = .{
            .authorization = authorization,
            .accept_encoding = .{ .override = identity_encoding },
        },
        .extra_headers = extra[0..extra_count],
    }) catch |err| return .{ .not_reached = @errorName(err) };
    defer request.deinit();

    request.sendBodiless() catch |err| return .{ .not_reached = @errorName(err) };

    var redirect_buffer: [4 * 1024]u8 = undefined;
    var response = request.receiveHead(&redirect_buffer) catch |err| return .{ .not_reached = @errorName(err) };

    var transfer_buffer: [4 * 1024]u8 = undefined;
    const body_reader = response.reader(&transfer_buffer);
    const body = body_reader.allocRemaining(gpa, .limited(max_body_bytes)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => try std.fmt.allocPrint(gpa, "[the answer could not be read: {s}]", .{@errorName(err)}),
    };

    if (response.head.status.class() != .success) {
        return .{ .rejected = .{ .status = response.head.status, .body = body } };
    }
    defer gpa.free(body);
    return .{ .ok = .{ .model_count = countModels(gpa, body) } };
}

fn countModels(gpa: std.mem.Allocator, body: []const u8) ?usize {
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, body, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const data = parsed.value.object.get("data") orelse return null;
    if (data != .array) return null;
    return data.array.items.len;
}

const testing = std.testing;

test "a catalogue with a data array is counted, and one without is null rather than zero" {
    const gpa = testing.allocator;
    try testing.expectEqual(@as(?usize, 2), countModels(gpa,
        \\{"object":"list","data":[{"id":"a"},{"id":"b"}]}
    ));
    try testing.expectEqual(@as(?usize, 0), countModels(gpa,
        \\{"object":"list","data":[]}
    ));
    try testing.expectEqual(@as(?usize, null), countModels(gpa,
        \\{"object":"list"}
    ));
    try testing.expectEqual(@as(?usize, null), countModels(gpa, "not json at all"));
    try testing.expectEqual(@as(?usize, null), countModels(gpa,
        \\{"data":"a string, not a list"}
    ));
}

test "a provider that cannot be reached is not reported as a wrong credential" {
    const gpa = testing.allocator;
    var outcome = try credential(gpa, testing.io, .openai_compat, "http://127.0.0.1:1/v1", "sk-not-a-real-key");
    defer outcome.deinit(gpa);
    try testing.expectEqual(std.meta.activeTag(outcome), Outcome.not_reached);
}

test {
    testing.refAllDecls(@This());
}
