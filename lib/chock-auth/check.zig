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
            .ok => |ok| if (ok.models) |models| {
                for (models) |model| gpa.free(model);
                gpa.free(models);
            },
            .not_reached => {},
        }
        self.* = undefined;
    }
};

pub const Ok = struct {
    model_count: ?usize,
    /// Sorted model identifiers from a standard `data[].id` catalogue. Null
    /// means the endpoint answered successfully in a shape Chock does not
    /// recognize. This typed result is shared by the CLI and future daemon/UI
    /// consumers; neither needs to retain or reparse a provider response.
    models: ?[]const []const u8,
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
        .aiand, .openai, .openai_compat => std.fmt.allocPrint(gpa, "Bearer {s}", .{token}),
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
        .aiand, .openai, .openai_compat => {
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
    const models = try parseModels(gpa, body);
    return .{ .ok = .{
        .model_count = if (models) |found| found.len else null,
        .models = models,
    } };
}

fn parseModels(gpa: std.mem.Allocator, body: []const u8) std.mem.Allocator.Error!?[]const []const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, body, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const CatalogueShape = enum { standard, codex };
    const Located = struct {
        entries: std.json.Value,
        id_field: []const u8,
        shape: CatalogueShape,
    };
    const located: Located = if (parsed.value.object.get("data")) |data|
        .{ .entries = data, .id_field = "id", .shape = .standard }
    else if (parsed.value.object.get("models")) |models|
        .{ .entries = models, .id_field = "slug", .shape = .codex }
    else
        return null;
    if (located.entries != .array) return null;

    var models: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (models.items) |model| gpa.free(model);
        models.deinit(gpa);
    }
    for (located.entries.array.items) |entry| {
        if (entry != .object) continue;
        if (located.shape == .codex) {
            if (entry.object.get("visibility")) |visibility| {
                if (visibility != .string or !std.mem.eql(u8, visibility.string, "list")) continue;
            }
        }
        const id = entry.object.get(located.id_field) orelse continue;
        if (id != .string or id.string.len == 0) continue;
        if (!safeModelId(id.string)) continue;
        try models.append(gpa, try gpa.dupe(u8, id.string));
    }
    const owned = try models.toOwnedSlice(gpa);
    std.mem.sort([]const u8, owned, {}, struct {
        fn lessThan(_: void, left: []const u8, right: []const u8) bool {
            return std.mem.order(u8, left, right) == .lt;
        }
    }.lessThan);
    return owned;
}

fn safeModelId(id: []const u8) bool {
    if (!std.unicode.utf8ValidateSlice(id)) return false;
    for (id) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    return true;
}

const testing = std.testing;

test "a catalogue returns sorted model ids, and an unknown shape stays unknown" {
    const gpa = testing.allocator;
    const found = (try parseModels(gpa,
        \\{"object":"list","data":[{"id":"z"},{"id":"a"},{"id":"bad\nline"},{"not_id":"ignored"}]}
    )).?;
    defer {
        for (found) |model| gpa.free(model);
        gpa.free(found);
    }
    try testing.expectEqual(@as(usize, 2), found.len);
    try testing.expectEqualStrings("a", found[0]);
    try testing.expectEqualStrings("z", found[1]);

    const empty = (try parseModels(gpa, "{\"object\":\"list\",\"data\":[]}")).?;
    defer gpa.free(empty);
    try testing.expectEqual(@as(usize, 0), empty.len);
    try testing.expect((try parseModels(gpa, "{\"object\":\"list\"}")) == null);
    try testing.expect((try parseModels(gpa, "not json at all")) == null);
    try testing.expect((try parseModels(gpa, "{\"data\":\"a string, not a list\"}")) == null);
}

test "the OpenAI Codex catalogue uses model slugs and hides non-picker entries" {
    const gpa = testing.allocator;
    const found = (try parseModels(gpa,
        \\{"models":[
        \\  {"slug":"gpt-z","display_name":"GPT Z","visibility":"list","supported_in_api":true},
        \\  {"slug":"gpt-hidden","display_name":"Hidden","visibility":"none","supported_in_api":true},
        \\  {"slug":"gpt-a","display_name":"GPT A","visibility":"list","supported_in_api":false}
        \\]}
    )).?;
    defer {
        for (found) |model| gpa.free(model);
        gpa.free(found);
    }
    try testing.expectEqual(@as(usize, 2), found.len);
    try testing.expectEqualStrings("gpt-a", found[0]);
    try testing.expectEqualStrings("gpt-z", found[1]);
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
