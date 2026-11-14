//! Authenticated HTTP transport used by client-hosted session workers.

const std = @import("std");
const event = @import("chock-proto").event;
const session_paths = @import("session.zig");

const max_response_bytes = 8 * 1024 * 1024;

pub const Client = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    origin: []const u8,
    token: []const u8,

    pub const Lease = struct { generation: u64, expires_ms: i64 };
    pub const Page = struct { events: []const event.Envelope, end_offset: u64 };
    pub const Append = struct { event_id: u64, next_offset: u64 };

    pub fn claim(self: Client, arena: std.mem.Allocator, session: []const u8, host_id: []const u8) !Lease {
        if (!session_paths.isValidId(session) or !validUuid(host_id)) return error.InvalidWorkerAddress;
        const payload = try std.json.Stringify.valueAlloc(arena, .{
            .action = "claim",
            .session = session,
            .placement = "client",
            .host_id = host_id,
        }, .{});
        const body = try self.request(arena, .POST, "/api/session-host", payload);
        const parsed = try std.json.parseFromSliceLeaky(Lease, arena, body, .{});
        if (parsed.generation == 0 or parsed.expires_ms <= 0) return error.InvalidLease;
        return parsed;
    }

    pub fn release(self: Client, arena: std.mem.Allocator, session: []const u8, host_id: []const u8, generation: u64) !void {
        if (!session_paths.isValidId(session) or !validUuid(host_id) or generation == 0) return error.InvalidWorkerAddress;
        const payload = try std.json.Stringify.valueAlloc(arena, .{
            .action = "release",
            .session = session,
            .host_id = host_id,
            .generation = generation,
        }, .{});
        _ = try self.request(arena, .POST, "/api/session-host", payload);
    }

    pub fn commands(
        self: Client,
        arena: std.mem.Allocator,
        session: []const u8,
        host_id: []const u8,
        generation: u64,
        after: u64,
    ) !Page {
        if (!session_paths.isValidId(session) or !validUuid(host_id) or generation == 0) return error.InvalidWorkerAddress;
        const target = try std.fmt.allocPrint(
            arena,
            "/api/worker/commands?session={s}&host_id={s}&generation={d}&after={d}",
            .{ session, host_id, generation, after },
        );
        const body = try self.request(arena, .GET, target, null);
        const page = try std.json.parseFromSliceLeaky(Page, arena, body, .{ .ignore_unknown_fields = true });
        return try validatePage(page, session, after);
    }

    pub fn append(
        self: Client,
        arena: std.mem.Allocator,
        session: []const u8,
        host_id: []const u8,
        generation: u64,
        event_id: u64,
        ev: event.Event,
    ) !Append {
        if (!session_paths.isValidId(session) or !validUuid(host_id) or generation == 0) return error.InvalidWorkerAddress;
        const payload = try std.json.Stringify.valueAlloc(arena, .{
            .session = session,
            .host_id = host_id,
            .generation = generation,
            .event_id = event_id,
            .event = ev,
        }, .{});
        const body = try self.request(arena, .POST, "/api/worker/events", payload);
        const appended = try std.json.parseFromSliceLeaky(Append, arena, body, .{});
        if (appended.event_id != event_id or appended.next_offset <= appended.event_id) return error.InvalidAppend;
        return appended;
    }

    fn request(self: Client, arena: std.mem.Allocator, method: std.http.Method, target: []const u8, payload: ?[]const u8) ![]const u8 {
        if (!validOrigin(self.origin) or !validBearer(self.token)) return error.InvalidWorkerAddress;
        const url = try std.fmt.allocPrint(arena, "{s}{s}", .{ self.origin, target });
        const uri = try std.Uri.parse(url);
        const authorization = try std.fmt.allocPrint(self.gpa, "Bearer {s}", .{self.token});
        defer {
            std.crypto.secureZero(u8, authorization);
            self.gpa.free(authorization);
        }

        var client: std.http.Client = .{ .allocator = self.gpa, .io = self.io };
        defer client.deinit();
        const headers = [_]std.http.Header{.{ .name = "accept-encoding", .value = "identity" }};
        var http_request = try client.request(method, uri, .{
            .keep_alive = false,
            .redirect_behavior = .not_allowed,
            .headers = .{
                .authorization = .{ .override = authorization },
                .content_type = if (payload != null) .{ .override = "application/json" } else .omit,
            },
            .extra_headers = &headers,
        });
        defer http_request.deinit();
        if (payload) |bytes| {
            const mutable_body = try self.gpa.dupe(u8, bytes);
            defer self.gpa.free(mutable_body);
            try http_request.sendBodyComplete(mutable_body);
        } else try http_request.sendBodiless();

        var head_buffer: [4 * 1024]u8 = undefined;
        var response = try http_request.receiveHead(&head_buffer);
        var transfer_buffer: [16 * 1024]u8 = undefined;
        const body_reader = response.reader(&transfer_buffer);
        const body = try body_reader.allocRemaining(arena, .limited(max_response_bytes));
        if (response.head.status != .ok) return error.WorkerRequestRefused;
        return body;
    }
};

fn validatePage(page: Client.Page, session: []const u8, after: u64) error{InvalidPage}!Client.Page {
    if (page.events.len > 64) return error.InvalidPage;
    var previous = after;
    for (page.events) |one| {
        if (one.id <= previous or !std.mem.eql(u8, one.session, session)) return error.InvalidPage;
        previous = one.id;
    }
    if (page.events.len != 0 and page.end_offset <= page.events[page.events.len - 1].id) return error.InvalidPage;
    return page;
}

fn validOrigin(origin: []const u8) bool {
    const uri = std.Uri.parse(origin) catch return false;
    if (!(std.mem.eql(u8, uri.scheme, "http") or std.mem.eql(u8, uri.scheme, "https"))) return false;
    if (uri.host == null or uri.user != null or uri.password != null or uri.query != null or uri.fragment != null) return false;
    return uri.path.percent_encoded.len == 0 or std.mem.eql(u8, uri.path.percent_encoded, "/");
}

fn validBearer(token: []const u8) bool {
    if (token.len != 43) return false;
    for (token) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return false;
    return true;
}

fn validUuid(text: []const u8) bool {
    if (text.len != 36) return false;
    for (text, 0..) |byte, index| {
        if (index == 8 or index == 13 or index == 18 or index == 23) {
            if (byte != '-') return false;
        } else if (!std.ascii.isHex(byte)) return false;
    }
    return true;
}

test "worker transport accepts only origin URLs and opaque worker bearers" {
    try std.testing.expect(validOrigin("https://daemon.example"));
    try std.testing.expect(validOrigin("http://127.0.0.1:7374/"));
    try std.testing.expect(!validOrigin("https://user:password@daemon.example"));
    try std.testing.expect(!validOrigin("https://daemon.example/path"));
    try std.testing.expect(!validOrigin("file:///tmp/chock"));
    try std.testing.expect(validBearer("0123456789abcdefghijklmnopqrstuvwxyz-ABCDEF"));
    try std.testing.expect(!validBearer("token"));
}

test "worker claim request names client placement and a host UUID" {
    const arena = std.testing.allocator;
    const lease_request = try std.json.Stringify.valueAlloc(arena, .{
        .action = "claim",
        .session = "01JQSESSION0000000000000000",
        .placement = "client",
        .host_id = "00000000-0000-4000-8000-000000000099",
    }, .{});
    defer arena.free(lease_request);
    try std.testing.expectEqualStrings(
        "{\"action\":\"claim\",\"session\":\"01JQSESSION0000000000000000\",\"placement\":\"client\",\"host_id\":\"00000000-0000-4000-8000-000000000099\"}",
        lease_request,
    );
    try std.testing.expect(session_paths.isValidId("01JQAAAAAAAAAAAAAAAAAAAAAA"));
    try std.testing.expect(validUuid("00000000-0000-4000-8000-000000000099"));
    try std.testing.expect(!validUuid("../commands?after=0"));
}

test "worker event pages are ordered, scoped, bounded, and carry an append offset" {
    const items = [_]event.Envelope{
        .{ .id = 100, .session = "01JQAAAAAAAAAAAAAAAAAAAAAA", .time_ms = 1, .event = .{ .unknown = .{ .kind = "test", .payload = .null } } },
        .{ .id = 200, .session = "01JQAAAAAAAAAAAAAAAAAAAAAA", .time_ms = 2, .event = .{ .unknown = .{ .kind = "test", .payload = .null } } },
    };
    const page = try validatePage(.{ .events = &items, .end_offset = 300 }, items[0].session, 0);
    try std.testing.expectEqual(@as(usize, 2), page.events.len);
    try std.testing.expectError(error.InvalidPage, validatePage(.{ .events = &items, .end_offset = 300 }, items[0].session, 100));
    try std.testing.expectError(error.InvalidPage, validatePage(.{ .events = &items, .end_offset = 200 }, items[0].session, 0));
}
