//! The mobile client's small, platform-persisted server history.
//!
//! Phantom owns the storage mechanism. This module owns the value written into
//! it, so Android, another native shell, and tests all agree on validation and
//! limits without knowing whether the host uses SharedPreferences or a file.

const std = @import("std");

pub const setting_key = "servers";
pub const max_setting_bytes: usize = 8 * 1024;
pub const max_servers: usize = 16;

pub const List = struct {
    items: std.ArrayList([]u8) = .empty,

    pub fn deinit(self: *List, gpa: std.mem.Allocator) void {
        for (self.items.items) |item| gpa.free(item);
        self.items.deinit(gpa);
        self.* = .{};
    }

    /// The most recently used server is first. Re-adding one moves it there.
    pub fn remember(self: *List, gpa: std.mem.Allocator, raw: []const u8) !void {
        const server = normalized(raw) orelse return error.InvalidServer;
        var found: ?usize = null;
        for (self.items.items, 0..) |item, index| {
            if (std.mem.eql(u8, item, server)) {
                found = index;
                break;
            }
        }
        if (found) |index| {
            const held = self.items.orderedRemove(index);
            try self.items.insert(gpa, 0, held);
            return;
        }

        const copy = try gpa.dupe(u8, server);
        errdefer gpa.free(copy);
        try self.items.insert(gpa, 0, copy);
        if (self.items.items.len > max_servers) {
            const old = self.items.pop().?;
            gpa.free(old);
        }
    }

    /// One server per line. Newlines are forbidden by `normalized`, making the
    /// representation both human-readable and unambiguous.
    pub fn load(self: *List, gpa: std.mem.Allocator, encoded: []const u8) !void {
        if (encoded.len > max_setting_bytes) return error.ValueTooLarge;
        var lines = std.mem.splitScalar(u8, encoded, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            try self.rememberOldest(gpa, line);
        }
    }

    fn rememberOldest(self: *List, gpa: std.mem.Allocator, raw: []const u8) !void {
        const server = normalized(raw) orelse return;
        for (self.items.items) |item| if (std.mem.eql(u8, item, server)) return;
        if (self.items.items.len == max_servers) return;
        const copy = try gpa.dupe(u8, server);
        errdefer gpa.free(copy);
        try self.items.append(gpa, copy);
    }

    /// Remove a saved server by the same normalization rules used for input.
    pub fn forget(self: *List, gpa: std.mem.Allocator, raw: []const u8) bool {
        const server = normalized(raw) orelse return false;
        for (self.items.items, 0..) |item, index| {
            if (!std.mem.eql(u8, item, server)) continue;
            gpa.free(self.items.orderedRemove(index));
            return true;
        }
        return false;
    }

    pub fn encode(self: *const List, allocator: std.mem.Allocator) ![]u8 {
        var out: std.Io.Writer.Allocating = .init(allocator);
        errdefer out.deinit();
        for (self.items.items, 0..) |item, index| {
            if (index != 0) try out.writer.writeByte('\n');
            try out.writer.writeAll(item);
        }
        if (out.written().len > max_setting_bytes) return error.ValueTooLarge;
        return out.toOwnedSlice();
    }
};

pub fn normalized(raw: []const u8) ?[]const u8 {
    var value = std.mem.trim(u8, raw, " \t\r\n");
    if (std.mem.endsWith(u8, value, "/")) {
        value = value[0 .. value.len - 1];
        if (std.mem.endsWith(u8, value, "/")) return null;
    }
    if (value.len == 0 or value.len > 512) return null;
    if (std.mem.indexOfAny(u8, value, "\r\n\x00") != null) return null;
    for (value) |byte| {
        if (byte <= 0x20 or byte >= 0x7f) return null;
    }

    // Bare host[:port] entries keep their established HTTP-on-LAN behavior;
    // explicit origins must parse as HTTP(S), with no credentials or URL path.
    var with_scheme: [519]u8 = undefined;
    const candidate = if (std.mem.indexOf(u8, value, "://") != null)
        value
    else blk: {
        const prefix = "http://";
        @memcpy(with_scheme[0..prefix.len], prefix);
        @memcpy(with_scheme[prefix.len .. prefix.len + value.len], value);
        break :blk with_scheme[0 .. prefix.len + value.len];
    };
    const uri = std.Uri.parse(candidate) catch return null;
    if ((!std.mem.eql(u8, uri.scheme, "http") and !std.mem.eql(u8, uri.scheme, "https")) or
        uri.host == null or uri.user != null or uri.password != null or uri.query != null or uri.fragment != null)
        return null;
    if (uri.path.percent_encoded.len != 0 and !std.mem.eql(u8, uri.path.percent_encoded, "/")) return null;
    return value;
}

test "server history is most-recent-first, unique, and round trips" {
    const gpa = std.testing.allocator;
    var list: List = .{};
    defer list.deinit(gpa);
    try list.remember(gpa, " https://one.example/ ");
    try list.remember(gpa, "two.example:7374");
    try list.remember(gpa, "https://one.example");
    try std.testing.expectEqualStrings("https://one.example", list.items.items[0]);
    try std.testing.expectEqualStrings("two.example:7374", list.items.items[1]);

    const encoded = try list.encode(gpa);
    defer gpa.free(encoded);
    var loaded: List = .{};
    defer loaded.deinit(gpa);
    try loaded.load(gpa, encoded);
    try std.testing.expectEqual(@as(usize, 2), loaded.items.items.len);
    try std.testing.expectEqualStrings(list.items.items[0], loaded.items.items[0]);
    try std.testing.expectEqualStrings(list.items.items[1], loaded.items.items[1]);
}

test "server history is bounded and refuses ambiguous values" {
    const gpa = std.testing.allocator;
    var list: List = .{};
    defer list.deinit(gpa);
    try std.testing.expectError(error.InvalidServer, list.remember(gpa, "   "));
    try std.testing.expectError(error.InvalidServer, list.remember(gpa, "one\ntwo"));
    try std.testing.expectError(error.InvalidServer, list.remember(gpa, "ftp://server.example"));
    try std.testing.expectError(error.InvalidServer, list.remember(gpa, "https://user@server.example"));
    try std.testing.expectError(error.InvalidServer, list.remember(gpa, "https://server.example/path"));
    try std.testing.expectError(error.InvalidServer, list.remember(gpa, "https://server.example:invalid"));
    try std.testing.expectError(error.InvalidServer, list.remember(gpa, "https://server.example?next=/admin"));
    try std.testing.expectError(error.InvalidServer, list.remember(gpa, "https://server.example//"));
    for (0..max_servers + 3) |index| {
        const server = try std.fmt.allocPrint(gpa, "server-{d}.example", .{index});
        defer gpa.free(server);
        try list.remember(gpa, server);
    }
    try std.testing.expectEqual(max_servers, list.items.items.len);
    try std.testing.expectEqualStrings("server-18.example", list.items.items[0]);
    try std.testing.expectEqualStrings("server-3.example", list.items.items[max_servers - 1]);
}

test "forget removes only the normalized matching server" {
    const gpa = std.testing.allocator;
    var list: List = .{};
    defer list.deinit(gpa);
    try list.remember(gpa, "https://one.example");
    try list.remember(gpa, "two.example:7374");

    try std.testing.expect(list.forget(gpa, " https://one.example/ "));
    try std.testing.expect(!list.forget(gpa, "https://unknown.example"));
    try std.testing.expectEqual(@as(usize, 1), list.items.items.len);
    try std.testing.expectEqualStrings("two.example:7374", list.items.items[0]);
}

test "oversized persisted server history is rejected without partial loading" {
    const gpa = std.testing.allocator;
    const encoded = try gpa.alloc(u8, max_setting_bytes + 1);
    defer gpa.free(encoded);
    @memset(encoded, 'a');
    var list: List = .{};
    defer list.deinit(gpa);
    try std.testing.expectError(error.ValueTooLarge, list.load(gpa, encoded));
    try std.testing.expectEqual(@as(usize, 0), list.items.items.len);
}

test "failed server-history growth frees the copied server" {
    const gpa = std.testing.allocator;
    // The string copy succeeds; the ArrayList growth that follows fails.
    var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 1 });
    var list: List = .{};
    defer list.deinit(failing.allocator());

    try std.testing.expectError(error.OutOfMemory, list.rememberOldest(failing.allocator(), "server.example"));
    try std.testing.expectEqual(@as(usize, 0), list.items.items.len);
}
