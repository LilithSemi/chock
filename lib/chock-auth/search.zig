//! Where a web search engine's vendor key is kept.

const std = @import("std");
const store = @import("store.zig");

pub const name_prefix = store.reserved_prefix ++ "search:";

pub const max_name_bytes: usize = 128;

pub fn nameIsAcceptable(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_bytes) return false;
    for (name) |c| {
        const ok = switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.' => true,
            else => false,
        };
        if (!ok) return false;
    }
    return true;
}

pub const KeyNameError = error{ OutOfMemory, NameNotAcceptable };

pub fn keyName(gpa: std.mem.Allocator, name: []const u8) KeyNameError![]u8 {
    if (!nameIsAcceptable(name)) return error.NameNotAcceptable;
    return std.mem.concat(gpa, u8, &.{ name_prefix, name });
}

pub const Error = store.Error || error{NameNotAcceptable};

pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    secrets: store.Secrets,
    name: []const u8,
    diag: ?*?store.Diagnostic,
) Error!?[]u8 {
    const key = try keyName(gpa, name);
    defer gpa.free(key);
    return secrets.get(gpa, io, key, diag);
}

pub fn save(
    gpa: std.mem.Allocator,
    io: std.Io,
    secrets: store.Secrets,
    name: []const u8,
    value: []const u8,
    diag: ?*?store.Diagnostic,
) Error!void {
    const key = try keyName(gpa, name);
    defer gpa.free(key);
    try secrets.put(gpa, io, key, value, diag);
}

const testing = std.testing;

const FakeSecrets = struct {
    const Entry = struct { name: []const u8, value: []const u8 };

    entries: std.ArrayList(Entry) = .empty,
    last_name: []const u8 = "",

    fn secrets(self: *FakeSecrets) store.Secrets {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = store.Secrets.VTable{ .get = getFn, .put = putFn };

    fn getFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        diag: ?*?store.Diagnostic,
    ) store.Error!?[]u8 {
        _ = io;
        _ = diag;
        const self: *FakeSecrets = @ptrCast(@alignCast(ptr));
        gpa.free(self.last_name);
        self.last_name = try gpa.dupe(u8, name);
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return try gpa.dupe(u8, entry.value);
        }
        return null;
    }

    fn putFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        value: []const u8,
        diag: ?*?store.Diagnostic,
    ) store.Error!void {
        _ = io;
        _ = diag;
        const self: *FakeSecrets = @ptrCast(@alignCast(ptr));
        gpa.free(self.last_name);
        self.last_name = try gpa.dupe(u8, name);
        for (self.entries.items) |*entry| {
            if (std.mem.eql(u8, entry.name, name)) {
                gpa.free(entry.value);
                entry.value = try gpa.dupe(u8, value);
                return;
            }
        }
        try self.entries.append(gpa, .{
            .name = try gpa.dupe(u8, name),
            .value = try gpa.dupe(u8, value),
        });
    }

    fn deinit(self: *FakeSecrets, gpa: std.mem.Allocator) void {
        for (self.entries.items) |entry| {
            gpa.free(entry.name);
            gpa.free(entry.value);
        }
        self.entries.deinit(gpa);
        gpa.free(self.last_name);
        self.* = undefined;
    }
};

test "a saved credential loads back byte for byte" {
    var fake = FakeSecrets{};
    defer fake.deinit(testing.allocator);

    try save(testing.allocator, testing.io, fake.secrets(), "brave", "vendor-key-123", null);
    const loaded = (try load(testing.allocator, testing.io, fake.secrets(), "brave", null)).?;
    defer {
        std.crypto.secureZero(u8, loaded);
        testing.allocator.free(loaded);
    }
    try testing.expectEqualStrings("vendor-key-123", loaded);
}

test "load for a name never saved gives null, not an error" {
    var fake = FakeSecrets{};
    defer fake.deinit(testing.allocator);

    try testing.expectEqual(
        @as(?[]u8, null),
        try load(testing.allocator, testing.io, fake.secrets(), "brave", null),
    );
}

test "the key the driver saw starts with name_prefix" {
    var fake = FakeSecrets{};
    defer fake.deinit(testing.allocator);

    try save(testing.allocator, testing.io, fake.secrets(), "brave", "vendor-key-123", null);
    try testing.expect(std.mem.startsWith(u8, fake.last_name, name_prefix));
    try testing.expectEqualStrings(name_prefix ++ "brave", fake.last_name);
}

test "nameIsAcceptable rejects the empty string, a colon, a slash, a space, and a newline" {
    try testing.expect(!nameIsAcceptable(""));
    try testing.expect(!nameIsAcceptable("work:key"));
    try testing.expect(!nameIsAcceptable("work/key"));
    try testing.expect(!nameIsAcceptable("work key"));
    try testing.expect(!nameIsAcceptable("work\nkey"));
}

test "nameIsAcceptable accepts ordinary names" {
    try testing.expect(nameIsAcceptable("brave"));
    try testing.expect(nameIsAcceptable("work-key"));
    try testing.expect(nameIsAcceptable("my_key.2"));
}

test "keyName, load, and save all refuse a name with a colon" {
    var fake = FakeSecrets{};
    defer fake.deinit(testing.allocator);

    try testing.expectError(error.NameNotAcceptable, keyName(testing.allocator, "work:key"));
    try testing.expectError(
        error.NameNotAcceptable,
        load(testing.allocator, testing.io, fake.secrets(), "work:key", null),
    );
    try testing.expectError(
        error.NameNotAcceptable,
        save(testing.allocator, testing.io, fake.secrets(), "work:key", "x", null),
    );
}

test "name_prefix is reserved, so no provider instance can be stored over it" {
    try testing.expect(store.nameIsReserved(name_prefix));
}
