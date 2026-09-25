//! Where a web search engine's vendor key is kept.
//!
//! An engine of the `api` kind needs a key, but the key is not a provider
//! instance: it has no model list and no base URL of its own in
//! `store.Store`'s index, and nothing looks it up through `lookup.zig`. It
//! goes straight to the `store.Secrets` driver under a reserved name, the way
//! `signing.zig` keeps the seal key.

const std = @import("std");
const store = @import("store.zig");

/// What the driver keeps a search credential under, before the user's own
/// name.
pub const name_prefix = store.reserved_prefix ++ "search:";

/// The longest name this file accepts.
pub const max_name_bytes: usize = 128;

/// Whether `name` is safe to join to `name_prefix`.
///
/// The stored key is `name_prefix ++ name`, built by concatenation and not
/// by a structured record. A name holding a colon could be spelled to reach
/// past its own prefix into another reserved key, so a colon is refused here
/// rather than trusted to never appear. Refusing it is what makes the
/// prefix a namespace instead of string concatenation that usually works.
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

/// The full driver key for `name`. Caller owns the result.
///
/// Validation happens here rather than only in `load` and `save`, so a
/// caller added later cannot reach the driver with an unchecked name.
pub fn keyName(gpa: std.mem.Allocator, name: []const u8) KeyNameError![]u8 {
    if (!nameIsAcceptable(name)) return error.NameNotAcceptable;
    return std.mem.concat(gpa, u8, &.{ name_prefix, name });
}

pub const Error = store.Error || error{NameNotAcceptable};

/// The credential the driver holds for this search engine, or null when it
/// holds none. Caller owns the result and must `secureZero` it before
/// freeing.
///
/// Null means the user named this engine in their config and has not run
/// the login for it yet. That is the ordinary first run, and not a fault.
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

/// Keep `value` under this search engine's name, replacing whatever was
/// there.
///
/// `value` is opaque bytes to this layer: a vendor key is not trimmed,
/// decoded, or otherwise transformed.
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

/// A driver that holds a small list of name/value pairs in memory.
const FakeSecrets = struct {
    const Entry = struct { name: []const u8, value: []const u8 };

    entries: std.ArrayList(Entry) = .empty,
    /// The last name a caller asked this driver to get or put.
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
