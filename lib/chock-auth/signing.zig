//! Where the software seal key's secret is kept.

const std = @import("std");
const store = @import("store.zig");

pub const secret_len: usize = 32;

pub const Secret = [secret_len]u8;

pub const key_name = store.reserved_prefix ++ "seal-key-v1";

pub const stored_len = secret_len * 2;

pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    secrets: store.Secrets,
    diag: ?*?store.Diagnostic,
) store.Error!?Secret {
    const text = try secrets.get(gpa, io, key_name, diag) orelse return null;
    defer {
        std.crypto.secureZero(u8, text);
        gpa.free(text);
    }

    if (text.len != stored_len) return error.StoreCorrupt;
    // Lower case only, checked here: std.fmt.hexToBytes takes either case, so a value written upper case would read back as the same secret under a second spelling.
    for (text) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return error.StoreCorrupt;
    }
    var secret: Secret = undefined;
    _ = std.fmt.hexToBytes(&secret, text) catch return error.StoreCorrupt;
    return secret;
}

pub fn save(
    gpa: std.mem.Allocator,
    io: std.Io,
    secrets: store.Secrets,
    secret: Secret,
    diag: ?*?store.Diagnostic,
) store.Error!void {
    var text = std.fmt.bytesToHex(secret, .lower);
    // The buffer is this frame's own, and it holds the secret in full.
    defer std.crypto.secureZero(u8, &text);
    try secrets.put(gpa, io, key_name, &text, diag);
}

const testing = std.testing;

const FakeSecrets = struct {
    name: []const u8 = "",
    value: []const u8 = "",
    unreadable: bool = false,

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
        if (self.unreadable) return error.StoreUnreadable;
        if (!std.mem.eql(u8, self.name, name)) return null;
        return try gpa.dupe(u8, self.value);
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
        gpa.free(self.name);
        gpa.free(self.value);
        self.name = try gpa.dupe(u8, name);
        self.value = try gpa.dupe(u8, value);
    }

    fn deinit(self: *FakeSecrets, gpa: std.mem.Allocator) void {
        gpa.free(self.name);
        gpa.free(self.value);
        self.* = undefined;
    }
};

test "a secret saved is the same secret loaded, byte for byte" {
    var fake = FakeSecrets{ .name = try testing.allocator.dupe(u8, ""), .value = try testing.allocator.dupe(u8, "") };
    defer fake.deinit(testing.allocator);

    const secret: Secret = [_]u8{ 0x01, 0x02, 0x03 } ++ [_]u8{0xab} ** 29;
    try save(testing.allocator, testing.io, fake.secrets(), secret, null);

    const loaded = (try load(testing.allocator, testing.io, fake.secrets(), null)).?;
    try testing.expectEqualSlices(u8, &secret, &loaded);

    const other: Secret = [_]u8{0x77} ** secret_len;
    try save(testing.allocator, testing.io, fake.secrets(), other, null);
    try testing.expectEqualSlices(u8, &other, &(try load(testing.allocator, testing.io, fake.secrets(), null)).?);
}

test "a machine that has never sealed anything holds no key, which is not a fault" {
    var fake = FakeSecrets{ .name = try testing.allocator.dupe(u8, ""), .value = try testing.allocator.dupe(u8, "") };
    defer fake.deinit(testing.allocator);
    try testing.expectEqual(
        @as(?Secret, null),
        try load(testing.allocator, testing.io, fake.secrets(), null),
    );
}

test "a stored value of the wrong width or alphabet is corrupt, never a missing key" {
    var fake = FakeSecrets{
        .name = try testing.allocator.dupe(u8, key_name),
        .value = try testing.allocator.dupe(u8, "abcd"),
    };
    defer fake.deinit(testing.allocator);
    try testing.expectError(
        error.StoreCorrupt,
        load(testing.allocator, testing.io, fake.secrets(), null),
    );

    testing.allocator.free(fake.value);
    fake.value = try testing.allocator.dupe(u8, &[_]u8{'z'} ** stored_len);
    try testing.expectError(
        error.StoreCorrupt,
        load(testing.allocator, testing.io, fake.secrets(), null),
    );

    testing.allocator.free(fake.value);
    fake.value = try testing.allocator.dupe(u8, &[_]u8{'A'} ** stored_len);
    try testing.expectError(
        error.StoreCorrupt,
        load(testing.allocator, testing.io, fake.secrets(), null),
    );
}

test "a driver that cannot be read is a fault and never an absent key" {
    var fake = FakeSecrets{
        .name = try testing.allocator.dupe(u8, ""),
        .value = try testing.allocator.dupe(u8, ""),
        .unreadable = true,
    };
    defer fake.deinit(testing.allocator);
    try testing.expectError(
        error.StoreUnreadable,
        load(testing.allocator, testing.io, fake.secrets(), null),
    );
}

test "the key's name is reserved, so no provider instance can be stored over it" {
    try testing.expect(std.mem.startsWith(u8, key_name, store.reserved_prefix));
    try testing.expect(store.nameIsReserved(key_name));
    try testing.expect(!store.nameIsReserved("work"));
}

test {
    testing.refAllDecls(@This());
}
