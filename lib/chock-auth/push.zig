//! Where a project's own push token is kept. A push with somebody attached asks that
//! person through the password helper. This is the store for a push with nobody there.

const std = @import("std");
const store = @import("store.zig");

pub const name_prefix = store.reserved_prefix ++ "push:";

pub const max_name_bytes: usize = 128;

/// A project names itself with the characters its state directory uses, so a name
/// holding anything else did not come from `projectKey` and names no project.
pub fn nameIsAcceptable(project: []const u8) bool {
    if (project.len == 0 or project.len > max_name_bytes) return false;
    for (project) |character| {
        const ok = switch (character) {
            'A'...'Z', 'a'...'z', '0'...'9', '-', '_' => true,
            else => false,
        };
        if (!ok) return false;
    }
    return true;
}

pub const KeyNameError = error{ OutOfMemory, NameNotAcceptable };

pub fn keyName(gpa: std.mem.Allocator, project: []const u8) KeyNameError![]u8 {
    if (!nameIsAcceptable(project)) return error.NameNotAcceptable;
    return std.mem.concat(gpa, u8, &.{ name_prefix, project });
}

pub const Error = store.Error || error{NameNotAcceptable};

/// Null means this project stored no token. That is the ordinary case and not a
/// fault: a push then has to ask somebody.
pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    secrets: store.Secrets,
    project: []const u8,
    diag: ?*?store.Diagnostic,
) Error!?[]u8 {
    const key = try keyName(gpa, project);
    defer gpa.free(key);
    return secrets.get(gpa, io, key, diag);
}

pub fn save(
    gpa: std.mem.Allocator,
    io: std.Io,
    secrets: store.Secrets,
    project: []const u8,
    token: []const u8,
    diag: ?*?store.Diagnostic,
) Error!void {
    const key = try keyName(gpa, project);
    defer gpa.free(key);
    try secrets.put(gpa, io, key, token, diag);
}

const testing = std.testing;

const FakeSecrets = @import("test_secrets.zig").FakeSecrets;

test "a saved token loads back byte for byte" {
    var fake = FakeSecrets{};
    defer fake.deinit(testing.allocator);

    try save(testing.allocator, testing.io, fake.secrets(), "chock-1a2b3c4d", "push-token-123", null);
    const loaded = (try load(testing.allocator, testing.io, fake.secrets(), "chock-1a2b3c4d", null)).?;
    defer {
        std.crypto.secureZero(u8, loaded);
        testing.allocator.free(loaded);
    }
    try testing.expectEqualStrings("push-token-123", loaded);
}

test "a project that stored nothing loads null, not an error" {
    var fake = FakeSecrets{};
    defer fake.deinit(testing.allocator);

    try testing.expectEqual(
        @as(?[]u8, null),
        try load(testing.allocator, testing.io, fake.secrets(), "chock-1a2b3c4d", null),
    );
}

test "a token stored for one project is not readable for another" {
    var fake = FakeSecrets{};
    defer fake.deinit(testing.allocator);

    try save(testing.allocator, testing.io, fake.secrets(), "one-aaaaaaaa", "token-for-one", null);
    try testing.expectEqual(
        @as(?[]u8, null),
        try load(testing.allocator, testing.io, fake.secrets(), "two-bbbbbbbb", null),
    );

    const mine = (try load(testing.allocator, testing.io, fake.secrets(), "one-aaaaaaaa", null)).?;
    defer testing.allocator.free(mine);
    try testing.expectEqualStrings("token-for-one", mine);
}

test "the key the store saw names the project under name_prefix" {
    var fake = FakeSecrets{};
    defer fake.deinit(testing.allocator);

    try save(testing.allocator, testing.io, fake.secrets(), "chock-1a2b3c4d", "push-token-123", null);
    try testing.expectEqualStrings(name_prefix ++ "chock-1a2b3c4d", fake.last_name);
}

test "a name that could not have come from projectKey is refused" {
    var fake = FakeSecrets{};
    defer fake.deinit(testing.allocator);

    for ([_][]const u8{ "", "has space", "has/slash", "has:colon", "dot.separated", ".." }) |bad| {
        try testing.expectError(
            error.NameNotAcceptable,
            load(testing.allocator, testing.io, fake.secrets(), bad, null),
        );
    }
    const too_long: [max_name_bytes + 1]u8 = @splat('a');
    try testing.expectError(
        error.NameNotAcceptable,
        load(testing.allocator, testing.io, fake.secrets(), &too_long, null),
    );
}

test "name_prefix is reserved, so no provider instance can be stored over it" {
    try testing.expect(store.nameIsReserved(name_prefix));
}
