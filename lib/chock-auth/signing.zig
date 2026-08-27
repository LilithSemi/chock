//! Where the software seal key's secret is kept.
//!
//! `lib/chock-pcsc/software.zig` holds a P-256 key pair in this process and
//! says, in its own top comment, that where the secret lives between runs is
//! not its business: `toSecret` and `fromSecret` are the whole of its storage
//! interface. This is the other end of those two calls.
//!
//! ## Neither library learns about the other
//!
//! **`chock-pcsc` must never import `chock-auth`**, because a verifier must not
//! need a credential store to check a signature. That is the half an auditor
//! uses, and an auditor has no store.
//!
//! **`chock-auth` imports no other Chock library either**, which is the rule
//! `lib/chock-auth.zig` already keeps: `chock login` runs before a session, a
//! workspace or a sandbox exists.
//!
//! So this file knows a secret is `secret_len` bytes and knows nothing else
//! about it. It never builds a key, never signs, and never reads a public part.
//! The caller holds both halves and joins them:
//!
//! ```
//! const secret = try signing.load(gpa, io, secrets, null) orelse fresh: {
//!     const made = software.Key.generate(io).toSecret();
//!     try signing.save(gpa, io, secrets, made, null);
//!     break :fresh made;
//! };
//! var key = try software.Key.fromSecret(secret);
//! ```
//!
//! **The caller makes the key, not this file.** Not every 32 bytes is a valid
//! P-256 scalar, and only the curve knows which are. A generator here would
//! either duplicate that rule or hand back a secret that cannot be used.
//!
//! ## The driver, and not the index
//!
//! This goes through `store.Secrets` and never through `store.Store`. A
//! `Store` entry is a provider instance, with a kind and a base URL, and it is
//! listed by `chock login`. A signing key is none of those things, so it gets
//! no index entry and appears in no listing of providers.
//!
//! It still gets the platform's own protection, which is the whole reason to
//! use the driver: a file at mode `0600` on Linux, the Keychain on macOS, and
//! whatever a later driver makes of those. Nothing here changes when the
//! driver does.
//!
//! ## Losing this secret loses no log and forges nothing
//!
//! A lost secret means the next seal is signed by a new key, so seals written
//! before it verify against a key nothing holds any more. **They still
//! verify**: a seal carries the public key that signed it. What is lost is the
//! proof that the same signer made the old and the new one.

const std = @import("std");
const store = @import("store.zig");

/// How many bytes a stored secret is. The same width
/// `chock-pcsc/software.zig`'s `secret_len` is, which is P-256's own scalar
/// width. **Written here rather than imported**: see this file's own top
/// comment on why the two libraries do not know about each other.
pub const secret_len: usize = 32;

/// The secret itself, as it is handed over.
pub const Secret = [secret_len]u8;

/// What the driver keeps the secret under. The prefix is
/// `store.reserved_prefix`, so `store.Store.put` refuses to store a provider
/// instance over it.
///
/// **The version is in the name.** A later key of a different width or a
/// different curve gets a different name, so a build that reads this one can
/// never mistake it for something else and no migration has to guess.
pub const key_name = store.reserved_prefix ++ "seal-key-v1";

/// How the secret is written: lowercase hexadecimal, `secret_len * 2`
/// characters. A driver's value is text, so raw bytes with a zero in them
/// would not survive the trip through either driver.
pub const stored_len = secret_len * 2;

/// The secret the driver holds, or null when it holds none.
///
/// **Null is "this machine has not signed yet" and not a fault.** A machine
/// that has never sealed a log has no key, and that is the ordinary first run.
/// A value that is there and is not `stored_len` characters of lowercase
/// hexadecimal **is** a fault: it is a store somebody edited, and reading it
/// back as "no key" would quietly make a new one and orphan every seal the old
/// one wrote.
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
    // Lower case only, and checked here: `std.fmt.hexToBytes` takes either
    // case, so a value written in upper case would read back as the same
    // secret under a second spelling. One value, one spelling.
    for (text) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return error.StoreCorrupt;
    }
    var secret: Secret = undefined;
    _ = std.fmt.hexToBytes(&secret, text) catch return error.StoreCorrupt;
    return secret;
}

/// Keep `secret`, replacing whatever was there.
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

/// A driver that holds one name and one value in memory. Neither a file nor a
/// Keychain, which is the reason `store.Secrets` is a vtable.
const FakeSecrets = struct {
    name: []const u8 = "",
    value: []const u8 = "",
    /// Set when `get` should fail the way a driver with a bad file does.
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
    // The property every seal already written depends on. A secret that did not
    // come back would give a new key on the next run, and a reader would find
    // two signers where there was one.
    var fake = FakeSecrets{ .name = try testing.allocator.dupe(u8, ""), .value = try testing.allocator.dupe(u8, "") };
    defer fake.deinit(testing.allocator);

    const secret: Secret = [_]u8{ 0x01, 0x02, 0x03 } ++ [_]u8{0xab} ** 29;
    try save(testing.allocator, testing.io, fake.secrets(), secret, null);

    const loaded = (try load(testing.allocator, testing.io, fake.secrets(), null)).?;
    try testing.expectEqualSlices(u8, &secret, &loaded);

    // And the mutation check: another secret gives another answer, so `load` is
    // not returning a constant.
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
