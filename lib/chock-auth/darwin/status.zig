//! What the Keychain answers, and what a person should do about it.
//!
//! Split from the driver so it builds and is tested on every host. The driver
//! beside it declares `extern` functions that only link against the Security
//! framework, so a Linux test binary cannot reference them at all.

const std = @import("std");

/// `OSStatus`, the result of every Security framework call. `MacTypes.h` gives
/// `typedef SInt32 OSStatus`, and `SInt32` is `signed int` on every 64 bit
/// Apple target.
pub const OSStatus = c_int;

pub const success: OSStatus = 0;
pub const auth_failed: OSStatus = -25293;
pub const duplicate_item: OSStatus = -25299;
pub const item_not_found: OSStatus = -25300;
pub const no_default_keychain: OSStatus = -25307;
pub const interaction_not_allowed: OSStatus = -25308;

/// What a status means for the caller, apart from the number itself.
pub const Meaning = enum {
    /// The call worked.
    ok,
    /// The Keychain holds no such item. Not a fault: an instance nobody has
    /// logged in for reads back as nothing.
    absent,
    /// The item is there and this process may not have it without asking a
    /// person, and asking is turned off.
    needs_unlock,
    /// The account has no default keychain at all.
    no_keychain,
    /// The item is there and the Keychain refused this process.
    refused,
    /// Anything else. The number is the only fact.
    other,
};

pub fn meaningOf(status: OSStatus) Meaning {
    return switch (status) {
        success => .ok,
        item_not_found => .absent,
        interaction_not_allowed => .needs_unlock,
        no_default_keychain => .no_keychain,
        auth_failed => .refused,
        else => .other,
    };
}

/// One sentence a person can act on, or null when the number is all there is.
///
/// **`needs_unlock` and `no_keychain` are the two an SSH session meets**, and
/// they are different problems with different answers, so they never share a
/// sentence. A locked keychain is unlocked. An account with no keychain has
/// never logged in graphically, and no amount of unlocking makes one.
pub fn adviceFor(status: OSStatus) ?[]const u8 {
    return switch (meaningOf(status)) {
        .needs_unlock => "the keychain is locked and this session cannot ask anybody to unlock it. " ++
            "Run security unlock-keychain first, or log in on the desktop.",
        .no_keychain => "this account has no default keychain. A login keychain is made by a " ++
            "desktop login, so an account only ever reached over ssh has none.",
        .refused => "the keychain refused this process.",
        .ok, .absent, .other => null,
    };
}

const testing = std.testing;

test "the statuses this driver acts on are told apart" {
    try testing.expectEqual(Meaning.ok, meaningOf(success));
    try testing.expectEqual(Meaning.absent, meaningOf(item_not_found));
    try testing.expectEqual(Meaning.needs_unlock, meaningOf(interaction_not_allowed));
    try testing.expectEqual(Meaning.no_keychain, meaningOf(no_default_keychain));
    try testing.expectEqual(Meaning.refused, meaningOf(auth_failed));
    try testing.expectEqual(Meaning.other, meaningOf(-1));
    try testing.expectEqual(Meaning.other, meaningOf(duplicate_item));
}

test "an absent item is not a fault, so it carries no advice" {
    try testing.expectEqual(@as(?[]const u8, null), adviceFor(item_not_found));
    try testing.expectEqual(@as(?[]const u8, null), adviceFor(success));
}

test "a locked keychain and an account with none read as different problems" {
    const locked = adviceFor(interaction_not_allowed).?;
    const none = adviceFor(no_default_keychain).?;
    try testing.expect(!std.mem.eql(u8, locked, none));
    try testing.expect(std.mem.indexOf(u8, locked, "unlock-keychain") != null);
    try testing.expect(std.mem.indexOf(u8, none, "unlock-keychain") == null);
    try testing.expect(std.mem.indexOf(u8, none, "ssh") != null);
}

test "every status this file names is negative except success, and none collide" {
    const named = [_]OSStatus{ auth_failed, duplicate_item, item_not_found, no_default_keychain, interaction_not_allowed };
    for (named) |one| try testing.expect(one < 0);
    for (named, 0..) |one, i| {
        for (named[i + 1 ..]) |other| try testing.expect(one != other);
    }
}
