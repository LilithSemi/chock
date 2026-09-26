//! What both protocol versions spell the same way, and the rule that picks one.
//!
//! Three enums are identical in version 1 and version 2, checked against both
//! schemas: a stop reason, a tool kind, and a permission option kind. They live
//! here so there is one definition rather than two that can drift.
//!
//! What is not here differs between the versions and belongs to each: the method
//! table, the session update variants, the capability tree, and a tool call's
//! status, which version 2 adds `cancelled` to.

const std = @import("std");

/// Why a prompt turn ended.
pub const StopReason = enum {
    end_turn,
    max_tokens,
    max_turn_requests,
    refusal,
    cancelled,

    pub fn wireName(self: StopReason) []const u8 {
        return @tagName(self);
    }
};

/// What a tool call is, for a client choosing how to draw it. `other` is the
/// default, so a tool that fits none of the rest still reports something.
pub const ToolKind = enum {
    read,
    edit,
    delete,
    move,
    search,
    fetch,
    execute,
    think,
    switch_mode,
    other,

    pub fn wireName(self: ToolKind) []const u8 {
        return @tagName(self);
    }
};

/// What one answer to `session/request_permission` means.
///
/// An `always` answer is a standing permission rather than one reply. Chock
/// treats that as a change to the policy table, which is the ratchet's business:
/// see `lib/chock-policy` and `docs/configure/policy.md`.
pub const PermissionKind = enum {
    allow_once,
    allow_always,
    reject_once,
    reject_always,

    pub fn wireName(self: PermissionKind) []const u8 {
        return @tagName(self);
    }

    pub fn fromWireName(name: []const u8) ?PermissionKind {
        inline for (@typeInfo(PermissionKind).@"enum".fields) |field| {
            if (std.mem.eql(u8, field.name, name)) return @enumFromInt(field.value);
        }
        return null;
    }

    pub fn permits(self: PermissionKind) bool {
        return switch (self) {
            .allow_once, .allow_always => true,
            .reject_once, .reject_always => false,
        };
    }

    /// Whether this answer is meant to bind later calls as well as this one.
    pub fn isStanding(self: PermissionKind) bool {
        return switch (self) {
            .allow_always, .reject_always => true,
            .allow_once, .reject_once => false,
        };
    }
};

/// A protocol version Chock speaks.
pub const Version = enum(u16) {
    v1 = 1,
    v2 = 2,

    pub fn number(self: Version) u16 {
        return @intFromEnum(self);
    }

    pub fn fromNumber(value: u16) ?Version {
        return switch (value) {
            1 => .v1,
            2 => .v2,
            else => null,
        };
    }
};

/// The newest version Chock speaks. Version 2 is an alpha whose own fields moved
/// between alphas, so it is spoken when a client asks for it and never chosen
/// over a version the client offered.
pub const newest: Version = .v2;

/// The oldest version Chock speaks.
pub const oldest: Version = .v1;

/// Which version to answer a client with.
///
/// `initialize` carries the newest version the **client** supports, so the
/// answer is the newest version both sides have. A client newer than Chock is
/// answered with Chock's newest, which the protocol says is how an agent
/// declines a version it does not have. A client older than anything Chock
/// speaks gets null, and the caller refuses the connection: answering version 1
/// to a client that asked for 0 would be inventing a version it never offered.
pub fn negotiate(client_version: u16) ?Version {
    if (client_version < oldest.number()) return null;
    if (client_version >= newest.number()) return newest;
    return Version.fromNumber(client_version);
}

const testing = std.testing;

test "the answer is the newest version both sides speak" {
    // A client on the released version gets it, and is never pushed onto the
    // alpha.
    try testing.expectEqual(Version.v1, negotiate(1).?);
    try testing.expectEqual(Version.v2, negotiate(2).?);

    // A client newer than Chock is answered with Chock's newest, which is how
    // an agent says it does not have that version.
    try testing.expectEqual(Version.v2, negotiate(3).?);
    try testing.expectEqual(Version.v2, negotiate(std.math.maxInt(u16)).?);

    // And a client older than anything here is refused rather than answered
    // with a version it never offered.
    try testing.expectEqual(@as(?Version, null), negotiate(0));
}

test "every version this speaks reads back as itself" {
    inline for (@typeInfo(Version).@"enum".fields) |field| {
        const one: Version = @enumFromInt(field.value);
        try testing.expectEqual(one, Version.fromNumber(one.number()).?);
        // And it is one `negotiate` can answer, so a version cannot be added to
        // the enum and left unreachable.
        try testing.expect(negotiate(one.number()) != null);
    }
    try testing.expectEqual(@as(?Version, null), Version.fromNumber(99));
}

test "an always answer is a standing one, and a once answer is not" {
    try testing.expect(PermissionKind.allow_always.isStanding());
    try testing.expect(PermissionKind.reject_always.isStanding());
    try testing.expect(!PermissionKind.allow_once.isStanding());
    try testing.expect(!PermissionKind.reject_once.isStanding());

    try testing.expect(PermissionKind.allow_once.permits());
    try testing.expect(PermissionKind.allow_always.permits());
    try testing.expect(!PermissionKind.reject_once.permits());
    try testing.expect(!PermissionKind.reject_always.permits());

    // All four, because the documentation site lists three and both schemas
    // list four, and a client may send the one the page left out.
    for ([_][]const u8{ "allow_once", "allow_always", "reject_once", "reject_always" }) |name| {
        try testing.expect(PermissionKind.fromWireName(name) != null);
    }
    try testing.expectEqual(@as(?PermissionKind, null), PermissionKind.fromWireName("maybe"));
}

test "a shared enum spells itself the way both schemas do" {
    inline for (.{ StopReason, ToolKind, PermissionKind }) |Kind| {
        inline for (@typeInfo(Kind).@"enum".fields) |field| {
            const one: Kind = @enumFromInt(field.value);
            try testing.expectEqualStrings(field.name, one.wireName());
        }
    }
    // Spot checks against the schemas, so a rename shows up as a failure here.
    try testing.expectEqualStrings("max_turn_requests", StopReason.max_turn_requests.wireName());
    try testing.expectEqualStrings("switch_mode", ToolKind.switch_mode.wireName());
}
