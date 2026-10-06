//! What both protocol versions spell the same way: a stop reason, a tool
//! kind, and a permission kind, kept here so there is one definition rather
//! than two that can drift.

const std = @import("std");

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

/// `other` is the default, for a tool that fits nothing else.
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

/// An `always` answer stands; `chock-policy`'s ratchet treats it as policy.
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

    pub fn isStanding(self: PermissionKind) bool {
        return switch (self) {
            .allow_always, .reject_always => true,
            .allow_once, .reject_once => false,
        };
    }
};

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

/// An alpha: spoken only if asked, never chosen over what they offered.
pub const newest: Version = .v2;

pub const oldest: Version = .v1;

/// Older than anything here gets null, never an invented version.
pub fn negotiate(client_version: u16) ?Version {
    if (client_version < oldest.number()) return null;
    if (client_version >= newest.number()) return newest;
    return Version.fromNumber(client_version);
}

const testing = std.testing;

test "the answer is the newest version both sides speak" {
    try testing.expectEqual(Version.v1, negotiate(1).?);
    try testing.expectEqual(Version.v2, negotiate(2).?);

    try testing.expectEqual(Version.v2, negotiate(3).?);
    try testing.expectEqual(Version.v2, negotiate(std.math.maxInt(u16)).?);

    try testing.expectEqual(@as(?Version, null), negotiate(0));
}

test "every version this speaks reads back as itself" {
    inline for (@typeInfo(Version).@"enum".fields) |field| {
        const one: Version = @enumFromInt(field.value);
        try testing.expectEqual(one, Version.fromNumber(one.number()).?);
        // Catches a version added but unreachable by `negotiate`.
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

    // All four, since a client may send the one docs left out.
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
    // Spot checks the schemas, so a rename fails here.
    try testing.expectEqualStrings("max_turn_requests", StopReason.max_turn_requests.wireName());
    try testing.expectEqualStrings("switch_mode", ToolKind.switch_mode.wireName());
}
