//! What a plugin says about itself, as data alone.
//!
//! Every type here is a plain value. Nothing here holds a function, a `type`,
//! or a pointer into a guest module, because the host must be able to build
//! one of these out of bytes it read from a file. The author facing shape,
//! which does hold a `type` and a `run` function, lives in
//! `chock-plugin-sdk`, and the SDK lowers it to this at compile time.
//!
//! The split is the point. A host reads a `Metadata` to decide whether to load
//! a plugin at all, so a `Metadata` must never need the plugin to run, and it
//! must never need the plugin's own compiled layout. See
//! `lib/chock-plugin-core/wire.zig` for the format that carries it.

const std = @import("std");

/// The range of Chock a plugin says it works with.
///
/// `min` is required, because a plugin that names no floor gives a host
/// nothing to refuse on. `rec` is the version the author tested against, and
/// `max` is a known ceiling. A null `max` means the author knows no ceiling,
/// which is not the same as promising every later version works.
pub const VersionConstraint = struct {
    min: std.SemanticVersion,
    rec: ?std.SemanticVersion = null,
    max: ?std.SemanticVersion = null,

    pub fn eql(a: VersionConstraint, b: VersionConstraint) bool {
        if (a.min.order(b.min) != .eq) return false;
        if (!optionalVersionEql(a.rec, b.rec)) return false;
        return optionalVersionEql(a.max, b.max);
    }
};

/// One translation of one piece of text. `locale` is a BCP 47 tag, such as
/// `"en"` or `"pt-BR"`. Chock does not translate anything itself, so a locale
/// it does not hold is a locale the author did not supply.
pub const LocaleField = struct {
    locale: []const u8,
    value: []const u8,

    pub fn eql(a: LocaleField, b: LocaleField) bool {
        if (!std.mem.eql(u8, a.locale, b.locale)) return false;
        return std.mem.eql(u8, a.value, b.value);
    }
};

/// One tool a plugin offers, as the host reads it.
///
/// `capabilities` is the part with consequence. Each entry is an action name
/// in the same language `lib/chock-policy/table.zig` uses for its `action`
/// key, such as `"fs.read"` or `"git.commit"`, so a plugin tool sits on the
/// policy table beside every built in tool instead of beside it. An empty set
/// is a claim that the tool changes nothing outside itself, and the host is
/// free to hold the plugin to that claim.
///
/// The declaration arrives before anything runs, which is the whole reason the
/// metadata is readable without an engine.
pub const ToolDescriptor = struct {
    name: []const u8,
    description: []const LocaleField = &.{},
    capabilities: []const []const u8 = &.{},

    pub fn eql(a: ToolDescriptor, b: ToolDescriptor) bool {
        if (!std.mem.eql(u8, a.name, b.name)) return false;
        if (!localesEql(a.description, b.description)) return false;
        if (a.capabilities.len != b.capabilities.len) return false;
        for (a.capabilities, b.capabilities) |x, y| {
            if (!std.mem.eql(u8, x, y)) return false;
        }
        return true;
    }
};

/// Everything a host learns about a plugin before it decides to load it.
pub const Metadata = struct {
    name: []const u8,
    version: std.SemanticVersion,
    chock_version: VersionConstraint,
    author: []const u8,
    description: []const LocaleField = &.{},
    tools: []const ToolDescriptor = &.{},

    /// The name of the guest symbol that carries the serialised form of this.
    /// See `lib/chock-plugin-core/wire.zig` for the bytes behind it.
    pub const symbol = "chock_plugin_metadata";

    /// Whether two records say the same thing, field for field. This is what
    /// makes a round trip through `wire.serialize` and `wire.parse` a fact a
    /// test can assert rather than a hope.
    pub fn eql(a: Metadata, b: Metadata) bool {
        if (!std.mem.eql(u8, a.name, b.name)) return false;
        if (a.version.order(b.version) != .eq) return false;
        if (!versionExtraEql(a.version, b.version)) return false;
        if (!a.chock_version.eql(b.chock_version)) return false;
        if (!std.mem.eql(u8, a.author, b.author)) return false;
        if (!localesEql(a.description, b.description)) return false;
        if (a.tools.len != b.tools.len) return false;
        for (a.tools, b.tools) |x, y| {
            if (!x.eql(y)) return false;
        }
        return true;
    }
};

fn localesEql(a: []const LocaleField, b: []const LocaleField) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!x.eql(y)) return false;
    }
    return true;
}

/// `std.SemanticVersion.order` reads `pre` but not `build`, and it compares
/// `pre` by precedence and not by text. A round trip must keep the exact
/// bytes, so this compares both strings directly.
fn versionExtraEql(a: std.SemanticVersion, b: std.SemanticVersion) bool {
    if (!optionalStringEql(a.pre, b.pre)) return false;
    return optionalStringEql(a.build, b.build);
}

fn optionalVersionEql(a: ?std.SemanticVersion, b: ?std.SemanticVersion) bool {
    if (a == null or b == null) return a == null and b == null;
    if (a.?.order(b.?) != .eq) return false;
    return versionExtraEql(a.?, b.?);
}

fn optionalStringEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

test "eql separates an absent pre release from an empty one" {
    // A null `pre` and a `pre` of "" are different declarations, and the wire
    // format keeps them apart, so `eql` must too. `order` cannot see the
    // difference on its own.
    const absent: std.SemanticVersion = .{ .major = 1, .minor = 0, .patch = 0 };
    const empty: std.SemanticVersion = .{ .major = 1, .minor = 0, .patch = 0, .pre = "" };
    try std.testing.expect(!versionExtraEql(absent, empty));
    try std.testing.expect(versionExtraEql(empty, empty));
}

test "eql sees a build tag that order ignores" {
    // `std.SemanticVersion.order` reads neither `build` nor the text of
    // `pre`, so a metadata comparison built on `order` alone would call two
    // different declarations the same.
    const a: std.SemanticVersion = .{ .major = 1, .minor = 2, .patch = 3, .build = "abc" };
    const b: std.SemanticVersion = .{ .major = 1, .minor = 2, .patch = 3, .build = "def" };
    try std.testing.expectEqual(std.math.Order.eq, a.order(b));
    try std.testing.expect(!versionExtraEql(a, b));
}

test "a tool that declares no capability differs from one that declares one" {
    // The capability set is what puts a plugin tool on the policy table, so a
    // comparison that skipped it would let a widened tool pass as unchanged.
    const quiet: ToolDescriptor = .{ .name = "hello" };
    const loud: ToolDescriptor = .{ .name = "hello", .capabilities = &.{"fs.read"} };
    try std.testing.expect(!quiet.eql(loud));
    try std.testing.expect(quiet.eql(.{ .name = "hello", .capabilities = &.{} }));
}

test "eql compares locale and value separately" {
    // Two descriptions that share their bytes in a different arrangement, such
    // as locale "en" with value "a" against locale "a" with value "en", must
    // not compare equal. A comparison that concatenated the two fields would
    // call them the same.
    const one: LocaleField = .{ .locale = "en", .value = "a" };
    const two: LocaleField = .{ .locale = "a", .value = "en" };
    try std.testing.expect(!one.eql(two));
}

test "a null ceiling and a stated ceiling are different constraints" {
    // A null `max` says the author knows no ceiling. It does not say every
    // later version works, so it must never compare equal to a stated one.
    const open: VersionConstraint = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } };
    const closed: VersionConstraint = .{
        .min = .{ .major = 0, .minor = 1, .patch = 0 },
        .max = .{ .major = 9, .minor = 0, .patch = 0 },
    };
    try std.testing.expect(!open.eql(closed));
}
