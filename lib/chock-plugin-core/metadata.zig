//! What a plugin says about itself, as data alone: no function, `type`, or
//! pointer, so a host can build one from bytes. `wire.zig` carries it.

const std = @import("std");

const schema = @import("schema.zig");

pub const Property = schema.Property;
pub const Shape = schema.Shape;
pub const Kind = schema.Kind;

/// Not a promise that every later version works.
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

/// `locale` is a BCP 47 tag, such as `"en"` or `"pt-BR"`.
pub const LocaleField = struct {
    locale: []const u8,
    value: []const u8,

    pub fn eql(a: LocaleField, b: LocaleField) bool {
        if (!std.mem.eql(u8, a.locale, b.locale)) return false;
        return std.mem.eql(u8, a.value, b.value);
    }
};

/// Action names from `chock-policy/table.zig`; empty claims no outside effect.
pub const ToolDescriptor = struct {
    name: []const u8,
    description: []const LocaleField = &.{},
    capabilities: []const []const u8 = &.{},

    parameters: []const schema.Property = &.{},

    pub fn eql(a: ToolDescriptor, b: ToolDescriptor) bool {
        if (!std.mem.eql(u8, a.name, b.name)) return false;
        if (!localesEql(a.description, b.description)) return false;
        if (a.capabilities.len != b.capabilities.len) return false;
        for (a.capabilities, b.capabilities) |x, y| {
            if (!std.mem.eql(u8, x, y)) return false;
        }
        return schema.propertiesEql(a.parameters, b.parameters);
    }
};

pub const Metadata = struct {
    name: []const u8,
    version: std.SemanticVersion,
    chock_version: VersionConstraint,
    author: []const u8,
    description: []const LocaleField = &.{},
    tools: []const ToolDescriptor = &.{},

    /// The guest symbol for the serialized form.
    pub const symbol = "chock_plugin_metadata";

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

/// `order` ignores `build`; `pre` compares by precedence, not text.
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
    // Null `pre` and `pre = ""` differ; `order` can't tell them apart.
    const absent: std.SemanticVersion = .{ .major = 1, .minor = 0, .patch = 0 };
    const empty: std.SemanticVersion = .{ .major = 1, .minor = 0, .patch = 0, .pre = "" };
    try std.testing.expect(!versionExtraEql(absent, empty));
    try std.testing.expect(versionExtraEql(empty, empty));
}

test "eql sees a build tag that order ignores" {
    const a: std.SemanticVersion = .{ .major = 1, .minor = 2, .patch = 3, .build = "abc" };
    const b: std.SemanticVersion = .{ .major = 1, .minor = 2, .patch = 3, .build = "def" };
    try std.testing.expectEqual(std.math.Order.eq, a.order(b));
    try std.testing.expect(!versionExtraEql(a, b));
}

test "a tool that declares no capability differs from one that declares one" {
    const quiet: ToolDescriptor = .{ .name = "hello" };
    const loud: ToolDescriptor = .{ .name = "hello", .capabilities = &.{"fs.read"} };
    try std.testing.expect(!quiet.eql(loud));
    try std.testing.expect(quiet.eql(.{ .name = "hello", .capabilities = &.{} }));
}

test "eql compares locale and value separately" {
    const one: LocaleField = .{ .locale = "en", .value = "a" };
    const two: LocaleField = .{ .locale = "a", .value = "en" };
    try std.testing.expect(!one.eql(two));
}

test "a null ceiling and a stated ceiling are different constraints" {
    const open: VersionConstraint = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } };
    const closed: VersionConstraint = .{
        .min = .{ .major = 0, .minor = 1, .patch = 0 },
        .max = .{ .major = 9, .minor = 0, .patch = 0 },
    };
    try std.testing.expect(!open.eql(closed));
}

test "a tool that takes a field differs from one that takes none" {
    const bare: ToolDescriptor = .{ .name = "greet" };
    const typed: ToolDescriptor = .{
        .name = "greet",
        .parameters = &.{.{
            .name = "who",
            .description = "Who to greet.",
            .required = true,
            .shape = .{ .kind = .string },
        }},
    };
    try std.testing.expect(!bare.eql(typed));
    try std.testing.expect(bare.eql(.{ .name = "greet", .parameters = &.{} }));
}
