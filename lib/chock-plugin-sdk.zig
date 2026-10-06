//! The guest half of the plugin interface: what a plugin author imports.

const std = @import("std");
const core = @import("chock-plugin-core");

pub const tools = @import("chock-plugin-sdk/tools.zig");
pub const metadata = @import("chock-plugin-sdk/metadata.zig");
pub const exports = @import("chock-plugin-sdk/exports.zig");

pub const Metadata = metadata.Metadata;
pub const Tool = metadata.Tool;
pub const RunFn = metadata.RunFn;
pub const LocaleField = core.LocaleField;
pub const VersionConstraint = core.VersionConstraint;

pub const abi_version = core.AbiVersion.current;

pub const version: std.SemanticVersion = std.SemanticVersion.parse(
    @import("chock-version").text,
) catch @compileError("build.zig.zon states a version that is not semantic: " ++
    @import("chock-version").text);

test {
    std.testing.refAllDecls(@This());
}

test "the SDK version is the version the project ships" {
    const printed = try std.fmt.allocPrint(std.testing.allocator, "{f}", .{version});
    defer std.testing.allocator.free(printed);
    try std.testing.expectEqualStrings(@import("chock-version").text, printed);
}
