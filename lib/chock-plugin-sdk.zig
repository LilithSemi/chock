//! The guest half of the plugin interface: what a plugin author imports.
//!
//! A plugin is one Zig file that declares `chock_plugin_metadata` and nothing
//! else. `plugins/hello.zig` is the whole shape:
//!
//! ```zig
//! const chock_plugin_sdk = @import("chock-plugin-sdk");
//!
//! const HelloTool = struct {
//!     pub fn run(ctx: chock_plugin_sdk.tools.Context, args: HelloTool) chock_plugin_sdk.tools.Result {
//!         return ctx.successResult("Hello, world!");
//!     }
//! };
//!
//! pub const chock_plugin_metadata: chock_plugin_sdk.Metadata = .{ ... };
//! ```
//!
//! This SDK is a compiler and not a header. It reads that declaration while
//! the plugin compiles, lowers it to the data only form in
//! `chock-plugin-core`, serialises it into a constant array, and emits the
//! three guest symbols. See `lib/chock-plugin-sdk/exports.zig`.
//!
//! ## What runs, and when
//!
//! Reading a plugin's metadata never runs a plugin. The blob and the ABI
//! version are constants a host reads out of the module, so a host inspects a
//! plugin and then refuses it, rather than running it to learn whether to run
//! it. `chock_plugin_init` binds the tool bodies and is the only thing a
//! plugin ever executes before the host has accepted it.
//!
//! ## Building a plugin
//!
//! The root source file of a plugin binary is
//! `lib/chock-plugin-sdk/start.zig`, not the author's own file. Zig analyses a
//! declaration only when something reaches it, and an author's file reaches
//! nothing, so a plugin built with the author's file as the root would emit no
//! symbols at all. `start.zig` names both halves and keeps the author's file a
//! plain declaration. `build.zig` shows the arrangement.

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

/// The plugin ABI this SDK writes. A plugin built with this SDK is refused by
/// a Chock that speaks another number, with a message naming both.
pub const abi_version = core.AbiVersion.current;

/// The Chock this SDK was built from. An author writes
/// `.chock_version = .{ .min = chock_plugin_sdk.version }` to say "the Chock I
/// built against", without having to keep a number of their own in step.
///
/// The text comes from `build.zig.zon` by way of `build.zig`, which is the one
/// file that can read the manifest. A copy of the number here would drift the
/// first time the project is released.
pub const version: std.SemanticVersion = std.SemanticVersion.parse(
    @import("chock-version").text,
) catch @compileError("build.zig.zon states a version that is not semantic: " ++
    @import("chock-version").text);

test {
    std.testing.refAllDecls(@This());
}

test "the SDK version is the version the project ships" {
    // `version` lands in every plugin's `chock_version`, so a wrong number
    // here makes every plugin lie about what it was built against.
    const printed = try std.fmt.allocPrint(std.testing.allocator, "{f}", .{version});
    defer std.testing.allocator.free(printed);
    try std.testing.expectEqualStrings(@import("chock-version").text, printed);
}
