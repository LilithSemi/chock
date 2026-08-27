//! The guest side, driven against the plugin the project actually ships.
//!
//! `plugins/hello.zig` arrives here as the module `chock-plugin`, and the
//! declaration below emits the three guest symbols into this test binary. The
//! tests then read the very bytes a real plugin carries rather than a copy
//! built for the occasion.
//!
//! The instantiation is by hand because the root of a `zig test` binary is the
//! test runner, not this file, so the SDK's automatic path cannot see the
//! plugin. See `lib/chock-plugin-sdk/exports.zig`.
//!
//! This binary is native, not wasm. The format carries no target: every field
//! is little endian with a stated width, so a blob written on one target reads
//! the same on another. `test/plugin/wasm.zig` reads the same plugin out of a
//! real `wasm32-freestanding` module beside this.

const std = @import("std");
const core = @import("chock-plugin-core");
const sdk = @import("chock-plugin-sdk");
const hello = @import("chock-plugin");

const plugin = sdk.exports.Exports(hello.chock_plugin_metadata);

comptime {
    _ = plugin;
}

const testing = std.testing;

test "no tool is bound until chock_plugin_init runs" {
    // Runs first on purpose: Zig runs the tests of a file in the order they
    // are written, and this is the only moment before the call below. A host
    // that skipped `chock_plugin_init` must get no entry points, never
    // uninitialised ones.
    try testing.expectEqual(@as(usize, 0), plugin.boundTools().len);
}

test "chock_plugin_init binds one entry per declared tool" {
    // Called through the exported symbol and not through the Zig declaration,
    // so this is the same call a host makes.
    const init = @extern(*const fn () callconv(.c) u32, .{ .name = core.init_symbol });
    try testing.expectEqual(@as(u32, 1), init());
    try testing.expectEqual(@as(usize, 1), plugin.boundTools().len);
    try testing.expectEqualStrings("hello", plugin.boundTools()[0].name);
}

test "the bound entry reaches the author's own tool body" {
    // The tool body lives in `plugins/hello.zig` and the thunk around it is
    // generated, so the answer below can only have come from the real body.
    const init = @extern(*const fn () callconv(.c) u32, .{ .name = core.init_symbol });
    _ = init();

    const Args = hello.chock_plugin_metadata.tools[0].type;
    const args: Args = .{};
    const answer = plugin.boundTools()[0].call(.{ .tool = "hello" }, &args);
    try testing.expectEqual(sdk.tools.Outcome.success, answer.outcome);
    try testing.expectEqualStrings("Hello, world!", answer.text);
}

test "chock_plugin_magic carries the ABI version this SDK writes" {
    // The symbol's name is the magic and its value is the version. A module
    // with no such symbol is not a Chock plugin at all, which is a different
    // failure from a number this Chock does not know.
    const word = @extern(*const u32, .{ .name = core.Magic.symbol });
    try testing.expectEqual(@intFromEnum(core.AbiVersion.current), word.*);
    try testing.expectEqual(core.AbiVersion.v1, core.abiVersion(word.*).?);
}

/// The exported blob, found the way a host finds it: read the fixed prefix
/// first, take the length out of it, and only then look at that many bytes.
fn exportedBlob() []const u8 {
    const head = @extern(*const [core.Prefix.len]u8, .{ .name = core.Metadata.symbol });
    const prefix = core.Prefix.read(head, null) catch unreachable;
    const whole: [*]const u8 = @ptrCast(head);
    return whole[0..prefix.total_len];
}

test "the exported blob parses back to the metadata the author declared" {
    // The acceptance test of the guest half: what `plugins/hello.zig` says
    // about itself is what a host reads out of the built plugin, with nothing
    // added, dropped, or reordered.
    var parsed = try core.parse(testing.allocator, exportedBlob(), null);
    defer parsed.deinit();

    try testing.expect(plugin.record.eql(parsed.record));

    try testing.expectEqualStrings("hello", parsed.record.name);
    try testing.expectEqualStrings("Tristan Ross <tristan.ross@midstall.com>", parsed.record.author);
    try testing.expectEqual(@as(usize, 1), parsed.record.description.len);
    try testing.expectEqualStrings("en", parsed.record.description[0].locale);
    try testing.expectEqualStrings("A simple hello world plugin", parsed.record.description[0].value);
    try testing.expectEqual(@as(usize, 1), parsed.record.tools.len);
    try testing.expectEqualStrings("hello", parsed.record.tools[0].name);
    try testing.expectEqual(@as(usize, 1), parsed.record.tools[0].description.len);
    try testing.expectEqualStrings("A simple hello world tool", parsed.record.tools[0].description[0].value);
    // hello declares no capability, so the host may hold it to changing
    // nothing outside itself.
    try testing.expectEqual(@as(usize, 0), parsed.record.tools[0].capabilities.len);
}

test "the exported blob states the Chock the plugin was built against" {
    // `plugins/hello.zig` writes `chock_plugin_sdk.version` and keeps no
    // number of its own, so a host reads a real version out of the blob.
    var parsed = try core.parse(testing.allocator, exportedBlob(), null);
    defer parsed.deinit();
    try testing.expectEqual(std.math.Order.eq, sdk.version.order(parsed.record.chock_version.min));
    try testing.expectEqual(std.math.Order.eq, sdk.version.order(parsed.record.chock_version.rec.?));
    try testing.expectEqual(@as(?std.SemanticVersion, null), parsed.record.chock_version.max);
}

test "the exported blob begins with the fixed prefix" {
    // A host reads these twelve bytes with no engine, no linear memory, and
    // no call into the plugin. They are the same three fields at the same
    // three offsets in every ABI.
    const blob = exportedBlob();
    try testing.expect(blob.len > core.Prefix.len);
    try testing.expectEqualSlices(u8, &.{ 'C', 'H', 'K', 0x9E }, blob[0..4]);
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, blob[4..8], .little));
    try testing.expectEqual(@as(u32, @intCast(blob.len)), std.mem.readInt(u32, blob[8..12], .little));
}
