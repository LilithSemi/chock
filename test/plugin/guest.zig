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
    const declared = hello.chock_plugin_metadata.tools.len;
    const init = @extern(*const fn () callconv(.c) u32, .{ .name = core.init_symbol });
    try testing.expectEqual(@as(u32, declared), init());
    try testing.expectEqual(declared, plugin.boundTools().len);
    try testing.expectEqualStrings("hello", plugin.boundTools()[0].name);
    try testing.expectEqualStrings("greet", plugin.boundTools()[1].name);
}

test "a tool that takes arguments is handed them as its own type" {
    // **The acceptance test of the guest half of argument schemas.** The body
    // in `plugins/hello.zig` answers `args.who`, so the string below can only
    // have come out of the record, through the generated thunk, and into a
    // field of the tool's own struct.
    //
    // The bytes are what `chock_plugin_core.args` writes for one required
    // string and one absent flag: present, a length of four, the four letters,
    // and an absent byte.
    const init = @extern(*const fn () callconv(.c) u32, .{ .name = core.init_symbol });
    _ = init();

    const record = "\x01\x04\x00\x00\x00Ross\x00";
    const answer = plugin.boundTools()[1].call(.{ .tool = "greet", .arguments = record });
    try testing.expectEqual(sdk.tools.Outcome.success, answer.outcome);
    try testing.expectEqualStrings("Ross", answer.text);
}

test "a record the tool cannot read is a failure and never a guess" {
    // A body that ran on a value nobody wrote would answer something the model
    // then builds on. The thunk has to refuse instead, and say so.
    const init = @extern(*const fn () callconv(.c) u32, .{ .name = core.init_symbol });
    _ = init();

    // A present byte with a length that runs past the end of the record.
    const truncated = "\x01\xff\x00\x00\x00Ross";
    const answer = plugin.boundTools()[1].call(.{ .tool = "greet", .arguments = truncated });
    try testing.expectEqual(sdk.tools.Outcome.failure, answer.outcome);
    try testing.expectEqualStrings(
        "the arguments for \"greet\" are not a record this plugin can read",
        answer.text,
    );
}

test "a tool that takes nothing is called with nothing, exactly as before" {
    // The ordinary plugin. Schemas must not have made a tool that takes no
    // argument need one.
    const init = @extern(*const fn () callconv(.c) u32, .{ .name = core.init_symbol });
    _ = init();

    const answer = plugin.boundTools()[0].call(.{ .tool = "hello" });
    try testing.expectEqual(sdk.tools.Outcome.success, answer.outcome);
    try testing.expectEqualStrings("Hello, world!", answer.text);
}

test "the bound entry reaches the author's own tool body" {
    // The tool body lives in `plugins/hello.zig` and the thunk around it is
    // generated, so the answer below can only have come from the real body.
    const init = @extern(*const fn () callconv(.c) u32, .{ .name = core.init_symbol });
    _ = init();

    const answer = plugin.boundTools()[0].call(.{ .tool = "hello" });
    try testing.expectEqual(sdk.tools.Outcome.success, answer.outcome);
    try testing.expectEqualStrings("Hello, world!", answer.text);
}

test "chock_plugin_magic carries the ABI version this SDK writes" {
    // The symbol's name is the magic and its value is the version. A module
    // with no such symbol is not a Chock plugin at all, which is a different
    // failure from a number this Chock does not know.
    const word = @extern(*const u32, .{ .name = core.Magic.symbol });
    try testing.expectEqual(@intFromEnum(core.AbiVersion.current), word.*);
    try testing.expectEqual(core.AbiVersion.current, core.abiVersion(word.*).?);
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
    try testing.expectEqual(@as(usize, 2), parsed.record.tools.len);
    try testing.expectEqualStrings("hello", parsed.record.tools[0].name);
    try testing.expectEqual(@as(usize, 1), parsed.record.tools[0].description.len);
    try testing.expectEqualStrings("A simple hello world tool", parsed.record.tools[0].description[0].value);
    // hello declares no capability, so the host may hold it to changing
    // nothing outside itself.
    try testing.expectEqual(@as(usize, 0), parsed.record.tools[0].capabilities.len);
    // And it takes nothing, which is a thing the record now says outright
    // rather than by saying nothing.
    try testing.expectEqual(@as(usize, 0), parsed.record.tools[0].parameters.len);
}

test "the exported blob carries what a tool takes, field by field" {
    // **The acceptance test of the discovery half.** `plugins/hello.zig`
    // declares `greet` with a required string and an optional flag, and a host
    // reads all of that out of the built plugin with no engine anywhere near
    // it. A schema that did not travel would leave the model told a tool takes
    // nothing while the tool needs a name.
    var parsed = try core.parse(testing.allocator, exportedBlob(), null);
    defer parsed.deinit();

    const greet = parsed.record.tools[1];
    try testing.expectEqualStrings("greet", greet.name);
    try testing.expectEqual(@as(usize, 2), greet.parameters.len);

    try testing.expectEqualStrings("who", greet.parameters[0].name);
    try testing.expectEqualStrings("The name to greet.", greet.parameters[0].description);
    try testing.expect(greet.parameters[0].required);
    try testing.expectEqual(core.Kind.string, greet.parameters[0].shape.kind);

    try testing.expectEqualStrings("loudly", greet.parameters[1].name);
    try testing.expectEqualStrings("True to shout the greeting.", greet.parameters[1].description);
    try testing.expect(!greet.parameters[1].required);
    try testing.expectEqual(core.Kind.boolean, greet.parameters[1].shape.kind);
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
    try testing.expectEqual(
        @as(u32, @intFromEnum(core.AbiVersion.current)),
        std.mem.readInt(u32, blob[4..8], .little),
    );
    try testing.expectEqual(@as(u32, @intCast(blob.len)), std.mem.readInt(u32, blob[8..12], .little));
}
