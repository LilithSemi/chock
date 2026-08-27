//! The plugin the project ships, read back out of a real
//! `wasm32-freestanding` module by the host side reader.
//!
//! `test/plugin/guest.zig` drives the guest half inside a native binary, where
//! it instantiates the SDK's exports by hand. That leaves two things untested,
//! and both are easy to get wrong.
//!
//! - The SDK's automatic path, where `lib/chock-plugin-sdk/exports.zig` reads
//!   `@import("root").chock_plugin_metadata` and emits the symbols with nobody
//!   asking it to. A plugin built the wrong way compiles and exports nothing
//!   at all, so only a look at the built module can tell.
//! - `chock_core.plugin_module`, which walks a module's sections and resolves
//!   the metadata out of its data segments. **That reader must work on what a
//!   real linker emits and not on what a test would emit.** Vulcan's own
//!   eighty three wasm tests were all hand built byte blobs, which is exactly
//!   why it could not run a single module from a real toolchain for years.
//!
//! So every test here starts from the module `build.zig` really builds, and
//! the ones that check a refusal reach it by changing one thing in that
//! module. Each of them says what it changed and what that stands for.
//!
//! **Nothing here runs the plugin**, and that is the design and not a gap:
//! reading a plugin executes no guest code, so a host learns a plugin's tools
//! and prices them before anything of it runs. See `lib/chock-core/plugin.zig`.
//! The engine lives in the plugin host process, which `test/plugin/engine.zig`
//! drives.

const std = @import("std");
const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");
const core = @import("chock-plugin-core");
const hello = @import("chock-plugin");
const wasm_path = @import("plugin_wasm_path").plugin_wasm_path;

const plugin = chock_core.plugin;
const plugin_module = chock_core.plugin_module;

/// The most this test will read off disk, which is the bound the host side
/// reader keeps as well. One number, so a module the reader would accept can
/// never be one this test refuses to read.
const max_module_bytes = plugin_module.max_module_bytes;

const testing = std.testing;

fn readModule(gpa: std.mem.Allocator) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        wasm_path,
        gpa,
        .limited(max_module_bytes),
    );
}

/// Where the metadata blob starts inside the module's own bytes.
///
/// Every blob starts with the magic word, so a search for it finds the
/// candidates. The magic can appear by chance in half a megabyte of debug
/// information, so each candidate is offered to the blob reader and the first
/// one that reads is the answer.
///
/// **This is a test looking for a needle in a file, and not how the host finds
/// the blob.** The host resolves the address the `chock_plugin_metadata`
/// global holds: see `chock_core.plugin_module`. The two roads meeting at the
/// same bytes is what one of the tests below states.
fn findBlob(module: []const u8) !usize {
    var magic_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &magic_bytes, core.Magic.word, .little);

    var at: usize = 0;
    while (std.mem.indexOfPos(u8, module, at, &magic_bytes)) |found| {
        at = found + 1;
        var parsed = core.parse(testing.allocator, module[found..], null) catch continue;
        parsed.deinit();
        return found;
    }
    return error.NoMetadataInModule;
}

/// A policy that allows everything, and one that denies one action.
const Decider = struct {
    denied: []const u8 = "",
    asked: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *Decider) void {
        for (self.asked.items) |one| testing.allocator.free(one);
        self.asked.deinit(testing.allocator);
    }

    fn decider(self: *Decider) plugin.Decider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = plugin.Decider.VTable{ .decide = decideFn };

    fn decideFn(ptr: *anyopaque, tool: []const u8, action: []const u8) chock_policy.table.Decision {
        const self: *Decider = @ptrCast(@alignCast(ptr));
        _ = tool;
        self.asked.append(testing.allocator, testing.allocator.dupe(u8, action) catch return .deny) catch
            return .deny;
        if (self.denied.len != 0 and std.mem.eql(u8, action, self.denied)) return .deny;
        return .allow;
    }

    fn sawAction(self: *const Decider, action: []const u8) bool {
        for (self.asked.items) |one| {
            if (std.mem.eql(u8, one, action)) return true;
        }
        return false;
    }
};

fn sentence(refusal: plugin_module.Refusal) ![]u8 {
    var text: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer text.deinit();
    try refusal.format(&text.writer);
    return text.toOwnedSlice();
}

test "the host side reader reads the real module as the author wrote it" {
    // The acceptance test. An author's declaration, the SDK's automatic path,
    // a wasm32-freestanding build, a linker, and a reader that starts no
    // engine, end to end.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);

    var read = try plugin_module.read(testing.allocator, module, null);
    defer read.deinit();

    const declared = comptime hello.chock_plugin_metadata.lower();
    try testing.expect(declared.eql(read.record()));
    try testing.expectEqualStrings("hello", read.record().name);
    try testing.expectEqualStrings("A simple hello world plugin", read.record().description[0].value);
    try testing.expectEqual(@as(usize, 1), read.record().tools.len);
    try testing.expectEqualStrings("hello", read.record().tools[0].name);
    try testing.expectEqual(@as(u32, @intFromEnum(core.AbiVersion.current)), read.abi_word);
    try testing.expectEqual(core.AbiVersion.current, read.parsed.abi_version);
}

test "the two roads to the blob meet at the same bytes" {
    // The reader resolves the address the `chock_plugin_metadata` global
    // holds. This test finds the blob by searching the file for the magic
    // word, which is a different road entirely, and the record read by each
    // must be the same. A reader that resolved the wrong address would still
    // pass the test above if the wrong address happened to hold a blob.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);

    var read = try plugin_module.read(testing.allocator, module, null);
    defer read.deinit();

    var searched = try core.parse(testing.allocator, module[try findBlob(module)..], null);
    defer searched.deinit();

    try testing.expect(searched.record.eql(read.record()));
}

test "the real linker exports the metadata as a global holding an address" {
    // The whole reader rests on this. `@export(&blob, ...)` is a data export,
    // and on wasm32 the linker turns one into an **exported global whose value
    // is the address**, not into the bytes. A reader written for a linker that
    // did something else would resolve nothing.
    //
    // The export section comes before every custom section in this module, so
    // the first time the name appears is in the export section. The kind byte
    // that follows it is checked rather than assumed, which is what makes the
    // change below mean what it says.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);

    const named = std.mem.indexOf(u8, module, core.Metadata.symbol).?;
    const kind_at = named + core.Metadata.symbol.len;
    try testing.expectEqual(
        plugin_module.ExportKind.global,
        @as(plugin_module.ExportKind, @enumFromInt(module[kind_at])),
    );

    module[kind_at] = @intFromEnum(plugin_module.ExportKind.function);
    var refusal: ?plugin_module.Refusal = null;
    try testing.expectError(
        error.IncompletePlugin,
        plugin_module.read(testing.allocator, module, &refusal),
    );
    const text = try sentence(refusal.?);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        "the module exports chock_plugin_metadata as a function, " ++
            "and a plugin exports it as a global",
        text,
    );
}

test "the module really is wasm" {
    // The blob would read the same out of a native binary, so this pins that
    // the file under it was built for the target a plugin actually runs on.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);
    try testing.expectEqualSlices(u8, &plugin_module.wasm_preamble, module[0..4]);
}

test "a real module built for another plugin ABI is refused with both numbers" {
    // The failure that happens constantly: a plugin built for another Chock.
    // The module states its ABI twice, in the `chock_plugin_magic` global and
    // in the blob's own prefix, and both are moved here so the refusal is
    // about the ABI and not about the two disagreeing.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);
    const blob_at = try findBlob(module);

    // The `chock_plugin_magic` global holds the four bytes in front of the
    // blob. Measured on this module, and asserted rather than assumed: if the
    // linker ever lays the two out differently, this fails here and says so
    // instead of quietly testing half of what it says it tests.
    try testing.expectEqual(
        @as(u32, @intFromEnum(core.AbiVersion.current)),
        std.mem.readInt(u32, module[blob_at - 4 ..][0..4], .little),
    );

    std.mem.writeInt(u32, module[blob_at - 4 ..][0..4], 7, .little);
    std.mem.writeInt(u32, module[blob_at + core.Prefix.abi_version_offset ..][0..4], 7, .little);

    var refusal: ?plugin_module.Refusal = null;
    try testing.expectError(
        error.UnknownAbiVersion,
        plugin_module.read(testing.allocator, module, &refusal),
    );
    const text = try sentence(refusal.?);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        "built for plugin ABI 7, this Chock speaks plugin ABI 1: rebuild the plugin",
        text,
    );
}

test "a real module whose two ABI numbers disagree is refused" {
    // Only the blob's own prefix is moved. A reader that read one of the two
    // numbers and trusted it would take this module for a plugin of whichever
    // number it happened to read.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);
    const blob_at = try findBlob(module);
    std.mem.writeInt(u32, module[blob_at + core.Prefix.abi_version_offset ..][0..4], 7, .little);

    var refusal: ?plugin_module.Refusal = null;
    try testing.expectError(
        error.AbiDisagrees,
        plugin_module.read(testing.allocator, module, &refusal),
    );
    const text = try sentence(refusal.?);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        "the module says it is plugin ABI 1 and its metadata says ABI 7",
        text,
    );
}

test "a real module with the magic word struck out of its blob is not a plugin" {
    // The magic is checked before any length prefixed read. A blob that is not
    // ours must never hand this reader a length to trust, and the module is
    // otherwise a perfectly good plugin, which is what makes this the case a
    // reader could get away with skipping.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);
    const blob_at = try findBlob(module);
    std.mem.writeInt(u32, module[blob_at..][0..4], 0xDEAD_BEEF, .little);

    var refusal: ?plugin_module.Refusal = null;
    try testing.expectError(
        error.NotAPlugin,
        plugin_module.read(testing.allocator, module, &refusal),
    );
    const text = try sentence(refusal.?);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        "not a Chock plugin: the metadata starts with 0xDEADBEEF, " ++
            "and every Chock plugin starts with 0x9E4B4843",
        text,
    );
}

test "a real module whose blob states four gigabytes is refused before it is allocated" {
    // The length is the first number in a blob a reader could act on, and it
    // comes from a file somebody else wrote. A reader that allocated first
    // would ask for four gigabytes on the word of a half megabyte file.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);
    const blob_at = try findBlob(module);
    std.mem.writeInt(
        u32,
        module[blob_at + core.Prefix.total_len_offset ..][0..4],
        std.math.maxInt(u32),
        .little,
    );

    var refusal: ?plugin_module.Refusal = null;
    try testing.expectError(
        error.TooLarge,
        plugin_module.read(testing.allocator, module, &refusal),
    );
    try testing.expectEqual(@as(u64, core.wire.max_blob_bytes), refusal.?.metadata.too_large.bound);
    try testing.expectEqual(@as(u64, std.math.maxInt(u32)), refusal.?.metadata.too_large.found);
}

test "a real module cut short is refused" {
    // Half a file is not a plugin. Nothing in the head of the module says the
    // tail is missing, so a reader that trusted a section length would walk
    // off the end of the buffer here.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);

    var refusal: ?plugin_module.Refusal = null;
    try testing.expectError(
        error.MalformedModule,
        plugin_module.read(testing.allocator, module[0 .. module.len / 2], &refusal),
    );
    try testing.expect(refusal.? == .malformed_module);

    // And one byte short, which is the cut a reader is most likely to survive
    // by accident.
    var short: ?plugin_module.Refusal = null;
    try testing.expectError(
        error.MalformedModule,
        plugin_module.read(testing.allocator, module[0 .. module.len - 1], &short),
    );
}

test "a file of the right length full of zeros is not a plugin" {
    // A zeroed page, or a file that failed to be written. It must be refused
    // at the first field, before any length in it is trusted.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);
    @memset(module, 0);

    try testing.expectError(error.NotWasm, plugin_module.read(testing.allocator, module, null));
}

test "a real module that exports no chock_plugin_magic is not a Chock plugin" {
    // The symbol name is the magic, so striking the name out of the export
    // section is the whole of what makes a module not a plugin. The name is
    // replaced everywhere it appears, so the debug information cannot leave a
    // copy behind for a reader to find by searching.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);

    var at: usize = 0;
    var replaced: usize = 0;
    while (std.mem.indexOfPos(u8, module, at, core.Magic.symbol)) |found| {
        module[found] = 'X';
        at = found + 1;
        replaced += 1;
    }
    try testing.expect(replaced > 0);

    var refusal: ?plugin_module.Refusal = null;
    try testing.expectError(
        error.NotAPlugin,
        plugin_module.read(testing.allocator, module, &refusal),
    );
    try testing.expectEqualStrings(core.Magic.symbol, refusal.?.missing_symbol.symbol);
}

test "the real plugin loads, and its tool is offered under a dotted action" {
    // The whole road: a module on disk, a reader, the collision rule, the
    // capability fold, and a definition the model would read.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);

    var session: plugin.Session = .init(testing.allocator);
    defer session.deinit();
    var policy: Decider = .{};
    defer policy.deinit();

    var failure: ?plugin.Failure = null;
    var read = try session.load(
        testing.allocator,
        "hello",
        module,
        policy.decider(),
        null,
        &failure,
    );
    defer read.deinit();

    try testing.expectEqual(@as(?plugin.Failure, null), failure);
    try testing.expect(policy.sawAction("plugin.hello.tool.hello"));

    const offer = session.find("hello").?;
    try testing.expectEqual(@as(?plugin.Refusal, null), offer.refused);
    try testing.expectEqualStrings("plugin.hello.tool.hello", offer.action);
    try testing.expectEqualStrings("A simple hello world tool", offer.definition.description);

    var offered: std.ArrayList(chock_core.tools.Definition) = .empty;
    defer offered.deinit(testing.allocator);
    try session.appendDefinitions(testing.allocator, &offered);
    try testing.expectEqual(@as(usize, 1), offered.items.len);
    try testing.expectEqualStrings("hello", offered.items[0].name);
}

test "the real plugin's tool is refused by policy like any other action" {
    // A plugin tool is on the policy table with everything else that has
    // consequence. A project that denies its action gets no tool, and gets it
    // before the model is ever offered the name.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);

    var session: plugin.Session = .init(testing.allocator);
    defer session.deinit();
    var policy: Decider = .{ .denied = "plugin.hello.tool.hello" };
    defer policy.deinit();

    var read = try session.load(testing.allocator, "hello", module, policy.decider(), null, null);
    defer read.deinit();

    const offer = session.find("hello").?;
    try testing.expectEqual(plugin.Refusal.policy, offer.refused.?);
    try testing.expectEqual(chock_policy.table.Decision.deny, offer.decision);

    var offered: std.ArrayList(chock_core.tools.Definition) = .empty;
    defer offered.deinit(testing.allocator);
    try session.appendDefinitions(testing.allocator, &offered);
    try testing.expectEqual(@as(usize, 0), offered.items.len);
}

test "a real module whose tool is named after a built-in fails to load entirely" {
    // The project owner's own rule, driven from a real module rather than from
    // a record built in a test. The plugin's own tool is renamed to `glob`,
    // which `chock_core.tools.Tool` already holds, by writing a fresh blob
    // over the one the module carries. The new blob is shorter, and the reader
    // reads exactly the length the blob states, so the leftover bytes behind
    // it change nothing.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);
    const blob_at = try findBlob(module);

    const blob = blob: {
        var read = try plugin_module.read(testing.allocator, module, null);
        defer read.deinit();
        const record = read.record();

        const renamed = try testing.allocator.alloc(core.ToolDescriptor, record.tools.len);
        defer testing.allocator.free(renamed);
        @memcpy(renamed, record.tools);
        renamed[0].name = "glob";

        var shadowing = record;
        shadowing.tools = renamed;
        break :blob try core.serializeAlloc(testing.allocator, shadowing);
    };
    defer testing.allocator.free(blob);

    // `glob` is shorter than `hello`, so the new blob fits where the old one
    // was. A test that had to grow the module would have to rewrite the data
    // segment's length and the data section's length as well, which is a
    // different thing to get wrong.
    const was = std.mem.readInt(u32, module[blob_at + core.Prefix.total_len_offset ..][0..4], .little);
    try testing.expect(blob.len < was);
    @memcpy(module[blob_at..][0..blob.len], blob);

    var session: plugin.Session = .init(testing.allocator);
    defer session.deinit();
    var policy: Decider = .{};
    defer policy.deinit();

    var failure: ?plugin.Failure = null;
    var loaded = try session.load(
        testing.allocator,
        "hello",
        module,
        policy.decider(),
        null,
        &failure,
    );
    defer loaded.deinit();

    // The module read perfectly well. The refusal is the host's, taken against
    // its own built-in list and never against what the plugin says about
    // itself.
    try testing.expectEqualStrings("glob", loaded.record().tools[0].name);
    try testing.expectEqual(plugin.Failure.shadows_built_in, failure.?);
    try testing.expect(session.isEmpty());
    try testing.expectEqual(@as(usize, 0), policy.asked.items.len);
}
