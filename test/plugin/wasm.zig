//! The plugin the project ships, read back out of the real
//! `wasm32-freestanding` module that `build.zig` builds. Tests of a refusal
//! reach it by changing one thing in that module.
//!
//! Nothing here runs the plugin. The engine lives in the plugin host process,
//! which `test/plugin/engine.zig` drives.

const std = @import("std");
const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");
const core = @import("chock-plugin-core");
const hello = @import("chock-plugin");
const wasm_path = @import("plugin_wasm_path").plugin_wasm_path;

const plugin = chock_core.plugin;
const plugin_module = chock_core.plugin_module;

/// The reader's own bound, so this test never refuses a module the reader takes.
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

/// The magic word can appear by chance in half a megabyte of debug information,
/// so the first candidate the blob reader accepts wins. The host does not search
/// like this: it resolves the address the `chock_plugin_metadata` global holds.
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
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);

    var read = try plugin_module.read(testing.allocator, module, null);
    defer read.deinit();

    const declared = comptime hello.chock_plugin_metadata.lower();
    try testing.expect(declared.eql(read.record()));
    try testing.expectEqualStrings("hello", read.record().name);
    try testing.expectEqualStrings("A simple hello world plugin", read.record().description[0].value);
    try testing.expectEqual(@as(usize, 2), read.record().tools.len);
    try testing.expectEqualStrings("hello", read.record().tools[0].name);
    try testing.expectEqualStrings("greet", read.record().tools[1].name);
    try testing.expectEqual(@as(usize, 2), read.record().tools[1].parameters.len);
    try testing.expectEqualStrings("who", read.record().tools[1].parameters[0].name);
    try testing.expectEqual(@as(u32, @intFromEnum(core.AbiVersion.current)), read.abi_word);
    try testing.expectEqual(core.AbiVersion.current, read.parsed.abi_version);
}

test "the two roads to the blob meet at the same bytes" {
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);

    var read = try plugin_module.read(testing.allocator, module, null);
    defer read.deinit();

    var searched = try core.parse(testing.allocator, module[try findBlob(module)..], null);
    defer searched.deinit();

    try testing.expect(searched.record.eql(read.record()));
}

test "the real linker exports the metadata as a global holding an address" {
    // On wasm32 the linker turns a data export into an exported global whose
    // value is the address, not into the bytes. The export section comes before
    // every custom section, so the first time the name appears is that section.
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
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);
    try testing.expectEqualSlices(u8, &plugin_module.wasm_preamble, module[0..4]);
}

test "a real module built for another plugin ABI is refused with both numbers" {
    // The module states its ABI twice, so both move together here.
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);
    const blob_at = try findBlob(module);

    // The `chock_plugin_magic` global holds the four bytes in front of the blob.
    // Asserted, so a linker that lays the two out differently fails here.
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
    const want = try std.fmt.allocPrint(
        testing.allocator,
        "built for plugin ABI 7, this Chock speaks plugin ABI {d}: rebuild the plugin",
        .{@intFromEnum(core.AbiVersion.current)},
    );
    defer testing.allocator.free(want);
    try testing.expectEqualStrings(want, text);
}

test "a real module whose two ABI numbers disagree is refused" {
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
    const want = try std.fmt.allocPrint(
        testing.allocator,
        "the module says it is plugin ABI {d} and its metadata says ABI 7",
        .{@intFromEnum(core.AbiVersion.current)},
    );
    defer testing.allocator.free(want);
    try testing.expectEqualStrings(want, text);
}

test "a real module with the magic word struck out of its blob is not a plugin" {
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
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);

    var refusal: ?plugin_module.Refusal = null;
    try testing.expectError(
        error.MalformedModule,
        plugin_module.read(testing.allocator, module[0 .. module.len / 2], &refusal),
    );
    try testing.expect(refusal.? == .malformed_module);

    var short: ?plugin_module.Refusal = null;
    try testing.expectError(
        error.MalformedModule,
        plugin_module.read(testing.allocator, module[0 .. module.len - 1], &short),
    );
}

test "a file of the right length full of zeros is not a plugin" {
    const module = try readModule(testing.allocator);
    defer testing.allocator.free(module);
    @memset(module, 0);

    try testing.expectError(error.NotWasm, plugin_module.read(testing.allocator, module, null));
}

test "a real module that exports no chock_plugin_magic is not a Chock plugin" {
    // The name is replaced everywhere it appears, so the debug information
    // cannot leave a copy behind for a search to find.
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
    try testing.expectEqual(@as(usize, 2), offered.items.len);
    try testing.expectEqualStrings("hello", offered.items[0].name);

    const nothing = try std.json.Stringify.valueAlloc(
        testing.allocator,
        offered.items[0].parameters,
        .{},
    );
    defer testing.allocator.free(nothing);
    try testing.expectEqualStrings("{\"type\":\"object\",\"properties\":{},\"required\":[]}", nothing);

    const greet = offered.items[1].parameters.object;
    try testing.expectEqualStrings("object", greet.get("type").?.string);
    const who = greet.get("properties").?.object.get("who").?.object;
    try testing.expectEqualStrings("string", who.get("type").?.string);
    try testing.expectEqualStrings("The name to greet.", who.get("description").?.string);
    try testing.expectEqualStrings("boolean", greet.get("properties").?.object.get("loudly").?.object.get("type").?.string);
    try testing.expectEqual(@as(usize, 1), greet.get("required").?.array.items.len);
    try testing.expectEqualStrings("who", greet.get("required").?.array.items[0].string);
}

test "the real plugin's tool is refused by policy like any other action" {
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
    try testing.expectEqual(@as(usize, 1), offered.items.len);
    try testing.expectEqualStrings("greet", offered.items[0].name);
}

test "a real module whose tool is named after a built-in fails to load entirely" {
    // A fresh blob goes over the one the module carries. The reader reads only
    // the length the blob states, so leftover bytes behind it change nothing.
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

    // `glob` is shorter than `hello`, so the new blob fits in place. A module
    // that had to grow would need its segment and section lengths rewritten.
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

    try testing.expectEqualStrings("glob", loaded.record().tools[0].name);
    try testing.expectEqual(plugin.Failure.shadows_built_in, failure.?);
    try testing.expect(session.isEmpty());
    try testing.expectEqual(@as(usize, 0), policy.asked.items.len);
}
