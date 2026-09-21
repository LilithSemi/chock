//! The Nix store's own byte caps, mirroring `lib/chock-policy/limits.zig`.

const std = @import("std");
const limits_mod = @import("limits.zig");

pub const Setting = limits_mod.Setting;
pub const parseSetting = limits_mod.parseSetting;
pub const SettingError = limits_mod.SettingError;

pub const BytesError = SettingError || error{PercentNotAllowed};

/// A percentage is refused rather than resolved, because a store object has no
/// machine quantity to be a share of the way a process count or a memory total
/// has.
pub fn parseBytes(text: []const u8) BytesError!u64 {
    return switch (try parseSetting(text)) {
        .absolute => |value| value,
        .percent => error.PercentNotAllowed,
    };
}

pub fn reasonText(reason: BytesError) []const u8 {
    return switch (reason) {
        error.PercentNotAllowed => "names a percentage, and a store byte cap has no machine quantity to be a share of",
        error.Malformed => limits_mod.reasonText(error.Malformed),
        error.PercentOverHundred => limits_mod.reasonText(error.PercentOverHundred),
        error.Overflow => limits_mod.reasonText(error.Overflow),
    };
}

/// The same number as `chock_nix.backend.default_max_object_bytes`, written
/// twice because this library imports no other chock library.
pub const default_max_object_bytes: u64 = 16 << 20;

pub const default_max_session_bytes: u64 = 256 << 20;

/// Every member is optional, so "this file named nothing" is told apart from
/// "this file named today's default".
pub const Nix = struct {
    max_object_bytes: ?u64 = null,
    max_session_bytes: ?u64 = null,
    /// The attribute under `devShells.<system>` the session's tool environment
    /// comes from. Null is `default`, which is what `nix develop` takes.
    dev_shell: ?[]const u8 = null,
};

pub const Resolved = struct {
    max_object_bytes: u64,
    max_session_bytes: u64,
    max_object_bytes_from_org: bool = false,
    max_session_bytes_from_org: bool = false,
    /// Null means the flake reference carries no attribute, so Nix takes
    /// `default` itself.
    dev_shell: ?[]const u8 = null,
};

pub fn foldLayers(project: Nix, operator: Nix, ceiling: ?Ceiling) Resolved {
    const resolved = Resolved{
        .max_object_bytes = project.max_object_bytes orelse operator.max_object_bytes orelse default_max_object_bytes,
        .max_session_bytes = project.max_session_bytes orelse operator.max_session_bytes orelse default_max_session_bytes,
        .dev_shell = project.dev_shell orelse operator.dev_shell,
    };
    return underCeiling(resolved, ceiling);
}

/// Text and not a number, because `org.zig` reads the whole bundle through one
/// `std.zon.parse.fromSliceAlloc` call and a quoted string is the one shape
/// that reader and `chock.zon`'s own bare integer can both go through.
pub const Ceiling = struct {
    max_object_bytes: ?[]const u8 = null,
    max_session_bytes: ?[]const u8 = null,
};

/// A minimum and never a refusal. A ceiling this build cannot parse is read as
/// no ceiling: `org.zig` refuses a bundle whose `nix` block does not parse, so
/// one that fails here can only have been built by hand.
pub fn underCeiling(resolved: Resolved, ceiling: ?Ceiling) Resolved {
    const bound = ceiling orelse return resolved;
    var held = resolved;
    if (bound.max_object_bytes) |text| {
        if (parseBytes(text)) |value| {
            if (value < held.max_object_bytes) {
                held.max_object_bytes = value;
                held.max_object_bytes_from_org = true;
            }
        } else |_| {}
    }
    if (bound.max_session_bytes) |text| {
        if (parseBytes(text)) |value| {
            if (value < held.max_session_bytes) {
                held.max_session_bytes = value;
                held.max_session_bytes_from_org = true;
            }
        } else |_| {}
    }
    return held;
}

pub const Diagnostic = struct {
    source: []const u8,
    fault: Fault,

    pub const Fault = union(enum) {
        file_not_zon: std.zon.parse.Diagnostics,
        not_a_struct_literal,
        unknown_field: []const u8,
        value_not_string_or_number: []const u8,
        invalid_setting: InvalidSetting,
        dev_shell_not_a_string,
        dev_shell_empty,
        dev_shell_has_hash: []const u8,
        negative_setting: []const u8,
        setting_overflow: []const u8,
        file_too_large: usize,
        read_failed: anyerror,
    };

    pub const InvalidSetting = struct {
        field: []const u8,
        text: []const u8,
        reason: BytesError,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.fault) {
            .file_not_zon => |*zon_diag| zon_diag.deinit(gpa),
            .unknown_field,
            .value_not_string_or_number,
            .negative_setting,
            .setting_overflow,
            .dev_shell_has_hash,
            => |name| gpa.free(name),
            .invalid_setting => |setting| {
                gpa.free(setting.field);
                gpa.free(setting.text);
            },
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.fault) {
            .file_not_zon => |*zon_diag| try writer.print(
                "{s} is not valid:\n{f}",
                .{ self.source, zon_diag },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{self.source},
            ),
            .unknown_field => |field| try writer.print(
                "{s}: the nix block names a field this reader does not know: {s}",
                .{ self.source, field },
            ),
            .value_not_string_or_number => |field| try writer.print(
                "{s}: the nix block's {s} field must be an absolute value or a number",
                .{ self.source, field },
            ),
            .invalid_setting => |setting| try writer.print(
                "{s}: the nix block's {s} field holds \"{s}\", which {s}",
                .{ self.source, setting.field, setting.text, reasonText(setting.reason) },
            ),
            .dev_shell_not_a_string => try writer.print(
                "{s}: the nix block's dev_shell field must be a string",
                .{self.source},
            ),
            .dev_shell_empty => try writer.print(
                "{s}: the nix block's dev_shell field is empty, and an attribute name cannot be",
                .{self.source},
            ),
            .dev_shell_has_hash => |name| try writer.print(
                "{s}: the nix block's dev_shell field holds \"{s}\". A # separates the flake from " ++
                    "the attribute, so the name cannot hold one",
                .{ self.source, name },
            ),
            .negative_setting => |field| try writer.print(
                "{s}: the nix block's {s} field is a negative number, and a byte cap cannot be",
                .{ self.source, field },
            ),
            .setting_overflow => |field| try writer.print(
                "{s}: the nix block's {s} field names a number too large to hold",
                .{ self.source, field },
            ),
            .file_too_large => |limit| try writer.print(
                "{s}: the file is larger than {d} bytes, so it was not read",
                .{ self.source, limit },
            ),
            .read_failed => |err| try writer.print(
                "{s}: the file could not be read: {t}",
                .{ self.source, err },
            ),
        }
    }
};

pub const ParseError = error{
    OutOfMemory,
    InvalidNix,
};

pub const LoadError = ParseError || error{
    NixFileTooLarge,
    ReadFailed,
};

fn note(out: ?*?Diagnostic, source: []const u8, fault: Diagnostic.Fault) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = .{ .source = source, .fault = fault };
    return true;
}

pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!Nix {
    return parseFrom(gpa, source, limits_mod.file_name, diag);
}

pub fn parseFrom(
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Nix {
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    var ast_owned = true;
    defer if (ast_owned) ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = true });
    var zoir_owned = true;
    defer if (zoir_owned) zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        if (note(diag, source_name, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidNix;
    }

    const node = try findNixNode(zoir, source_name, diag) orelse return .{};
    return parseFields(gpa, zoir, node, source_name, diag);
}

fn parseFields(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Nix {
    var nix = Nix{};
    switch (node.get(zoir)) {
        .empty_literal => return nix,
        .struct_literal => |fields| {
            for (fields.names, 0..) |name_id, index| {
                const name = name_id.get(zoir);
                const value_node = fields.vals.at(@intCast(index));
                if (std.mem.eql(u8, name, "max_object_bytes")) {
                    nix.max_object_bytes = try readBytes(gpa, zoir, "max_object_bytes", value_node, source_name, diag);
                } else if (std.mem.eql(u8, name, "max_session_bytes")) {
                    nix.max_session_bytes = try readBytes(gpa, zoir, "max_session_bytes", value_node, source_name, diag);
                } else if (std.mem.eql(u8, name, "dev_shell")) {
                    nix.dev_shell = try readDevShell(gpa, zoir, value_node, source_name, diag);
                } else {
                    _ = note(diag, source_name, .{ .unknown_field = try gpa.dupe(u8, name) });
                    return error.InvalidNix;
                }
            }
        },
        else => {
            _ = note(diag, source_name, .not_a_struct_literal);
            return error.InvalidNix;
        },
    }
    return nix;
}

fn readDevShell(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError![]const u8 {
    const text = switch (node.get(zoir)) {
        .string_literal => |text| text,
        else => {
            _ = note(diag, source_name, .dev_shell_not_a_string);
            return error.InvalidNix;
        },
    };
    if (text.len == 0) {
        _ = note(diag, source_name, .dev_shell_empty);
        return error.InvalidNix;
    }
    if (std.mem.indexOfScalar(u8, text, '#') != null) {
        _ = note(diag, source_name, .{ .dev_shell_has_hash = try gpa.dupe(u8, text) });
        return error.InvalidNix;
    }
    return gpa.dupe(u8, text);
}

fn readBytes(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    field: []const u8,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!u64 {
    switch (node.get(zoir)) {
        .string_literal => |text| {
            return parseBytes(text) catch |err| {
                const owned_field = try gpa.dupe(u8, field);
                const owned_text = try gpa.dupe(u8, text);
                if (!note(diag, source_name, .{ .invalid_setting = .{
                    .field = owned_field,
                    .text = owned_text,
                    .reason = err,
                } })) {
                    gpa.free(owned_field);
                    gpa.free(owned_text);
                }
                return error.InvalidNix;
            };
        },
        .int_literal => |lit| {
            const value = intLiteralToU64(lit) catch |err| {
                const owned_field = try gpa.dupe(u8, field);
                const taken = switch (err) {
                    error.NegativeSetting => note(diag, source_name, .{ .negative_setting = owned_field }),
                    error.SettingOverflow => note(diag, source_name, .{ .setting_overflow = owned_field }),
                };
                if (!taken) gpa.free(owned_field);
                return error.InvalidNix;
            };
            return value;
        },
        else => {
            _ = note(diag, source_name, .{ .value_not_string_or_number = try gpa.dupe(u8, field) });
            return error.InvalidNix;
        },
    }
}

const IntLiteralError = error{ NegativeSetting, SettingOverflow };

fn intLiteralToU64(lit: anytype) IntLiteralError!u64 {
    return switch (lit) {
        .small => |v| std.math.cast(u64, v) orelse error.NegativeSetting,
        .big => |big| big.toInt(u64) catch |err| switch (err) {
            error.NegativeIntoUnsigned => error.NegativeSetting,
            error.TargetTooSmall => error.SettingOverflow,
        },
    };
}

fn findNixNode(
    zoir: std.zig.Zoir,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), "nix")) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, source_name, .not_a_struct_literal);
            return error.InvalidNix;
        },
    }
}

pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Nix {
    return loadFrom(gpa, io, project_root, limits_mod.file_name, diag);
}

pub fn loadOperator(
    gpa: std.mem.Allocator,
    io: std.Io,
    config_dir: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Nix {
    return loadFrom(gpa, io, config_dir, limits_mod.operator_file_name, diag);
}

fn loadFrom(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Nix {
    const path = try std.fs.path.join(gpa, &.{ dir, source_name });
    defer gpa.free(path);

    const source = std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(limits_mod.max_file_bytes),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileNotFound, error.NotDir => return .{},
        error.StreamTooLong => {
            _ = note(diag, source_name, .{ .file_too_large = limits_mod.max_file_bytes });
            return error.NixFileTooLarge;
        },
        else => {
            _ = note(diag, source_name, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parseFrom(gpa, source, source_name, diag);
}

// Every test below builds its own source in the test binary.

const testing = std.testing;

fn absoluteDirPath(buffer: []u8, dir: std.Io.Dir) ![]u8 {
    const len = dir.realPath(testing.io, buffer) catch return error.RealPathFailed;
    return buffer[0..len];
}

test "a nix block is read, and the rest of the file is left to other readers" {
    const source =
        \\.{
        \\    .policy = .{ .rules = .{ .{ .action = "git.push", .decision = .deny } } },
        \\    .budget = .{ .max_cost = 5.0 },
        \\    .nix = .{ .max_object_bytes = "8MiB", .max_session_bytes = "128MiB" },
        \\}
    ;
    const nix = try parse(testing.allocator, source, null);
    try testing.expectEqual(@as(u64, 8 << 20), nix.max_object_bytes.?);
    try testing.expectEqual(@as(u64, 128 << 20), nix.max_session_bytes.?);
}

test "a bare ZON integer is read directly, with no string in between" {
    const nix = try parse(testing.allocator, ".{ .nix = .{ .max_object_bytes = 4096 } }", null);
    try testing.expectEqual(@as(u64, 4096), nix.max_object_bytes.?);
    try testing.expectEqual(@as(?u64, null), nix.max_session_bytes);

    try testing.expectError(
        error.InvalidNix,
        parse(testing.allocator, ".{ .nix = .{ .max_object_bytes = -1 } }", null),
    );
}

test "a file with no nix block, or a block naming one field, leaves the rest null" {
    for ([_][:0]const u8{ ".{}", ".{ .policy = .{} }", ".{ .budget = .{ .max_cost = 1.0 } }" }) |source| {
        const nix = try parse(testing.allocator, source, null);
        try testing.expectEqual(@as(?u64, null), nix.max_object_bytes);
        try testing.expectEqual(@as(?u64, null), nix.max_session_bytes);
    }

    const only_object = try parse(testing.allocator, ".{ .nix = .{ .max_object_bytes = \"1MiB\" } }", null);
    try testing.expectEqual(Nix{ .max_object_bytes = 1 << 20 }, only_object);
}

test "a misspelled field inside the nix block is refused rather than silently skipped" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(
        error.InvalidNix,
        parse(testing.allocator, ".{ .nix = .{ .max_objct_bytes = \"1MiB\" } }", &diag),
    );
    try testing.expectEqualStrings("max_objct_bytes", diag.?.fault.unknown_field);
    try testing.expectEqualStrings(limits_mod.file_name, diag.?.source);

    const nix = try parse(testing.allocator, ".{ .telepathy = .{ .range_m = 3 } }", null);
    try testing.expectEqual(@as(?u64, null), nix.max_object_bytes);
}

test "a percentage is refused for a byte cap, and the reason says why" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(
        error.InvalidNix,
        parse(testing.allocator, ".{ .nix = .{ .max_object_bytes = \"50%\" } }", &diag),
    );
    try testing.expectEqualStrings("max_object_bytes", diag.?.fault.invalid_setting.field);
    try testing.expectEqual(BytesError.PercentNotAllowed, diag.?.fault.invalid_setting.reason);

    try testing.expectError(error.PercentNotAllowed, parseBytes("50%"));
    try testing.expectError(error.PercentOverHundred, parseBytes("101%"));
}

test "an absolute value is read as a bare number or a number with a unit" {
    try testing.expectEqual(@as(u64, 300), try parseBytes("300"));
    try testing.expectEqual(@as(u64, 4 << 20), try parseBytes("4MiB"));
    try testing.expectEqual(@as(u64, 16 << 20), try parseBytes("16MiB"));
    try testing.expectEqual(@as(u64, 256 << 20), try parseBytes("256MiB"));
    try testing.expectError(error.Malformed, parseBytes("four"));
}

test "the nix caps come off the disk, and a project with no file gets nothing named" {
    const gpa = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absoluteDirPath(&path_buffer, tmp.dir);

    const missing = try load(gpa, testing.io, root, null);
    try testing.expectEqual(@as(?u64, null), missing.max_object_bytes);

    {
        var file = try tmp.dir.createFile(testing.io, limits_mod.file_name, .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, ".{ .nix = .{ .max_object_bytes = \"32MiB\" } }");
    }

    const written = try load(gpa, testing.io, root, null);
    try testing.expectEqual(@as(u64, 32 << 20), written.max_object_bytes.?);
}

test "the operator's own config.zon is read through the same loader, by a different name" {
    const gpa = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absoluteDirPath(&path_buffer, tmp.dir);

    {
        var file = try tmp.dir.createFile(testing.io, limits_mod.operator_file_name, .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, ".{ .nix = .{ .max_session_bytes = \"512MiB\" } }");
    }

    const written = try loadOperator(gpa, testing.io, root, null);
    try testing.expectEqual(@as(u64, 512 << 20), written.max_session_bytes.?);

    const project_side = try load(gpa, testing.io, root, null);
    try testing.expectEqual(@as(?u64, null), project_side.max_session_bytes);
}

test "the fold: the project wins over the operator, and the operator wins over the built in default" {
    const nothing_named = foldLayers(.{}, .{}, null);
    try testing.expectEqual(default_max_object_bytes, nothing_named.max_object_bytes);
    try testing.expectEqual(default_max_session_bytes, nothing_named.max_session_bytes);

    const operator_only = foldLayers(.{}, .{ .max_object_bytes = 4 << 20 }, null);
    try testing.expectEqual(@as(u64, 4 << 20), operator_only.max_object_bytes);

    const both_named = foldLayers(
        .{ .max_object_bytes = 32 << 20 },
        .{ .max_object_bytes = 4 << 20 },
        null,
    );
    try testing.expectEqual(@as(u64, 32 << 20), both_named.max_object_bytes);

    const mixed = foldLayers(
        .{ .max_session_bytes = 64 << 20 },
        .{ .max_object_bytes = 4 << 20 },
        null,
    );
    try testing.expectEqual(@as(u64, 4 << 20), mixed.max_object_bytes);
    try testing.expectEqual(@as(u64, 64 << 20), mixed.max_session_bytes);
}

test "a resolved pair of nix caps is held to an org ceiling, and never widened by one" {
    const generous = Nix{ .max_object_bytes = 128 << 20, .max_session_bytes = 1 << 30 };
    const resolved = foldLayers(generous, .{}, null);

    const held = underCeiling(resolved, .{ .max_object_bytes = "16MiB", .max_session_bytes = "256MiB" });
    try testing.expectEqual(@as(u64, 16 << 20), held.max_object_bytes);
    try testing.expectEqual(@as(u64, 256 << 20), held.max_session_bytes);
    try testing.expect(held.max_object_bytes_from_org);
    try testing.expect(held.max_session_bytes_from_org);

    const modest = Nix{ .max_object_bytes = 1 << 20, .max_session_bytes = 8 << 20 };
    const untouched = underCeiling(foldLayers(modest, .{}, null), .{ .max_object_bytes = "16MiB", .max_session_bytes = "256MiB" });
    try testing.expectEqual(@as(u64, 1 << 20), untouched.max_object_bytes);
    try testing.expectEqual(@as(u64, 8 << 20), untouched.max_session_bytes);
    try testing.expect(!untouched.max_object_bytes_from_org);
    try testing.expect(!untouched.max_session_bytes_from_org);

    try testing.expectEqual(resolved, underCeiling(resolved, null));
}

test "a ceiling may cap one field and say nothing about the other" {
    const resolved = foldLayers(.{ .max_object_bytes = 128 << 20, .max_session_bytes = 1 << 30 }, .{}, null);

    const object_only = underCeiling(resolved, .{ .max_object_bytes = "16MiB" });
    try testing.expectEqual(@as(u64, 16 << 20), object_only.max_object_bytes);
    try testing.expectEqual(resolved.max_session_bytes, object_only.max_session_bytes);
    try testing.expect(object_only.max_object_bytes_from_org);
    try testing.expect(!object_only.max_session_bytes_from_org);
}

test "a ceiling this build cannot parse changes nothing, rather than crashing" {
    const resolved = foldLayers(.{ .max_object_bytes = 128 << 20 }, .{}, null);
    const held = underCeiling(resolved, .{ .max_object_bytes = "not a number" });
    try testing.expectEqual(resolved.max_object_bytes, held.max_object_bytes);
    try testing.expect(!held.max_object_bytes_from_org);

    const percent_held = underCeiling(resolved, .{ .max_object_bytes = "50%" });
    try testing.expectEqual(resolved.max_object_bytes, percent_held.max_object_bytes);
    try testing.expect(!percent_held.max_object_bytes_from_org);
}

test "dev_shell names the devShells attribute, and an empty or hashed name is refused" {
    const gpa = testing.allocator;

    const named = try parse(gpa, ".{ .nix = .{ .dev_shell = \"ci\" } }", null);
    defer gpa.free(named.dev_shell.?);
    try testing.expectEqualStrings("ci", named.dev_shell.?);

    const quiet = try parse(gpa, ".{ .nix = .{ .max_object_bytes = 8 } }", null);
    try testing.expectEqual(@as(?[]const u8, null), quiet.dev_shell);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidNix,
        parse(gpa, ".{ .nix = .{ .dev_shell = \"\" } }", &diag),
    );
    try testing.expect(diag.?.fault == .dev_shell_empty);

    var hashed: ?Diagnostic = null;
    defer if (hashed) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidNix,
        parse(gpa, ".{ .nix = .{ .dev_shell = \".#ci\" } }", &hashed),
    );
    try testing.expectEqualStrings(".#ci", hashed.?.fault.dev_shell_has_hash);

    var typed: ?Diagnostic = null;
    defer if (typed) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidNix,
        parse(gpa, ".{ .nix = .{ .dev_shell = 3 } }", &typed),
    );
    try testing.expect(typed.?.fault == .dev_shell_not_a_string);
}

test "the project's dev_shell wins over the operator's, and an org ceiling says nothing about it" {
    const project = Nix{ .dev_shell = "ci" };
    const operator = Nix{ .dev_shell = "default" };

    try testing.expectEqualStrings("ci", foldLayers(project, operator, null).dev_shell.?);
    try testing.expectEqualStrings("default", foldLayers(.{}, operator, null).dev_shell.?);
    try testing.expectEqual(@as(?[]const u8, null), foldLayers(.{}, .{}, null).dev_shell);

    const bound = Ceiling{ .max_object_bytes = "1MiB" };
    const held = foldLayers(project, operator, bound);
    try testing.expectEqualStrings("ci", held.dev_shell.?);
    try testing.expectEqual(@as(u64, 1 << 20), held.max_object_bytes);
}
