//! The `context` block of a project's `chock.zon`: when transcript
//! compaction starts and how much recent context it preserves. The provider's
//! context limit remains the ceiling; this block only chooses behaviour below
//! it.

const std = @import("std");
const chock_zon = @import("chock-zon");

pub const file_name = "chock.zon";
pub const max_file_bytes = 1 << 20;

pub const Settings = struct {
    compact_at_percent: u8 = 75,
    warn_at_percent: u8 = 60,
    keep_recent_entries: u16 = 6,
    keep_recent_kib: u16 = 16,
    summary_max_kib: u16 = 16,
};

const Wire = struct {
    compact_at_percent: u8 = 75,
    warn_at_percent: u8 = 60,
    keep_recent_entries: u16 = 6,
    keep_recent_kib: u16 = 16,
    summary_max_kib: u16 = 16,
};

pub const ParseError = error{ OutOfMemory, InvalidContext };
pub const LoadError = ParseError || error{ ContextFileTooLarge, ReadFailed };

pub const Diagnostic = union(enum) {
    file_not_zon: ZonFailure,
    block_not_valid: ZonFailure,
    not_a_struct_literal,
    invalid_value: InvalidValue,
    file_too_large: usize,
    read_failed: anyerror,

    pub const ZonFailure = struct {
        arena: std.heap.ArenaAllocator,
        diag: std.zon.parse.Diagnostics,
    };
    pub const InvalidValue = struct { field: []const u8, detail: []const u8 };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        _ = gpa;
        switch (self.*) {
            .file_not_zon, .block_not_valid => |*failure| failure.arena.deinit(),
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .file_not_zon => |*failure| try writer.print("{s} is not valid:\n{f}", .{
                file_name, failure.diag.fmt(file_name),
            }),
            .block_not_valid => |*failure| try writer.print("{s}: the context block is not valid:\n{f}", .{
                file_name, failure.diag.fmt(file_name),
            }),
            .not_a_struct_literal => try writer.print("{s}: the file must hold a struct literal", .{file_name}),
            .invalid_value => |value| try writer.print(
                "{s}: the context block's {s} {s}",
                .{ file_name, value.field, value.detail },
            ),
            .file_too_large => |limit| try writer.print(
                "{s}: the file is larger than {d} bytes, so it was not read",
                .{ file_name, limit },
            ),
            .read_failed => |err| try writer.print("{s}: the file could not be read: {t}", .{ file_name, err }),
        }
    }
};

fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!Settings {
    var ast = std.zig.Ast.parse(gpa, source, .{ .mode = .zon }) catch return error.OutOfMemory;
    defer ast.deinit(gpa);
    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
    defer zoir.deinit(gpa);

    var arena: std.heap.ArenaAllocator = .init(gpa);
    var arena_owned = true;
    defer if (arena_owned) arena.deinit();

    if (zoir.hasCompileErrors()) {
        var zon_diag: std.zon.parse.Diagnostics = undefined;
        _ = std.zon.parse.fromZoir(Wire, .{
            .arena = arena.allocator(),
            .ast = &ast,
            .zoir = &zoir,
            .diagnostics = &zon_diag,
        }) catch {};
        if (note(diag, .{ .file_not_zon = .{ .arena = arena, .diag = zon_diag } })) arena_owned = false;
        return error.InvalidContext;
    }

    const node = try findNode(zoir, diag) orelse return .{};
    var zon_diag: std.zon.parse.Diagnostics = undefined;
    const wire = chock_zon.fromNode(
        Wire,
        gpa,
        arena.allocator(),
        source,
        &ast,
        &zoir,
        node,
        &zon_diag,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            if (note(diag, .{ .block_not_valid = .{ .arena = arena, .diag = zon_diag } })) arena_owned = false;
            return error.InvalidContext;
        },
    };
    const settings: Settings = .{
        .compact_at_percent = wire.compact_at_percent,
        .warn_at_percent = wire.warn_at_percent,
        .keep_recent_entries = wire.keep_recent_entries,
        .keep_recent_kib = wire.keep_recent_kib,
        .summary_max_kib = wire.summary_max_kib,
    };
    try validate(settings, diag);
    return settings;
}

fn validate(settings: Settings, diag: ?*?Diagnostic) ParseError!void {
    if (settings.compact_at_percent < 10 or settings.compact_at_percent > 95) return invalid(
        diag,
        "compact_at_percent",
        "must be from 10 through 95",
    );
    if (settings.warn_at_percent >= settings.compact_at_percent) return invalid(
        diag,
        "warn_at_percent",
        "must be less than compact_at_percent",
    );
    if (settings.keep_recent_entries > 64) return invalid(
        diag,
        "keep_recent_entries",
        "must be no more than 64",
    );
    if (settings.keep_recent_kib == 0 or settings.keep_recent_kib > 256) return invalid(
        diag,
        "keep_recent_kib",
        "must be from 1 through 256",
    );
    if (settings.summary_max_kib == 0 or settings.summary_max_kib > 64) return invalid(
        diag,
        "summary_max_kib",
        "must be from 1 through 64",
    );
}

fn invalid(diag: ?*?Diagnostic, field: []const u8, detail: []const u8) ParseError {
    _ = note(diag, .{ .invalid_value = .{ .field = field, .detail = detail } });
    return error.InvalidContext;
}

pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Settings {
    const path = try std.fs.path.join(gpa, &.{ project_root, file_name });
    defer gpa.free(path);
    const source = std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(max_file_bytes),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileNotFound, error.NotDir => return .{},
        error.StreamTooLong => {
            _ = note(diag, .{ .file_too_large = max_file_bytes });
            return error.ContextFileTooLarge;
        },
        else => {
            _ = note(diag, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);
    return parse(gpa, source, diag);
}

fn findNode(zoir: std.zig.Zoir, diag: ?*?Diagnostic) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(&zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(&zoir), "context")) return fields.vals.at(@intCast(index));
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidContext;
        },
    }
}

const testing = std.testing;

test "a context block controls thresholds and retention, and other blocks stay separate" {
    const settings = try parse(testing.allocator,
        \\.{
        \\  .policy = .{},
        \\  .context = .{
        \\    .compact_at_percent = 80,
        \\    .warn_at_percent = 65,
        \\    .keep_recent_entries = 12,
        \\    .keep_recent_kib = 32,
        \\    .summary_max_kib = 8,
        \\  },
        \\}
    , null);
    try testing.expectEqual(@as(u8, 80), settings.compact_at_percent);
    try testing.expectEqual(@as(u16, 12), settings.keep_recent_entries);
    try testing.expectEqual(@as(u16, 32), settings.keep_recent_kib);
    try testing.expectEqual(@as(u16, 8), settings.summary_max_kib);
}

test "unsafe or contradictory context bounds are refused" {
    try testing.expectError(error.InvalidContext, parse(
        testing.allocator,
        ".{ .context = .{ .compact_at_percent = 96 } }",
        null,
    ));
    try testing.expectError(error.InvalidContext, parse(
        testing.allocator,
        ".{ .context = .{ .compact_at_percent = 60, .warn_at_percent = 60 } }",
        null,
    ));
    try testing.expectError(error.InvalidContext, parse(
        testing.allocator,
        ".{ .context = .{ .keep_recent_kib = 0 } }",
        null,
    ));
}
