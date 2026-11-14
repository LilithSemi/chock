//! The name and address chock puts on every commit it makes or lets the agent make, from the
//! `identity` block of `chock.zon`. The agent's sandbox and the landing read the same value.

const std = @import("std");
const chock_zon = @import("chock-zon");

pub const file_name = "chock.zon";

pub const max_file_bytes = 1 << 20;

pub const default_name = "chock";
pub const default_email = "chock@localhost";

pub const Identity = struct {
    name: []const u8 = default_name,
    email: []const u8 = default_email,
};

pub const Field = enum { name, email };

pub const Why = enum {
    empty,
    angle_bracket,
    line_break,
    nul,

    pub fn sentence(self: Why) []const u8 {
        return switch (self) {
            .empty => "is empty",
            .angle_bracket => "holds a < or a >, which ends the field in a commit header",
            .line_break => "holds a line break, which would start a new commit header",
            .nul => "holds a NUL byte",
        };
    }
};

pub const Fault = struct {
    field: Field,
    why: Why,
};

/// Both halves reach a commit header, so each byte that could end or split a header line is refused.
pub fn refusal(identity: Identity) ?Fault {
    inline for (.{ Field.name, Field.email }) |field| {
        if (why(@field(identity, @tagName(field)))) |reason| return .{ .field = field, .why = reason };
    }
    return null;
}

fn why(text: []const u8) ?Why {
    if (std.mem.trim(u8, text, " \t").len == 0) return .empty;
    for (text) |byte| switch (byte) {
        '<', '>' => return .angle_bracket,
        '\n', '\r' => return .line_break,
        0 => return .nul,
        else => {},
    };
    return null;
}

pub const ParseError = error{
    InvalidIdentity,
} || std.mem.Allocator.Error;

pub const LoadError = ParseError || error{
    IdentityFileTooLarge,
    ReadFailed,
};

pub const Diagnostic = union(enum) {
    file_not_zon: ZonFailure,
    block_not_valid: ZonFailure,
    not_a_struct_literal,
    file_too_large: usize,
    read_failed: anyerror,
    refused: Fault,

    /// `arena` backs `diag`'s messages and must outlive it; `deinit` frees both together.
    pub const ZonFailure = struct {
        arena: std.heap.ArenaAllocator,
        diag: std.zon.parse.Diagnostics,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        _ = gpa;
        switch (self.*) {
            .file_not_zon, .block_not_valid => |*zf| zf.arena.deinit(),
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .file_not_zon => |*zf| try writer.print(
                "{s} is not valid:\n{f}",
                .{ file_name, zf.diag.fmt(file_name) },
            ),
            .block_not_valid => |*zf| try writer.print(
                "{s}: the identity block is not valid:\n{f}",
                .{ file_name, zf.diag.fmt(file_name) },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{file_name},
            ),
            .file_too_large => |limit| try writer.print(
                "{s} is larger than {d} bytes, so it was not read",
                .{ file_name, limit },
            ),
            .read_failed => |err| try writer.print(
                "{s} is there and could not be read: {s}",
                .{ file_name, @errorName(err) },
            ),
            .refused => |fault| try writer.print(
                "{s}: the {t} in the identity block {s}",
                .{ file_name, fault.field, fault.why.sentence() },
            ),
        }
    }
};

fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

const WireIdentity = struct {
    name: ?[]const u8 = null,
    email: ?[]const u8 = null,
};

/// The strings of the result belong to `gpa`; pass an arena.
pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!Identity {
    var ast = std.zig.Ast.parse(gpa, source, .{ .mode = .zon }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
    defer zoir.deinit(gpa);

    var arena: std.heap.ArenaAllocator = .init(gpa);
    var arena_owned = true;
    defer if (arena_owned) arena.deinit();

    if (zoir.hasCompileErrors()) {
        var zon_diag: std.zon.parse.Diagnostics = undefined;
        _ = std.zon.parse.fromZoir(WireIdentity, .{
            .arena = arena.allocator(),
            .ast = &ast,
            .zoir = &zoir,
            .diagnostics = &zon_diag,
        }) catch {};
        if (note(diag, .{ .file_not_zon = .{ .arena = arena, .diag = zon_diag } })) arena_owned = false;
        return error.InvalidIdentity;
    }

    const node = try findIdentityNode(zoir, diag) orelse return .{};

    var zon_diag: std.zon.parse.Diagnostics = undefined;
    const wire = chock_zon.fromNode(
        WireIdentity,
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
            return error.InvalidIdentity;
        },
    };

    const settled: Identity = .{
        .name = wire.name orelse default_name,
        .email = wire.email orelse default_email,
    };
    if (refusal(settled)) |fault| {
        _ = note(diag, .{ .refused = fault });
        return error.InvalidIdentity;
    }
    return .{
        .name = if (wire.name != null) try gpa.dupe(u8, settled.name) else default_name,
        .email = if (wire.email != null) try gpa.dupe(u8, settled.email) else default_email,
    };
}

pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Identity {
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
            return error.IdentityFileTooLarge;
        },
        else => {
            _ = note(diag, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, diag);
}

fn findIdentityNode(zoir: std.zig.Zoir, diag: ?*?Diagnostic) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(&zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(&zoir), "identity")) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidIdentity;
        },
    }
}

const testing = std.testing;

test "a project that writes nothing gets chock at localhost" {
    for ([_][:0]const u8{ ".{}", ".{ .apply = .{ .mode = .squash } }", ".{ .identity = .{} }" }) |source| {
        const got = try parse(testing.allocator, source, null);
        try testing.expectEqualStrings("chock", got.name);
        try testing.expectEqualStrings("chock@localhost", got.email);
    }
}

test "each half is set alone or together, and the default fills the other" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const both = try parse(arena, ".{ .identity = .{ .name = \"Acme Bot\", .email = \"bot@acme.com\" } }", null);
    try testing.expectEqualStrings("Acme Bot", both.name);
    try testing.expectEqualStrings("bot@acme.com", both.email);

    const only_name = try parse(arena, ".{ .identity = .{ .name = \"Acme Bot\" } }", null);
    try testing.expectEqualStrings("Acme Bot", only_name.name);
    try testing.expectEqualStrings(default_email, only_name.email);

    const only_email = try parse(arena, ".{ .apply = .{}, .identity = .{ .email = \"bot@acme.com\" } }", null);
    try testing.expectEqualStrings(default_name, only_email.name);
    try testing.expectEqualStrings("bot@acme.com", only_email.email);
}

test "an empty, blank or header splitting half is refused with a diagnostic" {
    const cases = [_]struct { field: []const u8, value: []const u8, fault: Fault }{
        .{ .field = "name", .value = "", .fault = .{ .field = .name, .why = .empty } },
        .{ .field = "email", .value = "", .fault = .{ .field = .email, .why = .empty } },
        .{ .field = "name", .value = "  \\t ", .fault = .{ .field = .name, .why = .empty } },
        .{ .field = "name", .value = "a<b", .fault = .{ .field = .name, .why = .angle_bracket } },
        .{ .field = "email", .value = "a>b", .fault = .{ .field = .email, .why = .angle_bracket } },
        .{ .field = "name", .value = "a\\nb", .fault = .{ .field = .name, .why = .line_break } },
        .{ .field = "email", .value = "a\\rb", .fault = .{ .field = .email, .why = .line_break } },
        .{ .field = "name", .value = "a\\x00b", .fault = .{ .field = .name, .why = .nul } },
    };
    for (cases) |case| {
        const source = try std.fmt.allocPrintSentinel(
            testing.allocator,
            ".{{ .identity = .{{ .{s} = \"{s}\" }} }}",
            .{ case.field, case.value },
            0,
        );
        defer testing.allocator.free(source);
        var diag: ?Diagnostic = null;
        defer if (diag) |*d| d.deinit(testing.allocator);
        try testing.expectError(error.InvalidIdentity, parse(testing.allocator, source, &diag));
        try testing.expectEqual(case.fault, diag.?.refused);
    }
}

test "a misspelled field is refused and is never read as the default" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(
        error.InvalidIdentity,
        parse(testing.allocator, ".{ .identity = .{ .nmae = \"x\" } }", &diag),
    );
    try testing.expect(diag != null);
}

test "the identity block sits beside the other blocks and none of them refuses it" {
    const source: [:0]const u8 = ".{ .identity = .{ .name = \"Acme Bot\" }, .apply = .{ .mode = .squash } }";
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const apply = @import("apply.zig");
    try testing.expectEqual(apply.Mode.squash, (try apply.parse(testing.allocator, source, null)).mode);
    try testing.expectEqualStrings("Acme Bot", (try parse(arena_state.allocator(), source, null)).name);
}
