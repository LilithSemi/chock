//! What a project's own `chock.zon` says about the image it wants. Never
//! from the model.

const std = @import("std");
const chock_zon = @import("chock-zon");

const ref = @import("oci").reference;

pub const file_name = "chock.zon";

pub const max_file_bytes: usize = 256 * 1024;

pub const Error = std.mem.Allocator.Error || error{
    ReadFailed,
    FileTooLarge,
};

pub const Answer = union(enum) {
    none,
    /// Owned by `load`'s allocator.
    named: []const u8,
    /// Owned by `load`'s allocator.
    refused: []const u8,
};

const block_name = "container";

/// `ignore_unknown_fields` is not used.
const Block = struct {
    image: []const u8,
};

/// No file names no image, same as no block.
pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
) Error!Answer {
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
        error.FileNotFound, error.NotDir => return .none,
        error.StreamTooLong => return error.FileTooLarge,
        else => return error.ReadFailed,
    };
    defer gpa.free(source);

    return parse(gpa, source);
}

/// The result borrows nothing from `source`.
pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8) std.mem.Allocator.Error!Answer {
    var ast = std.zig.Ast.parse(gpa, source, .{ .mode = .zon }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
    defer zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        return .{ .refused = try gpa.dupe(
            u8,
            file_name ++ " does not parse, so this project's container block could not be read",
        ) };
    }

    const node = switch (try findBlockNode(gpa, zoir)) {
        .none => return .none,
        .refused => |text| return .{ .refused = text },
        .named => |found| found,
    };

    // The refusal below never reads `zon_diag`, so the arena backing it
    // need not outlive this call.
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var zon_diag: std.zon.parse.Diagnostics = undefined;
    const block = chock_zon.fromNode(
        Block,
        gpa,
        arena_state.allocator(),
        source,
        &ast,
        &zoir,
        node,
        &zon_diag,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => return .{ .refused = try std.fmt.allocPrint(
            gpa,
            "the container block of " ++ file_name ++ " is not usable: it holds one field, " ++
                ".image, whose value is the image to read, such as .image = \"debian:stable-slim\"",
            .{},
        ) },
    };

    ref.check(block.image) catch |err| {
        return .{ .refused = try ref.refusalText(gpa, block.image, err) };
    };

    return .{ .named = try gpa.dupe(u8, block.image) };
}

/// Not a struct literal: a broken file, not an absent block.
const Located = union(enum) {
    none,
    refused: []const u8,
    named: std.zig.Zoir.Node.Index,
};

fn findBlockNode(gpa: std.mem.Allocator, zoir: std.zig.Zoir) std.mem.Allocator.Error!Located {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(&zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(&zoir), block_name)) {
                    return .{ .named = fields.vals.at(@intCast(index)) };
                }
            }
            return .none;
        },
        .empty_literal => return .none,
        else => return .{ .refused = try gpa.dupe(
            u8,
            file_name ++ " does not hold a struct at the top, so no block of it can be read",
        ) },
    }
}

const testing = std.testing;

test "a project that names an image gives that reference" {
    const source =
        \\.{
        \\    .container = .{ .image = "debian:stable-slim" },
        \\}
    ;
    const answer = try parse(testing.allocator, source);
    defer switch (answer) {
        .named, .refused => |text| testing.allocator.free(text),
        .none => {},
    };
    try testing.expectEqualStrings("debian:stable-slim", answer.named);
}

test "a file with other blocks and no container block names no image" {
    const source =
        \\.{
        \\    .language_servers = .{},
        \\    .plugins = .{},
        \\}
    ;
    const answer = try parse(testing.allocator, source);
    try testing.expectEqual(Answer.none, answer);
}

test "an empty file and a file with no block both name no image" {
    const empty = try parse(testing.allocator, ".{}");
    try testing.expectEqual(Answer.none, empty);

    const other = try parse(testing.allocator, ".{ .budget = .{} }");
    try testing.expectEqual(Answer.none, other);
}

test "a block that is not usable is a refusal a person can act on" {
    const source =
        \\.{
        \\    .container = .{ .imagee = "debian:stable-slim" },
        \\}
    ;
    const answer = try parse(testing.allocator, source);
    defer testing.allocator.free(answer.refused);
    try testing.expect(std.mem.indexOf(u8, answer.refused, ".image") != null);
}

test "a reference that breaks the rule is refused where a person can still fix it" {
    const source =
        \\.{
        \\    .container = .{ .image = "debian; rm -rf /" },
        \\}
    ;
    const answer = try parse(testing.allocator, source);
    defer testing.allocator.free(answer.refused);
    try testing.expect(answer.refused.len > 0);
}

test "a file that does not parse is a refusal and never a project with no image" {
    const answer = try parse(testing.allocator, ".{ .container = ");
    defer testing.allocator.free(answer.refused);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "does not parse") != null);
}

test "a top level that is not a struct is a broken file and not an absent block" {
    const answer = try parse(testing.allocator, "\"hello\"");
    defer testing.allocator.free(answer.refused);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "struct") != null);
}
