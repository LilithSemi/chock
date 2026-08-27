//! What a project says about the image it wants, read from its own
//! `chock.zon`.
//!
//! ```zon
//! .{
//!     .container = .{ .image = "debian:stable-slim" },
//! }
//! ```
//!
//! **Never from the model.** The reference decides which files every tool call
//! of the session can reach, so an agent that could name one could name its
//! own toolchain. `chock-container/reference.zig` states the same rule for the
//! value itself.

const std = @import("std");

const ref = @import("reference.zig");

pub const file_name = "chock.zon";

/// The largest `chock.zon` this reader accepts. The same bound every other
/// reader of the same file carries, so one file has one size limit.
pub const max_file_bytes: usize = 256 * 1024;

pub const Error = std.mem.Allocator.Error || error{
    /// The file is there and could not be read.
    ReadFailed,
    /// The file is larger than `max_file_bytes`.
    FileTooLarge,
};

/// What one `load` produced.
pub const Answer = union(enum) {
    /// The project names no image. **The ordinary answer**, and the one every
    /// project gave before this block existed.
    none,
    /// The reference this project names. Owned by the allocator `load` was
    /// given.
    named: []const u8,
    /// One sentence saying what is wrong with the block. Owned by the
    /// allocator `load` was given.
    refused: []const u8,
};

/// The block this file reads. Every other top level field is skipped, because
/// other parts of Chock own the other blocks of the same file.
const block_name = "container";

/// The shape of the block. `ignore_unknown_fields` is not used: a field
/// nobody here knows is a mistake worth naming, because a person who wrote
/// `.imagee` should hear about it rather than get a session with no image.
const Block = struct {
    image: []const u8,
};

/// Read `chock.zon` from `project_root` and take its `container` block.
///
/// A project with no such file names no image, which is the same answer a file
/// with no such block gets.
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

/// Read the `container` block out of `source`, the whole content of a
/// `chock.zon`. The result borrows nothing from `source`.
pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8) std.mem.Allocator.Error!Answer {
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    // **`std.zon.parse.Diagnostics` takes both trees over**, so the two flags
    // are what stop this file freeing them twice. The same handover
    // `lib/chock-core/mcp.zig` makes, and for the same reason.
    var ast_owned = true;
    defer if (ast_owned) ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
    var zoir_owned = true;
    defer if (zoir_owned) zoir.deinit(gpa);

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

    var zon_diag: std.zon.parse.Diagnostics = .{};
    ast_owned = false;
    zoir_owned = false;
    defer zon_diag.deinit(gpa);

    const block = std.zon.parse.fromZoirNodeAlloc(
        Block,
        gpa,
        ast,
        zoir,
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
    defer std.zon.parse.free(gpa, block);

    // The same rule the reference itself carries, applied where a person can
    // still act on it: at the start, over the project's own file, and never
    // during a session.
    ref.check(block.image) catch |err| {
        return .{ .refused = try ref.refusalText(gpa, block.image, err) };
    };

    return .{ .named = try gpa.dupe(u8, block.image) };
}

/// Where the `container` field is, or why there is no answer.
///
/// The union carries a refusal because a top level that is not a struct
/// literal is a broken file rather than a project with no block, and the two
/// must not read the same.
const Located = union(enum) {
    none,
    refused: []const u8,
    named: std.zig.Zoir.Node.Index,
};

fn findBlockNode(gpa: std.mem.Allocator, zoir: std.zig.Zoir) std.mem.Allocator.Error!Located {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), block_name)) {
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
    // The one file holds every project rule, so a project that named a
    // language server and no image must read as a project with no image, and
    // never as a broken file.
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
    // A misspelled field is the case this exists for. Ignoring it would give a
    // session with no image and no reason, which is the shape of fault that
    // costs an hour.
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
