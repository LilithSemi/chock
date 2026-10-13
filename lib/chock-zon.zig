//! Parsing one named block out of a larger ZON file.
//!
//! **A workaround for Zig 0.17.0.** `std.zon.parse.FromZoirOptions` carries a
//! `node` field, documented as the node to start parsing at, and
//! `fromZoirInner` builds its `InnerOptions` without it, so the value falls
//! back to `.root` and the whole file is parsed instead of the block. Nothing
//! Zig ships calls `fromZoir`, so the option is never exercised there.
//!
//! The way around it is to hand `fromSlice` the block's own source text, cut
//! out of the file with the span the AST already knows. That keeps a strict
//! parse inside the block, which `ignore_unknown_fields` could not: the flag
//! covers every struct in the parse, so relaxing the outer file would relax the
//! block with it.
//!
//! Delete this once a Zig release passes `node` through, and go back to
//! `std.zon.parse.fromZoir`.

const std = @import("std");

/// The source text of one Zoir node, cut from the file it was parsed from.
///
/// Sentinel terminated and owned by `arena`, because `fromSlice` takes a
/// `[:0]const u8` and a slice of the original carries no terminator.
pub fn nodeSource(
    arena: std.mem.Allocator,
    source: [:0]const u8,
    ast: *const std.zig.Ast,
    zoir: *const std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
) std.mem.Allocator.Error![:0]const u8 {
    // The token bounds and not `nodeToSpan`: that goes through `tokensToSpan`,
    // which collapses a span to its main token when the ends sit on different
    // lines. That is right for quoting one line of a diagnostic and wrong here,
    // where a block written across lines would be cut down to its opening `.{`.
    const ast_node = node.getAstNode(zoir);
    const first = ast.firstToken(ast_node);
    const last = ast.lastToken(ast_node);
    const start = ast.tokenStart(first);
    const end = ast.tokenStart(last) + @as(u32, @intCast(ast.tokenSlice(last).len));
    return arena.dupeSentinel(u8, source[start..end], 0);
}

/// `std.zon.parse.fromZoir` for one node, with the node actually honoured.
///
/// The positions in `diagnostics` are relative to the block, not to the file.
pub fn fromNode(
    T: type,
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    source: [:0]const u8,
    ast: *const std.zig.Ast,
    zoir: *const std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    diagnostics: *std.zon.parse.Diagnostics,
    options: struct { ignore_unknown_fields: bool = false },
) error{ OutOfMemory, ParseZon }!T {
    const block = try nodeSource(arena, source, ast, zoir, node);
    return std.zon.parse.fromSlice(T, .{
        .gpa = gpa,
        .arena = arena,
        .source = block,
        .diagnostics = diagnostics,
        .ignore_unknown_fields = options.ignore_unknown_fields,
    });
}

const testing = std.testing;

test "a named block is parsed on its own, and the rest of the file is not" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{ .rules = .{} },
        \\    .budget = .{ .max_cost = 5.0, .currency = "USD" },
        \\}
    ;

    var ast = try std.zig.Ast.parse(testing.allocator, source, .{ .mode = .zon });
    defer ast.deinit(testing.allocator);
    var zoir = try std.zig.ZonGen.generate(testing.allocator, ast, .{ .parse_str_lits = false });
    defer zoir.deinit(testing.allocator);

    const root: std.zig.Zoir.Node.Index = .root;
    const fields = root.get(&zoir).struct_literal;
    var budget: ?std.zig.Zoir.Node.Index = null;
    for (fields.names, 0..) |name, index| {
        if (std.mem.eql(u8, name.get(&zoir), "budget")) budget = fields.vals.at(@intCast(index));
    }

    const Wire = struct { max_cost: f64, currency: []const u8 };
    var diag: std.zon.parse.Diagnostics = undefined;
    const wire = try fromNode(Wire, testing.allocator, arena, source, &ast, &zoir, budget.?, &diag, .{});

    try testing.expectApproxEqAbs(@as(f64, 5.0), wire.max_cost, 1e-12);
    try testing.expectEqualStrings("USD", wire.currency);
}

test "a misspelled field inside the block is still refused" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{},
        \\    .budget = .{ .max_const = 5.0 },
        \\}
    ;

    var ast = try std.zig.Ast.parse(testing.allocator, source, .{ .mode = .zon });
    defer ast.deinit(testing.allocator);
    var zoir = try std.zig.ZonGen.generate(testing.allocator, ast, .{ .parse_str_lits = false });
    defer zoir.deinit(testing.allocator);

    const root: std.zig.Zoir.Node.Index = .root;
    const fields = root.get(&zoir).struct_literal;
    var budget: ?std.zig.Zoir.Node.Index = null;
    for (fields.names, 0..) |name, index| {
        if (std.mem.eql(u8, name.get(&zoir), "budget")) budget = fields.vals.at(@intCast(index));
    }

    const Wire = struct { max_cost: f64 = 0 };
    var diag: std.zon.parse.Diagnostics = undefined;
    // Strict: the outer file is not in the parse at all, so nothing has to be
    // relaxed to get past `.policy`.
    try testing.expectError(
        error.ParseZon,
        fromNode(Wire, testing.allocator, arena, source, &ast, &zoir, budget.?, &diag, .{}),
    );
}

test "a block written across lines is cut whole, not down to its opening brace" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{ .rules = .{} },
        \\    .budget = .{
        \\        .max_cost = 5.0,
        \\        .currency = "USD",
        \\    },
        \\}
    ;

    var ast = try std.zig.Ast.parse(testing.allocator, source, .{ .mode = .zon });
    defer ast.deinit(testing.allocator);
    var zoir = try std.zig.ZonGen.generate(testing.allocator, ast, .{ .parse_str_lits = false });
    defer zoir.deinit(testing.allocator);

    const root: std.zig.Zoir.Node.Index = .root;
    const fields = root.get(&zoir).struct_literal;
    var budget: ?std.zig.Zoir.Node.Index = null;
    for (fields.names, 0..) |name, index| {
        if (std.mem.eql(u8, name.get(&zoir), "budget")) budget = fields.vals.at(@intCast(index));
    }

    const cut = try nodeSource(arena, source, &ast, &zoir, budget.?);
    try testing.expect(std.mem.indexOf(u8, cut, "max_cost") != null);
    try testing.expect(std.mem.indexOf(u8, cut, "USD") != null);
    try testing.expect(std.mem.endsWith(u8, cut, "}"));

    const Wire = struct { max_cost: f64, currency: []const u8 };
    var diag: std.zon.parse.Diagnostics = undefined;
    const wire = try fromNode(Wire, testing.allocator, arena, source, &ast, &zoir, budget.?, &diag, .{});
    try testing.expectApproxEqAbs(@as(f64, 5.0), wire.max_cost, 1e-12);
    try testing.expectEqualStrings("USD", wire.currency);
}
