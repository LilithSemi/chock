//! The `budget` block: session cost ceiling.

const std = @import("std");

pub const file_name = "chock.zon";
pub const max_file_bytes = 1 << 20;

pub const Budget = struct {
    max_cost: f64,
    currency: []const u8 = "USD",
};

const WireBudget = struct {
    max_cost: f64,
    currency: ?[]const u8 = null,
};

pub const default_currency = "USD";

pub const ParseError = error{
    OutOfMemory,
    InvalidBudget,
    InvalidMaxCost,
};

pub const LoadError = ParseError || error{
    BudgetFileTooLarge,
    ReadFailed,
};

pub const CeilingError = error{
    AboveOrgCeiling,
    CurrencyDiffersFromCeiling,
};

pub const Diagnostic = union(enum) {
    file_not_zon: std.zon.parse.Diagnostics,
    block_not_valid: std.zon.parse.Diagnostics,
    not_a_struct_literal,
    max_cost_not_positive: f64,
    file_too_large: usize,
    read_failed: anyerror,
    above_org_ceiling: Ceilinged,
    currency_differs_from_ceiling: Currencies,

    pub const Ceilinged = struct {
        asked: f64,
        ceiling: f64,
        currency: []const u8,
    };

    /// Borrowed, not owned: the caller's budget and ceiling outlive the
    /// diagnostic.
    pub const Currencies = struct {
        asked: []const u8,
        ceiling: []const u8,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .file_not_zon, .block_not_valid => |*zon_diag| zon_diag.deinit(gpa),
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .file_not_zon => |*zon_diag| try writer.print(
                "{s} is not valid:\n{f}",
                .{ file_name, zon_diag },
            ),
            .block_not_valid => |*zon_diag| try writer.print(
                "{s}: the budget block is not valid:\n{f}",
                .{ file_name, zon_diag },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{file_name},
            ),
            .max_cost_not_positive => |value| try writer.print(
                "{s}: the budget's max_cost must be a number above zero, and this one is {d}",
                .{ file_name, value },
            ),
            .file_too_large => |limit| try writer.print(
                "{s}: the file is larger than {d} bytes, so it was not read",
                .{ file_name, limit },
            ),
            .read_failed => |err| try writer.print(
                "{s}: the file could not be read: {t}",
                .{ file_name, err },
            ),
            .above_org_ceiling => |pair| try writer.print(
                "a budget of {d} {s} is above the org policy bundle's ceiling of {d} {s}. " ++
                    "The budget comes from the budget block of {s}, or from the parent of a " ++
                    "subagent, and neither may pass the ceiling. Lower the budget, or ask " ++
                    "whoever issued the bundle for a higher ceiling.",
                .{ pair.asked, pair.currency, pair.ceiling, pair.currency, file_name },
            ),
            .currency_differs_from_ceiling => |pair| try writer.print(
                "the budget is in {s} and the org policy bundle's ceiling is in {s}. Two amounts " ++
                    "in two currencies cannot be compared, and an exchange rate invented here " ++
                    "would be a cap nobody wrote. Write the budget in {s}, or ask whoever issued " ++
                    "the bundle for a ceiling in {s}.",
                .{ pair.asked, pair.ceiling, pair.ceiling, pair.asked },
            ),
        }
    }
};

/// A site that hands over a `std.zon.parse.Diagnostics` must release it
/// itself when the answer is false, or the trees leak.
fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// The returned `Budget` owns its `currency` string, released by `free`.
/// A given `diag` must be released with `Diagnostic.deinit`.
pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!?Budget {
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    var ast_owned = true;
    defer if (ast_owned) ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
    var zoir_owned = true;
    defer if (zoir_owned) zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        // The two trees carry the message, line and column, and
        // `std.zon.parse.Diagnostics` owns both from this point.
        if (note(diag, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidBudget;
    }

    const node = try findBudgetNode(zoir, diag) orelse return null;

    var zon_diag: std.zon.parse.Diagnostics = .{};
    // From here the diagnostics own the two trees.
    ast_owned = false;
    zoir_owned = false;
    var zon_diag_owned = true;
    defer if (zon_diag_owned) zon_diag.deinit(gpa);

    const wire = std.zon.parse.fromZoirNodeAlloc(
        WireBudget,
        gpa,
        ast,
        zoir,
        node,
        &zon_diag,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            if (note(diag, .{ .block_not_valid = zon_diag })) zon_diag_owned = false;
            return error.InvalidBudget;
        },
    };
    defer std.zon.parse.free(gpa, wire);

    if (!(wire.max_cost > 0) or !std.math.isFinite(wire.max_cost)) {
        _ = note(diag, .{ .max_cost_not_positive = wire.max_cost });
        return error.InvalidMaxCost;
    }

    return Budget{
        .max_cost = wire.max_cost,
        .currency = try gpa.dupe(u8, wire.currency orelse default_currency),
    };
}

pub fn free(gpa: std.mem.Allocator, budget: Budget) void {
    gpa.free(budget.currency);
}

/// The fold for a number is the minimum, but a budget above its ceiling
/// refuses rather than silently lowering it. Two different currencies
/// refuse rather than compare. The answer borrows its `currency`, so both
/// must outlive it.
pub fn underCeiling(
    asked: ?Budget,
    ceiling: ?Budget,
    diag: ?*?Diagnostic,
) CeilingError!?Budget {
    const cap = ceiling orelse return asked;
    const want = asked orelse return cap;

    if (!std.mem.eql(u8, want.currency, cap.currency)) {
        _ = note(diag, .{ .currency_differs_from_ceiling = .{
            .asked = want.currency,
            .ceiling = cap.currency,
        } });
        return error.CurrencyDiffersFromCeiling;
    }
    if (want.max_cost > cap.max_cost) {
        _ = note(diag, .{ .above_org_ceiling = .{
            .asked = want.max_cost,
            .ceiling = cap.max_cost,
            .currency = cap.currency,
        } });
        return error.AboveOrgCeiling;
    }
    return want;
}

/// A given `diag` must be released with `Diagnostic.deinit`.
pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) LoadError!?Budget {
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
        error.FileNotFound => return null,
        error.StreamTooLong => {
            _ = note(diag, .{ .file_too_large = max_file_bytes });
            return error.BudgetFileTooLarge;
        },
        else => {
            _ = note(diag, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, diag);
}

fn findBudgetNode(zoir: std.zig.Zoir, diag: ?*?Diagnostic) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), "budget")) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidBudget;
        },
    }
}

const testing = std.testing;

test "a budget block is read, and the rest of the file is left to other readers" {
    const source =
        \\.{
        \\    .policy = .{ .rules = .{ .{ .action = "git.push", .decision = .deny } } },
        \\    .budget = .{ .max_cost = 5.0, .currency = "USD" },
        \\}
    ;
    const budget = (try parse(testing.allocator, source, null)).?;
    defer free(testing.allocator, budget);
    try testing.expectApproxEqAbs(@as(f64, 5.0), budget.max_cost, 1e-12);
    try testing.expectEqualStrings("USD", budget.currency);
}

test "a file with no budget block sets no cap, and that is not an error" {
    try testing.expectEqual(@as(?Budget, null), try parse(testing.allocator, ".{}", null));
    try testing.expectEqual(
        @as(?Budget, null),
        try parse(testing.allocator, ".{ .policy = .{} }", null),
    );
}

test "a misspelled field inside the budget block is refused rather than read as no cap" {
    try testing.expectError(
        error.InvalidBudget,
        parse(testing.allocator, ".{ .budget = .{ .max_cst = 5.0 } }", null),
    );
}

test "a cap of zero or below is refused when the file is read, not on the turn it would bite" {
    try testing.expectError(
        error.InvalidMaxCost,
        parse(testing.allocator, ".{ .budget = .{ .max_cost = 0.0 } }", null),
    );
    try testing.expectError(
        error.InvalidMaxCost,
        parse(testing.allocator, ".{ .budget = .{ .max_cost = -1.0 } }", null),
    );
}

test "the currency defaults to USD when the block leaves it out" {
    const budget = (try parse(testing.allocator, ".{ .budget = .{ .max_cost = 2.5 } }", null)).?;
    defer free(testing.allocator, budget);
    try testing.expectEqualStrings("USD", budget.currency);
}

test "the value a bad max_cost held reaches the caller, and no longer only a terminal" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(
        error.InvalidMaxCost,
        parse(testing.allocator, ".{ .budget = .{ .max_cost = -1.0 } }", &diag),
    );
    try testing.expectApproxEqAbs(@as(f64, -1.0), diag.?.max_cost_not_positive, 1e-12);

    var buffer: [160]u8 = undefined;
    try testing.expectEqualStrings(
        "chock.zon: the budget's max_cost must be a number above zero, and this one is -1",
        try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?}),
    );
}

test "a misspelled field names its line and column, and the trees behind it are released" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(
        error.InvalidBudget,
        parse(testing.allocator, ".{ .budget = .{ .max_cst = 5.0 } }", &diag),
    );

    var buffer: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.startsWith(u8, line, "chock.zon: the budget block is not valid:\n"));
    try testing.expect(std.mem.indexOf(u8, line, "1:18: error:") != null);
    try testing.expect(std.mem.indexOf(u8, line, "max_cst") != null);
}

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    try testing.expect(note(&diag, .not_a_struct_literal));
    try testing.expect(!note(&diag, .{ .read_failed = error.AccessDenied }));
    try testing.expectEqual(Diagnostic.not_a_struct_literal, diag.?);

    try testing.expect(!note(null, .not_a_struct_literal));
}

test "no two faults of this module read the same" {
    const cases: []const Diagnostic = &.{
        .not_a_struct_literal,
        .{ .max_cost_not_positive = 0 },
        .{ .file_too_large = max_file_bytes },
        .{ .read_failed = error.AccessDenied },
        .{ .above_org_ceiling = .{ .asked = 50, .ceiling = 5, .currency = "USD" } },
        .{ .currency_differs_from_ceiling = .{ .asked = "JPY", .ceiling = "USD" } },
    };
    var buffers: [6][512]u8 = undefined;
    var lines: [6][]const u8 = undefined;
    for (cases, 0..) |case, i| {
        lines[i] = try std.fmt.bufPrint(&buffers[i], "{f}", .{&case});
        try testing.expect(lines[i].len > 0);
    }
    for (lines, 0..) |line, i| {
        for (lines[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, line, other));
    }
}

test "a project under the org ceiling keeps its own budget" {
    const project = Budget{ .max_cost = 2.5, .currency = "USD" };
    const ceiling = Budget{ .max_cost = 5.0, .currency = "USD" };
    const folded = (try underCeiling(project, ceiling, null)).?;
    try testing.expectApproxEqAbs(@as(f64, 2.5), folded.max_cost, 1e-12);
    try testing.expectEqualStrings("USD", folded.currency);

    const at_the_line = (try underCeiling(
        .{ .max_cost = 5.0, .currency = "USD" },
        ceiling,
        null,
    )).?;
    try testing.expectApproxEqAbs(@as(f64, 5.0), at_the_line.max_cost, 1e-12);
}

test "a project above the org ceiling is refused, and the refusal names both numbers" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(error.AboveOrgCeiling, underCeiling(
        .{ .max_cost = 50.0, .currency = "USD" },
        .{ .max_cost = 5.0, .currency = "USD" },
        &diag,
    ));
    try testing.expectApproxEqAbs(@as(f64, 50.0), diag.?.above_org_ceiling.asked, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 5.0), diag.?.above_org_ceiling.ceiling, 1e-12);

    var buffer: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.indexOf(u8, line, "50 USD") != null);
    try testing.expect(std.mem.indexOf(u8, line, "5 USD") != null);
    try testing.expect(std.mem.indexOf(u8, line, "chock.zon") != null);
}

test "an org bundle with no ceiling leaves a project's own budget alone" {
    const project = Budget{ .max_cost = 900.0, .currency = "JPY" };
    const folded = (try underCeiling(project, null, null)).?;
    try testing.expectApproxEqAbs(@as(f64, 900.0), folded.max_cost, 1e-12);
    try testing.expectEqualStrings("JPY", folded.currency);

    try testing.expectEqual(@as(?Budget, null), try underCeiling(null, null, null));
}

test "a project with no budget of its own takes the org ceiling" {
    const folded = (try underCeiling(null, .{ .max_cost = 5.0, .currency = "USD" }, null)).?;
    try testing.expectApproxEqAbs(@as(f64, 5.0), folded.max_cost, 1e-12);
    try testing.expectEqualStrings("USD", folded.currency);
}

test "a budget and a ceiling in two currencies refuse rather than compare" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(error.CurrencyDiffersFromCeiling, underCeiling(
        .{ .max_cost = 900.0, .currency = "JPY" },
        .{ .max_cost = 5.0, .currency = "USD" },
        &diag,
    ));
    try testing.expectEqualStrings("JPY", diag.?.currency_differs_from_ceiling.asked);
    try testing.expectEqualStrings("USD", diag.?.currency_differs_from_ceiling.ceiling);

    try testing.expectError(error.CurrencyDiffersFromCeiling, underCeiling(
        .{ .max_cost = 1.0, .currency = "JPY" },
        .{ .max_cost = 5.0, .currency = "USD" },
        null,
    ));

    var buffer: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.indexOf(u8, line, "JPY") != null);
    try testing.expect(std.mem.indexOf(u8, line, "USD") != null);
}
