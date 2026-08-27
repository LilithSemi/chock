//! The `budget` block of `chock.zon`, which is what a session may spend.
//!
//! ```zon
//! .{
//!     .budget = .{
//!         .max_cost = 5.00,
//!         .currency = "USD",
//!     },
//! }
//! ```
//!
//! **The cap lives in `chock.zon` and nowhere else**, and that file is already
//! beyond the agent's reach: the workspace binds the project's
//! own copy back over the path read only, so a tool call that tries to write
//! it fails. The budget is therefore a control the user holds and the model
//! cannot touch, and that property comes for free from work already done.
//! `test/workspace/escape.zig` proves it on a running system rather than
//! taking it on trust.
//!
//! This reader is lenient about the rest of the file and strict inside its
//! own block, the same split `lib/chock-policy/table.zig` makes and for the
//! same reason: another milestone owns the other blocks, and a misspelled
//! field name inside this one must never become a cap that is not the cap the
//! author meant. `.max_cst = 5.0` is refused, not read as no cap at all.

const std = @import("std");

/// The name of the configuration file, in the project root.
/// `lib/chock-policy/table.zig` and `lib/chock-workspace/Workspace.zig` look
/// in the same place.
pub const file_name = "chock.zon";

/// The largest `chock.zon` this reader accepts, matching the policy reader's
/// own bound: the file comes from the project directory, so a hostile project
/// supplies it.
pub const max_file_bytes = 1 << 20;

pub const Budget = struct {
    /// The ceiling, in `currency`. **Enforced before a request goes out**,
    /// because money cannot be un-spent.
    max_cost: f64,
    /// ISO 4217. A session whose provider reports a different currency
    /// cannot be summed against this one, and `chock_proto.state.Spend` says
    /// so rather than adding the two. Always owned by this `Budget`, even
    /// when the file left it out: see `WireBudget`.
    currency: []const u8 = "USD",
};

/// The shape the file itself is parsed into, before the default is applied.
///
/// **`currency` is optional here and defaulted afterwards, on purpose.**
/// `std.zon.parse` leaves a field the file did not name at its declared
/// default, which for a slice is a string literal with no allocation behind
/// it, and then `std.zon.parse.free` walks every slice of the result and
/// frees it. A default of `"USD"` therefore crashes on the free path for
/// every file that did not spell the currency out, which is most of them.
/// An optional starts as null, frees nothing, and this file makes the owned
/// copy itself.
const WireBudget = struct {
    max_cost: f64,
    currency: ?[]const u8 = null,
};

pub const default_currency = "USD";

pub const ParseError = error{
    OutOfMemory,
    /// The file is not valid ZON, or the `budget` block does not match the
    /// schema. Pass a `Diagnostic` to learn which line, and why.
    InvalidBudget,
    /// `max_cost` is zero, negative, or not a number. A cap of zero would
    /// refuse the first turn of every session, which is never what an author
    /// meant to write, and a negative one has no meaning at all.
    InvalidMaxCost,
};

pub const LoadError = ParseError || error{
    /// The file is larger than `max_file_bytes`.
    BudgetFileTooLarge,
    /// The file exists and could not be read. Pass a `Diagnostic` to learn
    /// which fault the filesystem gave.
    ReadFailed,
};

/// What went wrong while the budget block was read, and the facts the error
/// alone throws away.
///
/// **The two ZON variants own memory.** `std.zon.parse.Diagnostics` holds the
/// syntax tree the message points into, which is why it can name a line and a
/// column. A caller that receives one must call `deinit`. Every other variant
/// holds numbers only.
pub const Diagnostic = union(enum) {
    /// The file is not valid ZON at all. The parser names the place.
    file_not_zon: std.zon.parse.Diagnostics,
    /// The file is valid ZON, and its `budget` block does not match the
    /// schema. A misspelled field name lands here.
    block_not_valid: std.zon.parse.Diagnostics,
    /// The top level of the file is not a struct literal.
    not_a_struct_literal,
    /// `max_cost` is not a number above zero. The value is what the file said.
    max_cost_not_positive: f64,
    /// The file is larger than `max_file_bytes`, so it was not read.
    file_too_large: usize,
    /// The file exists and the read failed. The fault is the filesystem's.
    read_failed: anyerror,

    /// Release what the diagnostic owns. Safe on every variant, so a caller
    /// can call it without asking which one it holds.
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
        }
    }
};

/// Fill `out` when the caller asked for one, and say whether it took `value`.
///
/// **The first fault is kept, not the last.** A later step can only fail
/// because an earlier one did, so the first is the one that explains the rest.
///
/// The answer matters because two variants own memory: a site that hands over
/// a `std.zon.parse.Diagnostics` must release it itself when the answer is
/// false, or the trees leak.
fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// Read the budget out of `source`, the whole content of a `chock.zon`. Null
/// when the file names no budget, which is a project that set no cap.
///
/// The returned `Budget` owns its `currency` string. `free` releases it with
/// the same allocator.
///
/// `diag` is optional. A caller that passes null pays nothing and learns only
/// the error. A caller that passes a slot must call `Diagnostic.deinit` on
/// whatever lands in it.
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
        // The two trees carry the message, the line and the column, so they
        // go to the caller whole rather than being flattened to a printed
        // line here. `std.zon.parse.Diagnostics` owns both from this point.
        if (note(diag, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidBudget;
    }

    const node = try findBudgetNode(zoir, diag) orelse return null;

    var zon_diag: std.zon.parse.Diagnostics = .{};
    // From here the diagnostics own the two trees, the same handover
    // `lib/chock-policy/table.zig` makes.
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

/// Release a `Budget` that `parse` or `load` returned.
pub fn free(gpa: std.mem.Allocator, budget: Budget) void {
    gpa.free(budget.currency);
}

/// Read `chock.zon` from `project_root` and take its budget. Null when the
/// project has no such file, or has one that names no budget: both mean the
/// same thing, which is that this project set no cap.
///
/// `diag` carries the same detail `parse` carries, and the same rule applies:
/// null costs nothing, and a filled slot must be released with
/// `Diagnostic.deinit`.
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

/// The node of the `budget` field at the top of the file. Null when the file
/// has no such field. Every other top level field is skipped, because other
/// milestones own the other blocks of this one file.
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
    // The ZON variants own the syntax tree the message points into. The
    // testing allocator fails this test if `deinit` misses it.
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
    // A reader has to be able to tell which one happened. Every variant is
    // rendered with a payload that is legal for it.
    const cases: []const Diagnostic = &.{
        .not_a_struct_literal,
        .{ .max_cost_not_positive = 0 },
        .{ .file_too_large = max_file_bytes },
        .{ .read_failed = error.AccessDenied },
    };
    var buffers: [4][256]u8 = undefined;
    var lines: [4][]const u8 = undefined;
    for (cases, 0..) |case, i| {
        lines[i] = try std.fmt.bufPrint(&buffers[i], "{f}", .{&case});
        try testing.expect(lines[i].len > 0);
    }
    for (lines, 0..) |line, i| {
        for (lines[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, line, other));
    }
}
