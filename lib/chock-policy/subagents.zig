//! How many subagents a project allows, from the `subagents` block of
//! `chock.zon`.
//!
//! ```zon
//! .{
//!     .subagents = .{
//!         .max_depth = 6,
//!         .max_width = 6,
//!     },
//! }
//! ```
//!
//! **The two limits are configuration, not constants in the loop.** Section
//! 3.3 asks for a tree 6 deep and 6 wide, which is 36 agents, and those two
//! numbers are the defaults here. A project writes its own pair, and section
//! 6.2 already puts `chock.zon` beyond the agent's reach: the workspace binds
//! the project's own copy back over that path read only, so **the model
//! cannot raise its own limit**. `test/workspace/escape.zig` proves that on a
//! running system.
//!
//! ## Zero is a real setting, and it is the one that is tested first
//!
//! `max_width = 0` refuses every spawn, so it disables subagents. That is a
//! setting an author can want, and it is also the cheapest way to prove the
//! limit works at all: a limit that is never exercised at its boundary is a
//! limit nobody has tested. `check` gives the zero case no branch of its own,
//! so the test at zero and the test at six read the same code.
//!
//! ## This reader is strict inside its own block and lenient outside it
//!
//! The same split `lib/chock-policy/table.zig` and `lib/chock-cost/budget.zig`
//! make, and for the same reason: other milestones own the other blocks of
//! this one file, and a misspelled field name inside this one must never
//! become a limit the author did not write. `.max_dpeth = 3` is refused, not
//! read as the default of 6.

const std = @import("std");

/// The name of the configuration file, in the project root.
/// `lib/chock-policy/table.zig` looks in the same place.
pub const file_name = "chock.zon";

/// The largest `chock.zon` this reader accepts, matching the policy reader's
/// own bound: the file comes from the project directory, so a hostile project
/// supplies it.
pub const max_file_bytes = 1 << 20;

/// A tree 6 deep and 6 wide, which is 36 agents.
pub const default_max_depth: u16 = 6;
pub const default_max_width: u16 = 6;

/// The largest value either limit may hold. `chock.zon` comes from the
/// project directory, so a hostile project writes it, and a limit of sixty
/// thousand is a request for a tree no machine runs. Sixty four is far above
/// the 6 by 6 tree the defaults give and still bounds what one file can ask a
/// later milestone to start.
pub const max_settable: u16 = 64;

/// What one project allows. Both members count agents, and both accept zero.
pub const Limits = struct {
    /// The longest spawn chain, counting the agent a person started as 1.
    max_depth: u16 = default_max_depth,
    /// The most subagents any one agent may start.
    max_width: u16 = default_max_width,

    /// How many agents the largest tree these limits allow holds, the agent
    /// a person started included. Saturating, because a file names both
    /// numbers and the count grows with the power of the depth.
    ///
    /// Nothing enforces this number. It exists so a person reading a pair of
    /// limits can see what they add up to, which the pair itself does not
    /// say. The defaults of 6 and 6 are called "36 agents", which is 6 times
    /// 6; the tree those two limits actually describe holds 9331.
    pub fn largestTree(self: Limits) u64 {
        var total: u64 = 0;
        var level: u64 = 1;
        var depth: u16 = 0;
        while (depth < self.max_depth) : (depth += 1) {
            total +|= level;
            level *|= self.max_width;
        }
        return total;
    }
};

/// Where the agent that wants to spawn stands now. Both numbers come from
/// facts the agent's own session already holds, and neither is anything the
/// model says.
pub const Standing = struct {
    /// How many agents there are from the root of the spawn tree down to
    /// this one, this one included. The agent a person started is at 1.
    depth: usize = 1,
    /// How many subagents this agent has already started, which is the
    /// number of `session.spawn` events in its own log.
    width: usize = 0,
};

/// Which limit refused a spawn. An enum and not a sentence, so a caller acts
/// on the member and never on the words, the same reason
/// `event.SessionEndReason` has a member for the budget.
pub const Refusal = enum {
    depth,
    width,

    /// The name of the field in `chock.zon` that gave this answer, so a
    /// message can tell the author what to change.
    pub fn limitName(self: Refusal) []const u8 {
        return switch (self) {
            .depth => "max_depth",
            .width => "max_width",
        };
    }
};

/// Whether `limits` allow the agent at `standing` to start one more subagent.
/// Null permits it. A member of `Refusal` names the limit that refused it.
///
/// **Depth is answered before width.** Depth is a property of the whole
/// chain, and width is a property of this one agent, so an agent that is
/// already as deep as the tree goes hears about the tree first. Both are
/// reported by `explain` with the numbers that produced them, so neither
/// answer hides the other.
///
/// A depth of zero names no agent at all, and no caller can reach this with
/// one: the agent that asks is itself in the chain it is asking about.
pub fn check(limits: Limits, standing: Standing) ?Refusal {
    std.debug.assert(standing.depth >= 1);
    if (standing.depth >= limits.max_depth) return .depth;
    if (standing.width >= limits.max_width) return .width;
    return null;
}

/// The sentence a refused agent reads. It names the field of `chock.zon`
/// that refused, the value that field holds, and the number the agent
/// reached, so the answer is actionable by whoever reads the log and does
/// not depend on the reader already knowing the limits. The caller frees it.
pub fn explain(
    gpa: std.mem.Allocator,
    refusal: Refusal,
    limits: Limits,
    standing: Standing,
) std.mem.Allocator.Error![]u8 {
    return switch (refusal) {
        .depth => std.fmt.allocPrint(
            gpa,
            "no subagent was started: {s} sets max_depth to {d}, and this agent is already {d} " ++
                "{s} down the spawn chain.",
            .{ file_name, limits.max_depth, standing.depth, plural(standing.depth, "agent", "agents") },
        ),
        .width => std.fmt.allocPrint(
            gpa,
            "no subagent was started: {s} sets max_width to {d}, and this agent has already " ++
                "started {d} {s}.",
            .{ file_name, limits.max_width, standing.width, plural(standing.width, "subagent", "subagents") },
        ),
    };
}

fn plural(count: usize, one: []const u8, many: []const u8) []const u8 {
    return if (count == 1) one else many;
}

/// The shape the file itself is parsed into. Every member is optional here
/// and defaulted afterwards, so a file that names one limit and not the
/// other keeps the default of the one it left out.
const WireLimits = struct {
    max_depth: ?u16 = null,
    max_width: ?u16 = null,
};

pub const ParseError = error{
    OutOfMemory,
    /// The file is not valid ZON, or the `subagents` block does not match the
    /// schema. A value below zero and a value above `max_settable` for a
    /// `u16` both arrive here. Pass a `Diagnostic` to learn which line, and
    /// why.
    InvalidSubagents,
    /// A limit is above `max_settable`.
    LimitTooLarge,
};

pub const LoadError = ParseError || error{
    /// The file is larger than `max_file_bytes`.
    SubagentFileTooLarge,
    /// The file exists and could not be read. Pass a `Diagnostic` to learn
    /// which fault the filesystem gave.
    ReadFailed,
};

/// What went wrong while the subagents block was read, and the facts the
/// error alone throws away.
///
/// **The two ZON variants own memory**, because they hold the syntax tree
/// their message points into, which is how they can name a line and a column.
/// A caller that receives one must call `deinit`.
pub const Diagnostic = union(enum) {
    /// The file is not valid ZON at all. The parser names the place.
    file_not_zon: std.zon.parse.Diagnostics,
    /// The file is valid ZON, and its `subagents` block does not match the
    /// schema. A misspelled field name, and a value a `u16` cannot hold, both
    /// land here.
    block_not_valid: std.zon.parse.Diagnostics,
    /// The top level of the file is not a struct literal.
    not_a_struct_literal,
    /// A limit is above `max_settable`.
    limit_too_large: LimitTooLarge,
    /// The file is larger than `max_file_bytes`, so it was not read.
    file_too_large: usize,
    /// The file exists and the read failed. The fault is the filesystem's.
    read_failed: anyerror,

    pub const LimitTooLarge = struct {
        /// `max_depth` or `max_width`, always a literal of this file.
        field: []const u8,
        value: u16,
    };

    /// Release what the diagnostic owns. Safe on every variant.
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
                "{s}: the subagents block is not valid:\n{f}",
                .{ file_name, zon_diag },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{file_name},
            ),
            .limit_too_large => |limit| try writer.print(
                "{s}: the subagents block sets {s} to {d}, and this reader accepts {d}",
                .{ file_name, limit.field, limit.value, max_settable },
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

/// Read the limits out of `source`, the whole content of a `chock.zon`. A
/// file that names no `subagents` block gets the defaults above, which is a
/// real answer and not a missing one: every project has limits,
/// and a project that wrote none has these.
///
/// `diag` is optional. A caller that passes null pays nothing and learns only
/// the error. A caller that passes a slot must call `Diagnostic.deinit` on
/// whatever lands in it.
pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!Limits {
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
        // line here.
        if (note(diag, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidSubagents;
    }

    const node = try findSubagentsNode(zoir, diag) orelse return .{};

    var zon_diag: std.zon.parse.Diagnostics = .{};
    // From here the diagnostics own the two trees, the same handover
    // `lib/chock-policy/table.zig` makes.
    ast_owned = false;
    zoir_owned = false;
    var zon_diag_owned = true;
    defer if (zon_diag_owned) zon_diag.deinit(gpa);

    const wire = std.zon.parse.fromZoirNodeAlloc(
        WireLimits,
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
            return error.InvalidSubagents;
        },
    };
    defer std.zon.parse.free(gpa, wire);

    const limits = Limits{
        .max_depth = wire.max_depth orelse default_max_depth,
        .max_width = wire.max_width orelse default_max_width,
    };
    // A mistake in the file is reported when Chock reads the file, not on the
    // turn the agent happens to ask for a subagent.
    inline for (.{ "max_depth", "max_width" }) |field| {
        if (@field(limits, field) > max_settable) {
            _ = note(diag, .{ .limit_too_large = .{
                .field = field,
                .value = @field(limits, field),
            } });
            return error.LimitTooLarge;
        }
    }
    return limits;
}

/// Read `chock.zon` from `project_root` and take its limits. A project with
/// no such file gets the defaults, the same answer a file with no `subagents`
/// block gets.
///
/// `diag` carries the same detail `parse` carries, and the same rule applies:
/// null costs nothing, and a filled slot must be released with
/// `Diagnostic.deinit`.
pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Limits {
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
            return error.SubagentFileTooLarge;
        },
        else => {
            _ = note(diag, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, diag);
}

/// The node of the `subagents` field at the top of the file. Null when the
/// file has no such field. Every other top level field is skipped, because
/// other milestones own the other blocks of this one file.
fn findSubagentsNode(zoir: std.zig.Zoir, diag: ?*?Diagnostic) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), "subagents")) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidSubagents;
        },
    }
}

// Every test below builds its own source in the test binary. The one test
// that needs a real file writes it into a fresh `std.testing.tmpDir`, so no
// test reads the checkout that Chock itself lives in.

const testing = std.testing;

/// The absolute path of an already open directory. `std.testing.tmpDir` hands
/// back a directory that only a relative path reaches, and `load` needs a
/// project root that does not depend on the working directory of the test
/// binary. Mirrors the helper of the same name in
/// `lib/chock-policy/table.zig`.
fn absoluteDirPath(buffer: []u8, dir: std.Io.Dir) ![]u8 {
    const len = dir.realPath(testing.io, buffer) catch return error.RealPathFailed;
    return buffer[0..len];
}

test "a limit of zero refuses the first spawn, and the refusal names the limit" {
    const gpa = testing.allocator;

    const no_width = Limits{ .max_depth = 6, .max_width = 0 };
    const first_attempt = Standing{ .depth = 1, .width = 0 };
    try testing.expectEqual(Refusal.width, check(no_width, first_attempt).?);
    try testing.expectEqualStrings("max_width", Refusal.width.limitName());

    const width_text = try explain(gpa, .width, no_width, first_attempt);
    defer gpa.free(width_text);
    try testing.expect(std.mem.indexOf(u8, width_text, "max_width") != null);
    try testing.expect(std.mem.indexOf(u8, width_text, "max_width to 0") != null);
    try testing.expect(std.mem.indexOf(u8, width_text, "chock.zon") != null);

    const no_depth = Limits{ .max_depth = 0, .max_width = 6 };
    try testing.expectEqual(Refusal.depth, check(no_depth, first_attempt).?);

    const depth_text = try explain(gpa, .depth, no_depth, first_attempt);
    defer gpa.free(depth_text);
    try testing.expect(std.mem.indexOf(u8, depth_text, "max_depth to 0") != null);

    // A limit of zero is the same code as any other limit: it refuses every
    // attempt, however deep or wide the agent already is.
    for (0..4) |width| {
        for (1..4) |depth| {
            try testing.expectEqual(
                Refusal.width,
                check(no_width, .{ .depth = depth, .width = width }).?,
            );
        }
    }
}

test "a limit of one permits exactly one, and refuses the second" {
    // The step above zero. Width one lets the first child through and stops
    // the second; depth one is an agent that may start nothing at all,
    // because it is itself the whole of the chain the limit allows.
    const one_wide = Limits{ .max_depth = 6, .max_width = 1 };
    try testing.expectEqual(@as(?Refusal, null), check(one_wide, .{ .depth = 1, .width = 0 }));
    try testing.expectEqual(Refusal.width, check(one_wide, .{ .depth = 1, .width = 1 }).?);
    try testing.expectEqual(Refusal.width, check(one_wide, .{ .depth = 1, .width = 2 }).?);

    const one_deep = Limits{ .max_depth = 1, .max_width = 6 };
    try testing.expectEqual(Refusal.depth, check(one_deep, .{ .depth = 1, .width = 0 }).?);

    const two_deep = Limits{ .max_depth = 2, .max_width = 6 };
    try testing.expectEqual(@as(?Refusal, null), check(two_deep, .{ .depth = 1, .width = 0 }));
    try testing.expectEqual(Refusal.depth, check(two_deep, .{ .depth = 2, .width = 0 }).?);
}

test "the boundary of each limit: the seventh level and the seventh child are refused" {
    // The default numbers. Every value on each side of the boundary,
    // not one point of it: an off by one is only visible where the answer
    // changes, and the answer must keep changing in the same place for every
    // value that follows.
    const limits = Limits{};
    try testing.expectEqual(default_max_depth, limits.max_depth);
    try testing.expectEqual(default_max_width, limits.max_width);

    for (1..default_max_depth) |depth| {
        try testing.expectEqual(
            @as(?Refusal, null),
            check(limits, .{ .depth = depth, .width = 0 }),
        );
    }
    for (default_max_depth..default_max_depth + 4) |depth| {
        try testing.expectEqual(Refusal.depth, check(limits, .{ .depth = depth, .width = 0 }).?);
    }

    for (0..default_max_width) |width| {
        try testing.expectEqual(
            @as(?Refusal, null),
            check(limits, .{ .depth = 1, .width = width }),
        );
    }
    for (default_max_width..default_max_width + 4) |width| {
        try testing.expectEqual(Refusal.width, check(limits, .{ .depth = 1, .width = width }).?);
    }
}

test "an agent that has reached both limits hears about the depth" {
    const limits = Limits{ .max_depth = 3, .max_width = 3 };
    try testing.expectEqual(Refusal.depth, check(limits, .{ .depth = 3, .width = 3 }).?);
    try testing.expectEqual(Refusal.width, check(limits, .{ .depth = 2, .width = 3 }).?);
    try testing.expectEqual(Refusal.depth, check(limits, .{ .depth = 3, .width = 2 }).?);
}

test "a subagents block is read, and the rest of the file is left to other readers" {
    const source =
        \\.{
        \\    .policy = .{ .rules = .{ .{ .action = "git.push", .decision = .deny } } },
        \\    .budget = .{ .max_cost = 5.0 },
        \\    .subagents = .{ .max_depth = 3, .max_width = 2 },
        \\}
    ;
    const limits = try parse(testing.allocator, source, null);
    try testing.expectEqual(@as(u16, 3), limits.max_depth);
    try testing.expectEqual(@as(u16, 2), limits.max_width);
}

test "a file with no subagents block gets the tree the default asks for" {
    for ([_][:0]const u8{ ".{}", ".{ .policy = .{} }", ".{ .budget = .{ .max_cost = 1.0 } }" }) |source| {
        const limits = try parse(testing.allocator, source, null);
        try testing.expectEqual(default_max_depth, limits.max_depth);
        try testing.expectEqual(default_max_width, limits.max_width);
    }

    const only_width = try parse(testing.allocator, ".{ .subagents = .{ .max_width = 0 } }", null);
    try testing.expectEqual(default_max_depth, only_width.max_depth);
    try testing.expectEqual(@as(u16, 0), only_width.max_width);
}

test "a limit of zero is read, where the budget's own cap of zero is refused" {
    // The two blocks answer differently on purpose, and this test says so.
    // A cap of zero money refuses the first turn of every session, which no
    // author means to write. A width of zero refuses every subagent, which is
    // exactly how an author turns subagents off.
    const limits = try parse(testing.allocator, ".{ .subagents = .{ .max_depth = 0, .max_width = 0 } }", null);
    try testing.expectEqual(@as(u16, 0), limits.max_depth);
    try testing.expectEqual(@as(u16, 0), limits.max_width);
    try testing.expectEqual(Refusal.depth, check(limits, .{}).?);
}

test "a misspelled field inside the subagents block is refused rather than read as the default" {
    try testing.expectError(
        error.InvalidSubagents,
        parse(testing.allocator, ".{ .subagents = .{ .max_dpeth = 0 } }", null),
    );
    try testing.expectError(
        error.InvalidSubagents,
        parse(testing.allocator, ".{ .subagents = .{ .max_wdith = 0 } }", null),
    );

    // A field name this reader does not know, outside the block, belongs to
    // another milestone. That one is read past.
    const limits = try parse(testing.allocator, ".{ .telepathy = .{ .range_m = 3 } }", null);
    try testing.expectEqual(default_max_width, limits.max_width);
}

test "a limit below zero or above the bound is refused when the file is read" {
    try testing.expectError(
        error.InvalidSubagents,
        parse(testing.allocator, ".{ .subagents = .{ .max_width = -1 } }", null),
    );
    try testing.expectError(
        error.LimitTooLarge,
        parse(testing.allocator, ".{ .subagents = .{ .max_width = 65 } }", null),
    );
    try testing.expectError(
        error.LimitTooLarge,
        parse(testing.allocator, ".{ .subagents = .{ .max_depth = 65 } }", null),
    );

    const at_bound = try parse(testing.allocator, ".{ .subagents = .{ .max_depth = 64, .max_width = 64 } }", null);
    try testing.expectEqual(max_settable, at_bound.max_depth);
    try testing.expectEqual(max_settable, at_bound.max_width);
}

test "the limits come off the disk, and a project with no file gets the defaults" {
    const gpa = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absoluteDirPath(&path_buffer, tmp.dir);

    // No file at all.
    const missing = try load(gpa, testing.io, root, null);
    try testing.expectEqual(default_max_width, missing.max_width);

    {
        var file = try tmp.dir.createFile(testing.io, file_name, .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, ".{ .subagents = .{ .max_width = 0 } }");
    }

    const written = try load(gpa, testing.io, root, null);
    try testing.expectEqual(@as(u16, 0), written.max_width);
    try testing.expectEqual(Refusal.width, check(written, .{}).?);
}

test "the largest tree a pair of limits allows is a number a person can read" {
    try testing.expectEqual(@as(u64, 1), (Limits{ .max_depth = 1, .max_width = 6 }).largestTree());
    try testing.expectEqual(@as(u64, 0), (Limits{ .max_depth = 0, .max_width = 6 }).largestTree());
    // One agent, and one child of it.
    try testing.expectEqual(@as(u64, 2), (Limits{ .max_depth = 2, .max_width = 1 }).largestTree());
    // 1 + 6 + 36 + 216 + 1296 + 7776, the default pair.
    try testing.expectEqual(@as(u64, 9331), (Limits{}).largestTree());
    // A width of zero is one agent and nothing under it, at any depth.
    try testing.expectEqual(@as(u64, 1), (Limits{ .max_depth = 6, .max_width = 0 }).largestTree());
}

test "the field and the value of a limit that is too large reach the caller" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(
        error.LimitTooLarge,
        parse(testing.allocator, ".{ .subagents = .{ .max_depth = 65 } }", &diag),
    );
    try testing.expectEqualStrings("max_depth", diag.?.limit_too_large.field);
    try testing.expectEqual(@as(u16, 65), diag.?.limit_too_large.value);

    var buffer: [160]u8 = undefined;
    try testing.expectEqualStrings(
        "chock.zon: the subagents block sets max_depth to 65, and this reader accepts 64",
        try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?}),
    );
}

test "a misspelled field names its line and column, and the trees behind it are released" {
    // The ZON variants own the syntax tree the message points into. The
    // testing allocator fails this test if `deinit` misses it.
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(
        error.InvalidSubagents,
        parse(testing.allocator, ".{ .subagents = .{ .max_dpeth = 0 } }", &diag),
    );

    var buffer: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.startsWith(u8, line, "chock.zon: the subagents block is not valid:\n"));
    try testing.expect(std.mem.indexOf(u8, line, "1:21: error:") != null);
    try testing.expect(std.mem.indexOf(u8, line, "max_dpeth") != null);
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
        .{ .limit_too_large = .{ .field = "max_width", .value = 65 } },
        .{ .file_too_large = max_file_bytes },
        .{ .read_failed = error.AccessDenied },
    };
    var buffers: [cases.len][256]u8 = undefined;
    var lines: [cases.len][]const u8 = undefined;
    for (cases, 0..) |case, i| {
        lines[i] = try std.fmt.bufPrint(&buffers[i], "{f}", .{&case});
        try testing.expect(lines[i].len > 0);
    }
    for (lines, 0..) |line, i| {
        for (lines[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, line, other));
    }
}
