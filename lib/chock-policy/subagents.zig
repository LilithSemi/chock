//! How many subagents a project allows, from the `subagents` block of
//! `chock.zon`. The workspace binds the project's own copy back over that path
//! read only, so the model cannot raise its own limit.

const std = @import("std");

pub const file_name = "chock.zon";

pub const max_file_bytes = 1 << 20;

pub const default_max_depth: u16 = 6;
pub const default_max_width: u16 = 6;

/// `chock.zon` comes from the project directory, so a hostile project writes
/// it, and a limit of sixty thousand is a request for a tree no machine runs.
pub const max_settable: u16 = 64;

pub const Limits = struct {
    max_depth: u16 = default_max_depth,
    max_width: u16 = default_max_width,
    /// Only `explain` reads this. A refusal that blamed `chock.zon` for a
    /// number an organisation set would send the author to edit a file that
    /// does not hold it.
    depth_from_org: bool = false,
    /// Separate from `depth_from_org`, because a bundle may cap one and say
    /// nothing about the other.
    width_from_org: bool = false,

    /// Saturating, because a file names both numbers and the count grows with
    /// the power of the depth. Nothing enforces this number: it exists so a
    /// person can see what a pair of limits adds up to. The defaults of 6 and 6
    /// are called "36 agents", and the tree they describe holds 9331.
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

pub const Standing = struct {
    depth: usize = 1,
    width: usize = 0,
};

/// A field and not a rule, and a minimum and not a decision. This lives here
/// and not in `org.zig` so that `org.zig` imports this file and this file
/// imports nothing but `std`.
pub const Ceiling = struct {
    max_depth: ?u16 = null,
    /// Zero is a real answer here: it turns subagents off across the
    /// installation.
    max_width: ?u16 = null,
};

/// A minimum, and never a refusal. A budget above its org ceiling refuses the
/// session, because a budget quietly lowered ends a session in the middle of
/// the work. A spawn refused by one of these limits says so where it happens,
/// so the narrowing is silent here and loud where it lands.
///
/// Whichever side wins sets the matching flag, so the sentence a refused agent
/// reads names the file or the bundle correctly.
pub fn underCeiling(limits: Limits, ceiling: ?Ceiling) Limits {
    const bound = ceiling orelse return limits;
    var held = limits;
    if (bound.max_depth) |depth| {
        if (depth < held.max_depth) {
            held.max_depth = depth;
            held.depth_from_org = true;
        }
    }
    if (bound.max_width) |width| {
        if (width < held.max_width) {
            held.max_width = width;
            held.width_from_org = true;
        }
    }
    return held;
}

pub const Refusal = enum {
    depth,
    width,

    pub fn limitName(self: Refusal) []const u8 {
        return switch (self) {
            .depth => "max_depth",
            .width => "max_width",
        };
    }
};

/// Whether `limits` allow the agent at `standing` to start one more subagent.
/// Null permits it.
///
/// Depth is answered before width, because depth is a property of the whole
/// chain and width of this one agent. A depth of zero names no agent, and no
/// caller can reach this with one.
pub fn check(limits: Limits, standing: Standing) ?Refusal {
    std.debug.assert(standing.depth >= 1);
    if (standing.depth >= limits.max_depth) return .depth;
    if (standing.width >= limits.max_width) return .width;
    return null;
}

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
            .{ sourceOf(limits, refusal), limits.max_depth, standing.depth, plural(standing.depth, "agent", "agents") },
        ),
        .width => std.fmt.allocPrint(
            gpa,
            "no subagent was started: {s} sets max_width to {d}, and this agent has already " ++
                "started {d} {s}.",
            .{ sourceOf(limits, refusal), limits.max_width, standing.width, plural(standing.width, "subagent", "subagents") },
        ),
    };
}

pub const org_source_name = "this installation's org policy bundle";

fn sourceOf(limits: Limits, refusal: Refusal) []const u8 {
    const from_org = switch (refusal) {
        .depth => limits.depth_from_org,
        .width => limits.width_from_org,
    };
    return if (from_org) org_source_name else file_name;
}

fn plural(count: usize, one: []const u8, many: []const u8) []const u8 {
    return if (count == 1) one else many;
}

const WireLimits = struct {
    max_depth: ?u16 = null,
    max_width: ?u16 = null,
};

pub const ParseError = error{
    OutOfMemory,
    InvalidSubagents,
    LimitTooLarge,
};

pub const LoadError = ParseError || error{
    SubagentFileTooLarge,
    ReadFailed,
};

/// The two ZON variants own memory, because they hold the syntax tree their
/// message points into. A caller that receives one must call `deinit`.
pub const Diagnostic = union(enum) {
    file_not_zon: std.zon.parse.Diagnostics,
    block_not_valid: std.zon.parse.Diagnostics,
    not_a_struct_literal,
    limit_too_large: LimitTooLarge,
    file_too_large: usize,
    read_failed: anyerror,

    pub const LimitTooLarge = struct {
        field: []const u8,
        value: u16,
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

/// The first fault is kept and not the last. The answer matters because two
/// variants own memory: a site that hands over a `std.zon.parse.Diagnostics`
/// must release it itself when the answer is false.
fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// A file that names no `subagents` block gets the defaults above, which is a
/// real answer and not a missing one.
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
        if (note(diag, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidSubagents;
    }

    const node = try findSubagentsNode(zoir, diag) orelse return .{};

    var zon_diag: std.zon.parse.Diagnostics = .{};
    // From here the diagnostics own the two trees.
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

const testing = std.testing;

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
    try testing.expectEqual(@as(u64, 2), (Limits{ .max_depth = 2, .max_width = 1 }).largestTree());
    try testing.expectEqual(@as(u64, 9331), (Limits{}).largestTree());
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

test "an org ceiling narrows a project's limits and never widens them" {
    const generous = Limits{ .max_depth = 8, .max_width = 8 };
    const capped = Ceiling{ .max_depth = 3, .max_width = 2 };

    const held = underCeiling(generous, capped);
    try testing.expectEqual(@as(u16, 3), held.max_depth);
    try testing.expectEqual(@as(u16, 2), held.max_width);

    const modest = Limits{ .max_depth = 2, .max_width = 1 };
    const untouched = underCeiling(modest, capped);
    try testing.expectEqual(@as(u16, 2), untouched.max_depth);
    try testing.expectEqual(@as(u16, 1), untouched.max_width);
    try testing.expect(!untouched.depth_from_org);
    try testing.expect(!untouched.width_from_org);

    const none = underCeiling(generous, null);
    try testing.expectEqual(@as(u16, 8), none.max_depth);
    try testing.expectEqual(@as(u16, 8), none.max_width);
}

test "a bundle may cap one limit and say nothing about the other" {
    const project = Limits{ .max_depth = 8, .max_width = 8 };
    const width_only = underCeiling(project, .{ .max_width = 2 });

    try testing.expectEqual(@as(u16, 8), width_only.max_depth);
    try testing.expectEqual(@as(u16, 2), width_only.max_width);
    try testing.expect(!width_only.depth_from_org);
    try testing.expect(width_only.width_from_org);

    const off = underCeiling(project, .{ .max_width = 0 });
    try testing.expectEqual(@as(u16, 0), off.max_width);
    try testing.expectEqual(Refusal.width, check(off, .{ .depth = 1, .width = 0 }).?);
}

test "a refusal names the org bundle when the org is what lowered the limit" {
    const gpa = testing.allocator;
    const lowered = underCeiling(.{ .max_depth = 8, .max_width = 8 }, .{ .max_width = 2 });

    const width_text = try explain(gpa, .width, lowered, .{ .depth = 1, .width = 2 });
    defer gpa.free(width_text);
    try testing.expect(std.mem.indexOf(u8, width_text, org_source_name) != null);
    try testing.expect(std.mem.indexOf(u8, width_text, file_name) == null);

    const depth_text = try explain(gpa, .depth, lowered, .{ .depth = 8, .width = 0 });
    defer gpa.free(depth_text);
    try testing.expect(std.mem.indexOf(u8, depth_text, file_name) != null);
    try testing.expect(std.mem.indexOf(u8, depth_text, org_source_name) == null);
}
