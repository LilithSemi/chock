//! How an approved `workspace.apply` lands in the project, from the `apply`
//! block of `chock.zon`, with a ceiling on the table that already exists.

const std = @import("std");
const table = @import("table.zig");

pub const file_name = "chock.zon";

pub const max_file_bytes = 1 << 20;

/// Named for what the project needs and not for what is given up.
/// `workspace.no_branch_move` would make an author work out what that had to do
/// with them.
/// A rule that names nothing reaches this row, because `workspace.integrate` is
/// matched by a catch all and by `workspace.*`. A rule naming `workspace.apply`
/// alone never reaches it.
///
/// There is no mode that means "move nothing". The ref is written on every
/// apply before any branch is touched, and "do not integrate" already has two
/// answers: a person says no to the approval, and an organisation denies this
/// row.
pub const integrate_action = "workspace.integrate";

/// An organisation that writes `workspace.*` with `deny` refuses the apply
/// itself as well as the integration, which is more than it asked for and never
/// less.
pub const namespace = "workspace";

pub const Mode = enum {
    /// The default, and the conservative one of the three that move a branch: a
    /// merge keeps both histories, and a rebase and a squash each rewrite one.
    merge,
    rebase,
    squash,
    ask,

    pub fn wireName(self: Mode) []const u8 {
        return switch (self) {
            .merge => "merge",
            .rebase => "rebase",
            .squash => "squash",
            .ask => "ask",
        };
    }

    /// Two types and not one with a hole in it, so no reader below this point
    /// has to wonder what `ask` does in a git call.
    pub fn settled(self: Mode) ?Landing {
        return switch (self) {
            .merge => .merge,
            .rebase => .rebase,
            .squash => .squash,
            .ask => null,
        };
    }

    /// `ask` is not one of them: a person is answering the question, not asking
    /// it again. Null moves no branch.
    pub fn fromAnswer(said: []const u8) ?Landing {
        const trimmed = std.mem.trim(u8, said, " \t\r\n");
        inline for (.{ Landing.merge, Landing.rebase, Landing.squash }) |landing| {
            if (std.ascii.eqlIgnoreCase(trimmed, landing.wireName())) return landing;
        }
        return null;
    }
};

/// What one apply really does to a branch. Every member moves a branch of the
/// user's: "no branch moves" is not a landing, so a caller that has none holds
/// null with a `chock_broker.integrate.Reason` beside it.
pub const Landing = enum {
    merge,
    rebase,
    squash,

    pub fn wireName(self: Landing) []const u8 {
        return switch (self) {
            .merge => "merge",
            .rebase => "rebase",
            .squash => "squash",
        };
    }

    /// Present tense and about the user's own branch, because the person
    /// reading it is deciding whether to let that happen.
    pub fn promise(self: Landing) []const u8 {
        return switch (self) {
            .merge => "your checked out branch is merged with this work, and your working tree " ++
                "is updated to the result",
            .rebase => "this work is replayed on top of your checked out branch, that branch is " ++
                "moved to the result, and your working tree is updated to it",
            .squash => "all of this work becomes one commit on your checked out branch, and your " ++
                "working tree is updated to it",
        };
    }
};

/// `merge` and not a park. The prompt names the landing and the branch before
/// a person answers, so being asked and saying yes must do the act and not a
/// smaller act the person then finishes by hand.
pub const Settings = struct {
    mode: Mode = .merge,
};

/// The mode `chock.zon` asked for, bounded by what the policy row permits. Null
/// is "no landing at all", and a caller that reads null parks the work.
///
/// This bounds the permission and never the landing. `deny` is the one decision
/// that takes the capability away. An optional and not a member of `Mode`,
/// because a `Mode.ref` would write the row's own judgement a second time and a
/// project could then ask for it.
pub fn boundBy(mode: Mode, decision: table.Decision) ?Mode {
    return switch (decision) {
        .allow, .ask, .agent_review, .agent_then_human => mode,
        .deny => null,
    };
}

pub const ParseError = error{
    InvalidApply,
} || std.mem.Allocator.Error;

pub const LoadError = ParseError || error{
    ApplyFileTooLarge,
    ReadFailed,
};

/// The two ZON variants own memory, because they hold the syntax tree their
/// message points into. A caller that receives one must call `deinit`.
pub const Diagnostic = union(enum) {
    file_not_zon: std.zon.parse.Diagnostics,
    block_not_valid: std.zon.parse.Diagnostics,
    not_a_struct_literal,
    file_too_large: usize,
    read_failed: anyerror,

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
                "{s}: the apply block is not valid:\n{f}",
                .{ file_name, zon_diag },
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
        }
    }
};

fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

const WireSettings = struct {
    mode: ?Mode = null,
};

pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!Settings {
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
        return error.InvalidApply;
    }

    const node = try findApplyNode(zoir, diag) orelse return .{};

    var zon_diag: std.zon.parse.Diagnostics = .{};
    ast_owned = false;
    zoir_owned = false;
    var zon_diag_owned = true;
    defer if (zon_diag_owned) zon_diag.deinit(gpa);

    const wire = std.zon.parse.fromZoirNodeAlloc(
        WireSettings,
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
            return error.InvalidApply;
        },
    };
    defer std.zon.parse.free(gpa, wire);

    var settings: Settings = .{};
    if (wire.mode) |mode| settings.mode = mode;
    return settings;
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
            return error.ApplyFileTooLarge;
        },
        else => {
            _ = note(diag, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, diag);
}

fn findApplyNode(zoir: std.zig.Zoir, diag: ?*?Diagnostic) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), "apply")) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidApply;
        },
    }
}

const testing = std.testing;

test "a project that writes nothing merges the work into the branch" {
    const gpa = testing.allocator;
    for ([_][:0]const u8{
        ".{}",
        ".{ .subagents = .{ .max_width = 2 } }",
        ".{ .budget = .{ .max_cost = 5.0, .currency = \"USD\" } }",
    }) |source| {
        const settings = try parse(gpa, source, null);
        try testing.expectEqual(Mode.merge, settings.mode);
        try testing.expect(settings.mode.settled() != null);
    }

    const empty_block = try parse(gpa, ".{ .apply = .{} }", null);
    try testing.expectEqual(Mode.merge, empty_block.mode);
}

test "no mode means move nothing, so a project cannot ask for one" {
    for (std.enums.values(Mode)) |mode| {
        try testing.expect(!std.mem.eql(u8, "ref", mode.wireName()));
    }
    for (std.enums.values(Landing)) |landing| {
        try testing.expect(!std.mem.eql(u8, "ref", landing.wireName()));
    }
    try testing.expectEqual(@as(usize, 3), std.enums.values(Landing).len);
}

test "each mode is read back by name" {
    const gpa = testing.allocator;
    inline for (.{ "merge", "rebase", "squash", "ask" }) |name| {
        const source = ".{ .apply = .{ .mode = ." ++ name ++ " } }";
        const settings = try parse(gpa, source, null);
        try testing.expectEqualStrings(name, settings.mode.wireName());
    }
}

test "a misspelled field is refused and is never read as the default" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidApply,
        parse(gpa, ".{ .apply = .{ .mdoe = .merge } }", &diag),
    );
    try testing.expect(diag != null);
}

test "a mode nobody defined is refused" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidApply,
        parse(gpa, ".{ .apply = .{ .mode = .fast_forward } }", &diag),
    );
    try testing.expect(diag != null);
}

test "a decision that permits integration keeps the mode, and deny is the one that parks the work" {
    const permitting = [_]table.Decision{ .allow, .ask, .agent_review, .agent_then_human };
    for (permitting) |decision| {
        for (std.enums.values(Mode)) |mode| {
            try testing.expectEqual(@as(?Mode, mode), boundBy(mode, decision));
        }
    }
    for (std.enums.values(Mode)) |mode| {
        try testing.expectEqual(@as(?Mode, null), boundBy(mode, .deny));
    }

    var named: usize = 0;
    for (std.enums.values(table.Decision)) |decision| {
        if (decision == .deny) {
            named += 1;
            continue;
        }
        for (permitting) |one| {
            if (one == decision) named += 1;
        }
    }
    try testing.expectEqual(std.enums.values(table.Decision).len, named);
}

test "three shapes of rule reach this row differently, and none of them takes the mode away" {
    const gpa = testing.allocator;
    const cases = [_]struct {
        rule: []const u8,
        reaches_the_row: bool,
    }{
        .{ .rule = ".{ .decision = .ask }", .reaches_the_row = true },
        .{ .rule = ".{ .action = \"workspace.*\", .decision = .ask }", .reaches_the_row = true },
        .{ .rule = ".{ .action = \"workspace.apply\", .decision = .ask }", .reaches_the_row = false },
    };

    for (cases) |case| {
        const source = try std.fmt.allocPrintSentinel(
            gpa,
            ".{{ .apply = .{{ .mode = .merge }}, .policy = .{{ .rules = .{{ {s} }} }} }}",
            .{case.rule},
            0,
        );
        defer gpa.free(source);

        const settings = try parse(gpa, source, null);
        try testing.expectEqual(Mode.merge, settings.mode);

        const parsed = try table.Table.parse(gpa, source, null);
        defer table.Table.destroy(gpa, parsed);
        const decision = parsed.ceilingChain(&.{"main"}, .{
            .agent_kind = "main",
            .model = "a-model",
            .tool = "request_action",
            .action = integrate_action,
        }, null);
        const expected: table.Decision = if (case.reaches_the_row) .ask else .allow;
        try testing.expectEqual(expected, decision);

        const bounded = boundBy(settings.mode, decision) orelse {
            try testing.expectEqualStrings("a mode", "no landing at all");
            return error.TheRowTookTheModeAway;
        };
        try testing.expectEqual(Mode.merge, bounded);
        try testing.expectEqualStrings("merge", bounded.settled().?.wireName());
    }
}

test "a project that says nothing about the row keeps the mode it configured" {
    const gpa = testing.allocator;
    const parsed = try table.Table.parse(gpa, ".{}", null);
    defer table.Table.destroy(gpa, parsed);

    const decision = parsed.ceilingChain(&.{"main"}, .{
        .agent_kind = "main",
        .model = "a-model",
        .tool = "request_action",
        .action = integrate_action,
    }, null);
    try testing.expectEqual(table.Decision.allow, decision);
    try testing.expectEqual(@as(?Mode, .merge), boundBy(.merge, decision));
}

test "one org rule closes the road for every project under it" {
    const gpa = testing.allocator;
    const source =
        \\.{ .apply = .{ .mode = .rebase } }
    ;
    const settings = try parse(gpa, source, null);
    try testing.expectEqual(Mode.rebase, settings.mode);

    const org_rules = [_]table.Rule{.{ .action = integrate_action, .decision = .deny }};
    const under_org = try table.Table.parseUnder(gpa, source, &org_rules, null);
    defer table.Table.destroy(gpa, under_org);

    const decision = under_org.ceilingChain(&.{"main"}, .{
        .agent_kind = "main",
        .model = "a-model",
        .tool = "request_action",
        .action = integrate_action,
    }, null);
    try testing.expectEqual(@as(?Mode, null), boundBy(settings.mode, decision));
}

test "a subagent moves no branch its parent could not" {
    const gpa = testing.allocator;
    const source =
        \\.{ .policy = .{ .rules = .{
        \\    .{ .agent_kind = "worker", .action = "workspace.integrate", .decision = .deny },
        \\} } }
    ;
    const parsed = try table.Table.parse(gpa, source, null);
    defer table.Table.destroy(gpa, parsed);

    const child = parsed.ceilingChain(&.{ "main", "worker" }, .{
        .agent_kind = "worker",
        .model = "a-model",
        .tool = "request_action",
        .action = integrate_action,
    }, null);
    try testing.expectEqual(@as(?Mode, null), boundBy(.merge, child));
}

test "the class name covers the row" {
    try testing.expect(table.patternCovers(namespace ++ ".*", integrate_action));
    try testing.expect(std.mem.startsWith(u8, integrate_action, namespace ++ "."));
}

test "a settled mode is a landing, and ask is not" {
    for (std.enums.values(Mode)) |mode| {
        const settled = mode.settled();
        if (mode == .ask) {
            try testing.expectEqual(@as(?Landing, null), settled);
            continue;
        }
        try testing.expect(settled != null);
        try testing.expectEqualStrings(mode.wireName(), settled.?.wireName());
    }
}

test "an answer names a landing and never the question" {
    try testing.expectEqual(Landing.merge, Mode.fromAnswer("merge").?);
    try testing.expectEqual(Landing.rebase, Mode.fromAnswer("  REBASE \n").?);
    try testing.expectEqual(Landing.squash, Mode.fromAnswer("Squash").?);
    try testing.expectEqual(@as(?Landing, null), Mode.fromAnswer("ask"));
    try testing.expectEqual(@as(?Landing, null), Mode.fromAnswer("ref"));
    try testing.expectEqual(@as(?Landing, null), Mode.fromAnswer(""));
    try testing.expectEqual(@as(?Landing, null), Mode.fromAnswer("y"));
}

test "every landing promises something a person can act on" {
    for (std.enums.values(Landing)) |landing| {
        try testing.expect(landing.promise().len > 0);
        try testing.expect(std.mem.indexOf(u8, landing.promise(), "branch") != null);
    }
}
