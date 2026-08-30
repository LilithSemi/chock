//! **How an approved `workspace.apply` lands in the project**, from the
//! `apply` block of `chock.zon`, with a ceiling on the table that already
//! exists.
//!
//! ```zon
//! .{
//!     .apply = .{ .mode = .merge },
//! }
//! ```
//!
//! Five modes. `ref` parks the work at `refs/chock/<session>` and moves no
//! branch of the user's, which is what every session did before this block
//! existed. `merge`, `rebase` and `squash` park the work at the same ref and
//! then carry it into the checked out branch. `ask` puts the choice to the
//! person at the moment of the apply.
//!
//! ## Why the mode is in `chock.zon` and the permission is on the table
//!
//! The two questions are not the same question, so they are not written in the
//! same place.
//!
//! **"Which shape do I want my work to land in" is a project's own taste.** A
//! project that rebases everything and a project that keeps merge commits are
//! both correct, both choices are reversible with one `git` command, and
//! neither is a security decision. That is a `chock.zon` knob, beside
//! `subagents` and `budget`, and `chock.zon` is bound read only into the
//! sandbox: `lib/chock-workspace/deny.zig` says so, and
//! `test/workspace/escape.zig` proves it against a real sandbox with "a tool
//! call cannot delete chock.zon". **So the agent cannot write this setting.**
//!
//! **"May an approval move my branch at all" is not the project's to answer.**
//! Before this block, approving an apply could never move a branch: the work
//! was parked at a ref and a person ran the merge. A project that writes
//! `merge` makes the same "y" at the same prompt do something larger, and an
//! organisation may well want that road closed everywhere. That is the exact
//! question `lib/chock-policy/hardening.zig` answers for the write and execute
//! rule, and the answer is the same: **a row on the table**, because the table
//! already folds an org bundle over a project and a parent over a child.
//!
//! So the two halves compose. `chock.zon` names the mode, `integrate_action`
//! decides whether that mode may be anything but `ref`, and `boundBy` is the
//! one place the two meet.
//!
//! ## Read as a ceiling, so a project that said nothing is unchanged
//!
//! `Table.ceilingChain` is the verb, not `Table.evaluateChain`, the same
//! reading `lib/chock-policy/access.zig` takes for a provider and a model. A
//! row nobody wrote answers `allow`, which is no ceiling at all, so a project
//! that writes `.mode = .merge` and an installation whose organisation has
//! never heard of this row gets `merge`. An organisation that wants the road
//! closed writes one rule:
//!
//! ```zon
//! .{ .action = "workspace.integrate", .decision = .deny }
//! ```
//!
//! and no project under that bundle can move a branch, because
//! `ceilingChain` folds the bundle in as one more term of a minimum.
//!
//! **`ask` cannot mean "ask" for this row.** The row is a capability of the
//! whole session, read once when the session starts, and the mode it bounds
//! has to be known before an apply is described, because the description is
//! what a person reads. There is no second question to put here that is not
//! already the approval itself. `boundBy` therefore reads only `allow` as
//! permission, which is the same reading `hardening.writeExecuteFor` and
//! `access.refusalNeeded` take.
//!
//! ## The mode is never a widening of the approval
//!
//! `Mode.ask` and the four settled modes all end in the same place: one
//! `workspace.apply` request, described in the mode that is really configured,
//! put to the policy table and, where the table says `ask`, to a person. **The
//! prompt names the mode.** `chock_broker.actions.WorkspaceApply` carries the
//! plan the mode produced, and `Action.summary` and `Action.detail` read it, so
//! a prompt cannot look the same in two modes that do different things.
//!
//! ## This reader is strict inside its own block and lenient outside it
//!
//! The same split `lib/chock-policy/subagents.zig` and
//! `lib/chock-cost/budget.zig` make. Other milestones own the other blocks of
//! this one file, and `.mdoe = .merge` is refused rather than read as the
//! default.

const std = @import("std");
const table = @import("table.zig");

/// The name of the configuration file, in the project root. Every other
/// reader of this file looks in the same place.
pub const file_name = "chock.zon";

/// The largest `chock.zon` this reader accepts, matching every other reader's
/// bound: the file comes from the project directory, so a hostile project
/// supplies it.
pub const max_file_bytes = 1 << 20;

/// The row that says whether an approved apply may move a branch of the
/// user's at all.
///
/// **Named for what the project needs and not for what is given up**, the same
/// rule `hardening.jit_action` keeps. An author writes this rule because they
/// want the work integrated, and `workspace.no_branch_move` would make them
/// work out what that had to do with them.
pub const integrate_action = "workspace.integrate";

/// The first segment of the row. A rule that names this class alone,
/// `workspace.*`, covers this row and `workspace.apply` beside it.
///
/// **That is on purpose and it is the safe direction.** An organisation that
/// writes `workspace.*` with `deny` refuses the apply itself as well as the
/// integration, which is more than it asked for and never less.
pub const namespace = "workspace";

/// What a project asks for.
pub const Mode = enum {
    /// The work is parked at `refs/chock/<session>` and no branch moves. **The
    /// default**, and what every project that has never heard of this block
    /// gets.
    ref,
    /// Park the work, then merge it into the checked out branch.
    merge,
    /// Park the work, then replay its commits on top of the checked out
    /// branch.
    rebase,
    /// Park the work, then put all of it on the checked out branch as one
    /// commit.
    squash,
    /// Put the choice to the person at the moment of the apply.
    ask,

    /// The word a log line, a `chock doctor` row and an approval prompt carry.
    pub fn wireName(self: Mode) []const u8 {
        return switch (self) {
            .ref => "ref",
            .merge => "merge",
            .rebase => "rebase",
            .squash => "squash",
            .ask => "ask",
        };
    }

    /// The mode this really is, or null for `ask`, which is a question and not
    /// an answer.
    ///
    /// **Two types and not one with a hole in it.** Everything below the point
    /// where a person has answered takes a `Landing`, so no later reader has to
    /// wonder what `ask` does in a git call.
    pub fn settled(self: Mode) ?Landing {
        return switch (self) {
            .ref => .ref,
            .merge => .merge,
            .rebase => .rebase,
            .squash => .squash,
            .ask => null,
        };
    }

    /// Whether this mode can end with a branch of the user's in a new place.
    /// True for `ask`, because the person may answer with one that does.
    pub fn mayMoveABranch(self: Mode) bool {
        return switch (self) {
            .ref => false,
            .merge, .rebase, .squash, .ask => true,
        };
    }

    /// The mode a person typed, or null for a word this does not know.
    /// **`ask` is not one of them**: a person is answering the question, not
    /// asking it again.
    pub fn fromAnswer(said: []const u8) ?Landing {
        const trimmed = std.mem.trim(u8, said, " \t\r\n");
        inline for (.{ Landing.ref, Landing.merge, Landing.rebase, Landing.squash }) |landing| {
            if (std.ascii.eqlIgnoreCase(trimmed, landing.wireName())) return landing;
        }
        return null;
    }
};

/// What one apply really does. `ask` is not here: see `Mode.settled`.
pub const Landing = enum {
    ref,
    merge,
    rebase,
    squash,

    pub fn wireName(self: Landing) []const u8 {
        return switch (self) {
            .ref => "ref",
            .merge => "merge",
            .rebase => "rebase",
            .squash => "squash",
        };
    }

    /// Whether this landing moves a branch of the user's.
    pub fn movesABranch(self: Landing) bool {
        return switch (self) {
            .ref => false,
            .merge, .rebase, .squash => true,
        };
    }

    /// The sentence an approval prompt carries for this landing. **Present
    /// tense and about the user's own branch**, because the person reading it
    /// is deciding whether to let that happen.
    pub fn promise(self: Landing) []const u8 {
        return switch (self) {
            .ref => "no branch of yours moves. The work waits at the ref until you merge it",
            .merge => "your checked out branch is merged with this work, and your working tree " ++
                "is updated to the result",
            .rebase => "this work is replayed on top of your checked out branch, that branch is " ++
                "moved to the result, and your working tree is updated to it",
            .squash => "all of this work becomes one commit on your checked out branch, and your " ++
                "working tree is updated to it",
        };
    }
};

/// What the `apply` block holds. A project that writes no block gets this.
pub const Settings = struct {
    mode: Mode = .ref,
};

/// The mode `chock.zon` asked for, bounded by what the policy row permits.
///
/// **Only `allow` keeps the mode.** See this file's own top comment: there is
/// nobody to ask at the moment this is decided, so `ask` holds the work at the
/// ref exactly as `deny` does.
pub fn boundBy(mode: Mode, decision: table.Decision) Mode {
    return switch (decision) {
        .allow => mode,
        .ask, .deny, .agent_review, .agent_then_human => .ref,
    };
}

/// What reading the `apply` block can fail with.
pub const ParseError = error{
    /// `chock.zon` is not ZON, its top level is not a struct literal, or its
    /// `apply` block is not valid: an unknown field, a mode nobody defined, a
    /// wrong type.
    InvalidApply,
} || std.mem.Allocator.Error;

/// What reading `chock.zon` itself can fail with.
pub const LoadError = ParseError || error{
    /// `chock.zon` is larger than `max_file_bytes`.
    ApplyFileTooLarge,
    /// `chock.zon` is there and could not be read.
    ReadFailed,
};

/// What went wrong while the `apply` block was read, and the facts the error
/// alone throws away.
///
/// **The two ZON variants own memory**, because they hold the syntax tree their
/// message points into, which is how they name a line and a column. A caller
/// that receives one must call `deinit`. The same contract
/// `subagents.Diagnostic` keeps.
pub const Diagnostic = union(enum) {
    /// The file is not valid ZON at all. The parser names the place.
    file_not_zon: std.zon.parse.Diagnostics,
    /// The file is valid ZON, and its `apply` block does not match the schema.
    /// A misspelled field name and a mode nobody defined both land here.
    block_not_valid: std.zon.parse.Diagnostics,
    /// The top level of the file is not a struct literal.
    not_a_struct_literal,
    /// The file is larger than `max_file_bytes`, so it was not read.
    file_too_large: usize,
    /// The file exists and the read failed. The fault is the filesystem's.
    read_failed: anyerror,

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

/// Fill `out` with the first fault and say whether it took it. A later fault
/// is there because an earlier one was, so the first is the one that explains
/// the rest. The answer matters because two variants own memory.
fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// What the block looks like on the way in. Every field optional, so a block
/// that names one of them keeps the default for the other.
const WireSettings = struct {
    mode: ?Mode = null,
};

/// Read the settings out of `source`, the whole content of a `chock.zon`. A
/// file that names no `apply` block gets the defaults, which is a real answer
/// and not a missing one.
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
    // From here the diagnostics own the two trees, the same handover
    // `lib/chock-policy/subagents.zig` makes.
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

    return .{ .mode = wire.mode orelse .ref };
}

/// Read `chock.zon` from `project_root` and take its settings. A project with
/// no such file gets the defaults, the same answer a file with no `apply`
/// block gets.
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

/// The node of the `apply` field at the top of the file. Null when the file
/// has no such field. Every other top level field is skipped, because other
/// milestones own the other blocks of this one file.
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
        // `.{}` names no field at all, which is a file that says nothing about
        // this block and not a file with the wrong shape.
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidApply;
        },
    }
}

const testing = std.testing;

test "a project that writes nothing parks the work at the ref" {
    // **The default this block must have.** Three files with no `apply` block
    // between them, and every one of them behaves the way every session did
    // before the block existed.
    const gpa = testing.allocator;
    for ([_][:0]const u8{
        ".{}",
        ".{ .subagents = .{ .max_width = 2 } }",
        ".{ .budget = .{ .max_cost = 5.0, .currency = \"USD\" } }",
    }) |source| {
        const settings = try parse(gpa, source, null);
        try testing.expectEqual(Mode.ref, settings.mode);
        try testing.expect(!settings.mode.mayMoveABranch());
    }
}

test "each mode is read back by name" {
    const gpa = testing.allocator;
    inline for (.{ "ref", "merge", "rebase", "squash", "ask" }) |name| {
        const source = ".{ .apply = .{ .mode = ." ++ name ++ " } }";
        const settings = try parse(gpa, source, null);
        try testing.expectEqualStrings(name, settings.mode.wireName());
    }
}

test "a misspelled field is refused and is never read as the default" {
    // The whole reason this reader is strict inside its own block: a project
    // that meant `merge` and typed `mdoe` must hear about it, not silently get
    // `ref`, and a project that meant `ref` must not silently get `merge`.
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

test "only allow keeps the mode, and every other decision parks the work" {
    // The whole product, so a member added to `Decision` cannot quietly join
    // the permitting side: this walks the enum itself rather than a list.
    for (std.enums.values(table.Decision)) |decision| {
        for (std.enums.values(Mode)) |mode| {
            const expected: Mode = if (decision == .allow) mode else .ref;
            try testing.expectEqual(expected, boundBy(mode, decision));
        }
    }
}

test "a project that says nothing about the row keeps the mode it configured" {
    // **Read as a ceiling.** An installation whose organisation has never
    // heard of this row must not have every project's setting taken away.
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
    try testing.expectEqual(Mode.merge, boundBy(.merge, decision));
}

test "one org rule closes the road for every project under it" {
    // **This is the whole justification for the row living on the table.** The
    // organisation writes one rule, in the same language, and no project can
    // raise it: the fold is a minimum, so the second half falls out of the
    // first.
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
    try testing.expectEqual(Mode.ref, boundBy(settings.mode, decision));
}

test "a subagent moves no branch its parent could not" {
    // A rule for `main` alone gives a child nothing, because the fold walks
    // every link of the chain and takes the minimum.
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
    try testing.expectEqual(Mode.ref, boundBy(.merge, child));
}

test "the class name covers the row" {
    // `workspace.*` must reach `workspace.integrate`, so an organisation that
    // wants to forbid every workspace row at once writes one rule.
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
    try testing.expectEqual(Landing.ref, Mode.fromAnswer("ref").?);
    try testing.expectEqual(Landing.squash, Mode.fromAnswer("Squash").?);
    // A person answering the question cannot answer it with the question.
    try testing.expectEqual(@as(?Landing, null), Mode.fromAnswer("ask"));
    try testing.expectEqual(@as(?Landing, null), Mode.fromAnswer(""));
    try testing.expectEqual(@as(?Landing, null), Mode.fromAnswer("y"));
}

test "every landing promises something a person can act on, and only ref promises nothing moves" {
    for (std.enums.values(Landing)) |landing| {
        try testing.expect(landing.promise().len > 0);
        try testing.expectEqual(landing != .ref, landing.movesABranch());
    }
}
