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
//! Four modes, and `merge` is the default. `merge`, `rebase` and `squash` each
//! park the work at `refs/chock/<session>` and then carry it into the checked
//! out branch. `ask` puts the choice to the person at the moment of the apply.
//!
//! ## There is no mode that means "move nothing"
//!
//! The ref is written on every apply, before any branch is touched:
//! `chock_broker.actions.performWorkspaceApply` runs `update-ref` first and
//! calls `lib/chock-broker/integrate.zig` afterwards. So `refs/chock/<session>`
//! is there whatever the mode is, and a mode that stopped after the step that
//! always happens would say only "do not integrate".
//!
//! **"Do not integrate" is a whether question, and it already has two
//! answers.** A person says `n` to the `workspace.apply` approval, and an
//! organisation writes `deny` on the `workspace.integrate` row. Writing the
//! same judgement a third time, as a mode, let a person approve an apply and
//! get less than the prompt had offered. So a mode says only **how** the work
//! lands, and `Landing` holds nothing but landings that move a branch.
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
//! decides whether an approved apply may move a branch at all, and `boundBy`
//! is the one place the two meet. `boundBy` answers null for `deny`, which is
//! "no landing at all", and a caller that reads null parks the work.
//!
//! ## Read as a ceiling, so a project that said nothing is unchanged
//!
//! `Table.ceilingChain` is the verb, not `Table.evaluateChain`, the same
//! reading `lib/chock-policy/access.zig` takes for a provider and a model. A
//! row nobody wrote answers `allow`, which is no ceiling at all, so a project
//! that writes nothing at all, on an installation whose organisation has never
//! heard of this row, gets `merge`. An organisation that wants the road
//! closed writes one rule:
//!
//! ```zon
//! .{ .action = "workspace.integrate", .decision = .deny }
//! ```
//!
//! and no project under that bundle can move a branch, because
//! `ceilingChain` folds the bundle in as one more term of a minimum.
//!
//! **The row decides whether, and the mode decides where.** They are two
//! answers and `boundBy` must not let one silently give the other. The row is
//! a capability of the whole session, read once when the session starts, and
//! the mode it bounds has to be settled before an apply is described, because
//! the description is what a person reads and it names the act. So `ask`
//! cannot mean "ask which mode" here: there is nobody at the keyboard at the
//! moment the row is read, and the question it would put is already the
//! `workspace.apply` approval.
//!
//! That is an argument about the question and not about the answer. This row
//! is a capability and it carries no question of its own. The one question an
//! apply ever puts is the `workspace.apply` approval, and that request is
//! answered by the `workspace.apply` row and not by this one. So `ask`,
//! `agent_review` and `agent_then_human` here say **that integration is
//! permitted and somebody has to say yes first**, and the somebody is whoever
//! the apply request already asks. None of the three says where the work
//! lands. Reading them as "no landing" took the mode away before the apply was
//! even described, so the person answered a prompt that could no longer carry
//! the work. `deny` is the one decision that removes the capability, so `deny` is
//! the one decision that parks the work at the ref.
//!
//! **A rule that names nothing reaches this row.** `workspace.integrate` is
//! matched by a catch all `.{ .decision = .ask }` and by `workspace.*` as well
//! as by its own name, so before this change a project that wrote one broad
//! rule about anything lost `.apply.mode` without ever naming an apply. A rule
//! that names `workspace.apply` alone never reached this row and never did.
//!
//! **So `deny` is the only ceiling this row puts on a landing.** An
//! organisation that writes `ask` here binds nothing about where the work
//! goes, and there is no rule today that caps a project at `merge` while
//! leaving `rebase` closed.
//!
//! ## The mode is never a widening of the approval
//!
//! `Mode.ask` and the three settled modes all end in the same place: one
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
    /// Park the work, then merge it into the checked out branch. **The
    /// default**, and what every project that has never heard of this block
    /// gets.
    ///
    /// **The conservative one of the three that move a branch**: a merge keeps
    /// both histories, and a rebase and a squash each rewrite one.
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
            .merge => .merge,
            .rebase => .rebase,
            .squash => .squash,
            .ask => null,
        };
    }

    /// The landing a person typed, or null for a word this does not know.
    /// **`ask` is not one of them**: a person is answering the question, not
    /// asking it again. **Null moves no branch**, so a person who typed
    /// something this does not know keeps their branch where it is.
    pub fn fromAnswer(said: []const u8) ?Landing {
        const trimmed = std.mem.trim(u8, said, " \t\r\n");
        inline for (.{ Landing.merge, Landing.rebase, Landing.squash }) |landing| {
            if (std.ascii.eqlIgnoreCase(trimmed, landing.wireName())) return landing;
        }
        return null;
    }
};

/// What one apply really does to a branch. `ask` is not here: see
/// `Mode.settled`.
///
/// **Every member moves a branch of the user's.** "No branch moves" is not a
/// landing, so it is not a member: a caller that has no landing holds null, and
/// why it holds null is a `chock_broker.integrate.Reason` beside it. That keeps
/// "which shape" and "whether at all" in two types, instead of one type with a
/// hole in it.
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

    /// The sentence an approval prompt carries for this landing. **Present
    /// tense and about the user's own branch**, because the person reading it
    /// is deciding whether to let that happen.
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

/// What the `apply` block holds. A project that writes no block gets this.
///
/// **`merge` and not a park.** A person who is asked "may I apply this work"
/// and answers yes has agreed to the act the prompt described, and the prompt
/// names the landing and the branch before they answer:
/// `chock_broker.actions.Action.summary` puts "and merge it into
/// refs/heads/main" on the one line every client shows. Being asked and saying
/// yes must do the act, and not a smaller act the person then finishes by hand.
pub const Settings = struct {
    mode: Mode = .merge,
};

/// The mode `chock.zon` asked for, bounded by what the policy row permits.
/// **Null is "no landing at all"**, which is what `deny` leaves, and a caller
/// that reads null parks the work at the ref and moves no branch.
///
/// **This bounds the permission and never the landing.** `decision` is the
/// answer for `integrate_action`, which says "may an approval move my branch
/// at all", and `mode` says "where does the work go when it does". `deny` is
/// the one decision that takes the capability away, so it is the one decision
/// that parks the work at the ref. `ask`, `agent_review` and
/// `agent_then_human` say that integration is permitted once somebody says
/// yes, and the only place anybody is asked is the `workspace.apply` approval,
/// which this row does not answer. A mode bound to nothing by one of those
/// three would take the merge away before the apply was described. See this
/// file's own top comment.
///
/// **An optional and not a member of `Mode`.** A `Mode.ref` that meant "do not
/// integrate" would write the same judgement the row already holds a second
/// time, and a project could then ask for it, which is the whole reason it no
/// longer exists.
pub fn boundBy(mode: Mode, decision: table.Decision) ?Mode {
    return switch (decision) {
        .allow, .ask, .agent_review, .agent_then_human => mode,
        .deny => null,
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

    // **The default is written once**, in `Settings`, so a block that names no
    // mode and a file with no block at all cannot answer differently.
    var settings: Settings = .{};
    if (wire.mode) |mode| settings.mode = mode;
    return settings;
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

test "a project that writes nothing merges the work into the branch" {
    // **The default this block must have.** Three files with no `apply` block
    // between them, and every one of them lands the work where the approval
    // prompt says it will.
    //
    // The project owner met the old default four times: he was asked "may I
    // apply this work", answered yes, and the work stopped at the ref while no
    // branch moved. Six approvals in one session, six parks. The approval is
    // the consent, and the prompt names the branch and the landing before he
    // answers, so yes has to do the act it described.
    //
    // Mutation check: put `mode: Mode = .rebase` in `Settings` and this fails
    // on the first source. The last case is why `parse` reads the default out
    // of `Settings` rather than writing a word of its own: a second spelling
    // could answer differently for a block that names no mode.
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

    // And a block that names no mode answers the same as no block at all,
    // because both read the one default `Settings` holds.
    const empty_block = try parse(gpa, ".{ .apply = .{} }", null);
    try testing.expectEqual(Mode.merge, empty_block.mode);
}

test "no mode means move nothing, so a project cannot ask for one" {
    // **`ref` is gone on purpose.** "Do not integrate" is a whether question,
    // and it is answered by a person saying `n` to the apply and by `deny` on
    // the `workspace.integrate` row. A mode of the same name wrote the
    // judgement a third time, and let an approved apply do less than the prompt
    // had offered.
    //
    // Mutation check: add a `ref` member back to either enum and this fails.
    for (std.enums.values(Mode)) |mode| {
        try testing.expect(!std.mem.eql(u8, "ref", mode.wireName()));
    }
    for (std.enums.values(Landing)) |landing| {
        try testing.expect(!std.mem.eql(u8, "ref", landing.wireName()));
    }
    // So every landing any apply can take moves a branch, which is what makes
    // null the one answer that moves none.
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
    // The whole reason this reader is strict inside its own block: a project
    // that meant `squash` and typed `mdoe` must hear about it, and not silently
    // get the default.
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
    // **The `workspace.integrate` row decides whether an apply may move a
    // branch, and `.apply.mode` decides where the work lands.** `ask`,
    // `agent_review` and `agent_then_human` each permit integration once
    // somebody says yes, and none of them names a landing, so a mode bound to
    // `ref` by one of them would take the merge away before anybody was asked.
    // Only `deny` takes the capability away, and that is the rule an
    // organisation writes.
    const permitting = [_]table.Decision{ .allow, .ask, .agent_review, .agent_then_human };
    for (permitting) |decision| {
        for (std.enums.values(Mode)) |mode| {
            try testing.expectEqual(@as(?Mode, mode), boundBy(mode, decision));
        }
    }
    for (std.enums.values(Mode)) |mode| {
        try testing.expectEqual(@as(?Mode, null), boundBy(mode, .deny));
    }

    // **The two lists together are the whole enum**, so a member added to
    // `Decision` cannot quietly join the permitting side. A later author has
    // to say here which side the new member belongs on.
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
    // **The regression test for the bug this file had**, and for the three
    // shapes that were measured against the real reader.
    //
    // `ask` on this row used to bind the mode to `ref`, so a project that
    // wrote `merge` got nothing, and the rule that did it did not have to name
    // an apply at all: a catch all and `workspace.*` both reach
    // `workspace.integrate`, while a rule that names `workspace.apply` alone
    // never reaches it. Those three cases are pinned apart here so nobody
    // re-derives the wrong story about which row feeds this function.
    const gpa = testing.allocator;
    const cases = [_]struct {
        rule: []const u8,
        reaches_the_row: bool,
    }{
        // A rule that names nothing at all. It matches every key, this one
        // included.
        .{ .rule = ".{ .decision = .ask }", .reaches_the_row = true },
        // The class rule. `workspace.*` covers `workspace.integrate`.
        .{ .rule = ".{ .action = \"workspace.*\", .decision = .ask }", .reaches_the_row = true },
        // **The apply row is a different row.** It answers the approval
        // request, and it is not what bounds the mode.
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

        // **The whole product.** Whichever of the two answers the row gave,
        // the project still gets the merge it configured, so the yes a person
        // gives at the apply prompt carries the work.
        const bounded = boundBy(settings.mode, decision) orelse {
            try testing.expectEqualStrings("a mode", "no landing at all");
            return error.TheRowTookTheModeAway;
        };
        try testing.expectEqual(Mode.merge, bounded);
        try testing.expectEqualStrings("merge", bounded.settled().?.wireName());
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
    try testing.expectEqual(@as(?Mode, .merge), boundBy(.merge, decision));
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
    // **Null is the whole of what `deny` leaves**: no landing, so no branch of
    // anybody's moves under this bundle whatever the project writes.
    try testing.expectEqual(@as(?Mode, null), boundBy(settings.mode, decision));
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
    try testing.expectEqual(@as(?Mode, null), boundBy(.merge, child));
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
    try testing.expectEqual(Landing.squash, Mode.fromAnswer("Squash").?);
    // A person answering the question cannot answer it with the question.
    try testing.expectEqual(@as(?Landing, null), Mode.fromAnswer("ask"));
    // And `ref` is not a landing any more, so a person who types it is a person
    // who named no landing, which moves no branch.
    try testing.expectEqual(@as(?Landing, null), Mode.fromAnswer("ref"));
    try testing.expectEqual(@as(?Landing, null), Mode.fromAnswer(""));
    try testing.expectEqual(@as(?Landing, null), Mode.fromAnswer("y"));
}

test "every landing promises something a person can act on" {
    // The promise is read into the approval prompt, so a landing with nothing
    // to say would be a landing a person approves without being told what it
    // does to their branch.
    for (std.enums.values(Landing)) |landing| {
        try testing.expect(landing.promise().len > 0);
        try testing.expect(std.mem.indexOf(u8, landing.promise(), "branch") != null);
    }
}
