//! The policy table. The policy is a static table in `chock.zon`. The key has
//! four parts: the agent kind, the model, the tool, and the action. The value
//! is `allow`, `ask`, `deny`, `agent_review`, or `agent_then_human`. The
//! broker evaluates the table, and the broker is the one process the agent
//! cannot reach.
//!
//! The table is declarative on purpose. A policy that a reader must execute
//! to understand is a bad property for a security control.
//!
//! ## The file
//!
//! This reader looks for the field `policy` at the top of `chock.zon`, and
//! `load` looks for `chock.zon` in the project root, the same place
//! `lib/chock-workspace/Workspace.zig` binds it back over the workspace read
//! only. Every other top level field is ignored, because a later milestone
//! adds more sections to the same file. Inside the `policy` block the reader
//! is strict: an unknown field name is an error. A field name with a typo
//! must never become a rule that matches more than the author wanted.
//!
//! ```zon
//! .{
//!     .policy = .{
//!         .agents = .{
//!             .{ .kind = "main" },
//!             .{ .kind = "reviewer", .parent = "main" },
//!         },
//!         .rules = .{
//!             .{ .action = "git.*", .decision = .ask },
//!             .{ .action = "git.push", .decision = .deny },
//!             .{ .agent_kind = "main", .action = "git.commit", .decision = .allow },
//!         },
//!     },
//! }
//! ```
//!
//! The file comes from the project directory, so a hostile project writes it.
//! This reader bounds what it accepts: `max_file_bytes` of text, `max_rules`
//! rules, `max_agents` agent kinds, and `max_check_work` for the read time
//! check. A file above any of those is refused with a named error, and the
//! message says which bound it passed.
//!
//! A rule has five fields. `agent_kind`, `model`, `tool` and `action` name the
//! key, and each of the four is optional. A field that is absent matches every
//! value. `decision` is the answer the rule gives, and it is required.
//!
//! A name that ends in `.*` matches every name below that prefix. `git.*`
//! matches `git.push` and `git.branch.delete`. It does not match `git` itself.
//! Any other name matches only itself. A bare `"*"` is an error: leave the
//! field out instead, so one meaning keeps one spelling.
//!
//! ## Which rule wins
//!
//! More than one rule can match one key. The most specific rule wins.
//! Specificity is compared one field at a time, in this order: the action,
//! then the tool, then the model, then the agent kind. The action comes first
//! because the action is what happens to the machine. The tool is only how the
//! agent asked for it, and the model and the agent kind are only who asked.
//!
//! Inside one field, a name that matches exactly beats a name that ends in
//! `.*`, and a longer prefix beats a shorter one. Both beat an absent field.
//!
//! Two rules can reach the same score in all four fields and still both match
//! one key. The more restrictive decision then wins, in the order `Decision`
//! declares its members: `deny`, then `agent_then_human`, then `ask`, then
//! `agent_review`, then `allow`. The order is therefore total, and the answer
//! never depends on the order the rules have in the file.
//!
//! ## An action no rule names
//!
//! `ask` is the answer when no rule matches. A policy that forgot a case must
//! not become permission.
//!
//! ## A child is never stronger than its parent
//!
//! Chock applies this in two places, and it needs both.
//!
//! `agents` declares which kind spawns which kind. `parse` refuses the file
//! when a declared child holds more than its declared parent for any key. That
//! is a mistake in the configuration, so the user reads about it when Chock
//! reads the file. The user does not read about it on the turn that happens to
//! hit the rule.
//!
//! `evaluateChain` is the second place, and it is the verb a caller wants. A
//! spawn chain at run time can hold a kind that the file declared no parent
//! for, so the intersection is taken again over the real chain. A child cannot
//! hold a permission its parent lacks, whatever the file says about that child
//! alone. `evaluateKindAlone` answers for one kind with no intersection at
//! all. Its name says what it leaves out, because a caller that reaches for it
//! by mistake loses the intersection for every kind the file declares no
//! parent for.
//!
//! ## An org bundle above the file, and a project that may only narrow it
//!
//! `chock.zon` is in the project directory, so the developer who owns that
//! directory writes it. An organisation that wants to bound every project at
//! once cannot use a file inside the thing it is bounding, so
//! `lib/chock-policy/org.zig` gives one layer above: a bundle of the same
//! rules, in the same language, given to the installation rather than to the
//! repository. `Table.org` holds it and `parseUnder` is how a table gets one.
//!
//! **It is the same intersection as before, with one more term in it.**
//! `evaluateChain` folds the bundle at every link of the chain exactly as it
//! folds the file, and the answer is the minimum of all of them.
//! A rule in `chock.zon` can therefore lower an answer and can never raise
//! one, so a project cannot widen what an org narrowed. That is a property of
//! a minimum, not a check a later author has to remember.
//!
//! ## The table cannot change while a session runs
//!
//! Chock parses `chock.zon` one time and holds the result in memory.
//!
//! ## An action nobody named, and the rules Chock ships for it
//!
//! "`ask` is the answer when no rule matches" is the rule for what
//! `chock.zon` did not name. `lib/chock-policy/defaults.zig` narrows that for
//! one case only: the ordinary tool calls `lib/chock-core/tools.zig` builds a
//! name for, so a project with no `chock.zon` at all still runs them without
//! a prompt. See that file's own top comment for the rules themselves and for
//! why every one of them names an action, never a tool alone.
//!
//! **A shipped default answers beside a project's own rules, not underneath
//! them.** `evaluateRules` reads the two rule lists together, in the one
//! search for a winner this file's own "Which rule wins" section already
//! describes, so a project rule beats a shipped default the same way any two
//! rules of `chock.zon` would settle a disagreement: the more specific
//! pattern wins, and a tie goes to the decision that permits less. **This
//! could not be built as one more term of the ceiling intersection
//! `Table.org` uses.** A ceiling can only ever narrow an answer that already
//! exists, and an unnamed action's existing answer is `ask`: intersecting
//! `ask` with anything can never produce `allow`, which is the one thing a
//! shipped default has to do for the tool calls it names.

const std = @import("std");
const defaults = @import("defaults.zig");

/// The name of the configuration file, in the project root.
/// `lib/chock-workspace/Workspace.zig` looks in the same place.
pub const file_name = "chock.zon";

/// The largest `chock.zon` this reader accepts. A policy table is a small
/// file. A larger one is a mistake or an attack, and either way the user must
/// hear about it instead of Chock reading a gigabyte into memory.
pub const max_file_bytes = 1 << 20;

/// The largest number of rules this reader accepts. A human writes a policy of
/// a few dozen lines. `chock.zon` comes from the project directory, so a
/// hostile project supplies it, and `max_file_bytes` alone admits about
/// fourteen thousand rules.
pub const max_rules = 512;

/// The largest number of agent kinds this reader accepts. A spawn tree that a
/// human designs holds a few kinds.
pub const max_agents = 64;

/// The largest amount of work the read time check may do. See
/// `checkChildrenAreWeaker`, which walks the product of three representative
/// lists for each declared parent link, and reads every rule two times for
/// each key.
///
/// One read compares the key against up to four patterns of one rule, so a
/// read costs what those names are long. The unit of this budget is therefore
/// one read of one byte, and `checkWorkFitsBudget` multiplies the number of
/// reads by the longest name the file spells out.
///
/// `max_rules`, `max_agents` and `max_file_bytes` bound neither half of that
/// on their own:
///
/// - The number of keys grows with the cube of the number of names the rules
///   spell out. 512 rules that each name a different model, a different tool,
///   and a different action reach 1.4 * 10^11 reads.
/// - The length of a name is what the file says it is. 72 rules whose three
///   names are 4600 bytes each make only 5.6 * 10^7 reads, and they measured
///   26 seconds from a file of 998 KB.
///
/// This budget is 4.3 * 10^9. The most expensive file it admits measured 0.98
/// seconds with `--release=safe`, which is the mode `pkgs/chock/default.nix`
/// builds in: 75 rules of three names of 64 bytes, under one parent link, for
/// 4.21 * 10^9 of the budget. The same 75 rules with names of 4600 bytes cost
/// 72 times as much and are refused.
///
/// The headroom above a plausible policy is real, and it is not large. 512
/// rules that name an action each, under 64 agent kinds, cost 2.1 * 10^9 and
/// are read. Give those same rules one shared model name and the cost is
/// 4.2 * 10^9, which is inside the budget by two percent. Give them a shared
/// tool name as well and it is 8.5 * 10^9, and the file is refused. An author
/// who reaches that point must spell out fewer names.
pub const max_check_work: u64 = 1 << 32;

/// What the table answers for one key. The members are in order of how much
/// they permit, from least to most, so `@intFromEnum` gives the rank that
/// `intersect` compares. A new member must go in its correct place.
///
/// ## The five, and why they are in this order
///
/// There are two more than `allow`, `ask` and `deny`: a reviewer subagent
/// decides, or a reviewer decides and then a person decides with the review in
/// front of them. The order below is what makes the intersection mean
/// anything, so it is worth stating why each step is a step:
///
/// * `deny` permits nothing at all.
/// * `agent_then_human` needs two yeses, a reviewer's and a person's. Anything
///   it lets through, `ask` would have let through as well, so it is the
///   stricter of the two.
/// * `ask` needs one yes, from a person.
/// * `agent_review` needs one yes, from a reviewer agent. It is above `ask`
///   because **it is the one decision that lets work through while nobody is
///   awake**, which is the whole reason it exists. A rule that says `ask`
///   therefore never becomes a rule a machine can answer.
/// * `allow` needs nothing.
///
/// **The order is what a reviewer cannot climb.** `intersect` is a minimum, so
/// a subagent whose own kind says `agent_review` under a parent that says
/// `deny` gets `deny`, and no reviewer is ever consulted. See
/// `lib/chock-broker/review.zig`, which is where that becomes an act.
pub const Decision = enum {
    deny,
    agent_then_human,
    ask,
    agent_review,
    allow,

    /// How much this decision permits. `deny` permits the least.
    pub fn rank(self: Decision) u8 {
        return @intFromEnum(self);
    }

    /// Whether this decision is answered by a reviewer agent before anybody
    /// else is asked.
    ///
    /// A verb rather than a comparison a caller writes for itself, so a sixth
    /// member cannot be added without this switch naming it.
    pub fn needsReview(self: Decision) bool {
        return switch (self) {
            .agent_review, .agent_then_human => true,
            .deny, .ask, .allow => false,
        };
    }

    /// Whether a person is asked once every other step has said yes.
    pub fn needsHuman(self: Decision) bool {
        return switch (self) {
            .ask, .agent_then_human => true,
            .deny, .agent_review, .allow => false,
        };
    }

    /// The policy of a subagent is the intersection of the policy of its
    /// parent and the policy of its agent kind. For one key that is the
    /// decision which permits less.
    pub fn intersect(a: Decision, b: Decision) Decision {
        return if (a.rank() <= b.rank()) a else b;
    }
};

/// The four parts of one policy question. Every part is a name that Chock
/// itself knows: the kind of the agent that asked, the alias of the model
/// behind it, the tool it called, and the action that tool wants to perform.
/// The action names of version 1 are a fixed list.
pub const Key = struct {
    agent_kind: []const u8,
    model: []const u8,
    tool: []const u8,
    action: []const u8,
};

/// One line of the table. Each of the four key fields is a pattern, and an
/// absent pattern matches every value. See this file's top comment for the
/// pattern language and for which rule wins.
pub const Rule = struct {
    agent_kind: ?[]const u8 = null,
    model: ?[]const u8 = null,
    tool: ?[]const u8 = null,
    action: ?[]const u8 = null,
    decision: Decision,
};

/// One agent kind, and the kind that spawns it. A kind with no `parent` is a
/// root, or a kind whose parent changes at run time. `evaluateChain` covers
/// the second case.
pub const Agent = struct {
    kind: []const u8,
    parent: ?[]const u8 = null,
};

/// The `policy` block of `chock.zon`.
pub const Policy = struct {
    agents: []const Agent = &.{},
    rules: []const Rule = &.{},
};

/// What can go wrong while reading a policy out of bytes that are already in
/// memory.
pub const ParseError = error{
    OutOfMemory,
    /// The file is not valid ZON, or the `policy` block does not match the
    /// schema. Pass a `Diagnostic` to learn which line, and why.
    InvalidPolicy,
    /// A key pattern that this file's top comment does not allow.
    InvalidPattern,
    /// Two `agents` entries name the same kind.
    DuplicateAgent,
    /// An `agents` entry names a parent that no entry declares.
    UnknownParent,
    /// The `parent` links make a loop.
    AgentCycle,
    /// A declared child holds more than its declared parent for at least one
    /// key.
    ChildStrongerThanParent,
    /// The policy holds more than `max_rules` rules.
    TooManyRules,
    /// The policy holds more than `max_agents` agent kinds.
    TooManyAgents,
    /// The read time check would cost more than
    /// `max_check_work`. The policy tells too many classes of key apart. The
    /// message names the numbers, so the author can spell out fewer names.
    PolicyTooComplex,
};

/// What can go wrong while reading a policy from the project root.
pub const LoadError = ParseError || error{
    /// The project has no `chock.zon`. The caller decides what to do about
    /// that. `parse` with the source `.{}` builds the safe table, where every
    /// key resolves to `ask`.
    NoPolicyFile,
    /// The file is larger than `max_file_bytes`.
    PolicyTooLarge,
    /// The file exists and could not be read. Pass a `Diagnostic` to learn
    /// which fault the filesystem gave.
    ReadFailed,
};

/// Why a policy was refused, in the words the author of `chock.zon` needs.
///
/// **Some variants own memory, and `deinit` releases all of them.** The two
/// ZON variants hold the syntax tree their message points into, which is how
/// they can name a line and a column. The variants that name an agent kind
/// hold a copy of the name, because the `Policy` those names live in is
/// released the moment the parse fails. A caller that gives `parse` or `load`
/// a slot must call `deinit` on whatever lands in it.
pub const Diagnostic = union(enum) {
    /// The file is not valid ZON at all. The parser names the place.
    file_not_zon: std.zon.parse.Diagnostics,
    /// The file is valid ZON, and its `policy` block does not match the
    /// schema. A misspelled field name lands here.
    block_not_valid: std.zon.parse.Diagnostics,
    /// The top level of the file is not a struct literal.
    not_a_struct_literal,
    /// The file exists and the read failed. The path is `project_root` joined
    /// with `file_name`, which the caller of `load` already holds.
    read_failed: anyerror,
    /// More rules than `max_rules`.
    too_many_rules: usize,
    /// More agent kinds than `max_agents`.
    too_many_agents: usize,
    /// A key field holds `"*"`. The field name is a literal of this file.
    pattern_matches_everything: []const u8,
    /// A key field holds a pattern the language does not allow.
    pattern_malformed: []const u8,
    /// A name field holds a name the language does not allow.
    name_malformed: []const u8,
    /// Two `agents` entries name the same kind. The kind is owned.
    duplicate_agent_kind: []const u8,
    /// An `agents` entry names a parent no entry declares. Both are owned.
    unknown_parent: Parent,
    /// The `parent` links make a loop. The kind that starts it is owned.
    agent_cycle: []const u8,
    /// A child that holds more than its parent. Every name in it is owned.
    child_stronger_than_parent: ChildStronger,
    /// The read time check would cost more than
    /// `max_check_work`. Numbers only.
    policy_too_complex: TooComplex,

    pub const Parent = struct {
        kind: []const u8,
        parent: []const u8,
    };

    pub const ChildStronger = struct {
        kind: []const u8,
        child_answer: Decision,
        parent_kind: []const u8,
        parent_answer: Decision,
        model: []const u8,
        tool: []const u8,
        action: []const u8,
    };

    pub const TooComplex = struct {
        reads: u64,
        longest_name: u64,
        work: u64,
        rules: u64,
        models: u64,
        tools: u64,
        actions: u64,
        links: u64,
    };

    /// Release what the diagnostic owns, with the allocator that filled it.
    /// Safe on every variant, so a caller can call it without asking which
    /// one it holds.
    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .file_not_zon, .block_not_valid => |*zon_diag| zon_diag.deinit(gpa),
            .duplicate_agent_kind, .agent_cycle => |name| gpa.free(name),
            .unknown_parent => |names| {
                gpa.free(names.kind);
                gpa.free(names.parent);
            },
            .child_stronger_than_parent => |names| {
                gpa.free(names.kind);
                gpa.free(names.parent_kind);
                gpa.free(names.model);
                gpa.free(names.tool);
                gpa.free(names.action);
            },
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
                "{s}: the policy block is not valid:\n{f}",
                .{ file_name, zon_diag },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{file_name},
            ),
            .read_failed => |err| try writer.print(
                "reading {s} failed: {s}",
                .{ file_name, @errorName(err) },
            ),
            .too_many_rules => |held| try writer.print(
                "{s}: the policy holds {d} rules, and this reader accepts {d}",
                .{ file_name, held, max_rules },
            ),
            .too_many_agents => |held| try writer.print(
                "{s}: the policy holds {d} agent kinds, and this reader accepts {d}",
                .{ file_name, held, max_agents },
            ),
            .pattern_matches_everything => |field| try writer.print(
                "{s}: the field {s} holds \"*\". Leave the field out to match every value.",
                .{ file_name, field },
            ),
            .pattern_malformed => |field| try writer.print(
                "{s}: the field {s} holds an invalid name. A name matches itself, and a name that ends in \".*\" matches every name below it.",
                .{ file_name, field },
            ),
            .name_malformed => |field| try writer.print(
                "{s}: the field {s} holds an invalid name",
                .{ file_name, field },
            ),
            .duplicate_agent_kind => |kind| try writer.print(
                "{s}: two agents name the kind {s}",
                .{ file_name, kind },
            ),
            .unknown_parent => |names| try writer.print(
                "{s}: the agent {s} names the parent {s}, and no agent declares that kind",
                .{ file_name, names.kind, names.parent },
            ),
            .agent_cycle => |kind| try writer.print(
                "{s}: the parents of the agent {s} make a loop",
                .{ file_name, kind },
            ),
            .child_stronger_than_parent => |names| try writer.print(
                "{s}: the agent {s} holds {t} and its parent {s} holds {t}, for {f}, {f}, and {f}",
                .{
                    file_name,
                    names.kind,
                    names.child_answer,
                    names.parent_kind,
                    names.parent_answer,
                    NameForMessage{ .field = "model", .name = names.model },
                    NameForMessage{ .field = "tool", .name = names.tool },
                    NameForMessage{ .field = "action", .name = names.action },
                },
            ),
            .policy_too_complex => |walk| try writer.print(
                "{s}: to prove that no child holds more than its parent, this reader must read a rule for a key {d} times, over names of up to {d} bytes. " ++
                    "That costs {d} units of work, and this reader accepts {d}. " ++
                    "The rules hold {d} lines, and they tell {d} models, {d} tools, and {d} actions apart, over {d} declared parent link{s}. " ++
                    "Name fewer of them, or give the names fewer bytes.",
                .{
                    file_name,
                    walk.reads,
                    walk.longest_name,
                    walk.work,
                    max_check_work,
                    walk.rules,
                    walk.models,
                    walk.tools,
                    walk.actions,
                    walk.links,
                    plural(walk.links),
                },
            ),
        }
    }
};

/// Why a spawn chain could not be folded, so the answer was `ask`.
///
/// A separate type from `Diagnostic`, because this is not a fault in the
/// file. The chain arrives from a session log, which holds whatever that file
/// holds, so a chain this reader cannot use is a run time fault and not a
/// broken caller. See `Table.evaluateChain`.
///
/// This owns nothing. Every name in it points into the `chain` and the `Key`
/// the caller passed, which the caller still holds.
pub const ChainFault = union(enum) {
    /// The chain names no agent at all.
    empty: []const u8,
    /// A link in the chain has no name.
    link_with_no_name: []const u8,
    /// The last link is not the kind that asked.
    last_link_is_not_the_asker: Mismatch,

    pub const Mismatch = struct {
        agent_kind: []const u8,
        last: []const u8,
    };

    pub fn format(self: ChainFault, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .empty => |action| try writer.print(
                "a policy question about the action {s} arrived with an empty spawn chain, so the answer is ask",
                .{action},
            ),
            .link_with_no_name => |action| try writer.print(
                "a policy question about the action {s} arrived with a spawn chain that holds a link with no name, so the answer is ask",
                .{action},
            ),
            .last_link_is_not_the_asker => |names| try writer.print(
                "a policy question from the kind {s} arrived with a spawn chain that ends in {s}, so the answer is ask",
                .{ names.agent_kind, names.last },
            ),
        }
    }
};

/// Fill `out` when the caller asked for one, and say whether it took `value`.
///
/// **The first fault is kept, not the last.** A later check can only fail
/// because an earlier one did, so the first is the one that explains the rest.
///
/// The answer matters because several variants own memory: a site that hands
/// one over must release it itself when the answer is false.
fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// Whether a diagnostic is wanted and still empty, which is the one case in
/// which a site should copy a name for it. A caller that passes null must pay
/// no allocation at all.
fn wantsDiagnostic(out: ?*?Diagnostic) bool {
    const slot = out orelse return false;
    return slot.* == null;
}

/// `note`, for `ChainFault`. The same first fault rule, and no answer is
/// needed because a `ChainFault` owns nothing there is anything to release.
fn noteChain(out: ?*?ChainFault, value: ChainFault) void {
    const slot = out orelse return;
    if (slot.* != null) return;
    slot.* = value;
}

/// A parsed policy table. `parse` and `load` are the only two constructors,
/// and both hand back a `*const Table`, so no caller ever holds a mutable
/// table. `destroy` ends the life of one. See this file's top comment on why,
/// and the comptime block at the end of this file for what enforces it.
pub const Table = struct {
    /// The rules, behind a pointer to const. Nothing can write a rule of a
    /// loaded table.
    policy: *const Policy,
    /// The rules of the org bundle above this project, or empty for a session
    /// that was given none. See this file's own top comment, and
    /// `lib/chock-policy/org.zig`.
    ///
    /// **Borrowed, and never owned.** The bundle is read before the table and
    /// released after it, so `destroy` frees nothing here. A caller that hands
    /// these in must keep them alive as long as the table.
    ///
    /// **Empty is exactly today's behaviour**, and it is not a special case
    /// anywhere: `ceilingRules` answers `allow` for a rule list that names
    /// nothing, and `allow` is the identity of `intersect`.
    org: []const Rule = &.{},
    /// The hash of the bytes this table was built from.
    hash: [std.crypto.hash.sha2.Sha256.digest_length]u8,

    /// Read the policy out of `source`, which must be the whole content of a
    /// `chock.zon`. The returned table owns a copy of every name in it, so the
    /// caller is free to release `source` at once. `destroy` releases the
    /// table, with the same allocator.
    /// `diag` is optional. A caller that passes null pays nothing, allocates
    /// nothing extra, and learns only the error. A caller that passes a slot
    /// must call `Diagnostic.deinit` on whatever lands in it.
    pub fn parse(
        gpa: std.mem.Allocator,
        source: [:0]const u8,
        diag: ?*?Diagnostic,
    ) ParseError!*const Table {
        return parseUnder(gpa, source, &.{}, diag);
    }

    /// `parse`, under the rules of an org bundle. See this file's own top
    /// comment: the bundle is the outermost layer and `source` may only narrow
    /// it.
    ///
    /// `org` is borrowed for the life of the table. It is
    /// `lib/chock-policy/org.zig`'s `Bundle.rules`, and passing an empty slice
    /// gives exactly the table `parse` gives.
    ///
    /// **The bundle is not validated here.** `org.parse` already refuses a
    /// pattern this language does not allow, and it is the one reader of a
    /// bundle. Checking it a second time would put two answers in the build to
    /// what a bundle may hold.
    pub fn parseUnder(
        gpa: std.mem.Allocator,
        source: [:0]const u8,
        org: []const Rule,
        diag: ?*?Diagnostic,
    ) ParseError!*const Table {
        var trees = try Trees.init(gpa, source, diag);
        var trees_owned = true;
        defer if (trees_owned) trees.deinit(gpa);

        const policy = policy: {
            const node = try findPolicyNode(trees.zoir, diag) orelse break :policy Policy{};
            // From here `trees.diag` owns the two trees. See `Trees`.
            trees.diag_owns_trees = true;
            break :policy std.zon.parse.fromZoirNodeAlloc(
                Policy,
                gpa,
                trees.ast,
                trees.zoir,
                node,
                &trees.diag,
                .{},
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.ParseZon => {
                    if (note(diag, .{ .block_not_valid = trees.diag })) trees_owned = false;
                    return error.InvalidPolicy;
                },
            };
        };
        errdefer std.zon.parse.free(gpa, policy);

        try validate(gpa, policy, diag);

        const owned = try gpa.create(Policy);
        errdefer gpa.destroy(owned);
        owned.* = policy;

        const table = try gpa.create(Table);
        table.* = .{ .policy = owned, .org = org, .hash = hashSource(source) };
        return table;
    }

    /// Read `chock.zon` from `project_root` and parse it. `project_root` is
    /// the same directory `Workspace` calls the project root, and the file has
    /// the same name there.
    ///
    /// `diag` carries the same detail `parse` carries, and the same rule
    /// applies: null costs nothing, and a filled slot must be released with
    /// `Diagnostic.deinit`.
    pub fn load(
        gpa: std.mem.Allocator,
        io: std.Io,
        project_root: []const u8,
        diag: ?*?Diagnostic,
    ) LoadError!*const Table {
        return loadUnder(gpa, io, project_root, &.{}, diag);
    }

    /// `load`, under the rules of an org bundle. See `parseUnder`.
    pub fn loadUnder(
        gpa: std.mem.Allocator,
        io: std.Io,
        project_root: []const u8,
        org: []const Rule,
        diag: ?*?Diagnostic,
    ) LoadError!*const Table {
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
            error.StreamTooLong => return error.PolicyTooLarge,
            error.FileNotFound, error.NotDir => return error.NoPolicyFile,
            else => {
                _ = note(diag, .{ .read_failed = err });
                return error.ReadFailed;
            },
        };
        defer gpa.free(source);

        return parseUnder(gpa, source, org, diag);
    }

    /// Release everything the table owns, with the allocator that built it.
    /// `self` is not valid after this call.
    ///
    /// The allocator is a parameter and not a field, so that a `Table` holds
    /// nothing a caller could aim somewhere else, and so that this function
    /// takes a pointer to const like every other function here. See the
    /// comptime block at the end of this file.
    ///
    /// Two things follow from that, and both are on the caller:
    ///
    /// - **Write `Table.destroy(gpa, t)`.** The allocator is the first
    ///   parameter, so `t.destroy(gpa)` does not compile.
    /// - **Give it a table `parse` or `load` made, and the allocator that
    ///   made it.** This function frees `self` itself, so it ends a table on
    ///   the stack or in static memory as readily as one on the heap. Nothing
    ///   in a `Table` says where it came from, which is the same reason the
    ///   allocator is not a field.
    pub fn destroy(gpa: std.mem.Allocator, self: *const Table) void {
        std.zon.parse.free(gpa, self.policy.*);
        gpa.destroy(self.policy);
        gpa.destroy(self);
    }

    /// The answer for one agent kind on its own, from the one rule that wins.
    /// `ask` when no rule matches.
    ///
    /// This applies no intersection. Use
    /// `evaluateChain`, which is the verb the broker wants. This one answers a
    /// narrower question: what does the file say about this kind alone. The
    /// read time check covers only the links the file declares, so a caller
    /// that uses this for a real request loses the intersection for every kind
    /// the file declares no parent for.
    ///
    /// **The org bundle is applied here as well**, because a caller that asks
    /// about one kind is still a caller that must not be told a project holds
    /// more than its organisation gave it.
    pub fn evaluateKindAlone(self: *const Table, key: Key) Decision {
        return evaluateRules(self.policy.rules, key).intersect(ceilingRules(self.org, key));
    }

    /// `chain` names every agent kind from the root of the spawn
    /// tree down to the agent that asked, root first. The answer is the
    /// intersection over the whole chain, so a child never holds a permission
    /// its parent lacks.
    ///
    /// **The caller builds this chain, and it is not
    /// `ApprovalRequest.spawn_chain` itself.** That field holds every parent
    /// between the root session and the agent that asked, and it leaves the
    /// asker out. See its own comment in `lib/chock-proto/event.zig`. The
    /// chain this function wants is the `agent_kind` of each of those links,
    /// in the order they are in, and then the kind of the agent that asked.
    /// A root agent asks with a chain of one link.
    ///
    /// `chain` is not this program's own data. The links come from
    /// `ApprovalRequest.spawn_chain`, which arrives as JSON in the session
    /// log, and a replayed log holds whatever that file holds. A chain this
    /// function cannot use is therefore a runtime fault and not a broken
    /// caller, so it gets an answer and not an assert. That answer is `ask`,
    /// the same as every other case the policy does not cover. There are three
    /// such chains:
    ///
    /// - an empty chain, which names no agent at all;
    /// - a chain that holds a link of length zero, which names no kind. The
    ///   rules cannot be read for a kind that has no name.
    /// - a chain whose last link is not the kind in `key`. The last link is
    ///   the agent that asked, so the two must not disagree about who asked.
    ///
    /// `fault` is filled for each of those three chains, and only for those
    /// three. It borrows from `chain` and `key`, so it is valid as long as
    /// the caller's own arguments are. A caller that passes null pays
    /// nothing: this function allocates in no case at all.
    pub fn evaluateChain(
        self: *const Table,
        chain: []const []const u8,
        key: Key,
        fault: ?*?ChainFault,
    ) Decision {
        if (chain.len == 0) {
            noteChain(fault, .{ .empty = key.action });
            return .ask;
        }
        for (chain) |kind| {
            if (kind.len > 0) continue;
            noteChain(fault, .{ .link_with_no_name = key.action });
            return .ask;
        }
        const last = chain[chain.len - 1];
        if (!std.mem.eql(u8, last, key.agent_kind)) {
            noteChain(fault, .{ .last_link_is_not_the_asker = .{
                .agent_kind = key.agent_kind,
                .last = last,
            } });
            return .ask;
        }

        // The first link seeds the fold. There is no `allow` here to seed it
        // with, so a chain that walks no link can never leave this function
        // with a decision the rules did not give it.
        //
        // **The org bundle is folded at every link, beside the file.** See this
        // file's own top comment: it is one more term of the same minimum, so
        // a project can lower an answer and can never raise one. A session with
        // no bundle folds an empty rule list, which answers `allow` and changes
        // nothing.
        const first = keyForKind(key, chain[0]);
        var result = evaluateRules(self.policy.rules, first).intersect(ceilingRules(self.org, first));
        for (chain[1..]) |kind| {
            const link = keyForKind(key, kind);
            result = result
                .intersect(evaluateRules(self.policy.rules, link))
                .intersect(ceilingRules(self.org, link));
        }
        return result;
    }

    /// The **ceiling** both layers put on `key`, folded over the whole spawn
    /// chain. `allow` when nothing names the key at all.
    ///
    /// This is the reading for a question about a resource rather than about
    /// an act: may this session use this provider, may it use this model. See
    /// `lib/chock-policy/access.zig`, which is the only caller and which says
    /// what the names are. `evaluateChain` is the reading for an act, and the
    /// two differ in exactly one place: what an action nobody named answers.
    ///
    /// * An act nobody named answers `ask`. A policy that forgot a case must
    ///   not become permission.
    /// * A resource nobody named answers `allow`. There is no ceiling on it,
    ///   and a project that wrote no rule about providers must behave the way
    ///   it did before providers could be named at all.
    ///
    /// `ratchet.ceilingFor` makes the same distinction, for the same reason,
    /// over an agent's own promises. Three layers now read the same rules two
    /// ways, and this is the one function that gives the second reading over a
    /// chain.
    ///
    /// `fault` is filled for the same three chains `evaluateChain` fills it
    /// for, and the answer for those is `deny`. **Not `ask`**: a chain this
    /// reader cannot fold is a log holding something Chock did not write, and
    /// there is nobody to ask about a model at the moment a session picks one.
    pub fn ceilingChain(
        self: *const Table,
        chain: []const []const u8,
        key: Key,
        fault: ?*?ChainFault,
    ) Decision {
        if (chain.len == 0) {
            noteChain(fault, .{ .empty = key.action });
            return .deny;
        }
        for (chain) |kind| {
            if (kind.len > 0) continue;
            noteChain(fault, .{ .link_with_no_name = key.action });
            return .deny;
        }
        const last = chain[chain.len - 1];
        if (!std.mem.eql(u8, last, key.agent_kind)) {
            noteChain(fault, .{ .last_link_is_not_the_asker = .{
                .agent_kind = key.agent_kind,
                .last = last,
            } });
            return .deny;
        }

        var result: Decision = .allow;
        for (chain) |kind| {
            const link = keyForKind(key, kind);
            result = result
                .intersect(ceilingRules(self.policy.rules, link))
                .intersect(ceilingRules(self.org, link));
        }
        return result;
    }

    /// The hash of the bytes this table was parsed from.
    ///
    /// Chock compares the file at the end of a session against what it read
    /// at the start. This is one half of that comparison.
    /// The other half is to read the file again and hash it with `hashSource`.
    /// A `Table` keeps no path on purpose, so it cannot read the file a second
    /// time. Nothing in this module can make that comparison, and no check
    /// here can remind a caller to make it. The caller owns it.
    pub fn sourceHash(self: *const Table) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
        return self.hash;
    }
};

/// `key` with a different agent kind, for one link of a spawn chain.
fn keyForKind(key: Key, agent_kind: []const u8) Key {
    return .{
        .agent_kind = agent_kind,
        .model = key.model,
        .tool = key.tool,
        .action = key.action,
    };
}

// Chock parses `chock.zon` one time and holds it in memory, so a
// change to the file cannot change the policy of a running session. These
// checks enforce that, instead of a comment that asks a later author to
// remember it. They fail the build, which is the one place a rule like this
// cannot be skipped.
comptime {
    const pointer = @typeInfo(@FieldType(Table, "policy")).pointer;
    if (!pointer.is_const) @compileError(
        "Table.policy must point to const, or a caller could rewrite a rule of a live session",
    );

    // Both namespaces, because a free function in this file can take a table
    // as well as a method can. `@typeInfo` reports the public declarations, so
    // this covers every function a caller outside this file can reach.
    refuseMutableTable(Table, "Table.");
    refuseMutableTable(@This(), "");
}

/// Fail the build when a public function of `namespace` takes a mutable
/// `*Table` in any position. `parse` and `load` hand back a `*const Table`, so
/// a mutable one is a table this file made, and a function that asks for one
/// is a function that means to change a table of a live session.
fn refuseMutableTable(comptime namespace: type, comptime prefix: []const u8) void {
    for (@typeInfo(namespace).@"struct".decls) |decl| {
        const info = switch (@typeInfo(@TypeOf(@field(namespace, decl.name)))) {
            .@"fn" => |function| function,
            else => continue,
        };
        for (info.params) |param| {
            const kind = param.type orelse continue;
            const pointer = switch (@typeInfo(kind)) {
                .pointer => |pointer| pointer,
                else => continue,
            };
            if (pointer.child != Table or pointer.is_const) continue;
            @compileError(prefix ++ decl.name ++
                " takes a mutable *Table, and no function may do that");
        }
    }
}

/// The answer `Table.evaluateKindAlone` gives, over a rule list on its own.
/// `validate` needs this before there is a `Table` to ask.
///
/// **`lib/chock-policy/defaults.zig`'s rules answer beside `rules`, not
/// underneath them.** `winnerFor` already finds the one rule of a list that
/// answers for `key`, and this asks it twice, once for each list, then keeps
/// whichever of the two answers `ruleBeats` prefers. That is the same search
/// `winnerFor` runs over one list that holds every rule of both, because
/// `ruleBeats` is a total order and the strongest rule of the whole is always
/// the stronger of the two lists' own strongest. See this file's own top
/// comment for why that must not be built as one more term of an
/// intersection instead.
fn evaluateRules(rules: []const Rule, key: Key) Decision {
    const winner = strongerOfTwoWinners(
        winnerFor(rules, key),
        winnerFor(defaults.rules, key),
    ) orelse return .ask;
    return winner.decision;
}

/// The rule `ruleBeats` would keep, between the winner of one list and the
/// winner of another. Null only when neither list held a match at all.
fn strongerOfTwoWinners(a: ?Rule, b: ?Rule) ?Rule {
    const left = a orelse return b;
    const right = b orelse return a;
    return if (ruleBeats(right, left)) right else left;
}

/// `evaluateRules`, for a layer that is read as a ceiling: **a key no rule
/// names answers `allow`**, which is no ceiling at all rather than the safe
/// answer to a question about an act.
///
/// The same rules and the same winner. See this file's own top comment for
/// which layer is read which way and why the two defaults have to differ.
fn ceilingRules(rules: []const Rule, key: Key) Decision {
    const answer = winnerFor(rules, key) orelse return .allow;
    return answer.decision;
}

/// The one rule of `rules` that answers for `key`, or null when none matches.
/// The two readings above differ only in what they make of null.
fn winnerFor(rules: []const Rule, key: Key) ?Rule {
    // Chock builds every key itself, out of names it already holds. An empty
    // part means the caller is broken, not that the file is.
    std.debug.assert(key.agent_kind.len > 0);
    std.debug.assert(key.model.len > 0);
    std.debug.assert(key.tool.len > 0);
    std.debug.assert(key.action.len > 0);

    var winner: ?Rule = null;
    for (rules) |rule| {
        if (!ruleMatches(rule, key)) continue;
        const best = winner orelse {
            winner = rule;
            continue;
        };
        if (ruleBeats(rule, best)) winner = rule;
    }
    return winner;
}

fn ruleMatches(rule: Rule, key: Key) bool {
    return patternMatches(rule.action, key.action) and
        patternMatches(rule.tool, key.tool) and
        patternMatches(rule.model, key.model) and
        patternMatches(rule.agent_kind, key.agent_kind);
}

/// True when `candidate` answers instead of `best`. The two rules are compared
/// one field at a time, in the order this file's top comment gives, and the
/// more restrictive decision breaks a tie. The order is therefore total, and
/// the answer never depends on the order the rules have in the file.
fn ruleBeats(candidate: Rule, best: Rule) bool {
    inline for (.{ "action", "tool", "model", "agent_kind" }) |field| {
        const left = patternScore(@field(candidate, field));
        const right = patternScore(@field(best, field));
        if (left != right) return left > right;
    }
    return candidate.decision.rank() < best.decision.rank();
}

/// The prefix of a class pattern. `git.*` names the class of every action
/// below `git`. Null when the pattern names one value exactly.
fn classPrefix(pattern: []const u8) ?[]const u8 {
    if (!std.mem.endsWith(u8, pattern, ".*")) return null;
    return pattern[0 .. pattern.len - 2];
}

/// True when `pattern` names `value`. An absent pattern names every value.
///
/// **Public because the pattern language is this file's**, and
/// `lib/chock-policy/ratchet.zig` reads the same key with the same rules. A
/// second implementation of `git.*` would be a second answer to "does this rule
/// cover this action", and the two would disagree the first time one of them
/// changed.
pub fn patternMatches(pattern: ?[]const u8, value: []const u8) bool {
    const text = pattern orelse return true;
    const prefix = classPrefix(text) orelse return std.mem.eql(u8, text, value);
    // `git.*` matches `git.push`, and it does not match `git` itself.
    return value.len > prefix.len + 1 and
        std.mem.startsWith(u8, value, prefix) and
        value[prefix.len] == '.';
}

/// True when every name `inner` names is also named by `outer`.
///
/// `patternMatches` answers about one value. This answers about one pattern,
/// which is the question `lib/chock-policy/ratchet.zig` asks when an agent
/// proposes a restriction over a whole class: `git.*` covers `git.push` and
/// covers `git.branch.*`, and `git.push` covers only itself.
///
/// **A name is a pattern that names itself**, so this answers `patternMatches`
/// for an `inner` that names one value exactly, and the two never disagree.
pub fn patternCovers(outer: []const u8, inner: []const u8) bool {
    const outer_prefix = classPrefix(outer) orelse return std.mem.eql(u8, outer, inner);
    const inner_prefix = classPrefix(inner) orelse return patternMatches(outer, inner);
    if (std.mem.eql(u8, outer_prefix, inner_prefix)) return true;
    // `git.*` covers `git.branch.*`, and it does not cover `gitlab.*`.
    return inner_prefix.len > outer_prefix.len + 1 and
        std.mem.startsWith(u8, inner_prefix, outer_prefix) and
        inner_prefix[outer_prefix.len] == '.';
}

/// True when `pattern` is a pattern this file's language allows: a name, or a
/// name and `.*`. A bare `"*"` is not one, and neither is a name that holds a
/// `*` or the byte `fresh_marker` invents.
///
/// **Public for `lib/chock-policy/ratchet.zig`**, which reads a pattern an
/// agent wrote rather than one `chock.zon` holds. `validatePattern` is the
/// same check with the message a file's author needs.
pub fn patternIsWellFormed(pattern: []const u8) bool {
    if (std.mem.eql(u8, pattern, "*")) return false;
    const body = classPrefix(pattern) orelse pattern;
    return body.len != 0 and
        std.mem.indexOfScalar(u8, body, '*') == null and
        std.mem.indexOfScalar(u8, body, 0) == null;
}

/// The score of every exact name, which is above the score of every class. A
/// class score is the number of names in its prefix, and no file can push that
/// this high, because `max_file_bytes` bounds the length of a name.
///
/// Every exact name holds the same score. Two exact patterns that both match
/// one key are the same string, so nothing about the name itself can ever
/// break a tie between two rules that both match.
const exact_score: u64 = 1 << 32;

fn patternScore(pattern: ?[]const u8) u64 {
    const text = pattern orelse return 0;
    const prefix = classPrefix(text) orelse return exact_score;
    return segmentCount(prefix);
}

fn segmentCount(name: []const u8) u64 {
    return std.mem.count(u8, name, ".") + 1;
}

/// The hash of one policy source, so two sources can be compared.
pub fn hashSource(source: []const u8) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
    var out: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &out, .{});
    return out;
}

/// The `Ast` and the `Zoir` of one parse, plus the diagnostics that report
/// what was wrong with them.
///
/// `std.zon.parse.Diagnostics.deinit` frees the two trees that were given to
/// the parse call, and the parse call takes them the moment it starts. Before
/// that call the trees are ours to free. `diag_owns_trees` holds which of the
/// two is true, so every failure path frees the trees exactly one time.
const Trees = struct {
    ast: std.zig.Ast,
    zoir: std.zig.Zoir,
    diag: std.zon.parse.Diagnostics = .{},
    diag_owns_trees: bool = false,

    fn init(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!Trees {
        var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
        };
        var ast_owned = true;
        errdefer if (ast_owned) ast.deinit(gpa);

        // `parse_str_lits = false` matches what `std.zon.parse.fromSlice`
        // does. The parse call below reads the string literals from the `Ast`,
        // and this file only reads field names, which are always available.
        var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
        var zoir_owned = true;
        errdefer if (zoir_owned) zoir.deinit(gpa);

        // A syntax error also arrives here, because `ZonGen.generate` lowers
        // the errors of the `Ast` into its own. When there is one, the `Zoir`
        // holds no nodes at all, so nothing may walk it.
        if (zoir.hasCompileErrors()) {
            // The two trees carry the message, the line and the column, so
            // they go to the caller whole rather than being flattened to a
            // printed line here. `std.zon.parse.Diagnostics` owns both from
            // this point, which is the same handover `parse` makes below.
            if (note(diag, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
                ast_owned = false;
                zoir_owned = false;
            }
            return error.InvalidPolicy;
        }

        return .{ .ast = ast, .zoir = zoir };
    }

    fn deinit(self: *Trees, gpa: std.mem.Allocator) void {
        if (self.diag_owns_trees) {
            self.diag.deinit(gpa);
        } else {
            self.ast.deinit(gpa);
            self.zoir.deinit(gpa);
        }
        self.* = undefined;
    }
};

/// The node of the `policy` field at the top of the file. Null when the file
/// has no such field, which is a file that says nothing about policy, and
/// therefore a table where every key resolves to `ask`.
fn findPolicyNode(zoir: std.zig.Zoir, diag: ?*?Diagnostic) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), "policy")) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidPolicy;
        },
    }
}

/// Everything about a policy that must be right before a session starts. A
/// mistake here is reported when Chock reads the file. The user does not read
/// about it on the turn that happens to hit the rule.
fn validate(gpa: std.mem.Allocator, policy: Policy, diag: ?*?Diagnostic) ParseError!void {
    // The counts come first, because every check below costs time in the
    // number of rules and the read time check costs a great
    // deal of it. `chock.zon` comes from the project directory, so a hostile
    // project writes it.
    if (policy.rules.len > max_rules) {
        _ = note(diag, .{ .too_many_rules = policy.rules.len });
        return error.TooManyRules;
    }
    if (policy.agents.len > max_agents) {
        _ = note(diag, .{ .too_many_agents = policy.agents.len });
        return error.TooManyAgents;
    }

    for (policy.rules) |rule| {
        inline for (.{ "agent_kind", "model", "tool", "action" }) |field| {
            try validatePattern(field, @field(rule, field), diag);
        }
    }

    for (policy.agents, 0..) |agent, index| {
        try validateName("kind", agent.kind, diag);
        for (policy.agents[index + 1 ..]) |other| {
            if (!std.mem.eql(u8, agent.kind, other.kind)) continue;
            // The name is copied, because `Table.parse` releases the `Policy`
            // it points into the moment this function returns an error.
            if (wantsDiagnostic(diag)) {
                _ = note(diag, .{ .duplicate_agent_kind = try gpa.dupe(u8, agent.kind) });
            }
            return error.DuplicateAgent;
        }

        const parent = agent.parent orelse continue;
        try validateName("parent", parent, diag);
        if (findAgent(policy.agents, parent) == null) {
            if (wantsDiagnostic(diag)) {
                const kind_copy = try gpa.dupe(u8, agent.kind);
                errdefer gpa.free(kind_copy);
                const parent_copy = try gpa.dupe(u8, parent);
                _ = note(diag, .{ .unknown_parent = .{ .kind = kind_copy, .parent = parent_copy } });
            }
            return error.UnknownParent;
        }
    }

    try checkNoCycle(gpa, policy.agents, diag);
    try checkChildrenAreWeaker(gpa, policy, diag);
}

fn findAgent(agents: []const Agent, kind: []const u8) ?Agent {
    for (agents) |agent| {
        if (std.mem.eql(u8, agent.kind, kind)) return agent;
    }
    return null;
}

/// `field` is always a literal of this file, so the diagnostic borrows it and
/// copies nothing.
fn validatePattern(field: []const u8, pattern: ?[]const u8, diag: ?*?Diagnostic) ParseError!void {
    const text = pattern orelse return;
    if (std.mem.eql(u8, text, "*")) {
        _ = note(diag, .{ .pattern_matches_everything = field });
        return error.InvalidPattern;
    }
    if (!patternIsWellFormed(text)) {
        _ = note(diag, .{ .pattern_malformed = field });
        return error.InvalidPattern;
    }
}

/// `field` is always a literal of this file. See `validatePattern`.
fn validateName(field: []const u8, name: []const u8, diag: ?*?Diagnostic) ParseError!void {
    if (name.len > 0 and
        std.mem.indexOfScalar(u8, name, '*') == null and
        std.mem.indexOfScalar(u8, name, 0) == null) return;
    _ = note(diag, .{ .name_malformed = field });
    return error.InvalidPattern;
}

fn checkNoCycle(gpa: std.mem.Allocator, agents: []const Agent, diag: ?*?Diagnostic) ParseError!void {
    for (agents) |start| {
        var current = start;
        var steps: usize = 0;
        while (current.parent) |parent| {
            steps += 1;
            if (steps > agents.len) {
                // Copied, for the reason `validate` gives above.
                if (wantsDiagnostic(diag)) {
                    _ = note(diag, .{ .agent_cycle = try gpa.dupe(u8, start.kind) });
                }
                return error.AgentCycle;
            }
            current = findAgent(agents, parent) orelse return error.UnknownParent;
        }
    }
}

/// A declared child must hold no more than its declared parent, for every
/// key. There is no need to walk every key that exists, because the
/// rules can only tell a finite number of classes of key apart. See
/// `representatives`.
///
/// Finite is not the same as small. `checkWorkFitsBudget` counts the walk
/// before the walk starts, and refuses a file that asks for too much of it.
fn checkChildrenAreWeaker(gpa: std.mem.Allocator, policy: Policy, diag: ?*?Diagnostic) ParseError!void {
    if (policy.agents.len == 0) return;

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const models = try representatives(arena, policy.rules, "model");
    const tools = try representatives(arena, policy.rules, "tool");
    const actions = try representatives(arena, policy.rules, "action");

    var links: usize = 0;
    for (policy.agents) |agent| {
        if (agent.parent != null) links += 1;
    }
    if (links == 0) return;
    try checkWorkFitsBudget(.{
        .models = models.len,
        .tools = tools.len,
        .actions = actions.len,
        .links = links,
        .rules = policy.rules.len,
        .longest_name = longestPattern(policy.rules),
    }, diag);

    for (policy.agents) |agent| {
        const parent_kind = agent.parent orelse continue;
        for (models) |model| for (tools) |tool| for (actions) |action| {
            const child_answer = evaluateRules(policy.rules, .{
                .agent_kind = agent.kind,
                .model = model,
                .tool = tool,
                .action = action,
            });
            const parent_answer = evaluateRules(policy.rules, .{
                .agent_kind = parent_kind,
                .model = model,
                .tool = tool,
                .action = action,
            });
            if (child_answer.rank() <= parent_answer.rank()) continue;

            // Every name here is copied. The two kinds live in the `Policy`
            // that `Table.parse` releases on this path, and a model, a tool,
            // or an action can also be a name `representatives` invented in
            // the arena above, which this function ends on the way out.
            if (wantsDiagnostic(diag)) {
                var owned: Diagnostic = .{ .child_stronger_than_parent = .{
                    .kind = "",
                    .child_answer = child_answer,
                    .parent_kind = "",
                    .parent_answer = parent_answer,
                    .model = "",
                    .tool = "",
                    .action = "",
                } };
                errdefer owned.deinit(gpa);
                const names = &owned.child_stronger_than_parent;
                names.kind = try gpa.dupe(u8, agent.kind);
                names.parent_kind = try gpa.dupe(u8, parent_kind);
                names.model = try gpa.dupe(u8, model);
                names.tool = try gpa.dupe(u8, tool);
                names.action = try gpa.dupe(u8, action);
                _ = note(diag, owned);
            }
            return error.ChildStrongerThanParent;
        };
    }
}

/// The length below which one read of a rule costs what a read of a name of
/// this length costs. A read compares up to four names, and it also does the
/// work around those comparisons, so the cost of a read stops falling once the
/// names are short. Measured with `--release=safe`: a read over names of 4
/// bytes and a read over names of 64 bytes both cost about 15 to 20
/// nanoseconds, and a read over names of 4600 bytes costs 460.
const shortest_billed_name = 64;

/// How far the read time check must walk, and what one step of
/// it costs. `checkWorkFitsBudget` turns this into one number.
const Walk = struct {
    /// The three representative lists. See `representatives`.
    models: u64,
    tools: u64,
    actions: u64,
    /// How many declared parent links the walk covers.
    links: u64,
    /// How many rules each key is read against.
    rules: u64,
    /// The longest name any rule spells out, in bytes.
    longest_name: u64,
};

/// Refuse a policy whose read time check would cost more than
/// `max_check_work`. The walk reads every rule two times for each key, the
/// number of keys is the product of the three representative lists and the
/// number of declared links, and one read costs what the names are long.
///
/// The count of the work comes before the work, so a hostile `chock.zon`
/// cannot hold the start of a session. The count is in `u64` and the
/// arithmetic saturates, because the product of six numbers a file controls
/// overflows any register.
fn checkWorkFitsBudget(walk: Walk, diag: ?*?Diagnostic) ParseError!void {
    const name_cost = @max(walk.longest_name, shortest_billed_name);
    const keys = walk.models *| walk.tools *| walk.actions *| walk.links;
    const reads = keys *| walk.rules *| 2;
    const work = reads *| name_cost;
    if (work <= max_check_work) return;

    _ = note(diag, .{ .policy_too_complex = .{
        .reads = reads,
        .longest_name = walk.longest_name,
        .work = work,
        .rules = walk.rules,
        .models = walk.models,
        .tools = walk.tools,
        .actions = walk.actions,
        .links = walk.links,
    } });
    return error.PolicyTooComplex;
}

/// The end of an English plural, for a count in a message to the user.
fn plural(count: u64) []const u8 {
    return if (count == 1) "" else "s";
}

/// The longest pattern any rule spells out, in bytes. A read of one rule
/// compares the key against up to four of these, and the value in the key is
/// a name Chock holds, so the pattern is what bounds the length of the
/// comparison.
fn longestPattern(rules: []const Rule) usize {
    var longest: usize = 0;
    for (rules) |rule| {
        inline for (.{ "agent_kind", "model", "tool", "action" }) |field| {
            if (@field(rule, field)) |pattern| longest = @max(longest, pattern.len);
        }
    }
    return longest;
}

/// The byte that marks a name this reader invented. No name in the file can
/// hold it, because `validatePattern` and `validateName` refuse one that does.
const fresh_marker = "\x00";

/// One value for each class of value the rules can tell apart, for one field.
/// Two values in the same class match exactly the same rules, so one of them
/// answers for all of them. The list holds every name the rules spell out, one
/// invented name below each class the rules name, and one invented name that
/// no pattern in the file matches at all.
///
/// This is what makes the check in `checkChildrenAreWeaker` finite. That check
/// walks the product of three of these lists for each declared parent link, so
/// it reads at most the cube of one more than the number of rules, for each
/// link. `checkWorkFitsBudget` refuses a policy that reaches too far up that
/// cube.
///
/// A name that two rules share earns one entry, because a second entry would
/// only make the walk read the same key again.
fn representatives(
    arena: std.mem.Allocator,
    rules: []const Rule,
    comptime field: []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    try list.ensureTotalCapacity(arena, rules.len + 1);
    list.appendAssumeCapacity(fresh_marker);

    for (rules) |rule| {
        const pattern = @field(rule, field) orelse continue;
        const name = if (classPrefix(pattern)) |prefix|
            try std.fmt.allocPrint(arena, "{s}.{s}", .{ prefix, fresh_marker })
        else
            pattern;
        if (holdsName(list.items, name)) continue;
        list.appendAssumeCapacity(name);
    }
    return list.items;
}

fn holdsName(names: []const []const u8, name: []const u8) bool {
    for (names) |held| {
        if (std.mem.eql(u8, held, name)) return true;
    }
    return false;
}

/// A name from `representatives`, written the way the author would have
/// written it, with the field it names.
///
/// An invented name holds `fresh_marker`. The bare marker stands for every
/// value the rules do not name, and there is no way to write that in the file,
/// so this prints `any action` and not a pattern the reader would refuse. An
/// invented name below a class stands for that class, and this prints the
/// class the way the author wrote it, as `the action git.*`.
const NameForMessage = struct {
    field: []const u8,
    name: []const u8,

    pub fn format(self: NameForMessage, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        if (std.mem.eql(u8, self.name, fresh_marker)) {
            return writer.print("any {s}", .{self.field});
        }
        try writer.print("the {s} ", .{self.field});
        for (self.name) |byte| try writer.writeByte(if (byte == 0) '*' else byte);
    }
};

// Every test below builds its own policy source in the test binary, and the one
// test that needs a real file writes it into a fresh `std.testing.tmpDir`. No
// test reads the checkout that Chock itself lives in.

/// A key for one agent kind and one action, with the two parts these tests do
/// not vary held still.
fn testKey(agent_kind: []const u8, action: []const u8) Key {
    return .{
        .agent_kind = agent_kind,
        .model = "test-model",
        .tool = "git",
        .action = action,
    };
}

/// The absolute path of an already open directory. `std.testing.tmpDir` hands
/// back a directory that only a relative path reaches, and `Table.load` needs
/// a project root that does not depend on the working directory of the test
/// binary. Mirrors the helper of the same name in
/// `lib/chock-workspace/worktree.zig`.
fn absoluteDirPath(buffer: []u8, dir: std.Io.Dir) ![]u8 {
    const len = dir.realPath(std.testing.io, buffer) catch return error.RealPathFailed;
    return buffer[0..len];
}

/// A policy source with `count` copies of `item` between `head` and `tail`.
/// Every `#` in `item` becomes the number of the copy, so each copy names a
/// different rule or a different agent kind.
fn repeatedSource(
    gpa: std.mem.Allocator,
    head: []const u8,
    item: []const u8,
    count: usize,
    tail: []const u8,
) ![:0]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try out.appendSlice(gpa, head);
    for (0..count) |index| {
        var digits: [24]u8 = undefined;
        const number = try std.fmt.bufPrint(&digits, "{d}", .{index});
        for (item) |byte| {
            if (byte == '#') {
                try out.appendSlice(gpa, number);
            } else {
                try out.append(gpa, byte);
            }
        }
    }
    try out.appendSlice(gpa, tail);
    return out.toOwnedSliceSentinel(gpa, 0);
}

/// A policy of `rules` rules under one declared parent link, where every rule
/// names a model, a tool and an action of its own, and every name is
/// `name_bytes` long. Two names of one field differ only in the digits at the
/// end, which is the shape that reads the most bytes for each comparison.
///
/// `name_bytes` must hold the digits of the largest index and one byte more.
fn wideSource(gpa: std.mem.Allocator, rules: usize, name_bytes: usize) ![:0]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try out.appendSlice(gpa, ".{ .policy = .{ .agents = .{ .{ .kind = \"p\" }, " ++
        ".{ .kind = \"c\", .parent = \"p\" } }, .rules = .{");
    for (0..rules) |index| {
        var digits: [24]u8 = undefined;
        const number = try std.fmt.bufPrint(&digits, "{d}", .{index});
        try out.appendSlice(gpa, " .{");
        inline for (.{ "model", "tool", "action" }) |field| {
            try out.appendSlice(gpa, " ." ++ field ++ " = \"");
            try out.appendNTimes(gpa, 'x', name_bytes - number.len);
            try out.appendSlice(gpa, number);
            try out.appendSlice(gpa, "\",");
        }
        try out.appendSlice(gpa, " .decision = .deny },");
    }
    try out.appendSlice(gpa, " } } }");
    return out.toOwnedSliceSentinel(gpa, 0);
}

/// The name `wideSource` gives to the field of the rule with this index.
fn wideName(buffer: []u8, index: usize, name_bytes: usize) ![]u8 {
    var digits: [24]u8 = undefined;
    const number = try std.fmt.bufPrint(&digits, "{d}", .{index});
    @memset(buffer[0..name_bytes], 'x');
    @memcpy(buffer[name_bytes - number.len ..][0..number.len], number);
    return buffer[0..name_bytes];
}

/// The name of every public function of this file, and of `Table`, that takes
/// a mutable `*Table` in any position. There must be none, because
/// `parse` and `load` hand back a `*const Table` and `destroy` takes one.
fn mutableTableFunctionNames() []const []const u8 {
    comptime {
        var names: []const []const u8 = &.{};
        for (.{ Table, @This() }) |namespace| {
            for (@typeInfo(namespace).@"struct".decls) |decl| {
                const info = switch (@typeInfo(@TypeOf(@field(namespace, decl.name)))) {
                    .@"fn" => |function| function,
                    else => continue,
                };
                for (info.params) |param| {
                    const kind = param.type orelse continue;
                    const pointer = switch (@typeInfo(kind)) {
                        .pointer => |pointer| pointer,
                        else => continue,
                    };
                    if (pointer.child != Table or pointer.is_const) continue;
                    names = names ++ [_][]const u8{decl.name};
                }
            }
        }
        return names;
    }
}

test "a policy that names an action exactly beats one that names a class" {
    const gpa = std.testing.allocator;

    // The same two rules in both orders. The answer must not depend on which
    // one the author wrote first.
    const class_first: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.*", .decision = .allow },
        \\            .{ .action = "git.push", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const exact_first: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.push", .decision = .deny },
        \\            .{ .action = "git.*", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;

    for ([_][:0]const u8{ class_first, exact_first }) |source| {
        const table = try Table.parse(gpa, source, null);
        defer Table.destroy(gpa, table);

        try std.testing.expectEqual(Decision.deny, table.evaluateKindAlone(testKey("main", "git.push")));
        try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "git.commit")));
        try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "git.branch.delete")));
    }

    // A longer prefix beats a shorter one, for the same reason.
    const nested: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.*", .decision = .allow },
        \\            .{ .action = "git.branch.*", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, nested, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.deny, table.evaluateKindAlone(testKey("main", "git.branch.delete")));
    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "git.commit")));
}

test "a subagent's policy is the intersection of its parent's and its kind's" {
    // Never a superset. A tree 6 deep becomes weaker at the
    // leaves, and this test proves a child cannot hold a permission its parent
    // lacks: `a3` and `a5` each hold an `allow` of their own, and the chain
    // takes both away.
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .agent_kind = "a0", .action = "git.push", .decision = .allow },
        \\            .{ .agent_kind = "a1", .action = "git.push", .decision = .allow },
        \\            .{ .agent_kind = "a2", .action = "git.push", .decision = .ask },
        \\            .{ .agent_kind = "a3", .action = "git.push", .decision = .allow },
        \\            .{ .agent_kind = "a4", .action = "git.push", .decision = .deny },
        \\            .{ .agent_kind = "a5", .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;

    const table = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, table);

    const chain = [_][]const u8{ "a0", "a1", "a2", "a3", "a4", "a5" };

    const alone = [_]Decision{ .allow, .allow, .ask, .allow, .deny, .allow };
    for (chain, alone) |kind, want| {
        try std.testing.expectEqual(want, table.evaluateKindAlone(testKey(kind, "git.push")));
    }

    // What the chain says at each depth. `a3` asks although its own kind
    // allows, because `a2` only asks. `a5` is denied although its own kind
    // allows, because `a4` denies.
    const want_chain = [_]Decision{ .allow, .allow, .ask, .ask, .deny, .deny };
    for (1..chain.len + 1) |depth| {
        const links = chain[0..depth];
        const got = table.evaluateChain(links, testKey(links[depth - 1], "git.push"), null);
        try std.testing.expectEqual(want_chain[depth - 1], got);

        if (depth > 1) {
            const parent_links = chain[0 .. depth - 1];
            const parent = table.evaluateChain(parent_links, testKey(parent_links[depth - 2], "git.push"), null);
            // Never a superset: the child holds at most what the parent holds.
            try std.testing.expect(got.rank() <= parent.rank());
        }
    }

    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("a5", "git.push")));
    try std.testing.expectEqual(Decision.deny, table.evaluateChain(&chain, testKey("a5", "git.push"), null));
}

test "an action no rule names resolves to ask, never to allow" {
    // The safe default. A policy that forgot a case must not become
    // permission.
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.commit", .decision = .allow },
        \\            .{ .action = "git.*", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;

    const table = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, table);

    // This action has a name of its own, and this policy forgot it.
    try std.testing.expectEqual(Decision.ask, table.evaluateKindAlone(testKey("main", "net.fetch")));
    // `git.*` names everything below `git`, and not `git` itself.
    try std.testing.expectEqual(Decision.ask, table.evaluateKindAlone(testKey("main", "git")));
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{ "main", "reviewer" }, testKey("reviewer", "net.fetch"), null),
    );

    // A file with an empty policy block, and a file that says nothing about
    // policy at all, both answer `ask` for every key.
    for ([_][:0]const u8{ ".{ .policy = .{} }", ".{}", ".{ .models = .{} }" }) |empty_source| {
        const empty = try Table.parse(gpa, empty_source, null);
        defer Table.destroy(gpa, empty);
        try std.testing.expectEqual(Decision.ask, empty.evaluateKindAlone(testKey("main", "git.push")));
        try std.testing.expectEqual(Decision.ask, empty.evaluateKindAlone(testKey("main", "workspace.apply")));
    }
}

test "a project can write the two review decisions, and a child still cannot climb to one" {
    // The two decisions a reviewer answers are written in `chock.zon` like
    // any other, and the intersection holds over them: the order of
    // `Decision`'s members is what a child
    // cannot climb, and `lib/chock-broker/review.zig` is what turns that into
    // an act.
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "workspace.apply", .decision = .agent_review },
        \\            .{ .action = "git.push", .decision = .agent_then_human },
        \\            .{ .agent_kind = "worker", .action = "workspace.apply", .decision = .agent_review },
        \\            .{ .agent_kind = "cautious", .action = "workspace.apply", .decision = .ask },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, table);

    try std.testing.expectEqual(
        Decision.agent_review,
        table.evaluateKindAlone(testKey("main", "workspace.apply")),
    );
    try std.testing.expectEqual(
        Decision.agent_then_human,
        table.evaluateKindAlone(testKey("main", "git.push")),
    );

    // A worker under a cautious parent gets the parent's `ask`, although its
    // own kind holds `agent_review`. That is the ratchet: narrowing is free
    // and climbing is not, so a reviewer is never reached for this key at all.
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{ "cautious", "worker" }, testKey("worker", "workspace.apply"), null),
    );
    // And the other way round the child keeps the narrower of the two.
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{ "worker", "cautious" }, testKey("cautious", "workspace.apply"), null),
    );

    // A file with a decision name this reader does not know is refused rather
    // than read as the nearest one it does. A misspelled decision that became
    // `allow` is the worst failure this file has.
    try std.testing.expectError(error.InvalidPolicy, Table.parse(gpa,
        \\.{ .policy = .{ .rules = .{ .{ .action = "git.push", .decision = .agent_reveiw } } } }
    , null));
}

test "a policy that gives a child more than its parent is refused when it is read" {
    // Not at evaluation time. A configuration mistake is reported when Chock
    // reads the file, not on the turn that happens to hit it.
    const gpa = std.testing.allocator;

    const child_rule_is_stronger: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "reviewer", .parent = "main" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "git.push", .decision = .deny },
        \\            .{ .agent_kind = "reviewer", .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(
        error.ChildStrongerThanParent,
        Table.parse(gpa, child_rule_is_stronger, null),
    );

    // The same mistake with no rule for the child at all: the child falls back
    // to a rule that names every kind, and that fallback is stronger than what
    // its parent holds. The check must cover a key the child never names.
    const child_falls_back_stronger: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "reviewer", .parent = "main" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "git.push", .decision = .deny },
        \\            .{ .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(
        error.ChildStrongerThanParent,
        Table.parse(gpa, child_falls_back_stronger, null),
    );

    // The two review decisions are ranked with the other three, so the
    // read time check covers them with no branch of its own. A child that may
    // have a machine answer for it, under a parent that has to wake a person,
    // is a child stronger than its parent.
    const child_would_be_reviewed: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "worker", .parent = "main" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "workspace.apply", .decision = .ask },
        \\            .{ .agent_kind = "worker", .action = "workspace.apply", .decision = .agent_review },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(
        error.ChildStrongerThanParent,
        Table.parse(gpa, child_would_be_reviewed, null),
    );

    // The mirror image reads without complaint, and only then is there a table
    // to evaluate at all.
    const child_is_weaker: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "reviewer", .parent = "main" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "git.push", .decision = .allow },
        \\            .{ .agent_kind = "reviewer", .action = "git.push", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, child_is_weaker, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "git.push")));
    try std.testing.expectEqual(Decision.deny, table.evaluateKindAlone(testKey("reviewer", "git.push")));
}

test "a field name with a typo inside the policy block is refused, not ignored" {
    // A rule with no `action` matches every action. If this reader ignored a
    // field name it did not know, `.actoin` would silently become a rule that
    // permits far more than the author wrote.
    const gpa = std.testing.allocator;

    const typo: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .actoin = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.InvalidPolicy, Table.parse(gpa, typo, null));

    // A field name this reader does not know, outside the policy block, is a
    // section of chock.zon that a later milestone adds. That one is ignored.
    const table = try Table.parse(gpa, ".{ .models = .{ .main = \"sonnet\" } }", null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.ask, table.evaluateKindAlone(testKey("main", "git.push")));
}

test "the table cannot be changed after a session starts" {
    // Chock parses chock.zon once and holds it. A change to the
    // file cannot change the policy of a running session.
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project_root = try absoluteDirPath(&path_buffer, tmp.dir);

    const at_start = ".{ .policy = .{ .rules = .{ .{ .action = \"git.push\", .decision = .allow } } } }";
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = file_name, .data = at_start });

    const table = try Table.load(gpa, std.testing.io, project_root, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "git.push")));

    const after_edit = ".{ .policy = .{ .rules = .{ .{ .action = \"git.push\", .decision = .deny } } } }";
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = file_name, .data = after_edit });

    // The session holds what it read.
    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "git.push")));

    // The edit did reach the file, so the line above is a fact about the
    // table and not about the file.
    const next_session = try Table.load(gpa, std.testing.io, project_root, null);
    defer Table.destroy(gpa, next_session);
    try std.testing.expectEqual(Decision.deny, next_session.evaluateKindAlone(testKey("main", "git.push")));

    // Chock also compares the hash at the end of a session and reports a
    // difference to the user. The table keeps what it read.
    try std.testing.expectEqualSlices(u8, &hashSource(at_start), &table.sourceHash());
    try std.testing.expect(!std.mem.eql(u8, &hashSource(after_edit), &table.sourceHash()));

    // The two facts above are about these two tables. The three facts below
    // are about the type, and they are what makes the rule hold for every
    // table. `policy` points to const, so no rule can be written through it.
    // `parse` and `load` hand back a `*const Table`, so no caller holds a
    // table it could point at a different `Policy`. And no public function of
    // this file asks for a mutable one.
    try std.testing.expect(@typeInfo(@FieldType(Table, "policy")).pointer.is_const);
    inline for (.{ Table.parse, Table.load }) |constructor| {
        const returns = @typeInfo(@typeInfo(@TypeOf(constructor)).@"fn".return_type.?)
            .error_union.payload;
        try std.testing.expect(@typeInfo(returns).pointer.is_const);
        try std.testing.expectEqual(Table, @typeInfo(returns).pointer.child);
    }
    const mutable = comptime mutableTableFunctionNames();
    try std.testing.expectEqual(@as(usize, 0), mutable.len);
}

test "an empty spawn chain answers ask, never allow" {
    // `ApprovalRequest.spawn_chain` is JSON in the session log, so a replayed
    // log can hold a chain with no links at all. That is a fault in the file
    // and not a broken caller, so it gets the same answer as every other case
    // the policy does not cover.
    const gpa = std.testing.allocator;

    // A policy that says `allow` for every kind and every action. If an empty
    // chain walked no link and kept the value it started with, the answer here
    // would be `allow`, which is the one answer it must never be.
    const allows_everything: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, allows_everything, null);
    defer Table.destroy(gpa, table);

    // One link answers `allow`, so the table really does permit this key.
    try std.testing.expectEqual(
        Decision.allow,
        table.evaluateChain(&.{"main"}, testKey("main", "git.push"), null),
    );

    const empty: []const []const u8 = &.{};
    try std.testing.expectEqual(Decision.ask, table.evaluateChain(empty, testKey("main", "git.push"), null));

    // A chain whose last link is not the kind that asked answers the same way.
    // The two must not disagree about who asked.
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{ "main", "reviewer" }, testKey("main", "git.push"), null),
    );
}

test "a spawn chain with a link of no name answers ask, never allow" {
    // `ApprovalRequest.spawn_chain` is JSON in the session log, so a replayed
    // log can hold a link whose `agent_kind` is the empty string. The format
    // carries an empty string in other fields already. A name of no bytes is a
    // kind the rules cannot be read for, so it gets the answer every other
    // case the policy does not cover gets.
    const gpa = std.testing.allocator;

    // The same policy the empty chain test uses: `allow` for every kind and
    // every action. The answers below are therefore facts about the chain.
    const allows_everything: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, allows_everything, null);
    defer Table.destroy(gpa, table);

    // Two named links answer `allow`, so the table really does permit this key.
    try std.testing.expectEqual(
        Decision.allow,
        table.evaluateChain(&.{ "main", "reviewer" }, testKey("reviewer", "git.push"), null),
    );

    // The root has no name. This chain passes the last link check, because its
    // last link is the kind that asked, so nothing else stops it.
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{ "", "reviewer" }, testKey("reviewer", "git.push"), null),
    );

    // The agent that asked has no name.
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{ "main", "" }, testKey("", "git.push"), null),
    );

    // One link, and it has no name.
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{""}, testKey("", "git.push"), null),
    );
}

test "a policy of few rules and long names is refused" {
    // The length of a name is what the file says it is, and a read of a rule
    // compares up to four of them. 72 rules of three names of 4600 bytes are
    // inside `max_rules`, inside `max_agents` and inside `max_file_bytes`, and
    // they make only 5.6 * 10^7 reads. That file measured 26 seconds of
    // startup with `--release=safe` while the bound counted reads alone.
    const gpa = std.testing.allocator;

    const long = try wideSource(gpa, 72, 4600);
    defer gpa.free(long);
    try std.testing.expect(long.len > 900 * 1024);
    try std.testing.expect(long.len < max_file_bytes);
    try std.testing.expectError(error.PolicyTooComplex, Table.parse(gpa, long, null));

    // The same shape at 27 rules, where the length of the name is the whole
    // difference between the two answers. Both files hold 27 rules, 3 names
    // each, and one declared parent link, so they walk the same number of
    // keys and read the same number of rules.
    const long_names = try wideSource(gpa, 27, 4600);
    defer gpa.free(long_names);
    try std.testing.expectError(error.PolicyTooComplex, Table.parse(gpa, long_names, null));

    const short_names = try wideSource(gpa, 27, 4);
    defer gpa.free(short_names);
    const table = try Table.parse(gpa, short_names, null);
    defer Table.destroy(gpa, table);

    // The file that is read is a real table, and not an empty one.
    var buffer: [4]u8 = undefined;
    const name = try wideName(&buffer, 11, 4);
    try std.testing.expectEqual(Decision.deny, table.evaluateKindAlone(.{
        .agent_kind = "c",
        .model = name,
        .tool = name,
        .action = name,
    }));
    try std.testing.expectEqual(Decision.ask, table.evaluateKindAlone(.{
        .agent_kind = "c",
        .model = name,
        .tool = name,
        .action = "no rule names this",
    }));
}

test "a name that holds the byte the read time check invents is refused" {
    // The read time check walks one invented name for each
    // class of key, and it marks an invented name with a NUL byte. The file
    // must not be able to write that byte. If it could, a rule could name the
    // representative for "matches nothing", that class would stop being
    // sampled, and a child could then hold `allow` where its parent only asks
    // and still be read.
    const gpa = std.testing.allocator;

    // The exact collision: the rule names the representative itself.
    const holds_the_marker: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "p" },
        \\            .{ .kind = "c", .parent = "p" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "c", .decision = .allow },
        \\            .{ .agent_kind = "p", .action = "\x00", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.InvalidPattern, Table.parse(gpa, holds_the_marker, null));

    // The same byte inside the prefix of a class pattern.
    const class_prefix_holds_the_marker: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.\x00.*", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.InvalidPattern, Table.parse(gpa, class_prefix_holds_the_marker, null));

    // An `agents` entry is read by `validateName`, which refuses the byte too.
    const kind_holds_the_marker: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "\x00" },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.InvalidPattern, Table.parse(gpa, kind_holds_the_marker, null));

    // Without the marker the same shape reads, so the refusal above is about
    // the byte and not about the shape of the file.
    const same_shape_without_it: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "p" },
        \\            .{ .kind = "c", .parent = "p" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "c", .decision = .ask },
        \\            .{ .agent_kind = "p", .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, same_shape_without_it, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("p", "git.push")));
}

test "a bare star is refused, so matching every value keeps one spelling" {
    // "Match everything" is spelled by leaving the field out. Two spellings of
    // one meaning is how a reader comes to believe a rule is narrower than it
    // is.
    const gpa = std.testing.allocator;

    inline for (.{ "agent_kind", "model", "tool", "action" }) |field| {
        const source = ".{ .policy = .{ .rules = .{ .{ ." ++ field ++
            " = \"*\", .decision = .allow } } } }";
        try std.testing.expectError(error.InvalidPattern, Table.parse(gpa, source, null));
    }

    const table = try Table.parse(gpa, ".{ .policy = .{ .rules = .{ .{ .decision = .allow } } } }", null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "net.fetch")));
}

test "one pattern covers another only when it names everything that one names" {
    // `patternCovers` is what `lib/chock-policy/ratchet.zig` asks when an agent
    // proposes a restriction over a class rather than over one action. It has
    // to agree with `patternMatches` wherever both can be asked, or a rule
    // would cover an action the ratchet thought it did not.
    try std.testing.expect(patternCovers("git.push", "git.push"));
    try std.testing.expect(!patternCovers("git.push", "git.commit"));
    // A class covers a name under it, and never the name it is built from.
    try std.testing.expect(patternCovers("git.*", "git.push"));
    try std.testing.expect(patternCovers("git.*", "git.branch.delete"));
    try std.testing.expect(!patternCovers("git.*", "git"));
    // A class covers a narrower class, and a narrower class never covers it.
    try std.testing.expect(patternCovers("git.*", "git.*"));
    try std.testing.expect(patternCovers("git.*", "git.branch.*"));
    try std.testing.expect(!patternCovers("git.branch.*", "git.*"));
    // A name never covers a class, however much of it the class names.
    try std.testing.expect(!patternCovers("git.push", "git.*"));
    // A prefix of a name is not a prefix of a class: `git.*` is about the
    // segment, not about the bytes.
    try std.testing.expect(!patternCovers("git.*", "gitlab.*"));
    try std.testing.expect(!patternCovers("git.*", "gitlab.push"));

    // Wherever the covered pattern names one value exactly, the two functions
    // answer the same thing. That is the property the ratchet leans on when it
    // asks about a concrete action.
    const patterns = [_][]const u8{ "git.push", "git.*", "git.branch.*", "net.fetch" };
    const values = [_][]const u8{ "git.push", "git.branch.delete", "git", "net.fetch", "nix.build" };
    for (patterns) |pattern| {
        for (values) |value| {
            try std.testing.expectEqual(patternMatches(pattern, value), patternCovers(pattern, value));
        }
    }
}

test "a well formed pattern is a name, or a name and a class star, and nothing else" {
    // The same rule `validatePattern` reports to the author of `chock.zon`,
    // read here by the ratchet for a pattern an agent wrote at run time. Two
    // spellings of the check would be two answers to what a pattern is.
    try std.testing.expect(patternIsWellFormed("git.push"));
    try std.testing.expect(patternIsWellFormed("git.*"));
    try std.testing.expect(patternIsWellFormed("a"));
    try std.testing.expect(!patternIsWellFormed("*"));
    try std.testing.expect(!patternIsWellFormed(""));
    try std.testing.expect(!patternIsWellFormed(".*"));
    try std.testing.expect(!patternIsWellFormed("git.*.push"));
    try std.testing.expect(!patternIsWellFormed("git\x00push"));

    // And the file reader refuses exactly what this refuses, so a pattern the
    // ratchet accepts is one `chock.zon` could have held.
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.InvalidPattern, Table.parse(
        gpa,
        ".{ .policy = .{ .rules = .{ .{ .action = \"git.*.push\", .decision = .deny } } } }",
        null,
    ));
}

test "a policy with more rules or more agents than the reader accepts is refused" {
    // `chock.zon` comes from the project directory, so a hostile project
    // writes it. `max_file_bytes` alone admits about fourteen thousand rules,
    // and the read time check costs the cube of the number of
    // names the rules spell out.
    const gpa = std.testing.allocator;

    const too_many_rules = try repeatedSource(
        gpa,
        ".{ .policy = .{ .rules = .{",
        " .{ .action = \"a#\", .decision = .deny },",
        max_rules + 1,
        " } } }",
    );
    defer gpa.free(too_many_rules);
    try std.testing.expectError(error.TooManyRules, Table.parse(gpa, too_many_rules, null));

    const at_the_rule_cap = try repeatedSource(
        gpa,
        ".{ .policy = .{ .rules = .{",
        " .{ .action = \"a#\", .decision = .deny },",
        max_rules,
        " } } }",
    );
    defer gpa.free(at_the_rule_cap);
    const table = try Table.parse(gpa, at_the_rule_cap, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.deny, table.evaluateKindAlone(testKey("main", "a0")));

    const too_many_agents = try repeatedSource(
        gpa,
        ".{ .policy = .{ .agents = .{",
        " .{ .kind = \"k#\" },",
        max_agents + 1,
        " } } }",
    );
    defer gpa.free(too_many_agents);
    try std.testing.expectError(error.TooManyAgents, Table.parse(gpa, too_many_agents, null));
}

test "a policy that would make the read time check walk too far is refused" {
    // The check reads every rule for every class of key, for
    // every declared link. The number of classes grows with the cube of the
    // number of names the rules spell out, so a file of 30 KB inside every
    // other cap can still hold the start of a session for minutes.
    const gpa = std.testing.allocator;

    const wide = try repeatedSource(
        gpa,
        ".{ .policy = .{ .agents = .{ .{ .kind = \"p\" }, .{ .kind = \"c\", .parent = \"p\" } }, .rules = .{",
        " .{ .model = \"m#\", .tool = \"t#\", .action = \"a#\", .decision = .deny },",
        max_rules,
        " } } }",
    );
    defer gpa.free(wide);
    try std.testing.expect(wide.len < 64 * 1024);
    try std.testing.expectError(error.PolicyTooComplex, Table.parse(gpa, wide, null));

    // The same number of rules, and the same number of links, over names that
    // vary in one field only. That policy is read, so the refusal above is
    // about how far the check must walk and not about the size of the file.
    const narrow = try repeatedSource(
        gpa,
        ".{ .policy = .{ .agents = .{ .{ .kind = \"p\" }, .{ .kind = \"c\", .parent = \"p\" } }, .rules = .{",
        " .{ .action = \"a#\", .decision = .deny },",
        max_rules,
        " } } }",
    );
    defer gpa.free(narrow);
    const table = try Table.parse(gpa, narrow, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.deny, table.evaluateKindAlone(testKey("c", "a7")));
}

test "two agents that name the same kind are refused" {
    // Which of the two would answer for that kind is not a question a security
    // control may leave open.
    const gpa = std.testing.allocator;

    const twice: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "main", .parent = "main" },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.DuplicateAgent, Table.parse(gpa, twice, null));
}

test "an agent whose parent no entry declares is refused" {
    // The read time check compares a child against its parent.
    // A parent that is not in the file is a link this reader cannot check.
    const gpa = std.testing.allocator;

    const missing_parent: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "reviewer", .parent = "main" },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.UnknownParent, Table.parse(gpa, missing_parent, null));
}

test "a loop in the parent links is refused" {
    // A loop has no root, so no walk up the tree ends, and no child in the
    // loop can be compared against a parent that is weaker than it.
    const gpa = std.testing.allocator;

    const loop: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "a", .parent = "c" },
        \\            .{ .kind = "b", .parent = "a" },
        \\            .{ .kind = "c", .parent = "b" },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.AgentCycle, Table.parse(gpa, loop, null));

    // An agent that names itself is the shortest loop there is.
    const names_itself: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "a", .parent = "a" },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.AgentCycle, Table.parse(gpa, names_itself, null));
}

test "a file larger than the byte cap, and a project with no file, are both reported" {
    // Neither is a table. The caller decides what to do about a project that
    // holds no policy, and `parse` with `.{}` builds the table where every key
    // resolves to `ask`.
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project_root = try absoluteDirPath(&path_buffer, tmp.dir);

    try std.testing.expectError(
        error.NoPolicyFile,
        Table.load(gpa, std.testing.io, project_root, null),
    );

    // One byte over the cap. The file is valid ZON, so it would read if the
    // cap did not stop it first.
    const oversized = try gpa.alloc(u8, max_file_bytes + 1);
    defer gpa.free(oversized);
    @memset(oversized, ' ');
    @memcpy(oversized[oversized.len - 4 ..], "\n.{}");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = file_name, .data = oversized });
    try std.testing.expectError(
        error.PolicyTooLarge,
        Table.load(gpa, std.testing.io, project_root, null),
    );

    // The same bytes under the cap are read, so the refusal is about the size
    // and not about what the file holds.
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = file_name, .data = oversized[4..] });
    const table = try Table.load(gpa, std.testing.io, project_root, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.ask, table.evaluateKindAlone(testKey("main", "git.push")));
}

test "the names in a refusal reach the caller, and no longer only a terminal" {
    const gpa = std.testing.allocator;
    const child_rule_is_stronger: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "reviewer", .parent = "main" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "git.push", .decision = .deny },
        \\            .{ .agent_kind = "reviewer", .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try std.testing.expectError(
        error.ChildStrongerThanParent,
        Table.parse(gpa, child_rule_is_stronger, &diag),
    );

    const names = diag.?.child_stronger_than_parent;
    try std.testing.expectEqualStrings("reviewer", names.kind);
    try std.testing.expectEqualStrings("main", names.parent_kind);
    try std.testing.expectEqual(Decision.allow, names.child_answer);
    try std.testing.expectEqual(Decision.deny, names.parent_answer);
    try std.testing.expectEqualStrings("git.push", names.action);

    // **The names are copies.** `Table.parse` releases the `Policy` they
    // point into on this path, so a diagnostic that borrowed them would
    // dangle. The testing allocator fails this test if `deinit` misses one.
    var buffer: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try std.testing.expectEqualStrings(
        "chock.zon: the agent reviewer holds allow and its parent main holds deny, " ++
            "for any model, any tool, and the action git.push",
        line,
    );
}

test "a misspelled decision names its line and column, and the trees behind it are released" {
    const gpa = std.testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try std.testing.expectError(error.InvalidPolicy, Table.parse(gpa,
        \\.{ .policy = .{ .rules = .{ .{ .action = "git.push", .decision = .agent_reveiw } } } }
    , &diag));

    var buffer: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try std.testing.expect(std.mem.startsWith(u8, line, "chock.zon: the policy block is not valid:\n"));
    try std.testing.expect(std.mem.indexOf(u8, line, "1:67: error:") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "agent_reveiw") != null);
}

test "a caller that wants no diagnostic allocates nothing extra for one" {
    // The outer optional is what lets a caller opt out. The testing allocator
    // fails this test if a refused parse leaks the copy it would have made
    // for a diagnostic that nobody asked for.
    const gpa = std.testing.allocator;
    const loop: [:0]const u8 =
        \\.{ .policy = .{ .agents = .{
        \\    .{ .kind = "a", .parent = "b" },
        \\    .{ .kind = "b", .parent = "a" },
        \\} } }
    ;
    try std.testing.expectError(error.AgentCycle, Table.parse(gpa, loop, null));
}

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    try std.testing.expect(note(&diag, .not_a_struct_literal));
    try std.testing.expect(!note(&diag, .{ .too_many_rules = 9 }));
    try std.testing.expectEqual(Diagnostic.not_a_struct_literal, diag.?);

    try std.testing.expect(!note(null, .not_a_struct_literal));
    try std.testing.expect(!wantsDiagnostic(null));
    try std.testing.expect(!wantsDiagnostic(&diag));
}

test "no two faults of this module read the same" {
    // A reader has to be able to tell which one happened. The two ZON
    // variants are left out, because both render a syntax tree that no
    // literal here can build; the tests above pin those two.
    const cases: []const Diagnostic = &.{
        .not_a_struct_literal,
        .{ .read_failed = error.AccessDenied },
        .{ .too_many_rules = 1 },
        .{ .too_many_agents = 1 },
        .{ .pattern_matches_everything = "action" },
        .{ .pattern_malformed = "action" },
        .{ .name_malformed = "kind" },
        .{ .duplicate_agent_kind = "main" },
        .{ .unknown_parent = .{ .kind = "main", .parent = "root" } },
        .{ .agent_cycle = "main" },
        .{ .child_stronger_than_parent = .{
            .kind = "child",
            .child_answer = .allow,
            .parent_kind = "parent",
            .parent_answer = .deny,
            .model = "m",
            .tool = "t",
            .action = "a",
        } },
        .{ .policy_too_complex = .{
            .reads = 1,
            .longest_name = 2,
            .work = 3,
            .rules = 4,
            .models = 5,
            .tools = 6,
            .actions = 7,
            .links = 8,
        } },
    };
    var buffers: [cases.len][1024]u8 = undefined;
    var lines: [cases.len][]const u8 = undefined;
    for (cases, 0..) |case, i| {
        lines[i] = try std.fmt.bufPrint(&buffers[i], "{f}", .{&case});
        try std.testing.expect(lines[i].len > 0);
    }
    for (lines, 0..) |line, i| {
        for (lines[i + 1 ..]) |other| try std.testing.expect(!std.mem.eql(u8, line, other));
    }
}

test "a spawn chain the reader cannot fold names why, and the answer stays ask" {
    // `evaluateChain` allocates in no case, so its fault type owns nothing
    // and borrows from the caller's own chain and key.
    const gpa = std.testing.allocator;
    const table = try Table.parse(gpa, ".{ .policy = .{ .rules = .{ .{ .decision = .allow } } } }", null);
    defer Table.destroy(gpa, table);

    var fault: ?ChainFault = null;
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{}, testKey("main", "git.push"), &fault),
    );
    try std.testing.expectEqualStrings("git.push", fault.?.empty);

    // **The first, not the last**, here too.
    _ = table.evaluateChain(&.{""}, testKey("", "git.push"), &fault);
    try std.testing.expectEqualStrings("git.push", fault.?.empty);

    var second: ?ChainFault = null;
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{"main"}, testKey("reviewer", "git.push"), &second),
    );
    var buffer: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        "a policy question from the kind reviewer arrived with a spawn chain that ends in main, so the answer is ask",
        try std.fmt.bufPrint(&buffer, "{f}", .{second.?}),
    );

    // A caller that wants no fault gets the same decision and stores nothing.
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{}, testKey("main", "git.push"), null),
    );
}

test "a project cannot widen what an org narrowed" {
    const gpa = std.testing.allocator;

    // The project is as permissive as a file can be about this act.
    const project_allows: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "provider.public.gpt-5", .decision = .allow },
        \\            .{ .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const org_narrows = [_]Rule{
        .{ .action = "provider.public.*", .decision = .deny },
        .{ .action = "git.push", .decision = .ask },
    };

    const bound = try Table.parseUnder(gpa, project_allows, &org_narrows, null);
    defer Table.destroy(gpa, bound);

    const chain = [_][]const u8{"main"};
    const push = testKey("main", "git.push");
    const model = testKey("main", "provider.public.gpt-5");

    try std.testing.expectEqual(Decision.ask, bound.evaluateChain(&chain, push, null));
    try std.testing.expectEqual(Decision.deny, bound.evaluateChain(&chain, model, null));
    // And for the reading a resource question takes, which is the one
    // `lib/chock-policy/access.zig` uses.
    try std.testing.expectEqual(Decision.deny, bound.ceilingChain(&chain, model, null));

    // The same project with no bundle above it holds what it wrote, so the
    // narrowing above is the bundle and not something the file did to itself.
    const alone = try Table.parse(gpa, project_allows, null);
    defer Table.destroy(gpa, alone);
    try std.testing.expectEqual(Decision.allow, alone.evaluateChain(&chain, push, null));
    try std.testing.expectEqual(Decision.allow, alone.evaluateChain(&chain, model, null));

    // The direction that is free. A project that is narrower than its
    // organisation keeps its own narrower answer, because the minimum does not
    // care which layer holds it.
    const project_narrows: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.push", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const org_permits = [_]Rule{
        .{ .action = "git.push", .decision = .allow },
    };
    const narrower = try Table.parseUnder(gpa, project_narrows, &org_permits, null);
    defer Table.destroy(gpa, narrower);
    try std.testing.expectEqual(Decision.deny, narrower.evaluateChain(&chain, push, null));

    // An org rule that names an act the project never mentioned still binds,
    // which is what makes the bundle the outer layer rather than an override
    // of rules that happen to collide.
    const org_only = [_]Rule{
        .{ .action = "net.fetch", .decision = .deny },
    };
    const unmentioned = try Table.parseUnder(gpa, project_allows, &org_only, null);
    defer Table.destroy(gpa, unmentioned);
    try std.testing.expectEqual(
        Decision.deny,
        unmentioned.evaluateChain(&chain, testKey("main", "net.fetch"), null),
    );

    // Every pair of decisions, so no ordering is right by accident: the answer
    // is the narrower of the two layers, whichever of them is narrower.
    const every = [_]Decision{ .deny, .agent_then_human, .ask, .agent_review, .allow };
    for (every) |from_project| {
        for (every) |from_org| {
            const source = try std.fmt.allocPrintSentinel(
                gpa,
                ".{{ .policy = .{{ .rules = .{{ .{{ .action = \"git.push\", .decision = .{t} }} }} }} }}",
                .{from_project},
                0,
            );
            defer gpa.free(source);
            const ceiling = [_]Rule{.{ .action = "git.push", .decision = from_org }};
            const both = try Table.parseUnder(gpa, source, &ceiling, null);
            defer Table.destroy(gpa, both);
            try std.testing.expectEqual(
                @min(from_project.rank(), from_org.rank()),
                both.evaluateChain(&chain, push, null).rank(),
            );
        }
    }
}

test "a session with no org bundle answers exactly as it did before bundles existed" {
    // The property that decides whether the outer layer may ship. An empty
    // bundle must change no answer anywhere, and `allow` being the identity of
    // `intersect` is why it does not.
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "worker", .parent = "main" },
        \\        },
        \\        .rules = .{
        \\            .{ .action = "git.*", .decision = .ask },
        \\            .{ .action = "git.push", .decision = .deny },
        \\            .{ .agent_kind = "main", .action = "git.commit", .decision = .allow },
        \\            .{ .action = "net.fetch", .decision = .agent_review },
        \\        },
        \\    },
        \\}
    ;

    const plain = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, plain);
    const with_empty = try Table.parseUnder(gpa, source, &.{}, null);
    defer Table.destroy(gpa, with_empty);

    // Every key the rules can tell apart, over every chain a two kind file can
    // make. A sampled comparison would prove nothing about the case that
    // differs.
    const kinds = [_][]const u8{ "main", "worker" };
    const actions = [_][]const u8{
        "git.push",
        "git.commit",
        "git.branch.delete",
        "net.fetch",
        "workspace.apply",
        "git",
    };
    const chains = [_][]const []const u8{
        &.{"main"},
        &.{"worker"},
        &.{ "main", "worker" },
        &.{ "main", "main" },
    };
    for (chains) |chain| {
        const asker = chain[chain.len - 1];
        for (actions) |action| {
            const key = testKey(asker, action);
            try std.testing.expectEqual(
                plain.evaluateChain(chain, key, null),
                with_empty.evaluateChain(chain, key, null),
            );
            try std.testing.expectEqual(
                plain.ceilingChain(chain, key, null),
                with_empty.ceilingChain(chain, key, null),
            );
        }
    }
    for (kinds) |kind| {
        for (actions) |action| {
            const key = testKey(kind, action);
            try std.testing.expectEqual(
                plain.evaluateKindAlone(key),
                with_empty.evaluateKindAlone(key),
            );
        }
    }

    // And the answers themselves are the ones this file has always given, so
    // the comparison above is not two functions agreeing on a wrong number.
    try std.testing.expectEqual(
        Decision.deny,
        with_empty.evaluateChain(&.{"main"}, testKey("main", "git.push"), null),
    );
    try std.testing.expectEqual(
        Decision.allow,
        with_empty.evaluateChain(&.{"main"}, testKey("main", "git.commit"), null),
    );
    try std.testing.expectEqual(
        Decision.ask,
        with_empty.evaluateChain(&.{ "main", "worker" }, testKey("worker", "git.commit"), null),
    );
    try std.testing.expectEqual(
        Decision.ask,
        with_empty.evaluateChain(&.{"main"}, testKey("main", "workspace.apply"), null),
    );
    // The hash of the bytes is the file's own and a bundle does not enter it.
    // Chock compares that hash at the end of a session, and a bundle
    // that changed it would make every such comparison fail.
    try std.testing.expectEqualSlices(u8, &plain.sourceHash(), &with_empty.sourceHash());
}

test "an org bundle is read as a ceiling, so a rule it never wrote narrows nothing" {
    // The one place the two layers are read differently, and the reason an org
    // that writes one rule does not cap every project at ask. A resource
    // nobody named has no ceiling; an act nobody named is still `ask`.
    const gpa = std.testing.allocator;

    const project: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.commit", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const one_rule = [_]Rule{
        .{ .action = "provider.public.*", .decision = .deny },
    };

    const bound = try Table.parseUnder(gpa, project, &one_rule, null);
    defer Table.destroy(gpa, bound);
    const chain = [_][]const u8{"main"};

    // The act the bundle says nothing about keeps the project's own answer.
    // Reading the bundle as a decision would have made this `ask`.
    try std.testing.expectEqual(
        Decision.allow,
        bound.evaluateChain(&chain, testKey("main", "git.commit"), null),
    );
    // And an act neither layer named is `ask`, which is the file's own rule
    // for a case nobody covered and is not something the bundle supplied.
    try std.testing.expectEqual(
        Decision.ask,
        bound.evaluateChain(&chain, testKey("main", "workspace.apply"), null),
    );
    // The one row the bundle did write still binds.
    try std.testing.expectEqual(
        Decision.deny,
        bound.evaluateChain(&chain, testKey("main", "provider.public.gpt-5"), null),
    );
}
