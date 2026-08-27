//! **Which providers and which models a session may use**, as rows on the
//! table that already exists.
//!
//! An organisation that gives a team a credential has decided which models
//! that credential reaches. It has not decided which of them a particular
//! project may send its code to, and those are different questions: the
//! credential is what the hub will honour, and this is what the organisation
//! wants honoured. "This project must not send code to the public API" is a
//! sentence about a project, and the credential cannot say it.
//!
//! ## Two rows, and nothing else
//!
//! ```zon
//! .{ .action = "provider.public", .decision = .deny }
//! .{ .action = "provider.public.gpt-5", .decision = .deny }
//! .{ .action = "provider.public.*", .decision = .deny }
//! .{ .action = "provider.*", .decision = .deny }
//! ```
//!
//! `provider.<instance>` is the instance itself, by the name it has in the
//! user's `config.zon`. `provider.<instance>.<model>` is one model at that
//! instance, by the id that goes on the wire. `rowsFor` builds both, `ceiling`
//! asks the table for both, and the answer is the narrower of the two. So one
//! line does the whole job either way: `provider.public` refuses the instance
//! whatever model is asked for, and `provider.public.*` refuses every model
//! there, which is the same refusal by the other road because a session always
//! names a model.
//!
//! ## Read as a ceiling, so a project that said nothing is unchanged
//!
//! `Table.ceilingChain` is the verb, not `Table.evaluateChain`. A row nobody
//! wrote answers `allow`, which is no ceiling at all. Every project that has
//! never heard of these names therefore behaves exactly as it did, and that is
//! the property to keep: a permission model that breaks every existing
//! configuration the day it ships is a permission model nobody turns on. See
//! `Table.ceilingChain` for why an act and a resource have to answer
//! differently for a name nobody wrote.
//!
//! A session may use a provider and a model when the answer is `allow`.
//! Anything else refuses, and `refusalNeeded` is the one place that says so.
//! **`ask` cannot mean "ask" here**: a model is picked before the first turn,
//! before a broker exists and before anybody is watching, so there is nobody
//! to put the question to. The same reading `src/run.zig`'s `provisionDecision`
//! already takes for `nix.build`.
//!
//! ## It folds through the chain, which is what makes it more than a checkbox
//!
//! `ceiling` folds over the spawn chain, so **a subagent cannot use a model
//! its parent could not.** An expensive model at the root and a cheap one
//! below is one rule per kind, and no child can climb back up, because the
//! answer is a minimum over every link and a minimum only falls.
//!
//! ## What these names cannot say
//!
//! Two limits, stated rather than worked around, because the answer to a thing
//! that does not fit the dotted language is to say so:
//!
//! * **"Any instance, this model" is not expressible.** A pattern is a prefix
//!   and a `.*`, so there is no wildcard in the middle. An organisation that
//!   wants one model refused everywhere writes one row per instance.
//! * **The instance name is the user's own.** It is the key in their
//!   `config.zon`, so a `provider.<instance>` row names something the user
//!   spells. It is not a secret and it is not a barrier against a user who
//!   edits their own configuration; it binds the project, the agent, and every
//!   subagent, which is what it is for. The credential is what the hub checks,
//!   and it is still the thing that decides what the wire will carry.

const std = @import("std");
const table = @import("table.zig");

/// The first segment of every row. A rule that names this class alone,
/// `provider.*`, covers every instance row and every model row below it.
pub const namespace = "provider";

/// The longest instance name a row can be built for.
pub const max_instance_bytes = 128;

/// The longest model id a row can be built for. Longer than a model id is
/// today, and bounded because it arrives from `--model` and from a
/// configuration file.
pub const max_model_bytes = 128;

/// The longest row either name produces.
pub const max_row_bytes = namespace.len + 1 + max_instance_bytes + 1 + max_model_bytes;

/// Why no row could be built. A name that cannot become a row is a name no
/// rule could ever have covered, so this is refused rather than folded into a
/// decision.
pub const Error = error{
    /// The instance name or the model id is empty. Chock builds both out of a
    /// configuration file and a command line, and neither may be nothing.
    NameIsEmpty,
    /// The instance name or the model id is longer than this module accepts.
    NameTooLong,
    /// The instance name or the model id holds a byte that would make the row
    /// read as a pattern rather than as a name: `*`, or a NUL.
    NameMalformed,
};

/// The two rows one provider and one model are measured against.
///
/// **One buffer and two slices of it**, because the instance row is a prefix
/// of the model row. A value type with no allocation, so the caller that picks
/// a model before a session exists needs no allocator to ask about it.
pub const Rows = struct {
    buffer: [max_row_bytes]u8,
    instance_len: usize,
    total_len: usize,

    /// `provider.<instance>`.
    pub fn instance(self: *const Rows) []const u8 {
        return self.buffer[0..self.instance_len];
    }

    /// `provider.<instance>.<model>`.
    pub fn model(self: *const Rows) []const u8 {
        return self.buffer[0..self.total_len];
    }
};

/// The two rows for one instance name and one model id.
///
/// A model id holds a dot often enough that it is the ordinary case, and that
/// is fine: `provider.local.gpt-4.1` is a name, `provider.local.*` covers it,
/// and `provider.local.gpt-4.*` covers it as well. An instance name may hold a
/// dot too, and then one row can be read two ways, as that instance or as a
/// model at a shorter one. **That can only narrow**, never widen, because
/// every row is one more term of a minimum, so it is a quirk of the namespace
/// and not a way through it.
pub fn rowsFor(instance_name: []const u8, model_id: []const u8) Error!Rows {
    try checkName(instance_name);
    try checkName(model_id);
    if (instance_name.len > max_instance_bytes) return error.NameTooLong;
    if (model_id.len > max_model_bytes) return error.NameTooLong;

    var rows: Rows = .{ .buffer = undefined, .instance_len = 0, .total_len = 0 };
    var written: usize = 0;
    written += copyInto(rows.buffer[written..], namespace);
    written += copyInto(rows.buffer[written..], ".");
    written += copyInto(rows.buffer[written..], instance_name);
    rows.instance_len = written;
    written += copyInto(rows.buffer[written..], ".");
    written += copyInto(rows.buffer[written..], model_id);
    rows.total_len = written;
    return rows;
}

fn checkName(name: []const u8) Error!void {
    if (name.len == 0) return error.NameIsEmpty;
    if (std.mem.indexOfScalar(u8, name, '*') != null) return error.NameMalformed;
    if (std.mem.indexOfScalar(u8, name, 0) != null) return error.NameMalformed;
}

fn copyInto(out: []u8, text: []const u8) usize {
    // Every bound was checked above, so a short buffer here is a broken
    // caller and not a name somebody wrote.
    std.debug.assert(out.len >= text.len);
    @memcpy(out[0..text.len], text);
    return text.len;
}

/// Everything the table needs to know about who is asking. The same four parts
/// `table.Key` holds, less the action, which is what `rows` supplies.
pub const Ask = struct {
    /// Every agent kind from the root of the spawn tree down to the agent that
    /// asks, root first. The chain `Table.ceilingChain` wants, which
    /// `src/run.zig`'s `policyChain` builds.
    chain: []const []const u8,
    /// The kind of the agent that asks. It must be the last link of `chain`.
    agent_kind: []const u8,
    /// The alias of the model behind this session, which is what
    /// `table.Key.model` holds everywhere else. **Not the model id in `rows`**:
    /// the alias says who is asking and the id says what is being asked for,
    /// and a rule can name either.
    model_alias: []const u8,
};

/// The name `table.Key.tool` carries for this question.
///
/// **No tool asks it.** A session picks its provider and its model before the
/// first turn, so the thing asking is the session itself. A name rather than
/// an empty string, because `table.Key` allows no empty part, and a project
/// that wants to write `.tool = "session"` on a rule can.
pub const tool_name = "session";

/// The ceiling this policy puts on one provider and one model, folded over the
/// whole spawn chain.
///
/// The narrower of the two rows. See this file's own top comment: one line at
/// either level refuses the whole thing, and a project that wrote neither gets
/// `allow`, which is what it got before these names existed.
///
/// `fault` is filled for a spawn chain this reader cannot fold, exactly as
/// `Table.ceilingChain` fills it, and the answer for one of those is `deny`.
pub fn ceiling(
    policy: *const table.Table,
    ask: Ask,
    rows: *const Rows,
    fault: ?*?table.ChainFault,
) table.Decision {
    const on_instance = policy.ceilingChain(ask.chain, .{
        .agent_kind = ask.agent_kind,
        .model = ask.model_alias,
        .tool = tool_name,
        .action = rows.instance(),
    }, fault);
    const on_model = policy.ceilingChain(ask.chain, .{
        .agent_kind = ask.agent_kind,
        .model = ask.model_alias,
        .tool = tool_name,
        .action = rows.model(),
    }, fault);
    return on_instance.intersect(on_model);
}

/// Whether `decision` refuses the provider and the model.
///
/// **Only `allow` permits.** See this file's own top comment on why `ask`
/// cannot mean "ask" for a question nobody is awake to answer. A verb rather
/// than a comparison each caller writes, so a sixth `Decision` cannot be added
/// without this one place naming it.
pub fn refusalNeeded(decision: table.Decision) bool {
    return switch (decision) {
        .allow => false,
        .deny, .ask, .agent_review, .agent_then_human => true,
    };
}

const testing = std.testing;

test "the two rows are the namespace, the instance, and the model, in that order" {
    // The names are the whole interface between a configuration file and a
    // policy file, so the exact spelling is the thing to pin.
    const rows = try rowsFor("public", "gpt-5");
    try testing.expectEqualStrings("provider.public", rows.instance());
    try testing.expectEqualStrings("provider.public.gpt-5", rows.model());

    const dotted = try rowsFor("local", "gpt-4.1");
    try testing.expectEqualStrings("provider.local", dotted.instance());
    try testing.expectEqualStrings("provider.local.gpt-4.1", dotted.model());
    try testing.expect(table.patternCovers("provider.*", dotted.model()));
    try testing.expect(table.patternCovers("provider.local.*", dotted.model()));
    try testing.expect(table.patternCovers("provider.local.gpt-4.*", dotted.model()));
    try testing.expect(!table.patternCovers("provider.public.*", dotted.model()));

    try testing.expect(table.patternIsWellFormed(rows.instance()));
    try testing.expect(table.patternIsWellFormed(rows.model()));
    try testing.expect(table.patternMatches(rows.instance(), rows.instance()));
    // The instance row is not the model row, which is why both are asked.
    try testing.expect(!table.patternMatches(rows.instance(), rows.model()));
}

test "a name that could not be a row is refused rather than folded into a decision" {
    try testing.expectError(error.NameIsEmpty, rowsFor("", "gpt-5"));
    try testing.expectError(error.NameIsEmpty, rowsFor("public", ""));
    try testing.expectError(error.NameMalformed, rowsFor("pub*", "gpt-5"));
    try testing.expectError(error.NameMalformed, rowsFor("public", "gpt*"));
    try testing.expectError(error.NameMalformed, rowsFor("pub\x00lic", "gpt-5"));

    const long_instance = "i" ** (max_instance_bytes + 1);
    try testing.expectError(error.NameTooLong, rowsFor(long_instance, "gpt-5"));
    const long_model = "m" ** (max_model_bytes + 1);
    try testing.expectError(error.NameTooLong, rowsFor("public", long_model));

    // One byte shorter is a row, so the bound is exact and the buffer holds
    // the longest pair.
    const at_instance = "i" ** max_instance_bytes;
    const at_model = "m" ** max_model_bytes;
    const rows = try rowsFor(at_instance, at_model);
    try testing.expectEqual(@as(usize, max_row_bytes), rows.model().len);
    try testing.expectEqual(namespace.len + 1 + max_instance_bytes, rows.instance().len);
}

test "a project that names no provider row keeps every model it had" {
    // The property that decides whether this ships: a configuration that has
    // never heard of these names must answer exactly as it did. `allow` here
    // is not permission, it is the absence of a ceiling.
    const gpa = testing.allocator;

    const empty = try table.Table.parse(gpa, ".{}", null);
    defer table.Table.destroy(gpa, empty);

    const rows = try rowsFor("public", "gpt-5");
    const ask = Ask{ .chain = &.{"main"}, .agent_kind = "main", .model_alias = "public" };
    try testing.expectEqual(table.Decision.allow, ceiling(empty, ask, &rows, null));
    try testing.expect(!refusalNeeded(ceiling(empty, ask, &rows, null)));

    // A project with rules about other things is still unchanged. The rule
    // below denies an act, and an act is not a provider row.
    const other = try table.Table.parse(gpa,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "git.push", .decision = .deny },
        \\} } }
    , null);
    defer table.Table.destroy(gpa, other);
    try testing.expectEqual(table.Decision.allow, ceiling(other, ask, &rows, null));

    // And the act itself still answers the way it always did, so reading the
    // rules as a ceiling for one question has not changed the other.
    try testing.expectEqual(table.Decision.deny, other.evaluateChain(&.{"main"}, .{
        .agent_kind = "main",
        .model = "public",
        .tool = "request_action",
        .action = "git.push",
    }, null));
}

test "a row at either level refuses the provider, and only allow permits" {
    const gpa = testing.allocator;

    const rows = try rowsFor("public", "gpt-5");
    const ask = Ask{ .chain = &.{"main"}, .agent_kind = "main", .model_alias = "public" };

    const by_instance = try table.Table.parse(gpa,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "provider.public", .decision = .deny },
        \\} } }
    , null);
    defer table.Table.destroy(gpa, by_instance);
    try testing.expectEqual(table.Decision.deny, ceiling(by_instance, ask, &rows, null));

    const by_model_class = try table.Table.parse(gpa,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "provider.public.*", .decision = .deny },
        \\} } }
    , null);
    defer table.Table.destroy(gpa, by_model_class);
    try testing.expectEqual(table.Decision.deny, ceiling(by_model_class, ask, &rows, null));

    const by_one_model = try table.Table.parse(gpa,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "provider.public.gpt-5", .decision = .deny },
        \\    .{ .action = "provider.public.gpt-5-mini", .decision = .allow },
        \\} } }
    , null);
    defer table.Table.destroy(gpa, by_one_model);
    try testing.expectEqual(table.Decision.deny, ceiling(by_one_model, ask, &rows, null));
    const cheap = try rowsFor("public", "gpt-5-mini");
    try testing.expectEqual(table.Decision.allow, ceiling(by_one_model, ask, &cheap, null));

    try testing.expect(!refusalNeeded(.allow));
    try testing.expect(refusalNeeded(.agent_review));
    try testing.expect(refusalNeeded(.ask));
    try testing.expect(refusalNeeded(.agent_then_human));
    try testing.expect(refusalNeeded(.deny));
}

test "a subagent cannot use a model its parent could not" {
    const gpa = testing.allocator;

    const expensive_at_the_root = try table.Table.parse(gpa,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .agent_kind = "main", .action = "provider.hub.big", .decision = .allow },
        \\    .{ .agent_kind = "worker", .action = "provider.hub.big", .decision = .deny },
        \\    .{ .action = "provider.hub.small", .decision = .allow },
        \\} } }
    , null);
    defer table.Table.destroy(gpa, expensive_at_the_root);

    const big = try rowsFor("hub", "big");
    const small = try rowsFor("hub", "small");

    const root = Ask{ .chain = &.{"main"}, .agent_kind = "main", .model_alias = "hub" };
    const child = Ask{
        .chain = &.{ "main", "worker" },
        .agent_kind = "worker",
        .model_alias = "hub",
    };

    try testing.expectEqual(table.Decision.allow, ceiling(expensive_at_the_root, root, &big, null));
    try testing.expectEqual(table.Decision.deny, ceiling(expensive_at_the_root, child, &big, null));
    // And the cheap one is there for both, so the child was narrowed and not
    // switched off.
    try testing.expectEqual(table.Decision.allow, ceiling(expensive_at_the_root, root, &small, null));
    try testing.expectEqual(table.Decision.allow, ceiling(expensive_at_the_root, child, &small, null));

    // The direction that would be the escalation. A file that gives the child
    // more than the parent gives the child nothing more, whatever it says
    // about that child alone.
    const child_asks_for_more = try table.Table.parse(gpa,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .agent_kind = "main", .action = "provider.hub.big", .decision = .deny },
        \\    .{ .agent_kind = "worker", .action = "provider.hub.big", .decision = .allow },
        \\} } }
    , null);
    defer table.Table.destroy(gpa, child_asks_for_more);
    try testing.expectEqual(table.Decision.deny, ceiling(child_asks_for_more, child, &big, null));
    // The same rules read for one kind alone would have said `allow`, which is
    // the answer the chain fold is there to refuse.
    try testing.expectEqual(table.Decision.allow, child_asks_for_more.evaluateKindAlone(.{
        .agent_kind = "worker",
        .model = "hub",
        .tool = tool_name,
        .action = big.model(),
    }));

    // A grandchild holds no more than the link above it either, which is what
    // makes this a fold rather than a comparison of two.
    const grandchild = Ask{
        .chain = &.{ "main", "worker", "helper" },
        .agent_kind = "helper",
        .model_alias = "hub",
    };
    try testing.expectEqual(table.Decision.deny, ceiling(expensive_at_the_root, grandchild, &big, null));
}

test "a spawn chain this reader cannot fold refuses the model and says why" {
    // A chain arrives from a session log, so a chain Chock did not write is a
    // runtime fault and gets an answer. That answer is `deny` and not `ask`,
    // because nobody is awake at the moment a session picks a model.
    const gpa = testing.allocator;

    const anything = try table.Table.parse(gpa, ".{}", null);
    defer table.Table.destroy(gpa, anything);
    const rows = try rowsFor("hub", "big");

    var empty_chain: ?table.ChainFault = null;
    try testing.expectEqual(table.Decision.deny, ceiling(anything, .{
        .chain = &.{},
        .agent_kind = "main",
        .model_alias = "hub",
    }, &rows, &empty_chain));
    try testing.expect(empty_chain.? == .empty);

    var nameless: ?table.ChainFault = null;
    try testing.expectEqual(table.Decision.deny, ceiling(anything, .{
        .chain = &.{ "main", "" },
        .agent_kind = "main",
        .model_alias = "hub",
    }, &rows, &nameless));
    try testing.expect(nameless.? == .link_with_no_name);

    var mismatch: ?table.ChainFault = null;
    try testing.expectEqual(table.Decision.deny, ceiling(anything, .{
        .chain = &.{ "main", "worker" },
        .agent_kind = "main",
        .model_alias = "hub",
    }, &rows, &mismatch));
    try testing.expect(mismatch.? == .last_link_is_not_the_asker);
}
