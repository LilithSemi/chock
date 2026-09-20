//! Which providers and which models a session may use, as rows on the table
//! that already exists. Read as a ceiling, so a row nobody wrote answers
//! `allow` and a project that never heard of these names is unchanged.

const std = @import("std");
const table = @import("table.zig");

pub const namespace = "provider";

pub const max_instance_bytes = 128;

/// Longer than a model id is today, and bounded because it arrives from
/// `--model` and from a configuration file.
pub const max_model_bytes = 128;

pub const max_row_bytes = namespace.len + 1 + max_instance_bytes + 1 + max_model_bytes;

pub const Error = error{
    NameIsEmpty,
    NameTooLong,
    /// A byte that would make the row read as a pattern rather than as a name:
    /// `*`, or a NUL.
    NameMalformed,
};

/// One buffer and two slices of it, because the instance row is a prefix of the
/// model row. No allocation, so a caller that picks a model before a session
/// exists needs no allocator.
pub const Rows = struct {
    buffer: [max_row_bytes]u8,
    instance_len: usize,
    total_len: usize,

    pub fn instance(self: *const Rows) []const u8 {
        return self.buffer[0..self.instance_len];
    }

    pub fn model(self: *const Rows) []const u8 {
        return self.buffer[0..self.total_len];
    }
};

/// A model id holds a dot often enough that it is the ordinary case. An
/// instance name may hold one too, and then a row can be read two ways, as that
/// instance or as a model at a shorter one. That can only narrow, because every
/// row is one more term of a minimum.
/// Two things these names cannot say. "Any instance, this model" is not
/// expressible, because a pattern is a prefix and a `.*` with no wildcard in
/// the middle. And the instance name is the user's own, so it is no barrier
/// against a user who edits their own configuration: it binds the project, the
/// agent and every subagent, and the credential is still what the hub checks.
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
    std.debug.assert(out.len >= text.len);
    @memcpy(out[0..text.len], text);
    return text.len;
}

pub const Ask = struct {
    chain: []const []const u8,
    agent_kind: []const u8,
    /// The alias, and not the model id in `rows`: the alias says who is asking
    /// and the id says what is being asked for, and a rule can name either.
    model_alias: []const u8,
};

/// No tool asks this question, because a session picks its provider before the
/// first turn. A name rather than an empty string, because `table.Key` allows
/// no empty part.
pub const tool_name = "session";

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

/// Only `allow` permits. A verb rather than a comparison each caller writes, so
/// a sixth `Decision` cannot be added without this one place naming it.
pub fn refusalNeeded(decision: table.Decision) bool {
    return switch (decision) {
        .allow => false,
        .deny, .ask, .agent_review, .agent_then_human => true,
    };
}

const testing = std.testing;

test "the two rows are the namespace, the instance, and the model, in that order" {
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

    const at_instance = "i" ** max_instance_bytes;
    const at_model = "m" ** max_model_bytes;
    const rows = try rowsFor(at_instance, at_model);
    try testing.expectEqual(@as(usize, max_row_bytes), rows.model().len);
    try testing.expectEqual(namespace.len + 1 + max_instance_bytes, rows.instance().len);
}

test "a project that names no provider row keeps every model it had" {
    const gpa = testing.allocator;

    const empty = try table.Table.parse(gpa, ".{}", null);
    defer table.Table.destroy(gpa, empty);

    const rows = try rowsFor("public", "gpt-5");
    const ask = Ask{ .chain = &.{"main"}, .agent_kind = "main", .model_alias = "public" };
    try testing.expectEqual(table.Decision.allow, ceiling(empty, ask, &rows, null));
    try testing.expect(!refusalNeeded(ceiling(empty, ask, &rows, null)));

    const other = try table.Table.parse(gpa,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "git.push", .decision = .deny },
        \\} } }
    , null);
    defer table.Table.destroy(gpa, other);
    try testing.expectEqual(table.Decision.allow, ceiling(other, ask, &rows, null));

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
    try testing.expectEqual(table.Decision.allow, ceiling(expensive_at_the_root, root, &small, null));
    try testing.expectEqual(table.Decision.allow, ceiling(expensive_at_the_root, child, &small, null));

    const child_asks_for_more = try table.Table.parse(gpa,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .agent_kind = "main", .action = "provider.hub.big", .decision = .deny },
        \\    .{ .agent_kind = "worker", .action = "provider.hub.big", .decision = .allow },
        \\} } }
    , null);
    defer table.Table.destroy(gpa, child_asks_for_more);
    try testing.expectEqual(table.Decision.deny, ceiling(child_asks_for_more, child, &big, null));
    try testing.expectEqual(table.Decision.allow, child_asks_for_more.evaluateKindAlone(.{
        .agent_kind = "worker",
        .model = "hub",
        .tool = tool_name,
        .action = big.model(),
    }));

    const grandchild = Ask{
        .chain = &.{ "main", "worker", "helper" },
        .agent_kind = "helper",
        .model_alias = "hub",
    };
    try testing.expectEqual(table.Decision.deny, ceiling(expensive_at_the_root, grandchild, &big, null));
}

test "a spawn chain this reader cannot fold refuses the model and says why" {
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
