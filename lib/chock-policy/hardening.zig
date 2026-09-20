//! Whether a project may give up one piece of sandbox hardening, as a row on
//! the table that already exists. It is a row and not a `chock.zon` knob
//! because every other knob narrows and this one widens.

const std = @import("std");
const table = @import("table.zig");

/// Named for what the project needs and not for what is given up.
/// `sandbox.wx_off` would make an author work out that a just in time compiler
/// is the thing that wants it.
/// V8 asks for write and execute over a 268 MB code range on Node v24.19.0, so
/// every Node, Deno and Bun program not started with `--jitless` needs this.
pub const jit_action = "sandbox.jit";

pub const namespace = "sandbox";

/// An enum and not a boolean, because the two members are read out loud in a
/// log line and in a `chock doctor` row.
/// W^X is hardening and not a boundary. `seccomp.zig` names three ways an
/// attacker reached such a page anyway, so this row gives up a cost and weakens
/// no claim. The two rules closing `personality` with `READ_IMPLIES_EXEC` and
/// `shmat` with `SHM_EXEC` go with it, and nothing else in the filter moves.
///
/// `ask` cannot mean "ask" here. The filter is built before the first turn,
/// before a broker exists, so there is nobody to put the question to.
pub const WriteExecute = enum {
    strict,
    relaxed,

    pub fn wireName(self: WriteExecute) []const u8 {
        return switch (self) {
            .strict => "strict",
            .relaxed => "relaxed",
        };
    }
};

pub fn writeExecuteFor(decision: table.Decision) WriteExecute {
    return switch (decision) {
        .allow => .relaxed,
        .ask, .deny, .agent_review, .agent_then_human => .strict,
    };
}

test "only allow relaxes the rule, and every other decision holds it" {
    // The whole product, so a member added to `Decision` cannot quietly join
    // the permitting side: this walks the enum itself rather than a list.
    for (std.enums.values(table.Decision)) |decision| {
        const expected: WriteExecute = if (decision == .allow) .relaxed else .strict;
        try std.testing.expectEqual(expected, writeExecuteFor(decision));
    }
}

test "a project that names no rule keeps the hardening" {
    const allocator = std.testing.allocator;
    const parsed = try table.Table.parse(allocator, ".{}", null);
    defer table.Table.destroy(allocator, parsed);

    const decision = parsed.evaluateChain(&.{"main"}, .{
        .agent_kind = "main",
        .model = "a-model",
        .tool = "sandbox",
        .action = jit_action,
    }, null);
    try std.testing.expectEqual(table.Decision.ask, decision);
    try std.testing.expectEqual(WriteExecute.strict, writeExecuteFor(decision));
}

test "a project rule turns it off, and an org bundle rule takes it back" {
    const allocator = std.testing.allocator;
    const source =
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "sandbox.jit", .decision = .allow },
        \\} } }
    ;
    const key: table.Key = .{
        .agent_kind = "main",
        .model = "a-model",
        .tool = "sandbox",
        .action = jit_action,
    };

    const project = try table.Table.parse(allocator, source, null);
    defer table.Table.destroy(allocator, project);
    try std.testing.expectEqual(
        WriteExecute.relaxed,
        writeExecuteFor(project.evaluateChain(&.{"main"}, key, null)),
    );

    const org_rules = [_]table.Rule{.{ .action = jit_action, .decision = .deny }};
    const under_org = try table.Table.parseUnder(allocator, source, &org_rules, null);
    defer table.Table.destroy(allocator, under_org);
    try std.testing.expectEqual(
        WriteExecute.strict,
        writeExecuteFor(under_org.evaluateChain(&.{"main"}, key, null)),
    );
}

test "a subagent holds no more than its parent" {
    const allocator = std.testing.allocator;
    const source =
        \\.{ .policy = .{ .rules = .{
        \\    .{ .agent_kind = "main", .action = "sandbox.jit", .decision = .allow },
        \\} } }
    ;
    const parsed = try table.Table.parse(allocator, source, null);
    defer table.Table.destroy(allocator, parsed);

    const child = parsed.evaluateChain(&.{ "main", "worker" }, .{
        .agent_kind = "worker",
        .model = "a-model",
        .tool = "sandbox",
        .action = jit_action,
    }, null);
    try std.testing.expectEqual(WriteExecute.strict, writeExecuteFor(child));
}

test "the class name covers the row" {
    try std.testing.expect(table.patternCovers(namespace ++ ".*", jit_action));
    try std.testing.expect(std.mem.startsWith(u8, jit_action, namespace ++ "."));
}
