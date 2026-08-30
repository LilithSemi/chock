//! **Whether a project may give up one piece of sandbox hardening**, as a row
//! on the table that already exists.
//!
//! Today there is one row, and it is the write and execute rule:
//! `mmap`, `mprotect` and `pkey_mprotect` asking for a page that is writable
//! and executable at the same time. `lib/chock-sandbox/linux/seccomp.zig`
//! answers `EPERM` for that, and a run time with a just in time compiler
//! cannot work under it. V8 asks for write and execute over a 268 MB code
//! range, measured on Node v24.19.0, so every Node, Deno and Bun program that
//! is not started with `--jitless` needs this row.
//!
//! ## Why this is a row and not a key in `chock.zon`
//!
//! **Every other `chock.zon` knob narrows, and this one widens.** `docs/sandbox.md`
//! states the rule for the sandbox limits: a project can lower any of them and
//! can never raise one. A plain `sandbox = .{ .allow_jit = true }` block would
//! sit beside knobs that all read the other way, and it would have to grow a
//! ratchet of its own to let an organisation forbid it. Three things follow
//! from putting it on the table instead, and none of them is new code:
//!
//! 1. **An organisation forbids it with one rule**, in the bundle
//!    `lib/chock-policy/org.zig` reads:
//!    `.{ .action = "sandbox.jit", .decision = .deny }`. `Table.evaluateChain`
//!    folds the bundle in as one more term of the same minimum, so a project
//!    cannot raise what the organisation lowered. That is a property of a
//!    minimum and not a check somebody has to remember to write.
//! 2. **A subagent holds no more than its parent.** The same fold walks the
//!    spawn chain, so a project that permits this for `main` and says nothing
//!    for a child gives the child nothing.
//! 3. **The rule already answers "who may widen this, and who authorises it".**
//!    That is the whole question the table exists for.
//!
//! ## `allow` and nothing else turns the rule off
//!
//! `Table.evaluateChain` is the verb, not `Table.ceilingChain`. An action
//! nobody named answers `ask`, so **a project that has never heard of this row
//! keeps the hardening**, which is the default this row must have.
//! `writeExecuteFor` reads only `allow` as permission.
//!
//! **`ask` cannot mean "ask" here.** The filter is built before the first turn,
//! before a broker exists and before anybody is watching, and every tool call
//! of the session runs under the one filter. There is nobody to put the
//! question to, and there is no later moment at which the answer could be
//! applied. This is the same reading `lib/chock-policy/access.zig` takes for a
//! provider and a model, and `src/run.zig`'s own `provisionDecision` takes for
//! `nix.build`: a capability of the whole session, answered once, where only
//! `allow` is yes.
//!
//! ## What is given up, stated rather than implied
//!
//! **W^X is documented hardening and it is not a boundary.**
//! `test/redteam/scope.zig` retires it by name: "a page that is both writable
//! and executable **is not an escape**, and it must never be reported as one".
//! `seccomp.zig`'s own comment names three ways an attacker got such a page
//! anyway, each proven by running code: `shmat` with `SHM_EXEC`, an ELF with a
//! read, write and execute `PT_GNU_STACK`, and a `memfd_create` file mapped
//! read and execute and then written through the descriptor. So this row lets a
//! project give up a cost, and it weakens no claim Chock makes.
//!
//! **Nothing else moves.** The two rules that close `personality` with
//! `READ_IMPLIES_EXEC` and `shmat` with `SHM_EXEC` were written to stop the
//! write and execute rule being walked around, so they go with it and nothing
//! else in the filter changes. Every call on `seccomp.zig`'s own
//! `blocked_calls` still kills, io_uring is still refused, Landlock still holds
//! the paths, and the network namespace is still empty.
//!
//! ## The session says which it ran with
//!
//! A session that gave this up is distinguishable afterwards from one that did
//! not. `chock_proto.event.SandboxOpen` is written once per attempt and carries
//! the answer, and `chock doctor` reports the same fact before a session
//! starts. This project has no silent degradation, so a row that turned a layer
//! off quietly would be the wrong shape whatever it was written in.

const std = @import("std");
const table = @import("table.zig");

/// The row name. Dotted, like every other action, so `sandbox.*` covers this
/// and whatever hardening row comes after it.
///
/// **It is named for what the project needs and not for what is given up.** An
/// author writes this rule because a run time compiles code at run time, and
/// `sandbox.wx_off` would make them work out that a just in time compiler is
/// the thing that wants it.
pub const jit_action = "sandbox.jit";

/// The first segment of every hardening row. A rule that names this class
/// alone, `sandbox.*`, covers `jit_action` and every row added below it.
pub const namespace = "sandbox";

/// Whether the write and execute rule is on for a session.
///
/// **An enum and not a boolean.** A caller acts on the member, and the two
/// members are read out loud in a log line and in a `chock doctor` row, which
/// is what a boolean named `strict` cannot do.
pub const WriteExecute = enum {
    /// A page may not be writable and executable at the same time. The default,
    /// and what a project that wrote no rule gets.
    strict,
    /// The rule is off, because this project's policy answered `allow` for
    /// `jit_action`.
    relaxed,

    /// The word a log line and a `chock doctor` row carry.
    pub fn wireName(self: WriteExecute) []const u8 {
        return switch (self) {
            .strict => "strict",
            .relaxed => "relaxed",
        };
    }
};

/// What `decision` means for the write and execute rule.
///
/// **Only `allow` relaxes it.** See this file's own top comment: there is
/// nobody to ask at the moment this is decided, so `ask` holds the hardening
/// exactly as `deny` does.
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
    // **The default this row must have, read through the real reader.** An
    // empty file answers `ask` for an action nobody named, and `ask` is
    // strict, so a project that has never heard of this row is unchanged.
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
    // **This is the whole justification for the row living on the table.** The
    // organisation writes one rule, in the same language, and the project
    // cannot raise it. Nothing here is a check: the fold is a minimum, so the
    // second half falls out of the first.
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
    // A rule for `main` alone gives a child nothing, because the fold walks
    // every link of the chain and takes the minimum.
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
    // `sandbox.*` must reach `sandbox.jit`, so an organisation that wants to
    // forbid every hardening row at once writes one rule and not one per row.
    try std.testing.expect(table.patternCovers(namespace ++ ".*", jit_action));
    try std.testing.expect(std.mem.startsWith(u8, jit_action, namespace ++ "."));
}
