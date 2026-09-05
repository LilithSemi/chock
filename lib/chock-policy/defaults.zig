//! The rules Chock ships, so a project with no `chock.zon` at all keeps
//! today's behaviour once the loop starts asking `table.Table` about every
//! tool call: an ordinary call runs, and nothing that needed a human before
//! this file existed needs one less now.
//!
//! `lib/chock-core/tools.zig`'s `Tool.actionInto` is what a tool call turns
//! into before it reaches the table. This file's own top comment there says
//! why: `.{ .action = "call.write_file", .decision = .ask }` is a name a
//! `chock.zon` author writes, and `rules` below is the same language, read by
//! the same table, so a rule here and a rule a project writes settle their
//! disagreement the one way `table.zig` already knows: the more specific
//! pattern wins, and a tie goes to whichever decision permits less. See
//! `table.zig`'s own top comment, "Which rule wins".
//!
//! ## Every rule here names an action, and never a tool alone
//!
//! **Measured, not assumed, and the opposite of the first guess.** A rule
//! that names an `.action` always beats a rule that names only a `.tool`,
//! whichever order the two are written in and whichever decision each one
//! carries. `table.zig`'s `ruleBeats` compares the four fields in the order
//! action, tool, model, agent kind, and scores an absent field as `0`. A
//! rule that leaves `.action` out scores `0` on the very first comparison, so
//! a rule that names any `.action` at all wins there before `.tool` is ever
//! read. **A tool wide `allow` therefore does not swallow a narrower
//! `exec.*` rule underneath it.** Pinned by the test
//! `"a rule that names an action beats a rule that names only a tool"`
//! below, which this file's rules still depend on for a different reason:
//! see the next paragraph.
//!
//! That specificity result only helps a project that wrote a narrower rule
//! of its own to win with. It does nothing for a key that no rule at all
//! contests, which is the case a shipped default exists for in the first
//! place. It is safe for `run_command` to line up four rules of its own, one
//! for each class `actionInto` can build, because `exec.*` is `run_command`'s
//! alone: nothing else in Chock ever asks the table about an `exec.*` key,
//! so a `.tool = "run_command"` default would have cost nothing there.
//!
//! It is **not** safe for a tool whose own name is also read for a second,
//! narrower question, and this is the reason every rule below names an
//! `.action`. `fetch_url` is the clear case: `lib/chock-broker/fetch.zig`
//! asks the table again for `net.fetch.*`, and `lib/chock-broker/network.zig`
//! asks it again for `net.connect.*`, both with `.tool = "fetch_url"`, once
//! the handler is already inside the call. `request_action` is the same
//! shape: the action it names is a request to run a distinct act such as
//! `git.push`, evaluated with `.tool = "request_action"` and the act's own
//! name, not with `call.request_action`. A rule of `.{ .tool = "fetch_url",
//! .decision = .allow }` would answer `allow` for `net.connect.evil.443` as
//! readily as for `call.fetch_url`, because nothing else would name that key.
//! A project that wrote no `chock.zon` at all has no narrower rule to
//! contest it with, so the broad one would be the only rule that matches,
//! and it would answer for a key it was never meant to. Naming the
//! exact action `actionInto` builds, and nothing wider, is what keeps a
//! shipped default from ever answering a question it was not written for.
//!
//! ## Seven names with no `call.*` rule at all
//!
//! `lib/chock-core/Loop.zig`'s `gateToolCall` answers seven tool names itself,
//! before it ever calls `Tool.actionInto` for them, so no `call.spawn_agent`,
//! `call.update_plan`, `call.restrict_self`, `call.fetch_url`, `call.ask_user`,
//! `call.set_title` or `call.request_action` key is ever built or evaluated by
//! anything in Chock. A rule here under one of those names would read as a
//! control and do nothing: this file ships none of them, on purpose, and an
//! author who wants to bound one of these seven writes the key that is
//! actually read instead.
//!
//! * `spawn_agent` is bounded by `chock.zon`'s own `subagents` block,
//!   `max_width` and `max_depth`. There is no table key.
//! * `restrict_self` narrowing needs nobody's permission, by design. Widening
//!   asks about `ratchet.widen_action`.
//! * `fetch_url` is decided per host, once the URL is known, at
//!   `net.fetch.*` and `net.connect.*`.
//! * `request_action` is decided at the requested act's own name, such as
//!   `git.push`, with `.tool = "request_action"`.
//! * `update_plan`, `ask_user` and `set_title` grant no capability and need no
//!   key at all.
//!
//! ## What is deliberately absent
//!
//! `net.connect.*` and `net.fetch.*` hold no rule here, on purpose. Chock
//! answers `ask` for a key nobody named, and a network reach is exactly the
//! kind of act that must keep asking until a project's own `chock.zon` says
//! otherwise. Adding a rule that spells `.decision = .ask` here would read
//! the same at first glance and mean something worse: it would be one more
//! line for the next author to wonder whether narrowing it is enough, when
//! today the true answer is that no rule exists at all.
//!
//! ## Where this folds in
//!
//! `table.zig`'s own `evaluateRules` reads `rules` beside a project's own,
//! in the same search for a winner. It does not read `rules` as a ceiling
//! the way `Table.org` is read: a ceiling can only ever narrow an existing
//! answer, and it can never turn an unnamed key's `ask` into this file's
//! `allow`, which is the one thing a shipped default has to do for a project
//! that wrote no `chock.zon` at all. See `evaluateRules`'s own comment.

const table = @import("table.zig");

/// One rule for every action `gateToolCall` actually asks the table about
/// for an ordinary tool call, so an empty or absent `chock.zon` still runs
/// them without a prompt.
///
/// `run_command` needs four rules, one for each class `actionInto` can
/// build, because `.tool = "run_command"` alone would be exactly the unsafe
/// shape this file's own top comment measures against. Every other tool
/// needs exactly one, because `actionInto` builds it exactly one name,
/// `"call." ++ @tagName(tool)`, and nothing else in Chock ever asks the
/// table about that name.
///
/// **The seven names `gateToolCall` answers itself hold no rule here.**
/// `spawn_agent`, `update_plan`, `restrict_self`, `fetch_url`, `ask_user`,
/// `set_title` and `request_action` never reach `Tool.actionInto` from
/// `gateToolCall`, so a `call.*` rule for any of them would never be built
/// or evaluated by anything. See this file's own top comment, "Seven names
/// with no `call.*` rule at all".
///
/// **A tool added to `lib/chock-core/tools.zig` and forgotten here does not
/// fail a build.** `chock-policy` imports no other chock library, so this
/// file cannot read the `Tool` enum to check itself against it. A forgotten
/// tool answers `ask`, the same as any other key nobody named: see
/// `"a tool this file forgot still answers ask"` below for why that is the
/// safe direction to fail in, and not a silent `allow`.
pub const rules: []const table.Rule = &.{
    .{ .action = "call.read_file", .decision = .allow },
    .{ .action = "call.list_directory", .decision = .allow },
    .{ .action = "call.glob", .decision = .allow },
    .{ .action = "call.grep", .decision = .allow },
    .{ .action = "call.write_file", .decision = .allow },
    .{ .action = "call.edit_file", .decision = .allow },
    .{ .action = "exec.nix.store.*", .decision = .allow },
    .{ .action = "exec.workspace.*", .decision = .allow },
    .{ .action = "exec.path.*", .decision = .allow },
    .{ .action = "exec.unparsed", .decision = .allow },
    .{ .action = "call.read_guidance", .decision = .allow },
    .{ .action = "call.read_memory", .decision = .allow },
    .{ .action = "call.write_memory", .decision = .allow },
    .{ .action = "call.provide_tool", .decision = .allow },
};

const std = @import("std");

/// A key for one action, with the parts these tests do not vary held still.
/// Mirrors `table.zig`'s own `testKey`, but the tool named here is never read
/// by any rule in `rules`: every rule above matches on `.action` alone, so
/// changing this constant must never change what a test below measures.
fn key(action: []const u8) table.Key {
    return .{
        .agent_kind = "main",
        .model = "test-model",
        .tool = "irrelevant-to-every-rule-here",
        .action = action,
    };
}

/// An empty policy, the same as a project with no `chock.zon` at all. See
/// `table.zig`'s own `LoadError.NoPolicyFile`: its own doc says `parse` with
/// the source `.{}` builds the table that answers this file is measuring
/// against.
fn emptyTable(gpa: std.mem.Allocator) !*const table.Table {
    return table.Table.parse(gpa, ".{}", null);
}

test "every action an ordinary tool call builds answers allow with no chock.zon at all" {
    const gpa = std.testing.allocator;
    const t = try emptyTable(gpa);
    defer table.Table.destroy(gpa, t);

    const call_actions = [_][]const u8{
        "call.read_file",
        "call.list_directory",
        "call.glob",
        "call.grep",
        "call.write_file",
        "call.edit_file",
        "call.read_guidance",
        "call.read_memory",
        "call.write_memory",
        "call.provide_tool",
    };
    for (call_actions) |action| {
        try std.testing.expectEqual(table.Decision.allow, t.evaluateKindAlone(key(action)));
    }

    const run_command_actions = [_][]const u8{
        "exec.nix.store.abc-jq.bin.jq",
        "exec.workspace.build%2Esh",
        "exec.path.jq",
        "exec.unparsed",
    };
    for (run_command_actions) |action| {
        try std.testing.expectEqual(table.Decision.allow, t.evaluateKindAlone(key(action)));
    }
}

test "net.connect and net.fetch hold no default rule and still answer ask" {
    const gpa = std.testing.allocator;
    const t = try emptyTable(gpa);
    defer table.Table.destroy(gpa, t);

    // `.tool` is set to "fetch_url" here, on purpose: this is the same key
    // `lib/chock-broker/fetch.zig` and `lib/chock-broker/network.zig` build
    // once a `fetch_url` call is already running. If a default rule ever
    // named `.tool = "fetch_url"` alone, this test would start answering
    // `allow` and would catch the regression this file's top comment warns
    // against.
    const fetch_key = table.Key{
        .agent_kind = "main",
        .model = "test-model",
        .tool = "fetch_url",
        .action = "net.fetch.com.example",
    };
    try std.testing.expectEqual(table.Decision.ask, t.evaluateKindAlone(fetch_key));

    const connect_key = table.Key{
        .agent_kind = "main",
        .model = "test-model",
        .tool = "fetch_url",
        .action = "net.connect.com.example.443",
    };
    try std.testing.expectEqual(table.Decision.ask, t.evaluateKindAlone(connect_key));
}

test "a tool this file forgot still answers ask" {
    const gpa = std.testing.allocator;
    const t = try emptyTable(gpa);
    defer table.Table.destroy(gpa, t);

    // No rule in `rules` names this action, and none ever will: it stands in
    // for whatever a future tool builds before this file is updated for it.
    try std.testing.expectEqual(
        table.Decision.ask,
        t.evaluateKindAlone(key("call.a_tool_this_file_has_never_heard_of")),
    );
}

test "a project rule narrows a shipped default, and never raises one" {
    const gpa = std.testing.allocator;

    const narrowed: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "call.write_file", .decision = .ask },
        \\        },
        \\    },
        \\}
    ;
    const t = try table.Table.parse(gpa, narrowed, null);
    defer table.Table.destroy(gpa, t);

    // Narrowed: the shipped default is `allow`, and the project's own rule
    // for the very same action wins because it is a tie in specificity and
    // `ask` is the more restrictive of the two decisions.
    try std.testing.expectEqual(table.Decision.ask, t.evaluateKindAlone(key("call.write_file")));
    // Every other shipped default is untouched.
    try std.testing.expectEqual(table.Decision.allow, t.evaluateKindAlone(key("call.read_file")));

    // Nothing in the Decision enum ranks above `allow`, so a project cannot
    // write a rule that raises a shipped default even if it tries: an
    // `.allow` rule for the same action changes nothing.
    const same_source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "call.read_file", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const same = try table.Table.parse(gpa, same_source, null);
    defer table.Table.destroy(gpa, same);
    try std.testing.expectEqual(table.Decision.allow, same.evaluateKindAlone(key("call.read_file")));
}

test "a rule that names an action beats a rule that names only a tool" {
    // The question this file's own top comment measures before it decides
    // anything: with a shipped default of the shape
    // `.{ .tool = "run_command", .decision = .allow }`, does a project's own
    // `.{ .action = "exec.workspace.*", .decision = .deny }` win, or does the
    // tool wide `allow`?
    //
    // Built from raw `table.Rule` values and not from `rules` above, because
    // the question is about `table.zig`'s own specificity rule, not about
    // what this file ships. The answer holds regardless of which rules a
    // policy actually names.
    const gpa = std.testing.allocator;

    const tool_wide_first: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .tool = "run_command", .decision = .allow },
        \\            .{ .action = "exec.workspace.*", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const action_first: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "exec.workspace.*", .decision = .deny },
        \\            .{ .tool = "run_command", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;

    for ([_][:0]const u8{ tool_wide_first, action_first }) |source| {
        const t = try table.Table.parse(gpa, source, null);
        defer table.Table.destroy(gpa, t);

        const workspace_key = table.Key{
            .agent_kind = "main",
            .model = "test-model",
            .tool = "run_command",
            .action = "exec.workspace.build%2Esh",
        };
        // The rule that names the action wins. A shipped default that named
        // only a tool would therefore be overridden by a project rule this
        // specific, whichever order the two rules are written in.
        try std.testing.expectEqual(table.Decision.deny, t.evaluateKindAlone(workspace_key));

        // The tool wide rule still answers for every action the narrower
        // rule does not cover, which is the entire hazard this file's top
        // comment describes: nothing stops it from answering for
        // `net.connect.*` or `net.fetch.*` as well, if it were ever given a
        // tool whose name is read for those too.
        const other_key = table.Key{
            .agent_kind = "main",
            .model = "test-model",
            .tool = "run_command",
            .action = "exec.path.jq",
        };
        try std.testing.expectEqual(table.Decision.allow, t.evaluateKindAlone(other_key));
    }
}
