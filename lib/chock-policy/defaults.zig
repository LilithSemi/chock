//! The rules Chock ships, so a project with no `chock.zon` at all keeps
//! today's behaviour once the loop starts asking `table.Table` about every
//! tool call: an ordinary call runs, and nothing that needed a human before
//! this file existed needs one less now.
//!
//! `lib/chock-core/tools.zig`'s `Tool.actionInto` is what a tool call turns
//! into before it reaches the table. `.{ .action = "call.write_file",
//! .decision = .ask }` is a name a `chock.zon` author writes, and `rules`
//! below is the same language, read by the same table, so it is tempting to
//! think a rule here and a rule a project writes settle a disagreement the
//! way two rules of one `chock.zon` would: the more specific pattern wins.
//! **They do not.** A shipped default is a lower class of rule, read only
//! when a project's own rules name nothing that matches the key at all. A
//! project rule that matches wins outright, whatever it names and however
//! wide it is next to a default, because the entire reason a default exists
//! is to answer for a key the project did not. See `table.zig`'s own top
//! comment, "An action nobody named, and the rules Chock ships for it", and
//! `evaluateRules` there for how the two lists are actually read.
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
//! place. It is safe for `run_command` to line up rules of its own for the
//! three classes `actionInto` can name a path into, because `exec.*` is
//! `run_command`'s alone: nothing else in Chock ever asks the table about an
//! `exec.*` key, so a `.tool = "run_command"` default would have cost
//! nothing there. `exec.unparsed`, the fourth name `actionInto` can build,
//! holds no rule at all: see "What is deliberately absent" below.
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
//! `exec.unparsed` joins them, and it did not always. `lib/chock-core/tools.zig`
//! answers `exec.unparsed` for a path it refuses to resolve, most often a `..`
//! component: resolving one correctly needs the filesystem, to follow any
//! symlink the segment before it might be, and reading only the string the
//! call gave is the right call there. **The fault this file shipped was
//! answering `allow` for the name that refusal produces, not the refusal
//! itself.** `./.git/../build.sh` and `./.git/../x/bin/bash` both name
//! `exec.unparsed`, because a `..` at a depth greater than zero does not
//! leave the project and `.git` always exists, and a project that denied
//! `exec.workspace.*`, `exec.path.*` and `exec.nix.store.*` by name still
//! answered `allow` for either, because none of the three named
//! `exec.unparsed` and the shipped default did. An unnameable program is not
//! a safe one merely for being unnameable: it is a program Chock could not
//! tell apart from any other, and that is exactly the case `ask` exists for.
//! Removing the rule, rather than spelling `.decision = .ask` here, keeps to
//! the same reasoning `net.connect.*` and `net.fetch.*` already gave: one
//! fewer line for a later author to wonder whether narrowing it is enough.
//!
//! ## Where this folds in
//!
//! `table.zig`'s own `evaluateRules` reads a project's own rules first, and
//! reads `rules` here only when the project named nothing that matches the
//! key. It does not read `rules` as a ceiling the way `Table.org` is read
//! either: a ceiling can only ever narrow an existing answer, and it can
//! never turn an unnamed key's `ask` into this file's `allow`, which is the
//! one thing a shipped default has to do for a project that wrote no
//! `chock.zon` at all. See `evaluateRules`'s own comment.

const table = @import("table.zig");

/// One rule for every action `gateToolCall` actually asks the table about
/// for an ordinary tool call, so an empty or absent `chock.zon` still runs
/// them without a prompt.
///
/// `run_command` needs three rules, one for each class `actionInto` can
/// build a path into, because `.tool = "run_command"` alone would be exactly
/// the unsafe shape this file's own top comment measures against. It builds
/// a fourth name, `exec.unparsed`, for a path it refuses to resolve, and that
/// one holds no rule here at all: see this file's own top comment, "What is
/// deliberately absent". Every other tool needs exactly one rule, because
/// `actionInto` builds it exactly one name, `"call." ++ @tagName(tool)`, and
/// nothing else in Chock ever asks the table about that name.
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

test "a project rule that never names an action still beats a shipped default" {
    // Measured against a real table. A shipped default always names an
    // `.action`, and `ruleBeats` scored an absent field as `0`, so a project
    // rule that named no `.action` at all lost to a shipped default on the
    // very first comparison, whatever the project rule said. A project must
    // be able to narrow, so a project's own rule has to win here regardless
    // of how specific it is next to a default: see this file's own top
    // comment, "A project rule wins over a shipped default outright".
    //
    // Each case below is one of the five shapes measured before the fix,
    // every one of which answered `allow` although the project rule named
    // was `deny`.
    const gpa = std.testing.allocator;

    const Case = struct {
        source: [:0]const u8,
        key: table.Key,
    };
    const cases = [_]Case{
        .{
            .source =
            \\.{ .policy = .{ .rules = .{
            \\    .{ .agent_kind = "reviewer", .decision = .deny },
            \\} } }
            ,
            .key = .{
                .agent_kind = "reviewer",
                .model = "test-model",
                .tool = "write_file",
                .action = "call.write_file",
            },
        },
        .{
            .source =
            \\.{ .policy = .{ .rules = .{
            \\    .{ .model = "m", .decision = .deny },
            \\} } }
            ,
            .key = .{
                .agent_kind = "main",
                .model = "m",
                .tool = "write_file",
                .action = "call.write_file",
            },
        },
        .{
            .source =
            \\.{ .policy = .{ .rules = .{
            \\    .{ .tool = "write_file", .decision = .deny },
            \\} } }
            ,
            .key = .{
                .agent_kind = "main",
                .model = "test-model",
                .tool = "write_file",
                .action = "call.write_file",
            },
        },
        .{
            .source =
            \\.{ .policy = .{ .rules = .{
            \\    .{ .tool = "run_command", .decision = .deny },
            \\} } }
            ,
            .key = .{
                .agent_kind = "main",
                .model = "test-model",
                .tool = "run_command",
                .action = "exec.path.jq",
            },
        },
        .{
            .source =
            \\.{ .policy = .{ .rules = .{
            \\    .{ .action = "exec.*", .decision = .deny },
            \\} } }
            ,
            .key = .{
                .agent_kind = "main",
                .model = "test-model",
                .tool = "run_command",
                .action = "exec.path.jq",
            },
        },
    };

    for (cases) |case| {
        const t = try table.Table.parse(gpa, case.source, null);
        defer table.Table.destroy(gpa, t);
        try std.testing.expectEqual(table.Decision.deny, t.evaluateKindAlone(case.key));
    }
}

test "exec.unparsed holds no shipped default, and answers ask like any other unnamed action" {
    // `exec.unparsed` was shipped as `allow`, so a path holding a `..` that
    // `lib/chock-core/tools.zig` refused to resolve ran without ever being
    // named by a project's own rules. See this file's own top comment,
    // "What is deliberately absent": the same reasoning that keeps
    // `net.connect.*` and `net.fetch.*` off this list applies here too, and
    // it is why `exec.unparsed` now joins them.
    const gpa = std.testing.allocator;
    const t = try emptyTable(gpa);
    defer table.Table.destroy(gpa, t);

    try std.testing.expectEqual(table.Decision.ask, t.evaluateKindAlone(key("exec.unparsed")));
}

test "a project rule denying every exec class still denies a path that could not be classified" {
    // Measured: `./build.sh` denies, but `./.git/../build.sh` and
    // `./.git/../x/bin/bash` both name `exec.unparsed` instead of
    // `exec.workspace.*`, because a `..` is never resolved lexically. None
    // of the three rules below names `exec.unparsed`, so with the old
    // shipped default of `allow` this fell straight through the project's
    // own denial of every exec class it knew to name.
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "exec.workspace.*", .decision = .deny },
        \\    .{ .action = "exec.path.*", .decision = .deny },
        \\    .{ .action = "exec.nix.store.*", .decision = .deny },
        \\} } }
    ;
    const t = try table.Table.parse(gpa, source, null);
    defer table.Table.destroy(gpa, t);

    try std.testing.expectEqual(table.Decision.deny, t.evaluateKindAlone(key("exec.workspace.build%2Esh")));
    try std.testing.expectEqual(table.Decision.ask, t.evaluateKindAlone(key("exec.unparsed")));
}
