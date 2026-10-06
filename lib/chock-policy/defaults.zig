//! The rules Chock ships, so a project with no `chock.zon` keeps today's
//! behaviour for every tool call. A project rule that matches always wins
//! over a shipped default, and an unnamed key answers `ask`.

const table = @import("table.zig");

/// One rule for every action an ordinary tool call builds. A forgotten tool
/// still answers `ask`.
pub const rules: []const table.Rule = &.{
    .{ .action = "call.read_file", .decision = .allow },
    .{ .action = "call.read_image", .decision = .allow },
    .{ .action = "call.list_directory", .decision = .allow },
    .{ .action = "call.glob", .decision = .allow },
    .{ .action = "call.grep", .decision = .allow },
    .{ .action = "call.write_file", .decision = .allow },
    .{ .action = "call.edit_file", .decision = .allow },
    .{ .action = "exec.devshell.*", .decision = .allow },
    .{ .action = "exec.nix.store.*", .decision = .ask },
    .{ .action = "exec.workspace.*", .decision = .allow },
    .{ .action = "exec.path.*", .decision = .allow },
    .{ .action = "call.read_guidance", .decision = .allow },
    .{ .action = "call.read_memory", .decision = .allow },
    .{ .action = "call.write_memory", .decision = .allow },
    .{ .action = "call.provide_tool", .decision = .allow },
    .{ .action = "call.nix_eval", .decision = .allow },
    .{ .action = "nix.net.build.opaque", .decision = .allow },
    .{ .action = "lsp.*", .decision = .allow },
    .{ .action = "web.search", .decision = .ask },

    .{ .action = "skill.read.operator", .decision = .allow },
    .{ .action = "skill.read.project", .decision = .ask },
    .{ .action = "skill.read.packaged", .decision = .ask },

    .{ .action = "secret.use.*", .decision = .ask },

    // `git.push`, `git.clone`, `git.fetch`, `git.pull` and `git.unknown` are
    // absent because each one reaches another host.
    .{ .action = "git.add", .decision = .allow },
    .{ .action = "git.am", .decision = .allow },
    .{ .action = "git.apply", .decision = .allow },
    .{ .action = "git.bisect", .decision = .allow },
    .{ .action = "git.branch", .decision = .allow },
    .{ .action = "git.branch.delete", .decision = .allow },
    .{ .action = "git.checkout", .decision = .allow },
    .{ .action = "git.cherry-pick", .decision = .allow },
    .{ .action = "git.clean", .decision = .allow },
    .{ .action = "git.commit", .decision = .allow },
    .{ .action = "git.config", .decision = .allow },
    .{ .action = "git.filter-branch", .decision = .allow },
    .{ .action = "git.fsck", .decision = .allow },
    .{ .action = "git.gc", .decision = .allow },
    .{ .action = "git.hash-object", .decision = .allow },
    .{ .action = "git.init", .decision = .allow },
    .{ .action = "git.merge", .decision = .allow },
    .{ .action = "git.mv", .decision = .allow },
    .{ .action = "git.notes", .decision = .allow },
    .{ .action = "git.prune", .decision = .allow },
    .{ .action = "git.rebase", .decision = .allow },
    .{ .action = "git.reflog", .decision = .allow },
    .{ .action = "git.remote", .decision = .allow },
    .{ .action = "git.repack", .decision = .allow },
    .{ .action = "git.replace", .decision = .allow },
    .{ .action = "git.reset", .decision = .allow },
    .{ .action = "git.restore", .decision = .allow },
    .{ .action = "git.revert", .decision = .allow },
    .{ .action = "git.rm", .decision = .allow },
    .{ .action = "git.stash", .decision = .allow },
    .{ .action = "git.submodule", .decision = .allow },
    .{ .action = "git.switch", .decision = .allow },
    .{ .action = "git.symbolic-ref", .decision = .allow },
    .{ .action = "git.tag", .decision = .allow },
    .{ .action = "git.update-index", .decision = .allow },
    .{ .action = "git.update-ref", .decision = .allow },
    .{ .action = "git.worktree", .decision = .allow },
};

const std = @import("std");

fn key(action: []const u8) table.Key {
    return .{
        .agent_kind = "main",
        .model = "test-model",
        .tool = "irrelevant-to-every-rule-here",
        .action = action,
    };
}

fn emptyTable(gpa: std.mem.Allocator) !*const table.Table {
    return table.Table.parse(gpa, ".{}", null);
}

test "every action an ordinary tool call builds answers allow with no chock.zon at all" {
    const gpa = std.testing.allocator;
    const t = try emptyTable(gpa);
    defer table.Table.destroy(gpa, t);

    const call_actions = [_][]const u8{
        "call.read_file",
        "call.read_image",
        "call.list_directory",
        "call.glob",
        "call.grep",
        "call.write_file",
        "call.edit_file",
        "call.read_guidance",
        "call.read_memory",
        "call.write_memory",
        "call.provide_tool",
        "call.nix_eval",
    };
    for (call_actions) |action| {
        try std.testing.expectEqual(table.Decision.allow, t.evaluateKindAlone(key(action)));
    }

    const run_command_actions = [_][]const u8{
        "exec.devshell.abc-jq.bin.jq",
        "exec.workspace.build%2Esh",
        "exec.path.jq",
    };
    for (run_command_actions) |action| {
        try std.testing.expectEqual(table.Decision.allow, t.evaluateKindAlone(key(action)));
    }
}

test "a store path outside the dev shell closure asks with no chock.zon at all" {
    const gpa = std.testing.allocator;
    const t = try emptyTable(gpa);
    defer table.Table.destroy(gpa, t);

    try std.testing.expectEqual(
        table.Decision.ask,
        t.evaluateKindAlone(key("exec.nix.store.abc-jq.bin.jq")),
    );
    try std.testing.expectEqual(
        table.Decision.allow,
        t.evaluateKindAlone(key("exec.devshell.abc-jq.bin.jq")),
    );
}

test "net.connect and net.fetch hold no default rule and still answer ask" {
    const gpa = std.testing.allocator;
    const t = try emptyTable(gpa);
    defer table.Table.destroy(gpa, t);

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

test "a build that fetches with no url is allowed by default, and a project can take it back" {
    const gpa = std.testing.allocator;

    const empty = try emptyTable(gpa);
    defer table.Table.destroy(gpa, empty);
    try std.testing.expectEqual(
        table.Decision.allow,
        empty.evaluateKindAlone(key("nix.net.build.opaque")),
    );

    const asking = try table.Table.parse(
        gpa,
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "nix.net.build.opaque", .decision = .ask },
        \\        },
        \\    },
        \\}
    ,
        null,
    );
    defer table.Table.destroy(gpa, asking);
    try std.testing.expectEqual(
        table.Decision.ask,
        asking.evaluateKindAlone(key("nix.net.build.opaque")),
    );

    const denying = try table.Table.parse(
        gpa,
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "nix.net.build.opaque", .decision = .deny },
        \\        },
        \\    },
        \\}
    ,
        null,
    );
    defer table.Table.destroy(gpa, denying);
    try std.testing.expectEqual(
        table.Decision.deny,
        denying.evaluateKindAlone(key("nix.net.build.opaque")),
    );

    try std.testing.expectEqual(
        table.Decision.ask,
        empty.evaluateKindAlone(key("net.connect.com.example.443")),
    );
}

test "web.search answers ask with no chock.zon at all" {
    const gpa = std.testing.allocator;
    const t = try emptyTable(gpa);
    defer table.Table.destroy(gpa, t);

    try std.testing.expectEqual(table.Decision.ask, t.evaluateKindAlone(key("web.search")));
}

test "the operator's own skills read without a question, and a stranger's ask" {
    const gpa = std.testing.allocator;
    const t = try emptyTable(gpa);
    defer table.Table.destroy(gpa, t);

    try std.testing.expectEqual(
        table.Decision.allow,
        t.evaluateKindAlone(key("skill.read.operator")),
    );
    try std.testing.expectEqual(
        table.Decision.ask,
        t.evaluateKindAlone(key("skill.read.project")),
    );
    try std.testing.expectEqual(
        table.Decision.ask,
        t.evaluateKindAlone(key("skill.read.packaged")),
    );
}

test "a project that trusts its own skills writes one rule, and the other layers stand" {
    const gpa = std.testing.allocator;
    const t = try table.Table.parse(
        gpa,
        ".{ .policy = .{ .rules = .{ .{ .action = \"skill.read.project\", .decision = .allow } } } }",
        null,
    );
    defer table.Table.destroy(gpa, t);

    try std.testing.expectEqual(
        table.Decision.allow,
        t.evaluateKindAlone(key("skill.read.project")),
    );
    try std.testing.expectEqual(
        table.Decision.ask,
        t.evaluateKindAlone(key("skill.read.packaged")),
    );
}

test "a tool this file forgot still answers ask" {
    const gpa = std.testing.allocator;
    const t = try emptyTable(gpa);
    defer table.Table.destroy(gpa, t);

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

    try std.testing.expectEqual(table.Decision.ask, t.evaluateKindAlone(key("call.write_file")));
    try std.testing.expectEqual(table.Decision.allow, t.evaluateKindAlone(key("call.read_file")));

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
        try std.testing.expectEqual(table.Decision.deny, t.evaluateKindAlone(workspace_key));

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
    const gpa = std.testing.allocator;
    const t = try emptyTable(gpa);
    defer table.Table.destroy(gpa, t);

    try std.testing.expectEqual(table.Decision.ask, t.evaluateKindAlone(key("exec.unparsed")));
}

test "device.* holds no shipped default, and answers ask like any other unnamed action" {
    const gpa = std.testing.allocator;
    const t = try emptyTable(gpa);
    defer table.Table.destroy(gpa, t);

    try std.testing.expectEqual(table.Decision.ask, t.evaluateKindAlone(key("device.usb.1d50.6018")));
}

test "a project rule denying every exec class still denies a path that could not be classified" {
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "exec.workspace.*", .decision = .deny },
        \\    .{ .action = "exec.path.*", .decision = .deny },
        \\    .{ .action = "exec.devshell.*", .decision = .deny },
        \\    .{ .action = "exec.nix.store.*", .decision = .deny },
        \\} } }
    ;
    const t = try table.Table.parse(gpa, source, null);
    defer table.Table.destroy(gpa, t);

    try std.testing.expectEqual(table.Decision.deny, t.evaluateKindAlone(key("exec.workspace.build%2Esh")));
    try std.testing.expectEqual(table.Decision.ask, t.evaluateKindAlone(key("exec.unparsed")));
}
