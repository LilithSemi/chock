//! The ratchet: an agent may propose policy, for a subagent it spawns and for
//! itself. Narrowing is free, and widening needs authorisation.

const std = @import("std");
const table = @import("table.zig");

const Decision = table.Decision;

/// One thing an agent has promised not to do, or not to do unasked.
///
/// Three members, and the comptime block at the end of this file allows no
/// fourth. A member that named a clause, a document or a principle would be the
/// route by which a tier that enforces nothing became the warrant for a rule
/// that enforces something.
pub const Restriction = struct {
    /// Required, and never a way to name everything. An agent that could
    /// restrict every action in one call could end its own session in one call.
    /// A class such as `git.*` is as wide as one restriction goes.
    action: []const u8,
    ceiling: Decision,
    reason: []const u8 = "",
};

/// Every act is checked against all of them, so an unbounded list would be an
/// unbounded cost on every decision.
pub const max_restrictions: usize = 32;

pub const max_action_bytes: usize = 64;

pub const max_reason_bytes: usize = 500;

/// This is the whole of the release valve. A widening is judged by the
/// acceptance modes, which already work for any action a project writes a rule
/// for, so there is no second approval path here.
/// An authorised widening writes one `policy.self` event with `authorised` set,
/// which the fold applies as a replacement by exact name. `Loop.runWiden` is the
/// only writer of that flag and refuses a proposal that does not name a promise
/// this session wrote under exactly that string. An older reader drops the
/// field and keeps the narrower promise.
///
/// Two places read the policy once, before the loop runs, so a promise made
/// during the session comes too late: `provisionDecision` for `nix.build`, and
/// the `admit` calls for which third party tools exist. Only a `deny` is spent
/// there, so the starting tool list can be narrower and never wider.
pub const widen_action = "policy.widen";

/// Built from `Decision` itself, so a member that is added cannot be missing
/// from either.
pub const ceiling_names_text = blk: {
    var text: []const u8 = "";
    for (@typeInfo(Decision).@"enum".fields) |field| {
        if (text.len != 0) text = text ++ ", ";
        text = text ++ "\"" ++ field.name ++ "\"";
    }
    break :blk text;
};

/// For a name a model wrote. A misspelling must be reported and never guessed
/// at. `ceilingFromLog` answers the same question differently on purpose.
pub fn ceilingNamed(text: []const u8) ?Decision {
    inline for (@typeInfo(Decision).@"enum".fields) |field| {
        if (std.mem.eql(u8, field.name, text)) return @field(Decision, field.name);
    }
    return null;
}

/// A name this build does not know answers `deny`, which is the whole
/// difference from `ceilingNamed`. A ceiling already in the log was written by
/// something that meant it, and this build cannot tell how much it permits, so
/// it reads as narrower than everything this build knows.
pub fn ceilingFromLog(text: []const u8) Decision {
    return ceilingNamed(text) orelse .deny;
}

/// The most `restrictions` leave for `subject`. `allow` when none covers it.
///
/// A minimum, which is what makes the ratchet a ratchet. Only a restriction
/// that covers the whole of `subject` answers, so an agent that promised
/// `git.push` and asks about `git.*` gets `allow` for the class. Nothing is
/// lost, because `narrow` is asked about one concrete action at the moment of
/// the act, and lifting a promise then means naming exactly what was promised.
/// Three facts make a promise unliftable, and no one of them is enough alone.
/// This is a minimum, there is no event that removes a restriction, and
/// `classify` refuses a proposal asking for more than the agent holds before
/// anything is written. The agent does not enforce any of it on itself:
/// `lib/chock-broker/Broker.zig` reads the folded restrictions in the one
/// process the agent cannot reach, and `src/run.zig`'s `promisesFor` folds
/// every ancestor's log too, out of the logs and never off the child's command
/// line, or one spawn would undo a promise.
pub fn ceilingFor(restrictions: []const Restriction, subject: []const u8) Decision {
    var held: Decision = .allow;
    for (restrictions) |one| {
        if (!table.patternCovers(one.action, subject)) continue;
        held = held.intersect(one.ceiling);
    }
    return held;
}

/// The order of the two is not a choice. Both are ceilings and the result is
/// the minimum, so this is the spawn chain's own intersection with one more
/// member in it.
pub fn narrow(
    answer: Decision,
    restrictions: []const Restriction,
    action: []const u8,
) Decision {
    return answer.intersect(ceilingFor(restrictions, action));
}

/// Three members and not a boolean: a caller has to tell "you already promised
/// this" from "you are asking to be allowed more".
pub const Proposal = enum {
    narrows,
    no_change,
    widens,
};

/// `held` is the self imposed ceiling and never the policy table's answer. The
/// two are separate ceilings that `narrow` intersects, so a project that denies
/// `git.push` does not stop an agent promising `ask` for it. Judging a proposal
/// against the table would let an agent's promise look like a widening of a
/// rule it cannot reach.
pub fn classify(held: Decision, proposed: Decision) Proposal {
    if (proposed.rank() < held.rank()) return .narrows;
    if (proposed.rank() == held.rank()) return .no_change;
    return .widens;
}

/// Why this restriction cannot be recorded, or null when it can. The bounds are
/// here, in the one place that decides what may be written, and not in the fold,
/// which reads logs that are already written.
pub fn refusalFor(restriction: Restriction) ?[]const u8 {
    if (restriction.action.len == 0) {
        return "nothing was promised: name the action you are giving up, for example " ++
            "\"net.fetch\" or \"git.*\". A promise that names nothing binds nothing.";
    }
    if (restriction.action.len > max_action_bytes) {
        return "nothing was promised: an action is a short dotted name such as \"git.push\", " ++
            "not a sentence. Say the detail in your reason.";
    }
    if (!table.patternIsWellFormed(restriction.action)) {
        return "nothing was promised: an action names itself, and a name that ends in \".*\" " ++
            "names every action below it. \"*\" on its own is not one of them: there is no way " ++
            "to promise something about every action at once, so name the one you mean.";
    }
    if (restriction.reason.len == 0) {
        return "nothing was promised: say why in \"reason\". A promise with no reason is one " ++
            "nobody can weigh in the morning, and yours is the only account of what you thought " ++
            "the task needed.";
    }
    if (restriction.reason.len > max_reason_bytes) {
        return "nothing was promised: a reason is one line, read beside the other promises of " ++
            "this session.";
    }
    return null;
}

// This fails the build if a member is added to `Decision` without a place in
// that order being decided, because a new member would change what `narrows`
// means for every proposal already in every log.
comptime {
    const fields = @typeInfo(Decision).@"enum".fields;
    if (fields.len != 5) @compileError(
        "Decision has gained or lost a member. The ratchet compares proposals by rank, so " ++
            "where the new one sits decides whether a promise already in a session log now " ++
            "reads as a narrowing or as a widening. Decide that, then update this count",
    );
    for (fields, 0..) |field, index| {
        if (field.value != index) @compileError(
            "Decision's members are no longer in rank order, and `rank` is `@intFromEnum`",
        );
    }
}

// A fourth member is the route a constitution clause would travel into a rule
// that enforces something, so this fails the build rather than trusting a later
// author to have read a comment.
comptime {
    const fields = @typeInfo(Restriction).@"struct".fields;
    const wanted = [_][]const u8{ "action", "ceiling", "reason" };
    if (fields.len != wanted.len) @compileError(
        "Restriction must hold exactly the action, the ceiling, and the agent's own reason. " ++
            "A member that named a clause of the constitution, or any other document, would " ++
            "make a tier that enforces nothing the warrant for a rule that enforces something",
    );
    for (fields, wanted) |field, name| {
        if (!std.mem.eql(u8, field.name, name)) @compileError(
            "Restriction's members must be, in order: action, ceiling, reason",
        );
    }
}

// Every test below is over values built in the test binary.

const testing = std.testing;

const every_decision = [_]Decision{ .deny, .agent_then_human, .ask, .agent_review, .allow };

test "a restriction never widens anything, for every decision and every ceiling" {
    for (every_decision) |answer| {
        for (every_decision) |ceiling| {
            const restrictions = [_]Restriction{
                .{ .action = "git.push", .ceiling = ceiling, .reason = "the task does not push" },
            };
            const got = narrow(answer, &restrictions, "git.push");
            try testing.expect(got.rank() <= answer.rank());
            try testing.expect(got.rank() <= ceiling.rank());
            try testing.expectEqual(@min(answer.rank(), ceiling.rank()), got.rank());

            try testing.expectEqual(answer, narrow(answer, &restrictions, "net.fetch"));
        }
    }

    for (every_decision) |answer| {
        try testing.expectEqual(answer, narrow(answer, &.{}, "git.push"));
    }
}

test "the fold of a chain and a self restriction is the narrowest of all of them" {
    const gpa = testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "git.push", .decision = .allow },
        \\            .{ .agent_kind = "worker", .action = "git.push", .decision = .ask },
        \\            .{ .agent_kind = "main", .action = "net.fetch", .decision = .allow },
        \\            .{ .agent_kind = "worker", .action = "net.fetch", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const parsed = try table.Table.parse(gpa, source, null);
    defer table.Table.destroy(gpa, parsed);

    const chain = [_][]const u8{ "main", "worker" };
    const key = table.Key{
        .agent_kind = "worker",
        .model = "test-model",
        .tool = "request_action",
        .action = "git.push",
    };

    const from_chain = parsed.evaluateChain(&chain, key, null);
    try testing.expectEqual(Decision.ask, from_chain);

    const promised_deny = [_]Restriction{
        .{ .action = "git.*", .ceiling = .deny, .reason = "this task changes nothing remote" },
    };
    try testing.expectEqual(Decision.deny, narrow(from_chain, &promised_deny, key.action));

    const promised_review = [_]Restriction{
        .{ .action = "git.*", .ceiling = .agent_review, .reason = "a reviewer may weigh this" },
    };
    try testing.expectEqual(Decision.ask, narrow(from_chain, &promised_review, key.action));

    const both = [_]Restriction{
        .{ .action = "git.*", .ceiling = .agent_review, .reason = "a reviewer may weigh this" },
        .{ .action = "git.push", .ceiling = .deny, .reason = "and this one not at all" },
    };
    const reversed = [_]Restriction{ both[1], both[0] };
    try testing.expectEqual(Decision.deny, narrow(from_chain, &both, key.action));
    try testing.expectEqual(Decision.deny, narrow(from_chain, &reversed, key.action));

    const fetch_key = table.Key{
        .agent_kind = "worker",
        .model = "test-model",
        .tool = "request_action",
        .action = "net.fetch",
    };
    try testing.expectEqual(Decision.allow, parsed.evaluateChain(&chain, fetch_key, null));
    const no_network = [_]Restriction{
        .{ .action = "net.fetch", .ceiling = .deny, .reason = "this task reads local files only" },
    };
    try testing.expectEqual(
        Decision.deny,
        narrow(parsed.evaluateChain(&chain, fetch_key, null), &no_network, fetch_key.action),
    );
}

test "a proposal that asks for more than the session holds is a widening" {
    try testing.expectEqual(Proposal.narrows, classify(.allow, .deny));
    try testing.expectEqual(Proposal.narrows, classify(.allow, .ask));
    try testing.expectEqual(Proposal.narrows, classify(.ask, .deny));
    try testing.expectEqual(Proposal.narrows, classify(.agent_review, .ask));

    try testing.expectEqual(Proposal.no_change, classify(.deny, .deny));
    try testing.expectEqual(Proposal.no_change, classify(.allow, .allow));

    try testing.expectEqual(Proposal.widens, classify(.deny, .ask));
    try testing.expectEqual(Proposal.widens, classify(.deny, .allow));
    try testing.expectEqual(Proposal.widens, classify(.ask, .allow));
    try testing.expectEqual(Proposal.widens, classify(.ask, .agent_review));
    try testing.expectEqual(Proposal.narrows, classify(.ask, .agent_then_human));

    for (every_decision) |held| {
        for (every_decision) |proposed| {
            const answer = classify(held, proposed);
            const widens = proposed.rank() > held.rank();
            try testing.expectEqual(widens, answer == .widens);
            try testing.expectEqual(proposed == held, answer == .no_change);
            if (answer != .widens) {
                const written = [_]Restriction{
                    .{ .action = "git.push", .ceiling = proposed, .reason = "why" },
                };
                try testing.expect(ceilingFor(&written, "git.push").rank() <= held.rank());
            }
        }
    }
}

test "a promise covers the class it names, and nothing covers what nobody promised" {
    const promises = [_]Restriction{
        .{ .action = "git.*", .ceiling = .ask, .reason = "no git without a person" },
        .{ .action = "net.fetch", .ceiling = .deny, .reason = "no network" },
    };

    try testing.expectEqual(Decision.ask, ceilingFor(&promises, "git.push"));
    try testing.expectEqual(Decision.ask, ceilingFor(&promises, "git.branch.delete"));
    try testing.expectEqual(Decision.ask, ceilingFor(&promises, "git.*"));
    try testing.expectEqual(Decision.ask, ceilingFor(&promises, "git.branch.*"));

    try testing.expectEqual(Decision.allow, ceilingFor(&promises, "workspace.apply"));
    try testing.expectEqual(Decision.allow, ceilingFor(&promises, "git"));
    try testing.expectEqual(Decision.allow, ceilingFor(&.{}, "git.push"));

    const one_act = [_]Restriction{
        .{ .action = "git.push", .ceiling = .deny, .reason = "not this one" },
    };
    try testing.expectEqual(Decision.deny, ceilingFor(&one_act, "git.push"));
    try testing.expectEqual(Decision.allow, ceilingFor(&one_act, "git.*"));
    const wider = [_]Restriction{
        one_act[0],
        .{ .action = "git.*", .ceiling = .agent_review, .reason = "a reviewer may weigh the rest" },
    };
    try testing.expectEqual(Decision.deny, ceilingFor(&wider, "git.push"));
    try testing.expectEqual(Decision.agent_review, ceilingFor(&wider, "git.commit"));
}

test "a promise about a class of third party tools narrows one of those tools" {
    const promises = [_]Restriction{
        .{ .action = "mcp.*", .ceiling = .deny, .reason = "no third party tool for this task" },
        .{ .action = "plugin.hello.*", .ceiling = .ask, .reason = "a person weighs this plugin" },
    };

    try testing.expectEqual(Decision.deny, ceilingFor(&promises, "mcp.time.tool.get_current_time"));
    try testing.expectEqual(Decision.ask, ceilingFor(&promises, "plugin.hello.tool.greet"));
    const no_writes = [_]Restriction{
        .{ .action = "fs.write", .ceiling = .deny, .reason = "read only from here" },
    };
    try testing.expectEqual(Decision.deny, ceilingFor(&no_writes, "fs.write"));

    try testing.expectEqual(
        Decision.deny,
        narrow(.allow, &promises, "mcp.time.tool.get_current_time"),
    );
    try testing.expectEqual(
        Decision.ask,
        narrow(.allow, &promises, "plugin.hello.tool.greet"),
    );
    try testing.expectEqual(
        Decision.allow,
        narrow(.allow, &promises, "plugin.other.tool.greet"),
    );
    try testing.expectEqual(
        Decision.deny,
        narrow(.deny, &promises, "plugin.other.tool.greet"),
    );
}

test "a ceiling a model misspells is refused, and one already in a log narrows to deny" {
    try testing.expectEqual(Decision.deny, ceilingNamed("deny").?);
    try testing.expectEqual(Decision.agent_then_human, ceilingNamed("agent_then_human").?);
    try testing.expectEqual(Decision.allow, ceilingNamed("allow").?);
    try testing.expectEqual(@as(?Decision, null), ceilingNamed("agent_reveiw"));
    try testing.expectEqual(@as(?Decision, null), ceilingNamed(""));
    try testing.expectEqual(@as(?Decision, null), ceilingNamed("ALLOW"));

    try testing.expectEqual(Decision.deny, ceilingFromLog("deny"));
    try testing.expectEqual(Decision.allow, ceilingFromLog("allow"));
    try testing.expectEqual(Decision.deny, ceilingFromLog("ask_two_people"));
    try testing.expectEqual(Decision.deny, ceilingFromLog(""));

    for (every_decision) |decision| {
        try testing.expectEqual(decision, ceilingNamed(@tagName(decision)).?);
        try testing.expect(std.mem.indexOf(u8, ceiling_names_text, @tagName(decision)) != null);
    }
}

test "a promise that binds nothing, or says nothing, is refused before it is written" {
    const good = Restriction{
        .action = "net.fetch",
        .ceiling = .deny,
        .reason = "this task reads local files only",
    };
    try testing.expectEqual(@as(?[]const u8, null), refusalFor(good));

    try testing.expect(refusalFor(.{ .action = "", .ceiling = .deny, .reason = "x" }) != null);
    try testing.expect(refusalFor(.{ .action = "*", .ceiling = .deny, .reason = "x" }) != null);
    try testing.expect(refusalFor(.{ .action = "a.*.b", .ceiling = .deny, .reason = "x" }) != null);
    try testing.expect(refusalFor(.{ .action = "a\x00b", .ceiling = .deny, .reason = "x" }) != null);

    try testing.expect(refusalFor(.{ .action = "net.fetch", .ceiling = .deny, .reason = "" }) != null);

    const long_action = "a" ** (max_action_bytes + 1);
    try testing.expect(refusalFor(.{ .action = long_action, .ceiling = .deny, .reason = "x" }) != null);
    const at_bound = "a" ** max_action_bytes;
    try testing.expectEqual(
        @as(?[]const u8, null),
        refusalFor(.{ .action = at_bound, .ceiling = .deny, .reason = "x" }),
    );
    const long_reason = "r" ** (max_reason_bytes + 1);
    try testing.expect(refusalFor(.{ .action = "net.fetch", .ceiling = .deny, .reason = long_reason }) != null);
}

test "the widening action is a name in the same namespace every other act uses" {
    const gpa = testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "policy.widen", .decision = .agent_then_human },
        \\        },
        \\    },
        \\}
    ;
    const parsed = try table.Table.parse(gpa, source, null);
    defer table.Table.destroy(gpa, parsed);

    const answer = parsed.evaluateChain(&.{"main"}, .{
        .agent_kind = "main",
        .model = "test-model",
        .tool = "restrict_self",
        .action = widen_action,
    }, null);
    try testing.expectEqual(Decision.agent_then_human, answer);
    try testing.expect(answer.needsReview() and answer.needsHuman());

    const empty = try table.Table.parse(gpa, ".{}", null);
    defer table.Table.destroy(gpa, empty);
    try testing.expectEqual(Decision.ask, empty.evaluateChain(&.{"main"}, .{
        .agent_kind = "main",
        .model = "test-model",
        .tool = "restrict_self",
        .action = widen_action,
    }, null));

    try testing.expect(table.patternIsWellFormed(widen_action));
    try testing.expect(table.patternCovers("policy.*", widen_action));
}
