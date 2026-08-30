//! The ratchet: **an agent may propose policy, for a subagent it spawns and
//! for itself. Narrowing is free. Widening needs authorisation.**
//!
//! One sentence, applied in two places. The first is already built:
//! `table.evaluateChain` folds the policy over a spawn chain, so a subagent
//! holds no more than its parent, whatever the file says about that child
//! alone. This file is the second, and it is the half that did not exist: **an
//! agent restricting itself, and that restriction being one it cannot then
//! lift.**
//!
//! ## The self imposed policy, and why the log is where it lives
//!
//! **A restriction held only in the model's attention is not a restriction.**
//! It is lost to a compaction, to a resume, to a handover to the daemon, and
//! to a subagent that never saw the turn it was written on. So a restriction
//! is an event in the session log, `policy.self`, folded by
//! `chock_proto.state.SelfPolicy` exactly the way the agent's own task list is
//! folded from `plan.update`. The log is the truth of a session, and a
//! promise is a claim about the session.
//!
//! ## Why it cannot be lifted, which is structural rather than a check
//!
//! Three facts together, and no one of them is enough alone:
//!
//! 1. **The effective ceiling is a minimum over every restriction that covers
//!    the action.** See `ceilingFor`. Adding one more can only lower it.
//! 2. **There is no event that removes a restriction.** The fold appends, the
//!    same rule `state.Plan` keeps: the only way to take a step off a task
//!    list is to say `abandoned` out loud, and here there is not even that.
//! 3. **A proposal that asks for more than the agent currently holds is
//!    refused before anything is written.** See `classify`. Nothing reaches the
//!    log, so there is nothing for the minimum to read.
//!
//! **And the agent does not enforce this on itself.** A check an agent
//! performs on itself is worth nothing. `lib/chock-broker/Broker.zig` reads
//! the folded restrictions and narrows the decision there, in the one process
//! the agent cannot reach, which is where the table already lives.
//!
//! ## A promise binds the children too, or one spawn undoes it
//!
//! An agent that promises not to apply its work and then starts a subagent to
//! apply it has kept the letter of the promise and none of it. A subagent is a
//! separate session with a log of its own, so its own fold holds none of its
//! parent's promises, and the rule has to be applied again:
//! **a child holds no more than its parent, in the half of the policy the
//! parent wrote as well as in the half the file holds.**
//!
//! `src/run.zig`'s own `promisesFor` is what does it. It walks up the
//! `parent_session` links and folds every ancestor's log, so a promise made at
//! the root reaches a grandchild. **Out of the logs and never off the child's
//! command line**: a parent asked to pass its promises down is a parent that
//! could pass none, and the session directory those logs sit in is outside
//! every workspace and mounted into no sandbox.
//!
//! ## The ranking, and the one thing it does not order
//!
//! `Decision` is ranked `deny < agent_then_human < ask < agent_review <
//! allow`, and its own doc comment says the rank is **how much the decision
//! permits**. That is exactly the question this file asks, so the rank is a
//! real order for it: a proposal narrows when it permits less, and `intersect`
//! is the minimum of the same order. The test "a restriction never widens
//! anything, for every decision and every ceiling" walks the whole product of
//! the five by the five and proves it rather than assuming it.
//!
//! **What the rank does not order is liveness.** `ask` permits less than
//! `agent_review` and it also stops an unattended session dead, because a
//! question nobody is awake to answer expires and an expiry is a refusal. So
//! a narrowing is free in the only sense the ratchet claims, which is
//! permission, and it can still cost a session the ability to finish. That is
//! the trap, and the answers to it are that a restriction must name the
//! action it gives up rather than
//! everything, and that the release is the authorisation path below.
//!
//! ## The release valve is the acceptance modes, and it needs no path of its own
//!
//! A widening proposal is the archetypal thing an arbitrator should judge
//! rather than a table: it is an agent saying, in the log, that it was wrong
//! about the task when it planned it, and whether that is true is a reading of
//! the case and not of a key. The acceptance modes already have the two
//! decisions for that, `agent_review` and `agent_then_human`, and
//! `lib/chock-broker/review.zig` already runs them.
//!
//! So **a widening is an action name and nothing more**: `widen_action`, in
//! the namespace every other act uses. A project that wants an agent to be
//! able to widen its own promise unattended writes one rule for it in
//! `chock.zon`, and
//! `Broker.request` then does what it does for every other action. There is no
//! second approval path here, and there is no code here that runs one.
//!
//! **This is wired now.** `chock_core.Loop.runWiden` is the caller, through the
//! `chock_core.arbiter` seam, and `src/run.zig`'s own `SessionArbiter` is what
//! puts the question to `Broker.request`. It could not be built before, because
//! `Loop.run` holds the exclusive lock on the session log for the whole session
//! and no `approval.response` could arrive mid session;
//! `lib/chock-broker/socket.zig` is what removed that wall, by letting an answer
//! arrive from another process without a second writer on the log.
//!
//! **A widening that nobody permits still writes nothing**, which is fact 3
//! above and unchanged. What is new is that it is now weighed, and the words the
//! agent gets back say which of the two happened.
//!
//! ## What an authorised widening does write, which is the one way out
//!
//! One `policy.self` event with `event.PolicySelf.authorised` set.
//! `chock_proto.state.SelfPolicy.apply` folds that one as a **replacement by
//! exact name** rather than as one more term of the minimum, so the promise it
//! names is really lifted and every other promise is untouched.
//!
//! Three things keep facts 1 to 3 true around it:
//!
//! * **Exact name and never a pattern.** `Loop.runWiden` refuses a proposal that
//!   does not name a promise this session wrote under exactly that string, which
//!   is the same rule `ceilingFor` keeps for the question it answers. Without it
//!   an authorised lift of `git.push` would be recorded while `git.*` still held
//!   it down, and a person would have spent a decision on nothing.
//! * **The agent cannot set the flag.** `Loop.runWiden` is the only writer of
//!   it, and it writes it only after an answer from the broker, which holds the
//!   policy table beyond the agent's reach.
//! * **An older reader keeps the older, narrower promise**, because it drops the
//!   field and folds a plain append over a minimum. See
//!   `event.PolicySelf.authorised`: the safe direction is holding the agent to
//!   more than it has to, never to less.
//!
//! ## Where a promise is enforced today, and where it is not
//!
//! **`Broker.request` is the only place a promise changes an outcome**, and
//! `workspace.apply` is the act it reaches it for. `chock run` asks at the end
//! of a session, and an agent asks mid session with `request_action`. That is a
//! real act with a real consequence, and it is also the only one an agent can
//! be stopped from by a promise today.
//!
//! Two places read the policy and do not read a promise, and both are honest
//! gaps rather than oversights:
//!
//! * `src/run.zig`'s `provisionDecision` answers `nix.build` once, before the
//!   first turn, to decide whether the `provide_tool` tool exists at all. A
//!   promise made during that session comes too late to change a tool list
//!   that was fixed before it started.
//! * An ordinary tool call inside the sandbox reaches no broker at all.
//!   `request_action` is the tool that would change that and it takes one act,
//!   `workspace.apply`, and refuses every other name. Widening it needs each
//!   act's own parameters to come from the model, which is a much larger thing
//!   to get right and is not built.
//!
//! ## May a self imposed restriction cite a clause of the constitution? No
//!
//! `lib/chock-core/constitution.zig` is the tier that asks and never enforces.
//! A self imposed restriction is the opposite: the broker refuses on it. The
//! open question is whether an agent's own restriction may name a clause as
//! its justification. It may not, for three
//! reasons, and the third is the decisive one.
//!
//! * **Authority would run the wrong way.** A document that enforces nothing
//!   cannot be the warrant for a rule that enforces something. A restriction
//!   binds because the agent made it, not because a text says it must, and a
//!   citation would put an unenforceable document at the root of an
//!   enforceable rule. That is the exact confusion the three tiers are kept
//!   apart to prevent, and `constitution.zig` states the rule for its own side
//!   of it: never write a check that enforces a clause.
//! * **It would make an arbitrator read a text instead of a case.** Every
//!   widening request would arrive as an argument about what a clause means,
//!   and "citing a principle to justify something the principle does not say"
//!   is the failure mode of every constitution ever written. The reviewer is
//!   asked whether the act should happen, and `review.taskFor` already tells
//!   it not to answer "who is right".
//! * **A field is the only way to cite, so there is no field.** The same guard
//!   `review.requesterText` uses: the leak is prevented by there being nothing
//!   to leak through. A `Restriction` holds the action, the ceiling, and the
//!   agent's own words, and the comptime block at the end of this file fails
//!   the build if a fourth member is added, so this cannot decay into a
//!   comment somebody stops reading.
//!
//! **The constitution may still cause a restriction, and that is the point of
//! it.** "Ask first when an action is hard to undo" is exactly the sort of
//! thinking that produces `git.push` at `ask` before the work starts. Conduct
//! shaping what an agent chooses to promise is the document working. Conduct
//! quoted as the authority for the promise is the document overreaching.

const std = @import("std");
const table = @import("table.zig");

const Decision = table.Decision;

/// One thing an agent has promised not to do, or not to do unasked.
///
/// **Three members, and the comptime block at the end of this file allows no
/// fourth.** See this file's own top comment on the constitution: a member
/// that named a clause, a document, or a principle would be the route by which
/// a tier that enforces nothing became the warrant for a rule that enforces
/// something.
pub const Restriction = struct {
    /// The action, or the class of actions, this covers. The same pattern
    /// language `table.Rule.action` speaks, read with `table.patternCovers`.
    ///
    /// **Required, and never a way to name everything.** A promise has to say
    /// what is being given up: an agent that could restrict every action in one
    /// call could end its own session in one call, which is the trap. A class
    /// such as `git.*` is as wide as one restriction goes.
    action: []const u8,
    /// The most this agent may hold for that action. `deny` promises the act
    /// will not happen at all; `ask` promises it will not happen without a
    /// person.
    ceiling: Decision,
    /// Why, in the agent's own words. **For the person who reads the log**, the
    /// same reader `review.Report.note` is written for. Nothing acts on it.
    reason: []const u8 = "",
};

/// How many restrictions one session may hold.
///
/// Thirty two, which is more promises than a task has and few enough that a
/// person can read the list. Every act is measured against all of them, so an
/// unbounded list would also be an unbounded cost on every decision.
pub const max_restrictions: usize = 32;

/// How long one restriction's action pattern may be. A pattern is a dotted
/// name, not a sentence.
pub const max_action_bytes: usize = 64;

/// How long one restriction's reason may be. One line, read beside the others
/// in a list, the same bound `review.max_note_bytes` gives a reviewer's note
/// and for the same reason: a record nobody reads in the morning is not a
/// record.
pub const max_reason_bytes: usize = 500;

/// The action a widening proposal is measured against, in the namespace every
/// other act uses.
///
/// **This is the whole of the release valve.** See this file's own top
/// comment: a widening is judged by the acceptance modes, and those already
/// work for any action a project writes a rule for. A project
/// that wants an agent to be able to widen its own promise with nobody awake
/// writes `.{ .action = "policy.widen", .decision = .agent_then_human }` in
/// `chock.zon`, which is beyond the agent's reach.
pub const widen_action = "policy.widen";

/// Every ceiling an agent may name, joined, for a tool schema and for the
/// message a proposal with a name nobody knows gets back. Built from
/// `Decision` itself, so a member that is added cannot be missing from either.
pub const ceiling_names_text = blk: {
    var text: []const u8 = "";
    for (@typeInfo(Decision).@"enum".fields) |field| {
        if (text.len != 0) text = text ++ ", ";
        text = text ++ "\"" ++ field.name ++ "\"";
    }
    break :blk text;
};

/// The ceiling named by `text`, or null for a name this build does not write.
///
/// **For a name a model wrote.** A misspelling must be reported and never
/// guessed at: see `ceilingFromLog`, which answers the same question for a
/// name that is already in the log and answers it differently on purpose.
pub fn ceilingNamed(text: []const u8) ?Decision {
    inline for (@typeInfo(Decision).@"enum".fields) |field| {
        if (std.mem.eql(u8, field.name, text)) return @field(Decision, field.name);
    }
    return null;
}

/// The ceiling a name out of the session log stands for.
///
/// **A name this build does not know answers `deny`**, which is the whole
/// difference from `ceilingNamed`. The two questions are not the same one:
///
/// * A model that misspells a ceiling has made a mistake and is told, because
///   a typo written into the log would be indistinguishable from a ceiling a
///   later Chock invented.
/// * A ceiling already in the log was written by something that meant it. This
///   build cannot tell how much it permits, and the two ways to read it are
///   "narrower than everything I know" and "as permissive as I like". The
///   first is the only one that keeps a promise a newer Chock recorded, and
///   the log is the truth of a session even for a reader that is older than
///   part of it.
pub fn ceilingFromLog(text: []const u8) Decision {
    return ceilingNamed(text) orelse .deny;
}

/// The most `restrictions` leave for `subject`, which is an action name or a
/// class of them. `allow` when none of them covers it, which is a session that
/// has promised nothing about this act.
///
/// **A minimum, and that is what makes the ratchet a ratchet.** Adding a
/// restriction can only lower this, so no list of restrictions ever permits
/// more than a shorter list of the same ones.
///
/// **Only a restriction that covers the whole of `subject` answers.** An agent
/// that promised `git.push` at `deny` and then asks about `git.*` is asking
/// about a class this session has said nothing about as a class, and the
/// answer is `allow` for it. Nothing is lost by that: `narrow` is asked about
/// one concrete action at the moment of the act, and `git.push` is still
/// denied there. What it buys is that lifting a promise means naming exactly
/// what was promised, rather than reaching for a wider pattern and hoping the
/// comparison reads it as new.
pub fn ceilingFor(restrictions: []const Restriction, subject: []const u8) Decision {
    var held: Decision = .allow;
    for (restrictions) |one| {
        if (!table.patternCovers(one.action, subject)) continue;
        held = held.intersect(one.ceiling);
    }
    return held;
}

/// What `answer` becomes once this session's own promises are applied to it.
/// `answer` is what the policy table said for the whole spawn chain, from
/// `table.evaluateChain`.
///
/// **The order of the two is not a choice.** Both are ceilings and the result
/// is the minimum, so this is the same intersection a spawn chain already
/// takes, with one more member in it. A chain of six kinds and one
/// self imposed restriction gives the narrowest of all seven.
///
/// `action` names one act, so it is a pattern that names itself: see
/// `table.patternCovers`.
pub fn narrow(
    answer: Decision,
    restrictions: []const Restriction,
    action: []const u8,
) Decision {
    return answer.intersect(ceilingFor(restrictions, action));
}

/// What one proposal would do to the promise a session already holds.
///
/// Three members and not a boolean, for the reason `Broker.Outcome` is not
/// one: a caller has to tell "you already promised this" from "you are asking
/// to be allowed more", and the two need different words back.
pub const Proposal = enum {
    /// The proposal permits less than this session already holds. Free: it
    /// applies at once, with nobody asked.
    narrows,
    /// The proposal permits exactly what this session already holds. Nothing
    /// is written, because a log entry that changes nothing is a log entry
    /// that costs a reader a line.
    no_change,
    /// The proposal permits more than this session already holds. **This is
    /// the one that needs authorisation**, and nothing is written for it: see
    /// this file's own top comment, and `widen_action`.
    widens,
};

/// Which of the three `proposed` is, against the ceiling this session already
/// holds for the same subject.
///
/// **`held` is the self imposed ceiling and never the policy table's answer.**
/// The two are separate ceilings that `narrow` intersects, so a project that
/// denies `git.push` does not stop an agent promising `ask` for it: that
/// promise is a narrowing of the agent's own word, it changes nothing about
/// what happens, and it is worth recording because it says what the agent
/// believed the task needed. Judging a proposal against the table would mix
/// two authorities in one comparison and let an agent's promise look like a
/// widening of a rule it cannot reach.
pub fn classify(held: Decision, proposed: Decision) Proposal {
    if (proposed.rank() < held.rank()) return .narrows;
    if (proposed.rank() == held.rank()) return .no_change;
    return .widens;
}

/// Why this restriction cannot be recorded, or null when it can. The bounds
/// are here, in the one place that decides what may be written, and not in the
/// fold, which reads logs that are already written.
///
/// The message is for the model that wrote the proposal, so each one says what
/// to write instead.
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

// The rank is the order this whole file compares with, and `Decision`'s own
// doc comment is what says it may be. This fails the build if a member is
// added to `Decision` without a place in that order being decided, because a
// new member would change what `narrows` means for every proposal already in
// every log.
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

// The reviewer's own asymmetry, one level up: a restriction says what it gives
// up and why, and it names no document. See this file's own top comment on the
// constitution. A fourth member is the route a clause would travel, so this
// fails the build rather than trusting a later author to have read the
// comment.
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

// Every test below is over values built in the test binary. The fold that puts
// a restriction in a log is `chock_proto.state.SelfPolicy`, and the caller
// that acts on one is `lib/chock-broker/Broker.zig`; both have tests of their
// own, because this module imports neither.

const testing = std.testing;

const every_decision = [_]Decision{ .deny, .agent_then_human, .ask, .agent_review, .allow };

test "a restriction never widens anything, for every decision and every ceiling" {
    // The property the whole file rests on, walked in full rather than
    // sampled: five decisions by five ceilings is twenty five pairs, so there
    // is no reason to test a subset of it.
    //
    // This is also the check the rank itself has to pass before anything may
    // lean on it. A ranking built for one question can be wrong for another,
    // and the question here is "does this let more through", which is the
    // question `Decision`'s own order is defined by.
    for (every_decision) |answer| {
        for (every_decision) |ceiling| {
            const restrictions = [_]Restriction{
                .{ .action = "git.push", .ceiling = ceiling, .reason = "the task does not push" },
            };
            const got = narrow(answer, &restrictions, "git.push");
            try testing.expect(got.rank() <= answer.rank());
            try testing.expect(got.rank() <= ceiling.rank());
            // The narrowest of the two, and not merely something no wider than
            // either: a function that always answered `deny` would pass the two
            // lines above and would make every promise meaningless.
            try testing.expectEqual(@min(answer.rank(), ceiling.rank()), got.rank());

            // An action no restriction covers is left exactly where the table
            // put it. A self policy that narrowed something it did not name
            // would be a session quietly losing permissions.
            try testing.expectEqual(answer, narrow(answer, &restrictions, "net.fetch"));
        }
    }

    for (every_decision) |answer| {
        try testing.expectEqual(answer, narrow(answer, &.{}, "git.push"));
    }
}

test "the fold of a chain and a self restriction is the narrowest of all of them" {
    // `evaluateChain` folds the policy over the spawn chain, and this folds one
    // more ceiling into the same minimum. The result must be the narrowest of
    // every member, whichever of them is narrowest, so the test drives both
    // orders: a chain narrower than the promise, and a promise narrower than
    // the chain.
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

    // A promise wider than the chain loses, and the chain still holds. This is
    // the direction that would be an escalation if the minimum were taken the
    // wrong way round.
    const promised_review = [_]Restriction{
        .{ .action = "git.*", .ceiling = .agent_review, .reason = "a reviewer may weigh this" },
    };
    try testing.expectEqual(Decision.ask, narrow(from_chain, &promised_review, key.action));

    // Two promises over the same act: the narrower of them answers, whichever
    // order they are in.
    const both = [_]Restriction{
        .{ .action = "git.*", .ceiling = .agent_review, .reason = "a reviewer may weigh this" },
        .{ .action = "git.push", .ceiling = .deny, .reason = "and this one not at all" },
    };
    const reversed = [_]Restriction{ both[1], both[0] };
    try testing.expectEqual(Decision.deny, narrow(from_chain, &both, key.action));
    try testing.expectEqual(Decision.deny, narrow(from_chain, &reversed, key.action));

    // The whole thing, in one line: seven members and the narrowest wins. The
    // key here is one the chain allows outright, so the promise is the only
    // thing that can be narrowing it.
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
    // The two acceptance modes are ranked with the other three, so they need
    // no branch of their own. Moving from `ask` to `agent_review` lets work
    // through while nobody is awake, which is more and not less.
    try testing.expectEqual(Proposal.widens, classify(.ask, .agent_review));
    try testing.expectEqual(Proposal.narrows, classify(.ask, .agent_then_human));

    // Every pair, so no member is ordered by accident. The three answers
    // partition the product: exactly one of them is true for each pair.
    for (every_decision) |held| {
        for (every_decision) |proposed| {
            const answer = classify(held, proposed);
            const widens = proposed.rank() > held.rank();
            try testing.expectEqual(widens, answer == .widens);
            try testing.expectEqual(proposed == held, answer == .no_change);
            // A proposal that is not a widening is one applying it would leave
            // no wider than it was. That is the link between `classify`, which
            // decides whether to write, and `narrow`, which reads what was
            // written.
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
    // And the class itself, which is what a later proposal about it is judged
    // against.
    try testing.expectEqual(Decision.ask, ceilingFor(&promises, "git.*"));
    try testing.expectEqual(Decision.ask, ceilingFor(&promises, "git.branch.*"));

    // An act nobody promised anything about is left alone. `allow` here is not
    // permission: it is the ceiling this session's own word puts on the act,
    // and the policy table still answers for it.
    try testing.expectEqual(Decision.allow, ceilingFor(&promises, "workspace.apply"));
    try testing.expectEqual(Decision.allow, ceilingFor(&promises, "git"));
    try testing.expectEqual(Decision.allow, ceilingFor(&.{}, "git.push"));

    // A promise about one act does not answer for the class above it, which is
    // what makes lifting a promise mean naming exactly what was promised.
    const one_act = [_]Restriction{
        .{ .action = "git.push", .ceiling = .deny, .reason = "not this one" },
    };
    try testing.expectEqual(Decision.deny, ceilingFor(&one_act, "git.push"));
    try testing.expectEqual(Decision.allow, ceilingFor(&one_act, "git.*"));
    // And the act itself is still denied whatever a wider promise says, because
    // the act is measured by the minimum over everything that covers it.
    const wider = [_]Restriction{
        one_act[0],
        .{ .action = "git.*", .ceiling = .agent_review, .reason = "a reviewer may weigh the rest" },
    };
    try testing.expectEqual(Decision.deny, ceilingFor(&wider, "git.push"));
    try testing.expectEqual(Decision.agent_review, ceilingFor(&wider, "git.commit"));
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
    // And a name this build has never heard of is the narrowest thing there
    // is, never the widest.
    try testing.expectEqual(Decision.deny, ceilingFromLog("ask_two_people"));
    try testing.expectEqual(Decision.deny, ceilingFromLog(""));

    // Every name a model may write is a name this build reads back, so the
    // schema and the reader cannot drift.
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
    // The byte the read time check invents for itself. A
    // restriction is not read by that check, and refusing it here keeps one
    // answer to what a pattern is.
    try testing.expect(refusalFor(.{ .action = "a\x00b", .ceiling = .deny, .reason = "x" }) != null);

    try testing.expect(refusalFor(.{ .action = "net.fetch", .ceiling = .deny, .reason = "" }) != null);

    // The bounds, one byte each side.
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
    // A reviewer reads it and then a person does, which is exactly right: the
    // agent is saying it was wrong about the task when it planned it, and that
    // is worth a reader.
    try testing.expectEqual(Decision.agent_then_human, answer);
    try testing.expect(answer.needsReview() and answer.needsHuman());

    // A project that writes no rule for it gets `ask`, the same safe default
    // every unnamed action gets, and `ask` cannot be answered in a session
    // whose loop holds the log lock. So the default really is a refusal.
    const empty = try table.Table.parse(gpa, ".{}", null);
    defer table.Table.destroy(gpa, empty);
    try testing.expectEqual(Decision.ask, empty.evaluateChain(&.{"main"}, .{
        .agent_kind = "main",
        .model = "test-model",
        .tool = "restrict_self",
        .action = widen_action,
    }, null));

    // And the name is well formed by this file's own rules, so a project can
    // write a rule for it and a class rule such as `policy.*` reaches it.
    try testing.expect(table.patternIsWellFormed(widen_action));
    try testing.expect(table.patternCovers("policy.*", widen_action));
}
