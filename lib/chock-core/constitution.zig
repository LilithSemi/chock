//! Chock's own expectations of an agent: engineering conduct, in the sense
//! Anthropic publishes a constitution for its own models. A document the
//! agent reads and reasons with.
//!
//! ## This is not the sandbox, and the two must never be confused
//!
//! **The sandbox is enforcement. This document is not.** The mount namespace,
//! the seccomp filter, the Landlock ruleset, and the policy table hold
//! against an agent that disagrees with them. Nothing here holds against
//! anything. It works only when the agent chooses to follow it.
//!
//! That is not a weakness, because the two do different jobs:
//!
//! | | Holds against | For |
//! |---|---|---|
//! | the layers in `chock-sandbox` and `chock-policy` | a hostile agent | the agent that does not want to do right |
//! | this document | nobody | the agent that does, which is nearly every agent nearly all the time |
//!
//! **So never write a check that enforces a clause here.** A check that
//! enforces conduct is capability, and capability belongs in the layers. A
//! clause that stands in for a layer is the fault this project has watched
//! fail three times in one week, with the git shim, the shell refusal, and
//! `env` defeating three harness rules at once. Read
//! `lib/chock-sandbox/Sandbox.zig` for what actually stops an agent.
//!
//! For the same reason there is no test in this file, or in `prompt.zig`,
//! that asserts a model obeys any of this. That is not a property of this
//! code. The tests pin what is: the document reaches the prompt whole, it
//! says who wrote it, and it stays apart from the other sources.
//!
//! ## May an agent's own promise cite a clause of this? No, and it was decided
//!
//! A `Restriction` has no member a clause could travel in, and
//! `lib/chock-policy/ratchet.zig`'s own comptime block fails the build if one
//! is added. The reasoning is written out there in full.
//!
//! ## Why this one is in the prompt, when everything else is an index line
//!
//! `guidance.zig`, `memory.zig`, and the subtree files in `instructions.zig`
//! all cost one line in the prompt and a tool call to fetch the body. That
//! rule is right and it stays right, and **this document is the one
//! exception to it**.
//!
//! The reason is decisive: **an agent cannot decide to read a document at the
//! moment the document matters**, because the moment it matters is the moment
//! the agent is about to do the wrong thing. An agent that is about to call
//! finished work that is not finished does not first call `read_guidance`.
//! Progressive disclosure works for a document the model asks for when it
//! knows it needs one, and this is exactly the document the model does not
//! know it needs.
//!
//! ## Where each clause came from
//!
//! Every one is a rule this project reached by being burned, not by taste:
//!
//! * **Report faithfully, and never call work done that is not done.** Three
//!   mechanisms here shipped with green tests and no caller at all, and a
//!   fourth stub gave a reason for itself that had quietly expired. No test
//!   catches this class, which is why it is conduct.
//! * **A refusal is information.** A red team session spent turns hunting for
//!   a proxy after `ssh` was missing, because a confusing failure led it to
//!   the wrong conclusion about the machine.
//! * **Ask first when an action is hard to undo.** Reversibility is the
//!   criterion the exec arbitration design already uses.
//! * **Correct rather than contradict.** The knowledgebase takes the newest
//!   entry of a name, so a correction costs nothing and two entries that
//!   disagree never reach the next agent.

const std = @import("std");

/// The most this document may grow to. The prompt pays for it on every turn,
/// and a document past this length is one the model reads the front of.
pub const max_bytes: usize = 1024;

/// The heading over the document.
///
/// **This is a third source, and it is the harness's own voice.**
/// `instructions.zig` marks the operator's block and the repository's block,
/// and `memory.zig`'s heading marks a note as the agent's own. Neither of
/// those layers occupies this one: an operator did not write this, a
/// repository did not write this, and the agent did not write this. Chock
/// did.
///
/// The last line is the honest part, and it is one line rather than a
/// paragraph. Chock asks for this conduct. The sandbox is what makes an
/// action impossible, and saying so keeps a model from reading a request as a
/// capability it can test.
pub const heading =
    \\## How Chock expects you to work
    \\## (written by Chock itself, not by your operator and not by this project. Chock asks
    \\## this of you. It is not a rule the sandbox makes you keep.)
;

/// The document. Six clauses, one line of reasoning each, and no preamble.
pub const text =
    \\* Report faithfully. Never say that work is done when it is not done. A
    \\  test that passes is not a feature that something calls. Say plainly
    \\  what you left undone.
    \\* A refusal is information. When a tool or the sandbox refuses you, find
    \\  out why before you try another route. A refusal usually tells you a
    \\  fact about this machine that you did not have.
    \\* Say when you are not sure, and say what would make you sure.
    \\* Ask first when an action is hard to undo. How easy the action is to
    \\  undo is the test, not how large the action is.
    \\* Correct, do not contradict. When you change an earlier answer or an
    \\  earlier note, say what changed.
    \\* Name the other option when you refuse. A bare no costs the reader a
    \\  turn.
    \\
;

const testing = std.testing;

test "the document is short enough that a model reads all of it" {
    try testing.expect(text.len <= max_bytes);
    try testing.expect(heading.len < text.len);
}

test "the heading names Chock as the writer and separates Chock from the operator and the project" {
    try testing.expect(std.mem.indexOf(u8, heading, "written by Chock itself") != null);
    try testing.expect(std.mem.indexOf(u8, heading, "not by your operator") != null);
    try testing.expect(std.mem.indexOf(u8, heading, "not by this project") != null);
}

test "the heading says Chock asks for this conduct and does not claim the sandbox keeps it" {
    try testing.expect(std.mem.indexOf(u8, heading, "Chock asks") != null);
    try testing.expect(std.mem.indexOf(u8, heading, "not a rule the sandbox makes you keep") != null);
}

test "every clause is a clause, so the document never becomes an essay" {
    // Six bullets, each one sentence of rule and one of reason. The shape is
    // what keeps the bound above reachable, and prose creeping in is how a
    // short document becomes a long one without any single change looking
    // wrong.
    var clauses: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "* ")) clauses += 1;
    }
    try testing.expectEqual(@as(usize, 6), clauses);
}
