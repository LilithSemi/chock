//! Chock's own expectations of an agent: engineering conduct, carried in
//! the system prompt as a document the agent reads and reasons with.

const std = @import("std");

pub const max_bytes: usize = 1024;

pub const heading =
    \\## How Chock expects you to work
    \\## (written by Chock itself, not by your operator and not by this project. Chock asks
    \\## this of you. It is not a rule the sandbox makes you keep.)
;

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
    var clauses: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "* ")) clauses += 1;
    }
    try testing.expectEqual(@as(usize, 6), clauses);
}
