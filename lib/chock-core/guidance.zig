//! Guidance: the engineering process the harness carries so the model does
//! not have to hold it.
//!
//! ## Not a longer prompt
//!
//! This is **progressive disclosure**, the same mechanism `index.zig`
//! gives the knowledgebase and the subtree instruction files:
//!
//! * The prompt names what exists, in one line each.
//! * `read_guidance` fetches the whole of one when the model decides it
//!   applies.
//!
//! The prompt grows by about one line per piece, not one paragraph, and a
//! piece the model never reads costs its one line and nothing else.
//!
//! ## Guidance is data, not code
//!
//! Every piece here is a compiled in string. There is no path from a piece
//! of guidance to a decision Chock makes, for the same reason a policy that
//! must be executed to be understood is refused.
//!
//! **A tool call cannot write guidance**, and there is nothing to write: the
//! shelf is in the binary.
//!
//! **Known gap: a project cannot yet add guidance of its own.** That needs a
//! read only path into the project the way `chock.zon` has one, and it is
//! not built.

const std = @import("std");
const index = @import("index.zig");

/// One piece of guidance. The description is the line in the prompt, and the
/// body is what `read_guidance` returns.
pub const Piece = struct {
    name: []const u8,
    description: []const u8,
    body: []const u8,
};

/// The shelf. **Kept short on purpose**: each entry costs a line of every
/// prompt, so a piece earns its place or it goes.
///
/// No piece tells the agent when to use a subagent. A tree of agents is proven
/// at one child, and guidance that pushed an agent towards a shape nobody has
/// measured would be advice ahead of evidence. The tool's own description says
/// what the two shapes are, which is where a caller reads it anyway.
pub const pieces = [_]Piece{
    .{
        .name = "plan-before-acting",
        .description = "Think about the approach before you change anything, when there is more than one way.",
        .body =
        \\# Plan before acting
        \\
        \\A task with more than one obvious approach is a task worth one
        \\paragraph of thought first. Small models act first and find the
        \\problem late, and a wrong approach costs every turn that follows it.
        \\
        \\Before the first change:
        \\
        \\1. Say what the finished work looks like. One sentence.
        \\2. Name the files you expect to touch. Read them.
        \\3. Say what could go wrong with the approach you picked. If a
        \\   second approach is close, say why you did not pick it.
        \\
        \\Then start. Do not plan a second time: a plan you keep rewriting is
        \\a task you have not started.
        ,
    },
    .{
        .name = "stop-when-done",
        .description = "Say what you did and stop. Do not keep working after the task is finished.",
        .body =
        \\# Stop when done, and say what you did
        \\
        \\A finished task needs a last message and no more tool calls. Small
        \\models trail off, or repeat a call that already worked, or start
        \\improving something nobody asked about.
        \\
        \\You are done when:
        \\
        \\* The change is in the files, not in your answer.
        \\* The build or the test command the prompt names still passes.
        \\* You committed the work with git.
        \\
        \\Then write one short message: what you changed, in which files, and
        \\anything the user has to know. Do not summarize the whole session.
        \\
        \\If you cannot finish, say that instead, and say what stopped you.
        \\An honest report of a half finished task is worth more than a
        \\confident report of a task you did not do.
        ,
    },
    .{
        .name = "read-before-editing",
        .description = "Read a file before you edit it, and pass the file_hash you were given.",
        .body =
        \\# Read before you edit
        \\
        \\`edit_file` replaces one exact piece of text. An edit built on text
        \\you guessed at, rather than text you read, is refused at best and a
        \\corrupt merge at worst.
        \\
        \\* Call `read_file` first. It gives you a `file_hash`.
        \\* Pass that `file_hash` back to `edit_file`. An edit against a file
        \\  that changed after you read it is then refused, and nothing is
        \\  written.
        \\* Give enough surrounding text that `old_string` appears exactly
        \\  once. A call whose `old_string` appears twice writes nothing.
        \\
        \\Prefer `edit_file` over `write_file` for a file that already exists.
        \\A small change is easier for a person to review than a whole file,
        \\and a person has to approve this work before it reaches them.
        ,
    },
    .{
        .name = "test-first-where-cheap",
        .description = "Write the failing test first when a test is cheap, then make it pass.",
        .body =
        \\# Test first where a test is cheap
        \\
        \\A test written first tells you when you are done. A test written
        \\afterwards tells you what the code already does, which you knew.
        \\
        \\Do this when a test is cheap: a pure function, a parser, a format,
        \\an error case. Skip it when the setup costs more than the change.
        \\
        \\1. Write the test. Name the fact it pins, not the function it
        \\   calls.
        \\2. Run it. **Watch it fail.** A test that passed before you wrote
        \\   the code is a test that pins nothing.
        \\3. Write the code. Run it again.
        \\
        \\Step 2 is the one people skip and it is the one that has value.
        ,
    },
    .{
        .name = "save-what-you-learned",
        .description = "Write a knowledgebase entry for anything a fresh agent would waste time re-deriving.",
        .body =
        \\# Save what you learned
        \\
        \\Use `write_memory` when this is true: **would a competent agent
        \\starting fresh on this project waste time working this out again?**
        \\That is the whole rule.
        \\
        \\It says yes to:
        \\
        \\* A fact that cost effort to find. A surprising behaviour, an
        \\  ordering that matters.
        \\* **A dead end.** "We tried X, it does not work, because Y" saves
        \\  the next agent the whole detour, and nobody thinks to write it
        \\  down. This is the most valuable entry you can write.
        \\* A decision and the reason behind it. The reason ages better than
        \\  the decision.
        \\* A project convention that is real and written nowhere.
        \\* Where the test server is, or what the build actually needs.
        \\
        \\It says no to what the repository already records: the code, the
        \\history, the tests, the task, and the current status.
        \\
        \\**Write a fact, not a status.** "The kernel takes the last matching
        \\mount" stays true. "The build is broken" is false in minutes.
        \\
        \\**Correcting an entry beats adding one.** If an entry is wrong,
        \\write the same name again with the right body. A read then gives
        \\your new version, so two entries that disagree never reach the next
        \\agent. The versions before it stay in the file, so a correction
        \\costs nothing and takes nothing away.
        \\
        \\When it is close, write it. A weak entry costs one line and can be
        \\deleted in a moment. An insight never written is gone, and nobody
        \\knows it is missing.
        ,
    },
};

/// The index the prompt carries: one line per piece.
pub fn indexEntries(allocator: std.mem.Allocator) std.mem.Allocator.Error![]index.Entry {
    const out = try allocator.alloc(index.Entry, pieces.len);
    for (&pieces, out) |piece, *line| {
        line.* = .{ .name = piece.name, .description = piece.description };
    }
    return out;
}

/// The whole of one piece, or null for a name that is not on the shelf.
pub fn find(name: []const u8) ?Piece {
    for (&pieces) |piece| {
        if (std.mem.eql(u8, piece.name, name)) return piece;
    }
    return null;
}

/// Every name on the shelf, joined, for the message a `read_guidance` call
/// with an unknown name gets back. Built at comptime from the shelf itself,
/// so a piece that is added cannot be missing from the message.
pub const names_text = blk: {
    var text: []const u8 = "";
    for (pieces) |piece| {
        if (text.len != 0) text = text ++ ", ";
        text = text ++ piece.name;
    }
    break :blk text;
};

const testing = std.testing;

test "every piece has a name, a one line description, and a body" {
    const allocator = testing.allocator;
    for (&pieces) |piece| {
        try testing.expect(piece.name.len != 0);
        try testing.expect(piece.body.len != 0);

        // The description is the whole cost of a piece nobody reads, so it
        // has to be one line and it has to be short.
        try testing.expect(std.mem.indexOfScalar(u8, piece.description, '\n') == null);
        const flat = try index.oneLine(allocator, piece.description);
        defer allocator.free(flat);
        try testing.expectEqualStrings(piece.description, flat);
    }
}

test "no two pieces share a name, so a fetch is never ambiguous" {
    for (&pieces, 0..) |a, i| {
        for (pieces[i + 1 ..]) |b| {
            try testing.expect(!std.mem.eql(u8, a.name, b.name));
        }
    }
}

test "a piece the model never reads costs one line and its body is not in the index" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const entries = try indexEntries(arena);
    try testing.expectEqual(pieces.len, entries.len);

    var out: std.ArrayList(u8) = .empty;
    try index.renderInto(arena, &out, entries);
    try testing.expectEqual(pieces.len, std.mem.count(u8, out.items, "\n"));

    var body_bytes: usize = 0;
    for (&pieces) |piece| body_bytes += piece.body.len;
    try testing.expect(out.items.len * 4 < body_bytes);
}

test "a name on the shelf is found, and one that is not is null rather than a crash" {
    try testing.expect(find("plan-before-acting") != null);
    try testing.expect(find("a-piece-nobody-wrote") == null);
    try testing.expect(std.mem.indexOf(u8, names_text, "plan-before-acting") != null);
}

test "the shelf names no tool this build does not offer" {
    // A piece that told the agent to use a subagent, or to fetch a URL,
    // would cost a turn to find out the tool is not there. The tool list is
    // read from `tools.zig` itself so this cannot drift.
    const core_tools = @import("tools.zig");
    const forbidden = [_][]const u8{ "spawn_subagent", "web_fetch", "read_image" };

    for (&pieces) |piece| {
        for (forbidden) |name| {
            if (std.mem.indexOf(u8, piece.body, name) != null) {
                // **The failure names the piece and prints its body.**
                // `expectEqualStrings` shows both sides, so a reader sees
                // where the word that is not a tool actually sits. A write to
                // the terminal would put a `failed command:` line in the
                // build log of every passing run of this suite.
                try std.testing.expectEqualStrings(piece.name, piece.body);
                return error.GuidanceNamesSomethingThatIsNotATool;
            }
        }
    }

    // And every tool a piece does name is real. Checked by the enum, so a
    // tool that is renamed leaves a piece of guidance naming the old one and
    // this notices.
    const named = [_][]const u8{ "read_file", "edit_file", "write_file", "write_memory" };
    for (named) |name| {
        try testing.expect(std.meta.stringToEnum(core_tools.Tool, name) != null);
    }
}
