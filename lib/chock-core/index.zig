//! The index: one line per thing that exists, in the system prompt, and a
//! tool that fetches the body of one when the model decides it applies.
//!
//! **This is one mechanism with three users**, and building it once is the
//! whole point. The prompt is short and every line is justified; a
//! knowledgebase of two hundred entries, or a shelf of guidance documents,
//! cannot live in a prompt that follows that rule. So the prompt names what
//! exists and nothing more:
//!
//! | Source | The index line | Fetched with |
//! |---|---|---|
//! | guidance shipped with Chock | one per piece | `read_guidance` |
//! | the knowledgebase | one per entry | `read_memory` |
//! | an `AGENTS.md` in a subdirectory | one per file | `read_file` |
//!
//! The prompt then grows by about one line per thing, never one paragraph,
//! and a piece of guidance the model never reads costs its one line and
//! nothing else.
//!
//! **A description is one line, always.** A description that carried a
//! newline would turn one index entry into two lines of prompt, and a
//! description nobody bounded would turn it into a paragraph. Both faults
//! break the size property the whole design rests on, and both are quiet:
//! the prompt simply gets bigger and nothing fails. `oneLine` is what stops
//! them, and it runs over every description, whoever wrote it.

const std = @import("std");

/// One line of the index: what the thing is called, and what it is.
pub const Entry = struct {
    /// How the thing is fetched. Short and stable.
    name: []const u8,
    /// What it is, in one line. Pass it through `oneLine` before it reaches
    /// here if anything other than Chock itself wrote it.
    description: []const u8,
};

/// The longest description an index line carries. Past this, `oneLine` cuts
/// and marks the cut. Chosen so a full index line stays inside one terminal
/// width, which is also about as much as a model needs to decide whether to
/// fetch the body.
pub const max_description_bytes: usize = 160;

/// What `oneLine` puts at the end of a description it had to cut, so a
/// reader can tell a short description from a shortened one.
pub const cut_marker = "...";

/// `text` as exactly one line, no longer than `max_description_bytes`.
///
/// Every newline, carriage return, and tab becomes a space, runs of spaces
/// collapse, and the ends are trimmed. A description that is still too long
/// is cut and `cut_marker` is put on the end.
///
/// **Run this over anything Chock did not write itself.** A description in a
/// knowledgebase entry comes from the agent, and one for an `AGENTS.md`
/// comes from whoever wrote the repository. Neither is trusted to keep to
/// one line, and neither has to be: this makes it one.
///
/// Caller owns the result and frees it with `allocator.free`.
pub fn oneLine(allocator: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]u8 {
    var flat: std.ArrayList(u8) = .empty;
    errdefer flat.deinit(allocator);

    var last_was_space = true;
    for (text) |byte| {
        const is_space = byte == ' ' or byte == '\n' or byte == '\r' or byte == '\t';
        if (is_space) {
            if (!last_was_space) try flat.append(allocator, ' ');
            last_was_space = true;
            continue;
        }
        try flat.append(allocator, byte);
        last_was_space = false;
    }
    while (flat.items.len != 0 and flat.items[flat.items.len - 1] == ' ') _ = flat.pop();

    if (flat.items.len <= max_description_bytes) return flat.toOwnedSlice(allocator);

    // Cut on a UTF-8 boundary, so the description stays text. A tool result
    // and a system prompt both travel as a JSON string, and half of a
    // multi byte character is not one: `lib/chock-core/tools.zig`'s own
    // `outputForModel` records what a provider does with bytes that are not
    // valid UTF-8.
    var keep = max_description_bytes - cut_marker.len;
    while (keep != 0 and flat.items[keep] & 0xC0 == 0x80) keep -= 1;

    flat.shrinkRetainingCapacity(keep);
    try flat.appendSlice(allocator, cut_marker);
    return flat.toOwnedSlice(allocator);
}

/// The first line of `text` that says something, for a file whose author
/// never wrote a description of it. A Markdown heading loses its `#` and its
/// spaces, so `# Build rules` reads as `Build rules`.
///
/// Answers an empty slice for a file with nothing in it. The caller decides
/// what an empty description means; this does not invent one.
///
/// The result is a slice of `text` and is not allocated. Pass it through
/// `oneLine` before it becomes an index entry.
pub fn firstMeaningfulLine(text: []const u8) []const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        var line = std.mem.trim(u8, raw, " \t\r");
        while (line.len != 0 and line[0] == '#') line = line[1..];
        line = std.mem.trim(u8, line, " \t\r");
        if (line.len != 0) return line;
    }
    return "";
}

/// Write `entries` as an index: one `- name: description` line each.
///
/// **This never writes a body**, and there is nowhere in this function for
/// one to arrive. That is the property the size test in `prompt.zig` pins,
/// and it is the one a later change would break in silence.
pub fn renderInto(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    entries: []const Entry,
) std.mem.Allocator.Error!void {
    for (entries) |entry| {
        try out.appendSlice(allocator, "- ");
        try out.appendSlice(allocator, entry.name);
        if (entry.description.len != 0) {
            try out.appendSlice(allocator, ": ");
            try out.appendSlice(allocator, entry.description);
        }
        try out.append(allocator, '\n');
    }
}

/// The longest one index line can be: the two byte bullet, the name, the two
/// byte separator, the description, and the newline. A caller that wants to
/// bound the prompt against the entry count needs this number, and reading
/// it from here rather than writing it out again is what keeps the two in
/// step.
pub fn maxLineBytes(max_name_bytes: usize) usize {
    return "- ".len + max_name_bytes + ": ".len + max_description_bytes + "\n".len;
}

const testing = std.testing;

test "a description with newlines in it becomes one line, so one entry costs one line" {
    const allocator = testing.allocator;
    const flat = try oneLine(allocator, "a fact\nabout\r\nthe build\t\tsystem  ");
    defer allocator.free(flat);

    try testing.expectEqualStrings("a fact about the build system", flat);
    try testing.expect(std.mem.indexOfScalar(u8, flat, '\n') == null);
}

test "a description past the bound is cut, and the cut is marked" {
    const allocator = testing.allocator;
    const long = "x" ** (max_description_bytes * 3);
    const flat = try oneLine(allocator, long);
    defer allocator.free(flat);

    try testing.expect(flat.len <= max_description_bytes);
    try testing.expect(std.mem.endsWith(u8, flat, cut_marker));
}

test "a cut description is still valid text, never half of a character" {
    const allocator = testing.allocator;
    const long = "\u{00e9}" ** (max_description_bytes * 2);
    const flat = try oneLine(allocator, long);
    defer allocator.free(flat);

    try testing.expect(std.unicode.utf8ValidateSlice(flat));
    try testing.expect(flat.len <= max_description_bytes);
}

test "the index carries names and descriptions, and nothing else" {
    const allocator = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    try renderInto(allocator, &out, &.{
        .{ .name = "mount-order", .description = "the kernel takes the last matching mount" },
        .{ .name = "no-description", .description = "" },
    });

    try testing.expectEqualStrings(
        "- mount-order: the kernel takes the last matching mount\n" ++
            "- no-description\n",
        out.items,
    );
}

test "an index of a hundred entries is a hundred lines" {
    const allocator = testing.allocator;
    var entries: [100]Entry = undefined;
    for (&entries) |*entry| entry.* = .{ .name = "entry", .description = "a description" };

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try renderInto(allocator, &out, &entries);

    try testing.expectEqual(@as(usize, 100), std.mem.count(u8, out.items, "\n"));
    try testing.expect(out.items.len <= 100 * maxLineBytes("entry".len));
}

test "the first meaningful line of a file skips blanks and drops a heading marker" {
    try testing.expectEqualStrings(
        "Build rules",
        firstMeaningfulLine("\n\n#  Build rules  \n\nUse zig build test.\n"),
    );
    try testing.expectEqualStrings("", firstMeaningfulLine("\n \n\t\n"));
}
