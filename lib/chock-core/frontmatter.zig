//! The YAML frontmatter a markdown file opens with, read the one way. Skills
//! and commands are different formats over the same frontmatter, so they share
//! this reader and cannot read a file differently.

const std = @import("std");

pub const fence = "---";

pub const Pair = struct {
    key: []const u8,
    value: []const u8,
};

pub const Split = struct {
    frontmatter: []const u8,
    body: []const u8,
};

/// Whether the first line with anything on it is a fence. A file that opens
/// one and never closes it is a different fault from a file with no
/// frontmatter at all.
pub fn opens(bytes: []const u8) bool {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t\r");
        if (trimmed.len == 0) continue;
        return std.mem.eql(u8, trimmed, fence);
    }
    return false;
}

pub fn split(bytes: []const u8) ?Split {
    var at: usize = 0;
    while (nextLine(bytes, &at)) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        if (!std.mem.eql(u8, trimmed, fence)) return null;
        break;
    }

    const starts = at;
    while (true) {
        const before = at;
        const line = nextLine(bytes, &at) orelse return null;
        if (!std.mem.eql(u8, std.mem.trim(u8, line, " \t\r"), fence)) continue;
        return .{ .frontmatter = bytes[starts..before], .body = bytes[at..] };
    }
}

pub fn nextLine(bytes: []const u8, at: *usize) ?[]const u8 {
    if (at.* >= bytes.len) return null;
    const rest = bytes[at.*..];
    const end = std.mem.indexOfScalar(u8, rest, '\n') orelse {
        at.* = bytes.len;
        return rest;
    };
    at.* += end + 1;
    return rest[0..end];
}

/// One frontmatter line that holds something. `pair` is null for a line the
/// reader takes nothing from, which a loader skips and a report names.
pub const Item = struct {
    line: usize,
    text: []const u8,
    pair: ?Pair = null,
    /// The line sits under the key that nests.
    nested: bool = false,
    /// The line is that key, so neither reader takes it for a field.
    nests: bool = false,
};

/// Every line of a frontmatter that holds something, blank lines and comments
/// left out. `nests` names the one key whose indented lines belong to it, and
/// an empty name gives a format with no nesting at all.
pub const Walk = struct {
    lines: std.mem.SplitIterator(u8, .scalar),
    nests: []const u8,
    line: usize,
    under: ?usize = null,

    pub fn next(self: *Walk) ?Item {
        while (self.lines.next()) |raw_line| {
            const line = self.line;
            self.line += 1;

            const raw = std.mem.trimEnd(u8, raw_line, "\r");
            const text = std.mem.trim(u8, raw, " \t");
            if (text.len == 0 or text[0] == '#') continue;
            const indent = indentOf(raw);

            if (self.under) |over| {
                if (indent > over) {
                    return .{
                        .line = line,
                        .text = text,
                        .pair = pairOf(text),
                        .nested = true,
                    };
                }
                self.under = null;
            }

            const pair = if (indent == 0) pairOf(text) else null;
            const named = pair orelse return .{ .line = line, .text = text };

            if (self.nests.len != 0 and std.mem.eql(u8, named.key, self.nests)) {
                if (named.value.len == 0) self.under = indent;
                return .{ .line = line, .text = text, .pair = named, .nests = true };
            }
            return .{ .line = line, .text = text, .pair = named };
        }
        return null;
    }
};

/// `bytes` is the whole file, so the line numbers count from its first line.
pub fn walk(bytes: []const u8, frontmatter: []const u8, nests: []const u8) Walk {
    return .{
        .lines = std.mem.splitScalar(u8, frontmatter, '\n'),
        .nests = nests,
        .line = lineOf(bytes, frontmatter),
    };
}

/// A name of lowercase letters, digits and single hyphens between them. Both
/// formats use it, so a name that works in one works in the other.
pub fn isTheShape(name: []const u8) bool {
    if (name.len == 0) return false;
    if (name[0] == '-' or name[name.len - 1] == '-') return false;
    for (name, 0..) |byte, at| {
        switch (byte) {
            'a'...'z', '0'...'9' => {},
            '-' => if (at != 0 and name[at - 1] == '-') return false,
            else => return false,
        }
    }
    return true;
}

pub fn indentOf(raw: []const u8) usize {
    var count: usize = 0;
    while (count < raw.len and raw[count] == ' ') count += 1;
    return count;
}

pub fn pairOf(text: []const u8) ?Pair {
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return null;
    const key = unquote(std.mem.trim(u8, text[0..colon], " \t"));
    if (key.len == 0) return null;
    return .{ .key = key, .value = unquote(std.mem.trim(u8, text[colon + 1 ..], " \t")) };
}

pub fn unquote(value: []const u8) []const u8 {
    if (value.len < 2) return value;
    const first = value[0];
    if (first != '"' and first != '\'') return value;
    if (value[value.len - 1] != first) return value;
    return value[1 .. value.len - 1];
}

/// The 1 based line in `bytes` that `part` starts on.
pub fn lineOf(bytes: []const u8, part: []const u8) usize {
    const offset = @intFromPtr(part.ptr) - @intFromPtr(bytes.ptr);
    return 1 + std.mem.count(u8, bytes[0..offset], "\n");
}

/// A YAML value that is only `|` or `>` with its indicators. YAML folds the lines
/// under it into the value, and the reader here keeps the marker instead.
pub fn isBlockMarker(value: []const u8) bool {
    if (value.len == 0) return false;
    if (value[0] != '|' and value[0] != '>') return false;
    for (value[1..]) |byte| switch (byte) {
        '-', '+', '0'...'9' => {},
        else => return false,
    };
    return true;
}

pub fn cut(
    allocator: std.mem.Allocator,
    value: []const u8,
    limit: usize,
) std.mem.Allocator.Error![]const u8 {
    if (value.len <= limit) return try allocator.dupe(u8, value);
    return try std.fmt.allocPrint(allocator, "{s}...", .{value[0..limit]});
}

const testing = std.testing;

test "a file opens frontmatter, and one that does not is told apart from one that never closes it" {
    try testing.expect(opens("---\nname: a\n---\n"));
    try testing.expect(opens("\n\n---\nname: a\n"));
    try testing.expect(!opens("# A title\n---\n"));

    const closed = split("---\nname: a\n---\nbody\n") orelse return error.TestExpectedSplit;
    try testing.expectEqualStrings("name: a\n", closed.frontmatter);
    try testing.expectEqualStrings("body\n", closed.body);

    try testing.expect(split("---\nname: a\n") == null);
    try testing.expect(split("# A title\nname: a\n") == null);
}

test "the walk gives every line that holds something, with the ones it reads nothing from" {
    const bytes =
        \\---
        \\name: one
        \\# a comment
        \\
        \\not a pair
        \\  indented: and not under anything
        \\metadata:
        \\  key: value
        \\description: after the nesting ends
        \\---
        \\
    ;
    const parts = split(bytes) orelse return error.TestExpectedSplit;
    var items = walk(bytes, parts.frontmatter, "metadata");

    const first = items.next() orelse return error.TestExpectedItem;
    try testing.expectEqual(@as(usize, 2), first.line);
    try testing.expectEqualStrings("one", first.pair.?.value);

    const loose = items.next() orelse return error.TestExpectedItem;
    try testing.expectEqual(@as(usize, 5), loose.line);
    try testing.expect(loose.pair == null);

    const stray = items.next() orelse return error.TestExpectedItem;
    try testing.expectEqual(@as(usize, 6), stray.line);
    try testing.expect(stray.pair == null);

    const nests_here = items.next() orelse return error.TestExpectedItem;
    try testing.expect(nests_here.nests);

    const under = items.next() orelse return error.TestExpectedItem;
    try testing.expect(under.nested);
    try testing.expectEqualStrings("key", under.pair.?.key);

    const after = items.next() orelse return error.TestExpectedItem;
    try testing.expect(!after.nested);
    try testing.expectEqualStrings("description", after.pair.?.key);

    try testing.expect(items.next() == null);
}

test "a format with no nesting reads an indented line as a line it takes nothing from" {
    const bytes =
        \\---
        \\metadata:
        \\  key: value
        \\---
        \\
    ;
    const parts = split(bytes) orelse return error.TestExpectedSplit;
    var items = walk(bytes, parts.frontmatter, "");

    const named = items.next() orelse return error.TestExpectedItem;
    try testing.expect(!named.nests);
    try testing.expectEqualStrings("metadata", named.pair.?.key);

    const indented = items.next() orelse return error.TestExpectedItem;
    try testing.expect(!indented.nested);
    try testing.expect(indented.pair == null);
}

test "a name holds lowercase letters, digits and single hyphens between them" {
    try testing.expect(isTheShape("review-a-diff"));
    try testing.expect(isTheShape("fix2"));
    try testing.expect(!isTheShape(""));
    try testing.expect(!isTheShape("-leading"));
    try testing.expect(!isTheShape("trailing-"));
    try testing.expect(!isTheShape("two--hyphens"));
    try testing.expect(!isTheShape("Upper"));
    try testing.expect(!isTheShape("with space"));
}

test "a pair loses its quotes, and a block marker is seen for what it is" {
    const pair = pairOf("description: \"what it does\"") orelse return error.TestExpectedPair;
    try testing.expectEqualStrings("description", pair.key);
    try testing.expectEqualStrings("what it does", pair.value);
    try testing.expect(pairOf("no colon here") == null);
    try testing.expect(pairOf(": value with no key") == null);

    try testing.expect(isBlockMarker("|"));
    try testing.expect(isBlockMarker(">-"));
    try testing.expect(isBlockMarker("|2"));
    try testing.expect(!isBlockMarker("| and then words"));
    try testing.expect(!isBlockMarker(""));
}

test "a detail longer than the limit is cut and marked" {
    const gpa = testing.allocator;

    const short = try cut(gpa, "brief", 16);
    defer gpa.free(short);
    try testing.expectEqualStrings("brief", short);

    const long = try cut(gpa, "0123456789abcdefghij", 10);
    defer gpa.free(long);
    try testing.expectEqualStrings("0123456789...", long);
}
