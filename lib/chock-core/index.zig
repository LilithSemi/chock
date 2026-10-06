//! The index: one line per thing that exists in the system prompt, and a
//! tool that fetches the body of one when the model decides it applies.

const std = @import("std");

pub const Entry = struct {
    name: []const u8,
    description: []const u8,
};

pub const max_description_bytes: usize = 160;

pub const cut_marker = "...";

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

    var keep = max_description_bytes - cut_marker.len;
    while (keep != 0 and flat.items[keep] & 0xC0 == 0x80) keep -= 1;

    flat.shrinkRetainingCapacity(keep);
    try flat.appendSlice(allocator, cut_marker);
    return flat.toOwnedSlice(allocator);
}

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
