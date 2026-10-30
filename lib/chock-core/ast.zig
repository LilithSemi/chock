//! The syntax tree Chock asks about, and the answer it reads back. There is
//! one parser that runs a program and another that runs a WebAssembly module,
//! and they share this file, so a rule means the same thing whichever of them
//! answered it.

const std = @import("std");

/// A file with more matches than this is a file whose rules have already
/// failed, so the count is a refusal and never a truncation.
pub const max_matches: usize = 4096;

pub const max_query_bytes: usize = 1 << 16;
pub const max_source_bytes: usize = 1 << 20;

pub const Error = std.mem.Allocator.Error || error{
    TooManyMatches,
    SourceTooLarge,
    QueryTooLarge,
    LanguageNotKnown,
    ParserFailed,
    Late,
};

pub const Match = struct {
    capture: []const u8,
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,

    /// Lines the match covers. One row is one line, so this is never zero.
    pub fn lines(self: Match) u32 {
        return self.end_line - self.start_line + 1;
    }
};

pub const Matches = []const Match;

/// What a parser is asked. The source is bytes and not a path, so a parser
/// that needs no filesystem never reaches one.
pub const Query = struct {
    language: []const u8,
    source: []const u8,
    query_text: []const u8,
    deadline: std.Io.Clock.Timestamp,
};

pub const Parser = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        run: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            io: std.Io,
            query: Query,
        ) Error!Matches,
    };

    pub fn run(
        self: Parser,
        arena: std.mem.Allocator,
        io: std.Io,
        query: Query,
    ) Error!Matches {
        return self.vtable.run(self.ptr, arena, io, query);
    }
};

/// Read what `tree-sitter query` writes. A capture comes two ways: with its
/// index in the query and the matched text, for a node on one row, and with
/// the name by itself for a node that covers more than one row. The second is
/// what a rule about long blocks sees, so both are read here.
///
/// Nothing after `end:` is looked at, which is why matched text holding a
/// bracket or a backtick cannot confuse this.
pub fn matchesFrom(arena: std.mem.Allocator, text: []const u8) Error!Matches {
    var found: std.ArrayList(Match) = .empty;
    errdefer found.deinit(arena);

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (!std.mem.startsWith(u8, line, "capture: ")) continue;
        const one = matchIn(line) orelse continue;
        if (found.items.len == max_matches) return error.TooManyMatches;
        try found.append(arena, one);
    }
    return found.toOwnedSlice(arena);
}

fn matchIn(line: []const u8) ?Match {
    const after_capture = line["capture: ".len..];
    const comma = std.mem.indexOfScalar(u8, after_capture, ',') orelse return null;
    const field = after_capture[0..comma];
    const name = if (std.mem.lastIndexOf(u8, field, " - ")) |dash|
        field[dash + 3 ..]
    else
        field;
    if (name.len == 0) return null;

    const rest = after_capture[comma..];
    const start = pointAfter(rest, "start: (") orelse return null;
    const end = pointAfter(rest, "end: (") orelse return null;
    if (end[0] < start[0]) return null;
    return .{
        .capture = name,
        .start_line = start[0],
        .start_column = start[1],
        .end_line = end[0],
        .end_column = end[1],
    };
}

fn pointAfter(text: []const u8, label: []const u8) ?[2]u32 {
    const at = std.mem.indexOf(u8, text, label) orelse return null;
    const inside = text[at + label.len ..];
    const close = std.mem.indexOfScalar(u8, inside, ')') orelse return null;
    var parts = std.mem.splitSequence(u8, inside[0..close], ", ");
    const row = numberIn(parts.next() orelse return null) orelse return null;
    const column = numberIn(parts.next() orelse return null) orelse return null;
    if (parts.next() != null) return null;
    return .{ row, column };
}

fn numberIn(field: []const u8) ?u32 {
    return std.fmt.parseInt(u32, std.mem.trim(u8, field, " \t"), 10) catch null;
}

const testing = std.testing;

/// Verbatim from `tree-sitter query` 0.26.11 over a five line Zig file with
/// `(comment) @c` and `(function_declaration) @fn`.
const real_two_forms =
    \\tiny.zig
    \\  pattern: 0
    \\    capture: 0 - c, start: (0, 0), end: (0, 7), text: `//! one`
    \\  pattern: 0
    \\    capture: 0 - c, start: (1, 0), end: (1, 7), text: `//! two`
    \\  pattern: 1
    \\    capture: fn, start: (2, 0), end: (4, 1)
    \\  pattern: 0
    \\    capture: 0 - c, start: (3, 4), end: (3, 13), text: `// inside`
    \\
;

test "a node covering rows prints no index and no text, and both forms read the same" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const got = try matchesFrom(arena, real_two_forms);
    try testing.expectEqual(@as(usize, 4), got.len);

    try testing.expectEqualStrings("c", got[0].capture);
    try testing.expectEqual(@as(u32, 0), got[0].start_line);
    try testing.expectEqual(@as(u32, 0), got[0].end_line);
    try testing.expectEqual(@as(u32, 1), got[0].lines());

    // The form a rule about long blocks sees: a name, no index, no text.
    try testing.expectEqualStrings("fn", got[2].capture);
    try testing.expectEqual(@as(u32, 2), got[2].start_line);
    try testing.expectEqual(@as(u32, 0), got[2].start_column);
    try testing.expectEqual(@as(u32, 4), got[2].end_line);
    try testing.expectEqual(@as(u32, 1), got[2].end_column);
    try testing.expectEqual(@as(u32, 3), got[2].lines());

    try testing.expectEqualStrings("c", got[3].capture);
    try testing.expectEqual(@as(u32, 3), got[3].start_line);
    try testing.expectEqual(@as(u32, 13), got[3].end_column);
}

test "the index before a capture's name is its place in the query" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The same query with its patterns the other way round, so `@c` is
    // capture 1. The name is what a rule is about, so the index is dropped.
    const swapped =
        \\tiny.zig
        \\  pattern: 1
        \\    capture: 1 - c, start: (0, 0), end: (0, 7), text: `//! one`
        \\
    ;
    const got = try matchesFrom(arena, swapped);
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqualStrings("c", got[0].capture);
}

test "matched text holding a bracket cannot confuse the reader" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const awkward =
        \\a.zig
        \\  pattern: 0
        \\    capture: 0 - c, start: (0, 0), end: (0, 20), text: `// end: (9, 9) `
        \\
    ;
    const got = try matchesFrom(arena, awkward);
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqual(@as(u32, 0), got[0].start_line);
    try testing.expectEqual(@as(u32, 20), got[0].end_column);
}

test "no match is no match, and a line the reader cannot use is left out" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqual(@as(usize, 0), (try matchesFrom(arena, "")).len);
    try testing.expectEqual(@as(usize, 0), (try matchesFrom(arena, "a.zig\n")).len);
    try testing.expectEqual(
        @as(usize, 0),
        (try matchesFrom(arena, "  capture: c, start: (bad), end: (0, 1)\n")).len,
    );
    try testing.expectEqual(
        @as(usize, 0),
        (try matchesFrom(arena, "  capture: , start: (0, 0), end: (0, 1)\n")).len,
    );
    // An end before its start is not a span this reader will answer with.
    try testing.expectEqual(
        @as(usize, 0),
        (try matchesFrom(arena, "  capture: c, start: (4, 0), end: (2, 1)\n")).len,
    );
}

test "a reply with more matches than the bound is refused and never cut short" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var many: std.ArrayList(u8) = .empty;
    defer many.deinit(testing.allocator);
    for (0..max_matches + 1) |_| {
        try many.appendSlice(
            testing.allocator,
            "    capture: 0 - c, start: (0, 0), end: (0, 1)\n",
        );
    }
    try testing.expectError(error.TooManyMatches, matchesFrom(arena, many.items));
}
