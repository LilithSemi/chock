//! A rule and what a parser found, turned into one answer. Arithmetic only, so
//! the answer is the same whichever parser ran and a disagreement between the
//! two is a fault in a parser rather than in a rule.

const std = @import("std");

const ast = @import("ast.zig");
const chock_policy = @import("chock-policy");

const style = chock_policy.style;

/// The tool a rule answers for, and the action that permits a parse. A rule
/// runs a parser, so the policy table decides whether any rule runs at all.
pub const policy_tool = "style";
pub const parse_action = "style.parse";

pub const Verdict = struct {
    /// False when the rule is broken, whatever the rule then does about it.
    permitted: bool,
    /// True when the write goes ahead anyway, which is what a reported rule
    /// means.
    lands: bool,
    /// The number the bound was compared against, for the sentence the model
    /// reads: a count of matches, a span of lines, or a share.
    worst: u32 = 0,
    /// One based, because a person and a model both count lines from one and
    /// a row from a syntax tree starts at zero. Zero means no line to name.
    first_line: u32 = 0,

    /// What the bound was, so a sentence can say both numbers.
    bound: u32 = 0,
};

/// Lines covered by at least one match, counted once each. Two matches over
/// the same lines are those lines and not twice them.
///
/// The spans are sorted first. A query cursor walks a tree, so a parent's
/// match can arrive before a child's and a later row before an earlier one,
/// and a sweep that trusted the order would undercount.
pub fn countedLines(arena: std.mem.Allocator, matches: ast.Matches) error{OutOfMemory}!u32 {
    if (matches.len == 0) return 0;

    const spans = try arena.alloc(Span, matches.len);
    defer arena.free(spans);
    for (matches, spans) |one, *span| {
        span.* = .{ .from = one.start_line, .to = one.end_line };
    }
    std.mem.sort(Span, spans, {}, Span.before);

    var total: u32 = 0;
    var from = spans[0].from;
    var to = spans[0].to;
    for (spans[1..]) |span| {
        // A span touching the one held extends it. One apart from it closes it.
        if (span.from <= to + 1) {
            to = @max(to, span.to);
            continue;
        }
        total += to - from + 1;
        from = span.from;
        to = span.to;
    }
    return total + to - from + 1;
}

const Span = struct {
    from: u32,
    to: u32,

    fn before(_: void, lhs: Span, rhs: Span) bool {
        if (lhs.from != rhs.from) return lhs.from < rhs.from;
        return lhs.to < rhs.to;
    }
};

pub fn verdictFor(
    arena: std.mem.Allocator,
    rule: style.Rule,
    matches: ast.Matches,
    file_lines: u32,
) error{OutOfMemory}!Verdict {
    const lands = rule.decision == .report;
    switch (rule.bound) {
        .max_matches => |bound| {
            const count: u32 = @intCast(matches.len);
            if (count <= bound) return .{ .permitted = true, .lands = true, .bound = bound };
            return .{
                .permitted = false,
                .lands = lands,
                .worst = count,
                .first_line = matches[bound].start_line + 1,
                .bound = bound,
            };
        },
        .max_lines => |bound| {
            for (matches) |one| {
                const covered = one.lines();
                if (covered > bound) return .{
                    .permitted = false,
                    .lands = lands,
                    .worst = covered,
                    .first_line = one.start_line + 1,
                    .bound = bound,
                };
            }
            return .{ .permitted = true, .lands = true, .bound = bound };
        },
        .max_share => |bound| {
            if (file_lines == 0 or matches.len == 0) {
                return .{ .permitted = true, .lands = true, .bound = bound };
            }
            const covered = try countedLines(arena, matches);
            const share: u32 = @intCast(@min(
                @as(u64, 100),
                @as(u64, covered) * 100 / @as(u64, file_lines),
            ));
            if (share <= bound) return .{ .permitted = true, .lands = true, .bound = bound };
            return .{
                .permitted = false,
                .lands = lands,
                .worst = share,
                .first_line = matches[0].start_line + 1,
                .bound = bound,
            };
        },
    }
}

/// Lines in the content a write would leave behind. A file with no closing
/// newline still has a last line.
pub fn linesIn(content: []const u8) u32 {
    if (content.len == 0) return 0;
    var total: u32 = 0;
    for (content) |byte| {
        if (byte == '\n') total += 1;
    }
    if (content[content.len - 1] != '\n') total += 1;
    return total;
}

/// The sentence a refusal carries. It names the rule and the line and never
/// the matched source: that text is the agent's own, and a line number is
/// what it needs to fix the file in this turn.
pub fn saidAbout(
    arena: std.mem.Allocator,
    tool: []const u8,
    rule: style.Rule,
    verdict: Verdict,
) std.mem.Allocator.Error![]u8 {
    const what = switch (rule.bound) {
        .max_matches => try std.fmt.allocPrint(
            arena,
            "{d} matches, and the rule permits {d}",
            .{ verdict.worst, verdict.bound },
        ),
        .max_lines => try std.fmt.allocPrint(
            arena,
            "a match covers {d} lines, and the rule permits {d}",
            .{ verdict.worst, verdict.bound },
        ),
        .max_share => try std.fmt.allocPrint(
            arena,
            "matches cover {d} percent of the lines, and the rule permits {d}",
            .{ verdict.worst, verdict.bound },
        ),
    };
    return std.fmt.allocPrint(
        arena,
        "{s} {s} the style rule {s}: {s}, first at line {d}.",
        .{
            tool,
            if (rule.decision == .refuse) "was refused by" else "broke",
            rule.name,
            what,
            verdict.first_line,
        },
    );
}

const testing = std.testing;

fn spanning(start: u32, end: u32) ast.Match {
    return .{
        .capture = "c",
        .start_line = start,
        .start_column = 0,
        .end_line = end,
        .end_column = 1,
    };
}

test "a bound is a ceiling and refuses only above itself" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ten: style.Rule = .{
        .name = "comment-block",
        .query = "c.scm",
        .bound = .{ .max_lines = 10 },
    };

    const ten_lines = [_]ast.Match{spanning(0, 9)};
    try testing.expect((try verdictFor(arena, ten, &ten_lines, 100)).permitted);

    const eleven_lines = [_]ast.Match{spanning(0, 10)};
    const refused = try verdictFor(arena, ten, &eleven_lines, 100);
    try testing.expect(!refused.permitted);
    try testing.expect(!refused.lands);
    try testing.expectEqual(@as(u32, 11), refused.worst);
    try testing.expectEqual(@as(u32, 1), refused.first_line);
    try testing.expectEqual(@as(u32, 10), refused.bound);
}

test "the line a refusal names is the first match that broke the bound" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ten: style.Rule = .{
        .name = "comment-block",
        .query = "c.scm",
        .bound = .{ .max_lines = 10 },
    };
    // The short one is first, so the line named is the long one's.
    const mixed = [_]ast.Match{ spanning(0, 2), spanning(20, 40) };
    const refused = try verdictFor(arena, ten, &mixed, 100);
    try testing.expect(!refused.permitted);
    try testing.expectEqual(@as(u32, 21), refused.worst);
    try testing.expectEqual(@as(u32, 21), refused.first_line);
}

test "a count of zero refuses the first match and names its line" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const none: style.Rule = .{
        .name = "no-shouty-comment",
        .query = "s.scm",
        .bound = .{ .max_matches = 0 },
    };
    try testing.expect((try verdictFor(arena, none, &.{}, 10)).permitted);

    const one = [_]ast.Match{spanning(6, 6)};
    const refused = try verdictFor(arena, none, &one, 10);
    try testing.expect(!refused.permitted);
    try testing.expectEqual(@as(u32, 1), refused.worst);
    try testing.expectEqual(@as(u32, 7), refused.first_line);
}

test "a count above zero names the line of the match that went over" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const two: style.Rule = .{
        .name = "at-most-two",
        .query = "s.scm",
        .bound = .{ .max_matches = 2 },
    };
    const three = [_]ast.Match{ spanning(0, 0), spanning(4, 4), spanning(9, 9) };
    try testing.expect((try verdictFor(arena, two, three[0..2], 20)).permitted);

    const refused = try verdictFor(arena, two, &three, 20);
    try testing.expect(!refused.permitted);
    try testing.expectEqual(@as(u32, 3), refused.worst);
    try testing.expectEqual(@as(u32, 10), refused.first_line);
}

test "a share counts a line once however many matches cover it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const share: style.Rule = .{
        .name = "comment-share",
        .query = "c.scm",
        .bound = .{ .max_share = 40 },
    };

    // Two matches over the same four lines are four lines.
    const overlapping = [_]ast.Match{ spanning(0, 3), spanning(2, 3) };
    try testing.expectEqual(@as(u32, 4), try countedLines(arena, &overlapping));
    try testing.expect((try verdictFor(arena, share, &overlapping, 10)).permitted);

    const refused = try verdictFor(arena, share, &overlapping, 9);
    try testing.expect(!refused.permitted);
    try testing.expectEqual(@as(u32, 44), refused.worst);

    // Matches apart from each other add up.
    const apart = [_]ast.Match{ spanning(0, 1), spanning(5, 6) };
    try testing.expectEqual(@as(u32, 4), try countedLines(arena, &apart));
}

test "matches out of order are counted right, because a cursor does not sort them" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A query cursor walks a tree, so a later row can arrive first. Both of
    // these cover four lines whatever order they come in.
    const forwards = [_]ast.Match{ spanning(0, 1), spanning(5, 6) };
    const backwards = [_]ast.Match{ spanning(5, 6), spanning(0, 1) };
    try testing.expectEqual(@as(u32, 4), try countedLines(arena, &forwards));
    try testing.expectEqual(@as(u32, 4), try countedLines(arena, &backwards));

    // A parent arriving before the child inside it is one span, not two.
    const nested = [_]ast.Match{ spanning(0, 9), spanning(3, 4) };
    try testing.expectEqual(@as(u32, 10), try countedLines(arena, &nested));

    // Two spans one line apart are one run, because the line between them is
    // the only gap and there is none.
    const touching = [_]ast.Match{ spanning(0, 1), spanning(2, 3) };
    try testing.expectEqual(@as(u32, 4), try countedLines(arena, &touching));

    // A real gap stays a gap.
    const gapped = [_]ast.Match{ spanning(0, 0), spanning(2, 2) };
    try testing.expectEqual(@as(u32, 2), try countedLines(arena, &gapped));
}

test "a reported rule is not permitted and still lets the write land" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const reported: style.Rule = .{
        .name = "soft",
        .query = "s.scm",
        .bound = .{ .max_matches = 0 },
        .decision = .report,
    };
    const one = [_]ast.Match{spanning(0, 0)};
    const got = try verdictFor(arena, reported, &one, 10);
    try testing.expect(!got.permitted);
    try testing.expect(got.lands);
}

test "an empty file has no share and refuses nothing" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const share: style.Rule = .{
        .name = "s",
        .query = "c.scm",
        .bound = .{ .max_share = 0 },
    };
    try testing.expect((try verdictFor(arena, share, &.{}, 0)).permitted);

    // A file of nothing but one comment is a whole share and refuses.
    const whole = [_]ast.Match{spanning(0, 0)};
    try testing.expect(!(try verdictFor(arena, share, &whole, 1)).permitted);
}

test "lines are counted with and without a closing newline" {
    try testing.expectEqual(@as(u32, 0), linesIn(""));
    try testing.expectEqual(@as(u32, 1), linesIn("one"));
    try testing.expectEqual(@as(u32, 1), linesIn("one\n"));
    try testing.expectEqual(@as(u32, 2), linesIn("one\ntwo"));
    try testing.expectEqual(@as(u32, 2), linesIn("one\ntwo\n"));
}

test "the sentence names the rule, both numbers and the line, and no source" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ten: style.Rule = .{
        .name = "comment-block",
        .query = "c.scm",
        .bound = .{ .max_lines = 10 },
    };
    const eleven = [_]ast.Match{spanning(0, 10)};
    const said = try saidAbout(arena, "write_file", ten, try verdictFor(arena, ten, &eleven, 100));

    try testing.expect(std.mem.indexOf(u8, said, "comment-block") != null);
    try testing.expect(std.mem.indexOf(u8, said, "11 lines") != null);
    try testing.expect(std.mem.indexOf(u8, said, "permits 10") != null);
    try testing.expect(std.mem.indexOf(u8, said, "line 1") != null);
    try testing.expect(std.mem.indexOf(u8, said, "refused") != null);

    const soft: style.Rule = .{
        .name = "soft",
        .query = "c.scm",
        .bound = .{ .max_matches = 0 },
        .decision = .report,
    };
    const one = [_]ast.Match{spanning(3, 3)};
    const reported = try saidAbout(arena, "edit_file", soft, try verdictFor(arena, soft, &one, 100));
    try testing.expect(std.mem.indexOf(u8, reported, "broke") != null);
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, reported, "refused"));
}
