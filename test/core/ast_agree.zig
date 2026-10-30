//! Both parsers over one file. Two implementations of one seam that answer
//! differently is a bug in one of them, and nothing else in this suite would
//! find it.
//!
//! Everything here is real: the module is the one `pkgs/chock/default.nix`
//! builds, the parser over it is the one the session uses, and the command is
//! `tree-sitter query` against the same grammar.
//!
//! The engine compiles every function in the module before the first answer,
//! which is minutes for a debug build, so `build.zig` builds this test only
//! where the module directory is in the environment, which is the dev shell.

const std = @import("std");

const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");

const ast_engine = @import("ast_engine");

const ast = chock_core.ast;
const style = chock_core.style;

const shared = @import("direct_spawn.zig");

/// Given by `build.zig`, which builds this test only when it has it.
const module_dir: []const u8 = @import("ast_real_path").module_dir;

const testing = std.testing;

const sample =
    \\//! One line of a doc comment.
    \\//! And a second.
    \\
    \\const std = @import("std");
    \\
    \\/// A block over three lines,
    \\/// which is what a bound on lines
    \\/// is about.
    \\pub fn main() void {
    \\    // One more, inside.
    \\    std.debug.print("hi\n", .{});
    \\}
    \\
;

const comment_query = "(comment) @c\n";

/// A node over four rows, which the command prints without an index and
/// without the matched text.
const block_query = "(function_declaration) @fn\n";

/// A file near the bound a parse is held to, built here rather than kept as a
/// fixture. The comments are the sample's, so the count stays small while the
/// tree gets big.
fn bigSource(arena: std.mem.Allocator) ![]const u8 {
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(arena, sample);
    while (text.items.len < 700 * 1024) try text.appendSlice(arena, "const held = 1;\n");
    return text.items;
}

/// Both parsers over one source and one query. The wasm side is given its own
/// budget, because the first answer waits for the engine to compile. It reads
/// no deadline, so this says what a session would ask for.
fn matchesFromBoth(
    arena: std.mem.Allocator,
    io: std.Io,
    command: ast.Parser,
    wasm: ast.Parser,
    source: []const u8,
    query: []const u8,
) ![2]ast.Matches {
    const by_command = try command.run(arena, io, .{
        .language = "zig",
        .source = source,
        .query_text = query,
        .deadline = shared.deadlineIn(io, 30 * std.time.ns_per_s),
    });
    const by_wasm = try wasm.run(arena, io, .{
        .language = "zig",
        .source = source,
        .query_text = query,
        .deadline = shared.deadlineIn(io, 20 * std.time.ns_per_min),
    });
    return .{ by_command, by_wasm };
}

// One test and one module, because the engine compiles it once a process and
// a test that built three parsers would pay for it three times.
test "the command and the module answer one file the same way" {
    if (shared.program_path == null or shared.parsers_dir == null) return error.SkipZigTest;

    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const module = try std.fmt.allocPrint(arena, "{s}/zig.wasm", .{module_dir});

    var fixture = try shared.Fixture.init(gpa, io);
    defer fixture.deinit(gpa);

    var session: ast_engine.Session = .{ .gpa = gpa, .path = module, .language = "zig" };
    defer session.deinit();

    const wasm = session.parser();
    // A module the engine would not compile refuses every parse with one
    // sentence, and that sentence is the only thing that says why, so the
    // failure names it instead of reading `ParserFailed` on its own.
    const both = matchesFromBoth(arena, io, fixture.parser(), wasm, sample, comment_query) catch |err| {
        try testing.expectEqualStrings("no refusal", session.refusal orelse "no refusal");
        return err;
    };
    const by_command = both[0];
    const by_wasm = both[1];

    // Every match, in the order the cursor walked the tree.
    try testing.expectEqual(@as(usize, 6), by_command.len);
    try testing.expectEqual(by_command.len, by_wasm.len);
    for (by_command, by_wasm) |one, other| {
        try testing.expectEqualStrings(one.capture, other.capture);
        try testing.expectEqual(one.start_line, other.start_line);
        try testing.expectEqual(one.start_column, other.start_column);
        try testing.expectEqual(one.end_line, other.end_line);
        try testing.expectEqual(one.end_column, other.end_column);
    }

    // A node over more than one row, which is the form the command prints
    // with no index and no matched text. A lines bound is about exactly this,
    // and Zig has no comment that covers two rows.
    const spanning = try matchesFromBoth(arena, io, fixture.parser(), wasm, sample, block_query);
    try testing.expectEqual(@as(usize, 1), spanning[0].len);
    try testing.expectEqual(spanning[0].len, spanning[1].len);
    try testing.expectEqual(spanning[0][0].start_line, spanning[1][0].start_line);
    try testing.expectEqual(spanning[0][0].end_line, spanning[1][0].end_line);
    try testing.expectEqual(@as(u32, 4), spanning[1][0].lines());

    // One rule a bound, so a disagreement cannot hide behind a rule that
    // refuses for a different reason.
    const rules = [_]chock_policy.style.Rule{
        .{ .name = "comment-count", .query = "comment.scm", .bound = .{ .max_matches = 5 } },
        .{ .name = "comment-share", .query = "comment.scm", .bound = .{ .max_share = 10 } },
        .{ .name = "comment-room", .query = "comment.scm", .bound = .{ .max_matches = 10 } },
    };
    const spans = [_]chock_policy.style.Rule{
        .{ .name = "block-lines", .query = "block.scm", .bound = .{ .max_lines = 2 } },
        .{ .name = "block-room", .query = "block.scm", .bound = .{ .max_lines = 10 } },
    };
    const file_lines = style.linesIn(sample);

    for (rules) |rule| {
        const said = try style.verdictFor(arena, rule, by_command, file_lines);
        const other = try style.verdictFor(arena, rule, by_wasm, file_lines);
        try testing.expectEqual(said.permitted, other.permitted);
        try testing.expectEqual(said.lands, other.lands);
        try testing.expectEqual(said.worst, other.worst);
        try testing.expectEqual(said.first_line, other.first_line);
    }
    for (spans) |rule| {
        const said = try style.verdictFor(arena, rule, spanning[0], file_lines);
        const other = try style.verdictFor(arena, rule, spanning[1], file_lines);
        try testing.expectEqual(said.permitted, other.permitted);
        try testing.expectEqual(said.worst, other.worst);
        try testing.expectEqual(said.first_line, other.first_line);
    }

    // This file breaks three of these five rules, so an agreement here is not
    // two parsers agreeing on nothing.
    try testing.expect(!(try style.verdictFor(arena, rules[0], by_wasm, file_lines)).permitted);
    try testing.expect(!(try style.verdictFor(arena, rules[1], by_wasm, file_lines)).permitted);
    try testing.expect((try style.verdictFor(arena, rules[2], by_wasm, file_lines)).permitted);
    try testing.expect(!(try style.verdictFor(arena, spans[0], spanning[1], file_lines)).permitted);
    try testing.expect((try style.verdictFor(arena, spans[1], spanning[1], file_lines)).permitted);

    // A second parse through the same module, and a big one. The module's
    // `free` gives nothing back, so a run that did not hand the heap back
    // would answer the first file and fail on this.
    const big = try bigSource(arena);
    const again = try matchesFromBoth(arena, io, fixture.parser(), wasm, big, comment_query);
    try testing.expectEqual(@as(usize, 6), again[0].len);
    try testing.expectEqual(again[0].len, again[1].len);
    for (again[0], again[1]) |one, other| {
        try testing.expectEqual(one.start_line, other.start_line);
        try testing.expectEqual(one.end_line, other.end_line);
    }

    // One module carries one grammar, and a language it has not got is no
    // answer rather than no matches. The parser knows which language its
    // module holds, so this never reaches the module.
    try testing.expectError(error.LanguageNotKnown, wasm.run(arena, io, .{
        .language = "rust",
        .source = "fn main() {}\n",
        .query_text = "(line_comment) @c\n",
        .deadline = shared.deadlineIn(io, 30 * std.time.ns_per_s),
    }));
}
