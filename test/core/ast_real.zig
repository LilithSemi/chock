//! The real `tree-sitter query` command against a real grammar, driven by the
//! production argument list and the production reader.
//!
//! `lib/chock-core/ast.zig` proves the reader against bytes captured from the
//! command. This proves those bytes are still what the command writes, which
//! is the half a captured sample cannot keep honest. The two output forms
//! matter most: a node on one row prints its index in the query and the
//! matched text, and a node over more than one row prints neither.
//!
//! The spawn here runs the program plainly, with no sandbox. Chock's own spawn
//! binds the staged files and confines the program, and a sandbox cannot nest
//! inside CI. So this covers the command, the grammar and the reader, and it
//! does not cover the mount set.

const std = @import("std");

const chock_core = @import("chock-core");

const ast = chock_core.ast;
const ast_command = chock_core.ast_command;

const testing = std.testing;
const shared = @import("direct_spawn.zig");

const DirectSpawn = shared.DirectSpawn;
const Fixture = shared.Fixture;
const deadlineIn = shared.deadlineIn;
const program_path = shared.program_path;
const parsers_dir = shared.parsers_dir;

test "the real command finds the real comments in a real file" {
    if (program_path == null or parsers_dir == null) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fixture = try Fixture.init(gpa, io);
    defer fixture.deinit(gpa);

    // Written here, so the rows the test asserts are rows it chose.
    const source =
        \\//! one
        \\//! two
        \\pub fn main() void {
        \\    // inside
        \\}
        \\
    ;

    const got = try fixture.parser().run(arena, io, .{
        .language = "zig",
        .source = source,
        .query_text = "(comment) @c\n",
        .deadline = deadlineIn(io, 30 * std.time.ns_per_s),
    });

    try testing.expectEqual(@as(usize, 3), got.len);
    for (got) |one| try testing.expectEqualStrings("c", one.capture);

    try testing.expectEqual(@as(u32, 0), got[0].start_line);
    try testing.expectEqual(@as(u32, 0), got[0].start_column);
    try testing.expectEqual(@as(u32, 1), got[0].lines());

    try testing.expectEqual(@as(u32, 1), got[1].start_line);
    try testing.expectEqual(@as(u32, 3), got[2].start_line);
    try testing.expectEqual(@as(u32, 4), got[2].start_column);
}

test "a node spanning rows comes back from the real command too" {
    if (program_path == null or parsers_dir == null) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fixture = try Fixture.init(gpa, io);
    defer fixture.deinit(gpa);

    const source =
        \\pub fn main() void {
        \\    var at: usize = 0;
        \\    at += 1;
        \\}
        \\
    ;

    const got = try fixture.parser().run(arena, io, .{
        .language = "zig",
        .source = source,
        .query_text = "(function_declaration) @fn\n",
        .deadline = deadlineIn(io, 30 * std.time.ns_per_s),
    });

    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqualStrings("fn", got[0].capture);
    try testing.expectEqual(@as(u32, 0), got[0].start_line);
    try testing.expectEqual(@as(u32, 3), got[0].end_line);
    // The number a max_lines rule is compared against.
    try testing.expectEqual(@as(u32, 4), got[0].lines());
}

test "a grammar the directory has not got is no answer, and never no matches" {
    if (program_path == null or parsers_dir == null) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fixture = try Fixture.init(gpa, io);
    defer fixture.deinit(gpa);

    // The name is one a path can hold, so this gets as far as looking for the
    // library. Zero matches would read as a file that breaks no rule, so a
    // grammar that is not there is an error and the gate leaves the write
    // alone rather than refusing it.
    try testing.expectError(error.LanguageNotKnown, fixture.parser().run(arena, io, .{
        .language = "nothing_is_here",
        .source = "x\n",
        .query_text = "(comment) @c\n",
        .deadline = deadlineIn(io, 30 * std.time.ns_per_s),
    }));
}
