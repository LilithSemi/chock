//! A style rule's other parser: one wasm module, compiled by Chock's own
//! engine in this process. The module holds tree-sitter's runtime and one
//! grammar, so a session has one language.

const std = @import("std");

const chock_core = @import("chock-core");
const wasm = @import("vulcan-wasm");

const ast = chock_core.ast;

const input_export = "ast_input";
const run_export = "ast_run";
const rows_export = "ast_rows";

const words_a_row = 6;
const max_module_bytes = 16 << 20;

/// What `pkgs/chock/ast-wasm/driver.c` answers with. A code this does not
/// know is a failed parse, which refuses the write.
const Failure = enum(i32) {
    input = -1,
    query = -2,
    rows = -3,
    memory = -4,
    parse = -5,
};

fn failureFor(answer: i32) ast.Error {
    return switch (answer) {
        @intFromEnum(Failure.rows) => error.TooManyMatches,
        @intFromEnum(Failure.memory) => error.OutOfMemory,
        else => error.ParserFailed,
    };
}

/// One module a session, compiled at the first parse and kept. A session that
/// could not compile it refuses every parse with the same sentence, because a
/// write Chock could not check is a write it does not make.
pub const Session = struct {
    gpa: std.mem.Allocator,
    path: []const u8,
    language: []const u8,
    instance: ?wasm.Instance = null,
    refusal: ?[]const u8 = null,

    pub fn parser(self: *Session) ast.Parser {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = ast.Parser.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        query: ast.Query,
    ) ast.Error!ast.Matches {
        const self: *Session = @ptrCast(@alignCast(ptr));
        if (self.refusal != null) return error.ParserFailed;
        if (!std.mem.eql(u8, query.language, self.language)) return error.LanguageNotKnown;
        try self.ready(io);
        return self.ask(arena, query.source, query.query_text);
    }

    /// The engine compiles every function in the module before the first
    /// answer. The call cannot be interrupted, so the query's deadline is not
    /// read here: the module's own bounds are what hold a parse down.
    fn ready(self: *Session, io: std.Io) ast.Error!void {
        if (self.instance != null) return;
        const bytes = std.Io.Dir.cwd().readFileAlloc(
            io,
            self.path,
            self.gpa,
            .limited(max_module_bytes),
        ) catch return self.refuse("the parse module's own file could not be read");
        defer self.gpa.free(bytes);

        self.instance = wasm.Instance.instantiate(self.gpa, bytes, &.{}) catch
            return self.refuse("the engine would not compile the parse module");
    }

    fn ask(
        self: *Session,
        arena: std.mem.Allocator,
        source: []const u8,
        query: []const u8,
    ) ast.Error!ast.Matches {
        if (source.len > ast.max_source_bytes) return error.SourceTooLarge;
        if (query.len > ast.max_query_bytes) return error.QueryTooLarge;

        const instance = &self.instance.?;
        const total = source.len + query.len;
        const base = instance.call1(u32, u32, input_export, @intCast(total)) catch
            return error.ParserFailed;
        if (base == 0) return error.OutOfMemory;

        const memory = instance.memory;
        if (@as(usize, base) + total > memory.len) return error.ParserFailed;
        @memcpy(memory[base..][0..source.len], source);
        @memcpy(memory[base + source.len ..][0..query.len], query);

        const answer = instance.call2(
            i32,
            u32,
            u32,
            run_export,
            @intCast(source.len),
            @intCast(query.len),
        ) catch return error.ParserFailed;
        if (answer < 0) return failureFor(answer);
        const count: usize = @intCast(answer);
        if (count == 0) return &.{};
        if (count > ast.max_matches) return error.TooManyMatches;

        const rows = instance.call0(u32, rows_export) catch return error.ParserFailed;
        if (rows == 0) return error.ParserFailed;
        const words = count * words_a_row;
        if (@as(usize, rows) + words * @sizeOf(u32) > memory.len) return error.ParserFailed;

        const found = try arena.alloc(ast.Match, count);
        for (found, 0..) |*slot, index| {
            const at = @as(usize, rows) + index * words_a_row * @sizeOf(u32);
            slot.* = .{
                // Copied out, because the parse after this one writes over the
                // names where the module keeps them.
                .capture = try arena.dupe(u8, textIn(memory, word(memory, at))),
                .start_line = word(memory, at + 4),
                .start_column = word(memory, at + 8),
                .end_line = word(memory, at + 12),
                .end_column = word(memory, at + 16),
            };
        }
        return found;
    }

    /// A refusal is kept, so every parse after the first failure answers the
    /// same way without trying again.
    fn refuse(self: *Session, why: []const u8) ast.Error {
        if (self.refusal == null) self.refusal = why;
        return error.ParserFailed;
    }

    pub fn deinit(self: *Session) void {
        if (self.instance) |*one| one.deinit();
        self.* = undefined;
    }
};

fn word(memory: []const u8, at: usize) u32 {
    return std.mem.readInt(u32, memory[at..][0..4], .little);
}

/// The capture name, read where the module left it. An empty name is one the
/// module had no room for, and no rule is about a capture name.
fn textIn(memory: []const u8, at: u32) []const u8 {
    if (at == 0 or at >= memory.len) return "";
    var end: usize = at;
    while (end < memory.len and memory[end] != 0) end += 1;
    return memory[at..end];
}

test "a module that cannot be read refuses every parse with the same sentence" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var session: Session = .{ .gpa = gpa, .path = "no-such-module.wasm", .language = "zig" };
    defer session.deinit();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const query: ast.Query = .{
        .language = "zig",
        .source = "const a = 1;\n",
        .query_text = "(comment) @c\n",
        .deadline = std.Io.Clock.Timestamp.now(io, .awake),
    };
    try std.testing.expectError(error.ParserFailed, session.parser().run(
        arena_state.allocator(),
        io,
        query,
    ));
    try std.testing.expect(session.refusal != null);
    try std.testing.expectError(error.ParserFailed, session.parser().run(
        arena_state.allocator(),
        io,
        query,
    ));
}

test "a language the module does not hold is not this parser's to answer" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var session: Session = .{ .gpa = gpa, .path = "no-such-module.wasm", .language = "zig" };
    defer session.deinit();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    try std.testing.expectError(error.LanguageNotKnown, session.parser().run(
        arena_state.allocator(),
        io,
        .{
            .language = "rust",
            .source = "fn main() {}\n",
            .query_text = "(line_comment) @c\n",
            .deadline = std.Io.Clock.Timestamp.now(io, .awake),
        },
    ));
}
