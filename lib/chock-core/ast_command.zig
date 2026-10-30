//! A syntax tree from `tree-sitter query`, run as a program of its own.
//!
//! The command wants two files and a parser library, so this file resolves the
//! library, builds the argument list, and reads what came back. Staging a file
//! and running a confined program are supplied through `Spawn`, because the
//! tool runner already does both and a second copy of either would drift.

const std = @import("std");

const ast = @import("ast.zig");
const chock_policy = @import("chock-policy");

pub const program = "tree-sitter";

/// One file a language, under the directory the dev shell exports.
pub const library_suffix = ".so";

pub const max_output_bytes: usize = 1 << 20;

pub const Error = ast.Error || error{
    Staging,
};

pub const Output = struct {
    text: []const u8,
    /// False when the program ended any way other than cleanly.
    ok: bool,
    timed_out: bool,
};

/// Staging a file and running a program, both of which the tool runner already
/// does inside the sandbox every other tool program runs in.
pub const Spawn = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Put `bytes` where the confined program can read them, and answer
        /// with the path. The staged file belongs to the implementation.
        stage: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            io: std.Io,
            bytes: []const u8,
        ) Error![]const u8,
        /// Run `argv` confined and answer with what it wrote.
        run: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            io: std.Io,
            argv: []const []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) Error!Output,
    };

    pub fn stage(
        self: Spawn,
        arena: std.mem.Allocator,
        io: std.Io,
        bytes: []const u8,
    ) Error![]const u8 {
        return self.vtable.stage(self.ptr, arena, io, bytes);
    }

    pub fn run(
        self: Spawn,
        arena: std.mem.Allocator,
        io: std.Io,
        argv: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Output {
        return self.vtable.run(self.ptr, arena, io, argv, deadline);
    }
};

/// The parser library a language resolves to, or null for a name this would
/// not put in a path. A language is checked here as well as where the block is
/// read, because this function is reached by callers that read no block.
/// Null for a language this host has no grammar for, which leaves the write
/// alone. A grammar that is there and then fails is a different answer.
pub fn libraryFor(
    arena: std.mem.Allocator,
    io: std.Io,
    parsers_dir: []const u8,
    language: []const u8,
) std.mem.Allocator.Error!?[]const u8 {
    if (!chock_policy.style.languageIsWellFormed(language)) return null;
    if (parsers_dir.len == 0) return null;
    const path: []const u8 = try std.fmt.allocPrint(
        arena,
        "{s}/{s}" ++ library_suffix,
        .{ parsers_dir, language },
    );
    _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch return null;
    return path;
}

/// `--config-path` is given a file of this project's own, so nothing of
/// anybody's home directory decides which grammar answers.
pub fn argvFor(
    arena: std.mem.Allocator,
    this: []const u8,
    library: []const u8,
    language: []const u8,
    query_path: []const u8,
    source_path: []const u8,
    config_path: []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    const argv = try arena.alloc([]const u8, 10);
    argv[0] = this;
    argv[1] = "query";
    argv[2] = "--config-path";
    argv[3] = config_path;
    argv[4] = "--lib-path";
    argv[5] = library;
    argv[6] = "--lang-name";
    argv[7] = language;
    argv[8] = query_path;
    argv[9] = source_path;
    return argv;
}

pub const Session = struct {
    /// The directory the `parsers` variable named, already resolved.
    parsers_dir: []const u8,
    spawn: Spawn,
    this: []const u8 = program,

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
        return self.ask(arena, io, query) catch |err| switch (err) {
            error.Staging => error.ParserFailed,
            else => |one| one,
        };
    }

    fn ask(
        self: *Session,
        arena: std.mem.Allocator,
        io: std.Io,
        query: ast.Query,
    ) Error!ast.Matches {
        if (query.source.len > ast.max_source_bytes) return error.SourceTooLarge;
        if (query.query_text.len > ast.max_query_bytes) return error.QueryTooLarge;

        const library = try libraryFor(arena, io, self.parsers_dir, query.language) orelse
            return error.LanguageNotKnown;

        const source_path = try self.spawn.stage(arena, io, query.source);
        const query_path = try self.spawn.stage(arena, io, query.query_text);
        // An empty file, so the command reads no configuration of its own.
        const config_path = try self.spawn.stage(arena, io, "{}\n");

        const argv = try argvFor(
            arena,
            self.this,
            library,
            query.language,
            query_path,
            source_path,
            config_path,
        );

        const got = try self.spawn.run(arena, io, argv, query.deadline);
        if (got.timed_out) return error.Late;
        if (!got.ok) return error.ParserFailed;
        if (got.text.len > max_output_bytes) return error.ParserFailed;
        return ast.matchesFrom(arena, got.text);
    }
};

const testing = std.testing;

/// A directory holding a stand-in grammar, because a language with no file
/// under the parsers directory is no library at all.
const Grammars = struct {
    tmp: std.testing.TmpDir,
    path: []u8,

    fn init(gpa: std.mem.Allocator) !Grammars {
        var tmp = std.testing.tmpDir(.{});
        try tmp.dir.writeFile(testing.io, .{
            .sub_path = "zig.so",
            .data = "stands in for a grammar",
        });
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try tmp.dir.realPath(testing.io, &buffer);
        return .{ .tmp = tmp, .path = try gpa.dupe(u8, buffer[0..length]) };
    }

    fn deinit(self: *Grammars, gpa: std.mem.Allocator) void {
        gpa.free(self.path);
        self.tmp.cleanup();
    }
};

const FakeSpawn = struct {
    staged: usize = 0,
    argv: []const []const u8 = &.{},
    answer: Output = .{ .text = "", .ok = true, .timed_out = false },
    fail_staging: bool = false,

    fn spawn(self: *FakeSpawn) Spawn {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Spawn.VTable{ .stage = stageFn, .run = runFn };

    fn stageFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        bytes: []const u8,
    ) Error![]const u8 {
        _ = io;
        _ = bytes;
        const self: *FakeSpawn = @ptrCast(@alignCast(ptr));
        if (self.fail_staging) return error.Staging;
        self.staged += 1;
        return std.fmt.allocPrint(arena, "/staged/{d}", .{self.staged});
    }

    fn runFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        argv: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Output {
        _ = io;
        _ = deadline;
        const self: *FakeSpawn = @ptrCast(@alignCast(ptr));
        self.argv = try arena.dupe([]const u8, argv);
        return self.answer;
    }
};

test "a language becomes one file name under the parsers directory" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "zig.so", .data = "stands in for a grammar" });
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(io, &buffer);
    const parsers = buffer[0..length];

    try testing.expectEqualStrings(
        try std.fmt.allocPrint(arena, "{s}/zig.so", .{parsers}),
        (try libraryFor(arena, io, parsers, "zig")).?,
    );

    // A grammar this directory has not got is no library, which leaves a
    // write of that language alone rather than refusing it.
    try testing.expectEqual(@as(?[]const u8, null), try libraryFor(arena, io, parsers, "nix"));

    // A name that would climb out of the directory gets no path at all, so
    // the caller has no library rather than the wrong one.
    try testing.expectEqual(
        @as(?[]const u8, null),
        try libraryFor(arena, io, parsers, "../../etc/passwd"),
    );
    try testing.expectEqual(
        @as(?[]const u8, null),
        try libraryFor(arena, io, parsers, "zig/../x"),
    );
    try testing.expectEqual(@as(?[]const u8, null), try libraryFor(arena, io, parsers, ""));
    // With no directory there is nothing to resolve against.
    try testing.expectEqual(@as(?[]const u8, null), try libraryFor(arena, io, "", "zig"));
}

test "the command is told its grammar and never reads a configuration of its own" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeSpawn{ .answer = .{
        .text = "  capture: 0 - c, start: (0, 0), end: (0, 7), text: `//! one`\n",
        .ok = true,
        .timed_out = false,
    } };
    var grammars = try Grammars.init(testing.allocator);
    defer grammars.deinit(testing.allocator);

    var session = Session{ .parsers_dir = grammars.path, .spawn = fake.spawn() };

    const got = try session.parser().run(arena, testing.io, .{
        .language = "zig",
        .source = "//! one\n",
        .query_text = "(comment) @c\n",
        .deadline = std.Io.Clock.Timestamp.now(testing.io, .awake),
    });
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqualStrings("c", got[0].capture);

    // Three files staged: the source, the query and an empty config.
    try testing.expectEqual(@as(usize, 3), fake.staged);

    try testing.expectEqualStrings("tree-sitter", fake.argv[0]);
    try testing.expectEqualStrings("query", fake.argv[1]);
    try testing.expectEqualStrings("--config-path", fake.argv[2]);
    try testing.expectEqualStrings("--lib-path", fake.argv[4]);
    try testing.expectEqualStrings(
        try std.fmt.allocPrint(arena, "{s}/zig.so", .{grammars.path}),
        fake.argv[5],
    );
    try testing.expectEqualStrings("--lang-name", fake.argv[6]);
    try testing.expectEqualStrings("zig", fake.argv[7]);
}

test "a language with no parser is refused before anything is staged" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeSpawn{};
    var grammars = try Grammars.init(testing.allocator);
    defer grammars.deinit(testing.allocator);

    var session = Session{ .parsers_dir = grammars.path, .spawn = fake.spawn() };

    try testing.expectError(error.LanguageNotKnown, session.parser().run(arena, testing.io, .{
        .language = "../../etc/passwd",
        .source = "",
        .query_text = "(comment) @c\n",
        .deadline = std.Io.Clock.Timestamp.now(testing.io, .awake),
    }));
    try testing.expectEqual(@as(usize, 0), fake.staged);
}

test "a source or a query over its bound starts no process" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeSpawn{};
    var grammars = try Grammars.init(testing.allocator);
    defer grammars.deinit(testing.allocator);

    var session = Session{ .parsers_dir = grammars.path, .spawn = fake.spawn() };

    const big = try gpa.alloc(u8, ast.max_source_bytes + 1);
    defer gpa.free(big);
    @memset(big, 'a');

    try testing.expectError(error.SourceTooLarge, session.parser().run(arena, testing.io, .{
        .language = "zig",
        .source = big,
        .query_text = "(comment) @c\n",
        .deadline = std.Io.Clock.Timestamp.now(testing.io, .awake),
    }));

    const long_query = try gpa.alloc(u8, ast.max_query_bytes + 1);
    defer gpa.free(long_query);
    @memset(long_query, 'a');

    try testing.expectError(error.QueryTooLarge, session.parser().run(arena, testing.io, .{
        .language = "zig",
        .source = "",
        .query_text = long_query,
        .deadline = std.Io.Clock.Timestamp.now(testing.io, .awake),
    }));

    try testing.expectEqual(@as(usize, 0), fake.staged);
}

test "a command that timed out is late, and one that failed is a failure" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var late = FakeSpawn{ .answer = .{ .text = "", .ok = false, .timed_out = true } };
    var grammars = try Grammars.init(testing.allocator);
    defer grammars.deinit(testing.allocator);

    var late_session = Session{ .parsers_dir = grammars.path, .spawn = late.spawn() };
    try testing.expectError(error.Late, late_session.parser().run(arena, testing.io, .{
        .language = "zig",
        .source = "",
        .query_text = "(comment) @c\n",
        .deadline = std.Io.Clock.Timestamp.now(testing.io, .awake),
    }));

    var broken = FakeSpawn{ .answer = .{ .text = "", .ok = false, .timed_out = false } };
    var broken_session = Session{ .parsers_dir = grammars.path, .spawn = broken.spawn() };
    try testing.expectError(error.ParserFailed, broken_session.parser().run(arena, testing.io, .{
        .language = "zig",
        .source = "",
        .query_text = "(comment) @c\n",
        .deadline = std.Io.Clock.Timestamp.now(testing.io, .awake),
    }));
}

test "a file that cannot be staged is a failure and never a silent pass" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeSpawn{ .fail_staging = true };
    var grammars = try Grammars.init(testing.allocator);
    defer grammars.deinit(testing.allocator);

    var session = Session{ .parsers_dir = grammars.path, .spawn = fake.spawn() };

    try testing.expectError(error.ParserFailed, session.parser().run(arena, testing.io, .{
        .language = "zig",
        .source = "//! one\n",
        .query_text = "(comment) @c\n",
        .deadline = std.Io.Clock.Timestamp.now(testing.io, .awake),
    }));
}

test "a command answering nothing is no match, and not a fault" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeSpawn{ .answer = .{ .text = "a.zig\n", .ok = true, .timed_out = false } };
    var grammars = try Grammars.init(testing.allocator);
    defer grammars.deinit(testing.allocator);

    var session = Session{ .parsers_dir = grammars.path, .spawn = fake.spawn() };

    const got = try session.parser().run(arena, testing.io, .{
        .language = "zig",
        .source = "const a = 1;\n",
        .query_text = "(comment) @c\n",
        .deadline = std.Io.Clock.Timestamp.now(testing.io, .awake),
    });
    try testing.expectEqual(@as(usize, 0), got.len);
}
