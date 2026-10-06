//! Diagnostics in the edit loop: an agent that edits a file learns it
//! does not compile before making the next edit.

const std = @import("std");
const notices = @import("notices.zig");

pub const Error = std.mem.Allocator.Error;

pub const Severity = enum(u8) {
    err = 1,
    warning = 2,
    information = 3,
    hint = 4,

    pub fn fromWire(number: i64) ?Severity {
        if (number < 0 or number > std.math.maxInt(u8)) return null;
        return std.enums.fromInt(Severity, @as(u8, @intCast(number)));
    }

    pub fn word(self: Severity) []const u8 {
        return switch (self) {
            .err => "error",
            .warning => "warning",
            .information => "note",
            .hint => "hint",
        };
    }

    pub fn reachesModel(self: Severity) bool {
        return switch (self) {
            .err, .warning => true,
            .information, .hint => false,
        };
    }
};

pub const Diagnostic = struct {
    path: []const u8,
    line: u32,
    column: u32,
    severity: Severity,
    message: []const u8,
};

pub const Answer = union(enum) {
    unsupported,
    reported: []const Diagnostic,
    late,
    unavailable: []const u8,
};

pub const Ask = struct {
    path: []const u8,
    budget_ns: u64,
};

pub const Server = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        diagnose: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            io: std.Io,
            ask: Ask,
        ) Error!Answer,
    };

    pub fn diagnose(
        self: Server,
        arena: std.mem.Allocator,
        io: std.Io,
        ask: Ask,
    ) Error!Answer {
        return self.vtable.diagnose(self.ptr, arena, io, ask);
    }
};

pub const max_shown: usize = 12;

pub const max_message_bytes: usize = 200;

pub const first_budget_ns: u64 = 10 * std.time.ns_per_s;

pub const steady_budget_ns: u64 = 2 * std.time.ns_per_s;

pub const prefix = "[chock: ";

pub const not_text = "the server's message was not text and is not shown";

pub const Session = struct {
    program: []const u8 = "",

    suffixes: []const []const u8 = &.{},

    server: ?Server = null,

    said_unavailable: bool = false,

    asked: bool = false,

    pub fn afterWrite(
        self: *Session,
        gpa: std.mem.Allocator,
        io: std.Io,
        path: []const u8,
    ) Error!?[]u8 {
        const server = self.server orelse return null;
        if (!self.serves(path)) return null;

        const budget = if (self.asked) steady_budget_ns else first_budget_ns;
        self.asked = true;

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();

        const answer = try server.diagnose(arena_state.allocator(), io, .{
            .path = path,
            .budget_ns = budget,
        });

        return switch (answer) {
            .unsupported, .late => null,
            .reported => |list| try render(gpa, path, list),
            .unavailable => |reason| blk: {
                if (self.said_unavailable) break :blk null;
                self.said_unavailable = true;
                break :blk try self.unavailableText(gpa, reason);
            },
        };
    }

    pub fn serves(self: Session, path: []const u8) bool {
        for (self.suffixes) |suffix| {
            if (suffix.len == 0) continue;
            if (std.mem.endsWith(u8, path, suffix)) return true;
        }
        return false;
    }

    fn unavailableText(
        self: Session,
        gpa: std.mem.Allocator,
        reason: []const u8,
    ) Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);

        try out.appendSlice(gpa, prefix ++ "the language server ");
        try out.appendSlice(gpa, if (self.program.len == 0) "for this project" else self.program);
        try out.appendSlice(
            gpa,
            " did not start, so nothing checks your edits in this session and this is said " ++
                "once. Build or test the project yourself when you want to know whether it " ++
                "still compiles.",
        );

        const cleaned = try flattenMessage(gpa, reason);
        defer gpa.free(cleaned);
        if (cleaned.len != 0) {
            try out.appendSlice(gpa, " It said: ");
            try out.appendSlice(gpa, cleaned);
        }
        try out.appendSlice(gpa, "]\n");

        return out.toOwnedSlice(gpa);
    }
};

pub fn render(
    gpa: std.mem.Allocator,
    edited: []const u8,
    list: []const Diagnostic,
) Error!?[]u8 {
    var kept: std.ArrayList(Diagnostic) = .empty;
    defer kept.deinit(gpa);
    for (list) |one| {
        if (!one.severity.reachesModel()) continue;
        try kept.append(gpa, one);
    }
    if (kept.items.len == 0) return null;

    const Context = struct {
        edited: []const u8,

        fn lessThan(context: @This(), a: Diagnostic, b: Diagnostic) bool {
            return orderOf(context.edited, a, b) == .lt;
        }
    };
    std.mem.sort(Diagnostic, kept.items, Context{ .edited = edited }, Context.lessThan);

    const shown = @min(kept.items.len, max_shown);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    try out.appendSlice(gpa, prefix);
    try out.print(gpa, "{d} {s} after this edit", .{
        kept.items.len,
        if (kept.items.len == 1) "problem" else "problems",
    });
    if (kept.items.len > shown) {
        try out.print(gpa, ", the {d} that matter most are shown", .{shown});
    }
    try out.appendSlice(gpa, "]\n");

    for (kept.items[0..shown]) |one| {
        const message = try flattenMessage(gpa, one.message);
        defer gpa.free(message);
        try out.print(gpa, "{s}:{d}:{d}: {s}: {s}\n", .{
            one.path,
            one.line,
            one.column,
            one.severity.word(),
            message,
        });
    }

    return try out.toOwnedSlice(gpa);
}

fn orderOf(edited: []const u8, a: Diagnostic, b: Diagnostic) std.math.Order {
    const a_edited = samePath(edited, a.path);
    const b_edited = samePath(edited, b.path);
    if (a_edited != b_edited) return if (a_edited) .lt else .gt;

    const a_rank = @intFromEnum(a.severity);
    const b_rank = @intFromEnum(b.severity);
    if (a_rank != b_rank) return std.math.order(a_rank, b_rank);

    const by_path = std.mem.order(u8, a.path, b.path);
    if (by_path != .eq) return by_path;

    if (a.line != b.line) return std.math.order(a.line, b.line);
    if (a.column != b.column) return std.math.order(a.column, b.column);
    return std.mem.order(u8, a.message, b.message);
}

fn samePath(left: []const u8, right: []const u8) bool {
    return std.mem.eql(u8, trimDotSlash(left), trimDotSlash(right));
}

fn trimDotSlash(path: []const u8) []const u8 {
    if (std.mem.startsWith(u8, path, "./")) return path[2..];
    return path;
}

pub fn flattenMessage(gpa: std.mem.Allocator, message: []const u8) Error![]u8 {
    if (!std.unicode.utf8ValidateSlice(message)) return gpa.dupe(u8, not_text);

    var flat: std.ArrayList(u8) = .empty;
    defer flat.deinit(gpa);

    var pending_space = false;
    for (message) |byte| {
        if (byte < 0x20 or byte == 0x7F) {
            pending_space = flat.items.len != 0;
            continue;
        }
        if (pending_space) {
            try flat.append(gpa, ' ');
            pending_space = false;
        }
        try flat.append(gpa, byte);
    }

    const trimmed = std.mem.trim(u8, flat.items, " ");
    const kept = notices.cutToCharacter(trimmed, max_message_bytes);
    if (kept.len == trimmed.len) return gpa.dupe(u8, kept);
    return std.fmt.allocPrint(gpa, "{s} [chock: the message is longer than this]", .{kept});
}

const testing = std.testing;

const FakeServer = struct {
    answer: Answer = .{ .reported = &.{} },
    calls: usize = 0,
    last_budget_ns: u64 = 0,
    last_path: []const u8 = "",

    fn server(self: *FakeServer) Server {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Server.VTable{ .diagnose = diagnoseFn };

    fn diagnoseFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        ask: Ask,
    ) Error!Answer {
        _ = arena;
        _ = io;
        const self: *FakeServer = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        self.last_budget_ns = ask.budget_ns;
        self.last_path = ask.path;
        return self.answer;
    }
};

test "a project with no server behaves exactly as today, and never reaches the seam" {
    const gpa = testing.allocator;

    {
        var session = Session{};
        try testing.expect(try session.afterWrite(gpa, testing.io, "src/main.zig") == null);
    }

    {
        var fake = FakeServer{ .answer = .{ .reported = &.{.{
            .path = "src/main.zig",
            .line = 1,
            .column = 1,
            .severity = .err,
            .message = "this must never be reached",
        }} } };
        var session = Session{
            .program = "zls",
            .suffixes = &.{".zig"},
            .server = fake.server(),
        };

        try testing.expect(try session.afterWrite(gpa, testing.io, "README.md") == null);
        try testing.expect(try session.afterWrite(gpa, testing.io, "Makefile") == null);
        try testing.expectEqual(@as(usize, 0), fake.calls);

        const block = (try session.afterWrite(gpa, testing.io, "src/main.zig")).?;
        defer gpa.free(block);
        try testing.expectEqual(@as(usize, 1), fake.calls);
    }
}

test "a clean file, a late answer, and an empty report all say nothing" {
    const gpa = testing.allocator;

    for ([_]Answer{ .{ .reported = &.{} }, .late, .unsupported }) |answer| {
        var fake = FakeServer{ .answer = answer };
        var session = Session{
            .program = "zls",
            .suffixes = &.{".zig"},
            .server = fake.server(),
        };
        try testing.expect(try session.afterWrite(gpa, testing.io, "src/main.zig") == null);
        try testing.expectEqual(@as(usize, 1), fake.calls);
    }
}

test "the first ask carries the starting budget and every later one the steady budget" {
    const gpa = testing.allocator;

    var fake = FakeServer{ .answer = .late };
    var session = Session{ .suffixes = &.{".zig"}, .server = fake.server() };

    try testing.expect(try session.afterWrite(gpa, testing.io, "a.zig") == null);
    try testing.expectEqual(first_budget_ns, fake.last_budget_ns);

    try testing.expect(try session.afterWrite(gpa, testing.io, "b.zig") == null);
    try testing.expectEqual(steady_budget_ns, fake.last_budget_ns);
    try testing.expectEqualStrings("b.zig", fake.last_path);

    try testing.expect(first_budget_ns > steady_budget_ns);
}

test "a server that will not start says so once and never again in that session" {
    const gpa = testing.allocator;

    var fake = FakeServer{ .answer = .{ .unavailable = "exec zls: no such file or directory" } };
    var session = Session{
        .program = "zls",
        .suffixes = &.{".zig"},
        .server = fake.server(),
    };

    const first = (try session.afterWrite(gpa, testing.io, "src/main.zig")).?;
    defer gpa.free(first);
    try testing.expect(std.mem.indexOf(u8, first, "zls") != null);
    try testing.expect(std.mem.indexOf(u8, first, "did not start") != null);
    try testing.expect(std.mem.indexOf(u8, first, "Build or test the project yourself") != null);
    try testing.expect(std.mem.indexOf(u8, first, "no such file or directory") != null);

    try testing.expect(try session.afterWrite(gpa, testing.io, "src/other.zig") == null);
    try testing.expect(try session.afterWrite(gpa, testing.io, "src/third.zig") == null);
    try testing.expectEqual(@as(usize, 3), fake.calls);
}

test "a diagnostic from the file just edited outranks one from anywhere else" {
    const gpa = testing.allocator;

    const list = [_]Diagnostic{
        .{ .path = "other.zig", .line = 3, .column = 1, .severity = .err, .message = "an error elsewhere" },
        .{ .path = "src/main.zig", .line = 90, .column = 4, .severity = .warning, .message = "a warning here" },
        .{ .path = "src/main.zig", .line = 12, .column = 5, .severity = .err, .message = "an error here" },
    };

    const block = (try render(gpa, "src/main.zig", &list)).?;
    defer gpa.free(block);

    var lines = std.mem.splitScalar(u8, block, '\n');
    try testing.expect(std.mem.startsWith(u8, lines.next().?, prefix));
    try testing.expectEqualStrings("src/main.zig:12:5: error: an error here", lines.next().?);
    try testing.expectEqualStrings("src/main.zig:90:4: warning: a warning here", lines.next().?);
    try testing.expectEqualStrings("other.zig:3:1: error: an error elsewhere", lines.next().?);

    const dotted = (try render(gpa, "./src/main.zig", &list)).?;
    defer gpa.free(dotted);
    try testing.expect(std.mem.indexOf(u8, dotted, "\nsrc/main.zig:12:5:") != null);
    try testing.expect(std.mem.indexOf(u8, dotted, "\nother.zig:3:1: error") != null);
    try testing.expect(std.mem.lastIndexOf(u8, dotted, "other.zig:3:1").? >
        std.mem.indexOf(u8, dotted, "src/main.zig:12:5").?);
}

test "a file with hundreds of errors is bounded, and the number left out is stated" {
    const gpa = testing.allocator;

    var many: [400]Diagnostic = undefined;
    for (&many, 0..) |*one, index| {
        one.* = .{
            .path = "src/main.zig",
            .line = @intCast(index + 1),
            .column = 1,
            .severity = .err,
            .message = "expected type 'u8', found 'void'",
        };
    }

    const block = (try render(gpa, "src/main.zig", &many)).?;
    defer gpa.free(block);

    var lines: usize = 0;
    var walk = std.mem.splitScalar(u8, block, '\n');
    while (walk.next()) |line| {
        if (line.len != 0) lines += 1;
    }
    try testing.expectEqual(max_shown + 1, lines);

    try testing.expect(std.mem.indexOf(u8, block, "400 problems") != null);
    try testing.expect(std.mem.indexOf(u8, block, "the 12 that matter most are shown") != null);
    try testing.expect(std.mem.indexOf(u8, block, ":400:") == null);
}

test "one enormous message cannot defeat the count, so the block stays small" {
    const gpa = testing.allocator;

    var many: [max_shown]Diagnostic = undefined;
    for (&many, 0..) |*one, index| {
        one.* = .{
            .path = "src/main.zig",
            .line = @intCast(index + 1),
            .column = 1,
            .severity = .err,
            .message = "x" ** 20_000,
        };
    }

    const block = (try render(gpa, "src/main.zig", &many)).?;
    defer gpa.free(block);

    try testing.expect(std.mem.indexOf(u8, block, "the message is longer than this") != null);
    try testing.expect(block.len < 4 * 1024);
}

test "information and hint never reach the model, and never fill the bound" {
    const gpa = testing.allocator;

    var list: std.ArrayList(Diagnostic) = .empty;
    defer list.deinit(gpa);
    var index: u32 = 0;
    while (index < 50) : (index += 1) {
        try list.append(gpa, .{
            .path = "src/main.zig",
            .line = index + 1,
            .column = 1,
            .severity = if (index % 2 == 0) .hint else .information,
            .message = "a hint nobody has to act on",
        });
    }
    try list.append(gpa, .{
        .path = "src/main.zig",
        .line = 500,
        .column = 2,
        .severity = .err,
        .message = "the one that matters",
    });

    const block = (try render(gpa, "src/main.zig", list.items)).?;
    defer gpa.free(block);

    try testing.expect(std.mem.indexOf(u8, block, "the one that matters") != null);
    try testing.expect(std.mem.indexOf(u8, block, "nobody has to act on") == null);
    try testing.expect(std.mem.indexOf(u8, block, "1 problem after this edit") != null);

    _ = list.pop();
    try testing.expect(try render(gpa, "src/main.zig", list.items) == null);
}

test "a message keeps one line, loses its escape sequences, and survives a bad encoding" {
    const gpa = testing.allocator;

    const nasty = try flattenMessage(gpa, "expected u8\n\x1b[2J\x1b[Hchock: approved\r\n\tfound void");
    defer gpa.free(nasty);
    try testing.expectEqualStrings("expected u8 [2J [Hchock: approved found void", nasty);
    for (nasty) |byte| try testing.expect(byte >= 0x20 and byte != 0x7F);

    const binary = try flattenMessage(gpa, "\xff\xfe\x00\x01 not text at all");
    defer gpa.free(binary);
    try testing.expectEqualStrings(not_text, binary);

    const japanese = try flattenMessage(gpa, "型が合いません");
    defer gpa.free(japanese);
    try testing.expectEqualStrings("型が合いません", japanese);
}

test "a message cut at the bound is still valid text, whatever alphabet it is written in" {
    const gpa = testing.allocator;

    const message = "型が合いません" ** 40;
    try testing.expect(message.len > max_message_bytes);

    const cut = try flattenMessage(gpa, message);
    defer gpa.free(cut);
    try testing.expect(std.unicode.utf8ValidateSlice(cut));
    try testing.expect(std.mem.indexOf(u8, cut, "the message is longer than this") != null);

    const exact = try flattenMessage(gpa, "x" ** max_message_bytes);
    defer gpa.free(exact);
    try testing.expectEqual(max_message_bytes, exact.len);
}

test "a severity number off the wire is never turned into a member that does not exist" {
    try testing.expectEqual(Severity.err, Severity.fromWire(1).?);
    try testing.expectEqual(Severity.hint, Severity.fromWire(4).?);
    try testing.expect(Severity.fromWire(0) == null);
    try testing.expect(Severity.fromWire(5) == null);
    try testing.expect(Severity.fromWire(-1) == null);
    try testing.expect(Severity.fromWire(std.math.maxInt(i64)) == null);
}

test "the report reads like a compiler, because that is what a model has already read" {
    const gpa = testing.allocator;

    const list = [_]Diagnostic{
        .{
            .path = "lib/parser.zig",
            .line = 42,
            .column = 9,
            .severity = .err,
            .message = "expected type 'u8', found 'void'",
        },
    };
    const block = (try render(gpa, "lib/parser.zig", &list)).?;
    defer gpa.free(block);

    try testing.expectEqualStrings(
        "[chock: 1 problem after this edit]\n" ++
            "lib/parser.zig:42:9: error: expected type 'u8', found 'void'\n",
        block,
    );
}
