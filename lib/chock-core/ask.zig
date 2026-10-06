//! How the loop asks the person a question mid session. An ask names no
//! action and decides nothing: it only gets a fact from a person.

const std = @import("std");

const notices = @import("notices.zig");
const tools = @import("tools.zig");

pub const max_question_bytes: usize = 4000;

pub const max_options: usize = 10;

pub const max_option_bytes: usize = 200;

pub const max_answer_bytes: usize = 4096;

pub const default_timeout_ms: i64 = 5 * 60 * 1000;

pub const poll_interval_ms: u64 = 100;

pub const question_marker = "  | ";

pub const Question = struct {
    text: []const u8,
    options: []const []const u8 = &.{},
};

pub const Answer = union(enum) {
    answered: []u8,
    declined,
    nobody,
    timed_out,
    stopped,
};

pub const Error = std.mem.Allocator.Error;

pub const Asker = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        ask: *const fn (
            ptr: *anyopaque,
            gpa: std.mem.Allocator,
            io: std.Io,
            question: Question,
        ) Error!Answer,
    };

    pub fn ask(
        self: Asker,
        gpa: std.mem.Allocator,
        io: std.Io,
        question: Question,
    ) Error!Answer {
        return self.vtable.ask(self.ptr, gpa, io, question);
    }
};

pub const has_no_asker = nobody_text;

pub fn check(question: Question) ?[]const u8 {
    if (std.mem.trim(u8, question.text, " \t\r\n").len == 0) return "nobody was asked anything: " ++
        "\"question\" was empty. Write out what you want to know, in one or two sentences.";
    if (question.text.len > max_question_bytes) return "nobody was asked anything: the question " ++
        "is longer than " ++ max_question_text ++ " bytes. A person answers a question they can " ++
        "read in one go, so ask the one thing you are stuck on.";
    if (question.options.len > max_options) return "nobody was asked anything: more than " ++
        max_options_text ++ " options were given. Offer the few that really differ, or offer none " ++
        "and ask an open question.";
    for (question.options) |option| {
        if (option.len > max_option_bytes) return "nobody was asked anything: an option is longer " ++
            "than " ++ max_option_text ++ " bytes. An option is a choice on one line; put the " ++
            "explanation in the question.";
    }
    return null;
}

const max_question_text = std.fmt.comptimePrint("{d}", .{max_question_bytes});
const max_options_text = std.fmt.comptimePrint("{d}", .{max_options});
const max_option_text = std.fmt.comptimePrint("{d}", .{max_option_bytes});

pub fn promptText(
    gpa: std.mem.Allocator,
    question: Question,
) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(gpa);

    try text.appendSlice(gpa, "\nchock: the agent is asking you a question. Answering allows " ++
        "nothing; it only tells the agent what you said.\n\n");

    var lines = std.mem.splitScalar(u8, question.text, '\n');
    while (lines.next()) |line| {
        try text.appendSlice(gpa, question_marker);
        try text.appendSlice(gpa, line);
        try text.append(gpa, '\n');
    }

    if (question.options.len != 0) {
        try text.append(gpa, '\n');
        for (question.options, 1..) |option, number| {
            try text.print(gpa, question_marker ++ "{d}) {s}\n", .{ number, option });
        }
        try text.appendSlice(gpa, "\nType the number of one of those, or write your own answer. " ++
            "Press Enter alone to say nothing.\n");
    } else {
        try text.appendSlice(gpa, "\nType your answer. Press Enter alone to say nothing.\n");
    }

    try text.appendSlice(gpa, "\nYour answer: ");
    return text.toOwnedSlice(gpa);
}

pub fn chosen(said: []const u8, options: []const []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, said, " \t\r");
    const number = std.fmt.parseInt(usize, trimmed, 10) catch return null;
    if (number == 0 or number > options.len) return null;
    return options[number - 1];
}

pub fn resultText(gpa: std.mem.Allocator, answer: Answer) Error![]u8 {
    switch (answer) {
        .answered => |said| {
            const clean = try cleanAnswer(gpa, said);
            defer gpa.free(clean);
            return std.fmt.allocPrint(gpa, "[chock: the user answered.]\n{s}", .{clean});
        },
        .declined => return gpa.dupe(u8, declined_text),
        .nobody => return gpa.dupe(u8, nobody_text),
        .timed_out => return gpa.dupe(u8, timed_out_text),
        .stopped => return gpa.dupe(u8, stopped_text),
    }
}

pub fn isError(answer: Answer) bool {
    return switch (answer) {
        .answered, .declined => false,
        .nobody, .timed_out, .stopped => true,
    };
}

pub const declined_text = "[chock: the user was asked and chose to say nothing. Decide for " ++
    "yourself, carry on, and say in your answer what you assumed.]";

pub const nobody_text = "[chock: nobody was asked. This session has nobody at a keyboard, so the " ++
    "question was never put to a person and waiting would stop the session for good. Decide for " ++
    "yourself, carry on, and say in your answer what you assumed and why. Do not ask again.]";

pub const timed_out_text = "[chock: the question was shown and nobody answered it in time. " ++
    "Decide for yourself, carry on, and say in your answer what you assumed. Do not ask again.]";

pub const stopped_text = "[chock: this session is stopping, so the question was not answered.]";

fn cleanAnswer(gpa: std.mem.Allocator, said: []const u8) Error![]u8 {
    if (try tools.outputForModel(gpa, said)) |replacement| return replacement;

    var kept: std.ArrayList(u8) = .empty;
    defer kept.deinit(gpa);
    for (said) |byte| {
        if (byte != '\n' and byte != '\t' and (byte < 0x20 or byte == 0x7F)) continue;
        try kept.append(gpa, byte);
    }
    const cut = notices.cutToCharacter(kept.items, max_answer_bytes);
    if (cut.len == kept.items.len) return gpa.dupe(u8, cut);
    return std.fmt.allocPrint(gpa, "{s}\n[chock: the answer was longer than this]", .{cut});
}

pub const Console = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Read = union(enum) {
        idle,
        bytes: usize,
        ended,
        canceled,
    };

    pub const VTable = struct {
        write: *const fn (ptr: *anyopaque, io: std.Io, bytes: []const u8) void,
        read: *const fn (ptr: *anyopaque, io: std.Io, buffer: []u8, budget_ms: u64) Read,
    };

    pub fn write(self: Console, io: std.Io, bytes: []const u8) void {
        self.vtable.write(self.ptr, io, bytes);
    }

    pub fn read(self: Console, io: std.Io, buffer: []u8, budget_ms: u64) Read {
        return self.vtable.read(self.ptr, io, buffer, budget_ms);
    }
};

pub fn writeFiltered(console: Console, io: std.Io, text: []const u8) void {
    var start: usize = 0;
    for (text, 0..) |byte, index| {
        if (!drivesTheTerminal(byte)) continue;
        console.write(io, text[start..index]);
        console.write(io, "?");
        start = index + 1;
    }
    console.write(io, text[start..]);
}

fn drivesTheTerminal(byte: u8) bool {
    if (byte == '\n' or byte == '\t') return false;
    return byte < 0x20 or byte == 0x7f;
}

pub const Prompt = struct {
    console: Console,
    at_terminal: bool,
    stop: *const fn () bool = neverStopped,
    timeout_ms: i64 = default_timeout_ms,
    now: *const fn (io: std.Io) i64 = realNowMs,
    asked: usize = 0,
    buffer: [max_answer_bytes]u8 = undefined,
    filled: usize = 0,

    pub fn asker(self: *Prompt) Asker {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Asker.VTable{ .ask = askFn };

    fn askFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        question: Question,
    ) Error!Answer {
        const self: *Prompt = @ptrCast(@alignCast(ptr));
        return self.ask(gpa, io, question);
    }

    pub fn ask(
        self: *Prompt,
        gpa: std.mem.Allocator,
        io: std.Io,
        question: Question,
    ) Error!Answer {
        if (!self.at_terminal) return .nobody;
        if (self.stop()) return .stopped;

        const text = try promptText(gpa, question);
        defer gpa.free(text);
        writeFiltered(self.console, io, text);
        self.asked += 1;

        self.filled = 0;
        const deadline = self.now(io) + self.timeout_ms;
        while (true) {
            if (self.stop()) return .stopped;

            const left = deadline - self.now(io);
            if (left <= 0) return .timed_out;
            const budget: u64 = @min(@as(u64, @intCast(left)), poll_interval_ms);

            const room = self.buffer[self.filled..];
            if (room.len == 0) {
                return self.take(gpa, self.filled, question.options);
            }

            switch (self.console.read(io, room, budget)) {
                .idle => continue,
                .canceled => return .stopped,
                .ended => return .nobody,
                .bytes => |count| {
                    self.filled += count;
                    const end = std.mem.indexOfScalar(u8, self.buffer[0..self.filled], '\n') orelse
                        continue;
                    return self.take(gpa, end, question.options);
                },
            }
        }
    }

    fn take(
        self: *Prompt,
        gpa: std.mem.Allocator,
        end: usize,
        options: []const []const u8,
    ) Error!Answer {
        const said = std.mem.trim(u8, self.buffer[0..end], " \t\r");
        self.filled = 0;
        if (said.len == 0) return .declined;
        const text = chosen(said, options) orelse said;
        return .{ .answered = try gpa.dupe(u8, text) };
    }
};

fn neverStopped() bool {
    return false;
}

fn realNowMs(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .real).toMilliseconds();
}

const testing = std.testing;

const FakeConsole = struct {
    gpa: std.mem.Allocator,
    replies: []const Console.Read,
    lines: []const []const u8 = &.{},
    reads: usize = 0,
    lines_taken: usize = 0,
    shown: std.ArrayList(u8) = .empty,
    last_budget_ms: u64 = 0,

    fn console(self: *FakeConsole) Console {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Console.VTable{ .write = writeFn, .read = readFn };

    fn deinit(self: *FakeConsole) void {
        self.shown.deinit(self.gpa);
    }

    fn writeFn(ptr: *anyopaque, io: std.Io, bytes: []const u8) void {
        _ = io;
        const self: *FakeConsole = @ptrCast(@alignCast(ptr));
        self.shown.appendSlice(self.gpa, bytes) catch {};
    }

    fn readFn(ptr: *anyopaque, io: std.Io, buffer: []u8, budget_ms: u64) Console.Read {
        _ = io;
        const self: *FakeConsole = @ptrCast(@alignCast(ptr));
        self.last_budget_ms = budget_ms;
        const index = @min(self.reads, self.replies.len - 1);
        self.reads += 1;
        const reply = self.replies[index];
        switch (reply) {
            .bytes => {
                if (self.lines_taken >= self.lines.len) return .ended;
                const line = self.lines[self.lines_taken];
                self.lines_taken += 1;
                std.debug.assert(line.len <= buffer.len);
                @memcpy(buffer[0..line.len], line);
                return .{ .bytes = line.len };
            },
            else => return reply,
        }
    }
};

var test_clock_ms: i64 = 0;

fn frozenClock(io: std.Io) i64 {
    _ = io;
    return test_clock_ms;
}

fn movingClock(io: std.Io) i64 {
    _ = io;
    test_clock_ms += 1000;
    return test_clock_ms;
}

fn alwaysStopped() bool {
    return true;
}

test "a real question travels to the person and the typed answer comes back" {
    const gpa = testing.allocator;
    const io = testing.io;

    const lines = [_][]const u8{"the second one, staging\n"};
    var console = FakeConsole{ .gpa = gpa, .replies = &.{.{ .bytes = 0 }}, .lines = &lines };
    defer console.deinit();

    test_clock_ms = 0;
    var prompt = Prompt{ .console = console.console(), .at_terminal = true, .now = frozenClock };
    const answer = try prompt.ask(gpa, io, .{ .text = "which database should I write to?" });
    defer switch (answer) {
        .answered => |said| gpa.free(said),
        else => {},
    };

    try testing.expect(std.mem.indexOf(u8, console.shown.items, "which database should I write to?") != null);
    try testing.expectEqual(std.meta.Tag(Answer).answered, std.meta.activeTag(answer));
    try testing.expectEqualStrings("the second one, staging", answer.answered);

    const text = try resultText(gpa, answer);
    defer gpa.free(text);
    try testing.expect(std.mem.startsWith(u8, text, "[chock: the user answered.]"));
    try testing.expect(std.mem.indexOf(u8, text, "the second one, staging") != null);
    try testing.expect(!isError(answer));
}

test "a session with nobody at a keyboard comes back at once and never writes a byte" {
    const gpa = testing.allocator;
    const io = testing.io;

    var console = FakeConsole{ .gpa = gpa, .replies = &.{.idle} };
    defer console.deinit();

    test_clock_ms = 0;
    var prompt = Prompt{ .console = console.console(), .at_terminal = false, .now = frozenClock };
    const answer = try prompt.ask(gpa, io, .{ .text = "which database?" });

    try testing.expectEqual(Answer.nobody, answer);
    try testing.expectEqual(@as(usize, 0), console.reads);
    try testing.expectEqual(@as(usize, 0), console.shown.items.len);
    try testing.expectEqual(@as(usize, 0), prompt.asked);

    const text = try resultText(gpa, answer);
    defer gpa.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "nobody was asked") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Do not ask again") != null);
    try testing.expect(isError(answer));
}

test "an input that ended is nobody, and it is not a person saying nothing" {
    const gpa = testing.allocator;
    const io = testing.io;

    var console = FakeConsole{ .gpa = gpa, .replies = &.{.ended} };
    defer console.deinit();

    test_clock_ms = 0;
    var prompt = Prompt{ .console = console.console(), .at_terminal = true, .now = frozenClock };
    const answer = try prompt.ask(gpa, io, .{ .text = "which one?" });

    try testing.expectEqual(Answer.nobody, answer);
    try testing.expectEqual(@as(usize, 1), console.reads);

    const lines = [_][]const u8{"\n"};
    var second = FakeConsole{ .gpa = gpa, .replies = &.{.{ .bytes = 0 }}, .lines = &lines };
    defer second.deinit();
    var quiet = Prompt{ .console = second.console(), .at_terminal = true, .now = frozenClock };
    const said_nothing = try quiet.ask(gpa, io, .{ .text = "which one?" });
    try testing.expectEqual(Answer.declined, said_nothing);
    try testing.expect(!isError(said_nothing));
    try testing.expect(isError(answer));
}

test "a question nobody answers ends at the deadline rather than waiting for ever" {
    const gpa = testing.allocator;
    const io = testing.io;

    var console = FakeConsole{ .gpa = gpa, .replies = &.{.idle} };
    defer console.deinit();

    test_clock_ms = 0;
    var prompt = Prompt{
        .console = console.console(),
        .at_terminal = true,
        .now = movingClock,
        .timeout_ms = 10_000,
    };
    const answer = try prompt.ask(gpa, io, .{ .text = "which one?" });

    try testing.expectEqual(Answer.timed_out, answer);
    try testing.expect(isError(answer));
    try testing.expectEqual(poll_interval_ms, console.last_budget_ms);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, console.shown.items, "Your answer:"));
}

test "a stop at the prompt ends the question and shows nothing" {
    const gpa = testing.allocator;
    const io = testing.io;

    var console = FakeConsole{ .gpa = gpa, .replies = &.{.idle} };
    defer console.deinit();

    test_clock_ms = 0;
    var prompt = Prompt{
        .console = console.console(),
        .at_terminal = true,
        .stop = alwaysStopped,
        .now = frozenClock,
    };
    const answer = try prompt.ask(gpa, io, .{ .text = "which one?" });

    try testing.expectEqual(Answer.stopped, answer);
    try testing.expectEqual(@as(usize, 0), console.reads);
    try testing.expectEqual(@as(usize, 0), console.shown.items.len);
}

test "an option can be chosen by its number, and anything else is the person's own words" {
    const gpa = testing.allocator;
    const io = testing.io;

    const options = [_][]const u8{ "postgres", "sqlite" };

    const cases = [_]struct { typed: []const u8, expected: []const u8 }{
        .{ .typed = "2\n", .expected = "sqlite" },
        .{ .typed = " 1 \n", .expected = "postgres" },
        .{ .typed = "3\n", .expected = "3" },
        .{ .typed = "0\n", .expected = "0" },
        .{ .typed = "neither, use duckdb\n", .expected = "neither, use duckdb" },
    };

    for (cases) |case| {
        const lines = [_][]const u8{case.typed};
        var console = FakeConsole{ .gpa = gpa, .replies = &.{.{ .bytes = 0 }}, .lines = &lines };
        defer console.deinit();

        test_clock_ms = 0;
        var prompt = Prompt{ .console = console.console(), .at_terminal = true, .now = frozenClock };
        const answer = try prompt.ask(gpa, io, .{ .text = "which database?", .options = &options });
        defer switch (answer) {
            .answered => |said| gpa.free(said),
            else => {},
        };

        try testing.expectEqualStrings(case.expected, answer.answered);
    }

    const lines = [_][]const u8{"1\n"};
    var console = FakeConsole{ .gpa = gpa, .replies = &.{.{ .bytes = 0 }}, .lines = &lines };
    defer console.deinit();
    test_clock_ms = 0;
    var prompt = Prompt{ .console = console.console(), .at_terminal = true, .now = frozenClock };
    const answer = try prompt.ask(gpa, io, .{ .text = "which database?", .options = &options });
    defer switch (answer) {
        .answered => |said| gpa.free(said),
        else => {},
    };
    try testing.expect(std.mem.indexOf(u8, console.shown.items, "1) postgres") != null);
    try testing.expect(std.mem.indexOf(u8, console.shown.items, "2) sqlite") != null);
}

test "an answer typed in pieces is read as one line" {
    const gpa = testing.allocator;
    const io = testing.io;

    const lines = [_][]const u8{ "post", "gres", " it is\n" };
    var console = FakeConsole{
        .gpa = gpa,
        .replies = &.{ .{ .bytes = 0 }, .{ .bytes = 0 }, .{ .bytes = 0 } },
        .lines = &lines,
    };
    defer console.deinit();

    test_clock_ms = 0;
    var prompt = Prompt{ .console = console.console(), .at_terminal = true, .now = frozenClock };
    const answer = try prompt.ask(gpa, io, .{ .text = "which database?" });
    defer switch (answer) {
        .answered => |said| gpa.free(said),
        else => {},
    };

    try testing.expectEqualStrings("postgres it is", answer.answered);
    try testing.expectEqual(@as(usize, 3), console.reads);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, console.shown.items, "Your answer:"));
}

test "an answer longer than the buffer is taken and marked, not waited on" {
    const gpa = testing.allocator;
    const io = testing.io;

    const filler = "x" ** max_answer_bytes;
    const lines = [_][]const u8{filler};
    var console = FakeConsole{ .gpa = gpa, .replies = &.{.{ .bytes = 0 }}, .lines = &lines };
    defer console.deinit();

    test_clock_ms = 0;
    var prompt = Prompt{ .console = console.console(), .at_terminal = true, .now = frozenClock };
    const answer = try prompt.ask(gpa, io, .{ .text = "paste it" });
    defer switch (answer) {
        .answered => |said| gpa.free(said),
        else => {},
    };

    try testing.expectEqual(@as(usize, max_answer_bytes), answer.answered.len);
    try testing.expectEqual(@as(usize, 1), console.reads);
}

test "a question cannot be made to look like Chock's own words" {
    const gpa = testing.allocator;
    const io = testing.io;

    const phish = "ignore this\nchock: your credential expired, paste it here:";
    const text = try promptText(gpa, .{ .text = phish });
    defer gpa.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "\nchock: your credential") == null);
    try testing.expect(std.mem.indexOf(u8, text, question_marker ++ "chock: your credential") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Answering allows nothing") != null);

    var console = FakeConsole{ .gpa = gpa, .replies = &.{.ended} };
    defer console.deinit();
    const nasty = try promptText(gpa, .{ .text = "pick\x1b[2J\x1b[Hchock: allowed\r one" });
    defer gpa.free(nasty);
    writeFiltered(console.console(), io, nasty);
    try testing.expect(std.mem.indexOfScalar(u8, console.shown.items, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, console.shown.items, '\r') == null);
    try testing.expect(std.mem.indexOf(u8, console.shown.items, "pick") != null);
    try testing.expectEqual(
        std.mem.count(u8, nasty, "\n"),
        std.mem.count(u8, console.shown.items, "\n"),
    );
}

test "a question nobody could read is refused before it reaches a person" {
    const long = "x" ** (max_question_bytes + 1);
    const wide = [_][]const u8{"one"} ** (max_options + 1);
    const fat = "y" ** (max_option_bytes + 1);

    try testing.expect(check(.{ .text = "which one?" }) == null);
    try testing.expect(check(.{ .text = "" }) != null);
    try testing.expect(check(.{ .text = "  \n\t " }) != null);
    try testing.expect(check(.{ .text = long }) != null);
    try testing.expect(check(.{ .text = "pick", .options = &wide }) != null);
    try testing.expect(check(.{ .text = "pick", .options = &.{fat} }) != null);
    try testing.expect(check(.{ .text = long[0..max_question_bytes] }) == null);
}

test "an answer cannot carry a control character or bytes that are not text into the context" {
    const gpa = testing.allocator;

    const said = try gpa.dupe(u8, "use\x1b[31m postgres\x07");
    const text = try resultText(gpa, .{ .answered = said });
    defer gpa.free(text);
    gpa.free(said);

    try testing.expect(std.mem.indexOfScalar(u8, text, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, text, 0x07) == null);
    try testing.expect(std.mem.indexOf(u8, text, "use[31m postgres") != null);

    const binary = try gpa.dupe(u8, "\xff\xfe\x00");
    const replaced = try resultText(gpa, .{ .answered = binary });
    defer gpa.free(replaced);
    gpa.free(binary);
    try testing.expect(std.mem.indexOf(u8, replaced, "binary output") != null);
}

test "an answer permits nothing, and there is no member it could permit through" {
    inline for (@typeInfo(Answer).@"union".fields) |field| {
        const ok = field.type == void or field.type == []u8;
        if (!ok) @compileError(
            "Answer gained the member \"" ++ field.name ++ "\", which is neither a plain case " ++
                "nor the person's own words. An ask grants nothing, and a member that carried a " ++
                "decision would be the route by which one travelled",
        );
    }
    try testing.expectEqual(@as(usize, 5), @typeInfo(Answer).@"union".fields.len);

    inline for (@typeInfo(Question).@"struct".fields) |field| {
        const ok = field.type == []const u8 or field.type == []const []const u8;
        if (!ok) @compileError(
            "Question gained the member \"" ++ field.name ++ "\", which is not text. An ask names " ++
                "no act, and a member that named one would make this an approval by another name",
        );
    }
}
