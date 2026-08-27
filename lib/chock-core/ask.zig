//! How the loop asks the person a question in the middle of a session.
//!
//! ## An ask is not an approval, and the two must never become one
//!
//! An approval asks "may I do this act". It names one `chock_broker.actions`
//! action, the policy table weighs it, and the answer is a decision recorded
//! against that act. An ask wants a fact a person holds and nothing else:
//! "which of these two APIs should I use", "is this the right database name".
//!
//! **An ask grants nothing and permits nothing.** A person who types "yes" into
//! one has authorised no act, because there is no act here to authorise.
//!
//! **A later reader will want to unify the two.** Do not. The moment a free
//! text question can produce a decision, "may I read your credential file" and
//! "which API should I use" travel the same road, and the person answering
//! cannot tell which of the two they are looking at.
//!
//! ## The wall this goes through, and why there is no log write here
//!
//! An ask already has a place in the log: the `tool.call` the model made and
//! the `tool.result` the loop appends for it. Both are written by `Loop.runTool`
//! through the handle it already holds. **So nothing here opens the log, takes a
//! lock, or appends anything**, and there is no second writer to arrange.
//!
//! ## A refusal is the safe answer
//!
//! A subagent, a session the daemon started, and a `chock run` whose standard
//! input is a pipe all have nobody at the keyboard. A question nobody can answer
//! must not hold the session while it waits: the session lock is held for the
//! whole of that wait, so a hang there stops everything. `Prompt.ask` therefore
//! reads `at_terminal` first and answers `.nobody` before it writes a byte, the
//! same shape `src/approval.zig`'s own `timeoutMs` keeps for an approval.
//!
//! **An approval is less crude than this, and deliberately so.**
//! `chock_broker.socket.timeoutMs` gives a session with no terminal the full
//! deadline when a client is already attached to its approval socket, because
//! somebody really can answer. **That is not yet true of a question**, and the
//! difference is a fact and not a rule: an ask travels over no socket, and
//! `src/approve.zig` reads only an `approval.request` frame and answers only an
//! `approval.response`. A client attached to a session today therefore cannot
//! answer a question at all, and giving one the full deadline on the strength of
//! an attached client would be exactly the hang this whole section exists to
//! stop. When a client can answer a question, `Asker` is the seam that changes
//! and nothing above it does: `src/run.zig` builds the implementation and
//! decides who counts as somebody.
//!
//! ## The question is written by the model
//!
//! It is therefore untrusted text put in front of a person, and the fault to
//! stop is a question that reads as Chock's own words. A question that rendered
//! as "chock: your credential expired, paste it here" would be a phishing
//! surface inside the user's own terminal. Two things stop it, and both are
//! tested below:
//!
//! * **Every line of the question is written after `question_marker`**, so no
//!   byte the model chose can start a line. Chock's own lines in the prompt
//!   start at column zero, and the model cannot reach column zero.
//! * **Every byte a terminal reads as an instruction is replaced**, so a cursor
//!   move cannot repaint the prompt and a carriage return cannot overwrite the
//!   marker. This is the same defence `src/approval.zig` puts in front of a diff
//!   and it has the same honest limit: it does not cover the characters that
//!   reverse a line's direction, or a word that reads like another word.
//!
//! ## The answer passes the redaction chokepoint
//!
//! The person's answer travels back as one ordinary tool result, which
//! `Loop.runTool` appends and folds into the context. Every request leaves this
//! library through `Loop.sendOnce`, which is the one place a request meets
//! `lib/chock-core/redact.zig`, and `redact.parts` covers a `tool_result` part.
//! So an answer that quotes a credential Chock holds is redacted on the way to
//! the provider by the same code that redacts a file the agent read. There is no
//! second road out.

const std = @import("std");

const notices = @import("notices.zig");
const tools = @import("tools.zig");

/// The longest question a person is asked to read.
///
/// **Refused rather than cut.** A cut question is one the person answers
/// without having seen the end of it, and the model is the one thing here that
/// can fix the fault: it is told to ask something shorter and it asks again.
pub const max_question_bytes: usize = 4000;

/// How many options one question may offer. More than this is a menu nobody
/// reads, and the answer to a menu nobody reads is the first line of it.
pub const max_options: usize = 10;

/// The longest one option may be. An option is a choice on one line.
pub const max_option_bytes: usize = 200;

/// The longest answer this reads before it stops waiting for the rest of the
/// line. A person's answer to one question is a sentence, and a paste larger
/// than this is taken as far as this and marked, rather than dropped.
pub const max_answer_bytes: usize = 4096;

/// How long the question stays on screen before nobody answering is the answer.
///
/// **The same five minutes an approval waits**, which is
/// `chock_broker.Broker.default_timeout_ms`. It is written again here rather
/// than imported because `chock-core` imports no `chock-broker`, per
/// `lib/chock-core/arbiter.zig`'s own top comment. Long enough to read a
/// question and think, and short enough that a session nobody is watching stops
/// instead of holding the session lock all night.
pub const default_timeout_ms: i64 = 5 * 60 * 1000;

/// How long one read of the console waits before the stop flag is looked at
/// again. Small enough that Ctrl-C at the prompt is noticed at once, and large
/// enough that waiting is not a busy loop.
pub const poll_interval_ms: u64 = 100;

/// What every line of the model's own question is written after.
///
/// **This is the boundary between the model's words and Chock's.**
pub const question_marker = "  | ";

/// What the loop wants asked. Every string is borrowed for the call.
pub const Question = struct {
    /// What the model wants to know, in its own words.
    text: []const u8,
    /// The answers the model would like to be given, or empty for a question
    /// with none. **Never a closed list**: see `Prompt.ask`, which takes typed
    /// text whether or not it matches one of these.
    options: []const []const u8 = &.{},
};

/// What came back.
///
/// **There is no member that permits anything**, and that is deliberate. The
/// most an answer can be is words.
pub const Answer = union(enum) {
    /// What the person typed, or the option they chose by number. Allocated
    /// with the `gpa` the call was given, and the caller frees it.
    answered: []u8,
    /// The person was asked and pressed Enter without typing. A deliberate "no
    /// answer", which is a different fact from nobody being there.
    declined,
    /// Nobody could be asked, so the question was never put to anybody. See
    /// this file's own top comment.
    nobody,
    /// The question was shown and the deadline passed with nothing typed.
    timed_out,
    /// The session is stopping, so the question was abandoned.
    stopped,
};

pub const Error = std.mem.Allocator.Error;

/// The seam itself.
///
/// **A vtable for the reason `chock_core.arbiter.Arbiter` is one**: what asks a
/// person is a terminal, a display, or a client on a socket, and every one of
/// those is `src/`'s to own because `lib/` writes to no device of its own. The
/// loop holds this, `src/run.zig` fills it in.
pub const Asker = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Put one question to a person. **Not being able to ask is not an
        /// error**: it is an `Answer` the agent reads and acts on, the same rule
        /// every tool call in Chock follows. Only running out of memory reaches
        /// the caller.
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

/// What an `ask_user` call gets when the session was started with no asker.
///
/// **A session with no asker is a real case and not a stub.** Every test of the
/// loop runs as one, and so does any caller that drives a session with no
/// terminal wired to it. The words are the same ones `Answer.nobody` gets,
/// because they are the same fact to the agent: nobody was asked.
pub const has_no_asker = nobody_text;

/// Why one question could not be asked at all, or null when it can be.
///
/// **Every one of these is the model's own to fix**, so the sentence says what
/// to send instead. A question that is refused reaches no person and costs
/// nobody's attention.
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

/// The question, as a person reads it. The caller owns the result.
pub fn promptText(
    gpa: std.mem.Allocator,
    question: Question,
) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(gpa);

    // Chock's own line, at column zero, and it says whose words follow. **It
    // never says an act needs permission**: this is a question and nothing here
    // can allow anything. See this file's own top comment.
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

/// The option a typed line names by its number, or null when it names none.
///
/// **A number is a shortcut and never a wall.** Anything that is not a number in
/// range is the person's own words, and the words are what the model is told.
pub fn chosen(said: []const u8, options: []const []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, said, " \t\r");
    const number = std.fmt.parseInt(usize, trimmed, 10) catch return null;
    if (number == 0 or number > options.len) return null;
    return options[number - 1];
}

/// What the model reads. The caller owns the result.
///
/// **The person's own words are put after a line of Chock's**, the same shape
/// `chock_core.fetch.textForModel` uses for a page. The header is what tells the
/// model whether it is reading an answer or reading the reason there is none.
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

/// Whether a result built from this answer is an error result.
///
/// **Only the three that carry no answer.** A person who deliberately said
/// nothing has answered the question, and a model told that was an error would
/// ask it again.
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

/// One answer, safe to put in the context.
///
/// A person can paste anything, so this does what
/// `chock_core.mcp.textForModel` does to a third party tool result, for the same
/// reasons stated there: bytes that are not valid UTF-8 are replaced, because
/// `std.json.Stringify` writes those as an array of integers and a provider
/// answers 400 to it, and every control character other than the newline and the
/// tab is removed.
fn cleanAnswer(gpa: std.mem.Allocator, said: []const u8) Error![]u8 {
    if (try tools.outputForModel(gpa, said)) |replacement| return replacement;

    var kept: std.ArrayList(u8) = .empty;
    defer kept.deinit(gpa);
    for (said) |byte| {
        // Only ASCII control characters are checked byte by byte, which is safe
        // over UTF-8: every byte of a multi byte character is 0x80 or above, so
        // none of them can be mistaken for one.
        if (byte != '\n' and byte != '\t' and (byte < 0x20 or byte == 0x7F)) continue;
        try kept.append(gpa, byte);
    }
    const cut = notices.cutToCharacter(kept.items, max_answer_bytes);
    if (cut.len == kept.items.len) return gpa.dupe(u8, cut);
    return std.fmt.allocPrint(gpa, "{s}\n[chock: the answer was longer than this]", .{cut});
}

/// Where the question goes and where the answer comes from.
///
/// **This is the same shape `src/approval.zig`'s own `Console` has, and it is a
/// second copy on purpose.** That one lives in `src/`, and nothing under `lib/`
/// may import `src/`. The two are joined by a bridge in `src/run.zig` that is
/// twenty lines of forwarding, which is the cost of the rule that keeps every
/// device in `src/`.
pub const Console = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    /// How one call to `read` ended.
    pub const Read = union(enum) {
        /// The budget passed with nothing typed. Look again.
        idle,
        /// This many bytes were read into the buffer.
        bytes: usize,
        /// The input ended. **There is nobody there**, which is not the same
        /// fact as somebody saying nothing.
        ended,
        /// Something asked this session to stop.
        canceled,
    };

    pub const VTable = struct {
        /// Show these bytes. **The result is dropped**: a terminal that went
        /// away must not turn a question into a crash.
        write: *const fn (ptr: *anyopaque, io: std.Io, bytes: []const u8) void,
        /// Wait at most `budget_ms` for something to be typed, and read what
        /// arrived into `buffer`. See `Read` for the four ways it ends.
        read: *const fn (ptr: *anyopaque, io: std.Io, buffer: []u8, budget_ms: u64) Read,
    };

    pub fn write(self: Console, io: std.Io, bytes: []const u8) void {
        self.vtable.write(self.ptr, io, bytes);
    }

    pub fn read(self: Console, io: std.Io, buffer: []u8, budget_ms: u64) Read {
        return self.vtable.read(self.ptr, io, buffer, budget_ms);
    }
};

/// Write text to a console with the bytes that drive a terminal taken out.
///
/// Tabs and newlines are kept, because a question may be more than one line.
/// Every other byte below a space, and the delete byte, becomes a lone question
/// mark, so the text a person reads keeps the same number of lines. Bytes at or
/// above `0x80` are passed through, because a question in a language other than
/// English is UTF-8.
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

/// True for a byte a terminal reads as an instruction rather than as text.
fn drivesTheTerminal(byte: u8) bool {
    if (byte == '\n' or byte == '\t') return false;
    return byte < 0x20 or byte == 0x7f;
}

/// An `Asker` that asks the person at a console.
///
/// **Built in place and never copied.** An `Asker` holds a pointer into this
/// struct, so a copy of it is an asker pointing at a value that has moved.
pub const Prompt = struct {
    console: Console,
    /// Whether there is anybody at that console. **Read before anything is
    /// written**, so a session with nobody comes straight back: see this file's
    /// own top comment.
    at_terminal: bool,
    /// Whether a stop has been asked for. A field so a test can answer it
    /// without raising a real signal at the whole test binary, the same shape
    /// `src/approval.zig` uses and for the same reason.
    stop: *const fn () bool = neverStopped,
    /// How long one question waits.
    timeout_ms: i64 = default_timeout_ms,
    /// What the deadline is measured against. **A field for the reason `stop` is
    /// one**: no test in this file measures elapsed time, so a test that wants
    /// the deadline reached moves this clock itself.
    now: *const fn (io: std.Io) i64 = realNowMs,
    /// How many questions reached the console. Counted rather than only shown,
    /// so a test can pin that a refused question reached nobody.
    asked: usize = 0,
    /// What has been typed so far and does not yet end a line.
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

    /// Put one question up and wait for a line, for at most `timeout_ms`.
    pub fn ask(
        self: *Prompt,
        gpa: std.mem.Allocator,
        io: std.Io,
        question: Question,
    ) Error!Answer {
        // **First, and before a byte is written.** A session with nobody at a
        // keyboard must come back at once: the session lock is held for the
        // whole of any wait, so a wait here stops everything else too.
        if (!self.at_terminal) return .nobody;
        // A person who pressed Ctrl-C is leaving, not answering.
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
                // A line longer than the buffer, which is a paste and not a
                // typed sentence. **Taken rather than dropped**: the person did
                // answer, and `cleanAnswer` marks the cut so the model is not
                // told a part is the whole. Reading on with no room would wait
                // out the deadline over a buffer nothing can add to.
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

    /// What the line up to `end` says.
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

// **No test here reads standard input**, which is the one thing this file is
// about: a test that did would wait for a person nobody is going to send. Every
// test drives `FakeConsole` instead. **No test measures elapsed time** either:
// the deadline is measured against `Prompt.now`, which a test moves itself.

const testing = std.testing;

/// A `Console` a test scripts. It never touches a terminal.
const FakeConsole = struct {
    gpa: std.mem.Allocator,
    /// What `read` answers, in order. The last one is repeated, so a test that
    /// scripts one answer does not depend on how many times the prompt looks.
    replies: []const Console.Read,
    /// The bytes each `bytes` reply delivers, in the same order.
    lines: []const []const u8 = &.{},
    reads: usize = 0,
    lines_taken: usize = 0,
    /// Everything that was shown, joined.
    shown: std.ArrayList(u8) = .empty,
    /// The budget of the last read, so a test can pin that the wait is bounded.
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
                // A script that ran out of lines has said everything it was
                // going to. Ending is the answer that cannot hang a test.
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

/// A clock a test moves. **A file scoped value, because `Prompt.now` is a plain
/// function pointer and not a closure**, which is what keeps `Prompt` copyable
/// and free of an allocator.
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
    // The whole point of this file in one drive. Before this, an agent that
    // needed a fact a person holds had no way to ask for it.
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

    // Mutation check: return `.declined` from `Prompt.take` for a line that is
    // not empty, and the `expectEqualStrings` on the answer fails.
}

test "a session with nobody at a keyboard comes back at once and never writes a byte" {
    // **The refusal path, and the reason it has to be fast.** A subagent, a
    // daemon session and a piped `chock run` all reach here. The session lock is
    // held for the whole of any wait, so a question that waited would stop
    // everything else in the session as well.
    const gpa = testing.allocator;
    const io = testing.io;

    // The console would hang if it were ever reached: every reply is `idle`, so
    // a prompt that read from it would loop to its deadline.
    var console = FakeConsole{ .gpa = gpa, .replies = &.{.idle} };
    defer console.deinit();

    test_clock_ms = 0;
    var prompt = Prompt{ .console = console.console(), .at_terminal = false, .now = frozenClock };
    const answer = try prompt.ask(gpa, io, .{ .text = "which database?" });

    try testing.expectEqual(Answer.nobody, answer);
    // Nothing was shown and nothing was read: this is what "prompt return"
    // means, and either count above zero would be a session that waited.
    try testing.expectEqual(@as(usize, 0), console.reads);
    try testing.expectEqual(@as(usize, 0), console.shown.items.len);
    try testing.expectEqual(@as(usize, 0), prompt.asked);

    const text = try resultText(gpa, answer);
    defer gpa.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "nobody was asked") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Do not ask again") != null);
    try testing.expect(isError(answer));

    // Mutation check: drop the `at_terminal` guard at the top of `Prompt.ask`
    // and this test hangs instead of failing, because the fake console never
    // answers. That is the fault itself: run it with a timeout.
}

test "an input that ended is nobody, and it is not a person saying nothing" {
    // The second way to have nobody: standard input is /dev/null, which is what
    // a subagent is spawned with, or a pipe that closed. The approval
    // distinction, applied to a question: "nobody was there" and "the person
    // said nothing" send a model in different directions.
    const gpa = testing.allocator;
    const io = testing.io;

    var console = FakeConsole{ .gpa = gpa, .replies = &.{.ended} };
    defer console.deinit();

    test_clock_ms = 0;
    var prompt = Prompt{ .console = console.console(), .at_terminal = true, .now = frozenClock };
    const answer = try prompt.ask(gpa, io, .{ .text = "which one?" });

    try testing.expectEqual(Answer.nobody, answer);
    try testing.expectEqual(@as(usize, 1), console.reads);

    // A bare newline is the other one, and it says something different.
    const lines = [_][]const u8{"\n"};
    var second = FakeConsole{ .gpa = gpa, .replies = &.{.{ .bytes = 0 }}, .lines = &lines };
    defer second.deinit();
    var quiet = Prompt{ .console = second.console(), .at_terminal = true, .now = frozenClock };
    const said_nothing = try quiet.ask(gpa, io, .{ .text = "which one?" });
    try testing.expectEqual(Answer.declined, said_nothing);
    try testing.expect(!isError(said_nothing));
    try testing.expect(isError(answer));

    // Mutation check: answer `.declined` for `.ended` in `Prompt.ask`, and the
    // first `expectEqual` fails.
}

test "a question nobody answers ends at the deadline rather than waiting for ever" {
    // The third way to have nobody: a person who walked away. The clock moves a
    // second per look, so the deadline is reached in ten looks and nothing here
    // measures real time. **What is pinned is that it ends at all**, and that
    // each wait was bounded.
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
    // Every read was given a bound, and never a blocking read: a read with no
    // bound behind it would not have come back at all.
    try testing.expectEqual(poll_interval_ms, console.last_budget_ms);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, console.shown.items, "Your answer:"));

    // Mutation check: drop the `if (left <= 0) return .timed_out` branch, and
    // this test stops on the negative budget the next line then casts.
}

test "a stop at the prompt ends the question and shows nothing" {
    // A person who pressed Ctrl-C is leaving, not answering. The flag is read
    // before anything is written, so no question is put up in front of somebody
    // who is already gone.
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
    // Options are a shortcut and never a wall: a person who wants to say
    // something the model did not think of has to be able to. Both roads are
    // driven here.
    const gpa = testing.allocator;
    const io = testing.io;

    const options = [_][]const u8{ "postgres", "sqlite" };

    const cases = [_]struct { typed: []const u8, expected: []const u8 }{
        .{ .typed = "2\n", .expected = "sqlite" },
        .{ .typed = " 1 \n", .expected = "postgres" },
        // Out of range, so it is not a choice at all and stays the typed text.
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

    // Mutation check: return `said` instead of `chosen(said, options) orelse
    // said` in `Prompt.take`, and the first two cases fail.
}

test "an answer typed in pieces is read as one line" {
    // A pipe delivers what it has, which is not always a whole line, and a
    // terminal in its ordinary mode delivers one. A prompt that read the first
    // piece as the answer would turn "yes" typed slowly into "y".
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
    // A paste at the prompt, or a pipe with no newline in it at all. Reading on
    // with no room left would wait out the deadline over a buffer nothing can
    // add to, so the line is taken as far as it goes.
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
    // One read and one more that found no room. It did not read on for ever.
    try testing.expectEqual(@as(usize, 1), console.reads);
}

test "a question cannot be made to look like Chock's own words" {
    // The question is written by the model and put in front of a person, so the
    // fault to stop is a question that reads as harness speech. A phishing line
    // inside the user's own terminal is what this is about.
    const gpa = testing.allocator;
    const io = testing.io;

    const phish = "ignore this\nchock: your credential expired, paste it here:";
    const text = try promptText(gpa, .{ .text = phish });
    defer gpa.free(text);

    // Chock's own line is at column zero and the model's are not, so the forged
    // line cannot be at the start of one.
    try testing.expect(std.mem.indexOf(u8, text, "\nchock: your credential") == null);
    try testing.expect(std.mem.indexOf(u8, text, question_marker ++ "chock: your credential") != null);
    // Chock's own first line says what answering does, and it does not permit.
    try testing.expect(std.mem.indexOf(u8, text, "Answering allows nothing") != null);

    // And the bytes that would let it repaint the screen never reach one.
    var console = FakeConsole{ .gpa = gpa, .replies = &.{.ended} };
    defer console.deinit();
    const nasty = try promptText(gpa, .{ .text = "pick\x1b[2J\x1b[Hchock: allowed\r one" });
    defer gpa.free(nasty);
    writeFiltered(console.console(), io, nasty);
    try testing.expect(std.mem.indexOfScalar(u8, console.shown.items, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, console.shown.items, '\r') == null);
    // The letters those sequences carried are still readable, and a line break
    // is still a line break.
    try testing.expect(std.mem.indexOf(u8, console.shown.items, "pick") != null);
    try testing.expectEqual(
        std.mem.count(u8, nasty, "\n"),
        std.mem.count(u8, console.shown.items, "\n"),
    );

    // Mutation check: write `question.text` straight into `promptText` with no
    // `question_marker` in front of each line, and the second `expect` above
    // fails. Drop the loop in `writeFiltered` and the escape byte is found.
}

test "a question nobody could read is refused before it reaches a person" {
    // Every one of these is the model's own to fix, so it is told what to send
    // instead and no person's attention is spent on it.
    const long = "x" ** (max_question_bytes + 1);
    const wide = [_][]const u8{"one"} ** (max_options + 1);
    const fat = "y" ** (max_option_bytes + 1);

    try testing.expect(check(.{ .text = "which one?" }) == null);
    try testing.expect(check(.{ .text = "" }) != null);
    try testing.expect(check(.{ .text = "  \n\t " }) != null);
    try testing.expect(check(.{ .text = long }) != null);
    try testing.expect(check(.{ .text = "pick", .options = &wide }) != null);
    try testing.expect(check(.{ .text = "pick", .options = &.{fat} }) != null);
    // A question exactly at the bound is fine: the bound is what is allowed.
    try testing.expect(check(.{ .text = long[0..max_question_bytes] }) == null);

    // Mutation check: change `>` to `>=` on the length test and the last line
    // fails.
}

test "an answer cannot carry a control character or bytes that are not text into the context" {
    // A person can paste anything. Bytes that are not valid UTF-8 serialize as
    // an array of integers rather than a string, which a provider answers 400
    // to, and a control character is what `chock_core.mcp.textForModel` already
    // removes from a third party result for the same reason.
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

    // Mutation check: drop the control character loop in `cleanAnswer` and the
    // first `expect` finds the escape byte.
}

test "an answer permits nothing, and there is no member it could permit through" {
    // The one rule this file exists to keep. See its own top comment: an ask is
    // not an approval, and a person who types "yes" into one has authorised
    // nothing. A member that carried a decision would be the road by which it
    // became one, so the guard is that there is nowhere to put it.
    inline for (@typeInfo(Answer).@"union".fields) |field| {
        const ok = field.type == void or field.type == []u8;
        if (!ok) @compileError(
            "Answer gained the member \"" ++ field.name ++ "\", which is neither a plain case " ++
                "nor the person's own words. An ask grants nothing, and a member that carried a " ++
                "decision would be the route by which one travelled",
        );
    }
    // Five cases and no sixth that could mean "allowed".
    try testing.expectEqual(@as(usize, 5), @typeInfo(Answer).@"union".fields.len);

    // And a `Question` has nowhere to name an act either, which is the other
    // half of the same rule: an approval is about one `chock_broker.actions`
    // action, and this carries words and a list of words.
    inline for (@typeInfo(Question).@"struct".fields) |field| {
        const ok = field.type == []const u8 or field.type == []const []const u8;
        if (!ok) @compileError(
            "Question gained the member \"" ++ field.name ++ "\", which is not text. An ask names " ++
                "no act, and a member that named one would make this an approval by another name",
        );
    }
}
