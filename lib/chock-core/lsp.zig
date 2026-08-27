//! Diagnostics in the edit loop: an agent that edits a file learns it does not
//! compile **before it makes the next edit**, instead of several turns later
//! with more work built on top of the mistake.
//!
//! **There is no structural editing here and no parser of any kind.** Chock
//! speaks one protocol and knows no language, and the moment a table of
//! "which command checks which language" appears in this project, the whole
//! reason for a language server is gone.
//!
//! ## Where the server runs, and why the agent cannot drive it
//!
//! **Inside the sandbox, in a process of the session's own.** Two facts decide
//! it and they point the same way:
//!
//! * A language server is a **parser reading files the agent just wrote**. That
//!   is attacker chosen input by design, and a parser is the classic place to
//!   find a memory safety fault. On the host it would run in the process that
//!   holds the provider credential, which is the arrangement a plugin is
//!   forbidden, word for word, for exactly this reason.
//! * It needs nothing the sandbox denies. It reads project files, it writes to
//!   a pipe, and it wants no network and no clock. That is a smaller request
//!   than any ordinary tool call already makes.
//!
//! **The server is Chock's and not the agent's**, and that is a property of
//! this file rather than a promise:
//!
//! * There is **no tool** for it. `lib/chock-core/tools.zig`'s `Tool` enum has
//!   no member here, so the model is never offered one, is never told one
//!   exists, and cannot name one. A general purpose process the agent could
//!   drive is exactly what a language server would become with a tool in front
//!   of it.
//! * The **program name comes from the project**, the same road
//!   `provision.Request.registry` takes: see `Session.program`. The model
//!   cannot choose which program starts.
//! * The **request set is closed**. A driver sends the handshake, tells the
//!   server a file changed, and reads what it publishes. There is no route from
//!   a tool call to an arbitrary request.
//!
//! So the agent's whole influence over the server is the content of the file it
//! just edited, which is the input the server exists to read.
//!
//! ## A project with no server must cost nothing at all
//!
//! **A harness that gets worse when a server is missing is worse than no
//! harness.** So `Session.afterWrite` answers null, silently, for every one of:
//!
//! * a session with no server,
//! * a file whose suffix no server serves,
//! * a server that answered nothing,
//! * a server that did not answer inside its budget,
//! * a server that failed to start, after the one time that was said.
//!
//! Null means the tool result is handed back byte for byte as the tool built
//! it. There is no refusal, no delay a caller can measure, and no line in the
//! context.
//!
//! **Silence is also the answer when the file is clean**, and that is a
//! decision rather than an omission. A "no problems" line on every edit is a
//! tail on every edit, which is the shape `lib/chock-core/notices.zig` learned
//! twice to distrust, and its absence is exactly what an agent reads today. The
//! honest cost is that silence does not tell the agent whether anything checked
//! at all; the agent then behaves as it does today and runs its own build,
//! which is the floor this feature must never go below.
//!
//! ## A diagnostic that arrives too late is dropped, never waited for
//!
//! A session that goes quiet for minutes reads as hung, and this project has
//! measured that. So the ask carries a budget and a server that misses it
//! answers `late`, which says nothing to the model at all.
//!
//! ## What comes back is third party text entering the model context
//!
//! **A language server is not a trust boundary the way an MCP server is.** It
//! supplies no tools, it answers no question the agent asked, and nothing it
//! says reaches a decision: it produces text that is shown to the model, and
//! this file treats it as exactly that, which is the same trust an instruction
//! file in the project holds and no more.

const std = @import("std");
const notices = @import("notices.zig");

pub const Error = std.mem.Allocator.Error;

/// How bad one diagnostic is. The numbers are the ones the Language Server
/// Protocol puts on the wire, so a driver converts with `fromWire` and never
/// with a table of its own.
pub const Severity = enum(u8) {
    /// `error` is a keyword, so the member cannot carry the word itself.
    /// `word` is what a reader sees.
    err = 1,
    warning = 2,
    information = 3,
    hint = 4,

    /// The severity `number` names, or null when it names none.
    ///
    /// **Null and not a default.** The number comes off a wire a third party
    /// program wrote, so it is untrusted input: `std.enums.fromInt` answers
    /// null for a value no member has, where `@enumFromInt` would be undefined
    /// behaviour. A driver that gets null has a diagnostic it cannot classify,
    /// and the safe reading of one of those is `warning`, which is the
    /// caller's decision to make and not this function's.
    pub fn fromWire(number: i64) ?Severity {
        if (number < 0 or number > std.math.maxInt(u8)) return null;
        return std.enums.fromInt(Severity, @as(u8, @intCast(number)));
    }

    /// The word a person and a model both read, in the spelling every compiler
    /// already prints.
    pub fn word(self: Severity) []const u8 {
        return switch (self) {
            .err => "error",
            .warning => "warning",
            .information => "note",
            .hint => "hint",
        };
    }

    /// Whether a diagnostic of this severity is worth a line of the context.
    ///
    /// **Only `error` and `warning`.** The question this whole file answers is
    /// whether the file still builds, and `information` and `hint` do not
    /// answer it: a real server publishes a hint for every unused import and
    /// every place a code action could apply, so keeping them would fill the
    /// bound with the two severities nobody has to act on and push the errors
    /// out.
    pub fn reachesModel(self: Severity) bool {
        return switch (self) {
            .err, .warning => true,
            .information, .hint => false,
        };
    }
};

/// One problem a server reported. Every string is borrowed for the length of
/// the call that produced it: see `Server.diagnose`, which hands its answer out
/// of an arena the caller owns.
pub const Diagnostic = struct {
    /// Where the problem is, **relative to the workspace root**, in the same
    /// spelling a tool call uses for a path. A driver converts the server's own
    /// URI into this form; see `samePath` for why a looser comparison was
    /// refused.
    path: []const u8,
    /// The line, counting from one, the way a person and every compiler count.
    /// **The protocol counts from zero**, so a driver adds one and this type
    /// never holds the wire's own numbering.
    line: u32,
    /// The column, counting from one, for the same reason.
    column: u32,
    severity: Severity,
    /// What the server said. Carried raw here and cleaned by `flattenMessage`
    /// on the way out, so nothing decides what a message means before the one
    /// place that bounds it.
    message: []const u8,
};

/// What one ask produced.
///
/// **Only `reported` can put anything in front of the model.** Every other
/// member is a way of saying nothing, and they are kept apart because they are
/// different facts about the session, not because a caller renders them
/// differently.
pub const Answer = union(enum) {
    /// No server serves this file, so nothing was asked and nothing ran.
    unsupported,
    /// The server answered. An empty slice is a real answer and means the file
    /// is clean.
    reported: []const Diagnostic,
    /// The server did not answer inside the budget. See this file's own top
    /// comment: a diagnostic that arrives too late to act on is dropped rather
    /// than waited for.
    late,
    /// The server could not be started at all, and this is the server's own
    /// reason in one sentence. Said once per session: see `Session`.
    unavailable: []const u8,
};

/// One question for the server: which file changed, and how long the answer is
/// worth waiting for.
///
/// **The content of the file is not here, and that is deliberate.** The server
/// runs inside the sandbox with the same mount tree the tool call wrote
/// through, so the file it reads is the file the tool just wrote. A copy of the
/// content in the ask would be a second source of truth that can drift from the
/// first, and the drift would be invisible.
pub const Ask = struct {
    path: []const u8,
    budget_ns: u64,
};

/// What actually talks to a language server.
///
/// **A seam, because the thing on the other side of it is a third party program
/// in a sandbox of its own.** The same shape `lib/chock-core/arbiter.zig`,
/// `chock_nix.provision.Runner` and `chock_core.tasks.Runner` already take.
/// `lib/chock-core/lsp_driver.zig` is the production implementation.
///
/// **One test in this project does start a real one**, and it is
/// `test/core/lsp.zig`. It does not provision it, which really would be a
/// build and not a test: it runs a `zls` the dev shell already put on the
/// machine, and it is skipped where there is none. That test found three
/// faults nothing else could, each of them a thing a real server does that a
/// server written to answer the driver never would: see
/// `test/core/lsp_zls_probe.zig`.
pub const Server = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Ask about one file and answer what the server said.
        ///
        /// **`arena` owns every byte of the answer**, including each
        /// `Diagnostic`'s own strings, and the caller frees the whole arena at
        /// once. An implementation therefore never has to unwind a partial
        /// answer, which is the one place a diagnostics path could plausibly
        /// leak on a session that runs for hours.
        ///
        /// The only failure is running out of memory. **A server that is
        /// broken, slow, or absent is an `Answer` and never an error**, the
        /// same rule `chock_nix.provision.resolve` follows: a fault in a
        /// language server must never end a session that is doing real work.
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

/// How many diagnostics reach the model, at most.
///
/// Twelve. One real mistake in a Zig file cascades into a page of them, so the
/// number that matters is how many a reader acts on rather than how many exist,
/// and a dozen already covers more separate mistakes than one edit makes. The
/// count left out is always stated, so a cut list is never read as a whole one.
pub const max_shown: usize = 12;

/// How much of one message reaches the model.
///
/// **A count alone is not a bound.** A server that writes a whole inferred type
/// into one message, which is a thing real servers do, would put four kilobytes
/// in a single line and defeat `max_shown` on its own. Two hundred bytes holds
/// a compiler sentence and cuts the rest.
pub const max_message_bytes: usize = 200;

/// How long the first ask of a session is worth waiting for.
///
/// Ten seconds. A server indexes a project before it answers anything, and that
/// cost is paid once, on whichever edit comes first. It is far above the steady
/// budget and still far below the point at which a person decides a session has
/// hung.
///
/// **Measured against a real `zls` 0.16 on 2026-08-22, and it is generous by
/// two orders of magnitude.** Building the sandbox, starting the server,
/// speaking the handshake and reading the first publication together took 16
/// to 124 milliseconds, over the whole of this project's own source tree. The
/// reason is that `zls` does not index a project before it answers: it parses
/// the documents it is handed and nothing else. **A server that does index,
/// such as one for a language with a whole crate graph to read, is not covered
/// by that measurement**, and this number is the one to look at first if such
/// a server ever answers `late` on its first ask.
pub const first_budget_ns: u64 = 10 * std.time.ns_per_s;

/// How long every later ask is worth waiting for.
///
/// Two seconds. The server is warm by then and a reply is a reparse of one
/// file. Past this the answer is worth less than the delay, so it is dropped:
/// see this file's own top comment.
///
/// **Measured on the same day and the same server**: a reply to a later ask
/// took about a millisecond for a small file, and about eleven milliseconds of
/// cpu time for a six thousand line one. Two seconds is a bound and not a
/// target.
pub const steady_budget_ns: u64 = 2 * std.time.ns_per_s;

/// The prefix on the one line of this block that Chock itself wrote. The same
/// mark `lib/chock-core/tools.zig` puts on every line of its own inside a tool
/// result, so a model has one thing to learn and not two.
pub const prefix = "[chock: ";

/// What a message becomes when it is not valid UTF-8. The alternative is a
/// content part the provider answers 400 to.
pub const not_text = "the server's message was not text and is not shown";

/// The language server of one session, and what it has already said.
///
/// **One per session, held by the caller that owns the session**, the same way
/// `chock_core.tasks.Table` is.
pub const Session = struct {
    /// The program that serves these files, for the one sentence a start
    /// failure produces.
    ///
    /// **From the project and never from the model.** The source is the
    /// `language_servers` block of `chock.zon`, which the workspace already
    /// binds back over the agent's copy read only, so an agent cannot name its
    /// own program by editing a file.
    program: []const u8 = "",

    /// The file suffixes this session's server serves, for example `.zig`.
    ///
    /// **Empty is the ordinary case and it costs nothing.** A project that
    /// states no server has no entry here, every ask answers `unsupported`
    /// before the seam is touched at all, and the tool result is the one the
    /// tool built.
    suffixes: []const []const u8 = &.{},

    /// Where the asking actually happens, or null for a session that has no
    /// server. Null and an empty `suffixes` are the same answer by two roads,
    /// and both are checked, because a caller that fills one and forgets the
    /// other must not reach the seam.
    server: ?Server = null,

    /// Whether the start failure has been said. **A confusing failure costs
    /// turns and a plain refusal costs one**, and a refusal repeated on every
    /// edit is neither: it is a tail on every edit that says nothing new.
    said_unavailable: bool = false,

    /// Whether anything has been asked yet, which is what decides between the
    /// two budgets.
    asked: bool = false,

    /// The block to append to the tool result of a write that just succeeded,
    /// or null when there is nothing to say. The caller owns a returned slice
    /// and frees it with `gpa.free`.
    ///
    /// `path` is the path the tool call named, and it is the file whose
    /// diagnostics rank first: see `orderOf`.
    ///
    /// **Every server answer travels in an arena that is gone before this
    /// returns.** The caller therefore holds one allocation and never a tree of
    /// borrowed strings, which is what keeps a session of hundreds of edits
    /// from growing a graveyard of them.
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

    /// Whether any suffix of this session's server matches `path`.
    ///
    /// A plain suffix comparison, because a suffix is what a project writes and
    /// what a reader checks. `.zig` matches `src/main.zig` and does not match
    /// `zig`, since the dot is part of what the project wrote.
    pub fn serves(self: Session, path: []const u8) bool {
        for (self.suffixes) |suffix| {
            if (suffix.len == 0) continue;
            if (std.mem.endsWith(u8, path, suffix)) return true;
        }
        return false;
    }

    /// The one sentence a session gets about a server that would not start.
    ///
    /// It names the program, says what it means for the rest of the session,
    /// and says what to do instead, which is what an agent can act on. The
    /// server's own reason comes last and is bounded, the same shape
    /// `chock_nix.provision.explainFailure` gives a Nix trace.
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

/// The block a set of diagnostics becomes, or null when none of them reaches
/// the model. The caller owns the result.
///
/// `edited` is the file the agent just wrote, and it ranks first: see
/// `orderOf`.
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

/// Which of two diagnostics the model reads first.
///
/// **The file decides before the severity does.** The agent can act on the file
/// it just wrote, in this turn, with the edit still in front of it; an error
/// somewhere else may have been there before the session started. So a warning
/// in the edited file outranks an error elsewhere, deliberately.
///
/// The order is total, so two runs over the same set produce the same block. It
/// does not rest on the sort being stable, because a sort that quietly stops
/// being stable would change what a model reads and no test would name the
/// reason.
fn orderOf(edited: []const u8, a: Diagnostic, b: Diagnostic) std.math.Order {
    const a_edited = samePath(edited, a.path);
    const b_edited = samePath(edited, b.path);
    if (a_edited != b_edited) return if (a_edited) .lt else .gt;

    const a_rank = @intFromEnum(a.severity);
    const b_rank = @intFromEnum(b.severity);
    if (a_rank != b_rank) return std.math.order(a_rank, b_rank);

    // Two diagnostics in different files, both outranked by the edited one.
    // Grouping by path keeps one file's problems together, which is how a
    // reader acts on them.
    const by_path = std.mem.order(u8, a.path, b.path);
    if (by_path != .eq) return by_path;

    if (a.line != b.line) return std.math.order(a.line, b.line);
    if (a.column != b.column) return std.math.order(a.column, b.column);
    return std.mem.order(u8, a.message, b.message);
}

/// Whether two paths name the same file.
///
/// **An exact comparison, after one leading `./` is dropped from each.** A
/// looser rule was refused on purpose: matching on the last component alone
/// would call `a/parser.zig` and `b/parser.zig` the same file, and the whole
/// value of the ordering is that the agent's own file is the one at the top. A
/// driver is what turns the server's URI into a workspace relative path, and a
/// driver that gets that wrong produces a report in the wrong order rather than
/// a wrong report.
fn samePath(left: []const u8, right: []const u8) bool {
    return std.mem.eql(u8, trimDotSlash(left), trimDotSlash(right));
}

fn trimDotSlash(path: []const u8) []const u8 {
    if (std.mem.startsWith(u8, path, "./")) return path[2..];
    return path;
}

/// One message, on one line, bounded, and safe to put in a JSON string. The
/// caller owns the result.
///
/// Three jobs, and each one is a fault this project has already paid for:
///
/// * **Every control character becomes one space.** A newline would break the
///   one line per diagnostic form that makes the block readable, and an escape
///   sequence is a hazard of its own, arriving here in text a third party
///   program wrote. A run of them collapses to a single space, so a
///   message written across three lines does not arrive with a corridor of
///   blanks in it.
/// * **A message that is not valid UTF-8 is replaced.** `std.json.Stringify`
///   writes invalid UTF-8 as an array of integers rather than a string, the
///   provider cannot classify the part, and the session ends on a 400. See
///   `chock_core.tools.outputForModel`, which is the same fault one layer down.
/// * **It is cut at `max_message_bytes`**, on a character boundary, and the cut
///   is marked so nothing reads a half sentence as a whole one.
pub fn flattenMessage(gpa: std.mem.Allocator, message: []const u8) Error![]u8 {
    if (!std.unicode.utf8ValidateSlice(message)) return gpa.dupe(u8, not_text);

    var flat: std.ArrayList(u8) = .empty;
    defer flat.deinit(gpa);

    var pending_space = false;
    for (message) |byte| {
        // Only ASCII control characters are checked byte by byte, which is
        // safe over UTF-8: every byte of a multi byte character is 0x80 or
        // above, so none of them can be mistaken for one.
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

// No test here starts a language server, and none reads a clock. Every server
// below is a table, and every budget is a number a test reads back rather than
// a duration anything measures.

const testing = std.testing;

/// A `Server` that answers from a table and records what it was asked.
const FakeServer = struct {
    answer: Answer = .{ .reported = &.{} },
    /// How many times `diagnose` was reached. **The whole of the "a project
    /// with no server costs nothing" test is that this stays zero.**
    calls: usize = 0,
    /// The budget of the last ask, so a test reads the number that was handed
    /// over instead of measuring how long anything took.
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
    // The first rule of this whole file: a harness that gets worse when a
    // server is missing is worse than no harness. Mutation check: let
    // `afterWrite` fall through to the seam when `server` is null, or drop the
    // `serves` check, and `fake.calls` stops being zero.
    const gpa = testing.allocator;

    {
        var session = Session{};
        try testing.expect(try session.afterWrite(gpa, testing.io, "src/main.zig") == null);
    }

    // A session with a server that serves other files. The suffix decides
    // before the seam is touched, so a project whose server does not know this
    // language pays nothing at all: no process, no wait, no line.
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

        // And the same session does reach the seam for a file it serves, or the
        // test above would pass for a session that never works at all.
        const block = (try session.afterWrite(gpa, testing.io, "src/main.zig")).?;
        defer gpa.free(block);
        try testing.expectEqual(@as(usize, 1), fake.calls);
    }
}

test "a clean file, a late answer, and an empty report all say nothing" {
    // Three different facts about a session, one answer to the model, and the
    // answer is the tool result the tool itself built. The late case is the one
    // that matters most: a diagnostic worth less than the delay is dropped and
    // never waited for.
    const gpa = testing.allocator;

    for ([_]Answer{ .{ .reported = &.{} }, .late, .unsupported }) |answer| {
        var fake = FakeServer{ .answer = answer };
        var session = Session{
            .program = "zls",
            .suffixes = &.{".zig"},
            .server = fake.server(),
        };
        try testing.expect(try session.afterWrite(gpa, testing.io, "src/main.zig") == null);
        // The seam really was asked. A null that came from not asking would
        // pass this test for the wrong reason.
        try testing.expectEqual(@as(usize, 1), fake.calls);
    }
}

test "the first ask carries the starting budget and every later one the steady budget" {
    // The budget is a value handed to the seam, so this reads the number that
    // was passed rather than measuring a duration. The suite has no wall clock
    // assertion and this does not add one.
    const gpa = testing.allocator;

    var fake = FakeServer{ .answer = .late };
    var session = Session{ .suffixes = &.{".zig"}, .server = fake.server() };

    try testing.expect(try session.afterWrite(gpa, testing.io, "a.zig") == null);
    try testing.expectEqual(first_budget_ns, fake.last_budget_ns);

    try testing.expect(try session.afterWrite(gpa, testing.io, "b.zig") == null);
    try testing.expectEqual(steady_budget_ns, fake.last_budget_ns);
    try testing.expectEqualStrings("b.zig", fake.last_path);

    // The starting budget really is the larger one, or the distinction buys
    // nothing.
    try testing.expect(first_budget_ns > steady_budget_ns);
}

test "a server that will not start says so once and never again in that session" {
    // A confusing failure costs turns and a plain refusal costs one. A refusal
    // repeated on every edit is neither. Mutation check: drop the
    // `said_unavailable` guard and the second edit produces a block.
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
    // What to do instead, which is the part an agent can act on.
    try testing.expect(std.mem.indexOf(u8, first, "Build or test the project yourself") != null);
    // The server's own reason, so a person reading the log knows what happened.
    try testing.expect(std.mem.indexOf(u8, first, "no such file or directory") != null);

    try testing.expect(try session.afterWrite(gpa, testing.io, "src/other.zig") == null);
    try testing.expect(try session.afterWrite(gpa, testing.io, "src/third.zig") == null);
    try testing.expectEqual(@as(usize, 3), fake.calls);
}

test "a diagnostic from the file just edited outranks one from anywhere else" {
    // The ordering rule, and the half of it that is easy to get backwards: a
    // **warning** in the edited file comes before an **error** somewhere else.
    // The agent can act on its own file this turn; an error elsewhere may have
    // been there before the session started.
    //
    // Mutation check: compare severity before the file in `orderOf` and the
    // first line becomes the error in `other.zig`.
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

    // The path the model wrote and the path the server reported may differ by a
    // leading "./", and that must not move a file out of first place.
    const dotted = (try render(gpa, "./src/main.zig", &list)).?;
    defer gpa.free(dotted);
    try testing.expect(std.mem.indexOf(u8, dotted, "\nsrc/main.zig:12:5:") != null);
    try testing.expect(std.mem.indexOf(u8, dotted, "\nother.zig:3:1: error") != null);
    try testing.expect(std.mem.lastIndexOf(u8, dotted, "other.zig:3:1").? >
        std.mem.indexOf(u8, dotted, "src/main.zig:12:5").?);
}

test "a file with hundreds of errors is bounded, and the number left out is stated" {
    // One real mistake in a Zig file cascades into a page of them. An uncapped
    // report would spend the whole context saying one thing four hundred times.
    // Mutation check: remove the `@min` in `render` and the block grows past
    // every bound below.
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

    // One header line plus exactly `max_shown` diagnostics, and the trailing
    // newline makes the last split entry empty.
    var lines: usize = 0;
    var walk = std.mem.splitScalar(u8, block, '\n');
    while (walk.next()) |line| {
        if (line.len != 0) lines += 1;
    }
    try testing.expectEqual(max_shown + 1, lines);

    // The whole count is stated, so a cut list is never read as a whole one.
    try testing.expect(std.mem.indexOf(u8, block, "400 problems") != null);
    try testing.expect(std.mem.indexOf(u8, block, "the 12 that matter most are shown") != null);
    // The last error is not in there, which is what the bound means.
    try testing.expect(std.mem.indexOf(u8, block, ":400:") == null);
}

test "one enormous message cannot defeat the count, so the block stays small" {
    // A count alone is not a bound. A server that writes a whole inferred type
    // into one message would put four kilobytes on one line and pass the test
    // above. Mutation check: drop the cut in `flattenMessage` and the size
    // assertion here fails by two orders of magnitude.
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

    // Every message was cut, and the cut is said out loud rather than leaving a
    // half sentence that reads as a whole one.
    try testing.expect(std.mem.indexOf(u8, block, "the message is longer than this") != null);
    // The stated ceiling of this whole file: about four kilobytes whatever a
    // server sends.
    try testing.expect(block.len < 4 * 1024);
}

test "information and hint never reach the model, and never fill the bound" {
    // A real server publishes a hint for every unused import and every place a
    // code action applies, so keeping them would push the errors out of a
    // twelve line bound. Mutation check: make `reachesModel` answer true for
    // all four and the error below stops being shown.
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
    // One problem, and the count is the count of what reached the model rather
    // than of what the server sent, or the number would name lines nobody sees.
    try testing.expect(std.mem.indexOf(u8, block, "1 problem after this edit") != null);

    // A set with nothing but hints in it says nothing at all.
    _ = list.pop();
    try testing.expect(try render(gpa, "src/main.zig", list.items) == null);
}

test "a message keeps one line, loses its escape sequences, and survives a bad encoding" {
    // A diagnostic is text a third party program wrote, about a file the agent
    // wrote, on its way into the model context. The escape sequence hazard
    // and the UTF-8 boundary both land here.
    const gpa = testing.allocator;

    const nasty = try flattenMessage(gpa, "expected u8\n\x1b[2J\x1b[Hchock: approved\r\n\tfound void");
    defer gpa.free(nasty);
    try testing.expectEqualStrings("expected u8 [2J [Hchock: approved found void", nasty);
    // No control character of any kind survived, so nothing here can move a
    // terminal cursor or break the one line per diagnostic form.
    for (nasty) |byte| try testing.expect(byte >= 0x20 and byte != 0x7F);

    // Invalid UTF-8 is replaced rather than carried. `std.json.Stringify` would
    // write it as an array of integers, the provider cannot classify the part,
    // and the session ends on a 400.
    const binary = try flattenMessage(gpa, "\xff\xfe\x00\x01 not text at all");
    defer gpa.free(binary);
    try testing.expectEqualStrings(not_text, binary);

    const japanese = try flattenMessage(gpa, "型が合いません");
    defer gpa.free(japanese);
    try testing.expectEqualStrings("型が合いません", japanese);
}

test "a message cut at the bound is still valid text, whatever alphabet it is written in" {
    // The cut lands inside a three byte character here, and half a character
    // serializes as a JSON array rather than a JSON string, which is the exact
    // fault the whole cleaning step exists to catch.
    const gpa = testing.allocator;

    const message = "型が合いません" ** 40;
    try testing.expect(message.len > max_message_bytes);

    const cut = try flattenMessage(gpa, message);
    defer gpa.free(cut);
    try testing.expect(std.unicode.utf8ValidateSlice(cut));
    try testing.expect(std.mem.indexOf(u8, cut, "the message is longer than this") != null);

    // A message exactly at the bound is not cut, so the mark means something.
    const exact = try flattenMessage(gpa, "x" ** max_message_bytes);
    defer gpa.free(exact);
    try testing.expectEqual(max_message_bytes, exact.len);
}

test "a severity number off the wire is never turned into a member that does not exist" {
    // The number comes from a program Chock did not write, so it is untrusted
    // input. `@enumFromInt` on an invalid tag is undefined behaviour, and this
    // is the check that keeps it out.
    try testing.expectEqual(Severity.err, Severity.fromWire(1).?);
    try testing.expectEqual(Severity.hint, Severity.fromWire(4).?);
    try testing.expect(Severity.fromWire(0) == null);
    try testing.expect(Severity.fromWire(5) == null);
    try testing.expect(Severity.fromWire(-1) == null);
    try testing.expect(Severity.fromWire(std.math.maxInt(i64)) == null);
}

test "the report reads like a compiler, because that is what a model has already read" {
    // The shape of one line, pinned, because it is the whole interface between
    // this file and the model: path, line, column, severity, message.
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
