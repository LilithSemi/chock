//! Where a screen's data comes from, as a value.
//!
//! The widget tree is the same in a terminal, a window and a browser, and the
//! three differ only in how they reach a session. A native run reads the loop it
//! is already inside. A browser asks `chock serve` over HTTP. Both answer this
//! one shape, so no screen holds a branch on which it is.
//!
//! The same decision `Sandbox.Driver` makes, for the same reason: a way of
//! getting at something is a value, and the caller picks it once.

const std = @import("std");
const event = @import("chock-proto").event;

/// What a caller gets when the data did not arrive. A screen draws each of these
/// differently, so they are separate rather than one failure.
pub const Error = error{
    /// Nothing answered. The daemon is not running, or the page lost the
    /// network. A screen says so and offers to wait.
    Unreachable,
    /// Something answered and refused. The reason is in `whyLast`.
    Refused,
    OutOfMemory,
};

/// One session, as a list shows it. The fields are `control.SessionRow`'s own,
/// so a screen shows what the daemon said rather than a shape invented here.
pub const Session = struct {
    id: []const u8,
    /// Milliseconds since the epoch. Zero when nothing has happened yet.
    started_ms: u64 = 0,
    /// The direct parent and completed event this session branched from.
    forked_from: []const u8 = "",
    forked_at: u64 = 0,
    model: []const u8 = "",
    /// What the agent named the session, or empty when it named nothing.
    title: []const u8 = "",
    /// What to call the project this belongs to, for a list covering more than
    /// one.
    project: []const u8 = "",
    /// That project's directory, which is what names it when opening the
    /// session. Empty where nothing recorded it.
    project_root: []const u8 = "",
    live: Live = .unknown,
    turns: u64 = 0,

    /// Three states and never two. A lock that could not be tested is not the
    /// same as a session sitting idle, and a reader who is told `idle` for both
    /// is told something false.
    pub const Live = enum {
        live,
        idle,
        unknown,

        pub fn fromWire(said: []const u8) Live {
            if (std.mem.eql(u8, said, "live")) return .live;
            if (std.mem.eql(u8, said, "idle")) return .idle;
            return .unknown;
        }

        pub fn text(self: Live) []const u8 {
            return switch (self) {
                .live => "live",
                .idle => "idle",
                .unknown => "unknown",
            };
        }
    };
};

/// One event of a session, as it was written to the log.
///
/// The event itself and not a summary of it. The interface already knows how to
/// draw every kind, so a source that reduced one to a line would be a second
/// renderer that drifts from the first.
pub const Entry = struct {
    /// The byte offset of this event in the log, so a reader asks for what came
    /// after it rather than for everything again.
    at: u64,
    /// When it happened, milliseconds since the epoch.
    time_ms: i64,
    ev: event.Event,
};

/// A question waiting on a person. The fields are `event.ApprovalRequest`'s own.
///
/// `request` is the envelope's id, the byte offset of the request in the log,
/// because an `ApprovalRequest` carries no id of its own and an
/// `ApprovalResponse` names it by that offset.
pub const Ask = struct {
    session: []const u8,
    request: u64,
    action: []const u8,
    summary: []const u8 = "",
    detail: []const u8 = "",
    reason: []const u8 = "",
    /// When an unanswered request becomes a refusal. Zero when the source did
    /// not say.
    timeout_at_ms: i64 = 0,
};

pub const Decision = enum { yes, no };

/// A stable, renderer-neutral description of one isolated workspace review.
/// The same shape feeds the terminal, desktop and browser interfaces.
pub const Review = struct {
    kind: Kind,
    base: []const u8 = "",
    source: []const u8 = "",
    files: []const File = &.{},

    pub const Kind = enum { git, overlay };
    pub const File = struct {
        path: []const u8,
        old_path: []const u8 = "",
        status: []const u8,
        selectable: bool = true,
        binary: bool = false,
        /// Binary, rename, deletion, symlink and mode changes are deliberately
        /// decided as one file. Ordinary text modifications expose hunks.
        atomic: bool = false,
        hunks: []const Hunk = &.{},
    };
    pub const Hunk = struct {
        number: usize,
        header: []const u8,
        lines: []const Line = &.{},
    };
    pub const Line = struct {
        origin: enum { context, addition, deletion },
        text: []const u8,
    };
};

pub const HunkChoice = struct { path: []const u8, number: usize };

pub const Selection = struct {
    paths: []const []const u8 = &.{},
    hunks: []const HunkChoice = &.{},
    rejected_paths: []const []const u8 = &.{},
    rejected_hunks: []const HunkChoice = &.{},
};

/// A way of reaching sessions. The caller owns `ptr` and keeps it alive for as
/// long as any screen holds this.
pub const Source = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    /// What this reaches, for a screen that says where it is looking. "daemon"
    /// in a browser, "this session" in a native run.
    name: []const u8,

    pub const VTable = struct {
        /// Every session the caller may see. The slice and its strings belong to
        /// `arena`.
        sessions: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
        ) Error![]const Session,

        /// Make an empty session in the source's default project. Its first
        /// prompt starts the turn. The returned identifier belongs to `arena`.
        create: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
        ) Error![]const u8,

        /// The events of one session after `at`. Answering an empty slice means
        /// nothing new, which is not an error.
        events: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            session: []const u8,
            after: u64,
        ) Error![]const Entry,

        /// The questions waiting on a person, across every session.
        asks: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
        ) Error![]const Ask,

        /// Say something in one session. The source carries it to whoever holds
        /// the session; what comes of it arrives back as events.
        prompt: *const fn (
            ptr: *anyopaque,
            session: []const u8,
            message: []const u8,
        ) Error!void,

        /// Fork one completed turn, or the latest one when `at` is null. The
        /// returned child identifier belongs to `arena`.
        fork: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            session: []const u8,
            at: ?u64,
        ) Error![]const u8,

        /// Read the stable workspace boundary belonging to a finished session.
        review: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            session: []const u8,
        ) Error!Review,

        /// Materialize exactly this selection without moving a user branch.
        select: *const fn (
            ptr: *anyopaque,
            session: []const u8,
            selection: Selection,
        ) Error!void,

        /// Remove the materialized result and leave the user branch alone.
        undoSelection: *const fn (ptr: *anyopaque, session: []const u8) Error!void,

        /// Answer one question. A second answer to the same request is refused
        /// by whoever holds the session, not here.
        answer: *const fn (
            ptr: *anyopaque,
            session: []const u8,
            request: u64,
            decision: Decision,
        ) Error!void,

        /// Why the last call refused, in words a person reads, or null when the
        /// last call worked. Borrowed from the source and good until the next
        /// call.
        whyLast: *const fn (ptr: *anyopaque) ?[]const u8,
    };

    pub fn sessions(self: Source, arena: std.mem.Allocator) Error![]const Session {
        return self.vtable.sessions(self.ptr, arena);
    }

    pub fn create(self: Source, arena: std.mem.Allocator) Error![]const u8 {
        return self.vtable.create(self.ptr, arena);
    }

    pub fn events(
        self: Source,
        arena: std.mem.Allocator,
        session: []const u8,
        after: u64,
    ) Error![]const Entry {
        return self.vtable.events(self.ptr, arena, session, after);
    }

    pub fn asks(self: Source, arena: std.mem.Allocator) Error![]const Ask {
        return self.vtable.asks(self.ptr, arena);
    }

    pub fn prompt(self: Source, session: []const u8, message: []const u8) Error!void {
        return self.vtable.prompt(self.ptr, session, message);
    }

    pub fn fork(
        self: Source,
        arena: std.mem.Allocator,
        session: []const u8,
        at: ?u64,
    ) Error![]const u8 {
        return self.vtable.fork(self.ptr, arena, session, at);
    }

    pub fn review(self: Source, arena: std.mem.Allocator, session: []const u8) Error!Review {
        return self.vtable.review(self.ptr, arena, session);
    }

    pub fn select(self: Source, session: []const u8, selection: Selection) Error!void {
        return self.vtable.select(self.ptr, session, selection);
    }

    pub fn undoSelection(self: Source, session: []const u8) Error!void {
        return self.vtable.undoSelection(self.ptr, session);
    }

    pub fn answer(
        self: Source,
        session: []const u8,
        request: u64,
        decision: Decision,
    ) Error!void {
        return self.vtable.answer(self.ptr, session, request, decision);
    }

    pub fn whyLast(self: Source) ?[]const u8 {
        return self.vtable.whyLast(self.ptr);
    }
};

/// A source that reaches nothing, for a screen under test and for a build that
/// has no way to reach a session yet.
pub const empty: Source = .{
    .ptr = undefined,
    .vtable = &.{
        .sessions = emptySessions,
        .create = emptyCreate,
        .events = emptyEvents,
        .asks = emptyAsks,
        .prompt = emptyPrompt,
        .fork = emptyFork,
        .review = emptyReview,
        .select = emptySelect,
        .undoSelection = emptyUndoSelection,
        .answer = emptyAnswer,
        .whyLast = emptyWhy,
    },
    .name = "nothing",
};

fn emptySessions(_: *anyopaque, _: std.mem.Allocator) Error![]const Session {
    return &.{};
}

fn emptyCreate(_: *anyopaque, arena: std.mem.Allocator) Error![]const u8 {
    return arena.dupe(u8, "") catch error.OutOfMemory;
}

fn emptyEvents(_: *anyopaque, _: std.mem.Allocator, _: []const u8, _: u64) Error![]const Entry {
    return &.{};
}

fn emptyAsks(_: *anyopaque, _: std.mem.Allocator) Error![]const Ask {
    return &.{};
}

fn emptyPrompt(_: *anyopaque, _: []const u8, _: []const u8) Error!void {}

fn emptyFork(_: *anyopaque, arena: std.mem.Allocator, session: []const u8, _: ?u64) Error![]const u8 {
    return arena.dupe(u8, session) catch error.OutOfMemory;
}

fn emptyReview(_: *anyopaque, _: std.mem.Allocator, _: []const u8) Error!Review {
    return .{ .kind = .git };
}

fn emptySelect(_: *anyopaque, _: []const u8, _: Selection) Error!void {}

fn emptyUndoSelection(_: *anyopaque, _: []const u8) Error!void {}

fn emptyAnswer(_: *anyopaque, _: []const u8, _: u64, _: Decision) Error!void {}

fn emptyWhy(_: *anyopaque) ?[]const u8 {
    return null;
}

test "a source that reaches nothing answers empty rather than failing" {
    const arena = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 0), (try empty.sessions(arena)).len);
    try std.testing.expectEqualStrings("", try empty.create(arena));
    try std.testing.expectEqual(@as(usize, 0), (try empty.events(arena, "01", 0)).len);
    try std.testing.expectEqual(@as(usize, 0), (try empty.asks(arena)).len);
    try empty.prompt("01", "hello");
    const child = try empty.fork(arena, "01", null);
    defer arena.free(child);
    try std.testing.expectEqualStrings("01", child);
    try std.testing.expectEqual(Review.Kind.git, (try empty.review(arena, "01")).kind);
    try empty.select("01", .{});
    try empty.undoSelection("01");
    try empty.answer("01", 1, .yes);
    try std.testing.expectEqual(@as(?[]const u8, null), empty.whyLast());
}
