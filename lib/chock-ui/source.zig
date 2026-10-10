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
        .events = emptyEvents,
        .asks = emptyAsks,
        .prompt = emptyPrompt,
        .answer = emptyAnswer,
        .whyLast = emptyWhy,
    },
    .name = "nothing",
};

fn emptySessions(_: *anyopaque, _: std.mem.Allocator) Error![]const Session {
    return &.{};
}

fn emptyEvents(_: *anyopaque, _: std.mem.Allocator, _: []const u8, _: u64) Error![]const Entry {
    return &.{};
}

fn emptyAsks(_: *anyopaque, _: std.mem.Allocator) Error![]const Ask {
    return &.{};
}

fn emptyPrompt(_: *anyopaque, _: []const u8, _: []const u8) Error!void {}

fn emptyAnswer(_: *anyopaque, _: []const u8, _: u64, _: Decision) Error!void {}

fn emptyWhy(_: *anyopaque) ?[]const u8 {
    return null;
}

test "a source that reaches nothing answers empty rather than failing" {
    const arena = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 0), (try empty.sessions(arena)).len);
    try std.testing.expectEqual(@as(usize, 0), (try empty.events(arena, "01", 0)).len);
    try std.testing.expectEqual(@as(usize, 0), (try empty.asks(arena)).len);
    try empty.prompt("01", "hello");
    try empty.answer("01", 1, .yes);
    try std.testing.expectEqual(@as(?[]const u8, null), empty.whyLast());
}
