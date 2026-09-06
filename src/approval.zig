//! The person at the keyboard, as a `chock_broker.Broker.Waiter`.
//!
//! ## The wall this goes through, and the reason it can
//!
//! `Broker.request` appends an `approval.request` to the session log and then
//! waits for an `approval.response` to appear in the same log. `Loop.run` holds
//! the exclusive lock on that log for the whole session, and `applyWork` takes
//! it again at the end, so **nothing outside this process can append the
//! answer**. Every question therefore expired, and an expired question is a
//! refusal. Three separate pieces of work stopped at that wall.
//!
//! The way through it is the seam the broker already has. `Waiter.wait` is the
//! one call inside `request` that gives control away, and whatever runs there
//! runs **inside the process that holds the lock**. So this file reads a person's
//! answer there and appends it through the very same `locked` handle the broker
//! is writing the question with. There is no second lock, no second open of the
//! log, and no change to `chock-proto`.
//!
//! **If you find yourself opening the log a second time here, stop.** That is
//! the bug this design exists to avoid: two handles on one log is the state the
//! exclusive lock is for.
//!
//! ## What this does not do, and what does it instead
//!
//! Only an interactive `chock run` has a person. A subagent and a session the
//! daemon started are both spawned with `.stdin = .ignore`, so they have no
//! terminal and nobody to ask. **`lib/chock-broker/socket.zig` is the other
//! half**: the same `Waiter` seam over a unix socket, so an answer can come
//! from a process that is not this one. It appends through the caller's own
//! `locked` handle too, for exactly the reason this file does, and
//! `src/run.zig`'s own `Approvers` is what gives the broker either of them or
//! both.
//!
//! **This file is unchanged by that**, and that is the point of a seam: the
//! terminal path behaves exactly as it did, and the tests below are what say
//! so.
//!
//! **And a third, in this file: `Display`.** Bare `chock` brings up a full
//! screen interface that owns the terminal, so `Terminal` cannot run there at
//! all: it would be a second reader of one descriptor and a second writer of
//! cells the display believes it owns. `Display` is the same seam again, over
//! the display's own approval region. It reads the log and writes the answer
//! exactly as `Terminal` does, and everything about the device is
//! `src/ui.zig`'s. See its own doc comment for the split.
//!
//! ## Three ways to have nobody, and none of them may hang
//!
//! A hang is the worst of the available answers, because the session lock is
//! held while it hangs, so nothing can read the log and nothing can end it.
//! Each way is stopped by something different, and all three are checked
//! rather than assumed:
//!
//! * **No terminal at all.** `hasTerminal` reads what standard input really
//!   is, and `timeoutMs` gives a session without one a timeout of zero, which
//!   the broker expires on its first look with no wait at all.
//! * **Standard input at end of file.** `Console.Read.ended`, which this
//!   answers with an `expired` response: nobody is there, which is a different
//!   fact from somebody saying no. `.ignore` is `/dev/null` on both platforms,
//!   so a subagent that reached this anyway ends here on its first look too.
//! * **A person who went to bed.** The broker's own deadline. `Console.read`
//!   is given the broker's budget and comes back when it passes, so the wait
//!   is a bounded wait and never a blocking read.
//!
//! ## Ctrl-C
//!
//! `src/interrupt.zig` installs its handler with no `SA_RESTART`, but
//! `std.posix.poll` retries an interrupted call itself, so a press does not
//! come back through the read. It sets a flag instead, and this reads that flag
//! at the top of every wait: see `Terminal.stop`. A press at the prompt
//! therefore ends the wait with `Wake.canceled`, and `request` answers
//! `error.Canceled` with the question still open and unanswered in the log,
//! which is the same state a crash at that moment leaves. `src/run.zig` treats
//! that as an apply that did not happen and keeps the workspace, so the work is
//! still on disk.
//!
//! ## What a person is shown, and why it is filtered
//!
//! The `detail` of an apply is a diff, which holds file content and a commit
//! message the agent wrote. Written to a terminal unfiltered, an agent could
//! put escape sequences in a file, move the cursor, and paint over the question
//! it is being asked, or draw a `y` that was never typed. So every byte of the
//! request is written through `writeFiltered`. That is not a complete defence
//! against every way text can mislead a reader, and the comment there says what
//! it does and does not cover.

const std = @import("std");
const chock_proto = @import("chock-proto");
const chock_broker = @import("chock-broker");
const chock_policy = @import("chock-policy");
const chock_io = @import("chock-io");
const interrupt = @import("interrupt.zig");
const tty = @import("tty.zig");
const ui = @import("ui.zig");

const event = chock_proto.event;
const Broker = chock_broker.Broker;

/// `chock_proto.storage.Locked` is not `pub`, so no file outside that one can
/// name it. This reaches the same type through the return type of
/// `Storage.lock`, which is public. The broker still takes `locked: anytype`;
/// this file needs the name because it holds a pointer to the handle the
/// caller took.
const Locked = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

/// The longest answer this reads before it gives up on the line. The words the
/// prompt names are one and three letters long, so anything near this is not
/// an answer to the question asked.
pub const max_answer_bytes: usize = 256;

/// How much of a request's `detail` reaches the terminal. A diff of a whole
/// tree is megabytes, and a screen a person cannot scroll back through is a
/// review nobody performs. What is left out is counted on screen, and the
/// whole of it is in the log either way.
pub const max_detail_bytes: usize = 8 * 1024;

/// Whether there is a person to ask.
///
/// **Read from what standard input really is**, not from whether this looks
/// like an interactive command. A subagent and a daemon session are both
/// spawned with `.stdin = .ignore`, which is `/dev/null`, and a pipe is not a
/// terminal either. Each of those is a session with nobody at the keyboard.
pub fn hasTerminal(io: std.Io) bool {
    return std.Io.File.stdin().isTty(io) catch false;
}

/// How long one approval waits for an answer.
///
/// **Zero without a terminal, and that is a refusal.** A question nobody can
/// answer must not hold the session lock for five minutes first: the broker
/// expires a request whose deadline has passed on its first look, with no wait
/// at all, and `Broker.reviewed` reads the same zero and spends nothing on a
/// review whose second half cannot happen.
///
/// With a terminal it is the broker's own default, five minutes, which is long
/// enough to read a diff and short enough that a session nobody is watching
/// stops instead of holding the lock all night.
pub fn timeoutMs(at_terminal: bool) i64 {
    return if (at_terminal) Broker.default_timeout_ms else 0;
}

/// Where the question goes and where the answer comes from.
///
/// **A seam, so that no test reads real standard input.** A test that did
/// would block forever with nobody to type into it, which is the one thing
/// this whole file is against. The same shape `chock_nix.provision.Runner` and
/// `chock_provider.retry.Sleeper` have, and for the same reason.
pub const Console = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    /// How one call to `read` ended.
    pub const Read = union(enum) {
        /// The budget passed with nothing typed. The broker's own deadline is
        /// what decides whether to ask again.
        idle,
        /// This many bytes were read into the buffer.
        bytes: usize,
        /// The input ended. **There is nobody there**, which is not the same
        /// fact as somebody answering no, and this file records it as an
        /// expiry for exactly that reason.
        ended,
        /// Something asked this session to stop.
        canceled,
    };

    pub const VTable = struct {
        /// Show these bytes. **The result is dropped**: a terminal that went
        /// away must not turn an approval into a crash, and the question is in
        /// the log whether or not it reached a screen.
        write: *const fn (ptr: *anyopaque, io: std.Io, bytes: []const u8) void,
        /// Wait at most `budget_ms` for something to be typed, and read what
        /// arrived into `buffer`. See `Read` for the four ways it ends.
        read: *const fn (
            ptr: *anyopaque,
            io: std.Io,
            buffer: []u8,
            budget_ms: u64,
        ) Read,
    };

    pub fn write(self: Console, io: std.Io, bytes: []const u8) void {
        self.vtable.write(self.ptr, io, bytes);
    }

    pub fn read(self: Console, io: std.Io, buffer: []u8, budget_ms: u64) Read {
        return self.vtable.read(self.ptr, io, buffer, budget_ms);
    }
};

/// The real `Console`: the terminal this process was started on.
///
/// The read is a `poll` with the broker's budget as its timeout, and then a
/// read of what `poll` said is there. **Not a blocking read**, because a
/// blocking read holds the session lock for as long as a person is away, and
/// the deadline the broker carries would then mean nothing.
pub const Stdin = struct {
    /// Where the answer is read from. Standard input, and a field rather than
    /// a constant for one reason: **fd 0 of a test binary belongs to the build
    /// runner**, which speaks to it over that descriptor, so a test that
    /// replaced fd 0 would break the runner instead of proving anything. The
    /// test below gives this a pipe of its own and drives the same `poll` and
    /// the same `read` the real one uses.
    fd: std.posix.fd_t = std.posix.STDIN_FILENO,

    pub fn console(self: *const Stdin) Console {
        return .{ .ptr = @constCast(self), .vtable = &vtable };
    }

    const vtable = Console.VTable{ .write = writeFn, .read = readFn };

    /// **Through `src/tty.zig`'s standard output writer, and flushed at once.**
    ///
    /// Two facts make both halves necessary. The writer is holding bytes that
    /// have not left yet, so a question written around it would arrive in front
    /// of the very rows it is asking about. And a question ends with no
    /// newline, because the answer is typed after it on the same line, so
    /// nothing later is going to push it out: an unflushed question is a
    /// program that looks like it has hung.
    fn writeFn(ptr: *anyopaque, io: std.Io, bytes: []const u8) void {
        _ = ptr;
        if (!tty.writeOut(bytes)) {
            // Nobody set the streams. Straight out is where a question always
            // went, and nothing is buffered to get ahead of.
            std.Io.File.stdout().writeStreamingAll(io, bytes) catch {};
            return;
        }
        tty.flushOut();
    }

    fn readFn(ptr: *anyopaque, io: std.Io, buffer: []u8, budget_ms: u64) Console.Read {
        _ = io;
        const self: *const Stdin = @ptrCast(@alignCast(ptr));
        std.debug.assert(buffer.len > 0);

        var fds = [_]std.posix.pollfd{.{
            .fd = self.fd,
            // A closed input is readable too: the read that follows gets the
            // end of the stream, which is the `ended` case with its own
            // answer.
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const timeout: i32 = if (budget_ms > std.math.maxInt(i32))
            std.math.maxInt(i32)
        else
            @intCast(budget_ms);

        // A poll that cannot run says nothing about the person, and the safe
        // reading of "this cannot be asked" is that nobody answered.
        const ready = std.posix.poll(&fds, timeout) catch return .ended;
        if (ready == 0) return .idle;

        const count = std.posix.read(self.fd, buffer) catch |err| switch (err) {
            // `poll` said there was something and there was not. Nothing was
            // lost, so wait again rather than call it an end.
            error.WouldBlock => return .idle,
            error.Canceled => return .canceled,
            else => return .ended,
        };
        if (count == 0) return .ended;
        return .{ .bytes = count };
    }
};

/// A `Broker.Waiter` that asks the person at this terminal.
///
/// **The answer is appended through `locked`**, the same handle the broker is
/// writing the question with. See this file's own top comment: that is the
/// whole reason this works without touching the lock.
pub const Terminal = struct {
    gpa: std.mem.Allocator,
    /// Read from, to find the open question. The broker reads it too, through
    /// its own `replay`, and a replay takes no lock.
    storage: chock_proto.storage.Storage,
    /// The caller's proof it holds the exclusive lock. **The only handle**.
    locked: *Locked,
    console: Console,
    /// Whether a stop has been asked for. A field so a test can answer it
    /// without raising a real signal at the whole test binary: see this file's
    /// own top comment for why a press does not arrive as a read error.
    stop: *const fn () bool = interrupt.requested,
    /// The id of the request this has already put on screen. A question is
    /// asked once, however many times the broker gives control away.
    prompted: ?u64 = null,
    /// What has been typed so far and does not yet end a line.
    answer: [max_answer_bytes]u8 = undefined,
    filled: usize = 0,
    /// The first fault that stopped this from answering, for the caller to
    /// report. A `Waiter` cannot give an error back to the broker.
    failed: ?anyerror = null,

    pub fn waiter(self: *Terminal) Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    /// The machine's own clock, the same one `Broker.SystemWaiter` reads, and
    /// for the same reason: `timeout_at_ms` is a unix time every client reads
    /// and not a number private to this process.
    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = ptr;
        return std.Io.Timestamp.now(io, .real).toMilliseconds();
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        const self: *Terminal = @ptrCast(@alignCast(ptr));
        return self.step(io, budget_ms);
    }

    /// One look: read the flag, find the question, ask it once, and read for
    /// at most the budget.
    ///
    /// Its own function, taking and giving ordinary values, so every test below
    /// drives the same code the broker drives.
    pub fn step(self: *Terminal, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        // **First, and before anything is shown.** A person who pressed Ctrl-C
        // is not answering a question; they are leaving.
        if (self.stop()) return .canceled;

        const open = self.openRequest(io) catch |err| {
            // The question was appended moments ago through the handle this
            // holds, so a log that cannot be read back is a broken log and not
            // an unanswered question. Waiting out the deadline would hold the
            // session lock for five minutes over a fault that is already
            // certain.
            self.report(err, "the session log could not be read, so nobody could be asked");
            return .canceled;
        } orelse return .slept;

        if (self.prompted == null or self.prompted.? != open) {
            self.ask(io, open) catch |err| {
                self.report(err, "the approval could not be shown");
                return .canceled;
            };
            self.prompted = open;
        }

        return self.readAnswer(io, open, budget_ms);
    }

    /// The id of the question that is still open, or null when there is none.
    ///
    /// **One definition, on the broker itself.** The socket waiter asks the same
    /// question, and two waiters that disagreed about which question is open
    /// would be one answering a question the other is showing.
    fn openRequest(self: *Terminal, io: std.Io) !?u64 {
        return Broker.openRequest(self.gpa, io, self.storage);
    }

    /// Put one question on screen.
    fn ask(self: *Terminal, io: std.Io, request_id: u64) !void {
        var replay = try self.storage.replay(self.gpa, io, request_id);
        defer replay.deinit();

        const parsed = try replay.next(io) orelse return error.RequestNotInTheLog;
        defer parsed.deinit();
        if (parsed.value.event != .approval_request) return error.RequestNotInTheLog;

        const text = try promptText(self.gpa, parsed.value.event.approval_request, .terminal);
        defer self.gpa.free(text);
        writeFiltered(self.console, io, text);
    }

    /// Read for at most the budget, and record an answer when there is one.
    fn readAnswer(
        self: *Terminal,
        io: std.Io,
        request_id: u64,
        budget_ms: u64,
    ) Broker.Waiter.Wake {
        const room = self.answer[self.filled..];
        if (room.len == 0) {
            // A line longer than the buffer is not one of the words the prompt
            // named, so it is not an approval. Refusing is the safe direction
            // and it ends the wait rather than reading the rest of it.
            return self.record(io, request_id, .refused_by_user);
        }

        switch (self.console.read(io, room, budget_ms)) {
            .idle => return .slept,
            .canceled => return .canceled,
            // Nobody is there. Not a refusal by a person: see `Console.Read`.
            .ended => return self.record(io, request_id, .expired),
            .bytes => |count| {
                self.filled += count;
                const line = self.answer[0..self.filled];
                const end = std.mem.indexOfScalar(u8, line, '\n') orelse return .slept;
                const said = line[0..end];
                self.filled = 0;
                const decision: event.ApprovalDecision = if (saysYes(said))
                    .approved_by_user
                else if (saysSession(said))
                    .approved_by_user_for_session
                else
                    .refused_by_user;
                return self.record(io, request_id, decision);
            },
        }
    }

    /// Append the answer through the caller's own handle. See this file's own
    /// top comment: this one line is the whole trick.
    ///
    /// **`action` is read back out of the request, not carried from `ask`.**
    /// `readAnswer` may take several looks to fill one line, and `ask` runs
    /// only on the first of them, so `record` reads the request fresh rather
    /// than keep a copy nothing frees at the end of a session. See
    /// `Broker.requestAction`.
    fn record(
        self: *Terminal,
        io: std.Io,
        request_id: u64,
        decision: event.ApprovalDecision,
    ) Broker.Waiter.Wake {
        const action = (Broker.requestAction(self.gpa, io, self.storage, request_id) catch |err| {
            self.report(err, "the answer could not be recorded");
            return .canceled;
        }) orelse {
            self.report(error.RequestNotInTheLog, "the answer could not be recorded");
            return .canceled;
        };
        defer self.gpa.free(action);

        _ = self.locked.append(self.gpa, io, .{ .approval_response = .{
            .request_id = request_id,
            .decision = decision,
            .responder = responder,
            .action = action,
        } }, std.Io.Timestamp.now(io, .real).toMilliseconds()) catch |err| {
            self.report(err, "the answer could not be written to the session log");
            return .canceled;
        };
        // The broker looks at the log before it waits again, so it reads this
        // on its very next look.
        return .slept;
    }

    /// Say what went wrong, once, and keep the first one for the caller.
    fn report(self: *Terminal, err: anyerror, what: []const u8) void {
        tty.print(.err, "chock run: {s}: {s}\n", .{ what, @errorName(err) });
        if (self.failed == null) self.failed = err;
    }
};

/// A `Broker.Waiter` that asks the person watching the display.
///
/// ## Why this exists beside `Terminal` and not instead of it
///
/// `Terminal` writes its own prompt straight at the terminal and reads its own
/// key from it. That is right for `chock run`, which owns no screen. It is
/// wrong the moment a display is up: the display owns the device, holds it in
/// raw mode for as long as it is reading, and keeps a copy of every cell.
/// **Two readers on one descriptor race for every byte**, and a prompt written
/// around the display lands in cells the display believes it owns.
///
/// So the display becomes the waiter while it is up, and `Terminal` keeps
/// answering when there is none. `src/run.zig`'s `Approvers` is what picks, and
/// it never gives a session both: see `Approvers.waiter` and `asksHere`.
///
/// ## What is here and what is in `src/ui.zig`
///
/// **This file owns the log and the display owns the device.** Everything
/// about which question is open, and about writing the answer down, is here and
/// is the same code `Terminal` runs. Everything about pixels, focus, raw mode
/// and keys is in `src/ui.zig`, behind `showApproval`, `awaitAnswer` and
/// `clearApproval`.
///
/// ## The lock, unchanged
///
/// The answer is appended through `locked`, the caller's own handle, exactly as
/// `Terminal` does. See this file's own top comment: that is the whole reason
/// any of this works without a second open of the log.
pub const Display = struct {
    gpa: std.mem.Allocator,
    /// Read from, to find the open question.
    storage: chock_proto.storage.Storage,
    /// The caller's proof it holds the exclusive lock. **The only handle**.
    locked: *Locked,
    /// The display. Borrowed: `src/run.zig` owns it and takes it down after the
    /// loop this waiter runs inside has ended.
    screen: *ui.Ui,
    /// Whether a stop has been asked for. A field for the same reason
    /// `Terminal.stop` is one.
    stop: *const fn () bool = interrupt.requested,
    /// The question already on screen. A question is put up once, however many
    /// times the broker gives control away.
    shown: ?u64 = null,
    /// When the question on screen expires, so the countdown can move.
    deadline_ms: i64 = 0,
    /// The first fault that stopped this from answering. A `Waiter` cannot give
    /// an error back to the broker.
    failed: ?anyerror = null,

    pub fn waiter(self: *Display) Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    /// The machine's own clock, the same one every other waiter reads.
    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = ptr;
        return std.Io.Timestamp.now(io, .real).toMilliseconds();
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        const self: *Display = @ptrCast(@alignCast(ptr));
        return self.step(io, budget_ms);
    }

    /// One look: read the flag, find the question, put it up once, and take
    /// keys for at most the budget.
    ///
    /// Its own function, taking and giving ordinary values, so a test drives
    /// exactly what the broker drives.
    pub fn step(self: *Display, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        // **First, and before anything is shown.** A person who pressed Ctrl-C
        // is not answering a question; they are leaving.
        if (self.stop()) {
            self.takeDown();
            return .canceled;
        }

        const open = self.openRequest(io) catch |err| {
            // The question was appended moments ago through the handle this
            // holds, so a log that cannot be read back is a broken log and not
            // an unanswered question.
            self.report(err, "the session log could not be read, so nobody could be asked");
            self.takeDown();
            return .canceled;
        } orelse {
            // Answered, by this waiter on an earlier look or by a client on the
            // approval socket. The region goes at once, because a question a
            // person can still see and can no longer answer is worse than none.
            self.takeDown();
            return .slept;
        };

        if (self.shown == null or self.shown.? != open) {
            self.putUp(io, open) catch |err| {
                self.report(err, "the approval could not be shown");
                self.takeDown();
                return .canceled;
            };
            self.shown = open;
        }

        self.screen.approvalLeft(
            self.deadline_ms - std.Io.Timestamp.now(io, .real).toMilliseconds(),
        );

        switch (self.screen.awaitAnswer(budget_ms)) {
            .waiting => return .slept,
            .canceled => {
                self.takeDown();
                return .canceled;
            },
            .answered => |said| {
                const decision: event.ApprovalDecision = switch (said) {
                    .approved => .approved_by_user,
                    .refused => .refused_by_user,
                };
                const wake = self.record(io, open, decision);
                self.takeDown();
                return wake;
            },
        }
    }

    /// The id of the question that is still open, or null when there is none.
    /// **One definition, on the broker itself**: see `Terminal.openRequest`.
    fn openRequest(self: *Display, io: std.Io) !?u64 {
        return Broker.openRequest(self.gpa, io, self.storage);
    }

    /// Put one question in the approval region.
    fn putUp(self: *Display, io: std.Io, request_id: u64) !void {
        var replay = try self.storage.replay(self.gpa, io, request_id);
        defer replay.deinit();

        const parsed = try replay.next(io) orelse return error.RequestNotInTheLog;
        defer parsed.deinit();
        if (parsed.value.event != .approval_request) return error.RequestNotInTheLog;
        const request = parsed.value.event.approval_request;

        // Built here rather than in `src/ui.zig`, because the chain is a fact
        // about the log and the display only ever reads what it is handed. The
        // strings below are borrowed from a replay that ends on the line after
        // this call, and `showApproval` copies every one of them.
        const chain = try chainText(self.gpa, request);
        defer self.gpa.free(chain);
        const review = if (request.review == .none) "" else try std.fmt.allocPrint(
            self.gpa,
            "{s}: {s}",
            .{ request.review.wireName(), request.review_note },
        );
        defer if (review.len != 0) self.gpa.free(review);

        self.deadline_ms = request.timeout_at_ms;
        self.screen.showApproval(.{
            .request_id = request_id,
            .action = request.action,
            .summary = request.summary,
            .reason = request.reason,
            .chain = chain,
            .depth = request.spawn_chain.len + 1,
            // The same bound the terminal prompt keeps, and for the same
            // reason: a diff of a whole tree is a review nobody performs. The
            // whole of it is in the log either way.
            .detail = request.detail[0..@min(request.detail.len, max_detail_bytes)],
            .review = review,
        });
    }

    /// Take the question off the screen and give the device back. Idempotent.
    fn takeDown(self: *Display) void {
        self.shown = null;
        self.deadline_ms = 0;
        self.screen.clearApproval();
    }

    /// Append the answer through the caller's own handle. The same one line
    /// `Terminal.record` is, and for the same reason.
    ///
    /// **`action` is read back out of the request.** See `Terminal.record`'s
    /// own doc comment and `Broker.requestAction`.
    fn record(
        self: *Display,
        io: std.Io,
        request_id: u64,
        decision: event.ApprovalDecision,
    ) Broker.Waiter.Wake {
        const action = (Broker.requestAction(self.gpa, io, self.storage, request_id) catch |err| {
            self.report(err, "the answer could not be recorded");
            return .canceled;
        }) orelse {
            self.report(error.RequestNotInTheLog, "the answer could not be recorded");
            return .canceled;
        };
        defer self.gpa.free(action);

        _ = self.locked.append(self.gpa, io, .{ .approval_response = .{
            .request_id = request_id,
            .decision = decision,
            .responder = display_responder,
            .action = action,
        } }, std.Io.Timestamp.now(io, .real).toMilliseconds()) catch |err| {
            self.report(err, "the answer could not be written to the session log");
            return .canceled;
        };
        // The broker looks at the log before it waits again, so it reads this
        // on its very next look.
        return .slept;
    }

    /// Say what went wrong, once, and keep the first one for the caller.
    ///
    /// **Standard error and not the region**, because the display is drawing on
    /// standard output and `src/tty.zig` keeps the two apart. A line written
    /// there scrolls the screen, which the display notices and repaints from.
    fn report(self: *Display, err: anyerror, what: []const u8) void {
        tty.print(.err, "chock run: {s}: {s}\n", .{ what, @errorName(err) });
        if (self.failed == null) self.failed = err;
    }
};

/// Every agent that asked, root first, as a person reads it.
///
/// **`you` is the first link and is not an agent.** The chain begins with the
/// person, because the question being asked is what the session was asked to
/// do. Everything after it comes out of the log.
///
/// The caller owns the result.
pub fn chainText(
    gpa: std.mem.Allocator,
    request: event.ApprovalRequest,
) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(gpa);
    try text.appendSlice(gpa, "you");
    for (request.spawn_chain) |link| {
        try text.appendSlice(gpa, " \u{25b8} ");
        try text.appendSlice(gpa, link.agent_kind);
    }
    try text.appendSlice(gpa, " \u{25b8} ");
    try text.appendSlice(gpa, request.agent_kind);
    return text.toOwnedSlice(gpa);
}

/// What the `responder` of an answer from a terminal says.
///
/// **Where the answer came from, and never a name.** A user name read from the
/// environment is unverified, and an unverified name in a security record is
/// worse than a plain fact: a reader would take it for proof of who approved.
/// Signing these records later is what makes a name worth writing.
pub const responder = "terminal";

/// What the `responder` of an answer given in the display says.
///
/// **A different word from `responder`**, because they are different facts: one
/// answer was typed at a bare prompt and the other in a full screen region that
/// no agent can draw in. A record that spelled them the same way would lose
/// which of the two a reader is looking at.
pub const display_responder = "display";

/// Whether an answer is plainly yes, for this one act alone.
///
/// **Anything that is not is a refusal**, which is the rule
/// `lib/chock-broker/review.zig` already keeps for a reviewer's answer. A
/// typed word this does not know is not permission, the prompt names the
/// three answers it accepts, and a bare newline is the default the prompt
/// shows in capitals.
pub fn saysYes(said: []const u8) bool {
    const trimmed = std.mem.trim(u8, said, " \t\r");
    if (trimmed.len == 0) return false;
    return std.ascii.eqlIgnoreCase(trimmed, "y") or std.ascii.eqlIgnoreCase(trimmed, "yes");
}

/// Whether an answer asks for the rest of the session, not only this once.
///
/// **A word of its own, and never a modifier on `saysYes`.** The two must
/// stay easy to tell apart at a glance from a person answering at three in
/// the morning, so `promptText` offers exactly two letters, `y` and `s`, to
/// the one asker that can keep the promise `s` makes, and never to
/// `Client.socket`: see that type's own doc comment. There is no third word
/// that reaches `chock.zon`: see
/// `event.ApprovalDecision.approved_by_user_for_session` for what this
/// actually records, and why it never reaches farther than this process.
pub fn saysSession(said: []const u8) bool {
    const trimmed = std.mem.trim(u8, said, " \t\r");
    if (trimmed.len == 0) return false;
    return std.ascii.eqlIgnoreCase(trimmed, "s") or std.ascii.eqlIgnoreCase(trimmed, "session");
}

/// Who is being asked, so `promptText` never offers a letter that asker
/// cannot act on.
///
/// **The session-wide memory needs the log's exclusive lock, and only one
/// asker ever holds it.** `Terminal` and `Display` both run inside the process
/// that holds that lock, so a `session` answer from either is a fact that
/// process can act on for the rest of its own run. A peer of the approval
/// socket is a different process, over a connection `lib/chock-broker/socket.zig`
/// does not trust with that memory: its own `decisionFrom` turns
/// `approved_by_user_for_session` from any peer into a refusal, whatever this
/// function prints. Offering the letter there would show a choice the answer
/// can never keep, so it is not offered.
pub const Client = enum {
    /// The process that holds the log's exclusive lock: `Terminal`, at
    /// `chock run`'s own terminal.
    terminal,
    /// `chock approve`, on the far side of the approval socket. See this
    /// type's own doc comment for why the session letter stops here.
    socket,
};

/// The question, as a person reads it. The caller owns the result.
///
/// Its own function, over an `ApprovalRequest` and nothing else, so a test
/// reads exactly what a person would and no test needs a terminal.
pub fn promptText(
    gpa: std.mem.Allocator,
    request: event.ApprovalRequest,
    client: Client,
) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(gpa);

    try text.appendSlice(gpa, "\nchock: this needs your approval before it can happen.\n\n");
    try text.print(gpa, "  action   {s}\n", .{request.action});

    // The chain is shown, because "a subagent three levels down asked for this"
    // is a fact that changes the answer. The agent that asked is last, the way
    // `Broker.policyChain` builds it.
    try text.appendSlice(gpa, "  asked by ");
    for (request.spawn_chain) |link| {
        try text.appendSlice(gpa, link.agent_kind);
        try text.appendSlice(gpa, " -> ");
    }
    try text.print(gpa, "{s}\n", .{request.agent_kind});

    try text.print(gpa, "  summary  {s}\n", .{request.summary});
    try text.print(gpa, "  reason   {s}\n", .{request.reason});

    // For `agent_then_human` the reviewer answered first and its verdict
    // travels with the question, so the person decides with the review in front
    // of them.
    switch (request.review) {
        .none => {},
        else => try text.print(
            gpa,
            "  review   {s}: {s}\n",
            .{ request.review.wireName(), request.review_note },
        ),
    }

    // Show the effect, never a command string. The user approves what changes.
    try text.appendSlice(gpa, "\n  what it changes\n\n");
    const shown = request.detail[0..@min(request.detail.len, max_detail_bytes)];
    try text.appendSlice(gpa, shown);
    if (shown.len != request.detail.len) {
        try text.print(
            gpa,
            "\n  ... {d} more bytes are in the session log and are not shown here.\n",
            .{request.detail.len - shown.len},
        );
    }

    // Two answers say yes, and everything else is a no. The terminal prompt
    // shows a third letter, `N`, only to mark the default when nothing is
    // typed, never as a third way to say yes.
    // `y` runs this one act and asks again next time. `s` runs it and
    // remembers this exact action for the rest of the session, so a project
    // that just wrote its first `ask` rule does not turn every later call into
    // the same question. Neither ever reaches `chock.zon`: see
    // `event.ApprovalDecision.approved_by_user_for_session`.
    //
    // **The socket never gets the second answer.** See `Client`'s own doc
    // comment: a choice this asker cannot keep is not offered to it.
    switch (client) {
        .terminal => try text.appendSlice(
            gpa,
            "\nAllow this once, or for the rest of the session? [y/N/s] ",
        ),
        .socket => try text.appendSlice(gpa, "\nAllow this? [y/N] "),
    }
    return text.toOwnedSlice(gpa);
}

/// Write text to a console with the bytes that drive a terminal taken out.
///
/// **The detail of a request is written by the agent**, so an escape sequence
/// in a file it changed would otherwise reach the terminal that is asking
/// about that very change: a cursor move can paint over the question, and a
/// clear can hide a line of the diff. Neither is a hypothetical, and both cost
/// nothing to stop.
///
/// Tabs and newlines are kept, because a diff is made of them. Every other
/// byte below a space, and the delete byte, becomes a lone question mark, so
/// the text a person reads is the same length in lines it would have been.
/// Bytes at or above `0x80` are passed through, because a diff of a real file
/// is UTF-8.
///
/// **This is not the whole of the problem.** Text can still mislead a reader
/// with the characters that reverse a line's direction, and with a name that
/// reads like another name. Those need a Unicode aware pass, and this stops
/// the one that rewrites the screen.
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

const testing = std.testing;

/// The name of one decision, without the words an `unknown` carries. The tests
/// read the log back after the replay that parsed it has ended, and a name
/// outlives that parse where a borrowed string does not.
const Decision = std.meta.Tag(event.ApprovalDecision);

/// A `Console` a test scripts. It never touches a terminal.
const FakeConsole = struct {
    /// What `read` answers, in order. The last one is repeated, so a test that
    /// scripts one answer does not depend on how many times the broker looks.
    replies: []const Console.Read,
    /// The bytes each `bytes` reply delivers, in the same order.
    lines: []const []const u8 = &.{},
    reads: usize = 0,
    lines_taken: usize = 0,
    /// Everything that was shown, joined.
    shown: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,
    /// The budget of the last read, so a test can pin that the broker's own
    /// bound reaches the thing that waits.
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

/// A policy that asks a person about everything.
const ask_everything =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .decision = .ask },
    \\        },
    \\    },
    \\}
;

fn neverStopped() bool {
    return false;
}

fn alwaysStopped() bool {
    return true;
}

/// What one end to end drive of the broker with a `Terminal` came back with.
const Drive = struct {
    outcome: ?Broker.Outcome,
    failure: ?anyerror,
    /// The decision of every `approval.response` in the log when it was over.
    /// The tag and not the value, because the value of an `unknown` borrows
    /// from a parse that ends with the replay.
    answers: []Decision,
    /// How many `approval.request` events are in the log.
    questions: usize,
    /// Everything that reached the screen.
    shown: []const u8,
    gpa: std.mem.Allocator,

    fn deinit(self: *Drive) void {
        self.gpa.free(self.answers);
    }
};

/// Drive a real `Broker` over a real in memory log with a real `Terminal`, and
/// read the log back afterwards.
///
/// **One lock, taken once**, and the waiter is given that same handle. That is
/// the arrangement this whole file exists to prove works.
fn drive(
    gpa: std.mem.Allocator,
    io: std.Io,
    console: *FakeConsole,
    stop: *const fn () bool,
    timeout_ms: i64,
) !Drive {
    var backing = try chock_proto.storage.Memory.init(gpa, "01APPROVAL");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var terminal = Terminal{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .console = console.console(),
        .stop = stop,
    };

    const policy = try chock_policy.table.Table.parse(gpa, ask_everything, null);
    defer chock_policy.table.Table.destroy(gpa, policy);

    const broker = Broker{ .policy = policy, .waiter = terminal.waiter() };
    const outcome = broker.request(gpa, io, store, &locked, .{
        .action = "workspace.apply",
        .summary = "move 3 objects and set refs/chock/01APPROVAL",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .model_alias = "main",
        .tool = "request_action",
        .tool_call_id = "call1",
        .timeout_ms = timeout_ms,
    }, null);

    var answers: std.ArrayList(Decision) = .empty;
    errdefer answers.deinit(gpa);
    var questions: usize = 0;
    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .approval_request => questions += 1,
            .approval_response => |response| try answers.append(gpa, std.meta.activeTag(response.decision)),
            else => {},
        }
    }

    // A fault the waiter could not give back to the broker is a fault a test
    // must not read past. See `Terminal.failed`.
    if (terminal.failed) |err| return err;

    return .{
        .outcome = if (outcome) |value| value else |_| null,
        .failure = if (outcome) |_| null else |err| err,
        .answers = try answers.toOwnedSlice(gpa),
        .questions = questions,
        .shown = console.shown.items,
        .gpa = gpa,
    };
}

test "an end of file on standard input refuses, and it does not wait for the deadline" {
    // The first of the three ways to have nobody. A pipe that closed, and a
    // session whose standard input is /dev/null, both arrive here. What is
    // pinned is that the answer is written at once and that it is a refusal:
    // a waiter that returned `slept` for an ended input would poll for the
    // whole five minutes with the session lock held.
    const gpa = testing.allocator;
    const io = testing.io;

    var console = FakeConsole{ .gpa = gpa, .replies = &.{.ended} };
    defer console.deinit();

    var result = try drive(gpa, io, &console, neverStopped, Broker.default_timeout_ms);
    defer result.deinit();

    try testing.expectEqual(Broker.Outcome.expired, result.outcome.?);
    try testing.expect(!result.outcome.?.permits());
    // One question and exactly one answer: the waiter's own, and no second one
    // from the broker's deadline.
    try testing.expectEqual(@as(usize, 1), result.questions);
    try testing.expectEqual(@as(usize, 1), result.answers.len);
    try testing.expectEqual(Decision.expired, result.answers[0]);
    // And it took one look at the console, not thousands.
    try testing.expectEqual(@as(usize, 1), console.reads);
}

test "a session with no terminal refuses at once and never reaches the console" {
    // The second way to have nobody, and the one a subagent and a daemon
    // session are in. `timeoutMs` gives them a deadline that has already
    // passed, so the broker expires the request on its first look with no wait
    // at all. The console proves it: nothing was shown and nothing was read.
    const gpa = testing.allocator;
    const io = testing.io;

    try testing.expectEqual(@as(i64, 0), timeoutMs(false));
    try testing.expectEqual(Broker.default_timeout_ms, timeoutMs(true));

    var console = FakeConsole{ .gpa = gpa, .replies = &.{.idle} };
    defer console.deinit();

    var result = try drive(gpa, io, &console, neverStopped, timeoutMs(false));
    defer result.deinit();

    try testing.expectEqual(Broker.Outcome.expired, result.outcome.?);
    try testing.expectEqual(@as(usize, 0), console.reads);
    try testing.expectEqual(@as(usize, 0), result.shown.len);
    // The record is still written, because these are to be signed later and a
    // decision with no record cannot become a signed one.
    try testing.expectEqual(@as(usize, 1), result.answers.len);
}

test "a yes and a no both leave a record that replays, written through the one handle" {
    // The two answers a person gives. Both are driven through a real broker
    // over a real log, and the log is read back afterwards, so what is pinned
    // is that the answer reached the log through the handle the broker itself
    // is writing with. A second handle would have failed to take the lock.
    const gpa = testing.allocator;
    const io = testing.io;

    const cases = [_]struct {
        typed: []const u8,
        outcome: Broker.Outcome,
        permits: bool,
    }{
        .{ .typed = "y\n", .outcome = .approved_by_user, .permits = true },
        .{ .typed = "yes\n", .outcome = .approved_by_user, .permits = true },
        .{ .typed = "Y\n", .outcome = .approved_by_user, .permits = true },
        .{ .typed = "n\n", .outcome = .refused_by_user, .permits = false },
        // A bare newline is the default the prompt shows in capitals.
        .{ .typed = "\n", .outcome = .refused_by_user, .permits = false },
        // A word this build does not know is not permission.
        .{ .typed = "maybe\n", .outcome = .refused_by_user, .permits = false },
    };

    for (cases) |case| {
        const lines = [_][]const u8{case.typed};
        var console = FakeConsole{
            .gpa = gpa,
            .replies = &.{.{ .bytes = 0 }},
            .lines = &lines,
        };
        defer console.deinit();

        var result = try drive(gpa, io, &console, neverStopped, Broker.default_timeout_ms);
        defer result.deinit();

        try testing.expectEqual(case.outcome, result.outcome.?);
        try testing.expectEqual(case.permits, result.outcome.?.permits());
        try testing.expectEqual(@as(usize, 1), result.questions);
        try testing.expectEqual(@as(usize, 1), result.answers.len);
        // The record names the same decision the caller was given, so a replay
        // of this log a week later reads what happened.
        try testing.expectEqual(
            @as(Decision, switch (case.outcome) {
                .approved_by_user => .approved_by_user,
                else => .refused_by_user,
            }),
            result.answers[0],
        );
        // And the question reached the screen.
        try testing.expect(std.mem.indexOf(u8, result.shown, "workspace.apply") != null);
        try testing.expect(std.mem.indexOf(u8, result.shown, "[y/N/s]") != null);
    }
}

test "an answer of session is its own decision, distinct from a plain yes" {
    // The third word the prompt accepts. It permits the act exactly as a
    // plain yes does, from the broker's own point of view: `Broker.Outcome`
    // has no member for it, only `event.ApprovalDecision` does, because the
    // extra promise is a fact for `state.SessionGrants` to remember and not a
    // fact about this one request. This is what the two must not be, and
    // this test is what would fail if `readAnswer` ever folded them together.
    const gpa = testing.allocator;
    const io = testing.io;

    const lines = [_][]const u8{"s\n"};
    var console = FakeConsole{
        .gpa = gpa,
        .replies = &.{.{ .bytes = 0 }},
        .lines = &lines,
    };
    defer console.deinit();

    var result = try drive(gpa, io, &console, neverStopped, Broker.default_timeout_ms);
    defer result.deinit();

    try testing.expectEqual(Broker.Outcome.approved_by_user, result.outcome.?);
    try testing.expect(result.outcome.?.permits());
    try testing.expectEqual(@as(usize, 1), result.answers.len);
    try testing.expectEqual(Decision.approved_by_user_for_session, result.answers[0]);
    try testing.expect(std.mem.indexOf(u8, result.shown, "[y/N/s]") != null);
}

test "a person who says session is not asked again, through a real Terminal and no fake" {
    // **The point of this task.** Every other test in this file drives one
    // question and stops. This drives two, over the same log, with a fresh
    // `state.Session` folded before each one, exactly the way
    // `src/run.zig`'s own `SessionArbiter.decideFn` and `carryCommit` do it
    // for a live session: a new `Session` and a new `Broker` on every turn,
    // because neither keeps one alive across a tool call.
    //
    // **Nothing here fills in `.action` by hand.** `Terminal.record`, real
    // production code, is the only thing that ever writes either
    // `approval.response`. A test that scripted the second line itself, the
    // way the two fakes elsewhere in this codebase do, would prove that
    // `SessionGrants` works and nothing about whether `Terminal` ever gives
    // it what it needs, which is exactly the gap that shipped four times
    // over with every test green.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01SESSIONGRANT");
    const store = backing.storage();
    defer store.close(io);

    const policy = try chock_policy.table.Table.parse(gpa, ask_everything, null);
    defer chock_policy.table.Table.destroy(gpa, policy);

    const ask = Broker.Request{
        .action = "workspace.apply",
        .summary = "move 3 objects and set refs/chock/01SESSIONGRANT",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .model_alias = "main",
        .tool = "request_action",
        .tool_call_id = "call1",
        .timeout_ms = Broker.default_timeout_ms,
    };

    // The first question: a person types "s".
    {
        var session = chock_proto.state.Session.init(gpa);
        defer session.deinit();
        {
            var replay = try store.replay(gpa, io, 0);
            defer replay.deinit();
            while (try replay.next(io)) |parsed| {
                defer parsed.deinit();
                try session.apply(parsed.value);
            }
        }

        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        const lines = [_][]const u8{"s\n"};
        var console = FakeConsole{
            .gpa = gpa,
            .replies = &.{.{ .bytes = 0 }},
            .lines = &lines,
        };
        defer console.deinit();

        var terminal = Terminal{
            .gpa = gpa,
            .storage = store,
            .locked = &locked,
            .console = console.console(),
        };

        const broker = Broker{ .policy = policy, .waiter = terminal.waiter(), .grants = &session.grants };
        // `session.arena.allocator()`, and not `gpa`: `session.grants` is
        // filled through that arena, and `Broker.grants_allocator`'s own doc
        // comment says why a live grant recorded through a different
        // allocator risks a later `grow` freeing arena memory through the
        // wrong one. `src/run.zig`'s `SessionArbiter.decideFn` is the
        // production caller this mirrors: nothing this call returns needs to
        // outlive `session`, so the whole call can use its arena.
        const outcome = try broker.request(session.arena.allocator(), io, store, &locked, ask, null);
        try testing.expectEqual(Broker.Outcome.approved_by_user, outcome);
        if (terminal.failed) |err| return err;
    }

    // The identical request again, from nothing: a fresh `Session` folded
    // from the log the first block left behind, and a fresh `Terminal` whose
    // console is never read from. If it is, the test that follows fails,
    // because the console this time has nothing to say.
    {
        var session = chock_proto.state.Session.init(gpa);
        defer session.deinit();
        {
            var replay = try store.replay(gpa, io, 0);
            defer replay.deinit();
            while (try replay.next(io)) |parsed| {
                defer parsed.deinit();
                try session.apply(parsed.value);
            }
        }

        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var console = FakeConsole{ .gpa = gpa, .replies = &.{.ended} };
        defer console.deinit();

        var terminal = Terminal{
            .gpa = gpa,
            .storage = store,
            .locked = &locked,
            .console = console.console(),
        };

        const broker = Broker{ .policy = policy, .waiter = terminal.waiter(), .grants = &session.grants };
        const outcome = try broker.request(session.arena.allocator(), io, store, &locked, ask, null);
        try testing.expectEqual(Broker.Outcome.approved_by_user, outcome);
        try testing.expectEqual(@as(usize, 0), console.reads);
        if (terminal.failed) |err| return err;
    }

    // Exactly one question was ever put to a person, however many times the
    // same act was asked about: the memory answered the second one before a
    // request for it ever reached the log. That is what `questions` pins,
    // and it is the fact this test is named for.
    //
    // **A response count alone used to stand in for that fact, and it no
    // longer can.** `Broker.request`'s own `ask` branch now writes a compact
    // `approval.response` when a grant answers, `request_id` zero, so a
    // session grant that works produces two responses on purpose: the real
    // answer `Terminal.record` wrote to the first question, and the record
    // of the second act the grant served with no question of its own. A bare
    // count of two would pass whether or not the grant actually fired, since
    // an unrelated second `askTheHuman` would also leave two responses
    // behind. So this checks the two apart by what each one is: one answered
    // request, real question and all, and one grant record with no request
    // behind it, naming the exact tool call it served.
    var questions: usize = 0;
    var answered_requests: usize = 0;
    var grant_records: usize = 0;
    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .approval_request => |request| {
                questions += 1;
                try testing.expectEqualStrings("workspace.apply", request.action);
            },
            .approval_response => |response| {
                try testing.expectEqualStrings("workspace.apply", response.action);
                try testing.expectEqual(Decision.approved_by_user_for_session, response.decision);
                if (response.request_id == 0) {
                    grant_records += 1;
                    try testing.expectEqualStrings("call1", response.tool_call_id);
                } else {
                    answered_requests += 1;
                }
            },
            else => {},
        }
    }
    try testing.expectEqual(@as(usize, 1), questions);
    try testing.expectEqual(@as(usize, 1), answered_requests);
    try testing.expectEqual(@as(usize, 1), grant_records);
}

test "a Ctrl-C at the prompt ends the wait and leaves the question open" {
    // A press does not come back through the read: `std.posix.poll` retries an
    // interrupted call itself. So the flag is what this reads, and it is read
    // before anything is shown. The question stays in the log with no answer,
    // which is the same state a crash at that moment leaves, and it is why
    // `src/run.zig` keeps the workspace.
    const gpa = testing.allocator;
    const io = testing.io;

    var console = FakeConsole{ .gpa = gpa, .replies = &.{.idle} };
    defer console.deinit();

    var result = try drive(gpa, io, &console, alwaysStopped, Broker.default_timeout_ms);
    defer result.deinit();

    try testing.expect(result.outcome == null);
    try testing.expectEqual(@as(anyerror, error.Canceled), result.failure.?);
    try testing.expectEqual(@as(usize, 1), result.questions);
    try testing.expectEqual(@as(usize, 0), result.answers.len);
    // Nothing was shown and nothing was read: a person who is leaving is not
    // asked a question first.
    try testing.expectEqual(@as(usize, 0), console.reads);
    try testing.expectEqual(@as(usize, 0), result.shown.len);
}

test "a console that says nothing still ends, and it ends as a refusal" {
    // The third way to have nobody: a person who went to bed. The console is
    // idle every time, so nothing this file does ends the wait and the only
    // thing left is the broker's own deadline. **What is pinned is that it
    // ends at all**, and that what it ends as does not permit the act. Nothing
    // here says how long it took: a waiter that read a person's answer with a
    // blocking read would not return from this call at all.
    const gpa = testing.allocator;
    const io = testing.io;

    var console = FakeConsole{ .gpa = gpa, .replies = &.{.idle} };
    defer console.deinit();

    var result = try drive(gpa, io, &console, neverStopped, 1);
    defer result.deinit();

    try testing.expectEqual(Broker.Outcome.expired, result.outcome.?);
    try testing.expect(!result.outcome.?.permits());
    try testing.expectEqual(@as(usize, 1), result.answers.len);
    try testing.expectEqual(Decision.expired, result.answers[0]);
}

test "the question is asked once however many looks it takes, and the wait is bounded" {
    // Driven through `Terminal.step` and not through the broker, so the number
    // of looks is this test's own and not the real clock's. Two facts, and
    // both are ones a person notices at once when they are wrong: a prompt
    // repainted every fifty milliseconds is unreadable, and a budget the
    // console never sees is a read with no bound behind it.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01APPROVAL");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    _ = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "workspace.apply",
        .summary = "move 3 objects",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 1);

    var console = FakeConsole{ .gpa = gpa, .replies = &.{.idle} };
    defer console.deinit();

    var terminal = Terminal{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .console = console.console(),
        .stop = neverStopped,
    };

    for (0..20) |_| {
        try testing.expectEqual(
            Broker.Waiter.Wake.slept,
            terminal.step(io, Broker.poll_interval_ms),
        );
    }

    try testing.expectEqual(@as(usize, 20), console.reads);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, console.shown.items, "Allow this once"));
    try testing.expectEqual(Broker.poll_interval_ms, console.last_budget_ms);
    // Twenty idle looks and still no answer: an idle console must not become
    // one.
    try testing.expect(terminal.failed == null);
}

test "an escape sequence in the diff cannot redraw the prompt" {
    // The detail is written by the agent whose work is being reviewed, so an
    // agent that wanted approval could put a cursor move in a file and paint
    // over the very question being asked. Every byte a terminal reads as an
    // instruction is replaced before it reaches the screen.
    const gpa = testing.allocator;
    const io = testing.io;

    var console = FakeConsole{ .gpa = gpa, .replies = &.{.ended} };
    defer console.deinit();

    const nasty = "diff --git a/x b/x\n\x1b[2J\x1b[Hchock: approved by the user\r\n\x07";
    writeFiltered(console.console(), io, nasty);

    // Not one of them is left.
    try testing.expect(std.mem.indexOfScalar(u8, console.shown.items, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, console.shown.items, '\r') == null);
    try testing.expect(std.mem.indexOfScalar(u8, console.shown.items, 0x07) == null);
    // The text itself is still readable, and the newlines and tabs a diff is
    // made of are still there.
    try testing.expect(std.mem.indexOf(u8, console.shown.items, "diff --git a/x b/x") != null);
    try testing.expectEqual(
        std.mem.count(u8, nasty, "\n"),
        std.mem.count(u8, console.shown.items, "\n"),
    );

    // And a byte above the ASCII range is left alone, because a diff of a real
    // file is UTF-8 and a mangled one is a diff nobody can read.
    console.shown.clearRetainingCapacity();
    writeFiltered(console.console(), io, "café\ttab\n");
    try testing.expectEqualStrings("café\ttab\n", console.shown.items);
}

test "the question names the act, the chain, the reason and the review" {
    // What a person needs before answering: the effect and never a command
    // string, and the whole spawn chain, because "a subagent three levels down
    // asked for this" changes the answer. The reviewer's verdict is added too,
    // and it travels with the question so the person decides with the review in
    // front of them.
    const gpa = testing.allocator;

    const chain = [_]event.SpawnLink{
        .{ .agent_kind = "main", .reason = "the task named a build" },
    };
    const text = try promptText(gpa, .{
        .action = "workspace.apply",
        .summary = "move 3 objects and set refs/chock/01ABC",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .spawn_chain = &chain,
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
        .review = .approved,
        .review_note = "the diff is the fix the task asked for",
    }, .terminal);
    defer gpa.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "workspace.apply") != null);
    try testing.expect(std.mem.indexOf(u8, text, "main -> coder") != null);
    try testing.expect(std.mem.indexOf(u8, text, "move 3 objects") != null);
    try testing.expect(std.mem.indexOf(u8, text, "the session made a commit") != null);
    try testing.expect(std.mem.indexOf(u8, text, "a1b2c3 fix the parser") != null);
    // The reviewer's verdict and its note, both.
    try testing.expect(std.mem.indexOf(u8, text, "approved") != null);
    try testing.expect(std.mem.indexOf(u8, text, "the fix the task asked for") != null);
    // The two answers, with the refusing one as the default.
    try testing.expect(std.mem.indexOf(u8, text, "[y/N/s]") != null);

    // A request no reviewer saw says nothing about a review, rather than
    // showing an empty one a reader would wonder about.
    const plain = try promptText(gpa, .{
        .action = "git.push",
        .summary = "push a1b2c3 to origin",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    }, .terminal);
    defer gpa.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "review") == null);
    // With no parents, the chain is the asking agent alone and there is no
    // arrow at all.
    try testing.expect(std.mem.indexOf(u8, plain, "->") == null);
    try testing.expect(std.mem.indexOf(u8, plain, "asked by coder") != null);
}

test "a diff too large for a screen is cut, and says how much was left out" {
    // A review nobody can scroll back through is a review nobody performs, and
    // an approval given without reading is worse than no approval at all. The
    // whole of it is in the log either way.
    const gpa = testing.allocator;

    const detail = try gpa.alloc(u8, max_detail_bytes + 4096);
    defer gpa.free(detail);
    @memset(detail, 'x');

    const text = try promptText(gpa, .{
        .action = "workspace.apply",
        .summary = "a very large change",
        .detail = detail,
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    }, .terminal);
    defer gpa.free(text);

    try testing.expectEqual(max_detail_bytes, std.mem.count(u8, text, "x"));
    try testing.expect(std.mem.indexOf(u8, text, "4096 more bytes") != null);
    // The question is still the last thing on screen, under the cut.
    try testing.expect(std.mem.endsWith(
        u8,
        text,
        "Allow this once, or for the rest of the session? [y/N/s] ",
    ));
}

test "a socket peer is never shown the letter it cannot keep" {
    // `chock approve` speaks for a peer of the approval socket, and
    // `lib/chock-broker/socket.zig`'s own clamp turns
    // `approved_by_user_for_session` from any peer into a refusal: see
    // `decisionFrom` there and `Client`'s own doc comment here. A prompt that
    // still printed `s` as a choice would be showing a person a letter that
    // grants a session no matter what they type, so it must be gone from the
    // words this asker reads, not merely from what the clamp does with it.
    const gpa = testing.allocator;

    const request: event.ApprovalRequest = .{
        .action = "workspace.apply",
        .summary = "move 3 objects",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    };

    const socket_text = try promptText(gpa, request, .socket);
    defer gpa.free(socket_text);
    try testing.expect(std.mem.indexOf(u8, socket_text, "[y/N/s]") == null);
    try testing.expect(std.mem.indexOf(u8, socket_text, "s]") == null);
    try testing.expect(std.mem.indexOf(u8, socket_text, "the rest of the session") == null);
    try testing.expect(std.mem.endsWith(u8, socket_text, "\nAllow this? [y/N] "));

    // The rest of the question is unchanged: only the last line names what a
    // socket peer may say.
    try testing.expect(std.mem.indexOf(u8, socket_text, "workspace.apply") != null);
    try testing.expect(std.mem.indexOf(u8, socket_text, "move 3 objects") != null);

    // The terminal, over the same request, still reads the letter: this is a
    // difference between askers and not a change to what the terminal offers.
    const terminal_text = try promptText(gpa, request, .terminal);
    defer gpa.free(terminal_text);
    try testing.expect(std.mem.indexOf(u8, terminal_text, "[y/N/s]") != null);
}

test "only a plain yes is a yes" {
    // The rule `lib/chock-broker/review.zig` already keeps for a reviewer's
    // answer, applied to a person's: anything that is not plainly an approval
    // is a refusal. A waiter that read "no" as a yes by accident would be the
    // worst bug this file could have, so the near misses are named here.
    try testing.expect(saysYes("y"));
    try testing.expect(saysYes("Y"));
    try testing.expect(saysYes("yes"));
    try testing.expect(saysYes("YES"));
    try testing.expect(saysYes(" y \r"));

    try testing.expect(!saysYes(""));
    try testing.expect(!saysYes("\r"));
    try testing.expect(!saysYes("n"));
    try testing.expect(!saysYes("no"));
    try testing.expect(!saysYes("yep"));
    try testing.expect(!saysYes("yy"));
    try testing.expect(!saysYes("y y"));
    try testing.expect(!saysYes("ye s"));
    // A word that holds one is not one.
    try testing.expect(!saysYes("eyes"));
}

test "only a plain session is a session, and the two words never both fire" {
    // The two words `promptText` offers must never overlap: a person reading
    // `[y/N/s]` at three in the morning has to be able to tell them apart, and
    // a waiter that answered both at once would leave `readAnswer`'s `if` to
    // pick one arbitrarily.
    try testing.expect(saysSession("s"));
    try testing.expect(saysSession("S"));
    try testing.expect(saysSession("session"));
    try testing.expect(saysSession("SESSION"));
    try testing.expect(saysSession(" s \r"));

    try testing.expect(!saysSession(""));
    try testing.expect(!saysSession("y"));
    try testing.expect(!saysSession("yes"));
    try testing.expect(!saysSession("n"));
    try testing.expect(!saysSession("no"));
    try testing.expect(!saysSession("sessions"));
    try testing.expect(!saysSession("ss"));

    const words = [_][]const u8{
        "",        "y",   "yes",    "n",     "no", "s",
        "session", "yep", "sesion", "maybe",
    };
    for (words) |word| {
        // Never both. `readAnswer` trusts exactly that to give one decision.
        try testing.expect(!(saysYes(word) and saysSession(word)));
    }
}

test "an answer typed in pieces is read as one line" {
    // A pipe delivers what it has, which is not always a whole line, and a
    // terminal in its ordinary mode delivers one. Both have to work: a waiter
    // that read the first piece as the answer would turn "yes" typed slowly
    // into a refusal.
    const gpa = testing.allocator;
    const io = testing.io;

    const lines = [_][]const u8{ "y", "e", "s\n" };
    var console = FakeConsole{
        .gpa = gpa,
        .replies = &.{ .{ .bytes = 0 }, .{ .bytes = 0 }, .{ .bytes = 0 } },
        .lines = &lines,
    };
    defer console.deinit();

    var result = try drive(gpa, io, &console, neverStopped, Broker.default_timeout_ms);
    defer result.deinit();

    try testing.expectEqual(Broker.Outcome.approved_by_user, result.outcome.?);
    try testing.expectEqual(@as(usize, 3), console.reads);
    // Asked once, however many pieces the answer arrived in.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, result.shown, "Allow this once"));
}

test "the real console polls with a bound, reads what arrived, and calls a closed end an end" {
    // The one part of this file a fake console cannot prove: `poll` and `read`
    // on a real descriptor, on both platforms. A pipe this test owns stands in
    // for the terminal, so **nothing here waits on a person**: every byte read
    // is one this test wrote, and every wait has a millisecond bound.
    //
    // Standard input itself is left alone. Fd 0 of a test binary is how the
    // build runner talks to it, so a test that replaced fd 0 would break the
    // runner rather than pin anything: see `Stdin.fd`.
    const io = testing.io;

    // `chock_io` and not a raw `pipe` call, because Linux and Darwin do not
    // make one the same way: see `lib/chock-io.zig`.
    const pipe = try chock_io.default().pipeCloseOnExec();
    const reading: std.Io.File = .{ .handle = pipe.read_fd, .flags = .{ .nonblocking = false } };
    var writing: std.Io.File = .{ .handle = pipe.write_fd, .flags = .{ .nonblocking = false } };
    defer reading.close(io);

    const source = Stdin{ .fd = pipe.read_fd };
    const console = source.console();
    var buffer: [max_answer_bytes]u8 = undefined;

    // Nothing written yet. The read comes back when the budget passes, which
    // is what makes the broker's deadline mean something: a blocking read
    // would not return here at all.
    try testing.expectEqual(Console.Read.idle, console.read(io, &buffer, 1));

    // What was written is what is read, whole.
    try writing.writeStreamingAll(io, "yes\n");
    switch (console.read(io, &buffer, 1)) {
        .bytes => |count| try testing.expectEqualStrings("yes\n", buffer[0..count]),
        else => return error.TheRealConsoleReadNothing,
    }

    // The writing end closes. That is a pipe that ended, and it is also what a
    // session whose standard input is /dev/null reads on its first look.
    writing.close(io);
    try testing.expectEqual(Console.Read.ended, console.read(io, &buffer, 1));
    // And it stays ended, so a broker that looks again does not start waiting.
    try testing.expectEqual(Console.Read.ended, console.read(io, &buffer, 1));
}

test "an answer longer than the buffer is a refusal, not a wait" {
    // A paste at the prompt, or a pipe with no newline in it at all. The two
    // words this reads are one and three letters long, so a line that fills the
    // buffer is not one of them. **Refusing is what ends the wait**: a waiter
    // that kept reading with no room left would poll to the deadline with a
    // full buffer and never look at it again.
    const gpa = testing.allocator;
    const io = testing.io;

    const filler = "x" ** max_answer_bytes;
    const lines = [_][]const u8{filler};
    var console = FakeConsole{
        .gpa = gpa,
        .replies = &.{.{ .bytes = 0 }},
        .lines = &lines,
    };
    defer console.deinit();

    var result = try drive(gpa, io, &console, neverStopped, Broker.default_timeout_ms);
    defer result.deinit();

    try testing.expectEqual(Broker.Outcome.refused_by_user, result.outcome.?);
    try testing.expect(!result.outcome.?.permits());
    try testing.expectEqual(@as(usize, 1), result.answers.len);
    try testing.expectEqual(Decision.refused_by_user, result.answers[0]);
    // One read and no more. The look after it found no room, answered, and
    // never went back to the console.
    try testing.expectEqual(@as(usize, 1), console.reads);
}
