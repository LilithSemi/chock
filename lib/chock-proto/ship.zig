//! Shipping a session log off the machine it was written on.
//!
//! **An audit trail that cannot leave the machine is not one.** The log is
//! already this project's record: every command folds it, a session replays
//! from it, and `chain.zig` makes an edit in the middle of it findable. This
//! file is the transport that carries those same bytes somewhere the person
//! who ran the session cannot reach.
//!
//! It is a **security control and not a convenience**. `chain.zig` says the
//! honest thing about what a hash chain defeats: whoever can rewrite the whole
//! file can write a chain that agrees with the new text. A copy that already
//! left the machine defeats that as well, because the copy that matters is no
//! longer somewhere the writer can edit. Export is what makes tampering futile
//! rather than only detectable.
//!
//! ## This is a transport, never a second source of truth
//!
//! `Loop.run` owns the log file and holds its exclusive lock for the whole
//! session. **Nothing here writes to a log, locks one, or appends an event.** A
//! `Shipper` reads a fold and pushes what it read at a `Sink`. That is the same
//! rule the approval socket keeps, which carries a question and an answer and
//! never a log write, and it is what let the mid session approval wall come
//! down without a second owner of the file.
//!
//! ## The bytes are shipped as they sit on disk
//!
//! **Never a re-encoding of the parsed event.** `chain.zig` holds a test with
//! reordered JSON keys proving that a verifier which encoded the envelope again
//! would call a sound log tampered: key order, the form of a number, and the
//! escape of one character all differ between two encoders and none of them
//! changes the meaning. So a record carries `Replay.line`, the exact bytes of
//! that line, and the header line goes first.
//!
//! A `FileDrop` therefore produces a file that is byte for byte the log, header
//! included, and `storage.verify` reads it at the far end with no special case
//! at all. That is what "verifiable at the far end" means here, and there is a
//! test that does exactly it.
//!
//! ## What an exported log proves, and what it does not
//!
//! `chain.not_a_signature` is the existing sentence and it is still the honest
//! one. An exported log proves that the bytes which arrived hold a chain that
//! agrees with itself. It does not prove who wrote them, and it does not prove
//! that the machine did not rewrite the whole file before the first line ever
//! left. **A signature over the chain head is a different piece of work and it
//! is not this one.**
//!
//! What export adds, and it is worth stating exactly: once a line has reached a
//! sink that the machine cannot write to, that line can no longer be edited on
//! the machine without the two copies disagreeing. The value is in the promptness,
//! which is the whole argument for shipping during a session rather than after it.
//!
//! ## Live, and not at the end
//!
//! **Decided: a line is shipped as the session appends it.**
//!
//! At the end is far simpler. It needs no cursor, no health record, and no
//! thought about a sink that is down while real work is going on. It is also
//! worth much less, for one reason: a session that ends badly is exactly the
//! session somebody wants the record of, and a session killed with `SIGKILL`
//! runs no deferred code at all. An export that only runs at the end ships
//! nothing for the runs that matter most. And every second between an event
//! being written and it leaving the machine is a second in which it can still
//! be edited with nothing to compare against.
//!
//! What live costs is bounded, and it is bounded because **both sinks this file
//! ships are local**. A `FileDrop` is a write to a file on the same machine and
//! a `Syslog` is a datagram to a unix socket the local daemon reads. Neither can
//! block on a network. That matters more here than it would elsewhere: `chock
//! run` is single threaded on the tool path, for the reason `src/main.zig`'s own
//! top comment gives, so a sink that blocked would block the session itself.
//!
//! **That is also why there is no OTLP sink here.** An HTTP exporter has to
//! queue and needs a thread of its own, and a thread is the one thing that path
//! may not have. It is a real piece of work and it is not this one.
//!
//! ## A sink that is down
//!
//! Two rules pull against each other and both matter:
//!
//! * **A session must not fail because an audit sink is down.** An observability
//!   feature that stops work is one an operator turns off.
//! * **An audit trail that silently stops arriving is worse than one that never
//!   started**, because a reader believes it is looking at the whole record.
//!
//! So the answer is three parts, and the first is the one that does the work:
//!
//! 1. **The log on disk is the queue.** `Shipper.cursor` advances only past a
//!    line the sink took. A sink that was down for a minute and comes back is
//!    given every line it missed, in order, from the file that still holds them.
//!    A transient outage therefore leaves **no gap at all**, rather than a gap
//!    somebody has to notice. This costs nothing: the log is already durable and
//!    already ordered, so there is no second buffer to size, flush, or lose.
//! 2. **The first failure is said at once**, and it is never a fatal error. See
//!    `Health.first_fault`. `send` returning an error stops the push and nothing
//!    else.
//! 3. **The end of a session says the whole state.** How many lines reached the
//!    sink, how many did not, the first fault by name, and the offset the
//!    shipping is stuck at. See `Health.format`, which is one sentence a caller
//!    prints, so the terminal and any other reader cannot drift apart.
//!
//! A fourth part falls out of shipping the bytes rather than a summary: the last
//! line of a session is its `session.end`, so **a far end that holds a session
//! with no `session.end` is looking at an incomplete record and can see that it
//! is.** No heartbeat protocol was needed for that.
//!
//! What is **not** built: nothing here tells the far end to expect a session
//! that never started, so a machine that was never able to reach the sink at all
//! is invisible at the sink. That needs the sink to hold a roster, which is a
//! hub feature and not a transport one.
//!
//! ## Why this file is not called `export`
//!
//! `export` is a keyword in Zig, so `pub const export = @import(...)` does not
//! compile. The command a person types is still `--export-dir`, and this is the
//! module behind it.

const std = @import("std");
const chain = @import("chain.zig");
const storage = @import("storage.zig");

/// What one attempt to hand a record to a sink came to.
///
/// **Two answers and not one, because a caller acts on them differently.** A
/// sink that could not be reached is retried, from the same cursor, when the
/// next event lands. A record the sink will not carry is never retried: a second
/// attempt would send the same bytes to the same sink and get the same answer,
/// and a shipper that retried it would stop for ever on one line.
pub const Delivery = union(enum) {
    /// The sink took it.
    delivered,
    /// The sink is there and this record cannot travel it. The text says why,
    /// and it is a literal of whichever sink refused, so it is borrowed and
    /// never freed.
    refused: []const u8,
};

/// What actually carries a record away from this machine.
///
/// **A seam, because the thing on the other side of it is not this program.**
/// The same shape `chock_nix.provision.Runner`, `approval.Console`,
/// `chock_provider.Client.Wire` and `chock_core.lsp.Server` already take, and
/// for the same reason: no test in this project may reach a real network or a
/// real syslog daemon, and a fake behind this seam is how a test drives every
/// path a real sink can take.
///
/// **The two sinks below are still measured against something real**, because a
/// protocol tested only against a stand-in is a mistake this project has already
/// paid for once. `FileDrop` is tested against a real file, and `Syslog` against
/// a real unix datagram socket the test itself binds in its own temporary
/// directory. Neither test needs a daemon.
pub const Sink = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Take one record.
        ///
        /// **An error means the sink could not be reached**, and the caller
        /// retries the same record later. A `Delivery.refused` means the sink is
        /// there and will not carry this one. See `Delivery`.
        ///
        /// The error set is open. A caller never branches on which fault it was:
        /// it keeps the first one by name, for a person to read, and every fault
        /// leads to the same place. Closing the set here would mean each sink
        /// translating a platform's own errors into a list this file guessed at.
        send: *const fn (ptr: *anyopaque, io: std.Io, record: Record) anyerror!Delivery,
        /// Make everything already taken as durable as this sink can make it.
        /// A datagram sink has nothing to do here and says so by doing nothing.
        flush: *const fn (ptr: *anyopaque, io: std.Io) anyerror!void,
        /// How far into the log this sink already holds, or null for a sink that
        /// cannot say.
        ///
        /// **This is what stops a continued session shipping its whole log
        /// again.** A `FileDrop` can answer exactly, because its file is byte
        /// for byte the log and so its own length *is* a log offset. A syslog
        /// daemon holds nothing anybody can read back, so it answers null and
        /// the shipper sends from the start. See `Shipper.resent_from_start`
        /// for why that direction is the right one.
        resumeAt: *const fn (ptr: *anyopaque, io: std.Io) anyerror!?u64,
        /// Whether this sink can be reached at all. **Nothing is sent.**
        ///
        /// An error means the same thing it means for `send`: the sink could
        /// not be reached. Returning without one means the transport is open
        /// and a record would travel it.
        ///
        /// **Not `resumeAt` under another name, and the two sinks below are
        /// why.** A `FileDrop.resumeAt` opens its file, so it really is a
        /// probe; a `Syslog.resumeAt` answers null with no socket at all,
        /// because a syslog daemon holds nothing this process can read back.
        /// So a caller that asked `resumeAt` and read the answer as reachable
        /// would call every syslog sink on every machine reachable, and one
        /// that wanted the truth had to send a record to learn it.
        ///
        /// **The caller this exists for is `chock doctor`**, which says
        /// before a session starts whether this machine can reach the sinks
        /// its installation requires. That command's own rule is that a second
        /// way to ask would be a second answer to keep true, so the probe
        /// lives here, beside the transport, rather than as a socket and a
        /// connect written out again somewhere else.
        ///
        /// A sink left open by this call stays open, and the next `send`
        /// takes it up. Closing is the caller's, exactly as it is after a
        /// `send`.
        reach: *const fn (ptr: *anyopaque, io: std.Io) anyerror!void,
    };

    pub fn send(self: Sink, io: std.Io, record: Record) anyerror!Delivery {
        return self.vtable.send(self.ptr, io, record);
    }

    pub fn flush(self: Sink, io: std.Io) anyerror!void {
        return self.vtable.flush(self.ptr, io);
    }

    pub fn resumeAt(self: Sink, io: std.Io) anyerror!?u64 {
        return self.vtable.resumeAt(self.ptr, io);
    }

    pub fn reach(self: Sink, io: std.Io) anyerror!void {
        return self.vtable.reach(self.ptr, io);
    }
};

/// One line of a log, on its way to a sink.
pub const Record = struct {
    /// The session the line belongs to. A sink that has to label a message uses
    /// this, and nothing here checks it.
    session: []const u8,
    /// Where the line starts in the log, which is the event's own identifier.
    /// Zero for the header line, which is the only line of a log that starts at
    /// zero.
    id: u64,
    /// **The bytes of the line exactly as they sit on disk**, without the
    /// newline that closes it. See this file's own top comment: a re-encoding
    /// would make a sound log read as tampered at the far end.
    line: []const u8,
    /// What kind of line this is. A sink that writes a copy of the log needs the
    /// header, and a sink that labels a message per event does not label the
    /// header differently. Kept so neither has to work it out from `id`.
    kind: Kind,

    pub const Kind = enum { header, event };
};

/// What shipping has come to for one session and one sink.
///
/// **A record and never a decision.** Nothing here stops a session. A caller
/// reads it, prints it, and carries on.
pub const Health = struct {
    /// How many lines the sink took, the header line included.
    delivered: u64 = 0,
    /// How many lines the sink was there for and would not carry.
    refused: u64 = 0,
    /// Why the first refusal was refused. A literal of whichever sink said it,
    /// so it is borrowed and never freed.
    first_refusal: ?[]const u8 = null,
    /// How many times the sink could not be reached at all.
    faults: u64 = 0,
    /// The first fault, kept and not the last. The same rule every diagnostic in
    /// this project keeps: a later fault can only happen because an earlier one
    /// did, so the first one is the one that explains the rest.
    first_fault: ?anyerror = null,
    /// The log offset nothing has been delivered from, or null when the shipper
    /// is caught up with everything the log holds.
    ///
    /// **This is the number that says whether the trail is still arriving.** A
    /// session that ends with this set has a tail nobody outside this machine
    /// holds, and it names exactly where the tail begins.
    stalled_at: ?u64 = null,
    /// True once a line was delivered after a fault. A sink that went away and
    /// came back leaves no gap, because the cursor never moved past what it
    /// missed, and this is what says so out loud rather than leaving a reader to
    /// work it out from two counts.
    recovered: bool = false,
    /// True when the sink could not say what it already holds **and this run
    /// took up a log an earlier run had already written**, so the whole of that
    /// log was sent from the start and the far end may hold some of it twice.
    ///
    /// **Duplicates, on purpose.** A duplicate at the far end is found by the
    /// event identifier and thrown away; a gap is found by nobody. So a sink
    /// that cannot say gets everything again, and this says that it did.
    ///
    /// **False for a session nobody continued**, which is every session a person
    /// starts fresh. Nothing can have been sent twice, so there is nothing to
    /// warn about, and a warning that fires on every run is one nobody reads by
    /// the second week. Measured on a real run before this was conditional: a
    /// fresh session with an unreachable syslog reported that its whole log had
    /// been sent again, and its log had never been sent at all. See
    /// `Shipper.continued`.
    resent_from_start: bool = false,

    /// Whether a person has to be told about this at all. False for the ordinary
    /// session, where every line went and nothing was refused.
    pub fn wantsSaying(self: Health) bool {
        return self.faults != 0 or self.refused != 0 or self.stalled_at != null or
            self.recovered or self.resent_from_start;
    }

    /// One sentence a caller prints. Held here, beside the counts, so the
    /// terminal and any other reader of a `Health` cannot drift apart.
    pub fn format(self: *const Health, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{d} lines of the session log reached the sink", .{self.delivered});
        if (self.refused != 0) {
            try writer.print(", {d} could not travel it ({s})", .{
                self.refused,
                self.first_refusal orelse "no reason given",
            });
        }
        if (self.faults != 0) {
            try writer.print(", and the sink could not be reached {d} {s} (first: {s})", .{
                self.faults,
                if (self.faults == 1) "time" else "times",
                @errorName(self.first_fault orelse error.Unexpected),
            });
        }
        if (self.stalled_at) |offset| {
            try writer.print(
                ". Nothing has been shipped from byte {d} of the log onward, so that tail is on this machine and nowhere else",
                .{offset},
            );
        } else if (self.recovered) {
            try writer.print(
                ". The sink came back and was given everything it missed, so there is no gap",
                .{},
            );
        }
        if (self.resent_from_start) {
            try writer.print(
                ". This sink cannot say what it already holds, so the whole log was sent again rather than risking a gap",
                .{},
            );
        }
        try writer.print(".", .{});
    }
};

/// Reads a log forward and pushes every complete line it finds at a `Sink`.
///
/// **It never writes, locks, or appends.** See this file's own top comment.
///
/// One shipper is one session and one sink. Call `push` whenever the log may
/// have grown, and `finish` once when the session is over.
pub const Shipper = struct {
    sink: Sink,
    /// The session these records belong to. Borrowed for the shipper's life.
    session: []const u8,
    /// The offset of the first line that has not been delivered. Zero until the
    /// header has gone, and then the start of the first event that has not.
    cursor: u64 = 0,
    /// Whether the header line has been delivered. The header is not an event
    /// and no replay yields it, so it is shipped on its own, once, before
    /// anything else. Without it the far end has nothing to anchor the chain to.
    sent_header: bool = false,
    /// Whether this run took up a log an earlier run had already written.
    ///
    /// **The caller knows and the shipper cannot.** `chock run --continue` and
    /// `--adopt` carry on a session another run wrote, and a sink that cannot
    /// say what it holds is then given lines it may already have. A session
    /// nobody continued has nothing that can arrive twice. Nothing else in this
    /// file reads it: see `Health.resent_from_start`.
    continued: bool = false,
    /// Whether `start` has run. `push` runs it, so a caller that never calls
    /// `start` still gets a shipper that resumes correctly.
    started: bool = false,
    health: Health = .{},

    /// Ask the sink how far it already is and take up from there.
    ///
    /// Called by `push` on its first run, so a caller does not have to. Its own
    /// function because a caller that wants the answer before the first event
    /// lands, which is every caller that prints something at the start of a
    /// session, can ask for it.
    pub fn start(self: *Shipper, io: std.Io) void {
        if (self.started) return;
        self.started = true;
        const held = self.sink.resumeAt(io) catch |err| {
            // The sink could not be asked. Treated exactly as a sink that cannot
            // say: send everything. An absent answer must never read as "it has
            // it all already", which is the one reading that produces a silent
            // gap.
            self.note(err, 0);
            self.health.resent_from_start = self.continued;
            return;
        } orelse {
            // **Only said when this run took up somebody else's log.** See
            // `Health.resent_from_start`: a fresh session sends nothing twice.
            self.health.resent_from_start = self.continued;
            return;
        };
        if (held == 0) return;
        // The sink holds the header and every line up to `held`, because its own
        // copy is byte for byte the log. See `Sink.VTable.resumeAt`.
        self.sent_header = true;
        self.cursor = held;
    }

    /// Ship every complete line of `store` that has not gone yet.
    ///
    /// **Returns nothing and can fail at nothing.** An observer watches and
    /// never decides, and an audit sink must not be a second place a session can
    /// be stopped. Everything that went wrong is in `health`.
    ///
    /// Safe to call as often as a caller likes, including on a log that has not
    /// grown: the cursor makes a call with nothing new a single failed replay
    /// and no send at all.
    pub fn push(self: *Shipper, gpa: std.mem.Allocator, io: std.Io, store: storage.Storage) void {
        self.start(io);

        if (!self.sent_header) {
            var buffer: [storage.max_header_bytes]u8 = undefined;
            const header = store.headerLine(io, &buffer) catch |err| {
                self.note(err, 0);
                return;
            };
            switch (self.deliver(io, .{
                .session = self.session,
                .id = 0,
                .line = header,
                .kind = .header,
            }, 0)) {
                .stop => return,
                .carry_on => self.sent_header = true,
            }
        }

        var replay = store.replay(gpa, io, self.cursor) catch |err| switch (err) {
            // The cursor sits at the end of the file. **Not a fault**: this is
            // what a shipper that is caught up looks like, and the cursor only
            // ever comes from a replay position on this same log, so no other
            // reading of this error is possible here.
            error.OffsetOutOfRange => return,
            else => {
                self.note(err, self.cursor);
                return;
            },
        };
        defer replay.deinit();

        while (true) {
            // Read before the call, never after, for the reason
            // `storage.verify` gives: a `next` that could not parse has already
            // stepped past the line it choked on, and a `next` that found a torn
            // fragment puts the position back at that fragment's start. Only the
            // value taken beforehand names the line this iteration is about.
            const at = replay.at();
            const parsed = replay.next(io) catch |err| {
                // A line this build cannot decode. The shipper cannot go past it
                // without shipping bytes it never read, so it stops here and
                // says where. `chain.Verdict.undecodable` is the same fact read
                // by the verifier.
                self.note(err, at);
                return;
            } orelse {
                // The end of what the log holds. A torn fragment ends a replay
                // the same way, and it is right that nothing ships it: a
                // fragment is a write that was never durable, so there is
                // nothing at the far end to be missing.
                self.health.stalled_at = null;
                return;
            };
            defer parsed.deinit();

            switch (self.deliver(io, .{
                .session = self.session,
                .id = parsed.value.id,
                .line = replay.line(),
                .kind = .event,
            }, at)) {
                .stop => return,
                .carry_on => self.cursor = replay.at(),
            }
        }
    }

    /// Ship whatever is left and make the sink durable. Call once, when the
    /// session is over.
    ///
    /// **The last push matters more than any other**, because the line it
    /// carries is the `session.end`, and that is what tells a reader at the far
    /// end that this session is a whole record rather than one that stopped.
    pub fn finish(self: *Shipper, gpa: std.mem.Allocator, io: std.Io, store: storage.Storage) void {
        self.push(gpa, io, store);
        self.sink.flush(io) catch |err| self.note(err, self.cursor);
    }

    /// What one `deliver` decided the loop should do next.
    const Step = enum { carry_on, stop };

    /// Hand one record over and fold the answer into `health`. `at` is the log
    /// offset the record starts at, which is what a stall is reported against.
    fn deliver(self: *Shipper, io: std.Io, record: Record, at: u64) Step {
        const answer = self.sink.send(io, record) catch |err| {
            self.note(err, at);
            return .stop;
        };
        switch (answer) {
            .delivered => {
                self.health.delivered += 1;
                if (self.health.faults != 0) self.health.recovered = true;
            },
            .refused => |why| {
                self.health.refused += 1;
                if (self.health.first_refusal == null) self.health.first_refusal = why;
            },
        }
        // A refused record is counted and stepped over: retrying it would send
        // the same bytes to the same sink for ever. See `Delivery`.
        self.health.stalled_at = null;
        return .carry_on;
    }

    /// Keep one fault. The first is kept and not the last, the same rule every
    /// diagnostic in this project keeps.
    fn note(self: *Shipper, err: anyerror, at: u64) void {
        self.health.faults += 1;
        if (self.health.first_fault == null) self.health.first_fault = err;
        self.health.stalled_at = at;
    }
};

/// A sink that appends the log's own bytes to a file.
///
/// **The result is byte for byte the log**, header line and all, so
/// `storage.verify` reads it at the far end with no special case. That is the
/// whole design: a collector that watches a directory gets files it can verify
/// with the code that wrote them.
///
/// The caller names the file. One file per session, in a directory a collector
/// reads, is what `src/run.zig` builds.
///
/// **Written positionally, from a length this sink keeps.** A write that lands
/// only in part leaves a fragment, and the next attempt writes the same bytes at
/// the same offsets and covers it, because the shipper's cursor did not move.
/// An appending write could not do that: it would put the fragment and then the
/// whole line one after the other, and the far end would read a broken chain
/// where nothing was ever tampered with.
pub const FileDrop = struct {
    /// Where the copy goes. Borrowed for this sink's life.
    path: []const u8,
    /// The open file, or null before the first record.
    file: ?std.Io.File = null,
    /// How many bytes of `path` this sink has written. Seeded from the file's
    /// own length when it opens, which is what makes a continued session take up
    /// where the last one stopped.
    written: u64 = 0,

    pub fn sink(self: *FileDrop) Sink {
        return .{ .ptr = self, .vtable = &file_drop_vtable };
    }

    /// Close the file, if one is open. Safe more than once.
    pub fn close(self: *FileDrop, io: std.Io) void {
        const file = self.file orelse return;
        self.file = null;
        file.close(io);
    }

    fn openIfNeeded(self: *FileDrop, io: std.Io) !std.Io.File {
        if (self.file) |file| return file;
        // `truncate` off: a drop file that already holds part of this session is
        // taken up rather than thrown away, which is what makes `--continue`
        // ship only what it adds.
        const file = try std.Io.Dir.cwd().createFile(io, self.path, .{ .truncate = false });
        errdefer file.close(io);
        self.written = try file.length(io);
        self.file = file;
        return file;
    }

    fn sendFn(ptr: *anyopaque, io: std.Io, record: Record) anyerror!Delivery {
        const self: *FileDrop = @ptrCast(@alignCast(ptr));
        const file = try self.openIfNeeded(io);
        try file.writePositionalAll(io, record.line, self.written);
        try file.writePositionalAll(io, "\n", self.written + record.line.len);
        self.written += record.line.len + 1;
        return .delivered;
    }

    fn flushFn(ptr: *anyopaque, io: std.Io) anyerror!void {
        const self: *FileDrop = @ptrCast(@alignCast(ptr));
        const file = self.file orelse return;
        try file.sync(io);
    }

    fn resumeAtFn(ptr: *anyopaque, io: std.Io) anyerror!?u64 {
        const self: *FileDrop = @ptrCast(@alignCast(ptr));
        _ = try self.openIfNeeded(io);
        // The file is byte for byte the log, so its own length is a log offset.
        return self.written;
    }

    /// **Opening the file is the whole probe.** A drop that can be created and
    /// whose length can be read is one a record travels, and nothing else this
    /// sink does can fail on a machine where that worked. The file is left
    /// open, and the first `send` takes it up.
    fn reachFn(ptr: *anyopaque, io: std.Io) anyerror!void {
        const self: *FileDrop = @ptrCast(@alignCast(ptr));
        _ = try self.openIfNeeded(io);
    }
};

const file_drop_vtable = Sink.VTable{
    .send = FileDrop.sendFn,
    .flush = FileDrop.flushFn,
    .resumeAt = FileDrop.resumeAtFn,
    .reach = FileDrop.reachFn,
};

/// The facility a Chock audit record is sent under: `authpriv`, which is 10.
///
/// **Not `local0` and not `daemon`.** An organisation that installs this wants
/// the record beside its other authorisation records, and `authpriv` is the
/// facility whose whole purpose is a record about who was allowed to do what.
/// A site that wants it elsewhere changes it at the daemon, which is where a
/// site's own routing belongs.
pub const syslog_facility: u8 = 10;

/// The severity every record is sent at: `notice`, which is 5.
///
/// One severity for every record, on purpose. A session log line is a fact and
/// not an alarm, and a transport that read the event and picked a severity would
/// be a second reader of the log making its own judgement about it.
pub const syslog_severity: u8 = 5;

/// The `PRI` value at the front of every message this sink writes.
pub const syslog_priority: u8 = syslog_facility * 8 + syslog_severity;

/// The application name in every message. RFC 5424 bounds it at 48 characters.
pub const syslog_app_name = "chock";

/// A sink that writes one RFC 5424 message per log line to a unix datagram
/// socket: `/dev/log` on Linux, `/var/run/syslog` on Darwin.
///
/// ## What this sink does not preserve
///
/// **A syslog message is not a copy of the log, and a collector cannot verify
/// the chain from these alone unless it reassembles them exactly.** Each message
/// carries one whole log line, so nothing is truncated by this sink, but the
/// framing around it is not the log's framing, and a daemon is free to rewrite,
/// reorder, or drop a datagram. Use `FileDrop` for a copy that verifies; use
/// this for a trail that reaches an existing collector on the day it is turned
/// on. `src/run.zig` allows both at once.
///
/// A line too large for one datagram is **refused rather than truncated**, and
/// the kernel is what says so: `EMSGSIZE` becomes `Delivery.refused`. A
/// truncated line in an audit trail reads as a line that was tampered with, so
/// sending half of one would be worse than recording that it did not fit.
///
/// ## The timestamp is `NILVALUE`, on purpose
///
/// Every message carries `-` where RFC 5424 puts the time, so the receiver
/// stamps its own. Nothing is lost: the log line inside the message already
/// carries the event's own `time_ms`, written by the session. And the receiver's
/// clock is the one an auditor should trust, because it is not the clock on the
/// machine under audit. The same reasoning makes `HOSTNAME` and `PROCID` nil.
///
/// `MSGID` is the session identifier. RFC 5424 bounds `MSGID` at 32 characters
/// and a session identifier is a 26 character ULID, so it fits with room to
/// spare, and it is the one label a collector needs to gather a session up.
pub const Syslog = struct {
    /// The socket to write to. Borrowed for this sink's life.
    path: []const u8,
    /// The connected datagram socket, or null before the first record.
    handle: ?std.posix.fd_t = null,

    /// Where a Linux machine's syslog socket is.
    pub const linux_path = "/dev/log";
    /// Where a Darwin machine's syslog socket is.
    pub const darwin_path = "/var/run/syslog";

    /// The usual socket for this platform. A caller may still name another.
    pub fn defaultPath() []const u8 {
        return switch (@import("builtin").os.tag) {
            .macos, .ios, .tvos, .watchos, .visionos => darwin_path,
            else => linux_path,
        };
    }

    pub const Error = error{
        /// A socket could not be made at all.
        SyslogSocketRefused,
        /// The path is longer than a unix socket address holds.
        SyslogPathTooLong,
        /// Nothing is listening on that path, or this process may not reach it.
        SyslogUnreachable,
        /// The write to the socket failed for a reason that is not a message
        /// too large for one datagram.
        SyslogWriteFailed,
    };

    pub fn sink(self: *Syslog) Sink {
        return .{ .ptr = self, .vtable = &syslog_vtable };
    }

    /// Close the socket, if one is open. Safe more than once.
    pub fn close(self: *Syslog) void {
        const handle = self.handle orelse return;
        self.handle = null;
        _ = std.posix.system.close(handle);
    }

    fn connectIfNeeded(self: *Syslog) Error!std.posix.fd_t {
        if (self.handle) |handle| return handle;

        var address: std.posix.sockaddr.un = .{ .path = @splat(0) };
        if (self.path.len >= address.path.len) return error.SyslogPathTooLong;
        @memcpy(address.path[0..self.path.len], self.path);

        // A datagram socket, because that is what `/dev/log` and
        // `/var/run/syslog` are. `std.Io.net.UnixAddress` connects a stream and
        // has no datagram mode, so this is one of the few places in Chock that
        // steps down to `std.posix.system`. The same step `lib/chock-proto/log.zig`
        // takes for `O_APPEND`, and for the same reason: the portable surface
        // has no way to ask.
        const made = std.posix.system.socket(std.posix.AF.UNIX, std.posix.SOCK.DGRAM, 0);
        if (std.posix.errno(made) != .SUCCESS) return error.SyslogSocketRefused;
        const handle: std.posix.fd_t = @intCast(made);
        errdefer _ = std.posix.system.close(handle);

        const joined = std.posix.system.connect(
            handle,
            @ptrCast(&address),
            @intCast(@sizeOf(std.posix.sockaddr.un)),
        );
        if (std.posix.errno(joined) != .SUCCESS) return error.SyslogUnreachable;

        self.handle = handle;
        return handle;
    }

    /// The RFC 5424 message for `record`, into `out`. Its own function so a test
    /// reads exactly the bytes the socket would carry, with no socket at all.
    pub fn frame(
        gpa: std.mem.Allocator,
        record: Record,
    ) std.mem.Allocator.Error![]u8 {
        return std.fmt.allocPrint(gpa, "<{d}>1 - - {s} - {s} - {s}", .{
            syslog_priority,
            syslog_app_name,
            if (record.session.len == 0) "-" else record.session,
            record.line,
        });
    }

    fn sendFn(ptr: *anyopaque, io: std.Io, record: Record) anyerror!Delivery {
        _ = io;
        const self: *Syslog = @ptrCast(@alignCast(ptr));
        const handle = try self.connectIfNeeded();

        // Built on the stack for the common line and on the heap for a long one.
        // A sink that allocated for every record would allocate on the tool path
        // of a single threaded session, once per event.
        var stack: [2048]u8 = undefined;
        var fixed: std.heap.FixedBufferAllocator = .init(&stack);
        var heap: ?[]u8 = null;
        defer if (heap) |bytes| std.heap.page_allocator.free(bytes);

        const message = frame(fixed.allocator(), record) catch built: {
            const bytes = try frame(std.heap.page_allocator, record);
            heap = bytes;
            break :built bytes;
        };

        const rc = std.posix.system.write(handle, message.ptr, message.len);
        const written: isize = @bitCast(@as(usize, @bitCast(rc)));
        if (written >= 0 and @as(usize, @intCast(written)) == message.len) return .delivered;
        return switch (std.posix.errno(rc)) {
            // One line larger than a datagram. The kernel refused it whole
            // rather than cutting it, which is the answer this sink wants: see
            // this type's own doc comment.
            .MSGSIZE => .{ .refused = "the line is larger than one syslog datagram" },
            // A short write on a datagram socket is not a thing the kernel does:
            // a datagram goes whole or not at all. Reported as a fault so a
            // reader is never told a line went when part of it did.
            .SUCCESS => error.SyslogWriteFailed,
            else => error.SyslogWriteFailed,
        };
    }

    fn flushFn(ptr: *anyopaque, io: std.Io) anyerror!void {
        _ = ptr;
        _ = io;
        // A datagram has left the machine by the time `write` returns. There is
        // nothing here to make durable, and saying so is better than an empty
        // function nobody can explain.
    }

    fn resumeAtFn(ptr: *anyopaque, io: std.Io) anyerror!?u64 {
        _ = ptr;
        _ = io;
        // A syslog daemon holds nothing this process can read back. See
        // `Sink.VTable.resumeAt` and `Health.resent_from_start`.
        return null;
    }

    /// Make the socket and connect it, **and write not one byte**.
    ///
    /// A connect on a unix datagram socket is a real answer: the kernel gives
    /// `ENOENT` for a path with nothing at it and `EACCES` for a socket this
    /// process may not reach, which are the two ways a syslog sink is down.
    /// So a message never has to be sent to learn it, and no record of a probe
    /// lands in an organisation's audit trail.
    ///
    /// The socket is left connected, and the first `send` takes it up.
    fn reachFn(ptr: *anyopaque, io: std.Io) anyerror!void {
        _ = io;
        const self: *Syslog = @ptrCast(@alignCast(ptr));
        _ = try self.connectIfNeeded();
    }
};

const syslog_vtable = Sink.VTable{
    .send = Syslog.sendFn,
    .flush = Syslog.flushFn,
    .resumeAt = Syslog.resumeAtFn,
    .reach = Syslog.reachFn,
};

const testing = std.testing;
const event = @import("event.zig");

/// A sink a test drives: it keeps every record and answers whatever the test
/// told it to answer next.
const FakeSink = struct {
    gpa: std.mem.Allocator,
    lines: std.ArrayList([]u8) = .empty,
    ids: std.ArrayList(u64) = .empty,
    flushes: usize = 0,
    /// What the next `send` answers. Reset by nothing: a test sets it, and sets
    /// it back.
    answer: Answer = .deliver,
    /// What `resumeAt` answers.
    holds: ?u64 = 0,
    /// How many sends have been attempted, refused and failed ones included.
    attempts: usize = 0,
    /// What `reach` answers: null for a sink that is there.
    reachable: ?anyerror = null,
    /// How many times this sink was reached for.
    reaches: usize = 0,

    const Answer = union(enum) {
        deliver,
        refuse: []const u8,
        fail: anyerror,
    };

    fn deinit(self: *FakeSink) void {
        for (self.lines.items) |one| self.gpa.free(one);
        self.lines.deinit(self.gpa);
        self.ids.deinit(self.gpa);
    }

    fn sink(self: *FakeSink) Sink {
        return .{ .ptr = self, .vtable = &fake_vtable };
    }

    /// Every line this sink took, joined the way a log file holds them.
    fn joined(self: *FakeSink) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.gpa);
        for (self.lines.items) |one| {
            try out.appendSlice(self.gpa, one);
            try out.append(self.gpa, '\n');
        }
        return out.toOwnedSlice(self.gpa);
    }

    fn sendFn(ptr: *anyopaque, io: std.Io, record: Record) anyerror!Delivery {
        _ = io;
        const self: *FakeSink = @ptrCast(@alignCast(ptr));
        self.attempts += 1;
        switch (self.answer) {
            .fail => |err| return err,
            .refuse => |why| return .{ .refused = why },
            .deliver => {},
        }
        try self.lines.append(self.gpa, try self.gpa.dupe(u8, record.line));
        try self.ids.append(self.gpa, record.id);
        return .delivered;
    }

    fn flushFn(ptr: *anyopaque, io: std.Io) anyerror!void {
        _ = io;
        const self: *FakeSink = @ptrCast(@alignCast(ptr));
        self.flushes += 1;
    }

    fn resumeAtFn(ptr: *anyopaque, io: std.Io) anyerror!?u64 {
        _ = io;
        const self: *FakeSink = @ptrCast(@alignCast(ptr));
        return self.holds;
    }

    fn reachFn(ptr: *anyopaque, io: std.Io) anyerror!void {
        _ = io;
        const self: *FakeSink = @ptrCast(@alignCast(ptr));
        self.reaches += 1;
        if (self.reachable) |err| return err;
    }

    const fake_vtable = Sink.VTable{
        .send = FakeSink.sendFn,
        .flush = FakeSink.flushFn,
        .resumeAt = FakeSink.resumeAtFn,
        .reach = FakeSink.reachFn,
    };
};

/// A message event with `text` in it, so a test writes one line of a log.
///
/// **`text` is comptime, and that is not a nicety.** A runtime slice here makes
/// `&.{ .{ .text = text } }` a pointer to a value on this function's own frame,
/// which is gone by the time a caller appends it. A comptime one is promoted to
/// a constant that lives as long as the program.
fn say(comptime text: []const u8) event.Event {
    return .{ .message = .{ .role = .assistant, .content = &.{.{ .text = text }} } };
}

/// A log on disk under a per test temporary directory, and the storage over it.
const TestLog = struct {
    tmp: std.testing.TmpDir,
    backing: *storage.JsonLines,
    store: storage.Storage,
    path: [:0]u8,
    gpa: std.mem.Allocator,

    fn open(gpa: std.mem.Allocator, io: std.Io, name: []const u8) !TestLog {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const dir_path = try @import("log.zig").absoluteDirPath(io, &buffer, tmp.dir);
        const path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ dir_path, name }, 0);
        errdefer gpa.free(path);

        const backing = try gpa.create(storage.JsonLines);
        errdefer gpa.destroy(backing);
        backing.* = .{ .log = try @import("log.zig").Log.open(io, path, "01TESTSESSION") };

        return .{
            .tmp = tmp,
            .backing = backing,
            .store = backing.storage(),
            .path = path,
            .gpa = gpa,
        };
    }

    fn deinit(self: *TestLog, io: std.Io) void {
        self.store.close(io);
        self.gpa.destroy(self.backing);
        self.gpa.free(self.path);
        self.tmp.cleanup();
    }

    /// Append one event and give back its identifier.
    fn append(self: *TestLog, io: std.Io, ev: event.Event, time_ms: i64) !u64 {
        var locked = try self.store.lock(io);
        defer locked.unlock(io) catch {};
        return locked.append(self.gpa, io, ev, time_ms);
    }
};

test "a log that was shipped verifies at the far end, with its chain intact" {
    // **The test this whole file exists for.** The bytes that arrive are the
    // bytes on disk, so the far end runs the same `storage.verify` the writer
    // would, over a file it never wrote, and the chain holds.
    //
    // Mutation check: make `Record.line` a fresh encoding of the parsed envelope
    // and this fails with `broken`, which is exactly the failure `chain.zig`'s
    // reordered key test predicts.
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "shipped-source");
    defer source.deinit(io);

    _ = try source.append(io, say("first"), 1000);
    _ = try source.append(io, say("second"), 2000);
    _ = try source.append(io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 3000);

    // The far end: a directory that holds a copy, and nothing else.
    var far = std.testing.tmpDir(.{});
    defer far.cleanup();
    var far_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const far_dir = try @import("log.zig").absoluteDirPath(io, &far_buffer, far.dir);
    const drop_path = try std.fmt.allocPrintSentinel(gpa, "{s}/copy.jsonl", .{far_dir}, 0);
    defer gpa.free(drop_path);

    var drop = FileDrop{ .path = drop_path };
    defer drop.close(io);
    var shipper = Shipper{ .sink = drop.sink(), .session = "01TESTSESSION" };
    shipper.finish(gpa, io, source.store);

    try testing.expectEqual(@as(u64, 0), shipper.health.faults);
    try testing.expectEqual(@as(u64, 0), shipper.health.refused);
    // Three events and the header line.
    try testing.expectEqual(@as(u64, 4), shipper.health.delivered);
    try testing.expectEqual(@as(?u64, null), shipper.health.stalled_at);

    // The copy is byte for byte the original. Anything less than this and the
    // chain check below would be checking a different file's chain.
    const original = try std.Io.Dir.cwd().readFileAlloc(io, source.path, gpa, .limited(1 << 20));
    defer gpa.free(original);
    const copy = try std.Io.Dir.cwd().readFileAlloc(io, drop_path, gpa, .limited(1 << 20));
    defer gpa.free(copy);
    try testing.expectEqualStrings(original, copy);

    // And the far end verifies it with the very code the writer uses, over a
    // log it opened for itself.
    var arrived = storage.JsonLines{ .log = try @import("log.zig").Log.open(io, drop_path, "01TESTSESSION") };
    const arrived_store = arrived.storage();
    defer arrived_store.close(io);

    const report = try storage.verify(arrived_store, gpa, io);
    try testing.expectEqual(chain.Verdict.intact, report.verdict);
    try testing.expectEqual(@as(u64, 3), report.events);
    try testing.expectEqual(@as(u64, 3), report.chained);
    try testing.expect(!report.edited());
}

test "an edit made after a log was shipped disagrees with the copy that left" {
    // The property export adds over the chain alone. A rewrite of the whole file
    // on this machine passes its own chain check, which `chain.zig` says plainly.
    // It cannot pass a comparison against a copy that is no longer here.
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "shipped-then-edited");
    defer source.deinit(io);
    _ = try source.append(io, say("what really happened"), 1000);

    var sink = FakeSink{ .gpa = gpa };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };
    shipper.finish(gpa, io, source.store);

    const shipped = try sink.joined();
    defer gpa.free(shipped);
    try testing.expect(std.mem.indexOf(u8, shipped, "what really happened") != null);

    // Somebody rewrites the file whole and rebuilds the chain over the new text.
    // Read `original` first: the rewrite has to keep the header, which is what
    // the first event's `prev` is anchored to.
    const original = try std.Io.Dir.cwd().readFileAlloc(io, source.path, gpa, .limited(1 << 20));
    defer gpa.free(original);
    const header_end = std.mem.indexOfScalar(u8, original, '\n').? + 1;
    const header = original[0 .. header_end - 1];

    var rewritten: std.ArrayList(u8) = .empty;
    defer rewritten.deinit(gpa);
    try rewritten.appendSlice(gpa, original[0..header_end]);
    try rewritten.print(
        gpa,
        "{{\"id\":0,\"time_ms\":1000,\"session\":\"01TESTSESSION\",\"prev\":\"{s}\"," ++
            "\"event\":{{\"message\":{{\"role\":\"assistant\",\"content\":[]}}}}}}\n",
        .{&chain.of(header)},
    );
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = source.path, .data = rewritten.items });

    // The rewrite passes its own chain check. This is the limit of a chain, and
    // it is why a copy that already left matters.
    var rewritten_log = storage.JsonLines{
        .log = try @import("log.zig").Log.open(io, source.path, "01TESTSESSION"),
    };
    const rewritten_store = rewritten_log.storage();
    defer rewritten_store.close(io);
    const report = try storage.verify(rewritten_store, gpa, io);
    try testing.expectEqual(chain.Verdict.intact, report.verdict);

    // And the copy that left says what the file no longer does.
    const now = try std.Io.Dir.cwd().readFileAlloc(io, source.path, gpa, .limited(1 << 20));
    defer gpa.free(now);
    try testing.expect(std.mem.indexOf(u8, now, "what really happened") == null);
    try testing.expect(!std.mem.eql(u8, shipped, now));
}

test "a sink that is down fails nothing, keeps the cursor, and backfills when it returns" {
    // The two rules that pull against each other, in one test. A session must
    // not fail because a sink is down, and a trail that stops arriving must not
    // do it quietly.
    //
    // Mutation check: advance the cursor on a failed send and the backfill below
    // loses the two lines the sink missed, which is the silent gap this shape
    // exists to prevent.
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "sink-that-is-down");
    defer source.deinit(io);

    var sink = FakeSink{ .gpa = gpa };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };

    // The header and one event go while the sink is up.
    _ = try source.append(io, say("before the outage"), 1000);
    shipper.push(gpa, io, source.store);
    try testing.expectEqual(@as(u64, 2), shipper.health.delivered);
    try testing.expect(!shipper.health.wantsSaying());

    // The sink goes away. Two events land while it is gone.
    sink.answer = .{ .fail = error.ConnectionRefused };
    _ = try source.append(io, say("during the outage"), 2000);
    shipper.push(gpa, io, source.store);
    _ = try source.append(io, say("still during"), 3000);
    shipper.push(gpa, io, source.store);

    // Nothing failed: `push` returns nothing and can fail at nothing. And
    // nothing is quiet about it either.
    try testing.expectEqual(@as(u64, 2), shipper.health.delivered);
    try testing.expect(shipper.health.faults >= 2);
    try testing.expectEqual(@as(?anyerror, error.ConnectionRefused), shipper.health.first_fault);
    try testing.expect(shipper.health.stalled_at != null);
    try testing.expect(shipper.health.wantsSaying());
    // The sentence a person reads names the offset the tail begins at.
    const said = try std.fmt.allocPrint(gpa, "{f}", .{&shipper.health});
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "could not be reached") != null);
    try testing.expect(std.mem.indexOf(u8, said, "on this machine and nowhere else") != null);

    // The sink comes back. Everything it missed is given to it, in order, from
    // the log that still holds it. **No gap.**
    sink.answer = .deliver;
    shipper.finish(gpa, io, source.store);

    try testing.expectEqual(@as(u64, 4), shipper.health.delivered);
    try testing.expectEqual(@as(?u64, null), shipper.health.stalled_at);
    try testing.expect(shipper.health.recovered);

    const shipped = try sink.joined();
    defer gpa.free(shipped);
    try testing.expect(std.mem.indexOf(u8, shipped, "before the outage") != null);
    try testing.expect(std.mem.indexOf(u8, shipped, "during the outage") != null);
    try testing.expect(std.mem.indexOf(u8, shipped, "still during") != null);

    // The recovered sentence replaces the stalled one, so a reader is not told a
    // tail is missing that has since arrived.
    const after = try std.fmt.allocPrint(gpa, "{f}", .{&shipper.health});
    defer gpa.free(after);
    try testing.expect(std.mem.indexOf(u8, after, "there is no gap") != null);
    try testing.expect(std.mem.indexOf(u8, after, "on this machine and nowhere else") == null);
}

test "a record the sink will not carry is counted and stepped over, never retried for ever" {
    // The other half of `Delivery`. A line one sink cannot take must not stop
    // every line after it, and it must not be quiet either.
    //
    // Mutation check: treat a refusal like a fault and the shipper never gets
    // past the first refused line, so the two events after it never ship.
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "refused-record");
    defer source.deinit(io);
    _ = try source.append(io, say("one"), 1000);
    _ = try source.append(io, say("two"), 2000);

    var sink = FakeSink{ .gpa = gpa, .answer = .{ .refuse = "too large for one datagram" } };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };
    shipper.push(gpa, io, source.store);

    // The header and both events were each tried exactly once.
    try testing.expectEqual(@as(usize, 3), sink.attempts);
    try testing.expectEqual(@as(u64, 3), shipper.health.refused);
    try testing.expectEqual(@as(u64, 0), shipper.health.faults);
    try testing.expectEqualStrings("too large for one datagram", shipper.health.first_refusal.?);
    try testing.expect(shipper.health.wantsSaying());

    // And the shipper is at the end of the log, so the next event ships.
    sink.answer = .deliver;
    _ = try source.append(io, say("three"), 3000);
    shipper.push(gpa, io, source.store);
    try testing.expectEqual(@as(u64, 1), shipper.health.delivered);
    const shipped = try sink.joined();
    defer gpa.free(shipped);
    try testing.expect(std.mem.indexOf(u8, shipped, "three") != null);
}

test "the header line goes first, and it hashes to the digest the chain is anchored to" {
    // Without the header the far end has nothing to anchor the chain to, and
    // `chain.Verifier.init` would have to be seeded with a digest that travelled
    // some other way. The invariant is that the line and the digest the same
    // interface gives up agree.
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "header-first");
    defer source.deinit(io);
    _ = try source.append(io, say("an event"), 1000);

    var sink = FakeSink{ .gpa = gpa };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };
    shipper.push(gpa, io, source.store);

    try testing.expectEqual(@as(usize, 2), sink.lines.items.len);
    // The header is the first record, and its identifier is zero, which is the
    // one offset no event can ever have.
    try testing.expectEqual(@as(u64, 0), sink.ids.items[0]);
    try testing.expect(sink.ids.items[1] != 0);

    var buffer: [storage.max_header_bytes]u8 = undefined;
    const header = try source.store.headerLine(io, &buffer);
    try testing.expectEqualStrings(header, sink.lines.items[0]);
    // The line and the digest the same interface gives up agree, so a far end
    // that hashes the line it received arrives at the anchor the writer used.
    const anchored = try source.store.verifier(io);
    try testing.expectEqualStrings(&chain.of(header), &anchored.expected);
}

test "a sink that already holds part of the log is not sent it again" {
    // A continued session. The drop file's own length is a log offset, because
    // the copy is byte for byte the log, so the second run ships only what it
    // adds.
    //
    // Mutation check: answer 0 from `resumeAt` and the copy holds the first
    // event twice, which breaks the chain at the far end.
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "continued-session");
    defer source.deinit(io);
    _ = try source.append(io, say("first run"), 1000);

    var far = std.testing.tmpDir(.{});
    defer far.cleanup();
    var far_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const far_dir = try @import("log.zig").absoluteDirPath(io, &far_buffer, far.dir);
    const drop_path = try std.fmt.allocPrintSentinel(gpa, "{s}/continued.jsonl", .{far_dir}, 0);
    defer gpa.free(drop_path);

    {
        var drop = FileDrop{ .path = drop_path };
        defer drop.close(io);
        var first = Shipper{ .sink = drop.sink(), .session = "01TESTSESSION" };
        first.finish(gpa, io, source.store);
        try testing.expectEqual(@as(u64, 2), first.health.delivered);
        try testing.expect(!first.health.resent_from_start);
    }

    _ = try source.append(io, say("second run"), 2000);

    {
        var drop = FileDrop{ .path = drop_path };
        defer drop.close(io);
        var second = Shipper{ .sink = drop.sink(), .session = "01TESTSESSION" };
        second.finish(gpa, io, source.store);
        // One line, not three: the header and the first event were already there.
        try testing.expectEqual(@as(u64, 1), second.health.delivered);
    }

    const original = try std.Io.Dir.cwd().readFileAlloc(io, source.path, gpa, .limited(1 << 20));
    defer gpa.free(original);
    const copy = try std.Io.Dir.cwd().readFileAlloc(io, drop_path, gpa, .limited(1 << 20));
    defer gpa.free(copy);
    try testing.expectEqualStrings(original, copy);
}

test "a continued session is sent to a forgetful sink again, and a fresh one is not" {
    // Duplicates over a gap. A duplicate is found at the far end by the event
    // identifier; a gap is found by nobody. So a sink that cannot say what it
    // holds gets the whole log again when this run took up somebody else's, and
    // it is told that it did.
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "sink-with-no-memory");
    defer source.deinit(io);
    _ = try source.append(io, say("one"), 1000);
    _ = try source.append(io, say("two"), 2000);

    var sink = FakeSink{ .gpa = gpa, .holds = null };
    defer sink.deinit();
    var shipper = Shipper{
        .sink = sink.sink(),
        .session = "01TESTSESSION",
        .continued = true,
    };
    shipper.finish(gpa, io, source.store);

    try testing.expectEqual(@as(u64, 3), shipper.health.delivered);
    try testing.expect(shipper.health.resent_from_start);
    try testing.expect(shipper.health.wantsSaying());
    const said = try std.fmt.allocPrint(gpa, "{f}", .{&shipper.health});
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "sent again") != null);

    // **And a session nobody continued says nothing about duplicates**, because
    // nothing can have been sent twice. Measured on a real run before this was
    // conditional: a fresh session with an unreachable syslog reported that its
    // whole log had been sent again, and that log had never been sent at all. A
    // warning that fires on every run is one nobody reads by the second week.
    //
    // Mutation check: set the flag unconditionally in `start` and this fails.
    var fresh = try TestLog.open(gpa, io, "fresh-session");
    defer fresh.deinit(io);
    _ = try fresh.append(io, say("the first turn"), 1000);
    var forgetful = FakeSink{ .gpa = gpa, .holds = null };
    defer forgetful.deinit();
    var first_run = Shipper{ .sink = forgetful.sink(), .session = "01TESTSESSION" };
    first_run.finish(gpa, io, fresh.store);

    try testing.expect(!first_run.health.resent_from_start);
    try testing.expect(!first_run.health.wantsSaying());
    // And every line still shipped, so the quieter answer costs nothing at all.
    try testing.expectEqual(@as(u64, 2), first_run.health.delivered);
}

test "a shipper that has nothing new does not send and does not report a fault" {
    // The ordinary case between two events. `push` runs on every event, so a
    // call with nothing new must cost nothing and must not look like a fault.
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "nothing-new");
    defer source.deinit(io);
    _ = try source.append(io, say("only one"), 1000);

    var sink = FakeSink{ .gpa = gpa };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };
    shipper.push(gpa, io, source.store);
    const after_first = sink.attempts;

    shipper.push(gpa, io, source.store);
    shipper.push(gpa, io, source.store);

    try testing.expectEqual(after_first, sink.attempts);
    try testing.expectEqual(@as(u64, 0), shipper.health.faults);
    try testing.expect(!shipper.health.wantsSaying());
}

test "an empty log ships its header and nothing else" {
    // A session that was started and did nothing. The far end still gets the
    // anchor, so a session that appears with a header and no events is a session
    // that really did nothing, not one whose events were lost on the way.
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "empty-log");
    defer source.deinit(io);

    var sink = FakeSink{ .gpa = gpa };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };
    shipper.finish(gpa, io, source.store);

    try testing.expectEqual(@as(u64, 1), shipper.health.delivered);
    try testing.expectEqual(@as(usize, 1), sink.flushes);
    try testing.expect(!shipper.health.wantsSaying());
}

test "the shipper writes nothing to the log it reads" {
    // **The rule this whole file is held to.** `Loop.run` owns the log and holds
    // its exclusive lock for the session, so a shipper that appended would be a
    // second writer of the one record. Measured against the bytes on disk.
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "read-only-shipper");
    defer source.deinit(io);
    _ = try source.append(io, say("the only event"), 1000);

    var sink = FakeSink{ .gpa = gpa };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };
    shipper.finish(gpa, io, source.store);
    // And again with a sink that fails, which is the path that could plausibly
    // want to write a mark of its own somewhere.
    sink.answer = .{ .fail = error.ConnectionRefused };
    _ = try source.append(io, say("a second event"), 2000);
    const after_append = try std.Io.Dir.cwd().readFileAlloc(io, source.path, gpa, .limited(1 << 20));
    defer gpa.free(after_append);
    shipper.finish(gpa, io, source.store);

    const after = try std.Io.Dir.cwd().readFileAlloc(io, source.path, gpa, .limited(1 << 20));
    defer gpa.free(after);
    try testing.expectEqualStrings(after_append, after);
    // The shipper also holds no lock: the session's own owner takes one after it.
    var locked = try source.store.lock(io);
    try locked.unlock(io);
}

test "a syslog message is RFC 5424, carries the whole line, and stamps no time of its own" {
    // The framing, with no socket at all. The timestamp, the hostname and the
    // process are all NILVALUE on purpose: see `Syslog`'s own doc comment. The
    // event's own time is inside the line the message carries.
    const gpa = testing.allocator;

    const message = try Syslog.frame(gpa, .{
        .session = "01JQAAAAAAAAAAAAAAAAAAAAAA",
        .id = 16,
        .line = "{\"id\":16,\"time_ms\":1000,\"event\":{}}",
        .kind = .event,
    });
    defer gpa.free(message);

    try testing.expectEqualStrings(
        "<85>1 - - chock - 01JQAAAAAAAAAAAAAAAAAAAAAA - {\"id\":16,\"time_ms\":1000,\"event\":{}}",
        message,
    );
    // The priority is authpriv at notice, worked out rather than typed twice.
    try testing.expectEqual(@as(u8, 85), syslog_priority);
    // The whole log line is in there, unaltered. A sink that shortened it would
    // put a line at the far end that reads as tampered with.
    try testing.expect(std.mem.endsWith(u8, message, "{\"id\":16,\"time_ms\":1000,\"event\":{}}"));

    // A record with no session still frames, with the NILVALUE a receiver
    // expects rather than an empty field it cannot parse.
    const anonymous = try Syslog.frame(gpa, .{ .session = "", .id = 0, .line = "{}", .kind = .header });
    defer gpa.free(anonymous);
    try testing.expectEqualStrings("<85>1 - - chock - - - {}", anonymous);
}

test "the syslog sink writes to a real unix datagram socket and reads back what it sent" {
    // **Not a real syslog daemon, and not a stand-in either.** The test binds a
    // datagram socket of its own in its own temporary directory and reads the
    // bytes the sink put on the wire. A sink measured only against a fake would
    // be a protocol tested against something more permissive than the real
    // thing, which this project has already paid for once.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try @import("log.zig").absoluteDirPath(io, &buffer, tmp.dir);
    const socket_path = try std.fmt.allocPrint(gpa, "{s}/s", .{dir_path});
    defer gpa.free(socket_path);

    const listener = bindDatagram(socket_path) orelse return error.SkipZigTest;
    defer _ = std.posix.system.close(listener);

    var syslog = Syslog{ .path = socket_path };
    defer syslog.close();
    const sink = syslog.sink();

    const answer = try sink.send(io, .{
        .session = "01JQAAAAAAAAAAAAAAAAAAAAAA",
        .id = 16,
        .line = "{\"id\":16}",
        .kind = .event,
    });
    try testing.expectEqual(Delivery.delivered, answer);
    // A datagram is gone by the time `write` returns, so `flush` has nothing to
    // do and must still be safe to call.
    try sink.flush(io);
    // And it cannot say what it already holds, which is what makes a continued
    // session send everything again rather than risk a gap.
    try testing.expectEqual(@as(?u64, null), try sink.resumeAt(io));

    var arrived: [512]u8 = undefined;
    const count = readDatagram(listener, &arrived) orelse return error.SkipZigTest;
    try testing.expectEqualStrings(
        "<85>1 - - chock - 01JQAAAAAAAAAAAAAAAAAAAAAA - {\"id\":16}",
        arrived[0..count],
    );
}

test "a syslog socket nothing is listening on is a fault the shipper survives" {
    // The rule that matters most: a session must not fail because an audit sink
    // is down. A path with no socket at it is exactly that case.
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "syslog-not-there");
    defer source.deinit(io);
    _ = try source.append(io, say("an event"), 1000);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try @import("log.zig").absoluteDirPath(io, &buffer, tmp.dir);
    const missing = try std.fmt.allocPrint(gpa, "{s}/nothing-here", .{dir_path});
    defer gpa.free(missing);

    var syslog = Syslog{ .path = missing };
    defer syslog.close();
    var shipper = Shipper{ .sink = syslog.sink(), .session = "01TESTSESSION" };
    // No error comes out of this call at all, which is the property.
    shipper.finish(gpa, io, source.store);

    try testing.expectEqual(@as(u64, 0), shipper.health.delivered);
    try testing.expect(shipper.health.faults != 0);
    try testing.expect(shipper.health.wantsSaying());
    try testing.expectEqual(@as(?u64, 0), shipper.health.stalled_at);

    // A path longer than a unix socket address holds is its own fault, and not a
    // crash.
    const long = try gpa.alloc(u8, 512);
    defer gpa.free(long);
    @memset(long, 'x');
    var far_too_long = Syslog{ .path = long };
    defer far_too_long.close();
    try testing.expectError(
        error.SyslogPathTooLong,
        far_too_long.sink().send(io, .{ .session = "s", .id = 0, .line = "{}", .kind = .header }),
    );
}

test "a sink is reached for with nothing sent, and a sink that is down says so" {
    // **The probe a caller needs before a session starts.** Until this there
    // was no way to ask a sink whether it is there without handing it a
    // record: `FileDrop.resumeAt` opens, which is a real probe, and
    // `Syslog.resumeAt` answers null with no socket at all, so a caller that
    // read the two the same way called every syslog sink reachable. Both sinks
    // are measured here against a real file and a real socket, never against
    // the fake.
    //
    // Mutation check: write one byte in either `reachFn` and the two "nothing
    // was sent" assertions below fail, which is a probe putting a record
    // nobody wrote into an organisation's audit trail.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try @import("log.zig").absoluteDirPath(io, &buffer, tmp.dir);

    // A file drop opens its file, which is the whole of what it does before it
    // writes, so opening it is the whole of the probe.
    const drop_path = try std.fmt.allocPrintSentinel(gpa, "{s}/reached.jsonl", .{dir_path}, 0);
    defer gpa.free(drop_path);
    var drop = FileDrop{ .path = drop_path };
    defer drop.close(io);
    try drop.sink().reach(io);

    const after = try std.Io.Dir.cwd().readFileAlloc(io, drop_path, gpa, .limited(1 << 20));
    defer gpa.free(after);
    try testing.expectEqualStrings("", after);

    // A drop under a directory that is not there cannot be reached, and it
    // says so rather than answering that it is fine.
    const missing_drop = try std.fmt.allocPrintSentinel(gpa, "{s}/no-such-dir/copy.jsonl", .{dir_path}, 0);
    defer gpa.free(missing_drop);
    var lost = FileDrop{ .path = missing_drop };
    defer lost.close(io);
    try testing.expectError(error.FileNotFound, lost.sink().reach(io));

    // And syslog connects and writes nothing. The first datagram the listener
    // reads is the record sent after the probe, so the probe left none there.
    const socket_path = try std.fmt.allocPrint(gpa, "{s}/s", .{dir_path});
    defer gpa.free(socket_path);
    const listener = bindDatagram(socket_path) orelse return error.SkipZigTest;
    defer _ = std.posix.system.close(listener);

    var syslog = Syslog{ .path = socket_path };
    defer syslog.close();
    try syslog.sink().reach(io);
    try testing.expectEqual(Delivery.delivered, try syslog.sink().send(io, .{
        .session = "01TESTSESSION",
        .id = 16,
        .line = "{\"id\":16}",
        .kind = .event,
    }));

    var arrived: [512]u8 = undefined;
    const count = readDatagram(listener, &arrived) orelse return error.SkipZigTest;
    try testing.expectEqualStrings(
        "<85>1 - - chock - 01TESTSESSION - {\"id\":16}",
        arrived[0..count],
    );

    // A path with nothing listening on it is what a required sink that is down
    // answers, and it is an error and never a quiet success. This is the one
    // reading a caller acts on.
    const nothing = try std.fmt.allocPrint(gpa, "{s}/not-a-socket", .{dir_path});
    defer gpa.free(nothing);
    var down = Syslog{ .path = nothing };
    defer down.close();
    try testing.expectError(error.SyslogUnreachable, down.sink().reach(io));
}

/// Bind a unix datagram socket at `path`, for the syslog test. Null when this
/// platform would not give one, which is what makes that test skip rather than
/// fail somewhere Chock does not run.
fn bindDatagram(path: []const u8) ?std.posix.fd_t {
    var address: std.posix.sockaddr.un = .{ .path = @splat(0) };
    if (path.len >= address.path.len) return null;
    @memcpy(address.path[0..path.len], path);

    const made = std.posix.system.socket(std.posix.AF.UNIX, std.posix.SOCK.DGRAM, 0);
    if (std.posix.errno(made) != .SUCCESS) return null;
    const handle: std.posix.fd_t = @intCast(made);

    const bound = std.posix.system.bind(
        handle,
        @ptrCast(&address),
        @intCast(@sizeOf(std.posix.sockaddr.un)),
    );
    if (std.posix.errno(bound) != .SUCCESS) {
        _ = std.posix.system.close(handle);
        return null;
    }
    return handle;
}

/// Read one datagram from `handle`. Null when nothing came.
fn readDatagram(handle: std.posix.fd_t, buffer: []u8) ?usize {
    const rc = std.posix.system.read(handle, buffer.ptr, buffer.len);
    const count: isize = @bitCast(@as(usize, @bitCast(rc)));
    if (count <= 0) return null;
    return @intCast(count);
}
