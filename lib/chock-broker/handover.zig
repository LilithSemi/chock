//! The handover socket: how one process asks a running session to stop, so
//! another process can become its owner.
//!
//! ## What was missing, and why this is the shape of it
//!
//! `src/detach.zig` hands over a session that has already stopped, and it
//! refuses a running one by name. It names two missing things: the loop
//! stopping at a turn boundary on another process's word, and a workspace
//! another process can take. This file is the first of the two.
//!
//! The process holding the session log's exclusive lock is the owner of that
//! session. So a handover is that lock moving, and the only thing a running
//! owner has to do is let go at a moment where the log is whole. **It will not
//! let go on its own**, because nothing outside the process can reach it:
//! `Loop.run` holds the lock for the whole session, and `flock(2)` refuses
//! everybody else. A signal is not the answer either. A signal says stop and
//! cannot say who is asking, cannot be refused, and cannot be taken back, so a
//! `SIGTERM` that raced a turn would end a session for a client that had
//! already given up.
//!
//! So the ask travels over a socket, and it follows the rule that let the
//! approval wall come down in `chock-broker/socket.zig`: **the socket carries a
//! question and an answer, and never a log write**. A client here holds no
//! handle on the log, appends nothing, and learns only what the session chooses
//! to answer. The session appends its own `session.end` through the handle it
//! already owns, exactly as it does for a Ctrl-C.
//!
//! ## A socket of its own, beside the approval socket
//!
//! Both live in `<session dir>/<id>.ctl`, the directory this user alone may
//! enter. The approval socket is `s` and this one is `h`.
//!
//! **They are not one descriptor, and that is deliberate.** The approval
//! socket's peers are read by `socket.Waiter.readOne`, which runs only while an
//! approval question is open, which is a small part of a session. A handover
//! ask that arrived on that descriptor would either sit unread for as long as
//! nobody asked for an approval, or would be read by `readOne` and dropped,
//! because `decisionFrom` answers null for every frame that is not an
//! `approval.response` for the open question. Two readers on one descriptor,
//! each able to eat the other's bytes, is the fault. Two descriptors, one
//! reader each, has none of it, and the trust boundary does not change: the
//! same `0o700` directory, the same peer uid check, the same refusal of
//! anything a person could not say.
//!
//! ## Three frames, and why they are words rather than event envelopes
//!
//! `chock-broker/socket.zig` frames an approval as the session log's own
//! envelope, and gives the reason: a client that can read a session log can
//! answer one. **There is no log event for a handover ask**, because a
//! question that nobody records is not a thing a log holds. Inventing one
//! would put a word in the log's vocabulary that no log ever contains. So the
//! frames here are plain lines:
//!
//! | Direction | Frame | Meaning |
//! |---|---|---|
//! | client to session | `ask` | will you hand this session over? |
//! | session to client | `ready` | yes, and I am waiting for you to say take |
//! | session to client | `waiting <reason>` | not yet, this is what I hold, and I will say ready when it is done |
//! | session to client | `busy <reason>` | no, and this is why |
//! | client to session | `take` | take it, I am the next owner |
//! | session to client | `handing over` | I am stopping now |
//!
//! ## The confirm step is what makes a client that gave up safe
//!
//! A session sees the ask only at a turn boundary, and a turn can be minutes
//! long. So a client that asked has to wait, and a client that waits can stop
//! waiting: a person presses Ctrl-C, or the client's own patience runs out.
//!
//! **Without a confirm step that is a session that stops for nobody.** The ask
//! would still be in the socket, the session would read it at its next
//! boundary, write `session.end`, and let go of the lock, and no process would
//! be there to take it. The person who typed the command would have been told
//! nothing happened, and their session would be over.
//!
//! So `ready` is not the end of the exchange. The session says `ready` and then
//! waits, for a budget its caller chooses, for the client to answer `take`. A
//! client that has gone is a write that fails or a read that ends, and either
//! one means the session drops the peer and carries on with its turn. **A
//! handover happens only when both processes said so, in that order.**
//!
//! A client that is still there and has simply not answered yet keeps its
//! place, and the next turn boundary reads its `take`. The budget bounds how
//! long one turn waits and it is not a deadline the client agreed to.
//!
//! ## What this waits for, and why the ask is held rather than refused
//!
//! A running session holds work that its log does not, and `src/detach.zig`
//! lists it. Two of those rows are still real at a turn boundary:
//!
//! * **A background command.** Its thread and its output live in this process.
//!   `Loop.recordFinishedTasks` writes a `task.complete` when it finishes, and
//!   a task still running when the process ends is never recorded at all.
//!   `src/run.zig` ends every task that still runs when a session stops, so a
//!   handover would not only lose the record, it would stop the command.
//! * **A subagent started in the background.** Its own process and its own
//!   log, both of which outlive this one, but the parent is what records the
//!   `agent.complete`, and the parent is what is about to go.
//!
//! **Neither one moves to another process, so this waits for it instead.** A
//! client that asks a session holding either is told `waiting <reason>`, which
//! names the counts, and then the ask stays open. Every turn boundary after
//! that looks again, and the first one that holds nothing answers `ready`. The
//! session keeps running its turns the whole time, so the wait costs the
//! session nothing and the work finishes as it would have.
//!
//! **This replaces a refusal, and it keeps what the refusal was for.** The old
//! answer was `busy <reason>` at once, which was honest and made a person ask
//! again by hand. Holding the ask makes the same promise the machine keeps:
//! the handover happens after the work is recorded, or it does not happen at
//! all. Nothing is carried that cannot be carried, and nothing is dropped.
//!
//! **The client owns the bound.** This file waits forever, because a session
//! has no opinion about how long a person will stand there. `chock detach`
//! passes its `--wait`, and a client whose patience runs out simply stops
//! reading: the session never got a `take`, so it never stops, and it carries
//! on with the work it was holding. See `Client.readOffer`.
//!
//! **A session may start more of that work while an ask is held**, because the
//! agent keeps taking turns and a turn may call `run_command` in the
//! background again. That is what the client's bound is for. Refusing the
//! agent a tool it is allowed to use, because somebody asked for the session,
//! would put the person's command in the agent's way.
//!
//! The other rows are not losses at this point. A tool call in flight cannot
//! exist at a turn boundary, because a turn boundary is where every tool result
//! of the last turn is already in the log. A language server ends with the
//! process and the next owner starts one on demand. The workspace and the
//! scratchpad both stay on disk for the next owner: see `src/run.zig`.
//!
//! ## What a client that never answers costs
//!
//! A client that connects, sends `ask`, and then stays alive and silent keeps
//! the one peer slot, and every turn boundary after that spends the whole
//! confirm budget in a `poll`. That is deliberate: it is the price of letting a
//! slow client keep its place across a turn, and it is bounded per turn rather
//! than unbounded. **No client Chock ships behaves that way**: `chock detach`
//! closes its stream on every path out, and a closed peer is dropped on the
//! next look.
//!
//! **A held ask costs less than that, and not more.** It has not been answered
//! `ready`, so no confirm budget is spent on it at all: a turn boundary reads
//! whatever the client already sent, without waiting, and looks at the counts.
//! A client that died while its ask was held is dropped by that same read, so a
//! wait that may last hours cannot lock every other asker out.
//!
//! ## One asker at a time
//!
//! A second client that connects while one is asking is answered `busy` and
//! closed. Two clients that both believe they are the next owner is the state
//! this whole exchange exists to make impossible, and a queue of askers would
//! only make the second one wait for an answer that the first one's handover
//! ends the process before it can give.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
/// Why the handover socket could not be opened. One type for the whole module:
/// see `chock-broker/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;
const socket = @import("socket.zig");

/// The name of this socket inside the session's own control directory. One
/// character, for the reason `socket.socket_name` is one: a unix socket path is
/// bounded at 107 bytes on Linux and 103 on Darwin, see `socket.max_socket_path`,
/// and the session directory has already spent most of it.
pub const socket_name = "h";

/// The longest frame this reads from a peer before it gives up on that peer.
///
/// Every frame in this protocol is one short word. Four kilobytes is far more
/// than any of them and far less than a client could use to make a session hold
/// memory on its behalf.
pub const max_frame_bytes: usize = 4096;

/// The frame a client sends to open the exchange.
pub const ask_frame = "ask";
/// The frame a client sends to accept a session that answered `ready`.
pub const take_frame = "take";
/// The frame a session answers when it will hand over if the client confirms.
pub const ready_frame = "ready";
/// The frame a session answers once it is stopping. The last thing the client
/// reads before the socket file goes with the process.
pub const handing_over_frame = "handing over";
/// What a refusal starts with. The rest of the line is a sentence a person
/// reads: see `look`.
pub const busy_prefix = "busy ";
/// What a held ask is answered with, once. The rest of the line names the work
/// the session still holds, and `ready` follows it when that work is done: see
/// `look`.
///
/// **Sent once per exchange and never repeated.** A session that said it again
/// at every turn boundary would fill a client's buffer with the same sentence,
/// and the client is already waiting for the one frame that changes anything.
pub const waiting_prefix = "waiting ";

/// How long a session waits for `take` after it answered `ready`, when its
/// caller states nothing else.
///
/// **Spent only when a client really asked**, and never on an ordinary turn:
/// `look` returns at once when no peer has sent anything. Five seconds is long
/// enough for a client on this machine to answer a line it is already waiting
/// for, and short enough that a client that died between `ask` and `take`
/// costs the session one pause and not a turn.
pub const default_confirm_budget_ms: u64 = 5_000;

/// Where one session's handover socket lives. The caller owns the strings.
pub const Paths = struct {
    gpa: std.mem.Allocator,
    /// The control directory, which `Endpoint.open` makes `0o700`. The same
    /// directory the approval socket sits in.
    dir: []u8,
    /// The socket itself.
    socket: []u8,

    pub fn deinit(self: *Paths) void {
        self.gpa.free(self.dir);
        self.gpa.free(self.socket);
        self.* = undefined;
    }
};

/// Where the handover socket of session `id` in `session_dir` lives. Makes
/// nothing: see `Endpoint.open`.
///
/// **Built from the session directory and the identifier and from nothing
/// else**, which is the property that lets a client reach a session it did not
/// start. `socket.pathsFor` keeps the same rule for the same reason.
pub fn pathsFor(
    gpa: std.mem.Allocator,
    session_dir: []const u8,
    id: []const u8,
) std.mem.Allocator.Error!Paths {
    const dir = try std.fmt.allocPrint(gpa, "{s}/{s}" ++ socket.dir_suffix, .{ session_dir, id });
    errdefer gpa.free(dir);
    const path = try std.fmt.allocPrint(gpa, "{s}/" ++ socket_name, .{dir});
    return .{ .gpa = gpa, .dir = dir, .socket = path };
}

/// What a session still holds at the turn boundary, which its log does not.
///
/// **Counts and not a boolean, so the refusal can say how many.** A person told
/// "something is still running" has to guess what to wait for; a person told
/// "2 background commands" knows.
pub const InFlight = struct {
    /// Background commands started and not yet recorded in the log.
    tasks: usize = 0,
    /// Subagents started in the background and not yet recorded in the log.
    children: usize = 0,

    /// True when nothing this session holds would be lost by stopping now.
    pub fn empty(self: InFlight) bool {
        return self.tasks == 0 and self.children == 0;
    }
};

/// What one look at the socket decided.
pub const Decision = enum {
    /// Nobody asked, or the ask was refused, or the client did not confirm.
    /// The session carries on with its turn, and nothing about it has changed.
    carry_on,
    /// A client asked, the session had nothing in flight, and the client
    /// confirmed. The session stops at this turn boundary.
    hand_over,
};

/// The listening end of one session's handover socket.
///
/// **Only the process that holds the session lock builds one of these.** It is
/// the owner of the session, and this is the one way anything else can ask it
/// to stop being the owner.
pub const Endpoint = struct {
    server: std.Io.net.Server,
    /// Borrowed from the caller's `Paths`, for `close` to remove.
    socket_path: []const u8,
    /// The uid this process runs as. Any other peer is closed at once.
    owner_uid: std.posix.uid_t,
    /// The one client that is asking, or null when nobody is. See this file's
    /// own top comment for why there is one and not a list.
    peer: ?std.posix.fd_t = null,
    /// Where the next frame starts in `buffer`, and how much of `buffer` has
    /// arrived.
    ///
    /// **Two cursors and not one, because one read brings more than one
    /// frame.** A client that is not waiting for `ready` before it sends `take`
    /// puts both frames in the socket at once, and one read then returns both.
    /// A reader that threw away whatever followed the first line break would
    /// drop that `take`, answer `ready`, wait out its whole confirm budget, and
    /// carry on: the handover would silently never happen. Measured, by writing
    /// the two frames back to back.
    start: usize = 0,
    filled: usize = 0,
    buffer: [max_frame_bytes]u8 = undefined,
    /// Whether this session has already answered `ready` to the peer it holds.
    ///
    /// **The exchange is two round trips, so one look is not always enough.**
    /// A client that has been told `ready` and has not yet said `take` keeps
    /// its place across turn boundaries, and this is what stops the next look
    /// from reading its `take` as an `ask` and answering `ready` twice.
    offered: bool = false,
    /// Whether the peer asked and the session answered `waiting` rather than
    /// `ready`, because it still held work that does not move.
    ///
    /// **The ask stays open across turn boundaries while this is set.** The
    /// frame has already been read, so a later look must not try to read it
    /// again: it looks at the counts instead, and answers `ready` at the first
    /// boundary that holds nothing. See this file's own top comment.
    waiting: bool = false,
    /// How many peers were closed because they were somebody else, or because
    /// one was already asking. Counted rather than only printed, so a test can
    /// pin that a refusal happened and not merely that no handover did.
    refused: usize = 0,
    /// Why the first refused peer was refused, for the caller to report.
    /// `look` has no error to give back: every refusal it makes is the right
    /// answer, so the reason has nowhere else to go.
    refusal: ?Diagnostic = null,

    pub const OpenError = socket.Endpoint.OpenError;

    /// Make the control directory, remove any socket a crash left there, and
    /// listen.
    ///
    /// **A stale socket is removed rather than refused**, for the reason
    /// `socket.Endpoint.open` gives: a file left by a process that is gone
    /// would wedge that session id forever, and this user alone can enter the
    /// directory it sits in.
    pub fn open(io: std.Io, paths: Paths, diag: ?*?Diagnostic) OpenError!Endpoint {
        const address = try socket.addressFor(paths.socket, diag);

        try socket.ensureDir(io, paths.dir, diag);

        std.Io.Dir.deleteFileAbsolute(io, paths.socket) catch |err| switch (err) {
            error.FileNotFound => {},
            else => {
                _ = diagnostic.note(diag, .{ .socket_not_removed = .{ .path = paths.socket, .err = err } });
                return error.SocketUnavailable;
            },
        };

        // Room in the kernel queue for the second asker, so `look` can accept
        // it and answer `busy` rather than letting the kernel refuse it. A
        // client the kernel refused cannot tell that from a session which is
        // not listening at all: measured on Darwin, where the queue refuses
        // rather than waits. `socket.Endpoint.open` makes the same trade.
        const server = address.listen(io, .{ .kernel_backlog = 4 }) catch |err| {
            _ = diagnostic.note(diag, .{ .socket_not_opened = .{ .path = paths.socket, .err = err } });
            return error.SocketUnavailable;
        };

        return .{
            .server = server,
            .socket_path = paths.socket,
            .owner_uid = std.posix.system.getuid(),
        };
    }

    /// Close the asking peer, stop listening, and remove the socket file.
    ///
    /// **A client that was waiting reads the end of the stream**, which is what
    /// tells it the session has gone rather than leaving it on a socket nothing
    /// will write to again.
    pub fn close(self: *Endpoint, io: std.Io) void {
        // **The file goes first, and the peer second.** Dropping the peer is
        // what lets the client run on and ask a daemon to start the next owner,
        // and that owner binds a new socket at this same path. A remove after
        // the drop could unlink the file the next owner had just made. Removing
        // first leaves no such moment.
        //
        // A session whose directory has already gone is not a fault worth
        // reporting: the file is scratch, and the next `open` removes a stale
        // one anyway.
        std.Io.Dir.deleteFileAbsolute(io, self.socket_path) catch {};
        self.server.deinit(io);
        self.dropPeer(io);
    }

    /// One look at the socket, at a turn boundary.
    ///
    /// **This must cost nothing on a turn nobody asked about**, because the
    /// loop calls it at the top of every turn. It accepts what the kernel
    /// already holds, reads what a peer already sent, and returns. It waits
    /// only after it has answered `ready`, and only for `confirm_budget_ms`:
    /// see this file's own top comment for why that wait is what makes a client
    /// that gave up safe.
    ///
    /// **A client that has not confirmed by the end of the budget keeps its
    /// place.** It is still connected, so it has not given up, and the next
    /// turn boundary reads its `take`. Dropping it would make the budget a
    /// deadline the client never agreed to, and a person on a slow link would
    /// have to ask again and again. A client that has really gone is a read
    /// that ends, and that one is dropped.
    ///
    /// `in_flight` is what the caller knows and this file cannot: see
    /// `InFlight`.
    pub fn look(
        self: *Endpoint,
        io: std.Io,
        in_flight: InFlight,
        confirm_budget_ms: u64,
    ) Decision {
        self.acceptPending(io);

        const handle = self.peer orelse return .carry_on;

        if (self.waiting) {
            // The ask was read at an earlier boundary and is still open. See
            // this file's own top comment: the work does not move, so the
            // session waits for it rather than refusing the person.
            self.noticeGoneWhileWaiting(io, handle);
            if (self.peer == null) return .carry_on;
            if (!in_flight.empty()) return .carry_on;
            if (!self.offer(io, handle)) return .carry_on;
        } else if (!self.offered) {
            // Nothing waited for here. A peer that has sent nothing yet is the
            // ordinary state of a socket nobody is using.
            const line = self.readFrame(io, handle, 0) orelse return .carry_on;

            // A frame this build does not know is a client this build cannot
            // talk to. It is answered rather than ignored, because a client
            // left waiting for a line that never comes looks exactly like a
            // session that is still in a turn.
            if (!std.mem.eql(u8, line, ask_frame)) {
                self.refuse(io, handle, "that is not a frame this session understands");
                return .carry_on;
            }

            // The wait this whole file is careful about. See the top comment:
            // neither of these moves to another process, so a handover that
            // carried them would be a false promise, and the ask is held until
            // they are done instead.
            if (!in_flight.empty()) {
                var line_buffer: [max_frame_bytes]u8 = undefined;
                const said = std.fmt.bufPrint(
                    &line_buffer,
                    waiting_prefix ++ "this session still holds {d} background command(s) and " ++
                        "{d} running subagent(s). Neither one moves to another process, so this " ++
                        "hands over at the first turn boundary after they finish.\n",
                    .{ in_flight.tasks, in_flight.children },
                ) catch waiting_prefix ++ "this session still holds work that does not move to " ++
                    "another process, so this hands over once it is done\n";
                if (!socket.writeAll(handle, said)) {
                    self.dropPeer(io);
                    return .carry_on;
                }
                self.waiting = true;
                return .carry_on;
            }

            if (!self.offer(io, handle)) return .carry_on;
        }

        // **The confirm, and the one place this waits.** `readFrame` drops the
        // peer itself on the end of the stream, so a null here is either a
        // client that is still thinking or one that has gone, and `self.peer`
        // says which.
        const confirm = self.readFrame(io, handle, confirm_budget_ms) orelse return .carry_on;
        if (!std.mem.eql(u8, confirm, take_frame)) {
            // A client that answered its own `ready` with something else is not
            // speaking this protocol. Say so, rather than leaving it waiting.
            self.refuse(io, handle, "that is not an answer to a ready this session sent");
            return .carry_on;
        }

        // The last thing this session says on this socket. The peer stays open
        // so the client reads the end of the stream when the session closes,
        // which is how it learns the lock is free rather than by guessing.
        _ = socket.writeAll(handle, handing_over_frame ++ "\n");
        return .hand_over;
    }

    /// True when a client is in the middle of an exchange. For a caller that
    /// reports what a session is doing.
    pub fn asking(self: *const Endpoint) bool {
        return self.peer != null;
    }

    /// Take the connection the kernel already holds, and refuse one that may
    /// not be here. Never waits.
    fn acceptPending(self: *Endpoint, io: std.Io) void {
        // Bounded, so a client reconnecting in a loop cannot hold this call.
        for (0..4) |_| {
            if (!socket.readable(self.server.socket.handle, 0)) return;
            const stream = self.server.accept(io) catch return;

            const uid = socket.peerUid(stream.socket.handle) orelse {
                // The kernel would not say who this is, so nothing it says can
                // be believed about who owns this session next.
                self.refused += 1;
                stream.close(io);
                continue;
            };
            if (uid != self.owner_uid) {
                self.refused += 1;
                _ = diagnostic.note(&self.refusal, .{ .client_uid_refused = .{
                    .uid = uid,
                    .owner_uid = self.owner_uid,
                } });
                stream.close(io);
                continue;
            }
            if (self.peer != null) {
                // One asker at a time: see this file's own top comment. The
                // second one is told, and not merely closed, so it does not
                // report a session that is not listening.
                self.refused += 1;
                _ = socket.writeAll(
                    stream.socket.handle,
                    busy_prefix ++ "another process is already asking for this session\n",
                );
                stream.close(io);
                continue;
            }
            self.peer = stream.socket.handle;
            self.start = 0;
            self.filled = 0;
            self.offered = false;
            self.waiting = false;
        }
    }

    /// One whole frame from the asking peer, without its newline, or null when
    /// none arrived within `timeout_ms`. Drops the peer on the end of the
    /// stream and on a frame with no line break in `max_frame_bytes`.
    ///
    /// The slice points into `self.buffer` and is valid until the next call.
    fn readFrame(self: *Endpoint, io: std.Io, handle: std.posix.fd_t, timeout_ms: u64) ?[]const u8 {
        while (true) {
            // A frame that already arrived, ahead of any poll. See `start`:
            // one read brings both of a client's frames when the client sent
            // them together, and the second one must not need a second read
            // that will never come.
            if (std.mem.indexOfScalar(u8, self.buffer[self.start..self.filled], '\n')) |offset| {
                const line = self.buffer[self.start .. self.start + offset];
                self.start += offset + 1;
                return std.mem.trimEnd(u8, line, "\r");
            }
            // Nothing whole in the buffer, so make room for a read. Moving what
            // is left to the front is what keeps a client that sends one byte
            // at a time from filling the buffer with frames already read.
            if (self.start != 0) {
                const rest = self.buffer[self.start..self.filled];
                std.mem.copyForwards(u8, self.buffer[0..rest.len], rest);
                self.filled = rest.len;
                self.start = 0;
            }
            // Checked before the poll, and not after. A peer that filled the
            // whole buffer with no line break is not speaking this protocol,
            // and once it stops sending, a poll never names it again, so a
            // check that only ran on a readable peer would hold the one slot
            // for ever and keep the real client out.
            if (self.filled == self.buffer.len) {
                self.dropPeer(io);
                return null;
            }

            const bounded: i32 = if (timeout_ms > std.math.maxInt(i32))
                std.math.maxInt(i32)
            else
                @intCast(timeout_ms);
            if (!socket.readable(handle, bounded)) return null;

            const read = std.posix.read(handle, self.buffer[self.filled..]) catch |err| switch (err) {
                // The poll said there was something and there was not. Nothing
                // is lost, so look again rather than drop a client that is
                // fine.
                error.WouldBlock => return null,
                else => {
                    self.dropPeer(io);
                    return null;
                },
            };
            if (read == 0) {
                self.dropPeer(io);
                return null;
            }
            self.filled += read;
        }
    }

    /// Answer `ready` and remember it. False when the client went away between
    /// asking and being answered, which leaves the session unchanged: that is
    /// the point of answering before stopping rather than after.
    fn offer(self: *Endpoint, io: std.Io, handle: std.posix.fd_t) bool {
        if (!socket.writeAll(handle, ready_frame ++ "\n")) {
            self.dropPeer(io);
            return false;
        }
        self.waiting = false;
        self.offered = true;
        return true;
    }

    /// Drop the peer of a held ask when it has gone, and keep anything it sent.
    ///
    /// **A held ask is the one state where nothing is read for many turns**, so
    /// a client that died would keep the one peer slot for the rest of the
    /// session and shut every other asker out. This is the read that notices.
    ///
    /// Whatever arrived is kept in the buffer rather than parsed. A client that
    /// puts `ask` and `take` in the socket together is speaking this protocol
    /// in a hurry and not incorrectly, and its `take` is read by the confirm
    /// step once `ready` has gone out.
    fn noticeGoneWhileWaiting(self: *Endpoint, io: std.Io, handle: std.posix.fd_t) void {
        while (socket.readable(handle, 0)) {
            if (self.start != 0) {
                const rest = self.buffer[self.start..self.filled];
                std.mem.copyForwards(u8, self.buffer[0..rest.len], rest);
                self.filled = rest.len;
                self.start = 0;
            }
            // A peer that filled the whole buffer and sent no line break is not
            // speaking this protocol, and it is holding the slot of a client
            // that is. `readFrame` drops one for the same reason.
            if (self.filled == self.buffer.len) {
                self.dropPeer(io);
                return;
            }
            const read = std.posix.read(handle, self.buffer[self.filled..]) catch |err| switch (err) {
                // The poll said there was something and there was not. Nothing
                // is lost, so leave the client where it is.
                error.WouldBlock => return,
                else => {
                    self.dropPeer(io);
                    return;
                },
            };
            if (read == 0) {
                self.dropPeer(io);
                return;
            }
            self.filled += read;
        }
    }

    /// Say no, with a sentence, and end the exchange.
    fn refuse(self: *Endpoint, io: std.Io, handle: std.posix.fd_t, reason: []const u8) void {
        var frame: [max_frame_bytes]u8 = undefined;
        const said = std.fmt.bufPrint(&frame, busy_prefix ++ "{s}\n", .{reason}) catch
            busy_prefix ++ "this session will not hand over now\n";
        _ = socket.writeAll(handle, said);
        self.dropPeer(io);
    }

    fn dropPeer(self: *Endpoint, io: std.Io) void {
        const handle = self.peer orelse return;
        const stream = std.Io.net.Stream{
            .socket = .{ .handle = handle, .address = .{ .ip4 = .loopback(0) } },
        };
        stream.close(io);
        self.peer = null;
        self.start = 0;
        self.filled = 0;
        self.offered = false;
        self.waiting = false;
    }
};

/// What a session answered a client that asked for it.
///
/// **Every arm is a fact about the session and never a guess.** A client that
/// reported a handover it did not see confirmed would send a person looking for
/// a session that is still running under its first owner.
pub const Answer = union(enum) {
    /// The session said `handing over`. It is stopping at this turn boundary,
    /// and the lock becomes free once it has written its `session.end`.
    handed_over,
    /// The session said no, and this is the sentence it gave. Borrowed from the
    /// caller's own buffer.
    busy: []const u8,
    /// Nothing is listening on that path. The session is running under a build
    /// with no handover socket, or its session directory makes a path longer
    /// than a unix socket allows.
    not_listening,
    /// The session said nothing before the caller's patience ran out. It is in
    /// the middle of a turn. **Nothing has changed about it**: a session that
    /// never answered `ready` never got a `take`, so it cannot stop for an ask
    /// this client has given up on.
    silent,
    /// The session answered something this build cannot read. Borrowed from the
    /// caller's own buffer.
    unreadable: []const u8,
};

/// What a session answered the `ask`.
pub const Offer = union(enum) {
    /// `ready`. The session will stop if this client sends `take`.
    offered,
    /// `waiting`, with the sentence it gave. Borrowed from the client's buffer.
    ///
    /// **The ask is still open and the session is still running.** It holds
    /// work that does not move to another process, it named that work, and it
    /// answers `ready` at the first turn boundary after the work is done. A
    /// caller that wants to keep waiting calls `readOffer` again.
    ///
    /// **An arm of its own, and never `busy`.** A `busy` ended the exchange and
    /// told a person to ask again by hand. This one is the session saying it
    /// will do the asking again itself, which is the opposite instruction.
    waiting: []const u8,
    /// `busy`, with the sentence it gave. Borrowed from the client's buffer.
    busy: []const u8,
    /// Nothing arrived before the client's patience ran out. **The session is
    /// still running**, in the middle of a turn.
    silent,
    /// The session's run ended on its own while this client waited, so nobody
    /// owns it now.
    ///
    /// **A member of its own, and never `silent`.** A turn can be minutes long,
    /// so a client waits, and a session that finishes in that time closes this
    /// socket. Reported as `silent` it read "it is still running normally",
    /// which was measured against a real session on 2026-08-23 and is the
    /// opposite of the truth: that session had ended, its work was in a kept
    /// workspace, and the person was told to wait longer.
    ended,
    /// Something this build cannot read. Borrowed from the client's buffer.
    unreadable: []const u8,
};

/// The client end of one exchange.
///
/// **Four steps and not one call, because the exchange is two round trips.**
/// The session answers only at a turn boundary, so a client that did the whole
/// thing in one call could only be driven against a stand-in: a test would have
/// to invent the session's frames, and a stand-in is always more forgiving than
/// the thing the client will meet. With the steps apart, a test drives a real
/// `Endpoint` between them, one look at a time, on one thread and with nothing
/// timing anything.
///
/// It is also what `src/detach.zig` needs. That command says "waiting for the
/// session to reach a turn boundary" between `sendAsk` and `readOffer`, and it
/// prints the table of what moves before it sends `take`.
///
/// **This holds no lock and appends nothing.** See this file's own top comment.
pub const Client = struct {
    handle: std.posix.fd_t,
    frames: Frames,

    /// Speak to a session over a socket somebody else connected. `buffer` holds
    /// every answer, and every borrowed string in a result points into it, so
    /// the caller owns it and it must live as long as the results do.
    pub fn over(handle: std.posix.fd_t, buffer: []u8) Client {
        return .{ .handle = handle, .frames = .{ .buffer = buffer } };
    }

    /// Ask for the session. False when nothing is on the other end.
    pub fn sendAsk(self: *Client) bool {
        return socket.writeAll(self.handle, ask_frame ++ "\n");
    }

    /// What the session answered the ask, waiting at most `patience_ms`.
    ///
    /// **A turn can be minutes long, so this is the read that waits.** A
    /// `.silent` here is not a failure of anything: the session is working, and
    /// it has neither agreed to hand over nor refused.
    ///
    /// **`patience_ms` bounds this one read**, the way it bounds every other
    /// read of this client. A session that answers `.waiting` has said what it
    /// holds and has kept the ask open, so a caller that reads again gives the
    /// work its own patience rather than what was left of the first wait. See
    /// `Offer.waiting`.
    pub fn readOffer(self: *Client, patience_ms: u64) Offer {
        const said = self.frames.next(self.handle, patience_ms) orelse
            return if (readEnded(self.handle)) .ended else .silent;
        if (std.mem.startsWith(u8, said, waiting_prefix)) {
            return .{ .waiting = said[waiting_prefix.len..] };
        }
        if (std.mem.startsWith(u8, said, busy_prefix)) return .{ .busy = said[busy_prefix.len..] };
        if (!std.mem.eql(u8, said, ready_frame)) return .{ .unreadable = said };
        return .offered;
    }

    /// Say this client is the next owner. False when the session has gone.
    pub fn sendTake(self: *Client) bool {
        return socket.writeAll(self.handle, take_frame ++ "\n");
    }

    /// The session's last word, waiting at most `patience_ms`.
    ///
    /// **This one may not be assumed.** A session that read `take` and then
    /// failed to write would leave a client believing it owns a session that is
    /// still running, which is the worst of the answers this file can give.
    pub fn readFinal(self: *Client, patience_ms: u64) Answer {
        const said = self.frames.next(self.handle, patience_ms) orelse return .silent;
        if (std.mem.startsWith(u8, said, busy_prefix)) return .{ .busy = said[busy_prefix.len..] };
        if (!std.mem.eql(u8, said, handing_over_frame)) return .{ .unreadable = said };
        return .handed_over;
    }

    /// Wait for the session to close this socket, which it does when its run
    /// ends. True when it did within `patience_ms`.
    ///
    /// **This is how the next owner knows the log lock is free, and it is a
    /// fact rather than a guess.** `Loop.run` releases the exclusive lock when
    /// it returns, and the run closes this socket after that: see
    /// `src/run.zig`'s phase 3, where the endpoint is closed after the loop has
    /// ended and before the log itself is closed. So the end of this stream
    /// happens strictly later than the unlock.
    ///
    /// The alternative was to ask the lock over and over, which is a poll with
    /// a number in it that nobody can justify. This waits on the one event that
    /// really orders the two processes.
    ///
    /// **False is not a failure.** It means the session is taking longer than
    /// this client chose to wait, and the caller then reports what it knows:
    /// the session agreed to hand over and has not let go yet.
    pub fn waitForEnd(self: *Client, patience_ms: u64) bool {
        // Anything the session still says is read and dropped. What is waited
        // for is the end of the stream and not a word.
        while (self.frames.next(self.handle, patience_ms)) |_| {}
        // `Frames.next` answers null both for a poll that found nothing and for
        // a read that ended, so this asks the descriptor which of the two
        // happened.
        return readEnded(self.handle);
    }
};

/// True when `handle` has reached the end of its stream.
///
/// A closed peer leaves a socket permanently readable with a read of zero
/// bytes, which is exactly how it differs from a peer that has simply said
/// nothing yet.
fn readEnded(handle: std.posix.fd_t) bool {
    if (!socket.readable(handle, 0)) return false;
    var scratch: [1]u8 = undefined;
    const read = std.posix.read(handle, &scratch) catch |err| switch (err) {
        // **The poll said there was something and there was not.** That is not
        // the end of anything, and answering true here would tell `chock detach`
        // the log lock is free while the first owner still holds it, which the
        // daemon's child then meets as `error.Busy`.
        error.WouldBlock => return false,
        // Every other error means this descriptor will not be read again, which
        // is the end of the stream by any reading that matters.
        else => return true,
    };
    return read == 0;
}

/// Ask the session listening at `socket_path` to hand over, and confirm when it
/// says it is ready. The four steps of `Client` in order, for a caller that
/// wants no say in between.
///
/// `patience_ms` bounds each of the two reads on its own.
///
/// **The path is bounded before it is connected**, and not only before it is
/// bound: `std.Io` copies it into `sun_path` on this end too, and a path past
/// that field ends a safety checked build on Darwin rather than failing. See
/// `socket.max_socket_path`. A session whose path is that long opened nothing,
/// so `not_listening` is the true answer.
pub fn ask(io: std.Io, socket_path: []const u8, patience_ms: u64, buffer: []u8) Answer {
    const address = socket.addressFor(socket_path, null) catch return .not_listening;
    const stream = address.connect(io) catch return .not_listening;
    defer stream.close(io);

    var client = Client.over(stream.socket.handle, buffer);
    if (!client.sendAsk()) return .not_listening;
    // Two reads at most. The session sends `waiting` once per exchange, so a
    // second one is a session this build cannot read: see `waiting_prefix`.
    for (0..2) |attempt| {
        switch (client.readOffer(patience_ms)) {
            .offered => break,
            // The session named what it holds and kept the ask open, so read
            // again for the `ready` that follows the work. A caller that wants
            // a say in between uses `Client` instead, which is what
            // `src/detach.zig` does.
            .waiting => |said| if (attempt == 0) continue else return .{ .unreadable = said },
            .busy => |said| return .{ .busy = said },
            .silent => return .silent,
            // Nobody is there to hand anything over, which reads to a caller of
            // this shortcut the same way a socket with no listener does.
            .ended => return .not_listening,
            .unreadable => |said| return .{ .unreadable = said },
        }
    }
    if (!client.sendTake()) return .silent;
    return client.readFinal(patience_ms);
}

/// Reads one frame at a time from a socket, over a buffer the caller owns.
///
/// **Two cursors, for the reason `Endpoint.start` gives**: one read brings more
/// than one frame, and a reader that dropped whatever followed the first line
/// break would lose an answer it is about to wait for. The client meets that
/// every time the session answers `ready` and `handing over` close together.
pub const Frames = struct {
    buffer: []u8,
    /// Where the next frame starts.
    start: usize = 0,
    /// How much of `buffer` has arrived.
    filled: usize = 0,

    /// The next whole frame, without its newline, or null when none arrived in
    /// `timeout_ms` or the peer went away. The slice points into `buffer` and
    /// is valid until the next call.
    fn next(self: *Frames, handle: std.posix.fd_t, timeout_ms: u64) ?[]const u8 {
        while (true) {
            if (std.mem.indexOfScalar(u8, self.buffer[self.start..self.filled], '\n')) |offset| {
                const line = self.buffer[self.start .. self.start + offset];
                self.start += offset + 1;
                return std.mem.trimEnd(u8, line, "\r");
            }
            if (self.start != 0) {
                const rest = self.buffer[self.start..self.filled];
                std.mem.copyForwards(u8, self.buffer[0..rest.len], rest);
                self.filled = rest.len;
                self.start = 0;
            }
            if (self.filled == self.buffer.len) return null;

            const bounded: i32 = if (timeout_ms > std.math.maxInt(i32))
                std.math.maxInt(i32)
            else
                @intCast(timeout_ms);
            if (!socket.readable(handle, bounded)) return null;
            const read = std.posix.read(handle, self.buffer[self.filled..]) catch return null;
            if (read == 0) return null;
            self.filled += read;
        }
    }
};

const testing = std.testing;

/// A handover socket and the temporary directory it sits in.
const Bench = struct {
    gpa: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    paths: Paths,
    endpoint: Endpoint,

    fn init(gpa: std.mem.Allocator, io: std.Io) !Bench {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(io, &buffer);

        var paths = try pathsFor(gpa, buffer[0..len], "01HANDOVER");
        errdefer paths.deinit();

        const endpoint = try Endpoint.open(io, paths, null);
        return .{ .gpa = gpa, .tmp = tmp, .paths = paths, .endpoint = endpoint };
    }

    fn deinit(self: *Bench, io: std.Io) void {
        self.endpoint.close(io);
        self.paths.deinit();
        self.tmp.cleanup();
    }

    /// Attach a client, the way `chock detach` would.
    ///
    /// **Through `socket.addressFor` and never `UnixAddress.init`**, which is
    /// what every other client of this socket does. `Endpoint.open` refuses a
    /// path past the bound before this runs, so no bench reaches the fault
    /// today; a bench that spelled the connect its own way would be the one
    /// place a later reader could copy the unbounded shape back out of.
    fn attach(self: *Bench, io: std.Io) !std.Io.net.Stream {
        const address = try socket.addressFor(self.paths.socket, null);
        return address.connect(io);
    }
};

/// Read one whole line from a client's end, with a bound that is not a
/// measurement: it is what makes a test that would otherwise hang fail instead.
fn readClientLine(stream: std.Io.net.Stream, buffer: []u8) ![]const u8 {
    var frames = Frames{ .buffer = buffer };
    return frames.next(stream.socket.handle, 1000) orelse error.NothingArrived;
}

/// Send one frame from a client's end.
fn sendFrame(stream: std.Io.net.Stream, frame: []const u8) !void {
    try testing.expect(socket.writeAll(stream.socket.handle, frame));
    try testing.expect(socket.writeAll(stream.socket.handle, "\n"));
}

test "the handover socket binds at exactly the bound and refuses one byte more" {
    // **This socket is the one a live session needs.** `chock detach` is a
    // command a person runs on purpose, and it already carried the real bound;
    // a running session bound through `std.Io.net.UnixAddress.max_len`, which
    // is 108 on Darwin and wrong there. See `socket.max_socket_path`.
    //
    // Mutation check: make `socket.max_socket_path` read
    // `std.Io.net.UnixAddress.max_len`. On Darwin the second half fails. On
    // Linux both halves still pass, because `std` binds an unterminated 108 at
    // either end, which is why that number is pinned in `chock-proto` instead.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try socket.BoundBench.open(gpa, io);
    defer bench.cleanup(io);

    var at_bound = try bench.pathsOfLength(socket.max_socket_path);
    defer at_bound.deinit();
    var endpoint = try Endpoint.open(io, .{
        .gpa = gpa,
        .dir = at_bound.dir,
        .socket = at_bound.socket,
    }, null);
    endpoint.close(io);

    var over = try bench.pathsOfLength(socket.max_socket_path + 1);
    defer over.deinit();
    var diag: ?Diagnostic = null;
    try testing.expectError(error.PathTooLong, Endpoint.open(io, .{
        .gpa = gpa,
        .dir = over.dir,
        .socket = over.socket,
    }, &diag));

    var said_buffer: [512]u8 = undefined;
    const said = try std.fmt.bufPrint(&said_buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.indexOf(u8, said, over.socket) != null);
    var number: [8]u8 = undefined;
    try testing.expect(std.mem.indexOf(
        u8,
        said,
        try std.fmt.bufPrint(&number, "{d}", .{socket.max_socket_path}),
    ) != null);

    // And the client end refuses the same path rather than reaching an
    // `@memcpy` past the end of `sun_path`. See `ask`.
    var frames: [max_frame_bytes]u8 = undefined;
    try testing.expect(ask(io, over.socket, 0, &frames) == .not_listening);
}

test "the socket path is built from the session directory and the identifier alone" {
    // **What lets a client reach a session it did not start.** `chock detach`
    // knows the project and the identifier and nothing a running process holds,
    // so a path keyed on anything else is a session nobody can ask for.
    //
    // Spelled out, and not compared against a second call to the same function:
    // two calls agreeing says nothing about what the path is. Mutation check:
    // change `socket_name` or `socket.dir_suffix` and this literal stops
    // matching, which is a running session no `chock detach` can reach.
    const gpa = testing.allocator;
    var paths = try pathsFor(gpa, "/state/p", "01ABC");
    defer paths.deinit();
    try testing.expectEqualStrings("/state/p/01ABC.ctl", paths.dir);
    try testing.expectEqualStrings("/state/p/01ABC.ctl/h", paths.socket);

    // And it is not the approval socket. One descriptor for both would let one
    // reader eat the other's frames: see this file's own top comment.
    var approval = try socket.pathsFor(gpa, "/state/p", "01ABC");
    defer approval.deinit();
    try testing.expectEqualStrings(approval.dir, paths.dir);
    try testing.expect(!std.mem.eql(u8, approval.socket, paths.socket));
}

test "a session with nothing in flight hands over only after the client confirms" {
    // **The whole exchange, and the fact it rests on**: the session stops
    // because two processes said so, in that order. The confirm is what makes a
    // client that gave up safe, so an answer of `ready` alone must never be a
    // handover.
    //
    // Driven one step at a time against the real `Endpoint`, on one thread,
    // with every budget at zero. Nothing here waits and nothing measures time.
    //
    // Mutation check: make `look` return `.hand_over` as soon as it has written
    // `ready`, and the first look below stops holding, which is a session that
    // stopped with nobody there to take the lock.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    const stream = try bench.attach(io);
    defer stream.close(io);
    var answers: [max_frame_bytes]u8 = undefined;
    var client = Client.over(stream.socket.handle, &answers);

    // Nobody has said anything yet. A look costs nothing and decides nothing.
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expect(bench.endpoint.asking());

    try testing.expect(client.sendAsk());
    // The session answers `ready` and finds no confirm, because none has been
    // sent. **It must not hand over here.**
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Offer.offered, client.readOffer(0));

    // And the client keeps its place, so a confirm that arrives one turn later
    // is still this client's. A drop here would make the budget a deadline the
    // client never agreed to.
    try testing.expect(bench.endpoint.asking());
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));

    try testing.expect(client.sendTake());
    try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Answer.handed_over, client.readFinal(0));
}

test "work that does not move to another process holds the handover open by name" {
    // A background command and a background subagent both live in this process,
    // and this process is what writes their record into the log. A handover
    // would lose whichever was running, and would tell the person who asked
    // that the work carried on. So the ask is held rather than taken, and the
    // session says what it holds.
    //
    // Mutation check: drop the `in_flight.empty()` guard in `look`, and a
    // session with a build running hands itself over, which loses that build's
    // own `task.complete`.
    const gpa = testing.allocator;
    const io = testing.io;

    const held = [_]InFlight{
        .{ .tasks = 1 },
        .{ .children = 1 },
        .{ .tasks = 2, .children = 3 },
    };
    for (held) |in_flight| {
        var bench = try Bench.init(gpa, io);
        defer bench.deinit(io);

        const stream = try bench.attach(io);
        defer stream.close(io);
        var answers: [max_frame_bytes]u8 = undefined;
        var client = Client.over(stream.socket.handle, &answers);

        try testing.expect(client.sendAsk());
        // The confirm goes in ahead of the look, so a `look` that ignored the
        // guard would reach `.hand_over` and this test would catch it.
        try testing.expect(client.sendTake());
        try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, in_flight, 0));

        const offer = client.readOffer(0);
        try testing.expect(offer == .waiting);
        // The sentence names what is waited for, and not merely that something
        // is in the way. A person told "wait" has to guess what for.
        try testing.expect(std.mem.indexOf(u8, offer.waiting, "background command") != null);
        try testing.expect(std.mem.indexOf(u8, offer.waiting, "subagent") != null);

        // **The ask is still this client's**, which is the whole difference
        // from the refusal this replaced. A dropped peer here would make the
        // person ask again by hand for work the session is already waiting on.
        try testing.expect(bench.endpoint.asking());

        // Every further turn boundary with the work still running says nothing
        // more and takes nothing. The `waiting` frame is sent once: a session
        // that repeated it would fill the client's buffer with one sentence.
        try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, in_flight, 0));
        try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, in_flight, 0));
        try testing.expectEqual(Offer.silent, client.readOffer(0));

        // And the first boundary that holds nothing hands over, on the `take`
        // this client sent before any of it. **This is the property the whole
        // change is for**: the work was waited for and then the session moved,
        // with nothing asked of the person in between.
        try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));
        try testing.expectEqual(Offer.offered, client.readOffer(0));
        try testing.expectEqual(Answer.handed_over, client.readFinal(0));
    }

    // With both counts at zero from the start no `waiting` is sent at all, so
    // the sentences above were the counts and nothing else about this session.
    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);
    const stream = try bench.attach(io);
    defer stream.close(io);
    var answers: [max_frame_bytes]u8 = undefined;
    var client = Client.over(stream.socket.handle, &answers);
    try testing.expect(client.sendAsk());
    try testing.expect(client.sendTake());
    try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Offer.offered, client.readOffer(0));
}

test "a client that goes away while its ask is held lets the next one in" {
    // **The one state where nothing is read for many turns.** A held ask waits
    // for work, not for a frame, so a client that died between asking and the
    // work finishing would keep the one peer slot for the rest of the session
    // and shut every other asker out with `busy`.
    //
    // Mutation check: take `noticeGoneWhileWaiting` out of `look`, and the
    // second client below is refused as a second asker, which is a session no
    // process can ever take.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    {
        const gone = try bench.attach(io);
        defer gone.close(io);
        var answers: [max_frame_bytes]u8 = undefined;
        var client = Client.over(gone.socket.handle, &answers);
        try testing.expect(client.sendAsk());
        try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{ .tasks = 1 }, 0));
        try testing.expect(client.readOffer(0) == .waiting);
        try testing.expect(bench.endpoint.asking());
    }

    // The client has gone. The next look notices, with the work still running,
    // and lets the slot go.
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{ .tasks = 1 }, 0));
    try testing.expect(!bench.endpoint.asking());

    // So a second person can ask, and is answered rather than told that
    // somebody else is already asking.
    const next = try bench.attach(io);
    defer next.close(io);
    var answers: [max_frame_bytes]u8 = undefined;
    var client = Client.over(next.socket.handle, &answers);
    try testing.expect(client.sendAsk());
    try testing.expect(client.sendTake());
    try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Offer.offered, client.readOffer(0));
}

test "a client that goes away after asking leaves the session running" {
    // **The case the confirm step exists for.** A turn can be minutes long, so
    // a person presses Ctrl-C on `chock detach` while the ask is still in the
    // socket. The session reads it at its next boundary and must not stop for a
    // client that is gone.
    //
    // Mutation check: treat a failed write of `ready`, or a read that ends, as
    // a confirm, and this session stops with nobody there to take the lock.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    {
        const stream = try bench.attach(io);
        var answers: [max_frame_bytes]u8 = undefined;
        var client = Client.over(stream.socket.handle, &answers);
        try testing.expect(client.sendAsk());
        stream.close(io);
    }

    // The ask is real and the client is not. A budget of zero is a poll that
    // does not wait: the end of the stream is already readable.
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expect(!bench.endpoint.asking());

    // And another look, and another. A dropped peer must not become a busy loop
    // or a second close of the same descriptor.
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
}

test "a second asker is told it was turned away, and the first exchange is untouched" {
    // Two processes that both believe they are the next owner is the state this
    // socket exists to make impossible. A second connection that was only
    // closed would read as a session that is not listening, and its client
    // would report the wrong reason.
    //
    // Mutation check: let the second peer take the slot, and the first client's
    // ask is thrown away, so the process that asked first waits for ever.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    const first = try bench.attach(io);
    defer first.close(io);
    var first_answers: [max_frame_bytes]u8 = undefined;
    var first_client = Client.over(first.socket.handle, &first_answers);

    // Accepted, and holding the slot with nothing said yet.
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expect(bench.endpoint.asking());

    const second = try bench.attach(io);
    defer second.close(io);
    var second_answers: [max_frame_bytes]u8 = undefined;
    var second_client = Client.over(second.socket.handle, &second_answers);
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(@as(usize, 1), bench.endpoint.refused);

    const turned_away = second_client.readOffer(0);
    try testing.expect(turned_away == .busy);
    try testing.expect(std.mem.indexOf(u8, turned_away.busy, "already asking") != null);

    // The first client still holds the exchange, and it is the one answered.
    try testing.expect(first_client.sendAsk());
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Offer.offered, first_client.readOffer(0));
}

test "nothing listening is its own answer, and never a silence" {
    // A client that read "nobody is there" as "the session is thinking" would
    // wait for a session that has already ended, and one that read it the other
    // way would report a running session as gone.
    //
    // Mutation check: fold `.not_listening` into `.silent` and `chock detach`
    // waits out its whole patience against a path with no socket on it.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &path_buffer);
    var paths = try pathsFor(gpa, path_buffer[0..len], "01NOBODY");
    defer paths.deinit();

    var buffer: [max_frame_bytes]u8 = undefined;
    try testing.expectEqual(Answer.not_listening, ask(io, paths.socket, 0, &buffer));
}

test "a session that answers nothing is reported as silent, and not as a handover" {
    // A turn is where the session is, and a turn can be minutes long. A client
    // that read silence as anything but silence would either report a handover
    // that never happened or a refusal the session never made.
    //
    // Mutation check: make `readOffer` fall through to `.offered` when the read
    // gives nothing, and `ask` sends a `take` to a session that never agreed.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    const stream = try bench.attach(io);
    defer stream.close(io);
    var answers: [max_frame_bytes]u8 = undefined;
    var client = Client.over(stream.socket.handle, &answers);

    // The endpoint never looks, which is a session in the middle of a turn. A
    // patience of zero is a poll that does not wait, so this test states a
    // budget and measures no time at all.
    try testing.expect(client.sendAsk());
    try testing.expectEqual(Offer.silent, client.readOffer(0));

    // **And the session is still whole.** The ask is in its socket and unread,
    // so its next look answers `ready` and finds no confirm, which is exactly
    // the mid turn refusal this file promises leaves a session running.
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
}

test "a session that ended while a client waited is not a session that is thinking" {
    // **Measured against a real session on 2026-08-23.** A turn can be minutes
    // long, so `chock detach` waits, and the session finished in that time and
    // closed this socket. Both look like "no frame arrived", and reported as
    // silence the command said "it is still running normally", which was the
    // opposite of the truth: the session had ended, its work was in a kept
    // workspace, and the person was told to wait longer.
    //
    // Mutation check: fold `.ended` back into `.silent` and the last line
    // stops holding, which is that false sentence again.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.tmp.cleanup();
    defer bench.paths.deinit();

    const stream = try bench.attach(io);
    defer stream.close(io);
    var answers: [max_frame_bytes]u8 = undefined;
    var client = Client.over(stream.socket.handle, &answers);

    try testing.expect(client.sendAsk());

    // The session is in a turn: it has not looked, and it is still there. A
    // patience of zero is a poll that does not wait, so this test states a
    // budget and measures no time at all.
    try testing.expectEqual(Offer.silent, client.readOffer(0));

    // The run ends. Nothing was ever answered on this socket.
    bench.endpoint.close(io);
    try testing.expectEqual(Offer.ended, client.readOffer(0));
}

test "a frame this build cannot read ends the exchange rather than the session" {
    // A client from another build, or a person with `nc`, must not be able to
    // stop somebody's session, and must not be able to hold the one peer slot
    // so the real client cannot have it.
    //
    // Mutation check: treat an unknown frame as `ask` and anything that can
    // reach the socket ends the session with one word.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    const stranger = try bench.attach(io);
    defer stranger.close(io);
    var stranger_answers: [max_frame_bytes]u8 = undefined;
    var stranger_frames = Frames{ .buffer = &stranger_answers };

    try testing.expect(socket.writeAll(stranger.socket.handle, "take\n"));
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expect(!bench.endpoint.asking());

    const said = stranger_frames.next(stranger.socket.handle, 0) orelse
        return error.NothingArrived;
    try testing.expect(std.mem.startsWith(u8, said, busy_prefix));

    // And the slot is free again, so the real client is not locked out by it.
    const real = try bench.attach(io);
    defer real.close(io);
    var real_answers: [max_frame_bytes]u8 = undefined;
    var real_client = Client.over(real.socket.handle, &real_answers);
    try testing.expect(real_client.sendAsk());
    try testing.expect(real_client.sendTake());
    try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));
    // Both answers are read in the order the session wrote them. A client that
    // read the second one first would report the session's `ready` as an answer
    // this build cannot read.
    try testing.expectEqual(Offer.offered, real_client.readOffer(0));
    try testing.expectEqual(Answer.handed_over, real_client.readFinal(0));
}

test "two frames that arrive in one read are two frames" {
    // **Measured, and it was a real fault in this file.** A client that does
    // not wait between `ask` and `take` puts both in the socket, and one read
    // brings both. The first version of the reader threw away whatever followed
    // the line break, so the `take` was lost, the session waited out its confirm
    // budget, and the handover silently never happened.
    //
    // Mutation check: set `filled` to zero after taking a frame, instead of
    // moving `start` past it, and this test stops holding.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    const stream = try bench.attach(io);
    defer stream.close(io);

    // One write, both frames, so the kernel hands the session a single read.
    try testing.expect(socket.writeAll(
        stream.socket.handle,
        ask_frame ++ "\n" ++ take_frame ++ "\n",
    ));
    try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));

    // And the client's own reader has the same fault to avoid: the session
    // answers `ready` and `handing over` close enough together that one read
    // brings both.
    var answers: [max_frame_bytes]u8 = undefined;
    var frames = Frames{ .buffer = &answers };
    try testing.expectEqualStrings(ready_frame, frames.next(stream.socket.handle, 0).?);
    try testing.expectEqualStrings(handing_over_frame, frames.next(stream.socket.handle, 0).?);
}

test "the end of the stream is what tells the next owner the session has let go" {
    // **The one event that orders the two processes.** `Loop.run` releases the
    // log's exclusive lock when it returns, and `src/run.zig` closes this
    // socket after that. So a client that waits for the end of this stream
    // knows the lock is free, and never has to ask the lock over and over with
    // a number nobody can justify.
    //
    // Mutation check: make `waitForEnd` answer true on a poll that found
    // nothing, and `chock detach` asks the daemon to adopt a session whose
    // first owner still holds the lock, which the daemon's child then meets as
    // `error.Busy`.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.tmp.cleanup();
    defer bench.paths.deinit();

    const stream = try bench.attach(io);
    defer stream.close(io);
    var answers: [max_frame_bytes]u8 = undefined;
    var client = Client.over(stream.socket.handle, &answers);

    try testing.expect(client.sendAsk());
    try testing.expect(client.sendTake());
    try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Offer.offered, client.readOffer(0));
    try testing.expectEqual(Answer.handed_over, client.readFinal(0));

    // **Still running.** The session has agreed and has not let go yet, which is
    // exactly the window a client must not act in.
    try testing.expect(!client.waitForEnd(0));

    // The run ends and closes the socket, which is the moment the lock is free.
    bench.endpoint.close(io);
    try testing.expect(client.waitForEnd(0));
}

test "a closed endpoint leaves no socket file, so a client learns nobody is there" {
    // A session that ended must not leave a path a client can connect to, and a
    // client already attached must read the end of the stream rather than wait
    // for a process that has gone. That is how `chock detach` learns the lock
    // is free without asking anybody.
    //
    // Mutation check: drop the `deleteFileAbsolute` in `close` and a client
    // connects to a socket with no listener behind it.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    const socket_path = try gpa.dupe(u8, bench.paths.socket);
    defer gpa.free(socket_path);

    const stream = try bench.attach(io);
    defer stream.close(io);

    bench.endpoint.close(io);

    var answers: [max_frame_bytes]u8 = undefined;
    var frames = Frames{ .buffer = &answers };
    try testing.expect(frames.next(stream.socket.handle, 0) == null);

    // And a new client is refused rather than left waiting.
    try testing.expectEqual(Answer.not_listening, ask(io, socket_path, 0, &answers));

    bench.paths.deinit();
    bench.tmp.cleanup();
}
