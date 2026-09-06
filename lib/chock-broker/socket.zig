//! The approval socket: the second implementation of `Broker.Waiter`, for a
//! session with nobody at its own keyboard.
//!
//! ## The wall, and the smallest thing that goes through it
//!
//! `Broker.request` writes an `approval.request` and then waits for an
//! `approval.response`. `Loop.run` holds the exclusive lock on the session log
//! for the whole session, so **nothing outside that process can append the
//! answer**. `src/approval.zig` went through that wall for one case, a person
//! at this process's own terminal, by answering inside `Waiter.wait`, which
//! runs in the process that already holds the lock. This file is the same trick
//! for every other case: the answer arrives over a unix socket instead of over
//! a keyboard, and it is still appended through the caller's own `locked`
//! handle.
//!
//! ## The broker does not have to own the log, and it does not have to append
//!
//! The broker is drawn as a process of its own, and the obvious reading is
//! that it takes the log with it. It does not have to, and it should not.
//!
//! What is missing today is not a second writer. It is a way for an **answer**
//! to reach the process that already holds the lock. The lock exists to make
//! exactly one process the owner of a session, and a transport that carried log
//! writes would put a second writer on the other end of it and would make
//! `Loop.run` ask permission for every turn it appends. **So the socket carries
//! the question and the answer, never a log write.** The lock holder keeps
//! writing, and a client that reaches it holds no handle on the log at all.
//!
//! That is also why nothing above `Broker.request` changes. `Waiter` was
//! already the one seam, `SystemWaiter` sleeps, `src/approval.zig` reads a
//! terminal, and this reads a socket. A caller still calls `request` and still
//! gets one `Outcome`.
//!
//! ## The socket is a trust boundary
//!
//! Anything that can reach it can approve an action, so three rules hold, and
//! each one is a test below:
//!
//! * **It lives beside the session log and never inside a workspace.** See
//!   `pathsFor`: a directory of its own next to the log, made `0o700`, in the
//!   session directory that no sandbox mount list names. The credential store
//!   rule is the precedent: never mounted, never reachable. A
//!   sandboxed tool call has a mount namespace that holds the workspace and the
//!   dev shell closure, so the path does not exist for it at all, and
//!   `test/sandbox/escape.zig` proves that with a real `Sandbox.spawn` against a
//!   socket the host can reach at the same moment.
//! * **A peer that is not this user is closed before it is read.** The
//!   operating system already gives the identity, so there is no token.
//!   `peerUid` reads it with `SO_PEERCRED` on Linux and `LOCAL_PEERCRED` on
//!   Darwin.
//! * **A client may say only what a person may say.** `decisionFrom` maps
//!   everything that is not a plain yes onto `refused_by_user`. Without it a
//!   client could write `allowed_by_policy` and claim the project's own table
//!   had permitted the act, which is a decision only the broker may reach.
//!
//! ## One format, which is the log's own
//!
//! `Broker.zig` promises that an approval travels as events and never over a
//! channel of its own. This keeps that promise: a question goes out as the
//! `approval.request` envelope exactly as the log holds it, and an answer comes
//! back as an `approval.response` envelope, one JSON object per line. Section
//! 14 already makes that envelope the frame for the unix socket and for server
//! sent events, so a client that can read a session log can answer one.
//!
//! **Two fields of the answer are ignored on purpose.** `responder` is stamped
//! here from the peer's own uid, because a name a client writes about itself is
//! a name nobody checked, and `id` is the log's to give.
//!
//! ## A peer that dies, and a session that dies
//!
//! Neither may leave the other waiting, and neither may leave the log in a
//! state a fold cannot read.
//!
//! * **A peer that dies mid question** is a read of zero bytes, or a write that
//!   fails. The peer is dropped and the question stays open with no answer,
//!   which is the same state a crash leaves and which the broker's own deadline
//!   then expires. Nothing partial is ever appended: an answer is appended only
//!   after a whole line has parsed, and `locked.append` writes one line or
//!   fails, which is what `lib/chock-proto/short_write_probe.zig` is for.
//! * **A session that dies** closes its listening socket with it, so a client
//!   blocked on a read gets the end of the stream rather than waiting forever.
//!   The socket file is removed by `close`, and a stale one left by a crash is
//!   removed by the next `open` on that path, so a session id is never wedged.
//! * **A write to a peer that has gone reports `EPIPE`, and the peer is
//!   dropped.** It does not raise `SIGPIPE` at this process, because
//!   `std.Io.Threaded.init` already installs a handler for that signal and
//!   `src/run.zig` holds a `Threaded` for the whole of every phase. So there is
//!   no signal disposition set here: a library that changed one would be
//!   changing the whole program's behaviour from the inside, and the test below
//!   pins the fault that matters, which is that one dead peer does not stop the
//!   session.
//!
//! ## What this is not
//!
//! It is not `/daemonize` and it is not the remote transport. There is no
//! `observe` stream here, no scope on a connection, and no HTTP. A client
//! attaches, is shown the open question, and answers it.

const std = @import("std");
const chock_proto = @import("chock-proto");

const Broker = @import("Broker.zig");
const diagnostic = @import("diagnostic.zig");
/// Why the broker refused an act, or could not carry one out. One type for
/// the whole module: see `chock-broker/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;
const event = chock_proto.event;

/// `chock_proto.storage.Locked` is not `pub`, so no file outside that one can
/// name it. This reaches the same type through the return type of
/// `Storage.lock`, which is public. `Broker.request` still takes
/// `locked: anytype`; this file needs the name because a `Waiter` holds a
/// pointer to the handle its caller took. `src/approval.zig` does the same.
const Locked = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

/// How many clients may be attached to one session at once.
///
/// Four, which is a terminal, a phone, and two spare. It is a bound and not a
/// target: every attached peer is polled and written to on every look, so an
/// unbounded list would be an unbounded cost on a loop that runs twenty times a
/// second. A fifth connection is accepted and closed at once, so a client
/// learns it was refused rather than hanging.
pub const max_peers: usize = 4;

/// The longest answer this reads from one peer before it gives up on that
/// peer.
///
/// An `approval.response` envelope is a few hundred bytes. Four kilobytes is
/// room for one that grew fields and far less than a client could use to make
/// this process hold memory on its behalf.
pub const max_answer_bytes: usize = 4096;

/// The name of the directory the socket sits in, appended to the session id.
/// A directory of its own, and not the socket file alone beside the log, for
/// one reason: **the directory's mode is the gate**. A unix socket's own file
/// mode is not honoured on every unix, and a directory nobody else may enter
/// cannot be walked into on any of them.
pub const dir_suffix = ".ctl";

/// The socket's own name inside that directory. One character, because a unix
/// socket path is bounded at `max_socket_path` and the session directory has
/// already spent most of it.
pub const socket_name = "s";

/// The longest unix socket path this machine really accepts.
///
/// **The body is `chock-proto/control.zig`'s**, beside `peerUid` and beside the
/// daemon socket that binds through the same call. This name stays where every
/// caller in this module already looks for it, the way `peerUid` below does.
pub const max_socket_path: usize = chock_proto.control.max_socket_path;

/// The address of a unix socket at `path`, or a refusal that names the path
/// and the bound it passed.
///
/// **Every socket of this module goes through this, the ones that bind and the
/// ones that connect**, because `std.Io` reads the path into `sun_path` on
/// either side. See `max_socket_path`.
///
/// The bound is `control.unixAddress`'s. This adds the one thing that call
/// cannot carry: a `Diagnostic` a person reads, naming the path and the number
/// it passed.
pub fn addressFor(
    path: []const u8,
    diag: ?*?Diagnostic,
) error{PathTooLong}!std.Io.net.UnixAddress {
    return chock_proto.control.unixAddress(path) catch {
        _ = diagnostic.note(diag, .{ .socket_path_too_long = .{
            .path = path,
            .bound = max_socket_path,
        } });
        return error.PathTooLong;
    };
}

/// The mode of that directory. Owner only. See `dir_suffix`.
pub const dir_mode: std.posix.mode_t = 0o700;

/// What the `responder` of an answer from this socket says, before the peer's
/// own uid is added.
///
/// **Where the answer came from, and never a name a client chose.** The uid is
/// worth writing where a user name is not, because the kernel is what said it:
/// see this file's own top comment.
pub const responder_prefix = "socket:";

/// Where one session's approval socket lives. The caller owns the strings.
pub const Paths = struct {
    gpa: std.mem.Allocator,
    /// The directory, made `0o700` by `Endpoint.open`.
    dir: []u8,
    /// The socket itself.
    socket: []u8,

    pub fn deinit(self: *Paths) void {
        self.gpa.free(self.dir);
        self.gpa.free(self.socket);
        self.* = undefined;
    }
};

/// Where the approval socket of session `id` in `session_dir` lives. Makes
/// nothing: see `Endpoint.open`.
pub fn pathsFor(
    gpa: std.mem.Allocator,
    session_dir: []const u8,
    id: []const u8,
) std.mem.Allocator.Error!Paths {
    const dir = try std.fmt.allocPrint(gpa, "{s}/{s}" ++ dir_suffix, .{ session_dir, id });
    errdefer gpa.free(dir);
    const socket = try std.fmt.allocPrint(gpa, "{s}/" ++ socket_name, .{dir});
    return .{ .gpa = gpa, .dir = dir, .socket = socket };
}

/// Make the control directory of one session, and make sure only this user can
/// enter it.
///
/// **Its own function because two sockets live in that directory now.** The
/// approval socket is one, and `chock-broker/handover.zig`'s is the other, and
/// either one may be the first to open. A second copy of this code would be a
/// second place the `0o700` gate could be got wrong, and the mode is the whole
/// boundary: see `dir_suffix`.
pub fn ensureDir(io: std.Io, dir_path: []const u8, diag: ?*?Diagnostic) Endpoint.OpenError!void {
    std.Io.Dir.createDirAbsolute(io, dir_path, .fromMode(dir_mode)) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => {
            _ = diagnostic.note(diag, .{ .socket_dir_not_made = .{ .path = dir_path, .err = err } });
            return error.SocketUnavailable;
        },
    };
    // The process umask narrows what `createDirAbsolute` asked for, and the
    // mode is the gate: see `dir_suffix`. So it is set again after the
    // fact, the same way `lib/chock-auth/paths.zig` does for a credential
    // file.
    // `iterate` is what makes the handle one `setPermissions` may be called
    // on: `std.Io.Dir.setPermissions` says so, and a handle opened without
    // it reaches the kernel as a bad descriptor.
    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true }) catch |err| {
        _ = diagnostic.note(diag, .{ .socket_dir_not_opened = .{ .path = dir_path, .err = err } });
        return error.SocketUnavailable;
    };
    dir.setPermissions(io, .fromMode(dir_mode)) catch |err| {
        dir.close(io);
        _ = diagnostic.note(diag, .{ .socket_dir_not_private = .{ .path = dir_path, .err = err } });
        return error.SocketUnavailable;
    };
    dir.close(io);
}

/// True when `handle` has something to read within `timeout_ms`.
///
/// **Public for `chock-broker/handover.zig` alone.** That file is the session's
/// other control socket and it reads a line the same way this one does. A
/// second copy of a poll wrapper is a second place a timeout sign can be got
/// wrong.
pub fn readable(handle: std.posix.fd_t, timeout_ms: i32) bool {
    var fds = [_]std.posix.pollfd{.{ .fd = handle, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = std.posix.poll(&fds, timeout_ms) catch return false;
    return ready != 0;
}

/// Write the whole of `bytes` to `handle`. False when the peer has gone.
///
/// A short write is not a failure: a socket takes what fits in its buffer and
/// says how much. This keeps going until the buffer is empty, which is what
/// makes a question larger than one socket buffer arrive whole. See
/// `lib/chock-proto/short_write_probe.zig` for the same fact about a file.
///
/// Public for the same reason `readable` is.
pub fn writeAll(handle: std.posix.fd_t, bytes: []const u8) bool {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = std.posix.system.write(handle, bytes.ptr + sent, bytes.len - sent);
        const written: isize = @bitCast(@as(usize, @bitCast(rc)));
        if (written > 0) {
            sent += @intCast(written);
            continue;
        }
        switch (std.posix.errno(rc)) {
            // Interrupted before anything was written. Nothing is lost.
            .INTR => continue,
            // The peer is not reading and the buffer is full. A client that
            // cannot take a question it asked for is one this session does not
            // wait on.
            .AGAIN => return false,
            else => return false,
        }
    }
    return true;
}

/// One attached client.
const Peer = struct {
    /// The connected socket, or null for a slot nothing is using.
    handle: ?std.posix.fd_t = null,
    /// The uid the kernel said is on the other end. See `peerUid`.
    uid: std.posix.uid_t = 0,
    /// The id of the question this peer has already been shown. A question is
    /// sent once per peer, however many times the broker gives control away.
    shown: ?u64 = null,
    /// What has arrived and does not yet end a line.
    filled: usize = 0,
    buffer: [max_answer_bytes]u8 = undefined,
};

/// The listening end of one session's approval socket.
///
/// **Only the process that holds the session lock builds one of these.** It is
/// the owner of the session, and this is how everything else reaches it.
pub const Endpoint = struct {
    server: std.Io.net.Server,
    /// Borrowed from the caller's `Paths`, for `close` to remove.
    socket_path: []const u8,
    /// The uid this process runs as. Any other peer is closed at once.
    owner_uid: std.posix.uid_t,
    peers: [max_peers]Peer = @splat(.{}),
    /// How many peers were closed because they were somebody else, or because
    /// there was no room. Counted rather than only printed, so a test can pin
    /// that a refusal happened and not merely that no answer arrived.
    refused: usize = 0,
    /// Why the first refused peer was refused, for the caller to report.
    /// **`acceptPending` has no error to give back**: it runs inside the
    /// waiter's own look and every refusal it makes is the right answer, so
    /// the reason has nowhere else to go. A field rather than a print, for
    /// the reason `failed` on `Waiter` is one.
    refusal: ?Diagnostic = null,

    pub const OpenError = error{
        /// The path is longer than a unix socket path may be, which is not the
        /// same number on both platforms: see `max_socket_path`. A session
        /// directory deep enough to reach this is a session that cannot be
        /// attached to, and it is not a failure of the session itself.
        PathTooLong,
        /// The directory or the socket could not be made.
        SocketUnavailable,
    };

    /// Make the directory, remove any socket a crash left there, and listen.
    ///
    /// **A stale socket is removed rather than refused.** A file left by a
    /// process that is gone would otherwise wedge that session id forever, and
    /// the directory it sits in is one this user alone can enter, so nothing
    /// else could have put it there.
    pub fn open(io: std.Io, paths: Paths, diag: ?*?Diagnostic) OpenError!Endpoint {
        const address = try addressFor(paths.socket, diag);

        try ensureDir(io, paths.dir, diag);

        std.Io.Dir.deleteFileAbsolute(io, paths.socket) catch |err| switch (err) {
            error.FileNotFound => {},
            else => {
                _ = diagnostic.note(diag, .{ .socket_not_removed = .{ .path = paths.socket, .err = err } });
                return error.SocketUnavailable;
            },
        };

        // **Twice `max_peers`, and the difference is what a refused client is
        // told.** The kernel queue holds connections nobody has accepted yet.
        // At exactly `max_peers` a fifth client is refused by the kernel before
        // `acceptPending` ever sees it, which reads to that client as a session
        // that is not listening at all: measured on Darwin, where the queue
        // refuses rather than waits. With room for it, Chock accepts it, counts
        // it, and closes it, so the client learns it was turned away and not
        // that the session had gone.
        const server = address.listen(io, .{ .kernel_backlog = max_peers * 2 }) catch |err| {
            _ = diagnostic.note(diag, .{ .socket_not_opened = .{ .path = paths.socket, .err = err } });
            return error.SocketUnavailable;
        };

        return .{
            .server = server,
            .socket_path = paths.socket,
            .owner_uid = std.posix.system.getuid(),
        };
    }

    /// Close every peer, stop listening, and remove the socket file.
    pub fn close(self: *Endpoint, io: std.Io) void {
        for (&self.peers) |*peer| self.dropPeer(io, peer);
        self.server.deinit(io);
        // A session whose directory has already gone is not a fault worth
        // reporting: the file is scratch, and the next `open` removes a stale
        // one anyway.
        std.Io.Dir.deleteFileAbsolute(io, self.socket_path) catch {};
    }

    /// How many clients are attached right now.
    ///
    /// **This is what decides whether a question may wait at all.** See
    /// `timeoutMs`: a session with nobody attached and nobody at a keyboard has
    /// nobody to ask, and holding the session lock for five minutes over a
    /// question that cannot be answered is the fault this whole file exists to
    /// remove, not one to add.
    pub fn attached(self: *const Endpoint) usize {
        var count: usize = 0;
        for (self.peers) |peer| {
            if (peer.handle != null) count += 1;
        }
        return count;
    }

    /// Take every connection the kernel already holds, and refuse the ones that
    /// may not be here. Never waits.
    pub fn acceptPending(self: *Endpoint, io: std.Io) void {
        // Bounded by the number of slots plus the ones that get refused, so one
        // client reconnecting in a loop cannot hold this call.
        for (0..max_peers * 2) |_| {
            if (!readable(self.server.socket.handle, 0)) return;
            const stream = self.server.accept(io) catch return;

            const uid = peerUid(stream.socket.handle) orelse {
                // The kernel would not say who this is, so this cannot be shown
                // a diff or believed about an answer.
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

            const slot = self.freeSlot() orelse {
                self.refused += 1;
                stream.close(io);
                continue;
            };
            slot.* = .{ .handle = stream.socket.handle, .uid = uid };
        }
    }

    fn freeSlot(self: *Endpoint) ?*Peer {
        for (&self.peers) |*peer| {
            if (peer.handle == null) return peer;
        }
        return null;
    }

    fn dropPeer(self: *Endpoint, io: std.Io, peer: *Peer) void {
        _ = self;
        const handle = peer.handle orelse return;
        const stream = std.Io.net.Stream{ .socket = .{ .handle = handle, .address = .{ .ip4 = .loopback(0) } } };
        stream.close(io);
        peer.* = .{};
    }
};

/// A `Broker.Waiter` that asks whatever has attached to this session's socket.
///
/// **The answer is appended through `locked`**, the same handle the broker is
/// writing the question with, exactly as `src/approval.zig` does. See this
/// file's own top comment: that is why no lock changes.
pub const Waiter = struct {
    gpa: std.mem.Allocator,
    /// Read from, to find the open question and to read it back for a client.
    /// The broker reads it too, through its own replay, and a replay takes no
    /// lock.
    storage: chock_proto.storage.Storage,
    /// The caller's proof it holds the exclusive lock. **The only handle.**
    locked: *Locked,
    endpoint: *Endpoint,
    /// Whether a stop has been asked for. A field so a test can answer it
    /// without raising a real signal at the whole test binary, the same shape
    /// `src/approval.zig` uses and for the same reason.
    stop: *const fn () bool = neverStopped,
    /// What spends the budget when there is nothing to poll. A field for the
    /// same reason `stop` is one: **no test in this suite measures elapsed
    /// time**, so the only way to pin that a look with nobody attached really
    /// does wait is to pin that the budget reaches the thing that waits.
    nap: *const fn (budget_ms: u64) void = pollNap,
    /// The first fault that stopped this from answering, for the caller to
    /// report. A `Waiter` cannot give an error back to the broker.
    failed: ?anyerror = null,
    /// The same fault, in the words a person reads. `failed` says a step
    /// went wrong and this says which step, and what it answered.
    diagnostic: ?Diagnostic = null,

    pub fn waiter(self: *Waiter) Broker.Waiter {
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
        const self: *Waiter = @ptrCast(@alignCast(ptr));
        return self.step(io, budget_ms);
    }

    /// One look: read the stop flag, take new clients, show the open question
    /// to whoever has not seen it, and read for at most the budget.
    ///
    /// Its own function, taking and giving ordinary values, so every test below
    /// drives the same code the broker drives.
    pub fn step(self: *Waiter, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        // **First, and before anything is sent.** A session that is being
        // stopped is not one that should show a question it cannot finish.
        if (self.stop()) return .canceled;

        self.endpoint.acceptPending(io);

        const open = Broker.openRequest(self.gpa, io, self.storage) catch |err| {
            // The question was appended moments ago through the handle this
            // holds, so a log that cannot be read back is a broken log and not
            // an unanswered question. Waiting out the deadline would hold the
            // session lock over a fault that is already certain.
            self.report(err, "the session log could not be read, so nobody could be asked");
            return .canceled;
        } orelse {
            // Nothing to ask about. The budget is still spent, so a caller that
            // drives this on an empty log does not turn into a busy loop.
            self.idle(budget_ms);
            return .slept;
        };

        self.show(io, open);
        return self.readAnswers(io, open, budget_ms);
    }

    /// Send the open question to every peer that has not been shown it.
    fn show(self: *Waiter, io: std.Io, request_id: u64) void {
        var line: ?[]u8 = null;
        defer if (line) |owned| self.gpa.free(owned);

        for (&self.endpoint.peers) |*peer| {
            if (peer.handle == null) continue;
            if (peer.shown != null and peer.shown.? == request_id) continue;

            if (line == null) {
                line = self.questionLine(io, request_id) catch |err| {
                    self.report(err, "the approval could not be read back out of the session log");
                    return;
                };
            }
            if (writeAll(peer.handle.?, line.?)) {
                peer.shown = request_id;
            } else {
                // The client went away between attaching and being asked. That
                // is not a fault of this session: drop it and carry on.
                self.endpoint.dropPeer(io, peer);
            }
        }
    }

    /// The `approval.request` envelope of `request_id`, as one line with its
    /// newline. Caller owns it.
    fn questionLine(self: *Waiter, io: std.Io, request_id: u64) ![]u8 {
        var replay = try self.storage.replay(self.gpa, io, request_id);
        defer replay.deinit();

        const parsed = try replay.next(io) orelse return error.RequestNotInTheLog;
        defer parsed.deinit();
        if (parsed.value.event != .approval_request) return error.RequestNotInTheLog;

        const text = try event.toJson(self.gpa, parsed.value);
        defer self.gpa.free(text);
        return std.fmt.allocPrint(self.gpa, "{s}\n", .{text});
    }

    /// Wait at most the budget for a line from any peer, and record the first
    /// answer that names the open question.
    fn readAnswers(
        self: *Waiter,
        io: std.Io,
        request_id: u64,
        budget_ms: u64,
    ) Broker.Waiter.Wake {
        var fds: [max_peers]std.posix.pollfd = undefined;
        var slots: [max_peers]usize = undefined;
        var count: usize = 0;
        for (&self.endpoint.peers, 0..) |*peer, index| {
            const handle = peer.handle orelse continue;
            // **Checked here and not after the poll.** A peer that filled the
            // whole buffer with no line break in it is not answering the
            // question: an `approval.response` envelope is a few hundred bytes.
            // Once it stops sending, the poll never names it again, so a check
            // that only ran on a readable peer would leave the slot held
            // forever and keep a client that would answer out.
            if (peer.filled == peer.buffer.len) {
                self.endpoint.dropPeer(io, peer);
                continue;
            }
            fds[count] = .{ .fd = handle, .events = std.posix.POLL.IN, .revents = 0 };
            slots[count] = index;
            count += 1;
        }
        if (count == 0) {
            // Nobody is attached. The budget is still spent, so the broker's
            // own deadline is what ends the wait and this does not spin.
            self.idle(budget_ms);
            return .slept;
        }

        const timeout: i32 = if (budget_ms > std.math.maxInt(i32))
            std.math.maxInt(i32)
        else
            @intCast(budget_ms);
        // A poll that cannot run says nothing about the peers, and looking
        // again at once would spin. Treat it as a look that found nothing.
        const ready = std.posix.poll(fds[0..count], timeout) catch return .slept;
        if (ready == 0) return .slept;

        for (fds[0..count], slots[0..count]) |entry, index| {
            if (entry.revents == 0) continue;
            const peer = &self.endpoint.peers[index];
            if (self.readOne(io, peer, request_id)) |decision| {
                return self.record(io, request_id, decision, peer.uid);
            }
        }
        return .slept;
    }

    /// Read what one peer has to say. Null when it said nothing this call, or
    /// nothing this request can act on.
    fn readOne(
        self: *Waiter,
        io: std.Io,
        peer: *Peer,
        request_id: u64,
    ) ?event.ApprovalDecision {
        const handle = peer.handle orelse return null;
        // A full buffer never reaches here: `readAnswers` drops that peer
        // before it polls, and this asserts the two agree.
        const room = peer.buffer[peer.filled..];
        std.debug.assert(room.len > 0);

        const read = std.posix.read(handle, room) catch |err| switch (err) {
            // `poll` said there was something and there was not. Nothing was
            // lost, so look again rather than drop a client that is fine.
            error.WouldBlock => return null,
            else => {
                self.endpoint.dropPeer(io, peer);
                return null;
            },
        };
        if (read == 0) {
            // The end of the stream: the client is gone. The question stays
            // open, which is what a crash at this moment leaves too.
            self.endpoint.dropPeer(io, peer);
            return null;
        }
        peer.filled += read;

        const line = peer.buffer[0..peer.filled];
        const end = std.mem.indexOfScalar(u8, line, '\n') orelse return null;
        const said = line[0..end];
        // Whatever came after the line break is a second frame this build has
        // no use for: one question is answered once.
        peer.filled = 0;

        return self.decisionFrom(said, request_id);
    }

    /// What one line from a peer decides about `request_id`, or null when it
    /// decides nothing.
    ///
    /// **A client may say only what a person may say.** See this file's own top
    /// comment: `allowed_by_policy` is a decision only the project's own table
    /// can reach, and a client that named it would be claiming the table had
    /// permitted the act. So a plain yes is the only thing that permits, and
    /// everything else is a refusal, which is the rule `src/approval.zig`
    /// already keeps for a person's typed answer.
    fn decisionFrom(
        self: *Waiter,
        said: []const u8,
        request_id: u64,
    ) ?event.ApprovalDecision {
        var parsed = event.fromJson(self.gpa, said) catch return null;
        defer parsed.deinit();

        if (parsed.value.event != .approval_response) return null;
        const answer = parsed.value.event.approval_response;
        // An answer to some other question is not an answer to this one, and
        // more than one can be open at a time: see `Broker.findAnswer`.
        if (answer.request_id != request_id) return null;

        return switch (answer.decision) {
            .approved_by_user => .approved_by_user,
            else => .refused_by_user,
        };
    }

    /// Append the answer through the caller's own handle. See this file's own
    /// top comment: this one line is the whole trick.
    ///
    /// **`action` is read back out of the request.** A `Waiter.wait` is
    /// handed only `io` and a budget, never the `Request` that
    /// `Broker.askTheHuman` already answered every other decision out of. See
    /// `Broker.requestAction` and `src/approval.zig`'s `Terminal.record`,
    /// which reads it back the same way for the same reason.
    fn record(
        self: *Waiter,
        io: std.Io,
        request_id: u64,
        decision: event.ApprovalDecision,
        uid: std.posix.uid_t,
    ) Broker.Waiter.Wake {
        const responder = std.fmt.allocPrint(
            self.gpa,
            responder_prefix ++ "{d}",
            .{uid},
        ) catch |err| {
            self.report(err, "the answer could not be recorded");
            return .canceled;
        };
        defer self.gpa.free(responder);

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

    /// Spend the budget with nothing to poll. A `wait` that came back at once
    /// with nothing waited for would turn `Broker.request` into a busy loop for
    /// the whole deadline, which is the fault the `Wake` enum was added for.
    fn idle(self: *Waiter, budget_ms: u64) void {
        self.nap(budget_ms);
    }

    /// Say what went wrong, once, and keep the first one for the caller.
    fn report(self: *Waiter, err: anyerror, what: []const u8) void {
        // `what` is a literal of this file, so the diagnostic borrows it and
        // copies nothing.
        _ = diagnostic.note(&self.diagnostic, .{ .waiter_step_failed = .{ .path = what, .err = err } });
        if (self.failed == null) self.failed = err;
    }
};

/// Two waiters, both of which may answer.
///
/// A person at the keyboard **and** a phone attached is the case this is for,
/// and it is the ordinary one: `chock run` in a terminal that somebody also
/// attached a client to. The first is looked at with no budget at all, so it is
/// a plain non blocking look, and the whole budget goes to the second, which is
/// the one that can wait on a descriptor. Either may end the wait.
pub const Pair = struct {
    first: Broker.Waiter,
    second: Broker.Waiter,

    pub fn waiter(self: *Pair) Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        const self: *Pair = @ptrCast(@alignCast(ptr));
        return self.first.nowMs(io);
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        const self: *Pair = @ptrCast(@alignCast(ptr));
        // **A cancellation from either one ends the wait.** A stop that only
        // one half noticed is a session that keeps holding the lock.
        if (self.first.wait(io, 0) == .canceled) return .canceled;
        return self.second.wait(io, budget_ms);
    }
};

/// How long one approval waits for an answer.
///
/// **Zero when there is nobody to ask, and that is a refusal.** A question
/// nobody can answer must not hold the session lock for five minutes first:
/// the broker expires a request whose deadline has passed on its first look,
/// with no wait at all.
///
/// There are two ways to have somebody, and a session needs only one of them:
/// a person at this process's own terminal, or a client already attached to
/// this session's socket. **Already attached, measured when the question is
/// asked**, and not "might attach later": a session nobody is watching has to
/// stop instead of holding the lock all night, and a client that attaches after
/// the question was written has the log to read it out of.
pub fn timeoutMs(at_terminal: bool, attached: usize) i64 {
    if (at_terminal or attached > 0) return Broker.default_timeout_ms;
    return 0;
}

/// The uid on the other end of a connected unix socket, or null when the
/// kernel would not say.
///
/// The operating system already gives the identity, so there is no token. The
/// two platforms spell it differently and mean the same thing.
///
/// **One implementation, and it lives in `chock-proto`.** The same check guards
/// `src/daemon.zig`'s control socket and `src/serve.zig`'s browser socket.
/// `src/serve.zig` is a pure client of the daemon, and its own test fails the
/// build if it imports `chock-broker`, so the body sits below both modules.
/// Two copies of a security check drift apart. This name stays where every
/// caller in this module already looks for it.
pub const peerUid = chock_proto.control.peerUid;

fn neverStopped() bool {
    return false;
}

/// The real nap: a `poll` over no descriptors, which is a sleep that the
/// process's own signals still reach.
fn pollNap(budget_ms: u64) void {
    if (budget_ms == 0) return;
    var nothing: [0]std.posix.pollfd = .{};
    const timeout: i32 = if (budget_ms > std.math.maxInt(i32))
        std.math.maxInt(i32)
    else
        @intCast(budget_ms);
    _ = std.posix.poll(&nothing, timeout) catch {};
}

const testing = std.testing;

/// A directory below `TMPDIR`, and socket paths of an exact length inside it.
///
/// **`std.testing.tmpDir` makes its directory below the build directory, and on
/// macos inside a Nix build that is already 112 bytes for a session socket.**
/// What `max_socket_path` bounds is the whole path, so a bench that cannot
/// build a path of exactly the bound proves nothing about the bound.
/// `src/detach.zig`'s own tests make their directory the same way and give the
/// measurements.
///
/// **Public for `chock-broker/handover.zig`'s tests alone**, which bind the
/// session's other control socket and have to test the same boundary. The same
/// reason `readable` and `writeAll` are public.
pub const BoundBench = struct {
    gpa: std.mem.Allocator,
    parent: std.Io.Dir,
    sub: [sub_len]u8,
    dir_path: []u8,

    /// The same count `std.testing.tmpDir` uses, so a name here is as unlikely
    /// to collide as one there.
    const random_bytes_count = 12;
    const sub_len = std.base64.url_safe.Encoder.calcSize(random_bytes_count);

    /// Make the directory, or answer `error.SkipZigTest` on a machine where no
    /// session socket could live in it at all.
    pub fn open(gpa: std.mem.Allocator, io: std.Io) !BoundBench {
        const root = root: {
            const given = std.process.Environ.getPosix(testing.environ, "TMPDIR") orelse "/tmp";
            const trimmed = std.mem.trimEnd(u8, given, "/");
            break :root if (trimmed.len == 0) "/" else trimmed;
        };

        var self: BoundBench = undefined;
        self.gpa = gpa;
        var random_bytes: [random_bytes_count]u8 = undefined;
        io.random(&random_bytes);
        _ = std.base64.url_safe.Encoder.encode(&self.sub, &random_bytes);

        self.dir_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ root, &self.sub });
        errdefer gpa.free(self.dir_path);
        // A separator and one character of file name. A machine with less room
        // than that holds no session socket at all, and a skip is the honest
        // answer rather than a failure.
        if (self.dir_path.len + 2 > max_socket_path) return error.SkipZigTest;

        self.parent = try std.Io.Dir.cwd().openDir(io, root, .{});
        errdefer self.parent.close(io);
        var made = try self.parent.createDirPathOpen(io, &self.sub, .{});
        made.close(io);
        return self;
    }

    /// A socket path of exactly `want` bytes in that directory. The caller owns
    /// the strings, and `Paths.deinit` releases them.
    pub fn pathsOfLength(self: *const BoundBench, want: usize) !Paths {
        const dir = try self.gpa.dupe(u8, self.dir_path);
        errdefer self.gpa.free(dir);
        const socket_path = try self.gpa.alloc(u8, want);
        @memcpy(socket_path[0..dir.len], dir);
        socket_path[dir.len] = '/';
        @memset(socket_path[dir.len + 1 ..], 'n');
        return .{ .gpa = self.gpa, .dir = dir, .socket = socket_path };
    }

    pub fn cleanup(self: *BoundBench, io: std.Io) void {
        self.parent.deleteTree(io, &self.sub) catch {};
        self.parent.close(io);
        self.gpa.free(self.dir_path);
        self.* = undefined;
    }
};

/// The name of one decision, without the words an `unknown` carries. A test
/// reads the log back after the replay that parsed it has ended, and a name
/// outlives that parse where a borrowed string does not.
const Decision = std.meta.Tag(event.ApprovalDecision);

/// A socket, its directory, and the temporary directory both sit in.
const Bench = struct {
    gpa: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    paths: Paths,
    endpoint: Endpoint,

    fn init(gpa: std.mem.Allocator, io: std.Io) !Bench {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const dir = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);

        var paths = try pathsFor(gpa, dir, "01SOCKET");
        errdefer paths.deinit();

        const endpoint = try Endpoint.open(io, paths, null);
        return .{ .gpa = gpa, .tmp = tmp, .paths = paths, .endpoint = endpoint };
    }

    fn deinit(self: *Bench, io: std.Io) void {
        self.endpoint.close(io);
        self.paths.deinit();
        self.tmp.cleanup();
    }

    /// Attach a client, the way `chock approve` would.
    fn attach(self: *Bench, io: std.Io) !std.Io.net.Stream {
        const address = try addressFor(self.paths.socket, null);
        return address.connect(io);
    }
};

/// A policy that asks a person about everything.
const ask_everything: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .decision = .ask },
    \\        },
    \\    },
    \\}
;

fn testRequest() Broker.Request {
    return .{
        .action = "workspace.apply",
        .summary = "move 3 objects and set refs/chock/01SOCKET",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .model_alias = "main",
        .tool = "request_action",
        .tool_call_id = "call1",
        .timeout_ms = Broker.default_timeout_ms,
    };
}

/// Write one answer frame the way a client with the `approve` scope would.
fn sendAnswer(
    gpa: std.mem.Allocator,
    stream: std.Io.net.Stream,
    request_id: u64,
    decision: event.ApprovalDecision,
) !void {
    const text = try event.toJson(gpa, .{
        .id = 0,
        .session = "01SOCKET",
        .time_ms = 0,
        .event = .{
            .approval_response = .{
                .request_id = request_id,
                .decision = decision,
                // A name this client made up. The endpoint ignores it: see
                // `Waiter.record`.
                .responder = "somebody",
            },
        },
    });
    defer gpa.free(text);
    try testing.expect(writeAll(stream.socket.handle, text));
    try testing.expect(writeAll(stream.socket.handle, "\n"));
}

/// Read one whole line from a client's end of the socket, with a bound.
fn readLine(stream: std.Io.net.Stream, buffer: []u8) ![]u8 {
    var filled: usize = 0;
    while (filled < buffer.len) {
        // One second is not a measurement of anything: it is the bound that
        // makes a test that would otherwise hang fail instead.
        if (!readable(stream.socket.handle, 1000)) return error.NothingArrived;
        const read = try std.posix.read(stream.socket.handle, buffer[filled..]);
        if (read == 0) return error.PeerClosed;
        filled += read;
        if (std.mem.indexOfScalar(u8, buffer[0..filled], '\n')) |end| return buffer[0..end];
    }
    return error.LineTooLong;
}

/// What one end to end drive of the broker with a socket `Waiter` came back
/// with.
const Drive = struct {
    outcome: ?Broker.Outcome,
    failure: ?anyerror,
    answers: []Decision,
    questions: usize,
    gpa: std.mem.Allocator,

    fn deinit(self: *Drive) void {
        self.gpa.free(self.answers);
    }
};

/// Read every approval record out of a log.
fn readBack(gpa: std.mem.Allocator, io: std.Io, store: chock_proto.storage.Storage) !Drive {
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
    return .{
        .outcome = null,
        .failure = null,
        .answers = try answers.toOwnedSlice(gpa),
        .questions = questions,
        .gpa = gpa,
    };
}

test "a client that attaches is shown the open question and its answer reaches the log" {
    // The whole point of this file in one drive: a process with no terminal
    // writes a question, a client that is not it reads that question off a
    // socket, and the answer it sends becomes an `approval.response` in the
    // log. Before this, that answer had nowhere to arrive.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const client = try bench.attach(io);
    defer client.close(io);

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    // The question is written by `request`, so the client is answered from
    // inside the wait. `on_wait` is the seam the broker's own tests use; here
    // the client is driven by hand between two `step` calls instead, so the
    // whole path runs with no thread and no timing.
    const request_id = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "workspace.apply",
        .summary = "move 3 objects",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 1);

    // One look: the client is accepted and shown the question.
    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 0));
    try testing.expectEqual(@as(usize, 1), bench.endpoint.attached());

    var line_buffer: [8192]u8 = undefined;
    const shown = try readLine(client, &line_buffer);
    // It is the log's own envelope, with the request's own id, and it holds
    // everything a client has to show.
    try testing.expect(std.mem.indexOf(u8, shown, "approval.request") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "workspace.apply") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "a1b2c3 fix the parser") != null);
    var parsed = try event.fromJson(gpa, shown);
    defer parsed.deinit();
    try testing.expectEqual(request_id, parsed.value.id);

    // The client answers, and the next look writes it down.
    try sendAnswer(gpa, client, request_id, .approved_by_user);
    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 1000));

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), result.answers.len);
    try testing.expectEqual(Decision.approved_by_user, result.answers[0]);

    // And the record says where the answer came from, not what the client
    // called itself.
    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    var responder_seen: bool = false;
    while (try replay.next(io)) |line| {
        defer line.deinit();
        if (line.value.event != .approval_response) continue;
        try testing.expect(std.mem.startsWith(u8, line.value.event.approval_response.responder, responder_prefix));
        try testing.expect(!std.mem.eql(u8, line.value.event.approval_response.responder, "somebody"));
        responder_seen = true;
    }
    try testing.expect(responder_seen);
}

test "a whole broker request is answered over the socket, and the outcome permits" {
    // The same path with `Broker.request` driving it rather than a test calling
    // `step`. What is pinned is that a real `request` ends with
    // `approved_by_user` from a client that is not the process holding the
    // lock, which is the fact every one of the four blocked pieces of work
    // needed and none of them could have.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const client = try bench.attach(io);
    defer client.close(io);

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    // A thread would be the other way to do this, and this file will not use
    // one: the tool path forks, and a forked process carries only the calling
    // thread. So the client answers from inside the broker's own wait, through
    // the seam the broker already has for exactly that.
    const Answerer = struct {
        gpa: std.mem.Allocator,
        io: std.Io,
        store: chock_proto.storage.Storage,
        client: std.Io.net.Stream,
        inner: *Waiter,
        line_buffer: [8192]u8 = undefined,
        failed: ?anyerror = null,

        fn waiter(self: *@This()) Broker.Waiter {
            return .{ .ptr = self, .vtable = &.{ .nowMs = nowMs, .wait = wait } };
        }

        fn nowMs(ptr: *anyopaque, io_inner: std.Io) i64 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.inner.waiter().nowMs(io_inner);
        }

        fn wait(ptr: *anyopaque, io_inner: std.Io, budget_ms: u64) Broker.Waiter.Wake {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            // Let the endpoint accept and show first.
            const first = self.inner.step(io_inner, 0);
            if (first == .canceled) return first;
            // Then be the client: read the question and answer it.
            const shown = readLine(self.client, &self.line_buffer) catch |err| {
                if (self.failed == null) self.failed = err;
                return .canceled;
            };
            var parsed = event.fromJson(self.gpa, shown) catch |err| {
                if (self.failed == null) self.failed = err;
                return .canceled;
            };
            defer parsed.deinit();
            sendAnswer(self.gpa, self.client, parsed.value.id, .approved_by_user) catch |err| {
                if (self.failed == null) self.failed = err;
                return .canceled;
            };
            // And read it back in, which is what the real waiter does on its
            // next look.
            return self.inner.step(io_inner, budget_ms);
        }
    };

    var answerer = Answerer{
        .gpa = gpa,
        .io = io,
        .store = store,
        .client = client,
        .inner = &socket_waiter,
    };

    const policy = try @import("chock-policy").table.Table.parse(gpa, ask_everything, null);
    defer @import("chock-policy").table.Table.destroy(gpa, policy);

    const broker = Broker{ .policy = policy, .waiter = answerer.waiter() };
    const outcome = try broker.request(gpa, io, store, &locked, testRequest(), null);
    if (answerer.failed) |err| return err;

    try testing.expectEqual(Broker.Outcome.approved_by_user, outcome);
    try testing.expect(outcome.permits());

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), result.questions);
    try testing.expectEqual(@as(usize, 1), result.answers.len);
    try testing.expectEqual(Decision.approved_by_user, result.answers[0]);
}

test "a client cannot claim the policy allowed it, and cannot claim a review did" {
    // The trust boundary at its narrowest. `Broker.Outcome.allowed_by_policy`
    // permits, and it is a statement about the project's own table, which is
    // kept beyond every agent's reach. A client that could write that decision
    // into the log would be a client that can forge the table's answer. Every
    // decision that is not a plain yes becomes a refusal instead, and the
    // refusal is recorded so a person reads what happened.
    const gpa = testing.allocator;
    const io = testing.io;

    const claimed = [_]event.ApprovalDecision{
        .allowed_by_policy,
        .approved_by_review,
        .{ .unknown = "approved_by_everyone" },
        // A client cannot grant itself the session wide memory either: that
        // word is for the person at this terminal alone, over the one handle
        // `src/approval.zig` holds, and a socket peer is never that.
        .approved_by_user_for_session,
    };

    for (claimed) |decision| {
        var bench = try Bench.init(gpa, io);
        defer bench.deinit(io);

        var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        const client = try bench.attach(io);
        defer client.close(io);

        var socket_waiter = Waiter{
            .gpa = gpa,
            .storage = store,
            .locked = &locked,
            .endpoint = &bench.endpoint,
        };

        const request_id = try locked.append(gpa, io, .{ .approval_request = .{
            .action = "workspace.apply",
            .summary = "move 3 objects",
            .detail = "",
            .reason = "the session made a commit",
            .agent_kind = "coder",
            .spawn_chain = &.{},
            .timeout_at_ms = 0,
            .tool_call_id = "call1",
        } }, 1);

        _ = socket_waiter.step(io, 0);
        var line_buffer: [8192]u8 = undefined;
        _ = try readLine(client, &line_buffer);
        try sendAnswer(gpa, client, request_id, decision);
        _ = socket_waiter.step(io, 1000);

        var result = try readBack(gpa, io, store);
        defer result.deinit();
        try testing.expectEqual(@as(usize, 1), result.answers.len);
        try testing.expectEqual(Decision.refused_by_user, result.answers[0]);
    }
}

test "an answer to another question is not an answer to this one" {
    // More than one request can be open at a time, because one turn holds more
    // than one tool call and a subagent can ask while its parent waits. A
    // waiter that took whatever arrived would hand one request the answer a
    // person gave to another one.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const client = try bench.attach(io);
    defer client.close(io);

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    const request_id = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "git.push",
        .summary = "push a1b2c3",
        .detail = "",
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 1);

    _ = socket_waiter.step(io, 0);
    var line_buffer: [8192]u8 = undefined;
    _ = try readLine(client, &line_buffer);

    // An id that is not this question's.
    try sendAnswer(gpa, client, request_id + 4096, .approved_by_user);
    _ = socket_waiter.step(io, 1000);

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    // Nothing was written. The question is still open, which is what lets the
    // deadline expire it and what lets the right answer still arrive.
    try testing.expectEqual(@as(usize, 0), result.answers.len);
    try testing.expectEqual(@as(usize, 1), result.questions);
}

test "a client that dies mid question leaves a log a fold can still read" {
    // The client is shown the question and then goes away without answering,
    // which is what a phone losing signal and a `chock approve` somebody
    // pressed Ctrl-C in both look like. Two facts: the session carries on, and
    // the log holds one open question and nothing partial.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    _ = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "workspace.apply",
        .summary = "move 3 objects",
        .detail = "",
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 1);

    {
        const client = try bench.attach(io);
        _ = socket_waiter.step(io, 0);
        try testing.expectEqual(@as(usize, 1), bench.endpoint.attached());
        var line_buffer: [8192]u8 = undefined;
        _ = try readLine(client, &line_buffer);
        client.close(io);
    }

    // The session looks again, notices the end of the stream, and carries on.
    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 10));
    try testing.expectEqual(@as(usize, 0), bench.endpoint.attached());
    try testing.expect(socket_waiter.failed == null);

    // And another look, and another: a dropped peer must not become a busy
    // loop or a second drop of the same slot.
    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 0));
    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 0));

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), result.questions);
    try testing.expectEqual(@as(usize, 0), result.answers.len);
    // The fold read the whole log, so nothing half written is in it.
    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |line| line.deinit();
    try testing.expect(!replay.truncated());
}

test "a client that goes away before it is shown anything does not end the session" {
    // The same death one moment earlier: attached, and gone before the question
    // was written, so the write to it is what finds out. **A client must not be
    // able to fault a session by disconnecting at the right moment**, because
    // then attaching one would be a way to end somebody else's work. What is
    // pinned is that the write failing drops that one peer, records no fault,
    // and leaves the session running.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    {
        const client = try bench.attach(io);
        // Accepted, and then gone with nothing sent to it yet.
        _ = socket_waiter.step(io, 0);
        try testing.expectEqual(@as(usize, 1), bench.endpoint.attached());
        client.close(io);
    }

    _ = try locked.append(gpa, io, .{
        .approval_request = .{
            .action = "workspace.apply",
            .summary = "move 3 objects",
            // Large enough that the write cannot fit in one socket buffer with a
            // closed peer, so the failure is reached rather than swallowed.
            .detail = "x" ** 4096,
            .reason = "the session made a commit",
            .agent_kind = "coder",
            .spawn_chain = &.{},
            .timeout_at_ms = 0,
            .tool_call_id = "call1",
        },
    }, 1);

    // This line is the test: reaching it at all means no signal ended the
    // process.
    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 10));
    try testing.expect(socket_waiter.failed == null);
    try testing.expectEqual(@as(usize, 0), bench.endpoint.attached());
}

test "a session that dies does not leave a client waiting forever" {
    // The other direction. A client blocked on a read must learn that the
    // session has gone, or a `chock approve` on somebody's phone waits until
    // they notice. Closing the endpoint closes every peer with it, and the end
    // of a stream is what a client reads.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    // Not `defer bench.deinit(io)`: this test closes the endpoint itself,
    // which is the event being tested, and then cleans up what is left.
    defer {
        bench.paths.deinit();
        bench.tmp.cleanup();
    }

    const client = try bench.attach(io);
    defer client.close(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };
    _ = socket_waiter.step(io, 0);
    try testing.expectEqual(@as(usize, 1), bench.endpoint.attached());

    bench.endpoint.close(io);

    // The client's read comes back at once with the end of the stream, rather
    // than waiting. `readLine` has a bound of its own, so a client that really
    // did wait forever fails here instead of hanging the suite.
    var line_buffer: [64]u8 = undefined;
    try testing.expectError(error.PeerClosed, readLine(client, &line_buffer));

    // And the socket file is gone, so the next session on this path is not
    // wedged by a leftover.
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.accessAbsolute(io, bench.paths.socket, .{}),
    );
}

test "a stale socket left by a crash does not wedge the path" {
    // A session that was killed leaves the socket file behind, and `bind`
    // refuses a path that already exists. Without this, one crash would make
    // that session id unattachable forever.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    // The first endpoint is abandoned without `close`, which is what a killed
    // process leaves.
    var abandoned = try Endpoint.open(io, bench.paths, null);
    abandoned.server.deinit(io);

    var second = try Endpoint.open(io, bench.paths, null);
    defer second.close(io);
    const client = try std.Io.net.UnixAddress.connect(
        &(try addressFor(bench.paths.socket, null)),
        io,
    );
    defer client.close(io);
    second.acceptPending(io);
    try testing.expectEqual(@as(usize, 1), second.attached());
}

test "the fifth client is refused rather than left hanging" {
    // `max_peers` is a bound and not a target: every attached peer is polled
    // and written to on every look. A connection past it is accepted and closed
    // at once, so a client learns it was refused.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var streams: [max_peers + 1]std.Io.net.Stream = undefined;
    for (streams[0..max_peers]) |*stream| stream.* = try bench.attach(io);
    defer for (streams) |stream| stream.close(io);

    bench.endpoint.acceptPending(io);
    try testing.expectEqual(max_peers, bench.endpoint.attached());
    try testing.expectEqual(@as(usize, 0), bench.endpoint.refused);

    // The one past the bound. It connects, because the kernel queue has room
    // for it: see `Endpoint.open` on why the backlog is larger than the number
    // of slots.
    streams[max_peers] = try bench.attach(io);
    bench.endpoint.acceptPending(io);
    try testing.expectEqual(max_peers, bench.endpoint.attached());
    try testing.expectEqual(@as(usize, 1), bench.endpoint.refused);

    // And it is told, by the end of its own stream, rather than left holding a
    // connection that will never say anything.
    var line_buffer: [64]u8 = undefined;
    try testing.expectError(error.PeerClosed, readLine(streams[max_peers], &line_buffer));
}

test "the socket sits in a directory this user alone can enter" {
    // The trust boundary is a filesystem one: anything that can reach the
    // socket can approve an action. A unix socket's own file mode is not
    // honoured on every unix, so the gate is the directory, and the mode is
    // set again after the fact because the process umask narrows what
    // `createDirAbsolute` asks for.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var dir = try std.Io.Dir.openDirAbsolute(io, bench.paths.dir, .{});
    defer dir.close(io);
    const stat = try dir.stat(io);
    try testing.expectEqual(dir_mode, stat.permissions.toMode() & 0o7777);
    // And the socket really is inside it, rather than beside it.
    try testing.expect(std.mem.startsWith(u8, bench.paths.socket, bench.paths.dir));
}

test "the peer credential call answers with this user's own uid" {
    // The operating system gives the identity, so there is no token. Linux and
    // Darwin spell it differently, and this is the one test that proves each
    // build asks its own kernel the right question.
    //
    // **Two answers, because either one alone is easy to fake.** A `peerUid`
    // that always answered null would refuse every client, and one that always
    // answered this process's own uid would accept every client and still pass
    // a test that only looked at a real connection. So a real connection must
    // answer this user, and a descriptor that is not a socket at all must
    // answer nothing.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    const client = try bench.attach(io);
    defer client.close(io);
    bench.endpoint.acceptPending(io);

    try testing.expectEqual(@as(usize, 1), bench.endpoint.attached());
    try testing.expectEqual(@as(usize, 0), bench.endpoint.refused);
    for (bench.endpoint.peers) |peer| {
        if (peer.handle == null) continue;
        try testing.expectEqual(std.posix.system.getuid(), peer.uid);
    }
    // And the client's own end says the same about the session, which is what
    // a client would check before it trusted a question.
    try testing.expectEqual(
        @as(?std.posix.uid_t, std.posix.system.getuid()),
        peerUid(client.socket.handle),
    );

    // A descriptor that is not a connected socket has no peer, and the answer
    // for it is nothing rather than a guess.
    const plain = try bench.tmp.dir.createFile(io, "not-a-socket", .{});
    defer plain.close(io);
    try testing.expectEqual(@as(?std.posix.uid_t, null), peerUid(plain.handle));
}

test "a peer that is not this user is closed before it is read" {
    // The trust boundary itself: anything that can reach this socket can
    // approve an action, so a connection from another account must be closed
    // and counted, not shown a diff.
    //
    // **The endpoint's own idea of who owns it is what is moved**, not the
    // connecting process, because a test cannot become another user. That is
    // the same comparison either way: `acceptPending` asks whether the uid the
    // kernel reported is this endpoint's owner, and here it is not.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    bench.endpoint.owner_uid = std.posix.system.getuid() +% 1;

    const client = try bench.attach(io);
    defer client.close(io);
    bench.endpoint.acceptPending(io);

    try testing.expectEqual(@as(usize, 0), bench.endpoint.attached());
    try testing.expectEqual(@as(usize, 1), bench.endpoint.refused);

    // And the client is told, by the end of its own stream, rather than left
    // holding a connection that will never say anything.
    var line_buffer: [64]u8 = undefined;
    try testing.expectError(error.PeerClosed, readLine(client, &line_buffer));
}

test "a session with nobody attached and no terminal waits for nothing at all" {
    // The refusal rule, through `timeoutMs`. A deadline that has already
    // passed is expired by the broker on its first look with no wait at all,
    // and that is the honest answer for a session nobody can answer. The three
    // other cases all have somebody.
    try testing.expectEqual(@as(i64, 0), timeoutMs(false, 0));
    try testing.expectEqual(Broker.default_timeout_ms, timeoutMs(true, 0));
    try testing.expectEqual(Broker.default_timeout_ms, timeoutMs(false, 1));
    try testing.expectEqual(Broker.default_timeout_ms, timeoutMs(true, 1));
}

/// What the counting nap below saw. A file scope value because a
/// `*const fn (u64) void` cannot capture, and these tests run one at a time.
var naps: usize = 0;
var last_nap_budget_ms: u64 = 0;

fn countingNap(budget_ms: u64) void {
    naps += 1;
    last_nap_budget_ms = budget_ms;
}

test "a look with nobody attached waits for the whole budget rather than spinning" {
    // The fault the `Wake` enum was added for, one level down: a `wait` that
    // comes back at once with nothing waited for turns `Broker.request` into a
    // busy loop holding the session lock for the whole deadline, which was
    // measured once already. **Nothing here reads a clock**: the budget is
    // pinned where it arrives, at the thing that waits, which is what
    // `Waiter.nap` is a field for.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    naps = 0;
    last_nap_budget_ms = 0;
    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
        .nap = countingNap,
    };

    // With no question at all.
    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 50));
    try testing.expectEqual(@as(usize, 1), naps);
    try testing.expectEqual(@as(u64, 50), last_nap_budget_ms);

    // And with a question nobody is there to see. This is the case that
    // matters: an open question and no peer is exactly the session a subagent
    // runs as, and it must not spin for five minutes.
    _ = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "git.push",
        .summary = "push a1b2c3",
        .detail = "",
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 1);
    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 25));
    try testing.expectEqual(@as(usize, 2), naps);
    try testing.expectEqual(@as(u64, 25), last_nap_budget_ms);

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 0), result.answers.len);
}

test "a peer that fills the buffer with no line break in it is dropped" {
    // An `approval.response` envelope is a few hundred bytes, so a peer that
    // sent `max_answer_bytes` without one is not answering the question. It has
    // to be dropped rather than polled forever: the slot it holds is one of
    // four, and a client that could hold one by sending nothing usable could
    // keep the real client out.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const client = try bench.attach(io);
    defer client.close(io);

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    _ = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "git.push",
        .summary = "push a1b2c3",
        .detail = "",
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 1);

    _ = socket_waiter.step(io, 0);
    var line_buffer: [8192]u8 = undefined;
    _ = try readLine(client, &line_buffer);
    try testing.expectEqual(@as(usize, 1), bench.endpoint.attached());

    const filler: [max_answer_bytes]u8 = @splat('x');
    try testing.expect(writeAll(client.socket.handle, &filler));

    // One look fills the buffer, the next finds no room and drops the peer.
    for (0..4) |_| _ = socket_waiter.step(io, 50);
    try testing.expectEqual(@as(usize, 0), bench.endpoint.attached());

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 0), result.answers.len);
}

test "a stop ends the wait before anything is shown, and leaves the question open" {
    // The same rule `src/approval.zig` keeps for a person who pressed Ctrl-C: a
    // session that is leaving does not first show a question it cannot finish.
    // The question stays in the log with no answer, which is the state a crash
    // leaves and which `src/run.zig` treats as an apply that did not happen.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const client = try bench.attach(io);
    defer client.close(io);

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
        .stop = alwaysStopped,
    };

    _ = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "workspace.apply",
        .summary = "move 3 objects",
        .detail = "",
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 1);

    try testing.expectEqual(Broker.Waiter.Wake.canceled, socket_waiter.step(io, 1000));
    // Not even accepted, so nothing was shown to anybody.
    try testing.expectEqual(@as(usize, 0), bench.endpoint.attached());

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), result.questions);
    try testing.expectEqual(@as(usize, 0), result.answers.len);
}

fn alwaysStopped() bool {
    return true;
}

test "a pair answers from either half, and a stop in either half ends the wait" {
    // A person at the keyboard and a client attached is the ordinary case, and
    // a wait that only one of them could end would make the other one useless.
    const io = testing.io;

    const Counting = struct {
        waits: usize = 0,
        answer: Broker.Waiter.Wake = .slept,
        last_budget_ms: u64 = 0,

        fn waiter(self: *@This()) Broker.Waiter {
            return .{ .ptr = self, .vtable = &.{ .nowMs = nowMs, .wait = wait } };
        }
        fn nowMs(ptr: *anyopaque, io_inner: std.Io) i64 {
            _ = ptr;
            _ = io_inner;
            return 1_700_000_000_000;
        }
        fn wait(ptr: *anyopaque, io_inner: std.Io, budget_ms: u64) Broker.Waiter.Wake {
            _ = io_inner;
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.waits += 1;
            self.last_budget_ms = budget_ms;
            return self.answer;
        }
    };

    var first = Counting{};
    var second = Counting{};
    var pair = Pair{ .first = first.waiter(), .second = second.waiter() };

    try testing.expectEqual(Broker.Waiter.Wake.slept, pair.waiter().wait(io, 50));
    // The first half is a look with no budget; the whole budget goes to the
    // half that can wait on a descriptor.
    try testing.expectEqual(@as(u64, 0), first.last_budget_ms);
    try testing.expectEqual(@as(u64, 50), second.last_budget_ms);

    first.answer = .canceled;
    try testing.expectEqual(Broker.Waiter.Wake.canceled, pair.waiter().wait(io, 50));
    // The second half was never asked, because the session is already leaving.
    try testing.expectEqual(@as(usize, 1), second.waits);

    first.answer = .slept;
    second.answer = .canceled;
    try testing.expectEqual(Broker.Waiter.Wake.canceled, pair.waiter().wait(io, 50));
}

test "a socket path longer than a unix socket path may be is refused and says so" {
    // A session this reaches has no approval socket and still runs; it must not
    // be a crash and it must not be silent.
    const gpa = testing.allocator;
    const io = testing.io;

    const long: [200]u8 = @splat('d');
    var paths = try pathsFor(gpa, "/tmp/" ++ ("x" ** 0), &long);
    defer paths.deinit();

    try testing.expectError(error.PathTooLong, Endpoint.open(io, paths, null));
}

test "the approval socket binds at exactly the bound and refuses one byte more" {
    // **The bound is not `std.Io.net.UnixAddress.max_len`.** `max_len` is a flat
    // 108 on every platform that is not Windows, which is past the end of
    // Darwin's `sun_path` and past the longest name another program can reach on
    // Linux. See `max_socket_path` for the measurement.
    //
    // Mutation check: make `max_socket_path` read
    // `std.Io.net.UnixAddress.max_len` again. On Darwin the first half ends the
    // test binary inside the bind, because `std` copies 108 bytes into a shorter
    // field. **On Linux both halves still pass**, because `std` binds an
    // unterminated path that fills the field, so what catches the mutation there
    // is the strict comparison in `chock-proto/control.zig`: the bound must stay
    // below `sun_path`.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try BoundBench.open(gpa, io);
    defer bench.cleanup(io);

    var at_bound = try bench.pathsOfLength(max_socket_path);
    defer at_bound.deinit();
    try testing.expectEqual(max_socket_path, at_bound.socket.len);
    var endpoint = try Endpoint.open(io, at_bound, null);
    endpoint.close(io);

    var over = try bench.pathsOfLength(max_socket_path + 1);
    defer over.deinit();
    var diag: ?Diagnostic = null;
    try testing.expectError(error.PathTooLong, Endpoint.open(io, over, &diag));

    // **The refusal names the path and the bound.** A person whose state
    // directory is deep has to read which limit they met and by how much, and a
    // bind that failed later would give them an error name and nothing else.
    var said_buffer: [512]u8 = undefined;
    const said = try std.fmt.bufPrint(&said_buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.indexOf(u8, said, over.socket) != null);
    var number: [8]u8 = undefined;
    try testing.expect(std.mem.indexOf(
        u8,
        said,
        try std.fmt.bufPrint(&number, "{d}", .{max_socket_path}),
    ) != null);
    try testing.expect(std.mem.indexOf(
        u8,
        said,
        try std.fmt.bufPrint(&number, "{d}", .{over.socket.len}),
    ) != null);
}

test "the question a client is shown is the log's own envelope and no second format" {
    // `Broker.zig` promises an approval travels as events and never over a
    // channel of its own, and the same envelope is the frame for the unix
    // socket. A client that can read a session log can therefore answer one,
    // with no second parser. What is pinned is that the bytes on the socket
    // parse back through `event.fromJson` into the same event.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const client = try bench.attach(io);
    defer client.close(io);

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    const chain = [_]event.SpawnLink{
        .{ .agent_kind = "main", .reason = "the task named a build" },
    };
    _ = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "git.push",
        .summary = "push a1b2c3 to origin",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .spawn_chain = &chain,
        .timeout_at_ms = 1_700_000_000_000,
        .tool_call_id = "call1",
        .review = .approved,
        .review_note = "the diff is the fix the task asked for",
    } }, 1);

    _ = socket_waiter.step(io, 0);
    var line_buffer: [8192]u8 = undefined;
    const shown = try readLine(client, &line_buffer);

    var parsed = try event.fromJson(gpa, shown);
    defer parsed.deinit();
    const question = parsed.value.event.approval_request;
    try testing.expectEqualStrings("git.push", question.action);
    // The whole chain is shown, because "a subagent three levels down asked
    // for this" changes the answer.
    try testing.expectEqual(@as(usize, 1), question.spawn_chain.len);
    try testing.expectEqualStrings("main", question.spawn_chain[0].agent_kind);
    // The reviewer's verdict travels with the question.
    try testing.expectEqualStrings("approved", question.review.wireName());
    try testing.expectEqualStrings("the diff is the fix the task asked for", question.review_note);
    try testing.expectEqual(@as(i64, 1_700_000_000_000), question.timeout_at_ms);
    // And it is exactly one line, so a client reads it the way it reads a log.
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, shown, "\n"));
}
