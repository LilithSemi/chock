//! `chock daemon`: the process that owns sessions, and the only thing a
//! frontend ever talks to.
//!
//! ## The daemon runs a child per session and never calls `Loop.run` itself
//!
//! That one decision is what makes this cheap, and three good things fall out
//! of it:
//!
//! * **The daemon is thin.** It does not reimplement the loop, the sandbox,
//!   or the tool runner. If `chock run` works, the daemon works.
//! * **The threading constraint is somebody else's.** `Registry.dispatch`
//!   forks, and `fork` carries only the calling thread, so the tool path
//!   needs a single threaded process. Each child **is** that process, the
//!   same `chock run` a person types by hand, so this one may use threads
//!   freely for its own sockets.
//! * **A session that crashes takes down one child, not the daemon.**
//!
//! ## This owns sessions, and `chock serve` owns nothing
//!
//! `chock serve` is a separate command in a separate process, and it is a
//! **client of this one**. The reason is future shape: in a hosted world the
//! daemon is somewhere else and the frontend sits in front of it. So the API
//! below is the security boundary, not the filesystem. Whatever a browser can
//! see, this handed over on purpose.
//!
//! The test of every verb here: **would this still work if the client were on
//! another machine?** Nothing below hands out a path, and nothing below takes
//! one except the project directory a person already typed.
//!
//! ## The session log is the interface, not a new protocol
//!
//! The log is already the truth of a session, and `chock_proto.storage` already
//! replays from an offset with `OffsetOutOfRange` and `OffsetNotLineStart` for
//! an offset a client made up. So this serves the log and invents no message
//! format. **If a client needs something the events cannot say, the event types
//! need a field.**
//!
//! The grammar itself lives in `chock_proto.control`, which both this and every
//! client link. See that file for why it is a module of its own.
//!
//! ## Every connection opens with a number
//!
//! Two machines means two install times, so one end is always older. A client
//! greets with the control protocol number it was built against, this daemon
//! answers with its own, and **both check the numbers rather than the shape of
//! the reply**. They have to be equal. A daemon that speaks another number is
//! not asked to do anything at all, and neither end goes on with a grammar the
//! other may not have. See `chock_proto.control.Greeting` and `accepts`, and
//! `lib/chock-pcsc/linux/driver.zig` for the real daemon that taught this: a
//! handshake that succeeds while the versions disagree is worse than none,
//! because it looks like it worked.
//!
//! ```
//! hello chock-control <protocol number>
//!     -> ok chock-control <protocol number>
//!     The first line of every connection, and nothing below is read until it
//!     agrees. See `chock_proto.control.Greeting`.
//!
//! start <project directory>\t<message>
//!     -> ok <session id>\t<log path>
//!
//! adopt <project directory>\t<session id>
//!     -> ok <session id>\t<log path>
//!
//! read <session id> <last event id>
//!     -> one line per event, then the connection closes.
//!
//! list <project directory>
//!     -> one line per session, `<started at>\t<the row as JSON>`.
//!
//! watch <project directory>\t<session id>\t<last event id>
//!     -> the header line, then one line per event, and it keeps sending as
//!        the session appends. Ends when the session does.
//!
//! answer <project directory>\t<session id>\t<request id>\t<yes|no>
//!     -> ok answered
//! ```
//!
//! **Events travel as the bytes the log holds.** `chock_proto.chain.Verifier`
//! hashes a line as it sits on disk, and `chock_proto.ship` says why a
//! re-encoding of the parsed envelope reads as tampered with. So `read` and
//! `watch` send `Replay.line`, and `watch` sends the header line first, which
//! is what a verifier is seeded from. A client that has only ever seen a
//! session over a socket can therefore check its chain.
//!
//! ## A client may say only what a person may say
//!
//! `answer` takes two words, `yes` and `no`, and nothing else parses. See
//! `chock_proto.control.Answer`: `allowed_by_policy` is a statement about the
//! project's own table, and a client that could name it would be forging that
//! table's answer.
//!
//! **This daemon does not write that answer into the log**, and could not: the
//! session's own process holds the exclusive lock. It connects to that
//! session's approval socket, which is exactly what `chock approve` does, and
//! `lib/chock-broker/socket.zig` clamps again on the far side. Two layers, and
//! the outer one cannot express what the inner one refuses.
//!
//! ## `adopt` is ownership changing hands, and nothing else
//!
//! The process that holds a session log's exclusive lock is the owner of that
//! session. So handing a session to this daemon is that lock changing hands,
//! and there is no transfer protocol to write: the last owner has already let
//! go, and this daemon's child takes the lock and folds the log. **The fold is
//! the truth of a session**, which is the same mechanism `chock usage`, `chock
//! plan` and compaction already use, so a replay at start is not new machinery.
//!
//! **What `adopt` refuses, and why each refusal is not a hint.** A session this
//! daemon may not take is named, never silently started:
//!
//! * A log that is not there. A client that names an identifier this machine
//!   never wrote must not have an empty session made under it.
//! * A log whose lock is held. That session has an owner, and this daemon does
//!   not take one from a process that is still using it.
//! * A lock that could not be tested at all. An absent answer is never a
//!   permissive answer, the same rule a policy keeps.
//!
//! **Nothing here is what stops two owners.** `flock(2)` is: the second process
//! to ask for the exclusive lock is refused by the kernel. The checks above turn
//! a race this daemon lost into a sentence a person can read instead of
//! `error.Busy` arriving from inside a child. See `src/run.zig`'s own
//! `refuseAdoptWithNothingToAdopt`, which is where the child checks the same
//! three facts again, on its own, a moment before it takes the lock.
//!
//! **`last event id` means "I already have this one, send what comes after".**
//! That is what `chock_proto.log.Log.resumeAfter` already means. Zero means the
//! client has nothing yet. A client that reconnects sends the identifier of the
//! last event it saw and gets no gap and no repeat, because an event identifier
//! is its own byte offset in the log.
//!
//! A failure is one line, `error <what happened>`, and then the connection
//! closes. A client that reads a whole connection therefore always gets
//! either events or a reason.
//!
//! ## What it listens on
//!
//! **A unix socket, and nothing else, unless somebody asks for more.** The
//! socket is where the peer credential check works, so it is the only address
//! a person who typed nothing gets.
//!
//! **A TCP listener is what `--host` turns on, and it is never a default.** A
//! default is not a deliberate choice, and loopback TCP authenticates nobody:
//! on a machine with more than one account, every local account can reach
//! `127.0.0.1` and drive this daemon. So `--host` is the whole difference
//! between a daemon this user alone can use and a daemon anything on the
//! machine can use.
//!
//! **`--host` is allowed and is not guarded.** Somebody who types `0.0.0.0` is
//! being deliberately insecure and that is their choice. Chock does no
//! authentication over a network at all: the supported way to expose this is a
//! reverse proxy such as Authelia in front of it, and a pairing bootstrap is
//! planned and is not built.
//!
//! ## Who may talk to it
//!
//! **The unix socket serves the user that started this daemon, and refuses
//! every other peer.** The kernel says who is on the other end of a connected
//! unix socket, and `chock_proto.control.peerUid` is the one place that asks
//! it, with `SO_PEERCRED` on Linux and `LOCAL_PEERCRED` on Darwin. A peer the
//! kernel will not name is refused as well, because an absent answer is never
//! a permissive answer.
//!
//! **A TCP peer carries no identity at all, and nothing below pretends to
//! check one.** There is no credential on a TCP connection to read, so the
//! socket's check covers the socket and only the socket. Authentication in
//! front of a TCP listener is the proxy's job: see `--host` above.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_broker = @import("chock-broker");
const chock_proto = @import("chock-proto");

const session_paths = @import("session.zig");
const sessions_cmd = @import("sessions.zig");
const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const control = chock_proto.control;

/// The largest request line this reads. A request holds a project path and a
/// message, both of which a person typed.
const max_request_bytes: usize = control.max_request_bytes;

/// How many events one `read` sends before it stops. A session log is bounded
/// by the turn limit and by `max_output_bytes` per tool result, so this is a
/// guard against a log somebody else wrote, never against a session Chock
/// produced.
const max_events_per_read: usize = 100_000;

/// How many addresses this can listen on at once: the unix socket, and the TCP
/// address `--host` turns on.
const max_listeners: usize = 2;

/// How many connections may be served at once.
///
/// A `watch` holds its connection for as long as a browser tab is open, so this
/// is not a burst limit: it is how many live views one daemon carries. Beyond
/// it a connection is accepted and refused by name, so a client learns it was
/// turned away rather than hanging, which is the rule
/// `lib/chock-broker/socket.zig` already keeps for its own peers.
const max_connections: usize = 64;

/// How long a `watch` sleeps between looks at a log that has not grown.
///
/// **A poll and not a file watch**, because the two platforms spell a file
/// watch differently and a log grows on the order of a turn, not a frame. A
/// quarter of a second is far below what a person notices and far above what
/// costs anything.
const watch_idle_ms: u64 = 250;

const usage_text =
    \\Usage: chock daemon [options]
    \\
    \\Owns sessions and answers `chock serve`, `chock detach`, and any other
    \\client. Listens on a unix socket in the state directory, and on nothing
    \\else until --host names an address.
    \\
    \\The unix socket serves the user that started this daemon. Every other peer
    \\is refused, by the credential the kernel puts on the connection.
    \\
    \\Options:
    \\  --socket <path>  The unix socket. Default is daemon.sock in the state directory.
    \\  --host <addr>    Also listen on this address, over TCP. Off by default.
    \\  --port <n>       The TCP port, with --host. 0 asks the system for one and
    \\                   prints it. Default 7373.
    \\
    \\Chock does no authentication over a network, and a TCP connection carries
    \\no credential to check. Anything that can route to a --host address can
    \\drive this daemon, so put a reverse proxy such as Authelia in front of it.
    \\
++ tty.options_text;

/// One session this daemon started. The log path is kept so a `read` never
/// takes a path from a client: a client names a session identifier this
/// daemon handed out, and nothing else.
const Session = struct {
    id: [session_paths.id_length]u8,
    log_path: [:0]u8,
    project: []u8,
};

const Daemon = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    /// The `chock` program itself, for the child of each session.
    exe_path: []const u8,
    env: *std.process.Environ.Map,
    /// The uid this process runs as. **A peer on the unix socket that is not
    /// this one is refused**: see `peerAllowed`.
    ///
    /// Zero is the refusing direction and not a real reading. `main` puts the
    /// measured uid here, and a caller that forgot would refuse every peer that
    /// is not root rather than serving anybody who asks.
    owner_uid: std.posix.uid_t = 0,
    /// Guards `sessions`. The accept loop and every session's own watching
    /// thread reach it.
    mutex: std.Io.Mutex = .init,
    sessions: std.ArrayList(Session) = .empty,
    /// How many connections are being served right now. See `max_connections`.
    live: std.atomic.Value(usize) = .init(0),

    fn deinit(self: *Daemon) void {
        for (self.sessions.items) |entry| {
            self.gpa.free(entry.log_path);
            self.gpa.free(entry.project);
        }
        self.sessions.deinit(self.gpa);
    }

    fn remember(self: *Daemon, entry: Session) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.sessions.append(self.gpa, entry);
    }

    /// The log path of a session this daemon started, or null. Copies the
    /// path out under the lock, so a caller never holds a pointer into a
    /// list another thread can grow.
    fn logPathFor(self: *Daemon, id: []const u8) !?[:0]u8 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |entry| {
            if (std.mem.eql(u8, &entry.id, id)) return try self.gpa.dupeZ(u8, entry.log_path);
        }
        return null;
    }
};

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) !u8 {
    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        error.BadArguments => return Exit.usage.code(),
    };

    var env = try environ.createMap(arena);

    // A real allocator here, unlike `chock run`'s session phase: this process
    // spawns children and never forks itself, so it may use threads.
    var threaded = std.Io.Threaded.init(gpa, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    var daemon = Daemon{
        .gpa = gpa,
        .io = io,
        .exe_path = exe_path,
        .env = &env,
        .owner_uid = std.posix.system.getuid(),
    };
    defer daemon.deinit();

    const socket_path = options.socket orelse path: {
        const state = chock_auth.paths.stateDir(arena, &env) catch |err| {
            tty.print(.err, "chock daemon: the state directory could not be found: {t}\n", .{err});
            return Exit.usage.code();
        };
        makeDirAll(io, state) catch |err| {
            tty.print(.err, "chock daemon: {s} could not be made: {t}\n", .{ state, err });
            return Exit.usage.code();
        };
        break :path control.socketPathIn(arena, state) catch return Exit.faulted.code();
    };

    var wanted_buffer: [max_listeners]control.Address = undefined;
    const wanted = listenSet(&wanted_buffer, socket_path, options);

    var listeners: [max_listeners]control.Listener = undefined;
    var opened: usize = 0;
    defer for (listeners[0..opened]) |*one| one.close(io);

    for (wanted) |address| {
        listeners[opened] = address.listen(io) catch |err| {
            tty.print(
                .err,
                "chock daemon: {f} could not be listened on: {t}\n",
                .{ address, err },
            );
            // **Named, because the fix is not obvious and it is not rare.** A
            // state directory under a long home spends most of the bound before
            // the socket's own name is added. Measured by running it.
            //
            // **The number is read from `control.max_socket_path` and never
            // written out.** This line said 108 on every platform, which is
            // false on Darwin by five bytes, and those five are the ones that
            // reach an `@memcpy` past the end of `sun_path`.
            if (err == error.PathTooLong) tty.print(
                .err,
                "chock daemon: a unix socket path is at most {d} bytes on this platform. " ++
                    "Name a shorter one with --socket.\n",
                .{control.max_socket_path},
            );
            return Exit.usage.code();
        };
        opened += 1;
        tty.print(.plain, "chock daemon: listening on {f}\n", .{reportable(address, listeners[opened - 1])});
    }

    accept(&daemon, listeners[0..opened]);
    return Exit.finished.code();
}

/// Make `path` and every directory above it that is missing.
///
/// **A daemon may be the first thing a person runs**, and then nothing has made
/// the state directory yet, nor the two directories above it that the XDG
/// layout puts it under. `createDirAbsolute` makes one level, so a single call
/// answers `FileNotFound` on a fresh machine, which is what this was before it
/// was measured by running it.
///
/// Its own small copy rather than `session.zig`'s, which is private to that
/// file and reports its own fault text. Both are the same three lines.
fn makeDirAll(io: std.Io, path: []const u8) !void {
    if (path.len == 0) return;
    std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse return err;
            try makeDirAll(io, parent);
            std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |second| switch (second) {
                error.PathAlreadyExists => return,
                else => return second,
            };
        },
        else => return err,
    };
}

/// Every address this daemon listens on, in the order it opens them.
///
/// **The unix socket is always there and the TCP address never is by
/// default.** A default is not a deliberate choice, and a TCP connection
/// carries no credential to check, so a person who has not typed `--host` gets
/// the one transport where the peer can be named. See this file's own top
/// comment.
///
/// Its own function, taking a buffer, so a test can read the whole set without
/// opening a socket.
fn listenSet(
    buffer: *[max_listeners]control.Address,
    socket_path: []const u8,
    options: Options,
) []const control.Address {
    buffer[0] = .{ .unix = socket_path };
    const host = options.host orelse return buffer[0..1];
    buffer[1] = .{ .ip = .{ .host = host, .port = options.port } };
    return buffer[0..2];
}

/// Whether a peer of the unix socket may be served.
///
/// **The owner of this daemon and nobody else**, and the rule is
/// `chock_proto.control.peerAllowed` rather than a copy of it. `chock serve`
/// guards its own socket with the same two lines, and a security check written
/// twice drifts apart.
///
/// This is for a unix socket. **A TCP connection carries no peer identity**,
/// so there is nothing here for a caller to ask about one: see this file's own
/// top comment.
const peerAllowed = control.peerAllowed;

/// The address to print, with the port the system chose filled in.
///
/// **A `--port 0` is how a test and a script ask for a free port**, and a
/// daemon that printed `0` would leave them nothing to connect to.
fn reportable(address: control.Address, listener: control.Listener) control.Address {
    return switch (address) {
        .unix => address,
        .ip => |ip| .{ .ip = .{ .host = ip.host, .port = listener.server.socket.address.getPort() } },
    };
}

/// Take connections from every listener and give each one a thread.
///
/// **A thread per connection, because a `watch` never ends on its own.** The
/// old shape served one connection at a time, which was right when every
/// request was a line in and a burst of lines out. A live view holds its
/// connection for as long as a browser tab is open, and one of those would
/// otherwise stop every other client.
fn accept(daemon: *Daemon, listeners: []control.Listener) void {
    var fds: [4]std.posix.pollfd = undefined;
    std.debug.assert(listeners.len <= fds.len);

    while (true) {
        for (listeners, 0..) |*one, index| {
            fds[index] = .{ .fd = one.server.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
        }
        // A poll that cannot run says nothing about the listeners, and looking
        // again at once would spin. One second is not a measurement: it is the
        // bound that keeps a fault from becoming a busy loop.
        const ready = std.posix.poll(fds[0..listeners.len], 1000) catch continue;
        if (ready == 0) continue;

        for (fds[0..listeners.len], listeners) |entry, *one| {
            if (entry.revents == 0) continue;
            var stream = one.server.accept(daemon.io) catch |err| {
                tty.print(.warn, "chock daemon: an incoming connection failed: {t}\n", .{err});
                continue;
            };

            // **The peer check, and it is the socket's alone.** A unix socket
            // carries the uid of whoever connected, and this daemon serves the
            // user that started it. A TCP connection carries no such thing, so
            // `unix_path` is what tells the two transports apart and nothing
            // below claims to have checked a TCP peer. See this file's own top
            // comment.
            if (one.unix_path != null and
                !peerAllowed(control.peerUid(stream.socket.handle), daemon.owner_uid))
            {
                // Refused by name, so a person who ran a client under another
                // account reads a sentence rather than finding a daemon that
                // drops connections.
                var buffer: [256]u8 = undefined;
                var writer = stream.writer(daemon.io, &buffer);
                fail(&writer.interface, "this daemon serves the user that started it, and you are not that user");
                tty.print(.warn, "chock daemon: a client of another user was refused.\n", .{});
                stream.close(daemon.io);
                continue;
            }

            if (daemon.live.load(.monotonic) >= max_connections) {
                // Accepted and refused by name, so a client learns it was
                // turned away rather than finding a daemon that is not there.
                var buffer: [256]u8 = undefined;
                var writer = stream.writer(daemon.io, &buffer);
                fail(&writer.interface, "this daemon is serving as many clients as it can");
                stream.close(daemon.io);
                continue;
            }

            _ = daemon.live.fetchAdd(1, .monotonic);
            const thread = std.Thread.spawn(.{}, runConnection, .{Connection{
                .daemon = daemon,
                .stream = stream,
            }}) catch {
                _ = daemon.live.fetchSub(1, .monotonic);
                stream.close(daemon.io);
                continue;
            };
            thread.detach();
        }
    }
}

const Connection = struct {
    daemon: *Daemon,
    stream: std.Io.net.Stream,
};

fn runConnection(conn: Connection) void {
    const daemon = conn.daemon;
    var stream = conn.stream;
    defer {
        stream.close(daemon.io);
        _ = daemon.live.fetchSub(1, .monotonic);
    }

    // **One arena per connection.** A `list` folds every session of a project
    // and a fold allocates a string per row, so freeing them one at a time
    // would be a second bookkeeping job with nothing to gain: the whole answer
    // dies with the connection.
    var arena = std.heap.ArenaAllocator.init(daemon.gpa);
    defer arena.deinit();

    serve(daemon, arena.allocator(), &stream);
}

fn serve(daemon: *Daemon, arena: std.mem.Allocator, stream: *std.Io.net.Stream) void {
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(daemon.io, &read_buffer);
    const reader = &stream_reader.interface;

    var write_buffer: [64 * 1024]u8 = undefined;
    var stream_writer = stream.writer(daemon.io, &write_buffer);
    const writer = &stream_writer.interface;
    // **Every path out of this function sends what it wrote.** The buffer is a
    // local, so a handler that answered and returned without flushing left its
    // whole answer here and closed the connection on the client. Measured by
    // running `start` against a real daemon and getting nothing back: `ok` is
    // one short line, so it never filled the buffer and never left on its own.
    defer writer.flush() catch {};

    if (!greet(reader, writer)) return;

    // **`takeDelimiter` and never `takeDelimiterExclusive`.** The exclusive one
    // stops at the line break without passing it, so the second read on one
    // connection gives back an empty line for ever. One read never met that,
    // which is why this was the exclusive call before the greeting existed.
    const line = (reader.takeDelimiter('\n') catch null) orelse {
        fail(writer, "the request had no line to read");
        return;
    };
    if (line.len > max_request_bytes) {
        fail(writer, "the request is too long");
        return;
    }

    const request = control.Request.parse(std.mem.trimEnd(u8, line, "\r")) catch |err| switch (err) {
        error.NoVerb => {
            fail(writer, control.no_verb_text);
            return;
        },
        error.BadArguments => {
            fail(writer, "that verb does not take those arguments");
            return;
        },
    };

    switch (request) {
        .start => |one| handleStart(daemon, writer, one),
        .adopt => |one| handleAdopt(daemon, writer, one),
        .read => |one| handleRead(daemon, arena, writer, one),
        .list => |one| handleList(daemon, arena, writer, one),
        .watch => |one| handleWatch(daemon, arena, writer, stream.socket.handle, one),
        .answer => |one| handleAnswer(daemon, arena, writer, one),
    }
}

/// Read the client's greeting and answer it. False once the client has been
/// told why it is being turned away.
///
/// **Nothing below this is reached until the numbers agree.** A client speaking
/// another number is refused before its request is read at all, so no verb of
/// this daemon ever runs for a grammar one end does not have. That the request
/// is unread is also what makes the refusal arrive: a socket closed with bytes
/// still unread is reset, and a reset discards what this daemon already wrote.
///
/// **This is the same over a unix socket and over TCP.** The greeting is one
/// line of the one grammar, and `chock_proto.control` is what holds it, so
/// there is nothing here that knows which transport it got.
fn greet(reader: *std.Io.Reader, writer: *std.Io.Writer) bool {
    const line = (reader.takeDelimiter('\n') catch null) orelse {
        fail(writer, "the connection carried no greeting");
        return false;
    };
    const asked = control.Greeting.parse(.ask, std.mem.trimEnd(u8, line, "\r")) catch {
        fail(writer, control.no_greeting_text);
        return false;
    };
    if (!control.accepts(control.protocol_version, asked.version)) {
        control.writeMismatch(writer, control.protocol_version, asked.version) catch return false;
        writer.flush() catch return false;
        return false;
    }
    (control.Greeting{}).write(.answer, writer) catch return false;
    // Flushed here rather than left to the handler, so a `watch` that sits on a
    // log with nothing new in it has still told its client the connection is
    // good.
    writer.flush() catch return false;
    return true;
}

fn handleStart(daemon: *Daemon, writer: *std.Io.Writer, one: control.Request.Start) void {
    if (one.project.len == 0 or one.message.len == 0) {
        fail(writer, "start needs a project directory and a message, and neither can be empty");
        return;
    }
    if (!std.fs.path.isAbsolute(one.project)) {
        fail(writer, "the project directory has to be an absolute path");
        return;
    }

    const id = session_paths.newId(daemon.io);
    beginSession(daemon, writer, one.project, id, one.message);
}

/// `adopt <project directory>\t<session id>`: become the owner of a session
/// that already exists. See this file's own top comment for what it refuses and
/// why none of that is what stops two owners.
fn handleAdopt(daemon: *Daemon, writer: *std.Io.Writer, one: control.Request.Adopt) void {
    const id = checkedSession(writer, one.project, one.session) orelse return;

    var paths = session_paths.pathsFor(daemon.gpa, daemon.env, one.project, &id) catch {
        fail(writer, "the session path could not be built");
        return;
    };
    defer paths.deinit();

    switch (sessions_cmd.readinessOf(daemon.gpa, daemon.io, paths.log, &id)) {
        .ready => {},
        .no_such_session => {
            fail(writer, "this machine holds no session with that identifier under that project");
            return;
        },
        .nothing_to_carry_on => {
            fail(writer, "that session holds nothing to carry on from");
            return;
        },
        .running => {
            fail(writer, "that session is running now, and the process holding its log's lock owns it");
            return;
        },
        .unknown => {
            fail(writer, "that session could not be read, or its lock could not be tested");
            return;
        },
    }

    beginSession(daemon, writer, one.project, id, null);
}

/// Check a project and a session identifier a client sent, together.
///
/// **An identifier is checked before a path is built from it.** A value that
/// reached a path unchecked is a path traversal, and three verbs now take one,
/// so the check is in one place rather than three.
fn checkedSession(
    writer: *std.Io.Writer,
    project: []const u8,
    given: []const u8,
) ?[session_paths.id_length]u8 {
    if (project.len == 0) {
        fail(writer, "that needs a project directory, and it cannot be empty");
        return null;
    }
    if (!std.fs.path.isAbsolute(project)) {
        fail(writer, "the project directory has to be an absolute path");
        return null;
    }
    if (!session_paths.isValidId(given)) {
        fail(writer, "that is not a session identifier");
        return null;
    }
    return given[0..session_paths.id_length].*;
}

/// Remember one session, start the child that runs it, and answer the client.
///
/// **One path for `start` and for `adopt`**, because the two differ in exactly
/// one thing: whether the child is given a message. Everything after that is the
/// same session, running in the same kind of child, writing the same log.
fn beginSession(
    daemon: *Daemon,
    writer: *std.Io.Writer,
    project: []const u8,
    id: [session_paths.id_length]u8,
    message: ?[]const u8,
) void {
    var paths = session_paths.pathsFor(daemon.gpa, daemon.env, project, &id) catch {
        fail(writer, "the session path could not be built");
        return;
    };
    defer paths.deinit();

    const log_path = daemon.gpa.dupeZ(u8, paths.log) catch {
        fail(writer, "out of memory");
        return;
    };
    const project_copy = daemon.gpa.dupe(u8, project) catch {
        daemon.gpa.free(log_path);
        fail(writer, "out of memory");
        return;
    };
    daemon.remember(.{ .id = id, .log_path = log_path, .project = project_copy }) catch {
        daemon.gpa.free(log_path);
        daemon.gpa.free(project_copy);
        fail(writer, "out of memory");
        return;
    };

    const owned_message: ?[]u8 = if (message) |text| daemon.gpa.dupe(u8, text) catch {
        fail(writer, "out of memory");
        return;
    } else null;

    const child = Child{
        .daemon = daemon,
        .id = id,
        .project = project_copy,
        .message = owned_message,
    };
    const thread = std.Thread.spawn(.{}, runChild, .{child}) catch {
        if (owned_message) |text| daemon.gpa.free(text);
        fail(writer, "the session could not be started");
        return;
    };
    // Detached: this daemon does not wait for a session to finish before it
    // answers the next request, and the child's own exit is reported into the
    // log, which is the interface. The thread's whole job is to reap the
    // child so it does not become a zombie.
    thread.detach();

    var text_buffer: [std.fs.max_path_bytes + session_paths.id_length + 8]u8 = undefined;
    const text = std.fmt.bufPrint(&text_buffer, "{s}\t{s}", .{ id, log_path }) catch {
        fail(writer, "the answer was longer than this daemon can write");
        return;
    };
    say(writer, .{ .ok = text });
}

const Child = struct {
    daemon: *Daemon,
    id: [session_paths.id_length]u8,
    /// Borrowed from the daemon's own session list, which outlives this.
    project: []const u8,
    /// Owned by this value, freed by `runChild`. **Null for a session this
    /// daemon adopted**, which carries on from what its log already holds and
    /// must be given no message of anybody else's: see `handleAdopt`.
    message: ?[]u8,
};

/// Spawn `chock run` for one session and wait for it. **This is where the
/// daemon's own threads go, and it is why it may have any**: nothing on this
/// thread forks, so the constraint that binds the tool path binds the child
/// and not this process.
fn runChild(child: Child) void {
    const daemon = child.daemon;
    defer if (child.message) |text| daemon.gpa.free(text);

    var argv_buffer: [8][]const u8 = undefined;
    var argv_len: usize = 0;
    for ([_][]const u8{ daemon.exe_path, "run", "--project", child.project, "--session", &child.id }) |word| {
        argv_buffer[argv_len] = word;
        argv_len += 1;
    }
    if (child.message) |text| {
        // `--` first, so a message that starts with a dash is a message and not
        // an option somebody could smuggle in from a socket.
        argv_buffer[argv_len] = "--";
        argv_buffer[argv_len + 1] = text;
        argv_len += 2;
    } else {
        argv_buffer[argv_len] = "--adopt";
        argv_len += 1;
    }
    const argv = argv_buffer[0..argv_len];

    var process = std.process.spawn(daemon.io, .{
        .argv = argv,
        .environ_map = daemon.env,
        .stdin = .ignore,
        // The transcript goes into the log, which is what a client reads.
        // Standard output would be a second copy of it that nobody reads.
        .stdout = .ignore,
        // Standard error is where a setup failure is reported, and a person
        // running the daemon in a terminal wants to see one.
        .stderr = .inherit,
    }) catch |err| {
        tty.print(.err, "chock daemon: session {s} could not be started: {t}\n", .{ child.id, err });
        return;
    };

    const term = process.wait(daemon.io) catch |err| {
        tty.print(.err, "chock daemon: session {s} could not be waited for: {t}\n", .{ child.id, err });
        return;
    };
    switch (term) {
        .exited => |status| tty.print(.plain, "chock daemon: session {s} exited {d}\n", .{ child.id, status }),
        else => tty.print(.warn, "chock daemon: session {s} did not exit normally\n", .{child.id}),
    }
}

fn handleRead(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    one: control.Request.Read,
) void {
    if (!session_paths.isValidId(one.session)) {
        fail(writer, "that is not a session identifier");
        return;
    }
    const log_path = (daemon.logPathFor(one.session) catch {
        fail(writer, "out of memory");
        return;
    }) orelse {
        // A client names a session this daemon handed out, never a path. So a
        // client cannot ask this daemon to read a file of its choosing.
        fail(writer, "this daemon did not start a session with that identifier");
        return;
    };
    defer daemon.gpa.free(log_path);

    var opened = openLog(daemon, writer, log_path, one.session) orelse return;
    defer opened.close(daemon.io);

    var feed = control.Feed{ .after = one.after };
    _ = feed.events(arena, daemon.io, opened.storage(), writer, max_events_per_read) catch |err| {
        // `OffsetOutOfRange` and `OffsetNotLineStart` are the two answers for
        // an identifier a client made up. Both reach the client by name.
        failWith(writer, "the session log could not be read from there", @errorName(err));
        return;
    };
    writer.flush() catch return;
}

/// `watch`: the same events, and it keeps sending.
///
/// **The header line goes first when the client has nothing.**
/// `chain.Verifier` is seeded from the digest of that line, so a client that
/// never got it cannot check the chain of what follows. A client resuming from
/// an offset already has it.
fn handleWatch(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    handle: std.posix.fd_t,
    one: control.Request.Watch,
) void {
    const id = checkedSession(writer, one.project, one.session) orelse return;

    var paths = session_paths.pathsFor(daemon.gpa, daemon.env, one.project, &id) catch {
        fail(writer, "the session path could not be built");
        return;
    };
    defer paths.deinit();

    _ = std.Io.Dir.cwd().statFile(daemon.io, paths.log, .{}) catch {
        // Never `Log.open`, which would make an empty log under an identifier
        // somebody mistyped and then report it as a session.
        fail(writer, "this machine holds no session with that identifier under that project");
        return;
    };

    var feed = control.Feed{ .after = one.after };
    if (one.after == 0) {
        var opened = openLog(daemon, writer, paths.log, &id) orelse return;
        defer opened.close(daemon.io);
        feed.header(daemon.io, opened.storage(), writer) catch |err| {
            failWith(writer, "the session log's header could not be read", @errorName(err));
            return;
        };
    }

    while (true) {
        // **The log is opened and closed each round.** A watch outlives a
        // session, and a descriptor held open across a session that ended and
        // was carried on would be reading a file nobody appends to any more.
        const grew = grow: {
            var opened = openLog(daemon, writer, paths.log, &id) orelse return;
            defer opened.close(daemon.io);
            break :grow feed.events(arena, daemon.io, opened.storage(), writer, 0) catch |err| {
                failWith(writer, "the session log could not be read", @errorName(err));
                return;
            };
        };
        writer.flush() catch return;

        // **The session ending is what ends a watch**, and it is checked with
        // the lock rather than with the last event alone: a session carried on
        // with `--continue` appends after its own `session.end`, and a watch
        // that stopped at that line would cut a live view short.
        if (feed.ended and sessions_cmd.livenessOf(daemon.io, paths.log) != .live) return;

        if (!grew) {
            // A client that closed its end is one this daemon stops reading a
            // log for. Without this a browser tab somebody shut would hold a
            // thread until the session ended.
            if (peerGone(handle, watch_idle_ms)) return;
        }
    }
}

/// One session log, open, with the storage interface over it.
///
/// **The `Log` and the `JsonLines` backend are kept together**, because the
/// backend borrows the log, and a helper that gave back only the interface
/// would leave a pointer into a value that had already gone.
///
/// Everything the daemon then does with it is `chock_proto.control.Feed`, which
/// is the same code `test/proto/control.zig` drives over a real socket. So the
/// wire is never proved against a stand-in of the daemon that accepts more than
/// the daemon does.
const Opened = struct {
    backing: chock_proto.storage.JsonLines,

    fn storage(self: *Opened) chock_proto.storage.Storage {
        return self.backing.storage();
    }

    fn close(self: *Opened, io: std.Io) void {
        self.backing.log.close(io);
    }
};

/// Open one session log, or say why not. Null once the client has been told.
fn openLog(
    daemon: *Daemon,
    writer: *std.Io.Writer,
    log_path: [:0]const u8,
    id: []const u8,
) ?Opened {
    const log = chock_proto.log.Log.open(daemon.io, log_path, id) catch |err| {
        failWith(writer, "the session log could not be opened", @errorName(err));
        return null;
    };
    return .{ .backing = .{ .log = log } };
}

/// True when the peer has closed its end. Waits at most `timeout_ms`.
///
/// **A read of zero bytes is the end of the stream**, and a hang up or an
/// error is the same fact arriving differently. A client of this protocol
/// sends one line and then only listens, so anything readable after that line
/// is either the close or a client speaking a protocol this daemon does not
/// have. Both end the watch.
fn peerGone(handle: std.posix.fd_t, timeout_ms: u64) bool {
    var fds = [_]std.posix.pollfd{.{
        .fd = handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const bounded: i32 = if (timeout_ms > std.math.maxInt(i32))
        std.math.maxInt(i32)
    else
        @intCast(timeout_ms);
    const ready = std.posix.poll(&fds, bounded) catch return false;
    if (ready == 0) return false;
    if (fds[0].revents & (std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL) != 0) return true;

    var scratch: [64]u8 = undefined;
    const read = std.posix.read(handle, &scratch) catch return true;
    return read == 0;
}

/// `list`: every session of one project, folded here and sent as rows.
///
/// **The fold runs on this side, and that is the point.** A client that folded
/// a log itself would need the log, which means the file, which means being on
/// this machine. See this file's own top comment.
fn handleList(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    one: control.Request.List,
) void {
    if (one.project.len == 0) {
        fail(writer, "list needs a project directory, and it cannot be empty");
        return;
    }
    if (!std.fs.path.isAbsolute(one.project)) {
        fail(writer, "the project directory has to be an absolute path");
        return;
    }

    const dir = session_paths.projectDir(arena, daemon.env, one.project) catch {
        fail(writer, "the session directory could not be built");
        return;
    };

    const found = sessions_cmd.list(arena, daemon.io, dir) catch {
        fail(writer, "out of memory");
        return;
    };

    for (found) |session| {
        const row = rowOf(session);
        const text = row.toJson(arena) catch {
            fail(writer, "a session could not be written out");
            return;
        };
        say(writer, .{ .record = .{ .id = session.started_ms, .payload = text } });
    }
    writer.flush() catch return;
}

/// One folded session as it travels.
///
/// **Its own conversion, so the wire type and the local one can move apart.**
/// `src/sessions.zig`'s `Session` holds a seal reading and paths, and neither
/// belongs to a client. See `chock_proto.control.SessionRow`, and the test
/// below that drives a real fold through this.
pub fn rowOf(session: sessions_cmd.Session) control.SessionRow {
    return .{
        .id = session.id,
        .started_ms = session.started_ms,
        .model = session.model,
        .model_count = session.model_count,
        .model_alias = session.model_alias,
        .live = @tagName(session.live),
        .end = if (session.end) |reason| reason.wireName() else null,
        .turns = session.spend.turns,
        .input_tokens = session.spend.input_tokens,
        .output_tokens = session.spend.output_tokens,
        .amount = session.spend.amount,
        .currency = session.spend.currency,
        .spend_enforceable = session.spend.enforceable(),
        .readable = session.readable,
        .complete = session.complete,
        .chain = control.verdictName(session.chain.verdict),
        .chain_events = session.chain.events,
        .chain_chained = session.chain.chained,
        .has_work = session.has_work,
        .has_root = session.has_root,
    };
}

/// `answer`: carry one decision to the session that asked.
///
/// **This daemon never writes it into the log**, and could not: the session's
/// own process holds the exclusive lock, which is what ownership means here. It
/// connects to that session's approval socket, exactly as `chock approve` does,
/// and the session appends the answer through the handle it already holds.
fn handleAnswer(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    one: control.Request.Answer_,
) void {
    const id = checkedSession(writer, one.project, one.session) orelse return;

    const dir = session_paths.projectDir(arena, daemon.env, one.project) catch {
        fail(writer, "the session directory could not be built");
        return;
    };
    var paths = chock_broker.socket.pathsFor(arena, dir, &id) catch {
        fail(writer, "the approval socket path could not be built");
        return;
    };
    defer paths.deinit();

    const address = control.unixAddress(paths.socket) catch {
        fail(writer, "the approval socket path is too long for a socket");
        return;
    };
    const stream = address.connect(daemon.io) catch {
        // A session that has ended removed its socket, and one that never had
        // an approval to ask about never made one.
        fail(writer, "that session is not listening for an answer, so it has ended or asked nothing");
        return;
    };
    defer stream.close(daemon.io);

    const text = chock_proto.event.toJson(arena, .{
        .id = 0,
        .session = &id,
        .time_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds(),
        .event = .{
            .approval_response = .{
                .request_id = one.request_id,
                // **The clamp.** `control.Answer` has two members, so there is no
                // third decision this line could carry. The session clamps again
                // on the far side: see this file's own top comment.
                .decision = one.decision.decision(),
                // Left empty on purpose. The session stamps the responder from the
                // peer credentials the kernel gave it, so a name written here
                // would be a name nobody checked.
                .responder = "",
            },
        },
    }) catch {
        fail(writer, "the answer could not be written out");
        return;
    };

    if (!chock_broker.socket.writeAll(stream.socket.handle, text) or
        !chock_broker.socket.writeAll(stream.socket.handle, "\n"))
    {
        fail(writer, "that session went away before it could be answered");
        return;
    }
    say(writer, .{ .ok = "answered" });
}

fn say(writer: *std.Io.Writer, reply: control.Reply) void {
    reply.write(writer) catch return;
}

fn fail(writer: *std.Io.Writer, what: []const u8) void {
    say(writer, .{ .failed = what });
    writer.flush() catch return;
}

fn failWith(writer: *std.Io.Writer, what: []const u8, reason: []const u8) void {
    writer.print(control.error_prefix ++ "{s}: {s}\n", .{ what, reason }) catch return;
    writer.flush() catch return;
}

const ParseError = error{ HelpWanted, BadArguments };

const Options = struct {
    /// The unix socket path, or null for the one in the state directory.
    socket: ?[]const u8 = null,
    /// The address of the TCP listener, or null for no TCP listener at all.
    /// **Null is the default**, and that is the whole of fault one: see
    /// `listenSet`.
    host: ?[]const u8 = null,
    port: u16 = control.default_port,
};

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};
    var port_named = false;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;

        if (std.mem.eql(u8, argument, "--port")) {
            index += 1;
            if (index >= args.len) {
                tty.print(.err, "chock daemon: --port needs a value.\n\n", .{});
                tty.print(.err, "{s}", .{usage_text});
                return error.BadArguments;
            }
            options.port = std.fmt.parseInt(u16, args[index], 10) catch {
                tty.print(.err, "chock daemon: --port takes a number, and \"{s}\" is not one.\n", .{args[index]});
                return error.BadArguments;
            };
            port_named = true;
            continue;
        }

        // **Allowed, and not guarded.** Somebody who types `0.0.0.0` is being
        // deliberately insecure and that is their choice, not a typo to catch.
        // Chock does no authentication over a network: see this file's own top
        // comment for what to put in front of it. What this flag does is turn
        // the TCP listener on at all, which nothing else does.
        if (std.mem.eql(u8, argument, "--host") or std.mem.eql(u8, argument, "--address") or
            std.mem.eql(u8, argument, "--bind"))
        {
            index += 1;
            if (index >= args.len) {
                tty.print(.err, "chock daemon: {s} needs a value.\n\n", .{argument});
                tty.print(.err, "{s}", .{usage_text});
                return error.BadArguments;
            }
            options.host = args[index];
            continue;
        }

        if (std.mem.eql(u8, argument, "--socket")) {
            index += 1;
            if (index >= args.len) {
                tty.print(.err, "chock daemon: --socket needs a value.\n\n", .{});
                tty.print(.err, "{s}", .{usage_text});
                return error.BadArguments;
            }
            if (!std.fs.path.isAbsolute(args[index])) {
                tty.print(
                    .err,
                    "chock daemon: --socket takes an absolute path, and \"{s}\" is not one.\n",
                    .{args[index]},
                );
                return error.BadArguments;
            }
            options.socket = args[index];
            continue;
        }

        tty.print(.err, "chock daemon: there is no option named {s}.\n\n", .{argument});
        tty.print(.err, "{s}", .{usage_text});
        return error.BadArguments;
    }

    // **A port with no host names nothing.** There is no TCP listener unless
    // `--host` turns one on, so a person who typed only `--port` believes they
    // have changed something that is not there. Refused rather than obeyed:
    // opening a listener for it is the very default this file exists to
    // remove.
    if (port_named and options.host == null) {
        tty.print(
            .err,
            "chock daemon: --port names the port of the TCP listener --host turns on, and there " ++
                "is no TCP listener without --host. Write `--host 127.0.0.1 --port <n>`, or drop " ++
                "--port and use the unix socket.\n",
            .{},
        );
        return error.BadArguments;
    }
    return options;
}

const testing = std.testing;

test "nothing but the unix socket is listened on until --host says so" {
    // **The transport decision.** A default is not a deliberate choice, and
    // loopback TCP authenticates nobody, so a person who types nothing gets the
    // one transport where the kernel names the peer. `--host` is what adds the
    // other one, and it is not guarded: somebody who types `0.0.0.0` is being
    // deliberately insecure and that is their choice.
    //
    // Mutation check: put the TCP address back in `listenSet` unconditionally
    // and the first block below fails, which is a daemon every local account
    // can drive.
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    var buffer: [max_listeners]control.Address = undefined;

    {
        const plain = try parseOptions(&.{});
        try testing.expect(plain.host == null);
        try testing.expect(plain.socket == null);
        try testing.expectEqual(control.default_port, plain.port);

        const set = listenSet(&buffer, "/state/daemon.sock", plain);
        try testing.expectEqual(@as(usize, 1), set.len);
        try testing.expectEqualStrings("/state/daemon.sock", set[0].unix);
        // Said in the other direction as well, so a set that grew a second TCP
        // address under another name still fails this.
        for (set) |address| try testing.expect(address != .ip);
    }

    {
        const bound = try parseOptions(&.{ "--host", "0.0.0.0", "--port", "9999" });
        try testing.expectEqualStrings("0.0.0.0", bound.host.?);
        const set = listenSet(&buffer, "/state/daemon.sock", bound);
        try testing.expectEqual(@as(usize, 2), set.len);
        // The socket is still first and is still there. A `--host` that
        // replaced the socket would take the checked transport away from a
        // person who only wanted to add one.
        try testing.expectEqualStrings("/state/daemon.sock", set[0].unix);
        try testing.expectEqualStrings("0.0.0.0", set[1].ip.host);
        try testing.expectEqual(@as(u16, 9999), set[1].ip.port);
    }

    // Nothing was said about any of it. A refusal of `--host`, or a warning
    // about it, is what this half of the test exists to catch coming back.
    try testing.expectEqualStrings("", said.err());
    try testing.expectEqualStrings("", said.out());

    for ([_][]const u8{ "--address", "--bind" }) |spelling| {
        const same = try parseOptions(&.{ spelling, "10.0.0.4" });
        try testing.expectEqualStrings("10.0.0.4", same.host.?);
    }

    // **A port with no host is refused rather than obeyed.** Obeying it would
    // mean opening a TCP listener for somebody who never named an address,
    // which is the default this test is about.
    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--port", "9999" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--host") != null);
}

test "the control socket serves the user that started the daemon and nobody else" {
    // **Fault two: the daemon's own control socket checked nobody.** Anything
    // that could reach the socket path could list sessions, read their events
    // and answer their approvals. The kernel already knows who connected, which
    // is the reason this socket has no token.
    //
    // Mutation check: make `peerAllowed` answer true always, and every account
    // on the machine can drive this daemon over a socket they can open.
    const io = testing.io;
    const mine = std.posix.system.getuid();

    // The decision itself, over the three answers the kernel can give. A uid
    // that is not this process's own cannot be arranged here without a second
    // account, so what is driven is the comparison, with the real uid on one
    // side of it.
    try testing.expect(peerAllowed(mine, mine));
    try testing.expect(!peerAllowed(mine +% 1, mine));
    try testing.expect(!peerAllowed(0, mine +% 1));
    // **A peer the kernel would not name is refused.** An absent answer is
    // never a permissive answer.
    try testing.expect(!peerAllowed(null, mine));

    // And the reading itself, over a real unix socket, because a check fed by a
    // call that answers null on this platform would refuse everybody and pass
    // every line above. This is the same call `lib/chock-broker/socket.zig`
    // makes, and there is one copy of it.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const socket_path = try std.fmt.allocPrint(
        testing.allocator,
        "{s}/d.sock",
        .{dir_buffer[0..dir_len]},
    );
    defer testing.allocator.free(socket_path);

    var listener = try (control.Address{ .unix = socket_path }).listen(io);
    defer listener.close(io);
    // A unix listener is what carries a peer credential, and `unix_path` is
    // what `accept` reads to tell the two transports apart.
    try testing.expect(listener.unix_path != null);

    const client = try (control.Address{ .unix = socket_path }).connect(io);
    defer client.close(io);
    const served = try listener.server.accept(io);
    defer served.close(io);

    const said_uid = control.peerUid(served.socket.handle);
    try testing.expectEqual(@as(?std.posix.uid_t, mine), said_uid);
    try testing.expect(peerAllowed(said_uid, mine));
    try testing.expect(!peerAllowed(said_uid, mine +% 1));
}

test "the daemon greets a client of its own number and refuses every other first line" {
    // **The whole connection turns on this line, and nothing below it is read
    // until it agrees.** A daemon that answered a client of another number
    // would be answering a grammar one of the two does not have, and this
    // daemon's verbs start sessions and carry approvals.
    //
    // Driven over buffers, because `greet` takes a reader and a writer: no
    // socket, and the very code a real connection runs.
    //
    // Mutation check: take out the `control.accepts` call and greet back
    // whatever arrived, which is what a real `pcscd` does and what
    // `lib/chock-pcsc` was written against. The second block below then reads
    // as agreed, and a client of another build goes on to send a request.
    const agreed = std.fmt.comptimePrint(
        "{s}{d}\n",
        .{ control.Greeting.ask_prefix, control.protocol_version },
    );

    {
        var reader = std.Io.Reader.fixed(agreed ++ "list /p\n");
        var buffer: [512]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try testing.expect(greet(&reader, &writer));
        try testing.expectEqualStrings(
            std.fmt.comptimePrint(
                "{s}{d}\n",
                .{ control.Greeting.answer_prefix, control.protocol_version },
            ),
            writer.buffered(),
        );
        // And the request line is still there for the read after it, which is
        // what `takeDelimiter` gives and `takeDelimiterExclusive` would not.
        try testing.expectEqualStrings("list /p", (try reader.takeDelimiter('\n')).?);
    }

    {
        const other = control.protocol_version + 1;
        var line_buffer: [64]u8 = undefined;
        const line = try std.fmt.bufPrint(
            &line_buffer,
            "{s}{d}\nstart /p\tgo\n",
            .{ control.Greeting.ask_prefix, other },
        );
        var reader = std.Io.Reader.fixed(line);
        var buffer: [512]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try testing.expect(!greet(&reader, &writer));

        // Both numbers, so a person knows which end to update.
        const said = writer.buffered();
        try testing.expect(std.mem.startsWith(u8, said, control.error_prefix));
        var ours: [16]u8 = undefined;
        var theirs: [16]u8 = undefined;
        try testing.expect(std.mem.indexOf(
            u8,
            said,
            try std.fmt.bufPrint(&ours, "{d}", .{control.protocol_version}),
        ) != null);
        try testing.expect(std.mem.indexOf(
            u8,
            said,
            try std.fmt.bufPrint(&theirs, "{d}", .{other}),
        ) != null);
    }

    // A client built before the greeting existed opens with a verb, which is
    // not a greeting. It is told what to do rather than being served.
    for ([_][]const u8{
        "start /p\tgo\n",
        "list /p\n",
        "adopt /p\t01JQ\n",
        "GET / HTTP/1.1\n",
        "hello chock-control\n",
        "hello something-else 1\n",
        "\n",
    }) |first| {
        var reader = std.Io.Reader.fixed(first);
        var buffer: [1024]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try testing.expect(!greet(&reader, &writer));
        try testing.expect(std.mem.startsWith(u8, writer.buffered(), control.error_prefix));
        try testing.expect(std.mem.indexOf(u8, writer.buffered(), "greeting") != null);
    }

    // And a connection that carried nothing at all is refused rather than
    // waited on.
    {
        var reader = std.Io.Reader.fixed("");
        var buffer: [512]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try testing.expect(!greet(&reader, &writer));
        try testing.expect(std.mem.startsWith(u8, writer.buffered(), control.error_prefix));
    }
}

test "the port and the socket parse, and a value that is not one is refused by name" {
    // **A refused value is named back**, so a person can see which of several
    // arguments the parser objected to.
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    // With `--host`, because a port with no host names nothing and is refused:
    // see the test above.
    try testing.expectEqual(
        @as(u16, 9999),
        (try parseOptions(&.{ "--host", "127.0.0.1", "--port", "9999" })).port,
    );
    // Zero asks the system for one, which is what a test wants.
    try testing.expectEqual(
        @as(u16, 0),
        (try parseOptions(&.{ "--host", "127.0.0.1", "--port", "0" })).port,
    );
    try testing.expectEqualStrings(
        "/run/user/1000/chock/d.sock",
        (try parseOptions(&.{ "--socket", "/run/user/1000/chock/d.sock" })).socket.?,
    );
    // A healthy parse is quiet.
    try testing.expectEqualStrings("", said.err());

    for ([_][]const u8{ "seventy", "70000" }) |value| {
        said.clear();
        try testing.expectError(error.BadArguments, parseOptions(&.{ "--port", value }));
        try testing.expect(std.mem.indexOf(u8, said.err(), value) != null);
    }

    // A relative socket path means something different in every working
    // directory, and a daemon and its clients would then disagree about where
    // it is.
    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--socket", "d.sock" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "absolute") != null);

    for ([_][]const u8{ "--port", "--host", "--socket" }) |flag| {
        said.clear();
        try testing.expectError(error.BadArguments, parseOptions(&.{flag}));
        try testing.expect(std.mem.indexOf(u8, said.err(), flag) != null);
    }

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{"--nonsense"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--nonsense") != null);
    try testing.expectEqualStrings("", said.out());
}

/// One request answered against a real session directory, with nothing
/// spawned. Its own type so every case below reads as one call and one answer.
///
/// **A refusal must not start a child**, so `remembered` is what proves nothing
/// began: `beginSession` records the session before it spawns the thread, and it
/// is the only thing that records one.
const Probe = struct {
    answer: []const u8,
    remembered: usize,
};

fn probeRequest(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    buffer: []u8,
    line: []const u8,
) Probe {
    var writer = std.Io.Writer.fixed(buffer);
    const request = control.Request.parse(line) catch {
        return .{ .answer = "error the request did not parse", .remembered = daemon.sessions.items.len };
    };
    switch (request) {
        .adopt => |one| handleAdopt(daemon, &writer, one),
        .list => |one| handleList(daemon, arena, &writer, one),
        .answer => |one| handleAnswer(daemon, arena, &writer, one),
        .read => |one| handleRead(daemon, arena, &writer, one),
        else => unreachable,
    }
    return .{ .answer = writer.buffered(), .remembered = daemon.sessions.items.len };
}

test "adopt refuses a session it may not take, and starts nothing when it does" {
    // **The process holding the log's exclusive lock owns the session.** So
    // this daemon takes a session only from nobody, and every other case is a
    // refusal that names itself. The success path is a real process spawn and
    // is not driven here; what is driven is every decision made before that
    // spawn, and the proof that none of them reached it.
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const home = dir_buffer[0..dir_len];

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", home);

    var daemon = Daemon{ .gpa = gpa, .io = io, .exe_path = "/nowhere/chock", .env = &env };
    defer daemon.deinit();

    const project = "/some/project";
    const id = "01JQ" ++ "A" ** 22;
    var answer_buffer: [4096]u8 = undefined;

    // A request with no tab at all is a client speaking a protocol this daemon
    // does not have, and it is refused before any handler runs.
    {
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project);
        try testing.expect(std.mem.startsWith(u8, got.answer, "error"));
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    // A relative project would key the session directory on a path that means
    // something different in every working directory.
    {
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt project\t" ++ id);
        try testing.expect(std.mem.indexOf(u8, got.answer, "absolute path") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    // **An identifier is checked before a path is built from it.** A value that
    // reached a path unchecked is a path traversal.
    {
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project ++ "\t../../../etc/passwd");
        try testing.expect(std.mem.indexOf(u8, got.answer, "not a session identifier") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    // A well formed identifier this machine never wrote. **It must not become an
    // empty session under that name**, which is what an unguarded `Log.open`
    // would make.
    {
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project ++ "\t" ++ id);
        try testing.expect(std.mem.indexOf(u8, got.answer, "holds no session") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    // Now give it a real log to look at.
    var paths = try session_paths.pathsFor(gpa, &env, project, id);
    defer paths.deinit();
    try session_paths.create(io, paths);

    // A log with a header and no event is a session with no conversation to
    // carry on from.
    {
        var seed = try chock_proto.log.Log.open(io, paths.log, id);
        seed.close(io);
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project ++ "\t" ++ id);
        try testing.expect(std.mem.indexOf(u8, got.answer, "nothing to carry on from") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    // Give it a conversation.
    {
        const log = try chock_proto.log.Log.open(io, paths.log, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        const content = [_]chock_proto.event.ContentPart{.{ .text = "carry this on" }};
        _ = try locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);
        try locked.unlock(io);
    }

    // **The one that matters: a session somebody owns is not taken from them.**
    // The lock here is held on a second open file description, which is what
    // `flock(2)` contends on. That a genuinely different process is refused as
    // well is pinned by `test/proto/lock.zig`, which spawns one.
    //
    // Mutation check: drop the `.running` case from `handleAdopt` and this
    // daemon starts a second owner for a session that already has one.
    {
        var owner = try chock_proto.log.Log.open(io, paths.log, id);
        defer owner.close(io);
        var held = try owner.lock(io);
        defer held.unlock(io) catch {};

        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project ++ "\t" ++ id);
        try testing.expect(std.mem.indexOf(u8, got.answer, "running now") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }
}

test "a listing over the wire says what the local fold says" {
    // **The fact a frontend rests on.** A browser can never read a log, so
    // everything it shows came through `rowOf`, and a field that was dropped
    // or renamed there would be a listing that quietly disagrees with
    // `chock sessions`.
    //
    // Mutation check: drop `.live` from `rowOf` and the row says `unknown` for
    // a session this test is holding the lock on.
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const home = dir_buffer[0..dir_len];

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", home);

    var daemon = Daemon{ .gpa = gpa, .io = io, .exe_path = "/nowhere/chock", .env = &env };
    defer daemon.deinit();

    const project = "/some/project";
    const id = "01JQ" ++ "A" ** 22;

    var paths = try session_paths.pathsFor(gpa, &env, project, id);
    defer paths.deinit();
    try session_paths.create(io, paths);
    {
        const log = try chock_proto.log.Log.open(io, paths.log, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        const content = [_]chock_proto.event.ContentPart{.{ .text = "hello" }};
        _ = try locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 2);
        try locked.unlock(io);
    }

    var answer_buffer: [64 * 1024]u8 = undefined;
    const got = probeRequest(&daemon, arena, &answer_buffer, "list " ++ project);
    try testing.expect(!std.mem.startsWith(u8, got.answer, "error"));

    // The wire row, parsed back the way a client parses it.
    const line = std.mem.trimEnd(u8, got.answer, "\n");
    const reply = try control.Reply.parse(line);
    var parsed = try control.SessionRow.fromJson(gpa, reply.record.payload);
    defer parsed.deinit();

    // And the local fold, read the way `chock sessions` reads it.
    const dir = try session_paths.projectDir(arena, &env, project);
    const local = try sessions_cmd.list(arena, io, dir);
    try testing.expectEqual(@as(usize, 1), local.len);

    // Field for field. **Written out rather than compared with one call**,
    // because the two types are different on purpose and a `expectEqualDeep`
    // would only be possible if they were the same type, which is the thing
    // this milestone decided against.
    const wire = parsed.value;
    try testing.expectEqualStrings(local[0].id, wire.id);
    try testing.expectEqual(local[0].started_ms, wire.started_ms);
    try testing.expectEqualStrings(local[0].model, wire.model);
    try testing.expectEqual(local[0].model_count, wire.model_count);
    try testing.expectEqualStrings(local[0].model_alias, wire.model_alias);
    try testing.expectEqualStrings(@tagName(local[0].live), wire.live);
    try testing.expectEqualStrings(local[0].end.?.wireName(), wire.end.?);
    try testing.expectEqual(local[0].spend.turns, wire.turns);
    try testing.expectEqual(local[0].spend.input_tokens, wire.input_tokens);
    try testing.expectEqual(local[0].spend.output_tokens, wire.output_tokens);
    try testing.expectEqual(local[0].spend.enforceable(), wire.spend_enforceable);
    try testing.expectEqual(local[0].readable, wire.readable);
    try testing.expectEqual(local[0].complete, wire.complete);
    try testing.expectEqualStrings(@tagName(local[0].chain.verdict), wire.chain);
    try testing.expectEqual(local[0].chain.events, wire.chain_events);
    try testing.expectEqual(local[0].chain.chained, wire.chain_chained);
    try testing.expectEqual(local[0].has_work, wire.has_work);
    try testing.expectEqual(local[0].has_root, wire.has_root);

    // The session ended and nobody holds the lock, so the fold and the row
    // agree that it is idle. A row that always said `unknown` would pass a
    // weaker version of this test.
    try testing.expectEqualStrings("idle", wire.live);
    try testing.expectEqualStrings("finished", wire.end.?);
}

test "a listing of a project with no sessions is an empty answer and not a refusal" {
    // A project nobody has run a session in is an ordinary thing, and a
    // frontend showing "no sessions yet" needs an answer it can tell apart
    // from a fault.
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", dir_buffer[0..dir_len]);

    var daemon = Daemon{ .gpa = gpa, .io = io, .exe_path = "/nowhere/chock", .env = &env };
    defer daemon.deinit();

    var answer_buffer: [4096]u8 = undefined;
    const got = probeRequest(&daemon, arena_state.allocator(), &answer_buffer, "list /never/run/here");
    try testing.expectEqualStrings("", got.answer);

    // A relative project is still refused, because it would key a directory on
    // whatever the daemon's own working directory happened to be.
    const relative = probeRequest(&daemon, arena_state.allocator(), &answer_buffer, "list project");
    try testing.expect(std.mem.indexOf(u8, relative.answer, "absolute path") != null);
}

test "answering a session that is not listening is a refusal and never a silent yes" {
    // **An approval nobody could deliver must not read as one that was
    // given.** This daemon cannot write into a session's log, so the only way
    // an answer lands is that session's own socket taking it, and a connect
    // that failed is a fact the client has to be told.
    //
    // Mutation check: answer `ok answered` when the connect fails and a
    // frontend shows an approval as sent that nothing ever received.
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", dir_buffer[0..dir_len]);

    var daemon = Daemon{ .gpa = gpa, .io = io, .exe_path = "/nowhere/chock", .env = &env };
    defer daemon.deinit();

    const id = "01JQ" ++ "A" ** 22;
    var answer_buffer: [4096]u8 = undefined;

    const got = probeRequest(
        &daemon,
        arena_state.allocator(),
        &answer_buffer,
        "answer /some/project\t" ++ id ++ "\t128\tyes",
    );
    // **The property, and not one sentence of it.** Which refusal arrives
    // depends on the machine: a session directory deep enough makes the socket
    // path longer than `control.max_socket_path`, and a shallow one reaches the
    // connect and finds nothing listening. Both are refusals and neither is an
    // answer, which is the whole fact this test is about. A test that named one
    // sentence would pass on one machine and fail on another.
    try testing.expect(std.mem.startsWith(u8, got.answer, control.error_prefix));
    try testing.expect(std.mem.indexOf(u8, got.answer, "answered") == null);
    try testing.expect(std.mem.indexOf(u8, got.answer, control.ok_prefix) == null);

    // An identifier that is not one is refused before a path is built from it,
    // the same rule every other verb keeps.
    const traversal = probeRequest(
        &daemon,
        arena_state.allocator(),
        &answer_buffer,
        "answer /some/project\t../../../etc\t1\tyes",
    );
    try testing.expect(std.mem.indexOf(u8, traversal.answer, "not a session identifier") != null);
}

test "read serves only a session this daemon started, and never a path a client named" {
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();

    var daemon = Daemon{ .gpa = gpa, .io = io, .exe_path = "/nowhere/chock", .env = &env };
    defer daemon.deinit();

    var answer_buffer: [4096]u8 = undefined;
    const got = probeRequest(
        &daemon,
        arena_state.allocator(),
        &answer_buffer,
        "read 01JQ" ++ "A" ** 22 ++ " 0",
    );
    try testing.expect(std.mem.indexOf(u8, got.answer, "did not start a session") != null);

    const bad = probeRequest(&daemon, arena_state.allocator(), &answer_buffer, "read ../../etc/passwd 0");
    try testing.expect(std.mem.indexOf(u8, bad.answer, "not a session identifier") != null);
}
