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
const builtin = @import("builtin");
const chock_auth = @import("chock-auth");
const chock_broker = @import("chock-broker");
const chock_container = @import("chock-container");
const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");
const vmm = @import("chock-vmm");
const chock_proto = @import("chock-proto");

const run_cmd = @import("run.zig");
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
    /// The child running a turn now, or null for a session running none. Held
    /// under the daemon's own mutex, because the thread that reaps a child
    /// clears it while another may be reading it.
    pid: ?std.posix.pid_t = null,
    /// The guest this session's tool calls run in, for a daemon whose operator
    /// chose the microVM driver. Null for every other session.
    guest: ?Guest = null,
};

/// One guest in a forked process of this daemon's, and the socket a `chock run`
/// child reaches it through.
///
/// **It outlives a turn and not the daemon.** `chock run` exits at the end of every
/// turn, so a guest owned by the child would boot and die each time. The daemon owns
/// it instead, which is also what keeps the vCPU threads out of the process that
/// dispatches tool calls.
///
/// **A process and not a thread, because the boundary round it goes on a whole
/// process.** A seccomp filter and a Landlock domain cannot be taken off again, so
/// a guest on a thread of this daemon could only be confined by confining the
/// daemon with it.
const Guest = struct {
    /// Everything the guest's own thread reads and writes. On the heap, because the
    /// thread outlives the call that started it.
    running: *Running,
    /// Where the guest is listening. Owned.
    socket: [:0]u8,
    /// Bumped as each turn starts. The thread that reaps a turn stops the guest
    /// only if this has not moved while it waited, so a session whose next turn
    /// arrived keeps the guest it already has.
    turns: u64 = 0,
};

/// What a guest's own thread and the daemon share.
///
/// **The thread no longer runs the guest; it forks it and then holds it.** A guest
/// is asked to stop by `PR_SET_PDEATHSIG`, which the kernel sends when the thread
/// that forked ends rather than when its process does, so the thread has to live
/// exactly as long as the guest. See `runGuest`.
const Running = struct {
    thread: std.Thread,
    /// Set by the thread once the guest says its socket is bound, so the daemon
    /// waits on a flag rather than looking for a file to appear.
    ready: std.atomic.Value(bool) = .init(false),
    /// Set by the daemon to ask the guest to stop.
    stopping: std.atomic.Value(bool) = .init(false),
    /// Set by the thread when it has given up on the guest, so a `ready` that
    /// never arrives can be told from a guest still coming up.
    ended: std.atomic.Value(bool) = .init(false),
};

/// How long a guest is kept after a turn ends.
///
/// **A window and not a session end event, because the daemon has none.**
/// `session.end` is written at the end of every turn and a session can be taken up
/// again with `--adopt`, so nothing in the log says a session will never run
/// another turn. Keeping the guest for a while covers the turns of one
/// conversation, and letting it go bounds what a daemon left running holds.
const guest_idle_ms: u64 = 5 * std.time.ms_per_min;

/// How long to wait for a guest to come up. `chock vmm` binds its socket after it
/// has read and measured the kernel, which takes a moment on a 17MB image.
const guest_boot_ms: u64 = 30 * std.time.ms_per_s;

/// How often to look for the socket while waiting.
const guest_look_ms: u64 = 100;

/// How many guests one daemon will hold at once. Each is a kernel and its memory,
/// so this is a real bound and not a round number: a client that opened sessions
/// in a loop must not be able to fill the machine.
const max_guests: usize = 4;

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
    /// What the operator's own `config.zon` says about sandboxing. Read once at
    /// start: a file edited under a running daemon changes the next daemon.
    sandbox: chock_policy.sandbox.Block = .{},
    /// The directory the daemon's own socket is in, which is where a guest's goes.
    /// Short on purpose: see `guestSocketPath`.
    socket_dir: []const u8 = "",

    fn deinit(self: *Daemon) void {
        for (self.sessions.items) |entry| {
            self.gpa.free(entry.log_path);
            self.gpa.free(entry.project);
            if (entry.guest) |one| {
                // The daemon is going, so every guest goes with it.
                one.running.stopping.store(true, .release);
                one.running.thread.join();
                self.gpa.destroy(one.running);
                self.gpa.free(one.socket);
            }
        }
        self.sessions.deinit(self.gpa);
        self.sandbox.deinit(self.gpa);
    }

    /// The guest of a session, and the turn number it is now on. Null when the
    /// session has none.
    fn guestFor(self: *Daemon, id: []const u8) ?Guest {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |entry| {
            if (std.mem.eql(u8, &entry.id, id)) return entry.guest;
        }
        return null;
    }

    /// Remember a guest, and say whether it was taken. False means another thread
    /// put one there first, and the caller stops the one it started.
    fn rememberGuest(self: *Daemon, id: []const u8, one: Guest) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            if (entry.guest != null) return false;
            entry.guest = one;
            return true;
        }
        return false;
    }

    /// Say a turn has begun, and answer which turn it is. The number is what a
    /// reaping thread compares against to know whether a later turn arrived.
    fn noteTurn(self: *Daemon, id: []const u8) ?u64 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            const one = &(entry.guest orelse return null);
            one.turns += 1;
            return one.turns;
        }
        return null;
    }

    /// Take a session's guest away, but only if it is still on `turns`. Answers the
    /// guest the caller now owns and must stop.
    fn takeGuest(self: *Daemon, id: []const u8, turns: u64) ?Guest {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            const one = entry.guest orelse return null;
            if (one.turns != turns) return null;
            entry.guest = null;
            return one;
        }
        return null;
    }

    /// How many sessions hold a guest right now.
    fn guestCount(self: *Daemon) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var count: usize = 0;
        for (self.sessions.items) |entry| {
            if (entry.guest != null) count += 1;
        }
        return count;
    }

    fn remember(self: *Daemon, entry: Session) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.sessions.append(self.gpa, entry);
    }

    /// Remember which process is running a session's turn, or that none is.
    fn notePid(self: *Daemon, id: []const u8, pid: ?std.posix.pid_t) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (std.mem.eql(u8, &entry.id, id)) entry.pid = pid;
        }
    }

    /// The process running a session's turn, or null. Read under the lock, so a
    /// caller never signals a number another thread has just replaced.
    fn pidFor(self: *Daemon, id: []const u8) ?std.posix.pid_t {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |entry| {
            if (std.mem.eql(u8, &entry.id, id)) return entry.pid;
        }
        return null;
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

    // A real allocator here, unlike `chock run`'s session phase. This process does
    // fork, for a guest, but the forked side builds an allocator of its own and
    // asks this `std.Io` for nothing that takes its lock: see `childMain` in
    // `src/vmm.zig`. So a thread here is still free.
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

    // **Refused rather than narrowed.** An operator who asked for a guest and is
    // given the native driver instead gets a weaker boundary than they asked for,
    // and nothing would say so. The refusal names the key that is missing.
    daemon.sandbox = readSandbox(gpa, io, arena, &env) orelse return Exit.usage.code();
    if (daemon.sandbox.missing()) |key| {
        tty.print(
            .err,
            "chock daemon: config.zon chose the microvm sandbox driver and names no {s}. " ++
                "Add .sandbox = .{{ .{s} = \"...\" }} to it. The guest images are the flake's " ++
                "own guest-kernel and guest-initrd outputs.\n",
            .{ key, key },
        );
        return Exit.usage.code();
    }
    if (daemon.sandbox.chosen() == .microvm) {
        tty.print(.plain, "chock daemon: tool calls run in a microVM guest, one a session\n", .{});
    }

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

    // A guest's socket goes here too, so the length that matters is this one's.
    daemon.socket_dir = std.fs.path.dirname(socket_path) orelse ".";

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
/// The `sandbox` block of the operator's own `config.zon`, or null when the file
/// is there and does not read. **A file that is not there is not a fault**: most
/// machines have none, and one that says nothing means the native driver.
fn readSandbox(
    gpa: std.mem.Allocator,
    io: std.Io,
    arena: std.mem.Allocator,
    env: *std.process.Environ.Map,
) ?chock_policy.sandbox.Block {
    const dir = chock_auth.paths.configDir(arena, env) catch return .{};
    const path = std.fs.path.joinZ(arena, &.{ dir, chock_auth.config.file_name }) catch return .{};

    const source = std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        arena,
        .limited(chock_auth.config.max_file_bytes),
        .of(u8),
        0,
    ) catch return .{};

    var diag: ?chock_policy.sandbox.Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    // **The whole file is zeroed once it is parsed, and a provider token is why.**
    // `config.zon` can carry one inline, and this buffer is in an arena that lives
    // as long as the daemon. `parse` scrubs the tree it builds, and the block it
    // answers owns every string in it, so nothing left here points back into
    // these bytes.
    defer std.crypto.secureZero(u8, source);
    return chock_policy.sandbox.parse(gpa, source, &diag) catch {
        if (diag) |*one| {
            tty.print(.err, "chock daemon: {s}: {f}\n", .{ path, one });
        } else {
            tty.print(.err, "chock daemon: {s} could not be read\n", .{path});
        }
        return null;
    };
}

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
        .create => |one| handleCreate(daemon, writer, one),
        .prompt => |one| handlePrompt(daemon, writer, one),
        .cancel => |one| handleCancel(daemon, writer, one),
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
    beginSession(daemon, writer, one.project, id, .{ .say = one.message });
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

    beginSession(daemon, writer, one.project, id, .carry_on);
}

/// `create <project directory>`: a session with a log and nothing running.
///
/// For a caller that has to name a session before it has anything to say in it.
/// `session/new` in the agent client protocol answers with an identifier and no
/// prompt, and `start` cannot do that: it makes a session and says something in
/// it at once.
fn handleCreate(daemon: *Daemon, writer: *std.Io.Writer, one: control.Request.Create) void {
    if (one.project.len == 0) {
        fail(writer, "create needs a project directory, and it cannot be empty");
        return;
    }
    if (!std.fs.path.isAbsolute(one.project)) {
        fail(writer, "the project directory has to be an absolute path");
        return;
    }

    beginSession(daemon, writer, one.project, session_paths.newId(daemon.io), .nothing);
}

/// `prompt <project directory>\t<session id>\t<message>`: one more message in a
/// session that already exists, and the turn it starts.
///
/// **A session nothing has written yet is not a fault here.** `create` answers
/// with an identifier before any log exists, so the first `prompt` on it is what
/// makes the log. `chock_proto.log.Log.open` creates, which is what lets that
/// work without a verb of its own.
///
/// What is refused is a session somebody is running now, the same thing `adopt`
/// refuses and for the same reason: the process holding the log's lock owns it,
/// and a second child would be a second owner.
fn handlePrompt(daemon: *Daemon, writer: *std.Io.Writer, one: control.Request.Prompt) void {
    const id = checkedSession(writer, one.project, one.session) orelse return;
    if (one.message.len == 0) {
        fail(writer, "prompt needs a message, and it cannot be empty");
        return;
    }

    var paths = session_paths.pathsFor(daemon.gpa, daemon.env, one.project, &id) catch {
        fail(writer, "the session path could not be built");
        return;
    };
    defer paths.deinit();

    switch (sessions_cmd.readinessOf(daemon.gpa, daemon.io, paths.log, &id)) {
        .running => {
            fail(writer, "that session is running now, and the process holding its log's lock owns it");
            return;
        },
        // Every other reading is a session this may write to, including one no
        // log exists for yet.
        .ready, .no_such_session, .nothing_to_carry_on, .unknown => {},
    }

    beginSession(daemon, writer, one.project, id, .{ .say = one.message });
}

/// `cancel <project directory>\t<session id>`: stop the turn a session is
/// running now.
///
/// **An interrupt and never a kill.** Chock's own handler ends the session with
/// `canceled_by_user` and writes that to the log, so a client reading the log
/// learns why it stopped. A killed child would leave the log stopping mid turn
/// with nothing saying why, which is the fault `src/interrupt.zig` exists to
/// prevent.
///
/// A session running nothing is not a fault: the agent client protocol says a
/// client may cancel a turn that has already ended, and answering that with a
/// failure would make a race look like a bug.
fn handleCancel(daemon: *Daemon, writer: *std.Io.Writer, one: control.Request.Cancel) void {
    const id = checkedSession(writer, one.project, one.session) orelse return;

    const pid = daemon.pidFor(&id) orelse {
        say(writer, .{ .ok = "that session is running nothing" });
        return;
    };

    std.posix.kill(pid, .INT) catch |err| switch (err) {
        // It ended between the read and the signal, which is the same answer as
        // running nothing.
        error.ProcessNotFound => {
            say(writer, .{ .ok = "that session is running nothing" });
            return;
        },
        else => {
            fail(writer, "that session's turn could not be interrupted");
            return;
        },
    };
    say(writer, .{ .ok = "interrupted" });
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
/// What a verb wants done with the session it names.
const Begin = union(enum) {
    /// Run a turn on this message. `start` and `prompt` both do this.
    say: []const u8,
    /// Run, carrying on from what the log already holds. `adopt` does this.
    carry_on,
    /// Make the session and run nothing. `create` does this, for a caller that
    /// has to name a session before it has anything to say in it.
    nothing,
};

/// **One path for every verb that names a session**, because they differ in
/// exactly one thing: what `Begin` says to do. Everything after that is the same
/// session, in the same kind of child, writing the same log.
fn beginSession(
    daemon: *Daemon,
    writer: *std.Io.Writer,
    project: []const u8,
    id: [session_paths.id_length]u8,
    begin: Begin,
) void {
    // Before the session exists at all, because refusing it a guest here is not
    // refusing it one: the child forks its own whenever this daemon hands it no
    // socket. See `run_cmd.chockOwnInProject`.
    if (daemon.sandbox.chosen() == .microvm and refuseChockOwn(daemon, writer, project)) return;

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

    if (begin == .nothing) {
        // The log is made here, so the session exists the moment its identifier
        // is handed out. `watch` refuses a session with no log, and a client that
        // was given an identifier it cannot yet watch would have been told about
        // something that is not there.
        var opened = openLog(daemon, writer, log_path, &id) orelse return;
        opened.backing.log.close(daemon.io);
    }

    if (begin != .nothing) {
        const owned_message: ?[]u8 = switch (begin) {
            .say => |text| daemon.gpa.dupe(u8, text) catch {
                fail(writer, "out of memory");
                return;
            },
            .carry_on, .nothing => null,
        };

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
    }

    var text_buffer: [std.fs.max_path_bytes + session_paths.id_length + 8]u8 = undefined;
    const text = std.fmt.bufPrint(&text_buffer, "{s}\t{s}", .{ id, log_path }) catch {
        fail(writer, "the answer was longer than this daemon can write");
        return;
    };
    say(writer, .{ .ok = text });
}

/// Whether this project is one no session may run against, because a guest for
/// it would be granted a directory of Chock's own. True means the client has
/// already been told, with both paths named.
///
/// **No session, and not a narrower grant.** A grant that quietly left the
/// project's backing out is a session whose every git read fails, and a daemon
/// that answered no socket would have the child fork a guest of its own over the
/// same project: see `run_cmd.chockOwnInProject`.
fn refuseChockOwn(daemon: *Daemon, writer: *std.Io.Writer, project: []const u8) bool {
    var room = std.heap.ArenaAllocator.init(daemon.gpa);
    defer room.deinit();
    const arena = room.allocator();

    const held = run_cmd.chockOwnInProject(arena, daemon.io, daemon.env, project) catch {
        fail(writer, "whether a guest for that project would hold one of Chock's own directories " ++
            "cannot be answered, so no session runs for it");
        return true;
    } orelse return false;

    const said = std.fmt.allocPrint(
        arena,
        "the project {s} holds {s}, which is Chock's own, so no session runs for it. A guest " ++
            "granted that directory reads this user's credentials. Name the project itself.",
        .{ held.project, held.own },
    ) catch {
        fail(writer, "that project holds one of Chock's own directories, so no session runs for it");
        return true;
    };
    tty.print(.err, "chock daemon: {s}\n", .{said});
    fail(writer, said);
    return true;
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

    // The guest this session's tool calls run in, started before the child so the
    // socket is there when it connects. A session that never runs a turn boots
    // none.
    const guest = startGuest(daemon, &child.id, child.project);
    const turn = daemon.noteTurn(&child.id);
    // Let it go after a while, unless another turn arrives first. See
    // `guest_idle_ms`: the daemon has no signal that a session is finished.
    defer if (turn) |which| releaseGuestLater(daemon, child.id, which);

    var argv_buffer: [10][]const u8 = undefined;
    var argv_len: usize = 0;
    for ([_][]const u8{ daemon.exe_path, "run", "--project", child.project, "--session", &child.id }) |word| {
        argv_buffer[argv_len] = word;
        argv_len += 1;
    }
    if (guest) |socket| {
        argv_buffer[argv_len] = "--guest";
        argv_buffer[argv_len + 1] = socket;
        argv_len += 2;
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

    if (process.id) |pid| daemon.notePid(&child.id, pid);
    // Cleared however the wait ends, so a signal never reaches a number the
    // kernel has given to somebody else.
    defer daemon.notePid(&child.id, null);

    const term = process.wait(daemon.io) catch |err| {
        tty.print(.err, "chock daemon: session {s} could not be waited for: {t}\n", .{ child.id, err });
        return;
    };
    switch (term) {
        .exited => |status| tty.print(.plain, "chock daemon: session {s} exited {d}\n", .{ child.id, status }),
        else => tty.print(.warn, "chock daemon: session {s} did not exit normally\n", .{child.id}),
    }
}

/// The socket of this session's guest, starting one if it has none. Null for a
/// daemon whose operator did not choose the microVM driver, and for a guest that
/// would not come up.
///
/// **A guest that will not start is not a session that runs without one.** The
/// child would sandbox tool calls with the native driver, which on a Mac is a
/// weaker boundary than the operator asked for. So the socket is null, the child
/// is told nothing, and the child forks a guest of its own rather than falling
/// back: see `forkOwnGuest` in `src/run.zig`. Which is also why a project this
/// daemon may grant nothing is turned away in `beginSession` and not here.
fn startGuest(
    daemon: *Daemon,
    id: *const [session_paths.id_length]u8,
    project: []const u8,
) ?[:0]const u8 {
    if (daemon.sandbox.chosen() != .microvm) return null;
    if (daemon.guestFor(id)) |had| return had.socket;

    if (daemon.guestCount() >= max_guests) {
        tty.print(
            .warn,
            "chock daemon: session {s} gets no guest: this daemon already holds {d}, which is " ++
                "all it will\n",
            .{ id, max_guests },
        );
        return null;
    }

    const socket = guestSocketPath(daemon, id) orelse return null;
    var socket_owned = true;
    defer if (socket_owned) daemon.gpa.free(socket);

    // The share set lives here and is freed once the fork has copied it, which
    // is the guest's own thread's first act. An arena because the set is a dozen
    // paths built out of the session's identifier and the project's.
    const room = daemon.gpa.create(std.heap.ArenaAllocator) catch return null;
    var room_owned = true;
    defer if (room_owned) {
        room.deinit();
        daemon.gpa.destroy(room);
    };
    room.* = std.heap.ArenaAllocator.init(daemon.gpa);

    const shares = guestShares(room.allocator(), daemon, id, project) orelse return null;

    const running = daemon.gpa.create(Running) catch return null;
    var running_owned = true;
    defer if (running_owned) daemon.gpa.destroy(running);
    running.* = .{ .thread = undefined };

    // Read once, so the processor count and the memory size are chosen against
    // the same numbers.
    const guest_machine = chock_policy.sandbox.Machine.now();

    const work = GuestWork{
        .daemon = daemon,
        .running = running,
        .options = .{
            .kernel = daemon.sandbox.kernel.?,
            .initrd = daemon.sandbox.initrd,
            .session = socket,
            .memory_mb = daemon.sandbox.memory(guest_machine, builtin.os.tag),
            .cpus = daemon.sandbox.processors(guest_machine, builtin.os.tag),
            .shares = shares,
            // The fork makes the channel, so nothing here can name it.
            .control = vmm.fork_sets_control,
        },
        .shares = room,
    };

    running.thread = std.Thread.spawn(.{}, runGuest, .{work}) catch |err| {
        tty.print(.err, "chock daemon: session {s} could not be given a guest: {t}\n", .{ id, err });
        return null;
    };
    room_owned = false;

    if (!waitForGuest(daemon.io, running)) {
        tty.print(
            .err,
            "chock daemon: the guest of session {s} did not come up, so the session runs none\n",
            .{id},
        );
        running.stopping.store(true, .release);
        running.thread.join();
        return null;
    }

    if (!daemon.rememberGuest(id, .{ .running = running, .socket = socket })) {
        // Another turn of this session got there first, so this one is spare.
        running.stopping.store(true, .release);
        running.thread.join();
        return daemon.guestFor(id).?.socket;
    }
    socket_owned = false;
    running_owned = false;
    tty.detail("chock daemon: session {s} has a guest at {s}\n", .{ id, socket });
    return socket;
}

/// What one guest's thread is given. Every part of it outlives the call that
/// started the thread.
const GuestWork = struct {
    daemon: *Daemon,
    running: *Running,
    options: vmm.Options,
    /// Holds `options.shares`. Released once the fork has copied the set.
    shares: *std.heap.ArenaAllocator,
};

/// Fork one guest and hold it until this daemon lets it go.
///
/// **The fork is here, and not on the thread that asked for a guest.** The kernel
/// kills a forked guest when the thread that forked it ends, and the thread that
/// asks for one lives for a turn and the idle window after it. `takeGuest`
/// answers null when a later turn bumped the count, so that thread ends while a
/// guest the next turn is using is still alive: forking there would kill a guest
/// in the middle of a turn. This thread ends when the guest is let go and at no
/// other time.
///
/// **Nothing of Mirage runs here any more.** The machine, its processors and the
/// ticker that interrupts them are all in the forked process, which is also the
/// only process the seccomp filter and the Landlock domain go on.
fn runGuest(work: GuestWork) void {
    const daemon = work.daemon;
    const running = work.running;

    // **The guest's console is this daemon's own output.** A person running the
    // daemon in a terminal reads it there, and `chock serve` forwards it. It
    // crosses the fork as a descriptor, because the forked process can open no
    // file outside the directories it serves.
    const console = std.Io.File.stdout();

    var child = vmm.forkHost(daemon.io, work.options, console.handle) catch |err| {
        tty.print(.err, "chock daemon: a guest's own process could not be started: {t}\n", .{err});
        releaseShares(daemon, work.shares);
        running.ended.store(true, .release);
        return;
    };
    // The fork copied the set, so this side has no further use for it.
    releaseShares(daemon, work.shares);

    // Registered before the flag below, so the flag is stored first: a daemon
    // waiting on a guest that will not come up must not also wait for it to be
    // reaped.
    defer {
        child.stop();
        const code = child.wait();
        if (code == 0) {
            tty.detail("chock daemon: a guest's own process ended, answering 0\n", .{});
        } else {
            tty.print(.err, "chock daemon: a guest's own process ended badly, answering {d}\n", .{code});
        }
        // **This end removes the socket, and not the guest.** The path is not in
        // the share set, so Landlock refuses the forked process its own unlink,
        // and a file left behind is one the next guest of this name trips over.
        std.Io.Dir.deleteFileAbsolute(daemon.io, work.options.session) catch {};
    }
    defer running.ended.store(true, .release);

    // **An empty set, and the line is still written.** The whole of what this
    // guest may serve crossed the fork in `options.shares`; the forked process
    // reads one line before it confines itself, and a parent that sent none would
    // leave it waiting for ever.
    child.sendShares(daemon.gpa, &.{}) catch |err| {
        tty.print(
            .err,
            "chock daemon: a guest's own process would not be told to start ({t}), so it is " ++
                "already gone\n",
            .{err},
        );
        return;
    };

    child.waitReady(daemon.io, guest_boot_ms) catch |err| {
        if (child.fault()) |said| {
            if (said.detail.len == 0) {
                tty.print(.err, "chock daemon: a guest: {s}.\n", .{said.said});
            } else {
                tty.print(.err, "chock daemon: a guest: {s}: {s}\n", .{ said.said, said.detail });
            }
        }
        tty.print(.err, "chock daemon: a guest did not come up: {t}\n", .{err});
        return;
    };
    if (child.sev != .off) {
        tty.print(.dim, "chock daemon: a guest's memory is encrypted ({s}).\n", .{child.sev.text()});
    }
    running.ready.store(true, .release);

    while (!running.stopping.load(.acquire)) {
        std.Io.sleep(daemon.io, .fromNanoseconds(guest_look_ms * std.time.ns_per_ms), .awake) catch
            return;
    }
}

fn releaseShares(daemon: *Daemon, room: *std.heap.ArenaAllocator) void {
    room.deinit();
    daemon.gpa.destroy(room);
}

/// Every directory a session's guest may serve: the Landlock domain of the
/// guest's own process, and the set it is offered, which are one list.
///
/// **A superset of what the child offers, and derived the same way.**
/// `chock run` works out the exact set once its workspace exists and offers it
/// over the session socket, but a Landlock domain can only ever be narrowed and
/// this one goes on before the guest's first thread runs. So this names the roots
/// those offers sit under, each from the session identifier and the project the
/// child is given. A share outside them is refused where it is offered, by name:
/// see `offerShare` in `src/vmm.zig`.
///
/// **It makes the directories it names.** `allowPath` refuses a path that is not
/// there, which would mean no guest at all rather than a narrower one, and the
/// session's own scratch does not exist until a turn runs. The child makes the
/// same ones and both are content with a directory that is already there.
///
/// **It grants nothing a session does not ask for.** An image tree is granted
/// only to a project that names an image, and the knowledgebase only when its
/// directory could be made. The grant is also the offer list, so a root granted
/// beyond what the child offers is a root an escape inside the guest reaches for
/// nothing.
///
/// **A `workspace.binds` entry is deliberately not here.** It names a host path
/// the project's `chock.zon` asked for, and whether the session may have it is
/// the policy's answer against the child's own spawn chain. Granting one here
/// would widen this guest's domain on the strength of a declaration nothing has
/// approved yet, so such a session is refused by name instead: the refusal comes
/// from `attachGuest` in `src/run.zig`, which names the path and says that
/// `chock run` on its own starts a guest with that directory in it. Only a
/// `read_only` or `write` bind becomes a mount, so a project whose binds are all
/// `copy` or `temp_copy` is unaffected.
/// The most roots `guestShares` can ever name, counted from the set itself.
///
/// **Every granted root is a path a compromised VMM may mount**, so the number is
/// worth saying out loud and worth keeping true: `docs/security/microvm.md` names
/// it and `test/docs/claims.zig` checks that page against this. Six roots are
/// always asked for, two of them conditionally, and the toolchain is one entry on
/// a machine with a store and one for each of this machine's own system
/// directories on a machine without one.
pub const max_granted_roots: usize = run_cmd.host_toolchain_candidates.len - 1 + 6;

fn guestShares(
    arena: std.mem.Allocator,
    daemon: *Daemon,
    id: *const [session_paths.id_length]u8,
    project: []const u8,
) ?[]const vmm.Options.Share {
    // The real path, because `chock run` resolves the project before it keys
    // anything on it and every directory below is keyed on a hash of that path.
    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = realPathOf(daemon.io, project, &project_buffer) orelse {
        tty.print(.err, "chock daemon: {s} has no real path, so no guest is started\n", .{project});
        return null;
    };

    var out: std.ArrayList(vmm.Options.Share) = .empty;
    // Reused, because `grant` dupes the path it is given into the arena before
    // this comes round again.
    var resolve_buffer: [std.fs.max_path_bytes]u8 = undefined;

    // The store, or this machine's own system directories when it has none. One
    // function with `chock run`, because a guest granted a different set from the
    // one its session binds is a session whose every tool call fails.
    const toolchain = run_cmd.hostToolchainPaths(arena, daemon.io) catch return null;
    for (toolchain) |path| grant(arena, &out, daemon.io, path, false) catch return null;

    const paths = session_paths.pathsFor(arena, daemon.env, root, id) catch return null;
    session_paths.create(daemon.io, paths) catch return null;
    // Writable, and the one entry that covers four of the child's: the attempt
    // directory, its object store, its worktree metadata and the pointer file all
    // sit under this.
    grant(arena, &out, daemon.io, paths.work, true) catch return null;

    // The project's own git directory, read only, which is where the workspace's
    // real objects and refs stay. A project whose `.git` is a file, or which is no
    // repository at all, gets an overlay backing instead, whose lower layer is the
    // project itself.
    const backing = run_cmd.projectGrantDir(arena, daemon.io, root) catch return null;

    // **The project is the only root here that a client names, and nothing
    // bounds where it is.** A project at or above Chock's own directories, and
    // `--project /` is the same shape, would put `credentials.zon` inside a read
    // grant. `beginSession` turns such a session away before this is reached, so
    // the set below is never built for one, and this asks the same question again
    // for any later caller of this function. The whole answer is in one place
    // because a refusal that only moved the grant into the child closed nothing:
    // see `run_cmd.chockOwnInProject`. Never a set with the backing quietly left
    // out, which is a session whose every git read fails.
    if (run_cmd.chockOwnInProject(arena, daemon.io, daemon.env, root) catch return null) |held| {
        tty.print(
            .err,
            "chock daemon: the project {s} holds {s}, which is Chock's own, so no guest is " ++
                "started for it. A guest granted that directory reads this user's " ++
                "credentials. Name the project itself.\n",
            .{ held.project, held.own },
        );
        return null;
    }
    grant(arena, &out, daemon.io, backing, false) catch return null;

    // One image tree, read only, and only for a project that names an image. The
    // name is read from the same `container` block the child reads, so the two
    // cannot pick different trees, and a project with no block is granted none of
    // them: every other project's image sits in that directory too.
    if (imageDirFor(arena, daemon.io, daemon.env, root)) |dir| {
        session_paths.createImageDir(daemon.io, dir) catch return null;
        grant(arena, &out, daemon.io, dir, false) catch return null;
    }

    // The toolchain cache and the scratchpad, the two a tool call writes outside
    // the workspace. Resolved the way the child resolves them, because a link in
    // the path would otherwise make the two spell one directory two ways.
    const cache_dir = session_paths.cacheDir(arena, daemon.env, root) catch return null;
    // The layout and not a bare directory, and the answer is said out loud for
    // the reason `session_paths.createCacheDir` gives: a persistent directory of
    // Chock's is never one a user finds later and cannot explain. The child says
    // it for a session it starts itself, and cannot once this has made it.
    // The diagnostic carries which of the layout's directories failed and why,
    // which `chock run` says and a bare refusal here threw away.
    var cache_diag: ?chock_core.Diagnostic = null;
    const cache_made = session_paths.createCacheDir(
        daemon.io,
        cache_dir,
        chock_core.cache.sinkOf(arena, &cache_diag),
    ) catch {
        if (cache_diag) |fault| {
            tty.print(
                .err,
                "chock daemon: the toolchain cache {s} could not be made ({f}), so no guest is " ++
                    "started: a session whose cache is missing has nowhere but the workspace " ++
                    "to write.\n",
                .{ cache_dir, fault },
            );
        } else {
            tty.print(
                .err,
                "chock daemon: the toolchain cache {s} could not be made, so no guest is " ++
                    "started.\n",
                .{cache_dir},
            );
        }
        return null;
    };
    if (cache_made) {
        tty.print(
            .plain,
            "chock daemon: this project has no toolchain cache yet, so one is made at {s}. " ++
                "`chock cache clear` empties it.\n",
            .{cache_dir},
        );
    }
    grant(arena, &out, daemon.io, resolvedOr(daemon.io, cache_dir, &resolve_buffer), true) catch
        return null;

    const scratch_dir = session_paths.scratchpadDir(arena, daemon.env, id) catch return null;
    session_paths.createDirAll(daemon.io, scratch_dir) catch return null;
    grant(arena, &out, daemon.io, resolvedOr(daemon.io, scratch_dir, &resolve_buffer), true) catch
        return null;

    // The knowledgebase, and only when its directory could be made: that is the
    // same condition the child offers it under, and a session keeping no notes
    // never reaches it.
    const memory_dir = session_paths.memoryDir(arena, daemon.env, root) catch return null;
    if (session_paths.createMemoryDir(daemon.io, memory_dir)) {
        grant(arena, &out, daemon.io, memory_dir, true) catch return null;
    } else |_| {}

    // The dev shell's own temporary directory is deliberately not here. A tool
    // call stages into the session scratchpad above, whether or not the project
    // has a dev shell, and the evaluation's own scratch space is read on the host
    // before a guest exists: see `toolStagingDir` in `src/run.zig`.

    return out.toOwnedSlice(arena) catch null;
}

/// Add one directory to the set, under a name no other entry has taken.
///
/// The name comes from `chock-sandbox`'s own naming, so a directory the child
/// offers again arrives under the name this gave it and replaces it rather than
/// taking a second offer slot.
///
/// **Only a path an entry already holds is dropped, and the direction of that
/// is what makes it safe.** `shareCovers(a, b)` asks whether `a` is inside `b`,
/// so the question here is whether the new path is inside one already granted.
/// Asked the other way round it drops a broader root that arrives second, which
/// is a session whose every tool call fails.
fn grant(
    arena: std.mem.Allocator,
    out: *std.ArrayList(vmm.Options.Share),
    io: std.Io,
    path: []const u8,
    writable: bool,
) std.mem.Allocator.Error!void {
    if (!isDirectory(io, path)) return;
    for (out.items) |had| {
        if (!vmm.shareCovers(path, had.host_path)) continue;
        if (had.writable or !writable) return;
    }
    // Duped, because a caller may hand this a path in a buffer of its own: the
    // set outlives every one of them and crosses a fork.
    try out.append(arena, .{
        .name = try vmm.shareNameFor(arena, out.items, path),
        .host_path = try arena.dupe(u8, path),
        .writable = writable,
    });
}

fn isDirectory(io: std.Io, path: []const u8) bool {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return stat.kind == .directory;
}

/// Where this project's image tree is kept, for a project that names an image,
/// and null for one that does not.
///
/// The `container` block and the directory name both come from the same two
/// functions `chock run` uses, so the daemon can never grant one tree while the
/// session mounts another. A block that cannot be read is no grant: the child
/// refuses such a session before it calls a tool.
fn imageDirFor(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    root: []const u8,
) ?[]const u8 {
    const named = switch (chock_container.config.load(arena, io, root) catch return null) {
        .named => |reference| reference,
        .none, .refused => return null,
    };
    const leaf = chock_container.reference.directoryName(arena, named) catch return null;
    return session_paths.imageDir(arena, env, leaf) catch null;
}

/// `path` with its links resolved, or `path` itself when it cannot be opened.
/// The answer may point into `buffer`, and `grant` dupes what it is given.
fn resolvedOr(io: std.Io, path: []const u8, buffer: []u8) []const u8 {
    return realPathOf(io, path, buffer) orelse path;
}

/// `path` with every link in it resolved, or null for a path that cannot be
/// opened. The answer points into `buffer`.
fn realPathOf(io: std.Io, path: []const u8, buffer: []u8) ?[]const u8 {
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{}) catch return null;
    defer dir.close(io);
    const length = dir.realPath(io, buffer) catch return null;
    return buffer[0..length];
}

/// Whether the guest bound its socket. It says so with a flag, so nothing here
/// looks for a file and calls its absence a failure to boot.
fn waitForGuest(io: std.Io, running: *Running) bool {
    var waited: u64 = 0;
    while (waited < guest_boot_ms) : (waited += guest_look_ms) {
        if (running.ready.load(.acquire)) return true;
        if (running.ended.load(.acquire)) return false;
        std.Io.sleep(io, .fromNanoseconds(guest_look_ms * std.time.ns_per_ms), .awake) catch
            return false;
    }
    return false;
}

/// How much of a session's identifier names its guest socket. A ULID's first ten
/// characters are its time to the millisecond, and the rest is random, so the tail
/// is what tells two sessions of one moment apart.
const guest_name_bytes: usize = 12;

/// Where a session's guest listens.
///
/// **Beside the daemon's own socket, and not beside the session's log.** A unix
/// socket path is bounded at `std.Io.net.UnixAddress.max_len`, 108 bytes, and the
/// log lives under a state directory, a project directory and a session
/// identifier: one real path came to 132 and `bind` refused it. The refusal said
/// only that nothing could hold a session there, which is why this now measures
/// the path and says the number.
fn guestSocketPath(
    daemon: *Daemon,
    id: *const [session_paths.id_length]u8,
) ?[:0]u8 {
    const tail = id[id.len - guest_name_bytes ..];
    const path = std.fmt.allocPrintSentinel(
        daemon.gpa,
        "{s}/g-{s}.sock",
        .{ daemon.socket_dir, tail },
        0,
    ) catch return null;

    if (path.len > std.Io.net.UnixAddress.max_len) {
        tty.print(
            .err,
            "chock daemon: a guest socket at {s} would be {d} bytes and a unix socket path " ++
                "takes {d}. Give the daemon a shorter --socket path: its own directory is " ++
                "where a guest's goes.\n",
            .{ path, path.len, std.Io.net.UnixAddress.max_len },
        );
        daemon.gpa.free(path);
        return null;
    }
    return path;
}

/// Stop a session's guest once `guest_idle_ms` has passed with no further turn.
/// Runs on the thread that reaped the turn, which has nothing else to do.
fn releaseGuestLater(daemon: *Daemon, id: [session_paths.id_length]u8, turn: u64) void {
    std.Io.sleep(
        daemon.io,
        .fromNanoseconds(guest_idle_ms * std.time.ns_per_ms),
        .awake,
    ) catch return;

    // Only if no later turn arrived. A turn that did bumped the count, and its own
    // thread is now the one that will let the guest go.
    const one = daemon.takeGuest(&id, turn) orelse return;
    defer daemon.gpa.free(one.socket);
    defer daemon.gpa.destroy(one.running);

    one.running.stopping.store(true, .release);
    one.running.thread.join();
    tty.detail("chock daemon: the guest of session {s} was let go after an idle spell\n", .{id});
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

test "the sandbox block holds no pointer into the file it was read from" {
    // `readSandbox` zeroes the whole of `config.zon` once it has parsed it,
    // because the file can carry a provider token inline. That is only safe while
    // the block owns every string in it: one still pointing into those bytes
    // would be a guest with a garbled kernel path and no sign of why.
    const gpa = testing.allocator;

    const source = try gpa.dupeZ(u8,
        \\.{
        \\    .providers = .{ .anthropic = .{ .token = "sk-not-a-real-one" } },
        \\    .sandbox = .{ .driver = "microvm", .kernel = "/opt/chock/Image", .initrd = "/opt/chock/initrd" },
        \\}
    );
    defer gpa.free(source);

    var block = try chock_policy.sandbox.parse(gpa, source, null);
    defer block.deinit(gpa);

    std.crypto.secureZero(u8, source);

    try testing.expectEqual(chock_policy.sandbox.Driver.microvm, block.chosen());
    try testing.expectEqualStrings("/opt/chock/Image", block.kernel.?);
    try testing.expectEqualStrings("/opt/chock/initrd", block.initrd.?);
}

test "a guest can only be reached through the fork" {
    // The function that runs a machine confines the process it runs in, so it is
    // private to its own file and `forkHost` is the only entry point. A caller
    // that wanted a guest on a thread of its own would have to make it public
    // again, which is a change somebody reviews rather than a field left out.
    try testing.expect(!@hasDecl(vmm, "host"));
    try testing.expect(@hasDecl(vmm, "forkHost"));
}

test "a guest's grant holds every directory its session offers" {
    // The grant goes on before the child has anything to say and can never be
    // widened, so a root left out here is a session whose every tool call fails.
    // This pins the derivation against the one `chock run` makes: the roots the
    // offers of `src/run.zig`'s own `guestShares` sit under.
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = testing.io;

    // The daemon's own notice that it made the cache goes to standard error, and
    // a test that let it reach the real one would be a line in the build log
    // that looks exactly like a failing suite. See `tty.Capture`.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var temp = testing.tmpDir(.{});
    defer temp.cleanup();
    var where: [std.fs.max_path_bytes]u8 = undefined;
    const length = try temp.dir.realPath(io, &where);
    const base = where[0..length];

    const state = try std.fs.path.join(arena, &.{ base, "state" });
    const data = try std.fs.path.join(arena, &.{ base, "data" });
    const project = try std.fs.path.join(arena, &.{ base, "project" });
    try session_paths.createDirAll(io, project);
    // A dev shell, because a project with one gets the same grant as a project
    // without one and this is the half that used to get a root of its own.
    var project_dir = try std.Io.Dir.openDirAbsolute(io, project, .{});
    defer project_dir.close(io);
    try project_dir.writeFile(io, .{ .sub_path = "flake.nix", .data = "{}\n" });

    var env = std.process.Environ.Map.init(arena);
    try env.put("HOME", try std.fs.path.join(arena, &.{ base, "home" }));
    try env.put("XDG_STATE_HOME", state);
    try env.put("XDG_DATA_HOME", data);
    try env.put("TMPDIR", try std.fs.path.join(arena, &.{ base, "tmp" }));

    var daemon: Daemon = .{ .gpa = gpa, .io = io, .exe_path = "chock", .env = &env };
    const id = session_paths.newId(io);

    const shares = guestShares(arena, &daemon, &id, project).?;

    // The cache is fresh, so the daemon says it made one and names where.
    try testing.expect(std.mem.indexOf(u8, said.err(), "chock cache clear") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), try session_paths.cacheDir(arena, &env, project)) != null);

    // Every directory `chock run` derives from the session and the project.
    const paths = try session_paths.pathsFor(arena, &env, project, &id);
    const wanted = [_][]const u8{
        paths.work,
        project,
        try session_paths.cacheDir(arena, &env, project),
        try session_paths.scratchpadDir(arena, &env, &id),
        try session_paths.memoryDir(arena, &env, project),
        (try run_cmd.toolStagingDir(arena, try session_paths.scratchpadDir(arena, &env, &id))).?,
    };
    for (wanted) |one| {
        var held = false;
        for (shares) |share| {
            if (vmm.shareCovers(one, share.host_path)) held = true;
        }
        if (!held) {
            const message = try std.fmt.allocPrint(arena, "no share covers {s}\n", .{one});
            try testing.expectEqualStrings("", message);
        }
    }

    // And the one the session's own log lives in is not granted: it holds every
    // other session of this project.
    for (shares) |share| {
        try testing.expect(!std.mem.eql(u8, share.host_path, paths.dir));
    }

    // The derivation never names more roots than the number the documentation
    // gives, and every granted root is a path a compromised VMM may mount.
    try testing.expect(shares.len <= max_granted_roots);

    // The dev shell's own temporary directory is not granted either, and that is
    // the point of staging in the scratchpad instead. It is per project rather
    // than per session, and nothing inside a guest reads it: the evaluation runs
    // on the host, and `scratchpad.environment` takes every name it exports out
    // of a tool call's environment.
    const dev_shell_staging = try session_paths.devShellStagingDir(arena, &env, project);
    for (shares) |share| {
        if (!vmm.shareCovers(dev_shell_staging, share.host_path)) continue;
        const message = try std.fmt.allocPrint(
            arena,
            "{s} is granted as {s}\n",
            .{ dev_shell_staging, share.name },
        );
        try testing.expectEqualStrings("", message);
    }
}

test "a project with no flake.nix is granted the directory its tool calls stage into" {
    // A project with no `flake.nix` has no dev shell, so its tool environment is
    // this process's own and the directory a call stages a program's input in
    // used to be the host's `TMPDIR`. The daemon grants the session's scratchpad
    // and never that, so the offer fell outside the grant and every tool call of
    // every project without a flake was refused. Chock's own projects all have
    // one, which is why no gate caught it.
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = testing.io;

    // Silences the cache-made notice `guestShares` prints below, rather than
    // letting it reach the test binary's real standard error.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var temp = testing.tmpDir(.{});
    defer temp.cleanup();
    var where: [std.fs.max_path_bytes]u8 = undefined;
    const length = try temp.dir.realPath(io, &where);
    const base = where[0..length];

    const project = try std.fs.path.join(arena, &.{ base, "project" });
    try session_paths.createDirAll(io, project);

    var env = std.process.Environ.Map.init(arena);
    try env.put("HOME", try std.fs.path.join(arena, &.{ base, "home" }));
    try env.put("XDG_STATE_HOME", try std.fs.path.join(arena, &.{ base, "state" }));
    try env.put("XDG_DATA_HOME", try std.fs.path.join(arena, &.{ base, "data" }));
    try env.put("TMPDIR", try std.fs.path.join(arena, &.{ base, "tmp" }));

    var daemon: Daemon = .{ .gpa = gpa, .io = io, .exe_path = "chock", .env = &env };
    const id = session_paths.newId(io);

    const shares = guestShares(arena, &daemon, &id, project).?;

    // Derived the way the child derives it, and resolved to the environment's own
    // value the way `src/run.zig`'s `guestShares` does for a session that is given
    // none: a path named here by hand would pass against any answer at all.
    const scratch = try session_paths.scratchpadDir(arena, &env, &id);
    const staging = (try run_cmd.toolStagingDir(arena, scratch)) orelse
        env.get("TMPDIR").?;

    for (shares) |share| {
        if (vmm.shareCovers(staging, share.host_path) and share.writable) return;
    }
    const message = try std.fmt.allocPrint(arena, "no writable share covers {s}\n", .{staging});
    try testing.expectEqualStrings("", message);
}

test "a project that holds Chock's own data directory is refused by name" {
    // A client names the project and nothing bounds where it is, so a project at
    // or above the data directory would put `credentials.zon` inside a read
    // grant. The answer is no guest at all, and never a narrower one: a grant
    // that silently drops the backing is a session whose git reads all fail.
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = testing.io;

    // The refusal is the security-relevant line here, so it is read back and
    // checked rather than only kept off the test binary's real standard error.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var temp = testing.tmpDir(.{});
    defer temp.cleanup();
    var where: [std.fs.max_path_bytes]u8 = undefined;
    const length = try temp.dir.realPath(io, &where);
    const base = where[0..length];

    var env = std.process.Environ.Map.init(arena);
    try env.put("HOME", try std.fs.path.join(arena, &.{ base, "home" }));
    try env.put("XDG_STATE_HOME", try std.fs.path.join(arena, &.{ base, "state" }));
    try env.put("XDG_DATA_HOME", try std.fs.path.join(arena, &.{ base, "data" }));
    try env.put("TMPDIR", try std.fs.path.join(arena, &.{ base, "tmp" }));

    var daemon: Daemon = .{ .gpa = gpa, .io = io, .exe_path = "chock", .env = &env };
    const id = session_paths.newId(io);

    // The project is the directory both of Chock's own live under, and it is no
    // repository, so the backing is the project itself.
    try testing.expectEqual(@as(?[]const vmm.Options.Share, null), guestShares(arena, &daemon, &id, base));

    // The refusal names the project that was asked for, and says why.
    try testing.expect(std.mem.indexOf(u8, said.err(), base) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "Name the project itself.") != null);
}

test "no session starts for a project that holds one of Chock's own directories" {
    // Refusing the grant is not refusing the guest: a daemon that answers no
    // socket has the child fork one of its own over the same project, so the
    // refusal has to turn the session away and not only the set. Each of the
    // three directories on its own, because a client naming the parent of any one
    // of them puts `credentials.zon` or `config.zon` inside a read grant.
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = testing.io;

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var temp = testing.tmpDir(.{});
    defer temp.cleanup();
    var where: [std.fs.max_path_bytes]u8 = undefined;
    const length = try temp.dir.realPath(io, &where);
    const base = where[0..length];

    const each = [_][]const u8{ "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME" };
    for (each) |variable| {
        var env = std.process.Environ.Map.init(arena);
        // The other two are somewhere else entirely, so the refusal can only come
        // from the one this turn puts inside the project.
        try env.put("HOME", try std.fs.path.join(arena, &.{ base, "home" }));
        try env.put("XDG_CONFIG_HOME", try std.fs.path.join(arena, &.{ base, "away", "config" }));
        try env.put("XDG_DATA_HOME", try std.fs.path.join(arena, &.{ base, "away", "data" }));
        try env.put("XDG_STATE_HOME", try std.fs.path.join(arena, &.{ base, "away", "state" }));
        try env.put("TMPDIR", try std.fs.path.join(arena, &.{ base, "tmp" }));

        const project = try std.fs.path.join(arena, &.{ base, "project" });
        try session_paths.createDirAll(io, project);
        try env.put(variable, try std.fs.path.join(arena, &.{ project, "inside" }));

        var daemon: Daemon = .{
            .gpa = gpa,
            .io = io,
            .exe_path = "/nonexistent/chock",
            .env = &env,
            .sandbox = .{ .driver = .microvm },
        };
        defer daemon.deinit();

        // `create` is the one verb that makes a session and starts no child, so
        // this reads the refusal and not a spawn.
        var buffer: [4096]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        beginSession(&daemon, &writer, project, session_paths.newId(io), .nothing);

        const answer = writer.buffered();
        if (!std.mem.startsWith(u8, answer, control.error_prefix)) {
            const message = try std.fmt.allocPrint(arena, "{s} inside the project was answered: {s}\n", .{ variable, answer });
            try testing.expectEqualStrings("", message);
        }
        // The path itself, so a person is told which directory stopped it rather
        // than being handed a narrower grant and no reason.
        const own = try std.fs.path.join(arena, &.{ project, "inside", "chock" });
        try testing.expect(std.mem.indexOf(u8, answer, own) != null);
        try testing.expect(std.mem.indexOf(u8, answer, project) != null);
        // And nothing of the session was made: no entry, so no log and no child.
        try testing.expectEqual(@as(usize, 0), daemon.sessions.items.len);
    }
}

test "a root that holds one already granted is kept, in whichever order the two arrive" {
    // The set is deduplicated by containment, and containment has a direction.
    // Reading it the wrong way round drops a broader root that arrives second,
    // which is a session whose every tool call fails, and appends a nested one
    // twice.
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = testing.io;

    var temp = testing.tmpDir(.{});
    defer temp.cleanup();
    var where: [std.fs.max_path_bytes]u8 = undefined;
    const length = try temp.dir.realPath(io, &where);
    const base = where[0..length];

    const outer = try std.fs.path.join(arena, &.{ base, "outer" });
    const inner = try std.fs.path.join(arena, &.{ base, "outer", "inner" });
    try session_paths.createDirAll(io, inner);

    // The broader root first: the one inside it needs no share of its own.
    var broad_first: std.ArrayList(vmm.Options.Share) = .empty;
    try grant(arena, &broad_first, io, outer, false);
    try grant(arena, &broad_first, io, inner, false);
    try testing.expectEqual(@as(usize, 1), broad_first.items.len);
    try testing.expectEqualStrings(outer, broad_first.items[0].host_path);

    // The narrower one first: the broader root still has to be granted.
    var narrow_first: std.ArrayList(vmm.Options.Share) = .empty;
    try grant(arena, &narrow_first, io, inner, false);
    try grant(arena, &narrow_first, io, outer, false);
    var holds_outer = false;
    for (narrow_first.items) |share| {
        if (std.mem.eql(u8, share.host_path, outer)) holds_outer = true;
    }
    try testing.expect(holds_outer);

    // A writable path inside a read only root is a share of its own: a grant
    // cannot be widened once it is on.
    var widening: std.ArrayList(vmm.Options.Share) = .empty;
    try grant(arena, &widening, io, outer, false);
    try grant(arena, &widening, io, inner, true);
    try testing.expectEqual(@as(usize, 2), widening.items.len);
}

test "a session is granted nothing it never asks for" {
    // The grant is also the offer list, so a root beyond what the child offers
    // is a root an escape inside the guest reaches and the session never wanted.
    // Nothing in a guest reads the dev shell's own temporary directory, and a
    // project naming no image mounts no image tree, where that directory holds
    // every other project's.
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = testing.io;

    // Silences the cache-made notice `guestShares` prints below, rather than
    // letting it reach the test binary's real standard error.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var temp = testing.tmpDir(.{});
    defer temp.cleanup();
    var where: [std.fs.max_path_bytes]u8 = undefined;
    const length = try temp.dir.realPath(io, &where);
    const base = where[0..length];

    const project = try std.fs.path.join(arena, &.{ base, "project" });
    try session_paths.createDirAll(io, project);

    var env = std.process.Environ.Map.init(arena);
    try env.put("HOME", try std.fs.path.join(arena, &.{ base, "home" }));
    try env.put("XDG_STATE_HOME", try std.fs.path.join(arena, &.{ base, "state" }));
    try env.put("XDG_DATA_HOME", try std.fs.path.join(arena, &.{ base, "data" }));
    try env.put("TMPDIR", try std.fs.path.join(arena, &.{ base, "tmp" }));

    // The image directory exists, which is what a machine with one image on it
    // looks like to every project after.
    try session_paths.createDirAll(io, try session_paths.imagesDir(arena, &env));

    var daemon: Daemon = .{ .gpa = gpa, .io = io, .exe_path = "chock", .env = &env };
    const id = session_paths.newId(io);

    const shares = guestShares(arena, &daemon, &id, project).?;

    const unwanted = [_][]const u8{
        try session_paths.imagesDir(arena, &env),
        try session_paths.devShellStagingDir(arena, &env, project),
    };
    for (unwanted) |one| {
        for (shares) |share| {
            if (!vmm.shareCovers(one, share.host_path)) continue;
            const message = try std.fmt.allocPrint(arena, "{s} is granted as {s}\n", .{ one, share.name });
            try testing.expectEqualStrings("", message);
        }
    }
}
