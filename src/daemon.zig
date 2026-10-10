//! `chock daemon`: the process that owns sessions and is the only thing a
//! frontend talks to. It forks a child per session and runs no agent loop itself.

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

const max_request_bytes: usize = control.max_request_bytes;

const max_events_per_read: usize = 100_000;

const max_listeners: usize = 2;

const max_connections: usize = 64;

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

const Session = struct {
    id: [session_paths.id_length]u8,
    log_path: [:0]u8,
    project: []u8,
    pid: ?std.posix.pid_t = null,
    guest: ?Guest = null,
};

const Guest = struct {
    running: *Running,
    socket: [:0]u8,
    turns: u64 = 0,
};

// PR_SET_PDEATHSIG fires when the thread that forked the guest ends, not when its process does, so the thread lives as long as the guest.
const Running = struct {
    thread: std.Thread,
    ready: std.atomic.Value(bool) = .init(false),
    stopping: std.atomic.Value(bool) = .init(false),
    ended: std.atomic.Value(bool) = .init(false),
};

const guest_idle_ms: u64 = 5 * std.time.ms_per_min;

const guest_boot_ms: u64 = 30 * std.time.ms_per_s;

const guest_look_ms: u64 = 100;

const max_guests: usize = 4;

const Daemon = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    exe_path: []const u8,
    env: *std.process.Environ.Map,
    owner_uid: std.posix.uid_t = 0,
    mutex: std.Io.Mutex = .init,
    sessions: std.ArrayList(Session) = .empty,
    live: std.atomic.Value(usize) = .init(0),
    sandbox: chock_policy.sandbox.Block = .{},
    socket_dir: []const u8 = "",

    fn deinit(self: *Daemon) void {
        for (self.sessions.items) |entry| {
            self.gpa.free(entry.log_path);
            self.gpa.free(entry.project);
            if (entry.guest) |one| {
                one.running.stopping.store(true, .release);
                one.running.thread.join();
                self.gpa.destroy(one.running);
                self.gpa.free(one.socket);
            }
        }
        self.sessions.deinit(self.gpa);
        self.sandbox.deinit(self.gpa);
    }

    fn guestFor(self: *Daemon, id: []const u8) ?Guest {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |entry| {
            if (std.mem.eql(u8, &entry.id, id)) return entry.guest;
        }
        return null;
    }

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

    fn notePid(self: *Daemon, id: []const u8, pid: ?std.posix.pid_t) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (std.mem.eql(u8, &entry.id, id)) entry.pid = pid;
        }
    }

    fn pidFor(self: *Daemon, id: []const u8) ?std.posix.pid_t {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |entry| {
            if (std.mem.eql(u8, &entry.id, id)) return entry.pid;
        }
        return null;
    }

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

const peerAllowed = control.peerAllowed;

fn reportable(address: control.Address, listener: control.Listener) control.Address {
    return switch (address) {
        .unix => address,
        .ip => |ip| .{ .ip = .{ .host = ip.host, .port = listener.server.socket.address.getPort() } },
    };
}

fn accept(daemon: *Daemon, listeners: []control.Listener) void {
    var fds: [4]std.posix.pollfd = undefined;
    std.debug.assert(listeners.len <= fds.len);

    while (true) {
        for (listeners, 0..) |*one, index| {
            fds[index] = .{ .fd = one.server.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
        }
        const ready = std.posix.poll(fds[0..listeners.len], 1000) catch continue;
        if (ready == 0) continue;

        for (fds[0..listeners.len], listeners) |entry, *one| {
            if (entry.revents == 0) continue;
            var stream = one.server.accept(daemon.io) catch |err| {
                tty.print(.warn, "chock daemon: an incoming connection failed: {t}\n", .{err});
                continue;
            };

            if (one.unix_path != null and
                !peerAllowed(control.peerUid(stream.socket.handle), daemon.owner_uid))
            {
                var buffer: [256]u8 = undefined;
                var writer = stream.writer(daemon.io, &buffer);
                fail(&writer.interface, "this daemon serves the user that started it, and you are not that user");
                tty.print(.warn, "chock daemon: a client of another user was refused.\n", .{});
                stream.close(daemon.io);
                continue;
            }

            if (daemon.live.load(.monotonic) >= max_connections) {
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
    // The buffer is local, so a handler that returns without flushing leaves its answer here and the client gets nothing back.
    defer writer.flush() catch {};

    if (!greet(reader, writer)) return;

    // takeDelimiterExclusive stops before the line break, so a second read on one connection would see an empty line forever.
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
        .projects => handleProjects(daemon, arena, writer),
        .watch => |one| handleWatch(daemon, arena, writer, stream.socket.handle, one),
        .answer => |one| handleAnswer(daemon, arena, writer, one),
    }
}

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
        .ready, .no_such_session, .nothing_to_carry_on, .unknown => {},
    }

    beginSession(daemon, writer, one.project, id, .{ .say = one.message });
}

fn handleCancel(daemon: *Daemon, writer: *std.Io.Writer, one: control.Request.Cancel) void {
    const id = checkedSession(writer, one.project, one.session) orelse return;

    const pid = daemon.pidFor(&id) orelse {
        say(writer, .{ .ok = "that session is running nothing" });
        return;
    };

    std.posix.kill(pid, .INT) catch |err| switch (err) {
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

const Begin = union(enum) {
    say: []const u8,
    carry_on,
    nothing,
};

fn beginSession(
    daemon: *Daemon,
    writer: *std.Io.Writer,
    project: []const u8,
    id: [session_paths.id_length]u8,
    begin: Begin,
) void {
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
        thread.detach();
    }

    var text_buffer: [std.fs.max_path_bytes + session_paths.id_length + 8]u8 = undefined;
    const text = std.fmt.bufPrint(&text_buffer, "{s}\t{s}", .{ id, log_path }) catch {
        fail(writer, "the answer was longer than this daemon can write");
        return;
    };
    say(writer, .{ .ok = text });
}

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
    project: []const u8,
    message: ?[]u8,
};

fn runChild(child: Child) void {
    const daemon = child.daemon;
    defer if (child.message) |text| daemon.gpa.free(text);

    const guest = startGuest(daemon, &child.id, child.project);
    const turn = daemon.noteTurn(&child.id);
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
        .stdout = .ignore,
        .stderr = .inherit,
    }) catch |err| {
        tty.print(.err, "chock daemon: session {s} could not be started: {t}\n", .{ child.id, err });
        return;
    };

    if (process.id) |pid| daemon.notePid(&child.id, pid);
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

    const guest_machine = chock_policy.sandbox.Machine.now();

    const console = guestConsolePath(daemon, id) orelse return null;
    var console_owned = true;
    defer if (console_owned) daemon.gpa.free(console);

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
            .control = vmm.fork_sets_control,
        },
        .shares = room,
        .console = console,
    };

    running.thread = std.Thread.spawn(.{}, runGuest, .{work}) catch |err| {
        tty.print(.err, "chock daemon: session {s} could not be given a guest: {t}\n", .{ id, err });
        return null;
    };
    room_owned = false;
    console_owned = false;

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
        running.stopping.store(true, .release);
        running.thread.join();
        return daemon.guestFor(id).?.socket;
    }
    socket_owned = false;
    running_owned = false;
    tty.detail("chock daemon: session {s} has a guest at {s}, console at {s}\n", .{ id, socket, console });
    return socket;
}

const GuestWork = struct {
    daemon: *Daemon,
    running: *Running,
    options: vmm.Options,
    shares: *std.heap.ArenaAllocator,
    /// Where the guest's console is written. Owned by the thread that runs the
    /// guest, and freed with it.
    console: [:0]u8,
};

fn runGuest(work: GuestWork) void {
    const daemon = work.daemon;
    const running = work.running;

    defer daemon.gpa.free(work.console);

    // A file and not this daemon's own output. A guest writes its kernel log and
    // its init script to this, and a daemon that answers many sessions would
    // otherwise have all of them spliced through its own messages.
    var console = std.Io.Dir.cwd().createFile(daemon.io, work.console, .{}) catch {
        tty.print(
            .err,
            "chock daemon: a guest's console could not be opened at {s}\n",
            .{work.console},
        );
        releaseShares(daemon, work.shares);
        running.ended.store(true, .release);
        return;
    };
    defer console.close(daemon.io);

    var child = vmm.forkHost(daemon.io, work.options, console.handle) catch |err| {
        tty.print(.err, "chock daemon: a guest's own process could not be started: {t}\n", .{err});
        releaseShares(daemon, work.shares);
        running.ended.store(true, .release);
        return;
    };
    releaseShares(daemon, work.shares);

    defer {
        child.stop();
        const code = child.wait();
        if (code == 0) {
            tty.detail("chock daemon: a guest's own process ended, answering 0\n", .{});
        } else {
            tty.print(.err, "chock daemon: a guest's own process ended badly, answering {d}\n", .{code});
        }
        std.Io.Dir.deleteFileAbsolute(daemon.io, work.options.session) catch {};
    }
    defer running.ended.store(true, .release);

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

pub const max_granted_roots: usize = run_cmd.host_toolchain_candidates.len - 1 + 6;

fn guestShares(
    arena: std.mem.Allocator,
    daemon: *Daemon,
    id: *const [session_paths.id_length]u8,
    project: []const u8,
) ?[]const vmm.Options.Share {
    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = realPathOf(daemon.io, project, &project_buffer) orelse {
        tty.print(.err, "chock daemon: {s} has no real path, so no guest is started\n", .{project});
        return null;
    };

    var out: std.ArrayList(vmm.Options.Share) = .empty;
    var resolve_buffer: [std.fs.max_path_bytes]u8 = undefined;

    const toolchain = run_cmd.hostToolchainPaths(arena, daemon.io) catch return null;
    for (toolchain) |path| grant(arena, &out, daemon.io, path, false) catch return null;

    const paths = session_paths.pathsFor(arena, daemon.env, root, id) catch return null;
    session_paths.create(daemon.io, paths) catch return null;
    session_paths.markProject(daemon.io, paths, root);
    grant(arena, &out, daemon.io, paths.work, true) catch return null;

    const backing = run_cmd.projectGrantDir(arena, daemon.io, root) catch return null;

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

    if (imageDirFor(arena, daemon.io, daemon.env, root)) |dir| {
        session_paths.createImageDir(daemon.io, dir) catch return null;
        grant(arena, &out, daemon.io, dir, false) catch return null;
    }

    const cache_dir = session_paths.cacheDir(arena, daemon.env, root) catch return null;
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

    const memory_dir = session_paths.memoryDir(arena, daemon.env, root) catch return null;
    if (session_paths.createMemoryDir(daemon.io, memory_dir)) {
        grant(arena, &out, daemon.io, memory_dir, true) catch return null;
    } else |_| {}

    return out.toOwnedSlice(arena) catch null;
}

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

fn resolvedOr(io: std.Io, path: []const u8, buffer: []u8) []const u8 {
    return realPathOf(io, path, buffer) orelse path;
}

fn realPathOf(io: std.Io, path: []const u8, buffer: []u8) ?[]const u8 {
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{}) catch return null;
    defer dir.close(io);
    const length = dir.realPath(io, buffer) catch return null;
    return buffer[0..length];
}

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

const guest_name_bytes: usize = 12;

/// Where a guest's console is written, beside its socket and named the same.
fn guestConsolePath(
    daemon: *Daemon,
    id: *const [session_paths.id_length]u8,
) ?[:0]u8 {
    const tail = id[id.len - guest_name_bytes ..];
    return std.fmt.allocPrintSentinel(
        daemon.gpa,
        "{s}/g-{s}.console",
        .{ daemon.socket_dir, tail },
        0,
    ) catch null;
}

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

fn releaseGuestLater(daemon: *Daemon, id: [session_paths.id_length]u8, turn: u64) void {
    std.Io.sleep(
        daemon.io,
        .fromNanoseconds(guest_idle_ms * std.time.ns_per_ms),
        .awake,
    ) catch return;

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
        fail(writer, "this daemon did not start a session with that identifier");
        return;
    };
    defer daemon.gpa.free(log_path);

    var opened = openLog(daemon, writer, log_path, one.session) orelse return;
    defer opened.close(daemon.io);

    var feed = control.Feed{ .after = one.after };
    _ = feed.events(arena, daemon.io, opened.storage(), writer, max_events_per_read) catch |err| {
        failWith(writer, "the session log could not be read from there", @errorName(err));
        return;
    };
    writer.flush() catch return;
}

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
        const grew = grow: {
            var opened = openLog(daemon, writer, paths.log, &id) orelse return;
            defer opened.close(daemon.io);
            break :grow feed.events(arena, daemon.io, opened.storage(), writer, 0) catch |err| {
                failWith(writer, "the session log could not be read", @errorName(err));
                return;
            };
        };
        writer.flush() catch return;

        if (feed.ended and sessions_cmd.livenessOf(daemon.io, paths.log) != .live) return;

        if (!grew) {
            if (peerGone(handle, watch_idle_ms)) return;
        }
    }
}

const Opened = struct {
    backing: chock_proto.storage.JsonLines,

    fn storage(self: *Opened) chock_proto.storage.Storage {
        return self.backing.storage();
    }

    fn close(self: *Opened, io: std.Io) void {
        self.backing.log.close(io);
    }
};

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

fn handleList(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    one: control.Request.List,
) void {
    // Empty asks for every project, which is what a picker covering more than
    // one needs. A named project still has to be a real path.
    if (one.project.len == 0) {
        const found = session_paths.listProjects(arena, daemon.io, daemon.env) catch {
            fail(writer, "the projects could not be read");
            return;
        };
        for (found) |project| {
            if (!listInto(daemon, arena, writer, project.dir, project.name, project.root)) return;
        }
        writer.flush() catch return;
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

    if (!listInto(daemon, arena, writer, dir, "", one.project)) return;
    writer.flush() catch return;
}

/// Write out every session in one directory. False when something refused and
/// the caller has already been told.
fn listInto(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    dir: []const u8,
    project: []const u8,
    root: []const u8,
) bool {
    const found = sessions_cmd.list(arena, daemon.io, dir) catch {
        fail(writer, "out of memory");
        return false;
    };

    for (found) |session| {
        var row = rowOf(session);
        row.project = project;
        row.project_root = root;
        const text = row.toJson(arena) catch {
            fail(writer, "a session could not be written out");
            return false;
        };
        say(writer, .{ .record = .{ .id = session.started_ms, .payload = text } });
    }
    return true;
}

/// Every project this daemon can see, one record each.
fn handleProjects(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer) void {
    const found = session_paths.listProjects(arena, daemon.io, daemon.env) catch {
        fail(writer, "the projects could not be read");
        return;
    };

    for (found, 0..) |one, index| {
        const row: control.ProjectRow = .{
            .root = one.root,
            .name = one.name,
            .sessions = one.sessions,
        };
        const text = row.toJson(arena) catch {
            fail(writer, "a project could not be written out");
            return;
        };
        say(writer, .{ .record = .{ .id = index, .payload = text } });
    }
    writer.flush() catch return;
}

pub fn rowOf(session: sessions_cmd.Session) control.SessionRow {
    return .{
        .id = session.id,
        .started_ms = session.started_ms,
        .model = session.model,
        .model_count = session.model_count,
        .model_alias = session.model_alias,
        .title = session.title,
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
                .decision = one.decision.decision(),
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
    socket: ?[]const u8 = null,
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
        for (set) |address| try testing.expect(address != .ip);
    }

    {
        const bound = try parseOptions(&.{ "--host", "0.0.0.0", "--port", "9999" });
        try testing.expectEqualStrings("0.0.0.0", bound.host.?);
        const set = listenSet(&buffer, "/state/daemon.sock", bound);
        try testing.expectEqual(@as(usize, 2), set.len);
        try testing.expectEqualStrings("/state/daemon.sock", set[0].unix);
        try testing.expectEqualStrings("0.0.0.0", set[1].ip.host);
        try testing.expectEqual(@as(u16, 9999), set[1].ip.port);
    }

    try testing.expectEqualStrings("", said.err());
    try testing.expectEqualStrings("", said.out());

    for ([_][]const u8{ "--address", "--bind" }) |spelling| {
        const same = try parseOptions(&.{ spelling, "10.0.0.4" });
        try testing.expectEqualStrings("10.0.0.4", same.host.?);
    }

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--port", "9999" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--host") != null);
}

test "the control socket serves the user that started the daemon and nobody else" {
    const io = testing.io;
    const mine = std.posix.system.getuid();

    try testing.expect(peerAllowed(mine, mine));
    try testing.expect(!peerAllowed(mine +% 1, mine));
    try testing.expect(!peerAllowed(0, mine +% 1));
    try testing.expect(!peerAllowed(null, mine));

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

    {
        var reader = std.Io.Reader.fixed("");
        var buffer: [512]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try testing.expect(!greet(&reader, &writer));
        try testing.expect(std.mem.startsWith(u8, writer.buffered(), control.error_prefix));
    }
}

test "the port and the socket parse, and a value that is not one is refused by name" {
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqual(
        @as(u16, 9999),
        (try parseOptions(&.{ "--host", "127.0.0.1", "--port", "9999" })).port,
    );
    try testing.expectEqual(
        @as(u16, 0),
        (try parseOptions(&.{ "--host", "127.0.0.1", "--port", "0" })).port,
    );
    try testing.expectEqualStrings(
        "/run/user/1000/chock/d.sock",
        (try parseOptions(&.{ "--socket", "/run/user/1000/chock/d.sock" })).socket.?,
    );
    try testing.expectEqualStrings("", said.err());

    for ([_][]const u8{ "seventy", "70000" }) |value| {
        said.clear();
        try testing.expectError(error.BadArguments, parseOptions(&.{ "--port", value }));
        try testing.expect(std.mem.indexOf(u8, said.err(), value) != null);
    }

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

    {
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project);
        try testing.expect(std.mem.startsWith(u8, got.answer, "error"));
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    {
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt project\t" ++ id);
        try testing.expect(std.mem.indexOf(u8, got.answer, "absolute path") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    {
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project ++ "\t../../../etc/passwd");
        try testing.expect(std.mem.indexOf(u8, got.answer, "not a session identifier") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    {
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project ++ "\t" ++ id);
        try testing.expect(std.mem.indexOf(u8, got.answer, "holds no session") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    var paths = try session_paths.pathsFor(gpa, &env, project, id);
    defer paths.deinit();
    try session_paths.create(io, paths);

    {
        var seed = try chock_proto.log.Log.open(io, paths.log, id);
        seed.close(io);
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project ++ "\t" ++ id);
        try testing.expect(std.mem.indexOf(u8, got.answer, "nothing to carry on from") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

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

    const line = std.mem.trimEnd(u8, got.answer, "\n");
    const reply = try control.Reply.parse(line);
    var parsed = try control.SessionRow.fromJson(gpa, reply.record.payload);
    defer parsed.deinit();

    const dir = try session_paths.projectDir(arena, &env, project);
    const local = try sessions_cmd.list(arena, io, dir);
    try testing.expectEqual(@as(usize, 1), local.len);

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

    try testing.expectEqualStrings("idle", wire.live);
    try testing.expectEqualStrings("finished", wire.end.?);
}

test "a listing of a project with no sessions is an empty answer and not a refusal" {
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

    const relative = probeRequest(&daemon, arena_state.allocator(), &answer_buffer, "list project");
    try testing.expect(std.mem.indexOf(u8, relative.answer, "absolute path") != null);
}

test "answering a session that is not listening is a refusal and never a silent yes" {
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
    try testing.expect(std.mem.startsWith(u8, got.answer, control.error_prefix));
    try testing.expect(std.mem.indexOf(u8, got.answer, "answered") == null);
    try testing.expect(std.mem.indexOf(u8, got.answer, control.ok_prefix) == null);

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
    try testing.expect(!@hasDecl(vmm, "host"));
    try testing.expect(@hasDecl(vmm, "forkHost"));
}

test "a guest's grant holds every directory its session offers" {
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

    const state = try std.fs.path.join(arena, &.{ base, "state" });
    const data = try std.fs.path.join(arena, &.{ base, "data" });
    const project = try std.fs.path.join(arena, &.{ base, "project" });
    try session_paths.createDirAll(io, project);
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

    try testing.expect(std.mem.indexOf(u8, said.err(), "chock cache clear") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), try session_paths.cacheDir(arena, &env, project)) != null);

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

    for (shares) |share| {
        try testing.expect(!std.mem.eql(u8, share.host_path, paths.dir));
    }

    try testing.expect(shares.len <= max_granted_roots);

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

    var env = std.process.Environ.Map.init(arena);
    try env.put("HOME", try std.fs.path.join(arena, &.{ base, "home" }));
    try env.put("XDG_STATE_HOME", try std.fs.path.join(arena, &.{ base, "state" }));
    try env.put("XDG_DATA_HOME", try std.fs.path.join(arena, &.{ base, "data" }));
    try env.put("TMPDIR", try std.fs.path.join(arena, &.{ base, "tmp" }));

    var daemon: Daemon = .{ .gpa = gpa, .io = io, .exe_path = "chock", .env = &env };
    const id = session_paths.newId(io);

    try testing.expectEqual(@as(?[]const vmm.Options.Share, null), guestShares(arena, &daemon, &id, base));

    try testing.expect(std.mem.indexOf(u8, said.err(), base) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "Name the project itself.") != null);
}

test "no session starts for a project that holds one of Chock's own directories" {
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

        var buffer: [4096]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        beginSession(&daemon, &writer, project, session_paths.newId(io), .nothing);

        const answer = writer.buffered();
        if (!std.mem.startsWith(u8, answer, control.error_prefix)) {
            const message = try std.fmt.allocPrint(arena, "{s} inside the project was answered: {s}\n", .{ variable, answer });
            try testing.expectEqualStrings("", message);
        }
        const own = try std.fs.path.join(arena, &.{ project, "inside", "chock" });
        try testing.expect(std.mem.indexOf(u8, answer, own) != null);
        try testing.expect(std.mem.indexOf(u8, answer, project) != null);
        try testing.expectEqual(@as(usize, 0), daemon.sessions.items.len);
    }
}

test "a root that holds one already granted is kept, in whichever order the two arrive" {
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

    var broad_first: std.ArrayList(vmm.Options.Share) = .empty;
    try grant(arena, &broad_first, io, outer, false);
    try grant(arena, &broad_first, io, inner, false);
    try testing.expectEqual(@as(usize, 1), broad_first.items.len);
    try testing.expectEqualStrings(outer, broad_first.items[0].host_path);

    var narrow_first: std.ArrayList(vmm.Options.Share) = .empty;
    try grant(arena, &narrow_first, io, inner, false);
    try grant(arena, &narrow_first, io, outer, false);
    var holds_outer = false;
    for (narrow_first.items) |share| {
        if (std.mem.eql(u8, share.host_path, outer)) holds_outer = true;
    }
    try testing.expect(holds_outer);

    var widening: std.ArrayList(vmm.Options.Share) = .empty;
    try grant(arena, &widening, io, outer, false);
    try grant(arena, &widening, io, inner, true);
    try testing.expectEqual(@as(usize, 2), widening.items.len);
}

test "a session is granted nothing it never asks for" {
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

    const project = try std.fs.path.join(arena, &.{ base, "project" });
    try session_paths.createDirAll(io, project);

    var env = std.process.Environ.Map.init(arena);
    try env.put("HOME", try std.fs.path.join(arena, &.{ base, "home" }));
    try env.put("XDG_STATE_HOME", try std.fs.path.join(arena, &.{ base, "state" }));
    try env.put("XDG_DATA_HOME", try std.fs.path.join(arena, &.{ base, "data" }));
    try env.put("TMPDIR", try std.fs.path.join(arena, &.{ base, "tmp" }));

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
