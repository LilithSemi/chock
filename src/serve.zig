//! `chock serve`: a browser in front of a daemon.
//!
//! ## It owns nothing, and that is the whole design
//!
//! `chock daemon` owns sessions. This command owns a socket a browser connects
//! to and a page it sends down it, and **nothing else**. Every fact it shows
//! came out of the daemon's own API, which makes that API the security
//! boundary rather than the filesystem, and puts it in the right place.
//!
//! The reason is future shape. In a hosted world the daemon is somewhere else
//! and this is the frontend in front of it. So the rule this file is written
//! to, and it applies to every line: **would this still work if the daemon
//! were on another machine?**
//!
//! Three things follow, and each is a thing this file does not do:
//!
//! * **It never reads a session log.** Nothing here imports the log module and
//!   nothing here builds a path from a session identifier.
//! * **It never takes a lock.** The process holding a log's exclusive lock is
//!   its owner, and this is not that process.
//! * **It never resolves a session directory.** It does not know where one is.
//!
//! ## There is no local case
//!
//! A daemon is a `chock_proto.control.Address`. **Nothing below branches on
//! whether that address is a unix socket on this machine or a host somewhere
//! else**, because the only code that knows the difference is
//! `Address.connect`. The default is the local socket, because that is the
//! common case and nobody should have to type an address to use it, and a
//! default is one value of a parameter rather than a special case beside it.
//!
//! Every route below does the same three things: connect to the address, run
//! one exchange, and turn what came back into a response. A route that wanted
//! a fourth thing would be the design going wrong.
//!
//! ## What it binds
//!
//! **A unix socket, and nothing else, unless somebody asks for more.** The
//! socket is where the peer credential check works, so it is the only address
//! a person who typed nothing gets. Loopback TCP authenticates nobody: on a
//! machine with more than one account, every local account can open
//! `127.0.0.1` and approve an action in this user's session.
//!
//! **A browser cannot open a unix socket, and that is not the question.**
//! nginx, Caddy and Authelia all proxy to one, and a reverse proxy is the
//! supported way to put authentication in front of this. So the default is the
//! shape a proxy asks for, and somebody who wants to point a browser straight
//! at this types `--host 127.0.0.1`. One flag, the direct case stays easy, and
//! there is no insecure default left.
//!
//! **A TCP listener is what `--host` turns on, and it is never a default.**
//! `--host` is allowed and is not guarded: somebody who types `0.0.0.0` is
//! being deliberately insecure and that is their choice. Chock does no
//! authentication over a network at all, here or in the daemon. A pairing
//! bootstrap is planned and is not built.
//!
//! ## Who may talk to it
//!
//! **The unix socket serves the user that started this command, and refuses
//! every other peer.** The kernel says who is on the other end of a connected
//! unix socket, and `chock_proto.control.peerUid` is the one place that asks
//! it. A peer the kernel will not name is refused as well, because an absent
//! answer is never a permissive answer.
//!
//! **A TCP peer carries no identity at all, and nothing below pretends to
//! check one.** There is no credential on a TCP connection to read, so the
//! socket's check covers the socket and only the socket. Authentication in
//! front of a TCP listener is the proxy's job: see `--host` above.
//!
//! **A proxy that runs under another account cannot open the socket**, because
//! the check is the peer's uid. Run the proxy as this user, or give the proxy a
//! `--host 127.0.0.1` address and accept what that address means.
//!
//! **The listener is this process's own, and it is not the daemon.** The rule
//! at the head of this file is about the address of the daemon, which is one
//! parameter with no local case. What this binds for a browser is a separate
//! thing, and asking whether it carries a peer credential is a question about
//! this process's inbound socket. `src/daemon.zig` draws the same line.
//!
//! A browser that reaches this can approve an action, so this is a trust
//! boundary in the same sense `lib/chock-broker/socket.zig` is. It keeps the
//! same rule and keeps it narrowly: **a client may say only what a person may
//! say.** `/api/answer` takes `yes` or `no`, parsed by
//! `chock_proto.control.Answer`, and there is no third word. The daemon clamps
//! again, and the session clamps a third time. None of the outer layers can
//! express what an inner one refuses.
//!
//! ## One project
//!
//! This serves the project it was started in, and the project is a command line
//! option rather than something a browser names. A page that could name a
//! directory would be a page that can ask the daemon about any directory this
//! user can read, and there is no reason for a frontend to be able to do that.
//! **A frontend over several projects needs the daemon to hold a roster**,
//! which is a hub feature and is not built.
//!
//! ## Why the page is HTML and not Phantom on wasm
//!
//! Phantom has a DOM backend that consumes the very `DisplayList` the terminal
//! backend does, so the four region layout could in principle be one widget
//! tree drawn two ways. **Measured, and it cannot be that yet**, for reasons
//! that are about the package and not about the idea:
//!
//! * The pinned `phantom` package ships `build`, `build.zig`, `build.zig.zon`
//!   and `lib` in its `paths`. `web/dom.webidl` is in none of them, and
//!   `addWebApp` reads that path, so the one call that builds a wasm app cannot
//!   run from the fetched package at all.
//! * `WebApp` builds no `FocusManager` and the wasm entry exports no key
//!   dispatch, so nothing focusable is reachable in a browser. That is the same
//!   family of gap as the one Chock already works around in the terminal, and
//!   it is wider there: in the terminal focus reaches one node, and on the web
//!   it reaches none.
//! * `ScrollRegion.offset` is not read by the DOM renderer, so the browser owns
//!   the scroll position and Phantom's own scroll state does not reach it.
//!
//! So this milestone ships a page and names that refusal rather than half
//! wiring a second interface. When `web` is added to phantom's `paths` and the
//! wasm entry gains a key dispatch, the page here is what gets replaced.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_proto = @import("chock-proto");

const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const control = chock_proto.control;

/// The port the browser connects to when `--host` is given and `--port` is
/// not.
///
/// **One past the daemon's**, so a person running both by hand does not have
/// to remember two unrelated numbers.
pub const default_port: u16 = control.default_port + 1;

/// The name of the unix socket this binds inside the state directory.
///
/// **Its own name, beside the daemon's `daemon.sock` and never the same file.**
/// One person runs both, and two listeners on one path is a race over which of
/// them a client reaches.
pub const socket_name = "serve.sock";

/// How many browser connections are served at once.
///
/// A live view holds its connection for as long as a tab is open, and a page
/// opens one of those plus short lived requests beside it, so this is how many
/// tabs one `chock serve` carries rather than a burst limit.
const max_connections: usize = 32;

/// The longest request line and header block this reads from a browser.
const max_head_bytes: usize = 16 * 1024;

const usage_text =
    \\Usage: chock serve [options]
    \\
    \\Puts a browser in front of a daemon. This owns no session: it is a client
    \\of `chock daemon`, which may be on this machine or on another one.
    \\
    \\Binds a unix socket in the state directory, and nothing else until --host
    \\names an address. The socket serves the user that started this command, and
    \\every other peer is refused by the credential the kernel puts on the
    \\connection. A reverse proxy such as nginx, Caddy or Authelia proxies to that
    \\socket, which is the supported way to put authentication in front of this.
    \\
    \\Options:
    \\  --daemon <address>  Where the daemon is. `unix:/path` or `host:port`.
    \\                      Default is the socket in the state directory, or
    \\                      $CHOCK_DAEMON when that is set.
    \\  --project <dir>     The project to show. Default is the working directory.
    \\  --socket <path>     The unix socket. Default is serve.sock in the state
    \\                      directory.
    \\  --host <addr>       Bind this address, over TCP, instead of the socket.
    \\                      Off by default. Write `--host 127.0.0.1` to point a
    \\                      browser straight at this.
    \\  --port <n>          The TCP port, with --host. 0 asks the system for one
    \\                      and prints it. Default 7374.
    \\
    \\Chock does no authentication over a network, and a TCP connection carries
    \\no credential to check. Anything that can route to a --host address can
    \\approve an action, so put a reverse proxy such as Authelia in front of it.
    \\
++ tty.options_text;

/// Everything this process was told.
const Options = struct {
    daemon: ?[]const u8 = null,
    project: ?[]const u8 = null,
    socket: ?[]const u8 = null,
    host: ?[]const u8 = null,
    port: u16 = default_port,
};

/// Everything this process runs on, once the options are resolved.
const Serve = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    /// Where the daemon is. **The only thing here that knows a transport**,
    /// and it knows it inside `connect`.
    daemon: control.Address,
    /// The project this shows, which a browser never names.
    project: []const u8,
    /// The uid this process runs as. **A peer on the unix socket that is not
    /// this one is refused**: see `control.peerAllowed`.
    owner_uid: std.posix.uid_t,
    live: std.atomic.Value(usize) = .init(0),
};

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) !u8 {
    _ = exe_path;

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

    const daemon_text = options.daemon orelse env.get(control.address_env) orelse text: {
        const state = chock_auth.paths.stateDir(arena, &env) catch |err| {
            tty.print(.err, "chock serve: the state directory could not be found: {t}\n", .{err});
            return Exit.usage.code();
        };
        const path = control.socketPathIn(arena, state) catch return Exit.faulted.code();
        break :text try std.fmt.allocPrint(arena, "unix:{s}", .{path});
    };
    const daemon = control.Address.parse(daemon_text) catch |err| {
        tty.print(
            .err,
            "chock serve: \"{s}\" is not a daemon address ({t}). Write `unix:/path` or `host:port`.\n",
            .{ daemon_text, err },
        );
        return Exit.usage.code();
    };

    const project = if (options.project) |named| absolute: {
        if (std.fs.path.isAbsolute(named)) break :absolute named;
        tty.print(
            .err,
            "chock serve: --project takes an absolute path, and \"{s}\" is not one.\n",
            .{named},
        );
        return Exit.usage.code();
    } else cwd: {
        // **The directory is opened first, and that is not a step that can be
        // dropped.** `Dir.realPath` reads `/proc/self/fd/<fd>` on Linux, and
        // `std.Io.Dir.cwd()` carries `AT_FDCWD`, which is not a descriptor and
        // has no entry there. Asking it directly answers `FileNotFound` every
        // time, so `chock serve` with no `--project` never started. Measured by
        // running it.
        var here = std.Io.Dir.cwd().openDir(io, ".", .{}) catch |err| {
            tty.print(.err, "chock serve: the working directory could not be opened: {t}\n", .{err});
            return Exit.usage.code();
        };
        defer here.close(io);
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = here.realPath(io, &buffer) catch |err| {
            tty.print(.err, "chock serve: the working directory could not be read: {t}\n", .{err});
            return Exit.usage.code();
        };
        break :cwd try arena.dupe(u8, buffer[0..length]);
    };

    var serve_state = Serve{
        .gpa = gpa,
        .io = io,
        .daemon = daemon,
        .project = project,
        .owner_uid = std.posix.system.getuid(),
    };

    // **The daemon is proved to be there before a browser is invited.** A page
    // that opened and then showed nothing would send somebody looking at their
    // own network rather than at the one thing that is wrong.
    //
    // **Said before it is tried, and that is not a nicety.** `std.Io.net` gives
    // no way to bound a connect, so an address that drops packets rather than
    // refusing them leaves this waiting for the kernel's own timeout, which is
    // over a minute. Measured. Without this line that reads as a program that
    // hung on startup for no reason; with it, the last thing on the screen names
    // exactly what is being waited for. A connect this can bound is a change to
    // `chock_proto.control` and it is not this milestone.
    tty.print(.plain, "chock serve: reaching the daemon at {f}\n", .{daemon});
    const probe = daemon.connect(io) catch |err| {
        var buffer: [1024]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        writer.writeAll("chock serve: ") catch {};
        control.refusalFor(&writer, daemon, err) catch {};
        tty.print(.err, "{s}", .{writer.buffered()});
        return Exit.usage.code();
    };
    probe.close(io);

    const socket_path = options.socket orelse path: {
        const state = chock_auth.paths.stateDir(arena, &env) catch |err| {
            tty.print(.err, "chock serve: the state directory could not be found: {t}\n", .{err});
            return Exit.usage.code();
        };
        makeDirAll(io, state) catch |err| {
            tty.print(.err, "chock serve: {s} could not be made: {t}\n", .{ state, err });
            return Exit.usage.code();
        };
        break :path std.fs.path.join(arena, &.{ state, socket_name }) catch
            return Exit.faulted.code();
    };

    const bind = bindAddress(socket_path, options);
    var listener = bind.listen(io) catch |err| {
        tty.print(.err, "chock serve: {f} could not be listened on: {t}\n", .{ bind, err });
        // Named, because the fix is not obvious and it is not rare. A state
        // directory under a long home spends most of the bound before the
        // socket's own name is added.
        //
        // **The number is read and never written out.** This line said 108 on
        // every platform, and Darwin takes 103: see `control.max_socket_path`.
        if (err == error.PathTooLong) tty.print(
            .err,
            "chock serve: a unix socket path is at most {d} bytes on this platform. " ++
                "Name a shorter one with --socket.\n",
            .{control.max_socket_path},
        );
        return Exit.usage.code();
    };
    defer listener.close(io);

    if (options.host) |host| {
        tty.print(.plain, "chock serve: open http://{s}:{d}/\n", .{
            host,
            listener.server.socket.address.getPort(),
        });
    } else {
        tty.print(.plain, "chock serve: listening on {f}\n", .{bind});
        tty.print(
            .plain,
            "chock serve: a browser reaches this through a reverse proxy that proxies to " ++
                "that socket. For a browser to open it directly, run " ++
                "`chock serve --host 127.0.0.1`.\n",
            .{},
        );
    }
    tty.print(.plain, "chock serve: showing {s} from the daemon at {f}\n", .{ project, daemon });

    while (true) {
        var stream = listener.server.accept(io) catch |err| {
            tty.print(.warn, "chock serve: an incoming connection failed: {t}\n", .{err});
            continue;
        };

        // **The peer check, and it is the socket's alone.** A unix socket
        // carries the uid of whoever connected, and this command serves the
        // user that started it. A TCP connection carries no such thing, so
        // `unix_path` is what tells the two transports apart and nothing below
        // claims to have checked a TCP peer. See this file's own top comment.
        if (listener.unix_path != null and
            !control.peerAllowed(control.peerUid(stream.socket.handle), serve_state.owner_uid))
        {
            // Refused in words a person reads, and not by a connection that
            // drops. `curl --unix-socket` under another account prints this.
            var buffer: [forbidden_response.len]u8 = undefined;
            var writer = stream.writer(io, &buffer);
            writer.interface.writeAll(forbidden_response) catch {};
            writer.interface.flush() catch {};
            tty.print(.warn, "chock serve: a client of another user was refused.\n", .{});
            stream.close(io);
            continue;
        }

        if (serve_state.live.load(.monotonic) >= max_connections) {
            stream.close(io);
            continue;
        }
        _ = serve_state.live.fetchAdd(1, .monotonic);
        const thread = std.Thread.spawn(.{}, runConnection, .{Connection{
            .serve = &serve_state,
            .stream = stream,
        }}) catch {
            _ = serve_state.live.fetchSub(1, .monotonic);
            stream.close(io);
            continue;
        };
        thread.detach();
    }
}

/// The address this binds for a browser or for a proxy.
///
/// **The unix socket unless `--host` names something else.** A default is not a
/// deliberate choice, and a TCP connection carries no credential to check, so a
/// person who has not typed `--host` gets the one transport where the peer can
/// be named. See this file's own top comment.
///
/// Its own function so a test can read the answer without opening a socket.
fn bindAddress(socket_path: []const u8, options: Options) control.Address {
    const host = options.host orelse return .{ .unix = socket_path };
    return .{ .ip = .{ .host = host, .port = options.port } };
}

/// What a peer of another user is told, as one whole HTTP response.
///
/// **A status and a sentence, and then the connection closes.** A peer that was
/// refused must read why. A connection that simply drops sends somebody looking
/// at their own proxy for a fault that is not there.
const forbidden_response = forbidden: {
    const body = "this socket serves the user that started chock serve, " ++
        "and you are not that user\n";
    break :forbidden std.fmt.comptimePrint(
        "HTTP/1.1 403 Forbidden\r\n" ++
            "content-type: text/plain; charset=utf-8\r\n" ++
            "content-length: {d}\r\n" ++
            "connection: close\r\n" ++
            "\r\n{s}",
        .{ body.len, body },
    );
};

/// Make `path` and every directory above it that is missing.
///
/// **`chock serve` may be the first thing a person runs**, and then nothing has
/// made the state directory yet, nor the two directories above it that the XDG
/// layout puts it under. `createDirAbsolute` makes one level, so a single call
/// answers `FileNotFound` on a fresh machine. `src/daemon.zig` carries the same
/// three lines for the same reason.
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

const Connection = struct {
    serve: *Serve,
    stream: std.Io.net.Stream,
};

fn runConnection(conn: Connection) void {
    const serve = conn.serve;
    var stream = conn.stream;
    defer {
        stream.close(serve.io);
        _ = serve.live.fetchSub(1, .monotonic);
    }

    var arena = std.heap.ArenaAllocator.init(serve.gpa);
    defer arena.deinit();

    var read_buffer: [max_head_bytes]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [64 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);

    var http = std.http.Server.init(&stream_reader.interface, &stream_writer.interface);
    while (true) {
        var request = http.receiveHead() catch return;
        handle(serve, arena.allocator(), &request) catch return;
        // One arena per request, not per connection: a browser keeps a
        // connection alive across many of them.
        _ = arena.reset(.retain_capacity);
    }
}

/// What this answers to.
///
/// **One list, and the dispatch below switches over it with no `else`**, so a
/// route can never be named and unhandled. That is the rule `src/main.zig`
/// keeps for its command table and `chock_proto.control` keeps for its verbs.
pub const Route = enum {
    /// The page itself.
    page,
    /// The listing, as one JSON array.
    sessions,
    /// One session's events, as server sent events.
    events,
    /// One answer to one open approval.
    answer,
};

/// The route a path names, or null.
///
/// **The query string is not part of the route.** A path with parameters on it
/// is the same route as one without, and reading the two together is how a
/// router grows a case nobody can find.
pub fn routeOf(target: []const u8) ?Route {
    const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
    if (std.mem.eql(u8, path, "/")) return .page;
    if (std.mem.eql(u8, path, "/api/sessions")) return .sessions;
    if (std.mem.eql(u8, path, "/api/events")) return .events;
    if (std.mem.eql(u8, path, "/api/answer")) return .answer;
    return null;
}

fn handle(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const route = routeOf(request.head.target) orelse {
        try sendWhole(request, "not found\n", .{ .status = .not_found });
        return;
    };

    // **A state changing route takes a POST.** A browser will follow a link or
    // preload a URL, and approving an action must never be something a page
    // can cause by being looked at.
    const wanted: std.http.Method = if (route == .answer) .POST else .GET;
    if (request.head.method != wanted and !(wanted == .GET and request.head.method == .HEAD)) {
        try sendWhole(request, "that route does not take that method\n", .{ .status = .method_not_allowed });
        return;
    }

    switch (route) {
        .page => try sendWhole(request, page_html, .{ .extra_headers = &.{
            .{ .name = "content-type", .value = "text/html; charset=utf-8" },
        } }),
        .sessions => try serveSessions(serve, arena, request),
        .events => try serveEvents(serve, arena, request),
        .answer => try serveAnswer(serve, arena, request),
    }
}

/// Ask the daemon for the listing and hand it over as one JSON array.
///
/// **The rows are passed through, not parsed and rebuilt.** A row is already
/// JSON that the daemon wrote, and re-encoding it here would be a second
/// encoder to keep in step with the first for no gain.
fn serveSessions(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const stream = serve.daemon.connect(serve.io) catch |err| {
        try respondUnreachable(arena, request, serve.daemon, err);
        return;
    };
    defer stream.close(serve.io);

    var read_buffer: [64 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);

    var body: std.ArrayList(u8) = .empty;
    const Gather = struct {
        gpa: std.mem.Allocator,
        body: *std.ArrayList(u8),
        failed: ?[]const u8 = null,

        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |one| {
                    if (self.body.items.len != 0) try self.body.append(self.gpa, ',');
                    try self.body.appendSlice(self.gpa, one.payload);
                },
                .failed => |text| {
                    self.failed = text;
                    return false;
                },
                .ok => {},
            }
            return true;
        }
    };
    var gather = Gather{ .gpa = arena, .body = &body };
    var said: control.Handshake = .{ .unreadable = "" };

    control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .list = .{ .project = serve.project } },
        &said,
        &gather,
        Gather.take,
    ) catch |err| {
        if (!said.ok()) {
            try respondHandshake(arena, request, serve.daemon, said);
            return;
        }
        try respondDaemonFault(arena, request, @errorName(err));
        return;
    };

    if (gather.failed) |text| {
        try respondDaemonRefusal(arena, request, text);
        return;
    }

    const json = try std.fmt.allocPrint(arena, "[{s}]", .{body.items});
    try sendWhole(request, json, .{ .extra_headers = &json_headers });
}

/// Stream one session's events to the browser, as they arrive.
///
/// **Server sent events, framed on the log's own identifiers.** An event
/// identifier is its own byte offset, so `Last-Event-ID` is a resume point with
/// no gap and no repeat. A browser reconnecting sends it by itself.
///
/// The data of each frame is the log's own line, byte for byte. See
/// `src/daemon.zig`: a re-encoding would read as tampered with to anything
/// that checks the chain.
fn serveEvents(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "that needs a session\n", .{ .status = .bad_request });
        return;
    };
    // A browser sends `Last-Event-ID` on a reconnect by itself, and the query
    // is what a first connection uses. The header wins, because it is the one
    // the browser knows is right.
    const after = lastEventId(request) orelse parseAfter(queryValue(request.head.target, "after"));

    const stream = serve.daemon.connect(serve.io) catch |err| {
        try respondUnreachable(arena, request, serve.daemon, err);
        return;
    };
    defer stream.close(serve.io);

    var read_buffer: [256 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);

    var body_buffer: [64 * 1024]u8 = undefined;
    var body = try request.respondStreaming(&body_buffer, .{
        .respond_options = .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/event-stream" },
                // A proxy that buffered this would turn a live view into one that
                // arrives all at once when the session ends.
                .{ .name = "cache-control", .value = "no-cache" },
                .{ .name = "x-accel-buffering", .value = "no" },
            },
        },
    });

    const Pump = struct {
        out: *std.http.BodyWriter,

        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |one| {
                    writeFrame(&self.out.writer, one) catch return false;
                    // Flushed per event, because an event held in a buffer is
                    // an event a person is not looking at.
                    self.out.flush() catch return false;
                },
                .failed => |text| {
                    // A refusal reaches the page as an event of its own, so a
                    // browser shows the reason rather than a stream that
                    // stopped.
                    self.out.writer.print("event: refused\ndata: {s}\n\n", .{text}) catch return false;
                    self.out.flush() catch return false;
                    return false;
                },
                .ok => {},
            }
            return true;
        }
    };
    var pump = Pump{ .out = &body };
    var said: control.Handshake = .{ .unreadable = "" };

    control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .watch = .{ .project = serve.project, .session = session, .after = after } },
        &said,
        &pump,
        Pump.take,
    ) catch {};

    // **A daemon this frontend cannot speak to reaches the page as words.** The
    // response headers went out before the exchange, so there is no status left
    // to send: a stream that simply stopped would look to a person like a
    // session that went quiet, which is the one reading that is wrong.
    if (!said.ok()) {
        var text: std.Io.Writer.Allocating = .init(arena);
        defer text.deinit();
        if (control.handshakeRefusal(&text.writer, serve.daemon, said)) {
            body.writer.print("event: refused\ndata: {s}\n\n", .{
                std.mem.trimEnd(u8, text.written(), "\n"),
            }) catch {};
            body.flush() catch {};
        } else |_| {}
    }

    body.end() catch {};
}

/// One server sent event frame for one record.
///
/// Its own function so a test can pin the framing without a socket. **The
/// identifier is the log's**, which is what makes a reconnect resume exactly.
pub fn writeFrame(writer: *std.Io.Writer, record: control.Reply.Record) std.Io.Writer.Error!void {
    // A log line is one line of JSON with no line break in it, so it needs no
    // splitting across `data:` fields.
    try writer.print("id: {d}\ndata: {s}\n\n", .{ record.id, record.payload });
}

/// Carry one answer to the daemon.
///
/// **A client may say only what a person may say.** The decision is read by
/// `control.Answer.parse`, which knows two words, so a browser that wrote
/// `allowed_by_policy` gets a refusal here and never reaches the daemon. The
/// daemon clamps again and the session clamps a third time: see this file's own
/// top comment.
fn serveAnswer(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const asked = answerFrom(request.head.target, serve.project) catch |err| {
        const text = switch (err) {
            error.NoSession => "that needs a session\n",
            error.NoRequest => "that needs the identifier of the approval it answers\n",
            error.NoDecision => "a decision is `yes` or `no`, and nothing else\n",
        };
        try sendWhole(request, text, .{ .status = .bad_request });
        return;
    };

    const stream = serve.daemon.connect(serve.io) catch |err| {
        try respondUnreachable(arena, request, serve.daemon, err);
        return;
    };
    defer stream.close(serve.io);

    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);

    const Answered = struct {
        said: ?[]const u8 = null,
        good: bool = false,

        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .ok => |text| {
                    self.good = true;
                    self.said = text;
                },
                .failed => |text| self.said = text,
                .record => {},
            }
            return false;
        }
    };
    var answered = Answered{};
    var said: control.Handshake = .{ .unreadable = "" };

    control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        asked,
        &said,
        &answered,
        Answered.take,
    ) catch |err| {
        if (!said.ok()) {
            try respondHandshake(arena, request, serve.daemon, said);
            return;
        }
        try respondDaemonFault(arena, request, @errorName(err));
        return;
    };

    if (!answered.good) {
        // **Never a quiet success.** An approval the daemon could not deliver
        // must not look to a person like one that landed.
        try respondDaemonRefusal(arena, request, answered.said orelse "the daemon said nothing");
        return;
    }
    try sendWhole(request, "{\"answered\":true}", .{ .extra_headers = &json_headers });
}

const json_headers = [_]std.http.Header{
    .{ .name = "content-type", .value = "application/json" },
};

/// Send one whole response, and never keep a connection this cannot clear.
///
/// **Every response goes through here, and the reason is a real crash.**
/// `std.http.Server.respond` calls `discardBody` to make the connection ready
/// for the next request, and that call asserts that a request whose method may
/// carry a body declared how long that body is. **A `POST` with neither a
/// `content-length` nor a `transfer-encoding` is legal and some clients send
/// one**, `curl -X POST` with no data among them, and it reached that assert
/// and killed the whole process. Measured by running it.
///
/// So a request that declares a body this never read is answered and the
/// connection is closed after it. That costs one connection per approval, which
/// is nothing, and it removes a way for anything that can reach this to stop it.
fn sendWhole(
    request: *std.http.Server.Request,
    content: []const u8,
    options: std.http.Server.Request.RespondOptions,
) !void {
    var with = options;
    with.keep_alive = options.keep_alive and mayKeepAlive(
        request.head.method,
        request.head.transfer_encoding,
        request.head.content_length,
    );
    try request.respond(content, with);
}

/// Whether a connection can be reused after this request is answered.
///
/// **False for a request whose body cannot be discarded**, which is one whose
/// method may carry a body and which said nothing about how long that body is.
/// See `reply` for the crash this exists to prevent.
///
/// Its own function taking three plain values, so a test drives every shape a
/// client can send with no socket and no server.
pub fn mayKeepAlive(
    method: std.http.Method,
    transfer_encoding: std.http.TransferEncoding,
    content_length: ?u64,
) bool {
    if (!method.requestHasBody()) return true;
    return transfer_encoding != .none or content_length != null;
}

pub const AnswerError = error{ NoSession, NoRequest, NoDecision };

/// The request one `/api/answer` call becomes.
///
/// **Its own function, and the clamp lives in it.** A test drives every word a
/// browser could send through this with no socket at all.
pub fn answerFrom(target: []const u8, project: []const u8) AnswerError!control.Request {
    const session = queryValue(target, "session") orelse return error.NoSession;
    const request_text = queryValue(target, "request") orelse return error.NoRequest;
    const request_id = std.fmt.parseInt(u64, request_text, 10) catch return error.NoRequest;
    const word = queryValue(target, "decision") orelse return error.NoDecision;
    const decision = control.Answer.parse(word) orelse return error.NoDecision;
    return .{ .answer = .{
        .project = project,
        .session = session,
        .request_id = request_id,
        .decision = decision,
    } };
}

/// The value of one query parameter, or null. **No unescaping**, because every
/// value this page sends is a session identifier, a number, or one of two
/// words, and none of those can hold a character that needs it. A value that
/// arrives with one is refused by whatever reads it.
pub fn queryValue(target: []const u8, name: []const u8) ?[]const u8 {
    const start = std.mem.indexOfScalar(u8, target, '?') orelse return null;
    var parts = std.mem.splitScalar(u8, target[start + 1 ..], '&');
    while (parts.next()) |part| {
        const equals = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        if (!std.mem.eql(u8, part[0..equals], name)) continue;
        const value = part[equals + 1 ..];
        if (value.len == 0) return null;
        return value;
    }
    return null;
}

fn parseAfter(text: ?[]const u8) u64 {
    const given = text orelse return 0;
    return std.fmt.parseInt(u64, given, 10) catch 0;
}

/// The `Last-Event-ID` a reconnecting browser sends, or null.
fn lastEventId(request: *std.http.Server.Request) ?u64 {
    var headers = request.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "last-event-id")) continue;
        return std.fmt.parseInt(u64, header.value, 10) catch null;
    }
    return null;
}

/// Say that the daemon could not be reached, in the words `chock detach` and
/// every other client uses.
///
/// **`502 Bad Gateway` and not `500`.** Nothing here is broken: the thing this
/// is a frontend for is not answering, which is exactly what that status
/// means, and a person reading a log of statuses can tell the two apart.
fn respondUnreachable(
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    address: control.Address,
    err: control.Address.ConnectError,
) !void {
    const text = try unreachableText(arena, address, err);
    try sendWhole(request, text, .{ .status = .bad_gateway, .extra_headers = &.{
        .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
    } });
}

/// The sentence a browser is shown when the daemon is not there. Caller owns
/// it. Its own function so a test needs no network to read it.
pub fn unreachableText(
    gpa: std.mem.Allocator,
    address: control.Address,
    err: control.Address.ConnectError,
) std.mem.Allocator.Error![]u8 {
    var text: std.Io.Writer.Allocating = .init(gpa);
    defer text.deinit();
    control.refusalFor(&text.writer, address, err) catch return error.OutOfMemory;
    return text.toOwnedSlice();
}

/// What a browser is shown when the daemon and this build do not speak one
/// control protocol number.
///
/// **A gateway status, because the fault is between two programs and not in the
/// request.** A person reading it has to know which end to update, so the
/// sentence is `control.handshakeRefusal`'s and names both numbers.
fn respondHandshake(
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    address: control.Address,
    said: control.Handshake,
) !void {
    const text = try handshakeText(arena, address, said);
    try sendWhole(request, text, .{ .status = .bad_gateway, .extra_headers = &.{
        .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
    } });
}

/// The sentence itself. Caller owns it. Its own function so a test needs no
/// daemon to read it, which is the shape `unreachableText` already has.
pub fn handshakeText(
    gpa: std.mem.Allocator,
    address: control.Address,
    said: control.Handshake,
) std.mem.Allocator.Error![]u8 {
    var text: std.Io.Writer.Allocating = .init(gpa);
    defer text.deinit();
    control.handshakeRefusal(&text.writer, address, said) catch return error.OutOfMemory;
    return text.toOwnedSlice();
}

fn respondDaemonRefusal(
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    what: []const u8,
) !void {
    const text = try std.fmt.allocPrint(arena, "the daemon would not: {s}\n", .{what});
    try sendWhole(request, text, .{ .status = .conflict, .extra_headers = &.{
        .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
    } });
}

fn respondDaemonFault(
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    what: []const u8,
) !void {
    const text = try std.fmt.allocPrint(arena, "the daemon could not be read: {s}\n", .{what});
    try sendWhole(request, text, .{ .status = .bad_gateway, .extra_headers = &.{
        .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
    } });
}

const ParseError = error{ HelpWanted, BadArguments };

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};
    var port_named = false;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;

        const takes_value = [_][]const u8{ "--daemon", "--project", "--socket", "--host", "--port" };
        var named: ?[]const u8 = null;
        for (takes_value) |one| {
            if (std.mem.eql(u8, argument, one)) named = one;
        }
        if (named) |flag| {
            index += 1;
            if (index >= args.len) {
                tty.print(.err, "chock serve: {s} needs a value.\n\n", .{flag});
                tty.print(.err, "{s}", .{usage_text});
                return error.BadArguments;
            }
            const value = args[index];
            if (std.mem.eql(u8, flag, "--daemon")) options.daemon = value;
            if (std.mem.eql(u8, flag, "--project")) options.project = value;
            if (std.mem.eql(u8, flag, "--socket")) options.socket = value;
            if (std.mem.eql(u8, flag, "--host")) options.host = value;
            if (std.mem.eql(u8, flag, "--port")) {
                port_named = true;
                options.port = std.fmt.parseInt(u16, value, 10) catch {
                    tty.print(
                        .err,
                        "chock serve: --port takes a number, and \"{s}\" is not one.\n",
                        .{value},
                    );
                    return error.BadArguments;
                };
            }
            continue;
        }

        tty.print(.err, "chock serve: there is no option named {s}.\n\n", .{argument});
        tty.print(.err, "{s}", .{usage_text});
        return error.BadArguments;
    }

    // **A `--port` on its own names nothing.** There is no TCP listener until
    // `--host` turns one on, so a person who typed only `--port` believes they
    // opened a port and did not. `src/daemon.zig` refuses the same pair.
    if (port_named and options.host == null) {
        tty.print(
            .err,
            "chock serve: --port names the port of the TCP listener --host turns on, and there " ++
                "is no TCP listener without --host. Write `--host 127.0.0.1 --port <n>`, or drop " ++
                "--port and use the unix socket.\n",
            .{},
        );
        return error.BadArguments;
    }
    return options;
}

/// The whole frontend, in one file with nothing fetched from anywhere.
///
/// **Nothing external, on purpose.** A page that pulled a script off the
/// internet would make a machine with no route out show a broken interface, and
/// Chock is a tool people run on machines like that.
///
/// The four regions are the ones the terminal draws: the sessions down the
/// left, the transcript in the middle, the open question at the foot, and the
/// state along the top.
const page_html =
    \\<!doctype html>
    \\<html lang="en">
    \\<head>
    \\<meta charset="utf-8">
    \\<meta name="viewport" content="width=device-width, initial-scale=1">
    \\<title>chock</title>
    \\<style>
    \\:root { color-scheme: light dark; --line: #8884; --dim: #8889; }
    \\* { box-sizing: border-box; }
    \\body { margin: 0; font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
    \\  height: 100vh; display: grid; grid-template-rows: auto 1fr auto;
    \\  grid-template-columns: 22rem 1fr; grid-template-areas: "top top" "side main" "ask ask"; }
    \\header { grid-area: top; padding: .5rem .75rem; border-bottom: 1px solid var(--line);
    \\  display: flex; gap: 1rem; align-items: baseline; }
    \\header b { font-weight: 600; }
    \\header span { color: var(--dim); }
    \\#side { grid-area: side; border-right: 1px solid var(--line); overflow-y: auto; }
    \\#main { grid-area: main; overflow-y: auto; padding: .5rem .75rem; }
    \\#ask { grid-area: ask; border-top: 1px solid var(--line); padding: .75rem; display: none; }
    \\#ask.open { display: block; }
    \\.row { padding: .5rem .75rem; border-bottom: 1px solid var(--line); cursor: pointer; }
    \\.row:hover { background: #8881; }
    \\.row.on { background: #8882; }
    \\.row .id { font-weight: 600; }
    \\.row .meta { color: var(--dim); font-size: 12px; }
    \\.dot { display: inline-block; width: .5rem; height: .5rem; border-radius: 50%; }
    \\.live { background: #2a2; } .idle { background: #888; } .unknown { background: #c82; }
    \\.ev { padding: .25rem 0; border-bottom: 1px solid var(--line); white-space: pre-wrap;
    \\  word-break: break-word; }
    \\.ev .kind { color: var(--dim); margin-right: .5rem; }
    \\.warn { color: #c82; }
    \\button { font: inherit; padding: .35rem .9rem; margin-right: .5rem; cursor: pointer; }
    \\pre { margin: .25rem 0; white-space: pre-wrap; }
    \\</style>
    \\</head>
    \\<body>
    \\<header><b>chock</b><span id="where"></span><span id="note"></span></header>
    \\<div id="side"></div>
    \\<div id="main"></div>
    \\<div id="ask"><div id="asktext"></div>
    \\  <p><button id="yes">Allow</button><button id="no">Refuse</button></p></div>
    \\<script>
    \\"use strict";
    \\let current = null, source = null, open = null;
    \\const $ = (id) => document.getElementById(id);
    \\const say = (t) => { $("note").textContent = t; };
    \\
    \\async function sessions() {
    \\  try {
    \\    const answer = await fetch("/api/sessions");
    \\    if (!answer.ok) { say(await answer.text()); return; }
    \\    say("");
    \\    draw(await answer.json());
    \\  } catch (e) { say(String(e)); }
    \\}
    \\
    \\function draw(rows) {
    \\  const side = $("side");
    \\  side.replaceChildren();
    \\  if (rows.length === 0) {
    \\    const empty = document.createElement("div");
    \\    empty.className = "row"; empty.textContent = "no sessions yet";
    \\    side.append(empty); return;
    \\  }
    \\  for (const row of rows.slice().reverse()) {
    \\    const el = document.createElement("div");
    \\    el.className = "row" + (row.id === current ? " on" : "");
    \\    const dot = document.createElement("span");
    \\    dot.className = "dot " + (row.live || "unknown");
    \\    const id = document.createElement("div");
    \\    id.className = "id"; id.append(dot, " " + row.id);
    \\    const meta = document.createElement("div");
    \\    meta.className = "meta";
    \\    const bits = [new Date(row.started_ms).toLocaleString()];
    \\    if (row.model) bits.push(row.model);
    \\    if (row.end) bits.push(row.end);
    \\    if (row.turns) bits.push(row.turns + " turns");
    \\    if (row.chain !== "intact") bits.push("chain " + row.chain);
    \\    meta.textContent = bits.join(" \u00b7 ");
    \\    el.append(id, meta);
    \\    el.onclick = () => watch(row.id);
    \\    side.append(el);
    \\  }
    \\}
    \\
    \\function watch(id) {
    \\  if (source) { source.close(); source = null; }
    \\  current = id; open = null; $("ask").className = "";
    \\  $("main").replaceChildren();
    \\  sessions();
    \\  source = new EventSource("/api/events?session=" + encodeURIComponent(id) + "&after=0");
    \\  source.onmessage = (m) => show(JSON.parse(m.data));
    \\  source.addEventListener("refused", (m) => say(m.data));
    \\  source.onerror = () => say("the event stream stopped");
    \\}
    \\
    \\function show(envelope) {
    \\  if (!envelope.event) return;
    \\  const kind = Object.keys(envelope.event)[0];
    \\  const body = envelope.event[kind];
    \\  if (kind === "approval.request") { ask(envelope.id, body); }
    \\  if (kind === "approval.response" && open !== null) { $("ask").className = ""; open = null; }
    \\  const el = document.createElement("div");
    \\  el.className = "ev";
    \\  const tag = document.createElement("span");
    \\  tag.className = "kind"; tag.textContent = kind;
    \\  const text = document.createElement("span");
    \\  text.textContent = summarise(kind, body);
    \\  el.append(tag, text);
    \\  const main = $("main");
    \\  const at_end = main.scrollTop + main.clientHeight >= main.scrollHeight - 40;
    \\  main.append(el);
    \\  if (at_end) main.scrollTop = main.scrollHeight;
    \\}
    \\
    \\function summarise(kind, body) {
    \\  if (!body) return "";
    \\  if (kind === "message") {
    \\    const parts = (body.content || []).map((p) => p.text || p.thinking || "").filter(Boolean);
    \\    return body.role + ": " + parts.join("\n");
    \\  }
    \\  if (kind === "tool.call") return body.name + " " + (body.arguments || "");
    \\  if (kind === "tool.result") return (body.ok === false ? "failed: " : "") + (body.output || "");
    \\  if (kind === "session.end") return body.reason + (body.detail ? ": " + body.detail : "");
    \\  if (kind === "approval.response") return body.decision + " by " + (body.responder || "somebody");
    \\  return JSON.stringify(body);
    \\}
    \\
    \\function ask(id, body) {
    \\  open = id;
    \\  const box = $("asktext");
    \\  box.replaceChildren();
    \\  const head = document.createElement("b");
    \\  head.textContent = body.action + ": " + (body.summary || "");
    \\  const why = document.createElement("div");
    \\  why.className = "meta"; why.textContent = body.reason || "";
    \\  const detail = document.createElement("pre");
    \\  detail.textContent = body.detail || "";
    \\  box.append(head, why, detail);
    \\  $("ask").className = "open";
    \\}
    \\
    \\async function answer(word) {
    \\  if (open === null || current === null) return;
    \\  const url = "/api/answer?session=" + encodeURIComponent(current) +
    \\    "&request=" + open + "&decision=" + word;
    \\  try {
    \\    const done = await fetch(url, { method: "POST" });
    \\    if (!done.ok) { say(await done.text()); return; }
    \\    say(""); $("ask").className = ""; open = null;
    \\  } catch (e) { say(String(e)); }
    \\}
    \\
    \\$("yes").onclick = () => answer("yes");
    \\$("no").onclick = () => answer("no");
    \\$("where").textContent = location.host;
    \\sessions();
    \\setInterval(sessions, 3000);
    \\</script>
    \\</body>
    \\</html>
    \\
;

const testing = std.testing;

test "serve reaches a daemon and never a session on disk" {
    // **The shape rule, pinned where it can be read.** Would this still work
    // if the daemon were on another machine? It would only if this file never
    // opens a log, never takes a lock, and never resolves a session directory,
    // and no type can say that: the property is about what is absent.
    //
    // So it is a grep over this file's own source. **Each needle is built by
    // joining two pieces**, so the test does not match itself, which is the
    // trap the first version of it fell into.
    //
    // Mutation check: read a log here to skip a round trip when the daemon is
    // local, which is exactly the shortcut a hosted deployment would have to
    // unpick, and this fails.
    const source = @embedFile("serve.zig");
    const opening = "@im" ++ "port(\"";
    const forbidden = [_][]const u8{
        // The modules a frontend must not link. Each one would give it a way
        // to reach a session without asking the daemon.
        opening ++ "chock-broker\")",
        opening ++ "chock-core\")",
        opening ++ "chock-workspace\")",
        // The two files of this command that know where a session lives.
        opening ++ "session.zig\")",
        opening ++ "sessions.zig\")",
        // And the calls that would open or lock one, whichever module they
        // came through.
        "Log." ++ "open",
        "." ++ "lock(",
        "paths" ++ "For(",
    };
    for (forbidden) |needle| {
        try testing.expect(std.mem.indexOf(u8, source, needle) == null);
    }

    // And the grep is looking at the right file, so the loop above is not
    // passing over nothing.
    try testing.expect(std.mem.indexOf(u8, source, "chock serve") != null);
    try testing.expect(std.mem.indexOf(u8, source, "control.exchange") != null);

    // **The peer check is reached, and it is never copied here.** The rule
    // above keeps this file out of `chock-broker`, which is where the check
    // used to live, and the wrong way out of that is a second body of it in
    // this file. So the body moved to `chock_proto.control`, which both this
    // file and the broker reach, and this pins that: the call is here and the
    // system call names of the two platforms are not.
    //
    // Mutation check: paste `peerUid`'s body back into this file and this
    // fails on the first needle below.
    for ([_][]const u8{
        "SO" ++ ".PEERCRED",
        "LOCAL" ++ "_PEERCRED",
        // The structure name of each platform, split so this list does not
        // match itself. That is the trap the first version of this fell into.
        "U" ++ "cred",
        "X" ++ "ucred",
    }) |copied| {
        try testing.expect(std.mem.indexOf(u8, source, copied) == null);
    }
    try testing.expect(std.mem.indexOf(u8, source, "control." ++ "peerUid") != null);
    try testing.expect(std.mem.indexOf(u8, source, "control." ++ "peerAllowed") != null);
}

test "nothing but the unix socket is bound until --host says so" {
    // **The default is the one transport where the kernel names the peer.**
    // Loopback TCP authenticates nobody: every local account can open
    // `127.0.0.1` and approve an action in this user's session. A browser
    // cannot open a unix socket, and that is not the question: nginx, Caddy
    // and Authelia all proxy to one, and a proxy is where authentication
    // belongs.
    //
    // Mutation check: make `bindAddress` answer an `ip` when `host` is null
    // and this fails on the first assertion.
    const plain = bindAddress("/state/serve.sock", .{});
    try testing.expect(plain == .unix);
    try testing.expectEqualStrings("/state/serve.sock", plain.unix);

    // `--host 127.0.0.1` is the one flag that puts a browser straight in
    // front of this, and it is a choice a person made.
    const direct = bindAddress("/state/serve.sock", .{ .host = "127.0.0.1", .port = 7374 });
    try testing.expect(direct == .ip);
    try testing.expectEqualStrings("127.0.0.1", direct.ip.host);
    try testing.expectEqual(@as(u16, 7374), direct.ip.port);

    // And `0.0.0.0` is allowed, because somebody who types it has chosen to be
    // reachable. Mutation check: refuse a host that is not loopback and this
    // fails.
    const wide = bindAddress("/state/serve.sock", .{ .host = "0.0.0.0", .port = 8080 });
    try testing.expect(wide == .ip);
    try testing.expectEqualStrings("0.0.0.0", wide.ip.host);

    // A `--socket` path is bound instead of the default one, and naming it
    // does not turn a TCP listener on.
    const named = bindAddress("/run/chock/other.sock", .{ .socket = "/run/chock/other.sock" });
    try testing.expect(named == .unix);
    try testing.expectEqualStrings("/run/chock/other.sock", named.unix);

    // The socket is not the daemon's. Two listeners on one path is a race over
    // which of them a client reaches.
    try testing.expect(!std.mem.eql(u8, socket_name, control.socket_name));
}

test "a peer that is not this user is refused on the socket, and a TCP peer is never claimed to be checked" {
    // **The check is one implementation and it is `chock_proto.control`'s.**
    // `src/daemon.zig` guards its control socket with the same two functions,
    // and `lib/chock-broker/socket.zig` guards the approval socket with them.
    // A security check written three times drifts apart.
    //
    // Mutation check: make `control.peerAllowed` answer true always, and every
    // account on the machine can approve an action in this user's session.
    const mine = std.posix.system.getuid();
    try testing.expect(control.peerAllowed(mine, mine));
    try testing.expect(!control.peerAllowed(mine +% 1, mine));
    // An absent answer is a refusal and never a pass. Mutation check: read a
    // null uid as allowed and a peer the kernel would not name gets in.
    try testing.expect(!control.peerAllowed(null, mine));

    // And a real unix socket really carries the credential, because a check
    // fed by a call that answers nothing would pass every test above and
    // refuse every peer in production.
    const io = testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket_path = try std.fmt.bufPrint(
        &path_buffer,
        "{s}/serve.sock",
        .{dir_buffer[0..dir_len]},
    );

    var listener = try (control.Address{ .unix = socket_path }).listen(io);
    defer listener.close(io);
    // A unix listener is what carries a peer credential, and `unix_path` is
    // what the accept loop reads to tell the two transports apart.
    try testing.expect(listener.unix_path != null);

    const client = try (control.Address{ .unix = socket_path }).connect(io);
    defer client.close(io);
    var served = try listener.server.accept(io);
    defer served.close(io);

    const said_uid = control.peerUid(served.socket.handle);
    try testing.expectEqual(@as(?std.posix.uid_t, mine), said_uid);
    try testing.expect(control.peerAllowed(said_uid, mine));
    try testing.expect(!control.peerAllowed(said_uid, mine +% 1));

    // The refusal a peer of another user reads. It is a whole HTTP response,
    // because a connection that drops sends somebody looking at their own
    // proxy for a fault that is not there.
    try testing.expect(std.mem.startsWith(u8, forbidden_response, "HTTP/1.1 403 Forbidden\r\n"));
    try testing.expect(std.mem.indexOf(u8, forbidden_response, "\r\n\r\n") != null);
    const head_end = std.mem.indexOf(u8, forbidden_response, "\r\n\r\n").? + 4;
    // The declared length is the length of what follows it. Mutation check:
    // write a constant `content-length` and a client hangs waiting for bytes
    // that never come.
    var length_buffer: [32]u8 = undefined;
    const declared = try std.fmt.bufPrint(
        &length_buffer,
        "content-length: {d}\r\n",
        .{forbidden_response.len - head_end},
    );
    try testing.expect(std.mem.indexOf(u8, forbidden_response, declared) != null);
}

test "a browser can decide exactly two things, and neither of them is the policy's" {
    // **The trust boundary at the outermost layer.** A page that could write
    // `allowed_by_policy` would be forging the project's own table, which is
    // kept beyond every agent's reach. The clamp is `control.Answer.parse`,
    // which knows two words, and the request is refused rather than mapped
    // down: a browser that sent nonsense is told so.
    //
    // Mutation check: fall back to `.no` for an unknown word and this passes
    // while a page that typed `allowed_by_policy` gets a refusal recorded and
    // no sign that its request was nonsense.
    const project = "/home/ross/chock";
    const id = "01JQ" ++ "A" ** 22;

    const yes = try answerFrom("/api/answer?session=" ++ id ++ "&request=128&decision=yes", project);
    try testing.expectEqual(control.Answer.yes, yes.answer.decision);
    try testing.expectEqual(@as(u64, 128), yes.answer.request_id);
    try testing.expectEqualStrings(id, yes.answer.session);
    // The project comes from the command line and never from the browser.
    try testing.expectEqualStrings(project, yes.answer.project);

    const no = try answerFrom("/api/answer?session=" ++ id ++ "&request=1&decision=no", project);
    try testing.expectEqual(control.Answer.no, no.answer.decision);

    for ([_][]const u8{
        "allowed_by_policy",
        "approved_by_policy",
        "approved_by_review",
        "approved_by_user",
        "YES",
        "y",
        "true",
    }) |word| {
        var target_buffer: [256]u8 = undefined;
        const target = try std.fmt.bufPrint(
            &target_buffer,
            "/api/answer?session={s}&request=1&decision={s}",
            .{ id, word },
        );
        try testing.expectError(error.NoDecision, answerFrom(target, project));
    }

    // And every part is required. A missing one is a refusal, never a default.
    try testing.expectError(
        error.NoSession,
        answerFrom("/api/answer?request=1&decision=yes", project),
    );
    try testing.expectError(
        error.NoRequest,
        answerFrom("/api/answer?session=" ++ id ++ "&decision=yes", project),
    );
    try testing.expectError(
        error.NoRequest,
        answerFrom("/api/answer?session=" ++ id ++ "&request=x&decision=yes", project),
    );
    try testing.expectError(
        error.NoDecision,
        answerFrom("/api/answer?session=" ++ id ++ "&request=1", project),
    );
}

test "a browser cannot name a project, so it cannot ask about a directory it was not shown" {
    // The project is a command line option. A page that could name one would
    // be a page that can ask the daemon about any directory this user can
    // read, and a frontend has no reason to be able to do that.
    //
    // Mutation check: read `project` out of the query string and this fails.
    const id = "01JQ" ++ "A" ** 22;
    const asked = try answerFrom(
        "/api/answer?session=" ++ id ++ "&request=1&decision=yes&project=/etc",
        "/home/ross/chock",
    );
    try testing.expectEqualStrings("/home/ross/chock", asked.answer.project);
}

test "every route is one the dispatch has a case for, and a query does not make a new one" {
    // One list, switched over with no `else`, so a route can never be named
    // and unhandled.
    try testing.expectEqual(Route.page, routeOf("/").?);
    try testing.expectEqual(Route.sessions, routeOf("/api/sessions").?);
    try testing.expectEqual(Route.events, routeOf("/api/events").?);
    try testing.expectEqual(Route.answer, routeOf("/api/answer").?);

    // A query string is not part of the route. Mutation check: match the whole
    // target and every request with a parameter on it becomes a 404.
    try testing.expectEqual(Route.events, routeOf("/api/events?session=01&after=0").?);
    try testing.expectEqual(Route.sessions, routeOf("/api/sessions?").?);

    // And a path this does not serve is not guessed at.
    for ([_][]const u8{
        "/api",
        "/api/",
        "/api/sessions/1",
        "/index.html",
        "/../etc/passwd",
        "",
    }) |target| try testing.expect(routeOf(target) == null);

    // Every member of `Route` is reachable from some path, so a route added to
    // the enum and never routed to fails here.
    var reached = std.EnumSet(Route).initEmpty();
    for ([_][]const u8{ "/", "/api/sessions", "/api/events", "/api/answer" }) |target| {
        reached.insert(routeOf(target).?);
    }
    try testing.expectEqual(std.enums.values(Route).len, reached.count());
}

test "a query value is read by name and an empty one is no value at all" {
    const target = "/api/events?session=01JQ&after=4096&empty=";
    try testing.expectEqualStrings("01JQ", queryValue(target, "session").?);
    try testing.expectEqualStrings("4096", queryValue(target, "after").?);
    // An empty value is not a value: `after=` must not read as zero by a
    // different route than `after` being absent.
    try testing.expect(queryValue(target, "empty") == null);
    try testing.expect(queryValue(target, "missing") == null);
    // A name that is a prefix of another is not that other one. Mutation
    // check: compare with `startsWith` and `after` answers for `aft`.
    try testing.expect(queryValue(target, "aft") == null);
    try testing.expect(queryValue(target, "sess") == null);
    try testing.expect(queryValue("/api/sessions", "session") == null);
}

test "an event frame carries the log's own identifier and the log's own bytes" {
    // **What makes a reconnect exact and a chain checkable.** An event
    // identifier is its own byte offset, so a browser sending `Last-Event-ID`
    // resumes with no gap and no repeat, and the data is the line as the log
    // holds it, which is what `chain.Verifier` hashes.
    //
    // Mutation check: re-encode the parsed envelope into the frame and a
    // client that verifies the chain calls a sound log tampered with.
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const line = "{\"id\":4096,\"session\":\"01JQ\",\"time_ms\":1,\"event\":{\"message\":{}}}";
    try writeFrame(&writer, .{ .id = 4096, .payload = line });

    try testing.expectEqualStrings("id: 4096\ndata: " ++ line ++ "\n\n", writer.buffered());
    // The frame ends in a blank line, which is what tells a browser one event
    // is whole. Without it nothing is delivered until the next one arrives.
    try testing.expect(std.mem.endsWith(u8, writer.buffered(), "\n\n"));
}

test "a daemon that is not running is a plain refusal that names what to do" {
    // The one every first time user meets, and it must not read as a bug in
    // this program. The words come from `control.refusalFor`, so `chock serve`
    // and every other client say the same thing.
    const gpa = testing.allocator;

    const said = try unreachableText(
        gpa,
        .{ .unix = "/run/user/1000/chock/daemon.sock" },
        error.NotListening,
    );
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "chock daemon") != null);
    try testing.expect(std.mem.indexOf(u8, said, "daemon.sock") != null);

    const remote = try unreachableText(
        gpa,
        .{ .ip = .{ .host = "10.0.0.4", .port = 7373 } },
        error.NotListening,
    );
    defer gpa.free(remote);
    try testing.expect(std.mem.indexOf(u8, remote, "10.0.0.4:7373") != null);
    // A remote daemon is not started by typing `chock daemon` here, so the
    // sentence must not say that.
    try testing.expect(std.mem.indexOf(u8, remote, "--host") != null);
}

test "a daemon of another control protocol number reaches the browser as words" {
    // **A frontend and a daemon are deployed apart**, which is the whole reason
    // this command is a client. So the two are the pair most likely to be built
    // at different times, and the browser has to be told which end to update
    // rather than shown an empty page or a stream that stopped.
    //
    // Mutation check: answer `respondDaemonFault` for a handshake that did not
    // agree, and a person reads `HandshakeFailed` where the two numbers should
    // be.
    const gpa = testing.allocator;

    const mismatch = try handshakeText(gpa, .{ .ip = .{ .host = "10.0.0.4", .port = 7373 } }, .{
        .mismatch = .{ .ours = 1, .theirs = 4 },
    });
    defer gpa.free(mismatch);
    try testing.expect(std.mem.indexOf(u8, mismatch, "10.0.0.4:7373") != null);
    try testing.expect(std.mem.indexOf(u8, mismatch, " 4 ") != null);
    try testing.expect(std.mem.indexOf(u8, mismatch, " 1") != null);

    // A daemon older than the greeting refuses in its own words, and they
    // travel whole rather than being replaced by a guess about why.
    const refused = try handshakeText(
        gpa,
        .{ .unix = "/run/user/1000/chock/daemon.sock" },
        .{ .refused = control.no_verb_text },
    );
    defer gpa.free(refused);
    try testing.expect(std.mem.indexOf(u8, refused, control.no_verb_text) != null);
    try testing.expect(std.mem.indexOf(u8, refused, "daemon.sock") != null);
}

test "the options parse, and a value that is not one is refused by name" {
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const plain = try parseOptions(&.{});
    try testing.expect(plain.daemon == null);
    try testing.expect(plain.project == null);
    try testing.expect(plain.socket == null);
    // **No host by default, so no TCP listener by default.** Mutation check:
    // give `host` a default of `127.0.0.1` and this fails, which is the hole
    // this file used to have.
    try testing.expect(plain.host == null);
    try testing.expectEqual(default_port, plain.port);
    // The default port is not the daemon's, so a person can run both.
    try testing.expect(default_port != control.default_port);

    const named = try parseOptions(&.{
        "--daemon",  "10.0.0.4:7373",
        "--project", "/home/ross/chock",
        "--socket",  "/run/chock/other.sock",
        "--host",    "0.0.0.0",
        "--port",    "8080",
    });
    try testing.expectEqualStrings("10.0.0.4:7373", named.daemon.?);
    try testing.expectEqualStrings("/home/ross/chock", named.project.?);
    try testing.expectEqualStrings("/run/chock/other.sock", named.socket.?);
    // **`--host` is allowed and unguarded.** Mutation check: refuse a host
    // that is not loopback and this fails.
    try testing.expectEqualStrings("0.0.0.0", named.host.?);
    try testing.expectEqual(@as(u16, 8080), named.port);
    try testing.expectEqualStrings("", said.err());

    for ([_][]const u8{ "--daemon", "--project", "--socket", "--host", "--port" }) |flag| {
        said.clear();
        try testing.expectError(error.BadArguments, parseOptions(&.{flag}));
        try testing.expect(std.mem.indexOf(u8, said.err(), flag) != null);
    }

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--host", "127.0.0.1", "--port", "seventy" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "seventy") != null);

    // **A `--port` with no `--host` names nothing**, so it is refused rather
    // than quietly ignored. Mutation check: accept it and a person believes
    // they opened a port that was never opened.
    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--port", "8080" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--host") != null);

    // And `0` is how a test asks the system for a free port, with `--host`.
    try testing.expectEqual(
        @as(u16, 0),
        (try parseOptions(&.{ "--host", "127.0.0.1", "--port", "0" })).port,
    );

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{"--nonsense"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--nonsense") != null);
    try testing.expectEqualStrings("", said.out());
}

test "a request whose body cannot be discarded gets an answer and not a panic" {
    // **The crash this found by being run.** `std.http.Server.respond` asserts,
    // inside `discardBody`, that a request whose method may carry a body said
    // how long that body is. A `POST` with neither a `content-length` nor a
    // `transfer-encoding` is legal, some clients send one, and it took the
    // whole process down. Anything that can reach `chock serve` could have
    // stopped it with one line of a request.
    //
    // Mutation check: return true unconditionally and this fails.
    try testing.expect(!mayKeepAlive(.POST, .none, null));
    try testing.expect(!mayKeepAlive(.PUT, .none, null));

    // A body that was declared is one the server can discard, so the
    // connection is still worth keeping.
    try testing.expect(mayKeepAlive(.POST, .none, 0));
    try testing.expect(mayKeepAlive(.POST, .none, 12));
    try testing.expect(mayKeepAlive(.POST, .chunked, null));

    // And a method that carries no body never reaches the assert at all, so
    // the ordinary page and listing keep their connection.
    try testing.expect(mayKeepAlive(.GET, .none, null));
    try testing.expect(mayKeepAlive(.HEAD, .none, null));
}

test "the page fetches nothing from anywhere else" {
    // **A machine with no route out has to show a working interface.** Chock
    // is a tool people run on those. A page that pulled a script or a font off
    // the internet would be broken there and nowhere a developer would notice.
    //
    // Mutation check: add a CDN link to the page and this fails.
    for ([_][]const u8{ "http://", "https://", "//cdn", "<script src", "<link " }) |outside| {
        try testing.expect(std.mem.indexOf(u8, page_html, outside) == null);
    }
    // And it really is a page, so the test above is not passing over nothing.
    try testing.expect(std.mem.indexOf(u8, page_html, "<!doctype html>") != null);
    try testing.expect(std.mem.indexOf(u8, page_html, "/api/sessions") != null);
    try testing.expect(std.mem.indexOf(u8, page_html, "/api/events") != null);
    try testing.expect(std.mem.indexOf(u8, page_html, "/api/answer") != null);
}
