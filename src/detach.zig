//! `chock detach`: hand a session to the daemon, which becomes its owner.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_broker = @import("chock-broker");
const chock_core = @import("chock-core");
const chock_proto = @import("chock-proto");

const session_paths = @import("session.zig");
const sessions_cmd = @import("sessions.zig");
const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const control = chock_proto.control;

pub const max_answer_bytes: usize = 8 * 1024;

const usage_text =
    \\Usage: chock detach [<session>] [options]
    \\
    \\Hands a session to the daemon, which becomes its owner and carries it on
    \\with no terminal. With no session, hands over the newest one of this project.
    \\
    \\The daemon has to be running already. Start one with `chock daemon`.
    \\
    \\A session that is still running is asked, and it answers at its next turn
    \\boundary, so this waits. A session running a background command or a
    \\background subagent says so and hands over once that work finishes,
    \\because neither of those moves to another process. Its workspace and its
    \\scratchpad do move.
    \\
    \\Options:
    \\  --project <dir>    The project. Defaults to the current directory.
    \\  --daemon <address> Where the daemon is. `unix:/path` or `host:port`.
    \\                     Default is the socket in the state directory, or
    \\                     $CHOCK_DAEMON when that is set.
    \\  --port <n>         A daemon on 127.0.0.1 at this port, which is the same
    \\                     as `--daemon 127.0.0.1:<n>`. Only a daemon started with
    \\                     --host listens on one.
    \\  --wait <seconds>   How long to wait for a running session to reach a turn
    \\                     boundary, and again for any background work it names.
    \\                     Default 300. A session that does not answer in time
    \\                     keeps running, unchanged.
    \\
++ tty.options_text;

pub const default_patience_ms: u64 = 300_000;

const Options = struct {
    project: ?[]const u8 = null,
    daemon: ?[]const u8 = null,
    port: ?u16 = null,
    session: []const u8 = "",
    patience_ms: u64 = default_patience_ms,
};

fn daemonAddress(
    arena: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    options: Options,
) std.mem.Allocator.Error!?control.Address {
    if (options.port) |port| {
        if (options.daemon != null) {
            tty.print(
                .err,
                "chock detach: --daemon and --port both name where the daemon is. Write one of " ++
                    "them.\n",
                .{},
            );
            return null;
        }
        return .{ .ip = .{ .host = control.default_host, .port = port } };
    }

    const text = options.daemon orelse env.get(control.address_env) orelse {
        const state = chock_auth.paths.stateDir(arena, env) catch |err| {
            tty.print(.err, "chock detach: the state directory could not be found: {t}\n", .{err});
            return null;
        };
        const path = try control.socketPathIn(arena, state);
        return .{ .unix = path };
    };

    return control.Address.parse(text) catch |err| {
        tty.print(
            .err,
            "chock detach: \"{s}\" is not a daemon address ({t}). Write `unix:/path` or " ++
                "`host:port`.\n",
            .{ text, err },
        );
        return null;
    };
}

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = exe_path;

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    var env = try environ.createMap(arena);
    defer env.deinit();

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        else => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    const daemon = try daemonAddress(arena, &env, options) orelse return Exit.usage.code();

    const project_root = resolveProject(arena, io, options.project) catch {
        tty.print(.err, "chock detach: the project directory could not be read.\n", .{});
        return Exit.usage.code();
    };

    const id = try chooseSession(arena, io, &env, project_root, options) orelse return Exit.usage.code();

    var paths = session_paths.pathsFor(arena, &env, project_root, id) catch |err| {
        tty.print(.err, "chock detach: the session path could not be built: {t}\n", .{err});
        return Exit.usage.code();
    };
    defer paths.deinit();

    var stopped_for_this = false;

    switch (sessions_cmd.readinessOf(gpa, io, paths.log, id)) {
        .running => {
            if (!reportMovableWorkspace(gpa, io, paths.log, id)) return Exit.usage.code();
            if (!reportDaemonListening(io, daemon, id)) return Exit.usage.code();
            switch (askRunningSession(arena, io, paths.dir, id, options.patience_ms)) {
                .handed_over => stopped_for_this = true,
                .ended => {
                    if (!reportReadiness(gpa, io, paths.log, id)) return Exit.usage.code();
                    if (!endedHandedOver(gpa, io, paths.log)) {
                        if (!reportKeptWorkspace(gpa, io, paths.work, id)) return Exit.usage.code();
                    }
                },
                else => return Exit.usage.code(),
            }
        },
        else => {
            if (!reportReadiness(gpa, io, paths.log, id)) return Exit.usage.code();
            if (!endedHandedOver(gpa, io, paths.log)) {
                if (!reportKeptWorkspace(gpa, io, paths.work, id)) return Exit.usage.code();
            }
        },
    }

    var socket_paths = chock_broker.socket.pathsFor(arena, paths.dir, id) catch |err| {
        tty.print(.err, "chock detach: the approval socket path could not be built: {t}\n", .{err});
        return Exit.usage.code();
    };
    defer socket_paths.deinit();

    return handOver(
        io,
        project_root,
        id,
        daemon,
        answerableAt(socket_paths.socket),
        stopped_for_this,
    );
}

fn reportDaemonListening(io: std.Io, address: control.Address, id: []const u8) bool {
    const stream = address.connect(io) catch |err| {
        if (err != error.NotListening) {
            tty.print(
                .err,
                "chock detach: the daemon at {f} could not be reached ({t}), so session {s} was " ++
                    "not handed over and it was not asked to stop. It is still running.\n",
                .{ address, err, id },
            );
            return false;
        }
        tty.print(
            .err,
            "chock detach: nothing is listening on {f} ({t}), so there is no daemon to hand " ++
                "session {s} to, and it was not asked to stop. It is still running. Start a " ++
                "daemon with `chock daemon`, and then run this again.\n",
            .{ address, err, id },
        );
        return false;
    };
    stream.close(io);
    return true;
}

// A unix socket path is bounded at 103 bytes on Darwin and 107 on Linux, found by hand: a deep home directory can exceed it.
fn answerableAt(socket_path: []const u8) bool {
    _ = chock_proto.control.unixAddress(socket_path) catch return false;
    return true;
}

const max_socket_path: usize = chock_proto.control.max_socket_path;

fn chooseSession(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    options: Options,
) std.mem.Allocator.Error!?[]const u8 {
    if (options.session.len != 0) {
        if (!session_paths.isValidId(options.session)) {
            tty.print(.err, "chock detach: {s} is not a session identifier.\n", .{options.session});
            return null;
        }
        return options.session;
    }
    const newest = session_paths.newestId(arena, io, env, project_root) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            tty.print(.err, "chock detach: the newest session could not be found: {t}\n", .{err});
            return null;
        },
    } orelse {
        tty.print(.err, "chock detach: this project has no session to hand over.\n", .{});
        return null;
    };
    return try arena.dupe(u8, &newest);
}

fn endedHandedOver(gpa: std.mem.Allocator, io: std.Io, log_path: [:0]const u8) bool {
    _ = std.Io.Dir.cwd().statFile(io, log_path, .{}) catch return false;
    const log = chock_proto.log.Log.open(io, log_path, "") catch return false;
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    var replay = store.replay(gpa, io, 0) catch return false;
    defer replay.deinit();

    var handed_over = false;
    while (replay.next(io) catch null) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .session_end) continue;
        handed_over = parsed.value.event.session_end.reason == .handed_over;
    }
    return handed_over;
}

fn reportMovableWorkspace(
    gpa: std.mem.Allocator,
    io: std.Io,
    log_path: [:0]const u8,
    id: []const u8,
) bool {
    const log = chock_proto.log.Log.open(io, log_path, "") catch return true;
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    var replay = store.replay(gpa, io, 0) catch return true;
    defer replay.deinit();

    var kind: ?std.meta.Tag(chock_proto.event.WorkspaceKind) = null;
    while (replay.next(io) catch null) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .workspace_open) continue;
        kind = std.meta.activeTag(parsed.value.event.workspace_open.kind);
    }

    const found = kind orelse return true;
    if (found == .worktree) return true;
    tty.print(
        .err,
        "chock detach: session {s} works in a {s} workspace, and only a git worktree moves to " ++
            "another process yet. Stop it with Ctrl-C first. Its work stays where it is, and " ++
            "`chock workspace adopt {s}` copies that work into the project.\n",
        .{ id, @tagName(found), id },
    );
    return false;
}

const Asked = enum {
    handed_over,
    not_listening,
    silent,
    ended,
    refused,
    unreadable,
    uncertain,
    still_holding,
};

fn askRunningSession(
    arena: std.mem.Allocator,
    io: std.Io,
    session_dir: []const u8,
    id: []const u8,
    patience_ms: u64,
) Asked {
    var paths = chock_broker.handover.pathsFor(arena, session_dir, id) catch {
        tty.print(.err, "chock detach: the handover socket path could not be built.\n", .{});
        return .not_listening;
    };
    defer paths.deinit();

    const address = chock_proto.control.unixAddress(paths.socket) catch {
        tty.print(
            .err,
            "chock detach: session {s} is running, and its session directory makes a handover " ++
                "socket path longer than a unix socket allows, so it opened none. Stop it with " ++
                "Ctrl-C and run this again, or give Chock a shorter state directory.\n",
            .{id},
        );
        return .not_listening;
    };
    const stream = address.connect(io) catch {
        tty.print(
            .err,
            "chock detach: session {s} is running and is not listening for a handover, so it " ++
                "cannot be taken from the process that owns it. Stop it first with Ctrl-C, which " ++
                "writes the session end, and then run this again.\n",
            .{id},
        );
        return .not_listening;
    };
    defer stream.close(io);

    var answers: [chock_broker.handover.max_frame_bytes]u8 = undefined;
    var client = chock_broker.handover.Client.over(stream.socket.handle, &answers);
    if (!client.sendAsk()) {
        tty.print(.err, "chock detach: session {s} closed the connection before it was asked.\n", .{id});
        return .not_listening;
    }

    tty.detail(
        "chock detach: waiting for session {s} to reach a turn boundary.\n",
        .{id},
    );

    var named_work = false;
    for (0..2) |attempt| {
        switch (client.readOffer(patience_ms)) {
            .offered => break,
            .waiting => |said| {
                if (attempt != 0) {
                    tty.print(
                        .err,
                        "chock detach: session {s} said twice what it is waiting for, which this " ++
                            "build cannot read, so it was not handed over.\n",
                        .{id},
                    );
                    return .unreadable;
                }
                named_work = true;
                tty.detail(
                    "chock detach: session {s} is not ready yet: {s}\n",
                    .{ id, said },
                );
                continue;
            },
            .busy => |said| {
                tty.print(
                    .err,
                    "chock detach: session {s} will not hand over: {s}\n",
                    .{ id, said },
                );
                return .refused;
            },
            .silent => {
                tty.print(
                    .err,
                    "chock detach: session {s} {s}\n",
                    .{ id, silentNote(named_work) },
                );
                return .silent;
            },
            .ended => {
                tty.detail(
                    "chock detach: session {s} ended on its own while this waited, so it is " ++
                        "handed over the way a stopped session always was.\n",
                    .{id},
                );
                return .ended;
            },
            .unreadable => |said| {
                tty.print(
                    .err,
                    "chock detach: session {s} answered something this build cannot read ({s}), " ++
                        "so it was not handed over.\n",
                    .{ id, said },
                );
                return .unreadable;
            },
        }
    }

    if (!client.sendTake()) {
        tty.print(
            .err,
            "chock detach: session {s} closed the connection before it was told to hand over, so " ++
                "it is still running.\n",
            .{id},
        );
        return .uncertain;
    }
    switch (client.readFinal(patience_ms)) {
        .handed_over => {},
        else => {
            tty.print(
                .err,
                "chock detach: session {s} did not confirm that it is stopping, so whether it is " ++
                    "still running is unknown. `chock sessions` says which sessions are running.\n",
                .{id},
            );
            return .uncertain;
        },
    }

    // The session closes this socket only after Loop.run releases the log's exclusive lock, so a closed stream proves the lock is free.
    if (!client.waitForEnd(patience_ms)) {
        tty.print(
            .err,
            "chock detach: session {s} agreed to hand over and has not let go yet. It is writing " ++
                "its session end. Run this again in a moment; `chock sessions` says which " ++
                "sessions are running.\n",
            .{id},
        );
        return .still_holding;
    }
    return .handed_over;
}

fn silentNote(named_work: bool) []const u8 {
    if (named_work) {
        return "still holds the background work it named, so it was not handed over and it is " ++
            "still running normally. It hands over on its own at the first turn boundary after " ++
            "that work finishes: give it longer with --wait <seconds>. Ctrl-C on the session " ++
            "stops that work rather than waiting for it.";
    }
    return "did not reach a turn boundary in time, so it was not handed over and it is still " ++
        "running normally. Give it longer with --wait <seconds>, or stop it with Ctrl-C.";
}

fn reportReadiness(gpa: std.mem.Allocator, io: std.Io, log_path: [:0]const u8, id: []const u8) bool {
    switch (sessions_cmd.readinessOf(gpa, io, log_path, id)) {
        .ready => return true,
        .no_such_session => tty.print(
            .err,
            "chock detach: this project has no session {s}. `chock sessions` lists the ones it " ++
                "does have.\n",
            .{id},
        ),
        .nothing_to_carry_on => tty.print(
            .err,
            "chock detach: session {s} holds no conversation to carry on from, so there is " ++
                "nothing for the daemon to take over.\n",
            .{id},
        ),
        // Reached only when a session took the lock back after it was asked: `main` sends a running session to askRunningSession instead.
        .running => tty.print(
            .err,
            "chock detach: session {s} is running now, and a session is not taken from the " ++
                "process that owns it. Another process took it between this one asking and the " ++
                "daemon being told. `chock sessions` says which sessions are running.\n",
            .{id},
        ),
        .unknown => tty.print(
            .err,
            "chock detach: session {s} could not be read, or its lock could not be tested, so " ++
                "it was not handed over.\n",
            .{id},
        ),
    }
    return false;
}

fn reportKeptWorkspace(gpa: std.mem.Allocator, io: std.Io, work_path: []const u8, id: []const u8) bool {
    const size = chock_core.cache.measure(gpa, io, work_path, std.math.maxInt(u64));
    if (size.files == 0) return true;
    tty.print(
        .err,
        "chock detach: session {s} left a workspace at {s}, which still holds work: {d} files, " ++
            "{d} bytes. A session the daemon adopts builds a new workspace from the project's " ++
            "committed state, the same way `chock run --continue` does, so that work would be " ++
            "left where it is. Take what you want out of it first. `chock workspace` lists it " ++
            "and removes it.\n",
        .{ id, work_path, size.files, size.bytes },
    );
    return false;
}

fn handOver(
    io: std.Io,
    project_root: []const u8,
    id: []const u8,
    address: control.Address,
    answerable: bool,
    stopped_for_this: bool,
) anyerror!u8 {
    const note = stoppedNote(stopped_for_this);

    const stream = address.connect(io) catch |err| {
        if (err != error.NotListening) {
            tty.print(
                .err,
                "chock detach: the daemon at {f} could not be reached ({t}), so session {s} was " ++
                    "not handed over.{s}\n",
                .{ address, err, id, note },
            );
            return Exit.usage.code();
        }
        tty.print(
            .err,
            "chock detach: nothing is listening on {f} ({t}), so there is no daemon to hand " ++
                "session {s} to. Start one with `chock daemon`, and then run this again.{s}\n",
            .{ address, err, id, note },
        );
        return Exit.usage.code();
    };
    defer stream.close(io);

    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buffer);
    const writer = &stream_writer.interface;

    var read_buffer: [max_answer_bytes]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buffer);
    const reader = &stream_reader.interface;

    const agreement = control.handshake(reader, writer, control.protocol_version) catch {
        tty.print(
            .err,
            "chock detach: the daemon closed the connection before it was asked.{s}\n",
            .{note},
        );
        return Exit.faulted.code();
    };
    if (!agreement.ok()) {
        reportHandshake(address, agreement, id, note);
        return Exit.usage.code();
    }

    (control.Request{ .adopt = .{ .project = project_root, .session = id } }).write(writer) catch {
        tty.print(
            .err,
            "chock detach: the daemon closed the connection before it was asked.{s}\n",
            .{note},
        );
        return Exit.faulted.code();
    };
    writer.flush() catch {
        tty.print(
            .err,
            "chock detach: the daemon closed the connection before it was asked.{s}\n",
            .{note},
        );
        return Exit.faulted.code();
    };

    const line = (reader.takeDelimiter('\n') catch null) orelse {
        tty.print(
            .err,
            "chock detach: the daemon said nothing about session {s}.{s}\n",
            .{ id, note },
        );
        return Exit.faulted.code();
    };

    return report(line, id, answerable, note);
}

fn reportHandshake(
    address: control.Address,
    said: control.Handshake,
    id: []const u8,
    note: []const u8,
) void {
    var buffer: [max_answer_bytes]u8 = undefined;
    var text = std.Io.Writer.fixed(&buffer);
    control.handshakeRefusal(&text, address, said) catch {};
    tty.print(
        .err,
        "chock detach: session {s} was not handed over.{s} {s}\n",
        .{ id, note, std.mem.trimEnd(u8, text.buffered(), "\n") },
    );
}

fn stoppedNote(stopped_for_this: bool) []const u8 {
    if (!stopped_for_this) return "";
    return " Session already stopped at a turn boundary for this handover, so nothing owns it " ++
        "now. Its work is safe: the log is whole and the workspace is on disk. " ++
        "`chock run --continue` in this project takes it back, and so does another " ++
        "`chock detach` once a daemon is running.";
}

fn report(line: []const u8, id: []const u8, answerable: bool, note: []const u8) u8 {
    const answer = std.mem.trimEnd(u8, line, "\r");
    if (std.mem.startsWith(u8, answer, "ok ")) {
        const rest = answer["ok ".len..];
        const tab = std.mem.indexOfScalar(u8, rest, '\t');
        const log_path = if (tab) |at| rest[at + 1 ..] else "";
        tty.out(.plain, "chock detach: the daemon owns session {s} now.\n", .{id});
        if (log_path.len != 0) tty.detail("chock detach: log {s}\n", .{log_path});
        if (answerable) {
            tty.out(
                .plain,
                "chock detach: answer its questions with `chock approve {s}`, on this machine.\n",
                .{id},
            );
        } else {
            tty.print(
                .warn,
                "chock detach: nobody can answer session {s}. Its session directory makes an " ++
                    "approval socket path longer than a unix socket allows, so it opens none, and " ++
                    "every question it asks is refused. Give Chock a shorter state directory to " ++
                    "change that.\n",
                .{id},
            );
        }
        return Exit.finished.code();
    }
    if (std.mem.startsWith(u8, answer, "error ")) {
        tty.print(
            .err,
            "chock detach: the daemon would not take session {s}: {s}{s}\n",
            .{ id, answer["error ".len..], note },
        );
        return Exit.usage.code();
    }
    tty.print(
        .err,
        "chock detach: the daemon answered something this build cannot read, so whether it " ++
            "took session {s} is unknown. `chock sessions` says which sessions are running.{s}\n",
        .{ id, note },
    );
    return Exit.faulted.code();
}

fn resolveProject(arena: std.mem.Allocator, io: std.Io, given: ?[]const u8) ![]const u8 {
    if (given) |path| {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return arena.dupe(u8, path);
        defer dir.close(io);
        const len = dir.realPath(io, &buffer) catch return arena.dupe(u8, path);
        return arena.dupe(u8, buffer[0..len]);
    }
    return std.process.currentPathAlloc(io, arena);
}

const ParseError = error{ HelpWanted, BadArguments };

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;
        if (std.mem.eql(u8, argument, "--project")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.project = args[index];
            continue;
        }
        if (std.mem.eql(u8, argument, "--daemon")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.daemon = args[index];
            continue;
        }
        if (std.mem.eql(u8, argument, "--port")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.port = std.fmt.parseInt(u16, args[index], 10) catch return error.BadArguments;
            continue;
        }
        if (std.mem.eql(u8, argument, "--wait")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            const seconds = std.fmt.parseInt(u32, args[index], 10) catch return error.BadArguments;
            options.patience_ms = @as(u64, seconds) * 1000;
            continue;
        }
        if (std.mem.startsWith(u8, argument, "-")) return error.BadArguments;
        if (options.session.len != 0) return error.BadArguments;
        options.session = argument;
    }
    return options;
}

const testing = std.testing;

const ShortTmp = struct {
    dir: std.Io.Dir,
    parent_dir: std.Io.Dir,
    sub_path: [sub_path_len]u8,
    whole: [std.fs.max_path_bytes]u8,
    whole_len: usize,

    const random_bytes_count = 12;
    const sub_path_len = std.base64.url_safe.Encoder.calcSize(random_bytes_count);

    fn path(self: *const ShortTmp) []const u8 {
        return self.whole[0..self.whole_len];
    }

    fn open(io: std.Io) !ShortTmp {
        const root = root: {
            const given = std.process.Environ.getPosix(testing.environ, "TMPDIR") orelse "/tmp";
            const trimmed = std.mem.trimEnd(u8, given, "/");
            break :root if (trimmed.len == 0) "/" else trimmed;
        };

        var self: ShortTmp = undefined;
        var random_bytes: [random_bytes_count]u8 = undefined;
        io.random(&random_bytes);
        _ = std.base64.url_safe.Encoder.encode(&self.sub_path, &random_bytes);

        const whole = std.fmt.bufPrint(&self.whole, "{s}/{s}", .{ root, &self.sub_path }) catch
            return error.SkipZigTest;
        self.whole_len = whole.len;

        var probe: [std.fs.max_path_bytes]u8 = undefined;
        const longest = std.fmt.bufPrint(
            &probe,
            "{s}/{s}" ++ chock_broker.socket.dir_suffix ++ "/" ++ chock_broker.handover.socket_name,
            .{ whole, "0" ** 26 },
        ) catch return error.SkipZigTest;
        if (!answerableAt(longest)) return error.SkipZigTest;

        self.parent_dir = try std.Io.Dir.cwd().openDir(io, root, .{});
        errdefer self.parent_dir.close(io);
        self.dir = try self.parent_dir.createDirPathOpen(io, &self.sub_path, .{});
        return self;
    }

    fn cleanup(self: *ShortTmp, io: std.Io) void {
        self.dir.close(io);
        self.parent_dir.deleteTree(io, &self.sub_path) catch {};
        self.parent_dir.close(io);
        self.* = undefined;
    }
};

test "a running session that will not answer is refused, and it keeps running normally" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = try ShortTmp.open(io);
    defer tmp.cleanup(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const session_dir = tmp.path();
    const id = "01JQ" ++ "R" ** 22;

    const paths = try chock_broker.handover.pathsFor(arena, session_dir, id);
    var endpoint = try chock_broker.handover.Endpoint.open(io, paths, null);
    defer endpoint.close(io);

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    try testing.expectEqual(Asked.silent, askRunningSession(arena, io, session_dir, id, 0));
    try testing.expect(std.mem.indexOf(u8, said.err(), id) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "still running") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "--wait") != null);
    try testing.expectEqualStrings("", said.out());

    try testing.expectEqual(
        chock_broker.handover.Decision.carry_on,
        endpoint.look(io, .{}, 0),
    );

    const address = try chock_proto.control.unixAddress(paths.socket);
    const patient = try address.connect(io);
    defer patient.close(io);
    var answers: [chock_broker.handover.max_frame_bytes]u8 = undefined;
    var client = chock_broker.handover.Client.over(patient.socket.handle, &answers);
    try testing.expectEqual(chock_broker.handover.Decision.carry_on, endpoint.look(io, .{}, 0));
    try testing.expect(client.sendAsk());
}

test "a workspace that does not move yet is refused before the session is ever asked" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const dir = dir_buffer[0..dir_len];
    const id = "01JQ" ++ "W" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}.jsonl", .{ dir, id }, 0);
    defer gpa.free(log_path);

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    const kinds = [_]chock_proto.event.WorkspaceKind{ .worktree, .overlay };
    for (kinds) |kind| {
        said.clear();
        tmp.dir.deleteFile(io, id ++ ".jsonl") catch {};
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        var locked = try store.lock(io);
        _ = try locked.append(gpa, io, .{ .workspace_open = .{
            .kind = kind,
            .attempt = "01JQ" ++ "B" ** 22,
            .path = "/state/somewhere",
            .base_commit = "a1b2c3",
        } }, 1);
        try locked.unlock(io);
        store.close(io);

        try testing.expectEqual(
            kind == .worktree,
            reportMovableWorkspace(gpa, io, log_path, id),
        );
        if (kind == .worktree) {
            try testing.expectEqualStrings("", said.err());
        } else {
            try testing.expect(std.mem.indexOf(u8, said.err(), "overlay") != null);
            try testing.expect(std.mem.indexOf(u8, said.err(), "Ctrl-C") != null);
            try testing.expect(std.mem.indexOf(u8, said.err(), "chock workspace adopt") != null);
            try testing.expect(std.mem.indexOf(u8, said.err(), id) != null);
        }
        try testing.expectEqualStrings("", said.out());
    }

    tmp.dir.deleteFile(io, id ++ ".jsonl") catch {};
    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        const content = [_]chock_proto.event.ContentPart{.{ .text = "carry this on" }};
        _ = try locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);
        try locked.unlock(io);
    }
    try testing.expect(reportMovableWorkspace(gpa, io, log_path, id));
}

test "a running session with no handover socket is refused, and not waited on" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = try ShortTmp.open(io);
    defer tmp.cleanup(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    try testing.expectEqual(
        Asked.not_listening,
        askRunningSession(arena, io, tmp.path(), "01JQ" ++ "N" ** 22, 0),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "is running") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "not listening") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "Ctrl-C") != null);
    try testing.expectEqualStrings("", said.out());
}

test "a live handover moves the lock, and never lets two processes hold it at once" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = try ShortTmp.open(io);
    defer tmp.cleanup(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const session_dir = tmp.path();
    const id = "01JQ" ++ "K" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ session_dir, id }, 0);

    const first_log = try chock_proto.log.Log.open(io, log_path, id);
    var first_backing = chock_proto.storage.JsonLines{ .log = first_log };
    const first_store = first_backing.storage();
    var first_locked = try first_store.lock(io);
    const content = [_]chock_proto.event.ContentPart{.{ .text = "carry this on" }};
    _ = try first_locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);

    const paths = try chock_broker.handover.pathsFor(arena, session_dir, id);
    var endpoint = try chock_broker.handover.Endpoint.open(io, paths, null);

    try testing.expectEqual(sessions_cmd.Readiness.running, sessions_cmd.readinessOf(gpa, io, log_path, id));

    const address = try chock_proto.control.unixAddress(paths.socket);
    const stream = try address.connect(io);
    defer stream.close(io);
    var answers: [chock_broker.handover.max_frame_bytes]u8 = undefined;
    var client = chock_broker.handover.Client.over(stream.socket.handle, &answers);

    try testing.expect(client.sendAsk());
    try testing.expectEqual(chock_broker.handover.Decision.carry_on, endpoint.look(io, .{}, 0));
    try testing.expectEqual(chock_broker.handover.Offer.offered, client.readOffer(0));
    try testing.expect(client.sendTake());
    try testing.expectEqual(chock_broker.handover.Decision.hand_over, endpoint.look(io, .{}, 0));
    try testing.expectEqual(chock_broker.handover.Answer.handed_over, client.readFinal(0));

    try testing.expectEqual(sessions_cmd.Readiness.running, sessions_cmd.readinessOf(gpa, io, log_path, id));
    try testing.expect(!client.waitForEnd(0));

    _ = try first_locked.append(gpa, io, .{ .session_end = .{
        .reason = .handed_over,
        .detail = "",
    } }, 2);
    try first_locked.unlock(io);
    endpoint.close(io);
    first_store.close(io);

    try testing.expect(client.waitForEnd(0));
    try testing.expectEqual(sessions_cmd.Readiness.ready, sessions_cmd.readinessOf(gpa, io, log_path, id));

    const second_log = try chock_proto.log.Log.open(io, log_path, id);
    var second_backing = chock_proto.storage.JsonLines{ .log = second_log };
    const second_store = second_backing.storage();
    defer second_store.close(io);
    var second_locked = try second_store.lock(io);
    defer second_locked.unlock(io) catch {};

    {
        const third_log = try chock_proto.log.Log.open(io, log_path, id);
        var third_backing = chock_proto.storage.JsonLines{ .log = third_log };
        const third_store = third_backing.storage();
        defer third_store.close(io);
        try testing.expectError(error.Busy, third_store.lock(io));
    }

    var folded = chock_proto.state.Session.init(gpa);
    defer folded.deinit();
    var replay = try second_store.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try folded.apply(parsed.value);
    }
    try testing.expectEqual(
        chock_proto.event.SessionEndReason.handed_over,
        std.meta.activeTag(folded.end_reason),
    );
}

test "a live handover waits for background work, and moves the lock only after it" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = try ShortTmp.open(io);
    defer tmp.cleanup(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const session_dir = tmp.path();
    const id = "01JQ" ++ "W" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ session_dir, id }, 0);

    const first_log = try chock_proto.log.Log.open(io, log_path, id);
    var first_backing = chock_proto.storage.JsonLines{ .log = first_log };
    const first_store = first_backing.storage();
    var first_locked = try first_store.lock(io);
    const content = [_]chock_proto.event.ContentPart{.{ .text = "build it" }};
    _ = try first_locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);

    const paths = try chock_broker.handover.pathsFor(arena, session_dir, id);
    var endpoint = try chock_broker.handover.Endpoint.open(io, paths, null);

    const address = try chock_proto.control.unixAddress(paths.socket);
    const stream = try address.connect(io);
    defer stream.close(io);
    var answers: [chock_broker.handover.max_frame_bytes]u8 = undefined;
    var client = chock_broker.handover.Client.over(stream.socket.handle, &answers);

    try testing.expect(client.sendAsk());
    try testing.expect(client.sendTake());

    const running = chock_broker.handover.InFlight{ .tasks = 1 };
    try testing.expectEqual(
        chock_broker.handover.Decision.carry_on,
        endpoint.look(io, running, 0),
    );
    const offer = client.readOffer(0);
    try testing.expect(offer == .waiting);
    try testing.expect(std.mem.indexOf(u8, offer.waiting, "background command") != null);

    try testing.expectEqual(
        chock_broker.handover.Decision.carry_on,
        endpoint.look(io, running, 0),
    );
    try testing.expectEqual(sessions_cmd.Readiness.running, sessions_cmd.readinessOf(gpa, io, log_path, id));
    try testing.expect(!client.waitForEnd(0));

    try testing.expectEqual(chock_broker.handover.Decision.hand_over, endpoint.look(io, .{}, 0));
    try testing.expectEqual(chock_broker.handover.Offer.offered, client.readOffer(0));
    try testing.expectEqual(chock_broker.handover.Answer.handed_over, client.readFinal(0));

    _ = try first_locked.append(gpa, io, .{ .session_end = .{
        .reason = .handed_over,
        .detail = "",
    } }, 2);
    try first_locked.unlock(io);
    endpoint.close(io);
    first_store.close(io);

    try testing.expect(client.waitForEnd(0));
    try testing.expectEqual(sessions_cmd.Readiness.ready, sessions_cmd.readinessOf(gpa, io, log_path, id));
}

test "the bound on a wait says what to do, and it is not the same advice twice" {
    const holding = silentNote(true);
    const quiet = silentNote(false);

    try testing.expect(std.mem.indexOf(u8, holding, "not handed over") != null);
    try testing.expect(std.mem.indexOf(u8, quiet, "not handed over") != null);
    try testing.expect(std.mem.indexOf(u8, holding, "still running") != null);
    try testing.expect(std.mem.indexOf(u8, quiet, "still running") != null);

    try testing.expect(std.mem.indexOf(u8, holding, "--wait") != null);
    try testing.expect(std.mem.indexOf(u8, quiet, "--wait") != null);

    try testing.expect(std.mem.indexOf(u8, holding, "background work") != null);
    try testing.expect(std.mem.indexOf(u8, holding, "on its own") != null);
    try testing.expect(std.mem.indexOf(u8, holding, "stops that work") != null);
    try testing.expect(std.mem.indexOf(u8, quiet, "turn boundary") != null);

    try testing.expect(!std.mem.eql(u8, holding, quiet));
}

test "the two control sockets share a directory and never share a descriptor" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = try ShortTmp.open(io);
    defer tmp.cleanup(io);

    const session_dir = tmp.path();
    const id = "01JQ" ++ "S" ** 22;

    var approval_paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
    defer approval_paths.deinit();
    var handover_paths = try chock_broker.handover.pathsFor(gpa, session_dir, id);
    defer handover_paths.deinit();

    const expected_dir = try std.fmt.allocPrint(gpa, "{s}/{s}.ctl", .{ session_dir, id });
    defer gpa.free(expected_dir);
    try testing.expectEqualStrings(expected_dir, approval_paths.dir);
    try testing.expectEqualStrings(expected_dir, handover_paths.dir);
    try testing.expect(!std.mem.eql(u8, approval_paths.socket, handover_paths.socket));

    var approvals = try chock_broker.socket.Endpoint.open(io, approval_paths, null);
    defer approvals.close(io);
    var handovers = try chock_broker.handover.Endpoint.open(io, handover_paths, null);
    defer handovers.close(io);

    const approval_address = try chock_proto.control.unixAddress(approval_paths.socket);
    const answering = try approval_address.connect(io);
    defer answering.close(io);
    const handover_address = try chock_proto.control.unixAddress(handover_paths.socket);
    const asking = try handover_address.connect(io);
    defer asking.close(io);

    approvals.acceptPending(io);
    try testing.expectEqual(@as(usize, 1), approvals.attached());
    try testing.expectEqual(chock_broker.handover.Decision.carry_on, handovers.look(io, .{}, 0));
    try testing.expect(handovers.asking());
    try testing.expectEqual(@as(usize, 0), handovers.refused);
    try testing.expectEqual(@as(usize, 0), approvals.refused);
}

test "a session handed over is answered by chock approve at the path it already knew" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = try ShortTmp.open(io);
    defer tmp.cleanup(io);

    const session_dir = tmp.path();
    const id = "01JQ" ++ "T" ** 22;

    var client_paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
    defer client_paths.deinit();
    const address = try chock_proto.control.unixAddress(client_paths.socket);

    {
        var approval_paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
        defer approval_paths.deinit();
        var handover_paths = try chock_broker.handover.pathsFor(gpa, session_dir, id);
        defer handover_paths.deinit();
        var approvals = try chock_broker.socket.Endpoint.open(io, approval_paths, null);
        var handovers = try chock_broker.handover.Endpoint.open(io, handover_paths, null);

        const before = try address.connect(io);
        before.close(io);
        approvals.close(io);
        handovers.close(io);
    }

    var approval_paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
    defer approval_paths.deinit();
    var approvals = try chock_broker.socket.Endpoint.open(io, approval_paths, null);
    defer approvals.close(io);

    const after = try address.connect(io);
    after.close(io);
}

test "the command line names one session at most, and no address unless one is typed" {
    try testing.expect((try parseOptions(&.{})).port == null);
    try testing.expect((try parseOptions(&.{})).daemon == null);
    try testing.expectEqualStrings("", (try parseOptions(&.{})).session);
    try testing.expectEqualStrings("01ABC", (try parseOptions(&.{"01ABC"})).session);
    try testing.expectEqual(@as(u16, 9191), (try parseOptions(&.{ "--port", "9191" })).port.?);
    try testing.expectEqualStrings(
        "unix:/run/chock/d.sock",
        (try parseOptions(&.{ "--daemon", "unix:/run/chock/d.sock" })).daemon.?,
    );
    try testing.expectError(error.BadArguments, parseOptions(&.{"--daemon"}));
    try testing.expectEqual(default_patience_ms, (try parseOptions(&.{})).patience_ms);
    try testing.expectEqual(@as(u64, 90_000), (try parseOptions(&.{ "--wait", "90" })).patience_ms);
    try testing.expectEqual(@as(u64, 0), (try parseOptions(&.{ "--wait", "0" })).patience_ms);
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--wait", "a while" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--wait"}));
    try testing.expectEqualStrings("/tmp/p", (try parseOptions(&.{ "--project", "/tmp/p" })).project.?);
    try testing.expectError(error.BadArguments, parseOptions(&.{ "01ABC", "01DEF" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--port", "seventy" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--port"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--nope"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}

test "a session that handed over is not refused for the workspace its handover kept" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const dir = dir_buffer[0..dir_len];
    const id = "01JQ" ++ "V" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}.jsonl", .{ dir, id }, 0);
    defer gpa.free(log_path);

    const endings = [_]chock_proto.event.SessionEndReason{ .handed_over, .errored, .finished };
    for (endings) |ending| {
        tmp.dir.deleteFile(io, id ++ ".jsonl") catch {};
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        var locked = try store.lock(io);
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = ending, .detail = "" } }, 1);
        try locked.unlock(io);
        store.close(io);

        try testing.expectEqual(ending == .handed_over, endedHandedOver(gpa, io, log_path));
    }

    tmp.dir.deleteFile(io, id ++ ".jsonl") catch {};
    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = .handed_over, .detail = "" } }, 1);
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = .errored, .detail = "" } }, 2);
        try locked.unlock(io);
    }
    try testing.expect(!endedHandedOver(gpa, io, log_path));

    tmp.dir.deleteFile(io, id ++ ".jsonl") catch {};
    try testing.expect(!endedHandedOver(gpa, io, log_path));
}

test "no daemon is found before a running session is asked, and not after" {
    const gpa = testing.allocator;
    const io = testing.io;
    const id = "01JQ" ++ "A" ** 22;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const socket_path = try std.fmt.allocPrint(gpa, "{s}/d.sock", .{dir_buffer[0..dir_len]});
    defer gpa.free(socket_path);

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    try testing.expect(!reportDaemonListening(io, .{ .unix = socket_path }, id));
    try testing.expect(std.mem.indexOf(u8, said.err(), "was not asked to stop") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "still running") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "chock daemon") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), socket_path) != null);
    try testing.expectEqualStrings("", said.out());

    said.clear();
    var listener = try (control.Address{ .unix = socket_path }).listen(io);
    defer listener.close(io);
    try testing.expect(reportDaemonListening(io, .{ .unix = socket_path }, id));
    try testing.expectEqualStrings("", said.err());

    said.clear();
    const on_loopback = control.Address{ .ip = .{ .host = control.default_host, .port = 0 } };
    var tcp = try on_loopback.listen(io);
    defer tcp.close(io);
    try testing.expect(reportDaemonListening(io, .{ .ip = .{
        .host = control.default_host,
        .port = tcp.server.socket.address.getPort(),
    } }, id));
    try testing.expectEqualStrings("", said.err());

    said.clear();
    const shut = try std.fmt.allocPrint(gpa, "{s}/shut", .{dir_buffer[0..dir_len]});
    defer gpa.free(shut);
    try tmp.dir.createDir(io, "shut", .default_dir);
    const inside = try std.fmt.allocPrint(gpa, "{s}/d.sock", .{shut});
    defer gpa.free(inside);
    {
        var shut_listener = try (control.Address{ .unix = inside }).listen(io);
        defer shut_listener.close(io);
        try tmp.dir.setFilePermissions(io, "shut", .fromMode(0o000), .{});
        defer tmp.dir.setFilePermissions(io, "shut", .fromMode(0o700), .{}) catch {};

        try testing.expect(!reportDaemonListening(io, .{ .unix = inside }, id));
        try testing.expect(std.mem.indexOf(u8, said.err(), "could not be reached") != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "still running") != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "chock daemon`") == null);
    }
}

test "the daemon a person did not name is the socket in the state directory" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", "/home/somebody");

    {
        const found = (try daemonAddress(arena, &env, .{})).?;
        try testing.expect(found == .unix);
        try testing.expect(std.mem.endsWith(u8, found.unix, control.socket_name));
        try testing.expect(std.mem.startsWith(u8, found.unix, "/home/somebody"));
    }

    try env.put(control.address_env, "10.0.0.4:7373");
    {
        const found = (try daemonAddress(arena, &env, .{})).?;
        try testing.expectEqualStrings("10.0.0.4", found.ip.host);
        try testing.expectEqual(@as(u16, 7373), found.ip.port);
    }

    {
        const found = (try daemonAddress(arena, &env, .{ .daemon = "unix:/run/chock/d.sock" })).?;
        try testing.expectEqualStrings("/run/chock/d.sock", found.unix);
    }
    {
        const found = (try daemonAddress(arena, &env, .{ .port = 9191 })).?;
        try testing.expectEqualStrings(control.default_host, found.ip.host);
        try testing.expectEqual(@as(u16, 9191), found.ip.port);
    }
    try testing.expectEqualStrings("", said.err());

    said.clear();
    try testing.expect(try daemonAddress(arena, &env, .{
        .daemon = "unix:/run/chock/d.sock",
        .port = 9191,
    }) == null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "--daemon") != null);

    said.clear();
    try testing.expect(try daemonAddress(arena, &env, .{ .daemon = "/run/chock/d.sock" }) == null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "/run/chock/d.sock") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "unix:/path") != null);
}

test "a failure after a session was stopped says so, and one before it does not" {
    try testing.expectEqualStrings("", stoppedNote(false));
    const note = stoppedNote(true);
    try testing.expect(note.len != 0);
    try testing.expect(std.mem.indexOf(u8, note, "already stopped") != null);
    try testing.expect(std.mem.indexOf(u8, note, "chock run --continue") != null);
}

test "a daemon that took the session is the only answer that exits finished" {
    const id = "01JQ" ++ "A" ** 22;
    const note = stoppedNote(false);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqual(Exit.finished.code(), report("ok " ++ id ++ "\t/state/s.jsonl", id, true, note));
    try testing.expect(std.mem.indexOf(u8, said.out(), "the daemon owns session") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "chock approve " ++ id) != null);
    try testing.expectEqualStrings("", said.err());

    said.clear();
    try testing.expectEqual(Exit.usage.code(), report("error that session is running now", id, true, note));
    try testing.expect(std.mem.indexOf(u8, said.err(), "that session is running now") != null);

    for ([_][]const u8{ "", "okay then" }) |unreadable| {
        said.clear();
        try testing.expectEqual(Exit.faulted.code(), report(unreadable, id, true, note));
        try testing.expect(std.mem.indexOf(u8, said.err(), "unknown") != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "chock sessions") != null);
    }

    said.clear();
    try testing.expectEqual(Exit.finished.code(), report("ok " ++ id, id, true, note));
    try testing.expect(std.mem.indexOf(u8, said.out(), "the daemon owns session") != null);

    said.clear();
    try testing.expectEqual(Exit.finished.code(), report("ok " ++ id, id, false, note));
    try testing.expect(std.mem.indexOf(u8, said.err(), "nobody can answer") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "the daemon owns session") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "chock approve") == null);
}

test "a socket path too long for the machine is measured before the closing advice is given" {
    const gpa = testing.allocator;

    const id = "01JQ" ++ "A" ** 22;
    var short = try chock_broker.socket.pathsFor(gpa, "/state/p", id);
    defer short.deinit();
    try testing.expect(answerableAt(short.socket));

    const deep = try std.fmt.allocPrint(gpa, "/state/{s}", .{"d" ** 120});
    defer gpa.free(deep);
    var over = try chock_broker.socket.pathsFor(gpa, deep, id);
    defer over.deinit();
    try testing.expect(!answerableAt(over.socket));

    const at_bound = try boundedPath(gpa, max_socket_path);
    defer gpa.free(at_bound);
    try testing.expect(answerableAt(at_bound));

    const over_bound = try boundedPath(gpa, max_socket_path + 1);
    defer gpa.free(over_bound);
    try testing.expect(!answerableAt(over_bound));
}

fn boundedPath(gpa: std.mem.Allocator, length: usize) std.mem.Allocator.Error![]u8 {
    const path = try gpa.alloc(u8, length);
    @memset(path, 'p');
    path[0] = '/';
    return path;
}

test "a session that is running is refused, and one nobody owns is handed over" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const dir = dir_buffer[0..dir_len];

    const id = "01JQ" ++ "A" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}.jsonl", .{ dir, id }, 0);
    defer gpa.free(log_path);

    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        const content = [_]chock_proto.event.ContentPart{.{ .text = "carry this on" }};
        _ = try locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);
        try locked.unlock(io);
    }

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    try testing.expect(reportReadiness(gpa, io, log_path, id));
    try testing.expectEqualStrings("", said.err());

    {
        var owner = try chock_proto.log.Log.open(io, log_path, id);
        defer owner.close(io);
        var held = try owner.lock(io);
        defer held.unlock(io) catch {};
        try testing.expect(!reportReadiness(gpa, io, log_path, id));
        try testing.expect(std.mem.indexOf(u8, said.err(), id) != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "running now") != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "chock sessions") != null);
        try testing.expectEqualStrings("", said.out());
    }

    said.clear();
    try testing.expect(reportReadiness(gpa, io, log_path, id));
    try testing.expectEqualStrings("", said.err());
}

test "a session whose workspace still holds work is refused, and an empty one is not" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const dir = dir_buffer[0..dir_len];

    const id = "01JQ" ++ "A" ** 22;
    const work = try std.fmt.allocPrint(gpa, "{s}/{s}.work", .{ dir, id });
    defer gpa.free(work);

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    try testing.expect(reportKeptWorkspace(gpa, io, work, id));

    try tmp.dir.createDir(io, id ++ ".work", .default_dir);
    try testing.expect(reportKeptWorkspace(gpa, io, work, id));
    try testing.expectEqualStrings("", said.err());

    var work_dir = try tmp.dir.openDir(io, id ++ ".work", .{});
    defer work_dir.close(io);
    try work_dir.writeFile(io, .{ .sub_path = "agent-wrote-this.txt", .data = "work nothing else holds\n" });
    try testing.expect(!reportKeptWorkspace(gpa, io, work, id));
    try testing.expect(std.mem.indexOf(u8, said.err(), work) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "1 files") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "chock workspace") != null);
    try testing.expectEqualStrings("", said.out());
}

test "a session folded by the next owner holds what the last owner held" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const id = "01JQ" ++ "H" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}.jsonl", .{ dir_buffer[0..dir_len], id }, 0);
    defer gpa.free(log_path);

    const child_id = "01JQ" ++ "K" ** 22;
    const user = [_]chock_proto.event.ContentPart{.{ .text = "carry this on" }};
    const answer = [_]chock_proto.event.ContentPart{.{ .text = "reading the parser" }};
    const steps = [_]chock_proto.event.PlanStep{
        .{ .id = "s1", .subject = "read the fold", .status = .done },
        .{ .id = "s2", .subject = "write the test", .status = .in_progress },
    };
    const promises = [_]chock_proto.event.SelfRestriction{
        .{ .action = "git.push", .ceiling = .deny, .reason = "nothing of mine leaves this machine" },
    };
    const written = [_]chock_proto.event.Event{
        .{ .session_start = .{ .agent_kind = "main", .model_alias = "local", .parent_session = "" } },
        .{ .message = .{ .role = .user, .content = &user } },
        .{ .message = .{ .role = .assistant, .content = &answer } },
        .{ .session_spawn = .{
            .child_session = child_id,
            .child_agent_kind = "reviewer",
            .reason = "a second reading of the diff",
            .budget_max_cost = 0.25,
            .budget_currency = "USD",
        } },
        .{ .usage = .{
            .input_tokens = 900,
            .output_tokens = 120,
            .cost = .{ .known = .{ .value = 0.5, .currency = "USD" } },
            .model = "a-model",
            .model_alias = "local",
        } },
        .{ .plan_update = .{ .steps = &steps } },
        .{ .policy_self = .{ .restrictions = &promises } },
    };

    var running = chock_proto.state.Session.init(gpa);
    defer running.deinit();
    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);

        var locked = try store.lock(io);
        for (written, 1..) |one, time_ms| {
            const offset = try locked.append(gpa, io, one, @intCast(time_ms));
            try running.apply(.{ .id = offset, .session = id, .time_ms = @intCast(time_ms), .event = one });
        }
        try locked.unlock(io);
    }

    var recovered = chock_proto.state.Session.init(gpa);
    defer recovered.deinit();
    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);

        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var replay = try store.replay(gpa, io, 0);
        defer replay.deinit();
        while (try replay.next(io)) |parsed| {
            defer parsed.deinit();
            try recovered.apply(parsed.value);
        }
    }

    try testing.expectEqualStrings(running.agent_kind, recovered.agent_kind);
    try testing.expectEqualStrings("main", recovered.agent_kind);
    try testing.expectEqualStrings(running.model_alias, recovered.model_alias);

    try testing.expectEqual(running.context.items.len, recovered.context.items.len);
    try testing.expectEqual(@as(usize, 2), recovered.context.items.len);

    try testing.expectEqual(running.children.items.len, recovered.children.items.len);
    try testing.expectEqual(@as(usize, 1), recovered.children.items.len);
    try testing.expectEqualStrings(child_id, recovered.children.items[0].session);
    try testing.expectEqualStrings("reviewer", recovered.children.items[0].agent_kind);
    try testing.expectEqual(@as(f64, 0.25), recovered.children.items[0].budget_max_cost);
    try testing.expectEqualStrings("USD", recovered.children.items[0].budget_currency);

    try testing.expectEqual(running.spend.input_tokens, recovered.spend.input_tokens);
    try testing.expectEqual(running.spend.output_tokens, recovered.spend.output_tokens);
    try testing.expectEqual(running.spend.turns, recovered.spend.turns);
    try testing.expectEqual(running.spend.amount, recovered.spend.amount);
    try testing.expectEqualStrings("USD", recovered.spend.currency);
    try testing.expectEqual(@as(u64, 900), recovered.last_input_tokens);

    const running_counts = running.plan.counts();
    const recovered_counts = recovered.plan.counts();
    try testing.expectEqual(running_counts.done, recovered_counts.done);
    try testing.expectEqual(running_counts.in_progress, recovered_counts.in_progress);
    try testing.expectEqual(@as(usize, 1), recovered_counts.done);
    try testing.expectEqual(@as(usize, 1), recovered_counts.in_progress);

    try testing.expectEqual(
        running.self_policy.restrictions.items.len,
        recovered.self_policy.restrictions.items.len,
    );
    try testing.expectEqual(@as(usize, 1), recovered.self_policy.restrictions.items.len);
    try testing.expectEqualStrings("git.push", recovered.self_policy.restrictions.items[0].action);
    try testing.expectEqualStrings("deny", recovered.self_policy.restrictions.items[0].ceiling.wireName());

    const after = try chock_proto.log.Log.open(io, log_path, id);
    var after_backing = chock_proto.storage.JsonLines{ .log = after };
    const after_store = after_backing.storage();
    defer after_store.close(io);
    var third = try after_store.lock(io);
    try third.unlock(io);
}

test "a handover with no daemon to hand to is refused, and it names what to do" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const socket_path = try std.fmt.allocPrint(gpa, "{s}/d.sock", .{dir_buffer[0..dir_len]});
    defer gpa.free(socket_path);

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    const id = "01JQ" ++ "A" ** 22;
    const code = try handOver(io, "/some/project", id, .{ .unix = socket_path }, true, false);
    try testing.expectEqual(Exit.usage.code(), code);
    try testing.expect(std.mem.indexOf(u8, said.err(), id) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "nothing is listening") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "chock daemon") != null);
    try testing.expectEqualStrings("", said.out());
}

const FakeDaemon = struct {
    io: std.Io,
    listener: control.Listener,
    speaks: u32,
    lenient: bool,
    thread: std.Thread = undefined,
    asked: bool = false,

    fn start(io: std.Io, path: []const u8, speaks: u32, lenient: bool) !*FakeDaemon {
        const self = try testing.allocator.create(FakeDaemon);
        errdefer testing.allocator.destroy(self);
        self.* = .{
            .io = io,
            .listener = try (control.Address{ .unix = path }).listen(io),
            .speaks = speaks,
            .lenient = lenient,
        };
        self.thread = try std.Thread.spawn(.{}, run, .{self});
        return self;
    }

    fn run(self: *FakeDaemon) void {
        var stream = self.listener.server.accept(self.io) catch return;
        defer stream.close(self.io);

        var read_buffer: [4096]u8 = undefined;
        var stream_reader = stream.reader(self.io, &read_buffer);
        var write_buffer: [4096]u8 = undefined;
        var stream_writer = stream.writer(self.io, &write_buffer);
        const writer = &stream_writer.interface;
        defer writer.flush() catch {};

        const line = (stream_reader.interface.takeDelimiter('\n') catch null) orelse return;
        const asked = control.Greeting.parse(.ask, line) catch return;
        if (!self.lenient and !control.accepts(self.speaks, asked.version)) {
            control.writeMismatch(writer, self.speaks, asked.version) catch {};
            writer.flush() catch {};
            return;
        }
        (control.Greeting{ .version = self.speaks }).write(.answer, writer) catch {};
        writer.flush() catch {};

        if ((stream_reader.interface.takeDelimiter('\n') catch null) != null) self.asked = true;
    }

    fn finish(self: *FakeDaemon) void {
        self.thread.join();
    }

    fn deinit(self: *FakeDaemon) void {
        self.listener.close(self.io);
        testing.allocator.destroy(self);
    }
};

test "a daemon of another control protocol number is never handed a session" {
    const gpa = testing.allocator;
    const io = testing.io;
    const id = "01JQ" ++ "A" ** 22;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    const other = control.protocol_version + 1;

    {
        const path = try std.fmt.allocPrint(gpa, "{s}/lenient.sock", .{dir_buffer[0..dir_len]});
        defer gpa.free(path);
        const fake = try FakeDaemon.start(io, path, other, true);
        defer fake.deinit();

        const code = try handOver(io, "/some/project", id, .{ .unix = path }, true, true);
        fake.finish();

        try testing.expectEqual(Exit.usage.code(), code);
        try testing.expect(!fake.asked);
        var ours: [16]u8 = undefined;
        var theirs: [16]u8 = undefined;
        try testing.expect(std.mem.indexOf(
            u8,
            said.err(),
            try std.fmt.bufPrint(&ours, "{d}", .{control.protocol_version}),
        ) != null);
        try testing.expect(std.mem.indexOf(
            u8,
            said.err(),
            try std.fmt.bufPrint(&theirs, "{d}", .{other}),
        ) != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "not handed over") != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "already stopped") != null);
    }

    {
        said.clear();
        const path = try std.fmt.allocPrint(gpa, "{s}/strict.sock", .{dir_buffer[0..dir_len]});
        defer gpa.free(path);
        const fake = try FakeDaemon.start(io, path, other, false);
        defer fake.deinit();

        const code = try handOver(io, "/some/project", id, .{ .unix = path }, true, false);
        fake.finish();

        try testing.expectEqual(Exit.usage.code(), code);
        try testing.expect(!fake.asked);
        var theirs: [16]u8 = undefined;
        try testing.expect(std.mem.indexOf(
            u8,
            said.err(),
            try std.fmt.bufPrint(&theirs, "{d}", .{other}),
        ) != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "not handed over") != null);
    }

    {
        said.clear();
        const path = try std.fmt.allocPrint(gpa, "{s}/same.sock", .{dir_buffer[0..dir_len]});
        defer gpa.free(path);
        const fake = try FakeDaemon.start(io, path, control.protocol_version, false);
        defer fake.deinit();

        _ = try handOver(io, "/some/project", id, .{ .unix = path }, true, false);
        fake.finish();
        try testing.expect(fake.asked);
    }

    try testing.expectEqualStrings("", said.out());
}

test "a session that changed hands is still answered by chock approve, at the same path" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = try ShortTmp.open(io);
    defer tmp.cleanup(io);

    const session_dir = tmp.path();
    const id = "01JQ" ++ "M" ** 22;

    var client_paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
    defer client_paths.deinit();

    const expected = try std.fmt.allocPrint(gpa, "{s}/{s}.ctl/s", .{ session_dir, id });
    defer gpa.free(expected);
    try testing.expectEqualStrings(expected, client_paths.socket);

    const address = try chock_proto.control.unixAddress(client_paths.socket);

    {
        var paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
        defer paths.deinit();
        var first = try chock_broker.socket.Endpoint.open(io, paths, null);
        const before = try address.connect(io);
        before.close(io);
        first.close(io);
    }

    if (address.connect(io)) |orphan| {
        orphan.close(io);
        return error.AClientReachedASessionWithNoOwner;
    } else |_| {}

    var paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
    defer paths.deinit();
    var second = try chock_broker.socket.Endpoint.open(io, paths, null);
    defer second.close(io);

    const after = try address.connect(io);
    after.close(io);
}
