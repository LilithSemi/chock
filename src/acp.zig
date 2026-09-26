//! `chock acp`: an editor drives Chock over the agent client protocol.
//!
//! ## It owns nothing, the same way `chock serve` owns nothing
//!
//! An editor launches this as a subprocess and talks to it on standard input and
//! output. `chock daemon` still owns every session. So this is a second frontend
//! beside `chock serve`, written to the same rule: **would this still work if the
//! daemon were on another machine?** It reads no session log, takes no lock, and
//! builds no path from a session identifier.
//!
//! ## Why a frontend and not the loop itself
//!
//! `chock_core.tools.Registry.dispatch` forks, and a fork carries only the
//! calling thread, so the process that runs a tool call must be single threaded.
//! This process has to read standard input while a turn is running, because
//! `session/cancel` and the answer to a permission request both arrive there. A
//! frontend may have threads because it never forks; the loop may not. That is
//! the whole reason this is a client of the daemon rather than a loop with a
//! protocol bolted onto it.
//!
//! ## Nothing but a protocol message reaches standard output
//!
//! The transport says so, in those words. `tty.print` already writes to standard
//! error, which the transport permits for logging, and nothing here calls
//! `tty.out` except the usage text, which is printed before a client exists.
//!
//! ## One consumer, two producers
//!
//! A thread reads standard input and a thread tails the session log, and both
//! push onto one queue that the main thread alone drains. So every write to
//! standard output happens on one thread, in one order, with no lock around the
//! writer, and a cancel that arrives in the middle of a turn is read rather than
//! waited on.

const std = @import("std");

const chock_acp = @import("chock-acp");
const chock_auth = @import("chock-auth");
const chock_proto = @import("chock-proto");

const control = chock_proto.control;
const event = chock_proto.event;

const jsonrpc = chock_acp.jsonrpc;
const updates = chock_acp.update;

const Exit = @import("main.zig").Exit;
const session_paths = @import("session.zig");
const tty = @import("tty.zig");

/// What this agent tells a client it is.
const agent_name = "chock";

/// The longest message this reads. The transport has no length header, so a peer
/// writing more than this with no newline is one this cannot frame.
const max_line_bytes: usize = 1024 * 1024;

const usage_text =
    \\Usage: chock acp [options]
    \\
    \\Speaks the agent client protocol on standard input and output, so an editor can
    \\drive Chock. Sessions are owned by `chock daemon`, which this connects to.
    \\
    \\Options:
    \\  --daemon <address>   The daemon to use. Defaults to the local socket.
    \\  --project <dir>      The project a session that names no directory uses.
    \\                       Defaults to the working directory.
    \\
;

const Options = struct {
    daemon: ?[]const u8 = null,
    project: ?[]const u8 = null,
};

const ParseError = error{ HelpWanted, BadArguments };

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) {
            return error.HelpWanted;
        }

        const split = std.mem.indexOfScalar(u8, argument, '=');
        const name = if (split) |at| argument[0..at] else argument;
        const inline_value: ?[]const u8 = if (split) |at| argument[at + 1 ..] else null;

        if (std.mem.eql(u8, name, "--daemon") or std.mem.eql(u8, name, "--project")) {
            const value = inline_value orelse next: {
                index += 1;
                if (index >= args.len) {
                    tty.print(.err, "chock acp: {s} needs a value.\n\n{s}", .{ name, usage_text });
                    return error.BadArguments;
                }
                break :next args[index];
            };
            if (std.mem.eql(u8, name, "--daemon")) options.daemon = value else options.project = value;
            continue;
        }

        tty.print(.err, "chock acp: there is no option named {s}.\n\n{s}", .{ name, usage_text });
        return error.BadArguments;
    }
    return options;
}

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
            tty.say(.out, .plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        error.BadArguments => return Exit.usage.code(),
    };

    var threaded = std.Io.Threaded.init(gpa, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    var env = try environ.createMap(arena);

    const daemon_text = options.daemon orelse env.get(control.address_env) orelse text: {
        const state = chock_auth.paths.stateDir(arena, &env) catch |err| {
            tty.print(.err, "chock acp: the state directory could not be found: {t}\n", .{err});
            return Exit.usage.code();
        };
        const path = control.socketPathIn(arena, state) catch return Exit.faulted.code();
        break :text try std.fmt.allocPrint(arena, "unix:{s}", .{path});
    };
    const daemon = control.Address.parse(daemon_text) catch |err| {
        tty.print(
            .err,
            "chock acp: \"{s}\" is not a daemon address ({t}). Write `unix:/path` or `host:port`.\n",
            .{ daemon_text, err },
        );
        return Exit.usage.code();
    };

    const project = projectPath(arena, io, options.project) catch |err| {
        tty.print(.err, "chock acp: the project directory could not be read: {t}\n", .{err});
        return Exit.usage.code();
    };

    var agent = Agent{
        .gpa = gpa,
        .io = io,
        .daemon = daemon,
        .project = project,
    };
    defer agent.deinit();
    return agent.run();
}

fn projectPath(arena: std.mem.Allocator, io: std.Io, named: ?[]const u8) ![]const u8 {
    if (named) |text| {
        if (std.fs.path.isAbsolute(text)) return arena.dupe(u8, text);
        return std.fs.path.resolve(arena, &.{text});
    }
    // `std.Io.Dir.cwd()` carries `AT_FDCWD`, which is not a descriptor, so the
    // directory is opened to be named. The same thing `chock serve` does.
    var here = try std.Io.Dir.cwd().openDir(io, ".", .{});
    defer here.close(io);
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try here.realPath(io, &buffer);
    return arena.dupe(u8, buffer[0..length]);
}

/// One thing for the main thread to do.
const Item = union(enum) {
    /// A protocol message, as the line it arrived as. Owned.
    line: []u8,
    /// One log event of the session whose turn is running. Owned.
    record: Record,
    /// The log tail ended. A turn that ends this way wrote no session end.
    watch_ended,
    /// Standard input closed, which is the editor going away.
    input_closed,

    const Record = struct { id: u64, payload: []u8 };

    fn deinit(self: Item, gpa: std.mem.Allocator) void {
        switch (self) {
            .line => |text| gpa.free(text),
            .record => |one| gpa.free(one.payload),
            .watch_ended, .input_closed => {},
        }
    }
};

/// A queue with one consumer and two producers.
///
/// Uncancelable throughout: a cancel of this process is standard input closing,
/// which arrives as an item, and a wait that could be cancelled would lose the
/// item a producer had already pushed.
const Queue = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    ready: std.Io.Condition = .init,
    items: std.ArrayList(Item) = .empty,

    fn push(self: *Queue, item: Item) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.items.append(self.gpa, item) catch {
            // Dropping it beats ending a session over one allocation, and the
            // log keeps the event either way.
            item.deinit(self.gpa);
            return;
        };
        self.ready.signal(self.io);
    }

    fn pop(self: *Queue) Item {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        while (self.items.items.len == 0) self.ready.waitUncancelable(self.io, &self.mutex);
        return self.items.orderedRemove(0);
    }

    fn deinit(self: *Queue) void {
        for (self.items.items) |one| one.deinit(self.gpa);
        self.items.deinit(self.gpa);
    }
};

/// A session this process has told a client about.
const Live = struct {
    /// Chock's own identifier, which is also the one the client was given. There
    /// is no second numbering to keep in step.
    id: [session_paths.id_length]u8,
    project: []u8,
    /// The log offset everything up to has been sent. A turn tails from here, so
    /// nothing is sent twice and nothing is missed.
    seen: u64 = 0,
    /// How many tokens this session's model holds, out of `session.config`. Null
    /// when nobody said, and then no context gauge is sent: ACP requires the size
    /// beside the use, and a gauge against a number nobody wrote reads as full or
    /// empty by accident.
    window: ?u64 = null,
    /// The merged plan. ACP plan entries carry no identifier, so a client cannot
    /// merge one and the whole plan goes every time.
    plan: std.ArrayList(Step) = .empty,
    /// Tool calls this session has opened, so a result can name the tool its call
    /// was for. ACP wants a kind and a title on the call and only an identifier
    /// on the update.
    calls: std.ArrayList(Call) = .empty,

    const Step = struct {
        id: []u8,
        subject: []u8,
        status: updates.StepStatus,
    };

    const Call = struct {
        id: []u8,
        tool: []u8,
    };

    fn deinit(self: *Live, gpa: std.mem.Allocator) void {
        gpa.free(self.project);
        for (self.plan.items) |step| {
            gpa.free(step.id);
            gpa.free(step.subject);
        }
        self.plan.deinit(gpa);
        for (self.calls.items) |call| {
            gpa.free(call.id);
            gpa.free(call.tool);
        }
        self.calls.deinit(gpa);
    }

    /// Merge one plan step in by identifier, the way Chock's own plan updates
    /// are meant to be read.
    fn mergeStep(
        self: *Live,
        gpa: std.mem.Allocator,
        id: []const u8,
        subject: []const u8,
        status: updates.StepStatus,
    ) !void {
        for (self.plan.items) |*held| {
            if (!std.mem.eql(u8, held.id, id)) continue;
            held.status = status;
            if (subject.len != 0) {
                gpa.free(held.subject);
                held.subject = try gpa.dupe(u8, subject);
            }
            return;
        }
        try self.plan.append(gpa, .{
            .id = try gpa.dupe(u8, id),
            .subject = try gpa.dupe(u8, subject),
            .status = status,
        });
    }

    fn noteCall(self: *Live, gpa: std.mem.Allocator, id: []const u8, tool: []const u8) !void {
        for (self.calls.items) |held| {
            if (std.mem.eql(u8, held.id, id)) return;
        }
        try self.calls.append(gpa, .{
            .id = try gpa.dupe(u8, id),
            .tool = try gpa.dupe(u8, tool),
        });
    }

    fn toolFor(self: *const Live, id: []const u8) []const u8 {
        for (self.calls.items) |held| {
            if (std.mem.eql(u8, held.id, id)) return held.tool;
        }
        return "";
    }
};

/// What one daemon exchange answered.
const Answered = struct {
    ok: ?[]const u8 = null,
    failed: ?[]const u8 = null,
    /// A fault reaching the daemon at all, which is not the same as a refusal.
    unreachable_reason: ?[]const u8 = null,

    fn refusal(self: Answered) ?[]const u8 {
        if (self.unreachable_reason) |text| return text;
        return self.failed;
    }
};

const Agent = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    daemon: control.Address,
    /// The project a `session/new` that names no directory of its own uses.
    project: []const u8,

    /// Null until `initialize` agrees one. Nothing else is answered before it.
    version: ?chock_acp.Version = null,
    sessions: std.ArrayList(Live) = .empty,
    queue: Queue = undefined,
    turn: ?Turn = null,
    out: *std.Io.Writer = undefined,
    /// The next id for a request this agent makes of the client.
    next_ask: u64 = 1,
    stopping: bool = false,

    /// The `session/prompt` waiting for a stop reason, and what is running for it.
    const Turn = struct {
        request: jsonrpc.Id,
        session: usize,
        /// Set when the log says a permission is waiting on the client.
        pending: ?Pending = null,
        /// True once a cancel has been sent to the daemon, so a second one does
        /// not go and the stop reason is the cancelled one whatever the log says.
        cancelled: bool = false,

        const Pending = struct {
            /// The id this agent sent the client, as the token it will echo.
            ask: []u8,
            /// The log offset of the approval request, which is what the daemon's
            /// `answer` verb names.
            request_id: u64,
        };
    };

    fn deinit(self: *Agent) void {
        for (self.sessions.items) |*one| one.deinit(self.gpa);
        self.sessions.deinit(self.gpa);
        if (self.turn) |one| if (one.pending) |pending| self.gpa.free(pending.ask);
    }

    fn run(self: *Agent) !u8 {
        self.queue = .{ .gpa = self.gpa, .io = self.io };
        defer self.queue.deinit();

        var out_buffer: [64 * 1024]u8 = undefined;
        var out_file = std.Io.File.stdout().writerStreaming(self.io, &out_buffer);
        self.out = &out_file.interface;

        var reader = InputReader{ .agent = self };
        const input_thread = std.Thread.spawn(.{}, InputReader.run, .{&reader}) catch {
            tty.print(.err, "chock acp: the input reader could not be started.\n", .{});
            return Exit.faulted.code();
        };
        // Detached: standard input closing is what ends this process, and that
        // arrives as an item rather than as a thread to wait for.
        input_thread.detach();

        while (!self.stopping) {
            const item = self.queue.pop();
            defer item.deinit(self.gpa);
            self.handle(item);
        }
        return Exit.finished.code();
    }

    fn handle(self: *Agent, item: Item) void {
        switch (item) {
            .line => |text| self.handleLine(text),
            .record => |one| self.handleRecord(one),
            .watch_ended => self.endTurn(.end_turn),
            .input_closed => self.stopping = true,
        }
    }

    // --- writing ---

    /// One notification. A failure to write is the editor going away, which ends
    /// this process rather than being reported to it.
    fn notify(self: *Agent, arena: std.mem.Allocator, method: []const u8, params: []const u8) void {
        const body = jsonrpc.notificationBody(arena, method, params) catch return;
        jsonrpc.writeFrame(arena, self.out, body) catch {
            self.stopping = true;
        };
    }

    fn answer(self: *Agent, arena: std.mem.Allocator, id: jsonrpc.Id, result: []const u8) void {
        const body = jsonrpc.resultBody(arena, id, result) catch return;
        jsonrpc.writeFrame(arena, self.out, body) catch {
            self.stopping = true;
        };
    }

    fn fail(
        self: *Agent,
        arena: std.mem.Allocator,
        id: jsonrpc.Id,
        code: jsonrpc.Code,
        said: []const u8,
    ) void {
        const body = jsonrpc.errorBody(arena, id, code, said) catch return;
        jsonrpc.writeFrame(arena, self.out, body) catch {
            self.stopping = true;
        };
    }

    /// The name of a client method in the version that was agreed.
    fn clientMethod(self: *const Agent, which: ClientMethod) []const u8 {
        const version = self.version orelse return switch (which) {
            .session_update => "session/update",
            .request_permission => "session/request_permission",
        };
        return switch (version) {
            .v1 => switch (which) {
                .session_update => chock_acp.v1.Method.session_update.wireName(),
                .request_permission => chock_acp.v1.Method.session_request_permission.wireName(),
            },
            .v2 => switch (which) {
                .session_update => chock_acp.v2.Method.session_update.wireName(),
                .request_permission => chock_acp.v2.Method.session_request_permission.wireName(),
            },
        };
    }

    const ClientMethod = enum { session_update, request_permission };

    fn send(self: *Agent, arena: std.mem.Allocator, one: updates.Update) void {
        const turn = self.turn orelse return;
        const live = &self.sessions.items[turn.session];
        const version = self.version orelse return;
        const params = (updates.encode(arena, version, &live.id, one) catch return) orelse return;
        self.notify(arena, self.clientMethod(.session_update), params);
    }

    // --- reading ---

    fn handleLine(self: *Agent, text: []const u8) void {
        var state = std.heap.ArenaAllocator.init(self.gpa);
        defer state.deinit();
        const arena = state.allocator();

        const any = jsonrpc.parseAny(arena, text) catch |err| {
            // A message with no readable id cannot be answered at all, so it is
            // said on standard error, which the transport keeps for exactly this.
            tty.print(.err, "chock acp: a message could not be read: {t}\n", .{err});
            return;
        };

        switch (any) {
            .reply => |one| self.handleReply(arena, one),
            .request => |one| self.handleRequest(arena, one),
        }
    }

    fn handleRequest(self: *Agent, arena: std.mem.Allocator, incoming: jsonrpc.Incoming) void {
        const method = Method.fromWireName(self.version, incoming.method) orelse {
            if (incoming.id) |id| {
                self.fail(arena, id, .method_not_found, jsonrpc.Code.method_not_found.text());
            }
            return;
        };

        // Nothing but `initialize` runs before the versions agree. A client that
        // skipped it is told so rather than served a guess.
        if (self.version == null and method != .initialize) {
            if (incoming.id) |id| {
                self.fail(arena, id, .invalid_request, "initialize has not been sent yet");
            }
            return;
        }

        switch (method) {
            .initialize => self.handleInitialize(arena, incoming),
            .authenticate => self.handleAuthenticate(arena, incoming),
            .session_new => self.handleSessionNew(arena, incoming),
            .session_load => self.handleSessionLoad(arena, incoming),
            .session_prompt => self.handleSessionPrompt(arena, incoming),
            .session_cancel => self.handleSessionCancel(arena, incoming),
            .session_list => self.handleSessionList(arena, incoming),
            .session_delete => self.handleSessionDelete(arena, incoming),
            .session_close => self.handleSessionClose(arena, incoming),
        }
    }

    /// A reply to a `session/request_permission` this agent sent.
    fn handleReply(self: *Agent, arena: std.mem.Allocator, reply: jsonrpc.Reply) void {
        // `if (self.turn) |*turn|` and never `&(self.turn orelse ...)`: the
        // second takes the address of a copy of the payload, so every write to
        // it is lost. That bug made every permission time out as a refusal.
        const turn = if (self.turn) |*one| one else return;
        const pending = turn.pending orelse return;
        if (!std.mem.eql(u8, pending.ask, reply.id.raw)) return;

        // A refused request and a rejected option are the same thing to the
        // session: nobody permitted it.
        const permitted = if (reply.failed()) false else permittedBy(arena, reply.result);

        self.tellDaemon(arena, pending.request_id, permitted);

        self.gpa.free(pending.ask);
        turn.pending = null;
    }

    /// Whether the option the client chose permits the action.
    ///
    /// An `outcome` of `cancelled` is the client saying nobody answered, which is
    /// a refusal: `lib/chock-policy` reads an unanswered question as `deny`, and
    /// this is the same reading.
    fn permittedBy(arena: std.mem.Allocator, result: []const u8) bool {
        const parsed = std.json.parseFromSlice(std.json.Value, arena, result, .{}) catch return false;
        const object = switch (parsed.value) {
            .object => |one| one,
            else => return false,
        };
        const outcome = switch (object.get("outcome") orelse return false) {
            .object => |one| one,
            else => return false,
        };
        switch (outcome.get("outcome") orelse return false) {
            .string => |text| if (!std.mem.eql(u8, text, "selected")) return false,
            else => return false,
        }
        const chosen = switch (outcome.get("optionId") orelse return false) {
            .string => |text| text,
            else => return false,
        };
        // The option identifiers are this agent's own, named after the kind they
        // carry, so the answer reads without a table.
        const kind = chock_acp.common.PermissionKind.fromWireName(chosen) orelse return false;
        return kind.permits();
    }

    /// Tell the daemon what was decided. The answer never travels back to the
    /// agent that asked: it reads the outcome out of its own log.
    fn tellDaemon(self: *Agent, arena: std.mem.Allocator, request_id: u64, permitted: bool) void {
        const turn = self.turn orelse return;
        const live = &self.sessions.items[turn.session];
        _ = self.ask(arena, .{ .answer = .{
            .project = live.project,
            .session = &live.id,
            .request_id = request_id,
            .decision = if (permitted) .yes else .no,
        } });
    }

    // --- the daemon ---

    /// One request, one answer. Every verb but `watch` is this shape.
    fn ask(self: *Agent, arena: std.mem.Allocator, request: control.Request) Answered {
        const stream = self.daemon.connect(self.io) catch |err| {
            return .{ .unreachable_reason = @errorName(err) };
        };
        defer stream.close(self.io);

        var read_buffer: [64 * 1024]u8 = undefined;
        var stream_reader = stream.reader(self.io, &read_buffer);
        var write_buffer: [8 * 1024]u8 = undefined;
        var stream_writer = stream.writer(self.io, &write_buffer);

        const Collect = struct {
            arena: std.mem.Allocator,
            out: *Answered,

            fn take(self_take: *@This(), reply: control.Reply) anyerror!bool {
                switch (reply) {
                    .ok => |text| {
                        self_take.out.ok = try self_take.arena.dupe(u8, text);
                        return false;
                    },
                    .failed => |text| {
                        self_take.out.failed = try self_take.arena.dupe(u8, text);
                        return false;
                    },
                    // A record here belongs to a verb that streams, and `ask` is
                    // not used for one.
                    .record => return true,
                }
            }
        };

        var answered = Answered{};
        var collect = Collect{ .arena = arena, .out = &answered };
        var said: control.Handshake = .{ .unreadable = "" };

        control.exchange(
            &stream_reader.interface,
            &stream_writer.interface,
            request,
            &said,
            &collect,
            Collect.take,
        ) catch |err| {
            if (!said.ok()) return .{ .unreachable_reason = "the daemon speaks another version" };
            if (answered.ok == null and answered.failed == null) {
                return .{ .unreachable_reason = @errorName(err) };
            }
        };
        return answered;
    }

    /// Tail one session's log onto the queue, on a thread of its own.
    ///
    /// The offset is what makes this safe to start after the turn: `watch` streams
    /// from a byte offset, so an event written before this connected is still
    /// delivered, and none is delivered twice.
    const Watcher = struct {
        agent: *Agent,
        project: []u8,
        session: [session_paths.id_length]u8,
        after: u64,

        fn run(self: *Watcher) void {
            const agent = self.agent;
            defer {
                agent.queue.push(.watch_ended);
                agent.gpa.free(self.project);
                agent.gpa.destroy(self);
            }

            const stream = agent.daemon.connect(agent.io) catch return;
            defer stream.close(agent.io);

            var read_buffer: [256 * 1024]u8 = undefined;
            var stream_reader = stream.reader(agent.io, &read_buffer);
            var write_buffer: [8 * 1024]u8 = undefined;
            var stream_writer = stream.writer(agent.io, &write_buffer);

            const Feed = struct {
                agent: *Agent,

                fn take(self_take: *@This(), reply: control.Reply) anyerror!bool {
                    switch (reply) {
                        .record => |one| {
                            const owned = self_take.agent.gpa.dupe(u8, one.payload) catch return false;
                            self_take.agent.queue.push(.{ .record = .{ .id = one.id, .payload = owned } });
                        },
                        // The daemon says why it stopped on standard error's own
                        // channel; here it just ends the tail.
                        .ok, .failed => return false,
                    }
                    return true;
                }
            };

            var feed = Feed{ .agent = agent };
            var said: control.Handshake = .{ .unreadable = "" };
            control.exchange(
                &stream_reader.interface,
                &stream_writer.interface,
                .{ .watch = .{
                    .project = self.project,
                    .session = &self.session,
                    .after = self.after,
                } },
                &said,
                &feed,
                Feed.take,
            ) catch {};
        }
    };

    fn startWatching(self: *Agent, live: *const Live) bool {
        const watcher = self.gpa.create(Watcher) catch return false;
        const project = self.gpa.dupe(u8, live.project) catch {
            self.gpa.destroy(watcher);
            return false;
        };
        watcher.* = .{
            .agent = self,
            .project = project,
            .session = live.id,
            .after = live.seen,
        };
        const thread = std.Thread.spawn(.{}, Watcher.run, .{watcher}) catch {
            self.gpa.free(project);
            self.gpa.destroy(watcher);
            return false;
        };
        thread.detach();
        return true;
    }

    // --- sessions this process knows ---

    fn find(self: *Agent, given: []const u8) ?usize {
        if (!session_paths.isValidId(given)) return null;
        for (self.sessions.items, 0..) |one, index| {
            if (std.mem.eql(u8, &one.id, given)) return index;
        }
        return null;
    }

    fn remember(self: *Agent, id: []const u8, project: []const u8) !usize {
        const owned = try self.gpa.dupe(u8, project);
        errdefer self.gpa.free(owned);
        try self.sessions.append(self.gpa, .{
            .id = id[0..session_paths.id_length].*,
            .project = owned,
        });
        return self.sessions.items.len - 1;
    }

    /// The session identifier out of a `params` object, and the session it names.
    fn sessionOf(
        self: *Agent,
        arena: std.mem.Allocator,
        incoming: jsonrpc.Incoming,
    ) ?usize {
        const named = stringField(arena, incoming.params, "sessionId") orelse {
            if (incoming.id) |id| self.fail(arena, id, .invalid_params, "that needs a sessionId");
            return null;
        };
        return self.find(named) orelse {
            if (incoming.id) |id| {
                self.fail(arena, id, .resource_not_found, "this agent holds no session with that identifier");
            }
            return null;
        };
    }

    // --- the methods ---

    /// Agree a version and say what this agent can do.
    ///
    /// The version is the newest both sides speak, and never the newest this one
    /// has: see `chock_acp.negotiate`.
    fn handleInitialize(self: *Agent, arena: std.mem.Allocator, incoming: jsonrpc.Incoming) void {
        const id = incoming.id orelse return;

        const asked = numberField(arena, incoming.params, "protocolVersion") orelse {
            self.fail(arena, id, .invalid_params, "initialize needs a protocolVersion");
            return;
        };
        const version = chock_acp.negotiate(std.math.cast(u16, asked) orelse 0) orelse {
            self.fail(arena, id, .invalid_request, "this agent does not speak that protocol version");
            return;
        };
        self.version = version;

        const result = capabilities(arena, version) catch return;
        self.answer(arena, id, result);
    }

    /// Chock holds no credential of its own to log in with.
    ///
    /// Its provider credentials come from `chock login`, which is a person at a
    /// terminal and not a method on this wire. So no authentication method is
    /// declared, and one asked for anyway is refused by name rather than by
    /// silence.
    fn handleAuthenticate(self: *Agent, arena: std.mem.Allocator, incoming: jsonrpc.Incoming) void {
        const id = incoming.id orelse return;
        self.fail(
            arena,
            id,
            .invalid_request,
            "chock has no authentication method on this wire. Its provider credentials are " ++
                "stored by `chock login`, which runs where a person can type one.",
        );
    }

    /// A session, with no turn running in it.
    ///
    /// `cwd` is the client's, and it is used as the project. `mcpServers` is
    /// refused rather than honoured: see `mcpRefusal`.
    fn handleSessionNew(self: *Agent, arena: std.mem.Allocator, incoming: jsonrpc.Incoming) void {
        const id = incoming.id orelse return;

        const cwd = stringField(arena, incoming.params, "cwd") orelse self.project;
        if (!std.fs.path.isAbsolute(cwd)) {
            self.fail(arena, id, .invalid_params, "cwd has to be an absolute path");
            return;
        }

        if (namesMcpServers(arena, incoming.params)) {
            self.fail(arena, id, .invalid_params, mcp_refusal);
            return;
        }

        const answered = self.ask(arena, .{ .create = .{ .project = cwd } });
        if (answered.refusal()) |text| {
            self.fail(arena, id, .internal_error, text);
            return;
        }
        const said = answered.ok orelse {
            self.fail(arena, id, .internal_error, "the daemon said nothing");
            return;
        };

        // `create` answers with the identifier and the log path, tab separated.
        // The path is the daemon's business and this frontend does not keep it.
        const tab = std.mem.indexOfScalar(u8, said, '\t') orelse said.len;
        const new_id = said[0..tab];
        if (!session_paths.isValidId(new_id)) {
            self.fail(arena, id, .internal_error, "the daemon answered with no session identifier");
            return;
        }

        _ = self.remember(new_id, cwd) catch {
            self.fail(arena, id, .internal_error, "out of memory");
            return;
        };

        const result = std.json.Stringify.valueAlloc(arena, .{ .sessionId = new_id }, .{}) catch return;
        self.answer(arena, id, result);
    }

    /// Take up a session that already exists, and replay what it holds.
    ///
    /// The protocol says a client is sent the whole conversation as updates before
    /// this answers, so the client ends up with what it would have had if it had
    /// been there. `session/resume` in version 2 is the same method renamed.
    fn handleSessionLoad(self: *Agent, arena: std.mem.Allocator, incoming: jsonrpc.Incoming) void {
        const id = incoming.id orelse return;

        const named = stringField(arena, incoming.params, "sessionId") orelse {
            self.fail(arena, id, .invalid_params, "that needs a sessionId");
            return;
        };
        if (!session_paths.isValidId(named)) {
            self.fail(arena, id, .invalid_params, "that is not a session identifier");
            return;
        }
        const cwd = stringField(arena, incoming.params, "cwd") orelse self.project;

        const known = self.find(named) orelse self.remember(named, cwd) catch {
            self.fail(arena, id, .internal_error, "out of memory");
            return;
        };

        // Read rather than watched: a load wants what is there now and then
        // answers. A watch would never answer, because it tails.
        const answered = self.replay(arena, known);
        if (answered) |text| {
            self.fail(arena, id, .resource_not_found, text);
            return;
        }
        self.answer(arena, id, "");
    }

    /// One turn. Answers when the log says how it ended, and not before.
    fn handleSessionPrompt(self: *Agent, arena: std.mem.Allocator, incoming: jsonrpc.Incoming) void {
        const id = incoming.id orelse return;

        if (self.turn != null) {
            self.fail(arena, id, .invalid_request, "this session is already running a turn");
            return;
        }

        const known = self.sessionOf(arena, incoming) orelse return;
        const text = promptText(arena, incoming.params) catch null orelse {
            self.fail(arena, id, .invalid_params, "the prompt held no text this agent can read");
            return;
        };

        const live = &self.sessions.items[known];

        // The watcher first, so nothing between here and the prompt is missed.
        // It tails from `seen`, so starting it early delivers nothing twice.
        if (!self.startWatching(live)) {
            self.fail(arena, id, .internal_error, "the session could not be watched");
            return;
        }

        const answered = self.ask(arena, .{ .prompt = .{
            .project = live.project,
            .session = &live.id,
            .message = text,
        } });
        if (answered.refusal()) |said| {
            self.fail(arena, id, .internal_error, said);
            return;
        }

        // The id outlives this arena, because the reply to it is written when the
        // log says the turn ended, so it is held on the agent's own allocator.
        const held = self.gpa.dupe(u8, id.raw) catch {
            self.fail(arena, id, .internal_error, "out of memory");
            return;
        };
        self.turn = .{ .request = .{ .raw = held }, .session = known };
    }

    fn handleSessionCancel(self: *Agent, arena: std.mem.Allocator, incoming: jsonrpc.Incoming) void {
        const known = self.sessionOf(arena, incoming) orelse return;
        const live = &self.sessions.items[known];

        if (self.turn) |*one| one.cancelled = true;

        // An interrupt, so the session writes its own end. Nothing is answered:
        // `session/cancel` is a notification, and the stop reason travels on the
        // reply to `session/prompt`.
        _ = self.ask(arena, .{ .cancel = .{
            .project = live.project,
            .session = &live.id,
        } });
    }

    fn handleSessionList(self: *Agent, arena: std.mem.Allocator, incoming: jsonrpc.Incoming) void {
        const id = incoming.id orelse return;

        const stream = self.daemon.connect(self.io) catch |err| {
            self.fail(arena, id, .internal_error, @errorName(err));
            return;
        };
        defer stream.close(self.io);

        var read_buffer: [256 * 1024]u8 = undefined;
        var stream_reader = stream.reader(self.io, &read_buffer);
        var write_buffer: [8 * 1024]u8 = undefined;
        var stream_writer = stream.writer(self.io, &write_buffer);

        var found: std.ArrayList(u8) = .empty;
        const Gather = struct {
            arena: std.mem.Allocator,
            found: *std.ArrayList(u8),
            project: []const u8,

            fn take(self_take: *@This(), reply: control.Reply) anyerror!bool {
                switch (reply) {
                    .record => |one| {
                        const named = listedSessionIn(self_take.arena, one.payload) orelse return true;
                        if (self_take.found.items.len != 0) try self_take.found.append(self_take.arena, ',');
                        // `cwd` as well as the identifier: the schema requires
                        // both, and every session this lists is under the one
                        // project the daemon was asked about.
                        try self_take.found.print(
                            self_take.arena,
                            "{{\"sessionId\":\"{s}\",\"cwd\":{f}}}",
                            .{ named, std.json.fmt(self_take.project, .{}) },
                        );
                    },
                    .failed => return false,
                    .ok => {},
                }
                return true;
            }
        };
        var gather = Gather{ .arena = arena, .found = &found, .project = self.project };
        var said: control.Handshake = .{ .unreadable = "" };
        control.exchange(
            &stream_reader.interface,
            &stream_writer.interface,
            .{ .list = .{ .project = self.project } },
            &said,
            &gather,
            Gather.take,
        ) catch {
            self.fail(arena, id, .internal_error, "the session list could not be read");
            return;
        };

        const result = std.fmt.allocPrint(arena, "{{\"sessions\":[{s}]}}", .{found.items}) catch return;
        self.answer(arena, id, result);
    }

    /// Chock keeps a session's log on purpose, and this frontend does not delete
    /// one.
    ///
    /// The log is the audit trail: `docs/security/threat-model.md` is written on
    /// the basis that it is kept. Removing one is `chock sessions remove`, which
    /// is gated by the `session.remove` action, and an editor is not where that
    /// decision belongs.
    fn handleSessionDelete(self: *Agent, arena: std.mem.Allocator, incoming: jsonrpc.Incoming) void {
        const id = incoming.id orelse return;
        self.fail(
            arena,
            id,
            .invalid_request,
            "chock does not delete a session's log from here. The log is this session's audit " ++
                "trail, and removing one is `chock sessions remove`, which is asked about under " ++
                "the session.remove action.",
        );
    }

    /// Forget a session, which is not the same as ending it.
    ///
    /// The daemon owns the session and its log outlives this process. So this
    /// drops what this frontend held and answers, and the session is still there
    /// for a `session/load` later.
    fn handleSessionClose(self: *Agent, arena: std.mem.Allocator, incoming: jsonrpc.Incoming) void {
        const id = incoming.id orelse return;
        const known = self.sessionOf(arena, incoming) orelse return;

        if (self.turn) |one| {
            if (one.session == known) {
                self.fail(arena, id, .invalid_request, "that session is running a turn");
                return;
            }
        }

        var live = self.sessions.orderedRemove(known);
        live.deinit(self.gpa);
        // Every turn holds an index into the list, and removing an entry moves
        // the ones after it.
        if (self.turn) |*one| {
            if (one.session > known) one.session -= 1;
        }
        self.answer(arena, id, "");
    }

    // --- the log, as a client reads it ---

    /// One log event, as whatever the client should be told about it.
    fn handleRecord(self: *Agent, one: Item.Record) void {
        var state = std.heap.ArenaAllocator.init(self.gpa);
        defer state.deinit();
        const arena = state.allocator();

        const turn = self.turn orelse return;
        const live = &self.sessions.items[turn.session];
        if (one.id > live.seen) live.seen = one.id;

        const parsed = std.json.parseFromSlice(event.Envelope, arena, one.payload, .{
            .ignore_unknown_fields = true,
        }) catch return;

        self.translate(arena, turn.session, parsed.value.event, one.id);
    }

    fn translate(
        self: *Agent,
        arena: std.mem.Allocator,
        which: usize,
        ev: event.Event,
        offset: u64,
    ) void {
        const live = &self.sessions.items[which];
        switch (ev) {
            .message => |one| self.sendMessage(arena, one),
            .tool_call => |one| {
                live.noteCall(self.gpa, one.call_id, one.tool) catch {};
                self.send(arena, .{ .tool = .{
                    .id = one.call_id,
                    .title = titleFor(arena, one) catch one.tool,
                    .name = one.tool,
                    .kind = toolKindFor(one.tool),
                    .phase = .started,
                } });
            },
            .tool_result => |one| self.send(arena, .{ .tool = .{
                .id = one.call_id,
                .title = "",
                .name = live.toolFor(one.call_id),
                .phase = if (one.is_error) .failed else .finished,
                .output = one.output,
            } }),
            .plan_update => |one| {
                for (one.steps) |step| {
                    live.mergeStep(self.gpa, step.id, step.subject, stepStatusFor(step.status)) catch {};
                }
                self.sendPlan(arena, which);
            },
            .session_title => |one| self.send(arena, .{ .title = one.title }),
            .session_config => |one| {
                if (one.context_limit_tokens) |held| live.window = held;
            },
            .usage => |one| {
                // The same measure `chock_proto.state.Session` keeps and
                // `lib/chock-core/compaction.zig` decides on, so the gauge a
                // client draws agrees with when Chock actually compacts.
                const used = one.input_tokens +
                    one.cache_creation_input_tokens + one.cache_read_input_tokens;
                const size = live.window orelse return;
                self.send(arena, .{
                    .usage = .{
                        .used = used,
                        .size = size,
                        .cost = switch (one.cost) {
                            .known => |money| money.value,
                            // Free is a number and unknown is not, and collapsing
                            // the two is what `lib/chock-cost` exists to stop.
                            .free => 0,
                            .unknown, .unrecognized => null,
                        },
                        .currency = switch (one.cost) {
                            .known => |money| money.currency,
                            else => "USD",
                        },
                    },
                });
            },
            .approval_request => |one| self.askPermission(arena, which, one, offset),
            .session_end => |one| self.endTurn(stopReasonFor(one.reason)),
            // Everything else is Chock's own record keeping. A client that wanted
            // the sandbox's mount list would be reading the log, which is what
            // `chock serve` is for.
            else => {},
        }
    }

    fn sendMessage(self: *Agent, arena: std.mem.Allocator, one: event.Message) void {
        for (one.content) |part| switch (part) {
            .text => |text| switch (one.role) {
                .assistant => self.send(arena, .{ .agent_message = .{ .text = text } }),
                .user => self.send(arena, .{ .user_message = .{ .text = text } }),
                else => {},
            },
            .reasoning => |thinking| {
                // Only the assistant reasons, and a thought is its own variant so
                // a client can hide reasoning without hiding the answer.
                if (one.role == .assistant and thinking.text.len != 0) {
                    self.send(arena, .{ .agent_thought = .{ .text = thinking.text } });
                }
            },
            // A tool use part is reported through `tool_call`, which carries the
            // identifier a client needs; sending it twice would draw it twice.
            else => {},
        };
    }

    fn sendPlan(self: *Agent, arena: std.mem.Allocator, which: usize) void {
        const live = &self.sessions.items[which];
        var steps: std.ArrayList(updates.PlanStep) = .empty;
        for (live.plan.items) |held| {
            steps.append(arena, .{ .subject = held.subject, .status = held.status }) catch return;
        }
        self.send(arena, .{ .plan = steps.items });
    }

    /// Put one approval to the client, and remember what its answer belongs to.
    ///
    /// The options are the four the protocol has. `allow_always` and
    /// `reject_always` are offered because a client draws them, and both are
    /// answered for this call alone: a standing permission is a policy rule, and
    /// `lib/chock-policy` will not take one from a socket. See
    /// `docs/configure/policy.md` on the ratchet.
    fn askPermission(
        self: *Agent,
        arena: std.mem.Allocator,
        which: usize,
        one: event.ApprovalRequest,
        offset: u64,
    ) void {
        const turn = if (self.turn) |*held| held else return;
        // One at a time: the loop asks about one action and waits, so a second
        // request before the first is answered would be the log going wrong.
        if (turn.pending != null) return;

        const live = &self.sessions.items[which];
        const ask_id = self.next_ask;
        self.next_ask += 1;

        const raw = std.fmt.allocPrint(arena, "{d}", .{ask_id}) catch return;
        const params = std.json.Stringify.valueAlloc(arena, .{
            .sessionId = &live.id,
            .toolCall = .{
                .toolCallId = if (one.tool_call_id.len != 0) one.tool_call_id else one.action,
                .title = one.summary,
                .kind = toolKindFor("").wireName(),
                .status = "pending",
                // The whole effect goes on the call, because the request itself
                // carries no content member. Chock never puts a command string
                // here: see `lib/chock-broker`.
                .content = .{.{
                    .type = "content",
                    .content = .{ .type = "text", .text = one.detail },
                }},
            },
            .options = .{
                .{ .optionId = "allow_once", .name = "Allow once", .kind = "allow_once" },
                .{ .optionId = "allow_always", .name = "Allow for this turn", .kind = "allow_always" },
                .{ .optionId = "reject_once", .name = "Refuse", .kind = "reject_once" },
            },
        }, .{}) catch return;

        const body = jsonrpc.requestBody(arena, .{ .raw = raw }, self.clientMethod(.request_permission), params) catch return;
        jsonrpc.writeFrame(arena, self.out, body) catch {
            self.stopping = true;
            return;
        };

        turn.pending = .{
            .ask = self.gpa.dupe(u8, raw) catch return,
            .request_id = offset,
        };
    }

    /// Answer the `session/prompt` that is waiting, and clear the turn.
    fn endTurn(self: *Agent, reason: chock_acp.common.StopReason) void {
        var state = std.heap.ArenaAllocator.init(self.gpa);
        defer state.deinit();
        const arena = state.allocator();

        const turn = self.turn orelse return;

        // A cancel that was sent wins over what the log says. A turn can finish
        // between the signal and the handler, and telling the client `end_turn`
        // for a turn it cancelled would make its own state wrong.
        const said = if (turn.cancelled) chock_acp.common.StopReason.cancelled else reason;

        if (turn.pending) |pending| {
            // Nobody answered, and the protocol says a client marks a pending
            // request cancelled when a turn ends. The daemon already read the
            // silence as a refusal.
            self.gpa.free(pending.ask);
        }

        const result = std.json.Stringify.valueAlloc(arena, .{
            .stopReason = said.wireName(),
        }, .{}) catch return;
        self.answer(arena, turn.request, result);

        self.gpa.free(turn.request.raw);
        self.turn = null;
    }

    /// Everything a session's log already holds, as updates. Null when it worked.
    fn replay(self: *Agent, arena: std.mem.Allocator, which: usize) ?[]const u8 {
        const live = &self.sessions.items[which];

        const stream = self.daemon.connect(self.io) catch {
            return "the daemon could not be reached";
        };
        defer stream.close(self.io);

        var read_buffer: [256 * 1024]u8 = undefined;
        var stream_reader = stream.reader(self.io, &read_buffer);
        var write_buffer: [8 * 1024]u8 = undefined;
        var stream_writer = stream.writer(self.io, &write_buffer);

        // A replay is a turn for the length of it, so `send` has somewhere to
        // read the session from. It answers nothing: there is no prompt waiting.
        const held = self.turn;
        self.turn = .{ .request = .{ .raw = "null" }, .session = which };
        defer self.turn = held;

        const Replay = struct {
            agent: *Agent,
            which: usize,
            failed: ?[]const u8 = null,

            fn take(self_take: *@This(), reply: control.Reply) anyerror!bool {
                switch (reply) {
                    .record => |one| {
                        var state = std.heap.ArenaAllocator.init(self_take.agent.gpa);
                        defer state.deinit();
                        const each = state.allocator();
                        const parsed = std.json.parseFromSlice(event.Envelope, each, one.payload, .{
                            .ignore_unknown_fields = true,
                        }) catch return true;
                        // An end in the replay is the end of a past turn, not of
                        // this load, so it is not translated.
                        if (parsed.value.event == .session_end) return true;
                        self_take.agent.translate(each, self_take.which, parsed.value.event, one.id);
                        const live_now = &self_take.agent.sessions.items[self_take.which];
                        if (one.id > live_now.seen) live_now.seen = one.id;
                    },
                    .failed => |text| {
                        self_take.failed = text;
                        return false;
                    },
                    .ok => {},
                }
                return true;
            }
        };

        var replaying = Replay{ .agent = self, .which = which };
        var said: control.Handshake = .{ .unreadable = "" };
        control.exchange(
            &stream_reader.interface,
            &stream_writer.interface,
            .{ .read = .{ .session = &live.id, .after = 0 } },
            &said,
            &replaying,
            Replay.take,
        ) catch {
            return "that session could not be read";
        };
        _ = arena;
        return replaying.failed;
    }
};

/// What this agent declares it can do, in the version that was agreed.
///
/// Version 1 and version 2 shape this differently: version 1 has four capability
/// objects beside each other, and version 2 has two. What is declared is the same
/// either way, and neither one declares a file or terminal capability, because
/// those are the client's and Chock calls neither.
fn capabilities(arena: std.mem.Allocator, version: chock_acp.Version) ![]u8 {
    const info = .{ .name = agent_name, .version = @import("chock-version").text };

    // A capability with no settings of its own is an empty JSON object. An empty
    // anonymous literal is a tuple, which serializes as `[]`, and a real client
    // reads that as neither present nor absent.
    const Present = struct {};

    return switch (version) {
        .v1 => std.json.Stringify.valueAlloc(arena, .{
            .protocolVersion = chock_acp.v1.protocol_version,
            .agentCapabilities = .{
                .loadSession = true,
                .promptCapabilities = .{
                    .image = true,
                    // A resource a client embeds arrives as text in the prompt,
                    // which is what Chock reads.
                    .embeddedContext = true,
                    // Nothing in Chock reads audio.
                    .audio = false,
                },
                // A server is named in the project's own `chock.zon`, not by a
                // client, so neither transport is offered here. See `mcp_refusal`.
                .mcpCapabilities = .{ .http = false, .sse = false },
                .sessionCapabilities = .{
                    .list = Present{},
                    .@"resume" = Present{},
                    .close = Present{},
                },
            },
            .agentInfo = info,
        }, .{}),
        .v2 => std.json.Stringify.valueAlloc(arena, .{
            .protocolVersion = chock_acp.v2.protocol_version,
            .capabilities = .{
                .session = .{
                    .list = Present{},
                    .@"resume" = Present{},
                    .close = Present{},
                },
            },
            .info = info,
        }, .{}),
    };
}

/// Why an MCP server a client names is refused rather than run.
///
/// An editor naming a server is an editor asking Chock to run a program, inside
/// the sandbox, with the project's own policy over it. Chock reads its servers
/// from the project's `chock.zon`, which the workspace binds back read only so the
/// agent cannot edit it. Taking a list from a socket would put that decision
/// where nobody reviewed it.
const mcp_refusal = "chock does not take an MCP server from a client. A server is named in the " ++
    "project's own chock.zon, where it is reviewable and the agent cannot change it. Start this " ++
    "session again with no mcpServers, and add the server to that file instead.";

fn namesMcpServers(arena: std.mem.Allocator, params: []const u8) bool {
    if (params.len == 0) return false;
    const parsed = std.json.parseFromSlice(std.json.Value, arena, params, .{}) catch return false;
    const object = switch (parsed.value) {
        .object => |one| one,
        else => return false,
    };
    return switch (object.get("mcpServers") orelse return false) {
        .array => |list| list.items.len != 0,
        else => false,
    };
}

fn stringField(arena: std.mem.Allocator, params: []const u8, name: []const u8) ?[]const u8 {
    if (params.len == 0) return null;
    const parsed = std.json.parseFromSlice(std.json.Value, arena, params, .{}) catch return null;
    const object = switch (parsed.value) {
        .object => |one| one,
        else => return null,
    };
    return switch (object.get(name) orelse return null) {
        .string => |text| text,
        else => null,
    };
}

fn numberField(arena: std.mem.Allocator, params: []const u8, name: []const u8) ?i64 {
    if (params.len == 0) return null;
    const parsed = std.json.parseFromSlice(std.json.Value, arena, params, .{}) catch return null;
    const object = switch (parsed.value) {
        .object => |one| one,
        else => return null,
    };
    return switch (object.get(name) orelse return null) {
        .integer => |number| number,
        else => null,
    };
}

/// The session identifier out of one row of the daemon's `list`.
///
/// A listing row is a summary of a session and not a log envelope, so the
/// identifier is `id` rather than `session`. Reading the envelope's name here
/// found nothing and listed no sessions at all.
fn listedSessionIn(arena: std.mem.Allocator, payload: []const u8) ?[]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, arena, payload, .{}) catch return null;
    const object = switch (parsed.value) {
        .object => |one| one,
        else => return null,
    };
    return switch (object.get("id") orelse return null) {
        .string => |text| if (session_paths.isValidId(text)) text else null,
        else => null,
    };
}

/// Every text block of a prompt, joined.
///
/// A prompt is a list of content blocks. Chock's own message is text, so a text
/// block and the text of a resource are read and an image block is not: Chock
/// reads an image a tool gives it, and a prompt is not a tool result.
fn promptText(arena: std.mem.Allocator, params: []const u8) !?[]const u8 {
    if (params.len == 0) return null;
    const parsed = try std.json.parseFromSlice(std.json.Value, arena, params, .{});
    const object = switch (parsed.value) {
        .object => |one| one,
        else => return null,
    };
    const blocks = switch (object.get("prompt") orelse return null) {
        .array => |list| list,
        else => return null,
    };

    var joined: std.ArrayList(u8) = .empty;
    for (blocks.items) |block| {
        const each = switch (block) {
            .object => |one| one,
            else => continue,
        };
        const kind = switch (each.get("type") orelse continue) {
            .string => |text| text,
            else => continue,
        };
        if (!std.mem.eql(u8, kind, "text") and !std.mem.eql(u8, kind, "resource")) continue;
        const text = switch (each.get("text") orelse continue) {
            .string => |held| held,
            else => continue,
        };
        if (joined.items.len != 0) try joined.append(arena, '\n');
        try joined.appendSlice(arena, text);
    }
    if (joined.items.len == 0) return null;
    return joined.items;
}

/// What a client should draw a tool call as.
///
/// Chock's own tools, by name. A tool this does not know is `other`, which is
/// what the protocol has the value for, and an MCP tool or a plugin tool is one of
/// those: its name is the server's to choose and guessing a kind from it would be
/// drawing a shape nobody declared.
fn toolKindFor(tool: []const u8) chock_acp.common.ToolKind {
    const known = [_]struct { []const u8, chock_acp.common.ToolKind }{
        .{ "read_file", .read },
        .{ "list_directory", .read },
        .{ "read_image", .read },
        .{ "write_file", .edit },
        .{ "edit_file", .edit },
        .{ "apply_patch", .edit },
        .{ "run_command", .execute },
        .{ "nix_build", .execute },
        .{ "nix_eval", .execute },
        .{ "search_files", .search },
        .{ "web_search", .search },
        .{ "web_fetch", .fetch },
        .{ "diagnostics", .think },
    };
    for (known) |pair| {
        if (std.mem.eql(u8, pair[0], tool)) return pair[1];
    }
    return .other;
}

/// What a person reads for a tool call. The tool's name, and the first argument
/// worth showing when there is one.
fn titleFor(arena: std.mem.Allocator, one: event.ToolCall) ![]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, arena, one.arguments, .{}) catch
        return one.tool;
    const object = switch (parsed.value) {
        .object => |held| held,
        else => return one.tool,
    };
    for ([_][]const u8{ "path", "query", "url", "installable" }) |name| {
        switch (object.get(name) orelse continue) {
            .string => |text| return std.fmt.allocPrint(arena, "{s} {s}", .{ one.tool, text }),
            else => {},
        }
    }
    if (object.get("argv")) |held| switch (held) {
        .array => |list| if (list.items.len != 0) switch (list.items[0]) {
            .string => |first| return std.fmt.allocPrint(arena, "{s} {s}", .{ one.tool, first }),
            else => {},
        },
        else => {},
    };
    return one.tool;
}

fn stepStatusFor(status: event.PlanStatus) updates.StepStatus {
    return switch (status) {
        .pending => .pending,
        .in_progress => .in_progress,
        .done => .done,
        .abandoned => .abandoned,
        // A status this version does not know is not progress, and reading it as
        // done would tell a client a step finished that may not have.
        .unknown => .pending,
    };
}

/// Why a turn ended, in the five words the protocol has.
///
/// Chock has eleven reasons and ACP has five, so three of Chock's map onto
/// `refusal`, which the protocol defines as the agent declining to continue. That
/// is what a budget cap and a stall are: Chock declining. Calling either
/// `end_turn` would say the model finished, which it did not.
fn stopReasonFor(reason: event.SessionEndReason) chock_acp.common.StopReason {
    return switch (reason) {
        .finished, .handed_over, .empty_response => .end_turn,
        .canceled_by_user => .cancelled,
        .turn_limit => .max_turn_requests,
        .refused_by_model, .budget_reached, .no_progress, .rate_limited, .errored => .refusal,
        // A reason this version does not know stopped the turn for a reason this
        // cannot name, which is nearer declining than finishing.
        .unknown => .refusal,
    };
}

/// The methods this agent answers, folded across both versions.
///
/// Each version spells some of these differently and version 2 renamed three, so
/// `fromWireName` reads the spelling of whichever version was agreed. Nothing
/// below it branches on a version to know what it was asked.
const Method = enum {
    initialize,
    authenticate,
    session_new,
    session_load,
    session_prompt,
    session_cancel,
    session_list,
    session_delete,
    session_close,

    fn fromWireName(version: ?chock_acp.Version, name: []const u8) ?Method {
        // Before `initialize` there is no version, and the only thing that may be
        // asked is `initialize`, which both versions spell alike.
        const which = version orelse {
            return if (std.mem.eql(u8, name, "initialize")) .initialize else null;
        };
        return switch (which) {
            .v1 => switch (chock_acp.v1.Method.fromWireName(name) orelse return null) {
                .initialize => .initialize,
                .authenticate => .authenticate,
                .session_new => .session_new,
                .session_load, .session_resume => .session_load,
                .session_prompt => .session_prompt,
                .session_cancel => .session_cancel,
                .session_list => .session_list,
                .session_delete => .session_delete,
                .session_close => .session_close,
                else => null,
            },
            .v2 => switch (chock_acp.v2.Method.fromWireName(name) orelse return null) {
                .initialize => .initialize,
                .auth_login => .authenticate,
                .session_new => .session_new,
                // Version 2 renamed `session/load` to `session/resume`.
                .session_resume => .session_load,
                .session_prompt => .session_prompt,
                .session_cancel => .session_cancel,
                .session_list => .session_list,
                .session_delete => .session_delete,
                .session_close => .session_close,
                else => null,
            },
        };
    }
};

/// Reads standard input and pushes each line onto the queue. Its own thread,
/// because the main thread has to keep answering while a turn runs.
const InputReader = struct {
    agent: *Agent,

    fn run(self: *InputReader) void {
        const agent = self.agent;
        var buffer: [max_line_bytes]u8 = undefined;
        var file = std.Io.File.stdin().readerStreaming(agent.io, &buffer);

        while (true) {
            const line = (file.interface.takeDelimiter('\n') catch break) orelse break;
            const trimmed = std.mem.trimEnd(u8, line, "\r");
            if (trimmed.len == 0) continue;
            const owned = agent.gpa.dupe(u8, trimmed) catch break;
            agent.queue.push(.{ .line = owned });
        }
        agent.queue.push(.input_closed);
    }
};

const testing = std.testing;

test "a method is read in the spelling of the version that was agreed" {
    // Before `initialize` there is no version, and only `initialize` is answered.
    try testing.expectEqual(Method.initialize, Method.fromWireName(null, "initialize").?);
    try testing.expectEqual(@as(?Method, null), Method.fromWireName(null, "session/new"));

    // Version 1 spells these three one way.
    try testing.expectEqual(Method.authenticate, Method.fromWireName(.v1, "authenticate").?);
    try testing.expectEqual(Method.session_load, Method.fromWireName(.v1, "session/load").?);

    // Version 2 renamed all three, and the old spellings reach nothing there. A
    // client on version 2 that sent `session/load` is told the method does not
    // exist rather than served the method it meant.
    try testing.expectEqual(Method.authenticate, Method.fromWireName(.v2, "auth/login").?);
    try testing.expectEqual(Method.session_load, Method.fromWireName(.v2, "session/resume").?);
    try testing.expectEqual(@as(?Method, null), Method.fromWireName(.v2, "authenticate"));
    try testing.expectEqual(@as(?Method, null), Method.fromWireName(.v2, "session/load"));
    try testing.expectEqual(@as(?Method, null), Method.fromWireName(.v2, "session/set_mode"));

    // And a client method is never answered as though this side implemented it.
    for ([_][]const u8{ "session/update", "session/request_permission", "fs/read_text_file" }) |theirs| {
        try testing.expectEqual(@as(?Method, null), Method.fromWireName(.v1, theirs));
    }
}

test "every reason a session can end has a stop reason, and none of them lies" {
    // Eleven of Chock's reasons map onto five of the protocol's, so this is the
    // test that no mapping claims the model finished when it did not.
    const finished = [_]event.SessionEndReason{ .finished, .handed_over, .empty_response };
    for (finished) |reason| try testing.expectEqual(
        chock_acp.common.StopReason.end_turn,
        stopReasonFor(reason),
    );

    try testing.expectEqual(chock_acp.common.StopReason.cancelled, stopReasonFor(.canceled_by_user));
    try testing.expectEqual(chock_acp.common.StopReason.max_turn_requests, stopReasonFor(.turn_limit));

    // Chock declining to carry on. The protocol has no word for a budget cap or
    // a stall, and `refusal` is what it calls an agent that will not continue.
    const declined = [_]event.SessionEndReason{
        .refused_by_model,                                 .budget_reached, .no_progress, .rate_limited, .errored,
        .{ .unknown = "something a later version knows" },
    };
    for (declined) |reason| try testing.expectEqual(
        chock_acp.common.StopReason.refusal,
        stopReasonFor(reason),
    );

    // Nothing maps onto `max_tokens`: Chock compacts rather than running out, so
    // claiming it would describe a thing that does not happen.
    inline for (@typeInfo(event.SessionEndReason).@"union".fields) |field| {
        const reason: event.SessionEndReason = if (field.type == void)
            @unionInit(event.SessionEndReason, field.name, {})
        else
            continue;
        try testing.expect(stopReasonFor(reason) != .max_tokens);
    }
}

test "a tool is drawn as what it does, and one nobody knows is other" {
    try testing.expectEqual(chock_acp.common.ToolKind.execute, toolKindFor("run_command"));
    try testing.expectEqual(chock_acp.common.ToolKind.read, toolKindFor("read_file"));
    try testing.expectEqual(chock_acp.common.ToolKind.edit, toolKindFor("write_file"));
    try testing.expectEqual(chock_acp.common.ToolKind.search, toolKindFor("web_search"));
    try testing.expectEqual(chock_acp.common.ToolKind.fetch, toolKindFor("web_fetch"));

    // An MCP tool's name is the server's to choose, so guessing a kind from it
    // would draw a shape nobody declared.
    try testing.expectEqual(chock_acp.common.ToolKind.other, toolKindFor("create_issue"));
    try testing.expectEqual(chock_acp.common.ToolKind.other, toolKindFor(""));
}

test "an abandoned step stays abandoned, and an unknown status is not progress" {
    try testing.expectEqual(updates.StepStatus.done, stepStatusFor(.done));
    try testing.expectEqual(updates.StepStatus.abandoned, stepStatusFor(.abandoned));
    try testing.expectEqual(updates.StepStatus.in_progress, stepStatusFor(.in_progress));
    // Reading a status this version does not know as done would tell a client a
    // step finished that may not have.
    try testing.expectEqual(updates.StepStatus.pending, stepStatusFor(.{ .unknown = "later" }));
}

test "a prompt's text blocks are read and its other blocks are not" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    const said = (try promptText(arena,
        \\{"sessionId":"s","prompt":[
        \\  {"type":"text","text":"first"},
        \\  {"type":"image","data":"...","mimeType":"image/png"},
        \\  {"type":"text","text":"second"}
        \\]}
    )).?;
    try testing.expectEqualStrings("first\nsecond", said);

    // A prompt with nothing readable is null rather than an empty message, so the
    // call is refused instead of starting a turn that says nothing.
    try testing.expectEqual(
        @as(?[]const u8, null),
        try promptText(arena, "{\"prompt\":[{\"type\":\"image\",\"data\":\"x\"}]}"),
    );
    try testing.expectEqual(@as(?[]const u8, null), try promptText(arena, "{}"));
    try testing.expectEqual(@as(?[]const u8, null), try promptText(arena, ""));
}

test "an mcp server a client names is noticed, and an empty list is not one" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    try testing.expect(namesMcpServers(arena,
        \\{"cwd":"/p","mcpServers":[{"name":"x","command":"/bin/true","args":[],"env":[]}]}
    ));

    // An empty list is a client saying it wants none, which is the ordinary case
    // and must not be refused.
    try testing.expect(!namesMcpServers(arena, "{\"cwd\":\"/p\",\"mcpServers\":[]}"));
    try testing.expect(!namesMcpServers(arena, "{\"cwd\":\"/p\"}"));
    try testing.expect(!namesMcpServers(arena, ""));
}

test "the refusal for an mcp server says where a server is named instead" {
    // A refusal that did not say where to put it would leave somebody stuck.
    try testing.expect(std.mem.indexOf(u8, mcp_refusal, "chock.zon") != null);
}

test "a capability answer is the shape of the version it was asked in" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    const one = try capabilities(arena, .v1);
    const one_parsed = try std.json.parseFromSlice(std.json.Value, arena, one, .{});
    try testing.expectEqual(@as(i64, 1), one_parsed.value.object.get("protocolVersion").?.integer);
    const v1_caps = one_parsed.value.object.get("agentCapabilities").?.object;
    try testing.expect(v1_caps.get("loadSession").?.bool);
    // The client's own methods are never declared here: Chock calls neither, and
    // a capability is what a side says about itself.
    try testing.expect(v1_caps.get("fs") == null);
    try testing.expect(v1_caps.get("terminal") == null);
    // A capability with no settings is an empty object. A real client refused an
    // empty array here, which is what an empty anonymous literal would serialize as.
    try testing.expectEqual(
        @as(usize, 0),
        v1_caps.get("sessionCapabilities").?.object.get("list").?.object.count(),
    );

    const two = try capabilities(arena, .v2);
    const two_parsed = try std.json.parseFromSlice(std.json.Value, arena, two, .{});
    try testing.expectEqual(@as(i64, 2), two_parsed.value.object.get("protocolVersion").?.integer);
    // Version 2 renamed both of the members version 1 answers with, and requires
    // the info rather than leaving it optional.
    try testing.expect(two_parsed.value.object.get("capabilities") != null);
    try testing.expect(two_parsed.value.object.get("info") != null);
    try testing.expect(two_parsed.value.object.get("agentCapabilities") == null);
    try testing.expect(two_parsed.value.object.get("agentInfo") == null);
}

test "the version answered is the newest both sides speak" {
    // The whole of the negotiation this command does, and the reason a released
    // client is never pushed onto the alpha.
    try testing.expectEqual(chock_acp.Version.v1, chock_acp.negotiate(1).?);
    try testing.expectEqual(chock_acp.Version.v2, chock_acp.negotiate(2).?);
    try testing.expectEqual(@as(?chock_acp.Version, null), chock_acp.negotiate(0));
}

test "only a selected allow option permits, and anything unreadable refuses" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    // The two that permit.
    try testing.expect(Agent.permittedBy(arena,
        \\{"outcome":{"outcome":"selected","optionId":"allow_once"}}
    ));
    try testing.expect(Agent.permittedBy(arena,
        \\{"outcome":{"outcome":"selected","optionId":"allow_always"}}
    ));

    // The two that refuse.
    try testing.expect(!Agent.permittedBy(arena,
        \\{"outcome":{"outcome":"selected","optionId":"reject_once"}}
    ));
    try testing.expect(!Agent.permittedBy(arena,
        \\{"outcome":{"outcome":"selected","optionId":"reject_always"}}
    ));

    // A client saying nobody answered. `lib/chock-policy` reads an unanswered
    // question as deny, and this is the same reading.
    try testing.expect(!Agent.permittedBy(arena, "{\"outcome\":{\"outcome\":\"cancelled\"}}"));

    // Everything unreadable refuses. This is the direction that matters: a reply
    // this cannot parse must never open an action nobody approved.
    for ([_][]const u8{
        "",
        "null",
        "{}",
        "[]",
        "not json",
        "{\"outcome\":null}",
        "{\"outcome\":{}}",
        "{\"outcome\":{\"outcome\":\"selected\"}}",
        "{\"outcome\":{\"outcome\":\"selected\",\"optionId\":\"something-else\"}}",
        "{\"outcome\":{\"outcome\":\"selected\",\"optionId\":42}}",
        "{\"outcome\":{\"optionId\":\"allow_once\"}}",
        "{\"optionId\":\"allow_once\"}",
    }) |bad| {
        try testing.expect(!Agent.permittedBy(arena, bad));
    }
}

test "the option identifiers offered are the kinds the protocol names" {
    // `permittedBy` reads the identifier as a kind, so an option offered under
    // a name that is not one would be refused however the person answered.
    for ([_][]const u8{ "allow_once", "allow_always", "reject_once" }) |offered| {
        try testing.expect(chock_acp.common.PermissionKind.fromWireName(offered) != null);
    }
}

test "a listing row is read by the name a summary uses, not a log envelope's" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    // What `chock daemon`'s `list` really answers with. The first draft looked
    // for `session`, which is the log envelope's name, and listed nothing.
    const row =
        \\{"id":"01M3F8DT9Z5D43FPM36F1G3556","started_ms":1790439778623,"model":"a-model",
        \\ "live":"idle","end":"errored","turns":1}
    ;
    try testing.expectEqualStrings("01M3F8DT9Z5D43FPM36F1G3556", listedSessionIn(arena, row).?);

    // A row with no identifier, or one that is not an identifier, is skipped
    // rather than listed as a session nobody can open.
    try testing.expectEqual(@as(?[]const u8, null), listedSessionIn(arena, "{\"id\":\"nonsense\"}"));
    try testing.expectEqual(@as(?[]const u8, null), listedSessionIn(arena, "{\"id\":7}"));
    try testing.expectEqual(@as(?[]const u8, null), listedSessionIn(arena, "{}"));
    try testing.expectEqual(@as(?[]const u8, null), listedSessionIn(arena, "not json"));
}
