//! `chock acp`: an editor drives Chock over the agent client protocol.

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

const agent_name = "chock";

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
    var here = try std.Io.Dir.cwd().openDir(io, ".", .{});
    defer here.close(io);
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try here.realPath(io, &buffer);
    return arena.dupe(u8, buffer[0..length]);
}

const Item = union(enum) {
    line: []u8,
    record: Record,
    watch_ended,
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

const Live = struct {
    id: [session_paths.id_length]u8,
    project: []u8,
    seen: u64 = 0,
    window: ?u64 = null,
    plan: std.ArrayList(Step) = .empty,
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

const Answered = struct {
    ok: ?[]const u8 = null,
    failed: ?[]const u8 = null,
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
    project: []const u8,

    version: ?chock_acp.Version = null,
    sessions: std.ArrayList(Live) = .empty,
    queue: Queue = undefined,
    turn: ?Turn = null,
    out: *std.Io.Writer = undefined,
    next_ask: u64 = 1,
    stopping: bool = false,

    const Turn = struct {
        request: jsonrpc.Id,
        session: usize,
        pending: ?Pending = null,
        cancelled: bool = false,

        const Pending = struct {
            ask: []u8,
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

    fn handleLine(self: *Agent, text: []const u8) void {
        var state = std.heap.ArenaAllocator.init(self.gpa);
        defer state.deinit();
        const arena = state.allocator();

        const any = jsonrpc.parseAny(arena, text) catch |err| {
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

    fn handleReply(self: *Agent, arena: std.mem.Allocator, reply: jsonrpc.Reply) void {
        // Never &(self.turn orelse ...): that form takes the address of a copy, so a write to it would be lost.
        const turn = if (self.turn) |*one| one else return;
        const pending = turn.pending orelse return;
        if (!std.mem.eql(u8, pending.ask, reply.id.raw)) return;

        const permitted = if (reply.failed()) false else permittedBy(arena, reply.result);

        self.tellDaemon(arena, pending.request_id, permitted);

        self.gpa.free(pending.ask);
        turn.pending = null;
    }

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
        const kind = chock_acp.common.PermissionKind.fromWireName(chosen) orelse return false;
        return kind.permits();
    }

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

        const answered = self.replay(arena, known);
        if (answered) |text| {
            self.fail(arena, id, .resource_not_found, text);
            return;
        }
        self.answer(arena, id, "");
    }

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
        if (self.turn) |*one| {
            if (one.session > known) one.session -= 1;
        }
        self.answer(arena, id, "");
    }

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
                const used = one.input_tokens +
                    one.cache_creation_input_tokens + one.cache_read_input_tokens;
                const size = live.window orelse return;
                self.send(arena, .{
                    .usage = .{
                        .used = used,
                        .size = size,
                        .cost = switch (one.cost) {
                            .known => |money| money.value,
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
                if (one.role == .assistant and thinking.text.len != 0) {
                    self.send(arena, .{ .agent_thought = .{ .text = thinking.text } });
                }
            },
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

    fn askPermission(
        self: *Agent,
        arena: std.mem.Allocator,
        which: usize,
        one: event.ApprovalRequest,
        offset: u64,
    ) void {
        const turn = if (self.turn) |*held| held else return;
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

    fn endTurn(self: *Agent, reason: chock_acp.common.StopReason) void {
        var state = std.heap.ArenaAllocator.init(self.gpa);
        defer state.deinit();
        const arena = state.allocator();

        const turn = self.turn orelse return;

        // A cancel that was sent wins over what the log says: the turn can finish between the signal and the handler.
        const said = if (turn.cancelled) chock_acp.common.StopReason.cancelled else reason;

        if (turn.pending) |pending| {
            self.gpa.free(pending.ask);
        }

        const result = std.json.Stringify.valueAlloc(arena, .{
            .stopReason = said.wireName(),
        }, .{}) catch return;
        self.answer(arena, turn.request, result);

        self.gpa.free(turn.request.raw);
        self.turn = null;
    }

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

fn capabilities(arena: std.mem.Allocator, version: chock_acp.Version) ![]u8 {
    const info = .{ .name = agent_name, .version = @import("chock-version").text };

    const Present = struct {};

    return switch (version) {
        .v1 => std.json.Stringify.valueAlloc(arena, .{
            .protocolVersion = chock_acp.v1.protocol_version,
            .agentCapabilities = .{
                .loadSession = true,
                .promptCapabilities = .{
                    .image = true,
                    .embeddedContext = true,
                    .audio = false,
                },
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
        .unknown => .pending,
    };
}

fn stopReasonFor(reason: event.SessionEndReason) chock_acp.common.StopReason {
    return switch (reason) {
        .finished, .handed_over, .empty_response => .end_turn,
        .canceled_by_user => .cancelled,
        .turn_limit => .max_turn_requests,
        .refused_by_model, .budget_reached, .no_progress, .rate_limited, .errored => .refusal,
        .unknown => .refusal,
    };
}

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
    try testing.expectEqual(Method.initialize, Method.fromWireName(null, "initialize").?);
    try testing.expectEqual(@as(?Method, null), Method.fromWireName(null, "session/new"));

    try testing.expectEqual(Method.authenticate, Method.fromWireName(.v1, "authenticate").?);
    try testing.expectEqual(Method.session_load, Method.fromWireName(.v1, "session/load").?);

    try testing.expectEqual(Method.authenticate, Method.fromWireName(.v2, "auth/login").?);
    try testing.expectEqual(Method.session_load, Method.fromWireName(.v2, "session/resume").?);
    try testing.expectEqual(@as(?Method, null), Method.fromWireName(.v2, "authenticate"));
    try testing.expectEqual(@as(?Method, null), Method.fromWireName(.v2, "session/load"));
    try testing.expectEqual(@as(?Method, null), Method.fromWireName(.v2, "session/set_mode"));

    for ([_][]const u8{ "session/update", "session/request_permission", "fs/read_text_file" }) |theirs| {
        try testing.expectEqual(@as(?Method, null), Method.fromWireName(.v1, theirs));
    }
}

test "every reason a session can end has a stop reason, and none of them lies" {
    const finished = [_]event.SessionEndReason{ .finished, .handed_over, .empty_response };
    for (finished) |reason| try testing.expectEqual(
        chock_acp.common.StopReason.end_turn,
        stopReasonFor(reason),
    );

    try testing.expectEqual(chock_acp.common.StopReason.cancelled, stopReasonFor(.canceled_by_user));
    try testing.expectEqual(chock_acp.common.StopReason.max_turn_requests, stopReasonFor(.turn_limit));

    const declined = [_]event.SessionEndReason{
        .refused_by_model,                                 .budget_reached, .no_progress, .rate_limited, .errored,
        .{ .unknown = "something a later version knows" },
    };
    for (declined) |reason| try testing.expectEqual(
        chock_acp.common.StopReason.refusal,
        stopReasonFor(reason),
    );

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

    try testing.expectEqual(chock_acp.common.ToolKind.other, toolKindFor("create_issue"));
    try testing.expectEqual(chock_acp.common.ToolKind.other, toolKindFor(""));
}

test "an abandoned step stays abandoned, and an unknown status is not progress" {
    try testing.expectEqual(updates.StepStatus.done, stepStatusFor(.done));
    try testing.expectEqual(updates.StepStatus.abandoned, stepStatusFor(.abandoned));
    try testing.expectEqual(updates.StepStatus.in_progress, stepStatusFor(.in_progress));
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

    try testing.expect(!namesMcpServers(arena, "{\"cwd\":\"/p\",\"mcpServers\":[]}"));
    try testing.expect(!namesMcpServers(arena, "{\"cwd\":\"/p\"}"));
    try testing.expect(!namesMcpServers(arena, ""));
}

test "the refusal for an mcp server says where a server is named instead" {
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
    try testing.expect(v1_caps.get("fs") == null);
    try testing.expect(v1_caps.get("terminal") == null);
    try testing.expectEqual(
        @as(usize, 0),
        v1_caps.get("sessionCapabilities").?.object.get("list").?.object.count(),
    );

    const two = try capabilities(arena, .v2);
    const two_parsed = try std.json.parseFromSlice(std.json.Value, arena, two, .{});
    try testing.expectEqual(@as(i64, 2), two_parsed.value.object.get("protocolVersion").?.integer);
    try testing.expect(two_parsed.value.object.get("capabilities") != null);
    try testing.expect(two_parsed.value.object.get("info") != null);
    try testing.expect(two_parsed.value.object.get("agentCapabilities") == null);
    try testing.expect(two_parsed.value.object.get("agentInfo") == null);
}

test "the version answered is the newest both sides speak" {
    try testing.expectEqual(chock_acp.Version.v1, chock_acp.negotiate(1).?);
    try testing.expectEqual(chock_acp.Version.v2, chock_acp.negotiate(2).?);
    try testing.expectEqual(@as(?chock_acp.Version, null), chock_acp.negotiate(0));
}

test "only a selected allow option permits, and anything unreadable refuses" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    try testing.expect(Agent.permittedBy(arena,
        \\{"outcome":{"outcome":"selected","optionId":"allow_once"}}
    ));
    try testing.expect(Agent.permittedBy(arena,
        \\{"outcome":{"outcome":"selected","optionId":"allow_always"}}
    ));

    try testing.expect(!Agent.permittedBy(arena,
        \\{"outcome":{"outcome":"selected","optionId":"reject_once"}}
    ));
    try testing.expect(!Agent.permittedBy(arena,
        \\{"outcome":{"outcome":"selected","optionId":"reject_always"}}
    ));

    try testing.expect(!Agent.permittedBy(arena, "{\"outcome\":{\"outcome\":\"cancelled\"}}"));

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
    for ([_][]const u8{ "allow_once", "allow_always", "reject_once" }) |offered| {
        try testing.expect(chock_acp.common.PermissionKind.fromWireName(offered) != null);
    }
}

test "a listing row is read by the name a summary uses, not a log envelope's" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();

    const row =
        \\{"id":"01M3F8DT9Z5D43FPM36F1G3556","started_ms":1790439778623,"model":"a-model",
        \\ "live":"idle","end":"errored","turns":1}
    ;
    try testing.expectEqualStrings("01M3F8DT9Z5D43FPM36F1G3556", listedSessionIn(arena, row).?);

    try testing.expectEqual(@as(?[]const u8, null), listedSessionIn(arena, "{\"id\":\"nonsense\"}"));
    try testing.expectEqual(@as(?[]const u8, null), listedSessionIn(arena, "{\"id\":7}"));
    try testing.expectEqual(@as(?[]const u8, null), listedSessionIn(arena, "{}"));
    try testing.expectEqual(@as(?[]const u8, null), listedSessionIn(arena, "not json"));
}
