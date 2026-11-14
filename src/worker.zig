//! A client-hosted executor for a session registered with the daemon.

const std = @import("std");
const chock_proto = @import("chock-proto");
const run_cmd = @import("run.zig");
const session_paths = @import("session.zig");
const worker_http = @import("worker_http.zig");
const interrupt = @import("interrupt.zig");
const tty = @import("tty.zig");
const ask = @import("chock-core").ask;

const event = chock_proto.event;
const Usage =
    \\Usage: chock worker --server <https://daemon.example> --session <id> [--project <directory>] [--once]
    \\
    \\Runs a client-placed session on this machine. The worker token is read
    \\from CHOCK_WORKER_TOKEN; it is never accepted as a command-line argument.
    \\Without --once, the worker waits for prompts and renews its host lease.
    \\
;

const Options = struct {
    server: ?[]const u8 = null,
    session: ?[]const u8 = null,
    project: ?[]const u8 = null,
    once: bool = false,
};

pub fn main(init: std.process.Init, exe_path: []const u8, args: []const []const u8) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const selected = parse(arena, args) catch |err| {
        if (err == error.Help) return 0;
        tty.out(.err, "{s}", .{Usage});
        return 2;
    };
    const server_arg = selected.server orelse {
        tty.out(.err, "chock worker: --server is required.\n", .{});
        return 2;
    };
    const session_arg = selected.session orelse {
        tty.out(.err, "chock worker: --session is required.\n", .{});
        return 2;
    };
    if (!session_paths.isValidId(session_arg)) {
        tty.out(.err, "chock worker: the session identifier is invalid.\n", .{});
        return 2;
    }
    const token_value = init.environ_map.get("CHOCK_WORKER_TOKEN") orelse {
        tty.out(.err, "chock worker: set CHOCK_WORKER_TOKEN to the scoped credential from the session Share screen.\n", .{});
        return 2;
    };
    const token = try init.gpa.dupe(u8, token_value);
    defer {
        std.crypto.secureZero(u8, token);
        init.gpa.free(token);
    }
    // The loop resets the per-command arena; keep these long-lived inputs in
    // the GPA for the lifetime of the worker.
    const server = try init.gpa.dupe(u8, server_arg);
    defer init.gpa.free(server);
    const session = try init.gpa.dupe(u8, session_arg);
    defer init.gpa.free(session);
    const project = try init.gpa.dupe(u8, selected.project orelse ".");
    defer init.gpa.free(project);

    var host_id: [36]u8 = undefined;
    try makeHostId(init.io, &host_id);
    const client: worker_http.Client = .{
        .gpa = init.gpa,
        .io = init.io,
        .origin = server,
        .token = token,
    };
    var active_generation: ?u64 = null;
    defer if (active_generation) |generation| {
        var release_arena = std.heap.ArenaAllocator.init(init.gpa);
        defer release_arena.deinit();
        client.release(release_arena.allocator(), session, &host_id, generation) catch
            tty.out(.warn, "chock worker: the lease could not be released cleanly; it will expire automatically.\n", .{});
    };
    var env = try init.minimal.environ.createMap(arena);
    var paths = try session_paths.pathsFor(init.gpa, &env, project, session);
    defer paths.deinit();
    try session_paths.create(init.io, paths);
    session_paths.markProject(init.io, paths, project);

    var last_exit: u8 = 0;
    while (true) {
        var lease = client.claim(arena, session, &host_id) catch {
            if (selected.once) {
                tty.out(.err, "chock worker: the session host lease could not be claimed.\n", .{});
                return 1;
            }
            std.Io.sleep(init.io, .fromMilliseconds(5000), .awake) catch return 1;
            _ = arena_state.reset(.retain_capacity);
            continue;
        };
        active_generation = lease.generation;

        const remote_before_sync = collectRemote(client, arena, session, &host_id, lease.generation) catch {
            if (selected.once) return 1;
            tty.out(.warn, "chock worker: session events could not be read; retrying.\n", .{});
            std.Io.sleep(init.io, .fromMilliseconds(5000), .awake) catch return 1;
            _ = arena_state.reset(.retain_capacity);
            continue;
        };
        _ = try reconcile(init.gpa, arena, init.io, client, session, &host_id, lease.generation, paths.log, remote_before_sync);
        lease = client.claim(arena, session, &host_id) catch return 1;
        active_generation = lease.generation;
        const remote = try collectRemote(client, arena, session, &host_id, lease.generation);
        if (!hasPendingTurn(remote)) {
            if (selected.once) return last_exit;
            tty.detail("chock worker: waiting for a prompt in session {s}\n", .{session});
            std.Io.sleep(init.io, .fromMilliseconds(5000), .awake) catch return last_exit;
            _ = arena_state.reset(.retain_capacity);
            continue;
        }

        var heartbeat_stop = std.atomic.Value(bool).init(false);
        var heartbeat_failed = std.atomic.Value(bool).init(false);
        var heartbeat_generation = std.atomic.Value(u64).init(lease.generation);
        var cancel_stop = std.atomic.Value(bool).init(containsWorkerCancellation(remote));
        const synchronizer = SessionSynchronizer{
            .client = client,
            .gpa = init.gpa,
            .io = init.io,
            .session = session,
            .host_id = &host_id,
            .log_path = paths.log,
            .stop = &heartbeat_stop,
            .cancel = &cancel_stop,
            .failed = &heartbeat_failed,
            .generation = &heartbeat_generation,
        };
        const thread = try std.Thread.spawn(.{}, SessionSynchronizer.run, .{synchronizer});
        const run_args = [_][]const u8{ "--project", project, "--session", session, "--adopt" };
        const worker_asker: WorkerAsker = .{
            .gpa = init.gpa,
            .io = init.io,
            .session = session,
            .log_path = paths.log,
        };
        last_exit = run: {
            const previous_stop = interrupt.useScopedStop(&cancel_stop);
            defer _ = interrupt.useScopedStop(previous_stop);
            break :run run_cmd.mainForClientWorker(
                arena,
                init.gpa,
                init.minimal.environ,
                exe_path,
                &run_args,
                worker_asker.asker(),
            ) catch 1;
        };
        heartbeat_stop.store(true, .release);
        thread.join();
        active_generation = heartbeat_generation.load(.acquire);
        if (heartbeat_failed.load(.acquire)) {
            tty.out(.err, "chock worker: the host lease expired while the local run was active.\n", .{});
            return 1;
        }

        // Reconcile the local turn log with the daemon after execution. The
        // daemon log remains canonical across worker restarts.
        const after_run = collectRemote(client, arena, session, &host_id, heartbeat_generation.load(.acquire)) catch return 1;
        _ = try reconcile(init.gpa, arena, init.io, client, session, &host_id, heartbeat_generation.load(.acquire), paths.log, after_run);
        if (selected.once) return last_exit;
        _ = arena_state.reset(.retain_capacity);
    }
}

/// Client-hosted agents append questions to their ordinary session history.
/// A human answer arrives in the canonical daemon log and is copied into this
/// local log by SessionSynchronizer, so this callback never needs a second
/// channel that could diverge from the session transcript.
const WorkerAsker = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    session: []const u8,
    log_path: [:0]const u8,

    fn asker(self: *const WorkerAsker) ask.Asker {
        return .{ .ptr = @ptrCast(@constCast(self)), .vtable = &.{ .ask = askFn } };
    }

    fn askFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        question: ask.Question,
    ) ask.Error!ask.Answer {
        const self: *const WorkerAsker = @ptrCast(@alignCast(ptr));
        const request_id = appendQuestion(self, gpa, io, question) catch return .nobody;
        var waited_ms: i64 = 0;
        while (waited_ms < ask.default_timeout_ms) {
            if (interrupt.requested()) return .stopped;
            if (readAnswer(self, gpa, io, request_id)) |answer| return .{ .answered = answer };
            std.Io.sleep(io, .fromMilliseconds(@intCast(ask.poll_interval_ms)), .awake) catch return .stopped;
            waited_ms += @intCast(ask.poll_interval_ms);
        }
        return .timed_out;
    }

    fn appendQuestion(
        self: *const WorkerAsker,
        gpa: std.mem.Allocator,
        io: std.Io,
        question: ask.Question,
    ) !u64 {
        var log = try chock_proto.log.Log.open(io, self.log_path, self.session);
        defer log.close(io);
        var locked = try log.lock(io);
        const request_id = try locked.append(gpa, io, .{ .agent_question = .{
            .text = question.text,
            .options = question.options,
        } }, std.Io.Timestamp.now(io, .real).toMilliseconds());
        try locked.unlock(io);
        return request_id;
    }

    fn readAnswer(
        self: *const WorkerAsker,
        gpa: std.mem.Allocator,
        io: std.Io,
        request_id: u64,
    ) ?[]u8 {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var log = chock_proto.log.Log.open(io, self.log_path, self.session) catch return null;
        defer log.close(io);
        var replay = log.replayFrom(arena, io, request_id) catch return null;
        defer replay.deinit();
        while (replay.next(io) catch return null) |parsed| {
            defer parsed.deinit();
            switch (parsed.value.event) {
                .agent_answer => |answer| if (answer.request_id == request_id)
                    return gpa.dupe(u8, answer.answer) catch null,
                else => {},
            }
        }
        return null;
    }
};

fn parse(arena: std.mem.Allocator, args: []const []const u8) !Options {
    var result: Options = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const one = args[index];
        if (std.mem.eql(u8, one, "--help") or std.mem.eql(u8, one, "-h")) {
            tty.out(.plain, "{s}", .{Usage});
            return error.Help;
        } else if (std.mem.eql(u8, one, "--once")) {
            result.once = true;
        } else if (std.mem.eql(u8, one, "--server") or std.mem.eql(u8, one, "--session") or std.mem.eql(u8, one, "--project")) {
            index += 1;
            if (index == args.len) return error.MissingValue;
            const value = args[index];
            if (std.mem.eql(u8, one, "--server")) result.server = value else if (std.mem.eql(u8, one, "--session")) result.session = value else result.project = try arena.dupe(u8, value);
        } else {
            return error.UnknownArgument;
        }
    }
    return result;
}

const SessionSynchronizer = struct {
    client: worker_http.Client,
    gpa: std.mem.Allocator,
    io: std.Io,
    session: []const u8,
    host_id: []const u8,
    log_path: [:0]const u8,
    stop: *std.atomic.Value(bool),
    cancel: *std.atomic.Value(bool),
    failed: *std.atomic.Value(bool),
    generation: *std.atomic.Value(u64),

    fn run(self: SessionSynchronizer) void {
        while (!self.stop.load(.acquire)) {
            std.Io.sleep(self.io, .fromMilliseconds(1000), .awake) catch return;
            if (self.stop.load(.acquire)) return;
            var arena_state = std.heap.ArenaAllocator.init(self.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            const lease = self.client.claim(arena, self.session, self.host_id) catch {
                self.failed.store(true, .release);
                return;
            };
            self.generation.store(lease.generation, .release);
            const remote = collectRemote(self.client, arena, self.session, self.host_id, lease.generation) catch {
                self.failed.store(true, .release);
                return;
            };
            _ = reconcile(self.gpa, arena, self.io, self.client, self.session, self.host_id, lease.generation, self.log_path, remote) catch {
                self.failed.store(true, .release);
                return;
            };
            if (containsWorkerCancellation(remote)) self.cancel.store(true, .release);
            // Appending session_end fences the generation. Reclaim immediately
            // so subsequent events and the next turn use the fresh fence.
            const refreshed = self.client.claim(arena, self.session, self.host_id) catch {
                self.failed.store(true, .release);
                return;
            };
            self.generation.store(refreshed.generation, .release);
        }
    }
};

fn collectRemote(
    client: worker_http.Client,
    arena: std.mem.Allocator,
    session: []const u8,
    host_id: []const u8,
    generation: u64,
) ![]const event.Envelope {
    var collected: std.ArrayList(event.Envelope) = .empty;
    var after: u64 = 0;
    while (true) {
        const page = try client.commands(arena, session, host_id, generation, after);
        try collected.appendSlice(arena, page.events);
        if (page.events.len == 0) break;
        after = page.events[page.events.len - 1].id;
    }
    return collected.items;
}

fn containsWorkerCancellation(events: []const event.Envelope) bool {
    var canceled = false;
    for (events) |one| switch (one.event) {
        .session_end => canceled = false,
        .worker_cancel => canceled = true,
        else => {},
    };
    return canceled;
}

fn reconcile(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    client: worker_http.Client,
    session: []const u8,
    host_id: []const u8,
    generation: u64,
    log_path: [:0]const u8,
    remote: []const event.Envelope,
) !u64 {
    var log = try chock_proto.log.Log.open(io, log_path, session);
    defer log.close(io);
    var local = try readLocalEvents(arena, io, &log);
    const common = @min(local.len, remote.len);
    for (local[0..common], remote[0..common]) |left, right| {
        if (!try sameEvent(arena, left.event, right.event)) return error.SessionHistoryDiverged;
    }

    var next_offset: u64 = @intCast((try log.file.length(io)));
    if (remote.len > local.len) {
        var locked = try log.lock(io);
        for (remote[local.len..]) |one| _ = try locked.append(gpa, io, one.event, one.time_ms);
        try locked.unlock(io);
        local = try readLocalEvents(arena, io, &log);
        next_offset = localNextOffset(arena, io, &log) catch next_offset;
    }
    if (local.len > remote.len) {
        if (remote.len != 0) {
            const tail = try client.commands(arena, session, host_id, generation, remote[remote.len - 1].id);
            next_offset = tail.end_offset;
        } else {
            next_offset = chock_proto.storage.header_line.len + 1;
        }
        for (local[remote.len..]) |one| {
            const appended = try client.append(arena, session, host_id, generation, next_offset, one.event);
            next_offset = appended.next_offset;
        }
    } else if (remote.len != 0) {
        // The last page's append position is recovered with a final inclusive
        // read. This remains distinct from its last delivered event ID.
        const tail = try client.commands(arena, session, host_id, generation, remote[remote.len - 1].id);
        next_offset = tail.end_offset;
    }
    return next_offset;
}

fn readLocalEvents(arena: std.mem.Allocator, io: std.Io, log: *chock_proto.log.Log) ![]event.Envelope {
    var replay = try log.replayFrom(arena, io, 0);
    defer replay.deinit();
    var out: std.ArrayList(event.Envelope) = .empty;
    while (try replay.next(io)) |parsed| {
        try out.append(arena, parsed.value);
    }
    return out.items[0..];
}

fn localNextOffset(arena: std.mem.Allocator, io: std.Io, log: *chock_proto.log.Log) !u64 {
    var replay = try log.replayFrom(arena, io, 0);
    defer replay.deinit();
    var next = replay.pos;
    while (try replay.next(io)) |_| {
        next = replay.pos;
    }
    return next;
}

fn sameEvent(arena: std.mem.Allocator, left: event.Event, right: event.Event) !bool {
    const a = try std.json.Stringify.valueAlloc(arena, left, .{});
    const b = try std.json.Stringify.valueAlloc(arena, right, .{});
    return std.mem.eql(u8, a, b);
}

fn hasPendingTurn(events: []const event.Envelope) bool {
    var latest_user: ?usize = null;
    var latest_end: ?usize = null;
    for (events, 0..) |one, index| switch (one.event) {
        .message => |message| if (std.meta.activeTag(message.role) == .user) {
            latest_user = index;
        },
        .session_end => latest_end = index,
        else => {},
    };
    return if (latest_user) |user_at|
        latest_end == null or user_at > latest_end.?
    else
        false;
}

fn makeHostId(io: std.Io, out: *[36]u8) std.Io.RandomSecureError!void {
    var raw: [16]u8 = undefined;
    try io.randomSecure(&raw);
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    const hex = "0123456789abcdef";
    var at: usize = 0;
    for (raw, 0..) |byte, index| {
        if (index == 4 or index == 6 or index == 8 or index == 10) {
            out[at] = '-';
            at += 1;
        }
        out[at] = hex[byte >> 4];
        out[at + 1] = hex[byte & 0x0f];
        at += 2;
    }
    std.crypto.secureZero(u8, &raw);
}

test "worker options keep bearer credentials out of arguments" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const parsed = try parse(arena_state.allocator(), &.{ "--server", "https://daemon.example", "--session", "01JQAAAAAAAAAAAAAAAAAAAAAA", "--once" });
    try std.testing.expect(parsed.once);
    try std.testing.expectError(error.UnknownArgument, parse(arena_state.allocator(), &.{"--token"}));
}

test "worker host ids have UUID v4 shape" {
    var host: [36]u8 = undefined;
    try makeHostId(std.testing.io, &host);
    try std.testing.expectEqual(@as(u8, '4'), host[14]);
    try std.testing.expect(host[19] == '8' or host[19] == '9' or host[19] == 'a' or host[19] == 'b');
}

test "worker notices a canonical cancellation command but ignores ordinary unknown events" {
    const session = "01JQAAAAAAAAAAAAAAAAAAAAAA";
    const events = [_]event.Envelope{
        .{ .id = 10, .session = session, .time_ms = 1, .event = .{ .unknown = .{ .kind = "future.event", .payload = .null } } },
        .{ .id = 20, .session = session, .time_ms = 2, .event = .{ .worker_cancel = .{ .requested_by = "00000000-0000-4000-8000-000000000001" } } },
    };
    try std.testing.expect(containsWorkerCancellation(&events));
    try std.testing.expect(!containsWorkerCancellation(events[0..1]));
    const later_turn = [_]event.Envelope{
        events[1],
        .{ .id = 30, .session = session, .time_ms = 3, .event = .{ .session_end = .{ .reason = .canceled_by_user, .detail = "" } } },
        .{ .id = 40, .session = session, .time_ms = 4, .event = .{ .message = .{ .role = .user, .content = &.{} } } },
    };
    try std.testing.expect(!containsWorkerCancellation(&later_turn));
}
