//! The other mcp.Host: a remote MCP server over the streamable HTTP
//! transport. This file holds the JSON-RPC and the event stream reading. The
//! socket, the address check and the credential belong to the broker, behind
//! `Exchange`, so nothing here ever holds a secret.

const std = @import("std");

const mcp = @import("mcp.zig");
const message = @import("mcp_message.zig");

/// A reference server answers a request with one event, and the whole reply
/// arrives in one frame. The bound is on the frame and not on the stream.
pub const max_frame_bytes = 1 << 16;

/// One answer, which is a tool list of up to `mcp.max_tools_per_server`
/// schemas and so much larger than one tool result. The local transport holds
/// its whole inbox to a bound of the same order.
pub const max_reply_bytes = 1 << 20;

const read_chunk_bytes = 4096;

pub const Error = mcp.Error;

pub const ReadError = error{ Late, Gone };

/// The body of an answer, read in pieces so the caller can stop at the reply
/// it asked for. A server may hold a stream open after answering.
pub const Body = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Zero is the end of the body.
        read: *const fn (
            ptr: *anyopaque,
            io: std.Io,
            into: []u8,
            deadline: std.Io.Clock.Timestamp,
        ) ReadError!usize,
        close: *const fn (ptr: *anyopaque, io: std.Io) void,
    };

    pub fn read(
        self: Body,
        io: std.Io,
        into: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReadError!usize {
        return self.vtable.read(self.ptr, io, into, deadline);
    }

    pub fn close(self: Body, io: std.Io) void {
        self.vtable.close(self.ptr, io);
    }
};

pub const Reply = struct {
    status: u16,
    kind: Kind = .other,
    /// What the answer named, which is empty for an answer that named none.
    session_id: []const u8 = "",
    /// Null for an answer with nothing to read, such as the 202 a
    /// notification gets.
    body: ?Body = null,

    pub const Kind = enum { json, event_stream, other };
};

pub const Post = struct {
    body: []const u8,
    /// Empty until the handshake answers with one.
    session_id: []const u8 = "",
    /// Empty for the handshake itself, which is what settles the version.
    protocol_version: []const u8 = "",
    deadline: std.Io.Clock.Timestamp,
};

/// The socket. The broker fills this in, adds the credential header, and
/// refuses a destination the policy did not name.
pub const Exchange = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        post: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            io: std.Io,
            one: Post,
        ) Error!Reply,
    };

    pub fn post(
        self: Exchange,
        arena: std.mem.Allocator,
        io: std.Io,
        one: Post,
    ) Error!Reply {
        return self.vtable.post(self.ptr, arena, io, one);
    }
};

/// The `data` of each event in a `text/event-stream` body. A frame that
/// crosses a read boundary is held until the rest of it arrives.
pub const Frames = struct {
    gpa: std.mem.Allocator,
    held: std.ArrayList(u8) = .empty,

    pub const PushError = error{ OutOfMemory, FrameTooLong };

    pub fn deinit(self: *Frames) void {
        self.held.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn push(self: *Frames, bytes: []const u8) PushError!void {
        try self.held.appendSlice(self.gpa, bytes);
        if (self.held.items.len <= max_frame_bytes) return;
        if (frameEnd(self.held.items) == null) return error.FrameTooLong;
    }

    /// Null while no frame is complete. An empty payload is a frame that
    /// carried no data line, which a caller skips.
    pub fn next(self: *Frames, arena: std.mem.Allocator) std.mem.Allocator.Error!?[]const u8 {
        const found = frameEnd(self.held.items) orelse return null;
        const payload = try dataIn(arena, self.held.items[0..found.body]);
        self.held.replaceRange(self.gpa, 0, found.after, &.{}) catch unreachable;
        return payload;
    }

    const End = struct { body: usize, after: usize };

    /// A frame ends at a line with nothing on it, whichever line ending the
    /// server writes.
    fn frameEnd(bytes: []const u8) ?End {
        var at: usize = 0;
        while (at < bytes.len) {
            const stop = std.mem.indexOfScalarPos(u8, bytes, at, '\n') orelse return null;
            if (lineOf(bytes[at..stop]).len == 0) return .{ .body = at, .after = stop + 1 };
            at = stop + 1;
        }
        return null;
    }

    fn dataIn(
        arena: std.mem.Allocator,
        frame: []const u8,
    ) std.mem.Allocator.Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        var lines = std.mem.splitScalar(u8, frame, '\n');
        while (lines.next()) |raw| {
            const line = lineOf(raw);
            // A line opening with a colon is a comment, and a field this
            // reader does not know is not a fault.
            if (line.len == 0 or line[0] == ':') continue;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            if (!std.mem.eql(u8, line[0..colon], "data")) continue;
            var value = line[colon + 1 ..];
            if (value.len != 0 and value[0] == ' ') value = value[1..];
            if (out.items.len != 0) try out.append(arena, '\n');
            try out.appendSlice(arena, value);
        }
        return out.toOwnedSlice(arena);
    }

    fn lineOf(raw: []const u8) []const u8 {
        if (raw.len != 0 and raw[raw.len - 1] == '\r') return raw[0 .. raw.len - 1];
        return raw;
    }
};

pub const Driver = struct {
    gpa: std.mem.Allocator,

    exchange: Exchange,

    /// Held from the handshake on, and sent with every later request.
    session_id: []const u8 = "",

    negotiated: []const u8 = "",

    ready: bool = false,

    last_id: i64 = 0,

    list_changed: usize = 0,

    ignored_requests: usize = 0,

    reinitialised: usize = 0,

    failure: ?[]const u8 = null,

    pub fn init(gpa: std.mem.Allocator, exchange: Exchange) Driver {
        return .{ .gpa = gpa, .exchange = exchange };
    }

    pub fn deinit(self: *Driver) void {
        self.forget();
        self.* = undefined;
    }

    pub fn host(self: *Driver) mcp.Host {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = mcp.Host.VTable{ .list = listFn, .call = callFn };

    const Asked = union(enum) {
        list,
        call: struct { name: []const u8, arguments: []const u8 },
    };

    fn listFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        budget_ns: u64,
    ) Error![]const mcp.Declared {
        const self: *Driver = @ptrCast(@alignCast(ptr));
        const reply = try self.ask(arena, io, deadlineIn(io, budget_ns), .list);
        return message.declaredFrom(arena, reply);
    }

    fn callFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) Error!mcp.Outcome {
        const self: *Driver = @ptrCast(@alignCast(ptr));
        const reply = try self.ask(arena, io, deadlineIn(io, budget_ns), .{
            .call = .{ .name = name, .arguments = arguments },
        });
        return message.outcomeFrom(arena, reply);
    }

    /// A 404 says the server dropped the session, so the handshake runs again
    /// and the question is put once more. Twice is a server that will not
    /// hold a session at all.
    fn ask(
        self: *Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
        asked: Asked,
    ) Error!std.json.Value {
        if (self.failure != null) return error.Gone;

        var attempt: usize = 0;
        while (true) : (attempt += 1) {
            self.handshake(arena, io, deadline) catch |err| return self.note(err);

            const id = self.nextId();
            const body = switch (asked) {
                .list => try message.listBody(arena, id),
                .call => |one| try message.callBody(arena, id, one.name, one.arguments),
            };

            if (self.answer(arena, io, deadline, body, id)) |reply| {
                return reply;
            } else |err| switch (err) {
                error.SessionGone => {
                    if (attempt != 0) return self.note(error.Gone);
                    self.reinitialised += 1;
                    self.forget();
                    continue;
                },
                else => |one| return self.note(one),
            }
        }
    }

    fn handshake(
        self: *Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.ready) return;

        const id = self.nextId();
        const opened = self.answer(
            arena,
            io,
            deadline,
            try message.initializeBody(arena, id),
            id,
        ) catch |err| return switch (err) {
            // Nothing to reinitialise: this is the initialise.
            error.SessionGone => error.Gone,
            else => |one| one,
        };

        const said = message.negotiatedIn(opened);
        const version = if (said.len != 0) said else message.protocol_version;
        const kept = try self.gpa.dupe(u8, version);
        self.gpa.free(self.negotiated);
        self.negotiated = kept;

        // The notification is not waited on: a server answers it 202. One that
        // answers with a body still hands one over, and it is closed here.
        const told = try self.exchange.post(arena, io, .{
            .body = try message.initializedBody(arena),
            .session_id = self.session_id,
            .protocol_version = self.negotiated,
            .deadline = deadline,
        });
        if (told.body) |one| one.close(io);

        self.ready = true;
    }

    const AnswerError = Error || error{SessionGone};

    fn answer(
        self: *Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
        body: []const u8,
        id: i64,
    ) AnswerError!std.json.Value {
        const reply = try self.exchange.post(arena, io, .{
            .body = body,
            .session_id = self.session_id,
            .protocol_version = self.negotiated,
            .deadline = deadline,
        });

        if (reply.body) |one| {
            // Every path below is done with the body: the next request opens its own.
            defer one.close(io);

            // A session this server no longer holds, which the caller may open again.
            if (reply.status == 404 and self.session_id.len != 0) return error.SessionGone;
            if (reply.status != 200) return error.Gone;

            try self.keepSession(reply.session_id);

            return switch (reply.kind) {
                .json => self.wholeReply(arena, io, one, deadline, id),
                .event_stream => self.streamedReply(arena, io, one, deadline, id),
                .other => error.Gone,
            };
        }

        if (reply.status == 404 and self.session_id.len != 0) return error.SessionGone;
        // A request must be answered. A 202 belongs to a notification.
        return error.Gone;
    }

    fn keepSession(self: *Driver, named: []const u8) Error!void {
        if (named.len == 0) return;
        if (std.mem.eql(u8, named, self.session_id)) return;
        const kept = try self.gpa.dupe(u8, named);
        self.gpa.free(self.session_id);
        self.session_id = kept;
    }

    fn wholeReply(
        self: *Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        body: Body,
        deadline: std.Io.Clock.Timestamp,
        id: i64,
    ) AnswerError!std.json.Value {
        _ = self;
        var held: std.ArrayList(u8) = .empty;
        defer held.deinit(arena);

        while (true) {
            var scratch: [read_chunk_bytes]u8 = undefined;
            const count = try read(body, io, &scratch, deadline);
            if (count == 0) break;
            if (held.items.len + count > max_reply_bytes) return error.Gone;
            try held.appendSlice(arena, scratch[0..count]);
        }

        const parsed = std.json.parseFromSliceLeaky(
            std.json.Value,
            arena,
            held.items,
            .{},
        ) catch return error.Gone;
        return message.replyFor(parsed, id) orelse error.Gone;
    }

    fn streamedReply(
        self: *Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        body: Body,
        deadline: std.Io.Clock.Timestamp,
        id: i64,
    ) AnswerError!std.json.Value {
        var frames = Frames{ .gpa = self.gpa };
        defer frames.deinit();

        var read_bytes: usize = 0;
        while (true) {
            while (try frames.next(arena)) |payload| {
                if (payload.len == 0) continue;
                const parsed = std.json.parseFromSliceLeaky(
                    std.json.Value,
                    arena,
                    payload,
                    .{},
                ) catch continue;
                if (message.isListChanged(parsed)) self.list_changed += 1;
                if (message.isServerRequest(parsed)) self.ignored_requests += 1;
                // The reply may come after a message the server sent first.
                if (message.replyFor(parsed, id)) |reply| return reply;
            }

            var scratch: [read_chunk_bytes]u8 = undefined;
            const count = try read(body, io, &scratch, deadline);
            // The stream ended with no answer in it.
            if (count == 0) return error.Gone;

            read_bytes += count;
            if (read_bytes > max_reply_bytes) return error.Gone;
            frames.push(scratch[0..count]) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.FrameTooLong => error.Gone,
            };
        }
    }

    fn read(
        body: Body,
        io: std.Io,
        into: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) AnswerError!usize {
        return body.read(io, into, deadline) catch |err| switch (err) {
            error.Late => error.Late,
            error.Gone => error.Gone,
        };
    }

    fn nextId(self: *Driver) i64 {
        self.last_id += 1;
        return self.last_id;
    }

    /// Drops the session the server named, so the next question opens one.
    fn forget(self: *Driver) void {
        self.gpa.free(self.session_id);
        self.gpa.free(self.negotiated);
        self.session_id = "";
        self.negotiated = "";
        self.ready = false;
    }

    fn note(self: *Driver, err: Error) Error {
        if (err == error.Gone and self.failure == null) self.failure = mcp.start_failed;
        return err;
    }
};

pub fn deadlineIn(io: std.Io, budget_ns: u64) std.Io.Clock.Timestamp {
    return std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{
        .raw = .fromNanoseconds(@intCast(budget_ns)),
        .clock = .awake,
    });
}

const testing = std.testing;

/// The answer a reference server gave to `initialize`, byte for byte.
const real_initialize_frame = "event: message\r\n" ++
    "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\"," ++
    "\"capabilities\":{\"tools\":{\"listChanged\":false}}," ++
    "\"serverInfo\":{\"name\":\"probe\",\"version\":\"1.29.0\"}}}\r\n" ++
    "\r\n";

const real_list_frame = "event: message\r\n" ++
    "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"echo\"," ++
    "\"description\":\"Give back the text it was given.\"," ++
    "\"inputSchema\":{\"type\":\"object\"}}]}}\r\n" ++
    "\r\n";

test "the frame a reference server writes gives up its data, whole or a byte at a time" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var whole = Frames{ .gpa = testing.allocator };
    defer whole.deinit();
    try whole.push(real_initialize_frame);
    const first = (try whole.next(arena)) orelse return error.TestExpectedFrame;
    try testing.expect(std.mem.startsWith(u8, first, "{\"jsonrpc\":\"2.0\",\"id\":1"));
    try testing.expect(std.mem.endsWith(u8, first, "}}}"));
    try testing.expect((try whole.next(arena)) == null);

    var dribbled = Frames{ .gpa = testing.allocator };
    defer dribbled.deinit();
    for (real_initialize_frame) |byte| try dribbled.push(&.{byte});
    const second = (try dribbled.next(arena)) orelse return error.TestExpectedFrame;
    try testing.expectEqualStrings(first, second);
}

test "a frame split at any offset still arrives in one piece" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    for (0..real_list_frame.len) |split| {
        var frames = Frames{ .gpa = testing.allocator };
        defer frames.deinit();
        try frames.push(real_list_frame[0..split]);
        try frames.push(real_list_frame[split..]);
        const payload = (try frames.next(arena)) orelse return error.TestExpectedFrame;
        try testing.expect(std.mem.indexOf(u8, payload, "\"name\":\"echo\"") != null);
    }
}

test "two frames in one read arrive in the order the server wrote them" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var frames = Frames{ .gpa = testing.allocator };
    defer frames.deinit();
    try frames.push(real_initialize_frame ++ real_list_frame);

    const first = (try frames.next(arena)) orelse return error.TestExpectedFrame;
    try testing.expect(std.mem.indexOf(u8, first, "\"id\":1") != null);
    const second = (try frames.next(arena)) orelse return error.TestExpectedFrame;
    try testing.expect(std.mem.indexOf(u8, second, "\"id\":2") != null);
    try testing.expect((try frames.next(arena)) == null);
}

test "a newline alone ends a line, two data lines join, and a field this reader skips is no fault" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var frames = Frames{ .gpa = testing.allocator };
    defer frames.deinit();
    try frames.push("id: 7\nevent: message\ndata: one\ndata: two\n\n");
    const joined = (try frames.next(arena)) orelse return error.TestExpectedFrame;
    try testing.expectEqualStrings("one\ntwo", joined);

    try frames.push(": a comment the standard allows\nevent: ping\n\n");
    const empty = (try frames.next(arena)) orelse return error.TestExpectedFrame;
    try testing.expectEqualStrings("", empty);

    try frames.push("data:no space after the colon\n\n");
    const tight = (try frames.next(arena)) orelse return error.TestExpectedFrame;
    try testing.expectEqualStrings("no space after the colon", tight);
}

test "a frame with no end to it is refused rather than held forever" {
    var frames = Frames{ .gpa = testing.allocator };
    defer frames.deinit();

    var lump: [4096]u8 = undefined;
    @memset(&lump, 'x');
    try frames.push("data: ");

    var written: usize = 0;
    while (written <= max_frame_bytes) : (written += lump.len) {
        frames.push(&lump) catch |err| {
            try testing.expectEqual(error.FrameTooLong, err);
            return;
        };
    }
    return error.TestExpectedRefusal;
}

/// One canned answer, with its body served out of a slice.
const Canned = struct {
    status: u16 = 200,
    kind: Reply.Kind = .event_stream,
    session_id: []const u8 = "",
    bytes: []const u8 = "",
    /// Null is an answer with no body at all, such as a 202.
    has_body: bool = true,
};

const Served = struct {
    bytes: []const u8,
    at: usize = 0,
    closed: bool = false,

    fn body(self: *Served) Body {
        return .{ .ptr = self, .vtable = &served_vtable };
    }

    fn readFn(
        ptr: *anyopaque,
        io: std.Io,
        into: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReadError!usize {
        _ = io;
        _ = deadline;
        const self: *Served = @ptrCast(@alignCast(ptr));
        const left = self.bytes.len - self.at;
        if (left == 0) return 0;
        // One byte at a time, so a reply that crosses a read is the normal case here.
        const count = @min(into.len, @min(left, 7));
        @memcpy(into[0..count], self.bytes[self.at..][0..count]);
        self.at += count;
        return count;
    }

    fn closeFn(ptr: *anyopaque, io: std.Io) void {
        _ = io;
        const self: *Served = @ptrCast(@alignCast(ptr));
        self.closed = true;
    }
};

const served_vtable = Body.VTable{ .read = Served.readFn, .close = Served.closeFn };

const FakeExchange = struct {
    canned: []const Canned,
    answered: usize = 0,
    posts: std.ArrayList(Post) = .empty,
    bodies: [16]Served = undefined,
    gpa: std.mem.Allocator,

    fn deinit(self: *FakeExchange) void {
        self.posts.deinit(self.gpa);
    }

    fn exchange(self: *FakeExchange) Exchange {
        return .{ .ptr = self, .vtable = &fake_vtable };
    }

    fn postFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        one: Post,
    ) Error!Reply {
        _ = io;
        const self: *FakeExchange = @ptrCast(@alignCast(ptr));
        try self.posts.append(self.gpa, .{
            .body = try arena.dupe(u8, one.body),
            .session_id = try arena.dupe(u8, one.session_id),
            .protocol_version = try arena.dupe(u8, one.protocol_version),
            .deadline = one.deadline,
        });

        if (self.answered >= self.canned.len) return error.Gone;
        const said = self.canned[self.answered];
        const index = self.answered;
        self.answered += 1;

        if (!said.has_body) return .{
            .status = said.status,
            .kind = said.kind,
            .session_id = said.session_id,
        };

        self.bodies[index] = .{ .bytes = try answeringId(arena, said.bytes, one.body) };
        return .{
            .status = said.status,
            .kind = said.kind,
            .session_id = said.session_id,
            .body = self.bodies[index].body(),
        };
    }

    /// Every body this fake handed out was closed, so a leak fails a test.
    fn everyBodyClosed(self: *const FakeExchange) bool {
        for (self.canned[0..self.answered], 0..) |said, index| {
            if (!said.has_body) continue;
            if (!self.bodies[index].closed) return false;
        }
        return true;
    }

    fn methodOf(self: *const FakeExchange, index: usize) []const u8 {
        const body = self.posts.items[index].body;
        const opens = std.mem.indexOf(u8, body, "\"method\":\"") orelse return "";
        const rest = body[opens + "\"method\":\"".len ..];
        const ends = std.mem.indexOfScalar(u8, rest, '"') orelse return "";
        return rest[0..ends];
    }
};

const fake_vtable = Exchange.VTable{ .post = FakeExchange.postFn };

/// A server answers the id it was asked, so the canned bytes take the id out
/// of the request they answer. The bytes themselves stay as a server wrote them.
fn answeringId(
    arena: std.mem.Allocator,
    canned: []const u8,
    asked: []const u8,
) std.mem.Allocator.Error![]const u8 {
    const wanted = idIn(asked) orelse return canned;
    const held = idIn(canned) orelse return canned;
    if (wanted == held) return canned;

    const opens = std.mem.indexOf(u8, canned, "\"id\":").? + "\"id\":".len;
    var ends = opens;
    while (ends < canned.len and std.ascii.isDigit(canned[ends])) ends += 1;
    return std.fmt.allocPrint(arena, "{s}{d}{s}", .{
        canned[0..opens],
        wanted,
        canned[ends..],
    });
}

fn idIn(body: []const u8) ?i64 {
    const opens = std.mem.indexOf(u8, body, "\"id\":") orelse return null;
    const rest = body[opens + "\"id\":".len ..];
    var ends: usize = 0;
    while (ends < rest.len and std.ascii.isDigit(rest[ends])) ends += 1;
    if (ends == 0) return null;
    return std.fmt.parseInt(i64, rest[0..ends], 10) catch null;
}

const accepted = Canned{ .status = 202, .kind = .json, .has_body = false };

fn handshakeThen(rest: []const Canned, buffer: []Canned) []const Canned {
    buffer[0] = .{ .session_id = "abc123", .bytes = real_initialize_frame };
    buffer[1] = accepted;
    @memcpy(buffer[2..][0..rest.len], rest);
    return buffer[0 .. 2 + rest.len];
}

test "the handshake runs first, and every later request carries the session and the version" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var room: [8]Canned = undefined;
    var fake = FakeExchange{
        .gpa = gpa,
        .canned = handshakeThen(&.{.{ .bytes = real_list_frame }}, &room),
    };
    defer fake.deinit();

    var driver = Driver.init(gpa, fake.exchange());
    defer driver.deinit();

    const declared = try driver.host().list(arena_state.allocator(), io, std.time.ns_per_s);
    try testing.expectEqual(@as(usize, 1), declared.len);
    try testing.expectEqualStrings("echo", declared[0].name);

    try testing.expectEqual(@as(usize, 3), fake.posts.items.len);
    try testing.expectEqualStrings("initialize", fake.methodOf(0));
    try testing.expectEqualStrings("notifications/initialized", fake.methodOf(1));
    try testing.expectEqualStrings("tools/list", fake.methodOf(2));

    try testing.expectEqualStrings("", fake.posts.items[0].session_id);
    try testing.expectEqualStrings("", fake.posts.items[0].protocol_version);
    try testing.expectEqualStrings("abc123", fake.posts.items[1].session_id);
    try testing.expectEqualStrings("2025-06-18", fake.posts.items[1].protocol_version);
    try testing.expectEqualStrings("abc123", fake.posts.items[2].session_id);

    try testing.expect(fake.everyBodyClosed());
}

test "a server that answers one JSON object instead of a stream is read the same way" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var room: [8]Canned = undefined;
    var fake = FakeExchange{ .gpa = gpa, .canned = handshakeThen(&.{.{
        .kind = .json,
        .bytes = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":" ++
            "[{\"name\":\"only\",\"inputSchema\":{\"type\":\"object\"}}]}}",
    }}, &room) };
    defer fake.deinit();

    var driver = Driver.init(gpa, fake.exchange());
    defer driver.deinit();

    const declared = try driver.host().list(arena_state.allocator(), io, std.time.ns_per_s);
    try testing.expectEqual(@as(usize, 1), declared.len);
    try testing.expectEqualStrings("only", declared[0].name);
}

test "a message the server sends first is counted, never answered, and does not hide the reply" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const asked_first = "event: message\r\n" ++
        "data: {\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"sampling/createMessage\",\"params\":{}}\r\n" ++
        "\r\n" ++
        "event: message\r\n" ++
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\r\n" ++
        "\r\n" ++
        real_list_frame;

    var room: [8]Canned = undefined;
    var fake = FakeExchange{
        .gpa = gpa,
        .canned = handshakeThen(&.{.{ .bytes = asked_first }}, &room),
    };
    defer fake.deinit();

    var driver = Driver.init(gpa, fake.exchange());
    defer driver.deinit();

    const declared = try driver.host().list(arena_state.allocator(), io, std.time.ns_per_s);
    try testing.expectEqual(@as(usize, 1), declared.len);
    try testing.expectEqual(@as(usize, 1), driver.ignored_requests);
    try testing.expectEqual(@as(usize, 1), driver.list_changed);
    // Three posts, so nothing was sent back to the server about either message.
    try testing.expectEqual(@as(usize, 3), fake.posts.items.len);
}

test "a dropped session is opened again once, and twice is a server that holds none" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var room: [8]Canned = undefined;
    var fake = FakeExchange{ .gpa = gpa, .canned = handshakeThen(&.{
        .{ .status = 404, .kind = .json, .bytes = "" },
        .{ .session_id = "second", .bytes = real_initialize_frame },
        accepted,
        .{ .bytes = real_list_frame },
    }, &room) };
    defer fake.deinit();

    var driver = Driver.init(gpa, fake.exchange());
    defer driver.deinit();

    const declared = try driver.host().list(arena_state.allocator(), io, std.time.ns_per_s);
    try testing.expectEqual(@as(usize, 1), declared.len);
    try testing.expectEqual(@as(usize, 1), driver.reinitialised);
    try testing.expectEqualStrings("second", driver.session_id);
    try testing.expectEqual(@as(usize, 6), fake.posts.items.len);
    try testing.expect(fake.everyBodyClosed());
}

test "a second dropped session gives up rather than opening sessions forever" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var room: [8]Canned = undefined;
    var fake = FakeExchange{ .gpa = gpa, .canned = handshakeThen(&.{
        .{ .status = 404, .kind = .json, .bytes = "" },
        .{ .session_id = "second", .bytes = real_initialize_frame },
        accepted,
        .{ .status = 404, .kind = .json, .bytes = "" },
    }, &room) };
    defer fake.deinit();

    var driver = Driver.init(gpa, fake.exchange());
    defer driver.deinit();

    try testing.expectError(
        error.Gone,
        driver.host().list(arena_state.allocator(), io, std.time.ns_per_s),
    );
}

test "a status that is not 200 reaches nothing, a redirect among them" {
    const gpa = testing.allocator;
    const io = testing.io;

    for ([_]u16{ 301, 302, 400, 401, 406, 500 }) |status| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();

        var room: [8]Canned = undefined;
        var fake = FakeExchange{
            .gpa = gpa,
            .canned = handshakeThen(&.{.{ .status = status, .kind = .json, .bytes = "" }}, &room),
        };
        defer fake.deinit();

        var driver = Driver.init(gpa, fake.exchange());
        defer driver.deinit();

        try testing.expectError(
            error.Gone,
            driver.host().list(arena_state.allocator(), io, std.time.ns_per_s),
        );
        try testing.expect(fake.everyBodyClosed());
    }
}

test "a stream that ends with no answer in it is a failure, never an empty tool list" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var room: [8]Canned = undefined;
    var fake = FakeExchange{ .gpa = gpa, .canned = handshakeThen(&.{.{
        .bytes = "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\"}\r\n\r\n",
    }}, &room) };
    defer fake.deinit();

    var driver = Driver.init(gpa, fake.exchange());
    defer driver.deinit();

    try testing.expectError(
        error.Gone,
        driver.host().list(arena_state.allocator(), io, std.time.ns_per_s),
    );
    try testing.expect(fake.everyBodyClosed());
}

test "a reply the server will not stop sending is refused at the bound" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const filler = "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\"}\r\n\r\n";
    var endless: std.ArrayList(u8) = .empty;
    defer endless.deinit(gpa);
    while (endless.items.len <= max_reply_bytes) try endless.appendSlice(gpa, filler);

    var room: [8]Canned = undefined;
    var fake = FakeExchange{
        .gpa = gpa,
        .canned = handshakeThen(&.{.{ .bytes = endless.items }}, &room),
    };
    defer fake.deinit();

    var driver = Driver.init(gpa, fake.exchange());
    defer driver.deinit();

    try testing.expectError(
        error.Gone,
        driver.host().list(arena_state.allocator(), io, std.time.ns_per_s),
    );
    try testing.expect(fake.everyBodyClosed());
}

test "a tool that failed is an answer, and the server stays in the session" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var room: [8]Canned = undefined;
    var fake = FakeExchange{ .gpa = gpa, .canned = handshakeThen(&.{.{
        .bytes = "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":" ++
            "{\"content\":[{\"type\":\"text\",\"text\":\"no such timezone\"}],\"isError\":true}}\r\n\r\n",
    }}, &room) };
    defer fake.deinit();

    var driver = Driver.init(gpa, fake.exchange());
    defer driver.deinit();

    const outcome = try driver.host().call(
        arena_state.allocator(),
        io,
        "echo",
        "{\"text\":\"hei\"}",
        std.time.ns_per_s,
    );
    try testing.expect(outcome.is_error);
    try testing.expectEqualStrings("no such timezone", outcome.text);
    try testing.expect(driver.failure == null);
}
