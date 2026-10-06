//! The production mcp.Host: an MCP server in the sandbox, over a
//! helper.Helper, speaking JSON-RPC on descriptors 0 and 1.
const std = @import("std");

const helper = @import("helper.zig");
const mcp = @import("mcp.zig");

pub const protocol_version = "2025-06-18";

pub const client_name = "chock";

pub const max_inbox_bytes = 4 << 20;

const read_chunk_bytes = 4096;

const empty_object = struct {}{};

pub const Protocol = struct {
    gpa: std.mem.Allocator,

    inbox: std.ArrayList(u8) = .empty,

    ready: bool = false,

    last_id: i64 = 0,

    handshake_id: ?i64 = null,

    list_changed: usize = 0,

    pub fn deinit(self: *Protocol) void {
        self.inbox.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn list(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
    ) mcp.Error![]const mcp.Declared {
        try self.handshake(arena, io, channel, deadline);

        const reply = try self.request(arena, io, channel, deadline, .{
            .jsonrpc = "2.0",
            .id = self.nextId(),
            .method = "tools/list",
            .params = empty_object,
        });

        const result = objectField(reply, "result") orelse return &.{};
        const declared = result.get("tools") orelse return &.{};
        if (declared != .array) return &.{};

        var out: std.ArrayList(mcp.Declared) = .empty;
        for (declared.array.items) |item| {
            if (item != .object) continue;
            const name = item.object.get("name") orelse continue;
            if (name != .string) continue;
            const description = blk: {
                const raw = item.object.get("description") orelse break :blk "";
                if (raw != .string) break :blk "";
                break :blk raw.string;
            };
            const schema = item.object.get("inputSchema") orelse std.json.Value.null;
            try out.append(arena, .{
                .name = name.string,
                .description = description,
                .schema = schema,
            });
        }
        return out.toOwnedSlice(arena);
    }

    pub fn call(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
        name: []const u8,
        arguments: []const u8,
    ) mcp.Error!mcp.Outcome {
        try self.handshake(arena, io, channel, deadline);

        const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, arguments, .{}) catch
            std.json.Value.null;
        const args: std.json.Value = if (parsed == .object)
            parsed
        else
            std.json.parseFromSliceLeaky(std.json.Value, arena, "{}", .{}) catch
                return error.OutOfMemory;

        const reply = try self.request(arena, io, channel, deadline, .{
            .jsonrpc = "2.0",
            .id = self.nextId(),
            .method = "tools/call",
            .params = .{ .name = name, .arguments = args },
        });

        if (objectField(reply, "error")) |failure| {
            const message = failure.get("message") orelse std.json.Value.null;
            const text = if (message == .string) message.string else "the server refused the call";
            return .{ .text = text, .is_error = true };
        }

        const result = objectField(reply, "result") orelse
            return .{ .text = "the server answered nothing", .is_error = true };

        var text: std.ArrayList(u8) = .empty;
        if (result.get("content")) |content| {
            if (content == .array) {
                for (content.array.items) |part| {
                    if (part != .object) continue;
                    const kind = part.object.get("type") orelse std.json.Value.null;
                    const kind_name = if (kind == .string) kind.string else "";
                    const body = part.object.get("text") orelse std.json.Value.null;
                    if (body == .string and std.mem.eql(u8, kind_name, "text")) {
                        if (text.items.len != 0) try text.append(arena, '\n');
                        try text.appendSlice(arena, body.string);
                        continue;
                    }
                    if (text.items.len != 0) try text.append(arena, '\n');
                    const named = try std.fmt.allocPrint(
                        arena,
                        "[chock: the server sent a {s} part, which this build does not carry]",
                        .{if (kind_name.len != 0) kind_name else "content"},
                    );
                    try text.appendSlice(arena, named);
                }
            }
        }

        const failed = blk: {
            const raw = result.get("isError") orelse break :blk false;
            if (raw != .bool) break :blk false;
            break :blk raw.bool;
        };
        return .{ .text = try text.toOwnedSlice(arena), .is_error = failed };
    }

    fn nextId(self: *Protocol) i64 {
        self.last_id += 1;
        return self.last_id;
    }

    fn handshake(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
    ) mcp.Error!void {
        if (self.ready) return;

        if (self.handshake_id == null) {
            const id = self.nextId();
            try self.send(arena, io, channel, deadline, .{
                .jsonrpc = "2.0",
                .id = id,
                .method = "initialize",
                .params = .{
                    .protocolVersion = protocol_version,
                    .capabilities = empty_object,
                    .clientInfo = .{ .name = client_name, .version = "1" },
                },
            });
            self.handshake_id = id;
        }
        _ = try self.awaitReply(arena, io, channel, deadline, self.handshake_id.?);

        try self.send(arena, io, channel, deadline, .{
            .jsonrpc = "2.0",
            .method = "notifications/initialized",
            .params = empty_object,
        });

        self.ready = true;
    }

    fn request(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
        message: anytype,
    ) mcp.Error!std.json.Value {
        try self.send(arena, io, channel, deadline, message);
        return self.awaitReply(arena, io, channel, deadline, self.last_id);
    }

    fn send(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
        message: anytype,
    ) mcp.Error!void {
        _ = self;
        const body = try std.json.Stringify.valueAlloc(arena, message, .{});
        const framed = try std.fmt.allocPrint(arena, "{s}\n", .{body});
        channel.writeAll(io, framed, deadline) catch |err| return switch (err) {
            error.Late, error.HelperGone => error.Gone,
        };
    }

    fn awaitReply(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
        id: i64,
    ) mcp.Error!std.json.Value {
        while (true) {
            const message = try self.receive(arena, io, channel, deadline);
            if (message != .object) continue;
            const object = message.object;

            if (object.get("method")) |method| {
                if (method == .string and
                    std.mem.eql(u8, method.string, "notifications/tools/list_changed"))
                {
                    self.list_changed += 1;
                }
                continue;
            }

            const answered = object.get("id") orelse continue;
            if (answered != .integer or answered.integer != id) continue;
            if (object.get("result") == null and object.get("error") == null) continue;
            return message;
        }
    }

    fn receive(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
    ) mcp.Error!std.json.Value {
        while (true) {
            if (try self.takeLine(arena)) |line| {
                if (line.len == 0) continue;
                const parsed = std.json.parseFromSliceLeaky(
                    std.json.Value,
                    arena,
                    line,
                    .{},
                ) catch continue;
                return parsed;
            }

            var scratch: [read_chunk_bytes]u8 = undefined;
            const count = channel.read(io, &scratch, deadline) catch |err| return switch (err) {
                error.Late => error.Late,
                error.HelperGone => error.Gone,
            };
            if (self.inbox.items.len + count > max_inbox_bytes) {
                channel.poisoned = true;
                return error.Gone;
            }
            try self.inbox.appendSlice(self.gpa, scratch[0..count]);
        }
    }

    fn takeLine(self: *Protocol, arena: std.mem.Allocator) mcp.Error!?[]const u8 {
        const end = std.mem.indexOfScalar(u8, self.inbox.items, '\n') orelse return null;
        var body = self.inbox.items[0..end];
        if (body.len != 0 and body[body.len - 1] == '\r') body = body[0 .. body.len - 1];
        const line = try arena.dupe(u8, body);
        self.inbox.replaceRange(self.gpa, 0, end + 1, &.{}) catch unreachable;
        return line;
    }
};

pub const Driver = struct {
    gpa: std.mem.Allocator,

    process: *helper.Helper,

    request: helper.Request,

    protocol: Protocol,

    failure: ?[]const u8 = null,

    pub fn init(gpa: std.mem.Allocator, process: *helper.Helper, request: helper.Request) Driver {
        return .{
            .gpa = gpa,
            .process = process,
            .request = request,
            .protocol = .{ .gpa = gpa },
        };
    }

    pub fn deinit(self: *Driver) void {
        self.protocol.deinit();
        self.* = undefined;
    }

    pub fn host(self: *Driver) mcp.Host {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = mcp.Host.VTable{ .list = listFn, .call = callFn };

    fn listFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        budget_ns: u64,
    ) mcp.Error![]const mcp.Declared {
        const self: *Driver = @ptrCast(@alignCast(ptr));
        const channel = try self.live(io);
        const deadline = helper.Channel.deadlineIn(io, budget_ns);
        return self.protocol.list(arena, io, channel, deadline) catch |err| {
            return self.note(err);
        };
    }

    fn callFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) mcp.Error!mcp.Outcome {
        const self: *Driver = @ptrCast(@alignCast(ptr));
        const channel = try self.live(io);
        const deadline = helper.Channel.deadlineIn(io, budget_ns);
        return self.protocol.call(arena, io, channel, deadline, name, arguments) catch |err| {
            return self.note(err);
        };
    }

    fn note(self: *Driver, err: mcp.Error) mcp.Error {
        if (err == error.Gone and self.failure == null) self.failure = mcp.start_failed;
        return err;
    }

    fn live(self: *Driver, io: std.Io) mcp.Error!*helper.Channel {
        if (self.failure != null) return error.Gone;
        if (!self.process.started) {
            self.process.start(io, self.request) catch {
                self.failure = mcp.start_failed;
                return error.Gone;
            };
        }
        return self.process.live() orelse {
            if (self.failure == null) self.failure = mcp.start_failed;
            return error.Gone;
        };
    }
};

fn objectField(message: std.json.Value, name: []const u8) ?std.json.ObjectMap {
    if (message != .object) return null;
    const field = message.object.get(name) orelse return null;
    if (field != .object) return null;
    return field.object;
}

const testing = std.testing;
const chock_io = @import("chock-io");

const Pair = struct {
    channel: helper.Channel,
    server_reads: std.Io.File,
    server_writes: std.Io.File,

    fn open() !Pair {
        const driver = chock_io.default();
        const requests = try driver.pipeCloseOnExec();
        const replies = try driver.pipeCloseOnExec();
        return .{
            .channel = .{
                .to_helper = .{ .handle = requests.write_fd, .flags = .{ .nonblocking = false } },
                .from_helper = .{ .handle = replies.read_fd, .flags = .{ .nonblocking = false } },
            },
            .server_reads = .{ .handle = requests.read_fd, .flags = .{ .nonblocking = false } },
            .server_writes = .{ .handle = replies.write_fd, .flags = .{ .nonblocking = false } },
        };
    }

    fn serverSays(self: *Pair, io: std.Io, bytes: []const u8) !void {
        try std.Io.File.writeStreamingAll(self.server_writes, io, bytes);
    }

    fn clientWrote(self: *Pair, io: std.Io, buffer: []u8) ![]const u8 {
        var data: [1][]u8 = .{buffer};
        const count = try std.Io.File.readStreaming(self.server_reads, io, &data);
        return buffer[0..count];
    }

    fn close(self: *Pair, io: std.Io) void {
        for ([_]std.Io.File{
            self.channel.to_helper,
            self.channel.from_helper,
            self.server_reads,
            self.server_writes,
        }) |file| {
            if (file.handle < 0) continue;
            std.Io.File.close(file, io);
        }
    }
};

fn generousDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return helper.Channel.deadlineIn(io, 30 * std.time.ns_per_s);
}

const initialize_reply =
    \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"probe","version":"1"}}}
++ "\n";

const list_reply =
    \\{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_current_time","description":"Get current time","inputSchema":{"type":"object","properties":{"timezone":{"type":"string"}}}},{"name":"convert_time","description":"Convert","inputSchema":{"type":"object"}}]}}
++ "\n";

test "one exchange runs over two pipes, and the framing is a newline and never a header" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io, list_reply);

    const declared = try protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    );
    try testing.expectEqual(@as(usize, 2), declared.len);
    try testing.expectEqualStrings("get_current_time", declared[0].name);
    try testing.expectEqualStrings("Get current time", declared[0].description);
    try testing.expect(declared[0].schema == .object);
    try testing.expectEqualStrings("convert_time", declared[1].name);

    var buffer: [4096]u8 = undefined;
    const wrote = try pair.clientWrote(io, &buffer);
    try testing.expect(std.mem.indexOf(u8, wrote, "Content-Length") == null);
    var lines = std.mem.tokenizeScalar(u8, wrote, '\n');
    const first = lines.next().?;
    try testing.expect(std.mem.indexOf(u8, first, "\"method\":\"initialize\"") != null);
    try testing.expect(std.mem.indexOf(u8, first, "\"capabilities\":{}") != null);
    const second = lines.next().?;
    try testing.expect(std.mem.indexOf(u8, second, "notifications/initialized") != null);
    const third = lines.next().?;
    try testing.expect(std.mem.indexOf(u8, third, "\"method\":\"tools/list\"") != null);
    try testing.expect(lines.next() == null);
}

test "a request the server sends with the client's own id is not read as the reply" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{}}
    ++ "\n");
    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":2,"method":"roots/list"}
    ++ "\n");
    try pair.serverSays(io, list_reply);

    const declared = try protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    );
    try testing.expectEqual(@as(usize, 2), declared.len);
    try testing.expectEqualStrings("get_current_time", declared[0].name);
}

test "a notification, an empty line, and a line that is not JSON are all walked past" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, "\n");
    try pair.serverSays(io, "this is not JSON at all\n");
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"hello"}}
    ++ "\n");
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":99,"result":{}}
    ++ "\n");
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":1}
    ++ "\n");
    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io, list_reply);

    const declared = try protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    );
    try testing.expectEqual(@as(usize, 2), declared.len);
}

test "a server that says its tool list changed is counted, and nothing is added" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}
    ++ "\n");
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}
    ++ "\n");
    try pair.serverSays(io, list_reply);

    const declared = try protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    );
    try testing.expectEqual(@as(usize, 2), declared.len);
    try testing.expectEqual(@as(usize, 2), protocol.list_changed);
}

test "the handshake happens one time, however many asks follow" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io, list_reply);
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"noon"}]}}
    ++ "\n");

    const arena = arena_state.allocator();
    _ = try protocol.list(arena, io, &pair.channel, generousDeadline(io));
    const outcome = try protocol.call(arena, io, &pair.channel, generousDeadline(io), "get_current_time",
        \\{"timezone":"UTC"}
    );
    try testing.expectEqualStrings("noon", outcome.text);
    try testing.expect(!outcome.is_error);

    var buffer: [8192]u8 = undefined;
    const wrote = try pair.clientWrote(io, &buffer);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, wrote, "\"method\":\"initialize\""));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, wrote, "notifications/initialized"));
    try testing.expect(std.mem.indexOf(u8, wrote, "\"arguments\":{\"timezone\":\"UTC\"}") != null);
}

test "a JSON-RPC error and a tool that failed are both results, and neither ends anything" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"Invalid request parameters"}}
    ++ "\n");
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Invalid timezone"}],"isError":true}}
    ++ "\n");

    const failed = try protocol.call(arena, io, &pair.channel, generousDeadline(io), "a", "{}");
    try testing.expect(failed.is_error);
    try testing.expectEqualStrings("Invalid request parameters", failed.text);

    const refused = try protocol.call(arena, io, &pair.channel, generousDeadline(io), "b", "{}");
    try testing.expect(refused.is_error);
    try testing.expectEqualStrings("Invalid timezone", refused.text);
}

test "a content part this build cannot show is named and never silently dropped" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"first"},{"type":"image","data":"AAAA"},{"type":"text","text":"last"}]}}
    ++ "\n");

    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        "a",
        "{}",
    );
    try testing.expect(std.mem.indexOf(u8, outcome.text, "first") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.text, "image") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.text, "last") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.text, "AAAA") == null);
}

test "a server that dies mid sentence leaves no half message that reads as a whole one" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, "{\"jsonrpc\":\"2.0\",\"id\":1,\"resu");
    std.Io.File.close(pair.server_writes, io);
    pair.server_writes = .{ .handle = -1, .flags = .{ .nonblocking = false } };

    try testing.expectError(error.Gone, protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    ));
    try testing.expect(pair.channel.poisoned);
    try testing.expectError(error.Gone, protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    ));
}

test "a reply that misses its budget is late, and the exchange can be tried again" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const past = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Late, protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        past,
    ));
    try testing.expect(!pair.channel.poisoned);

    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"only","inputSchema":{}}]}}
    ++ "\n");
    const declared = try protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    );
    try testing.expectEqual(@as(usize, 1), declared.len);
    try testing.expectEqualStrings("only", declared[0].name);
}

test "a line that never ends is refused rather than grown until the machine complains" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const Flood = struct {
        fn run(file: std.Io.File, driver: std.Io) void {
            var block: [16 << 10]u8 = @splat('x');
            var written: usize = 0;
            while (written < max_inbox_bytes + block.len) : (written += block.len) {
                std.Io.File.writeStreamingAll(file, driver, &block) catch return;
            }
        }
    };
    const thread = try std.Thread.spawn(.{}, Flood.run, .{ pair.server_writes, io });
    defer thread.join();

    try testing.expectError(error.Gone, protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    ));
    try testing.expect(pair.channel.poisoned);

    std.Io.File.close(pair.channel.from_helper, io);
    pair.channel.from_helper = .{ .handle = -1, .flags = .{ .nonblocking = false } };
}

test "a driver that never started answers gone, and says so once" {
    const gpa = testing.allocator;
    var process = helper.Helper.init(gpa);
    defer process.deinit(testing.io);

    var driver = Driver.init(gpa, &process, .{
        .config = .{ .root = "/nowhere", .mounts = &.{}, .rules = &.{}, .cwd = "/", .env = &.{} },
        .argv = &.{"/probe"},
    });
    defer driver.deinit();

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    const host = driver.host();
    try testing.expectError(error.Gone, host.list(
        arena_state.allocator(),
        testing.io,
        mcp.discovery_budget_ns,
    ));
    try testing.expect(driver.failure != null);
    try testing.expectEqualStrings(mcp.start_failed, driver.failure.?);

    try testing.expectError(error.Gone, host.call(
        arena_state.allocator(),
        testing.io,
        "anything",
        "{}",
        mcp.call_budget_ns,
    ));
}

test "an initialize that ran out of budget is waited for again and never sent twice" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const past = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Late, protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        past,
    ));
    try testing.expectEqual(@as(?i64, 1), protocol.handshake_id);

    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io, list_reply);
    _ = try protocol.list(arena_state.allocator(), io, &pair.channel, generousDeadline(io));

    var buffer: [8192]u8 = undefined;
    const wrote = try pair.clientWrote(io, &buffer);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, wrote, "\"method\":\"initialize\""));
}
