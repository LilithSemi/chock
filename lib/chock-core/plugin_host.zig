//! The plugin host process, and the pipe that reaches it.

const std = @import("std");
const builtin = @import("builtin");

const sandbox = @import("chock-sandbox");

const helper = @import("helper.zig");
const plugin = @import("plugin.zig");
const plugin_engine = @import("plugin_engine.zig");

pub const verb = "__plugin-host";

pub fn selfProgramPath(
    keep: std.mem.Allocator,
    io: std.Io,
    exe_path: []const u8,
) std.mem.Allocator.Error!?[]const u8 {
    for ([_][]const u8{ "/proc/self/exe", exe_path }) |candidate| {
        if (candidate.len == 0) continue;
        const resolved = std.Io.Dir.cwd().realPathFileAlloc(io, candidate, keep) catch continue;
        std.debug.assert(std.fs.path.isAbsolute(resolved));
        return resolved;
    }
    return null;
}

pub const max_inbox_bytes = 8 << 20;

const read_chunk_bytes = 4096;

pub const Op = enum {
    call,
    result,

    pub fn name(self: Op) []const u8 {
        return @tagName(self);
    }
};

pub const Call = struct {
    op: []const u8 = "call",
    id: i64,
    index: u32,
    arguments: []const u8,
};

pub const Result = struct {
    op: []const u8 = "result",
    id: i64,
    is_error: bool,
    text: []const u8,
};

pub const Protocol = struct {
    gpa: std.mem.Allocator,

    inbox: std.ArrayList(u8) = .empty,

    last_id: i64 = 0,

    pub fn deinit(self: *Protocol) void {
        self.inbox.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn call(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
        index: u32,
        arguments: []const u8,
    ) plugin.Error!plugin.Outcome {
        self.last_id += 1;
        const id = self.last_id;

        try self.send(arena, io, channel, deadline, Call{
            .id = id,
            .index = index,
            .arguments = arguments,
        });

        const reply = try self.awaitReply(arena, io, channel, deadline, id);
        const text = blk: {
            const raw = reply.get("text") orelse break :blk "";
            if (raw != .string) break :blk "";
            break :blk raw.string;
        };
        const failed = blk: {
            const raw = reply.get("is_error") orelse break :blk false;
            if (raw != .bool) break :blk false;
            break :blk raw.bool;
        };
        return .{ .text = text, .is_error = failed };
    }

    fn send(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
        message: anytype,
    ) plugin.Error!void {
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
    ) plugin.Error!std.json.ObjectMap {
        while (true) {
            const message = try self.receive(arena, io, channel, deadline);
            if (message != .object) continue;
            const object = message.object;

            const op = object.get("op") orelse continue;
            if (op != .string or !std.mem.eql(u8, op.string, Op.result.name())) continue;
            const answered = object.get("id") orelse continue;
            if (answered != .integer or answered.integer != id) continue;
            return object;
        }
    }

    fn receive(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
    ) plugin.Error!std.json.Value {
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

    fn takeLine(self: *Protocol, arena: std.mem.Allocator) plugin.Error!?[]const u8 {
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

    pub fn host(self: *Driver) plugin.Host {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = plugin.Host.VTable{ .call = callFn };

    fn callFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        index: u32,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) plugin.Error!plugin.Outcome {
        const self: *Driver = @ptrCast(@alignCast(ptr));
        _ = name;
        const channel = try self.live(io);
        const deadline = helper.Channel.deadlineIn(io, budget_ns);
        return self.protocol.call(arena, io, channel, deadline, index, arguments) catch |err| {
            return self.note(err);
        };
    }

    fn note(self: *Driver, err: plugin.Error) plugin.Error {
        if (err == error.Gone and self.failure == null) self.failure = plugin.start_failed;
        return err;
    }

    fn live(self: *Driver, io: std.Io) plugin.Error!*helper.Channel {
        if (self.failure != null) return error.Gone;
        if (!self.process.started) {
            self.process.start(io, self.request) catch {
                self.failure = plugin.start_failed;
                return error.Gone;
            };
        }
        return self.process.live() orelse {
            if (self.failure == null) self.failure = plugin.start_failed;
            return error.Gone;
        };
    }
};

pub fn serve(
    gpa: std.mem.Allocator,
    io: std.Io,
    input: std.Io.File,
    output: std.Io.File,
    runner: ?*plugin_engine.Runner,
    load_failure: ?[]const u8,
) !void {
    var inbox: std.ArrayList(u8) = .empty;
    defer inbox.deinit(gpa);

    while (true) {
        const end = std.mem.indexOfScalar(u8, inbox.items, '\n') orelse {
            var scratch: [read_chunk_bytes]u8 = undefined;
            var data: [1][]u8 = .{&scratch};
            const count = std.Io.File.readStreaming(input, io, &data) catch return;
            if (count == 0) return;
            if (inbox.items.len + count > max_inbox_bytes) return error.MessageTooLong;
            try inbox.appendSlice(gpa, scratch[0..count]);
            continue;
        };

        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const line = try arena.dupe(u8, inbox.items[0..end]);
        inbox.replaceRange(gpa, 0, end + 1, &.{}) catch unreachable;

        const request = parseCall(arena, line) orelse continue;
        const answer = runOne(arena, runner, load_failure, request);

        const body = try std.json.Stringify.valueAlloc(arena, Result{
            .id = request.id,
            .is_error = answer.is_error,
            .text = answer.text,
        }, .{});
        const framed = try std.fmt.allocPrint(arena, "{s}\n", .{body});
        try std.Io.File.writeStreamingAll(output, io, framed);
    }
}

fn parseCall(arena: std.mem.Allocator, line: []const u8) ?struct { id: i64, index: u32, arguments: []const u8 } {
    if (line.len == 0) return null;
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{}) catch return null;
    if (parsed != .object) return null;

    const op = parsed.object.get("op") orelse return null;
    if (op != .string or !std.mem.eql(u8, op.string, Op.call.name())) return null;

    const id = parsed.object.get("id") orelse return null;
    if (id != .integer) return null;

    const index = parsed.object.get("index") orelse return null;
    if (index != .integer or index.integer < 0 or index.integer > std.math.maxInt(u32)) return null;

    const arguments = blk: {
        const raw = parsed.object.get("arguments") orelse break :blk "";
        if (raw != .string) break :blk "";
        break :blk raw.string;
    };

    return .{ .id = id.integer, .index = @intCast(index.integer), .arguments = arguments };
}

fn runOne(
    arena: std.mem.Allocator,
    runner: ?*plugin_engine.Runner,
    load_failure: ?[]const u8,
    request: anytype,
) plugin.Outcome {
    if (load_failure) |why| return .{ .text = why, .is_error = true };
    const live = runner orelse return .{
        .text = "this plugin has no engine in this build of Chock",
        .is_error = true,
    };

    const outcome = live.call(arena, request.index, request.arguments) catch |err| return .{
        .text = if (live.refusal) |detail|
            std.fmt.allocPrint(arena, "the plugin could not run that tool: {f}", .{detail}) catch
                "the plugin could not run that tool"
        else
            std.fmt.allocPrint(arena, "the plugin could not run that tool: {t}", .{err}) catch
                "the plugin could not run that tool",
        .is_error = true,
    };
    return .{
        .text = arena.dupe(u8, outcome.text) catch "the answer could not be held",
        .is_error = outcome.is_error,
    };
}

pub fn lockdown(
    allocator: std.mem.Allocator,
    config: sandbox.Config,
    reach: []const sandbox.Config.Rule,
) std.mem.Allocator.Error!sandbox.Config {
    const rules = try allocator.alloc(sandbox.Config.Rule, reach.len);
    for (rules, reach) |*slot, one| slot.* = .{ .path = one.path, .access = readOnly(one.access) };

    var out = config;
    out.network = .none;
    out.net_broker = null;
    out.net_router = null;
    out.rules = rules;
    return out;
}

pub fn readOnly(access: sandbox.landlock.AccessFs) sandbox.landlock.AccessFs {
    return .{
        .execute = access.execute,
        .read_file = access.read_file,
        .read_dir = access.read_dir,
    };
}

const testing = std.testing;
const chock_io = @import("chock-io");

const Pair = struct {
    channel: helper.Channel,
    host_reads: std.Io.File,
    host_writes: std.Io.File,

    fn open() !Pair {
        const driver = chock_io.default();
        const requests = try driver.pipeCloseOnExec();
        const replies = try driver.pipeCloseOnExec();
        return .{
            .channel = .{
                .to_helper = .{ .handle = requests.write_fd, .flags = .{ .nonblocking = false } },
                .from_helper = .{ .handle = replies.read_fd, .flags = .{ .nonblocking = false } },
            },
            .host_reads = .{ .handle = requests.read_fd, .flags = .{ .nonblocking = false } },
            .host_writes = .{ .handle = replies.write_fd, .flags = .{ .nonblocking = false } },
        };
    }

    fn hostSays(self: *Pair, io: std.Io, bytes: []const u8) !void {
        try std.Io.File.writeStreamingAll(self.host_writes, io, bytes);
    }

    fn harnessWrote(self: *Pair, io: std.Io, buffer: []u8) ![]const u8 {
        var data: [1][]u8 = .{buffer};
        const count = try std.Io.File.readStreaming(self.host_reads, io, &data);
        return buffer[0..count];
    }

    fn close(self: *Pair, io: std.Io) void {
        for ([_]std.Io.File{
            self.channel.to_helper,
            self.channel.from_helper,
            self.host_reads,
            self.host_writes,
        }) |file| {
            if (file.handle < 0) continue;
            std.Io.File.close(file, io);
        }
    }
};

fn generousDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return helper.Channel.deadlineIn(io, 30 * std.time.ns_per_s);
}

test "one call goes out as a line, and the answer comes back" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.hostSays(io,
        \\{"op":"result","id":1,"is_error":false,"text":"Hello, world!"}
    ++ "\n");

    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    );
    try testing.expectEqualStrings("Hello, world!", outcome.text);
    try testing.expect(!outcome.is_error);

    var buffer: [4096]u8 = undefined;
    const wrote = try pair.harnessWrote(io, &buffer);
    try testing.expect(std.mem.indexOf(u8, wrote, "Content-Length") == null);
    try testing.expect(std.mem.endsWith(u8, wrote, "\n"));
    try testing.expect(std.mem.indexOf(u8, wrote, "\"op\":\"call\"") != null);
    try testing.expect(std.mem.indexOf(u8, wrote, "\"index\":0") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, wrote, "\n"));
}

test "a message that is not a result is walked past, whatever id it carries" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.hostSays(io, "\n");
    try pair.hostSays(io, "this is not JSON at all\n");
    try pair.hostSays(io,
        \\{"op":"progress","id":1,"text":"still working"}
    ++ "\n");
    try pair.hostSays(io,
        \\{"op":"result","id":99,"is_error":false,"text":"somebody else"}
    ++ "\n");
    try pair.hostSays(io,
        \\{"op":"result","id":1,"is_error":false,"text":"the real one"}
    ++ "\n");

    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    );
    try testing.expectEqualStrings("the real one", outcome.text);
}

test "a plugin that crashes answers at once and stays gone" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.hostSays(io, "{\"op\":\"result\",\"id\":1,\"te");
    std.Io.File.close(pair.host_writes, io);
    pair.host_writes = .{ .handle = -1, .flags = .{ .nonblocking = false } };

    try testing.expectError(error.Gone, protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    ));
    try testing.expect(pair.channel.poisoned);
    try testing.expectError(error.Gone, protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    ));
}

test "a plugin that hangs is late, and the session goes on" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const past = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Late, protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        past,
        0,
        "{}",
    ));
    try testing.expect(!pair.channel.poisoned);

    try pair.hostSays(io,
        \\{"op":"result","id":1,"is_error":false,"text":"late but here"}
    ++ "\n");
    try pair.hostSays(io,
        \\{"op":"result","id":2,"is_error":false,"text":"the second one"}
    ++ "\n");
    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    );
    try testing.expectEqualStrings("the second one", outcome.text);
}

test "a tool that failed is a result and never a fault of this host" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.hostSays(io,
        \\{"op":"result","id":1,"is_error":true,"text":"no such file"}
    ++ "\n");

    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    );
    try testing.expect(outcome.is_error);
    try testing.expectEqualStrings("no such file", outcome.text);
}

test "the model's arguments cross as a string and not as a parsed object" {
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.hostSays(io,
        \\{"op":"result","id":1,"is_error":false,"text":"ok"}
    ++ "\n");
    _ = try protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        3,
        "{\"path\":\"a\\nb\"}",
    );

    var buffer: [4096]u8 = undefined;
    const wrote = try pair.harnessWrote(io, &buffer);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, wrote, "\n"));
    try testing.expect(std.mem.indexOf(u8, wrote, "\"index\":3") != null);
    try testing.expect(std.mem.indexOf(u8, wrote, "path") != null);
}

test "a driver whose process never started answers gone, and says so once" {
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
    try testing.expectError(error.Gone, host.call(
        arena_state.allocator(),
        testing.io,
        0,
        "hello",
        "{}",
        plugin.call_budget_ns,
    ));
    try testing.expect(driver.failure != null);
    try testing.expectEqualStrings(plugin.start_failed, driver.failure.?);

    try testing.expectError(error.Gone, host.call(
        arena_state.allocator(),
        testing.io,
        0,
        "hello",
        "{}",
        plugin.call_budget_ns,
    ));
}

test "the lockdown takes the network and every rule the caller's config carried" {
    const permissive: sandbox.Config = .{
        .root = "/tmp/root",
        .mounts = &.{},
        .rules = &.{
            .{ .path = "/work", .access = sandbox.landlock.AccessFs.read_write },
        },
        .cwd = "/work",
        .env = &.{"PATH=/bin"},
        .network = .host,
    };
    const locked = try lockdown(testing.allocator, permissive, &.{});
    defer testing.allocator.free(locked.rules);

    try testing.expect(locked.network == .none);
    try testing.expectEqual(@as(usize, 0), locked.rules.len);
    try testing.expectEqualStrings("/tmp/root", locked.root);
    try testing.expectEqualStrings("/work", locked.cwd);
    try testing.expectEqual(@as(usize, 1), locked.env.len);
}

test "a writable path the caller states comes back read only" {
    const base: sandbox.Config = .{
        .root = "/tmp/root",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    };
    const locked = try lockdown(testing.allocator, base, &.{
        .{ .path = "/plugin.wasm", .access = sandbox.landlock.AccessFs.read_write },
        .{ .path = "/chock", .access = .{ .execute = true, .read_file = true } },
    });
    defer testing.allocator.free(locked.rules);

    try testing.expectEqual(@as(usize, 2), locked.rules.len);
    try testing.expectEqualStrings("/plugin.wasm", locked.rules[0].path);
    try testing.expect(locked.rules[0].access.read_file);
    try testing.expect(!locked.rules[0].access.write_file);
    try testing.expect(!locked.rules[0].access.remove_file);
    try testing.expect(!locked.rules[0].access.truncate);
    try testing.expect(!locked.rules[0].access.refer);
    try testing.expect(!locked.rules[0].access.make_reg);
    try testing.expect(locked.rules[1].access.execute);
    try testing.expect(locked.rules[1].access.read_file);
}

test "readOnly keeps only the three rights that read something" {
    const every = readOnly(sandbox.landlock.AccessFs.all);
    try testing.expect(every.execute);
    try testing.expect(every.read_file);
    try testing.expect(every.read_dir);

    var left = every;
    left.execute = false;
    left.read_file = false;
    left.read_dir = false;
    try testing.expectEqual(@as(u64, 0), left.bits());
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
            var block: [64 << 10]u8 = @splat('x');
            var written: usize = 0;
            while (written < max_inbox_bytes + block.len) : (written += block.len) {
                std.Io.File.writeStreamingAll(file, driver, &block) catch return;
            }
        }
    };
    const thread = try std.Thread.spawn(.{}, Flood.run, .{ pair.host_writes, io });
    defer thread.join();

    try testing.expectError(error.Gone, protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    ));
    try testing.expect(pair.channel.poisoned);

    std.Io.File.close(pair.channel.from_helper, io);
    pair.channel.from_helper = .{ .handle = -1, .flags = .{ .nonblocking = false } };
}

test "the program that is running is the answer, and never whatever argv[0] named" {
    if (builtin.target.os.tag != .linux) {
        return error.SkipZigTest;
    }

    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const running = try std.Io.Dir.cwd().realPathFileAlloc(io, "/proc/self/exe", arena);
    const answer = (try selfProgramPath(arena, io, "/proc/self/cmdline")).?;
    try testing.expectEqualStrings(running, answer);
}

test "a bare argv[0] still gives an absolute path, because a mount source has to be one" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;

    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const answer = (try selfProgramPath(arena, io, "chock")).?;
    try testing.expect(std.fs.path.isAbsolute(answer));

    const running = try std.Io.Dir.cwd().realPathFileAlloc(io, "/proc/self/exe", arena);
    try testing.expectEqualStrings(running, answer);
}

test "an empty argv[0] is not a candidate" {
    if (builtin.target.os.tag == .linux) {
        return error.SkipZigTest;
    }

    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();

    try testing.expectEqual(
        @as(?[]const u8, null),
        try selfProgramPath(arena_state.allocator(), io, ""),
    );
}

comptime {
    _ = plugin_engine.max_imports;
}
