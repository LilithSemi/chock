//! A helper: one long lived program inside the sandbox, reached over a pipe
//! in both directions, started by Chock and never named by the model.

const std = @import("std");
const sandbox = @import("chock-sandbox");
const chock_io = @import("chock-io");

pub const Error = error{
    HelperGone,
    Late,
};

pub const StartError = error{
    NoPipe,
    SpawnStuck,
} || std.mem.Allocator.Error;

pub const start_wait_ns: u64 = 5 * std.time.ns_per_s;

const start_step_ns: u64 = std.time.ns_per_ms;

pub const Request = struct {
    config: sandbox.Config,
    argv: []const []const u8,
};

pub const Channel = struct {
    to_helper: std.Io.File,
    from_helper: std.Io.File,

    poisoned: bool = false,

    pub fn deadlineIn(io: std.Io, budget_ns: u64) std.Io.Clock.Timestamp {
        return std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{
            .raw = .fromNanoseconds(@intCast(budget_ns)),
            .clock = .awake,
        });
    }

    pub fn writeAll(
        self: *Channel,
        io: std.Io,
        bytes: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.poisoned) return error.HelperGone;

        var written: usize = 0;
        while (written < bytes.len) {
            var data: [1][]const u8 = .{bytes[written..]};
            const outcome = std.Io.operateTimeout(io, .{ .file_write_streaming = .{
                .file = self.to_helper,
                .data = &data,
            } }, .{ .deadline = deadline }) catch |err| {
                self.poisoned = true;
                return switch (err) {
                    error.Timeout => error.Late,
                    else => error.HelperGone,
                };
            };
            const count = outcome.file_write_streaming catch {
                self.poisoned = true;
                return error.HelperGone;
            };
            if (count == 0) {
                self.poisoned = true;
                return error.HelperGone;
            }
            written += count;
        }
    }

    pub fn read(
        self: *Channel,
        io: std.Io,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        if (self.poisoned) return error.HelperGone;

        var data: [1][]u8 = .{buffer};
        const outcome = std.Io.operateTimeout(io, .{ .file_read_streaming = .{
            .file = self.from_helper,
            .data = &data,
        } }, .{ .deadline = deadline }) catch |err| switch (err) {
            error.Timeout => return error.Late,
            else => {
                self.poisoned = true;
                return error.HelperGone;
            },
        };
        const count = outcome.file_read_streaming catch {
            self.poisoned = true;
            return error.HelperGone;
        };
        if (count == 0) {
            self.poisoned = true;
            return error.HelperGone;
        }
        return count;
    }
};

pub const Helper = struct {
    arena: std.heap.ArenaAllocator,

    channel: ?Channel = null,

    null_fd: ?std.Io.File = null,

    thread: ?std.Thread = null,
    spawn_state: Spawn = .{},

    started: bool = false,

    pub fn init(gpa: std.mem.Allocator) Helper {
        return .{ .arena = .init(gpa) };
    }

    pub fn start(self: *Helper, io: std.Io, request: Request) StartError!void {
        return self.startWith(io, request, chock_io.default());
    }

    pub fn startWith(
        self: *Helper,
        io: std.Io,
        request: Request,
        driver: chock_io.Io,
    ) StartError!void {
        std.debug.assert(!self.started);
        self.started = true;

        const allocator = self.arena.allocator();
        const config_copy = try request.config.copy(allocator);
        const argv_copy = try sandbox.copyStrings(allocator, request.argv);

        const requests = driver.pipeCloseOnExec() catch return error.NoPipe;
        const replies = driver.pipeCloseOnExec() catch {
            closeRaw(io, requests.read_fd);
            closeRaw(io, requests.write_fd);
            return error.NoPipe;
        };

        var spawn_config = config_copy;
        spawn_config.stdin_fd = requests.read_fd;
        spawn_config.stdout_fd = replies.write_fd;
        // Stderr goes to /dev/null, not a pipe, so an undrained pipe cannot block the helper.
        const null_fd = std.Io.Dir.openFileAbsolute(io, "/dev/null", .{ .mode = .write_only }) catch null;
        if (null_fd) |file| spawn_config.stderr_fd = file.handle;

        self.spawn_state = .{ .allocator = allocator, .config = spawn_config, .argv = argv_copy };
        const thread = std.Thread.spawn(.{}, Spawn.run, .{&self.spawn_state}) catch {
            closeRaw(io, requests.read_fd);
            closeRaw(io, requests.write_fd);
            closeRaw(io, replies.read_fd);
            closeRaw(io, replies.write_fd);
            if (null_fd) |file| file.close(io);
            return error.OutOfMemory;
        };

        var waited: u64 = 0;
        while (@atomicLoad(std.posix.pid_t, &self.spawn_state.middle.pid, .acquire) == 0 and
            !self.spawn_state.done.load(.acquire) and waited < start_wait_ns)
        {
            std.Io.sleep(io, .fromNanoseconds(start_step_ns), .awake) catch {};
            waited += start_step_ns;
        }
        if (@atomicLoad(std.posix.pid_t, &self.spawn_state.middle.pid, .acquire) == 0 and
            !self.spawn_state.done.load(.acquire))
        {
            self.thread = thread;
            return error.SpawnStuck;
        }

        self.thread = thread;
        self.null_fd = null_fd;

        closeRaw(io, requests.read_fd);
        closeRaw(io, replies.write_fd);

        self.channel = .{
            .to_helper = .{ .handle = requests.write_fd, .flags = .{ .nonblocking = false } },
            .from_helper = .{ .handle = replies.read_fd, .flags = .{ .nonblocking = false } },
        };
    }

    pub fn live(self: *Helper) ?*Channel {
        if (self.channel) |*channel| {
            if (channel.poisoned) return null;
            return channel;
        }
        return null;
    }

    pub fn deinit(self: *Helper, io: std.Io) void {
        if (self.channel) |channel| {
            std.Io.File.close(channel.to_helper, io);
        }

        // Pairs with the release store in Spawn.run: a non-zero pid here means the handle beside it is already set.
        if (@atomicLoad(std.posix.pid_t, &self.spawn_state.middle.pid, .acquire) != 0) {
            sandbox.signalMiddle(self.spawn_state.middle.fd, std.posix.SIG.KILL) catch {};
        }

        if (self.thread) |one| one.join();
        sandbox.closeMiddle(&self.spawn_state.middle);

        if (self.channel) |channel| {
            std.Io.File.close(channel.from_helper, io);
        }
        if (self.null_fd) |file| file.close(io);
        self.channel = null;
        self.arena.deinit();
        self.* = undefined;
    }
};

fn closeRaw(io: std.Io, fd: std.posix.fd_t) void {
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    std.Io.File.close(file, io);
}

const Spawn = struct {
    allocator: std.mem.Allocator = undefined,
    config: sandbox.Config = undefined,
    argv: []const []const u8 = undefined,
    middle: sandbox.Middle = .{},
    done: std.atomic.Value(bool) = .init(false),
    term: std.process.Child.Term = undefined,
    spawn_err: ?sandbox.Sandbox.SpawnError = null,

    fn run(self: *Spawn) void {
        self.term = sandbox.spawn(self.allocator, self.config, self.argv, null, &self.middle) catch |err| {
            self.spawn_err = err;
            self.done.store(true, .release);
            return;
        };
        self.done.store(true, .release);
    }
};

const testing = std.testing;

const Pair = struct {
    channel: Channel,
    helper_reads: std.Io.File,
    helper_writes: std.Io.File,

    fn open() !Pair {
        const driver = chock_io.default();
        const requests = try driver.pipeCloseOnExec();
        const replies = try driver.pipeCloseOnExec();
        return .{
            .channel = .{
                .to_helper = .{ .handle = requests.write_fd, .flags = .{ .nonblocking = false } },
                .from_helper = .{ .handle = replies.read_fd, .flags = .{ .nonblocking = false } },
            },
            .helper_reads = .{ .handle = requests.read_fd, .flags = .{ .nonblocking = false } },
            .helper_writes = .{ .handle = replies.write_fd, .flags = .{ .nonblocking = false } },
        };
    }

    fn close(self: *Pair, io: std.Io) void {
        for ([_]std.Io.File{
            self.channel.to_helper,
            self.channel.from_helper,
            self.helper_reads,
            self.helper_writes,
        }) |file| {
            if (file.handle < 0) continue;
            std.Io.File.close(file, io);
        }
    }
};

fn generousDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return Channel.deadlineIn(io, 30 * std.time.ns_per_s);
}

test "a request reaches the helper and a reply comes back" {
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    try pair.channel.writeAll(io, "ask", generousDeadline(io));

    var seen: [8]u8 = undefined;
    var data: [1][]u8 = .{&seen};
    const got = try std.Io.File.readStreaming(pair.helper_reads, io, &data);
    try testing.expectEqualStrings("ask", seen[0..got]);

    try std.Io.File.writeStreamingAll(pair.helper_writes, io, "answer");
    var back: [8]u8 = undefined;
    const count = try pair.channel.read(io, &back, generousDeadline(io));
    try testing.expectEqualStrings("answer", back[0..count]);
}

test "a helper that exits answers the next read at once, and never waits" {
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    std.Io.File.close(pair.helper_writes, io);
    pair.helper_writes = .{ .handle = -1, .flags = .{ .nonblocking = false } };

    var back: [8]u8 = undefined;
    try testing.expectError(error.HelperGone, pair.channel.read(io, &back, generousDeadline(io)));
    try testing.expect(pair.channel.poisoned);

    try testing.expectError(error.HelperGone, pair.channel.read(io, &back, generousDeadline(io)));
}

test "a write to a helper that has gone is a failure, not a hang and not a silent success" {
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    std.Io.File.close(pair.helper_reads, io);
    pair.helper_reads = .{ .handle = -1, .flags = .{ .nonblocking = false } };

    try testing.expectError(
        error.HelperGone,
        pair.channel.writeAll(io, "ask", generousDeadline(io)),
    );
    try testing.expect(pair.channel.poisoned);

    var back: [8]u8 = undefined;
    try testing.expectError(error.HelperGone, pair.channel.read(io, &back, generousDeadline(io)));
    try testing.expectError(error.HelperGone, pair.channel.writeAll(io, "ask", generousDeadline(io)));
}

test "a reply that misses its budget is late, and the channel still works" {
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    const past = std.Io.Clock.Timestamp.now(io, .awake);
    var back: [16]u8 = undefined;
    try testing.expectError(error.Late, pair.channel.read(io, &back, past));
    try testing.expect(!pair.channel.poisoned);

    try std.Io.File.writeStreamingAll(pair.helper_writes, io, "answer");
    const count = try pair.channel.read(io, &back, generousDeadline(io));
    try testing.expectEqualStrings("answer", back[0..count]);
}

test "a helper that never started has no channel at all" {
    var helper = Helper.init(testing.allocator);
    try testing.expect(helper.live() == null);
    helper.deinit(testing.io);
}

test "a start whose pipe cannot be made leaves nothing behind" {
    var helper = Helper.init(testing.allocator);
    defer helper.deinit(testing.io);

    const result = helper.startWith(testing.io, .{
        .config = .{ .root = "/nowhere", .mounts = &.{}, .rules = &.{}, .cwd = "/", .env = &.{} },
        .argv = &.{"/probe"},
    }, chock_io.Fake.driver());
    try testing.expectError(error.NoPipe, result);
    try testing.expect(helper.live() == null);
}
