//! Background commands: a command runs while the turn goes on, its
//! output lands in a file, and the agent is told when it finishes.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const sandbox = @import("chock-sandbox");
const chock_proto = @import("chock-proto");

pub const sandbox_dir = "/run/chock/tasks";

pub fn sandboxDirFor(host_dir: []const u8) []const u8 {
    return if (sandbox.expresses.moved_paths) sandbox_dir else host_dir;
}

pub const host_leaf = @import("scratchpad.zig").tasks_leaf;

pub const extension = ".out";

pub const max_output_bytes: usize = 8 * 1024 * 1024;

pub const max_tasks: usize = 32;

pub const default_timeout_ns: u64 = 30 * 60 * std.time.ns_per_s;

pub const id_length = "task-00".len;

pub fn idFor(number: usize) [id_length]u8 {
    std.debug.assert(number >= 1 and number <= max_tasks);
    var out: [id_length]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "task-{d:0>2}", .{number}) catch unreachable;
    return out;
}

pub fn sandboxPathFor(
    allocator: std.mem.Allocator,
    host_dir: []const u8,
    id: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}{s}", .{ sandboxDirFor(host_dir), id, extension });
}

pub fn hostPathFor(
    allocator: std.mem.Allocator,
    tasks_dir: []const u8,
    id: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}{s}", .{ tasks_dir, id, extension });
}

pub const Request = struct {
    config: sandbox.Config,
    argv: []const []const u8,
    timeout_ns: u64 = default_timeout_ns,
    driver: sandbox.Sandbox.Driver = sandbox.Sandbox.native_driver,
    staged: []const []const u8 = &.{},
};

pub const Outcome = struct {
    status: chock_proto.event.TaskStatus,
    code: i64 = 0,
    output: []const u8,
    truncated: bool = false,
};

pub const Runner = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        run: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            request: *const Request,
        ) Outcome,
    };

    pub fn run(
        self: Runner,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: *const Request,
    ) Outcome {
        return self.vtable.run(self.ptr, allocator, io, request);
    }
};

pub const Completion = struct {
    id: []const u8,
    command: []const u8,
    status: chock_proto.event.TaskStatus,
    code: i64,
    output_path: []const u8,
    output_bytes: u64,
    truncated: bool,
};

pub fn freeCompletions(allocator: std.mem.Allocator, list: []Completion) void {
    for (list) |one| {
        allocator.free(one.id);
        allocator.free(one.command);
        allocator.free(one.output_path);
        if (one.status == .unknown) allocator.free(one.status.unknown);
    }
    allocator.free(list);
}

const Lock = struct {
    held: std.atomic.Value(bool) = .init(false),

    fn lock(self: *Lock) void {
        while (self.held.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.Thread.yield() catch std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *Lock) void {
        self.held.store(false, .release);
    }
};

pub const StartError = error{
    TooManyTasks,
} || std.mem.Allocator.Error;

pub const Table = struct {
    gpa: std.mem.Allocator,
    dir: []const u8,
    runner: Runner,

    mutex: Lock = .{},
    started: usize = 0,
    completed: usize = 0,
    finished: std.ArrayList(Completion) = .empty,
    threads: std.ArrayList(std.Thread) = .empty,
    lost: ?Diagnostic = null,

    pub fn takeLost(self: *Table) ?Diagnostic {
        self.mutex.lock();
        defer self.mutex.unlock();
        const taken = self.lost;
        self.lost = null;
        return taken;
    }

    fn noteLost(self: *Table, value: Diagnostic) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        diagnostic.note(&self.lost, value);
    }

    pub fn deinit(self: *Table) void {
        self.waitAll();
        if (self.take(self.gpa)) |taken| freeCompletions(self.gpa, taken) else |_| {}
        self.threads.deinit(self.gpa);
        self.finished.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn waitAll(self: *Table) void {
        while (true) {
            self.mutex.lock();
            const thread = self.threads.pop();
            self.mutex.unlock();
            if (thread) |one| one.join() else return;
        }
    }

    pub fn startedCount(self: *Table) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.started;
    }

    pub fn runningCount(self: *Table) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.started - self.completed;
    }

    pub fn start(
        self: *Table,
        io: std.Io,
        request: Request,
    ) StartError![id_length]u8 {
        self.mutex.lock();
        if (self.started >= max_tasks) {
            self.mutex.unlock();
            return error.TooManyTasks;
        }
        self.started += 1;
        const number = self.started;
        self.mutex.unlock();

        errdefer {
            self.mutex.lock();
            self.completed += 1;
            self.mutex.unlock();
        }

        const id = idFor(number);

        const job = try self.gpa.create(Job);
        errdefer self.gpa.destroy(job);
        job.* = .{ .table = self, .io = io, .id = id, .arena = .init(std.heap.page_allocator) };
        errdefer job.arena.deinit();

        job.request = try copyRequest(job.arena.allocator(), request);
        job.command = try joinArgv(job.arena.allocator(), request.argv);

        const thread = std.Thread.spawn(.{}, Job.run, .{job}) catch return error.OutOfMemory;

        self.mutex.lock();
        defer self.mutex.unlock();
        self.threads.append(self.gpa, thread) catch {
            diagnostic.note(&self.lost, .task_thread_not_tracked);
        };
        return id;
    }

    pub fn take(self: *Table, allocator: std.mem.Allocator) std.mem.Allocator.Error![]Completion {
        self.mutex.lock();
        defer self.mutex.unlock();

        const taken = try self.finished.toOwnedSlice(self.gpa);
        if (allocator.ptr == self.gpa.ptr and allocator.vtable == self.gpa.vtable) return taken;

        defer freeCompletions(self.gpa, taken);
        var copies = try allocator.alloc(Completion, taken.len);
        var made: usize = 0;
        errdefer freeCompletions(allocator, copies[0..made]);
        for (taken, 0..) |one, index| {
            copies[index] = .{
                .id = try allocator.dupe(u8, one.id),
                .command = try allocator.dupe(u8, one.command),
                .status = one.status,
                .code = one.code,
                .output_path = try allocator.dupe(u8, one.output_path),
                .output_bytes = one.output_bytes,
                .truncated = one.truncated,
            };
            made = index + 1;
        }
        return copies;
    }

    pub fn peek(self: *Table, allocator: std.mem.Allocator) std.mem.Allocator.Error![]Completion {
        self.mutex.lock();
        defer self.mutex.unlock();

        var copies = try allocator.alloc(Completion, self.finished.items.len);
        var made: usize = 0;
        errdefer freeCompletions(allocator, copies[0..made]);
        for (self.finished.items, 0..) |one, index| {
            copies[index] = .{
                .id = try allocator.dupe(u8, one.id),
                .command = try allocator.dupe(u8, one.command),
                .status = one.status,
                .code = one.code,
                .output_path = try allocator.dupe(u8, one.output_path),
                .output_bytes = one.output_bytes,
                .truncated = one.truncated,
            };
            made = index + 1;
        }
        return copies;
    }

    fn record(self: *Table, completion: Completion) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.completed += 1;
        self.finished.append(self.gpa, completion) catch {
            diagnostic.note(&self.lost, .task_record_not_kept);
        };
    }
};

const Job = struct {
    table: *Table,
    io: std.Io,
    id: [id_length]u8,
    arena: std.heap.ArenaAllocator,
    request: Request = undefined,
    command: []const u8 = undefined,

    fn run(self: *Job) void {
        const allocator = self.arena.allocator();
        const outcome = self.table.runner.run(allocator, self.io, &self.request);

        for (self.request.staged) |path| {
            std.Io.Dir.deleteFileAbsolute(self.io, path) catch {};
        }

        const host_path = hostPathFor(allocator, self.table.dir, &self.id) catch {
            self.finish(outcome, 0);
            return;
        };
        const written = writeOutput(self.io, host_path, outcome.output);
        self.finish(outcome, written);
    }

    fn finish(self: *Job, outcome: Outcome, written: u64) void {
        const gpa = self.table.gpa;
        const id = gpa.dupe(u8, &self.id) catch return self.release();
        const command = gpa.dupe(u8, self.command) catch {
            gpa.free(id);
            return self.release();
        };
        const output_path = sandboxPathFor(gpa, self.table.dir, &self.id) catch {
            gpa.free(id);
            gpa.free(command);
            return self.release();
        };
        self.table.record(.{
            .id = id,
            .command = command,
            .status = outcome.status,
            .code = outcome.code,
            .output_path = output_path,
            .output_bytes = written,
            .truncated = outcome.truncated,
        });
        self.release();
    }

    fn release(self: *Job) void {
        const gpa = self.table.gpa;
        self.arena.deinit();
        gpa.destroy(self);
    }
};

fn writeOutput(io: std.Io, path: []const u8, bytes: []const u8) u64 {
    var file = std.Io.Dir.createFileAbsolute(io, path, .{
        .permissions = .fromMode(0o600),
    }) catch return 0;
    defer file.close(io);
    file.writeStreamingAll(io, bytes) catch return 0;
    return bytes.len;
}

fn copyRequest(allocator: std.mem.Allocator, request: Request) std.mem.Allocator.Error!Request {
    var copy = request;
    copy.config = try request.config.copy(allocator);
    copy.argv = try sandbox.copyStrings(allocator, request.argv);
    copy.staged = try sandbox.copyStrings(allocator, request.staged);
    return copy;
}

fn joinArgv(allocator: std.mem.Allocator, argv: []const []const u8) std.mem.Allocator.Error![]const u8 {
    return std.mem.join(allocator, " ", argv);
}

const testing = std.testing;

const FakeRunner = struct {
    output: []const u8,
    status: chock_proto.event.TaskStatus = .exited,
    code: i64 = 0,
    truncated: bool = false,

    fn runner(self: *FakeRunner) Runner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: *const Request,
    ) Outcome {
        _ = io;
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));
        std.debug.assert(request.argv.len != 0);
        return .{
            .status = self.status,
            .code = self.code,
            .output = allocator.dupe(u8, self.output) catch &[_]u8{},
            .truncated = self.truncated,
        };
    }
};

const TestTable = struct {
    tmp: std.testing.TmpDir,
    dir: []u8,
    table: Table,

    fn init(gpa: std.mem.Allocator, fake: *FakeRunner) !TestTable {
        var tmp = testing.tmpDir(.{});
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(testing.io, &buffer);
        const dir = try std.fmt.allocPrint(gpa, "{s}/tasks", .{buffer[0..len]});
        try std.Io.Dir.createDirAbsolute(testing.io, dir, .default_dir);
        return .{
            .tmp = tmp,
            .dir = dir,
            .table = .{ .gpa = gpa, .dir = dir, .runner = fake.runner() },
        };
    }

    fn deinit(self: *TestTable, gpa: std.mem.Allocator) void {
        self.table.deinit();
        gpa.free(self.dir);
        self.tmp.cleanup();
    }
};

fn fakeConfig() sandbox.Config {
    return .{ .root = "/root", .mounts = &.{}, .rules = &.{}, .cwd = "/project", .env = &.{} };
}

test "a finished task writes its output to the host and reports where and how large" {
    const gpa = testing.allocator;
    var fake = FakeRunner{ .output = "build finished\n" };
    var harness = try TestTable.init(gpa, &fake);
    defer harness.deinit(gpa);

    const argv = [_][]const u8{ "make", "-j8" };
    const id = try harness.table.start(testing.io, .{ .config = fakeConfig(), .argv = &argv });
    try testing.expectEqualStrings("task-01", &id);

    harness.table.waitAll();
    const done = try harness.table.take(gpa);
    defer freeCompletions(gpa, done);

    try testing.expectEqual(@as(usize, 1), done.len);
    try testing.expectEqualStrings("task-01", done[0].id);
    try testing.expectEqualStrings("make -j8", done[0].command);
    try testing.expectEqual(chock_proto.event.TaskStatus.exited, done[0].status);
    try testing.expectEqual(@as(u64, "build finished\n".len), done[0].output_bytes);
    try testing.expect(!done[0].truncated);

    const expected_path = try sandboxPathFor(gpa, harness.dir, "task-01");
    defer gpa.free(expected_path);
    try testing.expectEqualStrings(expected_path, done[0].output_path);
    try testing.expect(std.mem.startsWith(u8, done[0].output_path, sandboxDirFor(harness.dir)));

    const host_path = try hostPathFor(gpa, harness.dir, &id);
    defer gpa.free(host_path);
    const contents = try std.Io.Dir.cwd().readFileAlloc(testing.io, host_path, gpa, .limited(1024));
    defer gpa.free(contents);
    try testing.expectEqualStrings("build finished\n", contents);

    const again = try harness.table.take(gpa);
    defer freeCompletions(gpa, again);
    try testing.expectEqual(@as(usize, 0), again.len);
}

test "peek reads a finished task without taking it, so the turn still drains it" {
    const gpa = testing.allocator;
    var fake = FakeRunner{ .output = "still building\n" };
    var harness = try TestTable.init(gpa, &fake);
    defer harness.deinit(gpa);

    const argv = [_][]const u8{"make"};
    _ = try harness.table.start(testing.io, .{ .config = fakeConfig(), .argv = &argv });
    harness.table.waitAll();

    const seen_first = try harness.table.peek(gpa);
    defer freeCompletions(gpa, seen_first);
    try testing.expectEqual(@as(usize, 1), seen_first.len);
    try testing.expectEqualStrings("task-01", seen_first[0].id);

    const seen_again = try harness.table.peek(gpa);
    defer freeCompletions(gpa, seen_again);
    try testing.expectEqual(@as(usize, 1), seen_again.len);
    try testing.expectEqualStrings("task-01", seen_again[0].id);

    const drained = try harness.table.take(gpa);
    defer freeCompletions(gpa, drained);
    try testing.expectEqual(@as(usize, 1), drained.len);
    try testing.expectEqualStrings("task-01", drained[0].id);
}

test "a task that has finished stops being a running task, however the record is drained" {
    const gpa = testing.allocator;
    var fake = FakeRunner{ .output = "done\n" };
    var harness = try TestTable.init(gpa, &fake);
    defer harness.deinit(gpa);

    try testing.expectEqual(@as(usize, 0), harness.table.runningCount());

    const argv = [_][]const u8{"true"};
    _ = try harness.table.start(testing.io, .{ .config = fakeConfig(), .argv = &argv });

    harness.table.waitAll();
    try testing.expectEqual(@as(usize, 0), harness.table.runningCount());
    const done = try harness.table.take(gpa);
    defer freeCompletions(gpa, done);
    try testing.expectEqual(@as(usize, 1), done.len);
    try testing.expectEqual(@as(usize, 0), harness.table.runningCount());
    try testing.expectEqual(@as(usize, 1), harness.table.startedCount());
}

test "a task keeps nothing of the tool call that started it" {
    const gpa = testing.allocator;
    var fake = FakeRunner{ .output = "ok" };
    var harness = try TestTable.init(gpa, &fake);
    defer harness.deinit(gpa);

    var call_arena = std.heap.ArenaAllocator.init(gpa);
    const call = call_arena.allocator();

    const mounts = try call.alloc(sandbox.namespace.Mount, 1);
    mounts[0] = .{ .bind = .{
        .source = try call.dupe(u8, "/nix/store/aaa"),
        .target = try call.dupe(u8, "/nix/store/aaa"),
        .read_only = true,
    } };
    const rules = try call.alloc(sandbox.Config.Rule, 1);
    rules[0] = .{ .path = try call.dupe(u8, "/project"), .access = .{} };
    const env = try call.alloc([]const u8, 1);
    env[0] = try call.dupe(u8, "TMPDIR=/run/chock/scratch");
    const argv = try call.alloc([]const u8, 1);
    argv[0] = try call.dupe(u8, "make");

    const id = try harness.table.start(testing.io, .{
        .config = .{
            .root = try call.dupe(u8, "/root"),
            .mounts = mounts,
            .rules = rules,
            .cwd = try call.dupe(u8, "/project"),
            .env = env,
        },
        .argv = argv,
    });

    call_arena.deinit();

    harness.table.waitAll();
    const done = try harness.table.take(gpa);
    defer freeCompletions(gpa, done);
    try testing.expectEqual(@as(usize, 1), done.len);
    try testing.expectEqualStrings(&id, done[0].id);
    try testing.expectEqualStrings("make", done[0].command);
}

test "a session may start max_tasks background tasks and no more" {
    const gpa = testing.allocator;
    var fake = FakeRunner{ .output = "x" };
    var harness = try TestTable.init(gpa, &fake);
    defer harness.deinit(gpa);

    const argv = [_][]const u8{"true"};
    var number: usize = 0;
    while (number < max_tasks) : (number += 1) {
        _ = try harness.table.start(testing.io, .{ .config = fakeConfig(), .argv = &argv });
    }
    try testing.expectEqual(max_tasks, harness.table.startedCount());
    try testing.expectError(
        error.TooManyTasks,
        harness.table.start(testing.io, .{ .config = fakeConfig(), .argv = &argv }),
    );

    harness.table.waitAll();
    const done = try harness.table.take(gpa);
    defer freeCompletions(gpa, done);
    try testing.expectEqual(max_tasks, done.len);
    try testing.expectError(
        error.TooManyTasks,
        harness.table.start(testing.io, .{ .config = fakeConfig(), .argv = &argv }),
    );
}

test "the file bound is far above what a model reads, and a capped task says truncated" {
    const tools_max = @import("tools.zig").max_output_bytes;
    try testing.expect(max_output_bytes > tools_max);
    try testing.expectEqual(@as(usize, 64 * 1024), tools_max);
    try testing.expectEqual(@as(usize, 8 * 1024 * 1024), max_output_bytes);
    try testing.expectEqual(@as(u64, 256 * 1024 * 1024), @as(u64, max_output_bytes) * max_tasks);

    const gpa = testing.allocator;
    var fake = FakeRunner{ .output = "the first bytes", .truncated = true };
    var harness = try TestTable.init(gpa, &fake);
    defer harness.deinit(gpa);

    const argv = [_][]const u8{"make"};
    _ = try harness.table.start(testing.io, .{ .config = fakeConfig(), .argv = &argv });
    harness.table.waitAll();

    const done = try harness.table.take(gpa);
    defer freeCompletions(gpa, done);
    try testing.expectEqual(@as(usize, 1), done.len);
    try testing.expect(done[0].truncated);
}

test "a task identifier is short, fixed width, and names its own file" {
    try testing.expectEqualStrings("task-01", &idFor(1));
    try testing.expectEqualStrings("task-32", &idFor(max_tasks));
    try testing.expectEqual(id_length, idFor(7).len);

    const gpa = testing.allocator;
    const host_dir = "/somewhere/on/the/host/tasks";
    const path = try sandboxPathFor(gpa, host_dir, &idFor(7));
    defer gpa.free(path);

    if (sandbox.expresses.moved_paths) {
        try testing.expectEqualStrings("/run/chock/tasks/task-07.out", path);
    } else {
        try testing.expectEqualStrings(host_dir ++ "/task-07.out", path);
    }
}

test "the background bound is far above a tool call's own, and is still a bound" {
    const call_bound = @import("tools.zig").default_timeout_ns;
    try testing.expect(default_timeout_ns > call_bound);
    try testing.expectEqual(@as(u64, 30 * 60 * std.time.ns_per_s), default_timeout_ns);
}
