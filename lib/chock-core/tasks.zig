//! Background commands: a command runs while the turn goes on, its output
//! lands in a file, and the agent is told when it finishes.
//!
//! ## The ceiling this removes
//!
//! A tool call is bounded by `tools.default_timeout_ns`, two minutes, so a
//! long build simply fails and **a project large enough to take minutes to
//! compile cannot be worked on at all**. There is no way to raise that bound
//! for one call without raising it for every call, and a two minute wait on
//! every `cat` is a different fault. A command that runs in the background is
//! the answer: the turn continues, and the result arrives later.
//!
//! ## The agent reads the output and cannot write it
//!
//! **This is the constraint that matters and it is not tidiness.** The file is
//! a record of what a command produced. An agent that could edit it could
//! fabricate a result: a build that failed, edited to say it passed, then cited
//! as evidence on the next turn. That is the same principle the append only
//! session log rests on, applied one level down.
//!
//! Mechanically it is a shape this project already has. The command runs inside
//! the sandbox writing to a pipe, **the harness reads that pipe and writes the
//! file on the host**, outside any sandbox, and the directory is bound into the
//! sandbox read only. `/run/chock` already carries a read only mount beside a
//! writable one, so nothing new is needed. See `lib/chock-core/tools.zig`'s own
//! `runCommand` for the two mounts side by side.
//!
//! **So this cannot live in the scratchpad.** The scratchpad is agent writable
//! by definition, and a `tasks` directory inside it would be writable whatever
//! the intent. Sibling directories, different mounts, different rules. See
//! `lib/chock-core/scratchpad.zig`.
//!
//! ## What the log records
//!
//! That the task ran, its exit status, where its output is, and how large it
//! was. **Not the contents.** A build's output is megabytes and the session log
//! is the one file a session cannot afford to bloat. See
//! `chock_proto.event.TaskComplete`, which carries exactly those fields.
//!
//! The completion is an event, so an agent acting on a background result leaves
//! a trace of having been told, the same way a subagent completion would.
//! `lib/chock-core/Loop.zig` delivers it at a safe point, which is where that
//! loop already reads the interrupt flag: the top of a turn, and the gap
//! between two tool calls of one turn.
//!
//! ## Two bounds, and both are needed
//!
//! `max_output_bytes` bounds one file and `max_tasks` bounds how many files
//! there are. Either one alone is not a bound: an unbounded number of eight
//! mebibyte files fills a disk exactly as well as one unbounded file.
//!
//! `max_output_bytes` is far above `tools.max_output_bytes`, and deliberately.
//! That number bounds what a **model** reads, 64 KiB, because a model pays for
//! every byte of it. The file has no such reason to be small: it is read with
//! `grep` and `tail` by a program, and a build log that stopped at 64 KiB would
//! have the one error in it cut off. Past the bound the harness keeps draining
//! the pipe and discards what it reads, so the command still finishes rather
//! than blocking on a full pipe, and the record says `truncated`.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
/// Why a piece of the loop's own scaffolding could not be made or kept. One
/// type for the whole module: see `chock-core/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;
const sandbox = @import("chock-sandbox");
const chock_proto = @import("chock-proto");

/// Where task output is mounted inside the sandbox, **read only**, on a build
/// that can move a path. See `sandboxDirFor`, which is what a caller asks.
///
/// Beside the scratchpad and never inside it. Written out here, the way
/// `cache.zig` and `memory.zig` write out their own, because this file states
/// the path and the sandbox library only carries it.
pub const sandbox_dir = "/run/chock/tasks";

/// Where the task directory `host_dir` appears inside the sandbox.
///
/// **Two answers, one per platform**, the same split `cache.sandboxDirFor` and
/// `scratchpad.sandboxDirFor` make. The read only half of the rule is kept
/// either way: on macOS the mount becomes a rule that permits a read and denies
/// a write, so the agent still cannot edit a record of what a command produced.
pub fn sandboxDirFor(host_dir: []const u8) []const u8 {
    return if (sandbox.expresses.moved_paths) sandbox_dir else host_dir;
}

/// The name of the directory on the host, relative to the session scratchpad.
/// The same name `scratchpad.tasks_leaf` builds, read from there so the two
/// cannot drift apart.
pub const host_leaf = @import("scratchpad.zig").tasks_leaf;

/// What one task's output file is called after its identifier.
pub const extension = ".out";

/// How much of one task's output is kept on disk. See this file's own top
/// comment for why this is not `tools.max_output_bytes`.
pub const max_output_bytes: usize = 8 * 1024 * 1024;

/// How many background tasks one session may start.
///
/// Thirty two, and with `max_output_bytes` this bounds the whole directory at
/// 256 MiB with no walk of it at all. A completed task's file stays for the
/// rest of the session, because it is a record and a record something removes
/// to make room is not a record, so the count is the only thing that can give
/// the bound.
pub const max_tasks: usize = 32;

/// How long one background task may run before the harness stops it.
///
/// Thirty minutes. The ceiling this whole file removes is a build of minutes,
/// so the bound has to be far above `tools.default_timeout_ns`; it is still a
/// bound, because a task nobody stops holds a thread and a sandbox for as long
/// as the session lives.
pub const default_timeout_ns: u64 = 30 * 60 * std.time.ns_per_s;

/// How many characters a task identifier has: `task-01` through `task-32`.
pub const id_length = "task-00".len;

/// The identifier of the `number`th task of a session, counting from one.
/// Short and readable, because the agent reads it in a tool result and names it
/// in the next call.
pub fn idFor(number: usize) [id_length]u8 {
    std.debug.assert(number >= 1 and number <= max_tasks);
    var out: [id_length]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "task-{d:0>2}", .{number}) catch unreachable;
    return out;
}

/// Where the agent finds the output of the task `id`, given the host directory
/// the task files are written to. Caller owns the result.
///
/// **The agent never builds this path and never names one.** It comes back in
/// the result of the call that started the task, and the only thing the agent
/// does with it is read it. That is what lets the path differ between platforms
/// with nothing to relearn: see `sandboxDirFor`.
pub fn sandboxPathFor(
    allocator: std.mem.Allocator,
    host_dir: []const u8,
    id: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}{s}", .{ sandboxDirFor(host_dir), id, extension });
}

/// Where the harness writes the output of the task `id`. Caller owns the
/// result.
pub fn hostPathFor(
    allocator: std.mem.Allocator,
    tasks_dir: []const u8,
    id: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}{s}", .{ tasks_dir, id, extension });
}

/// One command to run in the background, and everything running it needs.
/// Borrowed by the caller of `Table.start`, which copies every part of it that
/// outlives the call: see `Table.start`.
pub const Request = struct {
    config: sandbox.Config,
    argv: []const []const u8,
    timeout_ns: u64 = default_timeout_ns,
};

/// What a `Runner` answers with once the command has ended.
pub const Outcome = struct {
    status: chock_proto.event.TaskStatus,
    /// The exit code, or the signal number for a command a signal ended. Zero
    /// when the status names neither.
    code: i64 = 0,
    /// The command's own combined output, capped at `max_output_bytes`. Owned
    /// by the allocator the runner was given, which is the task's own arena, so
    /// nothing here is freed one piece at a time.
    output: []const u8,
    /// True when the command wrote more than `max_output_bytes`.
    truncated: bool = false,
};

/// What actually runs a command inside the sandbox.
///
/// **A seam, because the thing on the other side of it is `Sandbox.spawn`.**
/// `lib/chock-core/tools.zig` owns the pipe, the deadline, and the capture, and
/// this file owns the identifiers, the files, the bounds and the bookkeeping. A
/// test of the bookkeeping then needs no sandbox at all, which is what lets the
/// tests at the bottom of this file pin the read only rule and the two bounds
/// on both platforms instead of on Linux alone.
pub const Runner = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Run `request` to its end and answer what it produced. Called on a
        /// thread of the table's own, never on the caller's.
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

/// One finished task, as the log records it and as the agent is told it.
///
/// Every string is owned by the allocator `Table.take` was given, and freed
/// with `freeCompletions`.
pub const Completion = struct {
    id: []const u8,
    /// The command, joined with single spaces, so a person reading the log
    /// knows what ran. Not the arguments as JSON: the log already holds the
    /// `tool.call` that asked for it.
    command: []const u8,
    status: chock_proto.event.TaskStatus,
    code: i64,
    /// Where the output is, as the agent sees it. The host path is not
    /// recorded: it names a temp directory that no longer exists by the time
    /// anybody replays the log.
    output_path: []const u8,
    output_bytes: u64,
    truncated: bool,
};

/// Free a slice `Table.take` returned.
pub fn freeCompletions(allocator: std.mem.Allocator, list: []Completion) void {
    for (list) |one| {
        allocator.free(one.id);
        allocator.free(one.command);
        allocator.free(one.output_path);
        if (one.status == .unknown) allocator.free(one.status.unknown);
    }
    allocator.free(list);
}

/// The lock the table's own bookkeeping is kept under.
///
/// **Small on purpose.** `std.Io.Mutex.lock` takes an `Io` and answers
/// `Cancelable!void`, and a thread that is recording its own completion has no
/// answer to "you were canceled": it has already run the command and written
/// the file, so there is nothing left it may skip. Every critical section here
/// is one append or one pop of a list, so the wait is measured in
/// instructions.
const Lock = struct {
    held: std.atomic.Value(bool) = .init(false),

    fn lock(self: *Lock) void {
        while (self.held.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            // Give the other thread the processor rather than spinning on it.
            // A yield this platform refuses leaves the spin, which is correct
            // and only slower.
            std.Thread.yield() catch std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *Lock) void {
        self.held.store(false, .release);
    }
};

pub const StartError = error{
    /// This session has already started `max_tasks` background tasks. See that
    /// constant: the files are records and none of them is removed to make
    /// room, so the count is the whole bound.
    TooManyTasks,
} || std.mem.Allocator.Error;

/// Every background task of one session.
///
/// **Owned by the caller that owns the session**, which is `src/run.zig`, for
/// the same reason it owns the workspace and the credential store: a task
/// outlives the tool call that started it, and `tools.Registry.dispatch` is
/// built to know nothing that outlives one call.
pub const Table = struct {
    /// The allocator the records and the thread list are kept in.
    ///
    /// **Give this one no fork ever inherits a lock from.** A task's own thread
    /// allocates from it while another thread may be inside `Sandbox.spawn`,
    /// and `fork` carries only the calling thread, so a lock held at that
    /// moment is copied into the child as held forever. `src/run.zig` gives
    /// `std.heap.page_allocator`, which is the same answer `spawnCapturing`'s
    /// own thread arena already gives, for the reason
    /// `lib/chock-core/tools.zig`'s own top comment states in full.
    gpa: std.mem.Allocator,
    /// The host directory output files are written to. Borrowed, and kept
    /// alive by the caller for as long as this table is.
    dir: []const u8,
    runner: Runner,

    /// Guards everything below it. Taken by a task's own thread when it
    /// finishes, and by the loop when it drains.
    mutex: Lock = .{},
    started: usize = 0,
    /// How many tasks have finished, over the whole session. **Never goes
    /// down, and it is not `finished.items.len`**: that list is drained by
    /// every `take`, so it says how many finished since the last drain and not
    /// how many finished at all. See `runningCount`, which is the only reader.
    completed: usize = 0,
    finished: std.ArrayList(Completion) = .empty,
    threads: std.ArrayList(std.Thread) = .empty,
    /// The first thing this table lost, for the caller to report.
    ///
    /// **A field and not a print.** Both sites that fill it run on a
    /// child's own thread, under the mutex, at the one moment the
    /// allocator has already refused, so there is no error to give back
    /// and nothing to allocate a message in. `takeLost` is where the
    /// caller reads it; `src/run.zig` does that when the session ends.
    lost: ?Diagnostic = null,

    /// Wait for every task still running, then free everything.
    ///
    /// **It waits, and that is not optional.** A thread of this table holds a
    /// sandboxed process and writes into a directory this process is about to
    /// remove. Leaving one running past the end of the session would leave a
    /// program with no parent writing into a path that is gone.
    /// The first thing this table lost, and null once it has been taken.
    /// **The first, not the last**: a record that could not be kept and a
    /// thread that could not be tracked both mean the allocator refused,
    /// and the first refusal is the one that explains the run.
    pub fn takeLost(self: *Table) ?Diagnostic {
        self.mutex.lock();
        defer self.mutex.unlock();
        const taken = self.lost;
        self.lost = null;
        return taken;
    }

    /// Record a loss from a thread that does not already hold the mutex.
    fn noteLost(self: *Table, value: Diagnostic) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        diagnostic.note(&self.lost, value);
    }

    pub fn deinit(self: *Table) void {
        self.waitAll();
        // Whatever finished and was never drained. The table's own allocator
        // owns it, so this is the last chance anything has to free it.
        if (self.take(self.gpa)) |taken| freeCompletions(self.gpa, taken) else |_| {}
        self.threads.deinit(self.gpa);
        self.finished.deinit(self.gpa);
        self.* = undefined;
    }

    /// Wait for every task that is still running. Takes no lock while it
    /// waits: a thread that is finishing needs the lock to record itself.
    pub fn waitAll(self: *Table) void {
        while (true) {
            self.mutex.lock();
            const thread = self.threads.pop();
            self.mutex.unlock();
            if (thread) |one| one.join() else return;
        }
    }

    /// How many tasks this session has started. Never goes down: the bound is
    /// on the whole session, not on how many run at once.
    pub fn startedCount(self: *Table) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.started;
    }

    /// How many tasks are running right now.
    ///
    /// **What a handover asks about.** A background command lives in this
    /// process: its thread is here and only this process writes its
    /// `task.complete` into the log. So a session that let another process
    /// take it while one was running would lose that record, and the person
    /// who asked for the handover would believe the command carried on. See
    /// `chock_broker.handover`, which refuses for exactly this count.
    ///
    /// **Counted from two totals and never from the thread list.** `threads`
    /// holds every thread this table ever started, because a thread is removed
    /// only by `waitAll`, so its length is the number started and not the
    /// number running.
    pub fn runningCount(self: *Table) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.started - self.completed;
    }

    /// Start `request` in the background and answer the identifier of the task.
    ///
    /// **Every part of `request` is copied.** The `sandbox.Config` a tool call
    /// holds borrows its mounts, its rules and its environment from an arena
    /// that is freed the moment the call returns, and this outlives that by
    /// definition. A task that read the caller's own slices would be reading
    /// freed memory on the first turn that finished before it did.
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

        // **A task counted and never started must be counted back.** Everything
        // below can fail, and `runningCount` is `started` less `completed`, so
        // one failure here would leave that count above zero for the rest of
        // the session. A handover of the session would then be refused for ever
        // with "this session still holds 1 background command", which is a
        // session nothing can move and nothing that says why.
        errdefer {
            self.mutex.lock();
            self.completed += 1;
            self.mutex.unlock();
        }

        const id = idFor(number);

        const job = try self.gpa.create(Job);
        errdefer self.gpa.destroy(job);
        // Backed by the page allocator directly, never by `self.gpa`: this
        // arena is used by the task's own thread, beside a thread that may be
        // inside `Sandbox.spawn`. See `Table.gpa`.
        job.* = .{ .table = self, .io = io, .id = id, .arena = .init(std.heap.page_allocator) };
        errdefer job.arena.deinit();

        job.request = try copyRequest(job.arena.allocator(), request);
        job.command = try joinArgv(job.arena.allocator(), request.argv);

        const thread = std.Thread.spawn(.{}, Job.run, .{job}) catch return error.OutOfMemory;

        self.mutex.lock();
        defer self.mutex.unlock();
        self.threads.append(self.gpa, thread) catch {
            // The task is already running and its thread will record its own
            // completion, so the only thing lost is the join in `waitAll`.
            // Kept rather than swallowed, and kept rather than printed: see
            // `lost`.
            diagnostic.note(&self.lost, .task_thread_not_tracked);
        };
        return id;
    }

    /// Every task that has finished since the last call. The caller owns the
    /// result and frees it with `freeCompletions`.
    ///
    /// **Answers an empty slice when nothing finished**, which is the ordinary
    /// case and costs one lock. `Loop` calls this at every safe point.
    pub fn take(self: *Table, allocator: std.mem.Allocator) std.mem.Allocator.Error![]Completion {
        self.mutex.lock();
        defer self.mutex.unlock();

        const taken = try self.finished.toOwnedSlice(self.gpa);
        if (allocator.ptr == self.gpa.ptr and allocator.vtable == self.gpa.vtable) return taken;

        // A caller with an allocator of its own gets its own copies, so a turn
        // arena can hold them and the table's own allocator is never freed
        // from two places.
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

    /// Called by a task's own thread once it has written its output file.
    fn record(self: *Table, completion: Completion) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        // Before the append, and outside its `catch`: this task has stopped
        // running whether or not its record could be kept, and a count that
        // missed one would leave `runningCount` believing a task runs for ever,
        // which would refuse every handover of that session from then on.
        self.completed += 1;
        self.finished.append(self.gpa, completion) catch {
            // The record is what the log is built from, so losing one is
            // worth keeping. The file itself is already on disk either way.
            diagnostic.note(&self.lost, .task_record_not_kept);
        };
    }
};

/// One background task, alive from `Table.start` until its own thread ends.
/// Everything it reads is in its own arena, so nothing it touches belongs to
/// the tool call that started it.
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

        const host_path = hostPathFor(allocator, self.table.dir, &self.id) catch {
            self.finish(outcome, 0);
            return;
        };
        const written = writeOutput(self.io, host_path, outcome.output);
        self.finish(outcome, written);
    }

    /// Record the completion in the table's own allocator, then free the whole
    /// job. Nothing of the arena survives this call.
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

/// Write `bytes` to `path` on the host and answer how many landed there.
///
/// **This runs outside every sandbox**, in the harness process, which is what
/// makes the file a record the agent cannot edit. A failure answers zero: the
/// completion is still recorded, with a size of zero, so the agent learns the
/// task ended rather than waiting for a message that never comes.
fn writeOutput(io: std.Io, path: []const u8, bytes: []const u8) u64 {
    var file = std.Io.Dir.createFileAbsolute(io, path, .{
        // Nobody else on the host reads the output of a command run for this
        // user, the same mode `tools.stageContent` gives a staged file.
        .permissions = .fromMode(0o600),
    }) catch return 0;
    defer file.close(io);
    file.writeStreamingAll(io, bytes) catch return 0;
    return bytes.len;
}

/// A copy of `request` in `allocator`, sharing nothing with the original.
///
/// The config itself is copied by `sandbox.Config.copy`, which lives in the
/// library that owns the type: a second spelling here would be a copy that
/// forgets whichever field is added next. See its own doc comment.
fn copyRequest(allocator: std.mem.Allocator, request: Request) std.mem.Allocator.Error!Request {
    var copy = request;
    copy.config = try request.config.copy(allocator);
    copy.argv = try sandbox.copyStrings(allocator, request.argv);
    return copy;
}

/// The command as one line, for the log and for the agent. Single spaces, and
/// no quoting: this is read by a person, and the argv itself is already in the
/// `tool.call` event beside it.
fn joinArgv(allocator: std.mem.Allocator, argv: []const []const u8) std.mem.Allocator.Error![]const u8 {
    return std.mem.join(allocator, " ", argv);
}

const testing = std.testing;

/// A `Runner` that runs nothing and answers what a test told it to. The whole
/// point of the seam: the bookkeeping, the files, and the bounds are provable
/// with no sandbox, so they are provable on both platforms.
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
        // Read the copied request, so a test that freed the original would
        // fail here rather than pass by luck.
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

/// A `sandbox.Config` that names nothing real. Nothing here ever reaches
/// `Sandbox.spawn`, because `FakeRunner` runs nothing: these tests are about
/// the copy, the file, and the bounds.
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

    // Named from the directory the table really writes to, so this reads the
    // same fact on a build that moves a path and on one that does not: see
    // `sandboxDirFor`.
    const expected_path = try sandboxPathFor(gpa, harness.dir, "task-01");
    defer gpa.free(expected_path);
    try testing.expectEqualStrings(expected_path, done[0].output_path);
    try testing.expect(std.mem.startsWith(u8, done[0].output_path, sandboxDirFor(harness.dir)));

    // And the bytes really are on the host, written by this process and not by
    // anything inside a sandbox.
    const host_path = try hostPathFor(gpa, harness.dir, &id);
    defer gpa.free(host_path);
    const contents = try std.Io.Dir.cwd().readFileAlloc(testing.io, host_path, gpa, .limited(1024));
    defer gpa.free(contents);
    try testing.expectEqualStrings("build finished\n", contents);

    // Drained means drained: a second call answers nothing, so a loop that
    // polls at every safe point cannot tell the agent about one task twice.
    const again = try harness.table.take(gpa);
    defer freeCompletions(gpa, again);
    try testing.expectEqual(@as(usize, 0), again.len);
}

test "a task that has finished stops being a running task, however the record is drained" {
    // The count has to come from two totals and never from `finished.items.len`
    // or from `threads`. `finished` is emptied by every `take`, and `threads`
    // holds every thread ever started, because a thread is removed only by
    // `waitAll`. Mutation check: answer `finished.items.len`, and the last line
    // below reads zero while a task is still running; answer
    // `threads.items.len`, and the middle line reads one after the task is
    // over, so that session refuses every handover for the rest of its life.
    const gpa = testing.allocator;
    var fake = FakeRunner{ .output = "done\n" };
    var harness = try TestTable.init(gpa, &fake);
    defer harness.deinit(gpa);

    try testing.expectEqual(@as(usize, 0), harness.table.runningCount());

    const argv = [_][]const u8{"true"};
    _ = try harness.table.start(testing.io, .{ .config = fakeConfig(), .argv = &argv });

    // **Waited for and not timed.** This suite measures no elapsed time: the
    // join is what makes the task over, not a number of milliseconds.
    harness.table.waitAll();
    try testing.expectEqual(@as(usize, 0), harness.table.runningCount());
    // Still zero once the record has been drained, which is the case
    // `finished.items.len` gets wrong.
    const done = try harness.table.take(gpa);
    defer freeCompletions(gpa, done);
    try testing.expectEqual(@as(usize, 1), done.len);
    try testing.expectEqual(@as(usize, 0), harness.table.runningCount());
    // And the session still remembers it started one, which is what the cap is
    // measured against.
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

    // The dispatch returns, and everything it allocated goes with it.
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

    // The count is of the whole session and never goes down. A task that
    // finished still holds its file, because the file is a record, so a table
    // that let a finished task free a slot would break the disk bound the
    // count is there to give.
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
    // Two different numbers for two different readers. `tools.max_output_bytes`
    // bounds what a model reads and is paid for by the token; this bounds a
    // file a program greps.
    const tools_max = @import("tools.zig").max_output_bytes;
    try testing.expect(max_output_bytes > tools_max);
    try testing.expectEqual(@as(usize, 64 * 1024), tools_max);
    try testing.expectEqual(@as(usize, 8 * 1024 * 1024), max_output_bytes);
    // And the whole directory is bounded by the two together, with no walk.
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
    // The record says the file is not the whole story rather than pretending
    // it is, the same treatment a truncated tool result already gets.
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

    // **Two answers, one per platform.** A build that moves a path keeps the
    // constant; macOS reads the file where it really is, because a bind whose
    // target differs from its source is what `expressibleOn` refuses. Either
    // way the agent is told the path in the result and never builds one.
    //
    // Mutation check: answer `sandbox_dir` in both arms of `sandboxDirFor` and
    // the second half fails on Darwin.
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
