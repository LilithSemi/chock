//! A helper: one long lived program inside the sandbox, reached over a pipe in
//! both directions, started by Chock and never named by the model.
//!
//! ## Why this is one mechanism and not three
//!
//! Three things need exactly this and nothing more: a **language server**
//! (`lib/chock-core/lsp.zig`, whose `Server` had no production implementation
//! because of it), an **MCP server**, and a **plugin host**. Every one of them
//! is a process that outlives a tool call, runs inside the sandbox, and speaks
//! over a pipe both ways. Built three times they would be three lifecycles
//! that differ in small ways, and the small ways are the failure modes: which
//! one waits at teardown, which one restarts, which one leaves a half written
//! request on the wire.
//!
//! ## What a helper is not
//!
//! * **It is not a tool.** `lib/chock-core/tools.zig`'s `Tool` enum has no
//!   member here, so the model is never offered one, never told one exists,
//!   and cannot name one. A general purpose long lived process the agent could
//!   drive is the whole thing this is not.
//! * **It is not one process per call.** The tool runner is one process per
//!   call, on purpose. A helper is the same exception a plugin already gets: it
//!   holds no credential, it runs in the sandbox, and it is started by the
//!   harness.
//! * **It is not a boundary of its own.** A helper gets the same
//!   `sandbox.Config` a tool call gets, from the same caller, plus one
//!   descriptor. See `sandbox.Config.stdin_fd` for exactly what that
//!   descriptor adds and why none of it is a way out.
//!
//! ## Standard input, which is the part that changed a security invariant
//!
//! Every sandboxed program used to get `/dev/null` on descriptor 0, with no
//! way to ask for anything else, and `lib/chock-core/tools.zig` still asks for
//! nothing else: **a tool call must never block waiting on standard input
//! nobody will write.** That stays true, because the field a helper fills in
//! defaults to null and no tool call sets it.
//!
//! `sandbox.Config.stdin_fd` is where the argument about what a real pipe on
//! descriptor 0 gives a sandboxed process is written down, and
//! `test/sandbox/escape.zig` is where it is checked.
//!
//! ## Which signal ends a helper, and which does not
//!
//! A tool call's sandbox gets a process group of its own so
//! `tools.cancelRunningTool` can end it from a signal handler. A subagent
//! deliberately gets none, so the terminal's own Ctrl-C reaches it directly.
//! **A helper is the first shape and not the second, and it is registered for
//! neither.**
//!
//! * It has a group of its own for free: `Sandbox.spawn` always makes one, so
//!   nothing from the terminal reaches a helper. That is right. A first Ctrl-C
//!   promises the running work continues to a safe point, and a helper is part
//!   of that running work.
//! * It is **not** put in `tools.running_tool_handles`, so a second Ctrl-C does
//!   not reach it either. Two reasons, and either alone would decide it. That
//!   table is sized for exactly the calls this process can have running at
//!   once, one per background task plus the foreground call, so a helper in it
//!   would take a slot a background task needs and a second press would then
//!   miss a real build. And a helper is idle between asks: "stop now" is about
//!   work the user asked for, and a helper that is waiting on a read is not
//!   doing any.
//! * It is ended by `deinit`, which every path out of a session reaches,
//!   including the one a second Ctrl-C takes.
//!
//! ## A helper that dies, and a harness that dies
//!
//! Neither may leave the other waiting, and a half written request must never
//! be read as a whole one.
//!
//! * **A helper that exits** closes its end. The harness's next read answers
//!   end of file and its next write answers a broken pipe, both immediately,
//!   because `Sandbox.spawn`'s own middle process drops its copies of both
//!   descriptors as soon as the sandboxed program exists: see that driver's
//!   own comment beside the second fork. Neither answer is a wait.
//! * **A harness that exits** closes its end, so a helper blocked on a read of
//!   descriptor 0 gets end of file rather than waiting forever, and `deinit`
//!   then signals the helper outright.
//!
//! ## A helper that dies is not restarted
//!
//! **One start per session. A helper that ends is gone for the rest of the
//! session**, and its consumer says so once and then says nothing.
//!
//! The alternative is a restart, and a restart here does not converge. A
//! language server dies from a fault in its own parser, reading a file the
//! agent wrote; the agent then edits the same file again, which starts the
//! server again, which reads the same file again. That is a restart on every
//! edit that never gets anywhere, and this project's rule is that a confusing
//! failure costs turns while a plain refusal costs one.
//!
//! ## The cpu limit counts a whole session here, not one call
//!
//! A helper takes the same `sandbox.Limits` a tool call takes, and one of them
//! reads differently for a program that lives as long as the session:
//! **`cpu_seconds` is cumulative over the life of one process.** A tool call
//! starts a new process, so its 3600 seconds sit far above its 120 second
//! deadline and are never approached. A helper never restarts, so its count
//! only rises.
//!
//! **Measured against `zls` 0.16 on 2026-08-22**: about 11 milliseconds of cpu
//! time per ask on a six thousand line file, and a peak of 44 MiB resident. At
//! that rate the 3600 second default is reached after roughly three hundred
//! thousand asks of a large file, which no session does, so the default is
//! right for this server and nothing needs to change.
//!
//! **It is right for this server and not proven for every one.** A server that
//! re-checks a whole project on each change, rather than parsing the one
//! document it was handed, is orders of magnitude more expensive per ask, and
//! is the case in which this would be reached. What happens then is already
//! correct and worth stating: the kernel sends `SIGXCPU`, the helper exits, the
//! next read answers end of file, and `lib/chock-core/lsp.zig` says once that
//! the server stopped answering and then says nothing. The session runs on with
//! no diagnostics, which is what a session with no server does. Nothing is lost
//! except the checking, and the one line says so.
//!
//! ## Teardown waits, and that is not optional
//!
//! `deinit` joins the thread that is inside `Sandbox.spawn`, so it does not
//! return until the sandboxed program has been reaped. A helper writes below
//! the session scratchpad that teardown is about to remove, the same hazard
//! `chock_core.tasks.Table.deinit` waits for, and a helper has a longer life
//! than any task. It signals the helper first so the join is bounded by the
//! kernel and not by whatever the helper felt like doing.

const std = @import("std");
const sandbox = @import("chock-sandbox");
const chock_io = @import("chock-io");

/// What one exchange with a helper can fail with.
pub const Error = error{
    /// The helper is finished with: it exited, it closed its end, a write to
    /// it did not complete, or it never started. **Never cleared.** See this
    /// file's own top comment: a helper is not restarted.
    HelperGone,
    /// The helper did not answer inside the budget the caller set. The channel
    /// is still usable and the caller keeps whatever it did read.
    Late,
};

/// What could stop a helper from starting at all.
pub const StartError = error{
    /// A pipe could not be made. The one failure that happens before anything
    /// is forked.
    NoPipe,
    /// `Sandbox.spawn` did not report its own middle process inside the bound
    /// below, which means its pre-fork setup is wedged. Named apart from
    /// `NoPipe` because it says something quite different about the machine.
    SpawnStuck,
} || std.mem.Allocator.Error;

/// How long `start` waits for `Sandbox.spawn` to report the handle on its own
/// middle process, or to fail before it ever forks.
///
/// Five seconds, the same bound and for the same reason as
/// `chock_core.tools`'s own wait: probing the Landlock ABI and building the
/// seccomp filter is all that happens before that fork. **Reaching this is a
/// bug detector and never an expected wait.** It is not a budget on anything
/// the helper does; see `Channel` for those.
pub const start_wait_ns: u64 = 5 * std.time.ns_per_s;

/// How often that wait re-checks. Small enough that a healthy start is not
/// measurably slower for it.
const start_step_ns: u64 = std.time.ns_per_ms;

/// What to start, and where.
pub const Request = struct {
    /// The sandbox the helper runs in: **the same one a tool call gets**,
    /// built by the same caller, so a helper reaches nothing a tool call
    /// cannot. `stdin_fd`, `stdout_fd` and `stderr_fd` are overwritten by
    /// `Helper.start`, so whatever a caller puts there is ignored rather than
    /// half honoured.
    config: sandbox.Config,
    /// The program and its arguments. **From the project and never from the
    /// model**: see `lib/chock-core/lsp.zig`'s own `Session.program`.
    argv: []const []const u8,
};

/// The pipe that reaches one helper, in both directions.
pub const Channel = struct {
    /// Requests go in here. The helper reads it as descriptor 0.
    to_helper: std.Io.File,
    /// Replies come out of here. The helper writes it as descriptor 1.
    from_helper: std.Io.File,

    /// Set the first time an exchange leaves this channel in a state nothing
    /// can resynchronise, and **never cleared**. Every later call answers
    /// `HelperGone` without touching a descriptor.
    ///
    /// **A flag on the channel and not a rule for the caller**, because a
    /// caller that forgot the rule once would send its next request into a
    /// stream that is out of step with the reply it then reads, and would
    /// believe the answer.
    poisoned: bool = false,

    /// A deadline `budget_ns` from now, for one exchange.
    ///
    /// `.awake` and not `.real`: a deadline must not move when NTP steps the
    /// wall clock, or it fires early or never fires at all. The same choice
    /// `chock_core.tools`'s own capture deadline makes.
    pub fn deadlineIn(io: std.Io, budget_ns: u64) std.Io.Clock.Timestamp {
        return std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{
            .raw = .fromNanoseconds(@intCast(budget_ns)),
            .clock = .awake,
        });
    }

    /// Write the whole of `bytes` to the helper, or answer why not.
    ///
    /// **Every failure poisons the channel**, including running out of budget.
    /// A pipe write is allowed to be short, so a request larger than the pipe
    /// buffer takes several calls, and a failure part way through leaves the
    /// front of a request on the wire with no way to withdraw it. The helper
    /// would then read the front of one request joined to the whole of the
    /// next, and answer something plausible about neither. That is exactly the
    /// class `lib/chock-proto/short_write_probe.zig` exists for, one layer
    /// down, and the answer is the same: a partial write is a failure and is
    /// never treated as a smaller success.
    ///
    /// The same deadline is handed to every call in the loop, never a
    /// countdown recomputed per pass, so the bound is on the whole write.
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
                // A broken pipe is the ordinary way a helper that has exited
                // says so, and every other write failure leaves the same
                // half written request behind. One answer for all of them.
                self.poisoned = true;
                return error.HelperGone;
            };
            // A write of zero bytes would spin this loop forever with nothing
            // to show for it. The kernel does not do it on a pipe, so treat it
            // as the channel being unusable rather than as progress.
            if (count == 0) {
                self.poisoned = true;
                return error.HelperGone;
            }
            written += count;
        }
    }

    /// Read whatever the helper has said, up to `buffer.len` bytes, and answer
    /// how many landed. Never answers zero: end of file is `HelperGone`.
    ///
    /// **Running out of budget does not poison the channel**, and that is the
    /// one asymmetry with `writeAll`. Nothing was lost: the reply is still in
    /// the pipe, and a caller that keeps what it has already read consumes the
    /// rest on its next ask. A caller that threw its buffer away instead would
    /// read the tail of one reply as the head of the next, which is the read
    /// side of the same fault, so the buffer belongs to the caller and this
    /// function never owns one.
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
        // `error.EndOfStream` is the helper's exit, and every other read
        // failure leaves a channel nothing can resynchronise. One answer for
        // all of them, which is also the honest one: this helper is finished
        // with.
        const count = outcome.file_read_streaming catch {
            self.poisoned = true;
            return error.HelperGone;
        };
        if (count == 0) {
            // A read of zero is not an error in this interface, and it carries
            // no reply, so a caller that treated it as one would loop on a
            // dead pipe. It means the same thing as end of file here.
            self.poisoned = true;
            return error.HelperGone;
        }
        return count;
    }
};

/// One long lived sandboxed program, from `start` to `deinit`.
///
/// **The caller owns this value and must not move it while it is running.** A
/// thread of its own holds a pointer into `spawn_state` below for the whole
/// life of the helper, the same requirement `chock_core.tasks.Table` carries
/// for the same reason.
pub const Helper = struct {
    /// The allocator the copy of the request is kept in.
    ///
    /// **Give this one no fork ever inherits a lock from.** The helper's own
    /// thread is inside `Sandbox.spawn` while the session's own threads
    /// allocate, and `fork` carries only the calling thread, so a lock held by
    /// another thread at that moment is copied into the child as held forever.
    /// `std.heap.page_allocator` is the answer `chock_core.tasks.Table.gpa`
    /// already gives, for the reason `lib/chock-core/tools.zig`'s own top
    /// comment states in full.
    arena: std.heap.ArenaAllocator,

    /// Filled in by `start`. Null before it, and null after a start that
    /// failed, which is what `live` answers null from.
    channel: ?Channel = null,

    /// This process's own `/dev/null`, when `start` opened one for the
    /// helper's standard error. Closed by `deinit`.
    null_fd: ?std.Io.File = null,

    thread: ?std.Thread = null,
    spawn_state: Spawn = .{},

    /// Whether this helper has ever been started. **Read by `start` itself**:
    /// a second start is refused rather than silently making a second process,
    /// which is the restart this file's own top comment refuses.
    started: bool = false,

    pub fn init(gpa: std.mem.Allocator) Helper {
        return .{ .arena = .init(gpa) };
    }

    /// Start the helper. May be called once.
    ///
    /// Every part of `request` is copied into this helper's own arena, because
    /// the config a caller builds for a tool call is freed the moment that
    /// call returns and a helper outlives one call by definition. See
    /// `sandbox.Config.copy`.
    pub fn start(self: *Helper, io: std.Io, request: Request) StartError!void {
        return self.startWith(io, request, chock_io.default());
    }

    /// Same as `start`, with the `chock-io` driver named explicitly. Exists so
    /// a test can hand in `chock_io.Fake`, whose `pipeCloseOnExec` always
    /// fails, and reach the one failure that a real pipe cannot be made to
    /// produce without exhausting this process's whole descriptor table. The
    /// same seam, for the same reason, that `chock_core.tools` already has.
    pub fn startWith(
        self: *Helper,
        io: std.Io,
        request: Request,
        driver: chock_io.Io,
    ) StartError!void {
        // A second start would leave the first process running with nobody
        // holding its pipes. Refused, and it is the caller's mistake, not a
        // state to recover from.
        std.debug.assert(!self.started);
        self.started = true;

        const allocator = self.arena.allocator();
        const config_copy = try request.config.copy(allocator);
        const argv_copy = try sandbox.copyStrings(allocator, request.argv);

        // Both ends close on exec, so an unrelated exec elsewhere in this
        // process can never inherit one. `Sandbox.spawn`'s own child puts the
        // two it needs on descriptors 0 and 1 with `dup2`, which clears the
        // flag on the copy it makes, so the helper itself still gets them.
        const requests = driver.pipeCloseOnExec() catch return error.NoPipe;
        const replies = driver.pipeCloseOnExec() catch {
            closeRaw(io, requests.read_fd);
            closeRaw(io, requests.write_fd);
            return error.NoPipe;
        };

        var spawn_config = config_copy;
        spawn_config.stdin_fd = requests.read_fd;
        spawn_config.stdout_fd = replies.write_fd;
        // **Standard error goes to /dev/null on the host, and not to a pipe.**
        // A helper's own log is not Chock's business, and a pipe nobody drains
        // fills up and then wedges the helper mid sentence, which is the worst
        // of the three answers. Leaving it on this process's own standard
        // error instead would print a third party program's chatter over the
        // session's own output. A descriptor opened here, so it is closed
        // here: see `deinit`.
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

        // Wait, bounded, for the fork that has to inherit the two descriptors
        // this process is about to give up. Closing either one before that
        // fork could drop a pipe's last end. The same wait, and the same
        // reasoning, as `chock_core.tools`'s own capture: see `start_wait_ns`.
        var waited: u64 = 0;
        while (@atomicLoad(std.posix.pid_t, &self.spawn_state.middle.pid, .acquire) == 0 and
            !self.spawn_state.done.load(.acquire) and waited < start_wait_ns)
        {
            // Best effort: a canceled sleep only re-checks the condition
            // sooner than the step would have.
            std.Io.sleep(io, .fromNanoseconds(start_step_ns), .awake) catch {};
            waited += start_step_ns;
        }
        if (@atomicLoad(std.posix.pid_t, &self.spawn_state.middle.pid, .acquire) == 0 and
            !self.spawn_state.done.load(.acquire))
        {
            // Something is badly wrong before the fork. The thread is left
            // running rather than have this process close a write end out from
            // under a fork that has not happened; `deinit` still joins it.
            self.thread = thread;
            return error.SpawnStuck;
        }

        self.thread = thread;
        self.null_fd = null_fd;

        // Safe now. This process keeps one end of each pipe and gives up the
        // other, so a helper that exits really does bring a read here to end
        // of file, instead of this process holding the last write end open
        // against itself.
        closeRaw(io, requests.read_fd);
        closeRaw(io, replies.write_fd);

        self.channel = .{
            .to_helper = .{ .handle = requests.write_fd, .flags = .{ .nonblocking = false } },
            .from_helper = .{ .handle = replies.read_fd, .flags = .{ .nonblocking = false } },
        };
    }

    /// The channel, or null when this helper is not usable: it never started,
    /// or an exchange poisoned it. A consumer reads this before every ask and
    /// says nothing when it is null.
    pub fn live(self: *Helper) ?*Channel {
        if (self.channel) |*channel| {
            if (channel.poisoned) return null;
            return channel;
        }
        return null;
    }

    /// End the helper and wait for it.
    ///
    /// **It waits, and that is not optional**: see this file's own top
    /// comment. The order is what makes the wait bounded.
    ///
    /// 1. Close the request pipe, which is how a well behaved helper is told
    ///    there is nothing more to answer. A helper that reads end of file and
    ///    exits is then already gone before step 2 looks.
    /// 2. Signal the helper through the handle `Sandbox.spawn` filled in.
    ///    SIGKILL, because the session is over and a helper is a program this
    ///    project did not write and cannot assume answers a polite signal.
    ///    Nothing is lost by it: everything a helper produced was read when it
    ///    produced it. One signal ends every process the helper started, and
    ///    `Sandbox.spawn`'s own doc comment says why that follows from one
    ///    signal to one process.
    /// 3. Join, which returns once the sandboxed program has been reaped.
    /// 4. Give the handle up, which is this function's to do because the
    ///    caller of `Sandbox.spawn` owns it: see `Sandbox.Middle`. It is
    ///    closed **after** the join, so nothing closes a descriptor the thread
    ///    inside `Sandbox.spawn` might still be writing beside.
    ///
    /// ## A pid that has been reaped names nothing, and may soon name somebody
    ///
    /// **`Sandbox.spawn` reaps the process it forked before it returns.** From
    /// that moment the number is free, and the kernel gives it to whatever
    /// starts next. A `kill(-pid, SIGKILL)` after that reaches a process group
    /// this session never started, and SIGKILL to a whole group is about the
    /// worst thing to send at a stranger. Measured on 2026-08-22 on a machine
    /// that was busy building: an earlier version of this function signalled
    /// the number unconditionally and killed a build that had nothing to do
    /// with it.
    ///
    /// **That is why step 2 signals a handle and not a number, and why there
    /// is no longer a condition on it.** The version before this one only
    /// signalled while the spawn thread had not yet stored `done`, which
    /// narrowed the window to the few instructions between `Sandbox.spawn`'s
    /// own `waitpid` returning and that store, and did not close it. A handle
    /// answers `error.Gone` in exactly that window instead of reaching
    /// anybody, so the condition bought nothing and is gone. See
    /// `Sandbox.Middle`.
    ///
    /// Step 2 does nothing when there is no handle, which is a helper whose
    /// start failed before the fork.
    pub fn deinit(self: *Helper, io: std.Io) void {
        if (self.channel) |channel| {
            std.Io.File.close(channel.to_helper, io);
        }

        // The acquire load pairs with the release store `Sandbox.spawn` makes
        // after it has written the handle, so a non zero pid here means `fd`
        // beside it is already there to read. See `Sandbox.Middle`.
        if (@atomicLoad(std.posix.pid_t, &self.spawn_state.middle.pid, .acquire) != 0) {
            // Best effort and deliberately unchecked: the one expected failure
            // is `error.Gone`, a helper that has already ended, which is the
            // outcome asked for.
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

/// Close a raw descriptor this file opened, through `std.Io`.
fn closeRaw(io: std.Io, fd: std.posix.fd_t) void {
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    std.Io.File.close(file, io);
}

/// What the thread inside `Sandbox.spawn` reports back once that one call
/// returns. The same shape, and the same field by field reasoning, as
/// `chock_core.tools`'s own `SpawnThread`: read that one's doc comment for why
/// this is a raw `std.Thread.spawn` and why `middle.pid` is a plain field read
/// with `@atomicLoad`.
///
/// **`middle` outlives this struct's own use by the thread**, because `deinit`
/// closes the handle after the join. See `sandbox.Middle` for the ownership
/// rule this obeys.
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

// No test here starts a sandbox, and none reads a clock to decide anything. A
// `Channel` over two ordinary pipes is a real channel with a real peer, so
// every rule about a helper that dies, a budget that runs out, and a channel
// that is poisoned is checked on both platforms. The sandbox half is
// `test/core/helper.zig`, which is Linux only because `Sandbox.spawn` is.

const testing = std.testing;

/// Two pipes and the four descriptors they are made of, so a test can play the
/// helper by hand: write a reply into `helper_writes`, read a request out of
/// `helper_reads`, or close either one and watch what the channel answers.
const Pair = struct {
    channel: Channel,
    /// The end the helper would read its requests from.
    helper_reads: std.Io.File,
    /// The end the helper would write its replies to.
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

    /// A test that plays a helper's exit closes one of these ends itself and
    /// puts -1 in its place. Closing it twice would be a use after free, so
    /// this skips whatever is already gone.
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

/// A deadline far enough ahead that an exchange between two ends of one pipe
/// in one process reaches it only if something is genuinely stuck. Nothing
/// asserts how long anything took; this is a bound, not a measurement.
fn generousDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return Channel.deadlineIn(io, 30 * std.time.ns_per_s);
}

test "a request reaches the helper and a reply comes back" {
    // The floor: the mechanism carries bytes in both directions. Everything
    // below is about what happens when it stops.
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
    // The fault this whole file is written against: a session that goes quiet
    // for minutes reads as hung, and a helper that died is the easiest way to
    // get there. A closed write end is exactly what a helper's exit looks
    // like from here, because `Sandbox.spawn`'s own middle process gives up
    // its copy as soon as the sandboxed program exists.
    //
    // Mutation check: answer `Late` instead of `HelperGone` on end of file and
    // the caller waits out a budget for a reply nobody will ever send; drop
    // the poison and the caller asks again, forever.
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    // Both write ends of the reply pipe: the helper's own, and this test's
    // copy of it. End of file needs every one of them closed.
    std.Io.File.close(pair.helper_writes, io);
    pair.helper_writes = .{ .handle = -1, .flags = .{ .nonblocking = false } };

    var back: [8]u8 = undefined;
    try testing.expectError(error.HelperGone, pair.channel.read(io, &back, generousDeadline(io)));
    try testing.expect(pair.channel.poisoned);

    // And it stays gone. A second ask must not reach a descriptor again.
    try testing.expectError(error.HelperGone, pair.channel.read(io, &back, generousDeadline(io)));
}

test "a write to a helper that has gone is a failure, not a hang and not a silent success" {
    // A helper that stopped reading is the other half of the same fault. The
    // write must answer, and it must poison the channel: half a request is on
    // the wire with no way to withdraw it, and the helper would read the front
    // of this request joined to the whole of the next one.
    //
    // Mutation check: leave `poisoned` alone in `writeAll` and the caller
    // sends its next request into a stream that is out of step, then believes
    // the reply.
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

    // Every later exchange, in either direction, is refused without touching a
    // descriptor.
    var back: [8]u8 = undefined;
    try testing.expectError(error.HelperGone, pair.channel.read(io, &back, generousDeadline(io)));
    try testing.expectError(error.HelperGone, pair.channel.writeAll(io, "ask", generousDeadline(io)));
}

test "a reply that misses its budget is late, and the channel still works" {
    // The asymmetry with a write, and the reason it is safe: nothing was lost.
    // The bytes are still in the pipe, so a caller that keeps its buffer picks
    // the reply up on its next ask. A `Late` that poisoned the channel would
    // mean one slow first answer ended diagnostics for the whole session,
    // which is precisely what `chock_core.lsp`'s two budgets exist to avoid.
    //
    // The deadline is already in the past, so nothing here waits for a clock:
    // `operateTimeout` sees a passed deadline and answers at once.
    //
    // Mutation check: poison the channel on `error.Timeout` in `read` and the
    // second half of this test answers `HelperGone`.
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    const past = std.Io.Clock.Timestamp.now(io, .awake);
    var back: [16]u8 = undefined;
    try testing.expectError(error.Late, pair.channel.read(io, &back, past));
    try testing.expect(!pair.channel.poisoned);

    // The helper answers after all. The channel was never poisoned, so the
    // reply is still readable, whole.
    try std.Io.File.writeStreamingAll(pair.helper_writes, io, "answer");
    const count = try pair.channel.read(io, &back, generousDeadline(io));
    try testing.expectEqualStrings("answer", back[0..count]);
}

test "a helper that never started has no channel at all" {
    // A consumer reads `live` before every ask, so a helper that was never
    // started, or one a start failure left behind, has to answer null there
    // rather than a channel over descriptors nobody opened.
    var helper = Helper.init(testing.allocator);
    try testing.expect(helper.live() == null);
    helper.deinit(testing.io);
}

test "a start whose pipe cannot be made leaves nothing behind" {
    // The one failure a real pipe cannot be made to produce without exhausting
    // this process's descriptor table. `chock_io.Fake` fails every
    // `pipeCloseOnExec`, so this reaches the path where `start` has already
    // copied the request and has to give the whole thing up.
    var helper = Helper.init(testing.allocator);
    defer helper.deinit(testing.io);

    const result = helper.startWith(testing.io, .{
        .config = .{ .root = "/nowhere", .mounts = &.{}, .rules = &.{}, .cwd = "/", .env = &.{} },
        .argv = &.{"/probe"},
    }, chock_io.Fake.driver());
    try testing.expectError(error.NoPipe, result);
    // No channel, so a consumer says nothing rather than writing into a
    // descriptor that was never opened.
    try testing.expect(helper.live() == null);
}
