//! `chock guest`: what runs inside a microVM, one tool call at a time.
//!
//! **A subcommand and not a program of its own.** Chock installs one binary and
//! no helper beside it, which `test/plugin/one_binary.zig` pins. A guest's initrd
//! carries a Linux build of that one binary and runs `chock guest` in it, so the
//! program sandboxing a tool call inside a guest is the program that sandboxes
//! one outside.
//!
//! **A guest is a layer and not an alternative.** It has a kernel of its own, so
//! namespaces, seccomp, Landlock and cgroups all work in here, and this program
//! runs the very driver a Linux host runs. The boundary a tool call gets inside a
//! guest is the same boundary, built from the same `Config` and the same code.
//! Mirage's own design says a guest is root inside itself, which is exactly why
//! this still sandboxes.
//!
//! ## What it does, and what it deliberately does not
//!
//! It opens one stream to whoever started the guest, reads one request a line on
//! it, builds the `Config` that request describes, runs the driver, and answers.
//! That is all.
//!
//! * **It resolves no name and opens no socket.** A tool call that reaches the
//!   network gets a connected descriptor from the host, through Mirage's own
//!   `reaching` message. The host decides, resolves and connects, so a guest
//!   cannot ask for one host and be handed another.
//! * **It holds no policy.** Every question was answered on the host before a
//!   request was written. This program refuses a request it cannot build a
//!   `Config` from, and refuses nothing else.
//! * **It must not grow a copy of `addressIsReachable`.** That check runs on the
//!   host after a name resolves: see `lib/chock-broker/network.zig`.
//!
//! ## Linux, and nothing else
//!
//! A guest has a Linux kernel, so this program only ever runs on one. It reaches
//! the vsock with raw Linux calls, and a build for another platform answers the
//! command by saying which platform runs one rather than calling a syscall number
//! that means something else there.
//!
//! ## One thread, because the driver forks
//!
//! The driver forks, and a fork carries only the calling thread. So this program
//! is one thread and one loop, the same rule `lib/chock-core/tools.zig` states
//! for the host's tool path.

const std = @import("std");
const builtin = @import("builtin");
const chock_sandbox = @import("chock-sandbox");

const linux = std.os.linux;

/// Whether this build runs where the raw calls below mean what they say.
const is_linux = builtin.os.tag == .linux;

const tty = @import("tty.zig");

const wire = chock_sandbox.vm_wire;
const Sandbox = chock_sandbox.Sandbox;

/// The vsock port this connects to. `mirage_session.wire.control_port`, because
/// the host end asks for a stream on that port and nothing else routes here.
pub const default_port: u32 = 1024;

/// `VMADDR_CID_HOST`. Whoever started the guest is always at this address, and
/// there is no other address a guest can name.
const cid_host: u32 = 2;

/// Connect to whoever started this guest.
///
/// **A vsock and not a descriptor the init passed in.** A guest opens the
/// connection and the host takes it: that is the only direction Mirage's channel
/// runs, and an init made of busybox cannot open one.
fn dialHost(port: u32) DialError!std.posix.fd_t {
    // A syscall number is Linux's own, so on another platform it means something
    // else there. `main` refuses before this, and this refuses again rather than
    // depending on that.
    if (!is_linux) return error.NoSocket;

    // The raw calls, the way `lib/chock-sandbox/linux/driver.zig` reaches
    // `pidfd_send_signal`: `std.Io.net` has an address for IP and for a unix path
    // and none for a vsock, and a guest is Linux by construction.
    const made = linux.socket(linux.AF.VSOCK, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(made) != .SUCCESS) return error.NoSocket;
    const fd: std.posix.fd_t = @intCast(made);
    errdefer _ = linux.close(fd);

    const address = linux.sockaddr.vm{
        .port = port,
        .cid = cid_host,
        .flags = 0,
    };
    const joined = linux.connect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.vm));
    if (linux.errno(joined) != .SUCCESS) return error.NobodyThere;
    return fd;
}

pub const DialError = error{
    /// The kernel has no vsock at all, so this is not a guest of Mirage's.
    NoSocket,
    /// Nothing is listening on that port.
    NobodyThere,
};

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = exe_path;

    if (!is_linux) {
        tty.print(
            .err,
            "chock guest: this runs inside a Linux guest and this build is {t}. A guest's own " ++
                "init starts it, and nothing else does.\n",
            .{builtin.os.tag},
        );
        return 1;
    }

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    const port = portFrom(args) catch {
        tty.print(
            .err,
            "chock guest: this takes --port <number> and nothing else. It is started by a " ++
                "guest's own init, not by a person.\n",
            .{},
        );
        return 2;
    };

    const control = dialHost(port) catch |err| {
        // Nobody is listening, which means this is not a guest Chock started.
        tty.print(
            .err,
            "chock guest: nothing answered on vsock port {d} ({t}). This runs inside a " ++
                "microVM Chock started and nowhere else.\n",
            .{ port, err },
        );
        return 1;
    };
    defer _ = linux.close(control);

    const read_buffer = try gpa.alloc(u8, wire.max_message_bytes + 1);
    defer gpa.free(read_buffer);
    var write_buffer: [64 * 1024]u8 = undefined;

    // Blocking, because this loop has one thread and every read of it waits for
    // the host's next request.
    const stream = std.Io.File{ .handle = control, .flags = .{ .nonblocking = false } };
    var reader = stream.readerStreaming(io, read_buffer);
    var writer = stream.writerStreaming(io, &write_buffer);

    // **Before anything else on this stream.** The host waits for it, because
    // Mirage's own signal says the kernel booted and not that this is listening.
    writer.interface.writeAll(wire.hello_line) catch {};
    writer.interface.flush() catch {};

    var watch = Watch{ .fd = control, .io = io };
    const watcher = std.Thread.spawn(.{}, Watch.run, .{&watch}) catch null;
    defer if (watcher) |one| {
        watch.done.store(true, .release);
        one.join();
    };

    try serve(gpa, io, &reader.interface, &writer.interface, if (watcher == null) null else &watch);
    return 0;
}

/// How a call that is running ends early.
///
/// **A thread, because the driver blocks.** `Sandbox.spawn` returns when the
/// process it forked has ended, so the loop cannot watch the stream at the same
/// time. This thread is started once, before any call and so before any fork,
/// and it allocates nothing: a thread holding a lock at `fork` is what the one
/// thread rule in this file's heading is about.
///
/// **It reads the stream only while a call runs.** In that window the host is
/// waiting for an answer and writes nothing but a cancel, so anything readable
/// there is one. Between calls the loop is the only reader, and a cancel that
/// arrives after the answer went out is dropped by `serve` rather than drained
/// here: a drain after the answer can take the next request instead.
const Watch = struct {
    fd: std.posix.fd_t,
    io: std.Io,
    /// The call running now. The loop clears it before each call and the driver
    /// fills it in.
    middle: Sandbox.Middle = .{},
    armed: std.atomic.Value(bool) = .init(false),
    done: std.atomic.Value(bool) = .init(false),
    /// Taken by whoever touches the stream while a call runs. **Two readers, and
    /// one stream**: this thread watches for a cancel, and the call's own router
    /// asks the host to resolve a name on the same descriptor.
    reading: std.Io.Mutex = .init,

    /// How long a cancel that beat the fork waits for one.
    const wait_for_fork_ms: u32 = 1000;
    const poll_ms: i32 = 20;

    fn run(self: *Watch) void {
        var watching = [1]std.posix.pollfd{.{
            .fd = self.fd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        var line: [64]u8 = undefined;

        while (!self.done.load(.acquire)) {
            if (!self.armed.load(.acquire)) {
                sleepMs(poll_ms);
                continue;
            }
            // **Polled without the lock.** Holding it across the poll left it taken
            // for nearly every millisecond of every turn, and the call's own
            // resolver waits on this same lock to send a name: a resolve took
            // seventeen seconds to leave the guest because this thread kept
            // winning the re-lock, and the program called its name server dead.
            const ready = std.posix.poll(&watching, poll_ms) catch continue;
            if (ready == 0) continue;

            self.reading.lockUncancelable(self.io);
            defer self.reading.unlock(self.io);
            if (!self.armed.load(.acquire)) continue;

            // **Looked at before it is taken.** The call can end while this is
            // inside the poll above, and then what is readable is the next
            // request rather than a cancel. Reading it would swallow it and the
            // guest would answer that the request could not be read.
            //
            // **And never waited on.** The resolver holds this lock while it reads
            // the host's answer, so what the poll saw may be gone by now, and a
            // peek that waited would hold the lock for a byte nobody will send.
            const seen = linux.recvfrom(
                self.fd,
                &line,
                line.len,
                linux.MSG.PEEK | linux.MSG.DONTWAIT,
                null,
                null,
            );
            if (linux.errno(seen) != .SUCCESS) continue;
            const cancel = wire.cancelAtStart(line[0..seen]) orelse continue;

            // Exactly the cancel, so anything behind it stays for the loop.
            var taken: usize = 0;
            while (taken < cancel.bytes) {
                const got = linux.read(self.fd, line[taken..].ptr, cancel.bytes - taken);
                if (linux.errno(got) != .SUCCESS or got == 0) break;
                taken += got;
            }
            self.deliver(@enumFromInt(cancel.signal));
        }
    }

    /// Signal the call, waiting for the fork when a cancel arrived before it.
    fn deliver(self: *Watch, sig: std.posix.SIG) void {
        var waited: u32 = 0;
        while (waited < wait_for_fork_ms) : (waited += @intCast(poll_ms)) {
            if (!self.armed.load(.acquire)) return;
            if (@atomicLoad(std.posix.pid_t, &self.middle.pid, .acquire) != 0) break;
            sleepMs(poll_ms);
        }
        Sandbox.signalMiddle(self.middle.fd, sig) catch {};
    }
};

fn sleepMs(ms: i32) void {
    if (!is_linux) return;
    const every = std.os.linux.timespec{
        .sec = 0,
        .nsec = @as(isize, ms) * std.time.ns_per_ms,
    };
    _ = std.os.linux.nanosleep(&every, null);
}

/// The port `--port` named, or the default when nothing was said.
fn portFrom(args: []const []const u8) error{Unreadable}!u32 {
    if (args.len == 0) return default_port;
    if (args.len != 2) return error.Unreadable;
    if (!std.mem.eql(u8, args[0], "--port")) return error.Unreadable;
    return std.fmt.parseInt(u32, args[1], 10) catch error.Unreadable;
}

/// Answer requests until the stream ends. Split from `main` so a test can drive
/// it over a pair of pipes with no guest at all.
pub fn serve(
    gpa: std.mem.Allocator,
    io: std.Io,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    watch: ?*Watch,
) !void {
    while (true) {
        const line = wire.readLine(reader) catch |err| switch (err) {
            // The host let go, which is how a session ends.
            error.Ended, error.Broke => return,
            error.TooLong => {
                // **The line is still there.** `takeDelimiterInclusive` answers
                // `StreamTooLong` without consuming, so a loop that only answered
                // would read the same line and refuse it again for good.
                _ = reader.discardDelimiterInclusive('\n') catch return;
                try wire.write(writer, wire.Answer{
                    .refusal = "the request was longer than this build of chock-guest reads",
                });
                continue;
            },
            error.Unreadable => unreachable,
        };

        // A cancel for the call before this one, written after its answer had
        // already gone out. Dropped and never answered: answering it would put a
        // refusal in front of the next request's own answer.
        if (wire.cancelIn(line) != null) continue;

        const parsed = wire.parseLine(wire.Request, gpa, line) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // A line this build cannot read ends that request and not the
            // program: the next one may be readable.
            error.TooLong, error.Unreadable, error.Ended, error.Broke => {
                try wire.write(writer, wire.Answer{
                    .refusal = "the request could not be read by this build of chock-guest",
                });
                continue;
            },
        };
        defer parsed.deinit();

        try answer(gpa, io, reader, writer, parsed.value, watch);
    }
}

/// Run one request and write its answer.
fn answer(
    gpa: std.mem.Allocator,
    io: std.Io,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    request: wire.Request,
    watch: ?*Watch,
) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var config = wire.configFor(arena, request) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // The host asked for a trap this build cannot install. Refusing says so;
        // running the call anyway would give it a smaller trap set than the host
        // believes it asked for.
        error.UnknownTrap => return wire.write(writer, wire.Answer{
            .refusal = "the request named a syscall trap this build of chock-guest has no name for",
        }),
    };

    if (request.argv.len == 0) {
        return wire.write(writer, wire.Answer{
            .refusal = "the request named no program to run",
        });
    }

    // Zeroed rather than written out field by field: the driver fills this in,
    // and a feature added to `landlock.Features` must not have to be listed here
    // as well.
    // The host sends a path of this guest's, and this is where it is made. A
    // sandbox root has to be there before the driver binds it onto itself.
    std.Io.Dir.cwd().createDirPath(io, config.root) catch |err| {
        const said = try std.fmt.allocPrint(
            arena,
            "the guest could not make the directory it builds a sandbox in: {t}",
            .{err},
        );
        return wire.write(writer, wire.Answer{ .refusal = said });
    };

    // Where the call writes. **A file and not a pipe**: the driver blocks until
    // the process it forked has ended, so nothing here could drain a pipe and a
    // full one would stop the call for good.
    var wrote_out = std.Io.Dir.cwd().createFile(io, wire.guest_output, .{
        .read = true,
        .truncate = true,
    }) catch |err| return wire.write(writer, wire.Answer{
        .refusal = try std.fmt.allocPrint(
            arena,
            "the guest could not make the file a call writes to: {t}",
            .{err},
        ),
    });
    defer wrote_out.close(io);

    var wrote_err = std.Io.Dir.cwd().createFile(io, wire.guest_output_err, .{
        .read = true,
        .truncate = true,
    }) catch |err| return wire.write(writer, wire.Answer{
        .refusal = try std.fmt.allocPrint(
            arena,
            "the guest could not make the file a call writes to: {t}",
            .{err},
        ),
    });
    defer wrote_err.close(io);

    config.stdout_fd = wrote_out.handle;
    config.stderr_fd = wrote_err.handle;

    // **A guest can, and the host that sent this usually cannot.** This process is
    // root, so it can write a second identity into the map of the child it forks,
    // which is the only side that may: the kernel wants `CAP_SETUID` in the parent
    // namespace, and after unsharing the child no longer has it. The helpers then
    // become that identity and the procfs carries `hidepid=2`, so a call cannot
    // read their environment, which holds this program's own rather than the
    // curated one the call was given. See `Sandbox.Config.hide_helpers`.
    config.hide_helpers = true;

    // **The seam does not cross, so it is made here.** `Config.net_router` is a
    // table in the host's own address space, which is why the request carries the
    // network mode and not the seam: see `vm/wire.zig`. A call that asked for a
    // network and got no router is refused by the driver rather than run without
    // one, so this is given whenever the mode wants it.
    var reaching = HostNet{
        .io = io,
        .gpa = gpa,
        .reader = reader,
        .writer = writer,
        .watch = watch,
    };
    if (config.network != .none) config.net_router = reaching.router();

    setClock(io, request.now_ns);

    var report: Sandbox.LandlockReport = std.mem.zeroes(Sandbox.LandlockReport);

    var middle: ?*Sandbox.Middle = null;
    if (watch) |one| {
        one.middle = .{};
        one.armed.store(true, .release);
        middle = &one.middle;
    }
    defer if (watch) |one| Sandbox.closeMiddle(&one.middle);

    // **Disarmed before a single byte of the answer goes out, and never in a
    // `defer`.** The host writes its next request as soon as it has the answer,
    // and a watcher still armed reads that request, takes it for a cancel and
    // throws it away. The stream is then one message out of step for good.
    const term = Sandbox.spawn(arena, config, request.argv, &report, middle) catch |err| {
        if (watch) |one| one.armed.store(false, .release);
        // The name of the fault and never a sentence built here: the host holds
        // the words, and two spellings of one fault is how a message drifts.
        //
        // **With what the driver wrote.** A setup step that fails names the call
        // and the errno on its standard error, which is the file above, and a
        // refusal without it says `PivotFailed` and nothing a person can act on.
        const said = try std.fmt.allocPrint(arena, "the sandbox could not be built: {t}{s}", .{
            err,
            tailOf(arena, io, wrote_err) catch "",
        });
        return wire.write(writer, wire.Answer{ .refusal = said });
    };

    if (watch) |one| one.armed.store(false, .release);

    // Into the call's own standard error, which the host passes to the caller, so
    // this needs no second answer and cannot put the stream out of step.
    if (term == .signal) {
        const said = shortReadNote(arena, io, request);
        if (said.len != 0) {
            const at = if (wrote_err.stat(io)) |one| one.size else |_| 0;
            wrote_err.writePositionalAll(io, said, at) catch {};
        }
    }

    try sendOutput(io, writer, wrote_out, false);
    try sendOutput(io, writer, wrote_err, true);

    return wire.write(writer, wire.Answer{
        .ended = switch (term) {
            .exited => |code| .{ .exited = code },
            .signal => |sig| .{ .signalled = @intFromEnum(sig) },
            .stopped => |sig| .{ .stopped = @intFromEnum(sig) },
            .unknown => |code| .{ .unknown = code },
        },
        // The abi the guest's own kernel answered. A host reads it to know which
        // layers were really on inside, and a guest kernel with no Landlock at
        // all is a fact the host must be able to see.
        .landlock = .{ .applied = report.features.supported, .abi = report.abi },
    });
}

/// How a call inside this guest reaches the network.
///
/// **This guest resolves nothing and connects to nothing.** The driver puts a
/// router in the sandbox with the call, and that router asks two things: resolve
/// a name, and open an address. Both are forwarded. A name goes to the host on
/// this session's own stream, where the host's policy answers it. An address is
/// reached through Mirage's own channel, which hands back a stream already
/// connected there, so the connect happens where the policy is.
///
/// Its calls run on the thread that is inside `Sandbox.spawn`, because that is
/// where the driver serves the router: see `linux/driver.zig`'s own poll loop.
const HostNet = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    watch: ?*Watch,

    fn router(self: *HostNet) Sandbox.NetRouter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Sandbox.NetRouter.VTable = .{
        .resolve = resolveThunk,
        .open = openThunk,
    };

    fn resolveThunk(
        ptr: *anyopaque,
        host: []const u8,
        want: Sandbox.NetRouter.Family,
    ) Sandbox.NetRouter.Resolution {
        const self: *HostNet = @ptrCast(@alignCast(ptr));

        noteResolveAsked(host);

        // The cancel watcher reads this same stream, so it waits while this does.
        if (self.watch) |one| one.reading.lockUncancelable(self.io);
        defer if (self.watch) |one| one.reading.unlock(self.io);

        wire.write(self.writer, wire.Resolve{
            .resolve = host,
            .ipv6 = want == .ipv6,
        }) catch |err| return noteResolve("asking the host", host, err);

        const line = wire.readLine(self.reader) catch |err|
            return noteResolve("reading the host's answer", host, err);
        const said = wire.parseLine(wire.Resolved, self.gpa, line) catch |err|
            return noteResolve("reading the host's answer", host, err);
        defer said.deinit();

        const text = said.value.address orelse {
            if (said.value.refused) {
                _ = noteResolve("the policy refused it", host, error.Refused);
                return .refused;
            }
            return noteResolve("the host gave no address", host, error.NoAddress);
        };
        const got = wire.addressIn(text) orelse
            return noteResolve("the address the host gave", host, error.BadAddress);
        noteResolveAsked("the host answered with an address for");
        return .{ .granted = got };
    }

    /// Say on the console that a name reached this seam at all. Without it a guest
    /// with no DNS cannot be told apart from one whose resolver was never asked.
    fn noteResolveAsked(host: []const u8) void {
        var room: [256]u8 = undefined;
        const line = std.fmt.bufPrint(
            &room,
            "chock guest: [{d}ms] resolving {s}\n",
            .{ nowMs(), host },
        ) catch "chock guest: resolving a name\n";
        _ = linux.write(std.posix.STDERR_FILENO, line.ptr, line.len);
    }

    /// Milliseconds since this guest booted, so two notes can be compared.
    fn nowMs() i64 {
        var at: linux.timespec = undefined;
        if (linux.clock_gettime(.MONOTONIC, &at) != 0) return 0;
        return @as(i64, at.sec) * 1000 + @divTrunc(at.nsec, 1_000_000);
    }

    /// Say on the console why a name could not be resolved. Every failure here
    /// used to answer `unresolved` and keep its reason, so a guest with no DNS
    /// looked the same whatever had gone wrong.
    fn noteResolve(
        what: []const u8,
        host: []const u8,
        err: anyerror,
    ) Sandbox.NetRouter.Resolution {
        var room: [256]u8 = undefined;
        const line = std.fmt.bufPrint(
            &room,
            "chock guest: resolving {s} failed at {s}: {s}\n",
            .{ host, what, @errorName(err) },
        ) catch "chock guest: resolving a name failed\n";
        _ = linux.write(std.posix.STDERR_FILENO, line.ptr, line.len);
        return .unresolved;
    }

    /// **The stream Mirage hands back is the connection.** A descriptor does not
    /// cross a vsock, so the guest opens one to the reaching port and the host
    /// puts a connected descriptor on the other end of it.
    ///
    /// A refusal is the stream ending rather than an answer here, so a refused
    /// reach looks like a connection that opened and closed. The reason stays on
    /// the host, which is the same rule the netbroker states.
    fn openThunk(
        ptr: *anyopaque,
        address: Sandbox.NetRouter.Address,
        port: u16,
    ) Sandbox.NetBroker.Grant {
        const self: *HostNet = @ptrCast(@alignCast(ptr));
        _ = self;

        const fd = dialHost(reaching_port) catch return .refused;
        errdefer _ = linux.close(fd);

        var room: [wire.max_reaching_text]u8 = undefined;
        var line: [wire.max_reaching_text + 16]u8 = undefined;
        const said = std.fmt.bufPrint(&line, "{s} {d}\n", .{
            wire.writeAddress(&room, address),
            port,
        }) catch return .refused;

        var sent: usize = 0;
        while (sent < said.len) {
            const wrote = linux.write(fd, said[sent..].ptr, said.len - sent);
            if (linux.errno(wrote) != .SUCCESS) {
                _ = linux.close(fd);
                return .refused;
            }
            sent += wrote;
        }
        return .{ .granted = fd };
    }
};

/// `mirage_session.wire.reaching_port`. The one a guest asks to be connected on.
const reaching_port: u32 = 1025;

/// How far the guest's clock may be from the host's before it is set again.
const clock_slack_ns: i128 = std.time.ns_per_s;

/// Put the host's clock on this guest.
///
/// **Nothing else gives a guest the time.** The machine has no real time clock, so
/// it starts at the epoch: a commit is stamped 1970, a certificate is not yet
/// valid, and a build writes files older than the sources they came from. This
/// runs before the fork, where the caps to set a clock still exist.
fn setClock(io: std.Io, now_ns: i64) void {
    if (!is_linux or now_ns == 0) return;

    const held: i128 = std.Io.Timestamp.now(io, .real).nanoseconds;
    const apart = if (held > now_ns) held - now_ns else @as(i128, now_ns) - held;
    if (apart < clock_slack_ns) return;

    const wanted = std.os.linux.timespec{
        .sec = @intCast(@divTrunc(now_ns, std.time.ns_per_s)),
        .nsec = @intCast(@mod(now_ns, std.time.ns_per_s)),
    };
    _ = std.os.linux.clock_settime(.REALTIME, &wanted);
}

/// How much of the program one read is asked for when a call dies on a signal.
const probe_read_bytes: usize = 128 * 1024;

/// Whether the guest's own filesystem answered a short read for the program, as
/// a clause for the call's standard error.
///
/// **A short read is legal for `read` and fatal for a page fault.** A caller of
/// `read` loops for the rest; the kernel filling a run of pages cannot, so the
/// pages past the answer stay unfilled and the program dies on the first
/// instruction in them. That arrives as `SIGSEGV` or `SIGBUS` with nothing to
/// read, which is a whole afternoon of diagnosis unless somebody says this.
fn shortReadNote(
    arena: std.mem.Allocator,
    io: std.Io,
    request: wire.Request,
) []const u8 {
    if (request.argv.len == 0) return "";
    const here = whereGuestSees(arena, request, request.argv[0]) orelse return "";

    const file = std.Io.Dir.cwd().openFile(io, here, .{}) catch return "";
    defer file.close(io);
    const size = (file.stat(io) catch return "").size;

    const room = arena.alloc(u8, probe_read_bytes) catch return "";
    const wanted = @min(size, room.len);
    if (wanted == 0) return "";

    const got = std.os.linux.pread(file.handle, room.ptr, wanted, 0);
    if (std.os.linux.errno(got) != .SUCCESS or got >= wanted) return "";

    return std.fmt.allocPrint(
        arena,
        "\nchock guest: one read of {d} bytes of {s} answered {d}. The filesystem the host " ++
            "offered this guest answers short, and a page fault cannot ask again, so the " ++
            "program died on a page that was never filled.\n",
        .{ wanted, here, got },
    ) catch "";
}

/// Where this guest sees a path the sandbox names. The longest matching bind
/// wins, the same rule the host's own share set uses.
fn whereGuestSees(
    arena: std.mem.Allocator,
    request: wire.Request,
    wanted: []const u8,
) ?[]const u8 {
    var best: ?[]const u8 = null;
    var longest: usize = 0;
    for (request.mounts) |one| switch (one) {
        .bind => |b| {
            if (b.target.len <= longest) continue;
            if (!std.mem.startsWith(u8, wanted, b.target)) continue;
            longest = b.target.len;
            best = std.fmt.allocPrint(arena, "{s}{s}", .{ b.source, wanted[b.target.len..] }) catch null;
        },
        else => {},
    };
    return best;
}

/// The end of what the driver wrote, as one clause to put after a fault's name.
/// Empty when it wrote nothing.
fn tailOf(
    arena: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
) std.mem.Allocator.Error![]const u8 {
    const size = if (file.stat(io)) |one| one.size else |_| return "";
    if (size == 0) return "";

    var buffer: [max_fault_tail]u8 = undefined;
    const want: usize = @intCast(@min(size, buffer.len));
    const from = size - want;
    const got = file.readPositionalAll(io, buffer[0..want], from) catch return "";

    const said = std.mem.trim(u8, buffer[0..got], " \t\r\n");
    if (said.len == 0) return "";
    return std.fmt.allocPrint(arena, ", and it said: {s}", .{said});
}

/// How much of the driver's own words a refusal carries. Enough for the line it
/// prints and not the whole of a build's output.
const max_fault_tail: usize = 512;

/// Write what one descriptor of the call collected: a frame naming the length,
/// then the bytes.
///
/// **Read positionally.** The call wrote through the same open file, so the
/// offset is at the end of it and there is no seek on an `Io.File`.
fn sendOutput(io: std.Io, writer: *std.Io.Writer, file: std.Io.File, is_err: bool) !void {
    const size = if (file.stat(io)) |one| one.size else |_| 0;
    const sending = @min(size, wire.max_output_bytes);
    try wire.write(writer, wire.Output{ .output = sending, .err = is_err });
    if (sending == 0) return;

    var chunk: [64 * 1024]u8 = undefined;
    var sent: u64 = 0;
    while (sent < sending) {
        const want: usize = @intCast(@min(sending - sent, chunk.len));
        const got = file.readPositionalAll(io, chunk[0..want], sent) catch 0;
        if (got == 0) break;
        try writer.writeAll(chunk[0..got]);
        sent += got;
    }
    // A file that shrank under this still owes the host the bytes it promised.
    while (sent < sending) : (sent += 1) try writer.writeByte(0);
    try writer.flush();
}

const testing = std.testing;

/// One request a line, as the host would write them.
fn script(buffer: []u8, requests: []const wire.Request) ![]const u8 {
    var writer = std.Io.Writer.fixed(buffer);
    for (requests) |one| try wire.write(&writer, one);
    return writer.buffered();
}

const nothing_to_run = wire.Request{
    .root = "/",
    .mounts = &.{},
    .rules = &.{},
    .cwd = "/",
    .env = &.{},
    .argv = &.{},
};

test "a request naming no program is refused, and the one after it is still read" {
    var in_buffer: [4096]u8 = undefined;
    const lines = try script(&in_buffer, &.{ nothing_to_run, nothing_to_run });

    var reader = std.Io.Reader.fixed(lines);
    var out_buffer: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buffer);

    try serve(testing.allocator, testing.io, &reader, &writer, null);

    // Two answers, each a refusal, and the loop ended because the stream did.
    const said = writer.buffered();
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, said, "\n"));
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, said, "named no program"));
    // A refusal carries no exit code: a guest that could not run a call must
    // never report one it did not see.
    try testing.expect(std.mem.indexOf(u8, said, "\"ended\":null") != null);
}

test "a cancel between calls is dropped, and the request after it is still answered" {
    var in_buffer: [4096]u8 = undefined;
    const tail = try script(in_buffer[512..], &.{nothing_to_run});

    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(testing.allocator);
    // The host's own cancel for a call whose answer had already gone out.
    try joined.appendSlice(testing.allocator, wire.cancel_kill);
    try joined.appendSlice(testing.allocator, tail);

    var reader = std.Io.Reader.fixed(joined.items);
    var out_buffer: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buffer);

    try serve(testing.allocator, testing.io, &reader, &writer, null);

    // One answer and not two: a cancel is never answered, because the answer
    // would arrive in front of the next request's own.
    const said = writer.buffered();
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, said, "\n"));
    try testing.expect(std.mem.indexOf(u8, said, "named no program") != null);
}

test "a line this build cannot read ends that request and not the program" {
    var in_buffer: [4096]u8 = undefined;
    const tail = try script(in_buffer[512..], &.{nothing_to_run});

    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(testing.allocator);
    try joined.appendSlice(testing.allocator, "{this is not a request}\n");
    try joined.appendSlice(testing.allocator, tail);

    var reader = std.Io.Reader.fixed(joined.items);
    var out_buffer: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buffer);

    try serve(testing.allocator, testing.io, &reader, &writer, null);

    const said = writer.buffered();
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, said, "\n"));
    try testing.expect(std.mem.indexOf(u8, said, "could not be read") != null);
    try testing.expect(std.mem.indexOf(u8, said, "named no program") != null);
}

test "a stream that ends with nothing on it is not an error" {
    var reader = std.Io.Reader.fixed("");
    var out_buffer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buffer);

    try serve(testing.allocator, testing.io, &reader, &writer, null);
    try testing.expectEqual(@as(usize, 0), writer.buffered().len);
}

test "this program resolves nothing and holds no policy" {
    // Two properties the top comment states, read from the source so a later
    // change has to edit the comment as well.
    const own_source = @embedFile("guest.zig");
    for ([_][]const u8{
        "getAddressList",
        "addressIsReachable",
        "resolve",
        "chock-policy",
        "chock-broker",
    }) |name| {
        // The words appear in prose above, so this looks for the shapes a use
        // would have and not for the word itself.
        const called = try std.fmt.allocPrint(testing.allocator, "{s}(", .{name});
        defer testing.allocator.free(called);
        const imported = try std.fmt.allocPrint(testing.allocator, "@import(\"{s}\")", .{name});
        defer testing.allocator.free(imported);

        try testing.expect(std.mem.indexOf(u8, own_source, called) == null);
        try testing.expect(std.mem.indexOf(u8, own_source, imported) == null);
    }
}

test "the port comes from --port, and anything else is refused rather than guessed" {
    try testing.expectEqual(default_port, try portFrom(&.{}));
    try testing.expectEqual(@as(u32, 2048), try portFrom(&.{ "--port", "2048" }));

    // Each of these would otherwise be read as the default, and a guest that
    // dialled the wrong port would wait for a host that is not there.
    try testing.expectError(error.Unreadable, portFrom(&.{"2048"}));
    try testing.expectError(error.Unreadable, portFrom(&.{ "--port", "not-a-number" }));
    try testing.expectError(error.Unreadable, portFrom(&.{ "-p", "2048" }));
    try testing.expectError(error.Unreadable, portFrom(&.{ "--port", "1", "2" }));
}

/// A pair of connected streams, for a test that drives both halves of the wire.
fn pair() ![2]std.posix.fd_t {
    // **Not a failure on another platform, and not a pass either.** The call below
    // is a Linux syscall number, and checking its errno on Darwin reads a value
    // that means nothing: one run of this test came back with two descriptors that
    // were not sockets and failed on the first write with `EBADF`.
    if (!is_linux) return error.SkipZigTest;

    var fds: [2]i32 = undefined;
    const made = linux.socketpair(
        linux.AF.UNIX,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
        0,
        &fds,
    );
    if (linux.errno(made) != .SUCCESS) return error.SkipZigTest;
    return fds;
}

test "the host driver and this program agree, over a real pair of streams" {
    const gpa = testing.allocator;
    const io = testing.io;

    const fds = try pair();
    const host_end = fds[0];
    const guest_end = fds[1];
    defer _ = linux.close(host_end);

    // The guest answers one request and its side of the pair ends, so `serve`
    // returns rather than waiting for a second. One thread throughout: the driver
    // forks, and a fork carries only the calling thread.
    const host = std.Io.File{ .handle = host_end, .flags = .{ .nonblocking = false } };

    var read_buffer: [8192]u8 = undefined;
    var write_buffer: [8192]u8 = undefined;
    // Only its share set is read here: the request is written by hand below so
    // this test needs no second thread to answer it.
    const guest = chock_sandbox.vm_driver.Guest{
        .stream = host,
        .io = io,
        .shares = .{
            .root = "/mnt/shares",
            .shares = &.{
                .{ .name = "store", .host_path = "/nix/store", .writable = false },
            },
        },
        .read_buffer = &read_buffer,
        .write_buffer = &write_buffer,
    };

    // A request the guest refuses before it would spawn anything: no program to
    // run. That keeps this test free of a fork while still crossing the wire in
    // both directions through the real code on each side.
    const config = Sandbox.Config{
        .root = "/sandbox",
        .mounts = &.{.{ .bind = .{
            .source = "/nix/store/aaa-jq",
            .target = "/nix/store/aaa-jq",
            .read_only = true,
        } }},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    };

    // The driver writes its request, then waits for an answer. So the guest is
    // served first, from the bytes already in the socket, and the driver reads
    // what it wrote back. Two passes and no thread.
    // An arena: `translate` allocates one string a path, which is what its own
    // doc comment says to hold this way.
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var request_buffer: [8192]u8 = undefined;
    var writing = host.writer(io, &request_buffer);
    var share_fault: ?chock_sandbox.vm_shares.Fault = null;
    const moved = try chock_sandbox.vm_shares.translate(arena, config, guest.shares, &share_fault);
    const asked = (try wire.requestFor(arena, moved, &.{})).?;
    try wire.write(&writing.interface, asked);

    // The source the guest is told about is where the guest can reach it, and the
    // target is what a compiler message would print.
    try testing.expectEqualStrings("/mnt/shares/store/aaa-jq", asked.mounts[0].bind.source);
    try testing.expectEqualStrings("/nix/store/aaa-jq", asked.mounts[0].bind.target);

    const guest_stream = std.Io.File{ .handle = guest_end, .flags = .{ .nonblocking = false } };
    var guest_read: [8192]u8 = undefined;
    var guest_write: [8192]u8 = undefined;
    var guest_reader = guest_stream.reader(io, &guest_read);
    var guest_writer = guest_stream.writer(io, &guest_write);

    // The host end stops writing, so the guest sees the stream end after one
    // request and `serve` comes back.
    _ = linux.shutdown(host_end, linux.SHUT.WR);
    try serve(gpa, io, &guest_reader.interface, &guest_writer.interface, null);
    _ = linux.close(guest_end);

    // And the answer the guest wrote is one this build reads: a refusal naming
    // the reason, with no exit code invented for a call that never ran.
    var answer_buffer: [8192]u8 = undefined;
    var answer_reader = host.reader(io, &answer_buffer);
    const said = try wire.read(wire.Answer, gpa, &answer_reader.interface);
    defer said.deinit();
    try testing.expectEqual(@as(?wire.Answer.Ended, null), said.value.ended);
    try testing.expect(std.mem.indexOf(u8, said.value.refusal.?, "named no program") != null);
}
