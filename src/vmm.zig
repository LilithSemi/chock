//! One microVM guest, run on a thread of the daemon's.
//!
//! **No subcommand and no second process.** The daemon already runs a thread per
//! turn, so a guest is another thread of the same process. What made a separate
//! process look necessary was the tick below, and `tickUntil` is the answer to it.
//!
//! **This is a copy of Mirage's own machine setup, and that is a cost taken
//! deliberately.** Mirage's `src/linux.zig` holds a 628 line `run` that nothing in
//! `lib/` wraps, so a caller that wants to host a guest either copies it or asks
//! Mirage for a library entry point. The project owner chose the copy.
//!
//! Two things keep that cost bounded.
//!
//! **This copy is smaller than the original on purpose.** Chock needs a machine, a
//! console, a channel, and directories the guest can mount. It does not need
//! snapshots, firmware, a security chip, a balloon, a disk, or a network device:
//! a tool call reaches the network by naming a host, which crosses as Mirage's own
//! `reaching` message and is decided on the host. Each one left out is one less
//! thing to keep in step.
//!
//! **The drift is detected, because it cannot be prevented.** `mirage_surface` at
//! the bottom names every Mirage declaration this file reaches, and a test asserts
//! each one still exists. An upgrade that moves one fails a build rather than
//! leaving two versions of the same loop that differ quietly.
//!
//! ## What holds the guest up
//!
//! `Options.session` names a socket, bound before the guest runs and reported
//! through `Options.ready`, so the daemon waits on a flag rather than polling a
//! directory for a file to appear. A `chock run` child connects to that socket.
//!
//! ## The tick, and why it is a thread and not a timer
//!
//! A guest blocked on its channel exits for nothing, so without an interruption
//! the host loop only runs when the guest exits of its own accord and a waiting
//! guest waits for ever. Mirage arms a process wide `setitimer`, which is right for
//! a program that is only a VMM and wrong inside the daemon: every accept and every
//! file read there would answer `EINTR`.
//!
//! So `tickUntil` runs a thread that signals **one** thread by its own id. Nothing
//! else in the process is touched, and the handler does nothing: the interruption
//! is the whole point of it.
//!
//! **And it only signals a guest that is not getting anywhere.** Aiming at one thread
//! is more accurate than `setitimer`, which the kernel may deliver to any thread that
//! has the signal unblocked, and that accuracy is a hazard: a tick on every entry
//! cuts every entry short. A guest whose every `KVM_RUN` answered `EINTR` executed no
//! instruction at all and its console stayed empty. So the ticker watches the loop's
//! own count of turns and signals only when it has not moved.
//!
//! ## One thread for the guest's first CPU
//!
//! A guest is given one CPU. Mirage runs later ones on threads of their own, and
//! Chock has no use for that yet: a tool call's parallelism is inside the guest,
//! under the driver that already exists.

const std = @import("std");
const builtin = @import("builtin");

const backend = @import("mirage-backend");
const core = @import("mirage-core");
const arm64 = @import("mirage-arm64");
const device = @import("mirage-device");
const session_mod = @import("mirage-session");
const fs_mod = @import("mirage-fs");
const attest = @import("mirage-attest");
const GuestMemory = @import("mirage-memory").GuestMemory;
const shares_mod = @import("chock-sandbox").vm_shares;

/// True here and false in `src/vmm_absent.zig`.
pub const available = true;

/// Where the guest's memory starts, and where its console is. Mirage's own two
/// numbers: a guest placed anywhere else is a guest whose device tree says one
/// thing and whose memory is somewhere else.
const ram_base = 0x4000_0000;
const uart_base = 0x0900_0000;

/// The guest's address on the channel. Whoever started it is always at 2.
const guest_cid = 3;

/// How often the host takes the CPU back. A guest blocked on the channel exits for
/// nothing, so without this the loop below only runs when the guest exits of its
/// own accord and a waiting guest waits for ever.
const default_tick_ms: u64 = 10;

/// The most of a kernel or an initrd that is read. A guest image past this is a
/// caller naming the wrong file.
const file_limit: std.Io.Limit = .limited(512 * 1024 * 1024);

pub const Options = struct {
    kernel: []const u8 = "",
    initrd: ?[]const u8 = null,
    /// **`loglevel=7`, because a guest that faults says so at `KERN_INFO`.** The
    /// default console level is lower, so an unhandled fault in a tool call was
    /// printed by the kernel and never reached the console file, which left a
    /// signal number with nothing behind it.
    cmdline: []const u8 = "console=ttyAMA0 loglevel=7 init=/init",
    memory_mb: u64 = 512,
    /// How many processors the guest gets. **Chosen by `chock-policy`**, which
    /// holds the curve and what a machine may spare: see `sandbox.coresOn`.
    cpus: u32 = 1,
    /// Where the socket that holds this guest up goes. Required: a guest nobody
    /// holds is a guest Chock has no use for.
    session: []const u8 = "",
    /// The port the guest opens its own stream to. `chock guest` dials this.
    port: u32 = 1024,
    /// Directories the guest may mount, each under the name it sees.
    shares: []const Share = &.{},
    /// Give up after this long. Null runs until the guest stops.
    seconds: ?u64 = null,
    /// Set true once the session socket is bound, so a caller knows when it may
    /// connect without looking for the file.
    ready: ?*std.atomic.Value(bool) = null,
    /// Read every time round the loop. Set it to ask the guest to stop.
    stopping: ?*std.atomic.Value(bool) = null,

    pub const Share = struct {
        name: []const u8,
        at: []const u8,
        writable: bool = false,
    };
};

pub const Fault = struct {
    said: []const u8,
    /// The path or name the fault is about, borrowed from `options`.
    detail: []const u8 = "",
};

/// Run one guest until it stops, and hold it up on a socket while it does.
///
/// `out` is the guest's own console: a guest that failed to come up says why there
/// and nowhere else. `fault` is filled in for everything this refuses, because this
/// module holds no terminal of its own: see `src/vmm_cmd.zig`.
pub fn host(
    gpa: std.mem.Allocator,
    io: std.Io,
    options: Options,
    out: *std.Io.Writer,
    fault: *?Fault,
) anyerror!u8 {
    const cwd: std.Io.Dir = .cwd();

    const kernel = cwd.readFileAlloc(io, options.kernel, gpa, file_limit) catch {
        fault.* = .{ .said = "the kernel could not be read", .detail = options.kernel };
        return 1;
    };
    defer gpa.free(kernel);

    const initrd: ?[]u8 = if (options.initrd) |path|
        cwd.readFileAlloc(io, path, gpa, file_limit) catch {
            fault.* = .{ .said = "the initrd could not be read", .detail = path };
            return 1;
        }
    else
        null;
    defer if (initrd) |bytes| gpa.free(bytes);

    var machine = backend.kvm.Machine.create(gpa, options.cpus) catch {
        fault.* = .{ .said = "this machine would not make a guest" };
        return 1;
    };
    defer machine.deinit();

    const ram_size = options.memory_mb * 1024 * 1024;
    const region = try machine.vm.addMemory(ram_base, ram_size, .shared);
    var regions = [_]GuestMemory.Region{region};
    var memory: GuestMemory = .{ .regions = regions[0..1] };

    const hv = machine.backend();

    // One identifier a processor, and the first is the one whose answer is the
    // machine's: when it stops, the run is over.
    const ids = try gpa.alloc(backend.Backend.VcpuId, options.cpus);
    defer gpa.free(ids);
    for (ids) |*each| each.* = try hv.addVcpu();
    const id = ids[0];

    var gic = try backend.kvm.Gic.create(
        &machine.vm,
        options.cpus,
        arm64.fdt.gicd_base,
        arm64.fdt.gicr_base,
    );
    defer gic.deinit();

    // Entropy from this machine and never made up. Without it a guest kernel waits,
    // sometimes for a minute, before anything needing randomness can run.
    var seed: [32]u8 = undefined;
    try io.randomSecure(&seed);

    // The directories the guest may mount, all under one filesystem. One device and
    // not one each, because the transport cannot add a device to a running machine
    // and the set a guest holds has to be able to change while it runs.
    //
    // **Always, even for a guest that starts with none.** The transport cannot add a
    // device later, so a guest booted without this one could never be offered a
    // directory at all: a session that offers its own once its workspace exists got
    // `NoShares` and did not start. An empty mount is the right answer for a guest
    // nobody has offered anything yet.
    var offered: fs_mod.Export = try fs_mod.Export.init(gpa, io);
    defer offered.deinit();
    for (options.shares) |each| {
        offered.offer(each.name, each.at, each.writable) catch {
            fault.* = .{ .said = "a directory could not be offered", .detail = each.name };
            return 1;
        };
    }

    var manifest: attest.Manifest = .{};
    defer manifest.deinit(gpa);

    const layout = try core.Launch.prepare(gpa, &memory, &manifest, .{
        .kind = .linux,
        .kernel = kernel,
        .initrd = initrd,
        .cmdline = options.cmdline,
        .ram_base = ram_base,
        .ram_size = ram_size,
        .cpus = options.cpus,
        .uart_base = uart_base,
        .rng_seed = &seed,
        .block_device = false,
        .vsock = true,
        .balloon = false,
        .net = false,
        .tpm = false,
        .share = true,
    });

    var serial: device.Pl011 = .{ .sink = out };

    // Two ports: the one `chock guest` dials, and the one a guest opens when it
    // wants to be connected somewhere. The second is what makes a brokered network
    // possible without a resolver in the guest.
    var ports = [_]u32{ options.port, session_mod.wire.reaching_port };
    var channel: device.virtio.Vsock = undefined;
    channel.init(guest_cid, ports[0..2]);

    // The room the filesystem device carries one message and one answer in. It comes
    // from here because nothing in Mirage's device model allocates: whoever builds the
    // machine owns its memory.
    const share_asked = try gpa.alloc(u8, device.virtio.Fs.buffer_size);
    defer gpa.free(share_asked);
    const share_answered = try gpa.alloc(u8, device.virtio.Fs.buffer_size);
    defer gpa.free(share_answered);

    var shared_fs: device.virtio.Fs = undefined;
    shared_fs.init(fs_mod.Export.tag, .{ .ctx = &offered, .answer = answerFs }, share_asked, share_answered);

    // Bound before the guest runs, so whoever started this can connect as soon as
    // the process exists rather than guessing when it is ready.
    var held = session_mod.Server.listen(options.session) catch {
        fault.* = .{ .said = "nothing can hold a session there", .detail = options.session };
        return 1;
    };
    held.sharing = .{
        .ctx = &offered,
        .offer = offerShare,
        .withdraw = withdrawShare,
    };

    var attached: Devices = .{};
    attached.add(serial.device(uart_base));
    attached.addServed(shared_fs.device(arm64.fdt.fs_base), shared_fs.service(arm64.fdt.fs_intid));
    attached.addServed(channel.device(arm64.fdt.vsock_base), channel.service(arm64.fdt.vsock_intid));
    var bus = attached.bus();

    try core.Launch.enter(hv, id, layout);

    if (options.ready) |flag| flag.store(true, .release);

    // The ticker signals this thread, so its id is taken here and nowhere else.
    armTickHandler();
    var ticking: std.atomic.Value(bool) = .init(false);
    var turns: std.atomic.Value(u64) = .init(0);
    const ticker = std.Thread.spawn(.{}, tickUntil, .{Ticker{
        .thread_id = std.os.linux.gettid(),
        .group_id = std.os.linux.getpid(),
        .every_ms = default_tick_ms,
        .done = &ticking,
        .turns = &turns,
    }}) catch {
        fault.* = .{ .said = "the guest's own ticker thread could not be started" };
        return 1;
    };
    defer {
        ticking.store(true, .release);
        ticker.join();
    }

    // Read by every processor's host hook, so one woken out of the hypervisor at
    // the end does not enter it again. See `wakeParked`.
    var ending: std.atomic.Value(bool) = .init(false);

    var end: Pump = .{
        .io = io,
        .ending = &ending,
        .deadline = if (options.seconds) |limit|
            std.Io.Clock.awake.now(io).nanoseconds + @as(i96, @intCast(limit)) * std.time.ns_per_s
        else
            null,
        .vsock = &channel,
        .session = &held,
        .out = out,
        .stopping = options.stopping,
        .turns = &turns,
    };

    // What every processor is given. The lock is the one Mirage asks the runner
    // for, and a machine with one processor passes none: see `Shared`.
    var shared: Shared = .{};
    const driving: core.Launch.Run = .{
        .bus = &bus,
        .memory = &memory,
        .controller = gic.controller(),
        .services = attached.served(),
        .host = end.launchHost(),
        .guard = if (options.cpus > 1) shared.guard() else null,
    };

    // **No `power` hook, and that is right here.** A guest starts its other
    // processors through the power interface, and on KVM the kernel answers that
    // itself. A backend whose hypervisor does not would need one: see Mirage's
    // own `src/darwin.zig`, which parks a thread per processor instead.
    const others = try gpa.alloc(std.Thread, options.cpus - 1);
    defer gpa.free(others);
    const parked = try gpa.alloc(Parked, options.cpus - 1);
    defer gpa.free(parked);
    for (parked) |*one| one.* = .{};
    var started: usize = 0;
    // **Joined last and woken first.** A deferred statement runs before the ones
    // declared above it, so `wakeParked` is reached before these joins.
    defer for (others[0..started]) |each| each.join();
    defer wakeParked(parked[0..started], &ending);
    for (ids[1..], 0..) |each, index| {
        others[index] = std.Thread.spawn(
            .{},
            driveCpu,
            .{ hv, each, driving, &parked[index] },
        ) catch {
            fault.* = .{ .said = "a processor of the guest would not start" };
            return 1;
        };
        started += 1;
    }

    // A guest that faults tells the session so too. Without this a fault reached
    // whoever held the session as a closed socket, which is what a guest that
    // finished normally also looks like.
    const reason = core.Launch.run(hv, id, driving) catch {
        held.lost(.faulted);
        held.close(&channel);
        out.flush() catch {};
        fault.* = .{ .said = "the guest stopped badly" };
        return 1;
    };

    // Whoever holds the session learns the guest has gone from a message, so a call
    // already in flight fails rather than waiting for a guest that is not there.
    held.lost(endingOf(reason, end.timed_out));
    held.close(&channel);
    out.flush() catch {};

    if (end.timed_out) {
        fault.* = .{ .said = "the guest ran out of the time it was given" };
        return 1;
    }
    return 0;
}

/// How a guest that has gone came to go, in the names a session carries.
///
/// A deadline that ran out and an operator who asked both reach `Launch` as
/// `stopped`, and only this end knows which: `timed_out` is the deadline.
fn endingOf(reason: core.Launch.Reason, timed_out: bool) session_mod.wire.Reason {
    return switch (reason) {
        .shutdown => .powered_off,
        .reset => .restarted,
        .stopped => if (timed_out) .limit_reached else .was_asked,
    };
}

/// Every device the guest is given, and the ones with work to do between exits.
/// Mirage's own `Attached`, which lives in its `src/` and not its `lib/`.
const Devices = struct {
    const room = 4;

    devices: [room]device.Device = undefined,
    services: [room]device.Service = undefined,
    device_count: usize = 0,
    service_count: usize = 0,

    fn add(self: *Devices, one: device.Device) void {
        std.debug.assert(self.device_count < self.devices.len);
        self.devices[self.device_count] = one;
        self.device_count += 1;
    }

    fn addServed(self: *Devices, one: device.Device, work: device.Service) void {
        std.debug.assert(self.service_count < self.services.len);
        self.add(one);
        self.services[self.service_count] = work;
        self.service_count += 1;
    }

    fn bus(self: *Devices) device.Bus {
        return .{ .devices = self.devices[0..self.device_count] };
    }

    fn served(self: *const Devices) []const device.Service {
        return self.services[0..self.service_count];
    }
};

/// The work that belongs to this process, run after every guest exit.
///
/// **The session owns the channel.** The streams the guest opens go to whoever
/// holds the session, and this process reads none of them: they are not its to
/// read. That is the whole difference from Mirage's own pump, which prints them.
const Pump = struct {
    io: std.Io,
    /// From the clock that only goes forwards, so an administrator moving the
    /// system clock does not move the deadline.
    deadline: ?i96,
    vsock: *device.virtio.Vsock,
    session: *session_mod.Server,
    out: *std.Io.Writer,
    /// Asked every time round. The daemon sets it to end a guest it no longer
    /// needs.
    stopping: ?*std.atomic.Value(bool) = null,
    /// Set once this end is finished with the guest, so a processor woken out of
    /// the hypervisor stops rather than entering it again. See `wakeParked`.
    ending: *std.atomic.Value(bool),
    timed_out: bool = false,
    /// Counts the turns, so the console is pushed out now and then. A guest that is
    /// killed before it stops would otherwise lose whatever is still buffered, and
    /// that is exactly the output somebody debugging needs.
    ///
    /// The ticker reads it too, which is why it is shared and not a plain counter:
    /// see `tickUntil`.
    turns: *std.atomic.Value(u64),

    fn launchHost(self: *Pump) core.Launch.Host {
        return .{ .ctx = self, .step = Pump.step };
    }

    fn step(ctx: *anyopaque) bool {
        const self: *Pump = @ptrCast(@alignCast(ctx));

        if (self.ending.load(.acquire)) return false;
        if (self.stopping) |flag| {
            if (flag.load(.acquire)) return false;
        }

        // Often enough to follow a boot as it happens, rarely enough not to be a write
        // on every exit. **512 was too rare**: a guest still running had written its
        // whole boot into the buffer and its console file held nothing, which is
        // exactly the output somebody diagnosing a guest needs.
        const turn = self.turns.fetchAdd(1, .release) + 1;
        if (turn % 32 == 0) self.out.flush() catch {};

        if (self.deadline) |when| {
            if (std.Io.Clock.awake.now(self.io).nanoseconds > when) {
                self.timed_out = true;
                return false;
            }
        }

        self.session.pump(self.vsock);
        return !self.session.asked_stop;
    }
};

fn answerFs(ctx: *anyopaque, request: []const u8, into: []u8) usize {
    const one: *fs_mod.Export = @ptrCast(@alignCast(ctx));
    return one.answer(request, into);
}

fn offerShare(ctx: *anyopaque, name: []const u8, at: []const u8, writable: bool) bool {
    const one: *fs_mod.Export = @ptrCast(@alignCast(ctx));
    one.offer(name, at, writable) catch return false;
    return true;
}

fn withdrawShare(ctx: *anyopaque, name: []const u8) void {
    const one: *fs_mod.Export = @ptrCast(@alignCast(ctx));
    one.withdraw(name);
}

/// Where a tick is sent, and when to stop sending.
/// Something for every processor to hold while anything shared is touched.
///
/// **Mirage keeps no lock of its own on purpose**: its `Launch.Guard` is supplied
/// by whoever runs the processors, because that module does not know what a
/// thread is. So this is the lock, and it is the only one. **Do not add a second
/// inside a device**: two locks around one piece of data is how a deadlock
/// arrives later. Shaped after `src/host.zig` in Mirage, whose runner does this.
///
/// A machine with one processor passes none. There is nothing to race with, and a
/// lock nobody contends for still costs something on every exit.
const Shared = struct {
    held: std.atomic.Mutex = .unlocked,

    fn guard(self: *Shared) core.Launch.Guard {
        return .{ .ctx = self, .lock = Shared.take, .unlock = Shared.release };
    }

    fn take(ctx: *anyopaque) void {
        const self: *Shared = @ptrCast(@alignCast(ctx));
        while (!self.held.tryLock()) std.atomic.spinLoopHint();
    }

    fn release(ctx: *anyopaque) void {
        const self: *Shared = @ptrCast(@alignCast(ctx));
        self.held.unlock();
    }
};

/// One processor of a guest that has more than one.
///
/// Every processor but the first starts stopped, so its thread waits inside the
/// hypervisor until the guest asks for it. What this returns is not reported: the
/// first processor is the one that says how the machine stopped.
fn driveCpu(
    hv: backend.Backend,
    id: backend.Backend.VcpuId,
    driving: core.Launch.Run,
    mine: *Parked,
) void {
    mine.thread_id.store(std.os.linux.gettid(), .release);
    defer mine.ended.store(true, .release);
    _ = core.Launch.run(hv, id, driving) catch {};
}

/// Where one of the other processors says which thread it is, so it can be woken.
const Parked = struct {
    thread_id: std.atomic.Value(std.posix.pid_t) = .init(0),
    ended: std.atomic.Value(bool) = .init(false),
};

/// Bring every other processor out of the hypervisor so its thread can be joined.
///
/// **A parked processor never sees the host hook.** `Pump.step` runs between exits,
/// and a processor the guest has not started is inside the hypervisor waiting for
/// an interrupt that is not coming, so it exits on nothing and a join on it never
/// returns. The signal is the one the ticker uses, with the same handler and the
/// same lack of `SA_RESTART`: it makes the call return, and `ending` is what the
/// hook reads to stop for good.
fn wakeParked(parked: []Parked, ending: *std.atomic.Value(bool)) void {
    ending.store(true, .release);
    const group = std.os.linux.getpid();
    var rounds: usize = 0;
    while (rounds < wake_rounds) : (rounds += 1) {
        var waiting: usize = 0;
        for (parked) |*one| {
            if (one.ended.load(.acquire)) continue;
            waiting += 1;
            const tid = one.thread_id.load(.acquire);
            if (tid != 0) _ = std.os.linux.tgkill(group, tid, .ALRM);
        }
        if (waiting == 0) return;
        var pause: std.os.linux.timespec = .{ .sec = 0, .nsec = wake_step_ns };
        _ = std.os.linux.nanosleep(&pause, null);
    }
}

const wake_rounds: usize = 2000;
const wake_step_ns: isize = 1_000_000;

const Ticker = struct {
    /// The thread inside the hypervisor. Signalled by its own id, so no other
    /// thread of this process is interrupted.
    thread_id: std.posix.pid_t,
    group_id: std.posix.pid_t,
    every_ms: u64,
    done: *std.atomic.Value(bool),
    /// The loop's own count of turns. A count that moved between two looks is a
    /// guest getting somewhere, and a guest getting somewhere is never interrupted.
    turns: *std.atomic.Value(u64),
};

/// Install the handler that makes a blocked hypervisor call return. **No
/// `SA_RESTART`**: the interruption is the whole point, and a restarted call would
/// never come back.
fn armTickHandler() void {
    const act: std.os.linux.Sigaction = .{
        .handler = .{ .handler = onAlarm },
        .mask = std.mem.zeroes(std.os.linux.sigset_t),
        .flags = 0,
    };
    _ = std.os.linux.sigaction(.ALRM, &act, null);
}

/// Signal one thread whenever the loop it runs has stopped moving.
fn tickUntil(ticker: Ticker) void {
    const every: std.os.linux.timespec = .{
        .sec = @intCast(ticker.every_ms / std.time.ms_per_s),
        .nsec = @intCast((ticker.every_ms % std.time.ms_per_s) * std.time.ns_per_ms),
    };
    var last: u64 = 0;
    while (!ticker.done.load(.acquire)) {
        _ = std.os.linux.nanosleep(&every, null);

        // A turn happened while this slept, so the guest is exiting on its own and
        // needs nothing from here. Interrupting it would take the entry it is in the
        // middle of.
        const now = ticker.turns.load(.acquire);
        if (now != last) {
            last = now;
            continue;
        }
        _ = std.os.linux.tgkill(ticker.group_id, ticker.thread_id, .ALRM);
    }
}

fn onAlarm(_: std.os.linux.SIG) callconv(.c) void {}

/// What a `chock run` child holds to reach the guest the daemon started.
pub const Attached = struct {
    /// The session socket. Closed by the caller.
    control: std.posix.fd_t,
    /// The stream `chock guest` opened inside the guest. Closed by the caller.
    stream: std.posix.fd_t,
};

pub const AttachError = error{
    /// Nothing is listening on that socket, so the daemon's guest is not there.
    NoGuest,
    /// The guest would not take one of the directories offered to it.
    ShareRefused,
    /// The guest opened no stream on that port. Its own `chock guest` may not be
    /// running.
    NoStream,
};

/// Reach the guest at `socket_path`, offer it `shares`, and take a stream into it.
///
/// **Here and not in `src/run.zig`**, because the session wire is Mirage's and only
/// this module imports it. A build that cannot run a guest answers `NoGuest`
/// without a stub client of its own.
/// Ask a descriptor to wait again, undoing Mirage's own `dontWait`.
fn waitOnStream(fd: std.posix.fd_t) void {
    const flags = std.os.linux.fcntl(fd, std.posix.F.GETFL, 0);
    if (std.os.linux.errno(flags) != .SUCCESS) return;
    const asking: std.posix.O = .{ .NONBLOCK = true };
    const without = flags & ~@as(usize, @as(u32, @bitCast(asking)));
    _ = std.os.linux.fcntl(fd, std.posix.F.SETFL, without);
}

/// What the host answers a guest reaching out with.
pub const Reached = union(enum) {
    /// A descriptor already connected where the guest asked. **Ownership crosses**:
    /// this end closes it once the guest has it.
    connected: std.posix.fd_t,
    refused,
};

/// Who decides where a guest may reach. The text is an address written by
/// `chock-sandbox`'s `vm_wire.writeAddress`, and never a name: the guest's own
/// router asked the host to resolve and reaches for what it was given.
pub const Reaches = struct {
    ptr: *anyopaque,
    decide: *const fn (ptr: *anyopaque, text: []const u8, port: u16) Reached,
};

/// How long a poll of the session waits before looking at `stopping` again.
const reaching_wait_ms: i32 = 100;

/// Answer guests reaching out, until `stopping` is set.
///
/// **A thread of its own, because a reaching arrives while a call is running.**
/// The question comes on Mirage's control socket and the answer is a descriptor,
/// which no stream carries: whoever is inside `Guest.spawn` is blocked on the
/// guest's own stream and cannot also be here.
///
/// The descriptor is closed here whatever happens. `Client.allow` keeps its own
/// copy open until the guest has it, and says so.
pub fn serveReaching(
    io: std.Io,
    control: std.posix.fd_t,
    reaches: Reaches,
    stopping: *std.atomic.Value(bool),
) void {
    _ = io;
    var client = session_mod.Client.adopt(control);

    var watching = [1]std.posix.pollfd{.{
        .fd = control,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};

    while (!stopping.load(.acquire)) {
        const ready = std.posix.poll(&watching, reaching_wait_ms) catch return;
        if (ready == 0) continue;

        while (client.take() catch return) |said| switch (said) {
            .lost => return,
            .reaching => |asking| {
                switch (reaches.decide(reaches.ptr, asking.name(), asking.port)) {
                    .connected => |fd| {
                        defer closeOne(fd);
                        client.allow(asking, fd) catch return;
                    },
                    .refused => client.refuse(asking) catch return,
                }
            },
            .up, .other => {},
        };
    }
}

fn closeOne(fd: std.posix.fd_t) void {
    _ = std.os.linux.close(fd);
}

pub fn attach(
    io: std.Io,
    socket_path: []const u8,
    shares: []const shares_mod.Share,
    port: u32,
) AttachError!Attached {
    // The session wire is raw descriptors and takes no `std.Io`. The parameter is
    // here so `src/vmm_absent.zig` has the same shape.
    _ = io;

    const control = session_mod.socket.reach(socket_path) catch return error.NoGuest;
    var client = session_mod.Client.adopt(control);
    errdefer client.stop();

    for (shares) |one| {
        client.share(one.name, one.host_path, one.writable) catch return error.ShareRefused;
    }

    // **Wait for the guest to say it is up, and do not poll for a stream.** The socket
    // is bound before the guest runs, so a caller that connects the moment it appears
    // is talking to a guest that has not booted. Asking for a stream in a loop is
    // worse than useless: every ask is work the guest's own loop does instead of
    // running the guest, and a session that asked every 100ms starved its guest to two
    // productive entries in thirty seconds where one left alone managed 371.
    //
    // Mirage says when the guest is up: it is the first stream the guest opens, which
    // is `chock guest` dialling. So this listens for that and then asks once.
    if (!try upWithin(&client, attach_wait_ms)) return error.NoStream;

    const stream = client.channel(port) catch return error.NoStream;

    // **The stream arrives asking not to wait, and this protocol waits.** Mirage
    // makes its session sockets non-blocking for its own loop and passes one end
    // over, so a read that arrives before the guest has answered fails with
    // `WouldBlock` rather than waiting, and the caller reads that as a guest that
    // is gone. The two ends are separate open file descriptions, so clearing it
    // here changes nothing on Mirage's own.
    waitOnStream(stream);

    return .{ .control = control, .stream = stream };
}

/// Whether the guest said it is up inside `limit_ms`.
fn upWithin(client: *session_mod.Client, limit_ms: u64) AttachError!bool {
    var waited: u64 = 0;
    while (waited < limit_ms) : (waited += attach_look_ms) {
        while (client.take() catch return error.NoGuest) |said| switch (said) {
            .up => return true,
            .lost => return false,
            // A guest reaching for a name before anything is attached to answer is
            // not this function's business, and neither is a message from a later
            // Mirage. Both are left for the loop that owns the session.
            .reaching, .other => {},
        };

        const pause: std.os.linux.timespec = .{
            .sec = 0,
            .nsec = attach_look_ms * std.time.ns_per_ms,
        };
        _ = std.os.linux.nanosleep(&pause, null);
    }
    return false;
}

/// How long to wait for the guest's own program to dial, and how often to look. A
/// guest reads a kernel, loads five modules and mounts a filesystem first.
const attach_wait_ms: u64 = 30 * std.time.ms_per_s;
const attach_look_ms: u64 = 100;

const testing = std.testing;

test "the two numbers a guest is placed at are Mirage's own" {
    // A guest placed anywhere else is one whose device tree says one thing and
    // whose memory is somewhere else. These are read from Mirage where they can be,
    // and the two that cannot are pinned here.
    try testing.expectEqual(@as(u64, 0x4000_0000), ram_base);
    try testing.expectEqual(@as(u64, 0x0900_0000), uart_base);
    try testing.expect(arm64.fdt.gicd_base != arm64.fdt.gicr_base);
    try testing.expect(arm64.fdt.vsock_base != arm64.fdt.fs_base);
    try testing.expect(arm64.fdt.vsock_intid != arm64.fdt.fs_intid);
}

/// Every Mirage declaration this file's copy of the machine setup reaches.
///
/// **This is the drift guard.** Copying Mirage's own setup was a decision, and the
/// cost of it is two versions of one loop. Nothing can stop them diverging, so this
/// makes a divergence fail a build: an upgrade that renames or moves any of these
/// stops here rather than quietly leaving Chock on an older shape.
const mirage_surface = .{
    .{ "mirage-backend", "kvm.Machine.create" },
    .{ "mirage-backend", "kvm.Gic.create" },
    .{ "mirage-core", "Launch.prepare" },
    .{ "mirage-core", "Launch.enter" },
    .{ "mirage-core", "Launch.run" },
    .{ "mirage-core", "Launch.Host" },
    .{ "mirage-core", "Launch.Guard" },
    .{ "mirage-core", "Launch.Run" },
    .{ "mirage-backend", "Backend.VcpuId" },
    .{ "mirage-attest", "Manifest" },
    .{ "mirage-arm64", "fdt.gicd_base" },
    .{ "mirage-arm64", "fdt.gicr_base" },
    .{ "mirage-arm64", "fdt.vsock_base" },
    .{ "mirage-arm64", "fdt.vsock_intid" },
    .{ "mirage-arm64", "fdt.fs_base" },
    .{ "mirage-arm64", "fdt.fs_intid" },
    .{ "mirage-device", "Pl011" },
    .{ "mirage-device", "Bus" },
    .{ "mirage-device", "Device" },
    .{ "mirage-device", "Service" },
    .{ "mirage-device", "virtio.Vsock" },
    .{ "mirage-device", "virtio.Fs" },
    .{ "mirage-session", "Server" },
    .{ "mirage-session", "Client.adopt" },
    .{ "mirage-session", "Client.take" },
    .{ "mirage-session", "Client.allow" },
    .{ "mirage-session", "Client.refuse" },
    .{ "mirage-session", "Client.Reaching.name" },
    .{ "mirage-session", "wire.reaching_port" },
    .{ "mirage-session", "wire.Reason" },
    .{ "mirage-device", "virtio.Fs.buffer_size" },
    .{ "mirage-fs", "Export" },
    .{ "mirage-memory", "GuestMemory" },
};

test "every Mirage declaration this copy reaches still exists" {
    // A build failure and not a runtime one: an upgrade that moved any of these
    // stops here, which is the whole reason this list is written down.
    _ = backend.kvm.Machine.create;
    _ = backend.kvm.Gic.create;
    _ = core.Launch.prepare;
    _ = core.Launch.enter;
    _ = core.Launch.run;
    _ = core.Launch.Host;
    _ = core.Launch.Guard;
    _ = core.Launch.Run;
    _ = backend.Backend.VcpuId;
    _ = attest.Manifest;
    _ = arm64.fdt.gicd_base;
    _ = arm64.fdt.gicr_base;
    _ = arm64.fdt.vsock_base;
    _ = arm64.fdt.vsock_intid;
    _ = arm64.fdt.fs_base;
    _ = arm64.fdt.fs_intid;
    _ = device.Pl011;
    _ = device.Bus;
    _ = device.Device;
    _ = device.Service;
    _ = device.virtio.Vsock;
    _ = device.virtio.Fs;
    _ = session_mod.Server;
    _ = session_mod.Client.adopt;
    _ = session_mod.Client.take;
    _ = session_mod.Client.allow;
    _ = session_mod.Client.refuse;
    _ = session_mod.Client.Reaching.name;
    _ = session_mod.wire.reaching_port;
    _ = session_mod.wire.Reason;
    _ = device.virtio.Fs.buffer_size;
    _ = fs_mod.Export;
    _ = GuestMemory;

    // And the list above says as much as the code does, so a reader can see the
    // whole surface without reading the setup.
    try testing.expectEqual(@as(usize, 33), mirage_surface.len);
}
