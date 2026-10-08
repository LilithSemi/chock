//! One microVM guest, in a forked process of its own.

const std = @import("std");
const builtin = @import("builtin");

const sys = @import("vmm_sys.zig");

const backend = @import("mirage-backend");
const core = @import("mirage-core");
const arch = @import("mirage-arch");
const device = @import("mirage-device");
const session_mod = @import("mirage-session");
const fs_mod = @import("mirage-fs");
const attest = @import("mirage-attest");
const GuestMemory = @import("mirage-memory").GuestMemory;
const chock_sandbox = @import("chock-sandbox");
const shares_mod = chock_sandbox.vm_shares;

pub const available = true;

const ram_base: u64 = switch (builtin.cpu.arch) {
    .x86_64 => 0,
    .aarch64 => 0x4000_0000,
    else => @compileError("a guest is only placed for x86_64 and aarch64"),
};

/// The 32-bit window the x86 platform lays its devices in, from the virtio base
/// up to 4 GiB. Guest RAM must leave it clear: a memory slot over it makes the
/// kernel claim the range as System RAM, and a device can no longer take its own
/// region. The RAM that would land here moves above 4 GiB instead. aarch64 starts
/// its RAM above the devices, so it needs no hole.
const mmio_hole_base: u64 = 0xd000_0000;
const high_ram_base: u64 = 0x1_0000_0000;

const RamSlot = struct { gpa: u64, len: u64 };

/// Guest RAM slots that keep clear of a device window from `hole_base` to
/// `high_base`. RAM that would cross `hole_base` is split: the part below stays,
/// the rest is placed at `high_base`. A target with no window passes a `hole_base`
/// above every address, so one slot comes back. Returns the count written, 1 or 2.
fn ramSlots(base: u64, size: u64, hole_base: u64, high_base: u64, out: *[2]RamSlot) usize {
    if (base < hole_base and base + size > hole_base) {
        const low = hole_base - base;
        out[0] = .{ .gpa = base, .len = low };
        out[1] = .{ .gpa = high_base, .len = size - low };
        return 2;
    }
    out[0] = .{ .gpa = base, .len = size };
    return 1;
}

const uart_base = arch.platform.serial.addr;

const serial_on_port = arch.platform.serial_is_port;

const Serial = if (serial_on_port) device.Uart16550 else device.Pl011;

const Machine = if (builtin.os.tag == .macos) backend.hvf.Machine else backend.kvm.Machine;

// KVM makes the guest's memory, starts its processors, and holds the interrupt controller. Hypervisor.framework does none of them.
const own_memory = builtin.os.tag == .macos;
const own_cpus = builtin.os.tag == .macos;
const own_controller = builtin.os.tag == .macos;

const sev_possible = builtin.os.tag == .linux and builtin.cpu.arch == .x86_64;

const sev_policy: u32 = 0;

pub const Sev = enum {
    off,
    sev,

    pub fn text(self: Sev) []const u8 {
        return switch (self) {
            .off => "off",
            .sev => "sev",
        };
    }

    pub fn fromText(said: []const u8) Sev {
        if (std.mem.eql(u8, said, "sev")) return .sev;
        return .off;
    }
};

const guest_cid = 3;

const default_tick_ms: u64 = 10;

const file_limit: std.Io.Limit = .limited(512 * 1024 * 1024);

const default_cmdline: []const u8 = if (serial_on_port)
    "console=ttyS0 loglevel=7 init=/init"
else
    "console=ttyAMA0 loglevel=7 init=/init";

pub const Options = struct {
    kernel: []const u8 = "",
    initrd: ?[]const u8 = null,
    cmdline: []const u8 = default_cmdline,
    memory_mb: u64 = 512,
    cpus: u32 = 1,
    session: []const u8 = "",
    port: u32 = 1024,
    shares: []const Share = &.{},
    seconds: ?u64 = null,
    control: i32,

    pub const Share = shares_mod.Share;
};

pub const shareCovers = shares_mod.underneath;

pub const shareNameFor = shares_mod.nameFor;

pub const fork_sets_control: i32 = -1;

pub const Fault = struct {
    said: []const u8,
    detail: []const u8 = "",
};

const SharesLine = struct {
    shares: []const shares_mod.Share,
};

const ReadyLine = struct {
    ready: bool = false,
    said: []const u8 = "",
    detail: []const u8 = "",
    sev: []const u8 = "",
};

const fault_text_bytes: usize = 1024;

const fault_line_bytes: usize = 16 * 1024;

fn writeShares(
    allocator: std.mem.Allocator,
    into: *std.ArrayList(u8),
    shares: []const shares_mod.Share,
) !void {
    var writing: std.Io.Writer.Allocating = .fromArrayList(allocator, into);
    defer into.* = writing.toArrayList();
    try std.json.Stringify.value(SharesLine{ .shares = shares }, .{}, &writing.writer);
    try writing.writer.writeByte('\n');
}

fn readShares(allocator: std.mem.Allocator, line: []const u8) ![]shares_mod.Share {
    const parsed = try std.json.parseFromSlice(SharesLine, allocator, line, .{});
    defer parsed.deinit();

    const out = try allocator.alloc(shares_mod.Share, parsed.value.shares.len);
    var held: usize = 0;
    errdefer freeShares(allocator, out[0..held]);
    for (parsed.value.shares, out) |from, *to| {
        const name = try allocator.dupe(u8, from.name);
        errdefer allocator.free(name);
        to.* = .{
            .name = name,
            .host_path = try allocator.dupe(u8, from.host_path),
            .writable = from.writable,
        };
        held += 1;
    }
    return out;
}

fn freeShares(allocator: std.mem.Allocator, shares: []shares_mod.Share) void {
    for (shares) |one| {
        allocator.free(one.name);
        allocator.free(one.host_path);
    }
    allocator.free(shares);
}

pub const ForkError = error{
    NoChannel,
    NoFork,
    NoGuest,
};

pub const SendError = error{
    OutOfMemory,
    Broke,
};

pub const ReadyError = error{
    GuestRefused,
    GuestGone,
    GuestSlow,
};

pub const Child = struct {
    pid: std.posix.pid_t,
    control: i32,
    said: [fault_text_bytes]u8 = undefined,
    said_len: usize = 0,
    detail: [fault_text_bytes]u8 = undefined,
    detail_len: usize = 0,
    sev: Sev = .off,

    pub fn sendShares(
        self: *Child,
        allocator: std.mem.Allocator,
        shares: []const shares_mod.Share,
    ) SendError!void {
        var line: std.ArrayList(u8) = .empty;
        defer line.deinit(allocator);
        writeShares(allocator, &line, shares) catch return error.OutOfMemory;
        if (!writeAll(self.control, line.items)) return error.Broke;
    }

    pub fn waitReady(self: *Child, io: std.Io, limit_ms: u64) ReadyError!void {
        const deadline = std.Io.Clock.awake.now(io).nanoseconds +
            @as(i96, @intCast(limit_ms)) * std.time.ns_per_ms;

        var room: [fault_line_bytes]u8 = undefined;
        var filled: usize = 0;
        while (true) {
            const left = deadline - std.Io.Clock.awake.now(io).nanoseconds;
            if (left <= 0) return error.GuestSlow;

            var watching = [1]std.posix.pollfd{.{
                .fd = self.control,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const ready = std.posix.poll(&watching, millisecondsIn(left)) catch
                return error.GuestGone;
            if (ready == 0) continue;

            const got = switch (sys.read(self.control, room[filled..])) {
                .got => |count| count,
                .interrupted, .again => continue,
                .ended, .broke => return error.GuestGone,
            };

            const was = filled;
            filled += got;
            if (std.mem.indexOfScalar(u8, room[was..filled], '\n')) |at| {
                return self.readReady(room[0 .. was + at]);
            }
            if (filled == room.len) {
                self.note("the guest sent more than one line of fault text", "");
                return error.GuestRefused;
            }
        }
    }

    fn readReady(self: *Child, line: []const u8) ReadyError!void {
        var room: [fault_line_bytes]u8 = undefined;
        var fixed: std.heap.FixedBufferAllocator = .init(&room);
        const said = std.json.parseFromSliceLeaky(
            ReadyLine,
            fixed.allocator(),
            std.mem.trim(u8, line, " \t\r\n"),
            .{ .ignore_unknown_fields = true },
        ) catch {
            self.note("the guest said something this build cannot read", "");
            return error.GuestRefused;
        };
        if (said.ready) {
            self.sev = Sev.fromText(said.sev);
            return;
        }
        self.note(said.said, said.detail);
        return error.GuestRefused;
    }

    fn note(self: *Child, said: []const u8, detail: []const u8) void {
        self.said_len = copyInto(&self.said, said);
        self.detail_len = copyInto(&self.detail, detail);
    }

    pub fn fault(self: *Child) ?Fault {
        if (self.said_len == 0) return null;
        return .{
            .said = self.said[0..self.said_len],
            .detail = self.detail[0..self.detail_len],
        };
    }

    pub fn stop(self: *Child) void {
        if (self.control >= 0) {
            sys.close(self.control);
            self.control = -1;
        }
    }

    // A signalled child answers 128 plus the signal, the shell's own convention, so a killed guest is not read as one that exited 1.
    pub fn wait(self: *Child) u8 {
        var waited: u64 = 0;
        while (waited < stop_grace_ms) : (waited += stop_look_ms) {
            if (sys.reap(self.pid, false)) |code| return code;
            sys.sleepMs(stop_look_ms);
        }

        sys.killNow(self.pid);
        return sys.reap(self.pid, true) orelse 1;
    }
};

const stop_grace_ms: u64 = 5000;
const stop_look_ms: u64 = 5;

pub fn forkHost(io: std.Io, options: Options, console_fd: std.posix.fd_t) ForkError!Child {
    var pair: [2]i32 = undefined;
    if (!sys.channelPair(&pair)) return error.NoChannel;

    const rc = sys.forkNow() orelse {
        sys.close(pair[0]);
        sys.close(pair[1]);
        return error.NoFork;
    };

    if (rc != 0) {
        sys.close(pair[1]);
        return .{ .pid = rc, .control = pair[0] };
    }

    sys.close(pair[0]);
    sys.endWithParent();

    // fork copies the whole descriptor table and CLOEXEC does not apply since this child never execs: close everything but these two.
    chock_sandbox.after_fork.keepOnlyDescriptors(&.{ console_fd, pair[1] });

    for ([_]i32{ 0, 1, 2 }) |slot| {
        if (slot == console_fd or slot == pair[1]) continue;
        sys.dupOnto(console_fd, slot);
    }

    chock_sandbox.after_fork.resetSignalState();

    sys.ignoreWriteSignals();

    sys.ownSession();

    std.process.exit(childMain(io, options, console_fd, pair[1]));
}

fn childMain(io: std.Io, options: Options, console_fd: std.posix.fd_t, control: i32) u8 {
    var state: std.heap.DebugAllocator(.{ .thread_safe = true }) = .{};
    const gpa = state.allocator();

    const file: std.Io.File = .{ .handle = console_fd, .flags = .{ .nonblocking = false } };
    var out_buffer: [16 * 1024]u8 = undefined;
    var console = file.writer(io, &out_buffer);
    const out = &console.interface;

    var mine = options;
    mine.control = control;

    const room = gpa.alloc(u8, chock_sandbox.vm_wire.max_message_bytes) catch {
        sayFault(control, "there was no room to read the share set", "");
        return 1;
    };
    const taken = readLineInto(control, room) orelse {
        sayFault(control, "the share set never arrived on the control channel", "");
        return 1;
    };
    const sent = readShares(gpa, taken) catch {
        sayFault(control, "the share set on the control channel could not be read", "");
        return 1;
    };
    gpa.free(room);

    mine.shares = joinShares(gpa, options.shares, sent) catch {
        sayFault(control, "the share set could not be held", "");
        return 1;
    };

    var fault: ?Fault = null;
    const code = host(gpa, io, mine, out, &fault) catch |err| {
        out.flush() catch {};
        sayFault(control, "the guest ended badly", @errorName(err));
        return 1;
    };
    out.flush() catch {};
    if (fault) |said| sayFault(control, said.said, said.detail);
    return code;
}

fn joinShares(
    allocator: std.mem.Allocator,
    had: []const shares_mod.Share,
    sent: []const shares_mod.Share,
) ![]shares_mod.Share {
    const out = try allocator.alloc(shares_mod.Share, had.len + sent.len);
    @memcpy(out[0..had.len], had);
    @memcpy(out[had.len..], sent);
    return out;
}

fn sayReady(control: i32, sev: Sev) void {
    var room: [64]u8 = undefined;
    var writing: std.Io.Writer = .fixed(&room);
    writing.print("{{\"ready\":true,\"sev\":\"{s}\"}}\n", .{sev.text()}) catch return;
    _ = writeAll(control, writing.buffered());
}

fn sayFault(control: i32, said: []const u8, detail: []const u8) void {
    var room: [fault_line_bytes]u8 = undefined;
    var writing: std.Io.Writer = .fixed(&room);
    const line: ReadyLine = .{
        .ready = false,
        .said = said[0..@min(said.len, fault_text_bytes)],
        .detail = detail[0..@min(detail.len, fault_text_bytes)],
    };
    std.json.Stringify.value(line, .{}, &writing) catch return;
    writing.writeByte('\n') catch return;
    _ = writeAll(control, writing.buffered());
}

fn readLineInto(fd: i32, into: []u8) ?[]const u8 {
    var filled: usize = 0;
    while (filled < into.len) {
        const got = switch (sys.read(fd, into[filled..])) {
            .got => |count| count,
            .interrupted => continue,
            .again, .ended, .broke => return null,
        };

        const was = filled;
        filled += got;
        if (std.mem.indexOfScalar(u8, into[was..filled], '\n')) |at| return into[0 .. was + at];
    }
    return null;
}

fn writeAll(fd: i32, bytes: []const u8) bool {
    var sent: usize = 0;
    while (sent < bytes.len) {
        switch (sys.write(fd, bytes[sent..])) {
            .took => |count| sent += count,
            .interrupted => {},
            .again => if (!waitForRoom(fd)) return false,
            .broke => return false,
        }
    }
    return true;
}

const write_room_ms: i32 = 10_000;

fn waitForRoom(fd: i32) bool {
    var watching = [1]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.OUT,
        .revents = 0,
    }};
    const ready = std.posix.poll(&watching, write_room_ms) catch return false;
    return ready != 0;
}

fn dontWaitOn(fd: std.posix.fd_t) bool {
    return sys.waiting(fd, false);
}

fn millisecondsIn(nanoseconds: i96) i32 {
    const ms = @divFloor(nanoseconds, std.time.ns_per_ms);
    if (ms <= 0) return 1;
    if (ms > std.math.maxInt(i32)) return std.math.maxInt(i32);
    return @intCast(ms);
}

fn copyInto(into: []u8, from: []const u8) usize {
    const room = @min(into.len, from.len);
    @memcpy(into[0..room], from[0..room]);
    return room;
}

fn host(
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

    var sev_fd: ?i32 = if (comptime sev_possible) backend.kvm.Vm.openSev() else null;
    defer if (sev_fd) |fd| sys.close(fd);

    var sev: Sev = .off;
    var machine = made: {
        if (comptime sev_possible) {
            if (sev_fd != null) {
                if (Machine.createSev(gpa, options.cpus)) |encrypted| {
                    sev = .sev;
                    break :made encrypted;
                } else |_| {
                    sys.close(sev_fd.?);
                    sev_fd = null;
                }
            }
        }
        break :made Machine.create(gpa, options.cpus) catch {
            fault.* = .{ .said = "this machine would not make a guest" };
            return 1;
        };
    };
    defer machine.deinit();

    const ram_size = options.memory_mb * 1024 * 1024;

    const hole_base, const high_base = switch (builtin.cpu.arch) {
        .x86_64 => .{ mmio_hole_base, high_ram_base },
        else => .{ std.math.maxInt(u64), @as(u64, 0) },
    };
    var slots: [2]RamSlot = undefined;
    const slot_count = ramSlots(ram_base, ram_size, hole_base, high_base, &slots);

    var pages: ?[]align(std.heap.page_size_min) u8 = null;
    defer if (pages) |held| std.posix.munmap(held);
    var regions: [2]GuestMemory.Region = undefined;
    if (own_memory) {
        // One host block, mapped at the base. A macOS guest keeps its RAM below the
        // devices, so it never crosses the window and comes back as one slot.
        const room = std.posix.mmap(
            null,
            ram_size,
            .{ .READ = true, .WRITE = true },
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        ) catch {
            fault.* = .{ .said = "the guest's memory could not be set aside" };
            return 1;
        };
        pages = room;
        machine.map(room, slots[0].gpa) catch {
            fault.* = .{ .said = "this hypervisor would not take the guest's memory" };
            return 1;
        };
        regions[0] = .{ .gpa = slots[0].gpa, .len = slots[0].len, .backing = .{ .shared = room } };
    } else {
        for (slots[0..slot_count], 0..) |one, index| {
            regions[index] = machine.vm.addMemory(one.gpa, one.len, .shared) catch {
                fault.* = .{ .said = "this hypervisor would not take the guest's memory" };
                return 1;
            };
        }
    }
    var memory: GuestMemory = .{ .regions = regions[0..slot_count] };

    const hv = machine.backend();

    const id = try hv.addVcpu();
    const ids: []backend.Backend.VcpuId = if (own_cpus)
        &.{}
    else
        try gpa.alloc(backend.Backend.VcpuId, options.cpus - 1);
    defer if (!own_cpus) gpa.free(ids);
    if (!own_cpus) {
        for (ids) |*each| each.* = try hv.addVcpu();
    }

    var gic = if (own_controller)
        device.Gicv2{ .cpus = options.cpus }
    else
        try backend.platform.createController(&machine.vm, options.cpus);
    defer if (!own_controller) gic.deinit();

    var seed: [32]u8 = undefined;
    try io.randomSecure(&seed);

    var offered: fs_mod.Export = try fs_mod.Export.init(gpa, io);
    defer offered.deinit();
    for (options.shares) |each| {
        offered.offer(each.name, each.host_path, each.writable) catch {
            fault.* = .{ .said = "a directory could not be offered", .detail = each.name };
            return 1;
        };
    }

    var manifest: attest.Manifest = .{};
    defer manifest.deinit(gpa);

    var placing: arch.boot.Config = .{
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
    };
    if (own_controller) {
        placing.controller = .{ .gic_v2 = .{ .cpu_base = arch.fdt.gicv2_cpu_base } };
    }

    if (comptime sev_possible) {
        if (sev != .off) {
            placing.sev_c_bit = arch.platform.hostCBit();

            machine.vm.launchStart(sev_policy, sev_fd.?) catch {
                fault.* = .{ .said = "the guest's memory encryption would not start" };
                return 1;
            };
        }
    }

    const layout = try core.Launch.prepare(gpa, &memory, &manifest, placing);

    if (comptime sev_possible) {
        if (sev != .off) {
            var measured: [256]u8 = undefined;
            // The kernel, initrd, and page tables all sit in the low slot, so sealing
            // it covers the launch image. The relocated high slot starts empty.
            _ = machine.sevSeal(regions[0], &measured) catch {
                fault.* = .{ .said = "the guest's memory encryption would not seal" };
                return 1;
            };
        }
    }

    var serial: Serial = if (own_controller)
        .{ .sink = out, .line = .{ .controller = gic.controller(), .intid = arch.fdt.uart_intid } }
    else
        .{ .sink = out };

    var ports = [_]u32{ options.port, session_mod.wire.reaching_port };
    var channel: device.virtio.Vsock = undefined;
    channel.init(guest_cid, ports[0..2]);

    const share_asked = try gpa.alloc(u8, device.virtio.Fs.buffer_size);
    defer gpa.free(share_asked);
    const share_answered = try gpa.alloc(u8, device.virtio.Fs.buffer_size);
    defer gpa.free(share_answered);

    var shared_fs: device.virtio.Fs = undefined;
    shared_fs.init(fs_mod.Export.tag, .{ .ctx = &offered, .answer = answerFs }, share_asked, share_answered);

    var held = session_mod.Server.listen(options.session) catch {
        fault.* = .{ .said = "nothing can hold a session there", .detail = options.session };
        return 1;
    };
    var serving: Serving = .{ .offered = &offered, .granted = options.shares, .out = out };
    held.sharing = .{
        .ctx = &serving,
        .offer = offerShare,
        .withdraw = withdrawShare,
    };

    const platform = arch.platform;
    var attached: Devices = .{};

    var port_devices: [1]device.Device = undefined;
    var port_bus: ?device.Bus = null;
    if (serial_on_port) {
        port_devices[0] = serial.device(uart_base);
        port_bus = .{ .devices = &port_devices };
    } else {
        attached.add(serial.device(uart_base));
    }

    if (own_controller) {
        const halves = gic.devices(arch.fdt.gicd_base, arch.fdt.gicv2_cpu_base);
        attached.add(halves[0]);
        attached.add(halves[1]);
    }

    attached.addServed(shared_fs.device(platform.fs.addr), shared_fs.service(platform.fs.intid));
    attached.addServed(channel.device(platform.vsock.addr), channel.service(platform.vsock.intid));
    var bus = attached.bus();

    if (options.control < 0) {
        fault.* = .{ .said = "a guest is only run in a forked process, and this one has no control channel" };
        return 1;
    }

    if (!dontWaitOn(options.control)) {
        fault.* = .{ .said = "the control channel would not stop waiting" };
        return 1;
    }

    var layer: ?chock_sandbox.vm_confine.Layer = null;
    var diag: ?chock_sandbox.vm_confine.Diagnostic = null;
    chock_sandbox.vm_confine.install(gpa, options.shares, &layer, &diag) catch {
        fault.* = .{
            .said = "the host side of the guest's boundary would not install",
            .detail = refusalText(gpa, layer, diag),
        };
        return 1;
    };

    if (own_cpus) {
        try arch.boot.enter(Entering{ .hv = hv, .id = id }, layout);
    } else {
        try arch.boot.enter(&machine.vcpus[id], layout);
    }

    sayReady(options.control, sev);

    sys.armAlarmHandler();
    var ticking: std.atomic.Value(bool) = .init(false);
    var turns: std.atomic.Value(u64) = .init(0);
    const ticker = std.Thread.spawn(.{}, tickUntil, .{Ticker{
        .thread_id = sys.ownThread(),
        .group_id = sys.ownGroup(),
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
        .control = options.control,
        .turns = &turns,
    };

    const wanted: []Waiting = if (own_cpus) try gpa.alloc(Waiting, options.cpus) else &.{};
    defer if (own_cpus) gpa.free(wanted);
    var made: u32 = 1;
    var power: Power = .{};
    if (own_cpus) {
        for (wanted) |*one| one.* = .{};
        power = .{ .cpus = options.cpus, .made = &made, .wanted = wanted };
    }

    var shared: Shared = .{};
    const driving: core.Launch.Run = .{
        .bus = &bus,
        .memory = &memory,
        .controller = if (own_controller) gic.controller() else backend.platform.controllerLine(&gic),
        .services = attached.served(),
        .host = end.launchHost(),
        .guard = if (options.cpus > 1) shared.guard() else null,
        .ports = if (port_bus) |*one| one else null,
        .power = if (own_cpus) power.power() else null,
    };

    const others = try gpa.alloc(std.Thread, options.cpus - 1);
    defer gpa.free(others);
    const parked = try gpa.alloc(Parked, options.cpus - 1);
    defer gpa.free(parked);
    for (parked) |*one| one.* = .{};
    var started: usize = 0;
    defer for (others[0..started]) |each| each.join();
    defer wakeParked(parked[0..started], &ending);
    for (0..others.len) |index| {
        others[index] = if (own_cpus)
            std.Thread.spawn(.{}, driveParked, .{Parking{
                .hv = hv,
                .driving = driving,
                .mine = &parked[index],
                .ending = &ending,
                .wanted = wanted,
            }}) catch {
                fault.* = .{ .said = "a processor of the guest would not start" };
                return 1;
            }
        else
            std.Thread.spawn(
                .{},
                driveCpu,
                .{ hv, ids[index], driving, &parked[index], &ending },
            ) catch {
                fault.* = .{ .said = "a processor of the guest would not start" };
                return 1;
            };
        started += 1;
    }
    made = @intCast(1 + started);

    const reason = core.Launch.run(hv, id, driving) catch {
        held.lost(.faulted);
        held.close(&channel);
        out.flush() catch {};
        fault.* = .{ .said = "the guest stopped badly" };
        return 1;
    };

    if (Parked.failureIn(parked[0..started])) |err| {
        held.lost(.faulted);
        held.close(&channel);
        out.flush() catch {};
        fault.* = .{ .said = "a processor of the guest stopped badly", .detail = @errorName(err) };
        return 1;
    }

    held.lost(endingOf(reason, end.timed_out));
    held.close(&channel);
    out.flush() catch {};

    if (end.timed_out) {
        fault.* = .{ .said = "the guest ran out of the time it was given" };
        return 1;
    }
    return 0;
}

fn refusalText(
    allocator: std.mem.Allocator,
    layer: ?chock_sandbox.vm_confine.Layer,
    diag: ?chock_sandbox.vm_confine.Diagnostic,
) []const u8 {
    const named = @tagName(layer orelse .landlock);
    const said = diag orelse return named;
    return std.fmt.allocPrint(allocator, "{s}, {f}", .{ named, said }) catch named;
}

fn endingOf(reason: core.Launch.Reason, timed_out: bool) session_mod.wire.Reason {
    return switch (reason) {
        .shutdown => .powered_off,
        .reset => .restarted,
        .stopped => if (timed_out) .limit_reached else .was_asked,
    };
}

const Devices = struct {
    const room = 5;

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

const Pump = struct {
    io: std.Io,
    deadline: ?i96,
    vsock: *device.virtio.Vsock,
    session: *session_mod.Server,
    out: *std.Io.Writer,
    control: i32,
    ending: *std.atomic.Value(bool),
    timed_out: bool = false,
    turns: *std.atomic.Value(u64),

    fn launchHost(self: *Pump) core.Launch.Host {
        return .{ .ctx = self, .step = Pump.step };
    }

    fn step(ctx: *anyopaque) bool {
        const self: *Pump = @ptrCast(@alignCast(ctx));

        if (self.ending.load(.acquire)) return false;
        if (parentLetGo(self.control)) return false;

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

fn parentLetGo(control: i32) bool {
    var byte: [1]u8 = undefined;
    return switch (sys.read(control, &byte)) {
        .again, .interrupted, .got => false,
        .ended, .broke => true,
    };
}

fn answerFs(ctx: *anyopaque, request: []const u8, into: []u8) usize {
    const one: *fs_mod.Export = @ptrCast(@alignCast(ctx));
    return one.answer(request, into);
}

const Serving = struct {
    offered: *fs_mod.Export,
    granted: []const shares_mod.Share,
    out: *std.Io.Writer,

    fn covered(self: *const Serving, at: []const u8, writable: bool) bool {
        for (self.granted) |one| {
            if (!shares_mod.underneath(at, one.host_path)) continue;
            if (writable and !one.writable) continue;
            return true;
        }
        return false;
    }
};

fn offerShare(ctx: *anyopaque, name: []const u8, at: []const u8, writable: bool) bool {
    const self: *Serving = @ptrCast(@alignCast(ctx));
    if (!self.covered(at, writable)) {
        self.out.print(
            "chock vmm: {s} was not offered as {s}: this guest was granted no {s} access to " ++
                "it, and a grant cannot be widened once the guest is running\n",
            .{ at, name, if (writable) "writable" else "read" },
        ) catch {};
        self.out.flush() catch {};
        return false;
    }
    self.offered.offer(name, at, writable) catch |err| {
        self.out.print(
            "chock vmm: {s} was not offered as {s}: {t}. This guest was granted {d} " ++
                "directories and takes {d} offers in all\n",
            .{ at, name, err, self.granted.len, fs_mod.Export.max_offers },
        ) catch {};
        self.out.flush() catch {};
        return false;
    };
    return true;
}

fn withdrawShare(ctx: *anyopaque, name: []const u8) void {
    const self: *Serving = @ptrCast(@alignCast(ctx));
    self.offered.withdraw(name);
}

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

fn driveCpu(
    hv: backend.Backend,
    id: backend.Backend.VcpuId,
    driving: core.Launch.Run,
    mine: *Parked,
    ending: *std.atomic.Value(bool),
) void {
    mine.thread_id.store(sys.ownThread(), .release);
    defer mine.ended.store(true, .release);
    _ = core.Launch.run(hv, id, driving) catch |err| {
        mine.failure.store(@intFromError(err), .release);
        ending.store(true, .release);
    };
}

const Entering = struct {
    hv: backend.Backend,
    id: backend.Backend.VcpuId,

    pub fn setRegister(self: Entering, reg: backend.Backend.Register, value: u64) !void {
        try self.hv.setRegister(self.id, reg, value);
    }
};

const Waiting = struct {
    asked: std.atomic.Value(bool) = .init(false),
    entry: u64 = 0,
    context: u64 = 0,
};

const Power = struct {
    cpus: u32 = 0,
    made: *const u32 = undefined,
    wanted: []Waiting = &.{},

    fn start(ctx: *anyopaque, target: u64, entry: u64, context: u64) bool {
        if (own_cpus) {
            const self: *Power = @ptrCast(@alignCast(ctx));
            for (0..@min(self.cpus, self.wanted.len)) |index| {
                if (arch.fdt.affinity(@intCast(index)) != target) continue;
                if (index == 0 or index >= self.made.*) return false;
                if (self.wanted[index].asked.load(.acquire)) return false;

                self.wanted[index].entry = entry;
                self.wanted[index].context = context;
                self.wanted[index].asked.store(true, .release);
                return true;
            }
        }
        return false;
    }

    fn power(self: *Power) core.Launch.Power {
        return .{ .ctx = self, .start = Power.start };
    }
};

const Parking = struct {
    hv: backend.Backend,
    driving: core.Launch.Run,
    mine: *Parked,
    ending: *std.atomic.Value(bool),
    wanted: []Waiting,
};

fn driveParked(given: Parking) void {
    if (own_cpus) {
        given.mine.thread_id.store(sys.ownThread(), .release);
        defer given.mine.ended.store(true, .release);

        const id = given.hv.addVcpu() catch |err| {
            given.mine.failure.store(@intFromError(err), .release);
            given.ending.store(true, .release);
            return;
        };
        if (id >= given.wanted.len) return;

        while (!given.wanted[id].asked.load(.acquire)) {
            if (given.ending.load(.acquire)) return;
            std.Thread.yield() catch {};
        }
        if (given.ending.load(.acquire)) return;

        given.hv.setRegister(id, .pc, given.wanted[id].entry) catch return;
        given.hv.setRegister(id, .x0, given.wanted[id].context) catch return;
        given.hv.setRegister(id, .x1, 0) catch return;
        given.hv.setRegister(id, .x2, 0) catch return;
        given.hv.setRegister(id, .x3, 0) catch return;

        _ = core.Launch.run(given.hv, id, given.driving) catch |err| {
            given.mine.failure.store(@intFromError(err), .release);
            given.ending.store(true, .release);
        };
    }
}

const Parked = struct {
    thread_id: std.atomic.Value(sys.Thread) = .init(sys.no_thread),
    ended: std.atomic.Value(bool) = .init(false),
    failure: std.atomic.Value(u16) = .init(0),

    fn failureIn(parked: []const Parked) ?anyerror {
        for (parked) |*one| {
            const code = one.failure.load(.acquire);
            if (code != 0) return @errorFromInt(code);
        }
        return null;
    }
};

fn wakeParked(parked: []Parked, ending: *std.atomic.Value(bool)) void {
    ending.store(true, .release);
    const group = sys.ownGroup();
    var rounds: usize = 0;
    while (rounds < wake_rounds) : (rounds += 1) {
        var left: usize = 0;
        for (parked) |*one| {
            if (one.ended.load(.acquire)) continue;
            left += 1;
            const which = one.thread_id.load(.acquire);
            if (which != sys.no_thread) sys.alarmThread(group, which);
        }
        if (left == 0) return;
        sys.sleepMs(wake_step_ms);
    }
}

const wake_rounds: usize = 2000;
const wake_step_ms: u64 = 1;

const Ticker = struct {
    thread_id: sys.Thread,
    group_id: std.posix.pid_t,
    every_ms: u64,
    done: *std.atomic.Value(bool),
    turns: *std.atomic.Value(u64),
};

fn tickUntil(ticker: Ticker) void {
    var last: u64 = 0;
    while (!ticker.done.load(.acquire)) {
        sys.sleepMs(ticker.every_ms);

        const now = ticker.turns.load(.acquire);
        if (now != last) {
            last = now;
            continue;
        }
        sys.alarmThread(ticker.group_id, ticker.thread_id);
    }
}

pub const Attached = struct {
    control: std.posix.fd_t,
    stream: std.posix.fd_t,
};

pub const AttachError = error{
    NoGuest,
    ShareRefused,
    NoStream,
};

fn waitOnStream(fd: std.posix.fd_t) void {
    _ = sys.waiting(fd, true);
}

pub const Reached = union(enum) {
    connected: std.posix.fd_t,
    refused,
};

pub const Reaches = struct {
    ptr: *anyopaque,
    decide: *const fn (ptr: *anyopaque, text: []const u8, port: u16) Reached,
};

const reaching_wait_ms: i32 = 100;

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
    sys.close(fd);
}

pub fn attach(
    io: std.Io,
    socket_path: []const u8,
    shares: []const shares_mod.Share,
    port: u32,
    refused: ?*?shares_mod.Share,
) AttachError!Attached {
    _ = io;

    const control = session_mod.socket.reach(socket_path) catch return error.NoGuest;
    var client = session_mod.Client.adopt(control);
    errdefer client.stop();

    try handshake(&client, shares, refused);

    const stream = client.channel(port) catch return error.NoStream;

    waitOnStream(stream);

    return .{ .control = control, .stream = stream };
}

fn handshake(
    client: *session_mod.Client,
    shares: []const shares_mod.Share,
    refused: ?*?shares_mod.Share,
) AttachError!void {
    if (!try upWithin(client, attach_wait_ms)) return error.NoStream;

    for (shares) |one| {
        client.share(one.name, one.host_path, one.writable) catch {
            if (refused) |slot| slot.* = one;
            return error.ShareRefused;
        };
    }
}

fn upWithin(client: *session_mod.Client, limit_ms: u64) AttachError!bool {
    var waited: u64 = 0;
    while (waited < limit_ms) : (waited += attach_look_ms) {
        while (client.take() catch return error.NoGuest) |said| switch (said) {
            .up => return true,
            .lost => return false,
            .reaching, .other => {},
        };

        sys.sleepMs(attach_look_ms);
    }
    return false;
}

const attach_wait_ms: u64 = 30 * std.time.ms_per_s;
const attach_look_ms: u64 = 100;

const testing = std.testing;

test "guest ram that crosses the device window splits, leaving it clear" {
    var slots: [2]RamSlot = undefined;
    const count = ramSlots(0, 16 * 1024 * 1024 * 1024, 0xd000_0000, 0x1_0000_0000, &slots);

    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqual(@as(u64, 0), slots[0].gpa);
    try testing.expectEqual(@as(u64, 0xd000_0000), slots[0].len);
    try testing.expectEqual(@as(u64, 0x1_0000_0000), slots[1].gpa);
    // The total is kept: the part above the window moves, none is lost.
    try testing.expectEqual(16 * 1024 * 1024 * 1024, slots[0].len + slots[1].len);
    for (slots[0..count]) |one| {
        const stop = one.gpa + one.len;
        try testing.expect(stop <= 0xd000_0000 or one.gpa >= 0x1_0000_0000);
    }
}

test "guest ram below the device window stays one slot" {
    var slots: [2]RamSlot = undefined;
    const count = ramSlots(0, 512 * 1024 * 1024, 0xd000_0000, 0x1_0000_0000, &slots);

    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqual(@as(u64, 0), slots[0].gpa);
    try testing.expectEqual(@as(u64, 512 * 1024 * 1024), slots[0].len);
}

test "a target with no device window keeps one slot above its devices" {
    var slots: [2]RamSlot = undefined;
    const count = ramSlots(0x4000_0000, 16 * 1024 * 1024 * 1024, std.math.maxInt(u64), 0, &slots);

    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqual(@as(u64, 0x4000_0000), slots[0].gpa);
}

const Greeting = struct {
    path: []const u8,
    done: std.atomic.Value(bool) = .init(false),
    failure: ?anyerror = null,
    offered: bool = false,

    fn run(self: *Greeting) void {
        defer self.done.store(true, .release);

        const control = session_mod.socket.reach(self.path) catch |err| {
            self.failure = err;
            return;
        };
        defer session_mod.socket.close(control);

        var client = session_mod.Client.adopt(control);
        const offering = [_]shares_mod.Share{
            .{ .name = "work", .host_path = "/tmp", .writable = false },
        };
        handshake(&client, &offering, null) catch |err| {
            self.failure = err;
            return;
        };
        self.offered = true;
    }
};

fn takeAnything(ctx: *anyopaque, name: []const u8, at: []const u8, writable: bool) bool {
    _ = .{ ctx, name, at, writable };
    return true;
}

fn dropAnything(ctx: *anyopaque, name: []const u8) void {
    _ = .{ ctx, name };
}

test "a guest already up is still reached once its directories are offered" {
    var name: [96]u8 = undefined;
    const path = try std.fmt.bufPrint(&name, "/tmp/chock-vmm-up-{d}.sock", .{sys.ownGroup()});

    var channel: device.virtio.Vsock = undefined;
    const ports = [_]u32{1024};
    channel.init(3, ports[0..]);

    var held = try session_mod.Server.listen(path);
    defer held.close(&channel);
    held.guest_up = true;
    var nothing: u8 = 0;
    held.sharing = .{ .ctx = &nothing, .offer = takeAnything, .withdraw = dropAnything };

    var session: Greeting = .{ .path = path };
    const thread = try std.Thread.spawn(.{}, Greeting.run, .{&session});

    var turns: usize = 0;
    while (turns < 5000 and !session.done.load(.acquire)) : (turns += 1) {
        held.pump(&channel);
        sys.sleepMs(1);
    }
    thread.join();

    try testing.expectEqual(@as(?anyerror, null), session.failure);
    try testing.expect(session.offered);
}

test "a processor that stopped badly is the one read back, and zero means none" {
    var parked: [3]Parked = .{ .{}, .{}, .{} };
    try std.testing.expectEqual(@as(?anyerror, null), Parked.failureIn(&parked));

    parked[1].failure.store(@intFromError(error.OutOfMemory), .release);
    try std.testing.expectEqual(@as(?anyerror, error.OutOfMemory), Parked.failureIn(&parked));
}

test "the share set crosses the control channel and comes back as the same set" {
    const allocator = std.testing.allocator;
    const sent = [_]shares_mod.Share{
        .{ .name = "store", .host_path = "/nix/store", .writable = false },
        .{ .name = "work", .host_path = "/tmp/w", .writable = true },
    };

    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(allocator);
    try writeShares(allocator, &line, &sent);

    const read_back = try readShares(allocator, line.items);
    defer freeShares(allocator, read_back);

    try std.testing.expectEqual(sent.len, read_back.len);
    for (sent, read_back) |want, got| {
        try std.testing.expectEqualStrings(want.name, got.name);
        try std.testing.expectEqualStrings(want.host_path, got.host_path);
        try std.testing.expectEqual(want.writable, got.writable);
    }
}

test "a line arriving in pieces is still read as one line" {
    var pair: [2]i32 = undefined;
    try testing.expect(sys.channelPair(&pair));
    defer sys.close(pair[0]);

    try testing.expect(writeAll(pair[0], "{\"sha"));
    const rest = try std.Thread.spawn(.{}, sendRest, .{ pair[0], "res\":[]}\n" });
    defer rest.join();

    var room: [64]u8 = undefined;
    const taken = readLineInto(pair[1], &room) orelse return error.TestUnexpectedResult;
    sys.close(pair[1]);
    try testing.expectEqualStrings("{\"shares\":[]}", taken);
}

fn sendRest(fd: i32, bytes: []const u8) void {
    sys.sleepMs(20);
    _ = writeAll(fd, bytes);
}

test "a channel that ends before a line reads as no line" {
    var pair: [2]i32 = undefined;
    try testing.expect(sys.channelPair(&pair));
    defer sys.close(pair[1]);

    sys.close(pair[0]);
    var room: [64]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), readLineInto(pair[1], &room));
}

test "a parent that closed its half is the only thing that asks for the end" {
    var pair: [2]i32 = undefined;
    try testing.expect(sys.channelPair(&pair));
    try testing.expect(dontWaitOn(pair[1]));

    try testing.expect(!parentLetGo(pair[1]));

    sys.close(pair[0]);
    try testing.expect(parentLetGo(pair[1]));
    sys.close(pair[1]);
}

test "a signalled child reads as signalled, and one that will not stop is killed" {
    {
        const rc = sys.forkNow() orelse return error.TestUnexpectedResult;
        if (rc == 0) {
            sys.killNow(sys.ownGroup());
            std.process.exit(0);
        }

        var child: Child = .{ .pid = rc, .control = -1 };
        try testing.expectEqual(@as(u8, 128 + 9), child.wait());
    }

    {
        const rc = sys.forkNow() orelse return error.TestUnexpectedResult;
        if (rc == 0) {
            while (true) sys.sleepMs(1000);
        }

        var child: Child = .{ .pid = rc, .control = -1 };
        try testing.expectEqual(@as(u8, 128 + 9), child.wait());
    }
}

test "the ready line carries which memory encryption the guest came up under" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    for ([_]Sev{ .off, .sev }) |said| {
        var pair: [2]i32 = undefined;
        try testing.expect(sys.channelPair(&pair));
        defer sys.close(pair[0]);
        defer sys.close(pair[1]);

        sayReady(pair[1], said);
        var child: Child = .{ .pid = 0, .control = pair[0] };
        try child.waitReady(io, 1000);
        try testing.expectEqual(said, child.sev);
    }

    {
        var pair: [2]i32 = undefined;
        try testing.expect(sys.channelPair(&pair));
        defer sys.close(pair[0]);
        defer sys.close(pair[1]);

        _ = writeAll(pair[1], "{\"ready\":true}\n");
        var child: Child = .{ .pid = 0, .control = pair[0], .sev = .sev };
        try child.waitReady(io, 1000);
        try testing.expectEqual(Sev.off, child.sev);
    }

    try testing.expectEqual(Sev.off, Sev.fromText("sev_snp"));
    try testing.expectEqual(Sev.off, Sev.fromText(""));
}

test "the child's ready line is what a parent waits on, and its fault is what it reads" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    {
        var pair: [2]i32 = undefined;
        try testing.expect(sys.channelPair(&pair));
        defer sys.close(pair[0]);
        defer sys.close(pair[1]);

        sayReady(pair[1], .off);
        var child: Child = .{ .pid = 0, .control = pair[0] };
        try child.waitReady(io, 1000);
        try testing.expectEqual(@as(?Fault, null), child.fault());
    }

    {
        var pair: [2]i32 = undefined;
        try testing.expect(sys.channelPair(&pair));
        defer sys.close(pair[0]);
        defer sys.close(pair[1]);

        sayFault(pair[1], "the kernel could not be read", "/no/such/Image");
        var child: Child = .{ .pid = 0, .control = pair[0] };
        try testing.expectError(error.GuestRefused, child.waitReady(io, 1000));
        const said = child.fault() orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings("the kernel could not be read", said.said);
        try testing.expectEqualStrings("/no/such/Image", said.detail);
    }

    {
        var pair: [2]i32 = undefined;
        try testing.expect(sys.channelPair(&pair));
        defer sys.close(pair[0]);

        sys.close(pair[1]);
        var child: Child = .{ .pid = 0, .control = pair[0] };
        try testing.expectError(error.GuestGone, child.waitReady(io, 1000));
    }
}

test "a child that says nothing inside the limit is slow and not gone" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();

    var pair: [2]i32 = undefined;
    try testing.expect(sys.channelPair(&pair));
    defer sys.close(pair[0]);
    defer sys.close(pair[1]);

    var child: Child = .{ .pid = 0, .control = pair[0] };
    try testing.expectError(error.GuestSlow, child.waitReady(threaded.io(), 20));
}

test "a refusal names the layer and what the kernel answered" {
    const allocator = std.testing.allocator;
    const named = @tagName(chock_sandbox.vm_confine.Layer.landlock);
    const both = refusalText(allocator, .landlock, .{ .landlock = .{ .call = .add_rule, .errno = .NOENT } });
    defer if (both.ptr != named.ptr) allocator.free(both);
    try testing.expect(std.mem.indexOf(u8, both, "landlock") != null);
    try testing.expect(std.mem.indexOf(u8, both, "add_rule") != null);
    try testing.expect(std.mem.indexOf(u8, both, "NOENT") != null);

    try testing.expectEqualStrings("seccomp", refusalText(allocator, .seccomp, null));
}

test "the places a guest is put are the architecture's own, and no two share one" {
    try testing.expectEqual(
        @as(u64, switch (builtin.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 0x4000_0000,
            else => @compileError("a guest is only placed for x86_64 and aarch64"),
        }),
        ram_base,
    );
    const platform = arch.platform;
    try testing.expectEqual(platform.serial.addr, uart_base);

    try testing.expect(platform.vsock.addr != platform.fs.addr);
    try testing.expect(platform.vsock.intid != platform.fs.intid);
    try testing.expect(platform.serial.addr != platform.fs.addr);
    try testing.expect(platform.serial.addr != platform.vsock.addr);
}

test "the default cmdline names the console this architecture has" {
    const expected = if (serial_on_port) "console=ttyS0" else "console=ttyAMA0";
    const default: Options = .{ .control = -1 };
    try testing.expect(std.mem.startsWith(u8, default.cmdline, expected));
}
