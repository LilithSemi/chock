//! One microVM guest, in a forked process of its own.
//!
//! **A process and not a thread, because of what the boundary is made of.** A
//! seccomp filter and a Landlock domain go on a whole process and cannot be taken
//! off again, so a guest hosted on a thread of the harness could only be confined
//! by confining the harness with it. `forkHost` makes the process, `childMain`
//! runs it, and `chock_sandbox.vm_confine` is what goes on inside.
//!
//! **`forkHost` is the only way in.** Both `chock run` and `chock daemon` call it,
//! and the function that runs the machine is private to this file, so there is no
//! longer an entry point that boots a guest on a thread of its caller. It also
//! refuses a control channel it was not given, so an unconfined guest is not a
//! branch somebody can reach by leaving a field out.
//!
//! **Two hypervisors, one setup.** KVM on Linux and Hypervisor.framework on
//! macOS. The guest, the devices and the loop are the same; what differs is the
//! three things Apple's hypervisor does not do for itself, each named below as
//! `own_memory`, `own_cpus` and `own_controller`. The calls that are not
//! `std.posix`'s are in `src/vmm_sys.zig`.
//!
//! **This is a copy of Mirage's own machine setup, and that is a cost taken
//! deliberately.** Mirage's `src/linux.zig` holds a 718 line `run` that nothing in
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
//! thing to keep in step. What a Mirage upgrade can still change is what a
//! declaration does behind a name that did not change, so an upgrade is read
//! rather than only built.
//!
//! ## What holds the guest up
//!
//! `Options.session` names a socket, bound before the guest runs and reported on
//! the control channel, so the caller waits on a message rather than polling a
//! directory for a file to appear. A `chock run` child connects to that socket.
//!
//! ## The control channel
//!
//! A forked process shares no memory with its parent, so every answer between the
//! two crosses one socketpair: `sendShares` writes the share set down it,
//! `sayReady` answers on it, and the parent asks for the end by closing its half,
//! which the loop reads as a channel at its end. One descriptor carries all
//! three, and a parent that died carries the last of them by itself.
//!
//! ## The tick, and why it is a thread and not a timer
//!
//! A guest blocked on its channel exits for nothing, so without an interruption
//! the host loop only runs when the guest exits of its own accord and a waiting
//! guest waits for ever. Mirage arms a process wide `setitimer`, and this process
//! holds more than the guest's own processor: the virtiofs thread and the session
//! thread are here too, and a timer aimed at the process would have every read of
//! theirs answer `EINTR`.
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

/// The calls this file makes that `std.posix` has not got, on whichever platform
/// it is built for. See its own top comment.
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

/// True here and false in `src/vmm_absent.zig`.
pub const available = true;

/// Where the guest's memory starts, and where its console is. Both are the
/// architecture's own: a guest placed anywhere else is a guest whose device tree
/// says one thing and whose memory is somewhere else.
///
/// An x86 guest reaches long mode through structures in the first megabytes and
/// identity maps physical memory from zero, so its RAM starts at zero. An arm guest
/// is placed above the window its devices sit in. Mirage's `src/host.zig` makes the
/// same choice, and the two must agree.
///
/// **An architecture nobody has placed a guest for is refused, not given arm64's
/// layout.** An `else` here was safe only while the build gate named one
/// architecture. Mirage's own build refuses the same way.
const ram_base: u64 = switch (builtin.cpu.arch) {
    .x86_64 => 0,
    .aarch64 => 0x4000_0000,
    else => @compileError("a guest is only placed for x86_64 and aarch64"),
};

/// Where the guest finds its console: a guest physical address on arm, an I/O port
/// on x86.
const uart_base = arch.platform.serial.addr;

/// Whether the console is reached through an I/O port rather than memory. A port
/// needs a bus of its own, because a memory bus still answers an access that
/// matched nothing on it.
const serial_on_port = arch.platform.serial_is_port;

/// A 16550 behind an I/O port on x86, a memory mapped PL011 on arm. Mirage's own
/// runner picks between the two the same way.
const Serial = if (serial_on_port) device.Uart16550 else device.Pl011;

/// The machine, from whichever hypervisor this build sits on.
const Machine = if (builtin.os.tag == .macos) backend.hvf.Machine else backend.kvm.Machine;

/// **The three things Hypervisor.framework does not do that KVM does.** KVM
/// makes the guest's memory, starts the processors the guest asks for, and holds
/// the interrupt controller in the kernel. Apple's hypervisor does none of them,
/// so each one is done here instead, and the guest cannot tell the difference.
///
/// They are three names and not one because they are three separate pieces of
/// work. Mirage's own `src/darwin.zig` is where the shape of each comes from.
const own_memory = builtin.os.tag == .macos;
const own_cpus = builtin.os.tag == .macos;
const own_controller = builtin.os.tag == .macos;

/// Whether this build reaches the calls that drive AMD memory encryption. SEV is
/// x86's and KVM's, so no other target compiles them at all.
const sev_possible = builtin.os.tag == .linux and builtin.cpu.arch == .x86_64;

/// The launch policy a guest of Chock's is given. Zero refuses guest debugging
/// and key sharing, which is what a tool call wants: a policy that allowed
/// debugging would let whoever holds the host read the guest it protects.
const sev_policy: u32 = 0;

/// Whether the guest's memory is encrypted by the processor, and under which
/// feature.
///
/// **Off is the ordinary answer and not a failure.** The launch commands issue
/// through `/dev/sev`, which usually only root may open, so a guest on a machine
/// with no SEV, no permission, or no AMD processor runs in the clear. What is not
/// allowed is running in the clear once encryption has started: see `startSev`.
pub const Sev = enum {
    off,
    /// Guest memory is encrypted. Register state on an exit is not.
    sev,

    /// The word that goes on the wire and into a log.
    pub fn text(self: Sev) []const u8 {
        return switch (self) {
            .off => "off",
            .sev => "sev",
        };
    }

    /// The state a word on the wire names, or `.off` for anything this build
    /// does not know. **An unreadable word is never reported as encryption.**
    pub fn fromText(said: []const u8) Sev {
        if (std.mem.eql(u8, said, "sev")) return .sev;
        return .off;
    }
};

/// The guest's address on the channel. Whoever started it is always at 2.
const guest_cid = 3;

/// How often the host takes the CPU back. A guest blocked on the channel exits for
/// nothing, so without this the loop below only runs when the guest exits of its
/// own accord and a waiting guest waits for ever.
const default_tick_ms: u64 = 10;

/// The most of a kernel or an initrd that is read. A guest image past this is a
/// caller naming the wrong file.
const file_limit: std.Io.Limit = .limited(512 * 1024 * 1024);

/// What a guest is told when nobody says otherwise. The console's name follows the
/// architecture, and `pkgs/chock/guest.nix` builds the images that match.
const default_cmdline: []const u8 = if (serial_on_port)
    "console=ttyS0 loglevel=7 init=/init"
else
    "console=ttyAMA0 loglevel=7 init=/init";

pub const Options = struct {
    kernel: []const u8 = "",
    initrd: ?[]const u8 = null,
    /// **`loglevel=7`, because a guest that faults says so at `KERN_INFO`.** The
    /// default console level is lower, so an unhandled fault in a tool call was
    /// printed by the kernel and never reached the console file, which left a
    /// signal number with nothing behind it.
    /// The console's name is the architecture's: a kernel told to print to a port
    /// it has not got prints nowhere.
    cmdline: []const u8 = default_cmdline,
    memory_mb: u64 = 512,
    /// How many processors the guest gets. **Chosen by `chock-policy`**, which
    /// holds the curve and what a machine may spare: see `sandbox.coresOn`.
    cpus: u32 = 1,
    /// Where the socket that holds this guest up goes. Required: a guest nobody
    /// holds is a guest Chock has no use for.
    session: []const u8 = "",
    /// The port the guest opens its own stream to. `chock guest` dials this.
    port: u32 = 1024,
    /// Directories the guest may mount, each under the name it sees. **This is
    /// also the whole of the Landlock grant** the process running the guest gets,
    /// so a directory left out of it is one the host side cannot name either.
    shares: []const Share = &.{},
    /// Give up after this long. Null runs until the guest stops.
    seconds: ?u64 = null,
    /// The channel back to whoever forked this process. A caller of `forkHost`
    /// writes `fork_sets_control`, which `childMain` replaces with the child's own
    /// half: nothing before the fork can name a descriptor the fork has not made
    /// yet.
    ///
    /// **No default, and a guest refuses to boot without it.** The default would
    /// have been -1, and -1 once meant a caller that hosted the guest on a thread
    /// and was not confined. There is no such caller now, so the omission is a
    /// build error and a -1 that reached the machine anyway is a refusal.
    control: i32,

    /// The same shape `chock-sandbox` states, so the set offered to the guest and
    /// the set the Landlock grant is built from are one list and never two.
    pub const Share = shares_mod.Share;
};

/// Whether `path` is `root` itself or something under it, which is what makes one
/// share cover another. `chock-sandbox`'s own answer, so a caller deciding what to
/// grant and the grant itself read a path the same way.
pub const shareCovers = shares_mod.underneath;

/// A share name for `path` that no entry of `taken` holds. `chock-sandbox`'s own
/// naming, so a directory offered twice arrives under one name and replaces its
/// earlier offer rather than taking a second slot.
pub const shareNameFor = shares_mod.nameFor;

/// What a caller of `forkHost` writes for `Options.control`. The child's own half
/// of the channel is made by the fork, so nothing before it can name a descriptor:
/// this is replaced, and it is never the value a guest runs with.
pub const fork_sets_control: i32 = -1;

pub const Fault = struct {
    said: []const u8,
    /// The path or name the fault is about, borrowed from `options`.
    detail: []const u8 = "",
};

/// What the parent sends down the control channel, and the child reads at the
/// seam. **One message and one direction**: the share set, which is the only
/// thing the child cannot work out for itself and the only thing its Landlock
/// grant is built from.
const SharesLine = struct {
    shares: []const shares_mod.Share,
};

/// What the child sends back once its socket is bound, or instead of that.
const ReadyLine = struct {
    ready: bool = false,
    said: []const u8 = "",
    detail: []const u8 = "",
    /// Which memory encryption the guest came up under, as `Sev.text` writes it.
    /// Absent from an older child's line, which reads back as `.off`.
    sev: []const u8 = "",
};

/// The most of one fault's words this channel carries. **A longer `detail` loses
/// its tail.** A path may be `std.fs.max_path_bytes`, which is four times this,
/// and a channel sized for two fields that long escaped to their worst case would
/// be 48K of the parent's stack for a line a person reads. A kernel or an initrd
/// path is far shorter than this.
const fault_text_bytes: usize = 1024;

/// The room a fault line is given. A byte of text can take six inside a JSON
/// string, so this holds both fields escaped to their worst case.
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

/// The share set a line holds. The caller owns it and frees it with `freeShares`.
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
    /// The control channel could not be made, so there would be no way to send
    /// the share set or to ask for the end.
    NoChannel,
    /// This process would not fork.
    NoFork,
    /// **Never answered here.** It is what `src/vmm_absent.zig` answers, and the
    /// member is shared so a caller writes one switch for both builds.
    NoGuest,
};

pub const SendError = error{
    /// The share set could not be held long enough to write.
    OutOfMemory,
    /// The channel would not take it, so the child is already gone.
    Broke,
};

pub const ReadyError = error{
    /// The child said it would not come up. `Child.fault` says what it said.
    GuestRefused,
    /// The channel ended before the child said anything, so it died.
    GuestGone,
    /// Nothing arrived inside the limit.
    GuestSlow,
};

/// One forked guest, from the side that forked it.
///
/// The caller ends it with `stop` and then `wait`. **Nothing here reads the
/// guest's console**: the descriptor given to `forkHost` is where that goes, and
/// it is the caller's to open and to read.
pub const Child = struct {
    pid: std.posix.pid_t,
    /// The parent's half of the channel. Closing it is how the guest is asked to
    /// stop, so `stop` sets this to -1 rather than closing twice.
    control: i32,
    /// What the child said when it would not come up, copied in because the line
    /// it arrived on does not outlive the read. `fault` reads it back.
    said: [fault_text_bytes]u8 = undefined,
    said_len: usize = 0,
    detail: [fault_text_bytes]u8 = undefined,
    detail_len: usize = 0,
    /// Which memory encryption the guest came up under. Read after `waitReady`
    /// answers, and `.off` until then.
    sev: Sev = .off,

    /// Send the one message this channel carries: the directories the guest may
    /// mount, which is also the whole of its host side's Landlock grant.
    ///
    /// **Added to what the fork inherited, not put in its place.** A caller that
    /// had its set before the fork leaves it in `Options.shares` and sends none.
    /// A caller whose set only exists later sends it here. Naming one directory
    /// twice is a refusal the guest makes, not a merge this does.
    ///
    /// Send it once. The child reads exactly one line and then waits for nothing
    /// but the end.
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

    /// Wait for the child to say its session socket is bound.
    ///
    /// **It may read past the newline, and throws away what it read.** The child
    /// sends one line and then only ever closes, so there is nothing after the
    /// line to lose. `readLineInto` has the same hazard in the other direction and
    /// says so there.
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
            // A line that filled the room is a child saying something this
            // protocol has no shape for, which is not a child that came up.
            // `note` first, because `GuestRefused` promises `fault` says why.
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

    /// Why the child would not come up, in its own words, or null.
    pub fn fault(self: *Child) ?Fault {
        if (self.said_len == 0) return null;
        return .{
            .said = self.said[0..self.said_len],
            .detail = self.detail[0..self.detail_len],
        };
    }

    /// Ask the guest to stop, by closing the half the parent holds. The child's
    /// own loop reads that as a channel at its end: see `Pump.step`.
    pub fn stop(self: *Child) void {
        if (self.control >= 0) {
            sys.close(self.control);
            self.control = -1;
        }
    }

    /// Reap the child and answer what it exited with.
    ///
    /// **Bounded, because `stop` is a request and not a kill.** A guest wedged
    /// inside its own loop never reads the closed channel, and an unbounded wait
    /// here would hold the daemon at the end of every such session. So this waits
    /// `stop_grace_ms` for the guest to go of its own accord, then kills it.
    ///
    /// **A signalled child answers `128` plus the signal**, the shell's own
    /// convention, so a guest that `PR_SET_PDEATHSIG` or the kill below ended is
    /// not read as a guest that refused to come up and exited 1.
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

/// How long `wait` gives a guest to end after its channel closed, and how often
/// it looks. A guest that has not gone by then is not going to.
const stop_grace_ms: u64 = 5000;
const stop_look_ms: u64 = 5;

/// Run a guest in a process of its own, confined. The caller owns the result and
/// ends it with `stop` and then `wait`.
///
/// **The child inherits the caller's address space, so call this before the caller
/// has read a credential.** A fork placed between reading `.sandbox` and reading
/// the provider configuration is what keeps a token out of the process this one
/// confines. A fork after it copies one in.
///
/// **Call it from a thread that outlives the guest.** `PR_SET_PDEATHSIG` fires
/// when the thread that forked ends, not when its process does, so a guest forked
/// on a thread that finishes first is killed with it. macOS has no such flag, and
/// the control channel is what covers it there: see `sys.endWithParent`.
///
/// `console_fd` is where the guest's own console goes. It is a descriptor and not
/// a path because the confined child cannot open one: the console file is not in
/// the share set, and nothing says it should be. **It and the channel are the only
/// two descriptors the child keeps**: see the close in the child below.
pub fn forkHost(io: std.Io, options: Options, console_fd: std.posix.fd_t) ForkError!Child {
    // **Close on exec, on both halves.** The parent asks for the end by closing
    // its half, and a copy of it left in anything the parent later executes would
    // hold the channel open and the guest would never be asked.
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
    // A parent that dies must not leave a guest holding a kernel's worth of
    // memory and an open handle on the workspace.
    sys.endWithParent();

    // **`fork` copies the whole descriptor table, and `CLOEXEC` bears on an exec
    // this child never does.** So without this the guest process holds the session
    // log, the provider socket, the daemon's listener and the terminal. Landlock
    // covers no descriptor that was already open and `vmm_calls` allows `read`,
    // `write` and `sendmsg`, so an escape through a guest-written virtio ring
    // would reach every one of them. An open socket to the provider is a
    // credential by another name.
    chock_sandbox.after_fork.keepOnlyDescriptors(&.{ console_fd, pair[1] });

    // **Descriptors 0, 1 and 2 are filled in again, because the close above left
    // them free.** The next file the filesystem server opens would land on one of
    // them, and a panic in this process writes its message to descriptor 2: that
    // message would go into a guest's own file. The console is where everything
    // else this process says already goes.
    for ([_]i32{ 0, 1, 2 }) |slot| {
        if (slot == console_fd or slot == pair[1]) continue;
        sys.dupOnto(console_fd, slot);
    }

    // **Nothing of the parent's answer to a signal belongs here.** `chock run`
    // installs a handler that writes terminal escape sequences and then re-raises,
    // which is the harness's answer to Ctrl-C and not a guest's.
    chock_sandbox.after_fork.resetSignalState();

    // **The reset above cannot simply be dropped here: it also undoes the
    // ignore `std.Io.Threaded.init` put on `PIPE` and `IO`, and nothing puts it
    // back.** Without this, a write to a peer that hung up, the console or the
    // session socket, kills this process by signal instead of returning
    // `EPIPE` to the caller.
    sys.ignoreWriteSignals();

    // **A session of its own, so one Ctrl-C at the terminal does not take the
    // guest with it.** A terminal signals its whole foreground process group, and
    // a guest killed under a session the harness means to keep fails every tool
    // call after it. The parent asks this guest to stop by closing the channel and
    // in no other way.
    sys.ownSession();

    std.process.exit(childMain(io, options, console_fd, pair[1]));
}

/// The whole of what a forked guest process does.
///
/// **The share set it reads is never freed.** The process exits with what this
/// answers, and `host` holds that set for as long as the guest runs.
///
/// **It uses the `std.Io` the parent built, across a fork.** Two things make that
/// sound, and a std upgrade can break either. Every operation this process asks
/// of it runs inline on the calling thread, so none of them waits on a pool
/// thread the fork did not copy. And the one descriptor `std.Io.Threaded` caches
/// on Linux is the `/dev/null` it gives a spawned process, which the close in
/// `forkHost` shut and this process never asks for. A guest cannot spawn
/// anything: `execve` is not in `vmm_calls`.
fn childMain(io: std.Io, options: Options, console_fd: std.posix.fd_t, control: i32) u8 {
    var state: std.heap.DebugAllocator(.{ .thread_safe = true }) = .{};
    const gpa = state.allocator();

    const file: std.Io.File = .{ .handle = console_fd, .flags = .{ .nonblocking = false } };
    var out_buffer: [16 * 1024]u8 = undefined;
    var console = file.writer(io, &out_buffer);
    const out = &console.interface;

    var mine = options;
    mine.control = control;

    // **Read before anything is confined, because the grant is built from it.**
    // A blocking read and no deadline: the parent sends this when its workspace
    // exists, which is work of its own, and a parent that died takes this process
    // with it through `PR_SET_PDEATHSIG` rather than leaving it waiting.
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

    // The read above is the blocking one and the last of them. `host` asks this
    // channel not to wait before its own loop looks at it: see the seam there.
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

/// Both sets as one. The caller owns the result.
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

/// Tell the parent the session socket is bound, and under which memory
/// encryption. The word is one of a closed set, so this needs no escaping.
fn sayReady(control: i32, sev: Sev) void {
    var room: [64]u8 = undefined;
    var writing: std.Io.Writer = .fixed(&room);
    writing.print("{{\"ready\":true,\"sev\":\"{s}\"}}\n", .{sev.text()}) catch return;
    _ = writeAll(control, writing.buffered());
}

/// Tell the parent why the guest is not coming up, in words it prints as they are.
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

/// Read one line off `fd`, waiting for it. Null for a channel that ended first or
/// a line with no newline inside `into`.
///
/// **It may read past the newline, and nothing here does.** The parent sends one
/// message and then only ever closes, so there is nothing after the line to lose.
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

/// Whether the whole of `bytes` went down `fd`.
///
/// **A full buffer is not a broken channel, and neither is an interruption.**
/// `host` makes the child's half non-blocking for the loop that reads it, so
/// `sayReady` and `sayFault` write to a descriptor that can answer `EAGAIN`.
/// Waiting for room is what a blocking write would have done.
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

/// The longest a write to the control channel waits for room.
const write_room_ms: i32 = 10_000;

/// Wait for room on `fd`. False for a channel that will never have any, and for
/// one whose reader is taking longer than `write_room_ms`: the channel carries at
/// most a fault line against a buffer that holds far more, so a wait that long is
/// a parent that has stopped reading at all.
fn waitForRoom(fd: i32) bool {
    var watching = [1]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.OUT,
        .revents = 0,
    }};
    const ready = std.posix.poll(&watching, write_room_ms) catch return false;
    return ready != 0;
}

/// Ask a descriptor not to wait. The inverse of `waitOnStream`.
fn dontWaitOn(fd: std.posix.fd_t) bool {
    return sys.waiting(fd, false);
}

/// Nanoseconds as a `poll` timeout, which counts in milliseconds.
///
/// **Never zero for time that is left.** A zero timeout is a poll that answers at
/// once, so the last millisecond of a wait would be spent spinning on it.
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

/// Run one guest until it stops, and hold it up on a socket while it does.
///
/// `out` is the guest's own console: a guest that failed to come up says why there
/// and nowhere else, so a caller that does not flush it has thrown that away.
/// `fault` is filled in for everything this refuses, because this module holds no
/// terminal of its own.
///
/// **Private, so `forkHost` is the only way to boot a guest.** This confines the
/// process it runs in, which is sound for a process forked for one guest and would
/// confine the whole harness for a caller on a thread of its own. Keeping it
/// private is what stops that second caller existing at all, rather than leaving a
/// field whose omission somebody has to notice.
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

    // **`/dev/sev` is opened here for the same reason `/dev/kvm` is.** Nothing
    // below the confinement seam may open a path, and the launch commands issue
    // through this descriptor until the guest is sealed. A machine with no SEV,
    // no AMD processor, or a user who may not open it answers null, which is the
    // ordinary case and not a fault.
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
                    // The descriptor opened and the machine still would not take
                    // the feature, so this processor does not have it. Give the
                    // descriptor back and make an ordinary guest.
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

    // **Guest memory comes from a different side on each platform.** KVM is told
    // to make a region and holds it; Hypervisor.framework maps memory this
    // process already owns, so there it is set aside here and given over.
    var pages: ?[]align(std.heap.page_size_min) u8 = null;
    defer if (pages) |held| std.posix.munmap(held);
    const region = if (own_memory) got: {
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
        machine.map(room, ram_base) catch {
            fault.* = .{ .said = "this hypervisor would not take the guest's memory" };
            return 1;
        };
        break :got GuestMemory.Region{
            .gpa = ram_base,
            .len = ram_size,
            .backing = .{ .shared = room },
        };
    } else try machine.vm.addMemory(ram_base, ram_size, .shared);
    var regions = [_]GuestMemory.Region{region};
    var memory: GuestMemory = .{ .regions = regions[0..1] };

    const hv = machine.backend();

    // The first processor, whose answer is the machine's: when it stops, the run
    // is over.
    //
    // **Only the first, where the hypervisor binds a processor to the thread that
    // made it.** There every other processor is made by its own thread, inside
    // `driveParked`, because a processor made here could not be run there.
    const id = try hv.addVcpu();
    const ids: []backend.Backend.VcpuId = if (own_cpus)
        &.{}
    else
        try gpa.alloc(backend.Backend.VcpuId, options.cpus - 1);
    defer if (!own_cpus) gpa.free(ids);
    if (!own_cpus) {
        for (ids) |*each| each.* = try hv.addVcpu();
    }

    // The interrupt controller, whichever one this build gives a guest. KVM holds
    // an arm64 GIC and the x86 irqchip in the kernel, and Mirage picks between
    // them. Hypervisor.framework holds neither, so there one is built here and
    // the guest is told where both halves of it sit.
    var gic = if (own_controller)
        device.Gicv2{ .cpus = options.cpus }
    else
        try backend.platform.createController(&machine.vm, options.cpus);
    defer if (!own_controller) gic.deinit();

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
    // **A guest whose controller this process built is told where both halves of
    // it sit**, because the controller is not in the kernel for it to find. The
    // field is the architecture's, so only a build that has one reaches it.
    if (own_controller) {
        placing.controller = .{ .gic_v2 = .{ .cpu_base = arch.fdt.gicv2_cpu_base } };
    }

    if (comptime sev_possible) {
        if (sev != .off) {
            // **Both of these go before the page tables are built.** `prepare`
            // writes the tables, every entry carries the C-bit, and the launch has
            // to be open before the memory it measures is filled in.
            placing.sev_c_bit = arch.platform.hostCBit();

            // **A refusal, never a quiet downgrade.** Everything above this line
            // may answer that the machine has no encryption and make an ordinary
            // guest. From here it may not: the machine is already encrypted and
            // its memory is already placed, so a launch that will not start ends
            // the guest. Carrying on would run it in the clear and still report
            // encryption, which is worse than not starting.
            machine.vm.launchStart(sev_policy, sev_fd.?) catch {
                fault.* = .{ .said = "the guest's memory encryption would not start" };
                return 1;
            };
        }
    }

    const layout = try core.Launch.prepare(gpa, &memory, &manifest, placing);

    if (comptime sev_possible) {
        if (sev != .off) {
            // Measure what went in and close the launch. The measurement says
            // which guest this is, and the attestation manifest already carries
            // the same parts by name, so it is taken and not kept here.
            var measured: [256]u8 = undefined;
            _ = machine.sevSeal(region, &measured) catch {
                fault.* = .{ .said = "the guest's memory encryption would not seal" };
                return 1;
            };
        }
    }

    // **A built controller needs the console's interrupt line named.** The real
    // driver waits to be told there is room to send, and without a line to report
    // on, output stops the moment the early console hands over. A kernel held
    // controller raises the same line without being told.
    var serial: Serial = if (own_controller)
        .{ .sink = out, .line = .{ .controller = gic.controller(), .intid = arch.fdt.uart_intid } }
    else
        .{ .sink = out };

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
    var serving: Serving = .{ .offered = &offered, .granted = options.shares, .out = out };
    held.sharing = .{
        .ctx = &serving,
        .offer = offerShare,
        .withdraw = withdrawShare,
    };

    const platform = arch.platform;
    var attached: Devices = .{};

    // **The console goes on the bus its architecture reaches it through.** A bus
    // answers an access that matched nothing on it, so the port bus exists only
    // where there is something on it.
    var port_devices: [1]device.Device = undefined;
    var port_bus: ?device.Bus = null;
    if (serial_on_port) {
        port_devices[0] = serial.device(uart_base);
        port_bus = .{ .devices = &port_devices };
    } else {
        attached.add(serial.device(uart_base));
    }

    // A controller this process holds is on the bus like any other device. One the
    // kernel holds is not: the guest reaches it without this process seeing it.
    if (own_controller) {
        const halves = gic.devices(arch.fdt.gicd_base, arch.fdt.gicv2_cpu_base);
        attached.add(halves[0]);
        attached.add(halves[1]);
    }

    attached.addServed(shared_fs.device(platform.fs.addr), shared_fs.service(platform.fs.intid));
    attached.addServed(channel.device(platform.vsock.addr), channel.service(platform.vsock.intid));
    var bus = attached.bus();

    // **The outer layer, installed with no thread running.** Everything above has
    // opened what it needs: the guest's memory, its processors, the session socket
    // and the console. From here the only thing this process can name on disk is
    // the directories it serves, and every thread below inherits that.
    //
    // **A device this guest needs is opened above, never below.** `/dev/kvm` is,
    // through `Machine.create`, and anything else of that kind has to be too: the
    // filter permits no `openat` past this point and the grant names no device
    // node.
    //
    // A seccomp filter and a Landlock domain both go on credentials a new thread
    // inherits, so installing once here covers every processor. Installing after a
    // thread exists would have to reach one sitting inside `KVM_RUN`, which cannot
    // be done.
    // **A refusal and not a branch.** This used to be skipped for a caller with no
    // channel, which is how a guest could boot with no filter and no Landlock
    // domain. Every caller forks now, so a missing channel is a mistake and the
    // guest does not start.
    if (options.control < 0) {
        fault.* = .{ .said = "a guest is only run in a forked process, and this one has no control channel" };
        return 1;
    }

    // **This end owns the flag, because this end is what needs it.** `Pump.step`
    // looks at the channel between guest exits and a loop that waited there would
    // stop running the guest, so the invariant belongs where it is read rather
    // than with whoever handed the descriptor over.
    if (!dontWaitOn(options.control)) {
        fault.* = .{ .said = "the control channel would not stop waiting" };
        return 1;
    }

    var layer: ?chock_sandbox.vm_confine.Layer = null;
    var diag: ?chock_sandbox.vm_confine.Diagnostic = null;
    chock_sandbox.vm_confine.install(gpa, options.shares, &layer, &diag) catch {
        // **Nothing it installed can be taken off again**, so this process says
        // why and ends. It must never carry on unconfined.
        fault.* = .{
            .said = "the host side of the guest's boundary would not install",
            .detail = refusalText(gpa, layer, diag),
        };
        return 1;
    };

    // **The boot entry takes the processor itself, not the hypervisor's seam.**
    // Mirage's own runner does the same, because an x86 guest reaches long mode
    // through the whole segment and control state one call writes, which the
    // abstract backend does not carry. `core.Launch.enter` is the seam that does go
    // through the backend, and it does not compile for an arm64 guest at this
    // version: the shim it passes down keeps its one method private.
    if (own_cpus) {
        // **The backend's seam and a shim of this file's own.** A processor is the
        // hypervisor's there and `vcpus` is private, so nothing of it can be
        // passed down. `core.Launch.enter` would be the seam for this and does
        // not compile: the shim it builds keeps its one method private.
        try arch.boot.enter(Entering{ .hv = hv, .id = id }, layout);
    } else {
        try arch.boot.enter(&machine.vcpus[id], layout);
    }

    sayReady(options.control, sev);

    // The ticker signals this thread, so its id is taken here and nowhere else.
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
        .control = options.control,
        .turns = &turns,
    };

    // Where a processor the guest has not started waits, and who tells it the
    // guest asked. Both are nothing where the hypervisor starts them itself.
    const wanted: []Waiting = if (own_cpus) try gpa.alloc(Waiting, options.cpus) else &.{};
    defer if (own_cpus) gpa.free(wanted);
    var made: u32 = 1;
    var power: Power = .{};
    if (own_cpus) {
        for (wanted) |*one| one.* = .{};
        power = .{ .cpus = options.cpus, .made = &made, .wanted = wanted };
    }

    // What every processor is given. The lock is the one Mirage asks the runner
    // for, and a machine with one processor passes none: see `Shared`.
    var shared: Shared = .{};
    const driving: core.Launch.Run = .{
        .bus = &bus,
        .memory = &memory,
        .controller = if (own_controller) gic.controller() else backend.platform.controllerLine(&gic),
        .services = attached.served(),
        .host = end.launchHost(),
        .guard = if (options.cpus > 1) shared.guard() else null,
        .ports = if (port_bus) |*one| one else null,
        // **A hook where the hypervisor does not start the other processors, and
        // none where it does.** A guest starts them through the power interface,
        // and on KVM the kernel answers that itself. Hypervisor.framework answers
        // nothing, so there every other processor waits on a thread of its own
        // until this says the guest asked for it.
        .power = if (own_cpus) power.power() else null,
    };

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
    // How many processors really exist, read by the power interface: a guest told
    // one started that never did waits for it forever.
    made = @intCast(1 + started);

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

    // The first processor stops as if it were asked when another one fails, so a
    // normal reason here still has to be read against them: see `driveCpu`.
    if (Parked.failureIn(parked[0..started])) |err| {
        held.lost(.faulted);
        held.close(&channel);
        out.flush() catch {};
        fault.* = .{ .said = "a processor of the guest stopped badly", .detail = @errorName(err) };
        return 1;
    }

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

/// What a refused confinement is called, as one line.
///
/// **The layer and what the kernel answered, not the layer alone.** A layer names
/// the file somebody has to read and says nothing about why it refused, so a
/// refusal that carried only the layer sent a person there and no further.
///
/// The process this runs in is about to exit, so nothing frees the text, and a
/// refusal to allocate still keeps the layer's name.
fn refusalText(
    allocator: std.mem.Allocator,
    layer: ?chock_sandbox.vm_confine.Layer,
    diag: ?chock_sandbox.vm_confine.Diagnostic,
) []const u8 {
    const named = @tagName(layer orelse .landlock);
    const said = diag orelse return named;
    return std.fmt.allocPrint(allocator, "{s}, {f}", .{ named, said }) catch named;
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
    /// The console, the filesystem, the channel, and the two halves of an
    /// interrupt controller this process built rather than the kernel.
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
    /// Looked at every time round. The parent asks for the end by closing its own
    /// half.
    control: i32,
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
        if (parentLetGo(self.control)) return false;

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

/// Whether the parent has closed its half of the channel, which is how it asks for
/// the end.
///
/// **A would-block means it is still there and has said nothing**, and so does an
/// interruption: the ticker signals the very thread this runs on, so a tick that
/// landed on this read must never read as a parent that let go.
///
/// Outside `Pump` so it can be tested on a socketpair, because telling those two
/// answers apart is the whole of what replaced the `stopping` atomic.
fn parentLetGo(control: i32) bool {
    var byte: [1]u8 = undefined;
    return switch (sys.read(control, &byte)) {
        .again, .interrupted, .got => false,
        // A channel that answers anything else is a channel this end can no longer
        // be asked on, which is not a guest to keep running.
        .ended, .broke => true,
    };
}

fn answerFs(ctx: *anyopaque, request: []const u8, into: []u8) usize {
    const one: *fs_mod.Export = @ptrCast(@alignCast(ctx));
    return one.answer(request, into);
}

/// What an offer arriving over the session socket is checked against, and where
/// a refusal is said.
///
/// **The grant is on before any of this runs and can never be widened.** So a
/// directory outside it is one this process could offer and never open: the guest
/// would mount it and every read of it would answer `EACCES`, which reaches a
/// tool call as `MountTreeFailed` with no path in it. Refusing the offer instead
/// says which path, once, where it was asked for.
const Serving = struct {
    offered: *fs_mod.Export,
    /// Every directory this process was granted. `Options.shares` as `host` read
    /// it, which for a forked guest is what crossed the fork and what arrived on
    /// the control channel.
    granted: []const shares_mod.Share,
    /// The guest's own console, which is where a refusal is written. This module
    /// holds no terminal.
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
    // **The offer slots are a shared budget.** The grant this guest booted with
    // is offered too, so the set a session brings has the rest and not all
    // thirty-two of them. Said here, because the child's own count is of its own
    // offers and cannot see what the grant already spent.
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
/// hypervisor until the guest asks for it. A processor that stops on its own says
/// nothing: the first processor is the one that says how the machine stopped.
///
/// **A processor that stops badly ends the machine.** The first one waits in the
/// hypervisor for an interrupt a dead processor is never going to send, so a
/// second processor that failed quietly left the guest up with nothing driving
/// it: the session answered nothing and `chock run` never returned. `ending` is
/// what every host hook reads, and the ticker's signal is what brings the first
/// processor out to read it.
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

/// One processor, named the way the boot entry asks rather than the way the
/// hypervisor does. The entry writes registers and nothing else, so this carries
/// nothing but which processor they belong to.
const Entering = struct {
    hv: backend.Backend,
    id: backend.Backend.VcpuId,

    pub fn setRegister(self: Entering, reg: backend.Backend.Register, value: u64) !void {
        try self.hv.setRegister(self.id, reg, value);
    }
};

/// What a processor the guest has not started yet is waiting for, where the
/// hypervisor does not start it. Until the guest puts an address in this there
/// is nothing for the processor to begin at.
const Waiting = struct {
    asked: std.atomic.Value(bool) = .init(false),
    entry: u64 = 0,
    context: u64 = 0,
};

/// Who the guest asks to start another processor, where the hypervisor answers
/// nothing.
///
/// The guest names one by the number its device tree gave it, so that number is
/// turned back into which processor it is. **A number naming no processor is
/// refused**, because a guest told a processor started that never did waits for
/// it forever.
const Power = struct {
    cpus: u32 = 0,
    /// How many processors really exist. A thread that never made its own is one
    /// the guest must not be told about.
    made: *const u32 = undefined,
    wanted: []Waiting = &.{},

    fn start(ctx: *anyopaque, target: u64, entry: u64, context: u64) bool {
        // The body reads the device tree's own numbering, which only an arm
        // build has. A hypervisor that starts its own processors never gets here.
        if (own_cpus) {
            const self: *Power = @ptrCast(@alignCast(ctx));
            for (0..@min(self.cpus, self.wanted.len)) |index| {
                if (arch.fdt.affinity(@intCast(index)) != target) continue;
                // The first is running already, and one whose thread never made
                // its own cannot run.
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

/// Everything a processor the guest starts itself is given. One value rather
/// than five arguments, because a thread takes one.
const Parking = struct {
    hv: backend.Backend,
    driving: core.Launch.Run,
    mine: *Parked,
    ending: *std.atomic.Value(bool),
    wanted: []Waiting,
};

/// One processor of a guest, on a hypervisor that binds a processor to the
/// thread that made it.
///
/// **It makes its own and then waits**, because a processor made on the thread
/// above could never be run from here. After the guest asks for it, it is an
/// ordinary processor running the ordinary loop.
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

        // Where the guest said to begin and what with. The rest of the registers
        // are the guest's own business, and the power interface says they are zero.
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

/// Where one of the other processors says which thread it is, so it can be woken.
const Parked = struct {
    thread_id: std.atomic.Value(sys.Thread) = .init(sys.no_thread),
    ended: std.atomic.Value(bool) = .init(false),
    /// What this processor stopped with, as `@intFromError`, or zero for a
    /// processor that stopped on its own. See `driveCpu`.
    failure: std.atomic.Value(u16) = .init(0),

    /// What the first of these processors stopped badly with, if any did.
    fn failureIn(parked: []const Parked) ?anyerror {
        for (parked) |*one| {
            const code = one.failure.load(.acquire);
            if (code != 0) return @errorFromInt(code);
        }
        return null;
    }
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
    /// The thread inside the hypervisor. Signalled by its own id, so no other
    /// thread of this process is interrupted.
    thread_id: sys.Thread,
    group_id: std.posix.pid_t,
    every_ms: u64,
    done: *std.atomic.Value(bool),
    /// The loop's own count of turns. A count that moved between two looks is a
    /// guest getting somewhere, and a guest getting somewhere is never interrupted.
    turns: *std.atomic.Value(u64),
};

/// Signal one thread whenever the loop it runs has stopped moving.
fn tickUntil(ticker: Ticker) void {
    var last: u64 = 0;
    while (!ticker.done.load(.acquire)) {
        sys.sleepMs(ticker.every_ms);

        // A turn happened while this slept, so the guest is exiting on its own and
        // needs nothing from here. Interrupting it would take the entry it is in the
        // middle of.
        const now = ticker.turns.load(.acquire);
        if (now != last) {
            last = now;
            continue;
        }
        sys.alarmThread(ticker.group_id, ticker.thread_id);
    }
}

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
    _ = sys.waiting(fd, true);
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
    sys.close(fd);
}

/// `refused` is filled in with the share the guest would not take, so the caller
/// names the path rather than saying one of them was refused. Null for a caller
/// that does not want it.
pub fn attach(
    io: std.Io,
    socket_path: []const u8,
    shares: []const shares_mod.Share,
    port: u32,
    refused: ?*?shares_mod.Share,
) AttachError!Attached {
    // The session wire is raw descriptors and takes no `std.Io`. The parameter is
    // here so `src/vmm_absent.zig` has the same shape.
    _ = io;

    const control = session_mod.socket.reach(socket_path) catch return error.NoGuest;
    var client = session_mod.Client.adopt(control);
    errdefer client.stop();

    try handshake(&client, shares, refused);

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

/// Wait for the guest, then offer it this session's directories.
///
/// **Wait for the guest to say it is up, and do not poll for a stream.** The socket
/// is bound before the guest runs, so a caller that connects the moment it appears
/// is talking to a guest that has not booted. Asking for a stream in a loop is
/// worse than useless: every ask is work the guest's own loop does instead of
/// running the guest, and a session that asked every 100ms starved its guest to two
/// productive entries in thirty seconds where one left alone managed 371.
///
/// Mirage says when the guest is up: it is the first stream the guest opens, which
/// is `chock guest` dialling. So this listens for that and then asks once.
///
/// **The order of the two halves is the whole of this function.** `up` is sent once
/// a connection, and Mirage's `Client.share` waits for its own answer by reading
/// every message that arrives and throwing away the ones it has no use for, `up`
/// among them. So a session that offered first and waited second lost the message
/// whenever the guest had already dialled, which is every session whose own startup
/// outlasted a boot: it then waited the full thirty seconds and refused with `no
/// stream into the guest` after a console that said the guest was up. Waiting first
/// makes this the only reader of that message. Nothing is lost by the swap: the
/// guest mounts one filesystem and each offer is a name inside it, so a name offered
/// after the guest booted is a name the next tool call reads.
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

        sys.sleepMs(attach_look_ms);
    }
    return false;
}

/// How long to wait for the guest's own program to dial, and how often to look. A
/// guest reads a kernel, loads five modules and mounts a filesystem first.
const attach_wait_ms: u64 = 30 * std.time.ms_per_s;
const attach_look_ms: u64 = 100;

const testing = std.testing;

/// The session end of the test below, on a thread of its own: the server is pumped
/// by whoever holds the guest, and here that is the thread running the test.
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
    // The share handshake reads every message and keeps only its own answer, so a
    // session that offered first threw `up` away and then waited the full limit for
    // a second one Mirage never sends.
    var name: [96]u8 = undefined;
    const path = try std.fmt.bufPrint(&name, "/tmp/chock-vmm-up-{d}.sock", .{sys.ownGroup()});

    var channel: device.virtio.Vsock = undefined;
    const ports = [_]u32{1024};
    channel.init(3, ports[0..]);

    var held = try session_mod.Server.listen(path);
    defer held.close(&channel);
    // What `up` means is the guest's first stream, and this test runs no guest.
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
    // Zero standing for "no failure" rests on an error never being zero, which is
    // what lets one atomic carry both the fact and the name.
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
    // The channel is a stream, so a writer's one message is not a reader's one
    // read. A reader that took the first read for the whole line would parse half
    // a share set and confine the guest to it.
    //
    // The first piece is in the channel before the read starts, so the first read
    // answers it and nothing else. The rest arrives from a thread, which is what
    // makes the reader wait rather than race.
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
    // A parent that died before it sent the set must not read as a set of none,
    // which would confine the guest to nothing and say nothing about why.
    var pair: [2]i32 = undefined;
    try testing.expect(sys.channelPair(&pair));
    defer sys.close(pair[1]);

    sys.close(pair[0]);
    var room: [64]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), readLineInto(pair[1], &room));
}

test "a parent that closed its half is the only thing that asks for the end" {
    // This is what replaced the `stopping` atomic, and the two answers it has to
    // tell apart are a channel at its end and a channel that has said nothing.
    var pair: [2]i32 = undefined;
    try testing.expect(sys.channelPair(&pair));
    try testing.expect(dontWaitOn(pair[1]));

    // Nothing said, and the read does not wait.
    try testing.expect(!parentLetGo(pair[1]));

    sys.close(pair[0]);
    try testing.expect(parentLetGo(pair[1]));
    sys.close(pair[1]);
}

test "a signalled child reads as signalled, and one that will not stop is killed" {
    {
        // A guest the parent killed must not answer the same number a guest that
        // refused to come up exits with.
        const rc = sys.forkNow() orelse return error.TestUnexpectedResult;
        if (rc == 0) {
            sys.killNow(sys.ownGroup());
            std.process.exit(0);
        }

        var child: Child = .{ .pid = rc, .control = -1 };
        try testing.expectEqual(@as(u8, 128 + 9), child.wait());
    }

    {
        // A guest that never reads its closed channel. The wait is bounded, so
        // this ends rather than holding its caller for as long as the guest lives.
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

    // Both ways round, because a parent that always answered `.off` would pass a
    // test that only checked the ordinary case.
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

    // A line from a build that did not have the field reads back as off rather
    // than as a refusal, which is what `ignore_unknown_fields` is there for.
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

    // A word no build knows is never read as encryption.
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
        // A child that died before it said anything must not read as one that is
        // still coming up, which is what the `ended` flag used to answer.
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
    // The layer alone sends a person to the right file and no further, which is
    // the whole reason `install` takes a diagnostic.
    const allocator = std.testing.allocator;
    const named = @tagName(chock_sandbox.vm_confine.Layer.landlock);
    const both = refusalText(allocator, .landlock, .{ .landlock = .{ .call = .add_rule, .errno = .NOENT } });
    defer if (both.ptr != named.ptr) allocator.free(both);
    try testing.expect(std.mem.indexOf(u8, both, "landlock") != null);
    try testing.expect(std.mem.indexOf(u8, both, "add_rule") != null);
    try testing.expect(std.mem.indexOf(u8, both, "NOENT") != null);

    // And a layer with nothing behind it still names the layer.
    try testing.expectEqualStrings("seccomp", refusalText(allocator, .seccomp, null));
}

test "the places a guest is put are the architecture's own, and no two share one" {
    // A guest placed anywhere else is one whose device tree says one thing and
    // whose memory is somewhere else. Where RAM starts is pinned per architecture
    // against Mirage's own choice; the devices are read from Mirage itself.
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

    // Two devices at one address answer each other's accesses, and two sharing an
    // interrupt leave a driver woken for work that is not its own.
    try testing.expect(platform.vsock.addr != platform.fs.addr);
    try testing.expect(platform.vsock.intid != platform.fs.intid);
    try testing.expect(platform.serial.addr != platform.fs.addr);
    try testing.expect(platform.serial.addr != platform.vsock.addr);
}

test "the default cmdline names the console this architecture has" {
    // A kernel told to print to a port it has not got prints nowhere, and the
    // symptom is a guest that boots and says nothing. `pkgs/chock/guest.nix`
    // chooses the same two names from the same two cases.
    const expected = if (serial_on_port) "console=ttyS0" else "console=ttyAMA0";
    const default: Options = .{ .control = -1 };
    try testing.expect(std.mem.startsWith(u8, default.cmdline, expected));
}
