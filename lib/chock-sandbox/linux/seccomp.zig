const std = @import("std");
const bpf = @import("bpf.zig");
const linux = std.os.linux;

pub const RET_ALLOW: u32 = 0x7fff0000;
pub const RET_KILL_PROCESS: u32 = 0x80000000;
/// Return EPERM to the caller instead of killing it.
pub const RET_ERRNO_PERM: u32 = 0x00050000 | @as(u32, @intFromEnum(linux.E.PERM));
/// Hold the call, tell the supervisor it happened, and then let it run.
/// **Not a denial.** See `TrapCall`.
pub const RET_USER_NOTIF: u32 = linux.SECCOMP.RET.USER_NOTIF;

/// The calls Chock blocks outright. No correct tool needs one of these.
/// `unshare` and `setns` are here because the sandbox is already built when the filter
/// is installed. A later call can only try to leave it.
///
/// The whole mount family is here for the same reason. The mount tree is built before
/// the filter is installed, so no correct step needs one of these calls afterwards. A
/// process in its own user namespace holds CAP_SYS_ADMIN over that namespace, and can
/// otherwise call `umount2` to undo the read only bind mount that protects a file such
/// as chock.zon, then write or delete the file it was meant to protect.
///
/// This is a denylist of a syscall family the kernel keeps adding members to, not a
/// fixed set. `open_tree_attr`, syscall 467, was added in kernel 6.15 and was missed
/// on the first pass of this list. It combines `open_tree` and `mount_setattr` into
/// one call, so without `OPEN_TREE_CLONE` it can strip `MOUNT_ATTR_RDONLY` from a live
/// mount the same way `mount_setattr` can, and a filter that blocks `mount_setattr`
/// but not `open_tree_attr` still lets the read only bind be undone. Whoever raises
/// the kernel floor this project builds against must read `uapi/linux/mount.h` for the
/// target kernel and check whether the mount family gained another member before
/// trusting this list again.
///
/// `kexec_file_load` and `delete_module` sit beside `kexec_load`, `init_module`, and
/// `finit_module` for the same reason. Each one reaches the kernel today and is only
/// refused because the process lacks a capability in the initial user namespace. That
/// is luck, not design, so this filter names them itself instead of relying on it.
///
/// `add_key`, `keyctl`, and `request_key` are here because `Sandbox.applyLayers`
/// already joins a fresh session keyring before this filter goes on. `CLONE_NEWUSER`
/// gives a process a fresh user keyring on its own, but the kernel has no namespace
/// for the session keyring, so without that join a key planted on the host is
/// readable in here and a key added in here is readable, and revocable, from the
/// host. Once the join has run, nothing this sandbox executes has any legitimate
/// reason to touch a keyring again, so the three calls that reach one are refused
/// outright. The join has to run before this filter is installed, since the join
/// itself uses `keyctl`; blocking these calls afterwards costs nothing, because by
/// then the join has already finished.
///
/// The three io_uring calls are **not** here. They are on `refused_calls` below, which
/// answers `EPERM`. io_uring stays exactly as unavailable as it was; read that list for
/// why the answer changed and why the security did not.
///
/// `open_by_handle_at` sits here for the same reason as `kexec_file_load` and
/// `delete_module` above: it reaches the kernel today and is only refused because the
/// caller lacks `CAP_DAC_READ_SEARCH` in the user namespace that owns the target
/// filesystem's superblock, which a process born from `CLONE_NEWUSER` never holds over
/// a host filesystem, no matter how many capabilities it carries in its own namespace.
/// **Measured**, with a small C program run outside Chock entirely and then again as
/// `spawn-handle-escape` inside a real `Sandbox.spawn`: `open_by_handle_at` fails with
/// `EPERM` both times, for this repository's own unprivileged user and for `root`
/// inside a plain `unshare -U -r`. That is the capability check doing its job on its
/// own, with no help from Landlock or from this filter. See
/// `test/sandbox/escape.zig`'s "cannot reopen a file by handle" test for the full
/// account, including why dropping this entry would not open the hole that dropping
/// `mount` would. It is blocked anyway: a call refused only by luck is not a call this
/// project relies on being unlucky forever. `name_to_handle_at`, the call that only
/// encodes a handle and grants nothing by itself, is deliberately not here; that same
/// test needs it working to prove the handle it hands to `open_by_handle_at` was ever
/// real.
pub const blocked_calls = [_]linux.SYS{
    .ptrace,
    .bpf,
    .userfaultfd,
    .unshare,
    .setns,
    .process_vm_readv,
    .process_vm_writev,
    .kexec_load,
    .kexec_file_load,
    .init_module,
    .finit_module,
    .delete_module,
    .mount,
    .umount2,
    .pivot_root,
    .move_mount,
    .open_tree,
    .fsopen,
    .fsmount,
    .fsconfig,
    .mount_setattr,
    .open_tree_attr,
    .fspick,
    .add_key,
    .keyctl,
    .request_key,
    .chroot,
    .syslog,
    .reboot,
    .sethostname,
    .open_by_handle_at,
};

/// The calls the filter refuses with `EPERM` instead of killing the caller.
///
/// **io_uring is as unavailable as it was on the kill list, and that is the whole
/// point.** A refused `io_uring_setup` creates no ring. `io_uring_enter` submits no
/// operation, and `io_uring_register` gives no ring a buffer, a file, or an eventfd.
/// There is no ring to hold a submission queue, so there is no kernel worker to do an
/// operation the thread never made a syscall for. The bypass this list exists to close
/// is closed by the refusal, not by the death of the caller. **The only thing that
/// changed is that the process learns it was refused.**
///
/// io_uring is the standard way around a syscall filter. A process puts an operation in
/// a ring, and a kernel worker does the operation, so the thread that asked never makes
/// the syscall this filter reads. A rule written for that operation is not applied to it
/// at all. That is why these three calls must never succeed.
///
/// **Nothing got through when this was measured.** The red team run of 2026-08-22 set
/// up a ring, opened a mounted store path through it, and tried two writes outside the
/// workspace and a `connect`. Landlock refused both writes with EACCES, and the network
/// namespace gave ENETUNREACH, because a namespace is not a filter and so has no
/// syscall for io_uring to avoid making. That result is a property of which layers
/// happen to cover the file surface and the network today. It is not a statement about
/// every operation io_uring supports, and seccomp is the only layer that covers some of
/// them. **That run is unaffected by the change from a kill to a refusal**, because it
/// needed a ring and a refusal gives none.
///
/// ## Why the kill was dropped, measured on Node v24.19.0 with `strace`
///
/// The old text here ended "no program a coding agent runs needs a ring". That sentence
/// is false in the way that matters. libuv calls `io_uring_setup` six times while Node
/// starts, before it runs one line of the program, and it does this whatever the code
/// asks for. `UV_USE_IO_URING=0` does not stop it: six calls, measured. The probe is
/// meant to fail on a kernel older than 5.1, and libuv then falls back to its thread
/// pool. So Node does not need a ring. **It needs the probe to fail survivably.** A kill
/// ends the process before `main` and `node -e` cannot run at all, which is what stopped
/// an agent building a website with Node, Deno or Bun. With
/// `strace -e inject=io_uring_setup:error=EPERM` the same `node -e` runs and exits 0.
///
/// **Killing buys nothing here.** A hostile program is free to not call io_uring, so the
/// kill never stopped an attacker who read this file. It only stopped the honest
/// run time that probes and falls back. A refusal costs an attacker exactly what the
/// kill did, which is the ring, and costs the honest program nothing.
///
/// **This list is for a call that is probed and answered, and not for a call that is
/// simply forbidden.** Every member of `blocked_calls` above is on that list for a
/// reason of its own, and none of them is reached by a program that asks, reads the
/// answer, and takes another road. Moving one of them here needs the same measurement
/// this one got.
pub const refused_calls = [_]linux.SYS{
    .io_uring_setup,
    .io_uring_enter,
    .io_uring_register,
};

/// The calls a supervisor can be asked to observe, and the only calls it can
/// ever observe.
///
/// **A third category, beside the kill list and the refusal list.** A trapped
/// call is not stopped. The kernel holds it, tells another process that it
/// happened, and then lets it run. So this list answers a different question
/// from the two above: not "may this call happen", but "is this call counted".
///
/// **A closed set, and that is the whole safety argument.** A policy picks a
/// member of this enum. It never picks a syscall number. Two faults are
/// impossible because of that:
///
///   * A call on `blocked_calls` can never become a call that is only counted.
///     The `comptime` block below `bootstrap_calls` stops the build on any
///     overlap.
///   * A call that the handover itself makes can never be trapped. See
///     `bootstrap_calls`, which states why that would stop two processes
///     forever.
///
/// **The four members were measured on 2026-09-10, on this kernel.** `execve`,
/// `connect`, and `getdents64` are near zero in every workload measured, so
/// they cost nothing at all. `openat` costs about 11 microseconds for each
/// call, which is under 0.5% of a clean `zig build` and below the noise of
/// this machine. `connect` is the member that makes the network story
/// auditable. `statx`, `brk`, and `mmap` were measured beside them: they
/// double the cost and give no audit value, so they are deliberately not here.
pub const TrapCall = enum {
    openat,
    execve,
    connect,
    getdents64,

    /// The syscall this member names, for the architecture of this binary.
    pub fn number(self: TrapCall) linux.SYS {
        return switch (self) {
            .openat => .openat,
            .execve => .execve,
            .connect => .connect,
            .getdents64 => .getdents64,
        };
    }

    /// Which argument of this call is a pointer to a path, or null for a call
    /// that names no path at all.
    ///
    /// **A property of the member, and never a number written at the place
    /// that reads memory.** A member added above answers this question here,
    /// once, beside the syscall number it already answers. A reader that
    /// guessed would read the wrong pointer for one call and record a
    /// filename that was never a filename.
    ///
    /// `connect` is null on purpose. Its second argument is a `sockaddr` and
    /// not a path, and the one family that carries a path inside it needs the
    /// address to be decoded rather than copied. `getdents64` takes a
    /// descriptor, which names no path at all.
    pub fn pathArg(self: TrapCall) ?u2 {
        return switch (self) {
            .openat => 1,
            .execve => 0,
            .connect, .getdents64 => null,
        };
    }

    /// The member a notification names, or null for a number no member holds.
    ///
    /// **The number comes from the kernel, inside the notification.** The
    /// observed process cannot change it after the filter read it, so a count
    /// made from it cannot be forged.
    pub fn fromNumber(nr: i64) ?TrapCall {
        inline for (@typeInfo(TrapCall).@"enum".fields) |field| {
            const call: TrapCall = @enumFromInt(field.value);
            if (@intFromEnum(call.number()) == nr) return call;
        }
        return null;
    }
};

/// Which calls one filter hands to a supervisor. Empty is the default, and an
/// empty set builds exactly the filter this project always built.
pub const TrapSet = std.EnumSet(TrapCall);

/// The calls the observed process makes between the filter going on and the
/// supervisor holding the notification descriptor.
///
/// **A trap on one of these is not a slow call. It is a stop that never
/// ends.** `linux/driver.zig` installs the filter in B, the process that runs
/// the caller's program. B then writes the descriptor number to A, the
/// supervisor, and waits for A to answer. A takes the descriptor with
/// `pidfd_getfd`. Until that is finished, no process holds the descriptor, so
/// nothing can answer a notification. A trapped `write` or `read` in that
/// window would wait for a supervisor that does not exist yet, and A would
/// wait for B at the same moment.
///
/// `sendto` is here beside `write` because `linux/notify.zig` sends on that
/// socket with `MSG_NOSIGNAL`, so the death of the other process reaches it as
/// an `EPIPE` it can read rather than as a `SIGPIPE` that ends it.
///
/// **A comment is not the guarantee.** The `comptime` block below stops the
/// build if a `TrapCall` member ever names one of these calls. The test
/// "no call the handover makes can ever be trapped" reads the same fact again.
pub const bootstrap_calls = [_]linux.SYS{ .read, .write, .close, .sendto };

comptime {
    for (@typeInfo(TrapCall).@"enum".fields) |field| {
        const call: TrapCall = @enumFromInt(field.value);
        for (bootstrap_calls) |boot| {
            if (call.number() == boot) @compileError(
                "trapping " ++ field.name ++ " would stop the handover forever. See bootstrap_calls.",
            );
        }
        for (blocked_calls) |killed| {
            if (call.number() == killed) @compileError(
                "a killed call cannot also be an observed call: " ++ field.name,
            );
        }
        for (refused_calls) |refused| {
            if (call.number() == refused) @compileError(
                "a refused call cannot also be an observed call: " ++ field.name,
            );
        }
    }
}

/// The calls whose `prot` argument the filter reads. `prot` is argument index
/// 2 for all three.
pub const memory_calls = [_]linux.SYS{ .mmap, .mprotect, .pkey_mprotect };

/// The highest syscall number this project has classified, for the architecture
/// this binary is built for. A syscall is classified once a person has read it and
/// either put it on `blocked_calls` or decided on purpose to leave it off. Zig
/// 0.16.0 lists the aarch64 table through `listns`, syscall 470, and that is the
/// value below, checked by hand against `lib/zig/std/os/linux/syscalls.zig`.
///
/// This line only moves when a person raises it after reading the new syscalls.
/// The test below fails the build the day the standard library adds one past it.
///
/// This cannot see a syscall the running kernel has but Zig does not know about
/// yet. That gap is why the design also wants a warning when the running kernel
/// is newer than the version Chock was hardened for. This constant is one half
/// of that safeguard, not the whole of it.
pub const classified_through: usize = 470;

/// The audit constant for the architecture that this binary runs on.
/// A filter must refuse a call from any other architecture. A 64 bit kernel can run a
/// 32 bit binary, and the call numbers are different, so a filter without this check
/// can be passed.
///
/// These values are written by hand on purpose. `std.os.linux.AUDIT.ARCH` does not
/// compile in Zig 0.16.0, because its `FRV` field names `std.elf.EM.FRV` and that field
/// is called `CYGNUS_FRV`. Use the standard library again when the bug is fixed.
///
/// A value is the ELF machine number, with 0x80000000 for a 64 bit architecture and
/// 0x40000000 for a little endian architecture.
fn nativeAuditArch() u32 {
    const bit_64: u32 = 0x80000000;
    const little_endian: u32 = 0x40000000;
    return switch (@import("builtin").cpu.arch) {
        // EM_AARCH64 is 183.
        .aarch64 => 183 | bit_64 | little_endian,
        // EM_X86_64 is 62.
        .x86_64 => 62 | bit_64 | little_endian,
        // EM_RISCV is 243.
        .riscv64 => 243 | bit_64 | little_endian,
        else => @compileError("chock-sandbox has no audit arch for this target"),
    };
}

/// How to build the filter.
pub const Options = struct {
    /// Deny a page that is writable and executable at the same time.
    /// Turn this off for a project that needs a run time which allocates such a page.
    /// The Java code cache and some versions of V8 do this.
    strict_wx: bool = true,
    /// Refuse `connect` with `EPERM`. Off by default, and the Linux driver
    /// turns it on for one case only: `namespace.Network.filtered`.
    ///
    /// ## Why a `.filtered` sandbox needs this, and a `.none` one does not
    ///
    /// A filtered process is handed a **connected descriptor** over
    /// `SCM_RIGHTS`. That descriptor was made by the process on the other side
    /// of the boundary, so it belongs to **that** process's network namespace
    /// and not to the sandbox's own empty one. The sandbox's namespace
    /// therefore says nothing about where that one descriptor can reach.
    ///
    /// **Measured on 2026-08-23, on Linux 6.18.42.** A connected TCP socket:
    ///
    /// * `connect` to another address while connected answers `EISCONN`.
    /// * `connect` with `AF_UNSPEC` **succeeds** and dissolves the
    ///   association, and a `connect` to another address after that
    ///   **succeeds too**. So a granted descriptor really can be aimed
    ///   somewhere else.
    /// * `sendto` with another address on a connected socket ignores that
    ///   address: the bytes arrived at the connected peer, and the second
    ///   listener accepted nothing. So `connect` is the only way to re-aim
    ///   one.
    ///
    /// Refusing `connect` is what closes that, and it is the rule the whole
    /// design already states: **a filtered process does not open a
    /// connection. It asks for one.** A process that never calls `connect`
    /// loses nothing.
    ///
    /// **This narrows, it never widens.** `none` keeps exactly the filter it
    /// always had, so nothing that runs today changes, and `filtered` is
    /// strictly the stricter of the two on system calls as well as being the
    /// one with a channel out.
    ///
    /// **So the two modes do not carry the same filter, and a caller must not
    /// treat them as interchangeable.** Measured on 2026-08-24, with the
    /// driver reading this option as a plain `true`: four tests fail. See
    /// `linux/driver.zig`, where that line is, for which four and what each
    /// one names.
    ///
    /// **What it costs, stated rather than hidden.** `connect` is one call for
    /// every address family, and seccomp cannot read the address behind the
    /// pointer, so this also refuses a unix socket client inside the sandbox.
    /// A filtered program that wants to talk to a helper of its own uses
    /// `socketpair`, which this filter does not touch.
    ///
    /// `EPERM` and not a kill, for the reason the write and execute rule gives:
    /// a program that meets a refusal can answer it, and a program that is
    /// killed cannot.
    block_connect: bool = false,
    /// Which calls the supervisor observes. See `TrapCall`.
    ///
    /// **Empty by default, so nothing changes for a caller that does not
    /// ask.** An empty set adds no instruction at all, and the filter is byte
    /// for byte the filter this project always built.
    ///
    /// **Only for a filter that goes on with `installListening`.** A filter
    /// that returns `RET_USER_NOTIF` with no listener behind it makes the
    /// kernel answer the call with `ENOSYS`, which is worse than either a kill
    /// or a refusal: the program is told the call does not exist. So a filter
    /// built with a trap set must go on with that one call and no other.
    /// `linux/driver.zig` builds a second filter, with this field empty, for
    /// the supervisor process itself.
    ///
    /// **A refusal wins over an observation.** `block_connect` above emits its
    /// rule first, so a filter that both refuses `connect` and observes it
    /// refuses it and never counts it. That is the narrow answer, and it is
    /// the safe direction.
    traps: TrapSet = .initEmpty(),
};

/// Build the filter. The caller owns the memory.
///
/// One filter serves both the tool runner and the plugin host. Two profiles were
/// planned, but the write and execute rule reads the protection flags of the call,
/// so a compiler in a tool call and Vulcan in the plugin host both pass it.
pub fn build(allocator: std.mem.Allocator, options: Options) ![]bpf.Insn {
    var insns: std.ArrayList(bpf.Insn) = .empty;
    errdefer insns.deinit(allocator);

    // Refuse any architecture but this one, before anything reads a call number.
    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_arch));
    try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, nativeAuditArch(), 1, 0));
    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));

    // Load the call number one time. Every check below reads it.
    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));

    // The x32 ABI reports the same audit architecture as x86_64 and sets bit 30 in the
    // call number. Such a call matches no comparison below and would reach the allow at
    // the end. Kill it before any comparison runs.
    if (@import("builtin").cpu.arch == .x86_64) {
        try insns.append(allocator, bpf.jump(bpf.JMP_JGE_K, 0x40000000, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
    }

    for (blocked_calls) |call| {
        // std.os.linux.SYS has a usize tag, but a BPF constant is 32 bits wide.
        const number: u32 = @intCast(@intFromEnum(call));
        // If the number matches, fall to the kill. If not, skip over the kill.
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
    }

    // See `refused_calls`. Two instructions per call, and neither one touches the
    // accumulator, so the call number every check below reads is still in it.
    for (refused_calls) |call| {
        const number: u32 = @intCast(@intFromEnum(call));
        // If the number matches, fall to the refusal. If not, skip over it.
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
    }

    // See `Options.block_connect`. Two instructions, and neither one touches the
    // accumulator, so the call number every check below reads is still in it.
    if (options.block_connect) {
        const connect_number: u32 = @intCast(@intFromEnum(linux.SYS.connect));
        // If the number matches, fall to the refusal. If not, skip over it.
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, connect_number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
    }

    // Refuse `execveat` when its `flags` argument sets `AT_EMPTY_PATH`. This is
    // unconditional, unlike the write-and-execute rules below: it closes a real
    // boundary, not a hardening cost. `SECURITY.md`'s own definition of a security
    // bug names it directly: "defeats the Landlock rules".
    //
    // `AT_EMPTY_PATH` is what lets `execveat` run a bare descriptor with an empty
    // path string, rather than a real path it would otherwise resolve relative to
    // `dirfd`. `memfd_create` makes an anonymous file with no directory entry at
    // all, so `execveat(memfd, "", argv, envp, AT_EMPTY_PATH)` runs it without
    // ever naming a path. Landlock's execute right attaches to a path and only a
    // path, so a call that names none has nothing for that right to check.
    //
    // **Measured, in `test/sandbox/escape.zig`'s memfd escape test, before this
    // rule existed: the run lands.** A ruleset that grants /work every ordinary
    // right except execute still lets a process write those exact bytes into a
    // memfd and run them, after the identical bytes on disk were refused with
    // `EACCES` by the same ruleset. Nothing else Chock promises was defeated by
    // that: the seccomp filter installs once before this process's first line and
    // cannot be shed by any execve, so `ptrace` still dies with `SIGSYS`
    // afterward, and every other layer, the mount tree, the network namespace,
    // the resource limits, applies to whatever code lands exactly as it did
    // before. Only Landlock's own execute right, one specific stated boundary,
    // was the thing with nothing to check. This rule is what gives it something.
    //
    // This reads the `flags` argument, `execveat`'s fifth and index 4, rather
    // than blocking `memfd_create` itself. `memfd_create` alone grants nothing:
    // it makes memory a process already owns, and closing the step that never
    // executes anything costs whatever legitimate use of an anonymous, exec-free
    // memfd this sandbox's workload has, measured or not. The execute step is the
    // one that matters, and it is also the narrower rule: `strace` against
    // Node v24.19.0, Python 3.14 and Go 1.26 running an ordinary program each
    // shows neither `memfd_create` nor `execveat` called at all, so this refuses
    // a call none of them make and keeps every one of them running.
    //
    // An ordinary `execveat` call, with a real path and no empty-path flag, is
    // left alone. Nothing measured here needed one refused, so narrower costs
    // less than wider.
    {
        const execveat_number: u32 = @intCast(@intFromEnum(linux.SYS.execveat));
        const at_empty_path: u32 = 0x1000;
        // If this is not execveat, jump over the five instructions that follow.
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, execveat_number, 0, 5));
        // The kernel declares flags an int, so the low half is the whole value.
        // The high half of the 64 bit argument slot carries nothing.
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(4)));
        try insns.append(allocator, bpf.stmt(bpf.ALU_AND_K, at_empty_path));
        // The masked value equals AT_EMPTY_PATH only when the caller asked to run
        // a bare descriptor with no path at all. Fall through to the kill.
        // Otherwise skip past it.
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, at_empty_path, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
        // Put the call number back, because the checks that follow expect it.
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
    }

    // Refuse `socket(AF_VSOCK, ...)`, unconditionally, the same as the
    // `execveat` rule above and for the same reason: this closes a boundary
    // this sandbox's own design already claims, not a cost this project is
    // choosing to add.
    //
    // Every other address family a tool call can reach is inside the
    // network namespace `namespace.enter` always builds: `Network.none`
    // brings up no interface at all, and even `Network.filtered`'s one
    // granted descriptor was made on the other side of the boundary, in a
    // process that is not this one. `AF_VSOCK` answers to neither. A vsock
    // address names a hypervisor CID, not a route inside any network
    // namespace, and the kernel does not consult the calling process's
    // netns to decide whether one is reachable: a guest's vsock transport
    // is the same one every netns in that guest shares. So on any host
    // where Chock's own sandbox is itself the guest of a hypervisor, this
    // is a channel to that hypervisor with no network namespace, no
    // `Network` mode, and no policy rule standing in front of it at all,
    // for a process `Network.none` is supposed to leave with no route out
    // whatsoever.
    //
    // Codex already reasons this way and refuses `AF_VSOCK` even when its
    // own network policy would otherwise allow a connection, because a
    // vsock reaches the hypervisor and is outside any network policy by
    // construction. Nothing here depends on whether this particular host
    // happens to be a VM guest today: a filter built once has to hold on
    // every host it might run on, including the ones it does not know
    // about yet, and the cost of naming a family no coding tool has any
    // reason to open is nothing measured against.
    {
        const socket_number: u32 = @intCast(@intFromEnum(linux.SYS.socket));
        const af_vsock: u32 = 40;
        // If this is not socket, jump over the four instructions that follow.
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, socket_number, 0, 4));
        // The kernel declares domain an int, so the low half is the whole
        // value. socket's first argument, index 0.
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(0)));
        // AF_VSOCK and nothing else. Fall through to the kill on a match.
        // Otherwise skip past it: every other family this sandbox already
        // confines through the network namespace, and none of them needs
        // this rule to say so again.
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, af_vsock, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
        // Put the call number back, because the checks that follow expect it.
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
    }

    // Refuse a request for a page that is writable and executable at the
    // same time. The `prot` argument is a scalar. The filter can read it directly. A
    // filter can never read memory through a pointer.
    //
    // This rule raises the cost of running injected code. It is not a boundary. Do not
    // read it as a guarantee. An attacker ran injected code past this rule three ways.
    // Each way was proven by running code, not only argued.
    //
    //   - `shmat` has no `prot` argument. This rule never sees a `shmat` call. A
    //     process calls `shmget`, then `shmat` with `SHM_EXEC`, and gets a mapping
    //     that is writable and executable at the same time.
    //   - An ELF file can set its `PT_GNU_STACK` segment to read, write, and execute.
    //     The loader gives out that stack. No memory syscall runs for this rule to see.
    //   - A process calls `memfd_create`, then maps the file once with
    //     `PROT_READ | PROT_EXEC` and `MAP_SHARED`. It then calls `pwrite` on the file
    //     descriptor. No mapping is ever writable. The code the mapping runs still
    //     changes.
    //
    // The block below closes `personality(READ_IMPLIES_EXEC)`, and the block after it
    // closes `shmat` with `SHM_EXEC`. Both cost nothing to close. Neither closes the
    // other two routes above, and no rule that reads a syscall argument can.
    if (options.strict_wx) {
        // The kernel adds PROT_EXEC to a mapping inside do_mmap, after seccomp has
        // already inspected the prot argument that this filter reads below. It does
        // this when the calling thread has set the READ_IMPLIES_EXEC personality flag.
        // A caller can set that flag, then ask mmap for PROT_READ | PROT_WRITE only,
        // pass the rule that follows this block, and still receive a page that maps
        // rwxp. Refuse only the call that turns this behavior on. A build tool that
        // calls personality(ADDR_NO_RANDOMIZE) for a reproducible build, and the
        // standard read of the current value with personality(0xffffffff), must both
        // keep working.
        {
            const personality_number: u32 = @intCast(@intFromEnum(linux.SYS.personality));
            const read_implies_exec: u32 = 0x0400000;
            const read_current: u32 = 0xffffffff;
            // If this is not personality, jump over the six instructions that follow.
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, personality_number, 0, 6));
            // The kernel declares the parameter unsigned int, so the low half is the
            // whole value. The high half of the 64 bit argument slot carries nothing.
            try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(0)));
            // 0xffffffff only reads the current value and changes nothing. Let it
            // through by jumping straight to the restore at the end of this block.
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, read_current, 3, 0));
            try insns.append(allocator, bpf.stmt(bpf.ALU_AND_K, read_implies_exec));
            // The masked value equals READ_IMPLIES_EXEC only when the caller asked to
            // turn the bit on. Fall through to the deny. Otherwise skip past it.
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, read_implies_exec, 0, 1));
            try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
            // Put the call number back, because the checks that follow expect it.
            try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
        }

        // `shmat` has no `prot` argument, so the rule below never sees a `shmat` call.
        // Refuse it outright when the caller asks to attach the segment executable.
        // No tool a coding agent runs needs a shared memory segment, so this costs
        // nothing. `shmflg` is `shmat`'s third argument, index 2.
        {
            const shmat_number: u32 = @intCast(@intFromEnum(linux.SYS.shmat));
            const shm_exec: u32 = 0x8000;
            // If this is not shmat, jump over the five instructions that follow.
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, shmat_number, 0, 5));
            // The kernel declares shmflg an int, so the low half is the whole value.
            // The high half of the 64 bit argument slot carries nothing.
            try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(2)));
            try insns.append(allocator, bpf.stmt(bpf.ALU_AND_K, shm_exec));
            // The masked value equals SHM_EXEC only when the caller asked to attach
            // the segment executable. Fall through to the deny. Otherwise skip past it.
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, shm_exec, 0, 1));
            try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
            // Put the call number back, because the checks that follow expect it.
            try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
        }

        const prot_write_exec: u32 = 0x2 | 0x4;
        // The `prot` argument is number 2 for all three calls.
        for (memory_calls) |call| {
            const number: u32 = @intCast(@intFromEnum(call));
            // If this is not the call, jump over the six instructions that follow.
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 6));
            try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(2)));
            try insns.append(allocator, bpf.stmt(bpf.ALU_AND_K, prot_write_exec));
            // Both bits set means a request for write and execute at one time.
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, prot_write_exec, 0, 1));
            try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
            // Put the call number back, because the checks that follow expect it.
            try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
            // A jump of zero. It keeps the count above correct and reads clearly.
            try insns.append(allocator, bpf.stmt(bpf.JMP_JA, 0));
        }
    }

    // See `TrapCall`. Two instructions for each observed call, the same shape
    // the refusal loop has, and neither one touches the accumulator, so the
    // call number is still in it when the allow below is reached.
    //
    // **Last, after every rule that kills or refuses.** The sets are already
    // disjoint at compile time, so nothing here can take a boundary away. The
    // position says it a second time, for free: a call that some rule above
    // answered never reaches this point at all.
    var traps = options.traps.iterator();
    while (traps.next()) |call| {
        const number: u32 = @intCast(@intFromEnum(call.number()));
        // If the number matches, fall to the notification. If not, skip over it.
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_USER_NOTIF));
    }

    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ALLOW));
    return insns.toOwnedSlice(allocator);
}

/// Every call the path reader may make, and the only ones it may make.
///
/// **An allowlist, where every other filter in this file is a denylist.** The
/// reader is one loop of about forty lines and its whole job is four calls, so
/// the set of calls it needs can be written down completely. Nothing else can
/// be said about the process that holds `process_vm_readv`, which every other
/// process Chock starts is killed for making, so nothing else is permitted.
///
/// What each one is for:
///
///   * `process_vm_readv` copies the path out of the observed process. It is
///     the reason the reader exists, and it is a call on `blocked_calls`, so
///     the reader can never run under the filter the rest of the sandbox runs
///     under. `process_vm_writev` is **not** here: the reader reads.
///   * `ioctl` carries `SECCOMP_IOCTL_NOTIF_RECV` and `SECCOMP_IOCTL_NOTIF_SEND`.
///     The reader holds exactly one descriptor when this filter goes on,
///     which is the notification descriptor, so the descriptor argument can
///     reach nothing else. See `notify.runReader`, which closes every other
///     descriptor before it installs this.
///   * `poll` and `ppoll` wait for a notification. Which of the two the
///     standard library calls depends on the architecture, so both are named
///     when the architecture has both.
///   * `exit_group`, `exit`, `rt_sigreturn` and `restart_syscall` are how a
///     process ends and how it comes back from a signal. A process that could
///     not make them could not die cleanly or survive an interrupted wait.
///
/// **No `write`, no `openat`, no `socket`, no `connect`, and no `close`.** The
/// reader has no way to put a byte anywhere except the shared record it was
/// given before the filter went on, so a reader that was somehow turned
/// against its owner still reaches nothing.
pub const reader_calls = blk: {
    var list: []const linux.SYS = &.{
        .process_vm_readv,
        .ioctl,
        .ppoll,
        .exit_group,
        .exit,
        .rt_sigreturn,
        .restart_syscall,
    };
    // `poll` exists on x86_64 and does not exist on aarch64, where the
    // standard library calls `ppoll` instead. Naming a member the table does
    // not have would not build at all.
    if (@hasField(linux.SYS, "poll")) list = list ++ &[_]linux.SYS{.poll};
    break :blk list;
};

comptime {
    // **The reader's filter must permit a call the sandbox kills.** That is
    // the whole reason the reader is a process of its own, so a build in which
    // the two lists agreed would mean the separation had quietly been undone.
    var reads_memory = false;
    for (reader_calls) |call| {
        if (call == .process_vm_readv) reads_memory = true;
    }
    if (!reads_memory) @compileError(
        "the path reader cannot read a path without process_vm_readv. See reader_calls.",
    );
}

/// The filter the path reader runs under. **An allowlist**: every call not in
/// `reader_calls` kills the process.
///
/// The caller owns the memory.
pub fn buildReader(allocator: std.mem.Allocator) ![]bpf.Insn {
    return buildAllowlist(allocator, reader_calls);
}

/// Every call the pid namespace keeper may make, and the only ones it may
/// make. The keeper reaps orphaned processes, waits for its control socket,
/// reports that its filter is active, and exits.
pub const keeper_calls: []const linux.SYS = &.{
    .wait4,
    .ppoll,
    .write,
    .exit_group,
    .exit,
    .rt_sigreturn,
    .restart_syscall,
};

/// The allowlist for the pid namespace keeper. The caller owns the memory.
pub fn buildKeeper(allocator: std.mem.Allocator) ![]bpf.Insn {
    return buildAllowlist(allocator, keeper_calls);
}

fn buildAllowlist(allocator: std.mem.Allocator, calls: []const linux.SYS) ![]bpf.Insn {
    var insns: std.ArrayList(bpf.Insn) = .empty;
    errdefer insns.deinit(allocator);

    // Refuse any architecture but this one, before anything reads a call
    // number. The same first three instructions `build` writes, and for the
    // same reason: a call number means nothing until the architecture is known.
    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_arch));
    try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, nativeAuditArch(), 1, 0));
    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));

    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
    for (calls) |call| {
        const number: u32 = @intCast(@intFromEnum(call));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ALLOW));
    }

    // **The default is death, and it is the last instruction.** A call that
    // matched nothing above falls here.
    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
    return insns.toOwnedSlice(allocator);
}

pub const InstallError = error{
    /// This kernel has no `seccomp` system call at all.
    NotSupported,
    /// `prctl(PR_SET_NO_NEW_PRIVS)` was refused, so the filter was never
    /// offered to the kernel.
    NoNewPrivsRefused,
    /// The kernel refused the filter because this process holds neither
    /// `no_new_privs` nor `CAP_SYS_ADMIN`.
    NotPermitted,
    /// The kernel refused the filter itself. Either the instructions are not
    /// valid, or this kernel was built with no filter mode.
    Rejected,
    Unexpected,
};

/// Install a filter on the calling thread. The filter can never be removed.
/// Call this after the fork and before the exec.
///
/// **The `no_new_privs` flag goes on here, and never in a caller.** The filter
/// and the flag that makes the kernel accept it go on together, or neither one
/// goes on. A caller cannot get the order wrong, because it cannot get one
/// without the other.
///
/// **Each way this can fail has a name of its own.** A refused flag, a missing
/// privilege, and a filter the kernel could not read are three different
/// faults with three different repairs. A caller that reads only `Rejected`
/// looks for a bad filter when the real fault is one of the other two.
pub fn install(prog: bpf.Prog) InstallError!void {
    _ = try setModeFilter(prog, 0);
}

/// Install a filter and give back the notification descriptor for it. Every
/// word of `install` above applies here too.
///
/// **The only install a filter with a trap set may use.** A filter that
/// returns `RET_USER_NOTIF` with no listener behind it makes the kernel answer
/// the call with `ENOSYS`. See `Options.traps`.
///
/// The caller owns the descriptor. `linux/driver.zig` hands it to the
/// supervisor with `pidfd_getfd` and then closes its own copy, so the observed
/// process never holds a descriptor that could answer its own notifications.
pub fn installListening(prog: bpf.Prog) InstallError!i32 {
    const rc = try setModeFilter(prog, linux.SECCOMP.FILTER_FLAG.NEW_LISTENER);
    return @intCast(rc);
}

/// The one body both installs share, so the flag is the only difference
/// between them and the `no_new_privs` step cannot be lost from one of the two.
fn setModeFilter(prog: bpf.Prog, flags: u32) InstallError!usize {
    // Without `no_new_privs`, an unprivileged process cannot install a filter, because a
    // set-user-ID program could then be given a filter that lies to it.
    const pr = linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0);
    switch (linux.errno(pr)) {
        .SUCCESS => {},
        else => return error.NoNewPrivsRefused,
    }

    const rc = linux.seccomp(
        linux.SECCOMP.SET_MODE_FILTER,
        flags,
        @ptrCast(&prog),
    );
    return switch (linux.errno(rc)) {
        .SUCCESS => rc,
        .NOSYS => error.NotSupported,
        // The kernel answers EACCES only when the caller holds neither
        // `no_new_privs` nor `CAP_SYS_ADMIN`. The call above says the flag is
        // on, so this answer means the flag was lost between the two calls.
        // It is a different fault from a filter the kernel could not read.
        .ACCES => error.NotPermitted,
        .INVAL => error.Rejected,
        else => error.Unexpected,
    };
}

test "the filter starts by refusing a foreign architecture" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    // Instruction 0 must load the arch field. A filter that checks the call number
    // before the architecture can be passed with a 32 bit call on a 64 bit kernel.
    try std.testing.expectEqual(bpf.LD_W_ABS, prog[0].code);
    try std.testing.expectEqual(bpf.offset_of_arch, prog[0].k);
    try std.testing.expectEqual(bpf.JMP_JEQ_K, prog[1].code);
}

test "the filter ends with an allow" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    const last = prog[prog.len - 1];
    try std.testing.expectEqual(bpf.RET_K, last.code);
    try std.testing.expectEqual(@as(u32, RET_ALLOW), last.k);
}

test "the filter names every call that must be blocked" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    // **The failure names every syscall the filter forgot, and nothing is
    // written to the terminal.** A test that writes to standard error puts a
    // `failed command:` line in the build log even when it passes, so the
    // names are collected here and compared against nothing at the end:
    // `expectEqualStrings` prints both sides. A bare `expect` would say only
    // that some syscall was missing, and stopping at the first one would hide
    // the rest.
    var missing: std.ArrayList(u8) = .empty;
    defer missing.deinit(allocator);

    for (blocked_calls) |call| {
        const number: u32 = @intCast(@intFromEnum(call));
        var found = false;
        for (prog) |insn| {
            if (insn.code == bpf.JMP_JEQ_K and insn.k == number) found = true;
        }
        if (!found) try missing.print(allocator, "the filter does not check {s}\n", .{@tagName(call)});
    }

    try std.testing.expectEqualStrings("", missing.items);
}

test "every instruction the builder emits is one the kernel accepts" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    // A classic BPF program has a hard limit of 4096 instructions. A filter that grows
    // past it is refused at install time with EINVAL, which is a confusing failure.
    try std.testing.expect(prog.len <= 4096);
    for (prog) |insn| {
        const known = insn.code == bpf.LD_W_ABS or insn.code == bpf.JMP_JEQ_K or
            insn.code == bpf.JMP_JGE_K or insn.code == bpf.JMP_JA or
            insn.code == bpf.ALU_AND_K or insn.code == bpf.RET_K;
        try std.testing.expect(known);
    }
}

test "the architecture mismatch branch returns RET_KILL_PROCESS" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    // Instruction 1 is the JEQ on the arch field. jt = 1 skips the kill when the arch
    // matches. jf = 0 falls straight into instruction 2 when it does not. Instruction
    // 2 must be the kill, and it must return RET_KILL_PROCESS and nothing softer.
    try std.testing.expectEqual(@as(u8, 0), prog[1].jf);
    try std.testing.expectEqual(bpf.RET_K, prog[2].code);
    try std.testing.expectEqual(@as(u32, RET_KILL_PROCESS), prog[2].k);
}

/// True when `prog[i]` is a call number comparison the `blocked_calls` loop in
/// `build` could have emitted, and not an argument comparison from some other
/// rule that only coincidentally compares against the same numeric value.
///
/// **Why a numeric match on `k` is not enough on its own.** On aarch64,
/// `mount` is syscall 40, and `AF_VSOCK` is also 40: the vsock rule's own
/// inner comparison, `domain == AF_VSOCK`, carries the exact same `k` as
/// `mount`'s call number check, with the same `jt`/`jf` shape, because both
/// happen to kill on a match and fall through on a miss. Every genuine
/// `blocked_calls` comparison reads the call number that was loaded once, at
/// the top of the filter, into the accumulator, and every argument reading
/// rule, `execveat`'s and the socket rule's alike, reloads the accumulator
/// from `offsetOfArgLow` immediately beforehand. So the instruction directly
/// before a real `blocked_calls` comparison is never an argument load: it is
/// either that one initial load of `nr`, for the first entry, or the `RET_K`
/// of the entry before it, for every one after.
fn precededByArgumentLoad(prog: []const bpf.Insn, i: usize) bool {
    if (i == 0) return false;
    const before = prog[i - 1];
    return before.code == bpf.LD_W_ABS and before.k != bpf.offset_of_nr;
}

test "every blocked call comparison is followed by a kill instruction" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    // A comparison that falls through to something other than RET_K with
    // RET_KILL_PROCESS would let a blocked call reach the allow at the end.
    var checked: usize = 0;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K) continue;
        if (precededByArgumentLoad(prog, i)) continue;
        var is_blocked_call = false;
        for (blocked_calls) |call| {
            if (insn.k == @as(u32, @intCast(@intFromEnum(call)))) is_blocked_call = true;
        }
        if (!is_blocked_call) continue;

        try std.testing.expectEqual(bpf.RET_K, prog[i + 1].code);
        try std.testing.expectEqual(@as(u32, RET_KILL_PROCESS), prog[i + 1].k);
        checked += 1;
    }
    try std.testing.expectEqual(blocked_calls.len, checked);
}

test "every blocked call comparison jumps so the kill is reachable and the skip clears it" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    // jt = 0 falls into the kill on a match. jf = 1 skips exactly the one kill
    // instruction on no match. A wrong offset here either misses the kill on a
    // match or skips past it into the next check, and this test must catch both.
    var checked: usize = 0;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K) continue;
        if (precededByArgumentLoad(prog, i)) continue;
        var is_blocked_call = false;
        for (blocked_calls) |call| {
            if (insn.k == @as(u32, @intCast(@intFromEnum(call)))) is_blocked_call = true;
        }
        if (!is_blocked_call) continue;

        try std.testing.expectEqual(@as(u8, 0), insn.jt);
        try std.testing.expectEqual(@as(u8, 1), insn.jf);
        checked += 1;
    }
    try std.testing.expectEqual(blocked_calls.len, checked);
}

test "every refused call answers EPERM, and none of them kills" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    // **Two facts per call, and the second is the one this change is about.**
    // The refusal must be there, and it must not be a kill: a run time that
    // probes for a ring reads the answer and takes another road, and a killed
    // process reads nothing. Counted per call, the way the `blocked_calls`
    // tests count, so a rule missing for two of the three cannot pass on the
    // strength of the one left standing.
    var checked: usize = 0;
    for (refused_calls) |call| {
        const number: u32 = @intCast(@intFromEnum(call));
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != number) continue;
            // jt = 0 falls into the refusal on a match. jf = 1 skips exactly
            // that one instruction on no match, landing on the next check.
            try std.testing.expectEqual(@as(u8, 0), insn.jt);
            try std.testing.expectEqual(@as(u8, 1), insn.jf);
            try std.testing.expectEqual(bpf.RET_K, prog[i + 1].code);
            try std.testing.expectEqual(RET_ERRNO_PERM, prog[i + 1].k);
            try std.testing.expect(prog[i + 1].k != RET_KILL_PROCESS);
            checked += 1;
        }
    }
    try std.testing.expectEqual(refused_calls.len, checked);
}

test "the two lists share no call, so nothing is both killed and refused" {
    // **A call on both lists would be killed**, because the kill loop runs
    // first, and the refusal after it would never be reached. The filter would
    // still build and still install, and the only sign of it would be a run
    // time dying at startup. This is what says the move was a move.
    for (refused_calls) |refused| {
        for (blocked_calls) |blocked| {
            try std.testing.expect(refused != blocked);
        }
    }

    // And the three that moved really are the three io_uring calls. A list
    // that grew a fourth member needs the measurement `refused_calls` names,
    // so it fails here and a person reads why.
    try std.testing.expectEqualSlices(linux.SYS, &.{
        .io_uring_setup,
        .io_uring_enter,
        .io_uring_register,
    }, &refused_calls);
}

test "the refusal block adds only itself, and leaves the call number for the checks after it" {
    // Every check after this point reads the call number out of the
    // accumulator. An instruction here that loaded anything else would leave
    // all of them comparing the wrong value, while the filter still installed
    // and still looked correct. The same property `block_connect` is held to.
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    for (refused_calls) |call| {
        const number: u32 = @intCast(@intFromEnum(call));
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != number) continue;
            try std.testing.expectEqual(bpf.RET_K, prog[i + 1].code);
            // Two instructions and no load between them, so the next check
            // reads the call number and not a protection flag.
            try std.testing.expect(prog[i + 2].code != bpf.LD_W_ABS);
        }
    }
}

test "strict_wx off makes a shorter filter that reads no protection flag, but still reads execveat's" {
    const allocator = std.testing.allocator;
    const strict = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(strict);
    const loose = try build(allocator, .{ .strict_wx = false });
    defer allocator.free(loose);

    try std.testing.expect(strict.len > loose.len);

    // The execveat rule is a boundary, not hardening, so it is unconditional
    // and stays whether or not strict_wx does: its own AND mask, against
    // AT_EMPTY_PATH and nothing else, is the only one left once every
    // strict_wx mask (personality, shmat, and the three memory_calls) is
    // gone.
    var loose_masks: usize = 0;
    for (loose) |insn| {
        if (insn.code != bpf.ALU_AND_K) continue;
        try std.testing.expectEqual(@as(u32, 0x1000), insn.k);
        loose_masks += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), loose_masks);
}

test "the write and execute rule refuses with EPERM and does not kill" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(prog);

    // A run time that asks for a page which is writable and executable can often use a
    // different method after a failure. A kill would end the test suite of the user.
    //
    // This counts one match per call in memory_calls, the way the blocked_calls tests
    // above count. A found flag with no count would still pass if this rule were
    // missing for two of the three calls, and only checked the one call left standing.
    var checked: usize = 0;
    for (memory_calls) |call| {
        const number: u32 = @intCast(@intFromEnum(call));
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != number) continue;
            // i + 1 loads prot. i + 2 masks it. i + 3 compares the mask.
            // i + 4 returns EPERM when both write and execute bits were set.
            try std.testing.expectEqual(bpf.ALU_AND_K, prog[i + 2].code);
            try std.testing.expectEqual(bpf.JMP_JEQ_K, prog[i + 3].code);
            try std.testing.expectEqual(bpf.RET_K, prog[i + 4].code);
            try std.testing.expectEqual(RET_ERRNO_PERM, prog[i + 4].k);
            checked += 1;
        }
    }
    try std.testing.expectEqual(memory_calls.len, checked);
}

test "each write and execute block jumps over exactly its own six instructions" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(prog);

    // The outer jump enters the block on a match (jt = 0) and skips all six
    // instructions of the block on no match (jf = 6), landing on the next block's
    // own outer jump, or on the allow at the end of the filter for the last call.
    // The inner jump falls into the EPERM return on a match (jt = 0) and skips
    // exactly that one return on no match (jf = 1), landing on the restore of nr.
    // A wrong offset here would only show up in the probe test, which needs a
    // real kernel, so this test pins the offsets a unit test can check directly.
    var checked: usize = 0;
    for (memory_calls) |call| {
        const number: u32 = @intCast(@intFromEnum(call));
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != number) continue;
            try std.testing.expectEqual(@as(u8, 0), insn.jt);
            try std.testing.expectEqual(@as(u8, 6), insn.jf);

            const inner = prog[i + 3];
            try std.testing.expectEqual(bpf.JMP_JEQ_K, inner.code);
            try std.testing.expectEqual(@as(u8, 0), inner.jt);
            try std.testing.expectEqual(@as(u8, 1), inner.jf);
            checked += 1;
        }
    }
    try std.testing.expectEqual(memory_calls.len, checked);
}

test "the shmat rule refuses SHM_EXEC with EPERM and does not kill" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(prog);

    // shmat has no prot argument, so the write and execute rule above never sees
    // it. This is the separate rule that closes that gap. A kill here would end
    // the test suite of a tool that tries a shared memory segment for a reason
    // that has nothing to do with SHM_EXEC.
    const shmat_number: u32 = @intCast(@intFromEnum(linux.SYS.shmat));
    var found = false;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K or insn.k != shmat_number) continue;
        // i + 1 loads shmflg. i + 2 masks it. i + 3 compares the mask.
        // i + 4 returns EPERM when SHM_EXEC was set.
        try std.testing.expectEqual(bpf.LD_W_ABS, prog[i + 1].code);
        try std.testing.expectEqual(bpf.ALU_AND_K, prog[i + 2].code);
        try std.testing.expectEqual(bpf.JMP_JEQ_K, prog[i + 3].code);
        try std.testing.expectEqual(bpf.RET_K, prog[i + 4].code);
        try std.testing.expectEqual(RET_ERRNO_PERM, prog[i + 4].k);
        found = true;
    }
    try std.testing.expect(found);
}

test "the shmat rule jumps over exactly its own five instructions" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(prog);

    // The outer jump enters the block on a match (jt = 0) and skips all five
    // instructions of the block on no match (jf = 5), landing on the write and
    // execute rule's own first outer jump. The inner jump falls into the EPERM
    // return on a match (jt = 0) and skips exactly that one return on no match
    // (jf = 1), landing on the restore of nr.
    const shmat_number: u32 = @intCast(@intFromEnum(linux.SYS.shmat));
    var found = false;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K or insn.k != shmat_number) continue;
        try std.testing.expectEqual(@as(u8, 0), insn.jt);
        try std.testing.expectEqual(@as(u8, 5), insn.jf);

        const inner = prog[i + 3];
        try std.testing.expectEqual(bpf.JMP_JEQ_K, inner.code);
        try std.testing.expectEqual(@as(u8, 0), inner.jt);
        try std.testing.expectEqual(@as(u8, 1), inner.jf);
        found = true;
    }
    try std.testing.expect(found);
}

test "the execveat rule kills on AT_EMPTY_PATH and does not read strict_wx" {
    // Unlike shmat and the memory calls, this rule is not gated by
    // options.strict_wx: it closes a boundary, not a hardening cost, so it must
    // be present whether or not the caller turned write-and-execute off for a
    // JIT runtime.
    const allocator = std.testing.allocator;
    const execveat_number: u32 = @intCast(@intFromEnum(linux.SYS.execveat));
    const at_empty_path: u32 = 0x1000;

    inline for (.{ true, false }) |wx| {
        const prog = try build(allocator, .{ .strict_wx = wx });
        defer allocator.free(prog);

        var found = false;
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != execveat_number) continue;
            // i + 1 loads flags. i + 2 masks it to AT_EMPTY_PATH. i + 3 compares
            // the mask. i + 4 kills the process when AT_EMPTY_PATH was set: a
            // kill, and never RET_ERRNO_PERM, because a program that meant to
            // run a path-free descriptor is exactly the case this project does
            // not hand a recoverable answer to.
            try std.testing.expectEqual(bpf.LD_W_ABS, prog[i + 1].code);
            try std.testing.expectEqual(bpf.offsetOfArgLow(4), prog[i + 1].k);
            try std.testing.expectEqual(bpf.ALU_AND_K, prog[i + 2].code);
            try std.testing.expectEqual(at_empty_path, prog[i + 2].k);
            try std.testing.expectEqual(bpf.JMP_JEQ_K, prog[i + 3].code);
            try std.testing.expectEqual(at_empty_path, prog[i + 3].k);
            try std.testing.expectEqual(bpf.RET_K, prog[i + 4].code);
            try std.testing.expectEqual(RET_KILL_PROCESS, prog[i + 4].k);
            found = true;
        }
        try std.testing.expect(found);
    }
}

test "the execveat rule jumps over exactly its own five instructions" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(prog);

    const execveat_number: u32 = @intCast(@intFromEnum(linux.SYS.execveat));
    var found = false;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K or insn.k != execveat_number) continue;
        try std.testing.expectEqual(@as(u8, 0), insn.jt);
        try std.testing.expectEqual(@as(u8, 5), insn.jf);

        const inner = prog[i + 3];
        try std.testing.expectEqual(bpf.JMP_JEQ_K, inner.code);
        try std.testing.expectEqual(@as(u8, 0), inner.jt);
        try std.testing.expectEqual(@as(u8, 1), inner.jf);
        found = true;
    }
    try std.testing.expect(found);
}

test "the socket rule kills on AF_VSOCK and does not read strict_wx or block_connect" {
    // Neither option gates this: it is a boundary and not hardening, and it
    // is not about connect's own re-aim risk, so it must be present in
    // every combination of the two.
    const allocator = std.testing.allocator;
    const socket_number: u32 = @intCast(@intFromEnum(linux.SYS.socket));
    const af_vsock: u32 = 40;

    inline for (.{ true, false }) |wx| {
        inline for (.{ true, false }) |connect| {
            const prog = try build(allocator, .{ .strict_wx = wx, .block_connect = connect });
            defer allocator.free(prog);

            var found = false;
            for (prog, 0..) |insn, i| {
                if (insn.code != bpf.JMP_JEQ_K or insn.k != socket_number) continue;
                // i + 1 loads domain. i + 2 compares it to AF_VSOCK. i + 3
                // kills the process on a match: a kill, and never
                // RET_ERRNO_PERM, the same choice the execveat rule makes
                // and for the same reason.
                try std.testing.expectEqual(bpf.LD_W_ABS, prog[i + 1].code);
                try std.testing.expectEqual(bpf.offsetOfArgLow(0), prog[i + 1].k);
                try std.testing.expectEqual(bpf.JMP_JEQ_K, prog[i + 2].code);
                try std.testing.expectEqual(af_vsock, prog[i + 2].k);
                try std.testing.expectEqual(bpf.RET_K, prog[i + 3].code);
                try std.testing.expectEqual(RET_KILL_PROCESS, prog[i + 3].k);
                found = true;
            }
            try std.testing.expect(found);
        }
    }
}

test "the socket rule jumps over exactly its own four instructions" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(prog);

    const socket_number: u32 = @intCast(@intFromEnum(linux.SYS.socket));
    var found = false;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K or insn.k != socket_number) continue;
        try std.testing.expectEqual(@as(u8, 0), insn.jt);
        try std.testing.expectEqual(@as(u8, 4), insn.jf);

        const inner = prog[i + 2];
        try std.testing.expectEqual(bpf.JMP_JEQ_K, inner.code);
        try std.testing.expectEqual(@as(u8, 0), inner.jt);
        try std.testing.expectEqual(@as(u8, 1), inner.jf);
        found = true;
    }
    try std.testing.expect(found);
}

test "connect is left alone by default, and the block_connect filter refuses it with EPERM" {
    // **Both halves matter, and the first one is the one a later reader could
    // lose.** `Network.none` is what every tool call gets today, and a unix
    // socket client inside the sandbox works there. If this rule ever went on
    // for every filter, that would break with nothing naming it. Measured on
    // 2026-08-24: four tests fail when it does, and `linux/driver.zig` names
    // them. So the default must name `connect` nowhere at all.
    const allocator = std.testing.allocator;
    const connect_number: u32 = @intCast(@intFromEnum(linux.SYS.connect));

    const default = try build(allocator, .{});
    defer allocator.free(default);
    for (default) |insn| {
        try std.testing.expect(!(insn.code == bpf.JMP_JEQ_K and insn.k == connect_number));
    }

    const filtered = try build(allocator, .{ .block_connect = true });
    defer allocator.free(filtered);
    var found: usize = 0;
    for (filtered, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K or insn.k != connect_number) continue;
        // jt = 0 falls into the refusal on a match. jf = 1 skips exactly that
        // one instruction on no match. A wrong offset here either misses the
        // refusal or skips into the middle of the next check.
        try std.testing.expectEqual(@as(u8, 0), insn.jt);
        try std.testing.expectEqual(@as(u8, 1), insn.jf);
        // EPERM, and never a kill: see `Options.block_connect`. A program that
        // meets a refusal can ask the broker instead; a killed one cannot.
        try std.testing.expectEqual(bpf.RET_K, filtered[i + 1].code);
        try std.testing.expectEqual(RET_ERRNO_PERM, filtered[i + 1].k);
        try std.testing.expect(filtered[i + 1].k != RET_KILL_PROCESS);
        found += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), found);
}

test "the connect rule adds only itself, and leaves the call number for the checks after it" {
    // The rule sits in the middle of a filter whose every later check reads the
    // call number out of the accumulator. An instruction that loaded anything
    // else would leave every one of those checks comparing the wrong value, and
    // the filter would still install and still look correct.
    const allocator = std.testing.allocator;
    const without = try build(allocator, .{});
    defer allocator.free(without);
    const with = try build(allocator, .{ .block_connect = true });
    defer allocator.free(with);

    try std.testing.expectEqual(without.len + 2, with.len);

    // The filtered filter is the ordinary one with exactly two instructions put
    // in the middle of it, and every other instruction in the same order. So
    // find where the two differ, step over the two, and require the rest to
    // match again. A rule that displaced a check, changed a jump offset, or
    // reordered anything fails here.
    var at: usize = 0;
    while (at < without.len and std.meta.eql(without[at], with[at])) : (at += 1) {}
    try std.testing.expect(at < without.len);
    try std.testing.expectEqualSlices(bpf.Insn, without[at..], with[at + 2 ..]);

    // And the two that were put in are the comparison and the refusal, in that
    // order, with no load between them: every check after this point reads the
    // call number out of the accumulator, and a load here would leave all of
    // them comparing the wrong value while the filter still installed.
    const connect_number: u32 = @intCast(@intFromEnum(linux.SYS.connect));
    try std.testing.expectEqual(bpf.JMP_JEQ_K, with[at].code);
    try std.testing.expectEqual(connect_number, with[at].k);
    try std.testing.expectEqual(bpf.RET_K, with[at + 1].code);
}

test "no syscall in std.os.linux.SYS is numbered past classified_through" {
    // This only sees a syscall once Zig's standard library knows about it. A
    // kernel can gain a syscall before Zig does, and this test stays quiet
    // about it. That is a known gap, not a bug in this test.
    //
    // **This failure is not a broken test.** It means the Zig standard
    // library learned about a new syscall. Read each syscall the failure
    // names, decide whether it belongs on `blocked_calls`, and then raise
    // `classified_through` to the new highest number.
    //
    // The names are collected and compared against nothing, rather than
    // written to the terminal: `expectEqualStrings` prints both sides, so
    // the whole list is in the failure, and a test that writes to standard
    // error puts a `failed command:` line in the build log even when it
    // passes.
    const allocator = std.testing.allocator;
    const info = @typeInfo(linux.SYS).@"enum";
    var found_new: std.ArrayList(u8) = .empty;
    defer found_new.deinit(allocator);

    inline for (info.fields) |field| {
        if (field.value > classified_through) {
            try found_new.print(allocator, "{s} = {d}\n", .{ field.name, field.value });
        }
    }

    try std.testing.expectEqualStrings("", found_new.items);
}

/// Wait for one child and give back its exit code. The caller asserts on the
/// code. A signal interrupts `waitpid`, so the call is repeated on `EINTR`.
fn waitForExitCode(pid: linux.pid_t) !u32 {
    var status: u32 = undefined;
    var rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(rc));
    try std.testing.expect(linux.W.IFEXITED(status));
    return linux.W.EXITSTATUS(status);
}

/// A filter that answers `chdir` with EPERM and permits every other call.
/// `chdir` is the probe because `execute`, in `driver.zig`, calls it after the
/// real filter goes on. So a reader knows the real filter permits it, and a
/// refusal here can only come from the filter that the test installs.
fn chdirRefusedFilter() [4]bpf.Insn {
    return .{
        bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr),
        bpf.jump(bpf.JMP_JEQ_K, @intFromEnum(linux.SYS.chdir), 0, 1),
        bpf.stmt(bpf.RET_K, RET_ERRNO_PERM),
        bpf.stmt(bpf.RET_K, RET_ALLOW),
    };
}

/// Turn an `install` failure into an exit code. A child of these tests cannot
/// print: `test/proto/lock.zig` refuses a line in `lib/` that names standard
/// error, and this file obeys that rule. So the code carries the fault, and
/// the parent's own `expectEqual` prints it.
///
/// **Only `NotSupported` may skip an install failure.** Every other code below
/// is a fault on a machine that this project can run on at all. An earlier
/// version of these tests skipped on any `install` failure, and a mutation
/// that deleted the `prctl` call from `install` then turned both tests green
/// by skipping them. That is the exact shape of failure these tests exist to
/// catch.
fn installFaultCode(err: InstallError) u8 {
    return switch (err) {
        error.NotSupported => 3,
        error.Rejected => 4,
        error.NotPermitted => 5,
        error.NoNewPrivsRefused => 6,
        error.Unexpected => 7,
    };
}

// **The two tests below are the only ones in this file that call `install`.**
// Every other test reads the instructions that `build` returns. Those prove the
// filter is shaped correctly. None of them proves the kernel took it.
//
// Both tests run in a forked child, because a filter can never be removed. A
// filter on the test runner itself would stay on for every test after it.
//
// The children share these exit codes:
//   0     the child measured what the test asked for.
//   3..7  `install` failed. See `installFaultCode` for which fault each is.
//   10    the state before the measurement was not the state the test needs.
//   11    a `prctl` read failed, so the measurement is not available.
//   12    the measurement did not give the answer the test needs.

test "install turns on no_new_privs, and does not rely on a caller to do it" {
    // **A mutation that deletes the `prctl` call from `install` passes every
    // other test in this file.** `applyLayers`, in `driver.zig`, calls
    // `landlock.Ruleset.restrictSelf` first, and that call sets the same flag,
    // so the flag is already on by the time `install` runs there. This test
    // takes a child that has the flag off and measures `install` alone.
    // no_new_privs is inherited and cannot be cleared. A Nix builder can set
    // it before the test runner starts, so that environment cannot make the
    // required before-and-after measurement. Skip only that precondition. An
    // install failure in a measurable environment still fails below.
    const runner_nnp = linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(runner_nnp));
    if (runner_nnp != 0) return error.SkipZigTest;

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        const before = linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0);
        if (linux.errno(before) != .SUCCESS) std.process.exit(11);
        // Detect an unexpected state change between the parent check and the
        // measurement. This is a failure, not an environment skip.
        if (before != 0) std.process.exit(10);

        var insns = chdirRefusedFilter();
        install(bpf.Prog.init(&insns)) catch |err| std.process.exit(installFaultCode(err));

        const after = linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0);
        if (linux.errno(after) != .SUCCESS) std.process.exit(11);
        if (after != 1) std.process.exit(12);
        std.process.exit(0);
    }

    const code = try waitForExitCode(@intCast(fork_rc));
    if (code == 3) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), code);
}

test "the kernel enforces the filter that install returned success for" {
    // **`install` returning no error is not the same fact as a filter that
    // runs.** This test calls the one system call that the filter refuses, and
    // reads the errno back. It is the only check in this project that the
    // `bpf.Prog` layout, the mode number, and the argument order are all
    // correct.
    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        // The same call before the filter, so a refusal after it is the filter
        // and never the path.
        if (linux.errno(linux.chdir("/")) != .SUCCESS) std.process.exit(10);

        var insns = chdirRefusedFilter();
        install(bpf.Prog.init(&insns)) catch |err| std.process.exit(installFaultCode(err));

        if (linux.errno(linux.chdir("/")) != .PERM) std.process.exit(12);
        std.process.exit(0);
    }

    const code = try waitForExitCode(@intCast(fork_rc));
    if (code == 3) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), code);
}

test "a trap set puts a user notification return in the filter, and an empty one puts nothing" {
    // **Both halves, and the second is the one a later reader could lose.**
    // The default must stay the filter this project always built, or every
    // caller that never asked for an observation starts paying for one.
    //
    // Mutation check: delete the trap loop at the end of `build` and the
    // `observed` count here is zero.
    const allocator = std.testing.allocator;

    const plain = try build(allocator, .{});
    defer allocator.free(plain);
    for (plain) |insn| {
        try std.testing.expect(!(insn.code == bpf.RET_K and insn.k == RET_USER_NOTIF));
    }

    const watching = try build(allocator, .{ .traps = TrapSet.initMany(&.{ .openat, .execve }) });
    defer allocator.free(watching);

    var observed: usize = 0;
    for (&[_]TrapCall{ .openat, .execve }) |call| {
        const wanted: u32 = @intCast(@intFromEnum(call.number()));
        for (watching, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != wanted) continue;
            // jt = 0 falls into the notification on a match. jf = 1 skips
            // exactly that one instruction on no match, the same shape the
            // refusal loop has.
            try std.testing.expectEqual(@as(u8, 0), insn.jt);
            try std.testing.expectEqual(@as(u8, 1), insn.jf);
            try std.testing.expectEqual(bpf.RET_K, watching[i + 1].code);
            try std.testing.expectEqual(RET_USER_NOTIF, watching[i + 1].k);
            observed += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), observed);

    // A member that was not asked for is named nowhere.
    const connect_number: u32 = @intCast(@intFromEnum(linux.SYS.connect));
    for (watching) |insn| {
        try std.testing.expect(!(insn.code == bpf.JMP_JEQ_K and insn.k == connect_number));
    }
}

test "no call the handover makes can ever be trapped" {
    // **This is the deadlock guard, read at run time.** The `comptime` block
    // beside `bootstrap_calls` already stops the build on an overlap. This
    // test says the same thing where a person looking for the rule will find
    // it, and it fails for the right reason if that block is ever deleted.
    //
    // Mutation check: add `.read` to `TrapCall` and give it a `number` of
    // `.read`, and the build stops with the message `bootstrap_calls` names.
    // Delete the `comptime` block as well and this test fails instead.
    inline for (@typeInfo(TrapCall).@"enum".fields) |field| {
        const call: TrapCall = @enumFromInt(field.value);
        for (bootstrap_calls) |boot| {
            try std.testing.expect(call.number() != boot);
        }
    }
}

test "nothing on the kill list and nothing on the refusal list can be trapped" {
    // **A trapped call runs.** A configuration that turned a killed call into
    // a trapped one would take a boundary away and leave a count in its place,
    // and the filter would still build and still install. The `comptime` block
    // beside `bootstrap_calls` is what stops that. This reads it again.
    //
    // Mutation check: add `.ptrace` to `TrapCall` and the build stops.
    inline for (@typeInfo(TrapCall).@"enum".fields) |field| {
        const call: TrapCall = @enumFromInt(field.value);
        for (blocked_calls) |killed| {
            try std.testing.expect(call.number() != killed);
        }
        for (refused_calls) |refused| {
            try std.testing.expect(call.number() != refused);
        }
    }
}

test "a trapped call is never reached by a filter that already kills or refuses it" {
    // The two lists are disjoint from the trap set by construction, so this
    // checks the one overlap a runtime option can still make: `block_connect`
    // and an observed `connect`. The refusal must come first, so the call is
    // refused and never counted.
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{
        .block_connect = true,
        .traps = TrapSet.initMany(&.{.connect}),
    });
    defer allocator.free(prog);

    const connect_number: u32 = @intCast(@intFromEnum(linux.SYS.connect));
    var first_answer: ?u32 = null;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K or insn.k != connect_number) continue;
        if (first_answer == null) first_answer = prog[i + 1].k;
    }
    try std.testing.expectEqual(@as(?u32, RET_ERRNO_PERM), first_answer);
}

test "every syscall number a notification can carry maps back to the call it names" {
    inline for (@typeInfo(TrapCall).@"enum".fields) |field| {
        const call: TrapCall = @enumFromInt(field.value);
        try std.testing.expectEqual(
            @as(?TrapCall, call),
            TrapCall.fromNumber(@intCast(@intFromEnum(call.number()))),
        );
    }
    // `getppid` is on no list here. A number with no member must read as none
    // rather than as the first member.
    try std.testing.expectEqual(
        @as(?TrapCall, null),
        TrapCall.fromNumber(@intCast(@intFromEnum(linux.SYS.getppid))),
    );
}

test "the reader's filter permits its own four calls and kills the rest" {
    // **An allowlist is only an allowlist if the kernel enforces it.** The
    // list itself is checked in `linux/notify.zig`. This drives the filter the
    // list builds, in a real process, against one call it must permit and one
    // it must kill.
    //
    // A signal 31 death is the pass for the second half: the filter kills the
    // process rather than refusing the call, which is how every other denial
    // in this file behaves.
    //
    // Mutation check: make `buildReader` end with `RET_ALLOW` instead of
    // `RET_KILL_PROCESS` and the child exits 12 rather than dying.
    const allocator = std.testing.allocator;
    const insns = try buildReader(allocator);
    defer allocator.free(insns);

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        install(bpf.Prog.init(insns)) catch |err| std.process.exit(installFaultCode(err));

        // A permitted call, so a death below is the filter and not this line.
        // Zero descriptors and no timeout, which the kernel answers at once.
        var none: [0]linux.pollfd = .{};
        var instant: linux.timespec = .{ .sec = 0, .nsec = 0 };
        if (linux.errno(linux.ppoll(&none, 0, &instant, null)) != .SUCCESS) {
            std.process.exit(11);
        }

        // A call nobody put on the list. The filter kills this process here,
        // so the exit below is never reached.
        _ = linux.openat(linux.AT.FDCWD, "/", .{ .ACCMODE = .RDONLY }, 0);
        std.process.exit(12);
    }

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    if (linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 3) return error.SkipZigTest;

    try std.testing.expect(linux.W.IFSIGNALED(status));
    try std.testing.expectEqual(linux.SIG.SYS, linux.W.TERMSIG(status));
}

test "the keeper filter permits reap wait and readiness calls" {
    // Mutation check: remove wait4, ppoll, or write from keeper_calls. The
    // child then dies from SIGSYS at the missing call.
    const allocator = std.testing.allocator;
    const insns = try buildKeeper(allocator);
    defer allocator.free(insns);

    var pipe: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })));

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        install(bpf.Prog.init(insns)) catch |err| std.process.exit(installFaultCode(err));

        var status: u32 = undefined;
        const reap_rc = linux.waitpid(-1, &status, linux.W.NOHANG);
        if (linux.errno(reap_rc) != .CHILD) std.process.exit(11);

        var none: [0]linux.pollfd = .{};
        var instant: linux.timespec = .{ .sec = 0, .nsec = 0 };
        if (linux.errno(linux.ppoll(&none, 0, &instant, null)) != .SUCCESS) {
            std.process.exit(12);
        }

        const byte = [1]u8{1};
        if (linux.errno(linux.write(pipe[1], &byte, byte.len)) != .SUCCESS) {
            std.process.exit(13);
        }
        std.process.exit(0);
    }

    _ = linux.close(pipe[1]);

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    if (linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 3) return error.SkipZigTest;
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), linux.read(pipe[0], &byte, byte.len));
    _ = linux.close(pipe[0]);
}

test "the keeper filter kills a call outside its allowlist" {
    // Mutation check: end buildKeeper with RET_ALLOW. The child exits 12
    // instead of dying from SIGSYS.
    const allocator = std.testing.allocator;
    const insns = try buildKeeper(allocator);
    defer allocator.free(insns);

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        install(bpf.Prog.init(insns)) catch |err| std.process.exit(installFaultCode(err));
        _ = linux.openat(linux.AT.FDCWD, "/", .{ .ACCMODE = .RDONLY }, 0);
        std.process.exit(12);
    }

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    if (linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 3) return error.SkipZigTest;
    try std.testing.expect(linux.W.IFSIGNALED(status));
    try std.testing.expectEqual(linux.SIG.SYS, linux.W.TERMSIG(status));
}
