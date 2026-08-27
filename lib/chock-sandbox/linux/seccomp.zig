const std = @import("std");
const bpf = @import("bpf.zig");
const linux = std.os.linux;

pub const RET_ALLOW: u32 = 0x7fff0000;
pub const RET_KILL_PROCESS: u32 = 0x80000000;
/// Return EPERM to the caller instead of killing it.
pub const RET_ERRNO_PERM: u32 = 0x00050000 | @as(u32, @intFromEnum(linux.E.PERM));

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
/// `io_uring_setup`, `io_uring_enter` and `io_uring_register` are here because
/// io_uring is the standard way around a syscall filter. A process puts an operation
/// in a ring, and a kernel worker does the operation, so the thread that asked never
/// makes the syscall this filter reads. A rule written here is not applied to the
/// operation at all.
///
/// **Nothing got through when this was measured.** The red team run of 2026-08-22 set
/// up a ring, opened a mounted store path through it, and tried two writes outside the
/// workspace and a `connect`. Landlock refused both writes with EACCES, and the network
/// namespace gave ENETUNREACH, because a namespace is not a filter and so has no
/// syscall for io_uring to avoid making. That result is a property of which layers
/// happen to cover the file surface and the network today. It is not a statement about
/// every operation io_uring supports, and seccomp is the only layer that covers some of
/// them. Container runtimes commonly refuse these three calls for this reason, and no
/// program a coding agent runs needs a ring.
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
    .io_uring_setup,
    .io_uring_enter,
    .io_uring_register,
};

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

    // See `Options.block_connect`. Two instructions, and neither one touches the
    // accumulator, so the call number every check below reads is still in it.
    if (options.block_connect) {
        const connect_number: u32 = @intCast(@intFromEnum(linux.SYS.connect));
        // If the number matches, fall to the refusal. If not, skip over it.
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, connect_number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
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

    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ALLOW));
    return insns.toOwnedSlice(allocator);
}

pub const InstallError = error{
    /// The kernel has no seccomp filter mode.
    NotSupported,
    /// `no_new_privs` was not set, or the filter is not valid.
    Rejected,
    Unexpected,
};

/// Install a filter on the calling thread. The filter can never be removed.
/// Call this after the fork and before the exec.
pub fn install(prog: bpf.Prog) InstallError!void {
    // Without `no_new_privs`, an unprivileged process cannot install a filter, because a
    // set-user-ID program could then be given a filter that lies to it.
    const pr = linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0);
    switch (linux.errno(pr)) {
        .SUCCESS => {},
        else => return error.Rejected,
    }

    const rc = linux.seccomp(
        linux.SECCOMP.SET_MODE_FILTER,
        0,
        @ptrCast(&prog),
    );
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        .NOSYS => error.NotSupported,
        .INVAL, .ACCES => error.Rejected,
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

test "every blocked call comparison is followed by a kill instruction" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    // A comparison that falls through to something other than RET_K with
    // RET_KILL_PROCESS would let a blocked call reach the allow at the end.
    var checked: usize = 0;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K) continue;
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
    for (prog) |insn| {
        if (insn.code != bpf.JMP_JEQ_K) continue;
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

test "strict_wx off makes a shorter filter that does not read the protection flags" {
    const allocator = std.testing.allocator;
    const strict = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(strict);
    const loose = try build(allocator, .{ .strict_wx = false });
    defer allocator.free(loose);

    try std.testing.expect(strict.len > loose.len);
    for (loose) |insn| {
        try std.testing.expect(insn.code != bpf.ALU_AND_K);
    }
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
