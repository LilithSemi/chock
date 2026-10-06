const std = @import("std");
const bpf = @import("bpf.zig");
const linux = std.os.linux;

pub const RET_ALLOW: u32 = 0x7fff0000;
pub const RET_KILL_PROCESS: u32 = 0x80000000;
pub const RET_ERRNO_PERM: u32 = 0x00050000 | @as(u32, @intFromEnum(linux.E.PERM));
pub const RET_USER_NOTIF: u32 = linux.SECCOMP.RET.USER_NOTIF;

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

pub const refused_calls = [_]linux.SYS{
    .io_uring_setup,
    .io_uring_enter,
    .io_uring_register,
};

pub const TrapCall = enum {
    openat,
    execve,
    connect,
    getdents64,

    pub fn number(self: TrapCall) linux.SYS {
        return switch (self) {
            .openat => .openat,
            .execve => .execve,
            .connect => .connect,
            .getdents64 => .getdents64,
        };
    }

    pub fn pathArg(self: TrapCall) ?u2 {
        return switch (self) {
            .openat => 1,
            .execve => 0,
            .connect, .getdents64 => null,
        };
    }

    pub fn fromNumber(nr: i64) ?TrapCall {
        inline for (@typeInfo(TrapCall).@"enum".fields) |field| {
            const call: TrapCall = @enumFromInt(field.value);
            if (@intFromEnum(call.number()) == nr) return call;
        }
        return null;
    }
};

pub const TrapSet = std.EnumSet(TrapCall);

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

pub const memory_calls = [_]linux.SYS{ .mmap, .mprotect, .pkey_mprotect };

pub const classified_through: usize = 470;

fn nativeAuditArch() u32 {
    const bit_64: u32 = 0x80000000;
    const little_endian: u32 = 0x40000000;
    return switch (@import("builtin").cpu.arch) {
        .aarch64 => 183 | bit_64 | little_endian,
        .x86_64 => 62 | bit_64 | little_endian,
        .riscv64 => 243 | bit_64 | little_endian,
        else => @compileError("chock-sandbox has no audit arch for this target"),
    };
}

pub const Options = struct {
    strict_wx: bool = true,
    block_connect: bool = false,
    traps: TrapSet = .initEmpty(),
};

pub fn build(allocator: std.mem.Allocator, options: Options) ![]bpf.Insn {
    var insns: std.ArrayList(bpf.Insn) = .empty;
    errdefer insns.deinit(allocator);

    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_arch));
    try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, nativeAuditArch(), 1, 0));
    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));

    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));

    if (@import("builtin").cpu.arch == .x86_64) {
        try insns.append(allocator, bpf.jump(bpf.JMP_JGE_K, 0x40000000, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
    }

    for (blocked_calls) |call| {
        const number: u32 = @intCast(@intFromEnum(call));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
    }

    for (refused_calls) |call| {
        const number: u32 = @intCast(@intFromEnum(call));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
    }

    if (options.block_connect) {
        const connect_number: u32 = @intCast(@intFromEnum(linux.SYS.connect));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, connect_number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
    }

    {
        // AT_EMPTY_PATH lets execveat run a memfd_create file with no path to check.
        const execveat_number: u32 = @intCast(@intFromEnum(linux.SYS.execveat));
        const at_empty_path: u32 = 0x1000;
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, execveat_number, 0, 5));
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(4)));
        try insns.append(allocator, bpf.stmt(bpf.ALU_AND_K, at_empty_path));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, at_empty_path, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
    }

    {
        const socket_number: u32 = @intCast(@intFromEnum(linux.SYS.socket));
        const af_vsock: u32 = 40;
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, socket_number, 0, 4));
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(0)));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, af_vsock, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
    }

    if (options.strict_wx) {
        {
            const personality_number: u32 = @intCast(@intFromEnum(linux.SYS.personality));
            const read_implies_exec: u32 = 0x0400000;
            const read_current: u32 = 0xffffffff;
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, personality_number, 0, 6));
            try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(0)));
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, read_current, 3, 0));
            try insns.append(allocator, bpf.stmt(bpf.ALU_AND_K, read_implies_exec));
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, read_implies_exec, 0, 1));
            try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
            try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
        }

        {
            const shmat_number: u32 = @intCast(@intFromEnum(linux.SYS.shmat));
            const shm_exec: u32 = 0x8000;
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, shmat_number, 0, 5));
            try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(2)));
            try insns.append(allocator, bpf.stmt(bpf.ALU_AND_K, shm_exec));
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, shm_exec, 0, 1));
            try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
            try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
        }

        const prot_write_exec: u32 = 0x2 | 0x4;
        for (memory_calls) |call| {
            const number: u32 = @intCast(@intFromEnum(call));
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 6));
            try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(2)));
            try insns.append(allocator, bpf.stmt(bpf.ALU_AND_K, prot_write_exec));
            try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, prot_write_exec, 0, 1));
            try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
            try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
            try insns.append(allocator, bpf.stmt(bpf.JMP_JA, 0));
        }
    }

    var traps = options.traps.iterator();
    while (traps.next()) |call| {
        const number: u32 = @intCast(@intFromEnum(call.number()));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_USER_NOTIF));
    }

    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ALLOW));
    return insns.toOwnedSlice(allocator);
}

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
    if (@hasField(linux.SYS, "poll")) list = list ++ &[_]linux.SYS{.poll};
    break :blk list;
};

comptime {
    var reads_memory = false;
    for (reader_calls) |call| {
        if (call == .process_vm_readv) reads_memory = true;
    }
    if (!reads_memory) @compileError(
        "the path reader cannot read a path without process_vm_readv. See reader_calls.",
    );
}

pub fn buildReader(allocator: std.mem.Allocator) ![]bpf.Insn {
    return buildAllowlist(allocator, reader_calls);
}

pub const keeper_calls: []const linux.SYS = &.{
    .wait4,
    .ppoll,
    .write,
    .exit_group,
    .exit,
    .rt_sigreturn,
    .restart_syscall,
};

pub fn buildKeeper(allocator: std.mem.Allocator) ![]bpf.Insn {
    return buildAllowlist(allocator, keeper_calls);
}

pub const router_calls = blk: {
    var list: []const linux.SYS = &.{
        .accept4,
        .getsockopt,
        .recvfrom,
        .sendto,
        .recvmsg,
        .sendmsg,
        .read,
        .shutdown,
        .close,
        .fcntl,
        .ppoll,
        .clock_gettime,
        .exit_group,
        .exit,
        .rt_sigreturn,
        .restart_syscall,
    };
    if (@hasField(linux.SYS, "poll")) list = list ++ &[_]linux.SYS{.poll};
    break :blk list;
};

comptime {
    for (router_calls) |call| {
        const refused = switch (call) {
            .socket, .socketpair, .connect, .bind, .listen, .openat, .execve, .kill, .ptrace => true,
            else => false,
        };
        if (refused) @compileError(
            "the network router may not open or reach anything new. See router_calls.",
        );
    }
}

pub fn buildRouter(allocator: std.mem.Allocator) ![]bpf.Insn {
    return buildAllowlist(allocator, router_calls);
}

pub const vmm_calls = blk: {
    var list: []const linux.SYS = &.{
        .ioctl,
        .accept4,
        .recvmsg,
        .sendmsg,
        .socketpair,
        .read,
        .write,
        .ppoll,
        .close,
        .fcntl,
        .shutdown,
        .openat,
        .preadv,
        .pwritev,
        .readv,
        .writev,
        .statx,
        .getdents64,
        .mkdirat,
        .unlinkat,
        .renameat,
        .symlinkat,
        .linkat,
        .readlinkat,
        .ftruncate,
        .utimensat,
        .fchmod,
        .lseek,
        .clone,
        .mprotect,
        .sigaltstack,
        .futex,
        .tgkill,
        .gettid,
        .getpid,
        .rt_sigaction,
        .rt_sigprocmask,
        .rt_sigreturn,
        .restart_syscall,
        .mmap,
        .munmap,
        .madvise,
        .brk,
        .mremap,
        .clock_gettime,
        .clock_nanosleep,
        .nanosleep,
        .exit_group,
        .exit,
    };
    if (@hasField(linux.SYS, "poll")) list = list ++ &[_]linux.SYS{.poll};
    break :blk list;
};

comptime {
    for (vmm_calls) |call| {
        const refused = switch (call) {
            .socket,
            .connect,
            .bind,
            .listen,
            .execve,
            .execveat,
            .ptrace,
            .process_vm_readv,
            .process_vm_writev,
            .io_uring_setup,
            .io_uring_enter,
            .io_uring_register,
            .bpf,
            .keyctl,
            .add_key,
            .mount,
            .umount2,
            .pivot_root,
            .init_module,
            .finit_module,
            .userfaultfd,
            .perf_event_open,
            .kexec_load,
            .setuid,
            .setgid,
            .capset,
            .unshare,
            .setns,
            .name_to_handle_at,
            .open_by_handle_at,
            => true,
            else => false,
        };
        if (refused) @compileError(
            "the VMM may not open a socket, start a program, change a namespace " ++
                "or resolve a file without naming it. See vmm_calls.",
        );
    }
}

pub const FilesystemCaller = struct {
    names: []const []const u8,
    call: ?linux.SYS,
    note: []const u8 = "",
};

pub const fs_callers = [_]FilesystemCaller{
    .{ .names = &.{ "openFileAbsolute", "openDirAbsolute", "createFileAbsolute" }, .call = .openat },
    .{ .names = &.{"readPositionalAll"}, .call = .preadv },
    .{ .names = &.{"writePositionalAll"}, .call = .pwritev },
    .{ .names = &.{"statFile"}, .call = .statx, .note = "and a file's own length" },
    .{ .names = &.{"next"}, .call = .getdents64, .note = "a directory walk" },
    .{ .names = &.{"next"}, .call = .lseek, .note = "a walk rewinding a directory" },
    .{ .names = &.{"createDirAbsolute"}, .call = .mkdirat },
    .{ .names = &.{ "deleteFile", "deleteDirAbsolute" }, .call = .unlinkat },
    .{ .names = &.{"renameAbsolute"}, .call = .renameat },
    .{ .names = &.{"symLink"}, .call = .symlinkat },
    .{ .names = &.{"hardLink"}, .call = .linkat },
    .{ .names = &.{"readLink"}, .call = .readlinkat },
    .{ .names = &.{"setLength"}, .call = .ftruncate },
    .{ .names = &.{"setTimestamps"}, .call = .utimensat },
    .{ .names = &.{"setPermissions"}, .call = .fchmod },
    .{ .names = &.{"close"}, .call = .close },
    .{
        .names = &.{"deleteTree"},
        .call = null,
        .note = "`Export`'s own test harness takes its directory down with this. " ++
            "A served filesystem has no caller for it, so it earns no grant.",
    },
};

pub fn buildVmm(allocator: std.mem.Allocator) ![]bpf.Insn {
    return buildAllowlist(allocator, vmm_calls);
}

pub const device_calls: []const linux.SYS = &.{
    .recvmsg,
    .mount,
    .umount2,
    .mkdirat,
    .mknodat,
    .ppoll,
    .write,
    .exit_group,
    .exit,
    .rt_sigreturn,
    .restart_syscall,
};

comptime {
    for (device_calls) |call| {
        const refused = switch (call) {
            .openat, .socket, .socketpair, .connect, .bind, .listen, .execve, .kill, .ptrace => true,
            else => false,
        };
        if (refused) @compileError(
            "the device helper may not open a path or make a channel. See device_calls.",
        );
    }
}

pub fn buildDevice(allocator: std.mem.Allocator) ![]bpf.Insn {
    return buildAllowlist(allocator, device_calls);
}

fn buildAllowlist(allocator: std.mem.Allocator, calls: []const linux.SYS) ![]bpf.Insn {
    var insns: std.ArrayList(bpf.Insn) = .empty;
    errdefer insns.deinit(allocator);

    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_arch));
    try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, nativeAuditArch(), 1, 0));
    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));

    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
    for (calls) |call| {
        const number: u32 = @intCast(@intFromEnum(call));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ALLOW));
    }

    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
    return insns.toOwnedSlice(allocator);
}

pub const InstallError = error{
    NotSupported,
    NoNewPrivsRefused,
    NotPermitted,
    Rejected,
    Unexpected,
};

pub fn install(prog: bpf.Prog) InstallError!void {
    _ = try setModeFilter(prog, 0);
}

pub fn installListening(prog: bpf.Prog) InstallError!i32 {
    const rc = try setModeFilter(prog, linux.SECCOMP.FILTER_FLAG.NEW_LISTENER);
    return @intCast(rc);
}

pub const InstallProbe = union(enum) {
    ok,
    refused: InstallError,
    unknown,
};

pub fn probeInstall(prog: bpf.Prog) InstallProbe {
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS) return .unknown;

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return .unknown;
    }

    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        var answer: [1]u8 = .{0};
        if (install(prog)) |_| {} else |err| answer[0] = installFaultCode(err);
        _ = linux.write(fds[1], &answer, answer.len);
        std.process.exit(0);
    }

    _ = linux.close(fds[1]);
    var answer: [1]u8 = undefined;
    var filled: usize = 0;
    while (filled < answer.len) {
        const rc = linux.read(fds[0], answer[filled..].ptr, answer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        filled += rc;
    }
    _ = linux.close(fds[0]);

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);

    if (filled != answer.len) return .unknown;
    return installProbeFor(answer[0]);
}

fn installProbeFor(answer: u8) InstallProbe {
    if (answer == 0) return .ok;
    return switch (answer) {
        3 => .{ .refused = error.NotSupported },
        4 => .{ .refused = error.Rejected },
        5 => .{ .refused = error.NotPermitted },
        6 => .{ .refused = error.NoNewPrivsRefused },
        7 => .{ .refused = error.Unexpected },
        else => .unknown,
    };
}

fn setModeFilter(prog: bpf.Prog, flags: u32) InstallError!usize {
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
        .ACCES => error.NotPermitted,
        .INVAL => error.Rejected,
        else => error.Unexpected,
    };
}

test "the filter starts by refusing a foreign architecture" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

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

    try std.testing.expectEqual(@as(u8, 0), prog[1].jf);
    try std.testing.expectEqual(bpf.RET_K, prog[2].code);
    try std.testing.expectEqual(@as(u32, RET_KILL_PROCESS), prog[2].k);
}

fn precededByArgumentLoad(prog: []const bpf.Insn, i: usize) bool {
    if (i == 0) return false;
    const before = prog[i - 1];
    return before.code == bpf.LD_W_ABS and before.k != bpf.offset_of_nr;
}

test "every blocked call comparison is followed by a kill instruction" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

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

    var checked: usize = 0;
    for (refused_calls) |call| {
        const number: u32 = @intCast(@intFromEnum(call));
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != number) continue;
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
    for (refused_calls) |refused| {
        for (blocked_calls) |blocked| {
            try std.testing.expect(refused != blocked);
        }
    }

    try std.testing.expectEqualSlices(linux.SYS, &.{
        .io_uring_setup,
        .io_uring_enter,
        .io_uring_register,
    }, &refused_calls);
}

test "the refusal block adds only itself, and leaves the call number for the checks after it" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    for (refused_calls) |call| {
        const number: u32 = @intCast(@intFromEnum(call));
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != number) continue;
            try std.testing.expectEqual(bpf.RET_K, prog[i + 1].code);
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

    var checked: usize = 0;
    for (memory_calls) |call| {
        const number: u32 = @intCast(@intFromEnum(call));
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != number) continue;
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

    const shmat_number: u32 = @intCast(@intFromEnum(linux.SYS.shmat));
    var found = false;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K or insn.k != shmat_number) continue;
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
    const allocator = std.testing.allocator;
    const execveat_number: u32 = @intCast(@intFromEnum(linux.SYS.execveat));
    const at_empty_path: u32 = 0x1000;

    inline for (.{ true, false }) |wx| {
        const prog = try build(allocator, .{ .strict_wx = wx });
        defer allocator.free(prog);

        var found = false;
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != execveat_number) continue;
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
        try std.testing.expectEqual(@as(u8, 0), insn.jt);
        try std.testing.expectEqual(@as(u8, 1), insn.jf);
        try std.testing.expectEqual(bpf.RET_K, filtered[i + 1].code);
        try std.testing.expectEqual(RET_ERRNO_PERM, filtered[i + 1].k);
        try std.testing.expect(filtered[i + 1].k != RET_KILL_PROCESS);
        found += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), found);
}

test "the connect rule adds only itself, and leaves the call number for the checks after it" {
    const allocator = std.testing.allocator;
    const without = try build(allocator, .{});
    defer allocator.free(without);
    const with = try build(allocator, .{ .block_connect = true });
    defer allocator.free(with);

    try std.testing.expectEqual(without.len + 2, with.len);

    var at: usize = 0;
    while (at < without.len and std.meta.eql(without[at], with[at])) : (at += 1) {}
    try std.testing.expect(at < without.len);
    try std.testing.expectEqualSlices(bpf.Insn, without[at..], with[at + 2 ..]);

    const connect_number: u32 = @intCast(@intFromEnum(linux.SYS.connect));
    try std.testing.expectEqual(bpf.JMP_JEQ_K, with[at].code);
    try std.testing.expectEqual(connect_number, with[at].k);
    try std.testing.expectEqual(bpf.RET_K, with[at + 1].code);
}

test "no syscall in std.os.linux.SYS is numbered past classified_through" {
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

fn waitForExitCode(pid: linux.pid_t) !u32 {
    var status: u32 = undefined;
    var rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(rc));
    try std.testing.expect(linux.W.IFEXITED(status));
    return linux.W.EXITSTATUS(status);
}

fn chdirRefusedFilter() [4]bpf.Insn {
    return .{
        bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr),
        bpf.jump(bpf.JMP_JEQ_K, @intFromEnum(linux.SYS.chdir), 0, 1),
        bpf.stmt(bpf.RET_K, RET_ERRNO_PERM),
        bpf.stmt(bpf.RET_K, RET_ALLOW),
    };
}

fn installFaultCode(err: InstallError) u8 {
    return switch (err) {
        error.NotSupported => 3,
        error.Rejected => 4,
        error.NotPermitted => 5,
        error.NoNewPrivsRefused => 6,
        error.Unexpected => 7,
    };
}

test "the install probe answers about the machine and never about a child that said nothing" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const insns = try build(allocator, .{});
    defer allocator.free(insns);

    try std.testing.expectEqual(InstallProbe.ok, probeInstall(bpf.Prog.init(insns)));

    try std.testing.expectEqual(InstallProbe.ok, installProbeFor(0));
    try std.testing.expectEqual(
        InstallProbe{ .refused = error.NotSupported },
        installProbeFor(3),
    );
    try std.testing.expectEqual(InstallProbe.unknown, installProbeFor(200));
}

test "install turns on no_new_privs, and does not rely on a caller to do it" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const runner_nnp = linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(runner_nnp));
    if (runner_nnp != 0) return error.SkipZigTest;

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        const before = linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0);
        if (linux.errno(before) != .SUCCESS) std.process.exit(11);
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
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
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
            try std.testing.expectEqual(@as(u8, 0), insn.jt);
            try std.testing.expectEqual(@as(u8, 1), insn.jf);
            try std.testing.expectEqual(bpf.RET_K, watching[i + 1].code);
            try std.testing.expectEqual(RET_USER_NOTIF, watching[i + 1].k);
            observed += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), observed);

    const connect_number: u32 = @intCast(@intFromEnum(linux.SYS.connect));
    for (watching) |insn| {
        try std.testing.expect(!(insn.code == bpf.JMP_JEQ_K and insn.k == connect_number));
    }
}

test "no call the handover makes can ever be trapped" {
    inline for (@typeInfo(TrapCall).@"enum".fields) |field| {
        const call: TrapCall = @enumFromInt(field.value);
        for (bootstrap_calls) |boot| {
            try std.testing.expect(call.number() != boot);
        }
    }
}

test "nothing on the kill list and nothing on the refusal list can be trapped" {
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
    try std.testing.expectEqual(
        @as(?TrapCall, null),
        TrapCall.fromNumber(@intCast(@intFromEnum(linux.SYS.getppid))),
    );
}

test "the reader's filter permits its own four calls and kills the rest" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const insns = try buildReader(allocator);
    defer allocator.free(insns);

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        install(bpf.Prog.init(insns)) catch |err| std.process.exit(installFaultCode(err));

        var none: [0]linux.pollfd = .{};
        var instant: linux.timespec = .{ .sec = 0, .nsec = 0 };
        if (linux.errno(linux.ppoll(&none, 0, &instant, null)) != .SUCCESS) {
            std.process.exit(11);
        }

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
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

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
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

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

test "the router's filter permits the calls its loop makes and kills the rest" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const insns = try buildRouter(allocator);
    defer allocator.free(insns);

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        install(bpf.Prog.init(insns)) catch |err| std.process.exit(installFaultCode(err));

        var none: [0]linux.pollfd = .{};
        var instant: linux.timespec = .{ .sec = 0, .nsec = 0 };
        if (linux.errno(linux.ppoll(&none, 0, &instant, null)) != .SUCCESS) {
            std.process.exit(11);
        }

        var now: linux.timespec = undefined;
        if (linux.errno(linux.clock_gettime(.BOOTTIME, &now)) != .SUCCESS) {
            std.process.exit(12);
        }

        _ = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
        std.process.exit(13);
    }

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    if (linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 3) return error.SkipZigTest;

    try std.testing.expect(linux.W.IFSIGNALED(status));
    try std.testing.expectEqual(linux.SIG.SYS, linux.W.TERMSIG(status));
}

test "the router may not open a path, run a program, or write to a descriptor" {
    const forbidden = [_]linux.SYS{ .openat, .execve, .write, .socket, .connect, .ptrace, .kill };
    for (forbidden) |call| {
        for (router_calls) |permitted| {
            try std.testing.expect(call != permitted);
        }
    }

    const needed = [_]linux.SYS{ .accept4, .getsockopt, .recvfrom, .sendto, .recvmsg, .sendmsg, .read, .close };
    for (needed) |call| {
        var found = false;
        for (router_calls) |permitted| {
            if (call == permitted) found = true;
        }
        try std.testing.expect(found);
    }
}

test "the device helper's filter permits the calls it needs and kills the rest" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const insns = try buildDevice(allocator);
    defer allocator.free(insns);

    var pipe_fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&pipe_fds, .{})));
    defer _ = linux.close(pipe_fds[0]);

    const message = "ok";
    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        install(bpf.Prog.init(insns)) catch |err| std.process.exit(installFaultCode(err));

        var none: [0]linux.pollfd = .{};
        var instant: linux.timespec = .{ .sec = 0, .nsec = 0 };
        if (linux.errno(linux.ppoll(&none, 0, &instant, null)) != .SUCCESS) {
            std.process.exit(11);
        }

        const written = linux.write(pipe_fds[1], message.ptr, message.len);
        if (written != message.len) std.process.exit(12);

        _ = linux.openat(linux.AT.FDCWD, "/", .{ .ACCMODE = .RDONLY }, 0);
        std.process.exit(13);
    }

    _ = linux.close(pipe_fds[1]);
    var buf: [message.len]u8 = undefined;
    const read_back = linux.read(pipe_fds[0], &buf, buf.len);
    try std.testing.expectEqual(@as(usize, message.len), read_back);
    try std.testing.expectEqualStrings(message, buf[0..read_back]);

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    if (linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 3) return error.SkipZigTest;

    try std.testing.expect(linux.W.IFSIGNALED(status));
    try std.testing.expectEqual(linux.SIG.SYS, linux.W.TERMSIG(status));
}

test "the device helper may not open a path or make a new channel" {
    const forbidden = [_]linux.SYS{ .openat, .socket };
    for (forbidden) |call| {
        for (device_calls) |permitted| {
            try std.testing.expect(call != permitted);
        }
    }

    const needed = [_]linux.SYS{ .recvmsg, .mount, .umount2, .mkdirat, .mknodat, .ppoll, .write };
    for (needed) |call| {
        var found = false;
        for (device_calls) |permitted| {
            if (call == permitted) found = true;
        }
        try std.testing.expect(found);
    }
}

test "the VMM allow list holds every call a guest's filesystem answers with" {
    const allocator = std.testing.allocator;
    var wrong: std.ArrayList(u8) = .empty;
    defer wrong.deinit(allocator);

    for (fs_callers) |each| {
        const call = each.call orelse continue;
        var found = false;
        for (vmm_calls) |permitted| {
            if (permitted == call) found = true;
        }
        if (!found) try wrong.print(
            allocator,
            "`Export` reaches {t} through {s}, and the VMM allow list does not hold it\n",
            .{ call, each.names[0] },
        );
    }

    for ([_]linux.SYS{ .pread64, .pwrite64, .renameat2 }) |call| {
        for (vmm_calls) |permitted| {
            if (permitted == call) try wrong.print(allocator, "the VMM allow list holds {t}, which nothing reaches\n", .{call});
        }
    }

    try std.testing.expectEqualStrings("", wrong.items);
}

test "the VMM allow list holds the hypervisor and the channels it was handed" {
    const allocator = std.testing.allocator;
    var missing: std.ArrayList(u8) = .empty;
    defer missing.deinit(allocator);

    for ([_]linux.SYS{
        .ioctl, .accept4,     .recvmsg, .sendmsg, .socketpair,
        .fcntl, .read,        .write,   .ppoll,   .shutdown,
        .clone, .sigaltstack, .futex,   .tgkill,  .mmap,
    }) |call| {
        var found = false;
        for (vmm_calls) |permitted| {
            if (permitted == call) found = true;
        }
        if (!found) try missing.print(allocator, "the VMM allow list does not hold {t}\n", .{call});
    }

    try std.testing.expectEqualStrings("", missing.items);
}

test "the VMM allow list holds the streaming pair a console that is not a file needs" {
    const allocator = std.testing.allocator;
    var missing: std.ArrayList(u8) = .empty;
    defer missing.deinit(allocator);

    for ([_]linux.SYS{ .readv, .writev }) |call| {
        var found = false;
        for (vmm_calls) |permitted| {
            if (permitted == call) found = true;
        }
        if (!found) try missing.print(
            allocator,
            "the VMM allow list does not hold {t}, so a console that is a pipe kills the guest\n",
            .{call},
        );
    }

    try std.testing.expectEqualStrings("", missing.items);
}

test "the VMM filter is an allowlist that ends in a kill" {
    const insns = try buildVmm(std.testing.allocator);
    defer std.testing.allocator.free(insns);

    try std.testing.expect(insns.len > vmm_calls.len);
    try std.testing.expectEqual(RET_KILL_PROCESS, insns[insns.len - 1].k);
}
