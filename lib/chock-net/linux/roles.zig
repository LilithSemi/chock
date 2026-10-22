//! What each helper Chock runs beside a sandbox may ask the kernel for. Palisade
//! builds the filter from these lists and refuses the escape calls itself. The
//! VMM is Chock's own subprocess and gets its filter built here.

const std = @import("std");
const linux = std.os.linux;
const palisade = @import("palisade");

const bpf = palisade.linux.bpf;
const seccomp = palisade.linux.seccomp;

/// The network router holds CAP_NET_ADMIN and a socket to the untrusted side, so
/// it opens nothing: every descriptor it uses was handed to it.
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
        .clock_gettime,
        .exit_group,
        .exit,
        .rt_sigreturn,
        .restart_syscall,
    };
    list = list ++ seccomp.wait_calls;
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

/// The device helper holds CAP_SYS_ADMIN for the mounts it makes inside its own
/// namespace. It names no path of its own: a path arrives over the channel.
/// It waits with `ppoll` directly, so `wait_calls` would widen it for nothing.
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

/// The VMM serves one filesystem and one guest. It reads and writes paths, so its
/// list is the widest of the three, and the guard below is what keeps it bounded.
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
    // Where the target has the older call, Mirage forgets its bound socket path
    // with unlink, not unlinkat.
    if (@hasField(linux.SYS, "unlink")) list = list ++ &[_]linux.SYS{.unlink};
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
    return seccomp.buildAllowlist(allocator, vmm_calls);
}
