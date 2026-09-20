//! The Linux driver for chock-sandbox. `spawn` puts the sandbox's layers in a
//! fixed order and then runs the program. The order is not free to change: see
//! the comment above `enterNamespaces`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const landlock = @import("landlock.zig");
const namespace = @import("namespace.zig");
const capabilities = @import("capabilities.zig");
const seccomp = @import("seccomp.zig");
const notify = @import("notify.zig");
const bpf = @import("bpf.zig");
const rlimits = @import("rlimits.zig");
const cgroup = @import("cgroup.zig");
const netbroker = @import("netbroker.zig");
const routerlink = @import("routerlink.zig");
const router = @import("router.zig");
const devicelink = @import("devicelink.zig");
const netns = @import("netns.zig");
const nftables = @import("nftables.zig");
const iface = @import("../Sandbox.zig");
const Config = iface.Config;
const SetupError = iface.SetupError;
const SpawnError = iface.SpawnError;
const LandlockReport = iface.LandlockReport;
const LimitsReport = iface.LimitsReport;

/// Two `spawn` calls can be inside `Cgroup.create` at once, and two directories
/// with one name is two callers writing limits into one cgroup.
var cgroup_seed: std.atomic.Value(u64) = .init(0);

pub const guarantees: iface.Guarantees = iface.Guarantees.initMany(&.{
    .network_isolated,
    .signal_isolated,
    .ipc_isolated,
    .path_restricted,
    .syscall_restricted,
    .workspace_mounted,
});

const SetupStep = enum(u8) {
    stdin_redirect,
    process_group,
    close_fds,
    cgroup_join,
    resource_limits,
    namespace,
    network,
    device,
    scratch_mount,
    mount_tree,
    pivot,
    capabilities,
    landlock_init,
    landlock_rule,
    landlock_restrict,
    session_keyring,
    seccomp_install,
    notify_handover,
    fork,
    pdeathsig_pidfd,
    pdeathsig_prctl,
    exec,
};

const setup_failure_magic: u32 = 0x314B4843;

const SetupFailureRecord = extern struct {
    magic: u32 = setup_failure_magic,
    step: u8,
    errno: i32,
};

fn seccompOptionsFor(
    base: seccomp.Options,
    network: namespace.Network,
    hands_host_descriptor: bool,
) seccomp.Options {
    var options = base;
    options.block_connect = switch (network) {
        .none, .host => false,
        // Keyed on the descriptor and not on the mode. A connected descriptor made
        // in the host's own network namespace can be aimed somewhere else with
        // `connect`, and only `net_broker` hands one over.
        .filtered => hands_host_descriptor,
    };
    return options;
}

test "the filter for a mode is the caller's own, and only a filtered call has connect taken away" {
    try std.testing.expectEqual(false, seccompOptionsFor(.{}, .none, true).block_connect);
    try std.testing.expectEqual(false, seccompOptionsFor(.{}, .host, true).block_connect);
    try std.testing.expectEqual(true, seccompOptionsFor(.{}, .filtered, true).block_connect);

    try std.testing.expectEqual(false, seccompOptionsFor(.{}, .filtered, false).block_connect);

    for (std.enums.values(namespace.Network)) |network| {
        for ([_]bool{ false, true }) |hands| {
            const relaxed = seccompOptionsFor(.{ .strict_wx = false }, network, hands);
            try std.testing.expectEqual(false, relaxed.strict_wx);
        }
    }

    try std.testing.expectEqual(
        false,
        seccompOptionsFor(.{ .block_connect = true }, .none, true).block_connect,
    );
    try std.testing.expectEqual(
        false,
        seccompOptionsFor(.{ .block_connect = true }, .filtered, false).block_connect,
    );
}

test "the filter the default config gets is the filter a caller with no options gets" {
    const allocator = std.testing.allocator;

    const plain = try seccomp.build(allocator, .{});
    defer allocator.free(plain);

    const default_network = (Config{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    }).network;
    const defaulted = try seccomp.build(allocator, seccompOptionsFor(.{}, default_network, true));
    defer allocator.free(defaulted);

    try std.testing.expectEqualSlices(bpf.Insn, plain, defaulted);
}

/// Whether `kernel` can create a child inside the cgroup `containment` names.
/// `best_effort` promises nothing a kernel can take away; `supplied` needs
/// `CLONE_INTO_CGROUP`.
fn placementIsPossible(kernel: rlimits.Release, containment: iface.Containment) bool {
    return switch (containment) {
        .best_effort => true,
        .supplied => kernel.atLeast(cgroup.clone_into_cgroup_since),
    };
}

test "a caller supplied cgroup is refused below 5.7, and chock's own cgroup is refused on no kernel" {
    // 5.7 added `CLONE_INTO_CGROUP`. `clone3` itself is older, at 5.3, so the
    // flag is the only number to compare against.
    const supplied = iface.Containment{ .supplied = .{ .fd = 7 } };

    try std.testing.expect(!placementIsPossible(.{ .major = 4, .minor = 19 }, supplied));
    try std.testing.expect(!placementIsPossible(.{ .major = 5, .minor = 3 }, supplied));
    try std.testing.expect(!placementIsPossible(.{ .major = 5, .minor = 6 }, supplied));
    try std.testing.expect(placementIsPossible(.{ .major = 5, .minor = 7 }, supplied));
    try std.testing.expect(placementIsPossible(.{ .major = 6, .minor = 18 }, supplied));

    // A kernel this file could not read reads as 0.0, so an unreadable `uname` refuses.
    try std.testing.expect(!placementIsPossible(.{ .major = 0, .minor = 0 }, supplied));

    for ([_]rlimits.Release{
        .{ .major = 0, .minor = 0 },
        .{ .major = 4, .minor = 19 },
        .{ .major = 5, .minor = 6 },
        .{ .major = 6, .minor = 18 },
    }) |kernel| {
        try std.testing.expect(placementIsPossible(kernel, .best_effort));
    }
}

/// Start a program in the sandbox and wait for it.
///
/// Call this from a single threaded process. `fork` carries only the calling
/// thread, so a lock another thread held, such as the allocator's, is copied in
/// as held with nothing left to release it: the seccomp filter is therefore
/// built before the fork. One signal to the process `middle` names ends every
/// process of the call, through the pdeathsig chain and `cgroup.kill`, and
/// either mechanism alone is enough.
pub fn spawn(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    landlock_report: ?*LandlockReport,
    middle: ?*iface.Middle,
) SpawnError!std.process.Child.Term {
    // A filtered config with nobody to ask would come up as an ordinary `.none`
    // sandbox. This is also why `.filtered` cannot become the default: a default
    // cannot supply a broker.
    switch (config.network) {
        .filtered => {
            if (config.net_broker == null and config.net_router == null)
                return error.NetBrokerMissing;
            // The two want opposite things from one seccomp rule: the broker needs
            // `connect` refused, because it hands a descriptor from the host's own
            // network namespace across, and the router needs it permitted.
            if (config.net_broker != null and config.net_router != null)
                return error.NetRouterAndBroker;
        },
        .none, .host => {
            if (config.net_broker != null) return error.NetBrokerNotFiltered;
            if (config.net_router != null) return error.NetRouterNotFiltered;
        },
    }

    if (config.device_source != null and config.device_tree == null)
        return error.DeviceSourceNeedsTree;

    const routed = config.net_router != null;

    const kernel = rlimits.runningKernel();

    // The only other way into a cgroup is a write to `cgroup.procs` after the
    // fork, which leaves the child outside the caller's cgroup until it reaches
    // that write.
    if (!placementIsPossible(kernel, config.containment)) return error.CgroupPlacementUnsupported;

    const abi = landlock.probeAbi() catch return error.LandlockUnavailable;
    if (landlock_report) |report| report.* = .{ .abi = abi, .features = landlock.featuresFor(abi) };

    // The one layer this driver decides for itself. A process the netbroker
    // serves is handed a connected descriptor, which really can be aimed
    // somewhere else with `connect`. A routed call keeps `connect`, because the
    // kernel's own ruleset judges the address.
    const seccomp_options = seccompOptionsFor(config.seccomp_options, config.network, !routed);

    // Built in the parent, before the fork, so one less allocating step runs
    // between fork and exec. The supervisor never gets the trap instructions: a
    // filter that returns `RET_USER_NOTIF` with no listener makes the kernel
    // answer the call with `ENOSYS`.
    var middle_options = seccomp_options;
    middle_options.traps = .initEmpty();
    const insns = seccomp.build(allocator, middle_options) catch |err| return err;
    defer allocator.free(insns);

    const watching = seccomp_options.traps.count() != 0;
    const child_insns = if (watching)
        seccomp.build(allocator, seccomp_options) catch |err| return err
    else
        insns;
    defer if (watching) allocator.free(child_insns);

    const recording = watching and config.path_audit;
    const reader_insns = if (recording)
        seccomp.buildReader(allocator) catch |err| return err
    else
        &[_]bpf.Insn{};
    defer if (recording) allocator.free(reader_insns);

    const router_insns = if (routed)
        seccomp.buildRouter(allocator) catch |err| return err
    else
        &[_]bpf.Insn{};
    defer if (routed) allocator.free(router_insns);

    const wants_device = config.device_source != null;
    const device_insns = if (wants_device)
        seccomp.buildDevice(allocator) catch |err| return err
    else
        &[_]bpf.Insn{};
    defer if (wants_device) allocator.free(device_insns);

    const keeper_insns = seccomp.buildKeeper(allocator) catch |err| return err;
    defer allocator.free(keeper_insns);

    // A fork copies the whole address space, so this list is at the same address
    // in R. Not the shared page, which B inherits and gives up in `applyLayers`.
    const granted: []const []const u8 = if (recording)
        iface.grantPrefixes(allocator, config) catch |err| return err
    else
        &.{};
    defer if (recording) allocator.free(granted);

    // Best effort: a machine with no cgroup v2 tree still gets every rlimit, and
    // `group.support` is what stops a caller believing in a bound that is not
    // there. Nothing here runs for a caller supplied cgroup, because a second
    // writer is how two numbers disagree.
    var group: cgroup.Cgroup = switch (config.containment) {
        .best_effort => if (config.limits.wantsCgroup())
            cgroup.Cgroup.create(
                config.limits.memory_bytes,
                config.limits.processes,
                cgroup_seed.fetchAdd(1, .monotonic),
            )
        else
            .{ .support = .off },
        .supplied => .{ .support = .supplied },
    };
    defer group.destroy();

    if (config.limits_report) |report| report.* = .{
        .limits = config.limits,
        .cgroup = group.support,
        .nproc_applied = config.limits.processes != null and
            kernel.atLeast(rlimits.nproc_per_user_namespace_since),
    };

    // Every failure path from here to `execve` writes a record on this pipe and
    // ends its own process. A successful `execve` closes the write end through
    // CLOEXEC with nothing written.
    var pipe_fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&pipe_fds, .{ .CLOEXEC = true })) != .SUCCESS) return error.Unexpected;
    const read_fd = pipe_fds[0];
    const write_fd = pipe_fds[1];

    // A second pipe rather than more records on the setup pipe: a writer that
    // stayed open past `execve` would hold that read open for the whole call.
    var middle_pipe: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&middle_pipe, .{ .CLOEXEC = true })) != .SUCCESS) {
        _ = linux.close(read_fd);
        _ = linux.close(write_fd);
        return error.Unexpected;
    }
    const middle_read_fd = middle_pipe[0];
    const middle_write_fd = middle_pipe[1];

    // `execute` clears close-on-exec on the child's end in the last step before
    // `execve`, so a sandbox that failed to come up never hands a program a
    // channel out.
    var broker_fds: [2]i32 = .{ -1, -1 };
    var router_fds: [2]i32 = .{ -1, -1 };
    if (routed) {
        router_fds = routerlink.makePair() catch {
            _ = linux.close(read_fd);
            _ = linux.close(write_fd);
            _ = linux.close(middle_read_fd);
            _ = linux.close(middle_write_fd);
            return error.NetBrokerSocketFailed;
        };
    }
    errdefer closeBrokerPair(&router_fds);

    if (config.net_broker != null) {
        broker_fds = netbroker.makePair() catch {
            _ = linux.close(read_fd);
            _ = linux.close(write_fd);
            _ = linux.close(middle_read_fd);
            _ = linux.close(middle_write_fd);
            return error.NetBrokerSocketFailed;
        };
    }

    var device_fds: [2]i32 = .{ -1, -1 };
    if (wants_device) {
        device_fds = devicelink.makePair() catch {
            _ = linux.close(read_fd);
            _ = linux.close(write_fd);
            _ = linux.close(middle_read_fd);
            _ = linux.close(middle_write_fd);
            return error.DeviceSourceSocketFailed;
        };
    }
    errdefer closeBrokerPair(&device_fds);

    // Given up by B before B applies a single layer, so the observed program
    // never holds a mapping it could write a forged count into.
    const path_record: ?*notify.PathRecord = if (recording) mapPathRecord() else null;
    defer if (path_record) |record| unmapPathRecord(record);

    // A supplied cgroup is not joined after the fork: the child is created inside
    // it, so there is no instant at which it exists anywhere else. The plain
    // `fork` stays on the best effort path, which has to work where `clone3` is refused.
    const fork_rc = switch (config.containment) {
        .best_effort => linux.fork(),
        .supplied => |supplied| cgroup.forkInto(supplied.fd),
    };
    if (linux.errno(fork_rc) != .SUCCESS) {
        _ = linux.close(read_fd);
        _ = linux.close(write_fd);
        _ = linux.close(middle_read_fd);
        _ = linux.close(middle_write_fd);
        closeBrokerPair(&broker_fds);
        closeBrokerPair(&router_fds);
        return switch (config.containment) {
            .best_effort => error.Unexpected,
            .supplied => error.CgroupPlacementRefused,
        };
    }
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        _ = linux.close(read_fd);
        _ = linux.close(middle_read_fd);
        if (broker_fds[0] >= 0) {
            _ = linux.close(broker_fds[0]);
            broker_fds[0] = -1;
        }
        if (router_fds[0] >= 0) {
            _ = linux.close(router_fds[0]);
            router_fds[0] = -1;
        }
        if (device_fds[0] >= 0) {
            _ = linux.close(device_fds[0]);
            device_fds[0] = -1;
        }

        resetSignalState();
        newProcessGroup(write_fd, config.stderr_fd);

        // Before anything closes a descriptor and before any namespace: moving this
        // process moves every process it goes on to make. A supplied cgroup is never
        // joined here, because a join would give a caller the window the placement
        // exists to close.
        switch (config.containment) {
            .best_effort => joinCgroup(&group, write_fd, config.stderr_fd),
            .supplied => {},
        }

        redirectStdinToDevNull(write_fd, config.stderr_fd);
        // `device_fds[1]` is its own argument and never folded into the `@max` above:
        // a device source is exclusive with neither seam, so the `@max` trick would
        // silently drop whichever pair was smaller.
        enterNamespaces(
            config,
            write_fd,
            middle_write_fd,
            @max(broker_fds[1], router_fds[1]),
            device_fds[1],
        );

        // A holds `CAP_NET_ADMIN` in the user namespace that owns this network
        // namespace, which is the one moment either call can be made. With it still
        // held a flush of this table succeeds and every rule below becomes advice, so
        // B drops it and N keeps it alone.
        var table_session: nftables.Session = .{ .fd = -1 };
        if (routed) table_session = buildNetwork(write_fd, config.stderr_fd);

        // Mounted in A and not in B: A has to hold a descriptor on each area, and B
        // pivots into the new root and then denies itself every path. A mount made
        // here is in the same mount namespace B inherits.
        const areas = mountScratchAreas(config, write_fd);

        var notify_fds: [2]i32 = .{ -1, -1 };
        if (watching) {
            const pair_rc = linux.socketpair(
                linux.AF.UNIX,
                linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
                0,
                &notify_fds,
            );
            if (linux.errno(pair_rc) != .SUCCESS) {
                dieErrno(
                    write_fd,
                    config.stderr_fd,
                    .fork,
                    "socketpair for the notification handover",
                    linux.errno(pair_rc),
                );
            }
        }

        // `unshare(CLONE_NEWPID)` never moves its caller, so A stays outside the new
        // pid namespace and the first child becomes process 1. A opens a pidfd on
        // itself because B cannot: `pidfd_open` needs a pid number in the caller's own
        // namespace, and A's means nothing inside B's.
        const middle_pidfd_rc = linux.pidfd_open(linux.getpid(), 0);
        if (linux.errno(middle_pidfd_rc) != .SUCCESS) {
            dieErrno(
                write_fd,
                config.stderr_fd,
                .pdeathsig_pidfd,
                "pidfd_open",
                linux.errno(middle_pidfd_rc),
            );
        }
        const middle_pidfd: i32 = @intCast(middle_pidfd_rc);

        var keeper_fds: [2]i32 = undefined;
        const keeper_pair_rc = linux.socketpair(
            linux.AF.UNIX,
            linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
            0,
            &keeper_fds,
        );
        if (linux.errno(keeper_pair_rc) != .SUCCESS) {
            dieErrno(
                write_fd,
                config.stderr_fd,
                .fork,
                "socketpair for the pid namespace keeper",
                linux.errno(keeper_pair_rc),
            );
        }

        const keeper_fork_rc = linux.fork();
        if (linux.errno(keeper_fork_rc) != .SUCCESS) {
            die(write_fd, config.stderr_fd, .fork, error.Unexpected);
        }
        const keeper_pid: linux.pid_t = @intCast(keeper_fork_rc);
        if (keeper_pid == 0) {
            _ = linux.close(keeper_fds[0]);
            runKeeper(keeper_fds[1], middle_pidfd, write_fd, config.stderr_fd, keeper_insns);
        }

        _ = linux.close(keeper_fds[1]);
        keeper_fds[1] = -1;
        var keeper_ready: [1]u8 = undefined;
        var keeper_read_rc = linux.read(keeper_fds[0], &keeper_ready, keeper_ready.len);
        while (linux.errno(keeper_read_rc) == .INTR) {
            keeper_read_rc = linux.read(keeper_fds[0], &keeper_ready, keeper_ready.len);
        }
        if (linux.errno(keeper_read_rc) != .SUCCESS or keeper_read_rc != keeper_ready.len or
            keeper_ready[0] != 1)
        {
            die(write_fd, config.stderr_fd, .fork, error.Unexpected);
        }

        // N is a child of A, because every child A makes after `unshare(CLONE_NEWPID)`
        // is inside the namespace and only A can reap it. It comes before B, because a
        // connection made before N has bound the relay port is rewritten to a port
        // nothing holds and answered `ECONNREFUSED`.
        var router_pid: linux.pid_t = -1;
        var router_control_fd: i32 = -1;
        if (routed) {
            var router_ready_fds: [2]i32 = undefined;
            const router_pair_rc = linux.socketpair(
                linux.AF.UNIX,
                linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
                0,
                &router_ready_fds,
            );
            if (linux.errno(router_pair_rc) != .SUCCESS) {
                dieErrno(
                    write_fd,
                    config.stderr_fd,
                    .fork,
                    "socketpair for the network router",
                    linux.errno(router_pair_rc),
                );
            }

            const router_fork_rc = linux.fork();
            if (linux.errno(router_fork_rc) != .SUCCESS) {
                die(write_fd, config.stderr_fd, .fork, error.Unexpected);
            }
            if (router_fork_rc == 0) {
                _ = linux.close(router_ready_fds[0]);
                _ = linux.close(keeper_fds[0]);
                if (notify_fds[0] >= 0) _ = linux.close(notify_fds[0]);
                if (notify_fds[1] >= 0) _ = linux.close(notify_fds[1]);
                if (path_record) |record| unmapPathRecord(record);
                runRouter(
                    router_ready_fds[1],
                    router_fds[1],
                    table_session,
                    middle_pidfd,
                    router_insns,
                    write_fd,
                    config.stderr_fd,
                );
            }
            router_pid = @intCast(router_fork_rc);

            _ = linux.close(router_ready_fds[1]);
            var router_ready: [1]u8 = undefined;
            var router_read_rc = linux.read(router_ready_fds[0], &router_ready, router_ready.len);
            while (linux.errno(router_read_rc) == .INTR) {
                router_read_rc = linux.read(router_ready_fds[0], &router_ready, router_ready.len);
            }
            if (linux.errno(router_read_rc) != .SUCCESS or router_read_rc != router_ready.len or
                router_ready[0] != 1)
            {
                die(write_fd, config.stderr_fd, .network, error.Unexpected);
            }
            router_control_fd = router_ready_fds[0];

            _ = linux.close(router_fds[1]);
            router_fds[1] = -1;
            table_session.close();
            table_session = .{ .fd = -1 };
        }

        // D comes before B, because a program that asks for a path before D is
        // confined and listening would race it.
        var device_pid: linux.pid_t = -1;
        var device_control_fd: i32 = -1;
        if (wants_device) {
            var device_ready_fds: [2]i32 = undefined;
            const device_pair_rc = linux.socketpair(
                linux.AF.UNIX,
                linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
                0,
                &device_ready_fds,
            );
            if (linux.errno(device_pair_rc) != .SUCCESS) {
                dieErrno(
                    write_fd,
                    config.stderr_fd,
                    .fork,
                    "socketpair for the device helper",
                    linux.errno(device_pair_rc),
                );
            }

            const device_fork_rc = linux.fork();
            if (linux.errno(device_fork_rc) != .SUCCESS) {
                die(write_fd, config.stderr_fd, .fork, error.Unexpected);
            }
            if (device_fork_rc == 0) {
                _ = linux.close(device_ready_fds[0]);
                _ = linux.close(keeper_fds[0]);
                if (notify_fds[0] >= 0) _ = linux.close(notify_fds[0]);
                if (notify_fds[1] >= 0) _ = linux.close(notify_fds[1]);
                if (path_record) |record| unmapPathRecord(record);
                runDevice(
                    device_ready_fds[1],
                    device_fds[1],
                    config.root,
                    config.device_tree.?.host,
                    config.device_tree.?.inside,
                    middle_pidfd,
                    device_insns,
                    write_fd,
                    config.stderr_fd,
                );
            }
            device_pid = @intCast(device_fork_rc);

            _ = linux.close(device_ready_fds[1]);
            var device_ready: [1]u8 = undefined;
            var device_read_rc = linux.read(device_ready_fds[0], &device_ready, device_ready.len);
            while (linux.errno(device_read_rc) == .INTR) {
                device_read_rc = linux.read(device_ready_fds[0], &device_ready, device_ready.len);
            }
            if (linux.errno(device_read_rc) != .SUCCESS or device_read_rc != device_ready.len or
                device_ready[0] != 1)
            {
                die(write_fd, config.stderr_fd, .device, error.Unexpected);
            }
            device_control_fd = device_ready_fds[0];

            _ = linux.close(device_fds[1]);
            device_fds[1] = -1;
        }

        const inner_fork_rc = linux.fork();
        if (linux.errno(inner_fork_rc) != .SUCCESS) {
            die(write_fd, config.stderr_fd, .fork, error.Unexpected);
        }
        const inner_pid: linux.pid_t = @intCast(inner_fork_rc);

        if (inner_pid == 0) {
            _ = linux.close(keeper_fds[0]);
            // The layers are applied in B and not in A. The kernel gives a procfs the view
            // of the pid namespace of whichever process mounts it, and refuses the mount to
            // a process not in one it has `CAP_SYS_ADMIN` over: a `/proc` mount from A
            // answers `EPERM`.
            if (notify_fds[0] >= 0) _ = linux.close(notify_fds[0]);
            // B gives up the shared record first. B later runs code nobody here wrote, and
            // a mapping it kept would let it write its own numbers into a record that
            // claims to come from the kernel.
            if (path_record) |record| unmapPathRecord(record);
            applyLayers(allocator, config, abi, child_insns, write_fd, notify_fds[1]);
            armPdeathsig(write_fd, config.stderr_fd, middle_pidfd);
            execute(allocator, config, argv, write_fd, broker_fds[1]);
            unreachable;
        }

        _ = linux.close(middle_pidfd);

        // Without this close, the real parent's read would not see end of file until A
        // itself exits, which is not until the whole program has finished, so the
        // parent could not learn that setup succeeded.
        _ = linux.close(write_fd);

        if (broker_fds[1] >= 0) {
            _ = linux.close(broker_fds[1]);
            broker_fds[1] = -1;
        }

        if (config.stdout_fd != std.posix.STDOUT_FILENO) _ = linux.close(config.stdout_fd);
        if (config.stderr_fd != std.posix.STDERR_FILENO and config.stderr_fd != config.stdout_fd)
            _ = linux.close(config.stderr_fd);
        // The mirror image for `stdin_fd`: that is the read end of a pipe the caller
        // writes into, and a write answers `EPIPE` only once every read end is closed,
        // so a copy here would answer the caller's write into a buffer nobody drains.
        if (config.stdin_fd) |fd| {
            if (fd > std.posix.STDERR_FILENO and fd != config.stdout_fd and fd != config.stderr_fd)
                _ = linux.close(fd);
        }

        // Taken before `restrictMiddle`, and that order is a rule. `pidfd_getfd` needs
        // ptrace level access to B, and the kernel makes a process undumpable when a
        // credential change takes a capability away, so from then only `CAP_SYS_PTRACE`
        // in B's user namespace permits the take.
        var listener: i32 = -1;
        var child_pidfd: i32 = -1;
        if (notify_fds[0] >= 0) {
            _ = linux.close(notify_fds[1]);
            notify_fds[1] = -1;
            const child_pidfd_rc = linux.pidfd_open(inner_pid, 0);
            if (linux.errno(child_pidfd_rc) == .SUCCESS) child_pidfd = @intCast(child_pidfd_rc);
            listener = notify.takeListener(notify_fds[0], child_pidfd);
            _ = linux.close(notify_fds[0]);
            notify_fds[0] = -1;
        }

        // The reader is a child of A rather than of B, and that placement is what
        // bounds it: `process_vm_readv` names a pid, and a pid means nothing outside
        // the namespace of the process that wrote it down. A gives up the listener, so
        // a program that kills its own auditor gets `ENOSYS` rather than an answer
        // nobody will give.
        var reader_pid: linux.pid_t = -1;
        if (listener >= 0 and path_record != null) {
            const reader_rc = linux.fork();
            if (linux.errno(reader_rc) == .SUCCESS) {
                if (reader_rc == 0) runReader(
                    listener,
                    child_pidfd,
                    reader_insns,
                    path_record.?,
                    granted,
                );
                reader_pid = @intCast(reader_rc);
                _ = linux.close(listener);
                listener = -1;
            }
        }

        restrictMiddle(abi, insns, middle_write_fd);

        if (reader_pid >= 0) {
            // The reader holds the listener, and its counts are not final until
            // B has ended, so they are reported from `waitAndRelay` instead.
        } else if (listener >= 0) {
            var counts = notify.empty_counts;
            const outcome = notify.serve(listener, child_pidfd, &counts);
            _ = linux.close(listener);
            reportTraps(middle_write_fd, &counts);
            if (outcome == .fault) _ = linux.kill(inner_pid, std.posix.SIG.KILL);
        } else if (watching) {
            reportTraps(middle_write_fd, null);
        }
        if (child_pidfd >= 0) _ = linux.close(child_pidfd);

        waitAndRelay(inner_pid, keeper_pid, .{
            .pid = router_pid,
            .control_fd = router_control_fd,
        }, .{
            .pid = device_pid,
            .control_fd = device_control_fd,
        }, keeper_fds[0], &areas, middle_write_fd, if (reader_pid >= 0) .{
            .pid = reader_pid,
            .record = path_record.?,
        } else null);
        unreachable;
    }

    if (broker_fds[1] >= 0) {
        _ = linux.close(broker_fds[1]);
        broker_fds[1] = -1;
    }
    if (router_fds[1] >= 0) {
        _ = linux.close(router_fds[1]);
        router_fds[1] = -1;
    }
    if (device_fds[1] >= 0) {
        _ = linux.close(device_fds[1]);
        device_fds[1] = -1;
    }
    errdefer closeBrokerPair(&broker_fds);
    errdefer closeBrokerPair(&router_fds);
    errdefer closeBrokerPair(&device_fds);

    if (middle) |out| {
        // Opened before the pid is published: only this process reaps A, so A is still
        // a task the kernel can resolve. The descriptor comes back with `FD_CLOEXEC`
        // already set, which the kernel does for every pidfd.
        const pidfd_rc = linux.pidfd_open(pid, 0);
        if (linux.errno(pidfd_rc) != .SUCCESS) {
            _ = linux.kill(pid, .KILL);
            var reap_status: u32 = undefined;
            var reap_rc = linux.waitpid(pid, &reap_status, 0);
            while (linux.errno(reap_rc) == .INTR) {
                reap_rc = linux.waitpid(pid, &reap_status, 0);
            }
            _ = linux.close(read_fd);
            _ = linux.close(write_fd);
            _ = linux.close(middle_read_fd);
            _ = linux.close(middle_write_fd);
            return error.Unexpected;
        }
        out.fd = @intCast(pidfd_rc);
        // `fd` first and `pid` second, with a release store, because a caller watches
        // `pid` from another thread and then reads `fd` with an acquire load.
        @atomicStore(std.posix.pid_t, &out.pid, pid, .release);
    }

    _ = linux.close(write_fd);
    _ = linux.close(middle_write_fd);

    const maybe_failure = readSetupReport(read_fd) catch |err| {
        _ = linux.close(read_fd);
        _ = linux.close(middle_read_fd);
        return err;
    };
    _ = linux.close(read_fd);

    if (maybe_failure) |record| {
        _ = linux.close(middle_read_fd);
        var reap_status: u32 = undefined;
        var reap_rc = linux.waitpid(pid, &reap_status, 0);
        while (linux.errno(reap_rc) == .INTR) {
            reap_rc = linux.waitpid(pid, &reap_status, 0);
        }

        // The contents only, never `config.root` itself. One root is made per session
        // and every tool call spawns into it, so a spawn that removed it met `ENOENT`
        // on the next call's first mount and poisoned the whole session.
        removeContentsBestEffort(allocator, config.root);

        const step = std.enums.fromInt(SetupStep, record.step) orelse return error.UntrustedSetupReport;
        return setupErrorFor(step);
    }

    // The blocking wait below cannot come first: it would leave nobody reading
    // either link, and the program inside would block on an answer that arrives
    // after it has ended.
    const link: Link = if (router_fds[0] >= 0)
        .{ .router = .{ .fd = router_fds[0], .seam = config.net_router.? } }
    else if (broker_fds[0] >= 0)
        .{ .broker = .{ .fd = broker_fds[0], .seam = config.net_broker.? } }
    else
        .none;
    const device: ?DeviceOut = if (device_fds[0] >= 0)
        .{ .fd = device_fds[0], .source = config.device_source.? }
    else
        null;

    if (link != .none or device != null) {
        serveLinks(pid, link, device) catch |err| {
            closeBrokerPair(&broker_fds);
            closeBrokerPair(&router_fds);
            closeBrokerPair(&device_fds);
            _ = linux.close(middle_read_fd);
            _ = linux.kill(pid, .KILL);
            var reap_status: u32 = undefined;
            var reap_rc = linux.waitpid(pid, &reap_status, 0);
            while (linux.errno(reap_rc) == .INTR) {
                reap_rc = linux.waitpid(pid, &reap_status, 0);
            }
            return err;
        };
        closeBrokerPair(&broker_fds);
        closeBrokerPair(&router_fds);
        closeBrokerPair(&device_fds);
    }

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(wait_rc) == .INTR) {
        wait_rc = linux.waitpid(pid, &status, 0);
    }
    if (linux.errno(wait_rc) != .SUCCESS) {
        _ = linux.close(middle_read_fd);
        return error.Unexpected;
    }

    const middle_report = readMiddleReport(middle_read_fd);
    _ = linux.close(middle_read_fd);

    if (config.supervisor_audit) |audit| {
        inline for (comptime std.enums.values(iface.LayerName)) |layer| {
            if (comptime iface.failModeFor(.supervisor, layer) != null) {
                audit.record(layer, middle_report.layers.get(layer));
            }
        }
    }

    if (config.syscall_audit) |audit| switch (middle_report.traps) {
        .unasked => {},
        .observed => audit.record(.{ .observed = middle_report.trap_counts }),
        .unobserved => audit.record(.unobserved),
    };

    // Every number read out of the shared record is untrusted input.
    if (config.syscall_audit) |audit| {
        if (path_record) |record| audit.recordPaths(record);
    }

    const term: std.process.Child.Term = if (linux.W.IFSIGNALED(status))
        .{ .signal = linux.W.TERMSIG(status) }
    else
        .{ .exited = linux.W.EXITSTATUS(status) };
    reportLimitOutcome(config, &group, term, middle_report.scratch_full);
    return term;
}

/// Send `sig` to the process `fd` names. Safe to call from a signal handler:
/// one syscall, no allocation, no lock, and no path. No kernel version gate is
/// needed, because Landlock is newer than either pidfd call and `spawn` probes
/// the Landlock ABI first.
pub fn signalMiddle(fd: std.posix.fd_t, sig: std.posix.SIG) iface.SignalError!void {
    if (fd < 0) return error.NoHandle;
    const rc = linux.pidfd_send_signal(fd, sig, null, 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        // The process was reaped, so this handle names nothing. The same moment used
        // to be when a pid started naming a stranger.
        .SRCH => error.Gone,
        else => error.Unexpected,
    };
}

pub fn closeMiddle(middle: *iface.Middle) void {
    if (middle.fd < 0) return;
    _ = linux.close(middle.fd);
    middle.fd = -1;
}

fn closeBrokerPair(fds: *[2]i32) void {
    for (fds) |*fd| {
        if (fd.* < 0) continue;
        _ = linux.close(fd.*);
        fd.* = -1;
    }
}

const Link = union(enum) {
    none,
    broker: struct { fd: i32, seam: iface.NetBroker },
    router: struct { fd: i32, seam: iface.NetRouter },
};

const DeviceOut = struct {
    fd: i32,
    source: iface.DeviceSource,
};

fn sendChange(fd: i32, change: iface.DeviceSource.Change) bool {
    switch (change) {
        .place => |p| {
            devicelink.sendPlace(fd, p.kind, p.source, p.target) catch return false;
            return true;
        },
        .drop => |d| {
            devicelink.sendDrop(fd, d.target) catch return false;
            return true;
        },
    }
}

/// Answer the sandboxed program's requests for a connection, and carry a device
/// the caller pushes inward, until the call has ended. Runs in the real parent,
/// which holds the policy and the host's own network namespace. The pidfd is
/// not decoration: without it a grandchild the program forked and abandoned
/// would hold this loop after the program itself had finished. The link is read
/// before the pidfd, because the kernel reports both on one look.
fn serveLinks(pid: linux.pid_t, link: Link, device: ?DeviceOut) SpawnError!void {
    const watch_rc = linux.pidfd_open(pid, 0);
    if (linux.errno(watch_rc) != .SUCCESS) return error.Unexpected;
    const watch: i32 = @intCast(watch_rc);
    defer _ = linux.close(watch);

    const link_fd: i32 = switch (link) {
        .none => -1,
        .broker => |b| b.fd,
        .router => |r| r.fd,
    };
    const wakeup_fd: i32 = if (device) |d| d.source.vtable.wakeup(d.source.ptr) else -1;
    const budget: usize = switch (link) {
        .none => 0,
        .broker => netbroker.max_requests,
        .router => routerlink.max_requests,
    };

    var fds: [3]linux.pollfd = undefined;
    fds[0] = .{ .fd = watch, .events = linux.POLL.IN, .revents = 0 };
    var fds_len: usize = 1;
    var link_idx: ?usize = null;
    if (link_fd >= 0) {
        link_idx = fds_len;
        fds[fds_len] = .{ .fd = link_fd, .events = linux.POLL.IN, .revents = 0 };
        fds_len += 1;
    }
    var device_idx: ?usize = null;
    if (device != null) {
        device_idx = fds_len;
        fds[fds_len] = .{ .fd = wakeup_fd, .events = linux.POLL.IN, .revents = 0 };
        fds_len += 1;
    }

    var served: usize = 0;
    while (link == .none or served < budget) {
        const ready = linux.poll(&fds, fds_len, -1);
        switch (linux.errno(ready)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return,
        }

        // The link is read first: the kernel reports both this and the pidfd on one
        // look, and reading the pidfd first would lose a request that was really made.
        if (link_idx) |i| {
            if (fds[i].revents & linux.POLL.IN != 0) {
                switch (link) {
                    .none => unreachable,
                    .broker => |b| switch (netbroker.serveOne(b.fd, b.seam)) {
                        .served => {
                            served += 1;
                            continue;
                        },
                        .nothing => continue,
                        .peer_gone => return,
                    },
                    .router => |r| switch (routerlink.serveOne(r.fd, r.seam)) {
                        .served => {
                            served += 1;
                            continue;
                        },
                        .nothing => continue,
                        .peer_gone => return,
                    },
                }
            }
        }

        if (device) |d| {
            if (fds[device_idx.?].revents & linux.POLL.IN != 0) {
                while (d.source.vtable.next(d.source.ptr)) |change| {
                    if (sendChange(d.fd, change)) continue;
                    // A negative descriptor is the one thing `poll` ignores, so this drops the
                    // wakeup without moving any other index. Tearing the loop down here would take
                    // a working network with it.
                    fds[device_idx.?].fd = -1;
                    break;
                }
                continue;
            }
        }

        if (link_idx) |i| if (fds[i].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0) return;
        if (fds[0].revents != 0) return;
    }
}

const max_scratch_areas = 4;

const ScratchAreas = struct {
    fds: [max_scratch_areas]i32 = @splat(-1),
    count: usize = 0,

    fn anyFull(self: *const ScratchAreas) bool {
        for (self.fds[0..self.count]) |fd| {
            if (namespace.scratchIsFull(fd)) return true;
        }
        return false;
    }
};

/// A failure ends the process: a caller that asked for a capped area and got an
/// ordinary directory has no bound on what its program writes, and every other
/// layer would still apply.
fn mountScratchAreas(config: Config, write_fd: i32) ScratchAreas {
    var areas = ScratchAreas{};
    if (config.scratch.len > max_scratch_areas) {
        dieErrno(
            write_fd,
            config.stderr_fd,
            .scratch_mount,
            "too many scratch areas for one call",
            .@"2BIG",
        );
    }
    for (config.scratch) |area| {
        var diag: ?namespace.Diagnostic = null;
        const fd = namespace.mountScratch(
            config.root,
            area.target,
            config.limits.scratch_bytes,
            &diag,
        ) catch |err| dieNamespace(write_fd, config.stderr_fd, .scratch_mount, err, diag);
        areas.fds[areas.count] = fd;
        areas.count += 1;
    }
    return areas;
}

/// One record on the middle pipe: a tag byte, a slot byte, and an eight byte
/// value. Ten bytes is far below `PIPE_BUF`, so each record reaches the reader
/// whole. The tag values are fixed rather than counted from zero, so a read
/// that landed on something else is ignored instead of trusted.
const record_bytes = 10;

const tag_scratch_full: u8 = 0xD1;

/// Written whichever way it went, so that A saying nothing stays a third answer
/// of its own: a cancelled call kills A before `restrictMiddle` and must not
/// count as a confined supervisor.
const tag_middle_layer: u8 = 0xD2;

/// Counted from the fail mode table, so a fourth supervisor layer grows the
/// read buffer instead of overflowing the margin.
const middle_layer_count: usize = blk: {
    var found: usize = 0;
    for (std.enums.values(iface.LayerName)) |layer| {
        if (iface.failModeFor(.supervisor, layer) != null) found += 1;
    }
    break :blk found;
};

const tag_traps_observed: u8 = 0xD3;

const tag_trap_count: u8 = 0xD4;

const TrapState = enum {
    unasked,
    observed,
    unobserved,
};

const MiddleReport = struct {
    scratch_full: bool = false,
    layers: std.EnumArray(iface.LayerName, iface.SupervisorAudit.Outcome) =
        .initFill(.unsaid),
    traps: TrapState = .unasked,
    trap_counts: notify.Counts = notify.empty_counts,
};

fn writeMiddleRecord(middle_write_fd: i32, tag: u8, slot: u8, value: u64) void {
    var record: [record_bytes]u8 = undefined;
    record[0] = tag;
    record[1] = slot;
    std.mem.writeInt(u64, record[2..record_bytes], value, .little);
    _ = linux.write(middle_write_fd, &record, record.len);
}

fn reportScratch(areas: *const ScratchAreas, middle_write_fd: i32) void {
    if (!areas.anyFull()) return;
    writeMiddleRecord(middle_write_fd, tag_scratch_full, 0, 1);
}

fn reportMiddleLayer(
    middle_write_fd: i32,
    layer: iface.LayerName,
    fault: ?iface.SupervisorAudit.Fault,
) void {
    const value: u8 = if (fault) |one| @intFromEnum(one) else 0;
    writeMiddleRecord(middle_write_fd, tag_middle_layer, @intFromEnum(layer), value);
}

fn reportTraps(middle_write_fd: i32, counts: ?*const notify.Counts) void {
    writeMiddleRecord(middle_write_fd, tag_traps_observed, 0, if (counts == null) 0 else 1);
    const seen = counts orelse return;
    for (seen, 0..) |count, slot| {
        if (count == 0) continue;
        writeMiddleRecord(middle_write_fd, tag_trap_count, @intCast(slot), count);
    }
}

/// Exhaustive on purpose: a member added to `seccomp.InstallError` stops this
/// file compiling until it is named here, so a new fault cannot reach the log
/// as one of the old ones and name the wrong repair.
fn filterFaultFor(err: seccomp.InstallError) iface.SupervisorAudit.Fault {
    return switch (err) {
        error.NotSupported => .not_supported,
        error.NoNewPrivsRefused => .no_new_privs_refused,
        error.NotPermitted => .not_permitted,
        error.Rejected => .rejected,
        error.Unexpected => .unexpected,
    };
}

fn landlockFaultFor(err: landlock.RulesetError) iface.SupervisorAudit.Fault {
    return switch (err) {
        error.NotSupported => .not_supported,
        error.Rejected,
        error.PathNotFound,
        error.AccessDenied,
        error.NotADirectory,
        error.PathTooLong,
        => .rejected,
        error.Unexpected => .unexpected,
    };
}

fn capabilitiesFaultFor(err: capabilities.Error) iface.SupervisorAudit.Fault {
    return switch (err) {
        error.Rejected => .rejected,
    };
}

fn outcomeFor(value: u8) iface.SupervisorAudit.Outcome {
    if (value == 0) return .on;
    const fault = std.enums.fromInt(iface.SupervisorAudit.Fault, value) orelse .unexpected;
    return .{ .off = fault };
}

fn readMiddleReport(middle_read_fd: i32) MiddleReport {
    var buffer: [record_bytes * 2 * (2 + middle_layer_count + notify.call_count)]u8 = undefined;
    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(middle_read_fd, buffer[filled..].ptr, buffer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        filled += rc;
    }

    var report = MiddleReport{};
    var at: usize = 0;
    while (at + record_bytes <= filled) : (at += record_bytes) {
        const slot = buffer[at + 1];
        const value = std.mem.readInt(u64, buffer[at + 2 ..][0..8], .little);
        switch (buffer[at]) {
            tag_scratch_full => report.scratch_full = value != 0,
            tag_middle_layer => if (std.enums.fromInt(iface.LayerName, slot)) |layer| {
                report.layers.set(layer, outcomeFor(@truncate(value)));
            },
            tag_traps_observed => report.traps = if (value != 0) .observed else .unobserved,
            tag_trap_count => if (slot < notify.call_count) {
                report.trap_counts[slot] = value;
            },
            else => {},
        }
    }
    return report;
}

/// A signal number is not a reason: a call that ran out of memory dies from
/// `SIGKILL`, which is what a deadline or a Ctrl-C also looks like. `SIGXCPU`
/// and `SIGXFSZ` name their own limit and the cgroup counters name the rest. A
/// full scratch area is inferred, because `ENOSPC` is recorded nowhere.
fn reportLimitOutcome(
    config: Config,
    group: *cgroup.Cgroup,
    term: std.process.Child.Term,
    scratch_full: bool,
) void {
    const events = group.readEvents();

    var killed_by: ?rlimits.Diagnostic.Which = null;
    switch (term) {
        .signal => |sig| {
            killed_by = rlimits.limitForSignal(sig);
            if (killed_by == null and events.oom_kills > 0) killed_by = .memory;
        },
        else => {},
    }

    if (killed_by == null and scratch_full and endedBadly(term)) killed_by = .scratch_space;

    const report = LimitsReport{
        .limits = config.limits,
        .cgroup = group.support,
        .nproc_applied = if (config.limits_report) |slot| slot.nproc_applied else false,
        .events = events,
        .scratch_full = scratch_full,
        .killed_by = killed_by,
    };
    if (config.limits_report) |slot| slot.* = report;

    var buffer: [256]u8 = undefined;
    if (report.killedText(&buffer)) |sentence| {
        var line: [320]u8 = undefined;
        writeStderr(std.posix.STDERR_FILENO, std.fmt.bufPrint(&line, "sandbox: {s}\n", .{sentence}) catch
            "sandbox: a resource limit stopped the program\n");
        return;
    }
    if (events.fork_refusals > 0) {
        var line: [320]u8 = undefined;
        writeStderr(std.posix.STDERR_FILENO, std.fmt.bufPrint(
            &line,
            "sandbox: {d} fork(s) were refused by the limit of {?d} processes\n",
            .{ events.fork_refusals, config.limits.processes },
        ) catch "sandbox: a fork was refused by the process limit\n");
    }
}

fn endedBadly(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code != 0,
        else => true,
    };
}

/// A refusal ends the process: a program outside its cgroup has no memory bound
/// and no process bound at all, and nothing later in the setup would notice.
fn joinCgroup(group: *cgroup.Cgroup, write_fd: i32, stderr_fd: i32) void {
    if (group.join()) |join_errno| {
        dieErrno(write_fd, stderr_fd, .cgroup_join, "write to cgroup.procs", join_errno);
    }
    group.closeProcsFd();
}

fn readSetupReport(read_fd: i32) SpawnError!?SetupFailureRecord {
    var buffer: [@sizeOf(SetupFailureRecord)]u8 = undefined;
    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(read_fd, buffer[filled..].ptr, buffer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS) return error.Unexpected;
        if (rc == 0) break;
        filled += rc;
    }
    if (filled == 0) return null;
    if (filled != buffer.len) return error.UntrustedSetupReport;

    var extra: [1]u8 = undefined;
    while (true) {
        const rc = linux.read(read_fd, &extra, 1);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS) return error.Unexpected;
        if (rc != 0) return error.UntrustedSetupReport;
        break;
    }

    const record = std.mem.bytesToValue(SetupFailureRecord, &buffer);
    if (record.magic != setup_failure_magic) return error.UntrustedSetupReport;
    return record;
}

fn setupErrorFor(step: SetupStep) SetupError {
    return switch (step) {
        .stdin_redirect => error.StdinRedirectFailed,
        .process_group => error.ProcessGroupFailed,
        .close_fds => error.CloseFdsFailed,
        .cgroup_join => error.CgroupJoinFailed,
        .resource_limits => error.ResourceLimitFailed,
        .namespace => error.NamespaceFailed,
        .network => error.NetRouterUnavailable,
        .device => error.DeviceHelperFailed,
        .scratch_mount => error.ScratchMountFailed,
        .mount_tree => error.MountTreeFailed,
        .pivot => error.PivotFailed,
        .capabilities => error.CapabilitiesFailed,
        .landlock_init => error.LandlockInitFailed,
        .landlock_rule => error.LandlockRuleFailed,
        .landlock_restrict => error.LandlockRestrictFailed,
        .session_keyring => error.SessionKeyringFailed,
        .seccomp_install => error.SeccompInstallFailed,
        .notify_handover => error.NotifyHandoverFailed,
        .fork => error.ForkFailed,
        .pdeathsig_pidfd, .pdeathsig_prctl => error.PdeathsigSetupFailed,
        .exec => error.ExecFailed,
    };
}

/// Remove what `buildRoot` made under `root`, and leave `root` itself, which is
/// the caller's. The mounts are already gone with the child's own mount
/// namespace, whose `/` was `MS_PRIVATE`. A symbolic link in a `deny_read` path
/// once let `buildRoot` write outside `root`, where this walk cannot reach.
fn removeContentsBestEffort(allocator: std.mem.Allocator, root: []const u8) void {
    const root_z = allocator.dupeZ(u8, root) catch return;
    defer allocator.free(root_z);

    const dir_rc = linux.open(root_z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(dir_rc) != .SUCCESS) return;
    removeTreeFdBestEffort(allocator, @intCast(dir_rc));
}

const RemoveTreeFrame = struct {
    fd: i32,
    parent_fd: i32 = -1,
    // `NAME_MAX` on Linux is 255 bytes. +1 leaves room for the null the code
    // below always writes.
    name: [256]u8 = undefined,
    name_len: usize = 0,
    buffer: [4096]u8 = undefined,
    buffer_len: usize = 0,
    offset: usize = 0,

    fn nameZ(self: *const RemoveTreeFrame) [:0]const u8 {
        return self.name[0..self.name_len :0];
    }
};

/// Walks with `*at` calls relative to open descriptors: a deep enough tree makes
/// an absolute path exceed `PATH_MAX` and leaks everything below. The stack is
/// explicit, because a 4 KiB `getdents64` buffer per level overruns a default
/// 8 MiB stack at 4098 levels.
fn removeTreeFdBestEffort(allocator: std.mem.Allocator, root_fd: i32) void {
    var stack = std.ArrayList(RemoveTreeFrame).empty;
    defer {
        for (stack.items) |*frame| _ = linux.close(frame.fd);
        stack.deinit(allocator);
    }
    stack.append(allocator, .{ .fd = root_fd }) catch {
        _ = linux.close(root_fd);
        return;
    };

    while (stack.items.len > 0) {
        const top = &stack.items[stack.items.len - 1];

        if (top.offset >= top.buffer_len) {
            const nread = linux.getdents64(top.fd, &top.buffer, top.buffer.len);
            if (linux.errno(nread) != .SUCCESS or nread == 0) {
                _ = linux.close(top.fd);
                if (top.parent_fd != -1) _ = linux.unlinkat(top.parent_fd, top.nameZ(), linux.AT.REMOVEDIR);
                _ = stack.pop();
                continue;
            }
            top.buffer_len = nread;
            top.offset = 0;
        }

        const entry: *align(1) const linux.dirent64 = @ptrCast(&top.buffer[top.offset]);
        const name_offset = top.offset + @offsetOf(linux.dirent64, "name");
        const name_ptr: [*:0]const u8 = @ptrCast(&top.buffer[name_offset]);
        const name = std.mem.sliceTo(name_ptr, 0);
        const entry_type = entry.type;
        const dir_fd = top.fd;
        top.offset += entry.reclen;

        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        if (entry_type == linux.DT.DIR) {
            const child_rc = linux.openat(
                dir_fd,
                name_ptr,
                .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
                0,
            );
            if (linux.errno(child_rc) != .SUCCESS) continue;

            var child = RemoveTreeFrame{ .fd = @intCast(child_rc), .parent_fd = dir_fd };
            const copy_len = @min(name.len, child.name.len - 1);
            @memcpy(child.name[0..copy_len], name[0..copy_len]);
            child.name[copy_len] = 0;
            child.name_len = copy_len;

            // `append` can move `stack.items` to a new allocation, invalidating `top`.
            // Nothing above this point still reads `top` after this call.
            stack.append(allocator, child) catch {
                _ = linux.close(child.fd);
            };
        } else {
            _ = linux.unlinkat(dir_fd, name_ptr, 0);
        }
    }
}

/// Write `line` to `stderr_fd` directly: one syscall and none of the locking
/// `std.debug.print` does, which in a child of `fork` could be held by a thread
/// that no longer exists. The descriptor travels with each call rather than
/// being installed on number 2: `pipe2` takes the two lowest free numbers, so a
/// caller running with 1 and 2 closed gives 2 to the setup pipe's write end.
fn writeStderr(stderr_fd: i32, line: []const u8) void {
    _ = linux.write(stderr_fd, line.ptr, line.len);
}

fn printFault(stderr_fd: i32, err: anyerror) void {
    var buffer: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buffer, "sandbox: {s}\n", .{@errorName(err)}) catch
        "sandbox: an error occurred, and its name was too long to print\n";
    writeStderr(stderr_fd, line);
}

fn printDenyTargetSymlinkFault(stderr_fd: i32) void {
    writeStderr(
        stderr_fd,
        "sandbox: a deny_read entry in chock.zon names a symbolic link, and it will not be followed. Point deny_read at the real file, not at a link to it.\n",
    );
}

fn printBindSourceSymlinkFault(stderr_fd: i32) void {
    writeStderr(
        stderr_fd,
        "sandbox: a bind mount's source names a symbolic link, and it will not be followed. chock.zon is the usual case: make it a real file, not a link to one.\n",
    );
}

fn printBindTargetSymlinkFault(stderr_fd: i32) void {
    writeStderr(
        stderr_fd,
        "sandbox: a bind mount's target names a symbolic link, and it will not be followed. chock.zon is the usual case: make it a real file, not a link to one.\n",
    );
}

fn printFaultErrno(stderr_fd: i32, comptime what: []const u8, err: linux.E) void {
    var buffer: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buffer, "sandbox: {s} failed: {s}\n", .{ what, @tagName(err) }) catch
        "sandbox: a step failed, and its name was too long to print\n";
    writeStderr(stderr_fd, line);
}

fn reportSetupFailure(write_fd: i32, step: SetupStep, errno_value: i32) void {
    const record = SetupFailureRecord{ .step = @intFromEnum(step), .errno = errno_value };
    const bytes = std.mem.asBytes(&record);
    _ = linux.write(write_fd, bytes.ptr, bytes.len);
}

/// Report `step` as failed over the setup pipe, print the error name, and end
/// the process, so a setup fault can never reach `execve`. The record goes first
/// and the text second in every function of this family: a caller may name a
/// pipe whose read end is closed, and that write raises `SIGPIPE`, which would
/// leave `spawn` reading the end of file a successful `execve` reports itself with.
fn die(write_fd: i32, stderr_fd: i32, step: SetupStep, err: anyerror) noreturn {
    reportSetupFailure(write_fd, step, 0);
    printFault(stderr_fd, err);
    std.process.exit(1);
}

/// Same as `die`, for a step that can also say which call the kernel refused.
/// The namespace step kept calling plain `die` once, so a machine that refused
/// the user namespace answered errno 0 and two CI architectures failed 132
/// tests each saying only that the sandbox would not start.
fn dieNamespace(
    write_fd: i32,
    stderr_fd: i32,
    step: SetupStep,
    err: anyerror,
    diag: ?namespace.Diagnostic,
) noreturn {
    if (diag) |d| {
        reportSetupFailure(write_fd, step, @intFromEnum(d.errno));
        var buffer: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "sandbox: {f}\n", .{d}) catch
            "sandbox: a mount failed, and the reason was too long to print\n";
        writeStderr(stderr_fd, line);
    } else if (err == error.DenyTargetIsSymlink) {
        reportSetupFailure(write_fd, step, 0);
        printDenyTargetSymlinkFault(stderr_fd);
    } else if (err == error.BindSourceIsSymlink) {
        reportSetupFailure(write_fd, step, 0);
        printBindSourceSymlinkFault(stderr_fd);
    } else if (err == error.BindTargetIsSymlink) {
        reportSetupFailure(write_fd, step, 0);
        printBindTargetSymlinkFault(stderr_fd);
    } else {
        reportSetupFailure(write_fd, step, 0);
        printFault(stderr_fd, err);
    }
    std.process.exit(1);
}

fn dieLandlock(
    write_fd: i32,
    stderr_fd: i32,
    step: SetupStep,
    err: anyerror,
    diag: ?landlock.Diagnostic,
) noreturn {
    if (diag) |d| {
        reportSetupFailure(write_fd, step, @intFromEnum(d.errno));
        var buffer: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "sandbox: {f}\n", .{d}) catch
            "sandbox: a landlock call failed, and the reason was too long to print\n";
        writeStderr(stderr_fd, line);
    } else {
        reportSetupFailure(write_fd, step, 0);
        printFault(stderr_fd, err);
    }
    std.process.exit(1);
}

fn dieCapabilities(
    write_fd: i32,
    stderr_fd: i32,
    err: anyerror,
    diag: ?capabilities.Diagnostic,
) noreturn {
    if (diag) |d| {
        reportSetupFailure(write_fd, .capabilities, @intFromEnum(d.errno));
        var buffer: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "sandbox: {f}\n", .{d}) catch
            "sandbox: dropping capabilities failed, and the reason was too long to print\n";
        writeStderr(stderr_fd, line);
    } else {
        reportSetupFailure(write_fd, .capabilities, 0);
        printFault(stderr_fd, err);
    }
    std.process.exit(1);
}

fn dieLimit(write_fd: i32, stderr_fd: i32, err: anyerror, diag: ?rlimits.Diagnostic) noreturn {
    if (diag) |d| {
        reportSetupFailure(write_fd, .resource_limits, @intFromEnum(d.errno));
        var buffer: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "sandbox: {f}\n", .{d}) catch
            "sandbox: a resource limit failed, and the reason was too long to print\n";
        writeStderr(stderr_fd, line);
    } else {
        reportSetupFailure(write_fd, .resource_limits, 0);
        printFault(stderr_fd, err);
    }
    std.process.exit(1);
}

fn dieErrno(
    write_fd: i32,
    stderr_fd: i32,
    step: SetupStep,
    comptime what: []const u8,
    err: linux.E,
) noreturn {
    reportSetupFailure(write_fd, step, @intFromEnum(err));
    printFaultErrno(stderr_fd, what, err);
    std.process.exit(1);
}

fn dieWithErrno(write_fd: i32, stderr_fd: i32, step: SetupStep, errno: i32) noreturn {
    _ = stderr_fd;
    reportSetupFailure(write_fd, step, errno);
    std.process.exit(1);
}

fn dieRelay(err: anyerror) noreturn {
    printFault(std.posix.STDERR_FILENO, err);
    std.process.exit(1);
}

fn dieRelayErrno(comptime what: []const u8, err: linux.E) noreturn {
    printFaultErrno(std.posix.STDERR_FILENO, what, err);
    std.process.exit(1);
}

/// Wait for the grandchild running the caller's program and end this process the
/// same way. This process is process 1 nowhere, so it has no immunity from an
/// unhandled signal, which is what lets the real parent's own `waitpid` read
/// this process's death as the grandchild's.
fn waitAndRelay(
    pid: linux.pid_t,
    keeper_pid: linux.pid_t,
    network_router: RouterWatch,
    device: DeviceWatch,
    keeper_fd: i32,
    areas: *const ScratchAreas,
    middle_write_fd: i32,
    reader: ?ReaderWatch,
) noreturn {
    var status: u32 = undefined;
    var wait_rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(wait_rc) == .INTR) {
        wait_rc = linux.waitpid(pid, &status, 0);
    }
    if (linux.errno(wait_rc) != .SUCCESS) {
        dieRelayErrno("waitpid on the sandboxed program", linux.errno(wait_rc));
    }

    if (reader) |watch| reapReader(watch, middle_write_fd);

    // N is ended before the keeper, and that order is a rule. A pid namespace
    // cannot be torn down until every pid in it is reaped, not merely killed, and
    // N is a child of A, outside the namespace, so nothing inside can reap it.
    if (network_router.pid >= 0) reapRouter(network_router);

    if (device.pid >= 0) reapDevice(device);

    _ = linux.close(keeper_fd);
    var keeper_status: u32 = undefined;
    var keeper_wait_rc = linux.waitpid(keeper_pid, &keeper_status, 0);
    while (linux.errno(keeper_wait_rc) == .INTR) {
        keeper_wait_rc = linux.waitpid(keeper_pid, &keeper_status, 0);
    }
    if (linux.errno(keeper_wait_rc) != .SUCCESS or !linux.W.IFEXITED(keeper_status) or
        linux.W.EXITSTATUS(keeper_status) != 0)
    {
        dieRelay(error.Unexpected);
    }

    reportScratch(areas, middle_write_fd);

    if (linux.W.IFSIGNALED(status)) {
        const sig = linux.W.TERMSIG(status);
        std.posix.raise(sig) catch |err| dieRelay(err);
        dieRelay(error.Unexpected);
    }

    std.process.exit(linux.W.EXITSTATUS(status));
}

fn reapRouter(watch: RouterWatch) void {
    if (watch.control_fd >= 0) _ = linux.close(watch.control_fd);

    var status: u32 = undefined;
    var rc: usize = 0;
    var tries: usize = 0;
    while (tries < router_drain_tries) : (tries += 1) {
        rc = linux.waitpid(watch.pid, &status, linux.W.NOHANG);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc != 0) return,
            .INTR => continue,
            else => break,
        }
        var pause: linux.timespec = .{ .sec = 0, .nsec = router_drain_step_ns };
        _ = linux.nanosleep(&pause, null);
    }

    const kill_errno = linux.errno(linux.kill(watch.pid, .KILL));
    switch (kill_errno) {
        .SUCCESS, .SRCH => {},
        else => dieRelayErrno("end the network router", kill_errno),
    }
    rc = linux.waitpid(watch.pid, &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(watch.pid, &status, 0);
    if (linux.errno(rc) != .SUCCESS) {
        dieRelayErrno("waitpid on the network router", linux.errno(rc));
    }
}

const RouterWatch = struct {
    pid: linux.pid_t,
    control_fd: i32,
};

const router_drain_tries: usize = 500;
const router_drain_step_ns: isize = 1_000_000;

fn reapDevice(watch: DeviceWatch) void {
    if (watch.control_fd >= 0) _ = linux.close(watch.control_fd);

    var status: u32 = undefined;
    var rc: usize = 0;
    var tries: usize = 0;
    while (tries < router_drain_tries) : (tries += 1) {
        rc = linux.waitpid(watch.pid, &status, linux.W.NOHANG);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc != 0) return,
            .INTR => continue,
            else => break,
        }
        var pause: linux.timespec = .{ .sec = 0, .nsec = router_drain_step_ns };
        _ = linux.nanosleep(&pause, null);
    }

    const kill_errno = linux.errno(linux.kill(watch.pid, .KILL));
    switch (kill_errno) {
        .SUCCESS, .SRCH => {},
        else => dieRelayErrno("end the device helper", kill_errno),
    }
    rc = linux.waitpid(watch.pid, &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(watch.pid, &status, 0);
    if (linux.errno(rc) != .SUCCESS) {
        dieRelayErrno("waitpid on the device helper", linux.errno(rc));
    }
}

const DeviceWatch = struct {
    pid: linux.pid_t,
    control_fd: i32,
};

/// Build the sandbox its own network. The netlink socket has to be opened here,
/// because it belongs to the network namespace of whichever process created it.
/// A missing kernel module ends the call: a process in a user namespace cannot
/// make the kernel load one.
fn buildNetwork(write_fd: i32, stderr_fd: i32) nftables.Session {
    var route_diag: ?netns.Diagnostic = null;
    var route = netns.Session.open(&route_diag) catch |err|
        dieNetwork(write_fd, stderr_fd, err, netnsErrno(route_diag));
    _ = route.configure(&route_diag) catch |err|
        dieNetwork(write_fd, stderr_fd, err, netnsErrno(route_diag));
    route.close();

    var table_diag: ?nftables.Diagnostic = null;
    const table = nftables.Session.open(&table_diag) catch |err|
        dieNetwork(write_fd, stderr_fd, err, nftablesErrno(table_diag));
    table.install(&table_diag) catch |err|
        dieNetwork(write_fd, stderr_fd, err, nftablesErrno(table_diag));
    return table;
}

fn netnsErrno(diag: ?netns.Diagnostic) i32 {
    return if (diag) |one| one.errno else 0;
}

fn nftablesErrno(diag: ?nftables.Diagnostic) i32 {
    return if (diag) |one| one.errno else 0;
}

fn dieNetwork(write_fd: i32, stderr_fd: i32, err: anyerror, errno: i32) noreturn {
    if (err == error.KernelModuleMissing) {
        writeStderr(stderr_fd, missing_module_notice);
    } else {
        printFault(stderr_fd, err);
    }
    dieWithErrno(write_fd, stderr_fd, .network, errno);
}

const missing_module_notice =
    "sandbox: this host cannot give a sandbox its own filtered network.\n" ++
    "sandbox: a kernel module it needs is not loaded, and a sandbox cannot load one.\n" ++
    "sandbox: load these on the host and run again:\n" ++
    "sandbox:   modprobe " ++ network_modules ++ " " ++ filter_modules ++ "\n";

pub const network_modules = "dummy";

pub const filter_modules = "nf_tables nf_nat nft_chain_nat nft_redir nft_reject nf_conntrack";

fn runRouter(
    ready_fd: i32,
    link_fd: i32,
    table: nftables.Session,
    middle_pidfd: i32,
    insns: []const bpf.Insn,
    write_fd: i32,
    stderr_fd: i32,
) noreturn {
    armPdeathsig(write_fd, stderr_fd, middle_pidfd);

    var client = routerlink.Client{ .fd = link_fd, .session = table };
    var instance: router.Router = undefined;
    var diag: ?router.Diagnostic = null;
    // The listeners come up while the capability is still there. The resolver
    // binds port 53, which is privileged.
    instance.open(.{ .policy = client.policy(), .host = client.host() }, &diag) catch |err| {
        printFault(stderr_fd, err);
        dieWithErrno(write_fd, stderr_fd, .network, if (diag) |one| one.errno else 0);
    };

    keepOnlyTheseDescriptors(&.{
        ready_fd,
        link_fd,
        table.fd,
        instance.relay_fd,
        instance.resolver_fd,
    });

    var cap_diag: ?capabilities.Diagnostic = null;
    capabilities.keepOnly(linux.CAP.NET_ADMIN, &cap_diag) catch linux.exit(1);
    seccomp.install(bpf.Prog.init(insns)) catch linux.exit(1);

    // The last thing before the loop: A is blocked on this byte. `sendto` and not
    // `write`, because `write` is not on the router's allowlist and must not be: a
    // router that can write to a descriptor can write to one the far side sent it.
    const ready = [1]u8{1};
    const said = linux.sendto(ready_fd, &ready, ready.len, linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(said) != .SUCCESS or said != ready.len) linux.exit(1);

    while (!peerHasGone(ready_fd)) {
        // A monotonic clock that counts suspended time, never the wall clock: every
        // deadline in the router is a span, so a clock NTP can move would expire a
        // name early or hold one late.
        instance.step(monotonicMilliseconds(), router_idle_step_ms, null) catch linux.exit(1);
    }

    var drained: usize = 0;
    while (drained < router_drain_steps) : (drained += 1) {
        instance.step(monotonicMilliseconds(), router_drain_step_ms, null) catch break;
        if (instance.pendingBytes() == 0) break;
    }
    linux.exit(0);
}

const router_idle_step_ms: i32 = 20;

const router_drain_steps: usize = 16;
const router_drain_step_ms: i32 = 2;

/// D, the device helper. Never returns. It confines itself before it serves
/// anything, the order `runRouter` keeps, and binds the hidden device tree while
/// it still holds every capability it inherited.
///
/// D never pivots and does not need to: `pivot_root`, run later by B, changes
/// the root mount for the whole namespace the two share, which is why
/// `placeDevice` joins `Config.root` onto nothing and `bindDeviceTree`, which
/// runs earlier, still does. `CAP_SYS_ADMIN` and never `CAP_MKNOD`, so a bug
/// that fabricated a device node's own identity meets `EPERM`.
fn runDevice(
    ready_fd: i32,
    link_fd: i32,
    root: []const u8,
    hidden_host: []const u8,
    hidden_inside: []const u8,
    middle_pidfd: i32,
    insns: []const bpf.Insn,
    write_fd: i32,
    stderr_fd: i32,
) noreturn {
    armPdeathsig(write_fd, stderr_fd, middle_pidfd);

    keepOnlyTheseDescriptors(&.{ ready_fd, link_fd, stderr_fd });

    var tree_buffer: [device_path_capacity]u8 = undefined;
    if (!bindDeviceTree(&tree_buffer, root, hidden_inside, hidden_host)) linux.exit(1);

    var cap_diag: ?capabilities.Diagnostic = null;
    capabilities.keepOnly(linux.CAP.SYS_ADMIN, &cap_diag) catch linux.exit(1);
    seccomp.install(bpf.Prog.init(insns)) catch linux.exit(1);

    // `write`, and not the `sendto` `runRouter` uses. `device_calls` carries
    // `write` already and does not carry `sendto` at all: a helper that called
    // `sendto` here died at exactly this line with `SIGSYS`.
    const ready = [1]u8{1};
    const said = linux.write(ready_fd, &ready, ready.len);
    if (linux.errno(said) != .SUCCESS or said != ready.len) linux.exit(1);

    var state = DeviceSeamState{ .hidden = hidden_inside, .stderr_fd = stderr_fd };
    const seam = state.seam();

    while (true) {
        // `ppoll` and never `poll`: `seccomp.device_calls` names only the former, so
        // this loop calls it directly rather than through `linux.poll`, which resolves
        // to the plain syscall on some architectures.
        var fds = [2]linux.pollfd{
            .{ .fd = link_fd, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = ready_fd, .events = 0, .revents = 0 },
        };
        const ready_rc = linux.ppoll(&fds, fds.len, null, null);
        switch (linux.errno(ready_rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => linux.exit(1),
        }

        if (fds[0].revents & linux.POLL.IN != 0) {
            const outcome = devicelink.serveOne(link_fd, seam);
            switch (outcome) {
                .placed, .place_failed, .dropped, .drop_failed, .nothing => continue,
                .peer_gone => linux.exit(0),
            }
        }
        if (fds[0].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0) linux.exit(0);
        if (fds[1].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0) linux.exit(0);
    }
}

const device_kind_file: u8 = 0;

/// Stack allocated and never heap allocated: `seccomp.device_calls` has no
/// `mmap` or `brk`, so this process may not grow its own heap once its filter
/// is on.
const device_path_capacity: usize = std.fs.max_path_bytes;

const PlaceError = error{
    UnsupportedKind,
    PathUnusable,
    MkdirFailed,
    MknodFailed,
    MountFailed,
};

/// Join `root` with `path`, nul terminated for `mkdirat`, `mknodat`, `mount` and
/// `umount2`. `path` is bounded and refused, never resolved: it must start with
/// `/`, may not end in one, and may not carry a `..` component.
fn buildDeviceTarget(buffer: []u8, root: []const u8, path: []const u8) ?[:0]u8 {
    if (path.len <= 1 or path[0] != '/' or path[path.len - 1] == '/') return null;

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return null;
    }

    if (root.len + path.len >= buffer.len) return null;
    @memcpy(buffer[0..root.len], root);
    @memcpy(buffer[root.len..][0..path.len], path);
    buffer[root.len + path.len] = 0;
    return buffer[0 .. root.len + path.len :0];
}

/// Join `hidden` and `source`. This is the one new security check the path based
/// design turns on, because descriptor passing made it unnecessary: a leading
/// `/` would make the join ignore `hidden`, a `..` would climb out of it, and an
/// empty component would resolve to `hidden` itself.
fn buildDeviceSource(buffer: []u8, hidden: []const u8, source: []const u8) ?[:0]u8 {
    if (source.len == 0) return null;

    var it = std.mem.splitScalar(u8, source, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, "..")) return null;
    }

    const total = hidden.len + 1 + source.len;
    if (total >= buffer.len) return null;
    @memcpy(buffer[0..hidden.len], hidden);
    buffer[hidden.len] = '/';
    @memcpy(buffer[hidden.len + 1 ..][0..source.len], source);
    buffer[total] = 0;
    return buffer[0..total :0];
}

fn makeDeviceParents(buffer: []u8, full_len: usize) bool {
    var i: usize = 1;
    while (i < full_len) : (i += 1) {
        if (buffer[i] != '/') continue;
        buffer[i] = 0;
        const rc = linux.mkdirat(linux.AT.FDCWD, @ptrCast(buffer.ptr), 0o755);
        buffer[i] = '/';
        switch (linux.errno(rc)) {
            .SUCCESS, .EXIST => {},
            else => return false,
        }
    }
    return true;
}

fn bindDeviceTree(buffer: []u8, root: []const u8, inside: []const u8, host: []const u8) bool {
    const target = buildDeviceTarget(buffer, root, inside) orelse return false;
    if (!makeDeviceParents(buffer, target.len)) return false;
    const mkdir_rc = linux.mkdirat(linux.AT.FDCWD, target.ptr, 0o755);
    switch (linux.errno(mkdir_rc)) {
        .SUCCESS, .EXIST => {},
        else => return false,
    }

    var host_buffer: [device_path_capacity]u8 = undefined;
    const host_z = std.fmt.bufPrintZ(&host_buffer, "{s}", .{host}) catch return false;

    const mount_rc = linux.mount(host_z.ptr, target.ptr, null, linux.MS.BIND, 0);
    return linux.errno(mount_rc) == .SUCCESS;
}

/// Bind the node at `source`, relative to the hidden tree, at `target`.
///
/// Neither path is joined onto `Config.root`: nothing reaches this loop until
/// after B has pivoted, and `pivot_root` changes what `/` resolves to for every
/// process sharing that namespace. Read-write and never remounted, because
/// `namespace.markReadOnly` also sets `NODEV`, which then refuses to open the
/// device node. `mknodat` makes the placeholder with `S_IFREG`: a bind only
/// attaches to a target that already shares the source's own directory-ness.
fn placeDevice(
    target_buffer: []u8,
    source_buffer: []u8,
    hidden: []const u8,
    kind: u8,
    source: []const u8,
    target: []const u8,
) PlaceError!void {
    if (kind != device_kind_file) return error.UnsupportedKind;

    const target_z = buildDeviceTarget(target_buffer, "", target) orelse return error.PathUnusable;

    if (!makeDeviceParents(target_buffer, target_z.len)) return error.MkdirFailed;

    const mknod_rc = linux.mknodat(linux.AT.FDCWD, target_z.ptr, linux.S.IFREG | 0o600, 0);
    if (linux.errno(mknod_rc) != .SUCCESS) return error.MknodFailed;

    const source_z = buildDeviceSource(source_buffer, hidden, source) orelse return error.PathUnusable;

    const mount_rc = linux.mount(source_z.ptr, target_z.ptr, null, linux.MS.BIND, 0);
    if (linux.errno(mount_rc) != .SUCCESS) return error.MountFailed;
}

fn dropDevice(buffer: []u8, path: []const u8) PlaceError!void {
    const target = buildDeviceTarget(buffer, "", path) orelse return error.PathUnusable;
    const rc = linux.umount2(target.ptr, 0);
    if (linux.errno(rc) != .SUCCESS) return error.MountFailed;
}

fn reportDeviceFault(stderr_fd: i32, verb: []const u8, path: []const u8, err: PlaceError) void {
    var line_buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "sandbox: device {s} failed for {s}: {t}\n",
        .{ verb, path, err },
    ) catch return;
    _ = linux.write(stderr_fd, line.ptr, line.len);
}

const DeviceSeamState = struct {
    hidden: []const u8,
    stderr_fd: i32,

    fn seam(self: *DeviceSeamState) devicelink.DeviceSeam {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = devicelink.DeviceSeam.VTable{ .place = placeFn, .drop = dropFn };

    fn placeFn(ptr: *anyopaque, kind: u8, source: []const u8, target: []const u8) devicelink.DeviceSeam.Result {
        const self: *DeviceSeamState = @ptrCast(@alignCast(ptr));
        var target_buffer: [device_path_capacity]u8 = undefined;
        var source_buffer: [device_path_capacity]u8 = undefined;
        placeDevice(&target_buffer, &source_buffer, self.hidden, kind, source, target) catch |err| {
            reportDeviceFault(self.stderr_fd, "place", target, err);
            return .failed;
        };
        return .done;
    }

    fn dropFn(ptr: *anyopaque, path: []const u8) devicelink.DeviceSeam.Result {
        const self: *DeviceSeamState = @ptrCast(@alignCast(ptr));
        var buffer: [device_path_capacity]u8 = undefined;
        dropDevice(&buffer, path) catch |err| {
            reportDeviceFault(self.stderr_fd, "drop", path, err);
            return .failed;
        };
        return .done;
    }
};

/// `POLLHUP` and not a read: a read would take a byte the peer might have sent,
/// and nothing is ever sent on this socket after the readiness byte.
fn peerHasGone(fd: i32) bool {
    var watched = [1]linux.pollfd{.{ .fd = fd, .events = 0, .revents = 0 }};
    const rc = linux.poll(&watched, watched.len, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    return watched[0].revents & (linux.POLL.HUP | linux.POLL.ERR | linux.POLL.NVAL) != 0;
}

/// `BOOTTIME`, so a machine that suspended does not leave a name alive past the
/// moment the kernel forgot its address.
fn monotonicMilliseconds() i64 {
    var now: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &now)) != .SUCCESS) return 0;
    return @as(i64, now.sec) * std.time.ms_per_s +
        @divTrunc(@as(i64, now.nsec), std.time.ns_per_ms);
}

fn runKeeper(
    control_fd: i32,
    middle_pidfd: i32,
    write_fd: i32,
    stderr_fd: i32,
    insns: []const bpf.Insn,
) noreturn {
    armPdeathsig(write_fd, stderr_fd, middle_pidfd);
    keepOnlyDescriptors(control_fd, control_fd);

    var cap_diag: ?capabilities.Diagnostic = null;
    capabilities.dropAll(&cap_diag) catch linux.exit(1);
    seccomp.install(bpf.Prog.init(insns)) catch linux.exit(1);

    const ready = [1]u8{1};
    if (linux.errno(linux.write(control_fd, &ready, ready.len)) != .SUCCESS) linux.exit(1);

    var watched = [1]linux.pollfd{.{ .fd = control_fd, .events = linux.POLL.IN, .revents = 0 }};
    while (true) {
        var status: u32 = undefined;
        while (true) {
            const wait_rc = linux.waitpid(-1, &status, linux.W.NOHANG);
            switch (linux.errno(wait_rc)) {
                .SUCCESS => if (wait_rc == 0) break,
                .INTR => continue,
                .CHILD => break,
                else => linux.exit(1),
            }
        }

        watched[0].revents = 0;
        var pause: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
        const poll_rc = linux.ppoll(&watched, watched.len, &pause, null);
        switch (linux.errno(poll_rc)) {
            .SUCCESS => if (watched[0].revents != 0) linux.exit(0),
            .INTR => {},
            else => linux.exit(1),
        }
    }
}

// The order of the layers. Steps 0 and 1 run in A, steps 2 to 6 in B, and the
// order is not free to change.
//
// 0. Close every inherited descriptor, while `/proc` still shows the host's
//    view of this process. One kept open stays open across `pivot_root`.
// 1. The namespaces, because a mount needs a mount namespace.
// 2. The mount tree, because `pivot_root` needs it built.
// 3. `pivot_root`, so a Landlock rule opens each path where the sandboxed
//    program will see it and not where it sits on the host.
// 4. Landlock, because it needs to open each path.
// 5. The session keyring join. `CLONE_NEWUSER` gives a fresh user keyring, but
//    the kernel has no namespace for the session keyring.
// 6. seccomp last, because the filter blocks `unshare`, the mount family, and
//    the `keyctl` step 5 itself uses.

fn enterNamespaces(config: Config, write_fd: i32, middle_write_fd: i32, broker_fd: i32, device_fd: i32) void {
    closeInheritedFds(
        write_fd,
        middle_write_fd,
        config.stdout_fd,
        config.stderr_fd,
        config.stdin_fd,
        broker_fd,
        device_fd,
    );

    var diag: ?namespace.Diagnostic = null;
    namespace.enter(.{ .network = config.network, .mount = true }, &diag) catch |err|
        dieNamespace(write_fd, config.stderr_fd, .namespace, err, diag);
}

const applied_by_b = [_]iface.LayerName{
    .mount_tree,
    .pivot_root,
    .capabilities,
    .landlock,
    .session_keyring,
    .seccomp,
};

const resolv_conf =
    "# Written by chock. The resolver is the sandbox's own.\n" ++
    "nameserver 10.99.0.1\n" ++
    "options timeout:1 attempts:2\n";

comptime {
    const bytes = netns.address4;
    var rendered: [40]u8 = undefined;
    const text = std.fmt.bufPrint(&rendered, "nameserver {d}.{d}.{d}.{d}\n", .{
        bytes[0], bytes[1], bytes[2], bytes[3],
    }) catch @compileError("sandbox: the resolver address does not fit a resolv.conf line");
    if (std.mem.indexOf(u8, resolv_conf, text) == null) @compileError(
        "sandbox: resolv.conf must name the address the router binds. See netns.address4.",
    );
}

/// The name service switch, which matters exactly as much as `resolv.conf`.
/// This machine's own file returns from the lookup before it ever reaches
/// `dns`, so a sandbox that wrote a perfect `resolv.conf` and left this alone
/// would have a resolver nobody asks anything.
const nsswitch_conf =
    "# Written by chock. The sandbox asks its own resolver and nothing else.\n" ++
    "hosts: files dns\n" ++
    "passwd: files\n" ++
    "group: files\n" ++
    "shadow: files\n" ++
    "services: files\n" ++
    "protocols: files\n" ++
    "networks: files\n";

const hosts_file =
    "127.0.0.1\tlocalhost\n" ++
    "::1\tlocalhost ip6-localhost ip6-loopback\n";

/// The three files the sandbox writes for itself, the trust store link, and the
/// two directories it hides. The hidden paths are not optional:
/// `/run/nscd/socket` is an `AF_UNIX` socket, so a network namespace does not
/// touch it, and glibc asks nscd before it reads `resolv.conf` at all.
const trust_store_link_target = "/etc/ssl/certs/ca-certificates.crt";

pub const resolver_substitutions = [_]namespace.Substitution{
    .{ .text = .{ .target = "/etc/resolv.conf", .contents = resolv_conf } },
    .{ .text = .{ .target = "/etc/nsswitch.conf", .contents = nsswitch_conf } },
    .{ .text = .{ .target = "/etc/hosts", .contents = hosts_file } },
    .{ .link = .{ .target = trust_store_link_target, .link_to = iface.trust_store_inside } },
    .{ .hide = "/run/nscd" },
    .{ .hide = "/var/run/nscd" },
};

const resolver_text_targets = blk: {
    var targets: []const []const u8 = &.{};
    for (resolver_substitutions) |one| switch (one) {
        .text => |text| targets = targets ++ [_][]const u8{text.target},
        .link => {},
        .hide => {},
    };
    break :blk targets;
};

const owned_etc = namespace.OwnedDirectory{
    .target = "/etc",
    .remove = resolver_text_targets,
};

comptime {
    for (resolver_substitutions) |one| {
        const target = switch (one) {
            .text => |text| text.target,
            .link => |link| link.target,
            .hide => continue,
        };
        if (!std.mem.startsWith(u8, target, owned_etc.target ++ "/")) @compileError(
            "sandbox: every resolver substitution has to sit inside the directory a routed " ++
                "sandbox takes for itself. See ownDirectory and owned_etc.",
        );
    }
}

/// Steps 2 to 6, in B. The mount tree is built here and not in A, because a
/// procfs mount takes the pid namespace of whichever process makes it.
fn applyLayers(
    allocator: std.mem.Allocator,
    config: Config,
    abi: i32,
    insns: []const bpf.Insn,
    write_fd: i32,
    notify_fd: i32,
) void {
    // Every step below ends the process, and the fail mode table has to agree. The
    // table is read here as a constraint rather than as a switch: an edit that gave
    // one of these layers `open` for the sandboxed process stops this file
    // compiling.
    comptime {
        for (applied_by_b) |layer| {
            if (iface.failModeFor(.sandboxed, layer) != .closed) @compileError(
                "sandbox: applyLayers ends the process on every fault, so every layer it " ++
                    "applies must fail closed",
            );
        }
    }

    var diag: ?namespace.Diagnostic = null;
    namespace.buildRoot(allocator, config.root, config.mounts, &diag) catch |err|
        dieNamespace(write_fd, config.stderr_fd, .mount_tree, err, diag);

    // After the whole mount tree, so a bind the caller asked for cannot cover
    // them, and before the pivot, because every path below is written relative to
    // `config.root`, which stops being a path the moment this process pivots.
    if (config.net_router != null) {
        _ = namespace.ownDirectory(allocator, config.root, owned_etc, &diag) catch |err|
            dieNamespace(write_fd, config.stderr_fd, .mount_tree, err, diag);

        namespace.substitute(allocator, config.root, &resolver_substitutions, &diag) catch |err|
            dieNamespace(write_fd, config.stderr_fd, .mount_tree, err, diag);
    }

    namespace.pivotInto(allocator, config.root, &diag) catch |err|
        dieNamespace(write_fd, config.stderr_fd, .pivot, err, diag);

    var cap_diag: ?capabilities.Diagnostic = null;
    capabilities.dropAll(&cap_diag) catch |err|
        dieCapabilities(write_fd, config.stderr_fd, err, cap_diag);

    var landlock_diag: ?landlock.Diagnostic = null;
    var ruleset = landlock.Ruleset.init(abi, &landlock_diag) catch |err|
        dieLandlock(write_fd, config.stderr_fd, .landlock_init, err, landlock_diag);
    defer ruleset.deinit();
    for (config.rules) |rule| {
        ruleset.allowPath(rule.path, rule.access, &landlock_diag) catch |err|
            dieLandlock(write_fd, config.stderr_fd, .landlock_rule, err, landlock_diag);
    }

    // A routed sandbox grants read on the resolver it placed itself, because this
    // driver chooses those paths and nothing in `config.rules` names them. Without
    // it the router, the ruleset and the netns are all fine while every name lookup
    // fails: `cat /etc/resolv.conf` answered `EACCES` inside a routed tool call.
    if (config.net_router != null) {
        for (resolver_text_targets) |target| {
            ruleset.allowPath(target, .{ .read_file = true }, &landlock_diag) catch |err|
                dieLandlock(write_fd, config.stderr_fd, .landlock_rule, err, landlock_diag);
        }
    }
    ruleset.restrictSelf(&landlock_diag) catch |err|
        dieLandlock(write_fd, config.stderr_fd, .landlock_restrict, err, landlock_diag);

    joinFreshSessionKeyring(config.stderr_fd) catch |err|
        die(write_fd, config.stderr_fd, .session_keyring, err);

    if (notify_fd < 0) {
        seccomp.install(bpf.Prog.init(insns)) catch |err|
            die(write_fd, config.stderr_fd, .seccomp_install, err);
        return;
    }

    // The filter and the handover are one step and nothing may run between them.
    // `execve` is in the trap set, so this process's own `execve` is held by the
    // kernel until a supervisor answers it.
    const listener = seccomp.installListening(bpf.Prog.init(insns)) catch |err|
        die(write_fd, config.stderr_fd, .seccomp_install, err);

    // A filter whose listener nobody holds makes the kernel answer every observed
    // call with `ENOSYS`, so the program would be told `openat` does not exist.
    if (!notify.handOver(notify_fd, listener))
        die(write_fd, config.stderr_fd, .notify_handover, error.Unexpected);
}

const ReaderWatch = struct {
    pid: linux.pid_t,
    record: *notify.PathRecord,
};

fn mapPathRecord() ?*notify.PathRecord {
    // Zig 0.16's `linux.mmap` takes the flags as packed structs. The plain numbers
    // are what the kernel's own header calls `MAP_SHARED` and `MAP_ANONYMOUS`.
    const prot: linux.PROT = @bitCast(@as(u32, 0x1 | 0x2));
    const flags: linux.MAP = @bitCast(@as(u32, 0x01 | 0x20));
    const rc = linux.mmap(null, @sizeOf(notify.PathRecord), prot, flags, -1, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const record: *notify.PathRecord = @ptrFromInt(rc);
    record.* = .{};
    return record;
}

fn unmapPathRecord(record: *notify.PathRecord) void {
    _ = linux.munmap(@ptrCast(record), @sizeOf(notify.PathRecord));
}

fn reapReader(watch: ReaderWatch, middle_write_fd: i32) void {
    var status: u32 = undefined;
    const continue_errno = linux.errno(linux.kill(watch.pid, .CONT));
    switch (continue_errno) {
        .SUCCESS, .SRCH => {},
        else => dieRelayErrno("resume the path reader", continue_errno),
    }
    var rc: usize = 0;
    var tries: usize = 0;
    while (tries < 1000) : (tries += 1) {
        rc = linux.waitpid(watch.pid, &status, linux.W.NOHANG);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc != 0) break,
            .INTR => continue,
            else => break,
        }
        var pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&pause, null);
    }
    if (linux.errno(rc) == .SUCCESS and rc == 0) {
        const kill_errno = linux.errno(linux.kill(watch.pid, .KILL));
        switch (kill_errno) {
            .SUCCESS, .SRCH => {},
            else => dieRelayErrno("end the path reader", kill_errno),
        }
        rc = linux.waitpid(watch.pid, &status, 0);
        while (linux.errno(rc) == .INTR) rc = linux.waitpid(watch.pid, &status, 0);
    }

    const ending: ReaderEnd.Ending = if (linux.errno(rc) != .SUCCESS)
        .unknown
    else if (linux.W.IFSIGNALED(status))
        .signalled
    else
        .{ .exited = linux.W.EXITSTATUS(status) };
    if (!readerReported(.{
        .ready = watch.record.ready,
        .ended = watch.record.ended,
        .ending = ending,
    })) watch.record.reader_unreported = 1;

    reportTraps(middle_write_fd, &watch.record.counts);
}

pub const ReaderEnd = struct {
    ready: u32,
    ended: u32,
    ending: Ending,

    /// A union and not a status number beside a flag: `W.EXITSTATUS` of a status
    /// that names a signal is zero, so a rule on that number alone would read a
    /// `SIGKILL` as a clean exit by accident.
    pub const Ending = union(enum) {
        exited: u32,
        signalled,
        unknown,
    };
};

pub fn readerReported(end: ReaderEnd) bool {
    if (end.ready == 0) return false;
    if (end.ended == 0) return false;
    return switch (end.ending) {
        .exited => |status| status == 0,
        .signalled => true,
        .unknown => false,
    };
}

/// The path reader, R. Never returns. It confines itself before it reads
/// anything and is permitted `seccomp.reader_calls` and nothing else. It does
/// hold a copy of this program's own memory, including the provider credential,
/// and nothing here can scrub it: what is closed instead is every way out.
fn runReader(
    listener: i32,
    child_pidfd: i32,
    reader_insns: []const bpf.Insn,
    record: *notify.PathRecord,
    granted: []const []const u8,
) noreturn {
    keepOnlyDescriptors(listener, child_pidfd);

    // One capability is kept, and only one. `CAP_SYS_PTRACE` in the sandbox's own
    // user namespace is what lets this process read the observed program's memory
    // under Yama's restricted ptrace mode.
    var cap_diag: ?capabilities.Diagnostic = null;
    capabilities.keepOnly(linux.CAP.SYS_PTRACE, &cap_diag) catch linux.exit(1);

    // No Landlock ruleset of its own, which is a measurement and not an oversight.
    // Landlock only lets a process reach one in the same domain or nested inside
    // it, and the reader and the observed program build sibling domains: a reader
    // with an empty ruleset read nothing at all.
    seccomp.install(bpf.Prog.init(reader_insns)) catch linux.exit(1);

    record.ready = 1;
    const outcome = notify.serveRecording(listener, child_pidfd, record, granted);
    record.ended = 1;
    linux.exit(if (outcome == .fault) 1 else 0);
}

/// Before the filter goes on, because `close_range` is not on the reader's
/// allowlist.
fn keepOnlyDescriptors(first: i32, second: i32) void {
    keepOnlyTheseDescriptors(&.{ first, second });
}

fn keepOnlyTheseDescriptors(keep: []const i32) void {
    std.debug.assert(keep.len > 0 and keep.len <= 8);
    var sorted: [8]i32 = undefined;
    @memcpy(sorted[0..keep.len], keep);
    const held = sorted[0..keep.len];
    std.mem.sort(i32, held, {}, std.sort.asc(i32));

    const all: u32 = std.math.maxInt(u32);
    if (held[0] > 0) _ = linux.syscall3(.close_range, 0, @intCast(held[0] - 1), 0);
    for (held[1..], held[0 .. held.len - 1]) |high, low| {
        if (high > low + 1) {
            _ = linux.syscall3(.close_range, @intCast(low + 1), @intCast(high - 1), 0);
        }
    }
    _ = linux.syscall3(.close_range, @intCast(held[held.len - 1] + 1), all, 0);
}

/// What A holds while it waits for B: an empty Landlock ruleset and the same
/// seccomp filter B runs under. Best effort and never fatal, because killing A
/// would kill the caller's running program for a layer that protects nothing of
/// the caller's.
fn restrictMiddle(abi: i32, insns: []const bpf.Insn, middle_write_fd: i32) void {
    var cap_diag: ?capabilities.Diagnostic = null;
    if (capabilities.dropAll(&cap_diag)) |_| {
        middleLayerWent(.capabilities, middle_write_fd, null);
    } else |err| {
        printMiddleCapabilitiesFault(err, cap_diag);
        middleLayerWent(.capabilities, middle_write_fd, capabilitiesFaultFor(err));
    }

    var diag: ?landlock.Diagnostic = null;
    if (landlock.Ruleset.init(abi, &diag)) |ruleset| {
        var owned = ruleset;
        defer owned.deinit();
        if (owned.restrictSelf(&diag)) |_| {
            middleLayerWent(.landlock, middle_write_fd, null);
        } else |err| {
            printMiddleFault(err, diag);
            middleLayerWent(.landlock, middle_write_fd, landlockFaultFor(err));
        }
    } else |err| {
        printMiddleFault(err, diag);
        middleLayerWent(.landlock, middle_write_fd, landlockFaultFor(err));
    }

    if (seccomp.install(bpf.Prog.init(insns))) |_| {
        middleLayerWent(.seccomp, middle_write_fd, null);
    } else |err| {
        printMiddleFault(err, null);
        middleLayerWent(.seccomp, middle_write_fd, filterFaultFor(err));
    }
}

/// The fail mode is read from `iface.failModeFor` and never from the shape of
/// this file, so the value cannot drift away from the behaviour it names.
/// `comptime`, so the arm that does not apply is never emitted.
fn middleLayerWent(
    comptime layer: iface.LayerName,
    middle_write_fd: i32,
    fault: ?iface.SupervisorAudit.Fault,
) void {
    const mode = comptime iface.failModeFor(.supervisor, layer) orelse @compileError(
        "sandbox: the supervisor reports a layer the fail mode table says it never applies",
    );
    switch (comptime mode) {
        .open => reportMiddleLayer(middle_write_fd, layer, fault),
        .closed => {
            reportMiddleLayer(middle_write_fd, layer, fault);
            if (fault != null) dieRelay(error.Unexpected);
        },
    }
}

fn printMiddleCapabilitiesFault(err: anyerror, diag: ?capabilities.Diagnostic) void {
    var buffer: [256]u8 = undefined;
    const line = if (diag) |d|
        std.fmt.bufPrint(
            &buffer,
            "sandbox: the middle process could not drop its own capabilities: {f}\n",
            .{d},
        ) catch "sandbox: the middle process could not drop its own capabilities\n"
    else
        std.fmt.bufPrint(
            &buffer,
            "sandbox: the middle process could not drop its own capabilities: {s}\n",
            .{@errorName(err)},
        ) catch "sandbox: the middle process could not drop its own capabilities\n";
    writeStderr(std.posix.STDERR_FILENO, line);
}

fn printMiddleFault(err: anyerror, diag: ?landlock.Diagnostic) void {
    var buffer: [256]u8 = undefined;
    const line = if (diag) |d|
        std.fmt.bufPrint(
            &buffer,
            "sandbox: the middle process could not restrict itself: {f}\n",
            .{d},
        ) catch "sandbox: the middle process could not restrict itself\n"
    else
        std.fmt.bufPrint(
            &buffer,
            "sandbox: the middle process could not restrict itself: {s}\n",
            .{@errorName(err)},
        ) catch "sandbox: the middle process could not restrict itself\n";
    writeStderr(std.posix.STDERR_FILENO, line);
}

/// Join a fresh, anonymous session keyring. `CLONE_NEWUSER` gives a fresh user
/// keyring, but the kernel has no namespace for the session keyring, so a key
/// another host process planted there is readable from inside the sandbox. Must
/// run before `seccomp.install`, which blocks `keyctl`.
pub fn joinFreshSessionKeyring(stderr_fd: i32) error{JoinFailed}!void {
    const keyctl_join_session_keyring: usize = 1;
    const rc = linux.syscall2(.keyctl, keyctl_join_session_keyring, 0);
    const join_errno = linux.errno(rc);
    if (join_errno != .SUCCESS) {
        printFaultErrno(stderr_fd, "keyctl(KEYCTL_JOIN_SESSION_KEYRING)", join_errno);
        return error.JoinFailed;
    }
}

const last_reset_signal: u32 = 31;

/// Put every signal back to its default action with an empty mask. A child of
/// `fork` keeps the caller's own handlers: `chock run`'s `SIGTERM` handler was
/// inherited here, so the signal a deadline sent to cancel a call was caught,
/// this process did not die, and the timeout cancelled nothing. A blocked
/// signal defeats the same cancellation as a caught one.
fn resetSignalState() void {
    const to_default = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.DFL },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    var number: u32 = 1;
    while (number <= last_reset_signal) : (number += 1) {
        const sig: std.posix.SIG = @enumFromInt(number);
        if (sig == .KILL or sig == .STOP) continue;
        _ = linux.sigaction(sig, &to_default, null);
    }

    const empty = std.posix.sigemptyset();
    _ = linux.sigprocmask(std.posix.SIG.SETMASK, &empty, null);
}

/// Put this process, and everything it goes on to make, in a process group of
/// its own. A process group is not isolated by a PID namespace: `kill(0, sig)`
/// names an object the kernel holds and not a number a namespace can hide, and
/// a process inside `CLONE_NEWPID` still reached a process outside it. A
/// terminal also sends `SIGINT` to its whole foreground group, so one Ctrl-C
/// reached the caller and the running program alike.
fn newProcessGroup(write_fd: i32, stderr_fd: i32) void {
    const rc = linux.setpgid(0, 0);
    const pgid_errno = linux.errno(rc);
    if (pgid_errno != .SUCCESS) {
        dieErrno(
            write_fd,
            stderr_fd,
            .process_group,
            "setpgid into a group of the sandbox's own",
            pgid_errno,
        );
    }
}

/// Give the child `/dev/null` on descriptor 0. A password prompt then reads end
/// of file instead of hanging, and if descriptor 0 was the caller's controlling
/// terminal, `ioctl(0, TIOCSTI)` could push characters into its input queue. No
/// Landlock rule covers a descriptor that was already open. It stays valid after
/// `pivot_root`, because an open descriptor is not resolved again.
fn redirectStdinToDevNull(write_fd: i32, stderr_fd: i32) void {
    const fd_rc = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    const open_errno = linux.errno(fd_rc);
    if (open_errno != .SUCCESS) {
        dieErrno(write_fd, stderr_fd, .stdin_redirect, "open /dev/null for standard input", open_errno);
    }
    const fd: i32 = @intCast(fd_rc);

    const dup2_errno = linux.errno(linux.dup2(fd, std.posix.STDIN_FILENO));
    if (dup2_errno != .SUCCESS) {
        dieErrno(write_fd, stderr_fd, .stdin_redirect, "dup2 /dev/null onto standard input", dup2_errno);
    }

    if (fd != std.posix.STDIN_FILENO) _ = linux.close(fd);
}

/// Close every descriptor above standard error except the ones named, so one
/// opened before the sandbox was entered cannot reach the host filesystem after
/// `pivot_root`: a descriptor is not resolved again once open, so only closing
/// it removes it. `stdin_fd` is kept for exactly one number.
///
/// `device_fd` had no exemption once: A closed its own copy here, D forked
/// afterwards with nothing at that number, `poll` answered `POLLNVAL` for ever,
/// and the real parent's `sendmsg` answered `EPIPE`.
fn closeInheritedFds(
    write_fd: i32,
    middle_write_fd: i32,
    stdout_fd: i32,
    stderr_fd: i32,
    stdin_fd: ?i32,
    broker_fd: i32,
    device_fd: i32,
) void {
    const dir_rc = linux.open(
        "/proc/self/fd",
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    const dir_open_errno = linux.errno(dir_rc);
    if (dir_open_errno != .SUCCESS) {
        dieErrno(write_fd, stderr_fd, .close_fds, "open /proc/self/fd", dir_open_errno);
    }
    const dir_fd: i32 = @intCast(dir_rc);
    defer _ = linux.close(dir_fd);

    var buffer: [4096]u8 = undefined;
    while (true) {
        const nread = linux.getdents64(dir_fd, &buffer, buffer.len);
        const read_errno = linux.errno(nread);
        if (read_errno != .SUCCESS) {
            dieErrno(write_fd, stderr_fd, .close_fds, "read /proc/self/fd", read_errno);
        }
        if (nread == 0) break;

        var offset: usize = 0;
        while (offset < nread) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            // `name` is a flexible array member, so `@offsetOf` gives its true position.
            // `@sizeOf` would include tail padding the layout does not carry between entries.
            const name_offset = offset + @offsetOf(linux.dirent64, "name");
            const name_ptr: [*:0]const u8 = @ptrCast(&buffer[name_offset]);
            const name = std.mem.sliceTo(name_ptr, 0);

            if (std.fmt.parseInt(i32, name, 10)) |fd| {
                if (fd > std.posix.STDERR_FILENO and fd != dir_fd and fd != write_fd and
                    fd != middle_write_fd and fd != broker_fd and fd != device_fd and
                    fd != stdout_fd and fd != stderr_fd and fd != (stdin_fd orelse -1))
                {
                    const close_errno = linux.errno(linux.close(fd));
                    if (close_errno != .SUCCESS) {
                        dieErrno(
                            write_fd,
                            stderr_fd,
                            .close_fds,
                            "close an inherited descriptor",
                            close_errno,
                        );
                    }
                }
            } else |_| {}

            std.debug.assert(entry.reclen > 0);
            offset += entry.reclen;
        }
    }
}

/// Arm `PR_SET_PDEATHSIG` in a child of A and close the race that makes it
/// unreliable. The kernel delivers a death signal once, when `exit_notify` runs
/// for the parent, so an A that died first leaves nothing armed. `getppid`
/// cannot reveal that: A has no pid number in the namespace this process is
/// entering, so the pidfd names A by its underlying task instead.
fn armPdeathsig(write_fd: i32, stderr_fd: i32, middle_pidfd: i32) void {
    const pr_rc = linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @intFromEnum(std.posix.SIG.KILL), 0, 0, 0);
    const pr_errno = linux.errno(pr_rc);
    if (pr_errno != .SUCCESS) {
        dieErrno(write_fd, stderr_fd, .pdeathsig_prctl, "prctl(PR_SET_PDEATHSIG)", pr_errno);
    }

    var pfd = [1]linux.pollfd{.{ .fd = middle_pidfd, .events = linux.POLL.IN, .revents = 0 }};
    const poll_rc = linux.poll(&pfd, 1, 0);
    const middle_already_gone = linux.errno(poll_rc) == .SUCCESS and poll_rc > 0;
    _ = linux.close(middle_pidfd);

    if (middle_already_gone) {
        // A was already gone before the `prctl` above could register, so the kernel
        // never had a live target for PDEATHSIG. End this process the same way
        // PDEATHSIG would have, which is not a setup failure to report.
        std.posix.raise(std.posix.SIG.KILL) catch {};
        std.process.exit(1);
    }
}

fn execute(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    write_fd_in: i32,
    broker_fd: i32,
) noreturn {
    std.debug.assert(argv.len > 0);

    var write_fd = write_fd_in;

    redirectStandardStreams(config, write_fd);

    const stderr_fd = std.posix.STDERR_FILENO;

    const cwd_z = allocator.dupeZ(u8, config.cwd) catch |err| die(write_fd, stderr_fd, .exec, err);
    const chdir_errno = linux.errno(linux.chdir(cwd_z));
    if (chdir_errno != .SUCCESS) dieErrno(write_fd, stderr_fd, .exec, "chdir", chdir_errno);

    const argv_z = allocator.allocSentinel(?[*:0]const u8, argv.len, null) catch |err|
        die(write_fd, stderr_fd, .exec, err);
    for (argv, 0..) |arg, i| {
        argv_z[i] = allocator.dupeZ(u8, arg) catch |err| die(write_fd, stderr_fd, .exec, err);
    }

    const env_z = allocator.allocSentinel(?[*:0]const u8, config.env.len, null) catch |err|
        die(write_fd, stderr_fd, .exec, err);
    for (config.env, 0..) |item, i| {
        env_z[i] = allocator.dupeZ(u8, item) catch |err| die(write_fd, stderr_fd, .exec, err);
    }

    // Three of these limits would refuse the setup path itself if they went on
    // earlier: `RLIMIT_DATA` bounds memory inherited across two forks,
    // `RLIMIT_NOFILE` has to follow Landlock and the mount tree, and `RLIMIT_CPU`
    // should count the caller's program. `placeBrokerFd` comes first, because it
    // needs two spare descriptor numbers that `RLIMIT_NOFILE` would refuse.
    if (broker_fd >= 0) placeBrokerFd(broker_fd, &write_fd, stderr_fd);

    var limit_diag: ?rlimits.Diagnostic = null;
    rlimits.apply(config.limits, rlimits.runningKernel(), &limit_diag) catch |err|
        dieLimit(write_fd, stderr_fd, err, limit_diag);

    const exec_rc = linux.execve(argv_z[0].?, argv_z, env_z);
    dieErrno(write_fd, stderr_fd, .exec, "execve", linux.errno(exec_rc));
}

/// Put the broker socket on `netbroker.fd_number` and take its close-on-exec
/// flag off. The setup pipe is moved when it sits on that number: which number
/// it got is decided by the caller's own descriptor table, so a `dup2` onto it
/// would take away the one channel `dieErrno` reports an `execve` failure on.
/// `dup2` is what clears the flag.
fn placeBrokerFd(broker_fd: i32, write_fd: *i32, stderr_fd: i32) void {
    const target = netbroker.fd_number;

    if (write_fd.* == target) {
        const moved = linux.fcntl(write_fd.*, linux.F.DUPFD_CLOEXEC, @intCast(target + 1));
        if (linux.errno(moved) != .SUCCESS) {
            dieErrno(
                write_fd.*,
                stderr_fd,
                .exec,
                "fcntl to move the setup pipe off the broker descriptor",
                linux.errno(moved),
            );
        }
        _ = linux.close(write_fd.*);
        write_fd.* = @intCast(moved);
    }

    if (broker_fd == target) {
        const rc = linux.fcntl(target, linux.F.SETFD, 0);
        if (linux.errno(rc) != .SUCCESS) {
            dieErrno(
                write_fd.*,
                stderr_fd,
                .exec,
                "fcntl to clear close-on-exec on the broker descriptor",
                linux.errno(rc),
            );
        }
        return;
    }

    const rc = linux.dup2(broker_fd, target);
    if (linux.errno(rc) != .SUCCESS) {
        dieErrno(write_fd.*, stderr_fd, .exec, "dup2 onto the broker descriptor", linux.errno(rc));
    }
    _ = linux.close(broker_fd);
}

/// Point this process's own standard streams at the descriptors `config` names.
/// Standard input is replaced here and nowhere earlier, so every step of the
/// setup path reads descriptor 0 as `/dev/null` and a sandbox that failed to
/// come up hands the caller's pipe to nothing.
fn redirectStandardStreams(config: Config, write_fd: i32) void {
    if (config.stdin_fd) |fd| {
        if (fd != std.posix.STDIN_FILENO) {
            const dup2_errno = linux.errno(linux.dup2(fd, std.posix.STDIN_FILENO));
            if (dup2_errno != .SUCCESS)
                dieErrno(write_fd, config.stderr_fd, .exec, "dup2 onto standard input", dup2_errno);
        }
    }
    if (config.stdout_fd != std.posix.STDOUT_FILENO) {
        const dup2_errno = linux.errno(linux.dup2(config.stdout_fd, std.posix.STDOUT_FILENO));
        if (dup2_errno != .SUCCESS)
            dieErrno(write_fd, config.stderr_fd, .exec, "dup2 onto standard output", dup2_errno);
    }
    if (config.stderr_fd != std.posix.STDERR_FILENO) {
        const dup2_errno = linux.errno(linux.dup2(config.stderr_fd, std.posix.STDERR_FILENO));
        if (dup2_errno != .SUCCESS)
            dieErrno(write_fd, config.stderr_fd, .exec, "dup2 onto standard error", dup2_errno);
    }

    var closed: [3]i32 = @splat(-1);
    var closed_count: usize = 0;
    for ([_]i32{ config.stdout_fd, config.stderr_fd, config.stdin_fd orelse -1 }) |fd| {
        if (fd <= std.posix.STDERR_FILENO) continue;
        var seen = false;
        for (closed[0..closed_count]) |other| {
            if (other == fd) seen = true;
        }
        if (seen) continue;
        closed[closed_count] = fd;
        closed_count += 1;
        _ = linux.close(fd);
    }
}

fn absoluteDirPath(buffer: []u8, dir_fd: linux.fd_t) ![:0]u8 {
    var link_buffer: [64]u8 = undefined;
    const link = std.fmt.bufPrintZ(&link_buffer, "/proc/self/fd/{d}", .{dir_fd}) catch unreachable;
    const rc = linux.readlink(link, buffer.ptr, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.ReadlinkFailed;
    const len: usize = @intCast(rc);
    buffer[len] = 0;
    return buffer[0..len :0];
}

test "the middle pipe carries the scratch fact and a layer fact, and a reader tells them apart" {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    defer _ = linux.close(fds[0]);

    reportMiddleLayer(fds[1], .seccomp, .no_new_privs_refused);
    writeMiddleRecord(fds[1], tag_scratch_full, 0, 1);
    _ = linux.close(fds[1]);

    const report = readMiddleReport(fds[0]);
    try std.testing.expect(report.scratch_full);
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome{ .off = .no_new_privs_refused },
        report.layers.get(.seccomp),
    );
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome.unsaid,
        report.layers.get(.landlock),
    );
}

test "each layer the supervisor puts on itself comes back under its own name" {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    defer _ = linux.close(fds[0]);

    reportMiddleLayer(fds[1], .capabilities, .rejected);
    reportMiddleLayer(fds[1], .landlock, .not_supported);
    reportMiddleLayer(fds[1], .seccomp, null);
    _ = linux.close(fds[1]);

    const report = readMiddleReport(fds[0]);
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome{ .off = .rejected },
        report.layers.get(.capabilities),
    );
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome{ .off = .not_supported },
        report.layers.get(.landlock),
    );
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome.on,
        report.layers.get(.seccomp),
    );
}

test "a supervisor that said nothing is not a supervisor that was confined" {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    defer _ = linux.close(fds[0]);
    _ = linux.close(fds[1]);

    const report = readMiddleReport(fds[0]);
    try std.testing.expect(!report.scratch_full);
    for (comptime std.enums.values(iface.LayerName)) |layer| {
        try std.testing.expectEqual(
            iface.SupervisorAudit.Outcome.unsaid,
            report.layers.get(layer),
        );
    }
}

test "every way the filter can be refused reaches the reader as its own fault" {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    defer _ = linux.close(fds[0]);

    const errors = [_]seccomp.InstallError{
        error.NotSupported,
        error.NoNewPrivsRefused,
        error.NotPermitted,
        error.Rejected,
        error.Unexpected,
    };
    var seen: [errors.len]iface.SupervisorAudit.Fault = undefined;
    for (errors, 0..) |err, index| {
        reportMiddleLayer(fds[1], .seccomp, filterFaultFor(err));
        var record: [record_bytes]u8 = undefined;
        const rc = linux.read(fds[0], &record, record.len);
        try std.testing.expectEqual(.SUCCESS, linux.errno(rc));
        try std.testing.expectEqual(@as(usize, record_bytes), rc);
        try std.testing.expectEqual(tag_middle_layer, record[0]);

        try std.testing.expectEqual(
            @as(u8, @intFromEnum(iface.LayerName.seccomp)),
            record[1],
        );
        const value = std.mem.readInt(u64, record[2..record_bytes], .little);
        switch (outcomeFor(@truncate(value))) {
            .off => |fault| seen[index] = fault,
            .on, .unsaid => return error.TestUnexpectedResult,
        }
    }
    _ = linux.close(fds[1]);

    for (seen, 0..) |fault, index| {
        for (seen[index + 1 ..]) |other| try std.testing.expect(fault != other);
    }
}

test "a layer that went on is the only value byte that reads as confined" {
    try std.testing.expectEqual(iface.SupervisorAudit.Outcome.on, outcomeFor(0));
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome{ .off = .rejected },
        outcomeFor(@intFromEnum(iface.SupervisorAudit.Fault.rejected)),
    );
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome{ .off = .unexpected },
        outcomeFor(200),
    );
}

test "closeInheritedFds closes every descriptor above stderr, and leaves stderr open" {
    // Model a descriptor a long lived host process would still hold at the moment
    // it forks a sandboxed child: opened before the sandbox is entered, still
    // resolvable after `pivot_root`, because closing it is the only thing that
    // revokes it.
    const extra_a = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_a));
    const extra_b = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_b));
    defer _ = linux.close(@intCast(extra_a));
    defer _ = linux.close(@intCast(extra_b));

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        closeInheritedFds(-1, -1, -1, -1, null, -1, -1);

        const a_result = linux.fcntl(@intCast(extra_a), linux.F.GETFD, 0);
        const b_result = linux.fcntl(@intCast(extra_b), linux.F.GETFD, 0);
        const stderr_result = linux.fcntl(std.posix.STDERR_FILENO, linux.F.GETFD, 0);
        const closed_the_extras = linux.errno(a_result) == .BADF and linux.errno(b_result) == .BADF;
        const kept_stderr = linux.errno(stderr_result) == .SUCCESS;
        std.process.exit(if (closed_the_extras and kept_stderr) 0 else 1);
    }

    var status: u32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}

test "closeInheritedFds keeps exactly the middle pipe's write end, and no other" {
    // With the middle pipe's exemption absent, the scratch report was written to a
    // descriptor this pass had already closed, the write answered `EBADF`, and a
    // full scratch area came back with no limit named.
    const extra_a = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_a));
    const extra_b = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_b));
    defer _ = linux.close(@intCast(extra_a));
    defer _ = linux.close(@intCast(extra_b));

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        closeInheritedFds(-1, @intCast(extra_b), -1, -1, null, -1, -1);

        const a_result = linux.fcntl(@intCast(extra_a), linux.F.GETFD, 0);
        const b_result = linux.fcntl(@intCast(extra_b), linux.F.GETFD, 0);
        const closed_the_other = linux.errno(a_result) == .BADF;
        const kept_the_middle_pipe = linux.errno(b_result) == .SUCCESS;
        std.process.exit(if (closed_the_other and kept_the_middle_pipe) 0 else 1);
    }

    var status: u32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}

test "closeInheritedFds keeps exactly the device link's own child end, and no other" {
    // `device_fd` named no exemption at all before this, so A closed its own copy
    // before D could inherit an open one: `poll` answered `POLLNVAL` on every turn
    // of D's loop and the real parent's `sendmsg` answered `EPIPE`.
    const extra_a = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_a));
    const extra_b = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_b));
    defer _ = linux.close(@intCast(extra_a));
    defer _ = linux.close(@intCast(extra_b));

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        closeInheritedFds(-1, -1, -1, -1, null, -1, @intCast(extra_b));

        const a_result = linux.fcntl(@intCast(extra_a), linux.F.GETFD, 0);
        const b_result = linux.fcntl(@intCast(extra_b), linux.F.GETFD, 0);
        const closed_the_other = linux.errno(a_result) == .BADF;
        const kept_the_device_fd = linux.errno(b_result) == .SUCCESS;
        std.process.exit(if (closed_the_other and kept_the_device_fd) 0 else 1);
    }

    var status: u32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}

test "closeInheritedFds keeps exactly the descriptor Config.stdin_fd names, and no other" {
    const extra_a = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_a));
    const extra_b = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_b));
    defer _ = linux.close(@intCast(extra_a));
    defer _ = linux.close(@intCast(extra_b));

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        closeInheritedFds(-1, -1, -1, -1, @intCast(extra_b), -1, -1);

        const a_result = linux.fcntl(@intCast(extra_a), linux.F.GETFD, 0);
        const b_result = linux.fcntl(@intCast(extra_b), linux.F.GETFD, 0);
        const closed_the_other = linux.errno(a_result) == .BADF;
        const kept_the_named_one = linux.errno(b_result) == .SUCCESS;
        std.process.exit(if (closed_the_other and kept_the_named_one) 0 else 1);
    }

    var status: u32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}

test "the broker socket lands on its own number even when the setup pipe is already there" {
    const target = netbroker.fd_number;

    var pipe_fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&pipe_fds, .{})));
    defer _ = linux.close(pipe_fds[0]);
    defer _ = linux.close(pipe_fds[1]);

    const pair = try netbroker.makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);
    const token = "the-broker-socket";
    try std.testing.expectEqual(token.len, linux.write(pair[0], token, token.len));

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        if (linux.errno(linux.dup2(pipe_fds[1], target)) != .SUCCESS) std.process.exit(1);
        var write_fd: i32 = target;

        placeBrokerFd(pair[1], &write_fd, std.posix.STDERR_FILENO);

        var buffer: [64]u8 = undefined;
        const read = linux.read(target, &buffer, buffer.len);
        if (linux.errno(read) != .SUCCESS or !std.mem.eql(u8, buffer[0..read], token)) std.process.exit(1);

        const flags = linux.fcntl(target, linux.F.GETFD, 0);
        if (linux.errno(flags) != .SUCCESS or flags != 0) std.process.exit(1);

        if (write_fd == target) std.process.exit(1);
        const wrote = linux.write(write_fd, "p", 1);
        if (linux.errno(wrote) != .SUCCESS or wrote != 1) std.process.exit(1);
        std.process.exit(0);
    }

    var status: u32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));

    var one: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), linux.read(pipe_fds[0], &one, 1));
    try std.testing.expectEqual(@as(u8, 'p'), one[0]);
}

test "a filtered config with nobody to ask is refused, and refused before anything is forked" {
    var report: LandlockReport = undefined;
    try std.testing.expectError(error.NetBrokerMissing, spawn(
        std.testing.allocator,
        .{
            .root = "/does-not-exist",
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
            .network = .filtered,
        },
        &.{"/does-not-exist"},
        &report,
        null,
    ));

    const Never = struct {
        fn connect(ptr: *anyopaque, host: []const u8, port: u16) iface.NetBroker.Grant {
            _ = ptr;
            _ = host;
            _ = port;
            return .refused;
        }
    };
    var nothing: u8 = 0;
    const broker = iface.NetBroker{
        .ptr = &nothing,
        .vtable = &.{ .connect = Never.connect },
    };
    for ([_]namespace.Network{ .none, .host }) |network| {
        try std.testing.expectError(error.NetBrokerNotFiltered, spawn(
            std.testing.allocator,
            .{
                .root = "/does-not-exist",
                .mounts = &.{},
                .rules = &.{},
                .cwd = "/",
                .env = &.{},
                .network = network,
                .net_broker = broker,
            },
            &.{"/does-not-exist"},
            &report,
            null,
        ));
    }
}

test "a filtered config that names both seams is refused, and one that names a router outside filtered too" {
    var report: LandlockReport = undefined;

    const Never = struct {
        fn connect(_: *anyopaque, _: []const u8, _: u16) iface.NetBroker.Grant {
            return .refused;
        }
        fn resolve(_: *anyopaque, _: []const u8, _: iface.NetRouter.Family) iface.NetRouter.Resolution {
            return .refused;
        }
        fn open(_: *anyopaque, _: iface.NetRouter.Address, _: u16) iface.NetBroker.Grant {
            return .refused;
        }
    };
    var nothing: u8 = 0;
    const broker = iface.NetBroker{ .ptr = &nothing, .vtable = &.{ .connect = Never.connect } };
    const router_seam = iface.NetRouter{
        .ptr = &nothing,
        .vtable = &.{ .resolve = Never.resolve, .open = Never.open },
    };

    try std.testing.expectError(error.NetRouterAndBroker, spawn(
        std.testing.allocator,
        .{
            .root = "/does-not-exist",
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
            .network = .filtered,
            .net_broker = broker,
            .net_router = router_seam,
        },
        &.{"/does-not-exist"},
        &report,
        null,
    ));

    for ([_]namespace.Network{ .none, .host }) |network| {
        try std.testing.expectError(error.NetRouterNotFiltered, spawn(
            std.testing.allocator,
            .{
                .root = "/does-not-exist",
                .mounts = &.{},
                .rules = &.{},
                .cwd = "/",
                .env = &.{},
                .network = network,
                .net_router = router_seam,
            },
            &.{"/does-not-exist"},
            &report,
            null,
        ));
    }
}

test "a device source with no device tree is refused, and refused before anything is forked" {
    var report: LandlockReport = undefined;

    const Never = struct {
        fn wakeup(_: *anyopaque) i32 {
            return -1;
        }
        fn next(_: *anyopaque) ?iface.DeviceSource.Change {
            return null;
        }
    };
    var nothing: u8 = 0;
    const device = iface.DeviceSource{
        .ptr = &nothing,
        .vtable = &.{ .wakeup = Never.wakeup, .next = Never.next },
    };

    try std.testing.expectError(error.DeviceSourceNeedsTree, spawn(
        std.testing.allocator,
        .{
            .root = "/does-not-exist",
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .device_source = device,
        },
        &.{"/does-not-exist"},
        &report,
        null,
    ));
}

test "spawn reports the Landlock ABI and its features before it ever forks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    var report: LandlockReport = undefined;

    // A boundary that was never reached is not a boundary that held: a machine
    // that will not give a sandbox measures nothing here. Asked in a child, the
    // only way to ask without spending this process's own one namespace.
    if (!namespace.probeAvailability().available()) return error.SkipZigTest;

    const devnull_rc = linux.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(devnull_rc));
    const devnull: i32 = @intCast(devnull_rc);
    defer _ = linux.close(devnull);

    const saved_stderr_rc = linux.dup(std.posix.STDERR_FILENO);
    try std.testing.expectEqual(.SUCCESS, linux.errno(saved_stderr_rc));
    const saved_stderr: i32 = @intCast(saved_stderr_rc);
    defer _ = linux.close(saved_stderr);

    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.dup2(devnull, std.posix.STDERR_FILENO)));
    defer _ = linux.dup2(saved_stderr, std.posix.STDERR_FILENO);

    const err = spawn(std.testing.allocator, .{
        .root = root_z,
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    }, &.{"/does-not-exist"}, &report, null);

    _ = linux.dup2(saved_stderr, std.posix.STDERR_FILENO);

    if (err) |_| {
        return error.TestUnexpectedResult;
    } else |actual_err| {
        if (actual_err == error.LandlockUnavailable) return error.SkipZigTest;
        try std.testing.expectEqual(error.ExecFailed, actual_err);
    }

    try std.testing.expect(report.abi >= 1);
    try std.testing.expectEqual(landlock.featuresFor(report.abi), report.features);
}

test "regression: removeContentsBestEffort clears a tree too deep for an absolute path" {
    // The old walk built an absolute path for every entry, and a tree deep enough
    // made it exceed `PATH_MAX`, so the walk stopped with `ENAMETOOLONG` and left
    // 4098 directories on the host.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    const root_rc = linux.open(root_z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(root_rc));
    var dir_fd: i32 = @intCast(root_rc);

    const depth = 4100;
    var built: usize = 0;
    while (built < depth) : (built += 1) {
        if (linux.errno(linux.mkdirat(dir_fd, "d", 0o755)) != .SUCCESS) break;
        const next_rc = linux.openat(dir_fd, "d", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        if (linux.errno(next_rc) != .SUCCESS) break;
        _ = linux.close(dir_fd);
        dir_fd = @intCast(next_rc);
    }
    _ = linux.close(dir_fd);
    try std.testing.expectEqual(depth, built);

    removeContentsBestEffort(std.testing.allocator, root_z);

    const reopen_rc = linux.open(root_z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(reopen_rc));
    const reopened: i32 = @intCast(reopen_rc);
    defer _ = linux.close(reopened);
    try std.testing.expect(isEmptyDirectory(reopened));
}

fn isEmptyDirectory(dir_fd: i32) bool {
    var buffer: [4096]u8 = undefined;
    while (true) {
        const nread = linux.getdents64(dir_fd, &buffer, buffer.len);
        if (linux.errno(nread) != .SUCCESS) return false;
        if (nread == 0) return true;

        var offset: usize = 0;
        while (offset < nread) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            const name_offset = offset + @offsetOf(linux.dirent64, "name");
            const name_ptr: [*:0]const u8 = @ptrCast(&buffer[name_offset]);
            const name = std.mem.sliceTo(name_ptr, 0);
            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) return false;
            offset += entry.reclen;
        }
    }
}

test "a machine that refuses the user namespace says which call it refused, and with what errno" {
    // This machine gives a user namespace, so the only way to see the path a
    // machine that refuses one takes is to make `unshare` answer `EPERM`, which a
    // seccomp filter does. The filter is inherited, so it goes on a child.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{})));
    defer _ = linux.close(fds[0]);

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        var insns = [_]bpf.Insn{
            bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr),
            bpf.jump(bpf.JMP_JEQ_K, @intFromEnum(linux.SYS.unshare), 0, 1),
            bpf.stmt(bpf.RET_K, seccomp.RET_ERRNO_PERM),
            bpf.stmt(bpf.RET_K, seccomp.RET_ALLOW),
        };
        seccomp.install(bpf.Prog.init(&insns)) catch std.process.exit(3);

        const err = spawn(std.heap.page_allocator, .{
            .root = root_z,
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
            .stderr_fd = fds[1],
        }, &.{"/does-not-exist"}, null, null);
        if (err) |_| {
            std.process.exit(1);
        } else |actual| {
            if (actual == error.LandlockUnavailable) std.process.exit(4);
            if (actual != error.NamespaceFailed) std.process.exit(2);
            std.process.exit(0);
        }
    }

    _ = linux.close(fds[1]);
    var text: [256]u8 = undefined;
    var filled: usize = 0;
    while (filled < text.len) {
        const rc = linux.read(fds[0], text[filled..].ptr, text.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        filled += rc;
    }

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(status));

    const code = linux.W.EXITSTATUS(status);
    if (code == 3 or code == 4) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), code);

    try std.testing.expectEqualStrings(
        "sandbox: the unshare that makes the namespaces failed: PERM\n",
        text[0..filled],
    );
}

test "a landlock errno travels the setup pipe, and is not lost with the layer" {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{})));
    const read_fd = fds[0];
    const write_fd = fds[1];
    defer _ = linux.close(read_fd);

    reportSetupFailure(write_fd, .landlock_restrict, @intFromEnum(linux.E.PERM));
    _ = linux.close(write_fd);

    const record = (try readSetupReport(read_fd)).?;
    try std.testing.expectEqual(@intFromEnum(SetupStep.landlock_restrict), record.step);
    try std.testing.expectEqual(@as(i32, @intFromEnum(linux.E.PERM)), record.errno);

    try std.testing.expectEqual(
        @as(SetupError, error.LandlockRestrictFailed),
        setupErrorFor(.landlock_restrict),
    );
}

test "a handle answers Gone once the process it names has been reaped" {
    // A pid that has been reaped names nothing, and the kernel gives the number to
    // whatever starts next: a teardown path that signalled the number
    // unconditionally sent `SIGKILL` to the process group of an unrelated build.
    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);
    if (pid == 0) {
        _ = linux.nanosleep(&.{ .sec = 30, .nsec = 0 }, null);
        std.process.exit(0);
    }

    var middle: iface.Middle = .{ .pid = pid };
    const pidfd_rc = linux.pidfd_open(pid, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(pidfd_rc));
    middle.fd = @intCast(pidfd_rc);

    // Close on exec, which the kernel sets for every pidfd, checked rather than
    // trusted: without it an unrelated `execve` in a caller's process would inherit
    // a descriptor that kills a running tool call.
    const fd_flags = linux.fcntl(middle.fd, linux.F.GETFD, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(fd_flags));
    try std.testing.expect((fd_flags & linux.FD_CLOEXEC) != 0);

    try signalMiddle(middle.fd, std.posix.SIG.KILL);

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFSIGNALED(status));
    try std.testing.expectEqual(linux.SIG.KILL, linux.W.TERMSIG(status));

    try std.testing.expectError(error.Gone, signalMiddle(middle.fd, std.posix.SIG.KILL));

    closeMiddle(&middle);
    try std.testing.expectEqual(@as(std.posix.fd_t, -1), middle.fd);
    try std.testing.expectError(error.NoHandle, signalMiddle(middle.fd, std.posix.SIG.KILL));
    closeMiddle(&middle);
}

test "a reaped number really does name somebody else, and the handle still reaches nobody" {
    // The recycle is forced rather than waited for: inside a pid namespace of its
    // own the numbers start at 1, and `ns_last_pid` sets where the next one comes
    // from. A machine whose user namespace carries no capability measures nothing
    // here, because the child needs `CAP_SYS_ADMIN` to put the counter back.
    if (!namespace.probeAvailability().available()) return error.SkipZigTest;

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const outer: linux.pid_t = @intCast(fork_rc);

    if (outer == 0) {
        if (linux.errno(linux.unshare(linux.CLONE.NEWUSER | linux.CLONE.NEWPID)) != .SUCCESS) {
            std.process.exit(20);
        }

        const init_rc = linux.fork();
        if (linux.errno(init_rc) != .SUCCESS) std.process.exit(21);
        const init_pid: linux.pid_t = @intCast(init_rc);

        if (init_pid == 0) {
            const first_rc = linux.fork();
            if (linux.errno(first_rc) != .SUCCESS) std.process.exit(22);
            const first: linux.pid_t = @intCast(first_rc);
            if (first == 0) std.process.exit(0);

            const handle_rc = linux.pidfd_open(first, 0);
            if (linux.errno(handle_rc) != .SUCCESS) std.process.exit(23);
            const handle: i32 = @intCast(handle_rc);

            var status: u32 = undefined;
            var wait_rc = linux.waitpid(first, &status, 0);
            while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(first, &status, 0);
            if (linux.errno(wait_rc) != .SUCCESS) std.process.exit(24);

            const counter = linux.open("/proc/sys/kernel/ns_last_pid", .{ .ACCMODE = .WRONLY }, 0);
            if (linux.errno(counter) != .SUCCESS) std.process.exit(25);
            const counter_fd: i32 = @intCast(counter);
            var want_buf: [16]u8 = undefined;
            const want = std.fmt.bufPrint(&want_buf, "{d}", .{first - 1}) catch unreachable;
            const written = linux.write(counter_fd, want.ptr, want.len);
            _ = linux.close(counter_fd);
            if (linux.errno(written) != .SUCCESS) std.process.exit(26);

            const second_rc = linux.fork();
            if (linux.errno(second_rc) != .SUCCESS) std.process.exit(27);
            const second: linux.pid_t = @intCast(second_rc);
            if (second == 0) {
                _ = linux.nanosleep(&.{ .sec = 30, .nsec = 0 }, null);
                std.process.exit(0);
            }
            if (second != first) {
                _ = linux.kill(second, .KILL);
                _ = linux.waitpid(second, &status, 0);
                std.process.exit(28);
            }

            if (linux.errno(linux.kill(first, @as(std.posix.SIG, @enumFromInt(0)))) != .SUCCESS) {
                std.process.exit(29);
            }

            if (signalMiddle(handle, std.posix.SIG.KILL)) |_| {
                std.process.exit(30);
            } else |err| {
                if (err != error.Gone) std.process.exit(31);
            }

            _ = linux.nanosleep(&.{ .sec = 0, .nsec = 200_000_000 }, null);
            const nohang = linux.waitpid(second, &status, linux.W.NOHANG);
            if (nohang != 0) std.process.exit(32);

            _ = linux.kill(second, .KILL);
            _ = linux.waitpid(second, &status, 0);
            _ = linux.close(handle);
            std.process.exit(0);
        }

        var status: u32 = undefined;
        var wait_rc = linux.waitpid(init_pid, &status, 0);
        while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(init_pid, &status, 0);
        if (linux.errno(wait_rc) != .SUCCESS) std.process.exit(33);
        if (!linux.W.IFEXITED(status)) std.process.exit(34);
        std.process.exit(linux.W.EXITSTATUS(status));
    }

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(outer, &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(outer, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(status));

    const code = linux.W.EXITSTATUS(status);
    if (code == 20 or code == 28) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u8, 0), code);
}

test "a supplied cgroup the kernel refuses is reported by name, and nothing is forked" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    const not_a_cgroup_rc = linux.open("/proc/self", .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(not_a_cgroup_rc));
    const not_a_cgroup: i32 = @intCast(not_a_cgroup_rc);
    defer _ = linux.close(not_a_cgroup);

    for ([_]std.posix.fd_t{ not_a_cgroup, -1 }) |fd| {
        var middle: iface.Middle = .{};
        defer iface.closeMiddle(&middle);

        const err = spawn(std.testing.allocator, .{
            .root = root_z,
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
            .containment = .{ .supplied = .{ .fd = fd } },
        }, &.{"/does-not-exist"}, null, &middle);

        if (err) |_| {
            return error.TestUnexpectedResult;
        } else |actual| {
            if (actual == error.LandlockUnavailable) return error.SkipZigTest;
            try std.testing.expectEqual(error.CgroupPlacementRefused, actual);
        }

        try std.testing.expectEqual(@as(std.posix.pid_t, 0), middle.pid);
        try std.testing.expectEqual(@as(std.posix.fd_t, -1), middle.fd);
    }
}

const TestCgroupPair = struct {
    parent_buffer: [std.fs.max_path_bytes]u8 = undefined,
    parent_len: usize = 0,
    target_buffer: [std.fs.max_path_bytes]u8 = undefined,
    target_len: usize = 0,

    fn parent(self: *const TestCgroupPair) []const u8 {
        return self.parent_buffer[0..self.parent_len];
    }

    fn target(self: *const TestCgroupPair) []const u8 {
        return self.target_buffer[0..self.target_len];
    }
};

const supplied_memory_max = "100663296";

const supplied_pids_max = "97";

test "spawn puts the sandboxed program in the caller's own cgroup at creation, and writes nothing into it" {
    // Reading the child's membership afterwards cannot tell `CLONE_INTO_CGROUP`
    // from a write to `cgroup.procs`. The kernel's own `pids` accounting can: it
    // charges a new task to the destination cgroup when the clone names one and to
    // the current one when it does not.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    if (!namespace.probeAvailability().available()) return error.SkipZigTest;

    var pair = TestCgroupPair{};
    if (!makeTestCgroupPair(&pair)) return error.SkipZigTest;
    defer removeTestCgroup(pair.parent());
    defer removeTestCgroup(pair.target());

    if (!writeTestCgroupFile(pair.target(), "memory.max", supplied_memory_max)) return error.SkipZigTest;
    if (!writeTestCgroupFile(pair.target(), "pids.max", supplied_pids_max)) return error.SkipZigTest;

    var target_z: [std.fs.max_path_bytes]u8 = undefined;
    const target_path = nullTerminate(&target_z, pair.target()) orelse return error.SkipZigTest;
    const target_fd_rc = linux.open(
        target_path.ptr,
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(target_fd_rc) != .SUCCESS) return error.SkipZigTest;
    const target_fd: i32 = @intCast(target_fd_rc);
    defer _ = linux.close(target_fd);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{})));
    defer _ = linux.close(fds[0]);

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        std.process.exit(measureSuppliedPlacement(&pair, target_fd, root_z));
    }

    _ = linux.close(fds[1]);
    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(status));

    const code = linux.W.EXITSTATUS(status);
    if (code == 10 or code == 11) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), code);

    var buffer: [4096]u8 = undefined;
    try std.testing.expectEqualStrings(
        supplied_memory_max,
        readTestCgroupFile(pair.target(), "memory.max", &buffer) orelse return error.SkipZigTest,
    );
    try std.testing.expectEqualStrings(
        supplied_pids_max,
        readTestCgroupFile(pair.target(), "pids.max", &buffer) orelse return error.SkipZigTest,
    );
    try std.testing.expectEqualStrings(
        "max",
        readTestCgroupFile(pair.target(), "memory.swap.max", &buffer) orelse return error.SkipZigTest,
    );
}

fn measureSuppliedPlacement(
    pair: *const TestCgroupPair,
    target_fd: i32,
    root_z: [:0]const u8,
) u8 {
    if (!writeTestCgroupFile(pair.parent(), "cgroup.procs", "0")) return 10;
    var buffer: [4096]u8 = undefined;
    const current = readTestCgroupFile(pair.parent(), "pids.current", &buffer) orelse return 10;
    if (!writeTestCgroupFile(pair.parent(), "pids.max", current)) return 10;

    const devnull_rc = linux.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
    if (linux.errno(devnull_rc) != .SUCCESS) return 10;
    const devnull: i32 = @intCast(devnull_rc);

    const base = Config{
        .root = root_z,
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .stderr_fd = devnull,
    };

    const best_effort = base;
    if (spawn(std.heap.page_allocator, best_effort, &.{"/does-not-exist"}, null, null)) |_| {
        return 2;
    } else |err| {
        if (err == error.LandlockUnavailable) return 11;
        if (err != error.Unexpected) return 2;
    }

    var report: LimitsReport = undefined;
    var supplied = base;
    supplied.containment = .{ .supplied = .{ .fd = target_fd } };
    supplied.limits_report = &report;
    if (spawn(std.heap.page_allocator, supplied, &.{"/does-not-exist"}, null, null)) |_| {
        return 3;
    } else |err| {
        if (err == error.LandlockUnavailable) return 11;
        if (err != error.ExecFailed) return 3;
    }

    if (report.cgroup != .supplied) return 4;
    if (report.events.oom_kills != 0 or report.events.fork_refusals != 0) return 5;

    return 0;
}

fn makeTestCgroupPair(pair: *TestCgroupPair) bool {
    var probe = cgroup.Cgroup.create(1 << 30, 64, 0xC10E0);
    defer probe.destroy();
    if (!probe.support.applied()) return false;

    const ancestor = std.fs.path.dirname(probe.path()) orelse return false;

    pair.parent_len = makeTestCgroup(&pair.parent_buffer, ancestor, 0xC10E3) orelse return false;
    pair.target_len = makeTestCgroup(&pair.target_buffer, ancestor, 0xC10E4) orelse return false;
    return true;
}

fn makeTestCgroup(buffer: []u8, ancestor: []const u8, seq: u64) ?usize {
    const written = std.fmt.bufPrint(
        buffer,
        "{s}/chock.{d}.{d}",
        .{ ancestor, linux.getpid(), seq },
    ) catch return null;
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, written) orelse return null;
    if (linux.errno(linux.mkdirat(linux.AT.FDCWD, zeroed, 0o755)) != .SUCCESS) return null;
    return written.len;
}

fn removeTestCgroup(path: []const u8) void {
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, path) orelse return;
    var attempt: usize = 0;
    while (attempt < 400) : (attempt += 1) {
        switch (linux.errno(linux.unlinkat(linux.AT.FDCWD, zeroed, linux.AT.REMOVEDIR))) {
            .SUCCESS, .NOENT => return,
            else => {},
        }
        const request = linux.timespec{ .sec = 0, .nsec = 500 * std.time.ns_per_us };
        _ = linux.nanosleep(&request, null);
    }
}

fn writeTestCgroupFile(dir: []const u8, name: []const u8, contents: []const u8) bool {
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const written = std.fmt.bufPrint(&full, "{s}/{s}", .{ dir, name }) catch return false;
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, written) orelse return false;

    const fd_rc = linux.open(zeroed, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    const rc = linux.write(fd, contents.ptr, contents.len);
    return linux.errno(rc) == .SUCCESS and rc == contents.len;
}

fn readTestCgroupFile(dir: []const u8, name: []const u8, buffer: []u8) ?[]const u8 {
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const written = std.fmt.bufPrint(&full, "{s}/{s}", .{ dir, name }) catch return null;
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, written) orelse return null;

    const fd_rc = linux.open(zeroed, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(fd, buffer[filled..].ptr, buffer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS) return null;
        if (rc == 0) break;
        filled += rc;
    }
    return std.mem.trim(u8, buffer[0..filled], " \n\r");
}

fn nullTerminate(buffer: []u8, text: []const u8) ?[:0]const u8 {
    if (text.len + 1 > buffer.len) return null;
    @memcpy(buffer[0..text.len], text);
    buffer[text.len] = 0;
    return buffer[0..text.len :0];
}

test "a reader killed after it reported is still a reader that reported" {
    // A signal can land after the reader wrote `ended` and before its exit, and the
    // record is complete at that point. With the status carried as a plain number
    // beside a flag, deleting that arm changed nothing at all, because
    // `W.EXITSTATUS` of a signal status is zero.
    try std.testing.expect(readerReported(.{
        .ready = 1,
        .ended = 1,
        .ending = .signalled,
    }));
    try std.testing.expect(readerReported(.{
        .ready = 1,
        .ended = 1,
        .ending = .{ .exited = 0 },
    }));
}

test "a reader that never started, never ended, or faulted reported nothing" {
    try std.testing.expect(!readerReported(.{
        .ready = 0,
        .ended = 0,
        .ending = .{ .exited = 0 },
    }));
    try std.testing.expect(!readerReported(.{
        .ready = 1,
        .ended = 0,
        .ending = .signalled,
    }));
    try std.testing.expect(!readerReported(.{
        .ready = 1,
        .ended = 1,
        .ending = .{ .exited = 1 },
    }));
    try std.testing.expect(!readerReported(.{
        .ready = 1,
        .ended = 1,
        .ending = .unknown,
    }));
}

test "a reader that only claims to have started has still reported nothing" {
    try std.testing.expect(!readerReported(.{
        .ready = 1,
        .ended = 0,
        .ending = .signalled,
    }));
}

test "buildDeviceTarget joins root and path, and refuses what a device helper must never resolve" {
    var buffer: [device_path_capacity]u8 = undefined;

    const joined = buildDeviceTarget(&buffer, "/tmp/chock-session", "/dev/chock-widget0") orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp/chock-session/dev/chock-widget0", joined);

    try std.testing.expectEqual(@as(u8, 0), joined.ptr[joined.len]);

    try std.testing.expect(buildDeviceTarget(&buffer, "/tmp/chock-session", "dev/chock-widget0") == null);
    try std.testing.expect(buildDeviceTarget(&buffer, "/tmp/chock-session", "/") == null);
    try std.testing.expect(buildDeviceTarget(&buffer, "/tmp/chock-session", "/dev/") == null);

    try std.testing.expect(buildDeviceTarget(&buffer, "/tmp/chock-session", "/../etc/passwd") == null);
    try std.testing.expect(buildDeviceTarget(&buffer, "/tmp/chock-session", "/dev/../../etc/passwd") == null);

    var small: [8]u8 = undefined;
    try std.testing.expect(buildDeviceTarget(&small, "/tmp/chock-session", "/dev/chock-widget0") == null);
}

test "buildDeviceSource joins hidden and source, and refuses a source that escapes the hidden tree" {
    var buffer: [device_path_capacity]u8 = undefined;

    const joined = buildDeviceSource(&buffer, "/.chock-device-tree", "bus/usb/001/005") orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(
        "/.chock-device-tree/bus/usb/001/005",
        joined,
    );
    try std.testing.expectEqual(@as(u8, 0), joined.ptr[joined.len]);

    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "/etc/passwd") == null);
    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "bus/usb/") == null);
    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "bus//005") == null);
    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "") == null);

    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "..") == null);
    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "bus/../../etc/passwd") == null);
    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "../etc/passwd") == null);

    var small: [8]u8 = undefined;
    try std.testing.expect(buildDeviceSource(&small, "/.chock-device-tree", "bus/usb/001/005") == null);
}

test "makeDeviceParents makes every directory a path needs, and tolerates one already there" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    var buffer: [device_path_capacity]u8 = undefined;
    const target = buildDeviceTarget(&buffer, root_z, "/dev/sub/chock-widget0") orelse
        return error.TestUnexpectedResult;

    try std.testing.expect(makeDeviceParents(&buffer, target.len));
    const sub_rc = linux.openat(tmp.dir.handle, "dev/sub", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(sub_rc));
    _ = linux.close(@intCast(sub_rc));
    const leaf_rc = linux.openat(tmp.dir.handle, "dev/sub/chock-widget0", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.NOENT, linux.errno(leaf_rc));

    try std.testing.expect(makeDeviceParents(&buffer, target.len));
}

test "placeDevice binds a device read-write out of a hidden tree, once this process has pivoted the way B does, and a read only remount is the trap it must never repeat" {
    if (!namespace.probeAvailability().available()) return error.SkipZigTest;

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const child: linux.pid_t = @intCast(fork_rc);

    if (child == 0) {
        var diag: ?namespace.Diagnostic = null;
        namespace.enter(.{ .network = .none, .mount = true }, &diag) catch std.process.exit(20);

        const tmp = std.testing.tmpDir(.{});
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const root_z = absoluteDirPath(&path_buffer, tmp.dir.handle) catch std.process.exit(21);

        const host_tmp = std.testing.tmpDir(.{});
        var host_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const host_z = absoluteDirPath(&host_path_buffer, host_tmp.dir.handle) catch std.process.exit(21);

        var tree_buffer: [device_path_capacity]u8 = undefined;
        if (!bindDeviceTree(&tree_buffer, root_z, "/.chock-device-tree", host_z)) std.process.exit(22);

        // Written only now, after `bindDeviceTree` has run: a node made in the host
        // directory after the bind is still visible through it, because a bind shows
        // the same live filesystem and not a copy taken at bind time.
        const source_content = "chock device probe content\n";
        const create_rc = linux.openat(
            host_tmp.dir.handle,
            "named-source",
            .{ .ACCMODE = .WRONLY, .CREAT = true },
            0o644,
        );
        if (linux.errno(create_rc) != .SUCCESS) std.process.exit(23);
        const create_fd: i32 = @intCast(create_rc);
        const wrote = linux.write(create_fd, source_content.ptr, source_content.len);
        _ = linux.close(create_fd);
        if (linux.errno(wrote) != .SUCCESS or wrote != source_content.len) std.process.exit(23);

        if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS)
            std.process.exit(24);
        if (linux.errno(linux.mount(root_z, root_z, null, linux.MS.BIND | linux.MS.REC, 0)) != .SUCCESS)
            std.process.exit(24);
        var old_root_buf: [std.fs.max_path_bytes]u8 = undefined;
        const old_root_z = std.fmt.bufPrintZ(&old_root_buf, "{s}/.old_root", .{root_z}) catch std.process.exit(24);
        if (linux.errno(linux.mkdir(old_root_z.ptr, 0o755)) != .SUCCESS) std.process.exit(24);
        if (linux.errno(linux.pivot_root(root_z.ptr, old_root_z.ptr)) != .SUCCESS) std.process.exit(24);
        if (linux.errno(linux.chdir("/")) != .SUCCESS) std.process.exit(24);
        if (linux.errno(linux.umount2("/.old_root", linux.MNT.DETACH)) != .SUCCESS) std.process.exit(24);

        var target_buffer: [device_path_capacity]u8 = undefined;
        var source_buffer: [device_path_capacity]u8 = undefined;
        placeDevice(
            &target_buffer,
            &source_buffer,
            "/.chock-device-tree",
            device_kind_file,
            "named-source",
            "/dev/chock-widget0",
        ) catch std.process.exit(25);

        const placed_rc = linux.open("/dev/chock-widget0", .{ .ACCMODE = .RDWR }, 0);
        if (linux.errno(placed_rc) != .SUCCESS) std.process.exit(26);
        const placed_fd: i32 = @intCast(placed_rc);
        var read_buffer: [64]u8 = undefined;
        const read_n = linux.read(placed_fd, &read_buffer, read_buffer.len);
        if (linux.errno(read_n) != .SUCCESS) std.process.exit(27);
        if (!std.mem.eql(u8, read_buffer[0..read_n], source_content)) std.process.exit(28);

        // The mount must never be read only, because `namespace.markReadOnly` also
        // sets `NODEV`, which refuses to open the device node at all.
        if (linux.errno(linux.lseek(placed_fd, 0, linux.SEEK.SET)) != .SUCCESS) std.process.exit(29);
        const changed = "CHANGED";
        const wrote_through = linux.write(placed_fd, changed.ptr, changed.len);
        _ = linux.close(placed_fd);
        if (linux.errno(wrote_through) != .SUCCESS or wrote_through != changed.len) std.process.exit(30);

        const verify_rc = linux.openat(host_tmp.dir.handle, "named-source", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(verify_rc) != .SUCCESS) std.process.exit(31);
        const verify_fd: i32 = @intCast(verify_rc);
        var verify_buffer: [64]u8 = undefined;
        const verify_n = linux.read(verify_fd, &verify_buffer, verify_buffer.len);
        _ = linux.close(verify_fd);
        if (linux.errno(verify_n) != .SUCCESS) std.process.exit(31);
        if (!std.mem.startsWith(u8, verify_buffer[0..verify_n], changed)) std.process.exit(32);

        // The trap this pins, in the negative: with a `markReadOnly` shaped remount,
        // opening the very same node for writing answers `EROFS`.
        const target_z = buildDeviceTarget(&target_buffer, "", "/dev/chock-widget0") orelse
            std.process.exit(33);
        const attr = MountAttrProbe{
            .attr_set = mount_attr_rdonly_probe | mount_attr_nodev_probe,
        };
        const remount_rc = linux.syscall5(
            .mount_setattr,
            @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
            @intFromPtr(target_z.ptr),
            @as(usize, linux.AT.RECURSIVE),
            @intFromPtr(&attr),
            @sizeOf(MountAttrProbe),
        );
        if (linux.errno(remount_rc) != .SUCCESS) std.process.exit(34);
        const denied_rc = linux.open("/dev/chock-widget0", .{ .ACCMODE = .WRONLY }, 0);
        if (linux.errno(denied_rc) == .SUCCESS) {
            _ = linux.close(@intCast(denied_rc));
            std.process.exit(35); // The read only remount did not hold.
        }
        if (linux.errno(denied_rc) != .ROFS) std.process.exit(36);

        dropDevice(&target_buffer, "/dev/chock-widget0") catch std.process.exit(37);
        const after_rc = linux.open("/dev/chock-widget0", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(after_rc) != .SUCCESS) std.process.exit(38);
        const after_fd: i32 = @intCast(after_rc);
        var after_drop: [8]u8 = undefined;
        const after_n = linux.read(after_fd, &after_drop, after_drop.len);
        _ = linux.close(after_fd);
        if (linux.errno(after_n) != .SUCCESS) std.process.exit(39);
        if (after_n != 0) std.process.exit(40);

        placeDevice(
            &target_buffer,
            &source_buffer,
            "/.chock-device-tree",
            device_kind_file,
            "../etc/passwd",
            "/dev/chock-widget1",
        ) catch |err| {
            if (err != error.PathUnusable) std.process.exit(41);
            std.process.exit(0);
        };
        std.process.exit(42); // The escape was not refused.
    }

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(child, &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(child, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    if (linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 20) return error.SkipZigTest;
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}

const MountAttrProbe = extern struct {
    attr_set: u64 = 0,
    attr_clr: u64 = 0,
    propagation: u64 = 0,
    userns_fd: u64 = 0,
};
const mount_attr_rdonly_probe: u64 = 0x00000001;
const mount_attr_nodev_probe: u64 = 0x00000004;

test "a kind this helper does not implement is refused before anything is touched" {
    var target_buffer: [device_path_capacity]u8 = undefined;
    var source_buffer: [device_path_capacity]u8 = undefined;
    try std.testing.expectError(
        error.UnsupportedKind,
        placeDevice(
            &target_buffer,
            &source_buffer,
            "/.chock-device-tree",
            device_kind_file + 1,
            "bus/usb/001/005",
            "/dev/chock-widget0",
        ),
    );
}

test "a placement or a removal that fails says so on stderr, and never silently" {
    var pipe_fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&pipe_fds, .{})));
    defer _ = linux.close(pipe_fds[0]);

    reportDeviceFault(pipe_fds[1], "place", "/dev/chock-widget0", error.MountFailed);
    _ = linux.close(pipe_fds[1]);

    var buf: [256]u8 = undefined;
    const n = linux.read(pipe_fds[0], &buf, buf.len);
    try std.testing.expect(linux.errno(n) == .SUCCESS);
    const line = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, line, "place") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "/dev/chock-widget0") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "MountFailed") != null);
}
