//! The Linux driver for chock-sandbox. `spawn` puts the sandbox's layers in a
//! fixed order and then runs the program. The order is not free to change. See
//! the comment above `enterNamespaces` for what runs, in which of the two child
//! processes, and why it runs in that order.
//!
//! Moved here unchanged from `lib/chock-sandbox/Sandbox.zig` for the driver
//! split: this logic has survived three attack reviews
//! that each found host code execution or a sandbox escape, so the split
//! relocated it without touching a line, and put only the type declarations
//! every driver shares, `Config`, `SpawnError`, `SetupError`, and
//! `LandlockReport`, in the interface file this driver now imports them
//! from. See that file's own top comment for the interface this driver
//! implements, and `../darwin/driver.zig` for the driver beside it.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const landlock = @import("landlock.zig");
const namespace = @import("namespace.zig");
const capabilities = @import("capabilities.zig");
const seccomp = @import("seccomp.zig");
const bpf = @import("bpf.zig");
const rlimits = @import("rlimits.zig");
const cgroup = @import("cgroup.zig");
const netbroker = @import("netbroker.zig");
const iface = @import("../Sandbox.zig");
const Config = iface.Config;
const SetupError = iface.SetupError;
const SpawnError = iface.SpawnError;
const LandlockReport = iface.LandlockReport;
const LimitsReport = iface.LimitsReport;

/// Tells two cgroups made by the same process at the same moment apart.
/// `lib/chock-core/tools.zig` calls `spawn` from a thread of its own, so two
/// calls really can be inside `Cgroup.create` at once, and two directories
/// with one name is two callers writing limits into one cgroup.
var cgroup_seed: std.atomic.Value(u64) = .init(0);

/// This driver applies every layer Chock asks for. See `../Sandbox.zig`'s own
/// `Guarantee` for what each member means.
pub const guarantees: iface.Guarantees = iface.Guarantees.initMany(&.{
    .network_isolated,
    .signal_isolated,
    .ipc_isolated,
    .path_restricted,
    .syscall_restricted,
    .workspace_mounted,
});

/// One step of setup, in the order `applyLayers` and `execute` run them. A
/// child that fails one of these writes its tag, as a single byte, into
/// `SetupFailureRecord.step` over the setup pipe. See `spawn` for how the
/// record reaches the real caller, and `setupErrorFor` for how a step maps to
/// a `SetupError` member.
const SetupStep = enum(u8) {
    stdin_redirect,
    process_group,
    close_fds,
    cgroup_join,
    resource_limits,
    namespace,
    scratch_mount,
    mount_tree,
    pivot,
    capabilities,
    landlock_init,
    landlock_rule,
    landlock_restrict,
    session_keyring,
    seccomp_install,
    fork,
    pdeathsig_pidfd,
    pdeathsig_prctl,
    exec,
};

/// A witness value with no meaning of its own. Its only job is to make a read
/// that could ever land on a corrupt or truncated fragment easy to reject,
/// rather than trusted as a real step. The bytes spell "CHK1".
const setup_failure_magic: u32 = 0x314B4843;

/// The record a child writes over the setup pipe when a step of `applyLayers`
/// or `execute` fails, before the caller's program ever runs. Fixed size, and
/// always written by a single `write` call well under `PIPE_BUF`, so the
/// kernel carries it as one atomic unit: nothing else ever writes to this
/// pipe at the same time, since every writer ends its own process immediately
/// after this call.
const SetupFailureRecord = extern struct {
    magic: u32 = setup_failure_magic,
    step: u8,
    /// The raw errno the failing step read, or 0 when the step's own error
    /// came from a Zig error with no specific errno behind it.
    errno: i32,
};

// `SetupError`, named one member per `SetupStep` above so a caller can match
// on exactly which layer never came up, is declared on `../Sandbox.zig` now,
// not here: every driver's own `SpawnError` needs the same shape, and
// `SpawnError` itself lives there too. See that file's own comment on both.
// `setupErrorFor`, further down this file, is what actually maps a
// `SetupStep` to a `SetupError` member.

/// The seccomp options this driver really uses. `base` is what the caller
/// asked for, and the mode is the one thing the driver adds to it: see the
/// `block_connect` comment inside `spawn`.
///
/// **A function of its own, so a test can ask the question without a spawn.**
/// The rule it holds is one line, and it is the line that decides whether the
/// filter for a mode is the one that mode had before. A test that had to spawn
/// to read it would need a root, a mount and a program, and it could only see
/// the answer through a program's exit status. See `Options.block_connect` in
/// `seccomp.zig` for what turning this on costs.
fn seccompOptionsFor(base: seccomp.Options, network: namespace.Network) seccomp.Options {
    var options = base;
    options.block_connect = switch (network) {
        // Nothing is added for either of these. **`.none` gets exactly the
        // filter the caller asked for**, so a unix socket client inside an
        // ordinary tool call still works: that is the approval socket and the
        // git shim.
        .none, .host => false,
        .filtered => true,
    };
    return options;
}

test "the filter for a mode is the caller's own, and only a filtered call has connect taken away" {
    // **The default mode's filter must be exactly what the caller asked for.**
    // A tool call is `.none`, and a tool call is what the approval socket and
    // the git shim run inside: both connect to a unix socket, and
    // `block_connect` cannot read the address behind the pointer, so turning
    // it on there refuses those too. Measured on 2026-08-24 by reading this
    // switch as a plain `true`: four tests fail, named in `spawn`'s own
    // comment on `block_connect`.
    //
    // Mutation check: answer `true` for `.none` and the first line below
    // fails. Answer `false` for `.filtered` and the third fails.
    try std.testing.expectEqual(false, seccompOptionsFor(.{}, .none).block_connect);
    try std.testing.expectEqual(false, seccompOptionsFor(.{}, .host).block_connect);
    try std.testing.expectEqual(true, seccompOptionsFor(.{}, .filtered).block_connect);

    // A caller that turned the write and execute rule off keeps it off in
    // every mode. This function adds one thing and must take nothing.
    for (std.enums.values(namespace.Network)) |network| {
        const relaxed = seccompOptionsFor(.{ .strict_wx = false }, network);
        try std.testing.expectEqual(false, relaxed.strict_wx);
    }

    // **And a caller cannot ask for `block_connect` on a mode that does not
    // take it.** The driver decides this one field, so a `.none` config that
    // named it would otherwise get a filter no test in this project covers.
    try std.testing.expectEqual(
        false,
        seccompOptionsFor(.{ .block_connect = true }, .none).block_connect,
    );
}

test "the filter the default config gets is the filter a caller with no options gets" {
    // **The claim the rename rests on, written as instructions.** Renaming the
    // modes must not move one byte of the filter every tool call runs under,
    // so the two are built and compared instruction by instruction.
    //
    // This reads `Config.network`'s own default rather than naming a mode, so
    // a later reader who makes `.filtered` the default fails here and reads
    // why in `namespace.Network`.
    //
    // Mutation check: build the second filter with `.filtered` and the two
    // differ by exactly the two instructions the connect rule adds.
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
    const defaulted = try seccomp.build(allocator, seccompOptionsFor(.{}, default_network));
    defer allocator.free(defaulted);

    try std.testing.expectEqualSlices(bpf.Insn, plain, defaulted);
}

/// Whether `kernel` can put a child into the cgroup `containment` names as it
/// creates it.
///
/// **A function of its own, so a test can ask the question without an old
/// kernel**, the same reason `seccompOptionsFor` above is one. The refusal
/// this decides cannot be measured any other way in this project: nobody here
/// can run a 5.6 kernel, and a test that only ran on the machine it was
/// written on would prove the decision on exactly one release.
///
/// `best_effort` is always possible, because it promises nothing a kernel can
/// take away: a machine with no cgroup v2 tree at all still runs the program
/// with the rlimit floor. `supplied` needs `CLONE_INTO_CGROUP`. See
/// `cgroup.clone_into_cgroup_since` for the release and for why the floor this
/// library already keeps does not make the check dead code.
fn placementIsPossible(kernel: rlimits.Release, containment: iface.Containment) bool {
    return switch (containment) {
        .best_effort => true,
        .supplied => kernel.atLeast(cgroup.clone_into_cgroup_since),
    };
}

test "a caller supplied cgroup is refused below 5.7, and chock's own cgroup is refused on no kernel" {
    // **The kernel floor, asked at every boundary that matters.** 5.7 is the
    // release that added `CLONE_INTO_CGROUP`. `clone3` itself is older, at
    // 5.3, so the flag is the only number to compare against.
    //
    // Mutation check: read `clone_into_cgroup_since` as 5.3, the `clone3`
    // release, and the 5.6 line below passes when it must fail. Answer `true`
    // for `.supplied` and three lines fail at once.
    const supplied = iface.Containment{ .supplied = .{ .fd = 7 } };

    try std.testing.expect(!placementIsPossible(.{ .major = 4, .minor = 19 }, supplied));
    try std.testing.expect(!placementIsPossible(.{ .major = 5, .minor = 3 }, supplied));
    try std.testing.expect(!placementIsPossible(.{ .major = 5, .minor = 6 }, supplied));
    try std.testing.expect(placementIsPossible(.{ .major = 5, .minor = 7 }, supplied));
    try std.testing.expect(placementIsPossible(.{ .major = 6, .minor = 18 }, supplied));

    // **A kernel this file could not read at all reads as 0.0**, which is
    // older than every real release, so an unreadable `uname` refuses the
    // placement rather than attempting it. See `rlimits.runningKernel`.
    try std.testing.expect(!placementIsPossible(.{ .major = 0, .minor = 0 }, supplied));

    // And the other promise is refused by no kernel at all. Chock's own
    // cgroup is best effort, and a machine that cannot give one still runs
    // the program with the rlimit floor: that is the behaviour every caller
    // had before a caller could supply a cgroup, and this line is what stops
    // a later change taking it away.
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
/// Call this from a single threaded process, the same requirement
/// `namespace.enter` already carries. `spawn` calls `fork`, and `fork` only
/// carries the calling thread into the child. Any lock another thread of the
/// parent held at that moment, such as the allocator's own lock or the global
/// lock `std.debug.print` takes, is copied into the child as still held, with
/// no thread left in the child that could ever release it. A child stuck on a
/// lock like that hangs instead of running the sandboxed program or reporting
/// why it could not, which is the one thing `applyLayers` exists to avoid. To
/// keep that risk small, this function builds the seccomp filter before the
/// fork, in the parent, and the child never calls `std.debug.print`: see the
/// comment on `applyLayers` and on `die`.
///
/// `landlock_report`, if not null, is filled in with the Landlock ABI version
/// and the features it has, before the fork. See `LandlockReport`. Pass null
/// when the caller has no use for it.
///
/// `middle`, if not null, is filled in with a handle on the process this
/// function forks, right after that fork succeeds and before anything else
/// runs. Cancel a running call by signalling through that handle, never the
/// sandboxed program directly: the sandboxed program is process 1 of its own
/// pid namespace, and process 1 of a namespace with default signal handlers
/// cannot be killed by an ordinary signal such as SIGTERM. The process the
/// handle names is not process 1 anywhere, so it dies normally from any
/// signal, and its death takes the sandboxed program down with it: see the
/// comment on `waitAndRelay` for the relay, and `armPdeathsig` for why the
/// sandboxed program does not outlive it.
///
/// **One signal to that one process ends every process of the call, and the
/// pid namespace is why.** `signalMiddle` has no group form, so this reaches
/// only the middle process. That is enough: the middle process dies, the
/// sandboxed program's own `PR_SET_PDEATHSIG` fires and kills it, and the
/// kernel then kills every other process in the pid namespace whose process 1
/// has just died.
///
/// **Two mechanisms do this and either one is enough, which is worth stating
/// so a reader does not remove one believing the other is decoration.** The
/// chain above is the first. The second is `Cgroup.destroy`, which writes
/// `cgroup.kill` on the way out of this function and ends whatever is still in
/// the call's own cgroup. Measured on 2026-08-22 on Linux 6.18, with a
/// grandchild the sandboxed program forked writing to a file every 5
/// milliseconds and a `SIGKILL` sent to the middle process alone:
///
/// * Both in place: the file stopped.
/// * `PR_SET_PDEATHSIG` not armed: the file still stopped, because the cgroup
///   kill reached the grandchild.
/// * `cgroup.kill` not written: the file still stopped, because the pdeathsig
///   chain reached it.
/// * Neither: the file kept growing, and `test/sandbox/escape.zig`'s own
///   forked cancel test failed on it, which is what that test is for.
///
/// **They are not redundant, because the cgroup is best effort.** A machine
/// with no cgroup v2 tree, or one that delegates nothing, has `group.support`
/// off and gets the pdeathsig chain alone: measured on the same day, outside
/// this driver and with no cgroup at all, a grandchild left by a disarmed
/// pdeathsig ran on past 28 KB of output with nothing that named it. See
/// `armPdeathsig` and `cgroup.Cgroup.destroy`.
///
/// **A caller supplied cgroup gets the pdeathsig chain alone, for the same
/// reason and by the same rule.** `cgroup.kill` is a write, and this function
/// makes no write of any kind into a cgroup it was given: the caller owns that
/// tree, and one write there is the first step towards two owners. A caller
/// that wants the cgroup kill as well holds the cgroup and can write it
/// itself, after `spawn` has returned. See `iface.Containment`.
///
/// **The middle process is also the process group of the whole sandbox.** That
/// process calls `setpgid(0, 0)` before it makes anything else, so the group's
/// own identifier is that same number: see `newProcessGroup`, which still
/// wants the group for the two reasons its own comment gives. Nothing in Chock
/// signals the negated number any more, for the reason `Middle`'s own doc
/// comment gives.
pub fn spawn(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    landlock_report: ?*LandlockReport,
    middle: ?*iface.Middle,
) SpawnError!std.process.Child.Term {
    // **Before any layer, and before anything is forked.** A filtered config
    // with nobody to ask would otherwise come up as an ordinary `.none`
    // sandbox, and the program inside it would spend its whole run failing at
    // a channel it was told it had. See `iface.Config.net_broker`.
    //
    // **This is also why `.filtered` cannot become the default of
    // `iface.Config.network`.** A default cannot supply a broker: a broker is
    // a live object with an allocator, an io, a policy table and a spawn
    // chain, which only a caller holds. Measured on 2026-08-24: making
    // `.filtered` the default failed 69 tests, because every caller that names
    // no broker stops here.
    switch (config.network) {
        .filtered => if (config.net_broker == null) return error.NetBrokerMissing,
        .none, .host => if (config.net_broker != null) return error.NetBrokerNotFiltered,
    }

    // Read once, here, and used twice below: for the placement decision and
    // for the `RLIMIT_NPROC` decision the limits report carries. One read of
    // one kernel, so the two answers cannot disagree.
    const kernel = rlimits.runningKernel();

    // **The caller supplied cgroup is refused on an old kernel, before
    // anything is built and before anything is forked.** The only other way
    // into a cgroup is a write to `cgroup.procs` after the fork, which leaves
    // the child outside the caller's cgroup for as long as it takes to reach
    // that write. A caller that asked for containment at creation and got that
    // window instead would believe in a bound it does not have, so this
    // refuses and does not fall back.
    if (!placementIsPossible(kernel, config.containment)) return error.CgroupPlacementUnsupported;

    const abi = landlock.probeAbi() catch return error.LandlockUnavailable;
    if (landlock_report) |report| report.* = .{ .abi = abi, .features = landlock.featuresFor(abi) };

    // **The one layer this driver decides for itself rather than taking from
    // the caller.** A filtered process is handed a connected descriptor, and a
    // connected descriptor really can be aimed somewhere else with `connect`,
    // so `connect` is refused for exactly that case. See
    // `seccomp.Options.block_connect` for the measurement.
    //
    // **It only ever narrows, and both directions of that are already
    // measured.** Turning it off for a filtered call is caught by
    // `test/sandbox/escape.zig`'s own two filtered connect tests. Turning it
    // on for every call would take a unix socket client away from every tool
    // call that runs today. Measured on 2026-08-24, with this line read as a
    // plain `true`: four tests fail, and each one names a different thing that
    // breaks.
    //
    // * `test/broker/git_shim.zig`, "the real git run by its absolute path
    //   skips the shim": the shim's own socket.
    // * `test/sandbox/escape.zig`, "a tool call inside the sandbox cannot
    //   reach the session's approval socket": the errno stops being the one
    //   the test reads, so the sandbox stops proving what it claims.
    // * `test/sandbox/escape.zig`, "spawn applies every layer": `connect` to a
    //   remote host answers `EPERM` and no longer `ENETUNREACH`, so the
    //   namespace is no longer what refused it.
    // * `test/broker/actions.zig`, "the broker runs the action": the broker's
    //   own socket.
    //
    // All four read the errno rather than only the failure, which is what
    // makes them able to tell a narrowed filter from a closed network.
    const seccomp_options = seccompOptionsFor(config.seccomp_options, config.network);

    // Built here, in the parent, before the fork. The filter depends only on
    // `config.seccomp_options` and `config.network`, never on anything the
    // child alone knows, so building it before the fork is free: `fork` copies
    // this process's whole address space, so the child can read these same
    // instructions without any allocation or IPC of its own, and one less
    // allocating step runs between the fork and the exec. See the thread
    // safety note above.
    const insns = seccomp.build(allocator, seccomp_options) catch |err| return err;
    defer allocator.free(insns);

    // The cgroup, made here in the parent for the same reason the seccomp
    // filter is built here: the child that has to move into it is a child
    // that has already given up its ability to open a path, and A's own
    // `closeInheritedFds` runs before any of that. See `Cgroup.join`.
    //
    // **Best effort, and never a reason to refuse to run.** A machine with no
    // cgroup v2 tree, or one that delegates nothing, still gets every rlimit:
    // see `rlimits.zig`'s own top comment on why both layers exist. What must
    // not happen is a caller believing in a bound that is not there, and
    // `group.support` is what stops that.
    //
    // **Nothing here runs for a caller supplied cgroup, and that is the whole
    // second half of that promise.** The caller owns that tree and the numbers
    // in it. Chock writes no `memory.max`, no `pids.max` and no
    // `memory.swap.max` into it, because a second writer is how two numbers
    // disagree, and it makes no cgroup of its own either: a process is in one
    // cgroup, so a second directory would be an empty one nothing is ever
    // charged to. `group` stays a value that owns nothing, so the `defer`
    // below removes nothing, `readEvents` reads nothing, and the caller's own
    // cgroup is untouched by every line of this function.
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
    // Removed on every path out of this function, including the setup failure
    // path below and every error return before the fork. A `supplied` group
    // has nothing to remove: see `cgroup.Support.applied`, which `destroy`
    // reads first.
    defer group.destroy();

    if (config.limits_report) |report| report.* = .{
        .limits = config.limits,
        .cgroup = group.support,
        .nproc_applied = config.limits.processes != null and
            kernel.atLeast(rlimits.nproc_per_user_namespace_since),
    };

    // The setup pipe. Every failure path from here to `execve` writes a
    // SetupFailureRecord to the write end and ends its own process. A
    // successful `execve` closes the write end on its own, through CLOEXEC,
    // without writing anything. `spawn` reads the other end below to learn
    // which of the two happened. Both ends start CLOEXEC so a later, unrelated
    // exec in this process can never accidentally inherit either one.
    var pipe_fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&pipe_fds, .{ .CLOEXEC = true })) != .SUCCESS) return error.Unexpected;
    const read_fd = pipe_fds[0];
    const write_fd = pipe_fds[1];

    // The scratch pipe, and a second pipe rather than one more record on the
    // setup pipe. **The setup pipe answers "did the sandbox come up", and this
    // process learns that answer as soon as `execve` closes the child's copy,
    // not whenever the program eventually finishes.** A writer that stayed open
    // past `execve` would hold that read open for the whole call, and the
    // comment on A's own `close(write_fd)` below is the record of why that
    // matters. So the one fact that can only be known *after* the program has
    // ended travels a channel of its own, which this process reads after
    // `waitpid` has already returned: see `reportScratch`.
    var scratch_pipe: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&scratch_pipe, .{ .CLOEXEC = true })) != .SUCCESS) {
        _ = linux.close(read_fd);
        _ = linux.close(write_fd);
        return error.Unexpected;
    }
    const scratch_read_fd = scratch_pipe[0];
    const scratch_write_fd = scratch_pipe[1];

    // The broker pair, for a filtered call and for no other. `[0]` stays in
    // this process and is what the serve loop below reads. `[1]` crosses into
    // the sandbox and becomes the one channel out that the network namespace
    // does not close. Both ends are close-on-exec: `execute` clears the flag
    // on the child's end in the last step before `execve`, so a sandbox that
    // failed to come up never hands a program a channel out.
    var broker_fds: [2]i32 = .{ -1, -1 };
    if (config.network == .filtered) {
        broker_fds = netbroker.makePair() catch {
            _ = linux.close(read_fd);
            _ = linux.close(write_fd);
            _ = linux.close(scratch_read_fd);
            _ = linux.close(scratch_write_fd);
            return error.NetBrokerSocketFailed;
        };
    }

    // **The one place the two promises differ in what the kernel is asked
    // for.** A supplied cgroup is not joined after the fork: the child is
    // created inside it, in this one system call, so there is no instant at
    // which it exists anywhere else. Everything the child goes on to make,
    // which is B and every process B starts, inherits that membership. See
    // `cgroup.forkInto`, and `joinCgroup` for the best effort half.
    //
    // **The plain `fork` stays on the best effort path on purpose.** That path
    // has to work on a machine where `clone3` is refused, which a container
    // runtime's own seccomp filter still does, and it already carries no
    // promise a failure to place would break.
    const fork_rc = switch (config.containment) {
        .best_effort => linux.fork(),
        .supplied => |supplied| cgroup.forkInto(supplied.fd),
    };
    if (linux.errno(fork_rc) != .SUCCESS) {
        _ = linux.close(read_fd);
        _ = linux.close(write_fd);
        _ = linux.close(scratch_read_fd);
        _ = linux.close(scratch_write_fd);
        closeBrokerPair(&broker_fds);
        // **A placement that was refused is named, and never retried without
        // the cgroup.** No process was created, so nothing ran outside the
        // caller's cgroup and nothing has to be cleaned up. The best effort
        // path keeps the answer it always gave.
        return switch (config.containment) {
            .best_effort => error.Unexpected,
            .supplied => error.CgroupPlacementRefused,
        };
    }
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        // The child, called A in the comments below. A never reads the setup
        // pipe, only ever writes to it.
        _ = linux.close(read_fd);
        _ = linux.close(scratch_read_fd);
        // The parent's own end of the broker pair. **Nothing on this side of
        // the boundary may keep it**: a copy held here would be a second
        // reader of the requests, and it would also mean that a sandboxed
        // process could write a request that this process answers with the
        // parent's own end still open on both sides.
        if (broker_fds[0] >= 0) {
            _ = linux.close(broker_fds[0]);
            broker_fds[0] = -1;
        }

        // Every failure from here to `execve` ends the process with a record on
        // the setup pipe, through `die` or `dieErrno`. Neither function returns,
        // so nothing below can fall through to the next layer, or past
        // `applyLayers` into `execute`, without that layer having worked.
        //
        // The caller's own signal handling comes off first, and the sandbox's
        // own process group goes on second. Both are state this process kept
        // from the caller across the fork, and both are wrong for it. See each
        // function's own comment.
        resetSignalState();
        newProcessGroup(write_fd, config.stderr_fd);

        // The cgroup, before anything closes a descriptor and before any
        // namespace. Moving this process moves every process it goes on to
        // make, which is B and everything B starts, so one write here bounds
        // the whole call. See `Cgroup.join` for why it is a descriptor and
        // not a path, and why the pid written is `0`.
        //
        // **A supplied cgroup is never joined here, and the switch says so
        // rather than leaving it to a descriptor that happens to be -1.** This
        // process was created inside that cgroup, so a write would move it
        // nowhere. A later reader who added a join to this path would give
        // a caller the very window the placement exists to close.
        switch (config.containment) {
            .best_effort => joinCgroup(&group, write_fd, config.stderr_fd),
            .supplied => {},
        }

        // Point descriptor 0 at /dev/null before any layer goes on. See the
        // comment on `redirectStdinToDevNull` for why.
        redirectStdinToDevNull(write_fd, config.stderr_fd);
        enterNamespaces(config, write_fd, scratch_write_fd, broker_fds[1]);

        // The capped scratch areas, mounted here in A and not in B with the
        // rest of the mount tree. **A has to hold a descriptor on each one**,
        // and B is the wrong process to get one from: B pivots into the new
        // root and then denies itself every path, and by the time B has
        // finished A could not open the area by name even if it knew when to
        // try. A mount made here is in the same mount namespace B inherits, so
        // `buildRoot`'s own recursive bind of the root carries it into the tree
        // B pivots into, and the sandboxed program finds it at the path the
        // caller named. See `namespace.mountScratch`, and `reportScratch` for
        // what the descriptors are for.
        const areas = mountScratchAreas(config, write_fd);

        // namespace.enter above called unshare(CLONE_NEWPID), but unshare never
        // moves the calling process into the namespace it just made. Only a
        // child forked after that call lands there, as its process 1.
        // This process, A, stays in the pid namespace it already had. The second
        // fork here makes B, which becomes process 1 of the new namespace and is
        // the process that actually runs the caller's program.
        //
        // A opens a pidfd on itself first, so B can inherit a working liveness
        // handle for A across the fork. B cannot open this itself: B is about to
        // become process 1 of a pid namespace A is not a member of, so A's pid
        // number means nothing inside B's own namespace, and pidfd_open needs a
        // pid number in the caller's own namespace to resolve. A fd, once open,
        // needs no such resolution. It is just inherited across the fork like any
        // other descriptor. See armPdeathsig for what it is used for.
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

        const inner_fork_rc = linux.fork();
        if (linux.errno(inner_fork_rc) != .SUCCESS) {
            die(write_fd, config.stderr_fd, .fork, error.Unexpected);
        }
        const inner_pid: linux.pid_t = @intCast(inner_fork_rc);

        if (inner_pid == 0) {
            // **The layers are applied here, in B, and not in A.** B is inside
            // the pid namespace A only made, and the kernel gives a procfs the
            // view of the pid namespace of whichever process mounts it, and
            // refuses the mount to a process that is not in one it has
            // CAP_SYS_ADMIN over. Measured on 2026-08-21: a `/proc` mount from
            // A answers EPERM, and one that succeeded would have shown the
            // host's own processes, which is worse than none at all. So the
            // mount tree is built by the process that lives in the namespace.
            // See `namespace.Mount.Proc`, and `applyLayers` for the order of
            // the layers themselves, which is unchanged.
            applyLayers(allocator, config, abi, insns, write_fd);
            armPdeathsig(write_fd, config.stderr_fd, middle_pidfd);
            execute(allocator, config, argv, write_fd, broker_fds[1]);
            unreachable;
        }

        // A no longer needs the pidfd once B has it. B's own copy, inherited
        // across the fork above, is untouched by closing this one.
        _ = linux.close(middle_pidfd);

        // A's own copy of the scratch pipe's write end stays open until
        // `waitAndRelay` has read the areas and written its record. B's copy is
        // CLOEXEC, so B's own `execve` closes it, and `closeInheritedFds`
        // already ran in A before any of this: nothing the caller's program
        // holds names either end.
        //
        // Close this copy of the write end now that B exists and has its own.
        // Without this, the real parent's read of the pipe, further down this
        // function, would never see end of file until A itself exits, which does
        // not happen until the whole sandboxed program has finished running:
        // waitAndRelay below blocks on exactly that. The real parent needs to
        // learn "setup succeeded" as soon as B's own execve closes B's copy, not
        // whenever the program eventually finishes.
        _ = linux.close(write_fd);

        // Same reasoning again, for A's own copy of the broker pair's child
        // end. B has its own through the fork above, and A never speaks on it.
        // Without this close, the real parent's serve loop would keep reading
        // from a pair that still has a writer here, so a sandboxed program that
        // exited would not show up as the end of the stream.
        if (broker_fds[1] >= 0) {
            _ = linux.close(broker_fds[1]);
            broker_fds[1] = -1;
        }

        // Same reasoning, for config.stdout_fd and config.stderr_fd, when a
        // caller named a descriptor other than this process's own standard
        // output or standard error: B already has its own copy through the
        // fork above, so A's copy is not needed again, and every write end a
        // caller such as lib/chock-core/tools.zig's own spawnCapturing reads
        // for end of file must close here too, not only once A itself exits.
        // Skipped for a descriptor that still names this process's own
        // standard output or standard error: those must stay open for
        // whatever this process still needs them for below, such as
        // dieRelay's own use of printFault, and no caller that left the
        // default ever asked this process to give either one up.
        if (config.stdout_fd != std.posix.STDOUT_FILENO) _ = linux.close(config.stdout_fd);
        if (config.stderr_fd != std.posix.STDERR_FILENO and config.stderr_fd != config.stdout_fd)
            _ = linux.close(config.stderr_fd);
        // Same again for `config.stdin_fd`, and the mirror image of the reason
        // above. That descriptor is the **read** end of a pipe the caller
        // writes requests into, and a write to a pipe fails with `EPIPE` only
        // once every read end is closed. A copy held here would answer the
        // caller's write with success, into a buffer nobody will ever drain,
        // for as long as A lives, which is as long as the sandboxed program
        // itself. So a caller that learns a helper has stopped reading by
        // getting a broken pipe would instead learn nothing and then block.
        // See `lib/chock-core/helper.zig`, which relies on exactly that.
        if (config.stdin_fd) |fd| {
            if (fd > std.posix.STDERR_FILENO and fd != config.stdout_fd and fd != config.stderr_fd)
                _ = linux.close(fd);
        }

        // A applied no layer to itself, because B applies them all: see the
        // comment on the fork above. So A takes the two that cost it nothing
        // and keep the promise it used to keep by accident, that a process
        // holding this program's own memory reaches no path and makes no
        // dangerous call while it waits.
        restrictMiddle(abi, insns);

        // A is not process 1 anywhere, so it keeps ordinary signal semantics. It
        // waits for B and relays B's outcome as its own, so the real parent's
        // single waitpid on A, further down in this function, still sees the
        // caller's program's real Term.
        waitAndRelay(inner_pid, &areas, scratch_write_fd);
        unreachable;
    }

    // The child's end of the broker pair belongs to A and to B now. **This
    // process must give up its copy**, or the serve loop below would never
    // reach the end of the stream, which is how it learns the sandboxed
    // program has gone.
    if (broker_fds[1] >= 0) {
        _ = linux.close(broker_fds[1]);
        broker_fds[1] = -1;
    }
    // Closed on the way out of every branch below, the same rule the two pipes
    // follow: a session runs thousands of calls, and a descriptor left open on
    // an error path ends with the harness unable to open a file.
    errdefer closeBrokerPair(&broker_fds);

    if (middle) |out| {
        // **Opened here, in the real parent, and before the pid is
        // published.** Only this process reaps A, and it does not do so until
        // far below, so A is still a task the kernel can resolve at this
        // instant, whether it is running or already a zombie. A `pidfd_open`
        // from anywhere else would race the reap it exists to survive.
        //
        // The descriptor comes back with `FD_CLOEXEC` already set, which the
        // kernel does for every pidfd and which this project measured on
        // 2026-08-22 rather than trusted: see the test at the bottom of this
        // file. So an unrelated `execve` in the caller's process cannot
        // inherit a handle that kills a tool call.
        const pidfd_rc = linux.pidfd_open(pid, 0);
        if (linux.errno(pidfd_rc) != .SUCCESS) {
            // **A call nobody can cancel is worse than a call that never
            // started.** The caller asked for a handle, and without one a
            // Ctrl-C reaches nothing and the deadline enforces nothing: see
            // `newProcessGroup`, which is what took the terminal's own signal
            // away from a running program. A is fresh out of `fork` and this
            // process is its only reaper, so ending it here is safe and needs
            // no handle of its own.
            _ = linux.kill(pid, .KILL);
            var reap_status: u32 = undefined;
            var reap_rc = linux.waitpid(pid, &reap_status, 0);
            while (linux.errno(reap_rc) == .INTR) {
                reap_rc = linux.waitpid(pid, &reap_status, 0);
            }
            _ = linux.close(read_fd);
            _ = linux.close(write_fd);
            _ = linux.close(scratch_read_fd);
            _ = linux.close(scratch_write_fd);
            return error.Unexpected;
        }
        out.fd = @intCast(pidfd_rc);
        // `fd` first and `pid` second, with a release store, because a caller
        // watches `pid` for a non zero value from another thread and then
        // reads `fd`: see `iface.Middle`. `chock_core.tools` and
        // `chock_core.helper` both do exactly that with an acquire load.
        @atomicStore(std.posix.pid_t, &out.pid, pid, .release);
    }

    // The real parent's own copy of the write end. Closing it here, before the
    // read below, is what makes that read able to return end of file at all:
    // a read on a pipe blocks until every write end is closed, and this
    // process holds one of them too.
    _ = linux.close(write_fd);
    // Same rule for the scratch pipe, whose only writer is A.
    _ = linux.close(scratch_write_fd);

    // Both descriptors are closed on the way out of every branch below,
    // including this one. A caller such as `lib/chock-core/tools.zig` runs
    // thousands of tool calls in one session, so a descriptor left open on an
    // error path is a leak that ends with the harness unable to open a file.
    const maybe_failure = readSetupReport(read_fd) catch |err| {
        _ = linux.close(read_fd);
        _ = linux.close(scratch_read_fd);
        return err;
    };
    _ = linux.close(read_fd);

    if (maybe_failure) |record| {
        _ = linux.close(scratch_read_fd);
        // A setup failure. Reap A regardless of whatever it exited with. The
        // record above is the only outcome that matters here, never A's own
        // exit code, which this process must never read as meaningful again.
        var reap_status: u32 = undefined;
        var reap_rc = linux.waitpid(pid, &reap_status, 0);
        while (linux.errno(reap_rc) == .INTR) {
            reap_rc = linux.waitpid(pid, &reap_status, 0);
        }

        // What buildRoot made on the host under config.root is nothing but
        // scratch nobody asked to keep: the caller's program never ran, so
        // nothing in it is real output. This is the only place spawn ever
        // removes it. A real program's own output, once execve has happened,
        // is never ours to delete, no matter what that program's exit code is.
        //
        // The contents only, never config.root itself. **config.root belongs
        // to the caller and lives longer than one spawn.** src/run.zig builds
        // one root per session, in session_paths.create, and every tool call
        // of that session spawns into that same directory, so a spawn that
        // removed it took every later call of the session with it: the next
        // call's own buildRoot met ENOENT on its very first mount, and one
        // bad tool call poisoned the whole session. A directory this function
        // did not make is not this function's to remove.
        removeContentsBestEffort(allocator, config.root);

        const step = std.enums.fromInt(SetupStep, record.step) orelse return error.UntrustedSetupReport;
        return setupErrorFor(step);
    }

    // The sandboxed program is running now, so this is where its requests for
    // a connection are answered. **The blocking wait below cannot come first**:
    // it would leave nobody reading the pair for the whole call, and the
    // program inside would block on an answer that arrives after it has ended.
    if (broker_fds[0] >= 0) {
        serveBroker(pid, broker_fds[0], config.net_broker.?) catch |err| {
            closeBrokerPair(&broker_fds);
            _ = linux.close(scratch_read_fd);
            // A is still running and this process is its only reaper, so end
            // it rather than leave a call nobody is watching.
            _ = linux.kill(pid, .KILL);
            var reap_status: u32 = undefined;
            var reap_rc = linux.waitpid(pid, &reap_status, 0);
            while (linux.errno(reap_rc) == .INTR) {
                reap_rc = linux.waitpid(pid, &reap_status, 0);
            }
            return err;
        };
        closeBrokerPair(&broker_fds);
    }

    // End of file with no data: execve happened, and every byte of A's own
    // termination from here on belongs to the caller's program, relayed
    // through waitAndRelay untouched. This process must pass it through
    // exactly as it is, never reinterpret it.
    var status: u32 = undefined;
    var wait_rc = linux.waitpid(pid, &status, 0);
    // A signal caught by the parent while it waits interrupts the call with
    // EINTR. That is not the child failing, so retry instead of reporting it
    // as one.
    while (linux.errno(wait_rc) == .INTR) {
        wait_rc = linux.waitpid(pid, &status, 0);
    }
    if (linux.errno(wait_rc) != .SUCCESS) {
        _ = linux.close(scratch_read_fd);
        return error.Unexpected;
    }

    // A has exited, so its copy of the scratch pipe's write end is closed and
    // this read cannot block. **It has to happen after the wait**: the areas
    // only exist inside A's mount namespace, and A reads them once, after the
    // program it was watching has ended.
    const scratch_full = readScratchReport(scratch_read_fd);
    _ = linux.close(scratch_read_fd);

    // The program has ended, so the kernel's own counters are final and the
    // cgroup can be read. **Read before `destroy` removes it**, which the
    // `defer` above does on the way out of this function.
    const term: std.process.Child.Term = if (linux.W.IFSIGNALED(status))
        .{ .signal = linux.W.TERMSIG(status) }
    else
        .{ .exited = linux.W.EXITSTATUS(status) };
    reportLimitOutcome(config, &group, term, scratch_full);
    return term;
}

/// Send `sig` to the process `fd` names. See `iface.Middle`, and `spawn`'s own
/// doc comment for why one signal to that one process ends the whole call.
///
/// **Safe to call from a signal handler**: one syscall, no allocation, no
/// lock, and no path. `chock_core.tools.cancelRunningTool` calls it from one.
///
/// ## No kernel version gate, and the reason it is not needed
///
/// `pidfd_send_signal` arrived in Linux 5.1 and `pidfd_open` in 5.3. This file
/// reads `uname` already, for the `RLIMIT_NPROC` decision in `rlimits.zig`, so
/// a gate would be cheap to write. It would also be dead code. `spawn` probes
/// the Landlock ABI first and returns `error.LandlockUnavailable` when there
/// is none, and Landlock is a 5.13 mechanism, so a kernel that gets far enough
/// to fork anything here is at least two years newer than either call. The
/// `RLIMIT_NPROC` gate is not the same case: that one guards a **behaviour**
/// change inside a call every kernel has, where an ungated caller would
/// silently get a per user limit instead of a per user namespace one, and
/// nothing would fail.
///
/// `P_PIDFD` for `waitid` needs 5.4 and is not used at all: `spawn` is the
/// parent of the process this handle names and reaps it with an ordinary
/// `waitpid`, so nothing here ever waits on a descriptor.
pub fn signalMiddle(fd: std.posix.fd_t, sig: std.posix.SIG) iface.SignalError!void {
    if (fd < 0) return error.NoHandle;
    const rc = linux.pidfd_send_signal(fd, sig, null, 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        // The process was reaped, so this handle names nothing and the signal
        // reached nobody. **This is the whole point of the handle**: the same
        // moment used to be when a pid started naming a stranger.
        .SRCH => error.Gone,
        else => error.Unexpected,
    };
}

/// Give up a handle `spawn` opened. See `iface.closeMiddle`.
pub fn closeMiddle(middle: *iface.Middle) void {
    if (middle.fd < 0) return;
    _ = linux.close(middle.fd);
    // So a second call closes nothing. A descriptor closed twice is a fault
    // that lands on whatever unrelated thing opened that number in between,
    // which is the same shape of fault as the pid this whole handle replaces.
    middle.fd = -1;
}

/// Close whichever end of the broker pair is still open, and leave both at
/// -1, so a second call closes nothing. A descriptor closed twice lands on
/// whatever unrelated thing opened that number in between, the same fault
/// `closeMiddle` guards against.
fn closeBrokerPair(fds: *[2]i32) void {
    for (fds) |*fd| {
        if (fd.* < 0) continue;
        _ = linux.close(fd.*);
        fd.* = -1;
    }
}

/// Answer the sandboxed program's requests for a connection until it ends.
///
/// **This runs in the real parent**, the process that called `spawn`, and that
/// is the whole design: the parent holds the policy, so a sandboxed process
/// cannot reach a host merely by knowing its address, and it also holds the
/// host's own network namespace, which A gave up in `enterNamespaces` and B
/// never had. A is the wrong process for this twice over.
///
/// **Nothing waits without a bound.** The loop polls two descriptors: the
/// broker pair, which becomes readable when a request arrives and reaches the
/// end of the stream when the sandbox is gone, and a `pidfd` on A, which
/// becomes readable the moment A exits. So a program that never asks for
/// anything costs one blocked `poll` and no wakeups at all, and a program that
/// ends while nothing is in flight ends this loop at once.
///
/// **The pidfd is not decoration.** Without it, a sandboxed program that keeps
/// its end of the pair open in a process that never exits, such as a
/// grandchild the program forked and abandoned, would hold this loop after the
/// program itself had finished, and the caller's own `waitpid` would never
/// run.
///
/// `netbroker.max_requests` bounds the work: past it this loop closes its end
/// and returns, so a program that asks in a tight loop meets the end of the
/// stream rather than an unbounded cost here.
fn serveBroker(pid: linux.pid_t, broker_fd: i32, broker: iface.NetBroker) SpawnError!void {
    // **Opened here, before anything reaps A**, for the reason the `middle`
    // handle gives: this process is A's only reaper and has not run its
    // `waitpid` yet, so A is still a task the kernel can resolve, alive or a
    // zombie. A loop that could not watch A is a loop that could outlive the
    // call it belongs to, so a failure here is a refusal and not a shrug.
    const watch_rc = linux.pidfd_open(pid, 0);
    if (linux.errno(watch_rc) != .SUCCESS) return error.Unexpected;
    const watch: i32 = @intCast(watch_rc);
    defer _ = linux.close(watch);

    var served: usize = 0;
    while (served < netbroker.max_requests) {
        var fds = [2]linux.pollfd{
            .{ .fd = broker_fd, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = watch, .events = linux.POLL.IN, .revents = 0 },
        };
        const ready = linux.poll(&fds, fds.len, -1);
        switch (linux.errno(ready)) {
            .SUCCESS => {},
            // A signal reached this process while it waited. Nothing was lost,
            // so look again rather than end a call over it.
            .INTR => continue,
            else => return,
        }

        // **The request is read first, and A's death second.** A program that
        // asked and then exited has its request already in the pair, and the
        // kernel reports both descriptors on the same look. Reading the
        // request first costs one answer nobody collects. Reading the death
        // first would lose a request that was really made.
        if (fds[0].revents & linux.POLL.IN != 0) {
            switch (netbroker.serveOne(broker_fd, broker)) {
                // Counted, because this is the one a sandboxed process can
                // make happen on purpose.
                .served => {
                    served += 1;
                    continue;
                },
                // Not counted: a signal that interrupted the read is not a
                // request, and counting it would let a signal storm this
                // process did not cause spend a call's whole budget.
                //
                // **This cannot spin.** The two errnos behind it are `EINTR`,
                // which needs a real signal at this process and so cannot
                // repeat without one, and `EAGAIN`, which a blocking
                // descriptor that `poll` has just called readable does not
                // answer. Nothing a sandboxed process can send produces
                // either one.
                .nothing => continue,
                .peer_gone => return,
            }
        }
        // The end of the stream on the pair, with nothing to read: every copy
        // of the child's end is closed, so nothing will ask again.
        if (fds[0].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0) return;
        if (fds[1].revents != 0) return;
    }
}

/// How many capped scratch areas one call may have.
///
/// A fixed number, because A holds them in an array on its own stack and must
/// not allocate: see `namespace.mountScratch`. Four is above what any caller in
/// this project asks for, and a caller that names more is refused plainly
/// rather than given fewer areas than it asked for.
const max_scratch_areas = 4;

/// The descriptors A holds on this call's scratch areas, and nothing else.
const ScratchAreas = struct {
    fds: [max_scratch_areas]i32 = @splat(-1),
    count: usize = 0,

    /// True when any area had no space left in it. See
    /// `namespace.scratchIsFull` for what that reading is worth.
    fn anyFull(self: *const ScratchAreas) bool {
        for (self.fds[0..self.count]) |fd| {
            if (namespace.scratchIsFull(fd)) return true;
        }
        return false;
    }
};

/// Mount every area in `config.scratch`, in A, and keep a descriptor on each.
///
/// **A failure ends the process rather than running on.** A caller that asked
/// for a capped area and got an ordinary directory has no bound on what its
/// program writes, and every other layer would still apply, so the call would
/// look completely normal while the one limit that stops a disk filling was
/// silently absent.
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

/// The one byte A writes on the scratch pipe to say an area was full.
///
/// A fixed value rather than a bare 1, so a read that ever landed on something
/// else is ignored instead of trusted. There is no forgery to defend against
/// here, unlike on the setup pipe: both ends are `CLOEXEC`, A is the only
/// writer, and `closeInheritedFds` already ran, so the sandboxed program never
/// holds either end.
const scratch_full_byte: u8 = 0xD1;

/// Say whether any scratch area was full when the program ended, on the
/// scratch pipe.
///
/// Best effort. A write that fails costs the caller the sentence that names the
/// limit and nothing else, and the program's own outcome is untouched by it.
fn reportScratch(areas: *const ScratchAreas, scratch_write_fd: i32) void {
    if (!areas.anyFull()) return;
    const byte = [1]u8{scratch_full_byte};
    _ = linux.write(scratch_write_fd, &byte, byte.len);
}

/// Read the scratch pipe, which A has already closed by the time this runs.
/// False on end of file with no data, which is the ordinary case of a call that
/// filled nothing.
fn readScratchReport(scratch_read_fd: i32) bool {
    var byte: [1]u8 = undefined;
    while (true) {
        const rc = linux.read(scratch_read_fd, &byte, byte.len);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) return false;
        return byte[0] == scratch_full_byte;
    }
}

/// Work out whether a resource limit is what ended the program, and say so.
///
/// **A signal number is not a reason.** A tool call that ran out of memory
/// dies from `SIGKILL`, which is exactly what a caller sees when the harness
/// cancels a call on its deadline or when a person presses Ctrl-C twice. This
/// is the one place that can tell those apart, because it is the only place
/// that holds both the `Term` and the cgroup's own counters.
///
/// Three facts, in the order they are trusted:
///
/// * `SIGXCPU` and `SIGXFSZ` name their own limit. Nothing else sends them
///   here. See `rlimits.limitForSignal`, and `rlimits.cpu_grace_seconds` for
///   why the cpu limit arrives as `SIGXCPU` at all rather than as one more
///   `SIGKILL`.
/// * `memory.events`' own `oom_kill` counter, for a `SIGKILL`. A kill this
///   counted is the kernel enforcing `memory.max`, and no cancel increments
///   it.
/// * `pids.events`' own `max` counter, which is not a kill at all: the
///   program was refused a fork and probably carried on. It is still worth
///   saying, because "make: fork: Resource temporarily unavailable" is not a
///   message a person connects to a sandbox on their own.
///
/// * A scratch area with no space left in it, for a program that ended badly.
///   **This is the one fact here that is inferred rather than counted**, and
///   it is last on purpose: every counter above it is the kernel's own record,
///   while a full area is only evidence. `ENOSPC` is answered to the program
///   and never recorded anywhere, so there is nothing better to read, and a
///   program that filled the sandbox's own area and then failed is far more
///   likely to have failed because of it than not. See
///   `namespace.scratchIsFull` and `Sandbox.LimitsReport.killed_by`.
///
/// A caller that named no `limits_report` still gets the sentence, on this
/// process's own standard error, the same way `printMiddleFault` reports a
/// layer the middle process could not put on.
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

    // The counted facts above win over the inferred one. A program killed by
    // `memory.max` while its scratch area happened to be full is an out of
    // memory kill, and calling it a full area would name the wrong limit.
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

    // **Descriptor 2, and not `config.stderr_fd`.** This runs in the real
    // parent, after `waitpid`, and it is this process speaking about a limit it
    // enforced rather than the sandboxed program's own diagnostics. The doc
    // comment above has said "this process's own standard error" since it was
    // written, and every caller of `spawn` still reads the sentence there.
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

/// True when the program did not finish the way a working program does.
///
/// **A full scratch area is only worth naming for a program that failed.** One
/// that filled its area, cleaned up after itself and exited 0 did the work it
/// was asked to do, and a report that named a limit there would be telling a
/// person about a problem they do not have. `LimitsReport.scratch_full` still
/// carries the raw fact for a caller that wants it either way.
fn endedBadly(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code != 0,
        else => true,
    };
}

/// Move this process into the cgroup `spawn` made for this call, so that
/// every process the call goes on to make is inside it.
///
/// A refusal ends the process rather than running on. **A program outside its
/// cgroup has no memory bound and no process bound at all**, and nothing
/// later in the setup would notice: every other layer would still apply and
/// the call would look completely normal.
fn joinCgroup(group: *cgroup.Cgroup, write_fd: i32, stderr_fd: i32) void {
    if (group.join()) |join_errno| {
        dieErrno(write_fd, stderr_fd, .cgroup_join, "write to cgroup.procs", join_errno);
    }
    // This process's own copy is finished with the moment the move is done.
    // Closed here, before `closeInheritedFds`, so that pass needs no
    // exemption for it and cannot be widened by one more number.
    group.closeProcsFd();
}

/// Read the setup pipe to completion and decide which of the two things
/// `spawn`'s doc comment describes actually happened. Returns the record when
/// a step reported a failure, or null when the pipe closed with no data,
/// meaning `execve` happened.
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
    // A short record is never trusted as a different, smaller failure. Only a
    // full, exact-size record is ever read as one. Anything else is unreadable
    // and reported as such rather than guessed at.
    if (filled != buffer.len) return error.UntrustedSetupReport;

    // A well formed record is always the only thing its writer ever sends: the
    // writer's process ends immediately after the write call, closing its
    // copy of the pipe. One more byte here would mean something else wrote to
    // this pipe too, which nothing in this design ever does.
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

/// Map the step a `SetupFailureRecord` names to the `SetupError` member that
/// names it to `spawn`'s caller.
fn setupErrorFor(step: SetupStep) SetupError {
    return switch (step) {
        .stdin_redirect => error.StdinRedirectFailed,
        .process_group => error.ProcessGroupFailed,
        .close_fds => error.CloseFdsFailed,
        .cgroup_join => error.CgroupJoinFailed,
        .resource_limits => error.ResourceLimitFailed,
        .namespace => error.NamespaceFailed,
        .scratch_mount => error.ScratchMountFailed,
        .mount_tree => error.MountTreeFailed,
        .pivot => error.PivotFailed,
        .capabilities => error.CapabilitiesFailed,
        .landlock_init => error.LandlockInitFailed,
        .landlock_rule => error.LandlockRuleFailed,
        .landlock_restrict => error.LandlockRestrictFailed,
        .session_keyring => error.SessionKeyringFailed,
        .seccomp_install => error.SeccompInstallFailed,
        .fork => error.ForkFailed,
        .pdeathsig_pidfd, .pdeathsig_prctl => error.PdeathsigSetupFailed,
        .exec => error.ExecFailed,
    };
}

/// Remove everything `buildRoot` made on the host under `root`, best effort,
/// and leave `root` itself, empty, exactly as the caller handed it over.
///
/// **The directory is the caller's and outlives one spawn.** Its contents are
/// this library's own scratch. See the call site in `spawn` for what a
/// removed root did to the session that owned it.
///
/// The mounts inside it are already gone by the time this runs: they lived in
/// the child's own mount namespace, `buildRoot` made that namespace's own `/`
/// `MS_PRIVATE` before it mounted anything, so no mount ever propagated back
/// to the host, and the kernel tore the namespace down when the child exited.
/// `spawn` reaps that child before it calls this. What is left on the host is
/// therefore plain directories and files that `makePath`, or `buildRoot`'s
/// own deny path walk, created under `root` before any mount ever covered
/// them.
///
/// **This walk can only ever meet those, because `buildRoot` no longer lets a
/// path resolved by name put anything outside `root` in the first place.**
/// That was not always true: an intermediate symbolic link in a `deny_read`
/// path, planted in the project's own checkout and resolved by `mkdirat` and
/// `openat` calls that took a name instead of a pinned descriptor, once let
/// `buildRoot` create the covering file wherever that link pointed, measured
/// against a real `buildRoot` and never under `root` at all. This walk would
/// never have met a file placed that way, and could not have removed it. See
/// `pinDenyTarget` in `namespace.zig`, which now refuses a symbolic link at
/// any component of that path before a name is ever handed to the kernel.
///
/// A failure here is not reported: the caller already has the real failure,
/// from whichever layer actually failed, and leaked scratch is a nuisance,
/// not a fault worth returning as one. A leftover a walk could not remove is
/// harmless to the call after it either way, because `makePath` treats an
/// existing mount target as made.
fn removeContentsBestEffort(allocator: std.mem.Allocator, root: []const u8) void {
    const root_z = allocator.dupeZ(u8, root) catch return;
    defer allocator.free(root_z);

    const dir_rc = linux.open(root_z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(dir_rc) != .SUCCESS) return;
    removeTreeFdBestEffort(allocator, @intCast(dir_rc));
}

/// One open directory the walk in `removeTreeFdBestEffort` is partway through:
/// its own descriptor, the `getdents64` bytes read for it and how far into
/// them the walk has gotten, and, for everything but the root, the parent
/// descriptor and name needed to `rmdir` it once every entry inside is gone.
const RemoveTreeFrame = struct {
    fd: i32,
    /// -1 for the root frame, whose own directory this walk never removes:
    /// see `removeContentsBestEffort` for why the root itself stays. Every
    /// other frame's directory is removed by this walk, through `parent_fd`
    /// and `name`, once its own `getdents64` reads run dry.
    parent_fd: i32 = -1,
    // NAME_MAX on Linux is 255 bytes. +1 leaves room for the null the code
    // below always writes, so `nameZ` can hand back a sentinel-terminated
    // slice with no extra copy.
    name: [256]u8 = undefined,
    name_len: usize = 0,
    buffer: [4096]u8 = undefined,
    buffer_len: usize = 0,
    offset: usize = 0,

    fn nameZ(self: *const RemoveTreeFrame) [:0]const u8 {
        return self.name[0..self.name_len :0];
    }
};

/// Remove everything under the directory `root_fd` names, walking with `*at`
/// calls relative to open descriptors rather than building an absolute path
/// for every entry. A deep enough tree makes an absolute path exceed
/// `PATH_MAX`, and a build that stops there with ENAMETOOLONG leaves every
/// directory below that point unreachable and leaked. A descriptor relative
/// walk has no such limit tied to depth.
///
/// The walk itself is an explicit stack on `allocator`, not native recursion:
/// one call frame per directory level would put a 4 KiB `getdents64` buffer on
/// the call stack at every level, and the design review's own 4098 level tree
/// is already enough to overrun a default 8 MiB stack that way, trading one
/// crash for another. A heap allocated stack has no such bound tied to
/// process stack size. Only `OutOfMemory` or the descriptor limit can stop it,
/// and both already degrade gracefully below, the same as every other fault
/// in this best effort walk. Takes ownership of `root_fd` and closes it, and
/// every descriptor this walk opens under it, before returning.
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
                // This directory's entries are exhausted, or unreadable in a way
                // best effort cleanup cannot recover from either way. Remove it,
                // now that everything inside it is already gone, and move back
                // up to whichever directory listed it.
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

            // append can move `stack.items` to a new allocation, invalidating
            // `top`. Nothing above this point still reads `top` after this
            // call, so that invalidation is never observed.
            stack.append(allocator, child) catch {
                _ = linux.close(child.fd);
            };
        } else {
            _ = linux.unlinkat(dir_fd, name_ptr, 0);
        }
    }
}

/// Write `line` to `stderr_fd` directly: one syscall, no allocation, and none
/// of the locking `std.debug.print` does internally. `die` and `dieErrno` call
/// this instead, because both run in the child after `fork`, where that lock
/// could already be stuck held by a thread that no longer exists in this
/// process. See the thread safety note on `spawn`.
///
/// **`stderr_fd` is `Config.stderr_fd`, from the first setup step and not only
/// after `execve`.** This used to name descriptor 2 by number, so a caller that
/// said where a sandboxed program's diagnostics go was obeyed only once
/// `redirectStandardStreams` had put that descriptor in place, which is the
/// last step before `execve`. Every setup failure before that point went to the
/// caller's own terminal whatever the caller asked for, and two tests in
/// `lib/chock-core` that build a sandbox which cannot come up put two lines in
/// every build log because of it.
///
/// **Which descriptor a caller of this function passes depends on where it
/// runs, and there are three cases:**
///
/// * In A, and in B until `redirectStandardStreams` has run: `config.stderr_fd`
///   itself, which both processes hold open at that point.
/// * In B after `redirectStandardStreams`: descriptor 2, because that step has
///   already put the caller's own descriptor there and closed the copy
///   `config.stderr_fd` names, for every descriptor above standard error. A
///   write to the number in the config after that point reaches a closed
///   descriptor, or a later one that took the number back.
/// * In A after it has forked B and given up its own copy: descriptor 2 again,
///   which is A's own inherited standard error. `dieRelay` and
///   `printMiddleFault` are the only two, and neither is a setup failure.
///
/// **Nothing is duplicated onto descriptor 2 to make this work, and the three
/// cases above are the reason.** An install would still need all three: the
/// number in the config stops naming a descriptor in B, and again in A, at
/// exactly the two points above, so one `dup2` early in A would not answer the
/// question on its own.
///
/// It would also add a collision of the kind `placeBrokerFd` already has to
/// handle. Which numbers the two pipes take is decided by the caller's own
/// descriptor table, and `pipe2` takes the two lowest free ones: a caller that
/// runs with descriptors 1 and 2 closed gives number 2 to the setup pipe's own
/// write end, and a `dup2` onto 2 would take away the one channel every `die`
/// call reports through. The descriptor travels with each call instead, so no
/// pipe can be overwritten and no state of this process is changed.
fn writeStderr(stderr_fd: i32, line: []const u8) void {
    _ = linux.write(stderr_fd, line.ptr, line.len);
}

/// Print the name of `err` on `stderr_fd`. Shared by every terminal failure
/// path below, whether or not that path can still reach the setup pipe. See
/// `writeStderr` for which descriptor each caller names.
fn printFault(stderr_fd: i32, err: anyerror) void {
    var buffer: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buffer, "sandbox: {s}\n", .{@errorName(err)}) catch
        "sandbox: an error occurred, and its name was too long to print\n";
    writeStderr(stderr_fd, line);
}

/// The one sentence a project author reads for
/// `namespace.MountError.DenyTargetIsSymlink`, in place of `printFault`'s
/// bare error name.
///
/// **Why this gets a sentence and `printFault`'s other callers do not.**
/// Every other fault `dieNamespace` and its neighbours report is a kernel
/// refusing this process something. The bare name plus an errno is already
/// the diagnosis, because the fix is "give this process the privilege" or
/// "use a newer kernel", not something in a person's own project. This one
/// is different: it fires only because of a line the project itself wrote in
/// its own `chock.zon`, so a bare error name sends a person to search for a
/// Zig identifier instead of their own file. The reasoning for why a symlink
/// is refused rather than followed lives in `namespace.zig`'s own doc comment
/// on `DenyTargetIsSymlink`, and in the threat model. This sentence carries
/// only what to change.
///
/// **It does not, and cannot yet, name the entry.** `namespace.Diagnostic`
/// carries two enumerations and nothing else, on purpose: the hardest callers
/// build one in a forked child with no allocator, and this fault is
/// deliberate rather than a kernel errno, so it never fills one in. Naming
/// the offending path would mean carrying a path through that type for every
/// caller, not only this one, and that is a bigger change than this message.
fn printDenyTargetSymlinkFault(stderr_fd: i32) void {
    writeStderr(
        stderr_fd,
        "sandbox: a deny_read entry in chock.zon names a symbolic link, and it will not be followed. Point deny_read at the real file, not at a link to it.\n",
    );
}

/// The one sentence a project author reads for
/// `namespace.MountError.BindSourceIsSymlink`, in place of `printFault`'s
/// bare error name. Same reasoning as `printDenyTargetSymlinkFault`: this
/// fault fires because of a name in the project's own tree, not because the
/// kernel refused this process a privilege, so a bare error name sends a
/// person to search for a Zig identifier instead of their own file.
/// `chock.zon` is the case a person actually hits: it is read out of the
/// agent's own checkout, and nothing stops that checkout holding a symlink
/// in its place. The reasoning for why a symlink is refused rather than
/// followed lives in `namespace.zig`'s own doc comment on
/// `BindSourceIsSymlink`, and in the threat model. This sentence carries
/// only what to change.
fn printBindSourceSymlinkFault(stderr_fd: i32) void {
    writeStderr(
        stderr_fd,
        "sandbox: a bind mount's source names a symbolic link, and it will not be followed. chock.zon is the usual case: make it a real file, not a link to one.\n",
    );
}

/// Same as `printBindSourceSymlinkFault`, for
/// `namespace.MountError.BindTargetIsSymlink`: the same fault, on the other
/// side of the same mount.
fn printBindTargetSymlinkFault(stderr_fd: i32) void {
    writeStderr(
        stderr_fd,
        "sandbox: a bind mount's target names a symbolic link, and it will not be followed. chock.zon is the usual case: make it a real file, not a link to one.\n",
    );
}

/// Same as `printFault`, for a step that reads its own errno instead of
/// returning a Zig error, the same way `namespace.zig` names an errno it
/// cannot map to a specific recovery.
fn printFaultErrno(stderr_fd: i32, comptime what: []const u8, err: linux.E) void {
    var buffer: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buffer, "sandbox: {s} failed: {s}\n", .{ what, @tagName(err) }) catch
        "sandbox: a step failed, and its name was too long to print\n";
    writeStderr(stderr_fd, line);
}

/// Report `step` as failed over the setup pipe. The result of the write is
/// not checked: the process ends right after this call regardless, and a
/// write this small, well under PIPE_BUF, either lands whole or the pipe
/// itself is broken beyond anything this process could recover from anyway.
fn reportSetupFailure(write_fd: i32, step: SetupStep, errno_value: i32) void {
    const record = SetupFailureRecord{ .step = @intFromEnum(step), .errno = errno_value };
    const bytes = std.mem.asBytes(&record);
    _ = linux.write(write_fd, bytes.ptr, bytes.len);
}

/// Report `step` as failed over the setup pipe, print the error name, and end
/// the process. Every layer in `applyLayers` and `execute` calls this instead
/// of returning its error, so a setup fault can never reach `execve`. The exit
/// code passed to the kernel here carries no meaning `spawn` ever reads: once
/// this function has written to the pipe, spawn already knows the real
/// outcome from that, not from any exit code.
///
/// **The record goes first, and the text second, in every function of this
/// family.** The text goes to a descriptor the caller chose, and a caller can
/// choose a pipe whose read end is already closed: that write answers `EPIPE`
/// and raises `SIGPIPE`, whose default action, restored by `resetSignalState`,
/// ends this process where it stands. With the text first, that death happened
/// before the record was written, so `spawn` read end of file with no data,
/// which is exactly how a successful `execve` reports itself, and answered a
/// `Term` for a program that never ran. The setup pipe is this library's own
/// and always has a reader, so it cannot fail the same way.
fn die(write_fd: i32, stderr_fd: i32, step: SetupStep, err: anyerror) noreturn {
    reportSetupFailure(write_fd, step, 0);
    printFault(stderr_fd, err);
    std.process.exit(1);
}

/// Same as `die`, for a step that can also say which call the kernel refused.
/// Every step that carries a `namespace.Diagnostic` comes here: the namespaces
/// themselves, the scratch mount, the mount tree and the pivot.
///
/// **The errno reaches the parent, and not only this process's stderr.** A
/// mount fault used to answer `error.Unexpected` over the pipe and put the one
/// fact that identifies it on the terminal of a sandboxed child, where a caller
/// that is not a terminal never saw it. `SetupFailureRecord` always had the
/// field for this. It was written as zero because nothing carried the value
/// this far.
///
/// **The namespace step was missed when that was fixed.** It kept calling
/// plain `die`, so a machine that refused the user namespace answered
/// `error.NamespaceFailed` with errno 0. Measured on 2026-08-25: two CI
/// architectures failed 132 tests each, and the whole log could say only that
/// the sandbox would not start. Which call it was, and with what errno, is the
/// diagnosis, and none of it left the child.
fn dieNamespace(
    write_fd: i32,
    stderr_fd: i32,
    step: SetupStep,
    err: anyerror,
    diag: ?namespace.Diagnostic,
) noreturn {
    if (diag) |d| {
        // The record first, and the text second, for the reason `die` gives.
        reportSetupFailure(write_fd, step, @intFromEnum(d.errno));
        var buffer: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "sandbox: {f}\n", .{d}) catch
            "sandbox: a mount failed, and the reason was too long to print\n";
        writeStderr(stderr_fd, line);
    } else if (err == error.DenyTargetIsSymlink) {
        // No `diag`: this is `applyDenyMounts` refusing on purpose, never a
        // kernel errno, so there is nothing in `d.errno` to report. See
        // `printDenyTargetSymlinkFault` for why this fault alone gets a
        // sentence instead of `printFault`'s bare name.
        reportSetupFailure(write_fd, step, 0);
        printDenyTargetSymlinkFault(stderr_fd);
    } else if (err == error.BindSourceIsSymlink) {
        // No `diag`: `pinBindSource` refuses this on purpose, never a kernel
        // errno. See `printBindSourceSymlinkFault`.
        reportSetupFailure(write_fd, step, 0);
        printBindSourceSymlinkFault(stderr_fd);
    } else if (err == error.BindTargetIsSymlink) {
        // No `diag`: `makeFile` refuses this on purpose, never a kernel
        // errno. See `printBindTargetSymlinkFault`.
        reportSetupFailure(write_fd, step, 0);
        printBindTargetSymlinkFault(stderr_fd);
    } else {
        reportSetupFailure(write_fd, step, 0);
        printFault(stderr_fd, err);
    }
    std.process.exit(1);
}

/// Same as `dieNamespace`, for the three Landlock calls.
///
/// **The errno reaches the parent, and not only this process's stderr.**
/// Landlock used to print its own errno from inside this child, which is
/// the one thing `spawn`'s doc comment says the child never does: that
/// print takes a global lock a thread of the parent may have held at the
/// moment of the fork. `writeStderr` below takes no lock at all.
fn dieLandlock(
    write_fd: i32,
    stderr_fd: i32,
    step: SetupStep,
    err: anyerror,
    diag: ?landlock.Diagnostic,
) noreturn {
    if (diag) |d| {
        // The record first, and the text second, for the reason `die` gives.
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

/// Same as `dieLandlock`, for the capability drop.
///
/// **The errno reaches the parent, and not only this process's stderr**, for
/// the same reason `dieLandlock`'s own comment gives: this runs in the child
/// after `fork`, where `std.debug.print` could already be stuck on a lock a
/// thread of the parent held at the moment of the fork.
fn dieCapabilities(
    write_fd: i32,
    stderr_fd: i32,
    err: anyerror,
    diag: ?capabilities.Diagnostic,
) noreturn {
    if (diag) |d| {
        // The record first, and the text second, for the reason `die` gives.
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

/// Same as `dieNamespace`, for a resource limit the kernel refused.
///
/// **The errno reaches the parent**, for the reason `dieNamespace` gives: a
/// caller that is not a terminal never reads what this child prints, and
/// `error.ResourceLimitFailed` alone does not say which limit or why.
fn dieLimit(write_fd: i32, stderr_fd: i32, err: anyerror, diag: ?rlimits.Diagnostic) noreturn {
    if (diag) |d| {
        // The record first, and the text second, for the reason `die` gives.
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

/// Same as `die`, for a step that reads its own errno instead of returning a
/// Zig error.
fn dieErrno(
    write_fd: i32,
    stderr_fd: i32,
    step: SetupStep,
    comptime what: []const u8,
    err: linux.E,
) noreturn {
    // The record first, and the text second, for the reason `die` gives.
    reportSetupFailure(write_fd, step, @intFromEnum(err));
    printFaultErrno(stderr_fd, what, err);
    std.process.exit(1);
}

/// End the process for a fault on the relay path in `waitAndRelay`, after the
/// setup pipe is already closed. There is no channel left to report this to
/// spawn as a setup failure, and there must not be one: the caller's own
/// program has already started running by the time `waitAndRelay` runs, so
/// nothing from here on may ever look like a setup failure to spawn. This
/// exists only so the fault is not silent. The exit code it uses is not read
/// by spawn as meaning anything.
///
/// **Descriptor 2, and never `config.stderr_fd`.** This runs in A, after A has
/// closed its own copy of the descriptor a caller named: see that close in
/// `spawn`, and the third case on `writeStderr`. The number in the config names
/// no descriptor of A's by then, or names one A opened later that took the
/// number back.
fn dieRelay(err: anyerror) noreturn {
    printFault(std.posix.STDERR_FILENO, err);
    std.process.exit(1);
}

/// Same as `dieRelay`, for a step that reads its own errno, and on the same
/// descriptor for the same reason.
fn dieRelayErrno(comptime what: []const u8, err: linux.E) noreturn {
    printFaultErrno(std.posix.STDERR_FILENO, what, err);
    std.process.exit(1);
}

/// Wait for `pid`, the grandchild running the caller's program as process 1 of
/// the new pid namespace, and end this process the same way that grandchild
/// ended: by the same signal, or with the same exit code. Never returns.
///
/// This process, the intermediate between the real parent and the sandboxed
/// program, is an ordinary process in its own right pid namespace, not process 1
/// anywhere. Process 1 of a pid namespace does not get the default action for an
/// unhandled signal, so it does not die from a plain SIGTERM. That immunity does
/// not apply here, and raising the same signal on this process ends it the
/// normal way. That is what makes the relay possible: the real parent's own
/// waitpid, further up the call stack, reads this process's own death as the
/// grandchild's.
///
/// When the grandchild, process 1 of the new namespace, exits for any reason,
/// the kernel kills every other process left in that namespace. Chock wants
/// exactly that: a tool call that leaves stray children behind cannot outlive
/// the program the caller asked to run.
fn waitAndRelay(pid: linux.pid_t, areas: *const ScratchAreas, scratch_write_fd: i32) noreturn {
    var status: u32 = undefined;
    var wait_rc = linux.waitpid(pid, &status, 0);
    // A signal caught by this process while it waits interrupts the call with
    // EINTR. That is not the grandchild failing, so retry instead of reporting
    // it as one.
    while (linux.errno(wait_rc) == .INTR) {
        wait_rc = linux.waitpid(pid, &status, 0);
    }
    if (linux.errno(wait_rc) != .SUCCESS) {
        dieRelayErrno("waitpid on the sandboxed program", linux.errno(wait_rc));
    }

    // **Read the scratch areas here, and nowhere else.** They live in this
    // process's own mount namespace, which nothing outside it can see, and the
    // program that could have filled them has just ended, so this is both the
    // only place and the only moment the reading means anything. It happens
    // before the relay below, because every branch of that relay ends this
    // process.
    reportScratch(areas, scratch_write_fd);

    if (linux.W.IFSIGNALED(status)) {
        const sig = linux.W.TERMSIG(status);
        std.posix.raise(sig) catch |err| dieRelay(err);
        // raise() only returns on failure. The grandchild already died from this
        // exact signal, which the kernel only reports for a signal whose default
        // action is fatal, so raising it here should end this process the same
        // way and never reach the line below. Name the case anyway, so a kernel
        // surprise cannot fall through in silence.
        dieRelay(error.Unexpected);
    }

    std.process.exit(linux.W.EXITSTATUS(status));
}

// The order of the layers, and which of the two child processes runs each one.
// **Steps 0 and 1 run in A, in `enterNamespaces` below. Steps 2 to 6 run in B,
// in `applyLayers` below.** The order itself is the order it always was, and
// it is not free to change.
//
// 0. Close every inherited file descriptor first, while /proc still shows the
//    host's view of this process. A descriptor kept open past this point stays
//    open across every later step, including `pivot_root`.
// 1. The namespaces come first, because a mount needs a mount namespace.
// 2. The mount tree comes next, because `pivot_root` needs it built.
// 3. `pivot_root` moves the process into the new root, so a Landlock rule
//    below can open the paths it protects at the same paths the sandboxed
//    program will see, not at their location on the host.
// 4. Landlock comes next, because it needs to open each path.
// 5. The session keyring join comes after Landlock and before seccomp.
//    `CLONE_NEWUSER`, back in step 1, already gave this process a fresh user
//    keyring, but the kernel has no namespace for the session keyring, so it
//    is still the one this process inherited across the fork. This step
//    replaces it with a fresh, anonymous one, so a key added on either side
//    of the sandbox boundary can no longer be read, or destroyed, from the
//    other side. It is not covered by any namespace, which is exactly why
//    this call still has to run.
// 6. seccomp comes last, because the filter blocks `unshare`, the whole
//    mount family, and now `add_key`, `keyctl`, and `request_key` too, and
//    every one of those calls is still needed by a step above, including the
//    session keyring join, which uses `keyctl` itself. `insns` is already
//    built by the time this runs: `spawn` builds it in the parent, before
//    the fork, so this step only installs it.

/// Steps 0 and 1, in A: close every inherited descriptor, then take the
/// namespaces.
///
/// **These two stay in A, and everything below them runs in B.** The
/// descriptors are closed here because A opens a pidfd on itself right after
/// this, hands it to B for `armPdeathsig`, and a close that ran in B would
/// close that pidfd along with the rest. The namespaces are taken here because
/// `unshare(CLONE_NEWPID)` never moves its own caller into the namespace it
/// makes: only a child forked afterwards lands there, and that child is B.
fn enterNamespaces(config: Config, write_fd: i32, scratch_write_fd: i32, broker_fd: i32) void {
    closeInheritedFds(write_fd, scratch_write_fd, config.stdout_fd, config.stderr_fd, config.stdin_fd, broker_fd);

    // The slot is here for the reason `applyLayers` has one, and for one more:
    // `error.NamespaceFailed` on its own cannot tell a policy that refuses an
    // unprivileged user namespace from a machine that has no room for another
    // one, nor either of those from a map file this process may not write. See
    // `dieNamespace`.
    var diag: ?namespace.Diagnostic = null;
    namespace.enter(.{ .network = config.network, .mount = true }, &diag) catch |err|
        dieNamespace(write_fd, config.stderr_fd, .namespace, err, diag);
}

/// Steps 2 to 6 of the order above, in B, the process that runs the caller's
/// program. **The mount tree is built here and not in A**, because a procfs
/// mount takes the pid namespace of whichever process makes it: see the
/// comment on the second fork in `spawn`. A puts its own two layers on
/// afterwards, in `restrictMiddle`.
fn applyLayers(
    allocator: std.mem.Allocator,
    config: Config,
    abi: i32,
    insns: []const bpf.Insn,
    write_fd: i32,
) void {
    // One slot for both calls: `note` keeps the first fault, and a pivot can
    // only fail after a mount tree that did not, so the first is the one that
    // explains the rest.
    var diag: ?namespace.Diagnostic = null;
    namespace.buildRoot(allocator, config.root, config.mounts, &diag) catch |err|
        dieNamespace(write_fd, config.stderr_fd, .mount_tree, err, diag);
    namespace.pivotInto(allocator, config.root, &diag) catch |err|
        dieNamespace(write_fd, config.stderr_fd, .pivot, err, diag);

    // Right here, and nowhere else. `buildRoot` and `pivotInto`, just above,
    // are the last two steps that still need `CAP_SYS_ADMIN`; nothing below
    // this line, in this function, asks the kernel for anything a capability
    // gates. See `capabilities.dropAll`'s own top comment for what each of
    // its three calls closes and why the order inside it is fixed.
    var cap_diag: ?capabilities.Diagnostic = null;
    capabilities.dropAll(&cap_diag) catch |err|
        dieCapabilities(write_fd, config.stderr_fd, err, cap_diag);

    // One slot for all three calls, for the reason the mount slot above has
    // one: `note` keeps the first fault, and a rule can only be added to a
    // ruleset that was made.
    var landlock_diag: ?landlock.Diagnostic = null;
    var ruleset = landlock.Ruleset.init(abi, &landlock_diag) catch |err|
        dieLandlock(write_fd, config.stderr_fd, .landlock_init, err, landlock_diag);
    defer ruleset.deinit();
    for (config.rules) |rule| {
        ruleset.allowPath(rule.path, rule.access, &landlock_diag) catch |err|
            dieLandlock(write_fd, config.stderr_fd, .landlock_rule, err, landlock_diag);
    }
    ruleset.restrictSelf(&landlock_diag) catch |err|
        dieLandlock(write_fd, config.stderr_fd, .landlock_restrict, err, landlock_diag);

    joinFreshSessionKeyring(config.stderr_fd) catch |err|
        die(write_fd, config.stderr_fd, .session_keyring, err);

    seccomp.install(bpf.Prog.init(insns)) catch |err|
        die(write_fd, config.stderr_fd, .seccomp_install, err);
}

/// What A holds while it waits for B: a Landlock ruleset with no rule in it,
/// which permits no path at all, and the same seccomp filter B runs under.
///
/// **A is this program's own code and holds this process's own memory**, which
/// on the `chock run` path includes the credential of the provider. Before the
/// mount tree moved into B, A had every layer applied to itself, and it kept
/// that promise by accident rather than by decision. These two calls keep it on
/// purpose, and the empty ruleset is stricter than the pivot A used to have: A
/// opens no path after this, so denying every path costs it nothing.
///
/// Best effort, and never fatal. B already runs, and killing A here would kill
/// the caller's program for a layer that protects nothing of the caller's. A
/// failure is printed, because a recovery nobody can see is not a recovery.
fn restrictMiddle(abi: i32, insns: []const bpf.Insn) void {
    // **This is the one caller with nowhere to send a diagnostic.** The
    // setup pipe is already closed, the caller's own program is already
    // running, and nothing here may ever look like a setup failure to
    // `spawn`. So the reason is written straight to standard error, and
    // the slot is here only so that reason is the errno and not the bare
    // `error.Unexpected`.
    //
    // **A holds the same full capability set B does, until this runs.** A
    // never calls `buildRoot` or `pivotInto` itself, so nothing above this
    // line in A ever needed one, and A holds the caller's own provider
    // credential in its memory: best effort here still costs A nothing, for
    // the reason this whole function's own doc comment gives.
    var cap_diag: ?capabilities.Diagnostic = null;
    capabilities.dropAll(&cap_diag) catch |err| printMiddleCapabilitiesFault(err, cap_diag);

    var diag: ?landlock.Diagnostic = null;
    if (landlock.Ruleset.init(abi, &diag)) |ruleset| {
        var owned = ruleset;
        defer owned.deinit();
        owned.restrictSelf(&diag) catch |err| printMiddleFault(err, diag);
    } else |err| {
        printMiddleFault(err, diag);
    }

    seccomp.install(bpf.Prog.init(insns)) catch |err| printMiddleFault(err, null);
}

/// Same as `printMiddleFault`, for the one call in `restrictMiddle` that is
/// not a `landlock.Diagnostic`.
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

/// Name a layer the middle process could not put on itself. Its own line, so
/// a reader of the output knows the fault is about A and not about the
/// caller's own program, which by then is already running.
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
    // Descriptor 2, for the reason `dieRelay` gives: by the time this can run,
    // A has already given up its copy of the descriptor the caller named.
    writeStderr(std.posix.STDERR_FILENO, line);
}

/// Join a fresh, anonymous session keyring, replacing whichever one this
/// process inherited across the fork.
///
/// `CLONE_NEWUSER` gives a process a fresh *user* keyring on its own, but the
/// kernel has no namespace for the *session* keyring. Without this call, a
/// key another host process planted in the session keyring is still readable
/// from inside the sandbox, and a key the sandbox adds is still readable, and
/// revocable, from the host: the session keyring crosses the sandbox
/// boundary in both directions, in a way no namespace here closes. Operation
/// 1 is `KEYCTL_JOIN_SESSION_KEYRING`. A null name asks the kernel to
/// allocate a brand new, anonymous keyring, rather than joining a named one
/// that some other process could also join.
///
/// This must run before `seccomp.install`: the filter blocks `keyctl`, and a
/// filter can never be removed, so calling this after the filter goes on
/// would only ever fail. It is public so a test can call it directly,
/// outside a full `spawn`, and prove the fresh keyring really is empty. A
/// real caller never calls this itself. `applyLayers` already does, in the
/// one place order matters.
///
/// `stderr_fd` is where the errno goes, and it is a parameter for the reason
/// `writeStderr` gives. The errno is the only place the reason for a refusal
/// appears, since `error.JoinFailed` carries no number, and a caller that asked
/// for a quiet setup failure must not be given this one line on its terminal
/// either. A caller outside `spawn`, such as `test/sandbox/probe.zig`, names
/// descriptor 2.
pub fn joinFreshSessionKeyring(stderr_fd: i32) error{JoinFailed}!void {
    const keyctl_join_session_keyring: usize = 1;
    const rc = linux.syscall2(.keyctl, keyctl_join_session_keyring, 0);
    const join_errno = linux.errno(rc);
    if (join_errno != .SUCCESS) {
        printFaultErrno(stderr_fd, "keyctl(KEYCTL_JOIN_SESSION_KEYRING)", join_errno);
        return error.JoinFailed;
    }
}

/// The highest signal number this driver puts back to its default. 31 is the
/// last of the classic signals on every architecture this project builds for.
/// The real time signals above it need no reset: a caller of `spawn` that
/// installs a handler for one of those is outside anything this driver has
/// ever seen, and `rt_sigaction` on a number the running kernel does not have
/// only wastes a refused syscall.
const last_reset_signal: u32 = 31;

/// Put every signal back the way a fresh process gets it: the default action
/// for each one, and an empty mask.
///
/// **A child of `fork` keeps the caller's own signal handlers, and a handler
/// belongs to the caller's program, not to this one.** Measured on
/// 2026-08-21: `chock run` installs a `SIGINT` and `SIGTERM` handler that
/// prints "stopping at the next safe point" and sets a flag, and this
/// process kept it. Two faults came from that, and both were seen by the
/// project owner in one session:
///
/// * `lib/chock-core/tools.zig` cancels a tool call that runs past its
///   deadline by sending `SIGTERM` to this process, which is the only way it
///   has to end the sandboxed program (see `spawn`'s own doc comment on
///   `middle`). The caller's handler caught that signal here, printed its
///   message, and **this process did not die**, so the timeout cancelled
///   nothing and the call ran on.
/// * The message went to this process's own standard error, which is the
///   caller's terminal: this process never redirects its own descriptor 2,
///   only the sandboxed program's. So a user watching a session read
///   "chock: stopping at the next safe point" with nobody having pressed
///   anything.
///
/// `waitAndRelay` has the same need on its own: it ends this process by
/// raising the signal the sandboxed program died from, and an inherited
/// handler makes that `raise` return instead of ending anything.
///
/// The mask goes with the handlers for the same reason. A signal the caller
/// had blocked stays blocked here, and a blocked `SIGTERM` defeats the
/// cancellation above exactly as a caught one does.
///
/// Every failure is ignored on purpose. `rt_sigaction` refuses `SIGKILL` and
/// `SIGSTOP`, which are skipped below, and a number the running kernel does
/// not know, which is already at its default because nothing could have
/// installed a handler for it. Neither is a reason to refuse to run the
/// program.
fn resetSignalState() void {
    const to_default = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.DFL },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    var number: u32 = 1;
    while (number <= last_reset_signal) : (number += 1) {
        const sig: std.posix.SIG = @enumFromInt(number);
        // The two the kernel refuses, and `linux.sigaction` asserts on.
        if (sig == .KILL or sig == .STOP) continue;
        _ = linux.sigaction(sig, &to_default, null);
    }

    const empty = std.posix.sigemptyset();
    _ = linux.sigprocmask(std.posix.SIG.SETMASK, &empty, null);
}

/// Put this process, and every process it goes on to make, in a process group
/// of its own.
///
/// **A process group is not isolated by a PID namespace, and two different
/// faults come from the sandbox sharing its caller's group.**
///
/// The containment one: `kill(0, sig)` names the caller's own process group,
/// and a group is an object the kernel holds, not a number a namespace can
/// hide. Measured on 2026-08-21: a process inside `CLONE_NEWPID` reads
/// `getpgid(0)` as 0, because its group has no number there, and
/// `kill(0, sig)` from it still reached a process outside the namespace. So
/// the PID namespace, on its own, did **not** give `Guarantee.signal_isolated`
/// what it promises: a sandboxed program could signal the very process running
/// it. A group of the sandbox's own closes that, because a group directed
/// signal from inside then reaches nothing but the sandbox.
///
/// The other one: a terminal sends `SIGINT` to its whole foreground process
/// group, so one Ctrl-C reached the caller **and** the running program. That
/// makes `chock run`'s own first press message, which promises the current
/// work continues to a safe point, a false statement: the program died on
/// the same press. With this call the first press reaches only the caller.
///
/// **The caller must then end a running call itself**, because nothing from
/// the terminal reaches it any more. `lib/chock-core/tools.zig` does, in two
/// places: on a timeout, and on a second Ctrl-C, both through the handle
/// `spawn` gives it on this function's own process. See `spawn`'s own doc
/// comment on `middle`, and `iface.Middle` for why a handle and not the
/// number.
///
/// `setpgid(0, 0)` makes a group whose identifier is this process's own pid.
/// **Nothing in Chock signals that group any more**, and the group is kept for
/// the two reasons above and not for cancellation: a cancel reaches one
/// process and the pid namespace carries it to the rest, which `spawn`'s own
/// doc comment records the measurement for.
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

/// Give the child /dev/null on descriptor 0, replacing whatever standard
/// input this process had before the sandbox was ever entered.
///
/// Two reasons, both real. The sandboxed program must have no terminal, so a
/// password prompt reads EOF
/// from /dev/null and returns control to Chock instead of hanging on a read
/// nobody can ever answer. And if descriptor 0 was the caller's controlling
/// terminal, `ioctl(0, TIOCSTI)` can push characters straight into that
/// terminal's own input queue. No Landlock rule covers a descriptor that was
/// already open before the sandbox existed, so replacing the descriptor is
/// the only fix. Standard output and standard error are left untouched: a
/// caller needs the program's real output.
///
/// This runs before `applyLayers`, while /dev/null still resolves on the
/// host's own filesystem. The descriptor it opens stays valid after
/// `pivot_root`, because an already open file descriptor does not go through
/// path resolution again.
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

    // /dev/null is never opened as descriptor 0 directly, but dup2 is a
    // documented no-op when old and new already match. Guard the close so
    // that case can never close the descriptor this just set up.
    if (fd != std.posix.STDIN_FILENO) _ = linux.close(fd);
}

/// Close every file descriptor above standard error, except `write_fd`,
/// `scratch_write_fd`, `stdout_fd`, `stderr_fd`, and `stdin_fd`, so a
/// descriptor opened before
/// the sandbox was entered cannot be used to reach the host filesystem after
/// `pivot_root`. A descriptor does not go through path resolution again once
/// it is open, so `namespace.pivotInto` cannot revoke one on its own, and a
/// directory descriptor opened before this call could still reach the host
/// tree by name through `openat`. Only closing the descriptor removes it.
/// `write_fd` is the setup pipe every step in this function and every step
/// after it needs to keep working, so it is one descriptor this pass must
/// never touch. `stdout_fd` and `stderr_fd` are `Config.stdout_fd` and
/// `Config.stderr_fd`: when a caller named a descriptor other than this
/// process's own standard output or standard error there, `execute` still
/// needs it open, later, in B, to `dup2` it onto the caller's program's own
/// standard streams, so this pass must not close it out from under that
/// later step either. Either or both may already be at or below standard
/// error, the ordinary case of a caller that left the default, in which
/// case this loop was never going to touch them anyway.
///
/// **`stderr_fd` is also where every step after this pass writes the reason it
/// could not go on**, which is a second reason to keep it and not only the
/// `dup2` in `execute`. A pass that closed it would leave every later `die`
/// call writing to a descriptor that names nothing. See `writeStderr`.
///
/// `stdin_fd` is `Config.stdin_fd`, and it is null for every tool call. When
/// a caller named one it is kept for the same reason and by the same rule as
/// the two above, **and for exactly one number**: every other descriptor is
/// still closed, so a pipe on descriptor 0 widens what the sandboxed program
/// holds by one pipe and by nothing else. See `Config.stdin_fd` for what a
/// pipe there does and does not give.
///
/// `scratch_write_fd` is the second pipe, and it is the one exemption this
/// pass gained after the fact, so the reason is written down rather than left
/// to be guessed at. **It could not be avoided by making the pipe later.** The
/// real parent has to hold the read end, so the pipe has to exist before the
/// fork, and the fact it carries, whether a scratch area was full, is only
/// knowable after the sandboxed program has ended. So this process keeps the
/// write end through every layer and writes on it once, in `waitAndRelay`.
/// It reaches nothing: a pipe has no name in any filesystem, both ends are
/// `CLOEXEC` so the sandboxed program's own `execve` drops its copy, and the
/// only thing ever written on it is one byte this file chooses. Compare
/// `joinCgroup`, which closes its descriptor before this pass on purpose,
/// because it could.
///
/// This runs before any namespace or mount is set up, while `/proc` still shows
/// the host's view of this process's own descriptor table. The sandbox's mount
/// tree is never required to carry its own `/proc` mount for this to work.
fn closeInheritedFds(
    write_fd: i32,
    scratch_write_fd: i32,
    stdout_fd: i32,
    stderr_fd: i32,
    stdin_fd: ?i32,
    broker_fd: i32,
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
            // `name` is a flexible array member. `@offsetOf` gives its true
            // position. `@sizeOf` would include tail padding the layout does
            // not actually carry between entries.
            const name_offset = offset + @offsetOf(linux.dirent64, "name");
            const name_ptr: [*:0]const u8 = @ptrCast(&buffer[name_offset]);
            const name = std.mem.sliceTo(name_ptr, 0);

            // "." and ".." are not fd numbers and fail to parse here, which
            // skips them along with anything else this directory could ever
            // hold that is not purely digits.
            if (std.fmt.parseInt(i32, name, 10)) |fd| {
                // Skip the descriptor reading this directory, the two pipes,
                // the three standard streams, the caller's own chosen output
                // descriptors, and the broker pair's child end. Every other
                // descriptor is one the parent held before this process was
                // ever meant to run.
                if (fd > std.posix.STDERR_FILENO and fd != dir_fd and fd != write_fd and
                    fd != scratch_write_fd and fd != broker_fd and
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

/// Arm `PR_SET_PDEATHSIG` in B, the grandchild that is about to run the
/// caller's program, and close the one race that makes it unreliable on its
/// own.
///
/// The kernel delivers a process's death signal exactly once, at the moment
/// `exit_notify` runs for its parent, A. If A already died before this
/// process reached the `prctl` call below, that moment already passed with no
/// signal armed, and none will ever come: arming it now only sets up delivery
/// for whichever process A's death left as this process's new, effectively
/// invisible, parent.
///
/// `getppid` cannot reveal that A is already gone. This process is about to
/// become process 1 of a pid namespace A is not a member of, and a pid
/// namespace only shows processes that are members of it or one of its
/// descendants. A predates this namespace and belongs to neither, so A has no
/// pid number in here at all, whether A is alive or dead. `getppid` reads 0
/// unconditionally, before this call and after it, in both cases, which is
/// exactly why this function does not call it. `middle_pidfd`, opened by A on
/// itself before the fork that created this process and inherited across
/// that fork, names A by its underlying task instead of by a namespace
/// relative number, so a poll on it reports A's real state even though this
/// process can never see A's pid. A zero timeout asks whether A is already
/// gone, right now, with no wait: this is the whole reason the poll below can
/// close the race PR_SET_PDEATHSIG leaves open.
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
        // A was already gone before the prctl call above could register, so the
        // kernel never had a live target to deliver PDEATHSIG to. End this
        // process the same way PDEATHSIG would have: SIGKILL on itself. This is
        // not a setup failure to report over the pipe. It is the same outcome a
        // caller that signals A is meant to see, just reached by a different
        // path.
        std.posix.raise(std.posix.SIG.KILL) catch {};
        // SIGKILL cannot be caught, blocked, or ignored, and raise() does not
        // return on success, so this line is unreachable in practice. Named
        // anyway so a kernel surprise here is never silent.
        std.process.exit(1);
    }
}

/// Run the caller's program. Only reached once every layer above has applied.
/// Never returns: `execve` replaces this process on success, and every failure
/// path here calls `die` or `dieErrno`.
fn execute(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    write_fd_in: i32,
    broker_fd: i32,
) noreturn {
    // An empty argv is a programmer error: the caller has nothing to run. This
    // is not a fact the outside world can hand us, so it is asserted, not
    // returned as an error.
    std.debug.assert(argv.len > 0);

    // The setup pipe can move, in the one case below where it sits on the
    // number the broker socket has to have. Every `die` from here on names
    // this and never the descriptor this function was called with.
    var write_fd = write_fd_in;

    redirectStandardStreams(config, write_fd);

    // **Descriptor 2 from here down, and not `config.stderr_fd`.** The call
    // above has already put the descriptor the caller named onto descriptor 2,
    // and closed the copy the config names, so descriptor 2 now reaches the
    // caller's own destination and the number in the config reaches nothing.
    // See the second case on `writeStderr`.
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

    // **The last thing before the exec but one, and that position is a rule.**
    // Three
    // of these limits would refuse the setup path itself if they went on
    // earlier: `RLIMIT_DATA` bounds the mapped anonymous memory this process
    // inherited from the harness across two forks, and every allocation above
    // is still in front of it. `RLIMIT_NOFILE` has to come after Landlock and
    // the mount tree, which each open a descriptor per rule and per target.
    // `RLIMIT_CPU` should count the caller's program rather than the
    // sandbox coming up. See `rlimits.apply`'s own doc comment, which states
    // the same three as its contract.
    //
    // It is also after `namespace.enter`, which A ran, and that is what makes
    // `RLIMIT_NPROC` usable at all: the fresh user namespace gives it a
    // counter of its own. See `rlimits.nproc_per_user_namespace_since`.
    //
    // The one step that comes after it is `execve` itself. `placeBrokerFd`
    // above is the only thing between here and the layers, and it is above
    // this for the reason its own comment gives: it needs descriptor numbers
    // and `RLIMIT_NOFILE` is what would refuse them.
    // **After every layer, and just before the resource limits.** The broker
    // socket is the one descriptor that must survive `execve`, so it is the
    // one whose close-on-exec flag comes off, and it comes off this late so
    // that no step of the setup path can read or write it and a sandbox that
    // failed to come up never hands a program a channel out.
    //
    // Before `rlimits.apply` and not after, because this step needs two spare
    // descriptor numbers and `RLIMIT_NOFILE` is what would refuse them. A
    // caller that set a very small descriptor limit would otherwise lose the
    // one channel the program was given, and would lose it to a limit that has
    // nothing to do with it.
    if (broker_fd >= 0) placeBrokerFd(broker_fd, &write_fd, stderr_fd);

    var limit_diag: ?rlimits.Diagnostic = null;
    rlimits.apply(config.limits, rlimits.runningKernel(), &limit_diag) catch |err|
        dieLimit(write_fd, stderr_fd, err, limit_diag);

    const exec_rc = linux.execve(argv_z[0].?, argv_z, env_z);
    // execve only returns on failure. Its errno has no Zig error mapping to
    // report through, so name it directly.
    dieErrno(write_fd, stderr_fd, .exec, "execve", linux.errno(exec_rc));
}

/// Put the broker socket on `netbroker.fd_number` and take its close-on-exec
/// flag off, so the program `execve` is about to start finds it there.
///
/// **A fixed number, and the same shape `Config.stdin_fd` already uses.** A
/// program does not have to be told which descriptor it landed on, and Chock
/// does not have to write one into the environment, where a project's own
/// `.env` could then overwrite it.
///
/// **The setup pipe is moved out of the way when it sits on that number.** It
/// is the only other descriptor above standard error that B still holds by
/// this point: `closeInheritedFds` closed everything else, Landlock and the
/// mount tree closed theirs, and `redirectStandardStreams` has already run.
/// Which number the pipe got is decided by the caller's own descriptor table,
/// so it really can be three, and a `dup2` onto it would take away the one
/// channel `dieErrno` reports an `execve` failure on.
///
/// `dup2` is what clears the flag: the kernel always gives the new descriptor
/// a clear `FD_CLOEXEC`, whatever the old one had. The one case that needs
/// `fcntl` is a socket that already sits on the right number.
fn placeBrokerFd(broker_fd: i32, write_fd: *i32, stderr_fd: i32) void {
    const target = netbroker.fd_number;

    if (write_fd.* == target) {
        // Anywhere above the target. `F_DUPFD_CLOEXEC` gives the lowest free
        // number at or above the one asked for, and the broker socket is not
        // free, so this can never land on it.
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
        // Already on the number, so only the flag has to come off.
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
    // The original is not needed again: the copy at `target` holds the socket,
    // and a second number naming the same socket would let a program close one
    // and believe the channel had gone.
    _ = linux.close(broker_fd);
}

/// Point this process's own standard input, standard output and standard
/// error at `config.stdin_fd`, `config.stdout_fd` and `config.stderr_fd`,
/// replacing whatever this process, B, inherited across both forks. Runs
/// first in `execute`, in B, right before the caller's program's own
/// `execve`: see `Config.stdout_fd`'s own doc comment for why a caller names
/// a descriptor here instead of `spawn`'s own caller juggling its real
/// standard streams by hand.
///
/// A no-op for a caller that left every field at its default: `dup2` with
/// equal old and new descriptors is a documented no-op, the same guard
/// `redirectStdinToDevNull` already relies on above, so this never touches
/// descriptor 1 or 2 unless a caller actually asked for something else
/// there, and a null `stdin_fd` leaves descriptor 0 as the `/dev/null` A
/// already put there.
///
/// **Standard input is replaced here, and nowhere earlier, on purpose.**
/// `redirectStdinToDevNull` runs in A before the first layer, so every step
/// of the setup path reads descriptor 0 as `/dev/null`, and a sandbox that
/// failed to come up hands the caller's pipe to nothing. Only the caller's
/// own program, past every layer, ever sees the descriptor named here.
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
        // `config.stderr_fd` is still open here, and still the only descriptor
        // that reaches where the caller asked: this is the call that puts it on
        // descriptor 2, and it is the one that just failed.
        if (dup2_errno != .SUCCESS)
            dieErrno(write_fd, config.stderr_fd, .exec, "dup2 onto standard error", dup2_errno);
    }

    // This process's own copy of each descriptor the caller named: every
    // standard stream now holds its own reference, from the dup2 calls above,
    // so the original is not needed again, and an open copy left past this
    // point would keep whatever it names, such as a caller's own pipe, from
    // ever reaching end of file on the caller's own read of it, even after
    // this process's own program exits.
    //
    // A descriptor at or below standard error is never closed here: it is one
    // of the three streams themselves. A descriptor a later entry names again
    // is closed once, which is the ordinary case of a caller that puts
    // standard output and standard error on one pipe.
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

/// Read the absolute path of an already open directory descriptor, through
/// /proc/self/fd. std.testing.tmpDir hands back a directory under
/// .zig-cache/tmp, reached only through a relative path, but Config.root must
/// be absolute: buildRoot bind mounts it and pivotInto calls pivot_root on
/// it, and both need a path that resolves the same way no matter what the
/// test binary's own working directory is.
fn absoluteDirPath(buffer: []u8, dir_fd: linux.fd_t) ![:0]u8 {
    var link_buffer: [64]u8 = undefined;
    const link = std.fmt.bufPrintZ(&link_buffer, "/proc/self/fd/{d}", .{dir_fd}) catch unreachable;
    const rc = linux.readlink(link, buffer.ptr, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.ReadlinkFailed;
    const len: usize = @intCast(rc);
    buffer[len] = 0;
    return buffer[0..len :0];
}

test "closeInheritedFds closes every descriptor above stderr, and leaves stderr open" {
    // Model a descriptor a long lived host process would still be holding at the
    // moment it forks a sandboxed child, the exact leak the design review found:
    // a descriptor opened before the sandbox is entered, still open and still
    // resolvable after pivot_root, because closing it is the only thing that
    // actually revokes it.
    const extra_a = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_a));
    const extra_b = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_b));
    defer _ = linux.close(@intCast(extra_a));
    defer _ = linux.close(@intCast(extra_b));

    // The check has to run in a forked child. closeInheritedFds ends the process
    // on any internal failure, and it would otherwise close this test binary's
    // own working descriptors, such as the one the test runner uses to report
    // results.
    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        // -1 stands in for the two pipes, the broker socket, and the
        // caller's own output descriptors, none of which this direct call
        // has: no real fd in this test process is ever -1, so none of those
        // exemptions in closeInheritedFds matches anything here, and the
        // test still pins the function's real behaviour. Null is
        // `Config.stdin_fd` for every tool call, which is the case this test
        // is about.
        closeInheritedFds(-1, -1, -1, -1, null, -1);

        // F_GETFD fails with EBADF on a closed descriptor, and succeeds on an
        // open one. This is the only way to observe the pass from outside the
        // child's own address space, so the child reports it through its exit
        // status instead of a Zig assertion.
        const a_result = linux.fcntl(@intCast(extra_a), linux.F.GETFD, 0);
        const b_result = linux.fcntl(@intCast(extra_b), linux.F.GETFD, 0);
        const stderr_result = linux.fcntl(std.posix.STDERR_FILENO, linux.F.GETFD, 0);
        const closed_the_extras = linux.errno(a_result) == .BADF and linux.errno(b_result) == .BADF;
        // Standard error must survive, or a real die() call could never report
        // the error name it is supposed to print.
        const kept_stderr = linux.errno(stderr_result) == .SUCCESS;
        std.process.exit(if (closed_the_extras and kept_stderr) 0 else 1);
    }

    var status: u32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}

test "closeInheritedFds keeps exactly the scratch pipe's write end, and no other" {
    // The scratch pipe is the one exemption this pass gained after it was
    // written, and the pass is what stops a directory descriptor opened before
    // the sandbox reaching the host tree by name after `pivot_root`. So the
    // exemption has to be exactly one number wide, the same as the one
    // `Config.stdin_fd` adds, and this is the test that says so.
    //
    // **The middle process really does need it kept**, and it was measured the
    // hard way: with this exemption absent, the scratch report was written to a
    // descriptor this pass had already closed, the write answered `EBADF`, and
    // a full scratch area came back as "something stopped the program" with no
    // limit named. Every other check still passed.
    //
    // Mutation check: drop `scratch_write_fd` from the guard and `extra_b` is
    // closed, which fails the second assertion. Widen the guard to keep
    // anything more, and `extra_a` survives and fails the first.
    const extra_a = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_a));
    const extra_b = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_b));
    defer _ = linux.close(@intCast(extra_a));
    defer _ = linux.close(@intCast(extra_b));

    // A forked child, for the reason the two tests around this one state: the
    // call ends the process on any internal failure and would otherwise close
    // the test runner's own descriptors.
    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        closeInheritedFds(-1, @intCast(extra_b), -1, -1, null, -1);

        const a_result = linux.fcntl(@intCast(extra_a), linux.F.GETFD, 0);
        const b_result = linux.fcntl(@intCast(extra_b), linux.F.GETFD, 0);
        const closed_the_other = linux.errno(a_result) == .BADF;
        const kept_the_scratch_pipe = linux.errno(b_result) == .SUCCESS;
        std.process.exit(if (closed_the_other and kept_the_scratch_pipe) 0 else 1);
    }

    var status: u32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}

test "closeInheritedFds keeps exactly the descriptor Config.stdin_fd names, and no other" {
    // The pass that closes every inherited descriptor is the one thing that
    // stops a directory descriptor opened before the sandbox from reaching the
    // host tree by name after pivot_root, so the exemption `Config.stdin_fd`
    // adds has to be exactly one number wide.
    //
    // Mutation check: widen the guard in closeInheritedFds to keep anything
    // beyond that one number, for example by skipping the whole pass when
    // `stdin_fd` is set, and `extra_a` stays open and this test fails. Drop
    // the exemption entirely and `extra_b` is closed and it fails the other
    // way, which is the fault that would break every helper.
    const extra_a = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_a));
    const extra_b = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_b));
    defer _ = linux.close(@intCast(extra_a));
    defer _ = linux.close(@intCast(extra_b));

    // A forked child, for the reason the test above states: this call ends the
    // process on any internal failure and would otherwise close the test
    // runner's own descriptors.
    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        closeInheritedFds(-1, -1, -1, -1, @intCast(extra_b), -1);

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
    // **The one branch of `placeBrokerFd` that a real run almost never
    // takes.** Which number the setup pipe got is decided by the caller's own
    // descriptor table, so it really can be `netbroker.fd_number`, and a
    // `dup2` onto it would take away the one channel `dieErrno` reports an
    // `execve` failure on. It is unreachable from `test/sandbox/escape.zig`,
    // whose probe holds enough descriptors that the pipe never lands there, so
    // it is driven directly here.
    //
    // Three facts, in a forked child because `placeBrokerFd` ends the process
    // on any failure, the same reason the three `closeInheritedFds` tests fork:
    // the broker socket really is at the number, its close-on-exec flag really
    // is off, and the setup pipe still works from wherever it moved to.
    const target = netbroker.fd_number;

    var pipe_fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&pipe_fds, .{})));
    defer _ = linux.close(pipe_fds[0]);
    defer _ = linux.close(pipe_fds[1]);

    // The token proves which socket landed on the number, rather than only
    // that some descriptor did.
    const pair = try netbroker.makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);
    const token = "the-broker-socket";
    try std.testing.expectEqual(token.len, linux.write(pair[0], token, token.len));

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        // Put the setup pipe exactly where the broker socket has to go, which
        // is the case this test exists for.
        if (linux.errno(linux.dup2(pipe_fds[1], target)) != .SUCCESS) std.process.exit(1);
        var write_fd: i32 = target;

        // Descriptor 2 for the diagnostics, which is what `execute` itself
        // passes at this point in a real run: `redirectStandardStreams` has
        // already put the caller's own descriptor there. Nothing is written on
        // it on the path this test takes.
        placeBrokerFd(pair[1], &write_fd, std.posix.STDERR_FILENO);

        // The socket is at the number, and it is the socket the test wrote
        // into.
        var buffer: [64]u8 = undefined;
        const read = linux.read(target, &buffer, buffer.len);
        if (linux.errno(read) != .SUCCESS or !std.mem.eql(u8, buffer[0..read], token)) std.process.exit(1);

        // Its close-on-exec flag is off, or the program `execve` starts would
        // not find it at all.
        const flags = linux.fcntl(target, linux.F.GETFD, 0);
        if (linux.errno(flags) != .SUCCESS or flags != 0) std.process.exit(1);

        // And the setup pipe still reaches the parent from wherever it went,
        // which is what makes an `execve` failure reportable.
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

    // The byte the child wrote really arrived here, so the moved pipe is the
    // same pipe and not a descriptor that merely accepted a write.
    var one: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), linux.read(pipe_fds[0], &one, 1));
    try std.testing.expectEqual(@as(u8, 'p'), one[0]);
}

test "a filtered config with nobody to ask is refused, and refused before anything is forked" {
    // **The fail closed rule for this whole mechanism.** A filtered config
    // with no broker used to be the stub: the caller asked for a channel out
    // and got a `.none` sandbox with no sign that anything was missing, and
    // a program inside it would spend its whole run failing at a socket that
    // was never there.
    //
    // The refusal comes before `probeAbi`, before the seccomp filter is built
    // and before any fork, so this test needs no root, no mount and no
    // program: every path that could make one is behind the check.
    //
    // Mutation check: drop either arm of the switch in `spawn` and one of the
    // two calls below comes back with something other than the error it names.
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

    // And the other way round: a broker on a config that is not filtered has
    // no socket to be asked anything on, so the field would read as a
    // permission that is never used. A refusal says so. Silence would not.
    const Never = struct {
        fn connect(ptr: *anyopaque, host: []const u8, port: u16) iface.NetBroker.Grant {
            _ = ptr;
            _ = host;
            _ = port;
            // Never reached: the two calls below refuse before they fork.
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

test "spawn reports the Landlock ABI and its features before it ever forks" {
    // spawn fills in landlock_report right after probeAbi succeeds, before the
    // fork, so this has to hold no matter what happens to the child afterward.
    // A missing binary as argv[0] is enough to prove that, with no need to
    // build a real sandboxed program: the child still runs every layer, and
    // still fails, but only once it tries to exec a path that is not there.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    var report: LandlockReport = undefined;

    // **A boundary that was never reached is not a boundary that held.** This
    // test builds a whole sandbox, so a machine that will not give one
    // measures nothing here. Asked in a child, which is the only way to ask
    // without spending this process's own one namespace: see
    // `namespace.probeAvailability`. The CI job named "Sandbox" runs this
    // suite on a machine that can host one and fails rather than skips.
    if (!namespace.probeAvailability().available()) return error.SkipZigTest;

    // The child's execve on /does-not-exist is meant to fail, and when it does it
    // prints "sandbox: execve failed: NOENT" to standard error. That line is correct,
    // not a bug, but left alone it reads as a failure to anyone watching a normal
    // test run. Point this process's own standard error at /dev/null for the call,
    // then put the real one back, so this expected message goes quiet without
    // touching what die() prints for every other test or for a real failure.
    const devnull_rc = linux.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(devnull_rc));
    const devnull: i32 = @intCast(devnull_rc);
    defer _ = linux.close(devnull);

    const saved_stderr_rc = linux.dup(std.posix.STDERR_FILENO);
    try std.testing.expectEqual(.SUCCESS, linux.errno(saved_stderr_rc));
    const saved_stderr: i32 = @intCast(saved_stderr_rc);
    defer _ = linux.close(saved_stderr);

    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.dup2(devnull, std.posix.STDERR_FILENO)));
    // Restored on every exit from here, whether spawn succeeds, fails, or this
    // returns early through the SkipZigTest path below.
    defer _ = linux.dup2(saved_stderr, std.posix.STDERR_FILENO);

    // Finding 1: a missing argv[0] fails execve, the very last step of setup,
    // before the caller's program ever runs. That is a setup failure now, not
    // a Term, so spawn must report it as error.ExecFailed rather than handing
    // back a fabricated exit status.
    const err = spawn(std.testing.allocator, .{
        .root = root_z,
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    }, &.{"/does-not-exist"}, &report, null);

    // **Standard error goes back before the first assertion, and not on the
    // way out.** With the restore left to the deferred call above, a failing
    // assertion here printed what it expected and what it found into
    // /dev/null, and the whole test read as "failed without output". Measured
    // on 2026-08-25: that is exactly what a CI run answered for this test, and
    // the one line that would have named the real cause was the line that went
    // nowhere.
    _ = linux.dup2(saved_stderr, std.posix.STDERR_FILENO);

    if (err) |_| {
        return error.TestUnexpectedResult;
    } else |actual_err| {
        // A kernel with no Landlock is a valid environment. Report and skip,
        // the same as every other Landlock probe test in this library.
        if (actual_err == error.LandlockUnavailable) return error.SkipZigTest;
        try std.testing.expectEqual(error.ExecFailed, actual_err);
    }

    try std.testing.expect(report.abi >= 1);
    try std.testing.expectEqual(landlock.featuresFor(report.abi), report.features);
}

test "regression: removeContentsBestEffort clears a tree too deep for an absolute path" {
    // Pins the bug a design review found: the old walk built an absolute path
    // for every entry, and a tree deep enough made that path exceed PATH_MAX,
    // so the walk stopped with ENAMETOOLONG and left everything below that
    // point on the host, 4098 directories in the review's own case. This
    // builds a tree past that same depth by descending with mkdirat and
    // openat, never holding a full path at all, the same shape the fix uses
    // to remove it.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    // Opened by path, as a descriptor of its own, separate from tmp.dir's own
    // handle: the loop below closes dir_fd as it descends, and tmp.dir.handle
    // must stay open and valid for tmp.cleanup() to close later.
    const root_rc = linux.open(root_z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(root_rc));
    var dir_fd: i32 = @intCast(root_rc);

    // 4100 levels is past the 4098 the design review's own attack leaked, and
    // well past what a PATH_MAX sized absolute path could ever reach with a
    // single character name at each level.
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
    // The tree must have reached full depth, or this test would pass by
    // accident without ever exercising the case it exists to pin.
    try std.testing.expectEqual(depth, built);

    removeContentsBestEffort(std.testing.allocator, root_z);

    // The direct proof: the root is still there, and there is nothing left
    // in it. A walk that stopped partway down, the old ENAMETOOLONG failure
    // or a native stack overflow either one, leaves the first "d" behind and
    // fails the second half.
    const reopen_rc = linux.open(root_z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(reopen_rc));
    const reopened: i32 = @intCast(reopen_rc);
    defer _ = linux.close(reopened);
    try std.testing.expect(isEmptyDirectory(reopened));
}

/// True when the directory `dir_fd` names holds nothing but `.` and `..`.
/// Reads with `getdents64` directly, the same way the walk above does, so a
/// test asserting "nothing is left" needs no `std.Io` in a file that has
/// none.
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
    // **The fault this whole diagnostic exists for, driven end to end.** Before
    // it, `enterNamespaces` called plain `die`, so a machine that would not
    // give a user namespace answered `error.NamespaceFailed` with errno 0 over
    // the setup pipe and one word on a descriptor a caller that is not a
    // terminal never reads. Measured on 2026-08-25: two CI architectures
    // answered `MapFailed` and `NamespaceFailed` and nobody could say whether
    // it was `max_user_namespaces`, a nesting depth, or a capability, because
    // the errno was thrown away at the one place that had it.
    //
    // **The refusal is made rather than waited for.** This machine gives a
    // user namespace, so the only way to see the path a machine that refuses
    // one takes is to make `unshare` answer `EPERM`, which a seccomp filter
    // does exactly. The filter is permanent and inherited, so it goes on a
    // child of this test and never on the test runner itself.
    //
    // Mutation check: put `die` back in `enterNamespaces` in place of
    // `dieNamespace` and the line below arrives as "sandbox: NamespaceFailed",
    // which fails the comparison.
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
        // 3: the filter would not go on, so nothing below was ever asked.
        var insns = [_]bpf.Insn{
            bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr),
            bpf.jump(bpf.JMP_JEQ_K, @intFromEnum(linux.SYS.unshare), 0, 1),
            bpf.stmt(bpf.RET_K, seccomp.RET_ERRNO_PERM),
            bpf.stmt(bpf.RET_K, seccomp.RET_ALLOW),
        };
        seccomp.install(bpf.Prog.init(&insns)) catch std.process.exit(3);

        // **The page allocator, and never the test's own.** This is a forked
        // child of a test binary with more than one thread.
        const err = spawn(std.heap.page_allocator, .{
            .root = root_z,
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
            // Where the child's own line goes, which is the half of this a
            // caller that is not a terminal used to lose.
            .stderr_fd = fds[1],
        }, &.{"/does-not-exist"}, null, null);
        if (err) |_| {
            std.process.exit(1);
        } else |actual| {
            // 4: a kernel with no Landlock at all, which is a machine this
            // test cannot ask its question on.
            if (actual == error.LandlockUnavailable) std.process.exit(4);
            // 2: the sandbox failed somewhere else, so the line below is not
            // the one this test is about.
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
    // A machine with no seccomp and a machine with no Landlock are both
    // environments rather than faults, and neither one can be asked this
    // question at all.
    if (code == 3 or code == 4) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), code);

    // **The whole point.** Not "the sandbox would not start", but which call
    // the kernel refused and what it answered.
    try std.testing.expectEqualStrings(
        "sandbox: the unshare that makes the namespaces failed: PERM\n",
        text[0..filled],
    );
}

test "a landlock errno travels the setup pipe, and is not lost with the layer" {
    // **The point of the whole change, on the hardest path this project
    // has.** Before it, `Ruleset.restrictSelf` printed its errno to the
    // terminal of a sandboxed child, through `std.debug.print`, which takes a
    // global lock this child may have inherited as held for ever from a
    // thread the fork left behind. The caller was handed
    // `error.LandlockRestrictFailed` and nothing else, and a caller that is
    // not a terminal saw nothing at all.
    //
    // `SetupFailureRecord` always had the field for this. `dieLandlock` is
    // what finally fills it, and this pins that the value arrives.
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{})));
    const read_fd = fds[0];
    const write_fd = fds[1];
    defer _ = linux.close(read_fd);

    reportSetupFailure(write_fd, .landlock_restrict, @intFromEnum(linux.E.PERM));
    // Closed here and not with a defer: `readSetupReport` reads to the end of
    // the pipe, which needs every write end shut.
    _ = linux.close(write_fd);

    const record = (try readSetupReport(read_fd)).?;
    try std.testing.expectEqual(@intFromEnum(SetupStep.landlock_restrict), record.step);
    try std.testing.expectEqual(@as(i32, @intFromEnum(linux.E.PERM)), record.errno);

    // And the step still maps to the error the caller matches on, so carrying
    // the errno took nothing away.
    try std.testing.expectEqual(
        @as(SetupError, error.LandlockRestrictFailed),
        setupErrorFor(.landlock_restrict),
    );
}

test "a handle answers Gone once the process it names has been reaped" {
    // **The fault this whole mechanism exists for.** A pid that has been
    // reaped names nothing, and the kernel gives the number to whatever starts
    // next, so a cancel that arrives a moment late reaches a stranger.
    // Measured on 2026-08-22: a teardown path that signalled the number
    // unconditionally sent SIGKILL to the process group of an unrelated build.
    //
    // A handle cannot do that. It names one task, and once that task is reaped
    // there is nothing left for it to name, which is the `Gone` below.
    //
    // Mutation check: map SRCH to success in `signalMiddle` and a caller
    // believes it cancelled a call it did not. Drop the `fd < 0` guard and a
    // handle nobody opened turns into a syscall on descriptor -1.
    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);
    if (pid == 0) {
        // Long enough that the parent below is certainly the one that ends it.
        _ = linux.nanosleep(&.{ .sec = 30, .nsec = 0 }, null);
        std.process.exit(0);
    }

    var middle: iface.Middle = .{ .pid = pid };
    const pidfd_rc = linux.pidfd_open(pid, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(pidfd_rc));
    middle.fd = @intCast(pidfd_rc);

    // Close on exec, which `spawn`'s own comment beside `pidfd_open` claims
    // and which the kernel sets for every pidfd. Measured here rather than
    // trusted: without it, an unrelated `execve` anywhere in a caller's
    // process would inherit a descriptor that kills a running tool call.
    const fd_flags = linux.fcntl(middle.fd, linux.F.GETFD, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(fd_flags));
    try std.testing.expect((fd_flags & linux.FD_CLOEXEC) != 0);

    // While it is alive the handle reaches it, and this is what kills the
    // child: nothing else in this test does.
    try signalMiddle(middle.fd, std.posix.SIG.KILL);

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFSIGNALED(status));
    try std.testing.expectEqual(std.posix.SIG.KILL, linux.W.TERMSIG(status));

    // And now the number is free. The handle is not: it survived the reap,
    // which is the whole reason the caller of `spawn` owns it and `spawn`
    // does not close it.
    try std.testing.expectError(error.Gone, signalMiddle(middle.fd, std.posix.SIG.KILL));

    closeMiddle(&middle);
    try std.testing.expectEqual(@as(std.posix.fd_t, -1), middle.fd);
    // A handle that was given up is not a descriptor to signal, and a second
    // close is not a close of whatever opened that number in between.
    try std.testing.expectError(error.NoHandle, signalMiddle(middle.fd, std.posix.SIG.KILL));
    closeMiddle(&middle);
}

test "a reaped number really does name somebody else, and the handle still reaches nobody" {
    // **The other half, and the one that cannot be argued with.** The test
    // above proves the handle answers `Gone`. This one proves the number does
    // not: it makes the kernel hand the same pid out twice, on purpose, and
    // then asks each of the two ways to name that process what it reaches.
    //
    // The recycle is forced rather than waited for. Pids are handed out in
    // order, so waiting for one to come round again on the host means millions
    // of forks. Inside a pid namespace of its own the numbers start at 1, and
    // `ns_last_pid` sets where the next one comes from, so process 1 of that
    // namespace can put the counter back and get the number a second time.
    // That is a namespace this process made, so nothing outside it is touched.
    //
    // All of it runs in a forked child, for two reasons: `unshare` of a user
    // namespace needs a single threaded caller, and a namespace this test
    // runner joined would outlive the test.
    //
    // Mutation check: signal `middle.pid` with `kill` instead of `middle.fd`
    // with `signalMiddle` and the innocent process below dies, which is
    // exactly the 2026-08-22 incident in miniature.
    //
    // **A machine whose user namespace carries no capability measures nothing
    // here.** The child below needs `CAP_SYS_ADMIN` over the pid namespace it
    // just made to put the counter back, and a namespace made under Ubuntu's
    // `kernel.apparmor_restrict_unprivileged_userns` carries no capability at
    // all: measured on 2026-08-25, that child answered 26, a refused write to
    // `ns_last_pid`, on both CI architectures. The probe asks the same
    // question in the same shape, through the id map write, and skipping on
    // it keeps that answer from reading as this mechanism failing.
    if (!namespace.probeAvailability().available()) return error.SkipZigTest;

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const outer: linux.pid_t = @intCast(fork_rc);

    if (outer == 0) {
        // 20: this machine does not allow an unprivileged user namespace, so
        // there is no way to make a pid namespace and nothing to measure.
        if (linux.errno(linux.unshare(linux.CLONE.NEWUSER | linux.CLONE.NEWPID)) != .SUCCESS) {
            std.process.exit(20);
        }

        // `unshare` never moves the caller into the pid namespace it made.
        // Only a child forked afterward lands there, as its process 1, and
        // only that process can put its own namespace's counter back.
        const init_rc = linux.fork();
        if (linux.errno(init_rc) != .SUCCESS) std.process.exit(21);
        const init_pid: linux.pid_t = @intCast(init_rc);

        if (init_pid == 0) {
            const first_rc = linux.fork();
            if (linux.errno(first_rc) != .SUCCESS) std.process.exit(22);
            const first: linux.pid_t = @intCast(first_rc);
            if (first == 0) std.process.exit(0);

            // Opened while it is alive, which is the only time a handle can be
            // opened at all, and the same instant `spawn` opens its own.
            const handle_rc = linux.pidfd_open(first, 0);
            if (linux.errno(handle_rc) != .SUCCESS) std.process.exit(23);
            const handle: i32 = @intCast(handle_rc);

            var status: u32 = undefined;
            var wait_rc = linux.waitpid(first, &status, 0);
            while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(first, &status, 0);
            if (linux.errno(wait_rc) != .SUCCESS) std.process.exit(24);

            // The next pid handed out is this value plus one, so writing the
            // number below the one just freed asks for that same number back.
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
                // The innocent process. Long enough that anything that reached
                // it would show up below as a death rather than an exit.
                _ = linux.nanosleep(&.{ .sec = 30, .nsec = 0 }, null);
                std.process.exit(0);
            }
            // 28: the counter did not give the number back, so there is no
            // stranger holding it and nothing here to measure.
            if (second != first) {
                _ = linux.kill(second, .KILL);
                _ = linux.waitpid(second, &status, 0);
                std.process.exit(28);
            }

            // The number now names a live process this test did not mean to
            // touch. `kill(pid, 0)` sends nothing and only asks.
            if (linux.errno(linux.kill(first, @as(std.posix.SIG, @enumFromInt(0)))) != .SUCCESS) {
                std.process.exit(29);
            }

            // The handle, fired with the worst signal there is, at the moment
            // a caller's cancel would arrive too late.
            if (signalMiddle(handle, std.posix.SIG.KILL)) |_| {
                // 30: it reported that it signalled something. There is
                // nothing left for it to signal, so a caller told this would
                // believe it had cancelled a call that ended long ago.
                std.process.exit(30);
            } else |err| {
                // 31: anything but `Gone` means the handle did not answer the
                // way the whole mechanism claims it does.
                if (err != error.Gone) std.process.exit(31);
            }

            // The proof: the stranger is untouched. A signal by number would
            // have killed it outright, and `WNOHANG` reporting nothing is that
            // process still running.
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
    // A machine with no unprivileged user namespace, and one whose counter
    // would not give the number back, are both environments rather than
    // faults. Every other code is a real failure and names its own step.
    if (code == 20 or code == 28) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u8, 0), code);
}

test "a supplied cgroup the kernel refuses is reported by name, and nothing is forked" {
    // **Refuse, never degrade, driven through the real `spawn`.** A caller
    // that hands over a cgroup asked for the child to be created inside it.
    // When the kernel says no, the only remaining way in is the write after
    // the fork, which is exactly the window the placement exists to close. So
    // `spawn` reports it and starts nothing.
    //
    // **A descriptor that is not a cgroup v2 directory is a world where the
    // placement cannot work, and it needs no cgroup tree to build.** So this
    // runs on a machine with no `/sys/fs/cgroup` at all, which is what a Nix
    // build sandbox is.
    //
    // Mutation check: fall back to `linux.fork()` for a `.supplied` config
    // that the kernel refused, and this comes back as `error.ExecFailed` from
    // a child that really ran, with a `Middle` that names it.
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

    // A descriptor that names the wrong kind of thing, and a descriptor that
    // names nothing at all. Both are refusals a real caller can produce, and
    // neither may end with a program running outside the cgroup it asked for.
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
            // A kernel with no Landlock is a valid environment, and `spawn`
            // probes that before it reaches the fork. The same skip every
            // other Landlock test in this library takes.
            if (actual == error.LandlockUnavailable) return error.SkipZigTest;
            try std.testing.expectEqual(error.CgroupPlacementRefused, actual);
        }

        // **Nothing was created**, which is the half a returned error alone
        // does not prove. `Middle.pid` is written straight after the fork
        // succeeds, so a zero here says the fork never happened, and there is
        // no handle either.
        try std.testing.expectEqual(@as(std.posix.pid_t, 0), middle.pid);
        try std.testing.expectEqual(@as(std.posix.fd_t, -1), middle.fd);
    }
}

/// The cgroup a `spawn` test supplies, and the sibling the caller of that
/// `spawn` sits in. Both are made directly under the ancestor that delegates
/// the controllers, so each one has its own `pids.max` and neither needs
/// `cgroup.subtree_control` written anywhere.
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

/// The `memory.max` a test writes into the cgroup it supplies. **Not one of
/// `rlimits.Limits`' own defaults**, and not a round number a caller would
/// pick: the check afterwards is that this exact value is still there, so a
/// number chock might also have written would prove nothing.
const supplied_memory_max = "100663296";

/// The `pids.max` a test writes into the cgroup it supplies. Large enough for
/// the two processes `spawn` makes and everything they start, and different
/// from `rlimits.default_processes`, for the same reason as above.
const supplied_pids_max = "97";

test "spawn puts the sandboxed program in the caller's own cgroup at creation, and writes nothing into it" {
    // **The end to end half of the placement, with the same discriminator the
    // mechanism test in `cgroup.zig` uses.** A test that only reads the
    // child's membership afterwards cannot tell `CLONE_INTO_CGROUP` from a
    // write to `cgroup.procs` after the fork: both end with the child in the
    // right place. The kernel's own `pids` accounting can. It charges a new
    // task to the **destination** cgroup when the clone names one, and to the
    // **current** cgroup when it does not, so a process whose own cgroup has
    // no room left cannot fork at all and can still clone into one that has.
    //
    // So the child below tightens its own cgroup to exactly its current count
    // and then calls `spawn` twice:
    //
    // * `.best_effort`, which forks, and must fail because that child would
    //   have been charged to the cgroup the caller is in. This is the window
    //   the design forbids, measured rather than argued.
    // * `.supplied`, which clones into the cgroup the test made, and must
    //   build the whole sandbox and reach `execve`.
    //
    // Mutation check: read the `.supplied` arm of `spawn`'s own fork as
    // `linux.fork()` and the second call comes back `error.Unexpected`, which
    // is exit code 3 below. Make chock write its own limits into a supplied
    // cgroup and the two file comparisons at the end fail.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // **Asked before anything is tightened, because asking forks.** A machine
    // that will not give a user namespace cannot build a sandbox at all, so
    // the `.supplied` call would fail for a reason that has nothing to do with
    // a cgroup.
    if (!namespace.probeAvailability().available()) return error.SkipZigTest;

    var pair = TestCgroupPair{};
    if (!makeTestCgroupPair(&pair)) return error.SkipZigTest;
    defer removeTestCgroup(pair.parent());
    defer removeTestCgroup(pair.target());

    // **The caller writes the limits, and chock must leave them alone.** These
    // exact strings are read back at the end of this test.
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

    // **Everything below runs in a forked child.** It moves *itself* into a
    // cgroup this test made and tightens *that* cgroup, so this process keeps
    // its own cgroup and its own ability to fork whatever happens.
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
    // 10: this machine would not let the child into a cgroup of its own or
    // would not let it write `pids.max`. 11: no Landlock, so no sandbox was
    // ever built. Both are environments and neither is a measurement.
    if (code == 10 or code == 11) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), code);

    // **And the caller's numbers are the caller's own, still.** Chock's
    // defaults are a different memory ceiling and a different process count,
    // so a chock that wrote into this cgroup would leave one of these two
    // lines reading its number instead of the test's.
    var buffer: [4096]u8 = undefined;
    try std.testing.expectEqualStrings(
        supplied_memory_max,
        readTestCgroupFile(pair.target(), "memory.max", &buffer) orelse return error.SkipZigTest,
    );
    try std.testing.expectEqualStrings(
        supplied_pids_max,
        readTestCgroupFile(pair.target(), "pids.max", &buffer) orelse return error.SkipZigTest,
    );
    // `memory.swap.max` is the third file chock writes for a cgroup of its
    // own, and it writes `0` there. A fresh cgroup reads `max`, so this line
    // catches a write the two above would miss.
    try std.testing.expectEqualStrings(
        "max",
        readTestCgroupFile(pair.target(), "memory.swap.max", &buffer) orelse return error.SkipZigTest,
    );
}

/// The whole measurement, in the forked child that owns it. Answers the exit
/// code the test above reads. Never returns a value the caller has to
/// interpret twice: 0 is the measurement, 10 and 11 are environments, and
/// every other code names the assertion that did not hold.
fn measureSuppliedPlacement(
    pair: *const TestCgroupPair,
    target_fd: i32,
    root_z: [:0]const u8,
) u8 {
    // This process into the sibling cgroup, and that cgroup with no room for
    // one more process.
    if (!writeTestCgroupFile(pair.parent(), "cgroup.procs", "0")) return 10;
    var buffer: [4096]u8 = undefined;
    const current = readTestCgroupFile(pair.parent(), "pids.current", &buffer) orelse return 10;
    if (!writeTestCgroupFile(pair.parent(), "pids.max", current)) return 10;

    // **The sandbox's own diagnostics go to /dev/null.** `execve` on a path
    // that is not there is the expected end of the second call, and the child
    // says so on this descriptor. `build.zig` fails a test binary that writes
    // one byte to standard error.
    const devnull_rc = linux.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
    if (linux.errno(devnull_rc) != .SUCCESS) return 10;
    const devnull: i32 = @intCast(devnull_rc);

    // **The page allocator, and never the test's own.** This is a forked child
    // of a test binary, and the testing allocator's own bookkeeping belongs to
    // the process this one was copied from.
    const base = Config{
        .root = root_z,
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .stderr_fd = devnull,
    };

    // The window, measured. A fork from here is charged to this process's own
    // cgroup, which is full, so the call cannot even make its first process.
    const best_effort = base;
    if (spawn(std.heap.page_allocator, best_effort, &.{"/does-not-exist"}, null, null)) |_| {
        return 2;
    } else |err| {
        if (err == error.LandlockUnavailable) return 11;
        if (err != error.Unexpected) return 2;
    }

    // The placement, in exactly the same conditions. The only thing that
    // changed is which cgroup the kernel charges the new process to.
    var report: LimitsReport = undefined;
    var supplied = base;
    supplied.containment = .{ .supplied = .{ .fd = target_fd } };
    supplied.limits_report = &report;
    if (spawn(std.heap.page_allocator, supplied, &.{"/does-not-exist"}, null, null)) |_| {
        return 3;
    } else |err| {
        if (err == error.LandlockUnavailable) return 11;
        // `ExecFailed` is the last step of the setup, so every layer before
        // it came up. Anything else means the sandbox stopped earlier and
        // this proves nothing about the placement.
        if (err != error.ExecFailed) return 3;
    }

    // **And the report says who wrote the limits.** `ok` would claim chock
    // applied a memory bound it never wrote, and `off` would claim nothing
    // bounds the program at all.
    if (report.cgroup != .supplied) return 4;
    // Nothing was counted, because nothing of chock's own was there to count.
    if (report.events.oom_kills != 0 or report.events.fork_refusals != 0) return 5;

    return 0;
}

/// Make the two cgroups the placement test needs, under the ancestor that
/// delegates the controllers. False when this machine has no such ancestor,
/// which is a machine the test skips on.
fn makeTestCgroupPair(pair: *TestCgroupPair) bool {
    // The library's own walk, rather than a second one written here: a test
    // that made its cgroup somewhere else would not be testing the place a
    // real call uses. `create` makes one, and its path names the ancestor.
    var probe = cgroup.Cgroup.create(1 << 30, 64, 0xC10E0);
    defer probe.destroy();
    if (!probe.support.applied()) return false;

    const ancestor = std.fs.path.dirname(probe.path()) orelse return false;

    // The name carries this process's own live pid, the shape
    // `cgroup.sweepStaleSiblings` reads, so a sweep in another chock process
    // reads the maker as alive and leaves these alone, and a run that dies
    // before its cleanup leaves directories a later sweep removes by itself.
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

/// Remove a cgroup this test made, once the kernel has finished accounting the
/// exits of what was in it. **A retry and not one call**: `rmdir` on a cgroup
/// answers `EBUSY` until the last exit is counted, which is a gap
/// `cgroup.zig`'s own `remove_pause_ns` has the measurement for.
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

    // A cgroup control file takes the whole value in one write, so a short
    // write is a refusal and never something to continue from.
    const rc = linux.write(fd, contents.ptr, contents.len);
    return linux.errno(rc) == .SUCCESS and rc == contents.len;
}

/// One cgroup control file, with the trailing newline the kernel writes taken
/// off, so a caller compares the value and not the formatting.
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
