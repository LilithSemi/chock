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
fn seccompOptionsFor(
    base: seccomp.Options,
    network: namespace.Network,
    hands_host_descriptor: bool,
) seccomp.Options {
    var options = base;
    options.block_connect = switch (network) {
        // Nothing is added for either of these. **`.none` gets exactly the
        // filter the caller asked for**, so a unix socket client inside an
        // ordinary tool call still works: that is the approval socket and the
        // git shim.
        .none, .host => false,
        // **Keyed on the descriptor and not on the mode, and that is the whole
        // rule.** The refusal exists for one reason: a connected descriptor
        // made in the host's own network namespace really can be aimed
        // somewhere else with `connect`, so a process that is handed one must
        // not be able to make the call. `net_broker` hands one over.
        // `net_router` never does: the descriptor the router receives stays in
        // the router, which is a process of Chock's own that never runs the
        // caller's program.
        //
        // **A routed call must be able to connect, or it has no network.** The
        // whole point of the router is that an ordinary program that knows
        // nothing about Chock calls `connect` and reaches a permitted host,
        // with the kernel refusing everything else. Refusing the call here
        // would leave that program exactly where it was before the router
        // existed. See `iface.Config.net_router`, and `spawn`, which refuses a
        // config that names both seams for this reason.
        .filtered => hands_host_descriptor,
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
    // fails. Answer `false` for a filtered call that hands a descriptor and
    // the third fails.
    try std.testing.expectEqual(false, seccompOptionsFor(.{}, .none, true).block_connect);
    try std.testing.expectEqual(false, seccompOptionsFor(.{}, .host, true).block_connect);
    try std.testing.expectEqual(true, seccompOptionsFor(.{}, .filtered, true).block_connect);

    // **And a routed call keeps `connect`.** This is the line the whole router
    // rests on: the sandboxed program reaches a permitted host by calling
    // `connect` and letting the kernel's own ruleset judge the address. A
    // filter that refused the call would leave that program with no network at
    // all, and every escape test that says a permitted host is reachable would
    // then be measuring the refusal instead.
    //
    // Mutation check: answer `true` for a routed filtered call and this line
    // fails, together with every escape test that reaches a permitted host.
    try std.testing.expectEqual(false, seccompOptionsFor(.{}, .filtered, false).block_connect);

    // A caller that turned the write and execute rule off keeps it off in
    // every mode. This function adds one thing and must take nothing.
    for (std.enums.values(namespace.Network)) |network| {
        for ([_]bool{ false, true }) |hands| {
            const relaxed = seccompOptionsFor(.{ .strict_wx = false }, network, hands);
            try std.testing.expectEqual(false, relaxed.strict_wx);
        }
    }

    // **And a caller cannot ask for `block_connect` on a mode that does not
    // take it.** The driver decides this one field, so a `.none` config that
    // named it would otherwise get a filter no test in this project covers.
    try std.testing.expectEqual(
        false,
        seccompOptionsFor(.{ .block_connect = true }, .none, true).block_connect,
    );
    // The same for a routed call, which is the other mode that now answers
    // `false`: a caller must not be able to put the refusal back on and take
    // the router's own network away.
    try std.testing.expectEqual(
        false,
        seccompOptionsFor(.{ .block_connect = true }, .filtered, false).block_connect,
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
    // Mutation check: build the second filter with `.filtered` and `true` and
    // the two differ by exactly the two instructions the connect rule adds.
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
/// sandboxed program directly. The handle does not depend on a pid number
/// that can be reused. Its death takes the sandboxed program down with it.
/// See `waitAndRelay` for the relay and `armPdeathsig` for the parent link.
///
/// **One signal to that one process ends every process of the call, and the
/// pid namespace is why.** `signalMiddle` has no group form, so this reaches
/// only the middle process. That is enough. The middle process dies. The
/// sandboxed program and the keeper each get `PR_SET_PDEATHSIG`. The keeper's
/// death then clears every process left in the pid namespace.
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
        .filtered => {
            if (config.net_broker == null and config.net_router == null)
                return error.NetBrokerMissing;
            // **Both at once is refused rather than ranked.** The two want
            // opposite things from one seccomp rule: the broker needs
            // `connect` refused, because it hands a descriptor from the host's
            // own network namespace across the boundary, and the router needs
            // `connect` permitted, because a program reaching a permitted host
            // is the whole mechanism. A driver that quietly picked one would
            // give the other a sandbox that does not do what its field says.
            // See `seccompOptionsFor`.
            if (config.net_broker != null and config.net_router != null)
                return error.NetRouterAndBroker;
        },
        .none, .host => {
            if (config.net_broker != null) return error.NetBrokerNotFiltered;
            if (config.net_router != null) return error.NetRouterNotFiltered;
        },
    }

    // **A device source with no device tree is refused here, before anything
    // forks, the same as a filtered network with no broker above.**
    // `placeDevice` resolves a placement's own `source` against
    // `Config.device_tree.host`, which the device helper binds into the
    // sandbox's own root before anything pivots: see `runDevice`'s own
    // `bindDeviceTree`. Without this refusal, the config only found out once
    // a real device arrived, as a `MountFailed` this deep into a session,
    // with nothing in the error naming the field that was missing. See
    // `Config.device_source`, `Config.device_tree`, and
    // `SpawnError.DeviceSourceNeedsTree`.
    if (config.device_source != null and config.device_tree == null)
        return error.DeviceSourceNeedsTree;

    // Whether this call gets a network of its own with a ruleset on it. Read
    // in A, in B and in the parent below, so the three cannot disagree.
    const routed = config.net_router != null;

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
    // the caller.** A process the netbroker serves is handed a connected
    // descriptor, and a connected descriptor really can be aimed somewhere
    // else with `connect`, so `connect` is refused for exactly that case. See
    // `seccomp.Options.block_connect` for the measurement.
    //
    // **A routed call is the other case and keeps `connect`**, because the
    // kernel's own ruleset is what judges the address and the program has to
    // be able to make the call at all. `!routed` is what says so: see
    // `seccompOptionsFor`, and the refusal above of a config that names both
    // seams.
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
    const seccomp_options = seccompOptionsFor(config.seccomp_options, config.network, !routed);

    // Built here, in the parent, before the fork. The filter depends only on
    // `config.seccomp_options` and `config.network`, never on anything the
    // child alone knows, so building it before the fork is free: `fork` copies
    // this process's whole address space, so the child can read these same
    // instructions without any allocation or IPC of its own, and one less
    // allocating step runs between the fork and the exec. See the thread
    // safety note above.
    // **The supervisor never gets the trap instructions, and never can.** A
    // filter that returns `RET_USER_NOTIF` with no listener behind it makes
    // the kernel answer the call with `ENOSYS`, so A would be told that
    // `openat` does not exist on this machine. Only B installs its filter with
    // a listener, so only B can carry a trap set. See `seccomp.Options.traps`.
    var middle_options = seccomp_options;
    middle_options.traps = .initEmpty();
    const insns = seccomp.build(allocator, middle_options) catch |err| return err;
    defer allocator.free(insns);

    // The second program, for B. Identical to A's when nothing is observed, so
    // the ordinary call allocates once and not twice.
    const watching = seccomp_options.traps.count() != 0;
    const child_insns = if (watching)
        seccomp.build(allocator, seccomp_options) catch |err| return err
    else
        insns;
    defer if (watching) allocator.free(child_insns);

    // The third program, for R, the path reader. **Built here for the reason
    // the other two are**: a fork of a process with more than one thread may
    // find the allocator's own lock held by a thread that no longer exists,
    // and R is forked from A. See the thread safety note above.
    //
    // **A path audit with no trap set records nothing**, because a path is
    // read out of a call the kernel is holding. The two are asked for apart,
    // so the config that asks for one and not the other is honest about
    // getting nothing rather than being refused.
    const recording = watching and config.path_audit;
    const reader_insns = if (recording)
        seccomp.buildReader(allocator) catch |err| return err
    else
        &[_]bpf.Insn{};
    defer if (recording) allocator.free(reader_insns);

    // The fourth program, for N, the network router. **Built here for the
    // reason the three above are**, and N is forked from A as R is.
    const router_insns = if (routed)
        seccomp.buildRouter(allocator) catch |err| return err
    else
        &[_]bpf.Insn{};
    defer if (routed) allocator.free(router_insns);

    // The fifth program, for D, the device helper. **Built here for the
    // reason the three above are**, and D is forked from A as N is. Read
    // once, here, whether a device source was named at all: a session with
    // none must not pay for this build, and every later branch that asks the
    // same question reads this same value, so they cannot disagree.
    const wants_device = config.device_source != null;
    const device_insns = if (wants_device)
        seccomp.buildDevice(allocator) catch |err| return err
    else
        &[_]bpf.Insn{};
    defer if (wants_device) allocator.free(device_insns);

    // The keeper is always present, so its filter is built before any fork.
    // The keeper holds process 1 in the pid namespace and reaps orphans.
    const keeper_insns = seccomp.buildKeeper(allocator) catch |err| return err;
    defer allocator.free(keeper_insns);

    // **The boundary R splits paths on, built here for the reason the three
    // programs above are**, and before any fork for the same reason again.
    //
    // R cannot open a file: `seccomp.reader_calls` names no `openat`. It does
    // not have to. R is a fork of A and A is a fork of this process, and a
    // fork copies the whole address space, so this list is at the same address
    // in R the moment R starts. The strings it points at are the caller's own,
    // alive for the whole of this call. This is how the workspace this
    // replaces already reached R.
    //
    // **Not the shared page.** B inherits that mapping and gives it up in
    // `applyLayers`, so a boundary written there would be memory the observed
    // program's own process once held. This copy is private to R.
    //
    // See `iface.grantPrefixes` for what is in the set and what is not.
    const granted: []const []const u8 = if (recording)
        iface.grantPrefixes(allocator, config) catch |err| return err
    else
        &.{};
    defer if (recording) allocator.free(granted);

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

    // The middle pipe, and a second pipe rather than more records on the
    // setup pipe. **The setup pipe answers "did the sandbox come up", and this
    // process learns that answer as soon as `execve` closes the child's copy,
    // not whenever the program eventually finishes.** A writer that stayed open
    // past `execve` would hold that read open for the whole call, and the
    // comment on A's own `close(write_fd)` below is the record of why that
    // matters. So every fact A has to give back *after* the setup pipe is
    // closed travels a channel of its own, which this process reads after
    // `waitpid` has already returned.
    //
    // Two facts travel it today: whether a scratch area was full, which is
    // only knowable once the program has ended, and whether A could put a
    // seccomp filter on itself, which happens after A has already closed its
    // own end of the setup pipe. See `MiddleReport` for the record format and
    // `restrictMiddle` for the second fact.
    var middle_pipe: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&middle_pipe, .{ .CLOEXEC = true })) != .SUCCESS) {
        _ = linux.close(read_fd);
        _ = linux.close(write_fd);
        return error.Unexpected;
    }
    const middle_read_fd = middle_pipe[0];
    const middle_write_fd = middle_pipe[1];

    // The broker pair, for a filtered call and for no other. `[0]` stays in
    // this process and is what the serve loop below reads. `[1]` crosses into
    // the sandbox and becomes the one channel out that the network namespace
    // does not close. Both ends are close-on-exec: `execute` clears the flag
    // on the child's end in the last step before `execve`, so a sandbox that
    // failed to come up never hands a program a channel out.
    var broker_fds: [2]i32 = .{ -1, -1 };
    // The router's own pair, for a routed call and for no other. `[0]` stays
    // in this process and `[1]` goes to A, which hands it to the router and
    // keeps no copy. **Never placed on a descriptor number the caller's
    // program can see**, unlike the broker's: the router is a process of
    // Chock's own and the program it serves never learns it exists.
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

    // The device link's own pair, for a session that names `device_source` and
    // for no other. **Exclusive with neither of the two above**: a hardware
    // session may want a network and a device at once, so this is made
    // whenever `wants_device` is true, whatever `routed` or `config.net_broker`
    // say. `[0]` stays in this process, the same as the broker's and the
    // router's own `[0]`, and this process never reads from it: see
    // `serveLinks`'s own comment on why it only ever writes here.
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

    // The page the path reader writes and this process reads. It is shared
    // memory so the reader can report without a write capable descriptor.
    //
    // **Made before the fork on purpose, and given up by B before B applies a
    // single layer.** B inherits it, and B is this project's own code until
    // its own `execve`, which would replace the whole address space in any
    // case. So the observed program never holds a mapping it could write a
    // forged count into. See `applyLayers`.
    const path_record: ?*notify.PathRecord = if (recording) mapPathRecord() else null;
    defer if (path_record) |record| unmapPathRecord(record);

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
        _ = linux.close(middle_read_fd);
        _ = linux.close(middle_write_fd);
        closeBrokerPair(&broker_fds);
        closeBrokerPair(&router_fds);
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
        _ = linux.close(middle_read_fd);
        // The parent's own end of the broker pair. **Nothing on this side of
        // the boundary may keep it**: a copy held here would be a second
        // reader of the requests, and it would also mean that a sandboxed
        // process could write a request that this process answers with the
        // parent's own end still open on both sides.
        if (broker_fds[0] >= 0) {
            _ = linux.close(broker_fds[0]);
            broker_fds[0] = -1;
        }
        // The same rule again for the router's pair, and for the same reason.
        if (router_fds[0] >= 0) {
            _ = linux.close(router_fds[0]);
            router_fds[0] = -1;
        }
        // The same rule again for the device link's pair. Nothing on this side
        // of the boundary ever reads a device placement back: see
        // `serveLinks`'s own comment on why this process only ever writes to
        // its own copy of `[0]`, further down this function.
        if (device_fds[0] >= 0) {
            _ = linux.close(device_fds[0]);
            device_fds[0] = -1;
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
        // make. This includes the keeper, B, the optional reader, and every
        // process B starts. One write here bounds the whole call. See
        // `Cgroup.join` for why it is a descriptor and not a path, and why the
        // pid written is `0`.
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
        // **One channel out, and never two.** `spawn` refuses a config that
        // names both seams, so at most one of these is open: the broker's end,
        // which B keeps and the caller's program is handed, or the router's,
        // which A hands to N and nothing else ever holds.
        //
        // **`device_fds[1]` is its own argument, and never folded into the
        // `@max` above.** A device source is exclusive with neither seam, so a
        // call can carry a device source alongside a filtered network, and the
        // `@max` trick that picks one of two mutually exclusive pairs would
        // silently drop whichever of the two was smaller. See
        // `closeInheritedFds`'s own doc comment for what happened the one time
        // this argument was missing outright.
        enterNamespaces(
            config,
            write_fd,
            middle_write_fd,
            @max(broker_fds[1], router_fds[1]),
            device_fds[1],
        );

        // **The network, here, before anything is forked into it.** A is in
        // the network namespace `enterNamespaces` just took and holds
        // `CAP_NET_ADMIN` in the user namespace that owns it, which is the one
        // moment either call can be made at all. Nothing runs between this and
        // the router's own fork below, so the sandbox never holds a network
        // with no ruleset on it.
        //
        // **The capability is what the whole ruleset rests on.** Measured on
        // 2026-09-14: with `CAP_NET_ADMIN` still held, a flush of this table
        // succeeds and every rule below becomes advice. B drops every
        // capability inside `applyLayers`, before it runs the caller's
        // program, and N keeps this one and nothing else. See
        // `capabilities.dropAll`, `runRouter`, and `nftables.Session.install`.
        var table_session: nftables.Session = .{ .fd = -1 };
        if (routed) table_session = buildNetwork(write_fd, config.stderr_fd);

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

        // The channel that carries the notification descriptor from B to A.
        // See `notify.zig`'s own top comment for the handover and for why it
        // cannot stop either process forever.
        //
        // **Made here, after `enterNamespaces` and not before it.**
        // `closeInheritedFds` runs inside that call and closes every
        // descriptor it was not told to keep, so a pair made earlier would
        // need an exemption of its own, and an exemption is a thing that can
        // later be got wrong. `CLOEXEC` as well, so neither end can cross
        // `execve` even if a close were ever missed.
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

        // namespace.enter above called unshare(CLONE_NEWPID), but unshare never
        // moves its caller. A stays outside the new pid namespace. The first
        // child below is the keeper and becomes process 1. B is the next child
        // and gets ordinary process signal and exit behavior as process 2.
        //
        // A opens a pidfd on itself first, so B can inherit a working liveness
        // handle for A across the fork. B cannot open this itself: B is about to
        // enter a pid namespace A is not a member of, so A's pid
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

        // **N, the network router, forked here and nowhere else.** It has to
        // be a child of A for the reason R is: every child A makes after
        // `unshare(CLONE_NEWPID)` is inside the pid namespace, and A is the
        // only process that can reap it. It has to come **after** the keeper,
        // so process 1 is already there to hold the namespace, and **before**
        // B, because a program that connects before the relay is listening
        // gets a reset from the kernel rather than a connection.
        //
        // **A waits for N to say it is up.** The kernel's redirect is
        // installed already, so a connection made before N has bound the relay
        // port is rewritten to a port nothing holds and answered
        // `ECONNREFUSED` at once. That is a real failure a program would see,
        // and the handshake is what removes the race rather than making it
        // unlikely. The same shape the keeper's own readiness byte has.
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
            // **A keeps its end, and that is what tells N to finish later.**
            // The same socket carries the readiness byte one way and the end
            // of the call the other: closing it is how A says the sandboxed
            // program has gone, and it is what lets N carry the last bytes of
            // a connection out before it dies. See `reapRouter`.
            router_control_fd = router_ready_fds[0];

            // **A gives up both of its own copies the moment N holds them.**
            // The channel out is one: a copy here would keep the far end's
            // read from ever reaching the end of the stream, so the parent's
            // serve loop would not learn that the router has gone. The netlink
            // socket is the other: A is about to fork B, and a descriptor A
            // still holds is a descriptor B inherits, and that one writes the
            // kernel's allow set.
            _ = linux.close(router_fds[1]);
            router_fds[1] = -1;
            table_session.close();
            table_session = .{ .fd = -1 };
        }

        // **D, the device helper, forked here for the reason N is forked just
        // above: a device session may want a network too, so the two are
        // never mutually exclusive and D's own place in this order does not
        // depend on whether N ran.** It has to be a child of A for the reason
        // R and N are: every child A makes after `unshare(CLONE_NEWPID)` is
        // inside the pid namespace, and A is the only process that can reap
        // it. It has to come before B, for the reason N does: a program that
        // asks for a path before D is confined and listening would race it.
        //
        // **A waits for D to say it is up, the same handshake N's own
        // comment explains.** A device placed before D has installed its own
        // filter would be a device placed by a process this driver has not
        // yet bounded, which is the one thing `seccomp.device_calls` exists
        // to prevent.
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
            // **A keeps its end, and that is what tells D to leave later.**
            // The same shape `router_control_fd` above has, and for the same
            // reason: see `reapDevice`.
            device_control_fd = device_ready_fds[0];

            // **A gives up its own copy the moment D holds it.** A copy here
            // would keep the far end's read from ever reaching the end of the
            // stream, so a caller could send a placement after A's copy alone
            // remained open and have it silently go nowhere. A is about to
            // fork B, and a descriptor A still holds is a descriptor B
            // inherits, which a device link has no business crossing into.
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
            if (notify_fds[0] >= 0) _ = linux.close(notify_fds[0]);
            // **B gives up the shared record before it does anything else.**
            // B inherited the mapping across the fork above, and B is the one
            // process here that will later run code nobody in this project
            // wrote. A mapping it kept would let it write its own numbers into
            // a record that claims to come from the kernel. `execve` would
            // take the mapping away in any case, because it replaces the whole
            // address space, but this is written down rather than left to
            // that. See `notify.PathRecord`.
            if (path_record) |record| unmapPathRecord(record);
            applyLayers(allocator, config, abi, child_insns, write_fd, notify_fds[1]);
            armPdeathsig(write_fd, config.stderr_fd, middle_pidfd);
            execute(allocator, config, argv, write_fd, broker_fds[1]);
            unreachable;
        }

        // A no longer needs the pidfd once B has it. B's own copy, inherited
        // across the fork above, is untouched by closing this one.
        _ = linux.close(middle_pidfd);

        // A's own copy of the middle pipe's write end stays open until
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

        // **The notification descriptor is taken here, before
        // `restrictMiddle` below, and that order is a rule and not a
        // preference.** `pidfd_getfd` needs ptrace level access to B. B has
        // already dropped every capability of its own inside `applyLayers`,
        // and the kernel makes a process undumpable when a credential change
        // takes a capability away, so from that moment the take is permitted
        // only for a process holding `CAP_SYS_PTRACE` in B's user namespace. A
        // still holds that here. `restrictMiddle` is where A gives it up.
        //
        // **B is waiting for the answer while this runs**, and
        // `notify.takeListener` writes one whichever way the take went. See
        // `notify.zig`'s own top comment for the whole case list.
        var listener: i32 = -1;
        var child_pidfd: i32 = -1;
        if (notify_fds[0] >= 0) {
            // **B's end goes first, and before the read below.** A copy held
            // here would keep the socket's writing side open, so a B that
            // died before it said anything would leave this read waiting
            // instead of giving it end of file.
            _ = linux.close(notify_fds[1]);
            notify_fds[1] = -1;
            // Opened before the take, and used for both the take and the wait
            // below. A pidfd that could not be opened makes the take fail, so
            // B is told "no" and ends, rather than running on into a call
            // nothing would answer.
            const child_pidfd_rc = linux.pidfd_open(inner_pid, 0);
            if (linux.errno(child_pidfd_rc) == .SUCCESS) child_pidfd = @intCast(child_pidfd_rc);
            listener = notify.takeListener(notify_fds[0], child_pidfd);
            _ = linux.close(notify_fds[0]);
            notify_fds[0] = -1;
        }

        // **The path reader, forked here and nowhere else.** It has to be a
        // child of A rather than of B, and it has to come after B. Every child
        // A makes after `unshare(CLONE_NEWPID)` enters the same namespace.
        // That placement is what bounds
        // the reader: `process_vm_readv` names a pid, and a pid means nothing
        // outside the namespace of the process that wrote it down. See
        // `notify.zig`'s own top comment for the measurement.
        //
        // **A gives up its own copy of the listener the moment the reader has
        // one.** Two holders would mean that killing the reader left the
        // observed program waiting for an answer nobody would give. One holder
        // means the kernel answers `ENOSYS` instead, so a program that kills
        // its own auditor breaks its own opens. Measured on 2026-09-11, both
        // ways round.
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
            // A fork that failed leaves `reader_pid` at -1 and the listener in
            // A's own hands, so the loop below runs and the counts still
            // arrive. `ready` stays zero in the record, which is how the
            // session log says the paths are missing.
        }

        // A applied no layer to itself, because B applies them all: see the
        // comment on the fork above. So A takes the two that cost it nothing
        // and keep the promise it used to keep by accident, that a process
        // holding this program's own memory reaches no path and makes no
        // dangerous call while it waits.
        restrictMiddle(abi, insns, middle_write_fd);

        if (reader_pid >= 0) {
            // **The reader holds the listener, so A counts nothing here.**
            // The numbers are in the shared record and they are not final
            // until B has ended, so they are reported from inside
            // `waitAndRelay` below and not from this line.
        } else if (listener >= 0) {
            var counts = notify.empty_counts;
            const outcome = notify.serve(listener, child_pidfd, &counts);
            // **Closed before the wait below.** A process B left behind
            // that still carries the filter would be held in its next
            // observed call for as long as this descriptor lived. Closing it
            // makes the kernel answer that process `ENOSYS` instead, which is
            // a cost this project takes on purpose over a session that never
            // ends. The keeper clears anything B left behind during teardown.
            _ = linux.close(listener);
            reportTraps(middle_write_fd, &counts);
            // **A fault must never leave the session waiting.** B may be held
            // in a call that nothing will answer now, and the wait below would
            // never return. End B instead.
            if (outcome == .fault) _ = linux.kill(inner_pid, std.posix.SIG.KILL);
        } else if (watching) {
            reportTraps(middle_write_fd, null);
        }
        if (child_pidfd >= 0) _ = linux.close(child_pidfd);

        // A is not process 1 anywhere, so it keeps ordinary signal semantics. It
        // waits for B and relays B's outcome as its own, so the real parent's
        // single waitpid on A, further down in this function, still sees the
        // caller's program's real Term.
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

    // The child's end of the broker pair belongs to A and to B now. **This
    // process must give up its copy**, or the serve loop below would never
    // reach the end of the stream, which is how it learns the sandboxed
    // program has gone.
    if (broker_fds[1] >= 0) {
        _ = linux.close(broker_fds[1]);
        broker_fds[1] = -1;
    }
    // The same rule again for the router's pair, whose child end belongs to A
    // and then to N alone.
    if (router_fds[1] >= 0) {
        _ = linux.close(router_fds[1]);
        router_fds[1] = -1;
    }
    // The same rule again for the device link's pair, whose child end belongs
    // to A and then to D alone.
    if (device_fds[1] >= 0) {
        _ = linux.close(device_fds[1]);
        device_fds[1] = -1;
    }
    // Closed on the way out of every branch below, the same rule the two pipes
    // follow: a session runs thousands of calls, and a descriptor left open on
    // an error path ends with the harness unable to open a file.
    errdefer closeBrokerPair(&broker_fds);
    errdefer closeBrokerPair(&router_fds);
    errdefer closeBrokerPair(&device_fds);

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
            _ = linux.close(middle_read_fd);
            _ = linux.close(middle_write_fd);
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
    // Same rule for the middle pipe, whose only writer is A.
    _ = linux.close(middle_write_fd);

    // Both descriptors are closed on the way out of every branch below,
    // including this one. A caller such as `lib/chock-core/tools.zig` runs
    // thousands of tool calls in one session, so a descriptor left open on an
    // error path is a leak that ends with the harness unable to open a file.
    const maybe_failure = readSetupReport(read_fd) catch |err| {
        _ = linux.close(read_fd);
        _ = linux.close(middle_read_fd);
        return err;
    };
    _ = linux.close(read_fd);

    if (maybe_failure) |record| {
        _ = linux.close(middle_read_fd);
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
    // a connection are answered and where a device the caller pushed inward
    // is carried across. **The blocking wait below cannot come first**: it
    // would leave nobody reading either link for the whole call, and the
    // program inside would block on an answer that arrives after it has
    // ended. **One multiplexed loop, and never two run at once.** The broker
    // and the router are still mutually exclusive, because `spawn` refuses a
    // config that names both seams, but a device source is exclusive with
    // neither: see `serveLinks`'s own top comment.
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

    // **A session with no link and no device source runs this loop for
    // nothing.** `link == .none and device == null` is exactly the config
    // this whole call already had before either seam existed: no descriptor
    // to poll and no reason to wait here before the blocking wait below, so
    // that byte for byte unchanged case skips the loop entirely rather than
    // enter it only to poll nothing. See task 4b's own second property.
    if (link != .none or device != null) {
        serveLinks(pid, link, device) catch |err| {
            closeBrokerPair(&broker_fds);
            closeBrokerPair(&router_fds);
            closeBrokerPair(&device_fds);
            _ = linux.close(middle_read_fd);
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
        closeBrokerPair(&router_fds);
        closeBrokerPair(&device_fds);
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
        _ = linux.close(middle_read_fd);
        return error.Unexpected;
    }

    // A has exited, so its copy of the middle pipe's write end is closed and
    // this read cannot block. **It has to happen after the wait**: the areas
    // only exist inside A's mount namespace, and A reads them once, after the
    // program it was watching has ended.
    const middle_report = readMiddleReport(middle_read_fd);
    _ = linux.close(middle_read_fd);

    // **The one place the supervisor's own degradation stops being a printed
    // line.** A had no way to write the session log: `closeInheritedFds`
    // revoked every descriptor it did not name, and a second writer on a log
    // descriptor would interleave with this process anyway. So A said it on
    // the middle pipe and this process, which does hold the log, counts it.
    // See `iface.SupervisorAudit`.
    //
    // **Every layer A puts on itself, and the fail mode table says which.** A
    // layer A never applies has no fail mode for A, so it has no answer to
    // count: see `iface.failModeFor`.
    if (config.supervisor_audit) |audit| {
        inline for (comptime std.enums.values(iface.LayerName)) |layer| {
            if (comptime iface.failModeFor(.supervisor, layer) != null) {
                audit.record(layer, middle_report.layers.get(layer));
            }
        }
    }

    // The same route, for the same reason, carrying what the sandboxed program
    // asked the kernel for. A is the only process that can see it, and A holds
    // no log descriptor. See `iface.SyscallAudit` and `linux/notify.zig`.
    if (config.syscall_audit) |audit| switch (middle_report.traps) {
        // Nothing was asked for, so there is nothing to count. A zero here
        // would read as a program that opened nothing.
        .unasked => {},
        .observed => audit.record(.{ .observed = middle_report.trap_counts }),
        .unobserved => audit.record(.unobserved),
    };

    // The paths the reader wrote never went through the middle pipe. The
    // reader reports into memory this process shares with it. See
    // `notify.PathRecord`. **Every number read out of it is untrusted input**,
    // which `SyscallAudit.recordPaths` and `notify.PathRecord.name` are what
    // bound.
    if (config.syscall_audit) |audit| {
        if (path_record) |record| audit.recordPaths(record);
    }

    // The program has ended, so the kernel's own counters are final and the
    // cgroup can be read. **Read before `destroy` removes it**, which the
    // `defer` above does on the way out of this function.
    const term: std.process.Child.Term = if (linux.W.IFSIGNALED(status))
        .{ .signal = linux.W.TERMSIG(status) }
    else
        .{ .exited = linux.W.EXITSTATUS(status) };
    reportLimitOutcome(config, &group, term, middle_report.scratch_full);
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

/// Which of the two mutually exclusive network seams this call serves, or
/// neither. `spawn` refuses a config that names both `net_broker` and
/// `net_router`, so at most one of these ever carries a real descriptor. See
/// `Config.net_router`.
const Link = union(enum) {
    none,
    broker: struct { fd: i32, seam: iface.NetBroker },
    router: struct { fd: i32, seam: iface.NetRouter },
};

/// The host side of a device link, for a call that names `Config.device_source`.
/// `fd` is `device_fds[0]`: this process only ever writes to it, through
/// `devicelink.sendPlace` and `devicelink.sendDrop`, because
/// `devicelink.zig`'s own top comment is explicit that nothing ever answers
/// back on it.
const DeviceOut = struct {
    fd: i32,
    source: iface.DeviceSource,
};

/// Send one `change` to the in-sandbox helper. Errors are not this
/// function's to report: a `PeerGone` here means D has already ended, which
/// `serveLinks`' own loop learns on its next look through the ordinary
/// death of the sandboxed program, and a `PathUnusable` here is
/// `config.device_source`'s own bug, already unreachable from a sandboxed
/// process and so never something this file's own audit exists to catch.
///
/// False when the helper could not be reached, which is the only way either
/// send fails: the link is a socket pair with exactly two ends and this one is
/// writing. **The caller stops offering devices and keeps serving everything
/// else**, because a helper that has gone must not take a working network down
/// with it. See `serveLinks`, which is the only caller.
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

/// Answer the sandboxed program's requests for a connection, and carry a
/// device the caller pushes inward, until the call has ended.
///
/// **This runs in the real parent**, the process that called `spawn`, and that
/// is the whole design for `link`: the parent holds the policy, so a
/// sandboxed process cannot reach a host merely by knowing its address, and
/// it also holds the host's own network namespace, which A gave up in
/// `enterNamespaces` and B never had. A is the wrong process for this twice
/// over. `device` runs here for a different reason: `config.device_source` is
/// the caller's own object, alive for as long as the caller keeps it, and
/// only the real parent's own stack frame is guaranteed to still be there
/// when a device becomes available partway through a long running call.
///
/// **One loop where this driver used to run two, because devices are
/// exclusive with neither.** A hardware session may want a network and a
/// device at once, so the set of descriptors this polls is whichever of
/// `link`'s two members is real, plus `device`'s own wakeup when one was
/// named, plus the pidfd every call polls regardless. `poll`'s own manual
/// says a negative `fd` in one slot is simply skipped, so a member `link`
/// does not carry, or a call with no `device`, costs nothing here beyond the
/// slot in this array staying unused.
///
/// **Nothing waits without a bound.** A program that never asks for
/// anything, on a call with no device source either, costs one blocked
/// `poll` and no wakeups at all, and a program that ends while nothing is in
/// flight ends this loop at once. **The pidfd is not decoration.** Without
/// it, a sandboxed program that keeps its end of a pair open in a process
/// that never exits, such as a grandchild the program forked and abandoned,
/// would hold this loop after the program itself had finished, and the
/// caller's own `waitpid` would never run.
///
/// **The request is read before the pidfd, every look, and the device
/// wakeup is drained before it too.** A program that asked and then exited
/// has its request already in the pair, and the kernel reports both on the
/// same look: reading the request first costs one answer nobody collects,
/// and reading the pidfd first would lose a request that was really made.
/// The same reasoning extends to the device wakeup, which this loop reads
/// before the pidfd for the same reason, though the risk it closes is
/// smaller: a placement fed in the instant the program exits is one this
/// driver can still forward, and D outlives B by design, so forwarding it
/// costs nothing even when nothing is left to use it.
///
/// `netbroker.max_requests` and `routerlink.max_requests` still bound the
/// two links exactly as they always did: past the budget the link closes and
/// this loop reads that as the end of the stream. **The device source has no
/// such budget**, because it is never the sandboxed, untrusted program that
/// drives it: `config.device_source` is the caller's own trusted code, the
/// same reason nothing here rate limits `restrictMiddle` or `reportTraps`.
fn serveLinks(pid: linux.pid_t, link: Link, device: ?DeviceOut) SpawnError!void {
    // **Opened here, before anything reaps A**, for the reason the `middle`
    // handle gives: this process is A's only reaper and has not run its
    // `waitpid` yet, so A is still a task the kernel can resolve, alive or a
    // zombie. A loop that could not watch A is a loop that could outlive the
    // call it belongs to, so a failure here is a refusal and not a shrug.
    const watch_rc = linux.pidfd_open(pid, 0);
    if (linux.errno(watch_rc) != .SUCCESS) return error.Unexpected;
    const watch: i32 = @intCast(watch_rc);
    defer _ = linux.close(watch);

    const link_fd: i32 = switch (link) {
        .none => -1,
        .broker => |b| b.fd,
        .router => |r| r.fd,
    };
    // Read once, outside the loop: `Config.device_source` names one live
    // descriptor for the whole of one `spawn` call, the same as `link_fd`
    // above does, and re-asking on every turn would cost a call through the
    // seam's own vtable for an answer that cannot change.
    const wakeup_fd: i32 = if (device) |d| d.source.vtable.wakeup(d.source.ptr) else -1;
    // A budget only a real link needs: see this function's own top comment
    // on why the device source has none. `.none` never reads `served`
    // against it, because the loop below only ever counts a served link
    // request, and there is no link to serve.
    const budget: usize = switch (link) {
        .none => 0,
        .broker => netbroker.max_requests,
        .router => routerlink.max_requests,
    };

    // **Sized for what this call actually has, and never padded with a
    // sentinel slot.** `link_idx` and `device_idx` are `null` for a member
    // this call does not carry, and `fds[0..fds_len]` below is exactly the
    // set of descriptors this call polls: a session with no link and no
    // device source never reaches this function at all, see `spawn`'s own
    // guard, and a session with one of the two but not the other polls two
    // descriptors here and never three. This is what task 4b's own second
    // property rests on, and a fixed three element array with `-1` in the
    // unused slot would only be `poll`'s own business to skip, not a fact a
    // test could see from outside.
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
        // `poll` writes every `revents` field it examines fresh on every
        // call, for every index below `fds_len`, so nothing here has to
        // clear a slot before asking again.
        const ready = linux.poll(&fds, fds_len, -1);
        switch (linux.errno(ready)) {
            .SUCCESS => {},
            // A signal reached this process while it waited. Nothing was lost,
            // so look again rather than end a call over it.
            .INTR => continue,
            else => return,
        }

        // **The link is read first**, the property every server loop this
        // file has ever had states in its own comment, and for the same
        // reason: the kernel reports both this and the pidfd on the same
        // look, and reading the request first costs one answer nobody
        // collects, where reading the pidfd first would lose a request that
        // was really made.
        // **Two calls to `serveOne` and not one, because `netbroker.Outcome`
        // and `routerlink.Outcome` are two distinct types with the same
        // three members.** Zig has no common type a single `switch`
        // expression could return here, so the switch on `link` picks the
        // call and each arm switches its own answer, rather than force one
        // shared `Outcome` on two wires that owe each other nothing.
        if (link_idx) |i| {
            if (fds[i].revents & linux.POLL.IN != 0) {
                switch (link) {
                    .none => unreachable,
                    .broker => |b| switch (netbroker.serveOne(b.fd, b.seam)) {
                        // Counted, because this is the one a sandboxed
                        // process can make happen on purpose.
                        .served => {
                            served += 1;
                            continue;
                        },
                        // Not counted: a signal that interrupted the read is
                        // not a request, and counting it would let a signal
                        // storm this process did not cause spend a call's
                        // whole budget.
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

        // **The device wakeup is read next, and before the pidfd too**, for
        // the smaller version of the same reason. Drained in a loop of its
        // own: one wakeup can carry more than one change, and
        // `iface.DeviceSource.VTable.next`'s own doc comment says to keep
        // calling until it answers null.
        if (device) |d| {
            if (fds[device_idx.?].revents & linux.POLL.IN != 0) {
                while (d.source.vtable.next(d.source.ptr)) |change| {
                    if (sendChange(d.fd, change)) continue;
                    // **The helper is gone, so stop offering devices and keep
                    // serving the rest.** A negative descriptor is the one
                    // thing `poll` ignores, so this drops the wakeup out of
                    // the set without moving any other index. Tearing the
                    // whole loop down here would take a working network with
                    // it, which is a larger fault than the one that happened.
                    fds[device_idx.?].fd = -1;
                    break;
                }
                continue;
            }
        }

        // The end of the stream on the link, with nothing to read: every
        // copy of the child's end is closed, so nothing will ask again.
        if (link_idx) |i| if (fds[i].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0) return;
        // The pidfd, always at index 0: A has exited, so nothing more will
        // ever be there to serve.
        if (fds[0].revents != 0) return;
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

/// One record on the middle pipe: a tag byte that says which fact it carries,
/// a slot byte that says which member of that fact, and an eight byte value.
///
/// **Fixed width, and no length field.** A reader that meets a tag it does not
/// know steps over the record and reads the one after it, and a reader built
/// from a different version of this file cannot exist: both ends come from one
/// `pipe2` call in `spawn`, in one process, and the only writer is that
/// process's own first child. Ten bytes is far below `PIPE_BUF`, so each
/// record reaches the reader whole even though A writes several of them at
/// several different moments.
///
/// **The slot byte and the wide value are what carry a histogram.** A count of
/// system calls does not fit in a byte, and there is one count for each member
/// of `seccomp.TrapCall`. See `tag_trap_count`.
///
/// The tag values are fixed rather than counted from zero, so a read that ever
/// landed on something else is ignored instead of trusted. There is no forgery
/// to defend against here, unlike on the setup pipe: both ends are `CLOEXEC`,
/// A is the only writer, and `closeInheritedFds` already ran, so the sandboxed
/// program never holds either end.
const record_bytes = 10;

/// A scratch area had no space left in it when the program ended. The value
/// is 1.
const tag_scratch_full: u8 = 0xD1;

/// Whether A put one layer on itself. The slot byte is the tag value of an
/// `iface.LayerName`, and the value is 0 for a layer that went on and
/// otherwise a `SupervisorAudit.Fault`.
///
/// **Written whichever way it went**, so that "A said nothing" stays a third
/// answer of its own rather than reading as success. A tool call a person
/// cancelled kills A before it reaches `restrictMiddle` at all, and that call
/// must not be counted as one whose supervisor was confined.
///
/// **One record per layer, and the slot is what tells them apart.** This tag
/// used to carry the seccomp filter alone, so the two layers beside it reached
/// a terminal and nothing else. `chock_proto.event.SandboxSupervisor` already
/// carries a `layer` field for exactly this.
const tag_middle_layer: u8 = 0xD2;

/// How many `tag_middle_layer` records A can write, which is one for each
/// layer it puts on itself. **Counted from the fail mode table** rather than
/// spelled here, so a fourth layer given to the supervisor grows the read
/// buffer with it instead of silently overflowing the margin.
const middle_layer_count: usize = blk: {
    var found: usize = 0;
    for (std.enums.values(iface.LayerName)) |layer| {
        if (iface.failModeFor(.supervisor, layer) != null) found += 1;
    }
    break :blk found;
};

/// Whether A held the notification descriptor for this call. The value is 1
/// when it did and 0 when it did not.
///
/// **Written only when the caller asked for an observation**, so a session
/// that asked for none is a third answer of its own rather than a call that
/// failed to be watched. See `iface.SyscallAudit`.
const tag_traps_observed: u8 = 0xD3;

/// One member of the system call histogram. The slot byte is the tag value of
/// a `seccomp.TrapCall`, and the value is how many times the sandboxed program
/// made that call.
const tag_trap_count: u8 = 0xD4;

/// Whether A was asked to watch this call, and whether it could.
const TrapState = enum {
    /// The caller asked for no observation at all.
    unasked,
    /// A held the notification descriptor, so the counts are about this call.
    observed,
    /// A was asked and could not, so this call ran with nothing watching it.
    unobserved,
};

/// What `readMiddleReport` found on the middle pipe.
const MiddleReport = struct {
    /// True when a scratch area had no space left in it.
    scratch_full: bool = false,
    /// What A said about each layer it puts on itself. `.unsaid` when A never
    /// reached `restrictMiddle`, or could not write.
    layers: std.EnumArray(iface.LayerName, iface.SupervisorAudit.Outcome) =
        .initFill(.unsaid),
    /// What A said about watching the sandboxed program's system calls.
    traps: TrapState = .unasked,
    /// The histogram A counted. All zero unless `traps` is `.observed`.
    trap_counts: notify.Counts = notify.empty_counts,
};

/// Write one record. Best effort, for the reason `restrictMiddle` and
/// `reportScratch` both give: a write that fails costs the caller a fact and
/// never the program's own outcome.
fn writeMiddleRecord(middle_write_fd: i32, tag: u8, slot: u8, value: u64) void {
    var record: [record_bytes]u8 = undefined;
    record[0] = tag;
    record[1] = slot;
    // A byte order is named rather than left native, so a reader of this file
    // does not have to work out that both ends are always the same machine.
    std.mem.writeInt(u64, record[2..record_bytes], value, .little);
    _ = linux.write(middle_write_fd, &record, record.len);
}

/// Say whether any scratch area was full when the program ended, on the
/// middle pipe.
fn reportScratch(areas: *const ScratchAreas, middle_write_fd: i32) void {
    if (!areas.anyFull()) return;
    writeMiddleRecord(middle_write_fd, tag_scratch_full, 0, 1);
}

/// Say whether A could put one layer on itself, on the middle pipe. `fault` is
/// null for a layer that went on.
fn reportMiddleLayer(
    middle_write_fd: i32,
    layer: iface.LayerName,
    fault: ?iface.SupervisorAudit.Fault,
) void {
    const value: u8 = if (fault) |one| @intFromEnum(one) else 0;
    writeMiddleRecord(middle_write_fd, tag_middle_layer, @intFromEnum(layer), value);
}

/// Say what A saw of the sandboxed program's system calls, on the middle pipe.
///
/// `counts` is null for a call A was asked to watch and could not. See
/// `tag_traps_observed` for why that is not the same record as a histogram of
/// zeros.
fn reportTraps(middle_write_fd: i32, counts: ?*const notify.Counts) void {
    writeMiddleRecord(middle_write_fd, tag_traps_observed, 0, if (counts == null) 0 else 1);
    const seen = counts orelse return;
    for (seen, 0..) |count, slot| {
        // A call nobody made says nothing a zero does not already say, and the
        // pipe has room for a fixed number of records.
        if (count == 0) continue;
        writeMiddleRecord(middle_write_fd, tag_trap_count, @intCast(slot), count);
    }
}

/// Name the fault a failed `seccomp.install` in A is recorded as.
///
/// **Exhaustive on purpose.** A member added to `seccomp.InstallError` stops
/// this file compiling until it is named here too, so a new fault cannot reach
/// the log as one of the old ones. Before that error set was split, every
/// failure arrived as `Rejected`, and a record that said so would have named
/// the wrong repair.
fn filterFaultFor(err: seccomp.InstallError) iface.SupervisorAudit.Fault {
    return switch (err) {
        error.NotSupported => .not_supported,
        error.NoNewPrivsRefused => .no_new_privs_refused,
        error.NotPermitted => .not_permitted,
        error.Rejected => .rejected,
        error.Unexpected => .unexpected,
    };
}

/// Name the fault a failed Landlock call in A is recorded as. Exhaustive for
/// the reason `filterFaultFor` gives.
///
/// **The four path faults cannot reach this.** A's ruleset holds no rule at
/// all, so `allowPath` is never called and only `init` and `restrictSelf` can
/// fail. They are named anyway, because an error set is not a promise about
/// which caller uses which member.
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

/// Name the fault a failed `capabilities.dropAll` in A is recorded as.
/// Exhaustive for the reason `filterFaultFor` gives.
fn capabilitiesFaultFor(err: capabilities.Error) iface.SupervisorAudit.Fault {
    return switch (err) {
        error.Rejected => .rejected,
    };
}

/// Read the value byte of a `tag_middle_layer` record.
///
/// A value this build has no name for still reads as "the layer did not go
/// on", with `unexpected` standing in for the name. A record only A writes
/// cannot carry one, and reading it as success would be the one mistake this
/// whole record exists to stop.
fn outcomeFor(value: u8) iface.SupervisorAudit.Outcome {
    if (value == 0) return .on;
    const fault = std.enums.fromInt(iface.SupervisorAudit.Fault, value) orelse .unexpected;
    return .{ .off = fault };
}

/// Read the middle pipe, which A has already closed by the time this runs.
/// Every field keeps its default on end of file with no data, which is what a
/// call whose A was killed before it could say anything leaves behind.
fn readMiddleReport(middle_read_fd: i32) MiddleReport {
    // Room for twice as many records as A can write: one for each layer it
    // puts on itself, one for the scratch areas, one that says whether it
    // watched the program, and one for each member of `seccomp.TrapCall` that
    // the program used. A reader that stopped early
    // would leave bytes in a pipe nobody reads again, and the cost of the
    // margin is a few bytes of stack.
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
    // A trailing byte that is not a whole record is dropped. Nothing writes a
    // half record, so meeting one means the pipe was cut, and half a tag names
    // no fact.
    while (at + record_bytes <= filled) : (at += record_bytes) {
        const slot = buffer[at + 1];
        const value = std.mem.readInt(u64, buffer[at + 2 ..][0..8], .little);
        switch (buffer[at]) {
            tag_scratch_full => report.scratch_full = value != 0,
            // A slot this build has no layer for is dropped, for the reason
            // `tag_trap_count` below gives: an answer under the wrong layer's
            // name is worse than one that is missing.
            tag_middle_layer => if (std.enums.fromInt(iface.LayerName, slot)) |layer| {
                report.layers.set(layer, outcomeFor(@truncate(value)));
            },
            tag_traps_observed => report.traps = if (value != 0) .observed else .unobserved,
            // A slot this build has no member for is dropped. Counting it
            // against a member that exists would put a number under the wrong
            // name, which is worse than a number that is missing.
            tag_trap_count => if (slot < notify.call_count) {
                report.trap_counts[slot] = value;
            },
            else => {},
        }
    }
    return report;
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
        // **Its own member, and not `NamespaceFailed`.** The network namespace
        // was taken. What failed is the network built inside it, and the
        // repair is a different one: a kernel module the host has to load.
        // See `iface.SpawnError.NetRouterUnavailable`.
        .network => error.NetRouterUnavailable,
        // **Its own member, for the same reason `.network` has one.** A
        // device source was named, and the helper that places its devices
        // never said it was ready. See `iface.SpawnError.DeviceHelperFailed`.
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
        // **Its own member, and not `SeccompInstallFailed`.** The filter went
        // on. What failed is the handover of its notification descriptor to
        // the supervisor, and the repair is a different one: see
        // `notify.takeListener` for what the kernel checks before it permits
        // the take.
        .notify_handover => error.NotifyHandoverFailed,
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

/// Same as `dieErrno`, for a step whose errno came out of a `Diagnostic` and
/// is already a plain number. **A number and not a `linux.E`**, because the
/// diagnostics the network steps fill carry what the kernel answered, and an
/// integer from outside is not an enum until something checks it.
fn dieWithErrno(write_fd: i32, stderr_fd: i32, step: SetupStep, errno: i32) noreturn {
    _ = stderr_fd;
    // The record only. The caller printed the reason before it called this,
    // which is what `printFault` is for on the two network paths: the errno
    // alone does not say whether a module is missing or a capability is.
    reportSetupFailure(write_fd, step, errno);
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

/// Wait for `pid`, the grandchild running the caller's program as process 2 of
/// the new pid namespace. End this process with the same signal or exit code.
/// Never returns.
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
/// The keeper is process 1 of the new namespace. It stays alive until the
/// program and reader are reaped. Closing its control socket makes it exit.
/// The kernel then kills every process that the program left behind.
fn waitAndRelay(
    pid: linux.pid_t,
    keeper_pid: linux.pid_t,
    /// The network router. Both members are -1 for a call that has none.
    network_router: RouterWatch,
    /// The device helper. Both members are -1 for a call that names no
    /// `device_source`. Same shape as `network_router`, and reaped the same
    /// way, through `reapDevice`.
    device: DeviceWatch,
    keeper_fd: i32,
    areas: *const ScratchAreas,
    middle_write_fd: i32,
    reader: ?ReaderWatch,
) noreturn {
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

    // B is not process 1, so its exit does not wait for R to be reaped. R
    // watches B's pidfd and reports after this wait observes the same exit.
    if (reader) |watch| reapReader(watch, middle_write_fd);

    // **N is ended here, and before the keeper below, and that order is a rule
    // and not a preference.** A pid namespace cannot be torn down until every
    // pid in it is **reaped**, not merely killed: process 1's own exit path
    // waits for exactly that. N is a child of A, which is outside the
    // namespace, so nothing inside it can ever reap N. A zombie left here
    // would hold the keeper's exit forever and the whole session with it.
    //
    // **A kill and not a request.** N serves a loop with no way out of its
    // own: it runs for as long as the sandbox does, and the sandbox has just
    // ended. There is nothing for it to finish and nothing it could be waiting
    // on, so the wait below cannot block on work in flight.
    if (network_router.pid >= 0) reapRouter(network_router);

    // **D is ended the same way and for the same reason N is, just above.**
    // A device helper serves a loop with no way out of its own either: it
    // runs for as long as the sandbox does, and the sandbox has just ended.
    if (device.pid >= 0) reapDevice(device);

    // Closing this socket tells process 1 to leave. Its exit kills any process
    // that B left behind. Reap it last because its pid namespace cannot close
    // until every remaining member is gone.
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

    // **Read the scratch areas here, and nowhere else.** They live in this
    // process's own mount namespace, which nothing outside it can see, and the
    // program that could have filled them has just ended, so this is both the
    // only place and the only moment the reading means anything. It happens
    // before the relay below, because every branch of that relay ends this
    // process.
    reportScratch(areas, middle_write_fd);

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

/// End the network router and reap it. Called by A, from `waitAndRelay`, after
/// the sandboxed program has been reaped and before process 1 is told to go.
///
/// **It cannot hang, and that is the whole reason it is a function.** `SIGKILL`
/// cannot be caught, blocked or ignored, so N ends whatever it was doing, and
/// A is N's parent and its only reaper, so the wait below has exactly one
/// process to collect and no other waiter to race. The pid cannot be reused
/// before the wait returns, because the kernel keeps a reaped-by-nobody child
/// resolvable to its own parent.
fn reapRouter(watch: RouterWatch) void {
    // **The close comes first, and the kill is the fallback.** A program that
    // wrote its last bytes and exited leaves those bytes in the router, on the
    // way out, and a router killed at that instant drops them. Closing this
    // socket is what tells N that the program has gone, so N carries what it
    // holds and then leaves on its own. See `runRouter`.
    if (watch.control_fd >= 0) _ = linux.close(watch.control_fd);

    var status: u32 = undefined;
    var rc: usize = 0;
    var tries: usize = 0;
    // **A fixed bound, the same shape `reapReader` has.** A router that will
    // not leave must not hold the whole session, and a pid namespace cannot be
    // torn down until every pid in it is reaped, so a wait with no bound here
    // is a session that hangs.
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
        // `ESRCH` means N has already ended, which leaves a zombie to collect
        // exactly as a kill does.
        .SUCCESS, .SRCH => {},
        else => dieRelayErrno("end the network router", kill_errno),
    }
    rc = linux.waitpid(watch.pid, &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(watch.pid, &status, 0);
    if (linux.errno(rc) != .SUCCESS) {
        dieRelayErrno("waitpid on the network router", linux.errno(rc));
    }
}

/// What A holds about the network router while it waits for B.
const RouterWatch = struct {
    pid: linux.pid_t,
    /// The socket N said it was ready on. **Closing it is how N is told the
    /// call has ended.** -1 for a call with no router.
    control_fd: i32,
};

/// How long A waits for the router to carry its last bytes and leave, as a
/// number of one millisecond looks. Half a second, which is far above the two
/// turns of a poll loop a drain really takes and far below anything a person
/// would notice at the end of a tool call.
const router_drain_tries: usize = 500;
const router_drain_step_ns: isize = 1_000_000;

/// End the device helper and reap it. Called by A, from `waitAndRelay`, the
/// same moment `reapRouter` is: after the sandboxed program has been reaped
/// and before process 1 is told to go.
///
/// **The same shape `reapRouter` has, and a simpler one underneath.** D
/// carries no bytes of its own the way N's relay does: a placement is one
/// `mount`, already finished the moment `devicelink.serveOne` returns, so
/// there is nothing for D to drain and closing its control socket is enough
/// to make it leave on its own. The wait below still has a bound, for the
/// reason `reapRouter`'s own comment gives: a helper that will not leave must
/// not hold the whole session.
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
        // `ESRCH` means D has already ended, which leaves a zombie to collect
        // exactly as a kill does.
        .SUCCESS, .SRCH => {},
        else => dieRelayErrno("end the device helper", kill_errno),
    }
    rc = linux.waitpid(watch.pid, &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(watch.pid, &status, 0);
    if (linux.errno(rc) != .SUCCESS) {
        dieRelayErrno("waitpid on the device helper", linux.errno(rc));
    }
}

/// What A holds about the device helper while it waits for B. Same shape as
/// `RouterWatch`.
const DeviceWatch = struct {
    pid: linux.pid_t,
    /// The socket D said it was ready on. **Closing it is how D is told the
    /// call has ended.** -1 for a call with no `device_source`.
    control_fd: i32,
};

/// Build the sandbox its own network and put the ruleset on it. Runs in A,
/// inside the network namespace and while `CAP_NET_ADMIN` is still held.
///
/// The netlink socket the allow sets are written on comes back, because the
/// router needs one and **it has to be opened here**: a netlink socket belongs
/// to the network namespace of whichever process created it, and it has to be
/// created before the capability is narrowed to N alone.
///
/// **A missing kernel module ends the call rather than weakening it.** Every
/// one of `nf_tables`, `nf_nat`, `nft_chain_nat`, `nft_redir`, `nft_reject`,
/// `nf_conntrack` and `dummy` may be a module, and **a process in a user
/// namespace cannot make the kernel load one**. A sandbox that came up with a
/// network and no ruleset on it would reach whatever the host can reach, so
/// there is nothing to fall back to. See `iface.SpawnError.NetRouterUnavailable`.
fn buildNetwork(write_fd: i32, stderr_fd: i32) nftables.Session {
    var route_diag: ?netns.Diagnostic = null;
    var route = netns.Session.open(&route_diag) catch |err|
        dieNetwork(write_fd, stderr_fd, err, netnsErrno(route_diag));
    _ = route.configure(&route_diag) catch |err|
        dieNetwork(write_fd, stderr_fd, err, netnsErrno(route_diag));
    // The rtnetlink socket has nothing left to say. The network it built is a
    // property of the namespace and not of this descriptor.
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

/// Report a network that would not come up, with the errno the kernel gave.
///
/// **A module that is missing gets a sentence and not only an error name.**
/// It is the one fault here that a person can fix, and the fix is not obvious
/// from the name: `KernelModuleMissing` means the host has to load a module,
/// and no message anywhere else would say which. See `dieNoticeForDeny`, which
/// is the same shape for the one fault a project author can fix.
fn dieNetwork(write_fd: i32, stderr_fd: i32, err: anyerror, errno: i32) noreturn {
    if (err == error.KernelModuleMissing) {
        writeStderr(stderr_fd, missing_module_notice);
    } else {
        printFault(stderr_fd, err);
    }
    dieWithErrno(write_fd, stderr_fd, .network, errno);
}

/// What a person reads when the host has no nftables or no `dummy` device.
///
/// **A process in a user namespace cannot make the kernel load a module**, so
/// there is nothing Chock can do about this from inside and nothing to fall
/// back to: a sandbox with a network and no ruleset on it would reach whatever
/// the host can reach. The modules are named because `modprobe` needs names.
const missing_module_notice =
    "sandbox: this host cannot give a sandbox its own filtered network.\n" ++
    "sandbox: a kernel module it needs is not loaded, and a sandbox cannot load one.\n" ++
    "sandbox: load these on the host and run again:\n" ++
    "sandbox:   modprobe " ++ network_modules ++ " " ++ filter_modules ++ "\n";

/// The module `netns.Session.configure` needs, which is the `dummy` link kind
/// and nothing else. See `netns.link_kind`.
///
/// **One list, read by the notice above and by `src/doctor.zig`.** That command
/// asks this question before a session starts, and a second copy of a
/// `modprobe` line is a second thing to keep true.
pub const network_modules = "dummy";

/// The modules `nftables.Session.install` needs. See that file's own top
/// comment for why each one is a module on most kernels, and `network_modules`
/// above for why the list is stated once.
pub const filter_modules = "nf_tables nf_nat nft_chain_nat nft_redir nft_reject nf_conntrack";

/// N, the network router. Never returns.
///
/// **Confines itself before it serves anything**, and in this order: the two
/// listeners come up while `CAP_NET_BIND_SERVICE` is still held, then every
/// descriptor but the five it needs goes away, then every capability but
/// `CAP_NET_ADMIN`, then a seccomp allowlist. Only after all of that does it
/// say it is ready, so "ready" means "fully confined and listening" and never
/// one without the other.
///
/// What it is permitted afterwards is `seccomp.router_calls` and nothing else:
/// it cannot open a path, make a socket of any kind, run a program, or signal
/// anything. Every descriptor it will ever hold is one it already has, plus
/// the ones the kernel hands it through `accept4` and the far side hands it
/// through `SCM_RIGHTS`.
///
/// **It keeps one capability, and only one.** `CAP_NET_ADMIN` in the sandbox's
/// own user namespace is what lets it add an address to the kernel's allow
/// set, which is the whole mechanism: a name the policy permitted becomes an
/// address the kernel will carry, and nothing else ever becomes one. That
/// namespace was made a moment earlier and owns nothing of the host's, and the
/// filter above names no call the capability could otherwise be spent on: there
/// is no `socket`, so there is no second netlink socket to open, and the one it
/// holds was opened in A. See `capabilities.keepOnly`, and `runReader`, which
/// is the same shape for `CAP_SYS_PTRACE`.
///
/// **A layer that will not go on ends this process rather than weakening it.**
/// A router running with less than its full confinement is the one outcome
/// that must not happen quietly: it holds a descriptor from the host's own
/// network namespace and a capability the sandboxed program does not have.
/// Ending it is safe for the session, because A is waiting for the readiness
/// byte and reports a setup failure when it does not come.
fn runRouter(
    ready_fd: i32,
    link_fd: i32,
    table: nftables.Session,
    middle_pidfd: i32,
    insns: []const bpf.Insn,
    write_fd: i32,
    stderr_fd: i32,
) noreturn {
    // **Before anything else**, the same as the keeper. A that died between
    // the fork above and this line would otherwise leave N running with a
    // relay nobody reaps. See `armPdeathsig` for the race it closes.
    armPdeathsig(write_fd, stderr_fd, middle_pidfd);

    var client = routerlink.Client{ .fd = link_fd, .session = table };
    var instance: router.Router = undefined;
    var diag: ?router.Diagnostic = null;
    // **The listeners come up first, and while the capability is still
    // there.** The resolver binds port 53, which is privileged, so a process
    // that had already narrowed its capabilities would be refused it. See
    // `router.Error.PrivilegedPort`, which names exactly this mistake.
    instance.open(.{ .policy = client.policy(), .host = client.host() }, &diag) catch |err| {
        printFault(stderr_fd, err);
        dieWithErrno(write_fd, stderr_fd, .network, if (diag) |one| one.errno else 0);
    };

    // Every descriptor but the five this loop uses. `closeInheritedFds`
    // already ran in A, so what is left is A's own working set: the middle
    // pipe, the caller's output descriptors, and the scratch areas.
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

    // **The last thing before the loop.** A is blocked on this byte and forks
    // the caller's program only once it arrives, so nothing the program does
    // can reach a relay that is not there.
    //
    // **`sendto` and not `write`**, because `write` is not on the router's
    // allowlist and must not be put there: a router that can write to a
    // descriptor is a router that can write to one the far side sent it.
    const ready = [1]u8{1};
    const said = linux.sendto(ready_fd, &ready, ready.len, linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(said) != .SUCCESS or said != ready.len) linux.exit(1);

    // **The same socket is the control channel from here on.** A keeps its own
    // end open for as long as the sandboxed program runs and closes it once
    // that program has been reaped. See `reapRouter`.
    //
    // **A finite wait, and not the `-1` `router.run` uses.** The router has to
    // notice the close, and `Router.step` waits on the relay and the resolver
    // and knows nothing about this descriptor. A wait of `-1` here would leave
    // the router asleep until the next connection, which on a call that has
    // just ended never comes, and A would then fall back to killing it and
    // drop whatever it still held. The cost is one wakeup every
    // `router_idle_step_ms`, which for a call that lasts seconds is nothing.
    while (!peerHasGone(ready_fd)) {
        // **A monotonic clock that counts suspended time, and never the wall
        // clock.** Every deadline in the router is a span and not a date, so a
        // clock an administrator or NTP can move would expire a name early or
        // hold one late for no reason a reader could see. See `router.run`,
        // which this loop replaces: that one needs a `std.Io`, and a `std.Io`
        // needs calls this filter does not permit.
        instance.step(monotonicMilliseconds(), router_idle_step_ms, null) catch linux.exit(1);
    }

    // **The last bytes, carried after the program that wrote them has gone.**
    // A program that writes and exits leaves its bytes in this process, and a
    // router that stopped the instant the program did would drop them. Every
    // link is finished quickly here because the program is already gone, so
    // every inside socket is closed and every direction ends. The bound is
    // what makes this a drain and not a second loop with no way out.
    var drained: usize = 0;
    while (drained < router_drain_steps) : (drained += 1) {
        instance.step(monotonicMilliseconds(), router_drain_step_ms, null) catch break;
        if (instance.pendingBytes() == 0) break;
    }
    linux.exit(0);
}

/// How long the router sleeps in one turn of its loop when nothing is ready.
const router_idle_step_ms: i32 = 20;

/// How many turns the router may take to carry what it still holds once the
/// call has ended, and how long each one may wait.
///
/// **Two turns is what a drain really takes**: one to read what the program
/// wrote as its socket closes, and one to write it on. The bound is above that
/// for a write the kernel would not take at once, and it is still a bound:
/// `reapRouter` waits `router_drain_tries` milliseconds after this and then
/// kills.
const router_drain_steps: usize = 16;
const router_drain_step_ms: i32 = 2;

/// D, the device helper. Never returns.
///
/// **Confines itself before it serves anything**, the same order `runRouter`
/// keeps and for the same reason: `armPdeathsig` first, so a death of A
/// between the fork and this line does not leave D running with a link
/// nobody reads; then every descriptor but the three it needs goes away;
/// then the hidden device tree is bound in, while this process still holds
/// every capability it inherited; then every capability but `CAP_SYS_ADMIN`,
/// which is what a bind mount and an unmount both need in this sandbox's own
/// user namespace; then the allowlist `seccomp.buildDevice` built. Only after
/// all of that does it say it is ready, so "ready" means "fully confined and
/// listening" here.
///
/// **The hidden tree is bound here, in D, and not in B's own mount tree.** D
/// is forked and confined before B, precisely so a program inside the
/// sandbox can never ask for a path before D is ready to answer it: see this
/// file's own comment above D's fork in `spawn`. Binding the hidden tree in
/// B's own `applyLayers` instead would let D start serving placements before
/// that bind existed, for any device pushed in early enough, and a
/// placement asked for in that window would answer `MountFailed` for a
/// reason nothing near it explains.
///
/// **D never pivots, and it does not need to.** `pivot_root`, run later by B,
/// changes the root mount for the whole namespace the two of them share, so
/// D's own `/` moves to the sandbox's root at the instant B's own call
/// happens, the same as B's does, with no unshare and no pivot of D's own
/// asked for. Measured directly, standalone, outside this repository: two
/// processes sharing one mount namespace, one of them pivoting, and the
/// other one's fresh absolute lookups landing in the pivoted tree afterward,
/// never in the detached old one, so long as the path it asks for is
/// already sandbox-relative and carries no `Config.root` prefix of its own.
/// This is why `placeDevice` and `dropDevice`, unlike `bindDeviceTree`, join
/// `Config.root` onto nothing: see `placeDevice`'s own doc comment for the
/// argument that D never serves a placement before that pivot has already
/// happened, so a sandbox-relative path is the only kind this loop ever
/// needs to resolve.
///
/// **`CAP_SYS_ADMIN` and never `CAP_MKNOD`.** This process makes the
/// placeholder its own bind lands a device on with `mknodat`, and it never
/// makes one with `S_IFCHR` or `S_IFBLK`: see `placeDevice`. Keeping
/// `CAP_MKNOD` out of the set this process holds means a bug that tried to
/// fabricate a device node's own identity would meet `EPERM` from the kernel,
/// not merely a promise this file's own code keeps.
///
/// **What it is permitted afterwards is `seccomp.device_calls` and nothing
/// else.** It cannot open a path of its own choosing, make a socket of any
/// kind, run a program, or signal anything. It can only bind and unbind a
/// path under the one hidden tree `bindDeviceTree` already mounted, onto a
/// sandbox-relative path, both of them checked before they are ever passed
/// to a syscall: see `buildDeviceSource` and `buildDeviceTarget`.
///
/// **A layer that will not go on ends this process rather than weakening
/// it**, the same rule `runRouter`'s own comment states: D can reach the one
/// hidden tree Chock's own policy chose, and running with less than its
/// full confinement is the one outcome that must not happen quietly. Ending
/// it is safe for the session: A is waiting for the readiness byte and
/// reports a setup failure when it does not come.
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

    // Every descriptor but the three this loop uses: the control socket, the
    // device link, and standard error, which stays open for the whole of this
    // process's life so a placement that fails can still say so. See
    // `reportDeviceFault`.
    keepOnlyTheseDescriptors(&.{ ready_fd, link_fd, stderr_fd });

    // **Before any capability is dropped**, the same order `applyLayers`
    // keeps for B's own mount tree: build it while this process still holds
    // every capability it inherited, then narrow. See this function's own
    // top comment for why this runs in D rather than in B.
    var tree_buffer: [device_path_capacity]u8 = undefined;
    if (!bindDeviceTree(&tree_buffer, root, hidden_inside, hidden_host)) linux.exit(1);

    var cap_diag: ?capabilities.Diagnostic = null;
    capabilities.keepOnly(linux.CAP.SYS_ADMIN, &cap_diag) catch linux.exit(1);
    seccomp.install(bpf.Prog.init(insns)) catch linux.exit(1);

    // **The last thing before the loop.** A is blocked on this byte and
    // hands the caller's program a path to open only once it arrives, so
    // nothing the program does can reach a helper that is not there yet.
    //
    // **`write`, and not `sendto`.** `runRouter`'s own readiness byte goes
    // out with `sendto`, because `router_calls` gives N no general `write`
    // at all: a router that could write to a descriptor is a router that
    // could write to one the far side sent it. `device_calls` draws that
    // line differently: `write` is already on it, for `reportDeviceFault`,
    // and `sendto` is not on it at all. Measured on 2026-09-16: a helper
    // that called `sendto` here died at exactly this line with `SIGSYS`,
    // which is what `device_calls`'s own compile time guard cannot catch,
    // because `sendto` is not one of the calls it refuses outright.
    const ready = [1]u8{1};
    const said = linux.write(ready_fd, &ready, ready.len);
    if (linux.errno(said) != .SUCCESS or said != ready.len) linux.exit(1);

    var state = DeviceSeamState{ .hidden = hidden_inside, .stderr_fd = stderr_fd };
    const seam = state.seam();

    while (true) {
        // `ppoll` and never `poll`: `seccomp.device_calls` names only the
        // former. Unlike `router_calls`, which permits whichever one the
        // standard library calls on this architecture, this list is fixed at
        // one, so this loop must call that one directly rather than through
        // `linux.poll`, which resolves to the plain syscall on some
        // architectures and would be killed here.
        var fds = [2]linux.pollfd{
            .{ .fd = link_fd, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = ready_fd, .events = 0, .revents = 0 },
        };
        const ready_rc = linux.ppoll(&fds, fds.len, null, null);
        switch (linux.errno(ready_rc)) {
            .SUCCESS => {},
            // A signal reached this process while it waited. Nothing was
            // lost, so look again rather than end a call over it.
            .INTR => continue,
            else => linux.exit(1),
        }

        // **The link is read first, and A's own end of the control socket
        // second.** The same rule `serveLinks`' own comment states for the
        // real parent's loop, and for the same reason: a placement that
        // arrived in the same look as A's own close must still be placed.
        if (fds[0].revents & linux.POLL.IN != 0) {
            const outcome = devicelink.serveOne(link_fd, seam);
            switch (outcome) {
                // Both are already reported, through `state`'s own call into
                // `reportDeviceFault`: see `DeviceSeamState.placeFn` and
                // `.dropFn`. Nothing more to do here but look again.
                .placed, .place_failed, .dropped, .drop_failed, .nothing => continue,
                // The real parent's own end of the link has gone, which only
                // happens once the sandboxed program has ended: see
                // `serveLinks`'s own comment on when it stops writing here.
                .peer_gone => linux.exit(0),
            }
        }
        // The end of the stream on the link, with nothing to read.
        if (fds[0].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0) linux.exit(0);
        // A closed this end of the control socket to say the call has ended:
        // see `reapDevice`.
        if (fds[1].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0) linux.exit(0);
    }
}

/// Which kind of node `Place.kind` may ask for. **The only one this
/// milestone implements.** `devicelink.DeviceSeam.Result`'s own doc comment
/// names "kind can be a byte the seam does not implement" as one of the
/// ordinary reasons `place` answers `.failed`, and any other value takes
/// exactly that path: see `placeDevice`.
const device_kind_file: u8 = 0;

/// How large a full host path for a placed device may be: generous over any
/// real `Config.root`, which lives under a session's own scratch directory,
/// plus `devicelink.max_path_bytes` for the destination inside the sandbox.
/// Stack allocated, never heap allocated: `seccomp.device_calls` has no
/// `mmap` or `brk` in it, so this process may not grow its own heap once its
/// filter is on.
const device_path_capacity: usize = std.fs.max_path_bytes;

/// What can go wrong placing or dropping a device, named so
/// `reportDeviceFault` can say which step failed. **Never crosses a process
/// boundary**: `devicelink.zig`'s own top comment is explicit that nothing
/// answers back over the link, so this is reported the only other way this
/// process can, `write`, onto the descriptor it is given for that. See
/// `docs/error-handling.md`.
const PlaceError = error{
    /// `Place.kind` named something this helper does not implement.
    UnsupportedKind,
    /// `target` was empty, was not absolute, ended in `/`, carried a `..`
    /// component, or, joined onto `root`, did not fit this helper's own
    /// stack buffer.
    PathUnusable,
    /// A parent directory could not be made.
    MkdirFailed,
    /// The placeholder the bind lands the device on could not be made.
    MknodFailed,
    /// The bind, or the unmount that takes it back out, failed.
    MountFailed,
};

/// Join `root` with `path`, the destination a `Place` or a `Drop` named,
/// into `buffer` as a nul terminated string `mkdirat`, `mknodat`, `mount`'s
/// own "to" side, and `umount2` can all read directly.
///
/// **`root` is `Config.root`, a host path, only before B's own pivot.**
/// `bindDeviceTree` is the one caller that still passes it. Every other
/// caller, `placeDevice` and `dropDevice`, passes `""`, because by the time
/// either of them ever runs, this process's own `/` already is the
/// sandbox's: see `placeDevice`'s own doc comment. An empty `root` makes
/// this function a bounds check over `path` alone, joining nothing in
/// front of it.
///
/// **`path` is bounded and refused, never resolved.** It has to start with
/// `/`, so the join lands under `root` and never beside it; it may not end in
/// `/`, so there is always a leaf component; and it may not carry a `..`
/// component, so it cannot climb back out of the tree this call is scoped
/// to. None of that opens anything: this is a string check against bytes
/// that already crossed the wire, the same division `devicelink.serveOne`
/// itself keeps against its own seam. Null when any check fails, or when the
/// join would not fit `buffer`.
///
/// **Ordinary path resolution beyond this, the same as `namespace.zig`'s own
/// `makePath` keeps for every bind mount's target.** Neither walks its
/// intermediate components with `O_NOFOLLOW`, because neither can: this
/// process holds no descriptor to walk through, only the strings `mount`
/// and `mkdirat` read as names, and those two calls are all
/// `seccomp.device_calls` permits that ever read a target by name.
/// `config.root`'s own tree is this project's, built fresh for the call
/// under way, the same trust `makePath` already places in it.
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

/// Join `hidden` and `source` into `buffer`. **`hidden` is never prefixed
/// with `root` here**: by the time this runs, this process's own `/` is the
/// sandbox's, exactly the same as `namespace.pivotInto` already made B's,
/// so `hidden`, `Config.device_tree.inside`, is already an absolute path
/// this process can resolve directly. See `placeDevice`'s own doc comment
/// for why that is true only after the pivot, and never before it.
///
/// **This is the one new security check the whole path-based redesign turns
/// on.** Descriptor passing used to make a check like this unnecessary: the
/// far side opened the file itself, and this helper only ever placed the
/// descriptor it was handed, never a name it resolved on its own. A path
/// cannot carry that guarantee by itself, so `source` has to be checked
/// before it is ever joined onto `hidden`: a leading `/` would make the join
/// read from `/` directly and ignore `hidden` entirely; a `..` component
/// would climb back out of `hidden` one step at a time; and an empty
/// component, which a leading `/`, a trailing `/`, or a doubled `/` all
/// produce, would resolve to `hidden` itself or skip a directory silently.
/// One loop over every component catches all three, the same way
/// `buildDeviceTarget`'s own loop catches `..` for `target`.
///
/// **`hidden` is not checked here.** It is `Config.device_tree.inside`,
/// chosen by Chock's own host side and never by the far side that sends a
/// `Place`, so it carries the same trust `buildDeviceTarget` already places
/// in `root`. `bindDeviceTree` validates it once, at the one point it is
/// ever turned into a mount.
///
/// Null when `source` fails any of those checks, or when the join would not
/// fit `buffer`, the same contract `buildDeviceTarget` keeps.
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

/// Make every directory `buffer[0..full_len]`'s own parent needs, tolerating
/// one that is already there. **The same loop `namespace.zig`'s own
/// `makePath` walks**, written again here without an allocator: this runs
/// after this helper's own filter is on, and `device_path_capacity`'s own doc
/// comment is why that rules an allocator out. Mutates `buffer` in place and
/// leaves it exactly as it was found: each `/` in turn becomes a nul for the
/// one `mkdirat` call that needs it there, then goes back to a `/` before the
/// walk continues.
fn makeDeviceParents(buffer: []u8, full_len: usize) bool {
    var i: usize = 1;
    while (i < full_len) : (i += 1) {
        if (buffer[i] != '/') continue;
        buffer[i] = 0;
        const rc = linux.mkdirat(linux.AT.FDCWD, @ptrCast(buffer.ptr), 0o755);
        buffer[i] = '/';
        switch (linux.errno(rc)) {
            // `EEXIST` is not a failure here: `mkdir -p` tolerates a
            // directory a previous placement, or `root`'s own tree, already
            // made at this step.
            .SUCCESS, .EXIST => {},
            else => return false,
        }
    }
    return true;
}

/// Bind `host`, the one host directory this call's own device policy chose,
/// onto `root` joined with `inside`, so that a node made in `host` at any
/// point afterward, including after this whole sandbox has started, is
/// visible at that joined path. Spiked end to end before this function was
/// written, in an unprivileged user and mount namespace with a real
/// `pivot_root`: a directory bound in before the pivot shows a node created
/// in it after the pivot, because a bind shows the same live filesystem and
/// not a copy taken at bind time.
///
/// **This runs in D, before B exists, so `root` is still a plain host
/// path here, and it has to be joined.** `namespace.pivotInto`, run later by
/// B, changes what `/` means for every process that shares the namespace,
/// D included, at the instant B's own `pivot_root` call runs: this is a
/// property of `pivot_root` itself and not something either process asks
/// for by name, and it is why `placeDevice` and `dropDevice`, below, both
/// stop joining `root` onto anything. This call is the one exception,
/// because it runs before that instant, not after it. See `placeDevice`'s
/// own doc comment for the measurement and for why the two functions
/// disagree about `root` on purpose.
///
/// **`root` need not already be a mount point of its own for this.** Unlike
/// `pivot_root`, an ordinary bind mount lands on any directory that already
/// exists, mount point or not. Called from `runDevice`, before B has even
/// been forked, so `root` is still only a plain directory on the host disk
/// at this point, and this works regardless.
///
/// True on success. False leaves nothing new mounted, and `runDevice` ends
/// the process rather than serve a call it cannot answer.
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

/// Bind the node at `source`, relative to the hidden tree at `hidden`, at
/// `target`. The real work behind `DeviceSeamState.placeFn`, kept apart
/// from it so a test can call this directly with no fork, no filter, and no
/// `Sandbox.spawn` at all.
///
/// **Neither `hidden` nor `target` is joined onto `Config.root` here, and
/// that is deliberate, not an oversight.** Every call this function makes
/// runs from inside D's own served loop, which never starts until B has
/// already pivoted: `spawn`'s own real parent only calls `serveLinks`,
/// the loop that drains `Config.device_source` and sends what it drains to
/// D, after `readSetupReport` has read end of file with no failure record
/// on it, and B's own copy of that pipe's write end is `CLOEXEC`, held open
/// through the whole of `applyLayers`, including `namespace.pivotInto`, and
/// closed only by B's own `execve`. So by the time any `Place` or `Drop`
/// this function ever answers was even sent, `namespace.pivotInto` has
/// already run, on the one namespace D and B both still share, and
/// `pivot_root` changes what `/` resolves to for every process sharing
/// that namespace, this one included, at the instant it runs: see
/// `pivot_root(2)`'s own manual page, and `namespace.pivotInto`, which this
/// process never calls itself and does not need to. `hidden` and `target`
/// are therefore already sandbox-absolute paths by the time this runs, the
/// same as they are from inside the sandboxed program's own view, and
/// joining `Config.root` onto either one would resolve into whatever the
/// detached old root's own directory of that same name used to hold, which
/// is either nothing or the wrong thing.
///
/// **`bindDeviceTree` is the one exception, and it stays a exception on
/// purpose.** It runs before B is even forked, so `/` has not moved yet
/// when it runs, and joining `Config.root` there is still correct: see its
/// own doc comment.
///
/// **Read-write, and never remounted, on purpose.** `namespace.markReadOnly`
/// also sets `NODEV` on a read only mount, which then refuses to open the
/// device node at all: the same trap that once bit `/dev/null`'s own bind,
/// see `lib/chock-core/tools.zig`. No line below this one ever narrows what
/// the placed mount grants.
///
/// **`mknodat` makes the placeholder, and only ever with `S_IFREG`.**
/// Measured on 2026-09-16, with a raw `mount(2)` call and not only the
/// `mount(8)` command: a bind mount only ever attaches to a target that
/// already exists and already shares the source's own directory-ness, so a
/// character or block device, which is what this helper is for, needs a
/// target that is a file and not a directory before the mount can land on
/// it, and `mkdirat` cannot make one. `mknodat` can, and this call never
/// asks it for anything but `S_IFREG`: see `seccomp.device_calls`'s own doc
/// comment on `mknodat` for the capability that backs this up when the code
/// does not.
///
/// **The bind is named through two paths this call built and checked
/// itself, and never through a descriptor.** A descriptor opened outside
/// this process cannot become a mount inside its own mount namespace at
/// all: see `devicelink.zig`'s own top comment for the measurement. The
/// claim this file can honestly make instead is that the only source ever
/// resolved is one `buildDeviceSource` has already confirmed cannot climb
/// out of the one hidden tree `bindDeviceTree` bound in, and the sandboxed
/// program can neither read that tree nor choose what lives in it.
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

/// Take the node at `path` back out. The real work behind
/// `DeviceSeamState.dropFn`, kept apart from it for the reason `placeDevice`
/// is. **No `root` joined onto `path` here either**, for the same reason
/// `placeDevice` stopped: see that function's own doc comment.
fn dropDevice(buffer: []u8, path: []const u8) PlaceError!void {
    const target = buildDeviceTarget(buffer, "", path) orelse return error.PathUnusable;
    const rc = linux.umount2(target.ptr, 0);
    if (linux.errno(rc) != .SUCCESS) return error.MountFailed;
}

/// Say a placement or a removal failed, on the one descriptor this helper may
/// still write to once its own filter is on. **Never silent**, per
/// `docs/error-handling.md`: `devicelink.zig`'s own wire carries no answer
/// back to the real parent for either outcome, so this is the only place a
/// person reading the session's own log ever learns a device did not arrive.
fn reportDeviceFault(stderr_fd: i32, verb: []const u8, path: []const u8, err: PlaceError) void {
    var line_buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "sandbox: device {s} failed for {s}: {t}\n",
        .{ verb, path, err },
    ) catch return;
    _ = linux.write(stderr_fd, line.ptr, line.len);
}

/// The `devicelink.DeviceSeam` this helper serves `devicelink.serveOne` with.
/// Holds only what `placeDevice`, `dropDevice`, and `reportDeviceFault`
/// need: `hidden`, `Config.device_tree.inside`, read once at fork and never
/// written again, already sandbox-absolute by the time this seam ever
/// serves a placement, because nothing reaches this seam until after B has
/// pivoted: see `placeDevice`'s own doc comment; and `stderr_fd`, the one
/// descriptor left open for the whole of this process's life for exactly
/// the report `placeDevice` and `dropDevice` may need made. **No `root`
/// here.** `bindDeviceTree`, D's own earlier, one time call, is the only
/// place left that still needs it, and it reads `Config.root` directly.
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

/// True when the peer of `fd` has closed its end.
///
/// **`POLLHUP` and not a read.** A read would take a byte the peer might have
/// sent, and nothing is ever sent on this socket after the readiness byte, so
/// a read that returned one would be a message this process cannot explain.
fn peerHasGone(fd: i32) bool {
    var watched = [1]linux.pollfd{.{ .fd = fd, .events = 0, .revents = 0 }};
    const rc = linux.poll(&watched, watched.len, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    return watched[0].revents & (linux.POLL.HUP | linux.POLL.ERR | linux.POLL.NVAL) != 0;
}

/// The monotonic clock the router measures every lifetime on. `BOOTTIME`, so
/// a machine that suspended does not leave a name alive past the moment the
/// kernel forgot its address.
fn monotonicMilliseconds() i64 {
    var now: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &now)) != .SUCCESS) return 0;
    return @as(i64, now.sec) * std.time.ms_per_s +
        @divTrunc(@as(i64, now.nsec), std.time.ns_per_ms);
}

/// Process 1 of the sandbox pid namespace. It reaps orphans until A closes
/// the control socket. It holds no other descriptor and has no capability.
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
/// **These two stay in A.** The descriptors are closed here because A opens a
/// pidfd on itself afterward and gives it to the keeper and B. The namespaces
/// are taken here because `unshare(CLONE_NEWPID)` never moves its own caller.
/// The keeper is the first child made afterward. B runs steps 2 to 6.
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

    // The slot is here for the reason `applyLayers` has one, and for one more:
    // `error.NamespaceFailed` on its own cannot tell a policy that refuses an
    // unprivileged user namespace from a machine that has no room for another
    // one, nor either of those from a map file this process may not write. See
    // `dieNamespace`.
    var diag: ?namespace.Diagnostic = null;
    namespace.enter(.{ .network = config.network, .mount = true }, &diag) catch |err|
        dieNamespace(write_fd, config.stderr_fd, .namespace, err, diag);
}

/// Every layer `applyLayers` puts on the sandboxed program, in the order it
/// puts them on. **The list the comptime check inside that function walks**,
/// so a layer added there and not here is a layer nothing checks the fail mode
/// of.
const applied_by_b = [_]iface.LayerName{
    .mount_tree,
    .pivot_root,
    .capabilities,
    .landlock,
    .session_keyring,
    .seccomp,
};

/// What the sandbox's own resolver is, written where glibc looks for it.
///
/// **The address is the blackhole device's own**, which is the address
/// `router.Options.resolver_address` binds by default. The two are one value
/// and the `comptime` block below is what keeps them one: a resolver bound on
/// an address nothing names would answer nobody, and the failure would read as
/// "the network is down".
///
/// `timeout:1 attempts:2` because the resolver is a process one hop away in
/// the same namespace. The default is five seconds, which is what a program
/// would wait for each query if the router ever stopped answering.
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

/// The name service switch, and **it matters exactly as much as
/// `resolv.conf`**.
///
/// Measured on this project's own machine on 2026-09-14. Its own file reads
/// `hosts: mymachines mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] files myhostname dns`,
/// and `[NOTFOUND=return]` returns from the lookup **before it ever reaches
/// `dns`**. A sandbox that wrote a perfect `resolv.conf` and left that file
/// alone would have a resolver nobody asks anything.
///
/// `files dns` and nothing else: the sandbox's own `/etc/hosts` first, for
/// loopback, and the router second. Every other database answers from files,
/// because there is no directory service inside a sandbox to ask.
const nsswitch_conf =
    "# Written by chock. The sandbox asks its own resolver and nothing else.\n" ++
    "hosts: files dns\n" ++
    "passwd: files\n" ++
    "group: files\n" ++
    "shadow: files\n" ++
    "services: files\n" ++
    "protocols: files\n" ++
    "networks: files\n";

/// Loopback, so a program that reaches for `localhost` does not spend a query
/// on it. The router would refuse it in any case: `localhost` is not a name a
/// policy table names, and the address it would answer with is not one the
/// guard chain carries.
const hosts_file =
    "127.0.0.1\tlocalhost\n" ++
    "::1\tlocalhost ip6-localhost ip6-loopback\n";

/// The three files the sandbox writes for itself, the trust store link, and
/// the two directories it hides, applied by `applyLayers` for a routed call.
///
/// **The two hidden paths are not optional and are easy to leave out.**
/// Measured on 2026-09-14: `/run/nscd/socket` is an `AF_UNIX` socket, so a
/// network namespace does not touch it. glibc asks nscd before it reads
/// `resolv.conf` at all, nscd answers from the **host's** view of the network,
/// and the sandbox's own resolver is never consulted. A first end to end run
/// failed exactly that way with the ruleset loaded and the files correct.
///
/// Both spellings of the path are named, because `/var/run` is a symbolic link
/// to `/run` on most machines and a real directory on some, and glibc has used
/// each of the two over time.
///
/// Where a client that never heard of `SSL_CERT_FILE` looks for a trust
/// store on its own. `lib/chock-core/tools.zig` stages the host's bundle at
/// `iface.trust_store_inside`; the entry below is a symbolic link to that
/// path and never a copy of its own, so the two always name the same bytes.
///
/// **Two directories under `/etc`, and not a direct child of it.** Nothing
/// else this file places is nested this way, which is what the broadened
/// `comptime` check below is for: see that check's own comment.
const trust_store_link_target = "/etc/ssl/certs/ca-certificates.crt";

/// **Public because `src/doctor.zig` reads the same list**, and says which of
/// the two ways a routed sandbox on this host places these files: into an
/// `/etc` it makes itself, or into one it takes from the host with
/// `namespace.ownDirectory`. Neither answer blocks a session.
pub const resolver_substitutions = [_]namespace.Substitution{
    .{ .text = .{ .target = "/etc/resolv.conf", .contents = resolv_conf } },
    .{ .text = .{ .target = "/etc/nsswitch.conf", .contents = nsswitch_conf } },
    .{ .text = .{ .target = "/etc/hosts", .contents = hosts_file } },
    .{ .link = .{ .target = trust_store_link_target, .link_to = iface.trust_store_inside } },
    .{ .hide = "/run/nscd" },
    .{ .hide = "/var/run/nscd" },
};

/// The `text` targets of `resolver_substitutions`, which is what
/// `ownDirectory` takes away before `substitute` writes them again, and the
/// list `applyLayers` grants a Landlock read rule to below.
///
/// **The `link` entry is not one of these, on purpose.** `ownDirectory`'s
/// removal is for a name `substitute` is about to write straight over, and
/// `placeLink` already clears whatever is at its own target itself. The
/// Landlock rule the link needs is the one already granted on
/// `iface.trust_store_inside`, the file it points at: Landlock checks the
/// resolved file a read reaches and not the link's own name, so a second
/// rule on the link would permit nothing a program could not already reach.
///
/// Built from that list, so a file added to it is a file this removes, and
/// neither list can be edited without the other following.
const resolver_text_targets = blk: {
    var targets: []const []const u8 = &.{};
    for (resolver_substitutions) |one| switch (one) {
        .text => |text| targets = targets ++ [_][]const u8{text.target},
        .link => {},
        .hide => {},
    };
    break :blk targets;
};

/// The directory a routed sandbox takes for itself, so that it can write the
/// files above into it. See `namespace.ownDirectory` for what taking it
/// means and what it costs.
///
/// **`/etc` and nothing else.** That is where glibc looks for a resolver, and
/// it is the one directory a sandbox both needs to write and does not own on
/// an ordinary Linux machine. The `comptime` block below is what keeps the two
/// facts together: a target added anywhere outside `/etc` would be a file
/// this sandbox still could not place, and the build stops rather than the
/// session.
const owned_etc = namespace.OwnedDirectory{
    .target = "/etc",
    .remove = resolver_text_targets,
};

comptime {
    for (resolver_substitutions) |one| {
        // **Every target, not only the `text` ones, and inside `/etc`
        // rather than directly in it.** `trust_store_link_target` sits two
        // directories under `/etc`, not directly in it, so this checks a
        // prefix and not the exact directory `owned_etc.target` names. A
        // `hide` names no target of its own: there is nothing here to
        // write, so nothing to check.
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

/// Steps 2 to 6 of the order above, in B, the process that runs the caller's
/// program. **The mount tree is built here and not in A**, because a procfs
/// mount takes the pid namespace of whichever process makes it. See the
/// comment on B's fork in `spawn`. A puts its own two layers on afterward in
/// `restrictMiddle`.
fn applyLayers(
    allocator: std.mem.Allocator,
    config: Config,
    abi: i32,
    insns: []const bpf.Insn,
    write_fd: i32,
    notify_fd: i32,
) void {
    // **Every step below ends the process, and the fail mode table has to
    // agree.** This function has no path that runs on without a layer, and it
    // must not grow one: B is the caller's own program, and a tool call that
    // ran with a layer quietly missing is the one state the whole design
    // refuses. So the table is read here as a constraint rather than as a
    // switch. An edit that gave one of these layers `open` for the sandboxed
    // process stops this file compiling, which is the loudest a data field can
    // be about code that would then be wrong.
    //
    // It is stated here and not derived into a branch on purpose: writing a
    // runtime `open` arm for B would be adding a fail open path to the
    // sandboxed process to make a field look load bearing. See
    // `restrictMiddle`, which does derive, because it really has both.
    comptime {
        for (applied_by_b) |layer| {
            if (iface.failModeFor(.sandboxed, layer) != .closed) @compileError(
                "sandbox: applyLayers ends the process on every fault, so every layer it " ++
                    "applies must fail closed",
            );
        }
    }

    // One slot for both calls: `note` keeps the first fault, and a pivot can
    // only fail after a mount tree that did not, so the first is the one that
    // explains the rest.
    var diag: ?namespace.Diagnostic = null;
    namespace.buildRoot(allocator, config.root, config.mounts, &diag) catch |err|
        dieNamespace(write_fd, config.stderr_fd, .mount_tree, err, diag);

    // **The resolver files, after the whole mount tree and before the pivot.**
    // After, so a bind the caller asked for cannot cover them and so a `/etc`
    // that came from the host is already there to be covered. Before, because
    // every path below is written relative to `config.root`, which stops being
    // a path at all the moment this process pivots into it.
    //
    // **Only for a routed call**, and a call with no router makes none of
    // these calls at all: a sandbox with no network of its own has no resolver
    // to name, and rewriting a machine's `nsswitch.conf` for a program that
    // cannot reach anything would be a change with no purpose.
    if (config.net_router != null) {
        // **First the directory, then the files in it.** On a machine whose
        // sandbox binds the host's own `/etc`, `substitute` can neither cover
        // a target that is a symbolic link nor make one that is absent, and
        // between them those two cover most Linux machines that are not
        // NixOS. This takes `/etc` for the sandbox and takes the three names
        // out of it, so `substitute` finds nothing there and writes a real
        // file. A sandbox that holds no `/etc` at all, which is every machine
        // with Nix, gets `false` back and is unchanged.
        _ = namespace.ownDirectory(allocator, config.root, owned_etc, &diag) catch |err|
            dieNamespace(write_fd, config.stderr_fd, .mount_tree, err, diag);

        namespace.substitute(allocator, config.root, &resolver_substitutions, &diag) catch |err|
            dieNamespace(write_fd, config.stderr_fd, .mount_tree, err, diag);
    }

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

    // **A routed sandbox grants read on the resolver it placed itself.**
    // `substitute` above writes these files, this driver chooses their paths,
    // and nothing in `config.rules` names them. A caller cannot be asked to
    // grant access to files it does not place: it would have to know a path
    // that is this driver's own, and every caller would have to remember.
    //
    // **Without this a routed sandbox has a working router that no program
    // can use.** glibc finds the resolver's address in `/etc/resolv.conf` and
    // nowhere else, so a name lookup fails for every ordinary program while
    // the router, the ruleset and the netns are all fine. Measured
    // 2026-09-18: `cat /etc/resolv.conf` answered `EACCES` inside a routed
    // tool call, and a real session read that as "failed to resolve address",
    // which is several steps from its cause.
    //
    // **Read and nothing else.** The sandboxed program has no business
    // writing what the router told it, and `read_only` would add the execute
    // right to three text files for no reason.
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

    // **The filter and the handover are one step, and nothing may run between
    // them.** `execve` is in the trap set, so this process's own `execve` is
    // held by the kernel until a supervisor answers it. `notify.handOver`
    // gives the notification descriptor to A and waits for A to say it holds
    // it. Every call that runs in that window is named in
    // `seccomp.bootstrap_calls`, which no trap set can hold. See `notify.zig`.
    const listener = seccomp.installListening(bpf.Prog.init(insns)) catch |err|
        die(write_fd, config.stderr_fd, .seccomp_install, err);

    // **A "no" ends this process rather than letting it run on.** A filter
    // whose listener nobody holds makes the kernel answer every observed call
    // with `ENOSYS`, so the caller's program would be told that `openat` does
    // not exist. A setup failure names the step instead.
    if (!notify.handOver(notify_fd, listener))
        die(write_fd, config.stderr_fd, .notify_handover, error.Unexpected);
}

/// The path reader A forked, and the page it writes. See `runReader`.
const ReaderWatch = struct {
    pid: linux.pid_t,
    record: *notify.PathRecord,
};

/// Make the page the path reader and this process share.
///
/// **`MAP_SHARED` and anonymous.** Anonymous, so it has no name anywhere and
/// the sandboxed program cannot ask for it by one. Shared, so a write by the
/// reader is a write this process reads. Null when the kernel refused, which
/// turns the path audit off for this call and leaves everything else working.
fn mapPathRecord() ?*notify.PathRecord {
    // Zig 0.16's `linux.mmap` takes the flags as packed structs. The plain
    // numbers are what the kernel's own header calls `MAP_SHARED` and
    // `MAP_ANONYMOUS`, and `probe.zig` reads them the same way.
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

/// Wait for the path reader, say whether it reported a complete record, and
/// report the counts it made.
///
/// **The report is the reader's own `ended`, and never its exit status.** The
/// reader watches the observed program's own process descriptor as well as the
/// notification descriptor, so the program's end wakes it, its loop returns,
/// and it writes `ended` into the shared page before it exits. The keeper is
/// process 1, so the observed program's exit does not kill the reader.
/// A missing report therefore means the reader ended early.
fn reapReader(watch: ReaderWatch, middle_write_fd: i32) void {
    var status: u32 = undefined;
    // B can stop R before B exits. Resume R after B is reaped so it can read
    // the pidfd and report. A fixed bound prevents a stopped or hostile reader
    // from holding teardown forever. The pid cannot be reused before this wait.
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

    // The same route the counts always took. See `reportTraps`.
    reportTraps(middle_write_fd, &watch.record.counts);
}

/// What the supervisor knows about one reader when it reaps it.
pub const ReaderEnd = struct {
    /// `PathRecord.ready`, as the reader wrote it.
    ready: u32,
    /// `PathRecord.ended`, as the reader wrote it.
    ended: u32,
    /// How the reader's own process came to an end.
    ending: Ending,

    /// **A union and not a status number beside a flag.** The kernel's own
    /// wait status carries an exit code only for a process that ended itself,
    /// and `W.EXITSTATUS` of a status that names a signal is zero. A rule
    /// written on that number alone would read "killed by SIGKILL" as "exited
    /// cleanly" by accident rather than on purpose, and no test could tell the
    /// two apart.
    pub const Ending = union(enum) {
        /// The reader ended itself, with this status.
        exited: u32,
        /// A signal ended the reader.
        signalled,
        /// The wait gave back no status at all.
        unknown,
    };
};

/// True when the reader reported a complete record.
///
/// **Pure, so the rule can be checked without forking anything.** Every input
/// is something the supervisor already holds when it reaps, and the two that
/// come out of the shared page are untrusted: the reader writes them, and a
/// reader that never ran leaves them at zero. See `ReaderEnd`.
pub fn readerReported(end: ReaderEnd) bool {
    if (end.ready == 0) return false;
    // **The positive fact, and the reason the way the reader died is not it.**
    // The reader writes this the instant its loop returns, and the teardown
    // kill can land between that write and the reader's own `exit`.
    if (end.ended == 0) return false;
    return switch (end.ending) {
        // A non zero status is the reader's own loop saying it hit something
        // it could not carry on from, so the record may be short even though
        // the loop returned.
        .exited => |status| status == 0,
        // A signal after `ended` cannot make the completed record short.
        .signalled => true,
        // Nothing was read back, so there is nothing to believe.
        .unknown => false,
    };
}

/// The path reader, R. Never returns.
///
/// **Confines itself before it reads anything**, and in this order: every
/// descriptor but the two it was given, then every capability but the one its
/// read needs, then a seccomp allowlist. Only then does it touch the
/// notification descriptor. It puts no Landlock ruleset on itself, and the
/// body below says why that is a measurement rather than an oversight.
///
/// What it is permitted afterwards is `seccomp.reader_calls` and nothing else:
/// `process_vm_readv`, `ioctl`, a wait, and the calls a process needs to end.
/// It cannot open a path, make a socket, or write a byte to any descriptor.
///
/// **It does hold a copy of this program's own memory, and that is the one
/// thing here that is not closed.** The reader is a fork of the supervisor,
/// which is a fork of the process that holds the caller's provider credential,
/// so that credential is in the reader's address space the way it is in the
/// supervisor's. Nothing here can scrub it: this code does not know where it
/// is. What is closed instead is every way out. The reader holds two
/// descriptors, neither of which it may write to; it may not open a path, make
/// a socket, or signal a process; and the sandboxed program cannot read the
/// reader's memory either, because `process_vm_readv` and `ptrace` are both on
/// `seccomp.blocked_calls`. A reader is worth attacking only for what it can
/// then do, and it can do nothing.
///
/// **A layer that will not go on ends this process rather than weakening it.**
/// The reader's whole reason to exist is that it may make a call every other
/// process here is killed for making, so a reader running with less than its
/// full confinement is the one outcome that must not happen quietly. Ending it
/// is safe for the session: A has already given up the listener, so the kernel
/// answers the observed program's held calls with `ENOSYS`, and `ready` stays
/// zero in the record so the session log says the paths are missing.
fn runReader(
    listener: i32,
    child_pidfd: i32,
    reader_insns: []const bpf.Insn,
    record: *notify.PathRecord,
    granted: []const []const u8,
) noreturn {
    keepOnlyDescriptors(listener, child_pidfd);

    // **One capability is kept, and only one.** `CAP_SYS_PTRACE` in the
    // sandbox's own user namespace is what lets this process read the observed
    // program's memory at all under Yama's restricted ptrace mode, which is
    // the default on this project's machine. It is held in a namespace made a
    // moment earlier that owns nothing of the host's, and the filter below
    // names no call a capability could otherwise be spent on. See
    // `capabilities.keepOnly`.
    var cap_diag: ?capabilities.Diagnostic = null;
    capabilities.keepOnly(linux.CAP.SYS_PTRACE, &cap_diag) catch linux.exit(1);

    // **No Landlock ruleset of its own, and that is a measurement and not an
    // oversight.** Landlock has a rule about `ptrace`: a process in a domain
    // may only reach a process whose domain is that same domain or one nested
    // inside it. The reader is forked by the supervisor and the observed
    // program builds its own domain, so the two domains are siblings and
    // neither one contains the other. Measured on 2026-09-11: a reader that
    // put an empty ruleset on itself read nothing at all, and every path came
    // back in the record's `unread` count.
    //
    // **It costs the reader nothing, because the filter above already denies
    // more.** `seccomp.reader_calls` names no call that opens a path, makes a
    // socket, or writes a byte, so there is no file operation for a Landlock
    // rule to refuse. Landlock bounds which paths a process may reach. This
    // process may reach none, because it cannot ask.
    seccomp.install(bpf.Prog.init(reader_insns)) catch linux.exit(1);

    // **Set after the layers and before the loop.** A zero here is the fact
    // that says the reader never got as far as watching anything.
    record.ready = 1;
    const outcome = notify.serveRecording(listener, child_pidfd, record, granted);
    record.ended = 1;
    linux.exit(if (outcome == .fault) 1 else 0);
}

/// Close every descriptor this process holds except the two named.
///
/// **Before the filter goes on, because `close_range` is not on the reader's
/// allowlist.** The reader is left holding exactly two descriptors, so the
/// `ioctl` its filter permits can reach the notification descriptor and the
/// liveness handle and nothing else. `closeInheritedFds` already ran in A, so
/// what is left here is A's own working set: the middle pipe, the caller's
/// output descriptors, and the scratch areas.
fn keepOnlyDescriptors(first: i32, second: i32) void {
    keepOnlyTheseDescriptors(&.{ first, second });
}

/// The same, for a caller that has to keep more than two. **At most eight**,
/// which is more than any process here holds: the router keeps five and the
/// reader keeps two.
///
/// The list is sorted first and the gaps between its members are closed one
/// range at a time, so the caller may pass its descriptors in whatever order
/// it happens to hold them. A repeated number is harmless: the range between a
/// number and itself is empty.
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
///
/// **Printed and also recorded.** The printed line reaches a terminal and dies
/// with it, so nothing could answer afterwards whether the process holding the
/// provider credential ran with no filter on it. A cannot write the session
/// log itself: `closeInheritedFds` revoked that descriptor before any of this.
/// So the answer goes back on the middle pipe, and the real parent, which does
/// hold the log, counts it. See `tag_middle_filter` and
/// `iface.SupervisorAudit`.
fn restrictMiddle(abi: i32, insns: []const bpf.Insn, middle_write_fd: i32) void {
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

    // **The line first and the record second**, so the behaviour a person sees
    // is the behaviour they always saw, and the record is added behind it.
    // Written whichever way the install went: see `tag_middle_layer`.
    if (seccomp.install(bpf.Prog.init(insns))) |_| {
        middleLayerWent(.seccomp, middle_write_fd, null);
    } else |err| {
        printMiddleFault(err, null);
        middleLayerWent(.seccomp, middle_write_fd, filterFaultFor(err));
    }
}

/// What A does about a layer of its own that would not go on.
///
/// **The fail mode is read from `iface.failModeFor` and never from the shape
/// of this file.** The whole point of that table is that a reader, a report
/// and the log all learn the answer from one value instead of following a call
/// graph. Reading it here is what stops the value from drifting away from the
/// behaviour it names: change the table and this function compiles to
/// something else.
///
/// **`comptime`, so there is no unreachable branch in A.** The switch is
/// resolved when this file is compiled, so the arm that does not apply is
/// never analysed and never emitted. A `.closed` entry would make A end the
/// same way any other relay fault ends it.
fn middleLayerWent(
    comptime layer: iface.LayerName,
    middle_write_fd: i32,
    fault: ?iface.SupervisorAudit.Fault,
) void {
    const mode = comptime iface.failModeFor(.supervisor, layer) orelse @compileError(
        "sandbox: the supervisor reports a layer the fail mode table says it never applies",
    );
    switch (comptime mode) {
        // Counted and printed, and the process goes on. See `restrictMiddle`'s
        // own doc comment for why ending A here would cost the caller the
        // running program for nothing.
        .open => reportMiddleLayer(middle_write_fd, layer, fault),
        .closed => {
            reportMiddleLayer(middle_write_fd, layer, fault);
            if (fault != null) dieRelay(error.Unexpected);
        },
    }
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
/// `middle_write_fd`, `stdout_fd`, `stderr_fd`, `stdin_fd`, `broker_fd`, and
/// `device_fd`, so a descriptor opened before
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
/// `middle_write_fd` is the second pipe, and it is the one exemption this
/// pass gained after the fact, so the reason is written down rather than left
/// to be guessed at. **It could not be avoided by making the pipe later.** The
/// real parent has to hold the read end, so the pipe has to exist before the
/// fork, and every fact it carries is knowable only after this process has
/// already given up its own end of the setup pipe. So this process keeps the
/// write end through every layer and writes two short records on it, in
/// `restrictMiddle` and in `waitAndRelay`. It reaches nothing: a pipe has no
/// name in any filesystem, both ends are `CLOEXEC` so the sandboxed program's
/// own `execve` drops its copy, and the only thing ever written on it is the
/// fixed records this file chooses. Compare `joinCgroup`, which closes its
/// descriptor before this pass on purpose, because it could.
///
/// `broker_fd` and `device_fd` are each a seam's own child end, made in the
/// real parent before this process forked from it and carried across that
/// fork like any other descriptor. **Both must survive this pass, and each
/// for its own child to inherit later.** `broker_fd` is `execute`'s own copy
/// for B; `device_fd` is D's own copy of `device_fds[1]`, and D does not
/// exist yet when this pass runs, so the number has to survive here or D
/// forks with nothing open on it at all. `-1` when a call names no such seam,
/// which this pass already treats as a fd number nothing here has.
///
/// **Measured on 2026-09-16: a session with a device source and no filtered
/// network passed `-1` for this parameter before it had one of its own.**
/// `device_fds[1]` was open in A at the time this pass ran and closed by it
/// anyway, because nothing on the exception list named it. D, forked from A
/// afterward, inherited a fork of A's own descriptor table, which by then had
/// nothing at that number: `poll` answered `POLLNVAL` for it forever, and the
/// real parent's own `sendmsg` on the paired end answered `EPIPE`, because the
/// kernel counts a socket's peer as gone once every copy of the other end is
/// closed. Nothing D did was ever wrong; the descriptor it was told to use had
/// already gone before D could open it, let alone use it.
///
/// This runs before any namespace or mount is set up, while `/proc` still shows
/// the host's view of this process's own descriptor table. The sandbox's mount
/// tree is never required to carry its own `/proc` mount for this to work.
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
                // descriptors, the broker or router pair's child end, and the
                // device link's own child end. Every other descriptor is one
                // the parent held before this process was ever meant to run.
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

/// Arm `PR_SET_PDEATHSIG` in a child of A and close the one race that makes it
/// unreliable on its own. Both the keeper and B use this function.
///
/// The kernel delivers a process's death signal exactly once, at the moment
/// `exit_notify` runs for its parent, A. If A already died before this
/// process reached the `prctl` call below, that moment already passed with no
/// signal armed, and none will ever come: arming it now only sets up delivery
/// for whichever process A's death left as this process's new, effectively
/// invisible, parent.
///
/// `getppid` cannot reveal that A is already gone. This process is about to
/// enter a pid namespace A is not a member of, and a pid
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

test "the middle pipe carries the scratch fact and a layer fact, and a reader tells them apart" {
    // **The record format itself, writer against reader.** Before this, the
    // pipe carried one unframed byte with one meaning, so a second fact could
    // not be added without a reader that could tell two records apart. Both
    // records go in here, in the order A writes them, and both come back.
    //
    // Mutation check: make `readMiddleReport` stop after the first record and
    // the scratch fact is lost, because A writes the layer records first.
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    defer _ = linux.close(fds[0]);

    reportMiddleLayer(fds[1], .seccomp, .no_new_privs_refused);
    writeMiddleRecord(fds[1], tag_scratch_full, 0, 1);
    // The reader stops at end of file, and only the writer's own close gives
    // it one.
    _ = linux.close(fds[1]);

    const report = readMiddleReport(fds[0]);
    try std.testing.expect(report.scratch_full);
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome{ .off = .no_new_privs_refused },
        report.layers.get(.seccomp),
    );
    // **The slot is what tells one layer's answer from another's.** A reader
    // that ignored it would read the seccomp record as the answer for every
    // layer A puts on itself, which is how a refused Landlock ruleset comes to
    // read as a filter that would not install.
    //
    // Mutation check: write slot 0 for every layer in `reportMiddleLayer` and
    // this fails, because the capability record then lands on `.mount_tree`.
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome.unsaid,
        report.layers.get(.landlock),
    );
}

test "each layer the supervisor puts on itself comes back under its own name" {
    // The three records A really writes, together, read back apart. Before
    // this the pipe carried the filter alone, so the capability drop and the
    // Landlock ruleset reached a terminal and died with it.
    //
    // Mutation check: drop the slot byte from `reportMiddleLayer` and all
    // three answers land on one layer, so two of the three expectations fail.
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
    // **The third answer, and the reason the filter record is written both
    // ways.** A tool call a person cancelled kills A before it reaches
    // `restrictMiddle`, so nothing is written at all. Reading that as "the
    // filter went on" would count a call that was never measured as a call
    // that passed, which is the shape of the vacuous test this project has
    // been caught by before.
    //
    // Mutation check: give `MiddleReport.layers` a default of `.on` and this
    // fails; `readMiddleReport` never writes the field for an empty pipe.
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
    // **The distinction `seccomp.InstallError` was split to carry.** Before
    // that split every failure was `error.Rejected`, and a record that said so
    // would have named the wrong repair for four faults out of five. This pins
    // that the split survives the pipe: each error is a fault of its own, no
    // two share a value byte, and none of them arrives as `.on`.
    //
    // Mutation check: map two of the errors to the same member of
    // `FilterFault` in `filterFaultFor` and the `expect` on distinctness
    // fails.
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

        // Byte 1 is the slot, which names the layer, and the value starts at
        // byte 2. See `record_bytes`.
        try std.testing.expectEqual(
            @as(u8, @intFromEnum(iface.LayerName.seccomp)),
            record[1],
        );
        const value = std.mem.readInt(u64, record[2..record_bytes], .little);
        switch (outcomeFor(@truncate(value))) {
            .off => |fault| seen[index] = fault,
            // A filter that went on, or nothing said at all, for an install
            // that failed. Either one would make the whole record worthless.
            .on, .unsaid => return error.TestUnexpectedResult,
        }
    }
    _ = linux.close(fds[1]);

    for (seen, 0..) |fault, index| {
        for (seen[index + 1 ..]) |other| try std.testing.expect(fault != other);
    }
}

test "a layer that went on is the only value byte that reads as confined" {
    // The other half of the record's meaning. `reportMiddleLayer(fd, l, null)`
    // is what A writes when the install worked, and nothing else may read that
    // way, including a fault code from a build this one has never seen.
    //
    // Mutation check: return `.on` for the unrecognised value in `outcomeFor`
    // and the last case here fails.
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
        closeInheritedFds(-1, -1, -1, -1, null, -1, -1);

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

test "closeInheritedFds keeps exactly the middle pipe's write end, and no other" {
    // The middle pipe is the one exemption this pass gained after it was
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
    // Mutation check: drop `middle_write_fd` from the guard and `extra_b` is
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
    // The regression test for the fault task 4b's own end to end device
    // placement test found: `device_fd` named no exemption at all before this,
    // so A closed its own copy of `device_fds[1]` here, before D, forked from
    // A afterward, could ever inherit an open one. D's own `link_fd` then
    // named a descriptor nothing in D's fd table held: `poll` answered
    // `POLLNVAL` for it on every turn of D's own loop, and the real parent's
    // `sendmsg` on the paired end answered `EPIPE`, because a `SOCK_SEQPACKET`
    // pair with no process left holding the far end is exactly what `EPIPE`
    // means. See `closeInheritedFds`'s own doc comment.
    //
    // Mutation check: drop `device_fd` from the guard in `closeInheritedFds`
    // and `extra_b` is closed, which fails the second assertion. Widen the
    // guard to keep anything more, and `extra_a` survives and fails the first.
    const extra_a = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_a));
    const extra_b = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_b));
    defer _ = linux.close(@intCast(extra_a));
    defer _ = linux.close(@intCast(extra_b));

    // A forked child, for the reason every test around this one states: this
    // call ends the process on any internal failure and would otherwise close
    // the test runner's own descriptors.
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

test "a filtered config that names both seams is refused, and one that names a router outside filtered too" {
    // **The two seams are two implementations of one mode and never both at
    // once.** They want opposite things from one seccomp rule: the netbroker
    // needs `connect` refused, because it hands a descriptor from the host's
    // own network namespace across the boundary, and the router needs
    // `connect` permitted, because a program reaching a permitted host is the
    // whole mechanism. A driver that quietly picked one would give the other a
    // sandbox that does not do what its field says. See `seccompOptionsFor`.
    //
    // The refusal comes before `probeAbi`, before any filter is built and
    // before any fork, so this test needs no root, no mount and no program.
    //
    // Mutation check: drop either new arm of the switch in `spawn` and one of
    // the calls below comes back with something other than the error it names.
    var report: LandlockReport = undefined;

    const Never = struct {
        fn connect(_: *anyopaque, _: []const u8, _: u16) iface.NetBroker.Grant {
            // Never reached: every call below refuses before it forks.
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

    // And a router on a config that is not filtered, which has nothing to
    // route: the same rule the netbroker has, for the same reason.
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
    // **The dependency a placement has on a hidden tree of its own used to be
    // implicit.** `buildDeviceSource` only has something to join a `source`
    // onto once `Config.device_tree` names one, and a config that named
    // `device_source` with no `device_tree` would only discover that once a
    // real device arrived, as `MountFailed`, with the missing field never
    // named anywhere in the error.
    //
    // The refusal comes before `probeAbi`, before any filter is built and
    // before any fork, so this test needs no root, no mount and no program.
    //
    // Mutation check: drop the check this test pins and this call comes back
    // with `LandlockUnavailable` or worse, a real attempt to fork, instead of
    // `DeviceSourceNeedsTree`.
    var report: LandlockReport = undefined;

    const Never = struct {
        fn wakeup(_: *anyopaque) i32 {
            // Never reached: the call below refuses before it forks.
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

    // The other side of this check, a `device_source` with a `device_tree`
    // going on to place a device successfully, is not pinned here: clearing
    // this check lets `spawn` go on to fork and build a real sandbox, which
    // needs the same root and `probeAvailability` guard the full end to end
    // tests already carry. `escape.zig`'s device tests are that proof.
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
    try std.testing.expectEqual(linux.SIG.KILL, linux.W.TERMSIG(status));

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

test "a reader killed after it reported is still a reader that reported" {
    // A signal can land after the reader wrote `ended` and before its exit.
    // The record is complete at that point. The wait status cannot undo the
    // positive report in shared memory.
    //
    // Mutation check: change the `.signalled` arm of `readerReported` to
    // `false` and this first expectation fails. **Measured first with the
    // status carried as a plain number beside a flag, where deleting that same
    // arm changed nothing at all**, because `W.EXITSTATUS` of a signal status
    // is zero and the clean exit arm answered for it by accident. That is why
    // `ReaderEnd.Ending` is a union.
    try std.testing.expect(readerReported(.{
        .ready = 1,
        .ended = 1,
        .ending = .signalled,
    }));
    // The ordinary healthy shape is a clean reader exit.
    try std.testing.expect(readerReported(.{
        .ready = 1,
        .ended = 1,
        .ending = .{ .exited = 0 },
    }));
}

test "a reader that never started, never ended, or faulted reported nothing" {
    // The four ways a report is missing, each pinned on its own, because each
    // one is a different repair. **A reader that never ran leaves every field
    // at zero**, and that must never read as a clean run.
    //
    // Mutation check: delete the `ready` line, delete the `ended` line, change
    // the `.exited` arm to `true`, or change the `.unknown` arm to `true`, and
    // the matching expectation below fails.
    try std.testing.expect(!readerReported(.{
        .ready = 0,
        .ended = 0,
        .ending = .{ .exited = 0 },
    }));
    // **The one that catches a program killing its own reader.** The reader
    // was killed before its loop returned, so it wrote no report.
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
    // **Every number out of the shared page is untrusted input.** `ready`
    // alone is not a report, and a rule that believed it would call a reader
    // killed in its first instant a complete one.
    //
    // Mutation check: make `readerReported` give back `end.ready != 0` and
    // this fails.
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

    // A root with no trailing slash and a path with a leading one, joined
    // with nothing in between and nul terminated: this is what every later
    // `mkdirat`, `mknodat`, `mount`, and `umount2` call in this file reads.
    try std.testing.expectEqual(@as(u8, 0), joined.ptr[joined.len]);

    // Mutation check: drop the `path[0] != '/'` half of the guard and this
    // answers a joined string instead of null.
    try std.testing.expect(buildDeviceTarget(&buffer, "/tmp/chock-session", "dev/chock-widget0") == null);
    // Mutation check: drop the `path.len <= 1` half and an empty path joins
    // onto bare `root`, which names the session's own directory and not a
    // device inside it.
    try std.testing.expect(buildDeviceTarget(&buffer, "/tmp/chock-session", "/") == null);
    // A path with no leaf: `mount`'s own target would be `root` again.
    try std.testing.expect(buildDeviceTarget(&buffer, "/tmp/chock-session", "/dev/") == null);

    // Mutation check: delete the `..` component check and this answers a
    // string that climbs back out of `root` entirely.
    try std.testing.expect(buildDeviceTarget(&buffer, "/tmp/chock-session", "/../etc/passwd") == null);
    try std.testing.expect(buildDeviceTarget(&buffer, "/tmp/chock-session", "/dev/../../etc/passwd") == null);

    // Mutation check: drop the capacity check and this overruns `small`.
    var small: [8]u8 = undefined;
    try std.testing.expect(buildDeviceTarget(&small, "/tmp/chock-session", "/dev/chock-widget0") == null);
}

test "buildDeviceSource joins hidden and source, and refuses a source that escapes the hidden tree" {
    // **This is the one new security check the whole path-based redesign
    // turns on.** Tested directly with `..`, with an absolute path, and with
    // an embedded `../`, exactly as the task that introduced this function
    // required. See `buildDeviceSource`'s own doc comment for why descriptor
    // passing used to make this check unnecessary and a path cannot.
    var buffer: [device_path_capacity]u8 = undefined;

    const joined = buildDeviceSource(&buffer, "/.chock-device-tree", "bus/usb/001/005") orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(
        "/.chock-device-tree/bus/usb/001/005",
        joined,
    );
    try std.testing.expectEqual(@as(u8, 0), joined.ptr[joined.len]);

    // Mutation check: drop the `part.len == 0` half of the component check
    // and a leading `/`, a trailing `/`, or a doubled `/` all join onto a
    // path this function must refuse.
    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "/etc/passwd") == null);
    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "bus/usb/") == null);
    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "bus//005") == null);
    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "") == null);

    // Mutation check: drop the `std.mem.eql(u8, part, "..")` half and a `..`
    // component, alone or embedded, climbs back out of the hidden tree.
    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "..") == null);
    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "bus/../../etc/passwd") == null);
    try std.testing.expect(buildDeviceSource(&buffer, "/.chock-device-tree", "../etc/passwd") == null);

    // Mutation check: drop the capacity check and this overruns `small`.
    var small: [8]u8 = undefined;
    try std.testing.expect(buildDeviceSource(&small, "/.chock-device-tree", "bus/usb/001/005") == null);
}

test "makeDeviceParents makes every directory a path needs, and tolerates one already there" {
    // Raw syscalls through `tmp.dir.handle` throughout, the same rule this
    // whole file follows: `std.Io.Dir`'s own methods need an `Io` this file
    // does not carry. See the comment above `namespace.zig`'s own `makePath`.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    var buffer: [device_path_capacity]u8 = undefined;
    const target = buildDeviceTarget(&buffer, root_z, "/dev/sub/chock-widget0") orelse
        return error.TestUnexpectedResult;

    try std.testing.expect(makeDeviceParents(&buffer, target.len));
    // "dev" and "dev/sub" now exist, and the leaf itself does not: this
    // function only ever makes what `path`'s own parents need, and leaves
    // the leaf to `mknodat`.
    const sub_rc = linux.openat(tmp.dir.handle, "dev/sub", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(sub_rc));
    _ = linux.close(@intCast(sub_rc));
    const leaf_rc = linux.openat(tmp.dir.handle, "dev/sub/chock-widget0", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.NOENT, linux.errno(leaf_rc));

    // Mutation check: turn the `.EXIST` tolerance into a failure and this
    // second call, over the same directories the first one just made,
    // answers false instead of true.
    try std.testing.expect(makeDeviceParents(&buffer, target.len));
}

test "placeDevice binds a device read-write out of a hidden tree, once this process has pivoted the way B does, and a read only remount is the trap it must never repeat" {
    // **No hardware.** A named temp file stands in for a device node. Naming
    // it is a convenience for this test, not a requirement `placeDevice`
    // itself has.
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

        // A directory outside `root_z` entirely, standing in for the one
        // real host directory Chock's own policy would bind: `root_z`
        // becomes the sandbox's own filesystem view, and this must never be
        // reachable there by anything but the one bind `bindDeviceTree`
        // makes.
        const host_tmp = std.testing.tmpDir(.{});
        var host_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const host_z = absoluteDirPath(&host_path_buffer, host_tmp.dir.handle) catch std.process.exit(21);

        var tree_buffer: [device_path_capacity]u8 = undefined;
        if (!bindDeviceTree(&tree_buffer, root_z, "/.chock-device-tree", host_z)) std.process.exit(22);

        // **Written only now, after `bindDeviceTree` has already run.** This
        // is the hotplug property in miniature: a node made in the host
        // directory after the bind is still visible through it, because a
        // bind shows the same live filesystem and not a copy taken at bind
        // time. See `.superpowers/sdd/task-4b-report.md`.
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

        // **This process now does the same self-bind, `pivot_root`, and
        // detach `namespace.pivotInto` runs for B.** D itself never does
        // this: it is done here only so this test's own single process
        // exercises `placeDevice` exactly the way D really calls it, after
        // the namespace it shares has already pivoted. See `runDevice`'s
        // own doc comment for why D does not need to pivot itself for that
        // to be true.
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

        // From here on, this process's own `/` is the sandbox's, the same
        // as B's is once `applyLayers` reaches this same point, so every
        // path below is sandbox-relative, never `root_z`-prefixed again.
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

        // Read back what the probe wrote before the bind: proves the node
        // really is the source, not an empty file `mknodat` left behind.
        const placed_rc = linux.open("/dev/chock-widget0", .{ .ACCMODE = .RDWR }, 0);
        if (linux.errno(placed_rc) != .SUCCESS) std.process.exit(26);
        const placed_fd: i32 = @intCast(placed_rc);
        var read_buffer: [64]u8 = undefined;
        const read_n = linux.read(placed_fd, &read_buffer, read_buffer.len);
        if (linux.errno(read_n) != .SUCCESS) std.process.exit(27);
        if (!std.mem.eql(u8, read_buffer[0..read_n], source_content)) std.process.exit(28);

        // **Read-write, proved by writing through the placed node and
        // reading the change back from the original source.** Requirement 3
        // of task 4b's own brief: the mount must never be read only, because
        // `namespace.markReadOnly` also sets `NODEV`, which then refuses to
        // open the device node at all. Verified through `host_tmp.dir.handle`,
        // an already open descriptor from before the pivot: an ordinary file
        // operation relative to a held descriptor keeps working after a
        // detach, which is not true of a fresh, absolute lookup through the
        // same now-detached tree. See `runDevice`'s own doc comment.
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

        // **The trap this test pins, in the negative.** A remount with the
        // same flags `namespace.markReadOnly` uses proves the read only bind
        // this file must never make: with it, opening the very same node for
        // writing answers `EROFS`. If a later change made `placeDevice` call
        // something with this shape, this second half of the test would stop
        // finding the failure it expects and start finding a success
        // instead, which the parent below reads as this whole test failing.
        //
        // Mutation check: add a `markReadOnly`-shaped remount inside
        // `placeDevice` and the write-through assertion above starts failing
        // with `EROFS`, well before this block ever runs.
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
        // The placeholder `mknodat` made is empty again, its mount gone.
        const after_rc = linux.open("/dev/chock-widget0", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(after_rc) != .SUCCESS) std.process.exit(38);
        const after_fd: i32 = @intCast(after_rc);
        var after_drop: [8]u8 = undefined;
        const after_n = linux.read(after_fd, &after_drop, after_drop.len);
        _ = linux.close(after_fd);
        if (linux.errno(after_n) != .SUCCESS) std.process.exit(39);
        if (after_n != 0) std.process.exit(40);

        // **The escape check, proved against a real bind and not only
        // against the pure function.** The hidden tree really is bound in
        // and really does hold a node, and a source that climbs out of it
        // is still refused before `mount` is ever called.
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

/// `mount_setattr`'s own attribute structure, the same shape
/// `namespace.zig`'s own (private) `MountAttr` has, kept here rather than
/// exposed there: this file's own test above is the only caller outside that
/// module that ever needs to make a mount read only, and only to prove the
/// trap `placeDevice` must never walk back into. See `namespace.markReadOnly`.
const MountAttrProbe = extern struct {
    attr_set: u64 = 0,
    attr_clr: u64 = 0,
    propagation: u64 = 0,
    userns_fd: u64 = 0,
};
const mount_attr_rdonly_probe: u64 = 0x00000001;
const mount_attr_nodev_probe: u64 = 0x00000004;

test "a kind this helper does not implement is refused before anything is touched" {
    // Mutation check: delete the `kind != device_kind_file` check in
    // `placeDevice` and this call goes on to `mkdirat`, which either succeeds
    // on a path this test never authorised or fails for an unrelated reason,
    // either of which reads as the wrong error here.
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
    // Task 4b's own fifth property: a failed placement must be observable.
    // `reportDeviceFault` is the one place that promise is kept, since
    // `devicelink.zig`'s own wire carries no answer back to the real parent
    // for either outcome. This proves the line it writes names the verb, the
    // path, and the reason, which is what makes it a report and not only a
    // line.
    //
    // Mutation check: change `reportDeviceFault`'s format string to drop
    // `{s}` for `path` and this test's `expect` for the path substring fails.
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
