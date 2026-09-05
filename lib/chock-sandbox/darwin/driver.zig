//! The Darwin driver for chock-sandbox.
//!
//! ## What this driver is, and what it still refuses
//!
//! It applies four real layers: Seatbelt for paths, the network and signals,
//! and Darwin's own resource limits for appetite. See `seatbelt.zig` and
//! `limits.zig`, each of which carries the measurement behind every rule it
//! writes. What it cannot apply is the mount namespace, and that gap is
//! permanent: macOS has no bind mount, and there are only bad answers to
//! this.
//!
//! **So `spawn` refuses a config that needs a mount tree.** A bind whose target
//! is not its source, an overlay, a procfs, a capped scratch area, or a root
//! that is not `/`, each one is a request this platform cannot honour, and each
//! one is refused by name before anything is allocated or forked. Chock
//! refuses to run before it runs without a sandbox.
//!
//! **A config whose every path means the same thing inside the sandbox and
//! outside it does run, with the four layers on.** That is what
//! `lib/chock-workspace/layout.zig` builds: `Layout.in_place` leaves the
//! checkout, the project's own `.git` and the scratch object store each at its
//! own real path, so the whole workspace becomes a set of rules rather than a
//! set of mounts. See `expressibleOn` for the whole rule.
//!
//! ## The one thing that must never happen here
//!
//! **A layer this driver reports as on, and does not enforce, is worse than the
//! refusal this file used to be.** A refusal cannot mislead anybody. So every
//! claim below comes from a measurement on a real Apple Silicon Mac, macOS
//! 15.7.9, arm64, on 2026-08-25, and a layer that the measurement did not show
//! working is named `unsupported` rather than hoped for. Two were dropped that
//! way after being tried:
//!
//! * **There is no system call filter.** `Guarantee.syscall_restricted`'s own
//!   doc comment proposes `(deny syscall-unix ...)` for Darwin. It does not
//!   work: `(deny syscall-unix (syscall-number 26))` compiles, applies, and
//!   `ptrace` still returns 0. The only form that has any effect is the blanket
//!   `(deny syscall-unix)`, which stops `execve` and so cannot be used at all.
//! * **The machine's other processes are not hidden.** A sandboxed program
//!   reads the whole host process table through `sysctl KERN_PROC_ALL`, and
//!   taking `sysctl-read` away stops ordinary software starting. Darwin has no
//!   PID namespace. What it does give is that the program cannot *act* on any
//!   of them: see `seatbelt.Options.allow_signal_same_sandbox`.
//!
//! ## What `guarantees` claims, and why it claims it now
//!
//! `guarantees` named nothing at all until 2026-08-25, because understating is
//! the safe direction: Chock compares a policy against a driver and refuses
//! when the driver is short, so a driver that
//! claims nothing is refused, and a driver that claims a layer it has not got
//! is trusted. Nothing was reported and nothing could run, and the two were
//! consistent.
//!
//! It now names four layers, and it names them for one reason: a caller can
//! reach `spawn` and get a real sandbox. The mount gap is still permanent and
//! `workspace_mounted` is still absent, but the workspace no longer needs it: see
//! `lib/chock-workspace/layout.zig`, where `Layout.in_place` leaves every path
//! where it really is. `src/doctor.zig` reports the four, and each of the four
//! is refused by a test in `test/sandbox/darwin_escape.zig` that tried to break
//! it on a real Mac.

const std = @import("std");
const builtin = @import("builtin");
const iface = @import("../Sandbox.zig");
const namespace = @import("../linux/namespace.zig");
const landlock = @import("../linux/landlock.zig");
const seatbelt = @import("seatbelt.zig");
const limits = @import("limits.zig");

const Config = iface.Config;
const SetupError = iface.SetupError;
const SpawnError = iface.SpawnError;

/// What this driver declares, and what it enforces. The two are the same set,
/// and each member is proven by a test that tried to break it on a real Mac:
/// see `test/sandbox/darwin_escape.zig`.
///
/// **Nothing may be added here that a test does not break itself against.** A
/// layer this driver reports as on, and does not enforce, is worse than the
/// refusal this whole file used to be, because a policy comparison refuses a
/// driver that claims too little and accepts one that claims too much.
///
/// `syscall_restricted` and `workspace_mounted` are absent on purpose, and this
/// file's top comment says what was measured for each.
pub const guarantees: iface.Guarantees = iface.Guarantees.initMany(&.{
    .network_isolated,
    .signal_isolated,
    .ipc_isolated,
    .path_restricted,
});

/// Whether this process is already inside a profile of somebody else's, so
/// `spawn` cannot put one on a child. See `seatbelt.confinedAlready`, which
/// measures it. Re-exported here because a test reaches this driver through
/// `chock-sandbox.zig`'s own `darwin_driver_for_testing` and never reaches the
/// Seatbelt file directly.
pub const confinedAlready = seatbelt.confinedAlready;

/// The three states `confinedAlready` folds into two. A caller that must tell
/// a machine which refuses to nest a profile from a profile this code built
/// wrongly reads this instead. See `seatbelt.Nesting`.
pub const nesting = seatbelt.nesting;
pub const Nesting = seatbelt.Nesting;

/// The longest profile this driver builds. A workspace, a dev shell closure and
/// the deny list together are far below this; a config that is not is refused
/// rather than truncated. See `seatbelt.Builder.finish`.
const max_profile_bytes = 256 * 1024;

/// Why a config cannot be expressed on Darwin, or null when it can.
///
/// **Every member here is a request for the one layer this platform has not
/// got.** A path only means the same thing inside the sandbox and outside it
/// when nothing was remapped, and remapping is exactly what a mount namespace
/// does. So a caller that wants a tool call to run on macOS builds a config
/// whose every mount is a path that stays where it is.
pub const Inexpressible = enum {
    /// `Config.root` is not `/`. On Linux this directory becomes the root of
    /// the sandbox through `pivot_root`. Darwin has no pivot, so a driver that
    /// accepted a root would be promising a tree it never built.
    root_is_not_the_real_root,
    /// A bind mount asks for a source to appear at a different target. This is
    /// the workspace mount, and it is the whole of the mount gap.
    bind_moves_a_path,
    /// An overlay mount. macOS has no overlayfs. See
    /// `lib/chock-workspace/darwin/overlay.zig`, which says the same thing for
    /// the workspace, and the APFS clone it uses instead.
    overlay_mount,
    /// A fresh procfs. macOS has no procfs at all, and no PID namespace to give
    /// one a private view of.
    proc_mount,
    /// A capped scratch area. On Linux this is a tmpfs with a `size=` option,
    /// which is the only capacity limit an unprivileged process can put on a
    /// filesystem. An ordinary user on macOS cannot mount a filesystem at all,
    /// so there is nothing to cap and nothing to give.
    ///
    /// **Refused rather than quietly left out**, because a caller that asked
    /// for a bounded writable area and got an unbounded one, or none, would
    /// learn nothing until the disk filled. See `limits.zig`'s own
    /// `scratch_space`, which reports the same fact for the same reason.
    scratch_area,

    /// What was asked for, as a phrase that reads after "this sandbox needs ".
    pub fn text(self: Inexpressible) []const u8 {
        return switch (self) {
            .root_is_not_the_real_root => "a root of its own, and macos cannot pivot into one",
            .bind_moves_a_path => "a path to appear somewhere else, and macos has no bind mount",
            .overlay_mount => "an overlay filesystem, and macos has none",
            .proc_mount => "a procfs of its own, and macos has no procfs",
            .scratch_area => "a capped writable area, and an ordinary user on macos cannot mount a filesystem",
        };
    }
};

/// Whether `config` describes a sandbox Darwin can actually build.
///
/// **Separated from `spawn` so a test can ask without forking**, and so the
/// rule is one function a reader can check rather than four scattered
/// branches.
pub fn expressibleOn(config: Config) ?Inexpressible {
    if (!std.mem.eql(u8, config.root, "/")) return .root_is_not_the_real_root;
    if (config.scratch.len != 0) return .scratch_area;
    for (config.mounts) |mount| switch (mount) {
        .bind => |bind| if (!std.mem.eql(u8, bind.source, bind.target)) return .bind_moves_a_path,
        .overlay => return .overlay_mount,
        .proc => return .proc_mount,
        .deny => {},
    };
    return null;
}

/// A Landlock right set read as the two rights Seatbelt has.
///
/// **Seatbelt is coarser than Landlock and this function is where that is
/// admitted.** Landlock names sixteen rights; Seatbelt names `file-read*` and
/// `file-write*`. So a rule that asked for `make_dir` and not `write_file`
/// still gets `file-write*` here, which is wider than the caller asked for.
/// That is the honest reading: the alternative is to drop the right, and a
/// dropped write right is a tool call that cannot do its work.
///
/// `execute` maps to read, because Seatbelt governs execution with
/// `process-exec` and not with a right on the path. Measured on 2026-08-25: a
/// binary ran under a profile that permitted `process-exec*` and permitted no
/// read of that binary at all.
fn accessFor(rights: landlock.AccessFs) seatbelt.Access {
    return .{
        .read = rights.read_file or rights.read_dir or rights.execute,
        .write = rights.write_file or rights.truncate or rights.remove_file or
            rights.remove_dir or rights.make_char or rights.make_dir or
            rights.make_reg or rights.make_sock or rights.make_fifo or
            rights.make_block or rights.make_sym or rights.refer,
    };
}

/// Build the Seatbelt options for `config`. Allocates from `allocator`, before
/// the fork, the same way the Linux driver builds its seccomp filter there.
fn optionsFor(allocator: std.mem.Allocator, config: Config) std.mem.Allocator.Error!seatbelt.Options {
    var rules: std.ArrayList(seatbelt.Rule) = .empty;
    errdefer rules.deinit(allocator);
    var deny: std.ArrayList(seatbelt.Rule) = .empty;
    errdefer deny.deinit(allocator);

    // **The Landlock rules first and the mounts after, so a mount is the last
    // word on a path both name.** On Linux these are two layers and a program
    // needs both to permit an access. Seatbelt is one ordered list, so the two
    // have to be laid out in an order, and the mount layer is the one the
    // design already calls the boundary: see `chock-workspace`'s own
    // `Workspace.sandboxConfig`, which says of the read only object store that
    // "the mount layer is still what actually refuses a write". A rule written
    // after a mount would give back exactly that write.
    for (config.rules) |rule| try rules.append(allocator, .{
        .path = rule.path,
        .access = accessFor(rule.access),
    });

    for (config.mounts) |mount| switch (mount) {
        .bind => |bind| {
            try rules.append(allocator, .{
                .path = bind.source,
                .access = if (bind.read_only) .read_only else .read_write,
            });
            // **A read only bind has to say `deny`, and an allowance of read
            // alone does not.** A profile is a list of one access at a time,
            // so `(allow file-read*)` over a path an earlier rule made
            // writable leaves the write exactly where it was. Measured on
            // 2026-08-25: without this line a shell overwrote a file that the
            // mount list bound read only inside a read write parent, which on
            // Linux is the mount that keeps `commondir`, `gitdir` and
            // `config.worktree` out of an agent's reach. See `Rule.verb`.
            if (bind.read_only) try rules.append(allocator, .{
                .path = bind.source,
                .access = .{ .write = true },
                .verb = .deny,
            });
        },
        // A denied path is one file, so it is a `literal` and not a `subpath`.
        // Both halves are taken away: a caller that hid a file from the model
        // did not mean the model could still overwrite it.
        .deny => |denied| try deny.append(allocator, .{
            .path = denied.target,
            .access = .read_write,
            .reach = .literal,
        }),
        .overlay, .proc => unreachable, // `expressibleOn` refused these already.
    };

    // **Owned slices and never `items`.** A caller frees what this returns, and
    // `free` on an `ArrayList`'s items is wrong the moment its capacity is not
    // its length. See `spawnDarwin`, which frees both once the profile is
    // built.
    const owned_rules = try rules.toOwnedSlice(allocator);
    errdefer allocator.free(owned_rules);
    const owned_deny = try deny.toOwnedSlice(allocator);

    return .{
        .rules = owned_rules,
        .deny = owned_deny,
        // `.host` is the only case that opens the network, and the Linux driver
        // refuses it for everything except an act the user approved. `.filtered`
        // never reaches here: `spawn` refuses it above.
        .allow_network = config.network == .host,
    };
}

pub fn spawn(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    landlock_report: ?*iface.LandlockReport,
    middle: ?*iface.Middle,
) SpawnError!std.process.Child.Term {
    // **Before anything is allocated or forked**, so a refusal costs nothing
    // and can touch nothing. `landlock_report` is never filled in on this
    // platform: there is no Landlock to probe, and a stale value there would
    // read as a real probe.
    _ = landlock_report;

    // **A cgroup the caller made is refused by name, and it is refused
    // first.** macOS has no cgroup and no substitute for one, so there is
    // nothing here that could contain a child at creation. A driver that
    // accepted this config and ran the program anyway would give a caller a
    // sandbox with none of the containment it asked for, and would say
    // nothing. See `../Sandbox.zig`'s own `Containment` and
    // `expresses.cgroup_placement`, which is the same fact at compile time for
    // a caller that would rather not build such a config at all.
    switch (config.containment) {
        .best_effort => {},
        .supplied => return error.CgroupPlacementUnsupported,
    }

    if (expressibleOn(config) != null) return error.NoMountNamespace;

    // **A filtered config is refused rather than downgraded.** Darwin closes
    // the network exactly as `.none` does, so the isolation half is there, and
    // the other half is not: `../linux/netbroker.zig` is the exchange a
    // filtered process asks a host through, and it is Linux only. A process
    // told it had a channel out, and given none, would spend its whole run
    // failing at it. Reported with the member that says a broker is missing,
    // because from the program's side that is exactly what is missing.
    switch (config.network) {
        .filtered => return error.NetBrokerMissing,
        .none, .host => if (config.net_broker != null) return error.NetBrokerNotFiltered,
    }

    if (builtin.os.tag == .macos) {
        return spawnDarwin(allocator, config, argv, middle);
    } else {
        // This file is compiled for every host so its own tests run everywhere;
        // see `../../chock-sandbox.zig`'s own `darwin_driver_for_testing`. On a
        // host that is not macOS there is no `sandbox_init` to call, so this
        // build cannot confine anything and says so with the same refusal.
        return error.NoMountNamespace;
    }
}

/// Everything below here is named only from the `.macos` branch above, so a
/// build for another target never asks a linker for a Darwin symbol. Zig
/// analyses a function when it is referenced, and nothing on another target
/// references one.
fn spawnDarwin(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    middle: ?*iface.Middle,
) SpawnError!std.process.Child.Term {
    std.debug.assert(argv.len > 0);

    const options = try optionsFor(allocator, config);
    // **Freed here and not left to the caller's arena.** A tool call is one
    // `spawn` of many in a session, and a caller that hands this an ordinary
    // allocator would otherwise grow by one rule list per call.
    defer allocator.free(options.rules);
    defer allocator.free(options.deny);
    const profile_buffer = try allocator.alloc(u8, max_profile_bytes);
    defer allocator.free(profile_buffer);
    var builder = seatbelt.Builder.init(profile_buffer);
    const profile = builder.finish(options) catch |err| switch (err) {
        // Both are a config this driver cannot turn into a boundary, and both
        // are refused before the fork. A profile that was truncated or that
        // held a rule matching nothing is the exact shape of the false OK this
        // driver exists to avoid: see `seatbelt.checkPath`.
        error.ProfileTooLong, error.BadPath => return error.LandlockInitFailed,
    };

    // The setup pipe, and the cancel pipe. Both are close-on-exec, so a
    // successful `execve` closes the child's copy on its own and the parent
    // reads end of file rather than a record.
    var setup_fds: [2]std.c.fd_t = undefined;
    if (std.c.pipe(&setup_fds) != 0) return error.Unexpected;
    setCloexec(setup_fds[0]);
    setCloexec(setup_fds[1]);

    var cancel_fds: [2]std.c.fd_t = .{ -1, -1 };
    if (middle != null) {
        if (std.c.pipe(&cancel_fds) != 0) {
            _ = std.c.close(setup_fds[0]);
            _ = std.c.close(setup_fds[1]);
            return error.Unexpected;
        }
        setCloexec(cancel_fds[0]);
        setCloexec(cancel_fds[1]);
        // **Without this, cancelling a call that has already ended kills the
        // harness.** A write to a pipe whose reader is gone raises `SIGPIPE`,
        // and the harness has no handler for it. With it the same write answers
        // `EPIPE`, which `signalMiddle` reports as `error.Gone`: the process
        // ended, which is what the caller asked for. Measured on 2026-08-25:
        // `fcntl(fd, F_SETNOSIGPIPE, 1)` answers 0 on a pipe, and the write
        // then returns -1 with `EPIPE` and no signal.
        _ = std.c.fcntl(cancel_fds[1], std.c.F.SETNOSIGPIPE, @as(c_int, 1));
    }

    const a_pid = std.c.fork();
    if (a_pid < 0) {
        _ = std.c.close(setup_fds[0]);
        _ = std.c.close(setup_fds[1]);
        closePair(&cancel_fds);
        return error.Unexpected;
    }

    if (a_pid == 0) {
        // A, the middle process. It applies no layer of its own: its whole job
        // is to hold B as a child that nothing else can reap, so that a cancel
        // can never reach a stranger. See `middleLoop`.
        _ = std.c.close(setup_fds[0]);
        if (cancel_fds[1] >= 0) _ = std.c.close(cancel_fds[1]);
        runMiddle(allocator, config, argv, profile, setup_fds[1], cancel_fds[0]);
    }

    _ = std.c.close(setup_fds[1]);
    if (cancel_fds[0] >= 0) _ = std.c.close(cancel_fds[0]);

    if (middle) |handle| {
        // `fd` first and `pid` second, the same order the Linux driver writes
        // them in, so a caller that watches `pid` never reads an `fd` that is
        // not there yet. See `iface.Middle`.
        handle.fd = cancel_fds[1];
        @atomicStore(std.c.pid_t, &handle.pid, a_pid, .release);
    }

    const record = readSetupReport(setup_fds[0]);
    _ = std.c.close(setup_fds[0]);

    var status: c_int = 0;
    while (std.c.waitpid(a_pid, &status, 0) < 0) {
        if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) break;
    }

    if (record) |step| return setupErrorFor(step);
    return termFor(status);
}

/// One step of setup, in the order B runs them. B writes the tag of a step it
/// could not finish into the setup pipe and ends its own process.
///
/// **Named one member per `iface.SetupError` and no more.** A step this driver
/// has and Linux has not would need a new member on a shared type, and a driver
/// is not the place to widen one.
const SetupStep = enum(u8) {
    stdin_redirect = 1,
    process_group,
    close_fds,
    resource_limits,
    /// `sandbox_init` refused the profile. This is the Seatbelt layer, which is
    /// what Landlock is on the other driver, so it reports through the member
    /// that names a path layer that would not go on.
    confinement,
    fork,
    exec,
};

fn setupErrorFor(step: SetupStep) SpawnError {
    return switch (step) {
        .stdin_redirect => error.StdinRedirectFailed,
        .process_group => error.ProcessGroupFailed,
        .close_fds => error.CloseFdsFailed,
        .resource_limits => error.ResourceLimitFailed,
        .confinement => error.LandlockRestrictFailed,
        .fork => error.ForkFailed,
        .exec => error.ExecFailed,
    };
}

/// A witness value with no meaning of its own, so a read that landed on a
/// corrupt fragment is easy to reject rather than trusted as a real step. The
/// bytes spell "CHK1", the same as the Linux driver's own.
const setup_magic: u32 = 0x314B4843;

const SetupRecord = extern struct {
    magic: u32 = setup_magic,
    step: u8,
    errno: i32,
};

fn readSetupReport(read_fd: std.c.fd_t) ?SetupStep {
    var record: SetupRecord = undefined;
    var filled: usize = 0;
    const bytes = std.mem.asBytes(&record);
    while (filled < bytes.len) {
        const n = std.c.read(read_fd, bytes[filled..].ptr, bytes.len - filled);
        if (n < 0) {
            if (std.c._errno().* == @intFromEnum(std.c.E.INTR)) continue;
            return null;
        }
        if (n == 0) break;
        filled += @intCast(n);
    }
    // End of file with nothing in it is the ordinary case: `execve` worked and
    // closed the write end through its close-on-exec flag.
    if (filled == 0) return null;
    if (filled != bytes.len or record.magic != setup_magic) return .exec;
    return std.enums.fromInt(SetupStep, record.step) orelse .exec;
}

/// `FD_CLOEXEC` is 1 on Darwin, from `sys/fcntl.h`. Named here because Zig's
/// own `std.c` does not declare it.
const fd_cloexec: c_int = 1;

fn setCloexec(fd: std.c.fd_t) void {
    _ = std.c.fcntl(fd, std.c.F.SETFD, fd_cloexec);
}

fn closePair(fds: *[2]std.c.fd_t) void {
    for (fds) |*fd| {
        if (fd.* >= 0) _ = std.c.close(fd.*);
        fd.* = -1;
    }
}

/// What `waitpid` reported, as the type every caller of `spawn` reads.
fn termFor(status: c_int) std.process.Child.Term {
    const raw: c_uint = @bitCast(status);
    const signal: u32 = raw & 0x7f;
    if (signal == 0) return .{ .exited = @truncate((raw >> 8) & 0xff) };
    if (signal == 0x7f) return .{ .stopped = @enumFromInt(@as(u8, @truncate((raw >> 8) & 0xff))) };
    return .{ .signal = @enumFromInt(@as(u8, @truncate(signal))) };
}

fn writeRecord(write_fd: std.c.fd_t, step: SetupStep, errno: i32) void {
    const record = SetupRecord{ .step = @intFromEnum(step), .errno = errno };
    const bytes = std.mem.asBytes(&record);
    _ = std.c.write(write_fd, bytes.ptr, bytes.len);
}

fn die(write_fd: std.c.fd_t, stderr_fd: std.c.fd_t, step: SetupStep, what: []const u8) noreturn {
    writeRecord(write_fd, step, std.c._errno().*);
    // One line for a person, on the descriptor the caller named. A caller that
    // asked for a quiet failure pointed that at /dev/null and gets one, while
    // `spawn` still answers with the error that names the step.
    _ = std.c.write(stderr_fd, "sandbox: ", 9);
    _ = std.c.write(stderr_fd, what.ptr, what.len);
    _ = std.c.write(stderr_fd, "\n", 1);
    std.c._exit(127);
}

/// A, the middle process. Never confined, never the program the model asked
/// for: it is Chock's own code with Chock's own memory image, exactly like the
/// Linux driver's own middle process.
///
/// **A holds B and never reaps it until B has really ended, and that is the
/// whole reason A exists.** Darwin has no `pidfd`. A pid that has been reaped
/// names nothing and may soon name somebody else, and a `kill` by number after
/// that reaches a process this session never started: measured on 2026-08-22,
/// with a whole process group of an unrelated build taken down by one. So the
/// cancel never travels as a number. It travels as one byte on a pipe to A, and
/// A is the only process that ever names B's pid, and A cannot have reaped B
/// while it is still listening.
fn runMiddle(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    profile: [:0]const u8,
    write_fd: std.c.fd_t,
    cancel_read_fd: std.c.fd_t,
) noreturn {
    resetSignalState();

    // **The sandbox's own process group, before anything else.** Everything A
    // starts inherits it, so a signal sent to the harness's own group does not
    // reach the call, and a `kill(0, ...)` from inside the call does not reach
    // the harness. Seatbelt already refuses the second of those, measured on
    // 2026-08-25, and this is the layer that does not depend on the profile
    // having been applied yet.
    if (std.c.setpgid(0, 0) != 0) die(write_fd, config.stderr_fd, .process_group, "could not make a process group");

    const b_pid = std.c.fork();
    if (b_pid < 0) die(write_fd, config.stderr_fd, .fork, "could not fork the sandboxed process");
    if (b_pid == 0) {
        if (cancel_read_fd >= 0) _ = std.c.close(cancel_read_fd);
        runProgram(allocator, config, argv, profile, write_fd);
    }

    // A never writes to the setup pipe again, and it must not hold the write
    // end: the parent learns that the sandbox came up when the last copy of
    // that end closes, and a copy held here would hold that answer back for the
    // whole call.
    _ = std.c.close(write_fd);

    middleLoop(b_pid, cancel_read_fd);
}

/// Wait for B, and carry a cancel to it while it runs.
///
/// **kqueue and not a blocking read, because the two things A waits for must be
/// waited for together.** A read on the cancel pipe that is interrupted by
/// `SIGCHLD` has a window between the check for a finished B and the read
/// itself, and a B that ends inside that window leaves A blocked for ever.
/// `EVFILT_PROC` with `NOTE_EXIT` and `EVFILT_READ` on the pipe are registered
/// before either can happen, so neither can be missed.
fn middleLoop(b_pid: std.c.pid_t, cancel_read_fd: std.c.fd_t) noreturn {
    const kq = std.c.kqueue();
    if (kq < 0) {
        // No kqueue means no cancel, and a call that cannot be cancelled is
        // still a call. Wait plainly rather than refusing work that would
        // otherwise have run.
        relay(b_pid);
    }

    var changes: [2]std.c.Kevent = undefined;
    var count: c_int = 1;
    changes[0] = .{
        .ident = @intCast(b_pid),
        .filter = std.c.EVFILT.PROC,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE,
        .fflags = std.c.NOTE.EXIT,
        .data = 0,
        .udata = 0,
    };
    if (cancel_read_fd >= 0) {
        changes[1] = .{
            .ident = @intCast(cancel_read_fd),
            .filter = std.c.EVFILT.READ,
            .flags = std.c.EV.ADD | std.c.EV.ENABLE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        };
        count = 2;
    }
    if (std.c.kevent(kq, &changes, count, undefined, 0, null) < 0) relay(b_pid);

    while (true) {
        var event: std.c.Kevent = undefined;
        const n = std.c.kevent(kq, undefined, 0, @ptrCast(&event), 1, null);
        if (n < 0) {
            if (std.c._errno().* == @intFromEnum(std.c.E.INTR)) continue;
            relay(b_pid);
        }
        if (n == 0) continue;
        if (event.filter == std.c.EVFILT.PROC) relay(b_pid);
        if (event.filter != std.c.EVFILT.READ) continue;

        var byte: [1]u8 = undefined;
        const read_n = std.c.read(cancel_read_fd, &byte, 1);
        // End of file means the harness gave the handle up without ever using
        // it, which is the ordinary end of a call that nobody cancelled. B is
        // still running, so keep waiting for it.
        if (read_n <= 0) {
            var only: [1]std.c.Kevent = .{.{
                .ident = @intCast(cancel_read_fd),
                .filter = std.c.EVFILT.READ,
                .flags = std.c.EV.DELETE,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            }};
            _ = std.c.kevent(kq, &only, 1, undefined, 0, null);
            continue;
        }
        // The whole call, and not B alone: a tool call that started children of
        // its own is not cancelled by ending only the first of them. The group
        // is the one A made for itself, so nothing outside the call is in it.
        //
        // **A takes the signal out of its own hands first, and that is not
        // tidiness.** A is in that group too, so a `SIGTERM` sent to the group
        // would end A before it could reap B, and a B that ignores `SIGTERM`
        // would then be an orphan nothing is waiting for. Darwin has no
        // `prctl(PR_SET_PDEATHSIG)` to catch that afterwards. Ignoring the
        // signal in A alone leaves the group's other members with the default
        // handling they had. `SIGKILL` cannot be ignored, and needs no help:
        // it ends every process of the group at once, which is the whole call.
        const which: std.c.SIG = @enumFromInt(byte[0]);
        var ignore: std.c.Sigaction = undefined;
        @memset(std.mem.asBytes(&ignore), 0);
        ignore.handler = .{ .handler = std.c.SIG.IGN };
        _ = std.c.sigaction(which, &ignore, null);
        _ = std.c.kill(-std.c.getpid(), which);
    }
}

/// Wait for B and end with what B ended with, so the harness reads B's own
/// outcome through `waitpid` on A.
fn relay(b_pid: std.c.pid_t) noreturn {
    var status: c_int = 0;
    while (std.c.waitpid(b_pid, &status, 0) < 0) {
        if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) std.c._exit(127);
    }
    switch (termFor(status)) {
        .exited => |code| std.c._exit(code),
        .signal => |signal| {
            // Ending the same way B did, so the caller reads `.signal` and not
            // an exit code that hides it. The handler is already default and
            // the signal is not blocked: `resetSignalState` saw to both.
            _ = std.c.kill(std.c.getpid(), signal);
            std.c._exit(128 +% @as(u8, @truncate(@intFromEnum(signal))));
        },
        .stopped, .unknown => std.c._exit(127),
    }
}

/// B, the process that becomes the caller's program.
fn runProgram(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    profile: [:0]const u8,
    write_fd: std.c.fd_t,
) noreturn {
    redirectStdin(config, write_fd);
    closeInheritedFds(config, write_fd);
    redirectStandardStreams(config, write_fd);

    // Descriptor 2 from here down: the call above has already put the
    // descriptor the caller named onto it.
    const stderr_fd: std.c.fd_t = 2;

    const cwd_z = allocator.dupeZ(u8, config.cwd) catch die(write_fd, stderr_fd, .exec, "out of memory");
    if (std.c.chdir(cwd_z) != 0) die(write_fd, stderr_fd, .exec, "chdir into the sandbox failed");

    const argv_z = allocator.allocSentinel(?[*:0]const u8, argv.len, null) catch
        die(write_fd, stderr_fd, .exec, "out of memory");
    for (argv, 0..) |arg, index| {
        argv_z[index] = allocator.dupeZ(u8, arg) catch die(write_fd, stderr_fd, .exec, "out of memory");
    }
    const env_z = allocator.allocSentinel(?[*:0]const u8, config.env.len, null) catch
        die(write_fd, stderr_fd, .exec, "out of memory");
    for (config.env, 0..) |item, index| {
        env_z[index] = allocator.dupeZ(u8, item) catch die(write_fd, stderr_fd, .exec, "out of memory");
    }

    // **The limits before the confinement, and both after everything that
    // allocates.** `RLIMIT_CPU` should count the caller's program and not the
    // sandbox coming up, and the allocations above are all in front of it. See
    // `limits.apply`.
    const report = limits.apply(config.limits);
    // **A limit the caller asked for and the kernel refused is a refusal, not a
    // warning.** A program that ran on with no bound is exactly the false OK
    // this driver exists to avoid. The three limits Darwin does not have are a
    // different fact and never reach `unavailable`: see `limits.zig`.
    for ([_]limits.Report.State{ report.cpu_time, report.file_size, report.open_files }) |state| {
        if (state == .unavailable) die(write_fd, stderr_fd, .resource_limits, "a resource limit could not be set");
    }

    // **Last, and after the descriptors are closed.** Seatbelt checks paths,
    // and a descriptor opened before it went on is not a path: measured on
    // 2026-08-25, a process read a file through a descriptor it had opened
    // before `sandbox_init`, under a profile that denied that very path. So
    // `closeInheritedFds` above is not tidiness, it is the other half of this
    // layer.
    const support = seatbelt.apply(profile);
    if (!support.applied()) die(write_fd, stderr_fd, .confinement, "the sandbox profile was refused");

    _ = std.c.execve(argv_z[0].?, argv_z.ptr, env_z.ptr);
    die(write_fd, stderr_fd, .exec, "execve failed");
}

/// Put every signal back to its default and unblock the lot.
///
/// **The caller's handlers and mask are wrong for this process.** A harness that
/// ignores `SIGPIPE` would hand that to the program the model asked for, which
/// then behaves differently inside the sandbox from outside it, and a blocked
/// signal cannot end a runaway call at all.
fn resetSignalState() void {
    var action: std.c.Sigaction = undefined;
    @memset(std.mem.asBytes(&action), 0);
    action.handler = .{ .handler = std.c.SIG.DFL };
    var signal: u6 = 1;
    while (signal < 32) : (signal += 1) {
        // KILL and STOP cannot be changed, and the kernel answers EINVAL rather
        // than doing something surprising.
        _ = std.c.sigaction(@enumFromInt(signal), &action, null);
    }
    var empty: std.c.sigset_t = undefined;
    _ = std.c.sigemptyset(&empty);
    _ = std.c.sigprocmask(std.c.SIG.SETMASK, &empty, null);
}

/// Descriptor 0 is `/dev/null` before any layer goes on, unless the caller named
/// one. See `iface.Config.stdin_fd` for the two reasons in full: a password
/// prompt fails fast instead of waiting on input nobody will write, and there is
/// no route from descriptor 0 to the caller's own terminal.
fn redirectStdin(config: Config, write_fd: std.c.fd_t) void {
    const null_fd = std.c.open("/dev/null", .{ .ACCMODE = .RDWR });
    if (null_fd < 0) die(write_fd, config.stderr_fd, .stdin_redirect, "could not open /dev/null");
    if (std.c.dup2(null_fd, 0) < 0) die(write_fd, config.stderr_fd, .stdin_redirect, "could not redirect standard input");
    if (null_fd > 2) _ = std.c.close(null_fd);
}

/// Close every descriptor this process kept from the harness, except the few it
/// still needs.
///
/// **This is half of the path layer and not housekeeping.** Seatbelt checks a
/// path when a path is opened. An inherited descriptor was opened before the
/// profile went on, so no rule in the profile applies to it: measured on
/// 2026-08-25, a process read sixteen bytes of a file through such a descriptor
/// under a profile that denied that path outright.
fn closeInheritedFds(config: Config, write_fd: std.c.fd_t) void {
    var highest: std.c.rlimit = undefined;
    // A bound rather than a guess: the table cannot hold a descriptor above the
    // soft limit, and the cap keeps this loop finite on a machine that reports
    // no limit at all.
    const limit: usize = if (std.c.getrlimit(.NOFILE, &highest) == 0)
        @min(@as(u64, @intCast(highest.cur)), 1 << 16)
    else
        1 << 16;

    var fd: std.c.fd_t = 3;
    while (fd < limit) : (fd += 1) {
        if (fd == write_fd) continue;
        if (fd == config.stdout_fd or fd == config.stderr_fd) continue;
        if (config.stdin_fd) |kept| if (fd == kept) continue;
        _ = std.c.close(fd);
    }
}

/// Point the program's own output at whatever the caller named. The originals
/// are closed once they are duplicated, so the program holds one descriptor per
/// stream and no spare that a rule never covered.
fn redirectStandardStreams(config: Config, write_fd: std.c.fd_t) void {
    if (config.stdin_fd) |fd| {
        if (std.c.dup2(fd, 0) < 0) die(write_fd, config.stderr_fd, .stdin_redirect, "could not redirect standard input");
    }
    if (config.stdout_fd != 1) {
        if (std.c.dup2(config.stdout_fd, 1) < 0) die(write_fd, config.stderr_fd, .close_fds, "could not redirect standard output");
    }
    if (config.stderr_fd != 2) {
        if (std.c.dup2(config.stderr_fd, 2) < 0) die(write_fd, 2, .close_fds, "could not redirect standard error");
    }
    if (config.stdout_fd > 2) _ = std.c.close(config.stdout_fd);
    if (config.stderr_fd > 2 and config.stderr_fd != config.stdout_fd) _ = std.c.close(config.stderr_fd);
    if (config.stdin_fd) |fd| if (fd > 2) {
        _ = std.c.close(fd);
    };
}

/// Send `sig` to the whole of a running call, through the handle `spawn` gave.
///
/// **One `write` and nothing else, so this is safe from a signal handler**: no
/// allocation, no lock, and no path. It is also the reason the handle is a pipe
/// and not a pid. Darwin has no `pidfd`, and `kqueue`'s own `EVFILT_PROC` is a
/// notification rather than a way to send anything, so the only Darwin answer
/// that closes the reaped pid race is a process that never reaps while a cancel
/// may still be in flight. That process is A: see `runMiddle`.
///
/// `error.Gone` is the ordinary answer for a call that already ended. A closes
/// the read end when it exits, and a write to a pipe with no reader answers
/// `EPIPE` rather than raising `SIGPIPE`, because `spawn` set `F_SETNOSIGPIPE`
/// on this descriptor.
pub fn signalMiddle(fd: std.posix.fd_t, sig: std.posix.SIG) iface.SignalError!void {
    if (fd < 0) return error.NoHandle;
    if (builtin.os.tag == .macos) {
        const byte: [1]u8 = .{@truncate(@intFromEnum(sig))};
        while (true) {
            const n = std.c.write(fd, &byte, 1);
            if (n == 1) return;
            const err = std.c._errno().*;
            if (err == @intFromEnum(std.c.E.INTR)) continue;
            if (err == @intFromEnum(std.c.E.PIPE)) return error.Gone;
            return error.Unexpected;
        }
    } else {
        return error.NoHandle;
    }
}

/// Give up a handle `spawn` opened, and put the field back to -1 so a second
/// call cannot close a descriptor twice. A descriptor closed twice lands on
/// whatever unrelated thing opened that number in between, which is the same
/// shape of fault as the reaped pid this whole mechanism replaces.
pub fn closeMiddle(middle: *iface.Middle) void {
    if (builtin.os.tag == .macos) {
        if (middle.fd >= 0) _ = std.c.close(middle.fd);
    }
    middle.fd = -1;
}

/// A stub, never meant to run. The Linux driver joins a fresh session keyring so
/// a key planted on one side of the sandbox boundary cannot be read from the
/// other. Darwin has no session keyring concept. This exists only so both
/// drivers expose the same public shape; see `../Sandbox.zig`'s own "same public
/// shape" test.
pub fn joinFreshSessionKeyring(stderr_fd: std.posix.fd_t) error{Refused}!void {
    _ = stderr_fd;
    return error.Refused;
}

test "spawn refuses a config that needs the layer macos has not got" {
    // Each of these is a request for a mount namespace, and each one is refused
    // by name before anything is allocated or forked.
    const base = Config{ .root = "/", .mounts = &.{}, .rules = &.{}, .cwd = "/", .env = &.{} };

    var moved = base;
    moved.mounts = &.{.{ .bind = .{ .source = "/work/checkout", .target = "/home/me/project" } }};
    try std.testing.expectEqual(Inexpressible.bind_moves_a_path, expressibleOn(moved).?);

    var overlaid = base;
    overlaid.mounts = &.{.{ .overlay = .{ .lower = "/l", .upper = "/u", .work = "/w", .target = "/t" } }};
    try std.testing.expectEqual(Inexpressible.overlay_mount, expressibleOn(overlaid).?);

    var procfs = base;
    procfs.mounts = &.{.{ .proc = .{} }};
    try std.testing.expectEqual(Inexpressible.proc_mount, expressibleOn(procfs).?);

    var rooted = base;
    rooted.root = "/tmp/some/root";
    try std.testing.expectEqual(Inexpressible.root_is_not_the_real_root, expressibleOn(rooted).?);

    // A bind that leaves its path where it is needs no mount namespace, so it
    // is the one shape this platform can express.
    var identity = base;
    identity.mounts = &.{.{ .bind = .{ .source = "/nix/store/x", .target = "/nix/store/x", .read_only = true } }};
    try std.testing.expectEqual(@as(?Inexpressible, null), expressibleOn(identity));
}

test "spawn never allocates and never forks before it refuses" {
    // A stub returning success is the worst possible outcome this driver could
    // produce: it would give an agent the user's whole filesystem on a platform
    // that claims to be sandboxed. A FailingAllocator turns the first allocation
    // attempt into a test failure, so a refusal that had already begun real work
    // cannot pass quietly.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const err = spawn(failing.allocator(), .{
        .root = "/does-not-exist-and-must-never-be-touched",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    }, &.{"/bin/true"}, null, null);
    try std.testing.expectError(error.NoMountNamespace, err);
    try std.testing.expectEqual(@as(usize, 0), failing.allocations);
}

test "spawn leaves landlock_report and the middle handle untouched when it refuses" {
    var report: iface.LandlockReport = .{ .abi = -1, .features = undefined };
    var middle: iface.Middle = .{ .pid = -1, .fd = -2 };
    const err = spawn(std.testing.allocator, .{
        .root = "/does-not-matter",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    }, &.{"/bin/true"}, &report, &middle);
    try std.testing.expectError(error.NoMountNamespace, err);
    // Untouched, not merely unread: a caller must not be able to mistake a stale
    // value here for a real Landlock probe or a real forked process. There is no
    // Landlock on Darwin at all, so this one stays untouched even on a call that
    // succeeds.
    try std.testing.expectEqual(@as(i32, -1), report.abi);
    try std.testing.expectEqual(@as(std.posix.pid_t, -1), middle.pid);
    try std.testing.expectEqual(@as(std.posix.fd_t, -2), middle.fd);
}

test "a filtered config is refused rather than quietly given no channel out" {
    // Darwin closes the network exactly as `.none` does, so it would be easy to
    // let this through and call it filtered. The program would then spend its
    // whole run failing at a channel it was told it had.
    const err = spawn(std.testing.allocator, .{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .network = .filtered,
    }, &.{"/bin/true"}, null, null);
    try std.testing.expectError(error.NetBrokerMissing, err);
}

test "signalMiddle refuses a handle nobody opened" {
    try std.testing.expectError(error.NoHandle, signalMiddle(-1, std.posix.SIG.KILL));
}

test "closeMiddle leaves no descriptor a second call could close twice" {
    var middle: iface.Middle = .{ .pid = 7, .fd = -1 };
    closeMiddle(&middle);
    try std.testing.expectEqual(@as(std.posix.fd_t, -1), middle.fd);
    closeMiddle(&middle);
    try std.testing.expectEqual(@as(std.posix.fd_t, -1), middle.fd);
}

test "the guarantees name only the layers a test really proves" {
    // `syscall_restricted` is absent because `(deny syscall-unix (syscall-number
    // 26))` compiles, applies, and `ptrace` still returns 0: measured on
    // 2026-08-25. `workspace_mounted` is absent because the mount gap is
    // permanent, and `lib/chock-workspace/layout.zig` is how a tool call runs
    // anyway.
    try std.testing.expect(guarantees.contains(.network_isolated));
    try std.testing.expect(guarantees.contains(.signal_isolated));
    try std.testing.expect(guarantees.contains(.ipc_isolated));
    try std.testing.expect(guarantees.contains(.path_restricted));
    try std.testing.expect(!guarantees.contains(.syscall_restricted));
    try std.testing.expect(!guarantees.contains(.workspace_mounted));
    try std.testing.expectEqual(@as(usize, 4), guarantees.count());
}

test "a capped scratch area is refused rather than quietly left out" {
    // The one member of `Inexpressible` that names no mount. A caller that
    // asked for a bounded writable area and got an unbounded one would learn
    // nothing until the disk filled, which is the false OK this driver exists
    // to avoid.
    //
    // Mutation check: drop the `config.scratch.len` line in `expressibleOn` and
    // this fails.
    const config = Config{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .scratch = &.{.{ .target = "/run/chock/scratch" }},
    };
    try std.testing.expectEqual(Inexpressible.scratch_area, expressibleOn(config).?);
    try std.testing.expectError(error.NoMountNamespace, spawn(std.testing.allocator, config, &.{"/bin/true"}, null, null));
}

test "a cgroup the caller made is refused by name, and refused before every other check" {
    // **macOS has no cgroup and no substitute for one**, so a caller that
    // handed one over and got a running program would have a sandbox with
    // none of the containment it asked for. The refusal names the thing that
    // is missing, and it comes first, so a config that is otherwise perfectly
    // expressible here still refuses.
    //
    // Mutation check: drop the `config.containment` switch in `spawn` and the
    // first call below answers `error.NoMountNamespace`, which reads as a
    // mount problem for a config that has no mounts at all. Move the switch
    // after `expressibleOn` and the second call answers the same.
    const placeable = Config{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .containment = .{ .supplied = .{ .fd = 7 } },
    };
    // Nothing about this config needs a mount tree, so `NoMountNamespace`
    // would be the wrong word for it on every platform.
    try std.testing.expectEqual(@as(?Inexpressible, null), expressibleOn(placeable));
    try std.testing.expectError(
        error.CgroupPlacementUnsupported,
        spawn(std.testing.allocator, placeable, &.{"/bin/true"}, null, null),
    );

    // And a config that this platform could not express either way still
    // names the cgroup, because that is the field the caller has to change
    // first: no rearrangement of the mounts makes a cgroup appear on macOS.
    var also_unmountable = placeable;
    also_unmountable.root = "/somewhere-else";
    try std.testing.expectError(
        error.CgroupPlacementUnsupported,
        spawn(std.testing.allocator, also_unmountable, &.{"/bin/true"}, null, null),
    );

    // **And this build says so at compile time**, for a caller that would
    // rather not build such a config at all. `expresses.cgroup_placement` and
    // the refusal above must agree, or a caller is told one thing and given
    // another.
    try std.testing.expectEqual(builtin.os.tag == .linux, iface.expresses.cgroup_placement);
}

test "a read only bind takes write away, and a later read write bind gives it back" {
    // **The fault this pins was real and silent.** Measured on macOS 15.7.9 on
    // 2026-08-25: a profile that permitted read and write on a directory and
    // then permitted read alone on one file inside it let a shell overwrite
    // that file. A profile grants one access at a time, so an allowance of read
    // says nothing about writing. On Linux the same pair of mounts is what
    // keeps `commondir`, `gitdir` and `config.worktree` out of an agent's
    // reach: see `lib/chock-workspace/worktree.zig`.
    //
    // Mutation check: drop the `if (bind.read_only)` deny in `optionsFor` and
    // the first assertion below fails.
    // An arena, because `optionsFor` returns the items of two lists it built and
    // a caller frees the whole allocation rather than the used part of it.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const options = try optionsFor(allocator, .{
        .root = "/",
        .mounts = &.{
            .{ .bind = .{ .source = "/w", .target = "/w", .read_only = false } },
            .{ .bind = .{ .source = "/w/meta", .target = "/w/meta", .read_only = true } },
            .{ .bind = .{ .source = "/w/meta/index", .target = "/w/meta/index", .read_only = false } },
        },
        .rules = &.{},
        .cwd = "/w",
        .env = &.{},
    });

    var buffer: [4096]u8 = undefined;
    var builder = seatbelt.Builder.init(&buffer);
    const profile = try builder.finish(options);

    const takes_write = std.mem.indexOf(u8, profile, "(deny file-write* (subpath \"/w/meta\"))").?;
    const gives_it_back = std.mem.indexOf(u8, profile, "(allow file-read* file-write* (subpath \"/w/meta/index\"))").?;
    // The order is the whole meaning: the later rule wins, so the narrowing
    // covers the directory and the one file inside it is writable again.
    try std.testing.expect(gives_it_back > takes_write);
    // And the read half of the read only bind is still there, or git could not
    // read the file at all.
    try std.testing.expect(std.mem.indexOf(u8, profile, "(allow file-read* (subpath \"/w/meta\"))") != null);
}

test "a landlock rule is written before the mounts, so a mount is the last word" {
    // On Linux these are two layers and a program needs both. Here they are one
    // ordered list, so an order has to be chosen, and the mount layer is the
    // one the design already calls the boundary.
    //
    // Mutation check: move the `config.rules` loop below the `config.mounts`
    // loop in `optionsFor` and this fails, and a rule granting write over a
    // read only mount would then give the write back.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const options = try optionsFor(allocator, .{
        .root = "/",
        .mounts = &.{.{ .bind = .{ .source = "/w", .target = "/w", .read_only = true } }},
        .rules = &.{.{ .path = "/w", .access = landlock.AccessFs.read_write }},
        .cwd = "/w",
        .env = &.{},
    });

    var buffer: [4096]u8 = undefined;
    var builder = seatbelt.Builder.init(&buffer);
    const profile = try builder.finish(options);

    const from_the_rule = std.mem.indexOf(u8, profile, "(allow file-read* file-write* (subpath \"/w\"))").?;
    const from_the_mount = std.mem.indexOf(u8, profile, "(deny file-write* (subpath \"/w\"))").?;
    try std.testing.expect(from_the_mount > from_the_rule);
}

test "a landlock right set becomes the two rights seatbelt has" {
    // Seatbelt is coarser than Landlock, so this is where the widening is
    // admitted rather than hidden. A rule that may only create a directory still
    // gets `file-write*`, because the alternative is a tool call that cannot do
    // its work.
    try std.testing.expectEqual(seatbelt.Access{ .read = true }, accessFor(landlock.AccessFs.read_only));
    try std.testing.expectEqual(seatbelt.Access{ .read = true }, accessFor(.{ .execute = true }));
    try std.testing.expectEqual(seatbelt.Access{ .write = true }, accessFor(.{ .make_dir = true }));
    try std.testing.expectEqual(seatbelt.Access{}, accessFor(.{}));
}
