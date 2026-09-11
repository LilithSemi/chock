//! A sandbox for a tool call, behind a driver interface: see `Sandbox.zig`'s own
//! top comment for the shape and for why. On Linux,
//! the driver `Sandbox.spawn` selects always applies a user namespace, a PID
//! namespace, an IPC namespace, a mount namespace, Landlock, and seccomp, and
//! a network namespace unless the caller asks for the host's own network. No
//! layer there is sufficient alone. The PID and IPC namespaces have no
//! configuration field and cannot be turned off: see `namespace.enter` for
//! what each one refuses.
//!
//! On Darwin, the driver runs a real tool call. Seatbelt enforces the paths
//! it may read and write, the network including `AF_UNIX`, and the signals
//! and other interprocess communication it may send. Darwin's own resource
//! limits bound its appetite. **There is no system call filter and no bind
//! mount**, so two of the Linux layers have no equal there and the driver
//! claims neither. `spawn` succeeds for a configuration Darwin can express,
//! and refuses by name one it cannot. See `chock-sandbox/darwin/driver.zig`
//! for which is which, and for the measurement behind every claim.
//!
//! `landlock`, `bpf`, `seccomp`, and `namespace` below are the Linux driver's
//! own mechanism modules, re-exported here unchanged from before the driver
//! split, because `chock-workspace` and `chock-core`
//! both still reach `namespace.Mount` and `landlock.AccessFs` directly, not
//! only through `Sandbox.Config`. They live under `chock-sandbox/linux/` now,
//! the same as every other Linux-only file this module has; see
//! `tools/lint_linux_only.zig`'s own top comment for the rule that puts them
//! there. Exporting them here compiles cleanly for Darwin too, the same as it
//! always has: none of the four collides with a std.c type the way the old,
//! undivided Sandbox.zig once did, which is exactly the false negative
//! `tools/lint_linux_only.zig` exists to catch on the files that do carry
//! real Linux syscalls behind a portable looking name.
pub const landlock = @import("chock-sandbox/linux/landlock.zig");
pub const bpf = @import("chock-sandbox/linux/bpf.zig");
pub const seccomp = @import("chock-sandbox/linux/seccomp.zig");
pub const namespace = @import("chock-sandbox/linux/namespace.zig");
/// The supervisor half of the seccomp user notification, re-exported beside
/// `seccomp` above because a caller that names a `seccomp.TrapSet` reads the
/// counts this module defines. See its own top comment for the handover.
pub const notify = @import("chock-sandbox/linux/notify.zig");
/// The exchange a `namespace.Network.filtered` process uses to reach a host.
/// Re-exported here beside the four above, and for the same reason: the
/// program that runs **inside** a filtered sandbox calls `net_broker.ask`, and
/// the implementation of `Sandbox.NetBroker` that answers it lives in
/// `chock-broker`, so both sides need to name this module without reaching a
/// driver file directly.
pub const net_broker = @import("chock-sandbox/linux/netbroker.zig");
/// The cgroup v2 half of the resource limits, re-exported beside the four
/// above and for the same reason: a caller outside this library needs to name
/// it. `src/doctor.zig` asks this machine whether the memory and pids
/// controllers are delegated **before** a session starts, and everything that
/// walks the delegated parents is private to the file below, so
/// `Cgroup.create` is the only way to learn the answer. Exporting it compiles
/// cleanly for Darwin the same way `namespace` and `seccomp` already do.
pub const cgroup = @import("chock-sandbox/linux/cgroup.zig");
pub const Sandbox = @import("chock-sandbox/Sandbox.zig");
pub const spawn = Sandbox.spawn;
pub const Config = Sandbox.Config;
/// See `Sandbox.Middle`. Re-exported beside `spawn`, which fills one in, and
/// beside the two calls a caller needs to use it at all: every caller of
/// `spawn` that ever cancels a call holds one of these.
pub const Middle = Sandbox.Middle;
/// See `Sandbox.signalMiddle`.
pub const signalMiddle = Sandbox.signalMiddle;
/// See `Sandbox.closeMiddle`.
pub const closeMiddle = Sandbox.closeMiddle;
/// See `Sandbox.SignalError`.
pub const SignalError = Sandbox.SignalError;
/// See `Sandbox.NetBroker`. Re-exported beside `Config`, which names it, so a
/// caller that implements one never has to reach a file under `chock-sandbox/`
/// by path.
pub const NetBroker = Sandbox.NetBroker;
/// See `Sandbox.copyStrings`. Re-exported beside `Config.copy`, which uses it,
/// because a caller that copies a config for a process that outlives one tool
/// call has an argv to copy beside it and must not grow a second spelling of
/// this loop.
pub const copyStrings = Sandbox.copyStrings;
/// See `Sandbox.runtime_prefix`. Re-exported here because both
/// `chock-workspace` and `chock-core` place a path under it, and neither
/// imports the other.
pub const runtime_prefix = Sandbox.runtime_prefix;
/// See `Sandbox.expresses`. Re-exported beside `runtime_prefix`, because a
/// caller that places a path under that prefix is exactly the caller that has
/// to know whether this build can put it there.
pub const expresses = Sandbox.expresses;
/// See `Sandbox.resolvedPath`.
pub const resolvedPath = Sandbox.resolvedPath;
/// See `Sandbox.firstGap`. Re-exported because the two lists it compares are
/// built outside this library: `chock-workspace` writes the workspace half
/// and `chock-core` writes the toolchain half and the per call half.
pub const firstGap = Sandbox.firstGap;
/// See `Sandbox.LayerGap`.
pub const LayerGap = Sandbox.LayerGap;

/// Imported directly, not only through `Sandbox.zig`'s own comptime driver
/// dispatch, so this driver's tests run on every host this project builds
/// on, including the native Linux one `zig build test` normally runs: see
/// `chock-sandbox/darwin/driver.zig`'s own top comment for why that file has
/// nothing target-specific to make that unsafe.
pub const darwin_driver_for_testing = @import("chock-sandbox/darwin/driver.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
