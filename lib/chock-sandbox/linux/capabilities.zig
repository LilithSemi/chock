//! Dropping every capability a sandboxed process holds inside its own user
//! namespace, so the property is a decision this code makes rather than a
//! side effect of how `namespace.writeIdMaps` happens to map a uid.
//!
//! **The process holds a full capability set here today, and the uid map has
//! nothing to do with it.** A process that creates a user namespace holds
//! every capability inside that namespace from the moment `unshare` returns,
//! independent of what `uid_map` and `gid_map` are ever written to. Measured
//! directly, outside this project, with a standalone reproduction of
//! `namespace.writeIdMaps`'s own two lines: mapping the calling uid to itself
//! and mapping it to 0 both read `CapEff = CapPrm = CapBnd =
//! 000001ffffffffff` from `/proc/self/status`, the full set through
//! `CAP_CHECKPOINT_RESTORE`. `seccomp.zig`'s own comment on `blocked_calls`
//! already says as much: "a process in its own user namespace holds
//! CAP_SYS_ADMIN over that namespace." What actually keeps this harmless
//! today is that every syscall those capabilities would matter for inside
//! the sandbox's own namespaces is already refused by that same denylist,
//! and that the kernel's own `ns_capable` check never lets a capability held
//! in a namespace reach an ancestor of it, so none of this ever reaches the
//! host. Neither of those is a property of this file, and neither one drops
//! anything: a syscall the kernel adds tomorrow, gated by a capability and
//! not yet on that denylist, would work today. See
//! `test/sandbox/escape.zig`'s "the sandboxed process holds no capability in
//! its own user namespace", which fails against the code before this file
//! existed, for the ordinary, unprivileged, default sandbox path, not only
//! for root.
//!
//! `dropAll` closes three separate windows, because they are three separate
//! mechanisms the kernel keeps:
//!
//! 1. **The bounding set**, through `PR_CAPBSET_DROP`, once per capability.
//!    A capability removed from the bounding set can never re-enter the
//!    permitted set again: not through a file capability on an executable
//!    inside the sandbox, and not through anything this process or a child
//!    of it does after this call. This is the one closure that survives
//!    every future `execve`, including the caller's own program and
//!    everything it goes on to run.
//! 2. **The kernel's own uid-0 legacy grant**, through `PR_SET_SECUREBITS`.
//!    Without `SECBIT_NOROOT`, a process whose real, effective, or saved uid
//!    becomes 0 is handed capabilities back by compatibility code that
//!    predates file capabilities, on a path that does not go through the
//!    bounding set check at all. Mapping a sandboxed uid to 0, or running
//!    Chock as real root, both reach this path. The `_LOCKED` variants mean
//!    nothing later, in this process or a child, can ever turn the bits back
//!    off.
//! 3. **This process's own three capability sets**, through `capset`:
//!    effective, permitted, and inheritable, all cleared to zero. This is
//!    the only one of the three that changes what this process itself can
//!    do right now, before it ever calls `execve`. The other two only bound
//!    what a future `execve` can hand back.
//!
//! **Order inside `dropAll` is fixed and matters.** The bounding set drop
//! needs `CAP_SETPCAP` in this process's own permitted set, so it runs
//! first, while that capability is still held: dropping a capability out of
//! the bounding set does not remove it from permitted, only `capset` does
//! that, further down. `PR_SET_SECUREBITS` needs the same capability and
//! runs next, for the same reason. `capset` runs last, because it is the
//! step that gives `CAP_SETPCAP` up; nothing after it may still need a
//! capability this process no longer has.
//!
//! **Callers must run this only after every privileged step the sandbox
//! setup still needs.** `namespace.buildRoot` and `namespace.pivotInto` need
//! `CAP_SYS_ADMIN` over the mount tree this process is building; everything
//! after them in `driver.applyLayers` (Landlock, the session keyring join,
//! and seccomp installation) needs no capability at all, and running this
//! function right after `pivotInto` proves that, rather than assuming it.

const std = @import("std");
const linux = std.os.linux;
const namespace = @import("namespace.zig");

pub const Error = error{
    /// A `prctl` or `capset` call the kernel refused.
    Rejected,
};

/// Which call the kernel refused, and what it answered.
///
/// **The same shape `lib/chock-sandbox/linux/namespace.zig` and `landlock.zig`
/// chose**, for the reason both give: this owns no memory and allocates
/// nothing, and every caller of `dropAll` runs in a forked child where
/// `std.debug.print`'s global lock may already be stuck held by a thread that
/// no longer exists in this process.
pub const Diagnostic = struct {
    call: Call,
    errno: linux.E,

    pub const Call = enum {
        capbset_drop,
        set_securebits,
        capset,

        /// What was being done, as a phrase that reads after "capabilities: ".
        pub fn text(self: Call) []const u8 {
            return switch (self) {
                .capbset_drop => "PR_CAPBSET_DROP",
                .set_securebits => "PR_SET_SECUREBITS",
                .capset => "capset",
            };
        }
    };

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("capabilities: {s} failed: {s}", .{ self.call.text(), @tagName(self.errno) });
    }
};

/// Fill `diag` when the caller asked for one. The first fault is kept, not
/// the last, the same rule `namespace.zig`'s own `note` follows.
fn note(diag: ?*?Diagnostic, call: Diagnostic.Call, errno: linux.E) void {
    const slot = diag orelse return;
    if (slot.* != null) return;
    slot.* = .{ .call = call, .errno = errno };
}

/// `_LINUX_CAPABILITY_VERSION_3`: the capability ABI version that addresses
/// every capability through `linux.CAP.LAST_CAP` across two 32 bit words.
/// `std.os.linux` carries the two struct types this version needs
/// (`cap_user_header_t`, `cap_user_data_t`) but not this constant, so it is
/// named here. Version 1 only reaches the first 32 capabilities, which would
/// silently leave everything from `CAP_MAC_OVERRIDE` (32) up to
/// `CAP_CHECKPOINT_RESTORE` (40) out of the `capset` call below.
const capability_version_3: u32 = 0x20080522;

/// Drop every capability this process holds. See this file's own top comment
/// for what each of the three calls below closes, and for the order they
/// must run in.
pub fn dropAll(diag: ?*?Diagnostic) Error!void {
    return dropAllBut(null, diag);
}

/// Drop every capability except the one named, which stays in the permitted
/// and the effective set.
///
/// **For one caller: `linux/driver.zig`'s own `runReader`.** The path reader
/// needs `CAP_SYS_PTRACE` and nothing else. Yama's restricted ptrace mode,
/// which is the default on this project's own machine, permits a read of
/// another process's memory only from an ancestor of that process or from a
/// holder of that capability in that process's user namespace, and the reader
/// is a sibling of the process it reads. Measured on 2026-09-11: a sibling
/// read is answered `EPERM`, and a read by the parent succeeds.
///
/// **The capability is held in the sandbox's own user namespace, which owns
/// nothing.** That namespace was made by `unshare(CLONE_NEWUSER)` a moment
/// earlier, so a capability in it confers nothing at all over any object the
/// host owns. What it does confer is the one power the reader exists to have.
///
/// **The bounding set still goes empty**, so the capability cannot be regained
/// or carried across an `execve`. `capset` does not check the bounding set: it
/// only refuses a permitted set that is not a subset of the old one.
pub fn keepOnly(capability: u32, diag: ?*?Diagnostic) Error!void {
    return dropAllBut(capability, diag);
}

fn dropAllBut(keep: ?u32, diag: ?*?Diagnostic) Error!void {
    var cap: u32 = 0;
    while (cap <= linux.CAP.LAST_CAP) : (cap += 1) {
        const rc = linux.prctl(@intFromEnum(linux.PR.CAPBSET_DROP), @as(usize, cap), 0, 0, 0);
        const call_errno = linux.errno(rc);
        if (call_errno != .SUCCESS) {
            // EINVAL here, and only here, means a kernel older than
            // `linux.CAP.LAST_CAP` was built against: it does not recognize
            // this capability number at all, and every one below it in this
            // loop already came out clean. Every other errno is a real
            // refusal and must not be read as "nothing left to drop".
            if (call_errno == .INVAL) break;
            note(diag, .capbset_drop, call_errno);
            return error.Rejected;
        }
    }

    const secure_bits: usize = linux.SECBIT_NOROOT | linux.SECBIT_NOROOT_LOCKED |
        linux.SECBIT_NO_SETUID_FIXUP | linux.SECBIT_NO_SETUID_FIXUP_LOCKED |
        linux.SECBIT_NO_CAP_AMBIENT_RAISE | linux.SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;
    const secure_rc = linux.prctl(@intFromEnum(linux.PR.SET_SECUREBITS), secure_bits, 0, 0, 0);
    if (linux.errno(secure_rc) != .SUCCESS) {
        note(diag, .set_securebits, linux.errno(secure_rc));
        return error.Rejected;
    }

    var header = linux.cap_user_header_t{ .version = capability_version_3, .pid = 0 };
    var data = [_]linux.cap_user_data_t{
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
    };
    // **Inheritable stays empty for the kept capability too.** Inheritable is
    // what crosses an `execve`, and the one caller that keeps a capability
    // never execs.
    if (keep) |capability| {
        const word = capability / 32;
        const bit = @as(u32, 1) << @intCast(capability % 32);
        if (word < data.len) {
            data[word].permitted |= bit;
            data[word].effective |= bit;
        }
    }
    const capset_rc = linux.capset(&header, &data[0]);
    if (linux.errno(capset_rc) != .SUCCESS) {
        note(diag, .capset, linux.errno(capset_rc));
        return error.Rejected;
    }
}

test "dropAll clears effective, permitted, and inheritable, in a fresh user namespace" {
    // A single threaded child, the same reason `namespace.zig`'s own
    // `probeAvailability` forks one: `unshare(CLONE_NEWUSER)` is refused from
    // a process with more than one thread, and the Zig test runner may have
    // started others by the time this test runs.
    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) return error.SkipZigTest;

    if (fork_rc == 0) {
        // The same call `driver.enterNamespaces` makes, mapping the calling
        // uid to itself: the ordinary, unprivileged, default path, and the
        // one this file's own top comment measured already holds a full
        // capability set before `dropAll` ever runs.
        namespace.enter(.{}, null) catch std.process.exit(63);

        var diag: ?Diagnostic = null;
        dropAll(&diag) catch std.process.exit(63);

        var header = linux.cap_user_header_t{ .version = capability_version_3, .pid = 0 };
        var data: [2]linux.cap_user_data_t = undefined;
        if (linux.errno(linux.capget(&header, &data[0])) != .SUCCESS) std.process.exit(63);

        const all_zero = data[0].effective == 0 and data[1].effective == 0 and
            data[0].permitted == 0 and data[1].permitted == 0 and
            data[0].inheritable == 0 and data[1].inheritable == 0;
        std.process.exit(if (all_zero) 0 else 1);
    }

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    if (linux.errno(wait_rc) != .SUCCESS or !linux.W.IFEXITED(status)) return error.SkipZigTest;

    const code = linux.W.EXITSTATUS(status);
    if (code == 63) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), code);
}

test "keepOnly leaves one capability and takes every other one away" {
    // **The path reader needs `CAP_SYS_PTRACE` and must hold nothing else.**
    // A `keepOnly` that kept the whole set would give a process that reads
    // another process's memory every power the supervisor had.
    //
    // Mutation check: make `dropAllBut` ignore `keep` and the first
    // expectation fails; make it write the bit into every word and the
    // second fails.
    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) return error.SkipZigTest;

    if (fork_rc == 0) {
        namespace.enter(.{}, null) catch std.process.exit(63);
        keepOnly(linux.CAP.SYS_PTRACE, null) catch std.process.exit(63);

        var header = linux.cap_user_header_t{ .version = capability_version_3, .pid = 0 };
        var data: [2]linux.cap_user_data_t = undefined;
        if (linux.errno(linux.capget(&header, &data[0])) != .SUCCESS) std.process.exit(63);

        const only_ptrace: u32 = @as(u32, 1) << linux.CAP.SYS_PTRACE;
        const kept = data[0].effective == only_ptrace and data[0].permitted == only_ptrace;
        const rest_clear = data[1].effective == 0 and data[1].permitted == 0 and
            data[0].inheritable == 0 and data[1].inheritable == 0;
        if (!kept) std.process.exit(1);
        if (!rest_clear) std.process.exit(2);
        std.process.exit(0);
    }

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    if (linux.errno(wait_rc) != .SUCCESS or !linux.W.IFEXITED(status)) return error.SkipZigTest;

    const code = linux.W.EXITSTATUS(status);
    if (code == 63) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), code);
}
