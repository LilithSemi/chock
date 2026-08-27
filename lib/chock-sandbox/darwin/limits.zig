//! The resource limits half of the Darwin driver, and the honest record of how
//! much of it Darwin has.
//!
//! **Every other layer of this sandbox is about reach. This one is about
//! appetite.** A fork bomb, an allocation that never stops, and a descriptor
//! leak all pass Seatbelt without touching it, exactly as they pass Landlock and
//! seccomp on Linux. See `../linux/rlimits.zig`, which owns `Limits` and every
//! default in it, and whose top comment explains each number.
//!
//! ## What Darwin has, and what it has not
//!
//! **There is no cgroup on Darwin, and there is no substitute for one.** So the
//! Linux driver's two layers, the rlimit floor and the cgroup ceiling, come down
//! to the floor alone here. That is not a matter of writing more code: the
//! things the cgroup carried have no Darwin mechanism at all.
//!
//! Every row below was measured on macOS 15.7.9, arm64, on 2026-08-25, by
//! setting the limit and then trying to exceed it. A row is `ok` only where the
//! kernel actually refused the excess.
//!
//! | limit | Darwin | what the measurement showed |
//! |---|---|---|
//! | cpu time | ok | `RLIMIT_CPU` of 1 second ended a busy loop with `SIGXCPU` |
//! | size of one file | ok | `RLIMIT_FSIZE` of 4096 refused the write that would have passed it, with `EFBIG`, and the file was exactly 4096 bytes |
//! | open files | ok | `RLIMIT_NOFILE` of 24 refused the open after 21 more descriptors, with `EMFILE` |
//! | mapped memory | **unsupported** | `setrlimit` answers `EINVAL` for `RLIMIT_AS` and for `RLIMIT_DATA`. With both attempted, a 512 MiB anonymous mapping still succeeded |
//! | resident memory | **unsupported** | the Linux answer is `memory.max` in a cgroup, and Darwin has no cgroup |
//! | number of processes | **unsupported**, see below | `RLIMIT_NPROC` is settable and enforced, and it counts the user's processes across the whole machine |
//! | scratch space | **unsupported** | the Linux answer is a tmpfs with a `size=` option. An unprivileged user on macOS cannot mount a filesystem at all |
//!
//! ## Why the process limit is not applied, although it works
//!
//! `RLIMIT_NPROC` on Darwin counts every process of the user, on the machine,
//! not the processes of this sandbox. Darwin has no user namespaces, so it has
//! none of the per namespace behaviour Linux gained in 5.14; see
//! `../linux/rlimits.zig`'s own `nproc_per_user_namespace_since`.
//!
//! **Applied here it would not bound the sandbox, and it would stop the sandbox
//! running.** Measured on 2026-08-25: with `RLIMIT_NPROC` set to 4 on a machine
//! where the user already had far more than four processes, the very first
//! `fork` was refused with `EAGAIN`, before the sandbox had started anything at
//! all. So the caller's number means something entirely different here, and
//! obeying it produces a sandbox that cannot run a program rather than a sandbox
//! that is bounded. It is left off, and reported as unsupported, which is the
//! only honest pair of those two.

const std = @import("std");
const builtin = @import("builtin");
const rlimits = @import("../linux/rlimits.zig");

/// Named here rather than reached through `std.c` so the numbers are visible
/// beside the measurements that used them. They are Darwin's own, from
/// `sys/resource.h`, and they differ from Linux's.
const Resource = enum(c_int) {
    cpu = 0,
    file_size = 1,
    data = 2,
    core = 4,
    /// Darwin defines `RLIMIT_AS` and `RLIMIT_RSS` as the same number.
    address_space = 5,
    processes = 7,
    open_files = 8,
};

/// See `../linux/rlimits.zig`. The type is shared, so a caller writes one set of
/// numbers and each driver applies the part of it that platform really has.
pub const Limits = rlimits.Limits;

/// Which of the caller's limits went on, one field per limit, and never a plain
/// boolean for the whole layer.
///
/// **A single "limits applied" flag would be a false OK.** Three of the seven
/// limits have no Darwin mechanism, so a caller that read one flag would believe
/// in a memory bound that is not there. See this file's own top comment for the
/// measurement behind every row.
pub const Report = struct {
    /// The numbers that were asked for.
    limits: Limits = .{},
    cpu_time: State = .off,
    file_size: State = .off,
    open_files: State = .off,
    /// Always `unsupported` on Darwin. `RLIMIT_AS` and `RLIMIT_DATA` both
    /// answer `EINVAL`.
    mapped_memory: State = .{ .unsupported = .no_such_rlimit },
    /// Always `unsupported` on Darwin. There is no cgroup.
    memory: State = .{ .unsupported = .no_cgroup },
    /// Always `unsupported` on Darwin. `RLIMIT_NPROC` counts the user's
    /// processes across the machine, so it bounds the wrong thing.
    processes: State = .{ .unsupported = .counts_the_whole_user },
    /// Always `unsupported` on Darwin. An unprivileged user cannot mount a
    /// filesystem, so there is no capped area to give.
    scratch_space: State = .{ .unsupported = .no_mountable_filesystem },

    pub const State = union(enum) {
        /// The limit was set and the kernel enforces it.
        ok,
        /// The caller asked for no such limit.
        off,
        /// Darwin has no mechanism for this limit.
        unsupported: Reason,
        /// Darwin has one and this process did not get it.
        unavailable: Reason,

        pub const Reason = enum {
            no_such_rlimit,
            no_cgroup,
            counts_the_whole_user,
            no_mountable_filesystem,
            /// `setrlimit` was called and refused.
            set_refused,

            /// What happened, as a phrase that reads after "no limit: ".
            pub fn text(self: Reason) []const u8 {
                return switch (self) {
                    .no_such_rlimit => "macos has no resource limit for this",
                    .no_cgroup => "macos has no cgroup, so there is no memory ceiling",
                    .counts_the_whole_user => "the process limit on macos counts every process of the user, not this sandbox",
                    .no_mountable_filesystem => "an ordinary user on macos cannot mount a filesystem, so there is no capped area",
                    .set_refused => "the kernel refused the limit",
                };
            }
        };

        pub fn applied(self: State) bool {
            return self == .ok;
        }
    };

    /// True when at least one limit really went on. Used only for reporting.
    pub fn anyApplied(self: Report) bool {
        return self.cpu_time.applied() or self.file_size.applied() or self.open_files.applied();
    }
};

/// Set one limit, hard and soft together, and say what happened.
///
/// **The hard half matters as much as the soft one.** A process may raise its
/// own soft limit up to its hard limit at any time, so a soft limit alone is a
/// suggestion to a program that does not want it. Measured on 2026-08-25: with
/// both halves lowered, the same process could not put either back, and
/// `setrlimit` answered `EPERM`.
fn setBoth(resource: Resource, value: u64) Report.State {
    if (builtin.os.tag == .macos) {
        const limit: std.c.rlimit = .{ .cur = value, .max = value };
        if (std.c.setrlimit(@enumFromInt(@intFromEnum(resource)), &limit) != 0) {
            return .{ .unavailable = .set_refused };
        }
        return .ok;
    } else {
        return .{ .unsupported = .no_such_rlimit };
    }
}

/// Put the limits Darwin honours on this process, and answer which went on.
///
/// **Called after the fork and before `sandbox_init`.** A limit set here is
/// inherited by everything the program goes on to start, exactly as on Linux.
/// It runs before the confinement only because it needs nothing the confinement
/// would take away; the order of the two is otherwise free.
///
/// This never prints and never allocates, so it is safe in the window between
/// `fork` and `execve`.
pub fn apply(limits: Limits) Report {
    var report: Report = .{ .limits = limits };
    if (limits.cpu_seconds) |seconds| report.cpu_time = setBoth(.cpu, seconds);
    if (limits.file_size_bytes) |bytes| report.file_size = setBoth(.file_size, bytes);
    if (limits.open_files) |count| report.open_files = setBoth(.open_files, count);
    // `processes`, `memory_bytes`, `mapped_memory_bytes` and `scratch_bytes` are
    // deliberately not read. Their `Report` fields already say `unsupported`
    // from their defaults, and this file's top comment holds the measurement for
    // each one. **Do not add a `setBoth(.processes, ...)` line here**: it works,
    // and it stops the sandbox forking at all on any ordinary machine.
    return report;
}

test "the four limits Darwin cannot carry report unsupported before anything runs" {
    // The defaults are the claim, so a reader who deletes a line in `apply`
    // cannot accidentally turn one of these into an `ok`.
    const report = Report{};
    try std.testing.expect(!report.memory.applied());
    try std.testing.expect(!report.mapped_memory.applied());
    try std.testing.expect(!report.processes.applied());
    try std.testing.expect(!report.scratch_space.applied());
    try std.testing.expectEqual(Report.State.Reason.no_cgroup, report.memory.unsupported);
    try std.testing.expectEqual(Report.State.Reason.no_such_rlimit, report.mapped_memory.unsupported);
    try std.testing.expectEqual(Report.State.Reason.counts_the_whole_user, report.processes.unsupported);
    try std.testing.expectEqual(Report.State.Reason.no_mountable_filesystem, report.scratch_space.unsupported);
}

test "a limit the caller did not ask for reads off, not ok" {
    // `off` and `ok` must never read the same: one says nothing was asked for
    // and the other says a boundary exists.
    const report = apply(Limits.none);
    try std.testing.expectEqual(Report.State.off, report.cpu_time);
    try std.testing.expectEqual(Report.State.off, report.file_size);
    try std.testing.expectEqual(Report.State.off, report.open_files);
    try std.testing.expect(!report.anyApplied());
}

test "apply never claims a limit on a build that is not for macOS" {
    // A build for another target has no `setrlimit` of Darwin's to call, and
    // must say so rather than report a bound nothing enforces.
    if (builtin.os.tag == .macos) return;
    const report = apply(.{ .cpu_seconds = 10, .file_size_bytes = 4096, .open_files = 64 });
    try std.testing.expect(!report.cpu_time.applied());
    try std.testing.expect(!report.file_size.applied());
    try std.testing.expect(!report.open_files.applied());
    try std.testing.expectEqual(Report.State.Reason.no_such_rlimit, report.cpu_time.unsupported);
}
