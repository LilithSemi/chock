//! The resource limits half of the Darwin driver. Three of the seven limits
//! `../linux/rlimits.zig` defines have no Darwin mechanism and report unsupported.

const std = @import("std");
const builtin = @import("builtin");
const rlimits = @import("../linux/rlimits.zig");

const Resource = enum(c_int) {
    cpu = 0,
    file_size = 1,
    data = 2,
    core = 4,
    address_space = 5,
    processes = 7,
    open_files = 8,
};

pub const Limits = rlimits.Limits;

pub const Report = struct {
    limits: Limits = .{},
    cpu_time: State = .off,
    file_size: State = .off,
    open_files: State = .off,
    mapped_memory: State = .{ .unsupported = .no_such_rlimit },
    memory: State = .{ .unsupported = .no_cgroup },
    processes: State = .{ .unsupported = .counts_the_whole_user },
    scratch_space: State = .{ .unsupported = .no_mountable_filesystem },

    pub const State = union(enum) {
        ok,
        off,
        unsupported: Reason,
        unavailable: Reason,

        pub const Reason = enum {
            no_such_rlimit,
            no_cgroup,
            counts_the_whole_user,
            no_mountable_filesystem,
            set_refused,

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

    pub fn anyApplied(self: Report) bool {
        return self.cpu_time.applied() or self.file_size.applied() or self.open_files.applied();
    }
};

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

pub fn apply(limits: Limits) Report {
    var report: Report = .{ .limits = limits };
    if (limits.cpu_seconds) |seconds| report.cpu_time = setBoth(.cpu, seconds);
    if (limits.file_size_bytes) |bytes| report.file_size = setBoth(.file_size, bytes);
    if (limits.open_files) |count| report.open_files = setBoth(.open_files, count);
    // Do not set processes here: RLIMIT_NPROC counts the whole user, not the
    // sandbox, and stops it forking at all on an ordinary machine.
    return report;
}

test "the four limits Darwin cannot carry report unsupported before anything runs" {
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
    const report = apply(Limits.none);
    try std.testing.expectEqual(Report.State.off, report.cpu_time);
    try std.testing.expectEqual(Report.State.off, report.file_size);
    try std.testing.expectEqual(Report.State.off, report.open_files);
    try std.testing.expect(!report.anyApplied());
}

test "apply never claims a limit on a build that is not for macOS" {
    if (builtin.os.tag == .macos) return;
    const report = apply(.{ .cpu_seconds = 10, .file_size_bytes = 4096, .open_files = 64 });
    try std.testing.expect(!report.cpu_time.applied());
    try std.testing.expect(!report.file_size.applied());
    try std.testing.expect(!report.open_files.applied());
    try std.testing.expectEqual(Report.State.Reason.no_such_rlimit, report.cpu_time.unsupported);
}
