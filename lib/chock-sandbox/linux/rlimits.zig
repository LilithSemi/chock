//! Resource limits for sandboxed processes: memory, file descriptors, file
//! size, CPU time, process count, and scratch area size.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const default_memory_bytes: u64 = 2 << 30;

pub const default_mapped_memory_bytes: u64 = 16 << 30;

pub const default_processes: u64 = 256;

pub const default_open_files: u64 = 1024;

pub const default_file_size_bytes: u64 = 1 << 30;

pub const default_scratch_bytes: u64 = 256 << 20;

pub const scratch_memory_headroom: u64 = 4;

pub const default_cpu_seconds: u64 = 3600;

pub const cpu_grace_seconds: u64 = 30;

pub const nproc_per_user_namespace_since: Release = .{ .major = 5, .minor = 14 };

pub const Release = struct {
    major: u32,
    minor: u32,

    pub fn atLeast(self: Release, other: Release) bool {
        if (self.major != other.major) return self.major > other.major;
        return self.minor >= other.minor;
    }
};

pub const Limits = struct {
    memory_bytes: ?u64 = default_memory_bytes,
    mapped_memory_bytes: ?u64 = default_mapped_memory_bytes,
    processes: ?u64 = default_processes,
    open_files: ?u64 = default_open_files,
    file_size_bytes: ?u64 = default_file_size_bytes,
    cpu_seconds: ?u64 = default_cpu_seconds,
    scratch_bytes: ?u64 = default_scratch_bytes,

    pub const none: Limits = .{
        .memory_bytes = null,
        .mapped_memory_bytes = null,
        .processes = null,
        .open_files = null,
        .file_size_bytes = null,
        .cpu_seconds = null,
        .scratch_bytes = null,
    };

    pub fn narrow(self: Limits, other: Limits) Limits {
        return .{
            .memory_bytes = smaller(self.memory_bytes, other.memory_bytes),
            .mapped_memory_bytes = smaller(self.mapped_memory_bytes, other.mapped_memory_bytes),
            .processes = smaller(self.processes, other.processes),
            .open_files = smaller(self.open_files, other.open_files),
            .file_size_bytes = smaller(self.file_size_bytes, other.file_size_bytes),
            .cpu_seconds = smaller(self.cpu_seconds, other.cpu_seconds),
            .scratch_bytes = smaller(self.scratch_bytes, other.scratch_bytes),
        };
    }

    pub fn isEmpty(self: Limits) bool {
        return self.memory_bytes == null and self.mapped_memory_bytes == null and
            self.processes == null and self.open_files == null and
            self.file_size_bytes == null and self.cpu_seconds == null and
            self.scratch_bytes == null;
    }

    pub fn scratchFitsUnderMemory(self: Limits) bool {
        const memory = self.memory_bytes orelse return true;
        const scratch = self.scratch_bytes orelse return false;
        return scratch * scratch_memory_headroom <= memory;
    }

    pub fn wantsCgroup(self: Limits) bool {
        return self.memory_bytes != null or self.processes != null;
    }
};

fn smaller(a: ?u64, b: ?u64) ?u64 {
    const left = a orelse return b;
    const right = b orelse return left;
    return @min(left, right);
}

pub const Diagnostic = struct {
    limit: Which,
    errno: linux.E,

    pub const Which = enum {
        memory,
        mapped_memory,
        processes,
        open_files,
        file_size,
        cpu_time,
        core_dump,
        scratch_space,

        pub fn text(self: Which) []const u8 {
            return switch (self) {
                .memory => "memory",
                .mapped_memory => "mapped memory",
                .processes => "the number of processes",
                .open_files => "open files",
                .file_size => "the size of one file",
                .cpu_time => "cpu time",
                .core_dump => "core dumps",
                .scratch_space => "the space in the sandbox's own scratch area",
            };
        }
    };

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("the limit on {s} could not be set: {s}", .{
            self.limit.text(),
            @tagName(self.errno),
        });
    }
};

pub const Error = error{LimitRefused};

pub fn apply(limits: Limits, kernel: Release, diag: *?Diagnostic) Error!void {
    // A core dump is refused whatever the caller asked for; there is no configuration field for the other answer.
    try set(.CORE, 0, 0, .core_dump, diag);

    if (limits.mapped_memory_bytes) |bytes| try set(.DATA, bytes, bytes, .mapped_memory, diag);
    if (limits.open_files) |count| try set(.NOFILE, count, count, .open_files, diag);
    if (limits.file_size_bytes) |bytes| try set(.FSIZE, bytes, bytes, .file_size, diag);

    if (limits.cpu_seconds) |seconds| {
        // Soft below hard on purpose, so the death signal is SIGXCPU and not SIGKILL.
        try set(.CPU, seconds, seconds + cpu_grace_seconds, .cpu_time, diag);
    }

    if (limits.processes) |count| {
        // Skipped on a kernel where this counts the user's own processes on the host; see nproc_per_user_namespace_since.
        if (kernel.atLeast(nproc_per_user_namespace_since)) {
            try set(.NPROC, count, count, .processes, diag);
        }
    }
}

fn set(
    resource: linux.rlimit_resource,
    soft: u64,
    hard: u64,
    which: Diagnostic.Which,
    diag: *?Diagnostic,
) Error!void {
    const value = linux.rlimit{ .cur = soft, .max = hard };
    const rc = linux.setrlimit(resource, &value);
    const set_errno = linux.errno(rc);
    if (set_errno == .SUCCESS) return;
    if (diag.* == null) diag.* = .{ .limit = which, .errno = set_errno };
    return error.LimitRefused;
}

pub fn runningKernel() Release {
    var uts: linux.utsname = undefined;
    if (linux.errno(linux.uname(&uts)) != .SUCCESS) return .{ .major = 0, .minor = 0 };
    return parseRelease(std.mem.sliceTo(&uts.release, 0));
}

pub fn parseRelease(release: []const u8) Release {
    var parts = std.mem.splitScalar(u8, release, '.');
    const major_text = parts.next() orelse return .{ .major = 0, .minor = 0 };
    const minor_text = parts.next() orelse return .{ .major = 0, .minor = 0 };
    const major = std.fmt.parseInt(u32, leadingDigits(major_text), 10) catch return .{ .major = 0, .minor = 0 };
    const minor = std.fmt.parseInt(u32, leadingDigits(minor_text), 10) catch return .{ .major = major, .minor = 0 };
    return .{ .major = major, .minor = minor };
}

fn leadingDigits(text: []const u8) []const u8 {
    var end: usize = 0;
    while (end < text.len and std.ascii.isDigit(text[end])) end += 1;
    return text[0..end];
}

pub fn limitForSignal(signal: std.posix.SIG) ?Diagnostic.Which {
    if (signal == .XCPU) return .cpu_time;
    if (signal == .XFSZ) return .file_size;
    return null;
}

test "a null limit is the widest, and narrow can only ever lower a number" {
    const defaults = Limits{};
    const project_asks_for_more = Limits{
        .memory_bytes = 64 << 30,
        .mapped_memory_bytes = 1 << 40,
        .processes = 100000,
        .open_files = 1 << 20,
        .file_size_bytes = 1 << 40,
        .cpu_seconds = 1 << 20,
        .scratch_bytes = 1 << 40,
    };
    const folded = defaults.narrow(project_asks_for_more);
    try std.testing.expectEqual(defaults, folded);

    const project_asks_for_less = Limits{
        .memory_bytes = 1 << 20,
        .mapped_memory_bytes = 1 << 21,
        .processes = 4,
        .open_files = 16,
        .file_size_bytes = 1024,
        .cpu_seconds = 1,
        .scratch_bytes = 4096,
    };
    try std.testing.expectEqual(project_asks_for_less, defaults.narrow(project_asks_for_less));

    try std.testing.expectEqual(
        @as(?u64, 16),
        (Limits{ .open_files = null }).narrow(.{ .open_files = 16 }).open_files,
    );
    try std.testing.expectEqual(
        @as(?u64, 16),
        (Limits{ .open_files = 16 }).narrow(.{ .open_files = null }).open_files,
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        Limits.none.narrow(Limits.none).open_files,
    );

    const mixed = (Limits{ .memory_bytes = 100, .processes = 8 })
        .narrow(.{ .memory_bytes = 200, .processes = 4 });
    try std.testing.expectEqual(@as(?u64, 100), mixed.memory_bytes);
    try std.testing.expectEqual(@as(?u64, 4), mixed.processes);
}

test "the scratch cap cannot push the sandbox into an out of memory kill" {
    try std.testing.expect((Limits{}).scratchFitsUnderMemory());
    try std.testing.expect(default_scratch_bytes * scratch_memory_headroom <= default_memory_bytes);

    const memory: u64 = 1 << 30;
    try std.testing.expect((Limits{
        .memory_bytes = memory,
        .scratch_bytes = memory / scratch_memory_headroom,
    }).scratchFitsUnderMemory());
    try std.testing.expect(!(Limits{
        .memory_bytes = memory,
        .scratch_bytes = memory / scratch_memory_headroom + 1,
    }).scratchFitsUnderMemory());
    try std.testing.expect(!(Limits{
        .memory_bytes = memory,
        .scratch_bytes = memory,
    }).scratchFitsUnderMemory());

    try std.testing.expect((Limits{ .memory_bytes = null, .scratch_bytes = 1 << 40 }).scratchFitsUnderMemory());

    try std.testing.expect(!(Limits{ .memory_bytes = 1 << 30, .scratch_bytes = null }).scratchFitsUnderMemory());

    try std.testing.expect(Limits.none.scratchFitsUnderMemory());

    try std.testing.expect(!(Limits{}).narrow(.{ .memory_bytes = 1 << 20 }).scratchFitsUnderMemory());
}

test "a kernel release is compared by major then minor, and an unreadable one reads as old" {
    try std.testing.expectEqual(Release{ .major = 6, .minor = 18 }, parseRelease("6.18.42"));
    try std.testing.expectEqual(Release{ .major = 5, .minor = 15 }, parseRelease("5.15.0-91-generic"));
    try std.testing.expectEqual(Release{ .major = 5, .minor = 14 }, parseRelease("5.14.0"));
    try std.testing.expectEqual(Release{ .major = 6, .minor = 1 }, parseRelease("6.1.0-rc4"));

    try std.testing.expectEqual(Release{ .major = 0, .minor = 0 }, parseRelease(""));
    try std.testing.expectEqual(Release{ .major = 0, .minor = 0 }, parseRelease("linux"));
    try std.testing.expectEqual(Release{ .major = 0, .minor = 0 }, parseRelease("6"));

    try std.testing.expect((Release{ .major = 5, .minor = 14 }).atLeast(nproc_per_user_namespace_since));
    try std.testing.expect((Release{ .major = 6, .minor = 0 }).atLeast(nproc_per_user_namespace_since));
    try std.testing.expect(!(Release{ .major = 5, .minor = 13 }).atLeast(nproc_per_user_namespace_since));
    try std.testing.expect(!(Release{ .major = 4, .minor = 19 }).atLeast(nproc_per_user_namespace_since));
    try std.testing.expect(!(Release{ .major = 0, .minor = 0 }).atLeast(nproc_per_user_namespace_since));

    // Linux only: runningKernel calls uname through a raw Linux syscall number that crashes with SIGABRT on Darwin.
    if (builtin.os.tag != .linux) return;
    try std.testing.expect(runningKernel().major > 0);
}

test "a diagnostic names the resource and the errno, and every resource reads differently" {
    var buffer: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "the limit on memory could not be set: PERM",
        try std.fmt.bufPrint(&buffer, "{f}", .{Diagnostic{ .limit = .memory, .errno = .PERM }}),
    );

    const all = std.enums.values(Diagnostic.Which);
    for (all, 0..) |which, i| {
        try std.testing.expect(which.text().len > 0);
        for (all[i + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, which.text(), other.text()));
        }
    }
}

test "the two limits that kill say which one they were, through the signal number" {
    try std.testing.expectEqual(
        @as(?Diagnostic.Which, .cpu_time),
        limitForSignal(std.posix.SIG.XCPU),
    );
    try std.testing.expectEqual(
        @as(?Diagnostic.Which, .file_size),
        limitForSignal(std.posix.SIG.XFSZ),
    );

    try std.testing.expectEqual(
        @as(?Diagnostic.Which, null),
        limitForSignal(std.posix.SIG.TERM),
    );
    try std.testing.expectEqual(
        @as(?Diagnostic.Which, null),
        limitForSignal(std.posix.SIG.KILL),
    );
    try std.testing.expectEqual(
        @as(?Diagnostic.Which, null),
        limitForSignal(std.posix.SIG.SEGV),
    );
}

test "apply really sets the limits, in a forked child that cannot take this process with it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        var diag: ?Diagnostic = null;
        apply(.{
            .memory_bytes = null,
            .mapped_memory_bytes = null,
            .processes = null,
            .open_files = 42,
            .file_size_bytes = 4096,
            .cpu_seconds = 1234,
        }, runningKernel(), &diag) catch std.process.exit(2);

        var read_back: linux.rlimit = undefined;
        var ok = true;

        _ = linux.getrlimit(.NOFILE, &read_back);
        ok = ok and read_back.cur == 42 and read_back.max == 42;

        _ = linux.getrlimit(.FSIZE, &read_back);
        ok = ok and read_back.cur == 4096 and read_back.max == 4096;

        _ = linux.getrlimit(.CPU, &read_back);
        ok = ok and read_back.cur == 1234 and read_back.max == 1234 + cpu_grace_seconds;

        _ = linux.getrlimit(.CORE, &read_back);
        ok = ok and read_back.cur == 0 and read_back.max == 0;

        const raise = linux.rlimit{ .cur = 4096, .max = 4096 };
        const refused = linux.errno(linux.setrlimit(.NOFILE, &raise)) == .PERM;
        ok = ok and refused;

        std.process.exit(if (ok) 0 else 1);
    }

    var status: u32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}
