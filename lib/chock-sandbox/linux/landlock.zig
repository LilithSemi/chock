const std = @import("std");
const linux = std.os.linux;

const CREATE_RULESET_VERSION: u32 = 1 << 0;

const RESTRICT_SELF_LOG_NEW_EXEC_ON: u32 = 1 << 1;

/// What a Landlock ABI version can do. Each field names the version that added it.
pub const Features = struct {
    supported: bool,
    /// A rename or a link across two directories. ABI 2.
    refer: bool,
    truncate: bool,
    /// Rules for a TCP bind and a TCP connect. ABI 4.
    net: bool,
    ioctl_dev: bool,
    /// A scope for an abstract unix socket and for a signal. ABI 6.
    scope: bool,
    audit: bool,
};

pub fn featuresFor(abi: i32) Features {
    return .{
        .supported = abi >= 1,
        .refer = abi >= 2,
        .truncate = abi >= 3,
        .net = abi >= 4,
        .ioctl_dev = abi >= 5,
        .scope = abi >= 6,
        .audit = abi >= 7,
    };
}

fn auditFlags(features: Features) u32 {
    if (!features.audit) return 0;
    return RESTRICT_SELF_LOG_NEW_EXEC_ON;
}

pub const ProbeError = error{
    NotSupported,
    Unexpected,
};

pub fn probeAbi() ProbeError!i32 {
    const rc = linux.syscall3(.landlock_create_ruleset, 0, 0, CREATE_RULESET_VERSION);
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .NOSYS, .OPNOTSUPP => error.NotSupported,
        else => error.Unexpected,
    };
}

test "featuresFor gives each ABI version the features that version added" {
    try std.testing.expect(!featuresFor(0).supported);
    try std.testing.expect(featuresFor(1).supported);
    try std.testing.expect(!featuresFor(1).refer);
    try std.testing.expect(featuresFor(2).refer);
    try std.testing.expect(!featuresFor(2).truncate);
    try std.testing.expect(featuresFor(3).truncate);
    try std.testing.expect(!featuresFor(3).net);
    try std.testing.expect(featuresFor(4).net);
    try std.testing.expect(featuresFor(5).ioctl_dev);
    try std.testing.expect(featuresFor(6).scope);
    try std.testing.expect(!featuresFor(6).audit);
    try std.testing.expect(featuresFor(7).audit);
}

test "auditFlags asks the kernel to log the exec'd program's denials at ABI 7, and asks nothing below it" {
    try std.testing.expectEqual(@as(u32, 0), auditFlags(featuresFor(6)));
    try std.testing.expectEqual(@as(u32, 1 << 1), auditFlags(featuresFor(7)));
}

test "restrictSelf on ABI 7 succeeds with the audit flag, proved on a real kernel" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const abi = probeAbi() catch return error.SkipZigTest;
    if (!featuresFor(abi).audit) return error.SkipZigTest;
    const ok = restrictSelfSucceeds(abi) orelse return error.SkipZigTest;
    try std.testing.expect(ok);
}

test "restrictSelf below ABI 7 still succeeds, with no audit flag and no new refusal" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    _ = probeAbi() catch return error.SkipZigTest;
    try std.testing.expect(!featuresFor(6).audit);
    const ok = restrictSelfSucceeds(6) orelse return error.SkipZigTest;
    try std.testing.expect(ok);
}

/// Forks, builds a ruleset for `abi` in the child, and reports whether
/// `restrictSelf` succeeded. Returns null when nothing could be proved.
fn restrictSelfSucceeds(abi: i32) ?bool {
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return null;

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return null;
    }

    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        const record: [1]u8 = .{childRestrictSelf(abi)};
        _ = linux.write(fds[1], &record, 1);
        std.process.exit(0);
    }

    _ = linux.close(fds[1]);
    var record: [1]u8 = .{0};
    var held: usize = 0;
    while (held < record.len) {
        const rc = linux.read(fds[0], record[held..].ptr, record.len - held);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        held += rc;
    }
    _ = linux.close(fds[0]);

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);

    if (held != record.len) return null;
    return record[0] == 2;
}

fn childRestrictSelf(abi: i32) u8 {
    var ruleset = Ruleset.init(abi, null) catch return 1;
    if (ruleset.restrictSelf(null)) |_| return 2 else |_| return 0;
}

test "probeAbi reports a usable ABI version on a kernel with Landlock" {
    const abi = probeAbi() catch {
        return error.SkipZigTest;
    };
    try std.testing.expect(abi >= 1);
    try std.testing.expect(featuresFor(abi).supported);
}

/// The file access rights of Landlock ABI 1. Later versions add more.
pub const AccessFs = packed struct(u64) {
    execute: bool = false,
    write_file: bool = false,
    read_file: bool = false,
    read_dir: bool = false,
    remove_dir: bool = false,
    remove_file: bool = false,
    make_char: bool = false,
    make_dir: bool = false,
    make_reg: bool = false,
    make_sock: bool = false,
    make_fifo: bool = false,
    make_block: bool = false,
    make_sym: bool = false,
    refer: bool = false,
    truncate: bool = false,
    ioctl_dev: bool = false,
    _padding: u48 = 0,

    pub const read_only: AccessFs = .{
        .execute = true,
        .read_file = true,
        .read_dir = true,
    };

    /// read_only for a rule path that is a regular file, not a directory: the
    /// kernel refuses read_dir, a directory right, on a file.
    pub const read_only_file: AccessFs = .{
        .execute = true,
        .read_file = true,
    };

    pub const read_write: AccessFs = .{
        .execute = true,
        .write_file = true,
        .read_file = true,
        .read_dir = true,
        .remove_dir = true,
        .remove_file = true,
        .make_dir = true,
        .make_reg = true,
        .make_sock = true,
        .make_fifo = true,
        .make_sym = true,
        .refer = true,
        .truncate = true,
        .ioctl_dev = true,
    };

    /// Every right this struct knows. For `Ruleset.init` only, not for a grant.
    pub const all: AccessFs = .{
        .execute = true,
        .write_file = true,
        .read_file = true,
        .read_dir = true,
        .remove_dir = true,
        .remove_file = true,
        .make_char = true,
        .make_dir = true,
        .make_reg = true,
        .make_sock = true,
        .make_fifo = true,
        .make_block = true,
        .make_sym = true,
        .refer = true,
        .truncate = true,
        .ioctl_dev = true,
    };

    pub fn bits(self: AccessFs) u64 {
        return @bitCast(self);
    }

    pub fn maskFor(self: AccessFs, f: Features) AccessFs {
        var out = self;
        if (!f.refer) out.refer = false;
        if (!f.truncate) out.truncate = false;
        if (!f.ioctl_dev) out.ioctl_dev = false;
        return out;
    }
};

const RulesetAttr = extern struct {
    handled_access_fs: u64,
};

const PathBeneathAttr = extern struct {
    allowed_access: u64,
    parent_fd: i32,
};

pub const RulesetError = error{
    NotSupported,
    PathNotFound,
    AccessDenied,
    NotADirectory,
    PathTooLong,
    Rejected,
    Unexpected,
};

pub const Diagnostic = struct {
    call: Call,
    errno: linux.E,

    pub const Call = enum {
        create_ruleset,
        rule_path_open,
        add_rule,
        restrict_self,

        pub fn text(self: Call) []const u8 {
            return switch (self) {
                .create_ruleset => "create_ruleset",
                .rule_path_open => "open on a rule path",
                .add_rule => "add_rule",
                .restrict_self => "restrict_self",
            };
        }
    };

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("landlock: {s} failed: {s}", .{ self.call.text(), @tagName(self.errno) });
    }
};

fn note(diag: ?*?Diagnostic, call: Diagnostic.Call, errno: linux.E) void {
    const slot = diag orelse return;
    if (slot.* != null) return;
    slot.* = .{ .call = call, .errno = errno };
}

pub const Ruleset = struct {
    fd: i32,
    features: Features,

    pub fn init(abi: i32, diag: ?*?Diagnostic) RulesetError!Ruleset {
        const features = featuresFor(abi);
        const handled = AccessFs.all.maskFor(features);
        var attr = RulesetAttr{ .handled_access_fs = handled.bits() };
        const rc = linux.syscall3(
            .landlock_create_ruleset,
            @intFromPtr(&attr),
            @sizeOf(RulesetAttr),
            0,
        );
        switch (linux.errno(rc)) {
            .SUCCESS => return .{ .fd = @intCast(rc), .features = features },
            .NOSYS, .OPNOTSUPP => return error.NotSupported,
            else => |err| {
                note(diag, .create_ruleset, err);
                return error.Unexpected;
            },
        }
    }

    pub fn deinit(self: *Ruleset) void {
        _ = linux.close(self.fd);
        self.fd = -1;
    }

    pub fn allowPath(
        self: *Ruleset,
        path: []const u8,
        access: AccessFs,
        diag: ?*?Diagnostic,
    ) RulesetError!void {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path_z = std.fmt.bufPrintZ(&buffer, "{s}", .{path}) catch return error.PathTooLong;

        const dir_fd = linux.open(path_z, .{ .PATH = true, .CLOEXEC = true }, 0);
        switch (linux.errno(dir_fd)) {
            .SUCCESS => {},
            .NOENT => return error.PathNotFound,
            .ACCES => return error.AccessDenied,
            .NOTDIR => return error.NotADirectory,
            else => |err| {
                note(diag, .rule_path_open, err);
                return error.Unexpected;
            },
        }
        const dir_fd_i: i32 = @intCast(dir_fd);
        defer _ = linux.close(dir_fd_i);

        var attr = PathBeneathAttr{
            .allowed_access = access.maskFor(self.features).bits(),
            .parent_fd = dir_fd_i,
        };
        const rc = linux.syscall4(
            .landlock_add_rule,
            @intCast(self.fd),
            1, // LANDLOCK_RULE_PATH_BENEATH
            @intFromPtr(&attr),
            0,
        );
        switch (linux.errno(rc)) {
            .SUCCESS => return,
            else => |err| {
                note(diag, .add_rule, err);
                return error.Unexpected;
            },
        }
    }

    pub fn restrictSelf(self: *Ruleset, diag: ?*?Diagnostic) RulesetError!void {
        const pr = linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0);
        if (linux.errno(pr) != .SUCCESS) return error.Rejected;

        const rc = linux.syscall2(.landlock_restrict_self, @intCast(self.fd), auditFlags(self.features));
        switch (linux.errno(rc)) {
            .SUCCESS => return,
            else => |err| {
                note(diag, .restrict_self, err);
                return error.Unexpected;
            },
        }
    }
};

test "read_only does not carry a right that writes" {
    const ro = AccessFs.read_only;
    try std.testing.expect(ro.read_file);
    try std.testing.expect(!ro.write_file);
    try std.testing.expect(!ro.remove_file);
    try std.testing.expect(!ro.make_reg);
}

test "maskFor removes a right that the kernel ABI does not have" {
    const wanted = AccessFs{ .read_file = true, .truncate = true, .refer = true };
    const on_abi_1 = wanted.maskFor(featuresFor(1));
    try std.testing.expect(on_abi_1.read_file);
    try std.testing.expect(!on_abi_1.truncate);
    try std.testing.expect(!on_abi_1.refer);

    const on_abi_3 = wanted.maskFor(featuresFor(3));
    try std.testing.expect(on_abi_3.truncate);
}

test "all carries every right, so init can leave nothing unhandled" {
    const all = AccessFs.all;
    try std.testing.expect(all.execute);
    try std.testing.expect(all.write_file);
    try std.testing.expect(all.read_file);
    try std.testing.expect(all.read_dir);
    try std.testing.expect(all.remove_dir);
    try std.testing.expect(all.remove_file);
    try std.testing.expect(all.make_char);
    try std.testing.expect(all.make_dir);
    try std.testing.expect(all.make_reg);
    try std.testing.expect(all.make_sock);
    try std.testing.expect(all.make_fifo);
    try std.testing.expect(all.make_block);
    try std.testing.expect(all.make_sym);
    try std.testing.expect(all.refer);
    try std.testing.expect(all.truncate);
    try std.testing.expect(all.ioctl_dev);
}

test "read_write grants truncate and refer, but never a device node" {
    const rw = AccessFs.read_write;
    try std.testing.expect(rw.truncate);
    try std.testing.expect(rw.refer);
    try std.testing.expect(!rw.make_char);
    try std.testing.expect(!rw.make_block);
}

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    note(&diag, .create_ruleset, .NOSYS);
    note(&diag, .add_rule, .INVAL);
    try std.testing.expectEqual(Diagnostic.Call.create_ruleset, diag.?.call);
    try std.testing.expectEqual(linux.E.NOSYS, diag.?.errno);

    note(null, .add_rule, .INVAL);
}

test "a diagnostic names the call and the errno, and allocates nothing" {
    var buffer: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "landlock: restrict_self failed: PERM",
        try std.fmt.bufPrint(&buffer, "{f}", .{
            Diagnostic{ .call = .restrict_self, .errno = .PERM },
        }),
    );

    const calls = std.enums.values(Diagnostic.Call);
    for (calls, 0..) |call, i| {
        try std.testing.expect(call.text().len > 0);
        for (calls[i + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, call.text(), other.text()));
        }
    }
}

test "a rule for a path that is not there names the fault, and it reaches the caller" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const abi = probeAbi() catch return error.SkipZigTest;
    var ruleset = Ruleset.init(abi, null) catch return error.SkipZigTest;
    defer ruleset.deinit();

    var diag: ?Diagnostic = null;
    try std.testing.expectError(
        error.PathNotFound,
        ruleset.allowPath("/nonexistent-chock-landlock-path", AccessFs.read_write, &diag),
    );
    try std.testing.expectEqual(@as(?Diagnostic, null), diag);
}
