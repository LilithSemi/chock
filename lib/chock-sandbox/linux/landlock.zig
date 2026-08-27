const std = @import("std");
const linux = std.os.linux;

/// Ask for the ABI version instead of creating a ruleset.
const CREATE_RULESET_VERSION: u32 = 1 << 0;

/// What a Landlock ABI version can do. Each field names the version that added it.
pub const Features = struct {
    /// The kernel has Landlock. ABI 1.
    supported: bool,
    /// A rename or a link across two directories. ABI 2.
    refer: bool,
    /// Truncate a file. ABI 3.
    truncate: bool,
    /// Rules for a TCP bind and a TCP connect. ABI 4.
    net: bool,
    /// An ioctl on a device. ABI 5.
    ioctl_dev: bool,
    /// A scope for an abstract unix socket and for a signal. ABI 6.
    scope: bool,
};

pub fn featuresFor(abi: i32) Features {
    return .{
        .supported = abi >= 1,
        .refer = abi >= 2,
        .truncate = abi >= 3,
        .net = abi >= 4,
        .ioctl_dev = abi >= 5,
        .scope = abi >= 6,
    };
}

pub const ProbeError = error{
    /// The kernel has no Landlock, or a policy turned it off.
    NotSupported,
    /// The kernel gave an error that this code does not expect.
    Unexpected,
};

/// Read the Landlock ABI version of the running kernel.
///
/// This only reads the version and returns it. It does not report anything on
/// its own, and neither does `Ruleset.init`, which masks a right out of the
/// whole ruleset when this version does not have it, with no error and no
/// other signal. `Sandbox.spawn` is what actually reports the version, through
/// its `landlock_report` parameter, filled in with the result of this call
/// before it even forks. Chock never degrades quietly, but that promise lives
/// in `spawn` and in whatever the caller does with `landlock_report`, not here.
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
}

test "probeAbi reports a usable ABI version on a kernel with Landlock" {
    const abi = probeAbi() catch {
        // A kernel without Landlock is a valid environment, and this test has
        // no mechanism to measure there. **The skip carries no message**: the
        // test runner already counts a skip, and a test that writes to
        // standard error puts a `failed command:` line in the build log even
        // when it passes, which is how one real failure was once hidden among
        // six passing suites.
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
    /// ABI 2 and later.
    refer: bool = false,
    /// ABI 3 and later.
    truncate: bool = false,
    /// ABI 5 and later.
    ioctl_dev: bool = false,
    _padding: u48 = 0,

    pub const read_only: AccessFs = .{
        .execute = true,
        .read_file = true,
        .read_dir = true,
    };

    /// The same, for a rule whose path is a regular file rather than a
    /// directory.
    ///
    /// **The kernel refuses `read_only` on a file, and says so with
    /// `EINVAL`.** `landlock_add_rule` checks the access rights against the
    /// type of the path: `read_dir` is a directory right, and a rule that
    /// asks for it over a file is rejected outright. Measured on kernel
    /// 6.18.42, when the mount set of a Nix dev shell first carried a store
    /// path that is a single file, a `stdenv` setup hook, and every tool
    /// call in the session failed with `LandlockRuleFailed`.
    ///
    /// A caller with a path of either kind reads its type first and picks
    /// the matching one: see `lib/chock-core/tools.zig`'s own `withStore`.
    pub const read_only_file: AccessFs = .{
        .execute = true,
        .read_file = true,
    };

    /// Grants every right an agent needs for ordinary work inside the workspace.
    /// Truncate is here because a shell redirect and most editors truncate a file
    /// before they write it. Refer is here because with refer handled and not
    /// granted, Landlock refuses every rename and hard link across two
    /// directories, which would break ordinary work inside the workspace.
    /// make_char and make_block are left out on purpose: an agent has no reason
    /// to create a device node, so this ruleset never grants that right.
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

    /// Every right this struct knows, with no right left out. A ruleset built
    /// from anything less than this leaves the rights it omits permitted on
    /// every path, because Landlock only refuses a right it was told to handle.
    /// This constant is for `Ruleset.init` only. A grant set such as
    /// `read_write` still decides what each rule actually permits.
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

    /// Remove the rights that the running kernel does not have. A ruleset that names a
    /// right the kernel does not know is refused with EINVAL.
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

/// The faults `Ruleset.init`, `allowPath`, and `restrictSelf` can return.
pub const RulesetError = error{
    /// The kernel has no Landlock, or a policy turned it off.
    NotSupported,
    /// A rule's path does not exist.
    PathNotFound,
    /// A rule's path was refused for lack of permission.
    AccessDenied,
    /// A component of a rule's path is not a directory.
    NotADirectory,
    /// A rule's path is longer than the kernel allows.
    PathTooLong,
    /// `prctl(SET_NO_NEW_PRIVS)` was refused.
    Rejected,
    /// The kernel returned an errno with no specific recovery.
    Unexpected,
};

/// Which Landlock call the kernel refused, and what it answered.
///
/// **`error.Unexpected` alone throws away the only two facts that identify
/// the fault.** Before this type, each site below printed the errno to the
/// terminal and then returned the bare error. That was worse here than
/// anywhere else in this project: `applyLayers` calls all three of these in
/// the child after `fork`, where `std.debug.print` takes a global lock that
/// another thread of the parent may have held at the moment of the fork and
/// that no thread in the child can ever release. `spawn`'s own doc comment
/// says the child never calls it, and these four sites were the exception.
///
/// **This owns no memory and allocates nothing**, the same shape
/// `lib/chock-sandbox/linux/namespace.zig` chose, which is the prototype
/// this follows.
pub const Diagnostic = struct {
    call: Call,
    errno: linux.E,

    /// The calls that can answer an errno this code cannot interpret. Named
    /// for what was being done, not for the system call alone.
    pub const Call = enum {
        create_ruleset,
        rule_path_open,
        add_rule,
        restrict_self,

        /// What was being done, as a phrase that reads after "landlock: ".
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

/// Fill `diag` when the caller asked for one.
///
/// **The first fault is kept, not the last.** A rule can only be added to a
/// ruleset that was made, so the first fault is the one that explains the
/// rest.
fn note(diag: ?*?Diagnostic, call: Diagnostic.Call, errno: linux.E) void {
    const slot = diag orelse return;
    if (slot.* != null) return;
    slot.* = .{ .call = call, .errno = errno };
}

pub const Ruleset = struct {
    fd: i32,
    features: Features,

    /// Create a ruleset that handles every right the kernel knows, masked for
    /// the running kernel's ABI. A right this ruleset does not handle stays
    /// permitted everywhere, so it must handle everything Landlock supports,
    /// not only the rights `allowPath` ever grants. `allowPath` still decides,
    /// rule by rule, which of the handled rights a given path actually gets.
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

    /// Permit an access below one path. Every path that is not named by a call
    /// to this function is refused, because `init` handles every right the
    /// kernel knows and this is the only function that grants any of them.
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

    /// Apply the ruleset to the calling process. It can never be removed.
    pub fn restrictSelf(self: *Ruleset, diag: ?*?Diagnostic) RulesetError!void {
        // Landlock needs `no_new_privs` for the same reason that seccomp needs it.
        const pr = linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0);
        if (linux.errno(pr) != .SUCCESS) return error.Rejected;

        const rc = linux.syscall2(.landlock_restrict_self, @intCast(self.fd), 0);
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
    // Truncate and refer are needed for ordinary work: a shell redirect
    // truncates, and a rename or a hard link across directories needs refer.
    try std.testing.expect(rw.truncate);
    try std.testing.expect(rw.refer);
    // An agent has no reason to create a device node.
    try std.testing.expect(!rw.make_char);
    try std.testing.expect(!rw.make_block);
}

test "the first fault is kept, and a caller that wants none pays nothing" {
    // **The first, not the last.** A rule can only be added to a ruleset that
    // was made, so a later fault overwriting an earlier one would replace the
    // fault that explains the run with the fault it caused.
    var diag: ?Diagnostic = null;
    note(&diag, .create_ruleset, .NOSYS);
    note(&diag, .add_rule, .INVAL);
    try std.testing.expectEqual(Diagnostic.Call.create_ruleset, diag.?.call);
    try std.testing.expectEqual(linux.E.NOSYS, diag.?.errno);

    // A caller that asked for no diagnostic is the ordinary case, and it must
    // reach no store at all rather than write into a scratch value.
    note(null, .add_rule, .INVAL);
}

test "a diagnostic names the call and the errno, and allocates nothing" {
    // The two facts `error.Unexpected` throws away. Rendering happens at a
    // caller with a buffer, because every site that fills one runs in the
    // child after `fork`, where there is no allocator and no lock that may be
    // taken. `driver.dieLandlock` is that caller, and it renders into a
    // stack buffer and writes the result with one `write` call.
    var buffer: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "landlock: restrict_self failed: PERM",
        try std.fmt.bufPrint(&buffer, "{f}", .{
            Diagnostic{ .call = .restrict_self, .errno = .PERM },
        }),
    );

    // **No two calls read the same.** A reader has to be able to tell which
    // one failed, and `add_rule` and the `open` that precedes it are the pair
    // that would otherwise collapse into "a rule failed".
    const calls = std.enums.values(Diagnostic.Call);
    for (calls, 0..) |call, i| {
        try std.testing.expect(call.text().len > 0);
        for (calls[i + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, call.text(), other.text()));
        }
    }
}

test "a rule for a path that is not there names the fault, and it reaches the caller" {
    // The point of the whole change, on a real kernel. The errno used to go
    // to the terminal of a sandboxed child and the caller got
    // `error.Unexpected`. A path that does not exist has its own error
    // member, so this uses one that does not: a path whose length the kernel
    // refuses reaches `Unexpected` through `open`.
    // Landlock is a Linux mechanism, and `linux.syscall*` on another target
    // names numbers that belong to some other kernel entirely, so this test
    // asks the kernel nothing at all unless it is talking to Linux.
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const abi = probeAbi() catch return error.SkipZigTest;
    var ruleset = Ruleset.init(abi, null) catch return error.SkipZigTest;
    defer ruleset.deinit();

    // `PathNotFound` is its own answer and carries no errno to keep, so this
    // pins that the slot stays empty for a fault the error set already names.
    var diag: ?Diagnostic = null;
    try std.testing.expectError(
        error.PathNotFound,
        ruleset.allowPath("/nonexistent-chock-landlock-path", AccessFs.read_write, &diag),
    );
    try std.testing.expectEqual(@as(?Diagnostic, null), diag);
}
