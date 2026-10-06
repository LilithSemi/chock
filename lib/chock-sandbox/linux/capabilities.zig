//! Drops every capability a sandboxed process holds inside its own user
//! namespace: the bounding set, the uid-0 legacy grant, and this process's
//! own effective, permitted, and inheritable sets.

const std = @import("std");
const linux = std.os.linux;
const namespace = @import("namespace.zig");

pub const Error = error{
    Rejected,
};

pub const Diagnostic = struct {
    call: Call,
    errno: linux.E,

    pub const Call = enum {
        capbset_drop,
        set_securebits,
        capset,

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

fn note(diag: ?*?Diagnostic, call: Diagnostic.Call, errno: linux.E) void {
    const slot = diag orelse return;
    if (slot.* != null) return;
    slot.* = .{ .call = call, .errno = errno };
}

const capability_version_3: u32 = 0x20080522;

pub fn dropAll(diag: ?*?Diagnostic) Error!void {
    return dropAllBut(null, diag);
}

pub fn keepOnly(capability: u32, diag: ?*?Diagnostic) Error!void {
    return dropAllBut(capability, diag);
}

/// Call before dropAll or keepOnly, never after: changing user needs CAP_SETUID.
pub fn becomeUser(uid: linux.uid_t, gid: linux.gid_t, diag: ?*?Diagnostic) Error!void {
    const keep_rc = linux.prctl(@intFromEnum(linux.PR.SET_KEEPCAPS), 1, 0, 0, 0);
    if (linux.errno(keep_rc) != .SUCCESS) {
        note(diag, .set_securebits, linux.errno(keep_rc));
        return error.Rejected;
    }

    // The group first: after the user changes there is no `CAP_SETGID` left.
    if (linux.errno(linux.setgid(gid)) != .SUCCESS) {
        note(diag, .capset, linux.errno(linux.setgid(gid)));
        return error.Rejected;
    }
    if (linux.errno(linux.setuid(uid)) != .SUCCESS) {
        note(diag, .capset, linux.errno(linux.setuid(uid)));
        return error.Rejected;
    }

    // Permitted survived; effective did not, and every call below this needs it.
    var header = linux.cap_user_header_t{ .version = capability_version_3, .pid = 0 };
    var data = [_]linux.cap_user_data_t{
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
    };
    if (linux.errno(linux.capget(&header, &data[0])) != .SUCCESS) {
        note(diag, .capset, linux.errno(linux.capget(&header, &data[0])));
        return error.Rejected;
    }
    for (&data) |*word| word.effective = word.permitted;
    if (linux.errno(linux.capset(&header, &data[0])) != .SUCCESS) {
        note(diag, .capset, linux.errno(linux.capset(&header, &data[0])));
        return error.Rejected;
    }

    const off_rc = linux.prctl(@intFromEnum(linux.PR.SET_KEEPCAPS), 0, 0, 0, 0);
    if (linux.errno(off_rc) != .SUCCESS) {
        note(diag, .set_securebits, linux.errno(off_rc));
        return error.Rejected;
    }
}

fn dropAllBut(keep: ?u32, diag: ?*?Diagnostic) Error!void {
    var cap: u32 = 0;
    while (cap <= linux.CAP.LAST_CAP) : (cap += 1) {
        const rc = linux.prctl(@intFromEnum(linux.PR.CAPBSET_DROP), @as(usize, cap), 0, 0, 0);
        const call_errno = linux.errno(rc);
        if (call_errno != .SUCCESS) {
            // EINVAL here means an older kernel does not recognize this capability number.
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
    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) return error.SkipZigTest;

    if (fork_rc == 0) {
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
