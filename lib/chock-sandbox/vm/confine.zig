//! The host side of a guest's boundary. Confines the process that runs the
//! VMM to the offered shares, with Landlock and seccomp on Linux or one Seatbelt profile on Darwin.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const landlock = @import("../linux/landlock.zig");
const seccomp = @import("../linux/seccomp.zig");
const bpf = @import("../linux/bpf.zig");
const seatbelt = @import("../darwin/seatbelt.zig");
const shares_mod = @import("shares.zig");

pub const Layer = enum { landlock, seccomp, seatbelt, rlimit };

pub const Error = error{ Refused, OutOfMemory };

pub const Diagnostic = union(enum) {
    landlock: landlock.Diagnostic,
    seatbelt: seatbelt.Support,

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            inline else => |one| try writer.print("{f}", .{one}),
        }
    }
};

/// A caller that gets `Refused` must end the process. A layer already
/// installed before a later one fails cannot be taken off again.
pub fn install(
    allocator: std.mem.Allocator,
    shares: []const shares_mod.Share,
    which: *?Layer,
    diag: ?*?Diagnostic,
) Error!void {
    return switch (builtin.os.tag) {
        .macos => takeSeatbelt(allocator, shares, which, diag),
        else => takeLandlockAndSeccomp(allocator, shares, which, diag),
    };
}

fn takeLandlockAndSeccomp(
    allocator: std.mem.Allocator,
    shares: []const shares_mod.Share,
    which: *?Layer,
    diag: ?*?Diagnostic,
) Error!void {
    if (!noDumps()) {
        which.* = .rlimit;
        return error.Refused;
    }

    var said: ?landlock.Diagnostic = null;
    takeLandlock(shares, which, &said) catch |err| {
        if (diag) |slot| {
            if (said) |one| slot.* = .{ .landlock = one };
        }
        return err;
    };

    const insns = seccomp.buildVmm(allocator) catch return error.OutOfMemory;
    defer allocator.free(insns);
    seccomp.install(bpf.Prog.init(insns)) catch {
        which.* = .seccomp;
        return error.Refused;
    };
}

fn noDumps() bool {
    const none = linux.rlimit{ .cur = 0, .max = 0 };
    if (linux.errno(linux.setrlimit(.CORE, &none)) != .SUCCESS) return false;
    const pr = linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 0, 0, 0, 0);
    return linux.errno(pr) == .SUCCESS;
}

fn takeLandlock(
    shares: []const shares_mod.Share,
    which: *?Layer,
    diag: *?landlock.Diagnostic,
) Error!void {
    const abi = landlock.probeAbi() catch {
        which.* = .landlock;
        return error.Refused;
    };
    const features = landlock.featuresFor(abi);

    // A right this kernel cannot handle stays permitted on every path, inside or outside a share.
    if (landlock.AccessFs.all.bits() != landlock.AccessFs.all.maskFor(features).bits()) {
        which.* = .landlock;
        return error.Refused;
    }

    var ruleset = landlock.Ruleset.init(abi, diag) catch {
        which.* = .landlock;
        return error.Refused;
    };
    defer ruleset.deinit();

    for (shares) |one| {
        const wanted = if (one.writable)
            landlock.AccessFs.read_write
        else
            landlock.AccessFs.read_only;

        // Refuse instead of letting maskFor narrow a right this kernel cannot express.
        if (wanted.bits() != wanted.maskFor(features).bits()) {
            which.* = .landlock;
            return error.Refused;
        }

        ruleset.allowPath(one.host_path, wanted, diag) catch {
            which.* = .landlock;
            return error.Refused;
        };
    }

    ruleset.restrictSelf(diag) catch {
        which.* = .landlock;
        return error.Refused;
    };
}

const profile_overhead = 512;

const rule_overhead = 64;

fn takeSeatbelt(
    allocator: std.mem.Allocator,
    shares: []const shares_mod.Share,
    which: *?Layer,
    diag: ?*?Diagnostic,
) Error!void {
    if (!noCoreFile()) {
        which.* = .rlimit;
        return error.Refused;
    }

    const rules = try shareRules(allocator, shares);
    defer allocator.free(rules);

    var room: usize = profile_overhead;
    for (rules) |one| room += rule_overhead + 2 * one.path.len;
    const text = try allocator.alloc(u8, room);
    defer allocator.free(text);

    var builder = seatbelt.Builder.init(text);
    const profile = builder.finish(.{
        .rules = rules,
        .allow_exec = false,
        .allow_fork = false,
        .allow_sysctl_read = false,
        .allow_metadata = false,
    }) catch |err| {
        which.* = .seatbelt;
        if (diag) |slot| slot.* = .{ .seatbelt = .{ .unavailable = switch (err) {
            error.ProfileTooLong => .profile_too_long,
            error.BadPath => .path_not_resolvable,
        } } };
        return error.Refused;
    };

    const support = seatbelt.apply(profile);
    if (!support.applied()) {
        which.* = .seatbelt;
        if (diag) |slot| slot.* = .{ .seatbelt = support };
        return error.Refused;
    }
}

fn noCoreFile() bool {
    if (builtin.os.tag != .macos) return false;
    const none: std.c.rlimit = .{ .cur = 0, .max = 0 };
    return std.c.setrlimit(.CORE, &none) == 0;
}

/// Every share as the rules that grant it, sorted shortest path first so a
/// nested share's rules come after its parent's.
fn shareRules(
    allocator: std.mem.Allocator,
    shares: []const shares_mod.Share,
) error{OutOfMemory}![]seatbelt.Rule {
    const order = try allocator.alloc(usize, shares.len);
    defer allocator.free(order);
    for (order, 0..) |*slot, index| slot.* = index;
    std.mem.sort(usize, order, shares, shorterPathFirst);

    var needed: usize = shares.len;
    for (shares) |one| {
        if (!one.writable) needed += 1;
    }
    const rules = try allocator.alloc(seatbelt.Rule, needed);

    var count: usize = 0;
    for (order) |index| {
        const one = shares[index];
        rules[count] = .{
            .path = one.host_path,
            .access = if (one.writable) .read_write else .read_only,
        };
        count += 1;
        if (one.writable) continue;
        rules[count] = .{
            .path = one.host_path,
            .access = .{ .write = true },
            .verb = .deny,
        };
        count += 1;
    }
    return rules;
}

fn shorterPathFirst(shares: []const shares_mod.Share, left: usize, right: usize) bool {
    return shares[left].host_path.len < shares[right].host_path.len;
}

test "a read only share inside a writable one keeps its read and loses its write" {
    const allocator = std.testing.allocator;
    const rules = try shareRules(allocator, &.{
        .{ .name = "git", .host_path = "/work/.git", .writable = false },
        .{ .name = "work", .host_path = "/work", .writable = true },
    });
    defer allocator.free(rules);

    try std.testing.expectEqual(@as(usize, 3), rules.len);
    try std.testing.expectEqualStrings("/work", rules[0].path);
    try std.testing.expect(rules[0].access.write);
    try std.testing.expectEqual(seatbelt.Verb.allow, rules[0].verb);

    try std.testing.expectEqualStrings("/work/.git", rules[1].path);
    try std.testing.expect(rules[1].access.read);
    try std.testing.expect(!rules[1].access.write);

    try std.testing.expectEqualStrings("/work/.git", rules[2].path);
    try std.testing.expectEqual(seatbelt.Verb.deny, rules[2].verb);
    try std.testing.expect(rules[2].access.write);
}

test "a profile grants the share set, no program and no network" {
    const allocator = std.testing.allocator;
    const shares = [_]shares_mod.Share{
        .{ .name = "store", .host_path = "/nix/store", .writable = false },
        .{ .name = "work", .host_path = "/home/one/work", .writable = true },
    };
    const rules = try shareRules(allocator, &shares);
    defer allocator.free(rules);

    var text: [4096]u8 = undefined;
    var builder = seatbelt.Builder.init(&text);
    const profile = try builder.finish(.{
        .rules = rules,
        .allow_exec = false,
        .allow_fork = false,
        .allow_sysctl_read = false,
        .allow_metadata = false,
    });

    try std.testing.expect(std.mem.indexOf(u8, profile, "(deny default)") != null);
    try std.testing.expect(std.mem.indexOf(u8, profile, "(deny network*)") != null);
    try std.testing.expect(std.mem.indexOf(u8, profile, "process-exec") == null);
    try std.testing.expect(std.mem.indexOf(u8, profile, "sysctl-read") == null);
    try std.testing.expect(std.mem.indexOf(u8, profile, "file-read-metadata") == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        profile,
        "(allow file-read* (subpath \"/nix/store\"))",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        profile,
        "(allow file-read* file-write* (subpath \"/home/one/work\"))",
    ) != null);
}

test "a refusal says which mechanism answered, and never the other platform's" {
    var text: [128]u8 = undefined;
    const landlock_said = try std.fmt.bufPrint(&text, "{f}", .{
        Diagnostic{ .landlock = .{ .call = .add_rule, .errno = .NOENT } },
    });
    try std.testing.expect(std.mem.indexOf(u8, landlock_said, "landlock") != null);

    var more: [128]u8 = undefined;
    const seatbelt_said = try std.fmt.bufPrint(&more, "{f}", .{
        Diagnostic{ .seatbelt = .{ .unavailable = .profile_refused } },
    });
    try std.testing.expect(std.mem.indexOf(u8, seatbelt_said, "seatbelt") != null);
}
