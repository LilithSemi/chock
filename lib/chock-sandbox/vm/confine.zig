//! The host side of a guest's boundary.
//!
//! **The guest is a layer and so is this.** `vm/driver.zig` builds no boundary:
//! it sends a `Config` to a guest, which builds one inside itself. This is the
//! other side, around the process that runs the guest, so an escape from the
//! guest lands somewhere that can do very little on disk, though not nothing
//! at all: see the signal note below.
//!
//! ## What it grants, and why that is so little
//!
//! The mechanism grants the offered shares and nothing else. Everything else
//! the VMM needs is a descriptor it already holds when this runs: `/dev/kvm`,
//! the guest's memory, the bound session socket and the console. So the only
//! thing it can name on disk is what it serves to the guest.
//!
//! **Two platforms, one grant, two mechanisms.** Linux uses Landlock for the
//! paths and a seccomp allowlist for the calls. Darwin has neither, and uses
//! one Seatbelt profile for both halves. The notes below say which platform
//! each one is about, because a claim carried from one to the other is how
//! this project has been wrong about Darwin before.
//!
//! **Landlock covers files, not signals.** `RulesetAttr` has no `scoped` field,
//! so this file cannot ask for ABI 6's signal scope. `tgkill` stays reachable,
//! and a compromised VMM can still signal another process of the same user.
//! The Darwin arm is narrower here rather than wider: Seatbelt's
//! `(allow signal (target same-sandbox))` leaves the guest's own ticker able to
//! signal a processor thread and leaves every other process of the user alone.
//!
//! **A writable share needs ABI 5 and kernel 6.10.** `AccessFs.read_write`
//! carries `ioctl_dev`, which only exists from ABI 5 on. That, not Landlock's
//! own ABI 1 floor, is the real availability floor for any writable share.
//!
//! **Proving a grant held needs a real access.** `O_PATH` only asks the kernel
//! for a handle. Landlock's hooks fire on an access that reads or writes
//! something, not on an open with `O_PATH` alone.
//!
//! **Install this with no thread running.** A seccomp filter and a Landlock
//! domain are both attached to credentials a new thread inherits, so one install
//! before the first `clone` covers every processor. Installing afterwards would
//! have to reach a thread inside `KVM_RUN`, which cannot be done. Darwin is the
//! same shape for a different reason: `sandbox_init` may be called once per
//! process, so there is no second call to make later.
//!
//! **The network is closed on Darwin and open to an existing descriptor on
//! Linux.** The Linux arm keeps `accept4`, `recvmsg` and `sendmsg` for the
//! session socket this process already holds, because seccomp filters a call and
//! not a socket. Seatbelt has no such split: `(deny network*)` refuses a unix
//! socket as well as IP. **It stays closed, and that was measured rather than
//! argued.** The socket is bound and listening before `sandbox_init` runs, and
//! Seatbelt checks `network-bind` and `network-outbound` and not every later use
//! of a socket that already exists, so a guest on macOS 15.8.1 was reached over
//! that socket and ran a tool call with this profile on.
//!
//! **It refuses rather than narrowing.** An older Landlock ABI cannot express
//! every right, and `AccessFs.maskFor` drops what it cannot. For a tool call
//! that is a weakening somebody asked for. Here it would widen this grant with
//! nothing saying so. So a kernel that cannot express it gets a refusal, and so
//! does a macOS that will not take the profile.
//!
//! ## The one thing the Darwin grant adds, and why it cannot be removed
//!
//! Every Seatbelt profile this project builds carries one read of `/` as a
//! literal, because without it no program starts at all and the failure names
//! nothing: see `seatbelt.dyld_root_rule`. It grants the names of the top level
//! directories of the boot volume and no file content anywhere. It is the whole
//! difference between the two platforms' grants, and it is stated here rather
//! than left for a reader to find in the profile text.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const landlock = @import("../linux/landlock.zig");
const seccomp = @import("../linux/seccomp.zig");
const bpf = @import("../linux/bpf.zig");
const seatbelt = @import("../darwin/seatbelt.zig");
const shares_mod = @import("shares.zig");

/// Which layer would not install. The caller names it in its refusal, because
/// "the sandbox would not start" sends a person to the wrong file.
pub const Layer = enum { landlock, seccomp, seatbelt, rlimit };

pub const Error = error{ Refused, OutOfMemory };

/// What the layer that refused answered, in that layer's own words.
///
/// **This is platform neutral because the layer is not.** A
/// `landlock.Diagnostic` out-parameter on a Darwin path would name a mechanism
/// macOS has not got, and the next reader would go looking for the fault in the
/// wrong file. Each arm fills the one variant its own mechanism can speak.
pub const Diagnostic = union(enum) {
    landlock: landlock.Diagnostic,
    seatbelt: seatbelt.Support,

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            inline else => |one| try writer.print("{f}", .{one}),
        }
    }
};

/// Confine this process to `shares` and the descriptors it already holds.
///
/// `which` names the layer when this refuses. `diag` carries what that layer
/// answered. A caller that wants no detail passes null.
///
/// **`Refused` is fatal.** Nothing this function installs can be taken off
/// again: `RLIMIT_CORE` may already be zero, or Landlock may already be on,
/// before a later layer is the one that fails. A caller that gets `Refused`
/// must end the process rather than retry or continue unconfined.
pub fn install(
    allocator: std.mem.Allocator,
    shares: []const shares_mod.Share,
    which: *?Layer,
    diag: ?*?Diagnostic,
) Error!void {
    return switch (builtin.os.tag) {
        .macos => takeSeatbelt(allocator, shares, which, diag),
        // Every other target keeps the arm it had before Darwin got one. A
        // target with no Landlock refuses at its first layer, which is the fail
        // closed answer and not a weaker boundary.
        else => takeLandlockAndSeccomp(allocator, shares, which, diag),
    };
}

fn takeLandlockAndSeccomp(
    allocator: std.mem.Allocator,
    shares: []const shares_mod.Share,
    which: *?Layer,
    diag: ?*?Diagnostic,
) Error!void {
    // No core file and no debugger. A core of this process would hold the
    // guest's memory and whatever it read out of the shares, and a process that
    // cannot be dumped cannot be attached to by another of the same user.
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

    // **The handled set is the one that has to cover every right, not each
    // share's own grant.** `Ruleset.init` builds its handled set from
    // `AccessFs.all`, and `AccessFs.all`'s own doc comment says a right left
    // out of that set stays permitted on every path, not only unhandled
    // inside a share. The per-share check below only catches a widened grant
    // inside a share. It says nothing about a right this process never offered
    // a share for at all, which is what this check is for.
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

        // **Asked for, not masked.** A right this kernel cannot express would be
        // dropped quietly by `maskFor`, and a wider grant than this file promises
        // is the one thing it must never hand out.
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

/// The fixed part of a profile: the version line, the base denial, the read of
/// `/` dyld needs, and the network, signal and Mach lines. Room, not a size:
/// `Builder.finish` refuses a profile that would not fit rather than writing a
/// shorter one.
const profile_overhead = 512;

/// Room for one rule beside the path it names. The path is counted twice by the
/// caller, because every byte of it may be escaped.
const rule_overhead = 64;

fn takeSeatbelt(
    allocator: std.mem.Allocator,
    shares: []const shares_mod.Share,
    which: *?Layer,
    diag: ?*?Diagnostic,
) Error!void {
    // No core file. A core of this process would hold the guest's memory and
    // whatever it read out of the shares. **There is no second half here.**
    // `PR_SET_DUMPABLE` is Linux's, and macOS has no flag that answers to it,
    // so `noDumps`'s second call has no Darwin line rather than a silent one.
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
    // Every field left out below is the field's own default, and each one of
    // those defaults closes something: no network of any kind including
    // `AF_UNIX`, and no Mach service past the base denial. The three named here
    // are the ones whose defaults are open.
    //
    // `allow_signal_same_sandbox` keeps its default of true, which this grant
    // needs: the guest's ticker signals a processor thread. It is narrower than
    // the Linux arm, where `tgkill` reaches any process of the same user.
    const profile = builder.finish(.{
        .rules = rules,
        // A built machine has no caller for either. The Linux arm says the same
        // thing by leaving `execve` and `clone`'s process forms out of
        // `seccomp.vmm_calls`.
        .allow_exec = false,
        .allow_fork = false,
        // The host's whole process table is behind `sysctl-read`, and nothing
        // in a running VMM asks for it.
        .allow_sysctl_read = false,
        // The type, size and timestamps of any path on the machine, including
        // one no share names. The grant is the share set, so this stays off.
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

/// Every share as the rules that grant it, shortest path first.
///
/// **The order is the grant, and this is not the caller's order.** A profile's
/// last rule naming a path wins one access at a time, while
/// `shares_mod.Set.holding` says the longest match is the share that means
/// something for a path. A nested share is always the longer path, so writing
/// the shares shortest first is what makes the two agree. In the caller's own
/// order a read only share inside a writable one would keep its parent's write.
///
/// **A read only share takes two rules and not one.** An allowance naming only
/// `file-read*` says nothing about writing, so a write a parent granted stays
/// until a denial takes it away: see `seatbelt.Rule.verb`, which holds the
/// measurement.
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

/// A shorter path sorts first, which puts a share before anything nested inside
/// it. `std.mem.sort` is stable, so two shares of the same length keep the
/// caller's order, and two such shares cannot nest.
fn shorterPathFirst(shares: []const shares_mod.Share, left: usize, right: usize) bool {
    return shares[left].host_path.len < shares[right].host_path.len;
}

test "a read only share inside a writable one keeps its read and loses its write" {
    // The measured failure this pins: an allowance naming only `file-read*`
    // over a path an earlier rule made writable leaves the write in place. So
    // a read only share needs its own denial, and that denial has to come
    // after the parent's allowance.
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
    // A `landlock.Diagnostic` reaching a Darwin session would send a person to
    // a file macOS has nothing in, so the two variants are told apart here.
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
