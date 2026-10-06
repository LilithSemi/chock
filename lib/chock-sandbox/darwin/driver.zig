//! The Darwin driver for chock-sandbox. It applies Seatbelt, network and signal limits, and
//! resource limits, and refuses any config that needs a mount tree.

const std = @import("std");
const builtin = @import("builtin");
const iface = @import("../Sandbox.zig");
const namespace = @import("../linux/namespace.zig");
const landlock = @import("../linux/landlock.zig");
const seatbelt = @import("seatbelt.zig");
const limits = @import("limits.zig");

const Config = iface.Config;
const SetupError = iface.SetupError;
const SpawnError = iface.SpawnError;

pub const expresses: iface.Expresses = .{
    .moved_paths = false,
    .scratch_area = false,
    .procfs = false,
    .cgroup_placement = false,
    .device_passthrough = false,
};

pub const driver_name = "darwin";

pub const guarantees: iface.Guarantees = iface.Guarantees.initMany(&.{
    .network_isolated,
    .signal_isolated,
    .ipc_isolated,
    .path_restricted,
});

pub const confinedAlready = seatbelt.confinedAlready;

pub const nesting = seatbelt.nesting;
pub const Nesting = seatbelt.Nesting;

pub const default_mach_services = seatbelt.default_mach_services;

const max_profile_bytes = 256 * 1024;

pub const Inexpressible = enum {
    root_is_not_the_real_root,
    bind_moves_a_path,
    overlay_mount,
    proc_mount,
    scratch_area,

    pub fn text(self: Inexpressible) []const u8 {
        return switch (self) {
            .root_is_not_the_real_root => "a root of its own, and macos cannot pivot into one",
            .bind_moves_a_path => "a path to appear somewhere else, and macos has no bind mount",
            .overlay_mount => "an overlay filesystem, and macos has none",
            .proc_mount => "a procfs of its own, and macos has no procfs",
            .scratch_area => "a capped writable area, and an ordinary user on macos cannot mount a filesystem",
        };
    }
};

pub fn expressibleOn(config: Config) ?Inexpressible {
    if (!std.mem.eql(u8, config.root, "/")) return .root_is_not_the_real_root;
    if (config.scratch.len != 0) return .scratch_area;
    for (config.mounts) |mount| switch (mount) {
        .bind => |bind| if (!std.mem.eql(u8, bind.source, bind.target)) return .bind_moves_a_path,
        .overlay => return .overlay_mount,
        .proc => return .proc_mount,
        .deny => {},
    };
    return null;
}

fn accessFor(rights: landlock.AccessFs) seatbelt.Access {
    return .{
        .read = rights.read_file or rights.read_dir or rights.execute,
        .write = rights.write_file or rights.truncate or rights.remove_file or
            rights.remove_dir or rights.make_char or rights.make_dir or
            rights.make_reg or rights.make_sock or rights.make_fifo or
            rights.make_block or rights.make_sym or rights.refer,
    };
}

fn optionsFor(allocator: std.mem.Allocator, config: Config) std.mem.Allocator.Error!seatbelt.Options {
    var rules: std.ArrayList(seatbelt.Rule) = .empty;
    errdefer rules.deinit(allocator);
    var deny: std.ArrayList(seatbelt.Rule) = .empty;
    errdefer deny.deinit(allocator);

    for (config.rules) |rule| try rules.append(allocator, .{
        .path = rule.path,
        .access = accessFor(rule.access),
    });

    for (config.mounts) |mount| switch (mount) {
        .bind => |bind| {
            try rules.append(allocator, .{
                .path = bind.source,
                .access = if (bind.read_only) .read_only else .read_write,
            });
            if (bind.read_only) try rules.append(allocator, .{
                .path = bind.source,
                .access = .{ .write = true },
                .verb = .deny,
            });
        },
        .deny => |denied| try deny.append(allocator, .{
            .path = denied.target,
            .access = .read_write,
            .reach = .literal,
        }),
        .overlay, .proc => unreachable, // `expressibleOn` refused these already.
    };

    const owned_rules = try rules.toOwnedSlice(allocator);
    errdefer allocator.free(owned_rules);
    const owned_deny = try deny.toOwnedSlice(allocator);

    return .{
        .rules = owned_rules,
        .deny = owned_deny,
        .allow_network = config.network == .host,
    };
}

pub fn spawn(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    landlock_report: ?*iface.LandlockReport,
    middle: ?*iface.Middle,
) SpawnError!std.process.Child.Term {
    _ = landlock_report;

    switch (config.containment) {
        .best_effort => {},
        .supplied => return error.CgroupPlacementUnsupported,
    }

    if (expressibleOn(config) != null) return error.NoMountNamespace;

    switch (config.network) {
        .filtered => return error.NetBrokerMissing,
        .none, .host => if (config.net_broker != null) return error.NetBrokerNotFiltered,
    }

    if (builtin.os.tag == .macos) {
        return spawnDarwin(allocator, config, argv, middle);
    } else {
        return error.NoMountNamespace;
    }
}

fn spawnDarwin(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    middle: ?*iface.Middle,
) SpawnError!std.process.Child.Term {
    std.debug.assert(argv.len > 0);

    const options = try optionsFor(allocator, config);
    defer allocator.free(options.rules);
    defer allocator.free(options.deny);
    const profile_buffer = try allocator.alloc(u8, max_profile_bytes);
    defer allocator.free(profile_buffer);
    var builder = seatbelt.Builder.init(profile_buffer);
    const profile = builder.finish(options) catch |err| switch (err) {
        error.ProfileTooLong, error.BadPath => return error.LandlockInitFailed,
    };

    var setup_fds: [2]std.c.fd_t = undefined;
    if (std.c.pipe(&setup_fds) != 0) return error.Unexpected;
    setCloexec(setup_fds[0]);
    setCloexec(setup_fds[1]);

    var cancel_fds: [2]std.c.fd_t = .{ -1, -1 };
    if (middle != null) {
        if (std.c.pipe(&cancel_fds) != 0) {
            _ = std.c.close(setup_fds[0]);
            _ = std.c.close(setup_fds[1]);
            return error.Unexpected;
        }
        setCloexec(cancel_fds[0]);
        setCloexec(cancel_fds[1]);
        _ = std.c.fcntl(cancel_fds[1], std.c.F.SETNOSIGPIPE, @as(c_int, 1));
    }

    const a_pid = std.c.fork();
    if (a_pid < 0) {
        _ = std.c.close(setup_fds[0]);
        _ = std.c.close(setup_fds[1]);
        closePair(&cancel_fds);
        return error.Unexpected;
    }

    if (a_pid == 0) {
        _ = std.c.close(setup_fds[0]);
        if (cancel_fds[1] >= 0) _ = std.c.close(cancel_fds[1]);
        runMiddle(allocator, config, argv, profile, setup_fds[1], cancel_fds[0]);
    }

    _ = std.c.close(setup_fds[1]);
    if (cancel_fds[0] >= 0) _ = std.c.close(cancel_fds[0]);

    if (middle) |handle| {
        handle.fd = cancel_fds[1];
        @atomicStore(std.c.pid_t, &handle.pid, a_pid, .release);
    }

    const record = try readSetupReport(setup_fds[0]);
    _ = std.c.close(setup_fds[0]);

    var status: c_int = 0;
    while (std.c.waitpid(a_pid, &status, 0) < 0) {
        if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) return error.Unexpected;
    }

    if (record) |step| return setupErrorFor(step);
    return termFor(status);
}

const SetupStep = enum(u8) {
    stdin_redirect = 1,
    process_group,
    close_fds,
    resource_limits,
    confinement,
    fork,
    exec,
};

fn setupErrorFor(step: SetupStep) SpawnError {
    return switch (step) {
        .stdin_redirect => error.StdinRedirectFailed,
        .process_group => error.ProcessGroupFailed,
        .close_fds => error.CloseFdsFailed,
        .resource_limits => error.ResourceLimitFailed,
        .confinement => error.LandlockRestrictFailed,
        .fork => error.ForkFailed,
        .exec => error.ExecFailed,
    };
}

const setup_magic: u32 = 0x314B4843;

const SetupRecord = extern struct {
    magic: u32 = setup_magic,
    step: u8,
    errno: i32,
};

fn readSetupReport(read_fd: std.c.fd_t) SpawnError!?SetupStep {
    var record: SetupRecord = undefined;
    var filled: usize = 0;
    const bytes = std.mem.asBytes(&record);
    while (filled < bytes.len) {
        const n = std.c.read(read_fd, bytes[filled..].ptr, bytes.len - filled);
        if (n < 0) {
            if (std.c._errno().* == @intFromEnum(std.c.E.INTR)) continue;
            return error.Unexpected;
        }
        if (n == 0) break;
        filled += @intCast(n);
    }
    if (filled == 0) return null;
    if (filled != bytes.len or record.magic != setup_magic) return .exec;
    return std.enums.fromInt(SetupStep, record.step) orelse .exec;
}

const fd_cloexec: c_int = 1;

fn setCloexec(fd: std.c.fd_t) void {
    _ = std.c.fcntl(fd, std.c.F.SETFD, fd_cloexec);
}

fn closePair(fds: *[2]std.c.fd_t) void {
    for (fds) |*fd| {
        if (fd.* >= 0) _ = std.c.close(fd.*);
        fd.* = -1;
    }
}

fn termFor(status: c_int) std.process.Child.Term {
    const raw: c_uint = @bitCast(status);
    const signal: u32 = raw & 0x7f;
    if (signal == 0) return .{ .exited = @truncate((raw >> 8) & 0xff) };
    if (signal == 0x7f) return .{ .stopped = @enumFromInt(@as(u8, @truncate((raw >> 8) & 0xff))) };
    return .{ .signal = @enumFromInt(@as(u8, @truncate(signal))) };
}

fn writeRecord(write_fd: std.c.fd_t, step: SetupStep, errno: i32) void {
    const record = SetupRecord{ .step = @intFromEnum(step), .errno = errno };
    const bytes = std.mem.asBytes(&record);
    _ = std.c.write(write_fd, bytes.ptr, bytes.len);
}

fn die(write_fd: std.c.fd_t, stderr_fd: std.c.fd_t, step: SetupStep, what: []const u8) noreturn {
    writeRecord(write_fd, step, std.c._errno().*);
    _ = std.c.write(stderr_fd, "sandbox: ", 9);
    _ = std.c.write(stderr_fd, what.ptr, what.len);
    _ = std.c.write(stderr_fd, "\n", 1);
    std.c._exit(127);
}

fn runMiddle(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    profile: [:0]const u8,
    write_fd: std.c.fd_t,
    cancel_read_fd: std.c.fd_t,
) noreturn {
    resetSignalState();

    if (std.c.setpgid(0, 0) != 0) die(write_fd, config.stderr_fd, .process_group, "could not make a process group");

    const b_pid = std.c.fork();
    if (b_pid < 0) die(write_fd, config.stderr_fd, .fork, "could not fork the sandboxed process");
    if (b_pid == 0) {
        if (cancel_read_fd >= 0) _ = std.c.close(cancel_read_fd);
        runProgram(allocator, config, argv, profile, write_fd);
    }

    _ = std.c.close(write_fd);

    middleLoop(b_pid, cancel_read_fd);
}

fn middleLoop(b_pid: std.c.pid_t, cancel_read_fd: std.c.fd_t) noreturn {
    const kq = std.c.kqueue();
    if (kq < 0) {
        relay(b_pid);
    }

    var changes: [2]std.c.Kevent = undefined;
    var count: c_int = 1;
    changes[0] = .{
        .ident = @intCast(b_pid),
        .filter = std.c.EVFILT.PROC,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE,
        .fflags = std.c.NOTE.EXIT,
        .data = 0,
        .udata = 0,
    };
    if (cancel_read_fd >= 0) {
        changes[1] = .{
            .ident = @intCast(cancel_read_fd),
            .filter = std.c.EVFILT.READ,
            .flags = std.c.EV.ADD | std.c.EV.ENABLE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        };
        count = 2;
    }
    if (std.c.kevent(kq, &changes, count, undefined, 0, null) < 0) relay(b_pid);

    while (true) {
        var event: std.c.Kevent = undefined;
        const n = std.c.kevent(kq, undefined, 0, @ptrCast(&event), 1, null);
        if (n < 0) {
            if (std.c._errno().* == @intFromEnum(std.c.E.INTR)) continue;
            relay(b_pid);
        }
        if (n == 0) continue;
        if (event.filter == std.c.EVFILT.PROC) relay(b_pid);
        if (event.filter != std.c.EVFILT.READ) continue;

        var byte: [1]u8 = undefined;
        const read_n = std.c.read(cancel_read_fd, &byte, 1);
        if (read_n <= 0) {
            var only: [1]std.c.Kevent = .{.{
                .ident = @intCast(cancel_read_fd),
                .filter = std.c.EVFILT.READ,
                .flags = std.c.EV.DELETE,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            }};
            _ = std.c.kevent(kq, &only, 1, undefined, 0, null);
            continue;
        }
        const which: std.c.SIG = @enumFromInt(byte[0]);
        var ignore: std.c.Sigaction = undefined;
        @memset(std.mem.asBytes(&ignore), 0);
        ignore.handler = .{ .handler = std.c.SIG.IGN };
        _ = std.c.sigaction(which, &ignore, null);
        _ = std.c.kill(-std.c.getpid(), which);
    }
}

fn relay(b_pid: std.c.pid_t) noreturn {
    var status: c_int = 0;
    while (std.c.waitpid(b_pid, &status, 0) < 0) {
        if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) std.c._exit(127);
    }
    switch (termFor(status)) {
        .exited => |code| std.c._exit(code),
        .signal => |signal| {
            _ = std.c.kill(std.c.getpid(), signal);
            std.c._exit(128 +% @as(u8, @truncate(@intFromEnum(signal))));
        },
        .stopped, .unknown => std.c._exit(127),
    }
}

fn runProgram(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    profile: [:0]const u8,
    write_fd: std.c.fd_t,
) noreturn {
    redirectStdin(config, write_fd);
    closeInheritedFds(config, write_fd);
    redirectStandardStreams(config, write_fd);

    const stderr_fd: std.c.fd_t = 2;

    const cwd_z = allocator.dupeZ(u8, config.cwd) catch die(write_fd, stderr_fd, .exec, "out of memory");
    if (std.c.chdir(cwd_z) != 0) die(write_fd, stderr_fd, .exec, "chdir into the sandbox failed");

    const argv_z = allocator.allocSentinel(?[*:0]const u8, argv.len, null) catch
        die(write_fd, stderr_fd, .exec, "out of memory");
    for (argv, 0..) |arg, index| {
        argv_z[index] = allocator.dupeZ(u8, arg) catch die(write_fd, stderr_fd, .exec, "out of memory");
    }
    const env_z = allocator.allocSentinel(?[*:0]const u8, config.env.len, null) catch
        die(write_fd, stderr_fd, .exec, "out of memory");
    for (config.env, 0..) |item, index| {
        env_z[index] = allocator.dupeZ(u8, item) catch die(write_fd, stderr_fd, .exec, "out of memory");
    }

    const report = limits.apply(config.limits);
    for ([_]limits.Report.State{ report.cpu_time, report.file_size, report.open_files }) |state| {
        if (state == .unavailable) die(write_fd, stderr_fd, .resource_limits, "a resource limit could not be set");
    }

    const support = seatbelt.apply(profile);
    if (!support.applied()) die(write_fd, stderr_fd, .confinement, "the sandbox profile was refused");

    _ = std.c.execve(argv_z[0].?, argv_z.ptr, env_z.ptr);
    die(write_fd, stderr_fd, .exec, "execve failed");
}

fn resetSignalState() void {
    var action: std.c.Sigaction = undefined;
    @memset(std.mem.asBytes(&action), 0);
    action.handler = .{ .handler = std.c.SIG.DFL };
    var signal: u6 = 1;
    while (signal < 32) : (signal += 1) {
        _ = std.c.sigaction(@enumFromInt(signal), &action, null);
    }
    var empty: std.c.sigset_t = undefined;
    _ = std.c.sigemptyset(&empty);
    _ = std.c.sigprocmask(std.c.SIG.SETMASK, &empty, null);
}

fn redirectStdin(config: Config, write_fd: std.c.fd_t) void {
    const null_fd = std.c.open("/dev/null", .{ .ACCMODE = .RDWR });
    if (null_fd < 0) die(write_fd, config.stderr_fd, .stdin_redirect, "could not open /dev/null");
    if (std.c.dup2(null_fd, 0) < 0) die(write_fd, config.stderr_fd, .stdin_redirect, "could not redirect standard input");
    if (null_fd > 2) _ = std.c.close(null_fd);
}

fn closeInheritedFds(config: Config, write_fd: std.c.fd_t) void {
    var highest: std.c.rlimit = undefined;
    const limit: usize = if (std.c.getrlimit(.NOFILE, &highest) == 0)
        @min(@as(u64, @intCast(highest.cur)), 1 << 16)
    else
        1 << 16;

    var fd: std.c.fd_t = 3;
    while (fd < limit) : (fd += 1) {
        if (fd == write_fd) continue;
        if (fd == config.stdout_fd or fd == config.stderr_fd) continue;
        if (config.stdin_fd) |kept| if (fd == kept) continue;
        _ = std.c.close(fd);
    }
}

fn redirectStandardStreams(config: Config, write_fd: std.c.fd_t) void {
    if (config.stdin_fd) |fd| {
        if (std.c.dup2(fd, 0) < 0) die(write_fd, config.stderr_fd, .stdin_redirect, "could not redirect standard input");
    }
    if (config.stdout_fd != 1) {
        if (std.c.dup2(config.stdout_fd, 1) < 0) die(write_fd, config.stderr_fd, .close_fds, "could not redirect standard output");
    }
    if (config.stderr_fd != 2) {
        if (std.c.dup2(config.stderr_fd, 2) < 0) die(write_fd, 2, .close_fds, "could not redirect standard error");
    }
    if (config.stdout_fd > 2) _ = std.c.close(config.stdout_fd);
    if (config.stderr_fd > 2 and config.stderr_fd != config.stdout_fd) _ = std.c.close(config.stderr_fd);
    if (config.stdin_fd) |fd| if (fd > 2) {
        _ = std.c.close(fd);
    };
}

pub fn signalMiddle(fd: std.posix.fd_t, sig: std.posix.SIG) iface.SignalError!void {
    if (fd < 0) return error.NoHandle;
    if (builtin.os.tag == .macos) {
        const byte: [1]u8 = .{@truncate(@intFromEnum(sig))};
        while (true) {
            const n = std.c.write(fd, &byte, 1);
            if (n == 1) return;
            const err = std.c._errno().*;
            if (err == @intFromEnum(std.c.E.INTR)) continue;
            if (err == @intFromEnum(std.c.E.PIPE)) return error.Gone;
            return error.Unexpected;
        }
    } else {
        return error.NoHandle;
    }
}

pub fn closeMiddle(middle: *iface.Middle) void {
    if (builtin.os.tag == .macos) {
        if (middle.fd >= 0) _ = std.c.close(middle.fd);
    }
    middle.fd = -1;
}

pub fn joinFreshSessionKeyring(stderr_fd: std.posix.fd_t) error{Refused}!void {
    _ = stderr_fd;
    return error.Refused;
}

test "spawn refuses a config that needs the layer macos has not got" {
    const base = Config{ .root = "/", .mounts = &.{}, .rules = &.{}, .cwd = "/", .env = &.{} };

    var moved = base;
    moved.mounts = &.{.{ .bind = .{ .source = "/work/checkout", .target = "/home/me/project" } }};
    try std.testing.expectEqual(Inexpressible.bind_moves_a_path, expressibleOn(moved).?);

    var overlaid = base;
    overlaid.mounts = &.{.{ .overlay = .{ .lower = "/l", .upper = "/u", .work = "/w", .target = "/t" } }};
    try std.testing.expectEqual(Inexpressible.overlay_mount, expressibleOn(overlaid).?);

    var procfs = base;
    procfs.mounts = &.{.{ .proc = .{} }};
    try std.testing.expectEqual(Inexpressible.proc_mount, expressibleOn(procfs).?);

    var rooted = base;
    rooted.root = "/tmp/some/root";
    try std.testing.expectEqual(Inexpressible.root_is_not_the_real_root, expressibleOn(rooted).?);

    var identity = base;
    identity.mounts = &.{.{ .bind = .{ .source = "/nix/store/x", .target = "/nix/store/x", .read_only = true } }};
    try std.testing.expectEqual(@as(?Inexpressible, null), expressibleOn(identity));
}

test "spawn never allocates and never forks before it refuses" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const err = spawn(failing.allocator(), .{
        .root = "/does-not-exist-and-must-never-be-touched",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    }, &.{"/bin/true"}, null, null);
    try std.testing.expectError(error.NoMountNamespace, err);
    try std.testing.expectEqual(@as(usize, 0), failing.allocations);
}

test "spawn leaves landlock_report and the middle handle untouched when it refuses" {
    var report: iface.LandlockReport = .{ .abi = -1, .features = undefined };
    var middle: iface.Middle = .{ .pid = -1, .fd = -2 };
    const err = spawn(std.testing.allocator, .{
        .root = "/does-not-matter",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    }, &.{"/bin/true"}, &report, &middle);
    try std.testing.expectError(error.NoMountNamespace, err);
    try std.testing.expectEqual(@as(i32, -1), report.abi);
    try std.testing.expectEqual(@as(std.posix.pid_t, -1), middle.pid);
    try std.testing.expectEqual(@as(std.posix.fd_t, -2), middle.fd);
}

test "a filtered config is refused rather than quietly given no channel out" {
    const err = spawn(std.testing.allocator, .{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .network = .filtered,
    }, &.{"/bin/true"}, null, null);
    try std.testing.expectError(error.NetBrokerMissing, err);
}

test "signalMiddle refuses a handle nobody opened" {
    try std.testing.expectError(error.NoHandle, signalMiddle(-1, std.posix.SIG.KILL));
}

test "closeMiddle leaves no descriptor a second call could close twice" {
    var middle: iface.Middle = .{ .pid = 7, .fd = -1 };
    closeMiddle(&middle);
    try std.testing.expectEqual(@as(std.posix.fd_t, -1), middle.fd);
    closeMiddle(&middle);
    try std.testing.expectEqual(@as(std.posix.fd_t, -1), middle.fd);
}

test "the guarantees name only the layers a test really proves" {
    try std.testing.expect(guarantees.contains(.network_isolated));
    try std.testing.expect(guarantees.contains(.signal_isolated));
    try std.testing.expect(guarantees.contains(.ipc_isolated));
    try std.testing.expect(guarantees.contains(.path_restricted));
    try std.testing.expect(!guarantees.contains(.syscall_restricted));
    try std.testing.expect(!guarantees.contains(.workspace_mounted));
    try std.testing.expectEqual(@as(usize, 4), guarantees.count());
}

test "a capped scratch area is refused rather than quietly left out" {
    const config = Config{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .scratch = &.{.{ .target = "/run/chock/scratch" }},
    };
    try std.testing.expectEqual(Inexpressible.scratch_area, expressibleOn(config).?);
    try std.testing.expectError(error.NoMountNamespace, spawn(std.testing.allocator, config, &.{"/bin/true"}, null, null));
}

test "a cgroup the caller made is refused by name, and refused before every other check" {
    const placeable = Config{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .containment = .{ .supplied = .{ .fd = 7 } },
    };
    try std.testing.expectEqual(@as(?Inexpressible, null), expressibleOn(placeable));
    try std.testing.expectError(
        error.CgroupPlacementUnsupported,
        spawn(std.testing.allocator, placeable, &.{"/bin/true"}, null, null),
    );

    var also_unmountable = placeable;
    also_unmountable.root = "/somewhere-else";
    try std.testing.expectError(
        error.CgroupPlacementUnsupported,
        spawn(std.testing.allocator, also_unmountable, &.{"/bin/true"}, null, null),
    );

    try std.testing.expectEqual(builtin.os.tag == .linux, iface.expresses.cgroup_placement);
}

test "a read only bind takes write away, and a later read write bind gives it back" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const options = try optionsFor(allocator, .{
        .root = "/",
        .mounts = &.{
            .{ .bind = .{ .source = "/w", .target = "/w", .read_only = false } },
            .{ .bind = .{ .source = "/w/meta", .target = "/w/meta", .read_only = true } },
            .{ .bind = .{ .source = "/w/meta/index", .target = "/w/meta/index", .read_only = false } },
        },
        .rules = &.{},
        .cwd = "/w",
        .env = &.{},
    });

    var buffer: [4096]u8 = undefined;
    var builder = seatbelt.Builder.init(&buffer);
    const profile = try builder.finish(options);

    const takes_write = std.mem.indexOf(u8, profile, "(deny file-write* (subpath \"/w/meta\"))").?;
    const gives_it_back = std.mem.indexOf(u8, profile, "(allow file-read* file-write* (subpath \"/w/meta/index\"))").?;
    try std.testing.expect(gives_it_back > takes_write);
    try std.testing.expect(std.mem.indexOf(u8, profile, "(allow file-read* (subpath \"/w/meta\"))") != null);
}

test "a landlock rule is written before the mounts, so a mount is the last word" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const options = try optionsFor(allocator, .{
        .root = "/",
        .mounts = &.{.{ .bind = .{ .source = "/w", .target = "/w", .read_only = true } }},
        .rules = &.{.{ .path = "/w", .access = landlock.AccessFs.read_write }},
        .cwd = "/w",
        .env = &.{},
    });

    var buffer: [4096]u8 = undefined;
    var builder = seatbelt.Builder.init(&buffer);
    const profile = try builder.finish(options);

    const from_the_rule = std.mem.indexOf(u8, profile, "(allow file-read* file-write* (subpath \"/w\"))").?;
    const from_the_mount = std.mem.indexOf(u8, profile, "(deny file-write* (subpath \"/w\"))").?;
    try std.testing.expect(from_the_mount > from_the_rule);
}

test "a landlock right set becomes the two rights seatbelt has" {
    try std.testing.expectEqual(seatbelt.Access{ .read = true }, accessFor(landlock.AccessFs.read_only));
    try std.testing.expectEqual(seatbelt.Access{ .read = true }, accessFor(.{ .execute = true }));
    try std.testing.expectEqual(seatbelt.Access{ .write = true }, accessFor(.{ .make_dir = true }));
    try std.testing.expectEqual(seatbelt.Access{}, accessFor(.{}));
}
