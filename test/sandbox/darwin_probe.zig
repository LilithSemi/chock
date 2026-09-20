//! The program `test/sandbox/darwin_escape.zig` drives. Every operation really
//! tries the thing its name says, in a real sandbox on a real Mac, and reports
//! what the kernel answered. Nothing here reads a profile.
//!
//! Exit codes:
//!
//! * 0: the operation succeeded.
//! * 1: the kernel refused it.
//! * 2: the operation could not be done at all, so it says nothing.
//! * 20 and above: a fault outside the sandbox, in this program's own setup.

const std = @import("std");
const sandbox = @import("chock-sandbox");

extern "c" fn sandbox_init(profile: [*:0]const u8, flags: u64, errorbuf: *?[*:0]u8) c_int;
extern "c" fn shmat(id: c_int, addr: ?*const anyopaque, flags: c_int) ?*anyopaque;

const mach_port_t = c_uint;
const kern_return_t = c_int;

/// `bootstrap_port` is set by dyld before `main` runs and needs no call.
extern "c" fn bootstrap_look_up(bp: mach_port_t, service_name: [*:0]const u8, sp: *mach_port_t) kern_return_t;
extern "c" var bootstrap_port: mach_port_t;

const succeeded: u8 = 0;
const refused: u8 = 1;
const no_answer: u8 = 2;
const outer_fault: u8 = 20;
const spawn_refused: u8 = 21;
const inner_missing: u8 = 22;
const not_cancelled: u8 = 23;
/// Inside a `nix build` the builder already holds a Seatbelt profile, so
/// `sandbox_init` refuses and every operation here answers this.
const profile_refused: u8 = 24;
const not_expressible: u8 = 25;
const profile_unbuildable: u8 = 26;

fn exitFor(err: anyerror) u8 {
    return switch (err) {
        error.LandlockRestrictFailed => profile_refused,
        error.NoMountNamespace => not_expressible,
        error.LandlockInitFailed => profile_unbuildable,
        else => spawn_refused,
    };
}

const cancel_bound_ns: u64 = 20 * std.time.ns_per_s;
const cancel_step_ns: u64 = 2 * std.time.ns_per_ms;

fn zpath(buffer: []u8, path: []const u8) [*:0]const u8 {
    @memcpy(buffer[0..path.len], path);
    buffer[path.len] = 0;
    return @ptrCast(buffer.ptr);
}

fn openRead(path: []const u8) c_int {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    return std.c.open(zpath(&buffer, path), .{ .ACCMODE = .RDONLY });
}

/// A path rule that lets the open through and stops the read reads as a refusal.
fn readsBack(fd: c_int) bool {
    var byte: [1]u8 = undefined;
    return std.c.read(fd, &byte, 1) == 1;
}

fn join(arena: std.mem.Allocator, root: []const u8, rest: []const u8) []const u8 {
    return std.fs.path.join(arena, &.{ root, rest }) catch @panic("out of memory");
}

/// A name a sandbox denies answers `BOOTSTRAP_NOT_PRIVILEGED` (1100), not
/// `BOOTSTRAP_UNKNOWN_SERVICE` (1102), so a refusal is never a missing name.
fn machLookup(name: []const u8) u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    var port: mach_port_t = 0;
    const kr = bootstrap_look_up(bootstrap_port, zpath(&buffer, name), &port);
    return if (kr == 0) succeeded else refused;
}

/// `Sandbox.Config` carries no field for `Options.mach_services`, so nothing
/// public can widen the list. The profile text is typed out by hand.
fn widenedMachLookup(granted: []const u8, target: []const u8) u8 {
    var buffer: [1024]u8 = undefined;
    const profile = std.fmt.bufPrintZ(
        &buffer,
        "(version 1)\n(deny default)\n(allow file-read* (literal \"/\"))\n(deny mach-lookup)\n(allow mach-lookup (global-name \"{s}\"))\n",
        .{granted},
    ) catch return profile_unbuildable;
    var message: ?[*:0]u8 = null;
    if (sandbox_init(profile, 0, &message) != 0) return profile_refused;
    return machLookup(target);
}

/// Zig 0.16 has no `std.Thread.sleep`, and this program links libc anyway.
fn sleepStep() void {
    var step: std.c.timespec = .{ .sec = 0, .nsec = @intCast(cancel_step_ns) };
    _ = std.c.nanosleep(&step, null);
}

/// argv[0] is relative, because build.zig hands the test a path under
/// `.zig-cache`, and a relative path in a sandbox rule matches nothing.
fn resolve(arena: std.mem.Allocator, path: []const u8) []const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const fd = openRead(path);
    if (fd < 0) return path;
    defer _ = std.c.close(fd);
    if (std.c.fcntl(fd, std.c.F.GETPATH, @as([*]u8, &buffer)) != 0) return path;
    return arena.dupe(u8, std.mem.sliceTo(&buffer, 0)) catch @panic("out of memory");
}

fn baseMounts(
    arena: std.mem.Allocator,
    work: []const u8,
    self_dir: []const u8,
) []const sandbox.namespace.Mount {
    const mounts = arena.alloc(sandbox.namespace.Mount, 2) catch @panic("out of memory");
    mounts[0] = .{ .bind = .{ .source = work, .target = work, .read_only = false } };
    mounts[1] = .{ .bind = .{ .source = self_dir, .target = self_dir, .read_only = true } };
    return mounts;
}

fn runInside(
    arena: std.mem.Allocator,
    work: []const u8,
    self_path: []const u8,
    inner_argv: []const []const u8,
    extra_mounts: []const sandbox.namespace.Mount,
    network: sandbox.namespace.Network,
    limits: sandbox.Sandbox.Limits,
) u8 {
    const self_dir = std.fs.path.dirname(self_path) orelse "/";
    var mounts: std.ArrayList(sandbox.namespace.Mount) = .empty;
    mounts.appendSlice(arena, baseMounts(arena, work, self_dir)) catch @panic("out of memory");
    mounts.appendSlice(arena, extra_mounts) catch @panic("out of memory");

    const term = sandbox.spawn(arena, .{
        .root = "/",
        .mounts = mounts.items,
        .rules = &.{},
        .cwd = work,
        .env = &.{},
        .network = network,
        .limits = limits,
    }, inner_argv, null, null) catch |err| return exitFor(err);

    return switch (term) {
        .exited => |code| code,
        // A program the sandbox killed says nothing about the operation.
        else => inner_missing,
    };
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.args.toSlice(arena);
    if (args.len < 3) {
        return outer_fault;
    }
    const op = args[1];
    const root = args[2];
    const self_path = resolve(arena, args[0]);
    const work = join(arena, root, "work");
    const outside = join(arena, root, "outside");
    const limits = sandbox.Sandbox.Limits.none;

    if (std.mem.eql(u8, op, "in-read")) {
        const fd = openRead(args[3]);
        if (fd < 0) return refused;
        defer _ = std.c.close(fd);
        return if (readsBack(fd)) succeeded else refused;
    }

    if (std.mem.eql(u8, op, "in-write")) {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const fd = std.c.open(
            zpath(&buffer, args[3]),
            .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
            @as(std.c.mode_t, 0o600),
        );
        if (fd < 0) return refused;
        defer _ = std.c.close(fd);
        return if (std.c.write(fd, "x", 1) == 1) succeeded else refused;
    }

    if (std.mem.eql(u8, op, "in-connect")) {
        const socket = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
        if (socket < 0) return refused;
        defer _ = std.c.close(socket);
        var address: std.posix.sockaddr.in = .{
            .port = std.mem.nativeToBig(u16, 80),
            .addr = @bitCast([4]u8{ 1, 1, 1, 1 }),
        };
        const rc = std.c.connect(socket, @ptrCast(&address), @sizeOf(std.posix.sockaddr.in));
        return if (rc == 0) succeeded else refused;
    }

    if (std.mem.eql(u8, op, "in-unix")) {
        const socket = std.c.socket(std.c.AF.UNIX, std.c.SOCK.STREAM, 0);
        if (socket < 0) return refused;
        defer _ = std.c.close(socket);
        var address: std.posix.sockaddr.un = .{ .path = undefined };
        @memset(&address.path, 0);
        if (args[3].len >= address.path.len) return no_answer;
        @memcpy(address.path[0..args[3].len], args[3]);
        const rc = std.c.connect(socket, @ptrCast(&address), @sizeOf(std.posix.sockaddr.un));
        if (rc == 0) return succeeded;
        // A refusal and a socket nobody listens on are different facts.
        return if (std.c._errno().* == @intFromEnum(std.c.E.PERM)) refused else no_answer;
    }

    if (std.mem.eql(u8, op, "in-signal")) {
        const pid = std.fmt.parseInt(std.c.pid_t, args[3], 10) catch return no_answer;
        // Signal 0 sends nothing. The kernel only checks that the process exists.
        return if (std.c.kill(pid, @enumFromInt(0)) == 0) succeeded else refused;
    }

    if (std.mem.eql(u8, op, "in-signal-own")) {
        const child = std.c.fork();
        if (child < 0) return no_answer;
        if (child == 0) {
            var pause: std.c.timespec = .{ .sec = 30, .nsec = 0 };
            _ = std.c.nanosleep(&pause, null);
            std.c._exit(0);
        }
        var settle: std.c.timespec = .{ .sec = 0, .nsec = 200 * std.time.ns_per_ms };
        _ = std.c.nanosleep(&settle, null);
        const rc = std.c.kill(child, .TERM);
        var status: c_int = 0;
        _ = std.c.waitpid(child, &status, 0);
        return if (rc == 0) succeeded else refused;
    }

    if (std.mem.eql(u8, op, "in-shm")) {
        const id = std.fmt.parseInt(c_int, args[3], 10) catch return no_answer;
        const address = shmat(id, null, 0);
        const raw: isize = if (address) |pointer| @bitCast(@intFromPtr(pointer)) else -1;
        return if (raw == -1) refused else succeeded;
    }

    if (std.mem.eql(u8, op, "in-inherited-fd")) {
        // Descriptor 3 is a file the outer call opened outside the sandbox. If the
        // driver closed it, this is EBADF.
        return if (readsBack(3)) succeeded else refused;
    }

    if (std.mem.eql(u8, op, "in-mach-lookup")) {
        return machLookup(args[3]);
    }

    if (std.mem.eql(u8, op, "in-widen")) {
        var message: ?[*:0]u8 = null;
        const rc = sandbox_init("(version 1)(allow default)", 0, &message);
        if (rc != 0) {
            const fd = openRead(args[3]);
            if (fd < 0) return refused;
            defer _ = std.c.close(fd);
            return if (readsBack(fd)) succeeded else refused;
        }
        return succeeded;
    }

    if (std.mem.eql(u8, op, "in-file-size")) {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const fd = std.c.open(
            zpath(&buffer, args[3]),
            .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
            @as(std.c.mode_t, 0o600),
        );
        if (fd < 0) return no_answer;
        defer _ = std.c.close(fd);
        // A write past `RLIMIT_FSIZE` raises SIGXFSZ as well as answering EFBIG, and
        // the signal must not end this process before it reports.
        var ignore: std.c.Sigaction = undefined;
        @memset(std.mem.asBytes(&ignore), 0);
        ignore.handler = .{ .handler = std.c.SIG.IGN };
        _ = std.c.sigaction(.XFSZ, &ignore, null);
        var block: [8192]u8 = undefined;
        @memset(&block, 'a');
        var round: usize = 0;
        while (round < 8) : (round += 1) {
            if (std.c.write(fd, &block, block.len) < 0) return refused;
        }
        return succeeded;
    }

    if (std.mem.eql(u8, op, "in-sleep")) {
        var pause: std.c.timespec = .{ .sec = 120, .nsec = 0 };
        _ = std.c.nanosleep(&pause, null);
        return succeeded;
    }

    if (std.mem.eql(u8, op, "in-true")) return succeeded;

    if (std.mem.eql(u8, op, "runs")) {
        return runInside(arena, work, self_path, &.{ self_path, "in-true", root }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "read-outside")) {
        const secret = join(arena, outside, "secret.txt");
        return runInside(arena, work, self_path, &.{ self_path, "in-read", root, secret }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "read-allowed")) {
        const allowed = join(arena, work, "ok.txt");
        return runInside(arena, work, self_path, &.{ self_path, "in-read", root, allowed }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "write-outside")) {
        const target = join(arena, outside, "written-by-the-sandbox.txt");
        return runInside(arena, work, self_path, &.{ self_path, "in-write", root, target }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "write-allowed")) {
        const target = join(arena, work, "written-by-the-sandbox.txt");
        return runInside(arena, work, self_path, &.{ self_path, "in-write", root, target }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "read-symlink-out")) {
        const link = join(arena, work, "out.link");
        return runInside(arena, work, self_path, &.{ self_path, "in-read", root, link }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "read-denied-file")) {
        const hidden = join(arena, work, "hidden.env");
        const deny = arena.alloc(sandbox.namespace.Mount, 1) catch @panic("out of memory");
        deny[0] = .{ .deny = .{ .target = hidden } };
        return runInside(arena, work, self_path, &.{ self_path, "in-read", root, hidden }, deny, .none, limits);
    }

    if (std.mem.eql(u8, op, "read-beside-denied-file")) {
        const hidden = join(arena, work, "hidden.env");
        const allowed = join(arena, work, "ok.txt");
        const deny = arena.alloc(sandbox.namespace.Mount, 1) catch @panic("out of memory");
        deny[0] = .{ .deny = .{ .target = hidden } };
        return runInside(arena, work, self_path, &.{ self_path, "in-read", root, allowed }, deny, .none, limits);
    }

    if (std.mem.eql(u8, op, "connect")) {
        return runInside(arena, work, self_path, &.{ self_path, "in-connect", root }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "connect-unix")) {
        return runInside(arena, work, self_path, &.{ self_path, "in-unix", root, args[3] }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "signal-host")) {
        return runInside(arena, work, self_path, &.{ self_path, "in-signal", root, args[3] }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "signal-own-child")) {
        return runInside(arena, work, self_path, &.{ self_path, "in-signal-own", root }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "shm-attach")) {
        return runInside(arena, work, self_path, &.{ self_path, "in-shm", root, args[3] }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "mach-lookup")) {
        return runInside(arena, work, self_path, &.{ self_path, "in-mach-lookup", root, args[3] }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "mach-lookup-widened-allowed")) {
        // No `runInside`: see `widenedMachLookup`.
        return widenedMachLookup(sandbox.darwin_driver_for_testing.default_mach_services[0], sandbox.darwin_driver_for_testing.default_mach_services[0]);
    }

    if (std.mem.eql(u8, op, "mach-lookup-widened-lsd")) {
        // A LaunchServices lookup, which `default_mach_services` never carries.
        return widenedMachLookup(sandbox.darwin_driver_for_testing.default_mach_services[0], "com.apple.lsd.open");
    }

    if (std.mem.eql(u8, op, "widen")) {
        const secret = join(arena, outside, "secret.txt");
        return runInside(arena, work, self_path, &.{ self_path, "in-widen", root, secret }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "file-size")) {
        const target = join(arena, work, "big.txt");
        var capped = sandbox.Sandbox.Limits.none;
        capped.file_size_bytes = 4096;
        return runInside(arena, work, self_path, &.{ self_path, "in-file-size", root, target }, &.{}, .none, capped);
    }

    if (std.mem.eql(u8, op, "inherited-fd")) {
        // Opened outside the sandbox and deliberately not closed.
        const secret = join(arena, outside, "secret.txt");
        const fd = openRead(secret);
        if (fd < 0) return outer_fault;
        return runInside(arena, work, self_path, &.{ self_path, "in-inherited-fd", root }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "cancel")) return runCancel(arena, work, self_path, root);

    return outer_fault;
}

/// `spawn` is synchronous, so reading the handle while it runs needs a thread.
fn runCancel(arena: std.mem.Allocator, work: []const u8, self_path: []const u8, root: []const u8) u8 {
    const Call = struct {
        arena: std.mem.Allocator,
        work: []const u8,
        self_path: []const u8,
        root: []const u8,
        middle: sandbox.Middle = .{},
        term: std.process.Child.Term = undefined,
        failed: bool = false,
        failure: u8 = spawn_refused,
        done: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This()) void {
            const self_dir = std.fs.path.dirname(self.self_path) orelse "/";
            self.term = sandbox.spawn(self.arena, .{
                .root = "/",
                .mounts = baseMounts(self.arena, self.work, self_dir),
                .rules = &.{},
                .cwd = self.work,
                .env = &.{},
                .limits = sandbox.Sandbox.Limits.none,
            }, &.{ self.self_path, "in-sleep", self.root }, null, &self.middle) catch |err| {
                self.failed = true;
                self.failure = exitFor(err);
                self.done.store(true, .release);
                return;
            };
            self.done.store(true, .release);
        }
    };

    var call = Call{ .arena = arena, .work = work, .self_path = self_path, .root = root };
    const thread = std.Thread.spawn(.{}, Call.run, .{&call}) catch return outer_fault;

    var waited: u64 = 0;
    while (waited < cancel_bound_ns) : (waited += cancel_step_ns) {
        if (@atomicLoad(std.c.pid_t, &call.middle.pid, .acquire) != 0) break;
        if (call.done.load(.acquire)) break;
        sleepStep();
    }
    if (@atomicLoad(std.c.pid_t, &call.middle.pid, .acquire) == 0) {
        thread.join();
        return if (call.failed) call.failure else spawn_refused;
    }

    sandbox.signalMiddle(call.middle.fd, .KILL) catch {
        thread.join();
        sandbox.closeMiddle(&call.middle);
        return not_cancelled;
    };

    waited = 0;
    while (waited < cancel_bound_ns) : (waited += cancel_step_ns) {
        if (call.done.load(.acquire)) break;
        sleepStep();
    }
    const finished = call.done.load(.acquire);
    thread.join();
    sandbox.closeMiddle(&call.middle);

    if (!finished) return not_cancelled;
    if (call.failed) return call.failure;
    // Only an ended-by-signal outcome proves the handle reached the program.
    return switch (call.term) {
        .signal => succeeded,
        else => not_cancelled,
    };
}
