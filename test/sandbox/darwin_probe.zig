//! The program `test/sandbox/darwin_escape.zig` drives. Every operation here
//! really tries the thing its name says, inside a real sandbox that
//! `chock_sandbox.spawn` built, on a real Mac.
//!
//! **A test that says a path is refused has to have tried to open it.** This
//! project has already shipped one feature that had never worked against a real
//! server, because both in-house stand-ins accepted what no real one would. A
//! Seatbelt profile is exactly the kind of thing that shape of test cannot
//! catch: the profile compiles, applies, and denies nothing, and a test that
//! only looked at the profile text would pass. So nothing here inspects a
//! profile. Everything here opens, connects, signals or attaches, and reports
//! what the kernel answered.
//!
//! ## The exit code contract
//!
//! * **0**: the operation the name describes **succeeded**.
//! * **1**: the operation was **refused** by the kernel.
//! * **2**: the operation could not be carried out at all, so it says nothing.
//! * **20 and above**: a fault outside the sandbox, in this program's own setup.
//!
//! Both 0 and 1 are real answers, and which one a test wants depends on the
//! test. A profile that denied everything would pass a suite that only ever
//! looked for 1, so several tests below want 0.

const std = @import("std");
const sandbox = @import("chock-sandbox");

extern "c" fn sandbox_init(profile: [*:0]const u8, flags: u64, errorbuf: *?[*:0]u8) c_int;
extern "c" fn shmat(id: c_int, addr: ?*const anyopaque, flags: c_int) ?*anyopaque;

const succeeded: u8 = 0;
const refused: u8 = 1;
const no_answer: u8 = 2;
const outer_fault: u8 = 20;
const spawn_refused: u8 = 21;
const inner_missing: u8 = 22;
const not_cancelled: u8 = 23;

/// How long a cancel is given to end a call that is sleeping. Generous, because
/// a slow machine must not read as a broken cancel, and bounded, because a
/// cancel that never lands has to fail rather than hang the suite.
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

/// Read one byte, so a descriptor that opened and a descriptor that can really
/// be read are not confused. A path rule that let the open through and stopped
/// the read would otherwise pass as a refusal.
fn readsBack(fd: c_int) bool {
    var byte: [1]u8 = undefined;
    return std.c.read(fd, &byte, 1) == 1;
}

fn join(arena: std.mem.Allocator, root: []const u8, rest: []const u8) []const u8 {
    return std.fs.path.join(arena, &.{ root, rest }) catch @panic("out of memory");
}

/// One polling step. Zig 0.16 has no `std.Thread.sleep`, and this program links
/// libc for `sandbox_init` anyway.
fn sleepStep() void {
    var step: std.c.timespec = .{ .sec = 0, .nsec = @intCast(cancel_step_ns) };
    _ = std.c.nanosleep(&step, null);
}

/// The absolute, resolved path of `path`, through `F_GETPATH` on a descriptor
/// opened for it.
///
/// **This program's own argv[0] is a relative path**, because build.zig hands
/// the test a path under `.zig-cache` and the test spawns this program with it
/// unchanged. A relative path in a sandbox rule matches nothing, so the driver
/// refuses the whole spawn rather than building a boundary that is not there:
/// see `chock_sandbox`'s own `seatbelt.checkPath`. Measured on 2026-08-25, when
/// every test in the suite answered `spawn_refused` for exactly this reason,
/// which is the refusal doing its job.
fn resolve(arena: std.mem.Allocator, path: []const u8) []const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const fd = openRead(path);
    if (fd < 0) return path;
    defer _ = std.c.close(fd);
    // F_GETPATH is 50 on Darwin, from `sys/fcntl.h`.
    if (std.c.fcntl(fd, std.c.F.GETPATH, @as([*]u8, &buffer)) != 0) return path;
    return arena.dupe(u8, std.mem.sliceTo(&buffer, 0)) catch @panic("out of memory");
}

/// The mounts every spawn here uses: the work directory, writable, and the
/// directory this program lives in, readable, so the sandbox can exec it again.
///
/// **Every path is a bind whose target is its source.** That is the only shape
/// Darwin can express, and building it here rather than in the test keeps the
/// two from drifting apart. See `chock_sandbox`'s own Darwin driver and its
/// `expressibleOn`.
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

/// Run this program again, inside a sandbox, and answer with what it exited
/// with. Every operation whose real work happens inside the boundary goes
/// through here.
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
    }, inner_argv, null, null) catch return spawn_refused;

    return switch (term) {
        .exited => |code| code,
        // A program the sandbox killed says nothing about the operation it was
        // asked to try, so it must not read as either answer.
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
        // A refusal by the sandbox and a socket nobody is listening on are
        // different facts, and a test that read them the same way would pass
        // against a listener that had already gone away.
        return if (std.c._errno().* == @intFromEnum(std.c.E.PERM)) refused else no_answer;
    }

    if (std.mem.eql(u8, op, "in-signal")) {
        const pid = std.fmt.parseInt(std.c.pid_t, args[3], 10) catch return no_answer;
        // Signal 0 sends nothing. The kernel only checks that the process
        // exists and may be reached, so this asks the permission question and
        // has no other effect.
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
        // Descriptor 3 is where the outer call left an open file it had opened
        // outside the sandbox. If the driver closed it, this is EBADF.
        return if (readsBack(3)) succeeded else refused;
    }

    if (std.mem.eql(u8, op, "in-widen")) {
        var message: ?[*:0]u8 = null;
        const rc = sandbox_init("(version 1)(allow default)", 0, &message);
        if (rc != 0) {
            // The profile was not dropped. Prove it by trying the read again
            // rather than trusting the return value alone.
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
        // A write past `RLIMIT_FSIZE` raises SIGXFSZ as well as answering
        // EFBIG. The signal must not end this process before it can report.
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
        // The same config, reading the file next to the denied one. A profile
        // that denied the whole directory would pass the test above and fail
        // this one.
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
        // Opened here, outside the sandbox, and deliberately not closed. The
        // driver's own `closeInheritedFds` is the only thing between this
        // descriptor and the sandboxed program.
        const secret = join(arena, outside, "secret.txt");
        const fd = openRead(secret);
        if (fd < 0) return outer_fault;
        return runInside(arena, work, self_path, &.{ self_path, "in-inherited-fd", root }, &.{}, .none, limits);
    }

    if (std.mem.eql(u8, op, "cancel")) return runCancel(arena, work, self_path, root);

    return outer_fault;
}

/// Start a sandboxed program that would sleep for two minutes, then end it
/// through the handle `spawn` filled in, and answer whether the call really
/// stopped.
///
/// **This is the only test of the middle process, and there is no other way to
/// write it.** `spawn` is synchronous, so learning the handle while the call is
/// still running needs a thread, which is the same shape
/// `lib/chock-core/tools.zig` uses for the same reason.
fn runCancel(arena: std.mem.Allocator, work: []const u8, self_path: []const u8, root: []const u8) u8 {
    const Call = struct {
        arena: std.mem.Allocator,
        work: []const u8,
        self_path: []const u8,
        root: []const u8,
        middle: sandbox.Middle = .{},
        term: std.process.Child.Term = undefined,
        failed: bool = false,
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
            }, &.{ self.self_path, "in-sleep", self.root }, null, &self.middle) catch {
                self.failed = true;
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
        return spawn_refused;
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
    if (call.failed) return spawn_refused;
    // A program that slept for two minutes and then exited 0 was not cancelled.
    // Only an ended-by-signal outcome proves the handle reached it.
    return switch (call.term) {
        .signal => succeeded,
        else => not_cancelled,
    };
}
