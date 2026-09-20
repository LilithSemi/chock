//! Tests that try to escape the Darwin sandbox, each driving a real
//! `chock_sandbox.spawn` on a real Mac. Several want the operation to succeed,
//! because a profile that denied everything would pass a refusal-only suite.

const std = @import("std");
const builtin = @import("builtin");

const chock_sandbox = @import("chock-sandbox");

// The test runner panics on unknown argv, so build.zig embeds the probe path.
const probe_path = @import("probe_path").probe_path;

/// Read from the real constant, so an edit to the list cannot leave this stale.
const default_mach_services = chock_sandbox.darwin_driver_for_testing.default_mach_services;

/// 104 on Darwin and 108 on Linux. `std.Io.net.UnixAddress.max_len` is 108 on
/// every platform but Windows, so it is the wrong number here.
const sun_path_len = @typeInfo(@FieldType(std.posix.sockaddr.un, "path")).array.len;

const succeeded: u8 = 0;
const refused: u8 = 1;

/// Seatbelt matches the path the kernel resolved, so a rule naming `/tmp/x`,
/// where `/tmp` links to `/private/tmp`, matches nothing.
const Scratch = struct {
    tmp: std.testing.TmpDir,
    buffer: [std.fs.max_path_bytes]u8 = undefined,
    length: usize = 0,

    fn path(self: *const Scratch) []const u8 {
        return self.buffer[0..self.length];
    }

    fn cleanup(self: *Scratch) void {
        self.tmp.cleanup();
    }
};

/// `F_GETPATH` gives the resolved path. `std.testing.tmpDir` gives a relative
/// one, which matches nothing in a rule.
fn resolvedPath(handle: std.posix.fd_t, buffer: *[std.fs.max_path_bytes]u8) ![]const u8 {
    if (std.c.fcntl(handle, std.c.F.GETPATH, @as([*]u8, buffer)) != 0) return error.PathNotResolvable;
    return std.mem.sliceTo(buffer, 0);
}

fn scratch() !Scratch {
    const io = std.testing.io;
    var result = Scratch{ .tmp = std.testing.tmpDir(.{}) };
    result.length = (try resolvedPath(result.tmp.dir.handle, &result.buffer)).len;

    try result.tmp.dir.createDirPath(io, "work");
    try result.tmp.dir.createDirPath(io, "outside");
    try result.tmp.dir.writeFile(io, .{ .sub_path = "outside/secret.txt", .data = "this must never be read\n" });
    try result.tmp.dir.writeFile(io, .{ .sub_path = "work/ok.txt", .data = "ordinary content\n" });
    try result.tmp.dir.writeFile(io, .{ .sub_path = "work/hidden.env", .data = "API_KEY=secret\n" });

    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const secret = try std.fmt.bufPrint(&link_buffer, "{s}/outside/secret.txt", .{result.path()});
    try result.tmp.dir.symLink(io, secret, "work/out.link", .{});
    return result;
}

fn runProbe(argv: []const []const u8) !u8 {
    var child = try std.process.spawn(std.testing.io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(std.testing.io);
    return switch (term) {
        .exited => |code| code,
        else => 200,
    };
}

/// Nix on macOS runs every builder under `sandbox-exec`, and macOS refuses to
/// nest one profile in another, so `sandbox_init` answers -1 with `EPERM`
/// there. This must never fire on an ordinary Mac.
fn requireOwnProfile() !void {
    if (chock_sandbox.darwin_driver_for_testing.confinedAlready()) return error.SkipZigTest;
}

fn run(op: []const u8, root: []const u8) !u8 {
    return runProbe(&.{ probe_path, op, root });
}

fn runWith(op: []const u8, root: []const u8, extra: []const u8) !u8 {
    return runProbe(&.{ probe_path, op, root, extra });
}

test "a sandboxed program runs at all, and its exit code reaches the caller" {
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(succeeded, try run("runs", root.path()));
}

test "a path outside the sandbox cannot be read, and one inside it can" {
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("read-outside", root.path()));
    try std.testing.expectEqual(succeeded, try run("read-allowed", root.path()));
}

test "a path outside the sandbox cannot be written, and one inside it can" {
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("write-outside", root.path()));
    try std.testing.expectEqual(succeeded, try run("write-allowed", root.path()));
}

test "a symlink out of the sandbox is followed to where it points and refused" {
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("read-symlink-out", root.path()));
}

test "a denied file inside a reachable directory is still denied" {
    // Among two rules that both name a path the later one wins, so a denial
    // written before the allowance that covers it does nothing, and says nothing.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("read-denied-file", root.path()));
    try std.testing.expectEqual(succeeded, try run("read-beside-denied-file", root.path()));
}

test "a sandboxed program cannot open a connection" {
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("connect", root.path()));
}

test "a sandboxed program cannot reach a unix socket outside it" {
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();

    var socket_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket_path = try std.fmt.bufPrint(&socket_buffer, "{s}/outside/listener.sock", .{root.path()});
    if (socket_path.len >= sun_path_len) return error.SkipZigTest;
    const address = try std.Io.net.UnixAddress.init(socket_path);
    var server = try address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);

    try std.testing.expectEqual(refused, try runWith("connect-unix", root.path(), socket_path));
}

test "the control: a real Mach service resolves with no sandbox at all" {
    // `bootstrap_look_up` for `com.apple.launchd` answers
    // `BOOTSTRAP_UNKNOWN_SERVICE` with or without a sandbox, and `com.apple.lsd`
    // fails the same way, because launchd registers the longer names.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(succeeded, try runWith("in-mach-lookup", root.path(), default_mach_services[0]));
    try std.testing.expectEqual(succeeded, try runWith("in-mach-lookup", root.path(), "com.apple.lsd.open"));
}

test "the shipped default profile, with no opt in list at all, refuses a Mach lookup" {
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try runWith("mach-lookup", root.path(), default_mach_services[0]));
}

test "the shipped default profile refuses LaunchServices" {
    // `com.apple.lsd.open` is in neither Mach service list.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try runWith("mach-lookup", root.path(), "com.apple.lsd.open"));
}

test "the opt in list widens exactly the name it grants, and LaunchServices stays shut" {
    // Nothing through `sandbox.spawn` sets `Options.mach_services` today.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(succeeded, try run("mach-lookup-widened-allowed", root.path()));
    try std.testing.expectEqual(refused, try run("mach-lookup-widened-lsd", root.path()));
}

test "a sandboxed program cannot signal a process outside it, and can signal its own child" {
    // A bare `(deny signal)` takes the second half away. `(deny default)`
    // already refuses every signal, so the base rule is what enforces this.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();

    var pid_buffer: [16]u8 = undefined;
    const own_pid = try std.fmt.bufPrint(&pid_buffer, "{d}", .{std.c.getpid()});

    try std.testing.expectEqual(refused, try runWith("signal-host", root.path(), own_pid));
    try std.testing.expectEqual(succeeded, try run("signal-own-child", root.path()));
}

test "a sandboxed program cannot attach shared memory the host made" {
    // The one route out no file rule and no network rule covers.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();

    const key: c_int = 0; // IPC_PRIVATE
    const id = shmget(key, 4096, 0o1000 | 0o600);
    if (id < 0) return error.SkipZigTest; // No System V shared memory on this machine.
    defer _ = shmctl(id, 0, null); // IPC_RMID

    var id_buffer: [16]u8 = undefined;
    const id_text = try std.fmt.bufPrint(&id_buffer, "{d}", .{id});
    try std.testing.expectEqual(refused, try runWith("shm-attach", root.path(), id_text));
}

test "a descriptor opened before the sandbox does not survive into it" {
    // Seatbelt checks paths, and a descriptor is not a path. A process read a
    // file through one opened before `sandbox_init` under a denying profile.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("inherited-fd", root.path()));
}

test "a sandboxed program cannot drop the sandbox it is in" {
    // A second `sandbox_init` is refused with `EPERM`, widening or narrowing.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("widen", root.path()));
}

test "a resource limit Darwin really has stops the program that passes it" {
    // `RLIMIT_FSIZE` is one of three limits `darwin/limits.zig` reports as `ok`.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("file-size", root.path()));
}

test "a running call can be ended through the handle spawn gave" {
    // Darwin has no `pidfd`, so the handle is a pipe to a process that holds
    // the program and does not reap it while a cancel may be in flight.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(succeeded, try run("cancel", root.path()));
}

comptime {
    if (builtin.os.tag != .macos) @compileError("test/sandbox/darwin_escape.zig is for macOS only");
}

extern "c" fn shmget(key: c_int, size: usize, flags: c_int) c_int;
extern "c" fn shmctl(id: c_int, command: c_int, buffer: ?*anyopaque) c_int;
