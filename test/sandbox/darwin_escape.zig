//! Tests that try to escape the Darwin sandbox. Each one must fail to escape.
//!
//! **Every test here drives a real `chock_sandbox.spawn` on a real Mac.** None
//! of them reads a profile, and none of them asks a stand-in what it would have
//! done. A test that says a path is refused opened that path and was refused; a
//! test that says the network is closed tried to reach something. This project
//! has already shipped an LSP client that had never once worked against a real
//! server, because both in-house fakes accepted what no real one would, and a
//! Seatbelt profile is exactly the shape of thing that fools a fake: it
//! compiles, it applies, and it denies nothing at all.
//!
//! The other half of that rule is that several tests here want the operation to
//! **succeed**. A profile that denied everything would pass a suite that only
//! ever looked for a refusal, and it would also be useless. So the suite pins
//! both edges of every boundary it claims.
//!
//! See `test/sandbox/escape.zig` for the Linux suite this mirrors. The two share
//! no code, because they share no mechanism: none of Landlock, seccomp or a
//! namespace exists here.

const std = @import("std");
const builtin = @import("builtin");

const chock_sandbox = @import("chock-sandbox");

// Zig 0.16 removed std.process.argsWithAllocator, and the default test runner
// panics on any argv it does not recognize, so a CLI argument cannot carry the
// probe path. The path is embedded at build time by build.zig, through an
// options module built with `addOptionPath`.
const probe_path = @import("probe_path").probe_path;

/// The size of this platform's `sun_path`, read off the platform's own
/// structure so it cannot drift. 104 on Darwin and 108 on Linux. See the skip
/// below for why `std.Io.net.UnixAddress.max_len` is the wrong number.
const sun_path_len = @typeInfo(@FieldType(std.posix.sockaddr.un, "path")).array.len;

/// What one probe run answered. See `test/sandbox/darwin_probe.zig` for the
/// whole contract; these three are the only ones a test here reads.
const succeeded: u8 = 0;
const refused: u8 = 1;

/// A scratch tree for one probe run, with the two halves every test needs: a
/// `work` directory the sandbox may reach and an `outside` directory it may not.
///
/// **The path is resolved, not merely absolute, and that is a boundary and not
/// tidiness.** Seatbelt matches the path the kernel resolved. Measured on
/// 2026-08-25: a rule naming `/tmp/x`, where `/tmp` is a symlink to
/// `/private/tmp`, matches nothing. A test that handed the driver an unresolved
/// path would prove nothing about a rule that was never in force.
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

/// `F_GETPATH`, from Darwin's own `sys/fcntl.h`, gives the absolute path of an
/// open descriptor. **It gives the resolved path**, which is exactly the one
/// Seatbelt matches against, so this is the Darwin answer to what the Linux
/// suite reads out of `/proc/self/fd`. `std.testing.tmpDir` hands back a
/// directory under `.zig-cache/tmp`, reached only by a relative path, and a
/// relative path in a profile rule matches nothing at all.
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

    // A symlink inside the reachable half, aimed at the unreachable half. The
    // sandbox must follow it and still refuse.
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
        // A probe the system killed answers nothing, and must never be read as
        // a refusal by the sandbox.
        else => 200,
    };
}

/// Skip when this process is inside somebody else's Seatbelt profile, because
/// then `sandbox_init` is refused before it reads a profile and every test here
/// would report a boundary failure for a boundary that was never built.
///
/// **The stated reason: Nix on macOS runs every builder under `sandbox-exec`,
/// and macOS refuses to nest one profile inside another.** Measured on a real
/// Mac on 2026-08-25: from a login shell `sandbox_init` answered 0 for
/// `(allow default)` and for a deny-by-default profile; inside a Nix build the
/// same two calls answered -1 with `EPERM`. So the environment refuses the
/// question this file asks, and the whole suite has nothing to measure there.
/// See `chock-sandbox/darwin/seatbelt.zig`'s own `confinedAlready`, which asks
/// again at run time rather than reading an environment variable.
///
/// **This is not a platform guard and it must never fire on an ordinary Mac.**
/// A skip that always fires is a deleted test wearing a disguise. Proven on
/// 2026-08-25 by running this suite three ways on one machine: from a login
/// shell all 13 tests ran and passed, under
/// `sandbox-exec -p '(version 1)(allow default)'` all 13 skipped, and inside a
/// Nix build all 13 skipped.
///
/// A skip carries no message on purpose. A test that writes to standard error
/// puts a `failed command:` line in the build log whatever it exits with.
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
    // First, because every other test here is meaningless if `spawn` refuses.
    // It also pins the half of the driver a refusal can never exercise: the
    // fork, the profile, the exec and the relay of the program's own status
    // back through the middle process.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(succeeded, try run("runs", root.path()));
}

test "a path outside the sandbox cannot be read, and one inside it can" {
    // Both halves, because a driver that denied everything would pass the first
    // check and be useless.
    //
    // Mutation check: in `seatbelt.Builder.finish`, drop the `options.allow`
    // loop and the second case fails. Change `(deny default)` to
    // `(allow default)` and the first case fails.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("read-outside", root.path()));
    try std.testing.expectEqual(succeeded, try run("read-allowed", root.path()));
}

test "a path outside the sandbox cannot be written, and one inside it can" {
    // Mutation check: in the Darwin driver's own `optionsFor`, give every bind
    // `.read_only` and the second case fails while the first still passes,
    // which is how a sandbox that is merely broken is told from one that
    // confines.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("write-outside", root.path()));
    try std.testing.expectEqual(succeeded, try run("write-allowed", root.path()));
}

test "a symlink out of the sandbox is followed to where it points and refused" {
    // The link is inside the reachable half and its target is not, so a driver
    // that checked the path it was handed rather than the path the kernel
    // resolves would let this through. Measured on 2026-08-25: Seatbelt matches
    // the resolved path, so it does not.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("read-symlink-out", root.path()));
}

test "a denied file inside a reachable directory is still denied" {
    // **The one that catches a rule order fault, and it is the only one that
    // can.** Measured on 2026-08-25: among two rules that both name a path, the
    // later one wins, so a denial written before the allowance that covers it
    // compiles, applies, and does nothing at all. Nothing about that failure is
    // visible in the profile text or in any return value.
    //
    // Mutation check: move the `options.deny` loop in `seatbelt.Builder.finish`
    // above the `options.allow` loop. The first case here fails and the second
    // still passes, which is exactly the shape of a boundary that has quietly
    // gone away.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("read-denied-file", root.path()));
    // And the denial covers one file, not the directory it is in.
    try std.testing.expectEqual(succeeded, try run("read-beside-denied-file", root.path()));
}

test "a sandboxed program cannot open a connection" {
    // A real address on the real internet, and a real `connect`. The answer is
    // `EPERM` from Seatbelt rather than a routing failure, so a machine with no
    // network of its own still runs this test honestly.
    //
    // Mutation check: set `allow_network` to true in the Darwin driver's own
    // `optionsFor` and this fails on a machine that has a network.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("connect", root.path()));
}

test "a sandboxed program cannot reach a unix socket outside it" {
    // **The route a network rule that only covered IP would have left open.** A
    // service on this machine, reachable by its socket path, is exactly what a
    // program with no route to the internet would try next. The listener here is
    // real and outside the sandbox: the probe tells `EPERM` apart from a socket
    // nobody is listening on, so a listener that had already gone away fails the
    // test rather than passing it.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();

    var socket_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket_path = try std.fmt.bufPrint(&socket_buffer, "{s}/outside/listener.sock", .{root.path()});
    // A build tree deep enough to pass the bound cannot host this test, and
    // saying so is better than a refusal that reads as a sandbox that held.
    //
    // **`std.Io.net.UnixAddress.max_len` is 108 on every platform that is not
    // Windows, and Darwin's `sun_path` is 104**, so this line used to run on a
    // Mac the very cases that end the process inside `listen`: see
    // `lib/chock-proto/control.zig`'s `max_socket_path`. That constant is the
    // one home for the number, and this test target imports `probe_path` alone,
    // so the field itself is read here rather than a second copy of the number
    // being typed out.
    if (socket_path.len >= sun_path_len) return error.SkipZigTest;
    const address = try std.Io.net.UnixAddress.init(socket_path);
    var server = try address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);

    try std.testing.expectEqual(refused, try runWith("connect-unix", root.path(), socket_path));
}

test "a sandboxed program cannot signal a process outside it, and can signal its own child" {
    // **Both halves, and the second one is why the first is written the way it
    // is.** A bare `(deny signal)` gives the first half and takes the second
    // away, and a program that cannot signal a child it started itself is a
    // shell that cannot end a background job and a build that cannot stop its
    // workers. Measured on 2026-08-25.
    //
    // Mutation check: set `allow_signal_same_sandbox` to false in
    // `seatbelt.Options` and the second case fails. Change the `(deny signal)`
    // line to `(allow signal)` and the first case fails.
    //
    // **Not "drop the `(deny signal)` line", which was tried on 2026-08-25 and
    // caught nothing.** `(deny default)` already refuses every signal, so that
    // line is a statement of intent and not the thing enforcing this. The rule
    // that has to be attacked to test the boundary is the base one.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();

    // A process of this test's own, outside the sandbox, that the sandboxed
    // program is asked to reach. Its own pid is the simplest such process, and
    // it is certainly alive while the test runs.
    var pid_buffer: [16]u8 = undefined;
    const own_pid = try std.fmt.bufPrint(&pid_buffer, "{d}", .{std.c.getpid()});

    try std.testing.expectEqual(refused, try runWith("signal-host", root.path(), own_pid));
    try std.testing.expectEqual(succeeded, try run("signal-own-child", root.path()));
}

test "a sandboxed program cannot attach shared memory the host made" {
    // System V shared memory is the one route out that no file rule and no
    // network rule covers. Measured on 2026-08-25 with the control this needs:
    // the same attach succeeds under `(allow default)` and is refused with
    // `EPERM` under `(deny default)`, so the profile is what refuses it and not
    // the machine.
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
    // **Seatbelt checks paths, and a descriptor is not a path.** Measured on
    // 2026-08-25: a process read sixteen bytes of a file through a descriptor it
    // had opened before `sandbox_init`, under a profile that denied that very
    // path. So the driver closing what it inherited is not housekeeping, it is
    // the other half of the path layer.
    //
    // Mutation check: delete the `closeInheritedFds` call in the Darwin driver's
    // own `runProgram` and this test fails while every other test here passes.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("inherited-fd", root.path()));
}

test "a sandboxed program cannot drop the sandbox it is in" {
    // The whole layer is worth nothing if the program can call `sandbox_init`
    // again with a wider profile. Measured on 2026-08-25: the second call is
    // refused with `EPERM`, whether it would widen or narrow. The probe does not
    // trust that return value on its own; it tries the denied read again
    // afterwards.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("widen", root.path()));
}

test "a resource limit Darwin really has stops the program that passes it" {
    // `RLIMIT_FSIZE` is one of the three limits `darwin/limits.zig` reports as
    // `ok`, and this is what makes that report a measurement rather than a
    // hope. The other four report `unsupported`, and there is deliberately no
    // test here that pretends to prove one of them.
    //
    // Mutation check: delete the `file_size` line in `limits.apply` and this
    // fails.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(refused, try run("file-size", root.path()));
}

test "a running call can be ended through the handle spawn gave" {
    // **The one test of the middle process.** Darwin has no `pidfd`, so the
    // handle is a pipe to a process that holds the sandboxed program as a child
    // and never reaps it while a cancel may still be in flight. A cancel sent
    // as a bare pid would be the fault measured on 2026-08-22, when a teardown
    // path signalled a number and took down a whole process group holding an
    // unrelated build.
    //
    // The probe's sandboxed program would sleep for two minutes, so a test that
    // finishes at all is a cancel that landed, and the probe checks that the
    // call ended by signal rather than by the sleep finishing.
    try requireOwnProfile();
    var root = try scratch();
    defer root.cleanup();
    try std.testing.expectEqual(succeeded, try run("cancel", root.path()));
}

comptime {
    // This suite has no meaning anywhere else, and build.zig only builds it for
    // macOS. Saying so here as well means a reader who moves the build rule
    // meets the reason rather than a puzzling failure.
    if (builtin.os.tag != .macos) @compileError("test/sandbox/darwin_escape.zig is for macOS only");
}

extern "c" fn shmget(key: c_int, size: usize, flags: c_int) c_int;
extern "c" fn shmctl(id: c_int, command: c_int, buffer: ?*anyopaque) c_int;
