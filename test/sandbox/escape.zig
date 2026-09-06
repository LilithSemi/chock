//! Tests that try to escape the sandbox. Each one must fail to escape.

const std = @import("std");
const linux = std.os.linux;

// Zig 0.16 removed std.process.argsWithAllocator, and the default test runner
// panics on any argv it does not recognize, so a CLI argument cannot carry the
// probe path. The path is instead embedded at build time by build.zig, through
// an options module built with `addOptionPath`.
const probe_path = @import("probe_path").probe_path;

// `chock-sandbox` for one question only: what a probe answers when this
// machine will not give it a sandbox at all, which is the one state in which
// none of these tests can be answered. The same narrow import, for the same
// reason, that `test/sandbox/darwin_escape.zig` takes for `confinedAlready`.
const sandbox = @import("chock-sandbox");

/// Skip when the probe answered "this machine would not give me a sandbox".
///
/// **A boundary that was never reached is not a boundary that held.** Every
/// test here asks whether the sandbox stops something, and every one needs a
/// real sandbox to ask inside, so a machine that refuses one measures nothing
/// and must not report a row of passes. A skip is what says so.
///
/// **Read here, and never inside the probe's own operation code.** The probe
/// ends at the first layer it cannot build, whichever operation it was asked
/// for, so one status covers every one of them. See
/// `namespace.nothing_measured_exit_status`, and the CI job named "Sandbox",
/// which runs this suite on a machine that can host one and fails rather than
/// skips.
fn skipIfNothingMeasured(term: std.process.Child.Term) !void {
    const code = switch (term) {
        .exited => |c| c,
        else => return,
    };
    if (code == sandbox.namespace.nothing_measured_exit_status) return error.SkipZigTest;
}

/// Read the absolute path of an already open directory descriptor, through
/// /proc/self/fd. std.testing.tmpDir hands back a directory under
/// .zig-cache/tmp, reached only through a relative path, but the probe's
/// sandbox root must be absolute: it gets bind mounted and pivot_root'd into,
/// and both need a path that resolves the same way regardless of this test
/// binary's own working directory.
fn absoluteDirPath(buffer: []u8, dir_fd: linux.fd_t) ![:0]u8 {
    var link_buffer: [64]u8 = undefined;
    const link = std.fmt.bufPrintZ(&link_buffer, "/proc/self/fd/{d}", .{dir_fd}) catch unreachable;
    const rc = linux.readlink(link, buffer.ptr, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.ReadlinkFailed;
    const len: usize = @intCast(rc);
    buffer[len] = 0;
    return buffer[0..len :0];
}

/// Scratch space for one probe run, on the host side of whatever sandbox root
/// the probe builds inside it. The test owns this directory and its cleanup;
/// the probe only ever uses the path it is handed, on the command line, and
/// never picks a location of its own.
const ScratchRoot = struct {
    tmp: std.testing.TmpDir,
    path_buffer: [std.fs.max_path_bytes]u8 = undefined,
    path_len: usize = 0,

    fn path(self: *const ScratchRoot) []const u8 {
        return self.path_buffer[0..self.path_len];
    }

    /// Removing this directory can only happen once the probe that was
    /// handed it has exited: while it is still running, pivoted into a tree
    /// built under here, its own mounts make the directory busy even from
    /// outside its mount namespace, because a mount point stays busy for as
    /// long as any process is still using it. Once the probe exits, the
    /// kernel tears its private mount namespace down and every mount in it
    /// goes with it, so the plain directories underneath come out clean.
    /// Every function in this file that runs a probe against a ScratchRoot
    /// already waits for it to exit before returning, so a plain `defer
    /// scratch.cleanup()`, set up right after `scratchRoot()` returns, always
    /// fires late enough.
    fn cleanup(self: *ScratchRoot) void {
        self.tmp.cleanup();
    }
};

fn scratchRoot() !ScratchRoot {
    var result = ScratchRoot{ .tmp = std.testing.tmpDir(.{}) };
    const resolved = try absoluteDirPath(&result.path_buffer, result.tmp.dir.handle);
    result.path_len = resolved.len;
    return result;
}

fn runProbe(op: []const u8) !std.process.Child.Term {
    return runProbeArgv(&.{ probe_path, op });
}

/// Same as `runProbe`, for an operation that builds a sandbox root and so needs
/// a scratch path from the caller, made with `scratchRoot`.
fn runProbeWithRoot(op: []const u8, root: []const u8) !std.process.Child.Term {
    return runProbeArgv(&.{ probe_path, op, root });
}

/// Same as `runProbe`, for an operation that needs one or more further
/// arguments on the command line, such as a scratch root this test built with
/// `scratchRoot`, or a host pid or a host shmid the test built outside every
/// namespace.
fn runProbeArgv(argv: []const []const u8) !std.process.Child.Term {
    var child = try std.process.spawn(std.testing.io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(std.testing.io);
    try skipIfNothingMeasured(term);
    return term;
}

/// The size of the file at `path`, or null if it cannot be read. Used to watch
/// a file a sandboxed process is still appending to, from outside every
/// namespace it runs in.
fn fileSize(path: [:0]const u8) ?u64 {
    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, path, 0, .{ .SIZE = true }, &stx);
    if (linux.errno(rc) != .SUCCESS) return null;
    return stx.size;
}

/// What runReportPid reads back from the probe: its exit status, and whatever it
/// printed to standard output before it exited.
const ReportPidResult = struct {
    term: std.process.Child.Term,
    buffer: [16]u8 = undefined,
    len: usize = 0,

    fn text(self: *const ReportPidResult) []const u8 {
        return self.buffer[0..self.len];
    }
};

/// Run the probe's "spawn-report-pid" operation and read back the pid line it prints
/// on its own standard output, through the pipe this spawns the probe with.
fn runReportPid(root: []const u8) !ReportPidResult {
    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ probe_path, "spawn-report-pid", root },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });

    var result = ReportPidResult{ .term = undefined };
    const handle = child.stdout.?.handle;
    while (result.len < result.buffer.len) {
        const rc = linux.read(handle, result.buffer[result.len..].ptr, result.buffer.len - result.len);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break; // EOF or a read fault ends the loop either way.
        result.len += rc;
    }

    result.term = try child.wait(std.testing.io);
    try skipIfNothingMeasured(result.term);
    return result;
}

/// What `runProbeCapturing` read back: the probe's exit status, and the whole
/// of what it wrote on each of its own two output descriptors.
const CaptureResult = struct {
    term: std.process.Child.Term,
    out_buffer: [512]u8 = undefined,
    out_len: usize = 0,
    err_buffer: [512]u8 = undefined,
    err_len: usize = 0,

    fn out(self: *const CaptureResult) []const u8 {
        return self.out_buffer[0..self.out_len];
    }

    fn err(self: *const CaptureResult) []const u8 {
        return self.err_buffer[0..self.err_len];
    }
};

/// Read `handle` until end of file, into `buffer`, and answer how much arrived.
fn readPipeToEnd(handle: linux.fd_t, buffer: []u8) usize {
    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(handle, buffer[filled..].ptr, buffer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break; // End of file or a read fault, either way nothing more comes.
        filled += rc;
    }
    return filled;
}

/// Run the probe with a pipe on each of its output descriptors, and read both
/// to end of file.
///
/// **Both, and never only the one a test is about.** A test that reads one
/// descriptor can say what arrived there and can never say that nothing arrived
/// anywhere else, which is exactly half of what the two setup fault tests below
/// have to prove.
///
/// Standard output is drained first and standard error second. Neither
/// operation writes more than one short line to either, far below the pipe
/// buffer the kernel gives a pipe, so no writer can be blocked while this reads
/// the other descriptor.
fn runProbeCapturing(argv: []const []const u8) !CaptureResult {
    var child = try std.process.spawn(std.testing.io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });

    var result = CaptureResult{ .term = undefined };
    result.out_len = readPipeToEnd(child.stdout.?.handle, &result.out_buffer);
    result.err_len = readPipeToEnd(child.stderr.?.handle, &result.err_buffer);
    result.term = try child.wait(std.testing.io);
    try skipIfNothingMeasured(result.term);
    return result;
}

/// The whole line a sandbox that cannot build its mount tree writes. The path
/// the two tests below hand `spawn` was never made, so the mount of the new
/// root answers `ENOENT`, and both the call and the errno are in the line.
const mount_setup_fault_line = "sandbox: the mount call failed: NOENT\n";

/// Signal 0 sends nothing. The kernel only checks that a process under `pid` exists
/// and is reachable, so this is a liveness check with no side effect of its own.
fn processIsAlive(pid: linux.pid_t) bool {
    const rc = linux.kill(pid, @enumFromInt(0));
    return linux.errno(rc) == .SUCCESS;
}

/// The content written into the segment createHostShmSegment builds, the same shape
/// of secret the real attack this proves closed read out of a host segment.
const shm_secret = "SHARED-MEMORY-SECRET-FROM-HOST";

/// Build a System V shared memory segment on the host, outside every namespace, with
/// a marker written into it. The caller must remove it with removeHostShmSegment, in
/// a defer set up before this can fail, so a segment is never left behind by a test
/// that fails partway through.
fn createHostShmSegment() !usize {
    const ipc_private: usize = 0;
    const ipc_creat: usize = 0o1000;
    const size: usize = 4096;
    const shmid = linux.syscall3(.shmget, ipc_private, size, ipc_creat | 0o600);
    if (linux.errno(shmid) != .SUCCESS) return error.ShmgetFailed;

    const addr_rc = linux.syscall3(.shmat, shmid, 0, 0);
    if (linux.errno(addr_rc) != .SUCCESS) return error.ShmatFailed;
    const addr: [*]u8 = @ptrFromInt(addr_rc);
    @memcpy(addr[0..shm_secret.len], shm_secret);
    _ = linux.syscall1(.shmdt, addr_rc);

    return shmid;
}

/// Mark the segment for removal. The kernel destroys a segment with IPC_RMID the
/// moment nothing is attached to it, which is already true here since
/// createHostShmSegment detaches right after writing the marker.
fn removeHostShmSegment(shmid: usize) void {
    const ipc_rmid: usize = 0;
    _ = linux.syscall3(.shmctl, shmid, ipc_rmid, 0);
}

/// The payload written into the key createHostSessionKey plants, the same shape of
/// secret the real attack in Finding 1 read out of a host session keyring.
const session_key_payload = "chock-escape-session-key-payload";

/// Plant a key in this process's own session keyring: the one a child inherits
/// across fork, before Finding 1's join in applyLayers ever runs. `description`
/// must be unique per test run, so two suites running at once never collide over
/// the same key. Returns the key's serial number, so the caller can remove it
/// again with removeHostSessionKey, in a defer set up before this can fail.
fn createHostSessionKey(description: [:0]const u8) !i32 {
    const key_type = "user";
    // KEY_SPEC_SESSION_KEYRING. Negative special values like this one are how the
    // keyring syscalls name "the current session's keyring" without first having to
    // look up its real serial number.
    const key_spec_session_keyring: usize = @bitCast(@as(isize, -3));
    const rc = linux.syscall5(
        .add_key,
        @intFromPtr(key_type.ptr),
        @intFromPtr(description.ptr),
        @intFromPtr(session_key_payload.ptr),
        session_key_payload.len,
        key_spec_session_keyring,
    );
    if (linux.errno(rc) != .SUCCESS) return error.AddKeyFailed;
    return @intCast(rc);
}

/// Remove the key createHostSessionKey planted. KEYCTL_INVALIDATE, operation 21,
/// marks a key invalid and schedules it for immediate removal, so a failing test
/// never leaves key material sitting in the session keyring of whoever runs the
/// suite.
fn removeHostSessionKey(key_id: i32) void {
    const keyctl_invalidate: usize = 21;
    _ = linux.syscall2(.keyctl, keyctl_invalidate, @as(usize, @bitCast(@as(isize, key_id))));
}

test "a filtered process that calls ptrace dies with SIGSYS" {
    const term = try runProbe("ptrace");
    // One comparison and not a switch: `expectEqual` prints both sides, so a
    // process that ended some other way says how in the failure itself, and
    // this test writes nothing to standard error.
    try std.testing.expectEqual(std.process.Child.Term{ .signal = std.posix.SIG.SYS }, term);
}

test "a filtered process that calls umount2 dies with SIGSYS" {
    const term = try runProbe("umount-protected");
    // One comparison and not a switch: `expectEqual` prints both sides, so a
    // process that ended some other way says how in the failure itself, and
    // this test writes nothing to standard error.
    try std.testing.expectEqual(std.process.Child.Term{ .signal = std.posix.SIG.SYS }, term);
}

test "a filtered process that calls open_tree_attr dies with SIGSYS" {
    // open_tree_attr can undo the read only bind mount that protects chock.zon the
    // same way mount_setattr can, so the filter must kill it too. See the comment
    // above open-tree-attr-protected in probe.zig for the full attack.
    const term = try runProbe("open-tree-attr-protected");
    // One comparison and not a switch: `expectEqual` prints both sides, so a
    // process that ended some other way says how in the failure itself, and
    // this test writes nothing to standard error.
    try std.testing.expectEqual(std.process.Child.Term{ .signal = std.posix.SIG.SYS }, term);
}

test "a filtered process that calls userfaultfd dies with SIGSYS" {
    const term = try runProbe("userfaultfd");
    switch (term) {
        .signal => |sig| try std.testing.expectEqual(std.posix.SIG.SYS, sig),
        else => return error.TestUnexpectedResult,
    }
}

test "a filtered process that calls add_key dies with SIGSYS" {
    // The session keyring crosses the sandbox boundary in both directions unless
    // this call is refused: a key added here would still land in whichever session
    // keyring this process has, host or otherwise. The filter must kill the call
    // outright, with no dependence on which keyring is current.
    const term = try runProbe("add-key");
    // One comparison and not a switch: `expectEqual` prints both sides, so a
    // process that ended some other way says how in the failure itself, and
    // this test writes nothing to standard error.
    try std.testing.expectEqual(std.process.Child.Term{ .signal = std.posix.SIG.SYS }, term);
}

test "a filtered process that calls io_uring_setup is refused with EPERM and lives" {
    // Finding 3. A ring is the way around a syscall filter, because the thread that
    // submits an operation never makes the call the filter reads. The measured run
    // set up a ring and was stopped by Landlock and by the network namespace, not by
    // this filter, and neither of those covers every operation a ring can carry. See
    // `refused_calls` in lib/chock-sandbox/linux/seccomp.zig.
    //
    // **EPERM and no ring is the same refusal the kill was.** What changed is that
    // the caller is told. Node's libuv probes for a ring six times before it runs one
    // line, whatever `UV_USE_IO_URING` says, so a kill ended every Node program at
    // startup while buying nothing: a hostile program can simply not call io_uring.
    //
    // Exit status 1 is the probe's own word for "refused with EPERM", and it is not
    // "the call failed": the probe reads the errno, because two of the three calls
    // here would fail with EBADF under no filter at all. See `ringRefusal`.
    const term = try runProbe("io-uring-setup");
    // One comparison and not a switch: `expectEqual` prints both sides, so a
    // process that ended some other way says how in the failure itself, and
    // this test writes nothing to standard error.
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a filtered process that calls io_uring_enter is refused with EPERM and lives" {
    // The call that submits the operations. Refusing only the setup would leave a
    // ring another process made and handed over still usable.
    const term = try runProbe("io-uring-enter");
    // One comparison and not a switch: `expectEqual` prints both sides, so a
    // process that ended some other way says how in the failure itself, and
    // this test writes nothing to standard error.
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a filtered process that calls io_uring_register is refused with EPERM and lives" {
    // The call that gives a ring its buffers, its files, and its eventfd. Refused
    // for the same reason as io_uring_enter above, and with no ring here either.
    const term = try runProbe("io-uring-register");
    // One comparison and not a switch: `expectEqual` prints both sides, so a
    // process that ended some other way says how in the failure itself, and
    // this test writes nothing to standard error.
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a program that meets the io_uring refusal carries on and exits cleanly" {
    // **This is the whole reason the answer changed, and neither test above can
    // state it.** Each of those ends at the refusal, so each would still pass under
    // a filter that killed on the very next instruction. This one does ordinary work
    // after the refused probe and exits 0, which a killed process cannot do.
    const term = try runProbe("io-uring-then-work");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "the calls that are meant to kill still kill, so the io_uring change did not leak" {
    // **The other thirty were left alone on purpose**, and this is what says so.
    // Each of them is on `blocked_calls` for a reason of its own, and none of them is
    // probed and answered the way io_uring is, so moving one would need its own
    // measurement. A change that moved the whole list to EPERM would still pass every
    // io_uring test above, and it fails here.
    //
    // One operation per family the list covers, run through a real spawn: the mount
    // family, the keyring family, and process introspection are each represented by a
    // probe that already exists.
    for ([_][]const u8{
        "ptrace",
        "umount-protected",
        "open-tree-attr-protected",
        "add-key",
    }) |op| {
        const term = try runProbe(op);
        try std.testing.expectEqual(std.process.Child.Term{ .signal = std.posix.SIG.SYS }, term);
    }
}

test "the filter is not a deny all, an ordinary call still works" {
    const term = try runProbe("getpid");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "mmap refuses a request for write and execute together" {
    // This pins one narrow fact: mmap itself refuses prot = PROT_WRITE | PROT_EXEC.
    // It does not prove a process can never end up with a page that is both
    // writable and executable. See the comment on the write and execute rule in
    // seccomp.zig for three ways an attacker got such a page anyway.
    const term = try runProbe("mmap-wx");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a project that asked for a just in time compiler gets the page, and keeps every other rule" {
    // **The one setting on the policy table that widens**, measured through a
    // real spawn rather than through the shape of the filter. See
    // `lib/chock-policy/hardening.zig` for why it is a row on the table and not
    // a key in `chock.zon`, and `src/doctor.zig` and
    // `chock_proto.event.SandboxOpen` for the two places that say a session ran
    // this way.
    //
    // The default is the test above this one: `mmap-wx` gets EPERM. Here the
    // same call succeeds.
    const relaxed = try runProbe("mmap-wx-relaxed");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, relaxed);

    // **And nothing else moved.** A mistake that dropped the whole filter when
    // a project asked for this would pass the line above and fail here. `ptrace`
    // still kills, and io_uring is still refused with EPERM, under the very same
    // relaxed filter.
    const killed = try runProbe("ptrace-relaxed");
    try std.testing.expectEqual(std.process.Child.Term{ .signal = std.posix.SIG.SYS }, killed);
    const ring = try runProbe("io-uring-setup-relaxed");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, ring);
}

test "a two step change from read write to read execute succeeds" {
    const term = try runProbe("mmap-then-exec");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "pkey_mprotect refuses a request for write and execute together" {
    // Same narrow claim as the mmap test above, pinned for pkey_mprotect instead.
    const term = try runProbe("pkey-wx");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "personality(READ_IMPLIES_EXEC) cannot be used to pass around the rule" {
    const term = try runProbe("personality-rwx");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "reading the current personality still works" {
    const term = try runProbe("personality-read");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "shmat with SHM_EXEC is refused" {
    // shmat has no prot argument, so the write and execute rule cannot see this
    // request at all. This is the attack that rule cannot stop, closed instead by
    // a rule that reads shmat's own shmflg argument.
    const term = try runProbe("shmat-exec");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "shmat with no SHM_EXEC still works" {
    // The rule above must refuse only SHM_EXEC, not shmat itself.
    const term = try runProbe("shmat-plain");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a process in a network namespace cannot connect to a remote host" {
    const term = try runProbe("netns-connect");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a network namespace still permits a unix socket" {
    const term = try runProbe("netns-loopback");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a process in the mount tree cannot read the home directory, with ENOENT" {
    // Exit 1 from this probe means the open failed with the exact errno the
    // design predicts, ENOENT, not merely that it failed for some reason. Exit 5
    // would mean the refusal happened for the wrong reason. See the exit code
    // table at the top of probe.zig.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("read-home", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a read only bind mount refuses a write, with EROFS" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("write-readonly", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a submount under a read only target also refuses a write, with EROFS" {
    // A remount is never recursive, whatever flags it carries. mount_setattr
    // with AT_RECURSIVE is what makes a read only mark reach a tmpfs mounted
    // under a directory before that directory was marked read only. Without it,
    // this probe's write into the submount would succeed.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("write-readonly-submount", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a file with a bind mount over it cannot be deleted, with EBUSY" {
    // This is how chock.zon is protected. Landlock cannot do it, because a delete needs
    // write permission on the parent directory and the project root must stay writable.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("delete-mounted-file", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a file bound onto a target that did not exist yet carries the source's content" {
    // chock.zon is protected by binding a file over a file. buildRoot used to
    // create every mount target as a directory, which fails a file bind with
    // ENOTDIR unless source and target happen to already be the same path. This
    // probe uses a target that starts out missing, the shape a real project hits.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("file-bind-content", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a deny_read entry that is a symlink cannot bind the notice onto its target" {
    // `.env` inside the project points at a file here instead: a directory
    // this test made with its own scratchRoot, no relation to the sandbox
    // root at all and never named in any mount this probe builds. See
    // `deny.zig`'s own top comment: `deny_read` is the one project supplied
    // path in the whole mount tree, and a repository can hold a symlink.
    var outside = try scratchRoot();
    defer outside.cleanup();

    var scratch = try scratchRoot();
    defer scratch.cleanup();

    const term = try runProbeArgv(&.{ probe_path, "deny-symlink-outside", scratch.path(), outside.path() });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a tool call inside the sandbox cannot reach the session's approval socket" {
    // See `lib/chock-broker/socket.zig`: **anything that can reach that
    // socket can approve an action**, so a tool call must not be able to. The
    // credential store is the precedent, never mounted and never reachable, and this is the same claim
    // for the channel that answers approvals.
    //
    // The socket here is a real listening one, in a directory outside the
    // sandbox root, and **this test connects to it itself first**. Without that
    // step the whole thing would pass against a socket that was never made, and
    // would prove that a path which does not exist cannot be reached, which is
    // not a fact about the sandbox at all.
    var scratch = try scratchRoot();
    defer scratch.cleanup();

    // A directory of its own beside the root, so the socket is not carried in
    // by the recursive bind of `root` the way `spawned-landlock-read`'s marker
    // deliberately is.
    var session = try scratchRoot();
    defer session.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket_path = try std.fmt.bufPrint(&path_buffer, "{s}/s", .{session.path()});

    const address = try std.Io.net.UnixAddress.init(socket_path);
    var server = try address.listen(std.testing.io, .{ .kernel_backlog = 2 });
    defer server.deinit(std.testing.io);

    // The host reaches it. Everything below is therefore about the sandbox and
    // not about a missing file.
    {
        const reached = try address.connect(std.testing.io);
        reached.close(std.testing.io);
    }

    // Exit 1 means the connect failed with ENOENT specifically, which is what
    // a path that is not in this mount tree gives. Exit 0 would mean the tool
    // call reached the socket. See the exit code table at the top of probe.zig.
    const term = try runProbeArgv(&.{ probe_path, "spawn-approval-socket", scratch.path(), socket_path });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a Landlock rule refuses a write outside the workspace" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("landlock-write-outside", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a Landlock rule permits a write inside the workspace" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("landlock-write-inside", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a Landlock rule refuses a truncate outside the workspace" {
    // A reviewer proved this on a live kernel: with truncate left unhandled,
    // truncate("/other/secret", 0) succeeded and emptied a file Landlock was
    // supposed to protect, even though open() for read and for write on that
    // same file was correctly refused. This pins the fix: truncate must now
    // be refused the same way a write is.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("landlock-truncate-outside", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a Landlock rule permits a truncate inside the workspace" {
    // Truncate is granted inside the permitted directory, so an ordinary shell
    // redirect or editor save must keep working there.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("landlock-truncate-inside", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "spawn applies every layer, and a spawned process cannot call ptrace" {
    // This proves Sandbox.spawn's own seccomp filter, not a filter the spawned
    // program installed on itself. The spawned-ptrace probe does no setup of its
    // own, so only spawn's applyLayers can be the thing that kills it here.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-ptrace", scratch.path());
    switch (term) {
        .signal => |sig| try std.testing.expectEqual(std.posix.SIG.SYS, sig),
        else => return error.TestUnexpectedResult,
    }
}

test "spawn applies every layer, and a spawned process cannot read outside its rules" {
    // Same shape as the ptrace test above, for Landlock instead of seccomp. The
    // spawned-landlock-read probe does no setup of its own, so only the ruleset
    // spawn's applyLayers built can be the thing that refuses the read.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-landlock-escape", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "spawn applies every layer, and a spawned process cannot connect to a remote host" {
    // Same shape again, for the network namespace. The spawned-connect probe
    // does no setup of its own, so only the network namespace spawn's
    // applyLayers entered can be the thing that refuses the connect. This
    // Config also leaves `.network` unset, so it pins Finding 2's default: a
    // caller that says nothing about the network still gets `none`, not `host`.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-network-escape", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a filtered process still cannot open a connection of its own" {
    // The first half of what `filtered` means. The process is handed a
    // channel, and it must still have no way to make one.
    //
    // **The errno is the test, not the failure.** A filtered process is in the
    // same empty network namespace a `none` one gets, so a `connect` there
    // answers `ENETUNREACH` with no filter at all. The probe reports exit 1
    // only for `EPERM`, which is the seccomp rule, and exit 5 for any other
    // errno.
    //
    // Mutation check: delete `block_connect` from the driver's own
    // `seccomp_options` and the connect answers `ENETUNREACH`, so the probe
    // exits 5 and this fails.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-filtered-connect", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a filtered process can use the descriptor it is handed, and cannot aim it anywhere else" {
    // The other half, and the one that needed a measurement to get right. A
    // granted descriptor is a real connected socket, made on the far side of
    // the boundary, so it belongs to **that** side's network namespace and the
    // sandbox's own empty one says nothing about where it can reach.
    //
    // Measured on 2026-08-23, on Linux 6.18.42: a plain re-connect on a
    // connected TCP socket answers `EISCONN`, and a `connect` with `AF_UNSPEC`
    // followed by a `connect` elsewhere **both succeed**. So a granted
    // descriptor really can be aimed at another host, and refusing `connect`
    // for a filtered process is what closes it.
    //
    // Three facts, and the third is the one an exit code could not carry:
    //
    //  * the descriptor works, proved by a token the sandboxed process wrote
    //    into it arriving on the listener the broker really dialled;
    //  * the re-aim is refused with `EPERM`, which the probe reports as exit 0
    //    and reports anything else as exit 1 or 5;
    //  * the second listener, which the policy never permitted and the broker
    //    never dialled, has nothing in its backlog.
    //
    // Mutation check: delete `block_connect` and the re-aim succeeds, the
    // probe exits 1, and the second listener's backlog is no longer empty.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-filtered-grant", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a refused host is refused, and the sandboxed process learns nothing from the refusal" {
    // What a sandboxed process may find out by asking, which is nothing at
    // all. The probe asks for a host the table does not cover and then for one
    // it does, on the same socket, and requires:
    //
    //  * the first to be refused and the second to be granted, so this is not
    //    a broker that refuses everything;
    //  * the refusal to carry no descriptor, checked against the child's own
    //    `/proc/self/fd` before and after rather than against the reply alone;
    //  * **the refused host never to be resolved**, which the probe reads off
    //    the transport's own lookup count. A DNS query is a message to whoever
    //    runs that zone, so a broker that resolved first and refused second
    //    would hand a sandboxed process a channel out for any name it liked.
    //
    // Mutation check: move the policy read below the lookup in
    // `Network.answer` and the lookup count is two, so the probe exits 5.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-filtered-refused", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a subagent cannot reach a host its parent could not" {
    // The one question the network broker answers.
    // Both runs use the same policy source and ask for the same host on the
    // same port. The only difference is the spawn chain: one is the root, and
    // one is a subagent under a parent kind the policy refuses.
    //
    // **The first run is what stops the second being vacuous.** The table
    // really does say `allow` for the `fetcher` kind, so a `fetcher` that runs
    // as a root reaches the host. Under `main` it does not, and the only thing
    // that can have refused it is the intersection `evaluateChain` takes over
    // the chain.
    //
    // Mutation check: swap `evaluateChain` for `evaluateKindAlone` in
    // `Network.answer` and the second run grants, so it exits 0 and this
    // fails.
    var root_scratch = try scratchRoot();
    defer root_scratch.cleanup();
    const as_root = try runProbeWithRoot("spawn-filtered-chain-root", root_scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, as_root);

    var child_scratch = try scratchRoot();
    defer child_scratch.cleanup();
    const as_subagent = try runProbeWithRoot("spawn-filtered-chain-subagent", child_scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, as_subagent);
}

test "the channel stops at its own budget, and asking after it stops is a plain refusal" {
    // The far end answers `net_broker.max_requests` and then closes its end,
    // so a sandboxed process cannot make it work without bound: every ask
    // costs a policy read, and a permitted one costs a name lookup and a
    // connect besides. The probe asks two times too many and requires the
    // budget to be spent at exactly that number.
    //
    // **And an ask past the end must answer, not hang and not kill.** The two
    // extra asks are what says so: a channel that left the asker blocked would
    // hold a program inside a sandbox until the whole call's deadline, and one
    // that killed the asker would end a tool call with a bare signal number.
    // Both come back as `BrokerGone`, which is a refusal a program can act on.
    //
    // Mutation check: raise `max_requests` in the driver's own loop and the
    // ask past the budget is answered, so the probe exits 5. Lower it and the
    // far end goes at a different number, so the probe exits 5 again.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-filtered-budget", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a permitted name that resolves onto this machine reaches nothing" {
    // Whoever runs a permitted zone decides what its names answer, so a rule
    // about a host on the internet must not become a handle on the loopback
    // interface or on the cloud metadata service beside it. The policy here
    // permits the host outright and the name resolves to `127.0.0.1`.
    //
    // The probe requires that the name **was** resolved, because the policy
    // permitted it, and that nothing was dialled. That is what says the
    // address check is the thing that refused it, and that the check really
    // runs inside a spawn rather than only in a unit test.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-filtered-loopback", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "spawn gives the sandboxed process /dev/null on standard input, never a terminal" {
    // The sandboxed program must have no terminal, so a password prompt fails
    // fast instead of hanging on a read nobody can answer. It is also an injection channel closed: a descriptor left open on
    // the caller's controlling terminal would let ioctl(0, TIOCSTI) push
    // characters into that terminal's own input queue, and no Landlock rule
    // covers a descriptor that was already open before the sandbox existed.
    // spawned-stdin-devnull does no setup of its own, so this is entirely a fact
    // about what spawn's own child put on descriptor 0 before applyLayers ran.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-stdin-devnull", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a named stdin descriptor reaches the program as a pipe, and widens nothing else" {
    // `Config.stdin_fd` is the one field that changes what descriptor 0 is,
    // and descriptor 0 is where `/dev/null` goes, for two security reasons. So this test asks the two questions that decide
    // whether the field is safe, and not only whether it works:
    //
    // * **Does the caller's pipe really arrive?** Descriptor 0 must be a pipe,
    //   carrying exactly the bytes the caller wrote, and it must reach end of
    //   file when the caller is finished. A helper that cannot be told it is
    //   finished is a helper that never exits.
    // * **Does it widen anything else?** The caller leaves a directory
    //   descriptor on the host root open across the spawn, which is the leak
    //   `closeInheritedFds` exists to revoke, and it must still be gone. And
    //   descriptor 0 must not be a terminal, which is the injection route the
    //   `/dev/null` redirect closed in the first place.
    //
    // spawned-stdin-pipe does no setup of its own, so every one of those is a
    // fact about what `spawn` put on that descriptor.
    //
    // Mutation check: drop the `dup2` in `redirectStandardStreams` and
    // descriptor 0 stays a character device. Skip `closeInheritedFds` when
    // `stdin_fd` is set and the host root descriptor survives. Leave A's own
    // copy of the read end open after the second fork and the end of file
    // check never returns.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-stdin-pipe", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a setup failure is written to the descriptor the caller named, and not to descriptor 2" {
    // `Config.stderr_fd` says where a sandboxed program's own diagnostics go.
    // It used to be obeyed only from `execve` onwards, because the setup
    // failure paths in `linux/driver.zig` wrote to descriptor 2 by number, so a
    // caller could not ask for a quiet failure of the sandbox itself: two tests
    // in `lib/chock-core` build a sandbox that cannot exist and put two lines
    // in every build log because of it.
    //
    // **Both halves are checked, and either one alone would pass with the fault
    // still there.** A run that copied the line to both descriptors would
    // satisfy the first check, and a run that wrote nothing at all would
    // satisfy the second.
    //
    // The whole line is compared and not a fragment of it, so this also pins
    // what the line says: the call the kernel refused, and its errno. Neither
    // reaches a caller any other way for a failure this early.
    //
    // Mutation check: put `std.posix.STDERR_FILENO` back in `writeStderr` and
    // the named descriptor reads empty while descriptor 2 carries the line.
    // Hand `printFault` the error instead of the diagnostic in `dieNamespace` and
    // the line loses both the call and the errno.
    var scratch = try scratchRoot();
    defer scratch.cleanup();

    const result = try runProbeCapturing(
        &.{ probe_path, "spawn-setup-fault-named-stderr", scratch.path() },
    );
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try std.testing.expectEqualStrings(mount_setup_fault_line, result.out());
    try std.testing.expectEqualStrings("", result.err());
}

test "a setup failure with no descriptor named still lands on descriptor 2" {
    // The other half of the field's contract, and the one every caller in this
    // project relies on today: a caller that names nothing gets exactly the
    // behaviour `spawn` always had, which is the reason on its own standard
    // error. The default is `std.posix.STDERR_FILENO`, so nothing about the
    // threading above may change where this line goes.
    //
    // Mutation check: give `Config.stderr_fd` any other default, or hand
    // `applyLayers` a descriptor of its own choosing, and descriptor 2 reads
    // empty here.
    var scratch = try scratchRoot();
    defer scratch.cleanup();

    const result = try runProbeCapturing(
        &.{ probe_path, "spawn-setup-fault-default-stderr", scratch.path() },
    );
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try std.testing.expectEqualStrings(mount_setup_fault_line, result.err());
    try std.testing.expectEqualStrings("", result.out());
}

test "a setup failure still reaches spawn when the descriptor the caller named cannot be written" {
    // The hazard that comes with letting a caller choose the descriptor: a pipe
    // whose read end is closed answers `EPIPE` and raises `SIGPIPE`, and the
    // default action for that signal ends the process that was writing the
    // reason. `spawn` must still answer `error.ScratchMountFailed`, which it
    // can only do if the record reached the setup pipe before the text was
    // tried.
    //
    // **The wrong answer here is not a lost line, it is a wrong outcome.** End
    // of file with no data on the setup pipe is exactly how a successful
    // `execve` reports itself, so a caller would be told the program ran and
    // died from a signal, for a program that never started.
    //
    // The probe asks for more scratch areas than the driver allows, because
    // that step runs in the process `spawn` forks first and not in the
    // sandboxed process: see the probe's own comment for why a failure in the
    // sandboxed process proves nothing here.
    //
    // Mutation check: put the text back in front of the record in `dieErrno`
    // and this test reads a `Term` instead of the error, while the two tests
    // above still pass.
    var scratch = try scratchRoot();
    defer scratch.cleanup();

    const term = try runProbeWithRoot("spawn-setup-fault-closed-stderr", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "the global files of /proc that describe the host read empty" {
    // Measured on 2026-08-21, before this mask existed: /proc/cmdline gave
    // "lsm=landlock,yama,bpf", the system store path and the host name, which
    // hands a reader the list of enforcement mechanisms to work around;
    // /proc/version gave the kernel version; /proc/kallsyms gave every symbol
    // name; /proc/config.gz gave the kernel configuration.
    //
    // **This is a reduced surface and not a boundary.** See
    // `namespace.masked_proc_entries`: it is a list of names, and the next
    // kernel adds a file nobody masked. What refuses an attack is the rest of
    // the capability layers, and every other test in this file.
    //
    // The probe reads every name on that list, not one of them, and it fails
    // if fewer than three of them existed to read.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-proc-mask", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "the mask leaves /proc/self/exe working, and leaves the rest of /proc real" {
    // The pair that can break each other, and the reason this test sits beside
    // the one above. /proc is mounted so that a toolchain can find its own
    // installation: a mask that reached /proc/self brings back "unable to find
    // zig self exe path", and no compiler runs in the sandbox at all. A procfs
    // that went missing, or an empty thing mounted over the whole of it, would
    // instead make every read in the test above give zero bytes and pass for
    // the wrong reason. The probe pins both: /proc/self/exe resolves to the
    // path it was execed as, and /proc/uptime, which no mask names, still
    // holds bytes.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-proc-live", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a process cannot signal a process outside the sandbox, and does not kill it" {
    // A signal to some unused pid number would return ESRCH with or without a pid
    // namespace, and would prove nothing. So this builds a real target first: a
    // victim process on the host, outside every namespace, verified alive both
    // before and after the sandboxed process tries to reach it. This is the
    // attack from the design review: kill(host victim, SIGKILL) succeeded and took
    // down a process on the host from inside what was supposed to be a sandbox.
    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const victim_pid: linux.pid_t = @intCast(fork_rc);

    if (victim_pid == 0) {
        // The victim. It does nothing but wait to be signaled, either by the probe,
        // which must not be able to reach it, or by this test's own cleanup below.
        while (true) _ = linux.pause();
    }

    defer {
        // Runs even if an assertion below fails, so a broken build never leaves this
        // victim running past the end of the test.
        _ = linux.kill(victim_pid, .KILL);
        var reap_status: u32 = undefined;
        _ = linux.waitpid(victim_pid, &reap_status, 0);
    }

    var pid_buffer: [16]u8 = undefined;
    const pid_arg = try std.fmt.bufPrint(&pid_buffer, "{d}", .{victim_pid});

    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeArgv(&.{ probe_path, "spawn-signal-host", scratch.path(), pid_arg });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);

    // The direct proof: this is the same victim pid checked alive on the host before
    // the probe ever ran, and it is still alive now. A signal that had actually
    // reached it would show up here as a dead process, not as a refused syscall.
    try std.testing.expect(processIsAlive(victim_pid));
}

test "a process cannot attach to a System V shared memory segment made outside the sandbox" {
    // Same shape as the signal test above: the segment has to be real, made by the
    // parent outside every namespace, or a refusal proves nothing. This is the other
    // half of the design review's escape: shmat into a host segment succeeded, and
    // the sandboxed process both read the host's secret out of it and wrote back in.
    const shmid = try createHostShmSegment();
    // Removed even if an assertion below fails, so a broken build never leaves a
    // segment behind. `ipcs -m` should show none of this test's segments afterward.
    defer removeHostShmSegment(shmid);

    var shmid_buffer: [16]u8 = undefined;
    const shmid_arg = try std.fmt.bufPrint(&shmid_buffer, "{d}", .{shmid});

    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeArgv(&.{ probe_path, "spawn-shm-attach", scratch.path(), shmid_arg });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "the session keyring join gives the sandbox a keyring the host cannot see into" {
    // This is the channel the attacker found: a key added on the host, or found by
    // some other host process, was still readable by a process the sandbox was
    // supposed to contain, because CLONE_NEWUSER covers the user keyring but not
    // the session keyring. Plant a real key in this test process's own session
    // keyring first, the same one a child inherits across fork, or a refusal to
    // find it proves nothing.
    var desc_buffer: [64]u8 = undefined;
    const description = try std.fmt.bufPrintZ(&desc_buffer, "chock-escape-session-key-{d}", .{linux.getpid()});

    const key_id = try createHostSessionKey(description);
    // Removed even if an assertion below fails, so a broken build never leaves
    // this key behind in the session keyring of whoever runs the suite.
    defer removeHostSessionKey(key_id);

    const term = try runProbeArgv(&.{ probe_path, "session-keyring-fresh", description });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "the sandboxed process sees a fresh process id space, not the host's" {
    // The grandchild Sandbox.spawn runs the caller's program in is the first process
    // the kernel ever creates in the new namespace, so it is pid 1 there. A host pid
    // is never that small; this very test process is already a much larger number by
    // the time the suite reaches this line. Pid 1 outside a container is normally
    // init, a process this test must never be able to name or affect, so a small
    // number here is a fresh space, not a lucky host pid.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const result = try runReportPid(scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const text = std.mem.trimEnd(u8, result.text(), "\n");
    const pid = try std.fmt.parseInt(u32, text, 10);
    try std.testing.expectEqual(@as(u32, 1), pid);
}

test "Finding 1: a forged exit code from the old setup-failure range is relayed untouched, and the file it wrote survives" {
    // The attack from the design review: the sandboxed program does real work,
    // writes a file, then exits with 111, the value the old design used for
    // namespace_failed. A parent that still trusted that range would believe
    // the sandbox never came up and delete this whole root, output included.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-forge-exit", scratch.path());

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const output_path = try std.fmt.bufPrintZ(&path_buffer, "{s}/work/output.txt", .{scratch.path()});

    // The direct proof: the file is still there. If spawn had misread 111 as a
    // setup failure, it would have called removeContentsBestEffort on this same
    // root and taken this file down with everything else under it.
    try std.testing.expect(fileSize(output_path) != null);

    // The forged code must come back exactly as the program set it, not as
    // some SetupError spawn invented because it distrusted the range.
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 111 }, term);
}

test "Finding 2: signalling the process spawn forked also ends the sandboxed program" {
    // The attack from the design review: an attacker signalled the process
    // spawn forked, and the sandboxed program, reparented and still running,
    // kept appending to its own file forever. This drives spawn-signal-middle,
    // which prints the pid of the process spawn forked over standard output
    // while spawn is still blocked on the sandboxed program, exactly the pid a
    // real caller is meant to cancel by signalling, per spawn's own doc
    // comment.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ probe_path, "spawn-signal-middle", scratch.path() },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });

    var pid_line_buf: [16]u8 = undefined;
    var pid_line_len: usize = 0;
    const handle = child.stdout.?.handle;
    while (pid_line_len < pid_line_buf.len) {
        var byte: [1]u8 = undefined;
        const rc = linux.read(handle, &byte, 1);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        if (byte[0] == '\n') break;
        pid_line_buf[pid_line_len] = byte[0];
        pid_line_len += 1;
    }
    // **No pid line at all is an answer too.** The probe prints one only once
    // `spawn` has forked, so a machine that would not give it a sandbox prints
    // nothing and ends with `nothing_measured_exit_status`, and reading that
    // as a malformed number would report this mechanism as broken. See
    // `skipIfNothingMeasured`.
    if (pid_line_len == 0) {
        try skipIfNothingMeasured(try child.wait(std.testing.io));
        return error.TestUnexpectedResult;
    }
    const middle_pid = try std.fmt.parseInt(linux.pid_t, pid_line_buf[0..pid_line_len], 10);

    var heartbeat_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const heartbeat_path = try std.fmt.bufPrintZ(
        &heartbeat_path_buf,
        "{s}/work/heartbeat.txt",
        .{scratch.path()},
    );

    // Wait, bounded, for the sandboxed program's loop to actually start
    // growing the file, so the signal below cannot land before there is
    // anything running to kill. Two seconds is generous; this must never spin
    // forever if something is badly broken and the file never appears.
    var waited_ns: u64 = 0;
    var size_before_signal: u64 = 0;
    while (waited_ns < 2_000_000_000) : (waited_ns += 20_000_000) {
        _ = linux.nanosleep(&.{ .sec = 0, .nsec = 20_000_000 }, null);
        if (fileSize(heartbeat_path)) |size| {
            if (size > 0) {
                size_before_signal = size;
                break;
            }
        }
    }
    // **A file that never grew is an answer too.** `spawn` publishes the pid
    // of the process it forked before it builds any layer, so the pid line
    // above arrives even on a machine that then refuses the namespaces, and
    // the program inside never runs. The probe's own exit status is what tells
    // that apart from a real fault. See `skipIfNothingMeasured`.
    if (size_before_signal == 0) {
        try skipIfNothingMeasured(try child.wait(std.testing.io));
    }
    try std.testing.expect(size_before_signal > 0);

    // SIGTERM, an ordinary cancellation, not SIGKILL: process 1 of a pid
    // namespace ignores a plain SIGTERM sent to it directly, which is exactly
    // why this signals the middle process instead. See spawn's own doc
    // comment on middle_pid.
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.kill(middle_pid, .TERM)));

    // A bounded wait for the relay and the pid death signal to land, not a
    // fixed sleep guessed to be long enough and not a wait that can hang the
    // suite forever.
    const term = try child.wait(std.testing.io);
    // One comparison and not a switch: `expectEqual` prints both sides, so a
    // process that ended some other way says how in the failure itself, and
    // this test writes nothing to standard error.
    try std.testing.expectEqual(std.process.Child.Term{ .signal = std.posix.SIG.TERM }, term);

    // The direct proof: read the file's size well after the signal, twice,
    // one bounded wait apart. If the sandboxed program had survived as an
    // orphan, still appending every few milliseconds, these two reads would
    // differ. Equal reads is the file falling silent, which only happens once
    // the process producing it is truly gone.
    _ = linux.nanosleep(&.{ .sec = 0, .nsec = 200_000_000 }, null);
    const size_after_wait_one = fileSize(heartbeat_path) orelse size_before_signal;
    _ = linux.nanosleep(&.{ .sec = 0, .nsec = 200_000_000 }, null);
    const size_after_wait_two = fileSize(heartbeat_path) orelse size_after_wait_one;
    try std.testing.expectEqual(size_after_wait_one, size_after_wait_two);
}

test "a cancelled call takes the processes it started with it, not only the one that was signalled" {
    // **The claim the fix rests on, measured rather than reasoned.** Every
    // cancel in Chock used to signal a whole process group, with the negated
    // number, and that number is the fault this work removed: a pid that has
    // been reaped names nothing and may soon name somebody else. A handle has
    // no group form, so a cancel now reaches exactly one process, the one
    // `Sandbox.spawn` forked, and nothing else directly.
    //
    // That would be a leak if it stopped there. It does not, and two
    // mechanisms are why: the sandboxed program's own `PR_SET_PDEATHSIG` fires
    // when the signalled process dies, and the kernel then kills every other
    // process in the pid namespace whose process 1 has just died; and
    // `Cgroup.destroy` writes `cgroup.kill` on the way out of `spawn`. See
    // `Sandbox.spawn`'s own doc comment, which records both and says why
    // neither is decoration.
    //
    // The heartbeat here is written by a **grandchild** the sandboxed program
    // forked, never by the sandboxed program itself, so nothing about this
    // test can pass because the one signalled process happened to be the one
    // producing it. See the probe's own `spawned-fork-loop-write`.
    //
    // **This test pins the outcome and not one mechanism**, which is the
    // honest reading of the mutation check made on 2026-08-22: disarm
    // `armPdeathsig` alone and this still passes, because the cgroup kill
    // reaches the grandchild; drop the `cgroup.kill` write alone and it still
    // passes, because the pdeathsig chain does. Take both away and this test
    // and "Finding 2" above both fail on a heartbeat that went on growing,
    // which is the leak they exist to catch.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ probe_path, "spawn-signal-middle-forked", scratch.path() },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });

    var pid_line_buf: [16]u8 = undefined;
    var pid_line_len: usize = 0;
    const handle = child.stdout.?.handle;
    while (pid_line_len < pid_line_buf.len) {
        var byte: [1]u8 = undefined;
        const rc = linux.read(handle, &byte, 1);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        if (byte[0] == '\n') break;
        pid_line_buf[pid_line_len] = byte[0];
        pid_line_len += 1;
    }
    // **No pid line at all is an answer too.** The probe prints one only once
    // `spawn` has forked, so a machine that would not give it a sandbox prints
    // nothing and ends with `nothing_measured_exit_status`, and reading that
    // as a malformed number would report this mechanism as broken. See
    // `skipIfNothingMeasured`.
    if (pid_line_len == 0) {
        try skipIfNothingMeasured(try child.wait(std.testing.io));
        return error.TestUnexpectedResult;
    }
    const middle_pid = try std.fmt.parseInt(linux.pid_t, pid_line_buf[0..pid_line_len], 10);

    var forked_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const forked_path = try std.fmt.bufPrintZ(
        &forked_path_buf,
        "{s}/work/forked.txt",
        .{scratch.path()},
    );
    var heartbeat_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const heartbeat_path = try std.fmt.bufPrintZ(
        &heartbeat_path_buf,
        "{s}/work/heartbeat.txt",
        .{scratch.path()},
    );

    // Bounded, never a fixed sleep guessed to be long enough, and never a
    // spin that could hang the suite if something is badly broken.
    var waited_ns: u64 = 0;
    var size_before_signal: u64 = 0;
    while (waited_ns < 5_000_000_000) : (waited_ns += 20_000_000) {
        _ = linux.nanosleep(&.{ .sec = 0, .nsec = 20_000_000 }, null);
        if (fileSize(heartbeat_path)) |size| {
            if (size > 0) {
                size_before_signal = size;
                break;
            }
        }
    }
    // The grandchild is really running and really producing the file.
    // **A file that never grew is an answer too.** `spawn` publishes the pid
    // of the process it forked before it builds any layer, so the pid line
    // above arrives even on a machine that then refuses the namespaces, and
    // the program inside never runs. The probe's own exit status is what tells
    // that apart from a real fault. See `skipIfNothingMeasured`.
    if (size_before_signal == 0) {
        try skipIfNothingMeasured(try child.wait(std.testing.io));
    }
    try std.testing.expect(size_before_signal > 0);
    // And the fork really happened, so the writer above is the grandchild and
    // not the sandboxed program under another name.
    try std.testing.expect((fileSize(forked_path) orelse 0) > 0);

    // The cancel. **A handle and never the number**, which is the whole point:
    // this test process is not the parent of the middle process, so it opens a
    // handle of its own on it, exactly as a caller of `Sandbox.spawn` holds
    // one. SIGKILL, the signal a second Ctrl-C sends.
    const pidfd_rc = linux.pidfd_open(middle_pid, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(pidfd_rc));
    const middle_fd: i32 = @intCast(pidfd_rc);
    defer _ = linux.close(middle_fd);
    try std.testing.expectEqual(
        .SUCCESS,
        linux.errno(linux.pidfd_send_signal(middle_fd, .KILL, null, 0)),
    );

    // A bounded wait for the whole chain to run, and not a fixed sleep.
    const term = try child.wait(std.testing.io);
    // One comparison and not a switch: `expectEqual` prints both sides, so a
    // process that ended some other way says how in the failure itself, and
    // this test writes nothing to standard error.
    try std.testing.expectEqual(std.process.Child.Term{ .signal = std.posix.SIG.KILL }, term);

    // The direct proof, and the only one that matters: the grandchild's own
    // output has stopped. Two reads a bounded wait apart, well after the
    // signal. A grandchild left running appends every five milliseconds, so
    // these two would differ.
    _ = linux.nanosleep(&.{ .sec = 0, .nsec = 200_000_000 }, null);
    const size_after_wait_one = fileSize(heartbeat_path) orelse size_before_signal;
    _ = linux.nanosleep(&.{ .sec = 0, .nsec = 200_000_000 }, null);
    const size_after_wait_two = fileSize(heartbeat_path) orelse size_after_wait_one;
    try std.testing.expectEqual(size_after_wait_one, size_after_wait_two);
}

test "a process cannot signal its caller's process group, which a pid namespace does not hide" {
    // The attack a pid namespace does not answer on its own, and the one the
    // signal_isolated guarantee used to overclaim. `spawn-signal-host` above
    // proves a signal to a pid *number* is refused. This is the other spelling:
    // kill(0, sig) names no number, it names the caller's own process group,
    // which the kernel holds as an object a namespace cannot renumber away.
    //
    // Measured on 2026-08-21, before the fix: a process inside CLONE_NEWPID
    // read getpgid(0) as 0, because its group has no number there, and
    // kill(0, sig) from it still reached a process outside the namespace. That
    // is a sandboxed program signalling the very session running it.
    //
    // The probe puts itself in a process group of its own first, so this test
    // can never take the test runner down with it, and catches SIGUSR1 so that
    // it survives to report. Exit 0 means the signal reached nothing outside
    // the sandbox; exit 1 means it reached the caller.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-signal-group", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a signal to the caller's process group leaves the running call alone, and the call finishes" {
    // What makes `chock run`'s first Ctrl-C message true. That message
    // promises the current work continues to a safe point, and a terminal
    // sends SIGINT to its whole foreground process group, so before spawn took
    // a group of its own one press reached the session loop *and* the program
    // it was running.
    //
    // The probe takes a group of its own, which stands in for a session's
    // foreground group, then signals that whole group by group and never by
    // process, exactly as a terminal does. The sandboxed program catches the
    // signal rather than dying from it, because process 1 of a pid namespace
    // ignores every signal whose action is the default one, so its death is
    // not a thing this could rely on either way.
    //
    // Exit 0 is the pair of facts this pins: the press reached nothing inside
    // the call, **and** the call ran on to its own end and exited 0 afterward.
    // Exit 1 is the press reaching the sandboxed program.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-group-press", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a caller's own signal handler does not run in the process spawn forked, so a call can still be cancelled" {
    // The fault the project owner saw as a stop message nobody asked for. The
    // process spawn forks is a fork of the caller and never execs, so it kept
    // every signal handler the caller had installed. `chock run` installs one
    // for SIGINT and SIGTERM that prints "stopping at the next safe point" and
    // sets a flag, and two things came out of that:
    //
    //   * lib/chock-core/tools.zig cancels a tool call that runs past its
    //     deadline by sending SIGTERM to that same process. The inherited
    //     handler caught it, so the process did not die and the call ran on:
    //     the deadline cancelled nothing.
    //   * the handler's message went to that process's own standard error,
    //     which is the caller's terminal, so the message appeared with nobody
    //     having pressed anything.
    //
    // This is Finding 2's cancellation with a SIGTERM handler installed in the
    // caller first, and the probe proves that handler is really live by
    // raising the signal at itself before it ever calls spawn. Exit 0 means the
    // call was cancelled and the process spawn forked died from the signal.
    // Exit 1 means it outlived its own cancellation.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-signal-middle-handled", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

const limit_stopped_legibly = 10;
const limit_stopped_quietly = 11;
const limit_not_stopped = 12;
const limit_no_cgroup = 14;

/// The exit status of one limit run, as a plain number, so each test below
/// reads as the comparison it really is.
fn limitRun(op: []const u8, root: []const u8) !u8 {
    const term = try runProbeWithRoot(op, root);
    return switch (term) {
        .exited => |code| code,
        else => error.TestUnexpectedResult,
    };
}

test "a fork bomb inside the sandbox is stopped, and the same bomb with no limit is not" {
    // The attack in one line: a program that forks until it cannot. Nothing
    // in the namespaces, in Landlock or in seccomp refuses a fork.
    //
    // Mutation check: this is written as a comparison on purpose. Remove
    // `processes` from `Limits`, or stop `spawn` from making a cgroup, or
    // take the `RLIMIT_NPROC` call out of `rlimits.apply`, and the bounded
    // run answers `limit_not_stopped` exactly like the unbounded one, which
    // fails the first assertion below. There is no value of the bounded run
    // alone that passes without the limit being real.
    var bounded_scratch = try scratchRoot();
    defer bounded_scratch.cleanup();
    const bounded = try limitRun("spawn-fork-bomb", bounded_scratch.path());

    var unbounded_scratch = try scratchRoot();
    defer unbounded_scratch.cleanup();
    const unbounded = try limitRun("spawn-fork-bomb-unbounded", unbounded_scratch.path());

    // The same program, the same sandbox, and one difference: the limit.
    try std.testing.expect(bounded != unbounded);
    try std.testing.expectEqual(@as(u8, limit_not_stopped), unbounded);
    try std.testing.expect(bounded == limit_stopped_legibly or bounded == limit_stopped_quietly);
}

test "an allocation that never stops is stopped, and the same allocation with no limit is not" {
    // The probe writes to every block it takes, not only maps it. That
    // matters: an untouched mapping is the case `RLIMIT_AS` refuses and
    // `memory.max` correctly permits, so a probe that only mapped memory
    // would prove nothing about the limit that is actually on.
    //
    // Mutation check: remove `memory_bytes` and `mapped_memory_bytes` from
    // `Limits` and the bounded run reaches the same 512 MiB cap the unbounded
    // one does, which fails the comparison below.
    var bounded_scratch = try scratchRoot();
    defer bounded_scratch.cleanup();
    const bounded = try limitRun("spawn-mem-bomb", bounded_scratch.path());

    var unbounded_scratch = try scratchRoot();
    defer unbounded_scratch.cleanup();
    const unbounded = try limitRun("spawn-mem-bomb-unbounded", unbounded_scratch.path());

    try std.testing.expect(bounded != unbounded);
    try std.testing.expectEqual(@as(u8, limit_not_stopped), unbounded);
    try std.testing.expect(bounded == limit_stopped_legibly or bounded == limit_stopped_quietly);
}

test "descriptor exhaustion is stopped, and the same program with no limit is not" {
    // The cheapest of the three attacks to write and the least visible in a
    // log: a program that opens and never closes. `RLIMIT_NOFILE` is the only
    // thing standing in the way, and it is per process, which is why the
    // process count is bounded too.
    var bounded_scratch = try scratchRoot();
    defer bounded_scratch.cleanup();
    const bounded = try limitRun("spawn-fd-bomb", bounded_scratch.path());

    var unbounded_scratch = try scratchRoot();
    defer unbounded_scratch.cleanup();
    const unbounded = try limitRun("spawn-fd-bomb-unbounded", unbounded_scratch.path());

    try std.testing.expect(bounded != unbounded);
    try std.testing.expectEqual(@as(u8, limit_not_stopped), unbounded);
    try std.testing.expect(bounded == limit_stopped_legibly or bounded == limit_stopped_quietly);
}

test "a limit that killed the program says which limit it was, and not only that a signal arrived" {
    // **This project's most repeated lesson: a confusing failure costs turns
    // and a plain refusal costs one.** `memory.max` kills with a bare
    // SIGKILL, which is exactly what a caller sees when the harness cancels a
    // call on its deadline or when a person presses Ctrl-C twice. A caller
    // that only had the `Term` could not tell those apart.
    //
    // This run leaves `mapped_memory_bytes` off, so the rlimit floor refuses
    // nothing and `memory.max` is the only thing that can stop the program.
    // That is deliberate: an allocation the floor refuses ends with the
    // program's own `OutOfMemory`, which was always legible, and only the
    // cgroup kill has the problem this test is about.
    //
    // **A machine with no cgroup layer skips, and a machine with one cannot.**
    // The probe answers `limit_no_cgroup` from `LimitsReport.cgroup` before
    // it reads the outcome at all, so a `memory.max` that was never written
    // is a failure here and not a quiet skip.
    //
    // Mutation check: make `reportLimitOutcome` stop reading `memory.events`,
    // or make it leave `killed_by` null, and this drops to
    // `limit_stopped_quietly`. Stop `applyLimits` writing `memory.max` and it
    // drops to `limit_not_stopped`. Both fail the assertion below.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const bounded = try limitRun("spawn-mem-bomb-cgroup", scratch.path());

    if (bounded == limit_no_cgroup) {
        // No cgroup v2 tree, or none delegated to this user. The rlimit floor
        // still stops a runaway allocation, which the test above pins, and
        // there is no kernel counter on this machine to name the limit with.
        return error.SkipZigTest;
    }
    try std.testing.expectEqual(@as(u8, limit_stopped_legibly), bounded);
}

/// The number of entries directly under `path`, or null when it cannot be
/// read. Used to prove, from outside every namespace, that the files a
/// sandboxed program made are not on the host's own filesystem.
fn hostEntryCount(path: [:0]const u8) ?usize {
    const dir_rc = linux.open(path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(dir_rc) != .SUCCESS) return null;
    const dir_fd: linux.fd_t = @intCast(dir_rc);
    defer _ = linux.close(dir_fd);

    var count: usize = 0;
    var buffer: [4096]u8 = undefined;
    while (true) {
        const nread = linux.getdents64(dir_fd, &buffer, buffer.len);
        if (linux.errno(nread) != .SUCCESS) return null;
        if (nread == 0) return count;

        var offset: usize = 0;
        while (offset < nread) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            const name_ptr: [*:0]const u8 = @ptrCast(&buffer[offset + @offsetOf(linux.dirent64, "name")]);
            const name = std.mem.sliceTo(name_ptr, 0);
            offset += entry.reclen;
            // "." and ".." are in every directory and are not entries anybody
            // wrote.
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            count += 1;
        }
    }
}

test "many small files are stopped, the same files with no cap are not, and neither run reaches the host disk" {
    // The attack in one line: a program that writes files until the disk is
    // full. Every file is far under `RLIMIT_FSIZE`, so that limit never sees
    // it, and nothing in the namespaces, in Landlock, in seccomp or in the
    // cgroup refuses a write.
    //
    // Mutation check, and this test makes two separate claims so it needs two.
    //
    //   * **The cap.** Stop `mountScratchAreas` passing
    //     `config.limits.scratch_bytes` to `namespace.mountScratch`, or make
    //     `mountScratch` build an empty option string whatever it was given,
    //     and the bounded run reaches the same internal cap the unbounded one
    //     does, which fails the first assertion below.
    //   * **The area being memory rather than the host's disk.** Make
    //     `mountScratch` skip the `mount` call and only create the directory,
    //     and both runs write into `<root>/run/chock/scratch` on the real
    //     filesystem, which fails the last two assertions. That is the shape
    //     of the fault worth catching: a scratch area that quietly became an
    //     ordinary directory bounds nothing and fills the user's disk, and
    //     every other check in this file would still pass.
    var bounded_scratch = try scratchRoot();
    defer bounded_scratch.cleanup();
    const bounded = try limitRun("spawn-disk-files", bounded_scratch.path());

    var unbounded_scratch = try scratchRoot();
    defer unbounded_scratch.cleanup();
    const unbounded = try limitRun("spawn-disk-files-unbounded", unbounded_scratch.path());

    // The same program, the same sandbox, and one difference: the cap.
    try std.testing.expect(bounded != unbounded);
    try std.testing.expectEqual(@as(u8, limit_not_stopped), unbounded);
    try std.testing.expect(bounded == limit_stopped_legibly or bounded == limit_stopped_quietly);

    // **The host is untouched, by either run.** The area is a tmpfs mounted
    // inside the call's own mount namespace, so every file the program made
    // went into memory and disappeared with that namespace. The directory the
    // mount sat on is still here, on the real filesystem, and it must be
    // empty. The unbounded run is checked too, and it is the more interesting
    // of the two: that is the run that wrote the most.
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const bounded_host = try std.fmt.bufPrintZ(
        &path_buffer,
        "{s}/run/chock/scratch",
        .{bounded_scratch.path()},
    );
    try std.testing.expectEqual(@as(?usize, 0), hostEntryCount(bounded_host));

    var unbounded_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const unbounded_host = try std.fmt.bufPrintZ(
        &unbounded_buffer,
        "{s}/run/chock/scratch",
        .{unbounded_scratch.path()},
    );
    try std.testing.expectEqual(@as(?usize, 0), hostEntryCount(unbounded_host));
}

test "one enormous file in a scratch area is still stopped, and the same file with no limit is not" {
    // The other half of the disk row, and the half that already had an answer:
    // `RLIMIT_FSIZE`. **A tmpfs is a filesystem this project had never put
    // that limit against**, and a limit that held on one filesystem and not on
    // another is a hole nobody would find by reading. The scratch cap on this
    // run is far above what the program writes, on purpose, so the area cannot
    // be what stops it.
    //
    // Mutation check, and it was run rather than reasoned about, which is the
    // only reason this test is worth anything. Take the `RLIMIT_FSIZE` call out
    // of `rlimits.apply` and the bounded run reaches the same internal cap the
    // unbounded one does, which fails the comparison below.
    //
    // **The first version of this test passed that mutation**, because
    // `disk_one_scratch_limit` was 8 MiB and the program can write 12.8 MiB, so
    // the area filled and stopped the run in the file size limit's place. The
    // cap is now five times what the program can write, for that reason and no
    // other. See `disk_one_scratch_limit` in `test/sandbox/probe.zig`.
    var bounded_scratch = try scratchRoot();
    defer bounded_scratch.cleanup();
    const bounded = try limitRun("spawn-disk-one", bounded_scratch.path());

    var unbounded_scratch = try scratchRoot();
    defer unbounded_scratch.cleanup();
    const unbounded = try limitRun("spawn-disk-one-unbounded", unbounded_scratch.path());

    try std.testing.expect(bounded != unbounded);
    try std.testing.expectEqual(@as(u8, limit_not_stopped), unbounded);
    try std.testing.expect(bounded == limit_stopped_legibly or bounded == limit_stopped_quietly);
}

test "a full scratch area names itself, and does not read as the machine's own disk being full" {
    // **This project's most repeated lesson: a confusing failure costs turns
    // and a plain refusal costs one.** A program that fills a scratch area
    // prints "No space left on device" and exits, and a person who reads only
    // that goes and looks at their own filesystem, finds it fine, and has lost
    // a turn. Nothing in the kernel counts a full filesystem the way
    // `memory.events` counts an out of memory kill, so the fact has to be read
    // from the area itself, after the program has ended, by the one process
    // that can still see it.
    //
    // This is the same bounded run as the file bomb test above, read for a
    // stricter outcome: not merely that something stopped the program, but
    // that `Sandbox.LimitsReport` could say which limit it was.
    //
    // Mutation check: make `namespace.scratchIsFull` always answer false, or
    // make `reportScratch` write nothing, or drop the `.scratch_space` branch
    // in `reportLimitOutcome`, and this falls to `limit_stopped_quietly`. Stop
    // the cap being applied at all and it falls to `limit_not_stopped`. Every
    // one of those fails the assertion below, and none of them can be reached
    // by an absolute number that happens to be right.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const bounded = try limitRun("spawn-disk-files", scratch.path());
    try std.testing.expectEqual(@as(u8, limit_stopped_legibly), bounded);
}
