//! One dangerous operation per run. A test starts this program and reads the result.
//!
//! Exit codes:
//!   0 - the operation succeeded, or was blocked in the way the test expects.
//!   1 - the kernel refused the operation, with the errno the design predicts.
//!   2 - the operation name given on the command line is unknown.
//!   3 - the sandbox setup itself failed, before the probed operation ran.
//!   4 - a netns-connect check could not prove the network namespace was entered.
//!   5 - the kernel refused the operation, but not with the errno the design
//!       predicts.
//!  63 - this machine would not give the sandbox its namespaces. Not a pass and
//!       not a failure: the caller skips. See
//!       `namespace.nothing_measured_exit_status`.
//! A death by SIGSYS means the seccomp filter killed the process, which is a pass for
//! a call in `blocked_calls`.

const std = @import("std");
const sandbox = @import("chock-sandbox");
/// The real network broker and the real policy table. Only the transport in
/// `filteredEscape` stands in.
const chock_broker = @import("chock-broker");
const chock_policy = @import("chock-policy");
/// A real session log, in memory, for `askingEscape`. `Broker.request` needs a
/// real `chock_proto.storage.Storage` to write the question and the answer into.
const chock_proto = @import("chock-proto");
const dynamic_probe_path = @import("dynamic_probe_path").dynamic_probe_path;
const linux = std.os.linux;

const stdin_pipe_token = "chock-helper-request";

const opens_in_probe = 17;

/// A path nothing grants. The kernel tells the reader before it runs the call,
/// so a missing path is recorded the same way as one that exists.
const named_ungranted = "/etc/chock-probe-secret";

/// A path the configuration does grant. It must be counted and never named.
const named_granted = "/nix/store";

/// End `spawned-kill-the-reader` when its own alarm goes off. One system call
/// and nothing else, because this runs in a signal handler.
fn endOnAlarm(_: std.posix.SIG) callconv(.c) void {
    linux.exit(alarm_exit_status);
}

const alarm_exit_status = 9;

/// Where the path reader is, as the sandboxed program sees it. The keeper is
/// process 1, the program is process 2, and the reader is process 3.
const reader_pid_in_namespace: linux.pid_t = 3;

/// For the operations that read `spawn`'s own error instead of letting it out.
/// Returns for every other error, and prints nothing.
fn endIfNothingMeasured(err: anyerror) void {
    if (err != error.NamespaceFailed) return;
    std.process.exit(sandbox.namespace.nothing_measured_exit_status);
}

/// A machine with no user namespace proves neither a hold nor a leak. Nothing
/// is printed, because `build.zig` fails a build on any test stderr.
fn enterOrEndUnmeasured(options: sandbox.namespace.Options) void {
    sandbox.namespace.enter(options, null) catch {
        std.process.exit(sandbox.namespace.nothing_measured_exit_status);
    };
}

/// `root` is scratch space the caller made and cleans up.
fn enterTestRoot(arena: std.mem.Allocator, root: []const u8) !void {
    // The tree is built outside the namespace, while the paths are still
    // writable. Only the workspace under `root` is new.
    const work = try std.fs.path.join(arena, &.{ root, "work" });
    try makeTestDir(arena, work);

    const guarded = try std.fs.path.join(arena, &.{ work, "chock.zon" });
    try writeTestFile(arena, guarded, ".{}\n");

    enterOrEndUnmeasured(.{ .network = .none, .mount = true });
    try sandbox.namespace.buildRoot(arena, root, &.{
        .{ .bind = .{ .source = work, .target = "/work", .read_only = false } },
        .{ .bind = .{ .source = guarded, .target = "/work/chock.zon", .read_only = true } },
        .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } },
    }, null);
    try sandbox.namespace.pivotInto(arena, root, null);
}

// Zig 0.16 moved directory creation and file writes behind std.Io.Dir, which
// needs an Io this probe does not carry, so this calls the kernel directly.
fn makeTestDir(arena: std.mem.Allocator, path: []const u8) !void {
    const path_z = try arena.dupeZ(u8, path);
    switch (linux.errno(linux.mkdir(path_z.ptr, 0o755))) {
        .SUCCESS, .EXIST => {},
        else => return error.SetupFailed,
    }
}

fn writeTestFile(arena: std.mem.Allocator, path: []const u8, contents: []const u8) !void {
    const path_z = try arena.dupeZ(u8, path);
    const fd_rc = linux.open(path_z.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (linux.errno(fd_rc) != .SUCCESS) return error.SetupFailed;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    const written = linux.write(fd, contents.ptr, contents.len);
    if (linux.errno(written) != .SUCCESS or written != contents.len) return error.SetupFailed;
}

/// A build time path from `addOptionPath` is relative to the build root, and
/// the kernel resolves a bind mount source inside a process building its own.
fn absolutePath(arena: std.mem.Allocator, path: []const u8) ![]const u8 {
    if (path.len != 0 and path[0] == '/') return path;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const rc = linux.getcwd(&buffer, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.SetupFailed;
    // `getcwd` counts the terminator it wrote. A cwd of `/` must not become
    // `//path`, so the separator is added only when there is none already.
    const cwd = std.mem.sliceTo(buffer[0..rc], 0);
    if (std.mem.eql(u8, cwd, "/")) return std.fmt.allocPrint(arena, "/{s}", .{path});
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ cwd, path });
}

/// `std.fs.selfExePathAlloc` does not exist in this Zig version, so the link at
/// /proc/self/exe is read directly.
fn selfExePath(arena: std.mem.Allocator) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const rc = linux.readlink("/proc/self/exe", &buffer, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.SetupFailed;
    return arena.dupe(u8, buffer[0..rc]);
}

fn readToEnd(fd: i32, buffer: []u8) []u8 {
    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(fd, buffer[filled..].ptr, buffer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        filled += rc;
    }
    return buffer[0..filled];
}

/// A trust store is a few hundred kilobytes of PEM, and more is read short.
const max_host_file_bytes = 4 << 20;

/// Read a whole file on the host into `arena`. Follows a link on purpose: the
/// host trust store is a link into the Nix store on a NixOS machine.
fn readWholeFile(arena: std.mem.Allocator, path: []const u8) ![]const u8 {
    const path_z = try arena.dupeZ(u8, path);
    const fd_rc = linux.open(path_z.ptr, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return error.SetupFailed;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    const buffer = try arena.alloc(u8, max_host_file_bytes);
    const filled = readToEnd(fd, buffer);
    if (filled.len == 0) return error.SetupFailed;
    return filled;
}

/// `root` names a directory nothing made, so `namespace.buildRoot` fails on it
/// inside `spawn`'s own child.
fn absentRoot(arena: std.mem.Allocator, root: []const u8) ![]const u8 {
    return std.fs.path.join(arena, &.{ root, "absent" });
}

/// The nix store, so the exec inside the sandbox finds its shared libraries,
/// and this binary as /probe, so the sandboxed child can run itself again.
fn baseEscapeConfig(arena: std.mem.Allocator) !struct {
    mounts: []const sandbox.namespace.Mount,
    rules: []const sandbox.Config.Rule,
} {
    const self_path = try selfExePath(arena);
    const mounts = try arena.dupe(sandbox.namespace.Mount, &.{
        .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } },
        .{ .bind = .{ .source = self_path, .target = "/probe", .read_only = true } },
        .{ .proc = .{} },
        // `/dev/null` is also what makes `/dev` exist. A Landlock rule needs a
        // path the kernel can resolve, or the program meets EACCES.
        .{ .bind = .{ .source = "/dev/null", .target = "/dev/null", .read_only = false } },
    });
    const rules = try arena.dupe(sandbox.Config.Rule, &.{
        .{ .path = "/nix/store", .access = sandbox.landlock.AccessFs.read_only },
        // The ruleset handles the execute right for every path, so without this
        // rule execve meets EACCES. /probe is a file, so read_dir gives EINVAL.
        .{ .path = "/probe", .access = .{ .execute = true, .read_file = true } },
    });
    return .{ .mounts = mounts, .rules = rules };
}

const filtered_host = "api.anthropic.com";

const filtered_refused_host = "secret.evil.test";

/// The policy every filtered probe runs under. The port stays open, because the
/// kernel chooses the ports these probes use at run time.
const filtered_policy: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.connect.com.anthropic.*", .decision = .allow },
    \\        },
    \\    },
    \\}
;

/// The same, with the parent kind refused. `evaluateChain` takes the
/// intersection over the whole chain, so a permitted subagent is still refused.
const filtered_deny_parent_policy: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .agent_kind = "main", .action = "net.connect.com.anthropic.*", .decision = .deny },
    \\            .{ .agent_kind = "fetcher", .action = "net.connect.com.anthropic.*", .decision = .allow },
    \\        },
    \\    },
    \\}
;

const Listener = struct {
    fd: i32,
    port: u16,

    fn hasPending(self: Listener) bool {
        var fds = [1]linux.pollfd{.{ .fd = self.fd, .events = linux.POLL.IN, .revents = 0 }};
        const ready = linux.poll(&fds, 1, 0);
        return linux.errno(ready) == .SUCCESS and ready > 0;
    }

    fn readFirst(self: Listener, buffer: []u8) ?[]u8 {
        if (!self.hasPending()) return null;
        const rc = linux.accept4(self.fd, null, null, linux.SOCK.CLOEXEC);
        if (linux.errno(rc) != .SUCCESS) return null;
        const peer: i32 = @intCast(rc);
        defer _ = linux.close(peer);
        const read = linux.read(peer, buffer.ptr, buffer.len);
        if (linux.errno(read) != .SUCCESS) return null;
        return buffer[0..read];
    }
};

/// A backlog and no accept: the kernel completes the handshake into that
/// backlog, so a connect succeeds while this process is inside `Sandbox.spawn`.
fn listenLoopback() !Listener {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SetupFailed;
    const fd: i32 = @intCast(rc);

    var address = linux.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    if (linux.errno(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
        return error.SetupFailed;
    if (linux.errno(linux.listen(fd, 8)) != .SUCCESS) return error.SetupFailed;

    var length: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.errno(linux.getsockname(fd, @ptrCast(&address), &length)) != .SUCCESS)
        return error.SetupFailed;
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, address.port) };
}

fn connectLoopback(port: u16) !i32 {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SetupFailed;
    const fd: i32 = @intCast(rc);
    errdefer _ = linux.close(fd);

    const address = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    if (linux.errno(linux.connect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
        return error.SetupFailed;
    return fd;
}

/// The one stand-in of the filtered probes. `dial` ignores the address and
/// connects to a loopback socket, because no test may reach the network.
const ProbeTransport = struct {
    /// What a name resolves to. Every host resolves to this, including the one
    /// the policy refuses, so a refusal is never a name that failed to resolve.
    resolves_to: chock_broker.network.Transport.Address,
    port: u16,
    /// How many names were resolved. Zero for a host the policy refused.
    lookups: usize = 0,
    dials: usize = 0,

    fn transport(self: *ProbeTransport) chock_broker.network.Transport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_broker.network.Transport.VTable{ .lookup = lookupFn, .dial = dialFn };

    fn lookupFn(
        ptr: *anyopaque,
        io: std.Io,
        host: []const u8,
        port: u16,
    ) chock_broker.network.Transport.LookupError!chock_broker.network.Transport.Address {
        _ = io;
        _ = host;
        const self: *ProbeTransport = @ptrCast(@alignCast(ptr));
        self.lookups += 1;
        var address = self.resolves_to;
        address.setPort(port);
        return address;
    }

    fn dialFn(
        ptr: *anyopaque,
        io: std.Io,
        address: chock_broker.network.Transport.Address,
    ) chock_broker.network.Transport.DialError!std.posix.fd_t {
        _ = io;
        _ = address;
        const self: *ProbeTransport = @ptrCast(@alignCast(ptr));
        self.dials += 1;
        return connectLoopback(self.port) catch error.NotConnected;
    }
};

const FilteredRun = struct {
    term: std.process.Child.Term,
    lookups: usize,
    dials: usize,
    granted: usize,
    refused: usize,
};

const device_probe_path = "/dev/chock-probe0";

const device_tree_inside = "/.chock-device-tree";

/// Relative to the hidden tree's own host directory. `Change.place.source` names
/// this same string, so the helper resolves it against that tree.
const device_probe_source = "probe0";

const device_probe_content = "chock device probe content\n";

const QueuedChange = struct {
    /// Written when `nextFn` hands `change` back, never before, so the file
    /// arrives as a live hotplug and not as a snapshot copy.
    write: ?struct { path: []const u8, content: []const u8 } = null,
    change: sandbox.DeviceSource.Change,
};

/// The wakeup is a pipe with one byte per change, so `POLLIN` stops when the
/// queue empties.
const DeviceSourceStub = struct {
    wakeup_fds: [2]i32,
    queue: [4]QueuedChange = undefined,
    queue_len: usize = 0,
    served: usize = 0,

    fn init(changes: []const QueuedChange) !DeviceSourceStub {
        var fds: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS) return error.PipeFailed;
        var self = DeviceSourceStub{ .wakeup_fds = fds };
        for (changes, 0..) |c, i| self.queue[i] = c;
        self.queue_len = changes.len;
        const marks = [_]u8{1} ** 4;
        const written = linux.write(fds[1], &marks, changes.len);
        if (linux.errno(written) != .SUCCESS or written != changes.len) return error.PipeFailed;
        return self;
    }

    fn deinit(self: *DeviceSourceStub) void {
        _ = linux.close(self.wakeup_fds[0]);
        _ = linux.close(self.wakeup_fds[1]);
    }

    fn deviceSource(self: *DeviceSourceStub) sandbox.DeviceSource {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = sandbox.DeviceSource.VTable{ .wakeup = wakeupFn, .next = nextFn };

    fn wakeupFn(ptr: *anyopaque) i32 {
        const self: *DeviceSourceStub = @ptrCast(@alignCast(ptr));
        return self.wakeup_fds[0];
    }

    fn nextFn(ptr: *anyopaque) ?sandbox.DeviceSource.Change {
        const self: *DeviceSourceStub = @ptrCast(@alignCast(ptr));
        if (self.served >= self.queue_len) return null;
        const queued = self.queue[self.served];
        self.served += 1;

        if (queued.write) |w| {
            var path_buf: [std.fs.max_path_bytes]u8 = undefined;
            if (std.fmt.bufPrintZ(&path_buf, "{s}", .{w.path})) |path_z| {
                const fd_rc = linux.open(path_z.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
                if (linux.errno(fd_rc) == .SUCCESS) {
                    const fd: i32 = @intCast(fd_rc);
                    _ = linux.write(fd, w.content.ptr, w.content.len);
                    _ = linux.close(fd);
                }
            } else |_| {}
        }

        // The matching read for the byte `init` put on the wakeup pipe.
        var one: [1]u8 = undefined;
        _ = linux.read(self.wakeup_fds[0], &one, 1);
        return queued.change;
    }
};

const DeviceRun = struct {
    term: std.process.Child.Term,
    served: usize,
};

fn deviceEscape(
    arena: std.mem.Allocator,
    root: []const u8,
    op: []const u8,
    op_argv: []const []const u8,
    extra_mounts: []const sandbox.namespace.Mount,
    extra_rules: []const sandbox.Config.Rule,
    extra_net_broker: ?sandbox.NetBroker,
) !DeviceRun {
    const base = try baseEscapeConfig(arena);

    // `/dev` has to exist as a real directory before `applyLayers` builds the
    // ruleset: a rule can only be added for a path that already resolves.
    const devnull_mount = sandbox.namespace.Mount{
        .bind = .{ .source = "/dev/null", .target = "/dev/null", .read_only = false },
    };
    const mounts = try std.mem.concat(
        arena,
        sandbox.namespace.Mount,
        &.{ base.mounts, &.{devnull_mount}, extra_mounts },
    );

    // Landlock walks the hierarchy when a path is opened, so a rule on `/dev`
    // covers a file that appears later. `device_tree_inside` gets no rule.
    const dev_rule = sandbox.Config.Rule{
        .path = "/dev",
        .access = .{ .read_file = true, .write_file = true },
    };
    const rules = try std.mem.concat(
        arena,
        sandbox.Config.Rule,
        &.{ base.rules, &.{dev_rule}, extra_rules },
    );

    // A sibling of `root`, never a path inside it, because `root` becomes the
    // sandbox's own filesystem view.
    const host_dir = try std.fs.path.join(arena, &.{ root, "..", "chock-device-tree" });
    try makeTestDir(arena, host_dir);
    const source_path = try std.fs.path.join(arena, &.{ host_dir, device_probe_source });

    var stub = try DeviceSourceStub.init(&.{
        .{
            .write = .{ .path = source_path, .content = device_probe_content },
            .change = .{ .place = .{ .kind = 0, .source = device_probe_source, .target = device_probe_path } },
        },
    });
    defer stub.deinit();

    const argv = try std.mem.concat(arena, []const u8, &.{ &.{ "/probe", op }, op_argv });

    const term = try sandbox.spawn(arena, .{
        .root = root,
        .mounts = mounts,
        .rules = rules,
        .cwd = "/",
        .env = &.{},
        .network = if (extra_net_broker != null) .filtered else .none,
        .net_broker = extra_net_broker,
        .device_source = stub.deviceSource(),
        .device_tree = .{ .host = host_dir, .inside = device_tree_inside },
    }, argv, null, null);

    return .{ .term = term, .served = stub.served };
}

/// Read out of `/proc/<pid>/task/<pid>/children`. Zero for a pid this machine
/// has no such file for, which the caller reads as nothing to count.
fn countChildren(pid: linux.pid_t) usize {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/task/{d}/children", .{ pid, pid }) catch return 0;
    const fd_rc = linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return 0;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);
    var buf: [256]u8 = undefined;
    const n = linux.read(fd, &buf, buf.len);
    if (linux.errno(n) != .SUCCESS) return 0;
    var it = std.mem.tokenizeAny(u8, buf[0..n], " \n");
    var count: usize = 0;
    while (it.next()) |_| count += 1;
    return count;
}

const ChildCountContext = struct {
    arena: std.mem.Allocator,
    root: []const u8,
    read_fd: i32,
    device: bool,
    middle: sandbox.Middle = .{},
    term: std.process.Child.Term = undefined,
    err: ?anyerror = null,
};

/// A plain function and not a closure, because `std.Thread.spawn` takes one.
/// Every answer travels through `ctx`, read only after `thread.join()` returns.
fn runChildCountSpawn(ctx: *ChildCountContext) void {
    const base = baseEscapeConfig(ctx.arena) catch |err| {
        ctx.err = err;
        return;
    };

    // Declared at function scope, because a `sandbox.DeviceSource` borrows this
    // address for the whole of the `spawn` call further down.
    var stub: DeviceSourceStub = undefined;
    var device_source: ?sandbox.DeviceSource = null;
    var device_tree: ?sandbox.Config.DeviceTree = null;
    if (ctx.device) {
        stub = DeviceSourceStub.init(&.{}) catch |err| {
            ctx.err = err;
            return;
        };
        device_source = stub.deviceSource();
        // A `device_tree` is required exactly when `device_source` is, even
        // when nothing is placed through it. See `DeviceSourceNeedsTree`.
        const host_dir = std.fs.path.join(ctx.arena, &.{ ctx.root, "..", "chock-device-tree-none" }) catch |err| {
            ctx.err = err;
            return;
        };
        makeTestDir(ctx.arena, host_dir) catch |err| {
            ctx.err = err;
            return;
        };
        device_tree = .{ .host = host_dir, .inside = device_tree_inside };
    }
    defer if (ctx.device) stub.deinit();

    ctx.term = sandbox.spawn(ctx.arena, .{
        .root = ctx.root,
        .mounts = base.mounts,
        .rules = base.rules,
        .cwd = "/",
        .env = &.{},
        .network = .none,
        .stdin_fd = ctx.read_fd,
        .device_source = device_source,
        .device_tree = device_tree,
    }, &.{ "/probe", "spawned-hold-until-closed" }, null, &ctx.middle) catch |err| {
        ctx.err = err;
        return;
    };
}

const ChildCountRun = struct {
    term: std.process.Child.Term,
    children: usize,
};

/// `sandbox.spawn` blocks until the whole call has ended, so counting A's own
/// children needs the background thread this starts.
fn childCountEscape(arena: std.mem.Allocator, root: []const u8, device: bool) !ChildCountRun {
    var pipe_fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&pipe_fds, .{})) != .SUCCESS) return error.SetupFailed;
    const read_fd = pipe_fds[0];
    const write_fd = pipe_fds[1];

    var ctx = ChildCountContext{ .arena = arena, .root = root, .read_fd = read_fd, .device = device };
    const thread = try std.Thread.spawn(.{}, runChildCountSpawn, .{&ctx});

    // Bounded, so a machine that never gives a pid cannot hang the test. This
    // acquire load pairs with the release store on the other thread.
    var tries: usize = 0;
    while (@atomicLoad(std.posix.pid_t, &ctx.middle.pid, .acquire) == 0 and tries < 500) : (tries += 1) {
        var pause: linux.timespec = .{ .sec = 0, .nsec = 2_000_000 };
        _ = linux.nanosleep(&pause, null);
    }
    const a_pid = @atomicLoad(std.posix.pid_t, &ctx.middle.pid, .acquire);

    var children: usize = 0;
    if (a_pid != 0) {
        // A moment for B, and D when `device` is true, to reach the point
        // `/proc` sees them. A's own pid appears the instant `fork` returns.
        var pause: linux.timespec = .{ .sec = 0, .nsec = 200_000_000 };
        _ = linux.nanosleep(&pause, null);
        children = countChildren(a_pid);
    }

    // Ends the hold. `spawn` already closed this process's copy of `read_fd`.
    _ = linux.close(write_fd);
    thread.join();

    if (ctx.err) |err| return err;
    return .{ .term = ctx.term, .children = children };
}

fn filteredEscape(
    arena: std.mem.Allocator,
    root: []const u8,
    op: []const u8,
    ports: []const u8,
    source: [:0]const u8,
    chain: []const []const u8,
    resolves_to: chock_broker.network.Transport.Address,
    dial_port: u16,
) !FilteredRun {
    const base = try baseEscapeConfig(arena);
    const policy = try chock_policy.table.Table.parse(arena, source, null);

    // `std.Io.Threaded.init_single_threaded` never spawns a worker thread, so
    // this probe stays single threaded across `Sandbox.spawn`'s own `fork()`.
    var io_impl: std.Io.Threaded = .init_single_threaded;

    var transport = ProbeTransport{ .resolves_to = resolves_to, .port = dial_port };
    var network = chock_broker.network.Network{
        .gpa = arena,
        // `finishConnect` passes `self.io` to `transport.lookup` and
        // `transport.dial`, so this may not hold `undefined`.
        .io = io_impl.io(),
        .table = policy,
        .chain = chain,
        .agent_kind = chain[chain.len - 1],
        .model = "main",
        .tool = "mcp",
        .transport = transport.transport(),
    };

    const term = try sandbox.spawn(arena, .{
        .root = root,
        .mounts = base.mounts,
        .rules = base.rules,
        .cwd = "/",
        .env = &.{},
        .network = .filtered,
        .net_broker = network.netBroker(),
    }, &.{ "/probe", op, ports }, null, null);

    return .{
        .term = term,
        .lookups = transport.lookups,
        .dials = transport.dials,
        .granted = network.granted,
        .refused = network.refused,
    };
}

/// No rule at all, which `Table.evaluateChain` answers with `ask`, so the
/// table's own default routes the connection to `Broker.request`.
const ask_policy: [:0]const u8 =
    \\.{ .policy = .{ .rules = .{} } }
;

/// A second host, so the second reentrant `Broker.request` is not the same
/// question twice.
const second_filtered_host = "second.example.com";

/// The child asks, blocks, and asks again, so only one is ever open.
fn openRequest(gpa: std.mem.Allocator, store: chock_proto.storage.Storage) ?u64 {
    var replay = store.replay(gpa, undefined, 0) catch return null;
    defer replay.deinit();

    var last_request: ?u64 = null;
    var answered = false;
    while (replay.next(undefined) catch null) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .approval_request => {
                last_request = parsed.value.id;
                answered = false;
            },
            .approval_response => |response| {
                if (last_request != null and response.request_id == last_request.?) answered = true;
            },
            else => {},
        }
    }
    if (last_request) |id| {
        if (!answered) return id;
    }
    return null;
}

/// Stands in for the person who would answer through the broker socket. It
/// proves the log, lock and turn mechanics, and not that socket waiter.
const AskArbiter = struct {
    gpa: std.mem.Allocator,
    store: chock_proto.storage.Storage,
    locked: *chock_broker.network.Locked,
    now_ms: i64 = 1_700_000_000_000,
    waits: usize = 0,
    /// One answer per open request, in order, the last entry repeating.
    decisions: []const chock_proto.event.ApprovalDecision = &.{.approved_by_user},
    answered: usize = 0,
    /// False for the "nobody is there" case: every open request is left as it
    /// is, so `askTheHuman`'s own deadline is what ends the wait.
    answers: bool = true,
    /// The wait count at which this arbiter reports a cancellation instead.
    cancel_at: ?usize = null,

    fn waiter(self: *AskArbiter) chock_broker.Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_broker.Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = io;
        const self: *AskArbiter = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) chock_broker.Broker.Waiter.Wake {
        _ = io;
        const self: *AskArbiter = @ptrCast(@alignCast(ptr));
        self.waits += 1;
        if (self.cancel_at) |at| {
            if (self.waits >= at) return .canceled;
        }
        if (self.answers) {
            if (openRequest(self.gpa, self.store)) |id| {
                const index = @min(self.answered, self.decisions.len - 1);
                _ = self.locked.append(self.gpa, undefined, .{ .approval_response = .{
                    .request_id = id,
                    .decision = self.decisions[index],
                    .responder = "arbiter",
                } }, self.now_ms) catch {};
                self.answered += 1;
            }
        }
        self.now_ms += @intCast(budget_ms);
        return .slept;
    }
};

const AskingRun = struct {
    term: std.process.Child.Term,
    granted: usize,
    refused: usize,
    requests: usize,
    responses: usize,
    verdict: chock_proto.chain.Verdict,
    /// True when the `tool.call`, every `approval.request` and
    /// `approval.response` the spawn caused, and the `tool.result` are in order.
    turn_intact: bool,
};

/// A session log in memory brackets the call the way `Loop.runTool` brackets a
/// real tool call, and a real `Broker.request` answers the `ask`.
fn askingEscape(
    arena: std.mem.Allocator,
    root: []const u8,
    op: []const u8,
    ports: []const u8,
    resolves_to: chock_broker.network.Transport.Address,
    dial_port: u16,
    decisions: []const chock_proto.event.ApprovalDecision,
    answers: bool,
    cancel_at: ?usize,
) !AskingRun {
    const base = try baseEscapeConfig(arena);
    const policy = try chock_policy.table.Table.parse(arena, ask_policy, null);

    var backing = try chock_proto.storage.Memory.init(arena, "01PROBEASK");
    const store = backing.storage();

    var locked = try store.lock(undefined);
    const call_id = try locked.append(arena, undefined, .{ .tool_call = .{
        .call_id = "call1",
        .tool = "mcp",
        .arguments = "{}",
    } }, 1_700_000_000_000);

    var arbiter = AskArbiter{
        .gpa = arena,
        .store = store,
        .locked = &locked,
        .decisions = decisions,
        .answers = answers,
        .cancel_at = cancel_at,
    };
    var broker = chock_broker.Broker{ .policy = policy, .waiter = arbiter.waiter() };

    // What forces `askPermits` to read `self.io` for real. Every production
    // caller wires `approval_wait_ns`, and null here would skip that read.
    var approval_wait_ns: std.atomic.Value(u64) = .init(0);

    var io_impl: std.Io.Threaded = .init_single_threaded;

    var transport = ProbeTransport{ .resolves_to = resolves_to, .port = dial_port };
    var network = chock_broker.network.Network{
        .gpa = arena,
        // `askPermits` reads `self.io` when `approval_wait_ns` is set, and
        // `finishConnect` passes it on, so this may not hold `undefined`.
        .io = io_impl.io(),
        .table = policy,
        .chain = &.{"main"},
        .agent_kind = "main",
        .model = "main",
        .tool = "mcp",
        .transport = transport.transport(),
        .asker = .{
            .broker = &broker,
            .storage = store,
            .locked = &locked,
            .approval_wait_ns = &approval_wait_ns,
        },
    };

    const term = try sandbox.spawn(arena, .{
        .root = root,
        .mounts = base.mounts,
        .rules = base.rules,
        .cwd = "/",
        .env = &.{},
        .network = .filtered,
        .net_broker = network.netBroker(),
    }, &.{ "/probe", op, ports }, null, null);

    const result_id = try locked.append(arena, undefined, .{ .tool_result = .{
        .call_id = "call1",
        .output = "done",
        .is_error = false,
        .truncated = false,
    } }, 1_700_000_000_002);

    var requests: usize = 0;
    var responses: usize = 0;
    var first_request_id: ?u64 = null;
    var last_response_id: ?u64 = null;
    {
        var replay = try store.replay(arena, undefined, 0);
        defer replay.deinit();
        while (try replay.next(undefined)) |parsed| {
            defer parsed.deinit();
            switch (parsed.value.event) {
                .approval_request => {
                    requests += 1;
                    if (first_request_id == null) first_request_id = parsed.value.id;
                },
                .approval_response => {
                    responses += 1;
                    last_response_id = parsed.value.id;
                },
                else => {},
            }
        }
    }

    const verdict = (try chock_proto.storage.verify(store, arena, undefined)).verdict;

    const turn_intact = requests > 0 and
        call_id < (first_request_id orelse std.math.maxInt(u64)) and
        (last_response_id orelse 0) < result_id;

    return .{
        .term = term,
        .granted = network.granted,
        .refused = network.refused,
        .requests = requests,
        .responses = responses,
        .verdict = verdict,
        .turn_intact = turn_intact,
    };
}

/// An address on the public internet, so `addressIsReachable` permits it.
const filtered_public_address: chock_broker.network.Transport.Address =
    .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } };

/// The token a filtered child writes into a granted connection.
const filtered_token = "the-broker-opened-this";

// The network router.

const RoutedRun = struct {
    term: std.process.Child.Term,
    lookups: usize,
    dials: usize,
    granted: usize,
    refused: usize,
};

/// The same `Network` the netbroker path uses, through its other face.
fn routedEscape(
    arena: std.mem.Allocator,
    root: []const u8,
    op: []const u8,
    ports: []const u8,
    source: [:0]const u8,
    chain: []const []const u8,
    resolves_to: chock_broker.network.Transport.Address,
    dial_port: u16,
) !RoutedRun {
    const base = try baseEscapeConfig(arena);
    const policy = try chock_policy.table.Table.parse(arena, source, null);

    var io_impl: std.Io.Threaded = .init_single_threaded;

    var transport = ProbeTransport{ .resolves_to = resolves_to, .port = dial_port };
    var network = chock_broker.network.Network{
        .gpa = arena,
        .io = io_impl.io(),
        .table = policy,
        .chain = chain,
        .agent_kind = chain[chain.len - 1],
        .model = "main",
        .tool = "mcp",
        .transport = transport.transport(),
    };

    const term = try sandbox.spawn(arena, .{
        .root = root,
        .mounts = base.mounts,
        .rules = base.rules,
        .cwd = "/",
        .env = &.{},
        .network = .filtered,
        .net_router = network.netRouter(),
    }, &.{ "/probe", op, ports }, null, null);

    return .{
        .term = term,
        .lookups = transport.lookups,
        .dials = transport.dials,
        .granted = network.granted,
        .refused = network.refused,
    };
}

const dns_type_a: u16 = 1;

const Resolved = union(enum) {
    address: [4]u8,
    /// `REFUSED`, which is what a name the policy refuses answers with.
    refused,
    /// No error and no answer, from a permitted name with no such record.
    empty,
    silent,
    unreadable,
};

/// Written here and not `std.Io.net.HostName`, because this probe is statically
/// linked and what is under test is the wire the router parses.
fn askResolver(name: []const u8, kind: u16) Resolved {
    var query: [512]u8 = undefined;
    const length = buildDnsQuery(&query, 0x4321, name, kind) orelse return .unreadable;

    const sock_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(sock_rc) != .SUCCESS) return .silent;
    const fd: i32 = @intCast(sock_rc);
    defer _ = linux.close(fd);

    // A deadline, so a resolver that never answers is a result and not a hang.
    const timeout = linux.timeval{ .sec = 3, .usec = 0 };
    _ = linux.setsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.RCVTIMEO,
        @ptrCast(&timeout),
        @sizeOf(linux.timeval),
    );

    const where = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, 53),
        .addr = @bitCast(sandbox.netns.address4),
    };
    const sent = linux.sendto(
        fd,
        &query,
        length,
        0,
        @ptrCast(&where),
        @sizeOf(linux.sockaddr.in),
    );
    if (linux.errno(sent) != .SUCCESS or sent != length) return .silent;

    var reply: [512]u8 = undefined;
    const got = linux.recvfrom(fd, &reply, reply.len, 0, null, null);
    if (linux.errno(got) != .SUCCESS) return .silent;
    return readDnsReply(reply[0..got], 0x4321, kind);
}

fn buildDnsQuery(out: []u8, id: u16, name: []const u8, kind: u16) ?usize {
    if (out.len < 12) return null;
    std.mem.writeInt(u16, out[0..2], id, .big);
    // Recursion desired, and nothing else: an ordinary query of opcode zero.
    std.mem.writeInt(u16, out[2..4], 0x0100, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], 0, .big);
    std.mem.writeInt(u16, out[8..10], 0, .big);
    std.mem.writeInt(u16, out[10..12], 0, .big);

    var at: usize = 12;
    var start: usize = 0;
    while (start <= name.len) {
        const end = std.mem.indexOfScalarPos(u8, name, start, '.') orelse name.len;
        const label = name[start..end];
        if (label.len == 0 or label.len > 63) return null;
        if (at + 1 + label.len > out.len) return null;
        out[at] = @intCast(label.len);
        at += 1;
        @memcpy(out[at..][0..label.len], label);
        at += label.len;
        if (end == name.len) break;
        start = end + 1;
    }
    if (at + 5 > out.len) return null;
    out[at] = 0;
    at += 1;
    std.mem.writeInt(u16, out[at..][0..2], kind, .big);
    at += 2;
    std.mem.writeInt(u16, out[at..][0..2], 1, .big);
    at += 2;
    return at;
}

fn readDnsReply(bytes: []const u8, id: u16, kind: u16) Resolved {
    if (bytes.len < 12) return .unreadable;
    if (std.mem.readInt(u16, bytes[0..2], .big) != id) return .unreadable;
    const flags = std.mem.readInt(u16, bytes[2..4], .big);
    if (flags & 0x8000 == 0) return .unreadable;
    const rcode = flags & 0xf;
    if (rcode == 5) return .refused;
    if (rcode != 0) return .unreadable;

    const answers = std.mem.readInt(u16, bytes[6..8], .big);
    if (answers == 0) return .empty;

    // Walk past the one question. The router echoes the question it was asked,
    // so the name here carries no compression pointer.
    var at: usize = 12;
    while (at < bytes.len) {
        const label = bytes[at];
        if (label & 0xc0 != 0) return .unreadable;
        at += 1;
        if (label == 0) break;
        at += label;
    }
    at += 4;
    if (at + 12 > bytes.len) return .unreadable;

    // A compression pointer in every reply the router builds.
    at += if (bytes[at] & 0xc0 != 0) 2 else return .unreadable;
    const answer_kind = std.mem.readInt(u16, bytes[at..][0..2], .big);
    at += 2;
    // class, then ttl
    at += 2 + 4;
    const length = std.mem.readInt(u16, bytes[at..][0..2], .big);
    at += 2;
    if (answer_kind != kind or length != 4) return .unreadable;
    if (at + 4 > bytes.len) return .unreadable;
    return .{ .address = bytes[at..][0..4].* };
}

fn connectToAddress(bytes: [4]u8, port: u16) !i32 {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SetupFailed;
    const fd: i32 = @intCast(rc);
    errdefer _ = linux.close(fd);

    const where = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(bytes),
    };
    if (linux.errno(linux.connect(fd, @ptrCast(&where), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
        return error.NotConnected;
    return fd;
}

/// Spelled out rather than imported, because this is the hostile side.
const routed_table_name = "chock";

/// Answers the errno for the delete, or null when the exchange could not
/// happen. With `CAP_NET_ADMIN` still held the batch succeeds.
fn askToDeleteRuleset() ?linux.E {
    const fd_rc = linux.socket(
        linux.AF.NETLINK,
        linux.SOCK.RAW | linux.SOCK.CLOEXEC,
        linux.NETLINK.NETFILTER,
    );
    // A kernel with no nfnetlink cannot be asked, which is not a refusal.
    if (linux.errno(fd_rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    const me = linux.sockaddr.nl{ .pid = 0, .groups = 0 };
    if (linux.errno(linux.bind(fd, @ptrCast(&me), @sizeOf(linux.sockaddr.nl))) != .SUCCESS)
        return null;

    // Every nftables change is a batch, so a bare delete is refused by shape.
    const subsys: u16 = 10;
    const del_table: u16 = 2;
    const batch_begin: u16 = 16;
    const batch_end: u16 = 17;
    const nfproto_inet: u8 = 1;
    const nfta_table_name: u16 = 1;

    var batch: [128]u8 = @splat(0);
    var at: usize = 0;

    at += writeNetlinkHeader(batch[at..], batch_begin, 0x001, 0, 0, subsys);
    const delete_at = at;
    at += writeNetlinkHeader(batch[at..], (subsys << 8) | del_table, 0x001 | 0x004, 1, nfproto_inet, 0);
    at += writeNetlinkString(batch[at..], nfta_table_name, routed_table_name);
    std.mem.writeInt(u32, batch[delete_at..][0..4], @intCast(at - delete_at), .little);
    at += writeNetlinkHeader(batch[at..], batch_end, 0x001, 2, 0, subsys);

    const sent = linux.sendto(fd, &batch, at, 0, null, 0);
    if (linux.errno(sent) != .SUCCESS or sent != at) return null;

    var reply: [1024]u8 = undefined;
    const got = linux.recvfrom(fd, &reply, reply.len, 0, null, null);
    if (linux.errno(got) != .SUCCESS) return null;

    // The first refusal, whichever message carries it: the kernel refuses the
    // batch at `NFNL_MSG_BATCH_BEGIN` and never reads the delete.
    var acknowledged = false;
    var offset: usize = 0;
    while (offset + 16 <= got) {
        const length = std.mem.readInt(u32, reply[offset..][0..4], .little);
        if (length < 16 or offset + length > got) break;
        const kind = std.mem.readInt(u16, reply[offset + 4 ..][0..2], .little);
        // `NLMSG_ERROR` is 2 and carries a negative errno, zero meaning taken.
        if (kind == 2 and offset + 20 <= got) {
            const code = std.mem.readInt(i32, reply[offset + 16 ..][0..4], .little);
            if (code != 0) return @enumFromInt(if (code < 0) -code else code);
            acknowledged = true;
        }
        offset += (length + 3) & ~@as(usize, 3);
    }
    if (acknowledged) return .SUCCESS;
    return null;
}

/// The caller fills the length in for a message that carries attributes.
fn writeNetlinkHeader(
    out: []u8,
    kind: u16,
    flags: u16,
    sequence: u32,
    family: u8,
    res_id: u16,
) usize {
    @memset(out[0..20], 0);
    std.mem.writeInt(u32, out[0..4], 20, .little);
    std.mem.writeInt(u16, out[4..6], kind, .little);
    std.mem.writeInt(u16, out[6..8], flags, .little);
    std.mem.writeInt(u32, out[8..12], sequence, .little);
    out[16] = family;
    std.mem.writeInt(u16, out[18..20], res_id, .big);
    return 20;
}

fn writeNetlinkString(out: []u8, kind: u16, text: []const u8) usize {
    const payload = text.len + 1;
    std.mem.writeInt(u16, out[0..2], @intCast(4 + payload), .little);
    std.mem.writeInt(u16, out[2..4], kind, .little);
    @memcpy(out[4..][0..text.len], text);
    out[4 + text.len] = 0;
    var total = 4 + payload;
    while (total % 4 != 0) : (total += 1) out[total] = 0;
    return total;
}

/// The host's own files, bound in read only. Written by the probe rather than
/// taken from the host, because `nsswitch.conf`'s content decides the result.
const HostileEtc = struct {
    /// A `hosts:` line that never reaches `dns`. A real systemd line depends on
    /// which NSS modules exist, and `files` is what it amounts to.
    const nsswitch =
        "passwd:    files\n" ++
        "group:     files\n" ++
        "hosts:     files\n" ++
        "services:  files\n" ++
        "protocols: files\n";

    /// `192.0.2.1` is the documentation range of RFC 5737 and answers nobody.
    const resolv = "nameserver 192.0.2.1\noptions timeout:1 attempts:1\n";

    const hosts = "127.0.0.1\tlocalhost\n";

    const Shape = enum {
        regular,
        /// `resolv.conf` is a symbolic link into `/run/systemd/resolve`, which
        /// no sandbox holds. `substitute` refuses such a target.
        linked,
        /// No `resolv.conf` and no `nsswitch.conf`, as on Alpine. The directory
        /// is bound read only, so `writeSubstitute` answers `EROFS`.
        absent,
    };

    /// Nothing inside the sandbox is there, so a bind over it lands nowhere.
    const systemd_stub = "../run/systemd/resolve/stub-resolv.conf";

    /// What `std.crypto.Certificate.Bundle.rescan` reads first on Linux. A
    /// sandbox that takes `/etc` must go on giving the host's bytes here.
    const trust_store_directory = "ssl/certs";
    const trust_store_name = "ssl/certs/ca-certificates.crt";
    pub const trust_store_path = "/etc/ssl/certs/ca-certificates.crt";

    const TrustStore = struct {
        hash: u64,
        /// True for this host's real certificates. Both get the byte check.
        real: bool,
    };

    /// What is written when this host has no trust store. It does not parse.
    const no_trust_store = "# this host has no certificates\n";

    /// Beside the root, because everything inside it is removed between calls.
    fn build(arena: std.mem.Allocator, beside: []const u8, shape: Shape) !struct {
        path: []const u8,
        trust_store: TrustStore,
    } {
        const path = try std.fmt.allocPrintSentinel(arena, "{s}-host-etc", .{beside}, 0);
        switch (linux.errno(linux.mkdirat(linux.AT.FDCWD, path.ptr, 0o755))) {
            .SUCCESS, .EXIST => {},
            else => return error.SetupFailed,
        }
        // Whatever a previous run left, or the sandbox meets two shapes.
        try remove(arena, path, "nsswitch.conf");
        try remove(arena, path, "resolv.conf");
        try remove(arena, path, "hosts");

        switch (shape) {
            .regular => {
                try write(arena, path, "nsswitch.conf", nsswitch);
                try write(arena, path, "resolv.conf", resolv);
                try write(arena, path, "hosts", hosts);
            },
            .linked => {
                try write(arena, path, "nsswitch.conf", nsswitch);
                try write(arena, path, "hosts", hosts);
                try link(arena, path, "resolv.conf", systemd_stub);
            },
            .absent => {
                try write(arena, path, "hosts", hosts);
            },
        }

        return .{ .path = path, .trust_store = try writeTrustStore(arena, path) };
    }

    fn writeTrustStore(arena: std.mem.Allocator, directory: []const u8) !TrustStore {
        const ssl = try std.fmt.allocPrintSentinel(arena, "{s}/ssl", .{directory}, 0);
        switch (linux.errno(linux.mkdirat(linux.AT.FDCWD, ssl.ptr, 0o755))) {
            .SUCCESS, .EXIST => {},
            else => return error.SetupFailed,
        }
        const certs = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ directory, trust_store_directory }, 0);
        switch (linux.errno(linux.mkdirat(linux.AT.FDCWD, certs.ptr, 0o755))) {
            .SUCCESS, .EXIST => {},
            else => return error.SetupFailed,
        }

        const real = readWholeFile(arena, trust_store_path) catch null;
        const bytes = real orelse no_trust_store;
        try write(arena, directory, trust_store_name, bytes);
        return .{ .hash = std.hash.Wyhash.hash(0, bytes), .real = real != null };
    }

    fn remove(arena: std.mem.Allocator, directory: []const u8, name: []const u8) !void {
        const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ directory, name }, 0);
        // `unlinkat` acts on the name, so it takes a link away as readily.
        switch (linux.errno(linux.unlinkat(linux.AT.FDCWD, path.ptr, 0))) {
            .SUCCESS, .NOENT, .NOTDIR => {},
            else => return error.SetupFailed,
        }
    }

    fn link(
        arena: std.mem.Allocator,
        directory: []const u8,
        name: []const u8,
        target: []const u8,
    ) !void {
        const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ directory, name }, 0);
        const target_z = try arena.dupeZ(u8, target);
        if (linux.errno(linux.symlinkat(target_z.ptr, linux.AT.FDCWD, path.ptr)) != .SUCCESS) {
            return error.SetupFailed;
        }
    }

    fn write(
        arena: std.mem.Allocator,
        directory: []const u8,
        name: []const u8,
        bytes: []const u8,
    ) !void {
        const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ directory, name }, 0);
        const fd_rc = linux.open(
            path.ptr,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
            0o644,
        );
        if (linux.errno(fd_rc) != .SUCCESS) return error.SetupFailed;
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);
        const wrote = linux.write(fd, bytes.ptr, bytes.len);
        if (linux.errno(wrote) != .SUCCESS or wrote != bytes.len) return error.SetupFailed;
    }
};

fn routedGlibc(arena: std.mem.Allocator, root_arg: []const u8, shape: HostileEtc.Shape) !u8 {
    // glibc looks in `/etc/resolv.conf`, `/etc/nsswitch.conf`, and the nscd
    // socket, which is `AF_UNIX` and which a network namespace does not touch.
    // The host's own nscd is bound in, or the masking holds by accident.
    const base = try baseEscapeConfig(arena);
    const listener = listenLoopback() catch |err| {
        std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
        return 3;
    };
    defer _ = linux.close(listener.fd);

    var mounts = try std.ArrayList(sandbox.namespace.Mount).initCapacity(arena, base.mounts.len + 3);
    mounts.appendSliceAssumeCapacity(base.mounts);
    mounts.appendAssumeCapacity(.{ .bind = .{
        .source = try absolutePath(arena, dynamic_probe_path),
        .target = "/dynamic",
        .read_only = true,
    } });
    // An `/etc` of the shape a machine without Nix gives, read only, as
    // `src/run.zig` binds one. Only `regular` could start before `ownDirectory`.
    const host_etc = HostileEtc.build(arena, root_arg, shape) catch |err| {
        std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
        return 3;
    };
    mounts.appendAssumeCapacity(.{ .bind = .{
        .source = host_etc.path,
        .target = "/etc",
        .read_only = true,
    } });

    if (pathExists(nscd_directory_z)) {
        // Not read only. Connecting to a unix socket needs write permission on
        // the socket itself.
        mounts.appendAssumeCapacity(.{ .bind = .{
            .source = nscd_directory_z,
            .target = nscd_target,
            .read_only = false,
        } });
    }

    var rules = try std.ArrayList(sandbox.Config.Rule).initCapacity(arena, base.rules.len + 3);
    rules.appendSliceAssumeCapacity(base.rules);
    // A file, so `read_only_file`: a directory right over a file is refused.
    rules.appendAssumeCapacity(.{
        .path = "/dynamic",
        .access = sandbox.landlock.AccessFs.read_only_file,
    });
    // Without this rule glibc cannot open the resolver files it was given.
    rules.appendAssumeCapacity(.{
        .path = "/etc",
        .access = sandbox.landlock.AccessFs.read_only,
    });
    if (pathExists(nscd_directory_z)) {
        rules.appendAssumeCapacity(.{
            .path = nscd_target,
            .access = sandbox.landlock.AccessFs.read_write,
        });
    }

    const policy = try chock_policy.table.Table.parse(arena, filtered_policy, null);
    var io_impl: std.Io.Threaded = .init_single_threaded;
    var transport = ProbeTransport{
        .resolves_to = filtered_public_address,
        .port = listener.port,
    };
    var network = chock_broker.network.Network{
        .gpa = arena,
        .io = io_impl.io(),
        .table = policy,
        .chain = &.{"main"},
        .agent_kind = "main",
        .model = "main",
        .tool = "mcp",
        .transport = transport.transport(),
    };

    const term = try sandbox.spawn(arena, .{
        .root = root_arg,
        .mounts = mounts.items,
        .rules = rules.items,
        .cwd = "/",
        .env = &.{},
        .network = .filtered,
        .net_router = network.netRouter(),
    }, &.{ "/dynamic", "resolve", filtered_host, "93.184.216.34" }, null, null);

    if (term != .exited or term.exited != 0) return reportChildTerm(term);

    // One lookup on the far side. Zero lookups with a successful resolve is
    // what an unmasked nscd looks like: somebody else answered the program.
    if (transport.lookups != 1) {
        std.debug.print(
            "glibc resolved a name and the far side was asked {d} times\n",
            .{transport.lookups},
        );
        return 5;
    }
    return 0;
}

/// The child is handed the hash of the bytes this wrote, so it checks that the
/// file it reads is the host's own and not a gap that happens to open.
fn routedTrustStore(arena: std.mem.Allocator, root_arg: []const u8) !u8 {
    const base = try baseEscapeConfig(arena);

    // What is under test is what stays readable once the sandbox takes `/etc`.
    const host_etc = HostileEtc.build(arena, root_arg, .regular) catch |err| {
        std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
        return 3;
    };

    var mounts = try std.ArrayList(sandbox.namespace.Mount).initCapacity(arena, base.mounts.len + 1);
    mounts.appendSliceAssumeCapacity(base.mounts);
    mounts.appendAssumeCapacity(.{ .bind = .{
        .source = host_etc.path,
        .target = "/etc",
        .read_only = true,
    } });

    var rules = try std.ArrayList(sandbox.Config.Rule).initCapacity(arena, base.rules.len + 1);
    rules.appendSliceAssumeCapacity(base.rules);
    rules.appendAssumeCapacity(.{
        .path = "/etc",
        .access = sandbox.landlock.AccessFs.read_only,
    });

    const policy = try chock_policy.table.Table.parse(arena, filtered_policy, null);
    var io_impl: std.Io.Threaded = .init_single_threaded;
    var transport = ProbeTransport{ .resolves_to = filtered_public_address, .port = routed_port };
    var network = chock_broker.network.Network{
        .gpa = arena,
        .io = io_impl.io(),
        .table = policy,
        .chain = &.{"main"},
        .agent_kind = "main",
        .model = "main",
        .tool = "mcp",
        .transport = transport.transport(),
    };

    const spec = try std.fmt.allocPrint(arena, "{x}:{d}", .{
        host_etc.trust_store.hash,
        @intFromBool(host_etc.trust_store.real),
    });

    const term = try sandbox.spawn(arena, .{
        .root = root_arg,
        .mounts = mounts.items,
        .rules = rules.items,
        .cwd = "/",
        .env = &.{},
        .network = .filtered,
        .net_router = network.netRouter(),
    }, &.{ "/probe", "routed-trust-store", spec }, null, null);

    return reportChildTerm(term);
}

/// Spelled out on purpose: an import would agree with any change.
const owned_backing_inside: [:0]const u8 = "/.chock-owned";

const nscd_directory_z: [:0]const u8 = "/run/nscd";

/// glibc spells `_PATH_NSCDSOCKET` as `/var/run/nscd/socket`. `/var/run` is a
/// symbolic link on the host and absent inside a sandbox with only a toolchain.
const nscd_target = "/var/run/nscd";

/// The policy permits any port, because the kernel chooses these.
const routed_port: u16 = 443;

fn filteredPorts(arena: std.mem.Allocator, granted: u16, other: u16) ![]const u8 {
    return std.fmt.allocPrint(arena, "{d},{d}", .{ granted, other });
}

fn splitPorts(text: []const u8) ?struct { u16, u16 } {
    const comma = std.mem.indexOfScalar(u8, text, ',') orelse return null;
    const first = std.fmt.parseInt(u16, text[0..comma], 10) catch return null;
    const second = std.fmt.parseInt(u16, text[comma + 1 ..], 10) catch return null;
    return .{ first, second };
}

/// Two calls and not one, because a connected TCP socket refuses a plain
/// re-connect with `EISCONN` and gives way only after an `AF_UNSPEC` disconnect.
fn tryToReaim(fd: i32, port: u16) linux.E {
    var nothing = linux.sockaddr.in{ .family = linux.AF.UNSPEC, .port = 0, .addr = 0 };
    const loose = linux.connect(fd, @ptrCast(&nothing), @sizeOf(linux.sockaddr.in));
    if (linux.errno(loose) != .SUCCESS) return linux.errno(loose);

    const address = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const again = linux.connect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in));
    return linux.errno(again);
}

/// An exit code says what the child decided, and this says what it was handed.
fn openDescriptorCount() usize {
    const rc = linux.open("/proc/self/fd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return 0;
    const dir: i32 = @intCast(rc);
    defer _ = linux.close(dir);

    var count: usize = 0;
    var buffer: [4096]u8 = undefined;
    while (true) {
        const nread = linux.getdents64(dir, &buffer, buffer.len);
        if (linux.errno(nread) != .SUCCESS or nread == 0) break;
        var offset: usize = 0;
        while (offset < nread) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            count += 1;
            offset += entry.reclen;
        }
    }
    return count;
}

/// Under `runtime_prefix`, which belongs to Chock and not to the project.
const scratch_target = sandbox.runtime_prefix ++ "/scratch";

/// Both the area and the rule: Landlock refuses an area no rule names, and
/// `landlock_add_rule` refuses a rule whose path does not exist.
fn diskEscapeConfig(arena: std.mem.Allocator) !struct {
    mounts: []const sandbox.namespace.Mount,
    rules: []const sandbox.Config.Rule,
    scratch: []const sandbox.namespace.Scratch,
} {
    const base = try baseEscapeConfig(arena);
    const rules = try arena.alloc(sandbox.Config.Rule, base.rules.len + 1);
    @memcpy(rules[0..base.rules.len], base.rules);
    rules[base.rules.len] = .{ .path = scratch_target, .access = sandbox.landlock.AccessFs.read_write };

    const scratch = try arena.dupe(sandbox.namespace.Scratch, &.{
        .{ .target = scratch_target },
    });
    return .{ .mounts = base.mounts, .rules = rules, .scratch = scratch };
}

/// How many children `spawned-fork-bomb` makes before it stops on its own.
const fork_bomb_cap: u8 = 64;
/// Well under the cap, so the two runs cannot be confused.
const fork_bomb_limit: u64 = 8;

/// 512 MiB in all, far past the limit the bounded run gets.
const mem_bomb_cap: u8 = 64;
/// One block, in bytes. Touched, not only mapped: an untouched mapping is what
/// `RLIMIT_AS` refuses and `memory.max` does not.
const mem_bomb_block_bytes: usize = 8 << 20;
/// Both ceilings, so this proves something on a machine with no cgroups.
const mem_bomb_limit: u64 = 128 << 20;

const fd_bomb_cap: u8 = 200;
const fd_bomb_limit: u64 = 32;

/// How many files `spawned-disk-file-bomb` makes before it stops on its own.
const disk_file_cap: u8 = 250;
/// Small on purpose: the attack is the number of files and not the size of any
/// one, which `RLIMIT_FSIZE` cannot see.
const disk_file_bytes: usize = 4096;

/// Chosen against the page size and never a number of files: a file costs a
/// whole page, so 512 KiB holds 8 files here and 128 on a 4 KiB page machine.
const disk_file_limit: u64 = 512 << 10;

/// How many blocks `spawned-disk-one-bomb` writes, which is 12.8 MiB of work.
const disk_one_cap: u8 = 200;
const disk_one_block_bytes: usize = 64 << 10;
const disk_one_file_limit: u64 = 1 << 20;
/// It must hold more than `spawned-disk-one-bomb` can write, which is 12.8 MiB,
/// or the area fills first and the file size limit is never the bound.
const disk_one_scratch_limit: u64 = 64 << 20;

/// `stopped_legibly` means `LimitsReport` named the limit, and `stopped_quietly`
/// is what a machine with no cgroups gets for memory.
const LimitOutcome = enum(u8) {
    stopped_legibly = 10,
    stopped_quietly = 11,
    /// The program ran to its own internal cap. Nothing bounded it.
    not_stopped = 12,
    unreadable = 13,
    /// The cgroup layer did not apply here, so the test skips. Answered before
    /// the outcome is read, so a cgroup that bounded nothing still fails.
    no_cgroup = 14,
};

/// `cap` is the program's own ceiling, and reaching it means no limit did
/// anything. `named` is whether `LimitsReport` could say which limit it was.
fn limitOutcome(term: std.process.Child.Term, cap: u8, named: bool) u8 {
    return @intFromEnum(switch (term) {
        .exited => |code| blk: {
            if (code >= cap) break :blk LimitOutcome.not_stopped;
            // A count below the program's own cap means a syscall was refused:
            // EAGAIN on a fork, ENOMEM on an allocation, EMFILE on an open.
            break :blk if (named) LimitOutcome.stopped_legibly else LimitOutcome.stopped_quietly;
        },
        // Killed. `memory.max` does this, and so does the cpu limit.
        .signal => if (named) LimitOutcome.stopped_legibly else LimitOutcome.stopped_quietly,
        else => LimitOutcome.unreadable,
    });
}

/// The kernel gives a leak the lowest free number, far below this bound.
const open_fd_set_scan_limit: i32 = 1024;

/// Zero matches no `S.IF*` constant, so a failed `statx` reads as a mismatch.
fn fileTypeOf(fd: i32) u32 {
    var stx: linux.Statx = undefined;
    const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, linux.STATX.BASIC_STATS, &stx);
    if (linux.errno(rc) != .SUCCESS) return 0;
    return stx.mode & linux.S.IFMT;
}

/// Refuses every request, because the program it spawns never asks.
const RefusingBroker = struct {
    fn connectFn(_: *anyopaque, _: []const u8, _: u16) sandbox.NetBroker.Grant {
        return .refused;
    }

    const vtable = sandbox.NetBroker.VTable{ .connect = connectFn };

    fn broker(self: *RefusingBroker) sandbox.NetBroker {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

/// Every one is opened without `FD_CLOEXEC`, because `spawn` must revoke a
/// descriptor whose owner never marked it. `io_uring` may be absent.
const HarnessDescriptors = struct {
    log: i32,
    credential: i32,
    control: [2]i32,
    epoll: i32,
    /// An io_uring ring, or -1 on a machine that would not make one.
    ring: i32,
    upstream: i32,
    /// The workspace git directory, reached as a directory descriptor, which is
    /// the shape that still reaches the host tree after `pivot_root`.
    workspace: i32,

    fn open(arena: std.mem.Allocator, root: []const u8) !HarnessDescriptors {
        const log_path = try std.fs.path.joinZ(arena, &.{ root, "session.log" });
        const log_rc = linux.open(log_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        if (linux.errno(log_rc) != .SUCCESS) return error.SetupFailed;

        const credential_rc = linux.memfd_create("chock-credential", 0);
        if (linux.errno(credential_rc) != .SUCCESS) return error.SetupFailed;

        var control: [2]i32 = undefined;
        const control_rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &control);
        if (linux.errno(control_rc) != .SUCCESS) return error.SetupFailed;

        const epoll_rc = linux.epoll_create1(0);
        if (linux.errno(epoll_rc) != .SUCCESS) return error.SetupFailed;

        var params: linux.io_uring_params = std.mem.zeroes(linux.io_uring_params);
        const ring_rc = linux.io_uring_setup(4, &params);
        const ring: i32 = if (linux.errno(ring_rc) == .SUCCESS) @intCast(ring_rc) else -1;

        const upstream_rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
        if (linux.errno(upstream_rc) != .SUCCESS) return error.SetupFailed;

        const workspace_rc = linux.open("/", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        if (linux.errno(workspace_rc) != .SUCCESS) return error.SetupFailed;

        return .{
            .log = @intCast(log_rc),
            .credential = @intCast(credential_rc),
            .control = control,
            .epoll = @intCast(epoll_rc),
            .ring = ring,
            .upstream = @intCast(upstream_rc),
            .workspace = @intCast(workspace_rc),
        };
    }

    /// How many of the shapes above this machine really gave.
    fn openCount(self: HarnessDescriptors) usize {
        var count: usize = 0;
        for ([_]i32{
            self.log,
            self.credential,
            self.control[0],
            self.control[1],
            self.epoll,
            self.ring,
            self.upstream,
            self.workspace,
        }) |fd| {
            if (fd < 0) continue;
            if (linux.errno(linux.fcntl(fd, linux.F.GETFD, 0)) == .SUCCESS) count += 1;
        }
        return count;
    }
};

/// Seven of the eight, because `io_uring` is the one a machine may refuse.
const required_harness_descriptors: usize = 7;

fn reportChildTerm(term: std.process.Child.Term) u8 {
    switch (term) {
        .signal => |sig| {
            // Only a failure to raise can reach the return below. Name it.
            std.posix.raise(sig) catch |err| {
                std.debug.print("could not re-raise {s}: {s}\n", .{ @tagName(sig), @errorName(err) });
            };
            return 1;
        },
        .exited => |code| return code,
        else => return 2,
    }
}

var caller_signal_seen: std.atomic.Value(bool) = .init(false);

/// A handler runs between any two instructions, so it takes no lock.
fn onCallerSignal(_: std.posix.SIG) callconv(.c) void {
    caller_signal_seen.store(true, .monotonic);
}

/// The default action of every signal these operations use ends a process, and
/// a dead process reports nothing.
fn catchSignal(sig: std.posix.SIG) void {
    const action = std.posix.Sigaction{
        .handler = .{ .handler = onCallerSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(sig, &action, null);
}

/// Every caller treats the bound as a failure, so a broken build never hangs.
const probe_wait_bound_ns: u64 = 10 * std.time.ns_per_s;
const probe_wait_step_ns: u64 = 1 * std.time.ns_per_ms;

fn pathExists(path: [:0]const u8) bool {
    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, path, 0, .{ .TYPE = true }, &stx);
    return linux.errno(rc) == .SUCCESS;
}

fn waitForPath(path: [:0]const u8) bool {
    var waited: u64 = 0;
    while (waited < probe_wait_bound_ns) : (waited += probe_wait_step_ns) {
        if (pathExists(path)) return true;
        _ = linux.nanosleep(&.{ .sec = 0, .nsec = @intCast(probe_wait_step_ns) }, null);
    }
    return pathExists(path);
}

/// `spawn` is synchronous, so a thread of its own is the only way to learn the
/// pid it forked and act on it before the whole call finishes.
const ThreadedSpawn = struct {
    allocator: std.mem.Allocator,
    root: []const u8,
    mounts: []const sandbox.namespace.Mount,
    rules: []const sandbox.Config.Rule,
    argv: []const []const u8,
    middle: sandbox.Middle = .{},
    term: std.process.Child.Term = undefined,
    spawn_err: ?anyerror = null,
    /// Set with `.release` after `term` or `spawn_err` is already written, so
    /// an `.acquire` load of it makes a plain read of either one safe.
    done: std.atomic.Value(bool) = .init(false),

    fn run(self: *ThreadedSpawn) void {
        self.term = sandbox.spawn(self.allocator, .{
            .root = self.root,
            .mounts = self.mounts,
            .rules = self.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, self.argv, null, &self.middle) catch |err| {
            self.spawn_err = err;
            self.done.store(true, .release);
            return;
        };
        self.done.store(true, .release);
    }

    fn waitForMiddlePid(self: *ThreadedSpawn) linux.pid_t {
        var waited: u64 = 0;
        while (waited < probe_wait_bound_ns) : (waited += probe_wait_step_ns) {
            const pid = @atomicLoad(linux.pid_t, &self.middle.pid, .acquire);
            if (pid != 0) return pid;
            if (self.done.load(.acquire)) return 0;
            _ = linux.nanosleep(&.{ .sec = 0, .nsec = @intCast(probe_wait_step_ns) }, null);
        }
        return @atomicLoad(linux.pid_t, &self.middle.pid, .acquire);
    }

    /// False when the bound ran out, which is a real answer: a `spawn` that
    /// never returns after a signal is a fault.
    fn waitForDone(self: *ThreadedSpawn) bool {
        var waited: u64 = 0;
        while (waited < probe_wait_bound_ns) : (waited += probe_wait_step_ns) {
            if (self.done.load(.acquire)) return true;
            _ = linux.nanosleep(&.{ .sec = 0, .nsec = @intCast(probe_wait_step_ns) }, null);
        }
        return self.done.load(.acquire);
    }

    /// Read in every branch that gives up on a bounded wait, because a sandbox
    /// that never came up makes those waits run out first.
    fn endIfSandboxRefused(self: *ThreadedSpawn) void {
        if (!self.done.load(.acquire)) return;
        if (self.spawn_err) |err| endIfNothingMeasured(err);
    }

    /// Through the handle, which reaches the middle process only and still ends
    /// the whole call. A `kill` on the negated number is the fault to avoid.
    fn killCall(self: *ThreadedSpawn) void {
        if (@atomicLoad(linux.pid_t, &self.middle.pid, .acquire) == 0) return;
        sandbox.signalMiddle(self.middle.fd, .KILL) catch {};
    }

    /// Only after `spawn` has returned. See `sandbox.Middle`.
    fn closeHandle(self: *ThreadedSpawn) void {
        sandbox.closeMiddle(&self.middle);
    }
};

/// `baseEscapeConfig` on its own gives no writable path.
fn workEscapeConfig(arena: std.mem.Allocator, root: []const u8) !struct {
    mounts: []const sandbox.namespace.Mount,
    rules: []const sandbox.Config.Rule,
} {
    const work = try std.fs.path.join(arena, &.{ root, "work" });
    try makeTestDir(arena, work);

    const base = try baseEscapeConfig(arena);
    const mounts = try std.mem.concat(arena, sandbox.namespace.Mount, &.{
        base.mounts,
        &.{.{ .bind = .{ .source = work, .target = "/work", .read_only = false } }},
    });
    const rules = try std.mem.concat(arena, sandbox.Config.Rule, &.{
        base.rules,
        &.{.{ .path = "/work", .access = sandbox.landlock.AccessFs.read_write }},
    });
    return .{ .mounts = mounts, .rules = rules };
}

const file_over_file_content = "chock file over file probe content\n";

/// Written into the root but named in no rule, so only a missing Landlock
/// layer could let the read through.
const spawned_landlock_target = "/unguarded/marker";

/// A mount target made as a directory for a file source gives ENOTDIR.
fn enterFileOverFileTestRoot(arena: std.mem.Allocator, root: []const u8) !void {
    const source = try std.fs.path.join(arena, &.{ root, "source-file" });
    try writeTestFile(arena, source, file_over_file_content);

    enterOrEndUnmeasured(.{ .network = .none, .mount = true });
    try sandbox.namespace.buildRoot(arena, root, &.{
        .{ .bind = .{ .source = source, .target = "/marker", .read_only = false } },
    }, null);
    try sandbox.namespace.pivotInto(arena, root, null);
}

/// The submount has to exist before buildRoot binds "guarded" onto itself,
/// because a bind mount carries only the submounts already under its source.
fn enterSubmountTestRoot(arena: std.mem.Allocator, root: []const u8) !void {
    const guarded = try std.fs.path.join(arena, &.{ root, "guarded" });
    const sub = try std.fs.path.join(arena, &.{ guarded, "sub" });
    try makeTestDir(arena, guarded);

    enterOrEndUnmeasured(.{ .network = .none, .mount = true });

    try makeTestDir(arena, sub);
    try mountTmpfs(arena, sub);

    try sandbox.namespace.buildRoot(arena, root, &.{
        .{ .bind = .{ .source = guarded, .target = "/guarded", .read_only = true } },
    }, null);
    try sandbox.namespace.pivotInto(arena, root, null);
}

fn mountTmpfs(arena: std.mem.Allocator, path: []const u8) !void {
    const path_z = try arena.dupeZ(u8, path);
    if (linux.errno(linux.mount(null, path_z.ptr, "tmpfs", 0, 0)) != .SUCCESS) {
        return error.SetupFailed;
    }
}

fn createShmSegment() !usize {
    const ipc_private: usize = 0;
    const ipc_creat: usize = 0o1000;
    const size: usize = 4096;
    const shmid = linux.syscall3(.shmget, ipc_private, size, ipc_creat | 0o600);
    if (linux.errno(shmid) != .SUCCESS) return error.ShmgetFailed;
    return shmid;
}

/// IPC_RMID destroys a segment the moment it has zero attaches, so this must
/// run after the shmat attempt.
fn removeShmSegment(shmid: usize) void {
    const ipc_rmid: usize = 0;
    _ = linux.syscall3(.shmctl, shmid, ipc_rmid, 0);
}

fn outsideDir(arena: std.mem.Allocator, root: []const u8) ![:0]const u8 {
    return std.fmt.allocPrintSentinel(arena, "{s}/outside", .{root}, 0);
}

/// Every setup failure must reach the caller as an error, or a broken ruleset
/// reads as one that refused the operation.
fn enterLandlockWriteTestRoot(arena: std.mem.Allocator, root: []const u8) ![:0]const u8 {
    const inside = try std.fmt.allocPrintSentinel(arena, "{s}/inside", .{root}, 0);
    try makeTestDir(arena, inside);
    try makeTestDir(arena, try outsideDir(arena, root));

    const abi = try sandbox.landlock.probeAbi();
    var ruleset = try sandbox.landlock.Ruleset.init(abi, null);
    try ruleset.allowPath(inside, sandbox.landlock.AccessFs.read_write, null);
    try ruleset.restrictSelf(null);
    // The kernel holds its own reference once restrictSelf succeeds.
    ruleset.deinit();
    return inside;
}

fn enterLandlockTruncateTestRoot(arena: std.mem.Allocator, root: []const u8) !struct {
    inside_file: [:0]const u8,
    outside_file: [:0]const u8,
} {
    const inside = try std.fmt.allocPrintSentinel(arena, "{s}/inside", .{root}, 0);
    const inside_file = try std.fmt.allocPrintSentinel(arena, "{s}/file", .{inside}, 0);
    try makeTestDir(arena, inside);
    try writeTestFile(arena, inside_file, "chock landlock truncate probe content\n");

    const outside_file = try std.fmt.allocPrintSentinel(arena, "{s}/truncate-file", .{try outsideDir(arena, root)}, 0);
    try makeTestDir(arena, try outsideDir(arena, root));
    try writeTestFile(arena, outside_file, "chock landlock truncate probe content\n");

    const abi = try sandbox.landlock.probeAbi();
    var ruleset = try sandbox.landlock.Ruleset.init(abi, null);
    try ruleset.allowPath(inside, sandbox.landlock.AccessFs.read_write, null);
    try ruleset.restrictSelf(null);
    ruleset.deinit();
    return .{ .inside_file = inside_file, .outside_file = outside_file };
}

/// 1 is the pass, and it means `EPERM`. Two of the three probes pass the
/// descriptor -1, so a call that got through would fail with `EBADF` anyway.
fn ringRefusal(rc: usize) u8 {
    return switch (linux.errno(rc)) {
        .SUCCESS => 0,
        .PERM => 1,
        else => 4,
    };
}

// Zig 0.16 removed std.process.argsAlloc. A hosted main can instead take
// std.process.Init.Minimal as its first parameter, and the runtime fills it in.
pub fn main(init: std.process.Init.Minimal) !u8 {
    return runOperation(init) catch |err| {
        // The machine, and not the boundary: the sandbox could not be built at
        // all. Nothing printed, for the reason `enterOrEndUnmeasured` gives.
        if (err == error.NamespaceFailed) return sandbox.namespace.nothing_measured_exit_status;
        return err;
    };
}

fn runOperation(init: std.process.Init.Minimal) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("usage: probe <operation> [host-id]\n", .{});
        return 2;
    }
    // Every "spawn-" operation lets sandbox.spawn build the whole sandbox,
    // including its own unshare, inside a child. A filter installed here is
    // inherited across that fork and would kill that child's unshare.
    const builds_own_root = std.mem.eql(u8, args[1], "read-home") or
        std.mem.eql(u8, args[1], "write-readonly") or
        std.mem.eql(u8, args[1], "delete-mounted-file") or
        std.mem.eql(u8, args[1], "write-readonly-submount") or
        std.mem.eql(u8, args[1], "file-bind-content") or
        std.mem.eql(u8, args[1], "deny-symlink-outside") or
        std.mem.eql(u8, args[1], "bind-source-symlink") or
        std.mem.eql(u8, args[1], "deny-intermediate-symlink") or
        std.mem.eql(u8, args[1], "spawn-ptrace") or
        std.mem.eql(u8, args[1], "spawn-landlock-escape") or
        std.mem.eql(u8, args[1], "spawn-network-escape") or
        std.mem.eql(u8, args[1], "spawn-signal-host") or
        std.mem.eql(u8, args[1], "spawn-shm-attach") or
        std.mem.eql(u8, args[1], "spawn-report-pid") or
        std.mem.eql(u8, args[1], "spawn-default-signal") or
        std.mem.eql(u8, args[1], "spawn-keeper-reaps") or
        std.mem.eql(u8, args[1], "spawn-stdin-devnull") or
        std.mem.eql(u8, args[1], "spawn-stdin-pipe") or
        std.mem.eql(u8, args[1], "spawn-proc-mask") or
        std.mem.eql(u8, args[1], "spawn-proc-live") or
        std.mem.eql(u8, args[1], "spawn-caps-drop") or
        std.mem.eql(u8, args[1], "spawn-open-fd-set") or
        std.mem.eql(u8, args[1], "spawn-open-fd-set-filtered") or
        std.mem.eql(u8, args[1], "spawn-supervisor-audit") or
        std.mem.eql(u8, args[1], "spawn-syscall-audit") or
        std.mem.eql(u8, args[1], "spawn-syscall-audit-off") or
        std.mem.eql(u8, args[1], "spawn-syscall-audit-daemon") or
        std.mem.eql(u8, args[1], "spawn-path-audit") or
        std.mem.eql(u8, args[1], "spawn-path-audit-off") or
        std.mem.eql(u8, args[1], "spawn-path-audit-dynamic") or
        std.mem.eql(u8, args[1], "spawn-path-audit-killed") or
        std.mem.eql(u8, args[1], "spawn-path-audit-stopped") or
        std.mem.eql(u8, args[1], "spawn-signal-middle-setsid") or
        std.mem.eql(u8, args[1], "spawn-memfd-exec") or
        std.mem.eql(u8, args[1], "spawn-handle-escape") or
        std.mem.eql(u8, args[1], "spawn-vsock") or
        std.mem.eql(u8, args[1], "spawn-proc-self-mem-write-landlock") or
        std.mem.eql(u8, args[1], "spawn-proc-self-mem-write-mount") or
        std.mem.eql(u8, args[1], "spawn-setns-proc1") or
        std.mem.eql(u8, args[1], "spawn-cgroup-remount") or
        std.mem.eql(u8, args[1], "cgroup-surface") or
        std.mem.eql(u8, args[1], "spawn-setup-fault-named-stderr") or
        std.mem.eql(u8, args[1], "spawn-setup-fault-default-stderr") or
        std.mem.eql(u8, args[1], "spawn-setup-fault-closed-stderr") or
        std.mem.eql(u8, args[1], "spawn-forge-exit") or
        std.mem.eql(u8, args[1], "spawn-signal-middle") or
        std.mem.eql(u8, args[1], "spawn-signal-middle-forked") or
        std.mem.eql(u8, args[1], "spawn-signal-middle-handled") or
        std.mem.eql(u8, args[1], "spawn-signal-group") or
        std.mem.eql(u8, args[1], "spawn-approval-socket") or
        std.mem.eql(u8, args[1], "spawn-group-press") or
        std.mem.startsWith(u8, args[1], "spawn-filtered-") or
        std.mem.startsWith(u8, args[1], "spawn-routed-") or
        std.mem.eql(u8, args[1], "spawn-device-place") or
        std.mem.eql(u8, args[1], "spawn-device-hidden-denied") or
        std.mem.eql(u8, args[1], "spawn-device-with-broker") or
        std.mem.eql(u8, args[1], "spawn-device-children") or
        std.mem.eql(u8, args[1], "spawn-device-children-none") or
        std.mem.eql(u8, args[1], "spawn-fork-bomb") or
        std.mem.eql(u8, args[1], "spawn-fork-bomb-unbounded") or
        std.mem.eql(u8, args[1], "spawn-mem-bomb") or
        std.mem.eql(u8, args[1], "spawn-mem-bomb-unbounded") or
        std.mem.eql(u8, args[1], "spawn-mem-bomb-cgroup") or
        std.mem.eql(u8, args[1], "spawn-fd-bomb") or
        std.mem.eql(u8, args[1], "spawn-fd-bomb-unbounded") or
        std.mem.startsWith(u8, args[1], "spawn-disk-");

    // The Landlock write and truncate probes enter no namespace, so they are
    // not part of builds_own_root, but they still need scratch space.
    const needs_scratch_root = builds_own_root or
        std.mem.eql(u8, args[1], "landlock-write-outside") or
        std.mem.eql(u8, args[1], "landlock-write-inside") or
        std.mem.eql(u8, args[1], "landlock-truncate-outside") or
        std.mem.eql(u8, args[1], "landlock-truncate-inside");

    // These carry one more argument: a host pid, a host shmid, or a key
    // description, made outside every namespace, because none can pick one.
    const needs_id_arg = std.mem.eql(u8, args[1], "spawn-signal-host") or
        std.mem.eql(u8, args[1], "spawned-signal-host") or
        std.mem.eql(u8, args[1], "spawn-shm-attach") or
        std.mem.eql(u8, args[1], "spawned-shm-attach") or
        // The approval socket is on a path no mount list names, so escape.zig
        // makes a real one and hands the path down.
        std.mem.eql(u8, args[1], "spawn-approval-socket") or
        std.mem.eql(u8, args[1], "spawned-approval-socket") or
        // Outside the sandbox root, so a symlink target is no part of it.
        std.mem.eql(u8, args[1], "deny-symlink-outside") or
        std.mem.eql(u8, args[1], "bind-source-symlink") or
        std.mem.eql(u8, args[1], "deny-intermediate-symlink") or
        // Only the caller knows which number its open descriptor landed on.
        std.mem.eql(u8, args[1], "spawned-stdin-pipe") or
        // The child cannot read the network mode of the sandbox it woke in.
        std.mem.eql(u8, args[1], "spawned-open-fd-set") or
        // Both ports are ephemeral, so no rule and no constant could name them.
        std.mem.startsWith(u8, args[1], "spawned-filtered-") or
        std.mem.startsWith(u8, args[1], "routed-") or
        std.mem.eql(u8, args[1], "session-keyring-fresh");

    // The scratch root comes off the command line, so this probe never
    // invents a location of its own.
    const expected_args: usize = 2 +
        @as(usize, if (needs_scratch_root) 1 else 0) +
        @as(usize, if (needs_id_arg) 1 else 0);
    if (args.len != expected_args) {
        std.debug.print("usage: probe <operation> [root] [id]\n", .{});
        return 2;
    }
    var next_arg: usize = 2;
    const root_arg: []const u8 = blk: {
        if (!needs_scratch_root) break :blk "";
        const value = args[next_arg];
        next_arg += 1;
        break :blk value;
    };
    const id_arg: []const u8 = blk: {
        if (!needs_id_arg) break :blk "";
        const value = args[next_arg];
        next_arg += 1;
        break :blk value;
    };

    // A "spawned-" operation does no setup at all, not even its own filter, and
    // must have no path of its own to the outcome it checks.
    const spawned = std.mem.startsWith(u8, args[1], "spawned-");

    // A "netns-" operation enters the namespaces instead of installing the
    // filter, because `unshare` is a blocked call. The mount tree operations
    // enter them themselves, so this block must not enter for those.
    if (spawned) {
        // Nothing to set up. See the comment on `spawned` above.
    } else if (std.mem.startsWith(u8, args[1], "netns-")) {
        // A setup failure has an exit code of its own, so it never reads as
        // the kernel refusing the probed operation.
        enterOrEndUnmeasured(.{});
    } else if (std.mem.eql(u8, args[1], "session-keyring-fresh")) {
        // Nothing to set up here either. No filter goes on, because the read
        // back calls request_key, which is itself a blocked call.
    } else if (!builds_own_root) {
        // Several operations below take a plain exit code of 1 as their
        // "refused" pass, so a failed filter build needs one of its own. The
        // relaxed filter gives up the write and execute rule, and nothing else.
        const relaxed_wx = std.mem.endsWith(u8, args[1], "-relaxed");
        const insns = sandbox.seccomp.build(arena, .{ .strict_wx = !relaxed_wx }) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        sandbox.seccomp.install(sandbox.bpf.Prog.init(insns)) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
    }

    if (std.mem.eql(u8, args[1], "netns-connect")) {
        // A failed connect alone proves nothing on a machine with no route.
        // /proc/net/route prints an "Iface" header when it prints anything, but
        // this kernel prints zero bytes while `lo` is down.
        var route_buf: [4096]u8 = undefined;
        const route_fd = linux.open("/proc/net/route", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(route_fd) != .SUCCESS) {
            std.debug.print(
                "could not open /proc/net/route: {s}\n",
                .{@tagName(linux.errno(route_fd))},
            );
            return 4;
        }
        const route_handle: i32 = @intCast(route_fd);
        defer _ = linux.close(route_handle);

        const read_rc = linux.read(route_handle, &route_buf, route_buf.len);
        if (linux.errno(read_rc) != .SUCCESS) {
            std.debug.print(
                "could not read /proc/net/route: {s}\n",
                .{@tagName(linux.errno(read_rc))},
            );
            return 4;
        }
        var route_rows: usize = 0;
        var route_line_it = std.mem.splitScalar(u8, route_buf[0..read_rc], '\n');
        while (route_line_it.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "Iface")) continue; // the header line
            route_rows += 1;
        }
        if (route_rows != 0) {
            std.debug.print(
                "routing table has a route, the network namespace was not entered\n",
                .{},
            );
            return 4;
        }

        // From the connect side the failure must be ENETUNREACH.
        const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
        if (linux.errno(fd) != .SUCCESS) return 1;
        var addr = std.mem.zeroes(linux.sockaddr.in);
        addr.family = linux.AF.INET;
        addr.port = std.mem.nativeToBig(u16, 53);
        // 1.1.1.1
        addr.addr = std.mem.nativeToBig(u32, 0x01010101);
        const rc = linux.connect(@intCast(fd), @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
        const connect_errno = linux.errno(rc);
        if (connect_errno != .NETUNREACH) {
            std.debug.print(
                "connect did not fail with ENETUNREACH, got: {s}\n",
                .{@tagName(connect_errno)},
            );
            return 4;
        }
        return 1;
    }
    if (std.mem.eql(u8, args[1], "netns-loopback")) {
        // A network namespace must still permit a unix socket.
        const fd = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM, 0);
        return if (linux.errno(fd) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "netns-af-packet")) {
        // AF_PACKET moves whole link layer frames and answers to no route, so
        // what holds it back is which interfaces the namespace has.
        const eth_p_all: u16 = 0x0003;
        const fd_rc = linux.socket(linux.AF.PACKET, linux.SOCK.RAW, std.mem.nativeToBig(u16, eth_p_all));
        if (linux.errno(fd_rc) != .SUCCESS) {
            std.debug.print("netns-af-packet: socket(AF_PACKET): {s}\n", .{@tagName(linux.errno(fd_rc))});
            return 4;
        }
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);

        // /proc/net/dev is namespace aware whichever mount serves the file, and
        // anything beyond "lo" means this operation is not about what it claims.
        var dev_buf: [4096]u8 = undefined;
        const dev_fd_rc = linux.open("/proc/net/dev", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(dev_fd_rc) != .SUCCESS) {
            std.debug.print("netns-af-packet: open /proc/net/dev: {s}\n", .{@tagName(linux.errno(dev_fd_rc))});
            return 4;
        }
        const dev_fd: i32 = @intCast(dev_fd_rc);
        defer _ = linux.close(dev_fd);
        const dev_read = linux.read(dev_fd, &dev_buf, dev_buf.len);
        if (linux.errno(dev_read) != .SUCCESS) {
            std.debug.print("netns-af-packet: read /proc/net/dev: {s}\n", .{@tagName(linux.errno(dev_read))});
            return 4;
        }
        var iface_count: usize = 0;
        var saw_lo = false;
        var dev_lines = std.mem.splitScalar(u8, dev_buf[0..dev_read], '\n');
        while (dev_lines.next()) |line| {
            // Both header lines carry a colon of their own kind.
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const name = std.mem.trim(u8, line[0..colon], " \t");
            if (name.len == 0 or std.mem.eql(u8, name, "Inter-|") or std.mem.eql(u8, name, "face")) continue;
            iface_count += 1;
            if (std.mem.eql(u8, name, "lo")) saw_lo = true;
        }
        if (!saw_lo or iface_count != 1) {
            std.debug.print(
                "netns-af-packet: expected only lo, found {d} interface(s)\n",
                .{iface_count},
            );
            return 4;
        }

        // One interface is left, lo, which namespace.enter leaves down.
        // ENETDOWN, and not a route or permission failure, is the answer.
        var ifr: linux.ifreq = std.mem.zeroes(linux.ifreq);
        @memcpy(ifr.ifrn.name[0..2], "lo");
        const ioctl_rc = linux.ioctl(fd, linux.SIOCGIFINDEX, @intFromPtr(&ifr));
        if (linux.errno(ioctl_rc) != .SUCCESS) {
            std.debug.print("netns-af-packet: SIOCGIFINDEX lo: {s}\n", .{@tagName(linux.errno(ioctl_rc))});
            return 4;
        }
        const ifindex = ifr.ifru.ivalue;

        var sll = std.mem.zeroes(linux.sockaddr.ll);
        sll.family = linux.AF.PACKET;
        sll.ifindex = ifindex;
        sll.protocol = std.mem.nativeToBig(u16, eth_p_all);
        var frame = [_]u8{0} ** 32;
        const send_rc = linux.sendto(fd, &frame, frame.len, 0, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll));
        const send_errno = linux.errno(send_rc);
        if (send_errno != .NETDOWN) {
            std.debug.print("netns-af-packet: sendto did not fail with ENETDOWN, got {s}\n", .{@tagName(send_errno)});
            return 4;
        }
        return 1;
    }

    if (std.mem.eql(u8, args[1], "session-keyring-fresh")) {
        // id_arg describes a key escape.zig planted in the session keyring this
        // process inherited across the fork. Finding it means the join failed.
        sandbox.Sandbox.joinFreshSessionKeyring(std.posix.STDERR_FILENO) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };

        const description_z = arena.dupeZ(u8, id_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        // "user" matches the type escape.zig used when it planted the key.
        const key_type = "user";
        const rc = linux.syscall4(
            .request_key,
            @intFromPtr(key_type.ptr),
            @intFromPtr(description_z.ptr),
            0,
            0,
        );
        const find_errno = linux.errno(rc);
        if (find_errno == .SUCCESS) return 0; // Found the host's key. The join did nothing.
        // A fresh keyring holds no such key, so the kernel answers ENOKEY.
        return if (find_errno == .NOKEY) 1 else 5;
    }

    // The operations below are the "spawned-" ones. No code above this point
    // ran for them, so what they meet is a real applyLayers' own doing.
    if (std.mem.eql(u8, args[1], "spawned-handle-escape")) {
        // `name_to_handle_at` turns a path into an opaque handle, and reopening
        // it names no path for a Landlock rule to match.
        const target: [:0]const u8 = "/work/handle-target";
        const write_fd_rc = linux.open(target, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        if (linux.errno(write_fd_rc) != .SUCCESS) {
            std.debug.print("spawned-handle-escape: create /work/handle-target: {s}\n", .{@tagName(linux.errno(write_fd_rc))});
            return 5;
        }
        const write_fd: i32 = @intCast(write_fd_rc);
        _ = linux.write(write_fd, "handle\n", 7);
        _ = linux.close(write_fd);

        // `name_to_handle_at` encodes what a path lookup already reached.
        var raw: [136]u8 align(@alignOf(linux.file_handle)) = undefined;
        const handle: *linux.file_handle = @ptrCast(&raw);
        handle.handle_bytes = 128;
        var mount_id: i32 = undefined;
        const encode_rc = linux.name_to_handle_at(linux.AT.FDCWD, target, handle, &mount_id, 0);
        if (linux.errno(encode_rc) != .SUCCESS) {
            std.debug.print("spawned-handle-escape: name_to_handle_at: {s}\n", .{@tagName(linux.errno(encode_rc))});
            return 5;
        }

        // Not `O_PATH`: a path only descriptor carries no file operations.
        const mount_fd_rc = linux.open("/work", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        if (linux.errno(mount_fd_rc) != .SUCCESS) {
            std.debug.print("spawned-handle-escape: open /work: {s}\n", .{@tagName(linux.errno(mount_fd_rc))});
            return 5;
        }
        const mount_fd: i32 = @intCast(mount_fd_rc);

        const open_rc = linux.syscall3(
            .open_by_handle_at,
            @as(usize, @bitCast(@as(isize, mount_fd))),
            @intFromPtr(handle),
            0,
        );
        std.debug.print("spawned-handle-escape: open_by_handle_at: {s}\n", .{@tagName(linux.errno(open_rc))});
        return if (linux.errno(open_rc) == .SUCCESS) 0 else 6;
    }

    if (std.mem.eql(u8, args[1], "spawned-ptrace")) {
        const rc = linux.syscall4(.ptrace, 0, 0, 0, 0);
        // An installed filter kills this process before this line runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "spawned-vsock")) {
        // The filter kills this on the domain argument alone, before the kernel
        // reads whether this host has a vsock transport.
        const rc = linux.socket(linux.AF.VSOCK, linux.SOCK.STREAM, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "spawned-setns-proc1")) {
        // A kernel can refuse the keeper's namespace fd once it drops
        // capabilities, so this process's own fd is the control.
        var fd_rc = linux.open("/proc/1/ns/mnt", .{ .ACCMODE = .RDONLY }, 0);
        const init_errno = linux.errno(fd_rc);
        if (init_errno == .ACCES or init_errno == .PERM) {
            fd_rc = linux.open("/proc/self/ns/mnt", .{ .ACCMODE = .RDONLY }, 0);
        } else if (init_errno != .SUCCESS) {
            std.debug.print("spawned-setns-proc1: open /proc/1/ns/mnt: {s}\n", .{@tagName(init_errno)});
            return 5;
        }
        if (linux.errno(fd_rc) != .SUCCESS) {
            std.debug.print("spawned-setns-proc1: open control namespace: {s}\n", .{@tagName(linux.errno(fd_rc))});
            return 6;
        }
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);

        // setns sits on blocked_calls, so the filter reads neither the fd nor
        // the namespace it names.
        const rc = linux.setns(fd, 0);
        // The filter kills the process, so this line never runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "spawned-proc-self-mem-write-landlock")) {
        // Neither ptrace nor process_vm_writev is called: this is open() and
        // write() on a regular file. The kernel answers EROFS and not Landlock's
        // EACCES, because an O_WRONLY open meets the mount's own mark first.
        const fd_rc = linux.open("/proc/self/mem", .{ .ACCMODE = .WRONLY }, 0);
        const open_errno = linux.errno(fd_rc);
        if (open_errno == .SUCCESS) {
            _ = linux.close(@intCast(fd_rc));
            return 0;
        }
        return if (open_errno == .ROFS) 1 else 5;
    }

    if (std.mem.eql(u8, args[1], "spawned-proc-self-mem-write-mount")) {
        // write_file is granted on /proc on purpose, so a refusal cannot be
        // Landlock's doing. No real caller grants that.
        const fd_rc = linux.open("/proc/self/mem", .{ .ACCMODE = .WRONLY }, 0);
        const open_errno = linux.errno(fd_rc);
        if (open_errno == .SUCCESS) {
            _ = linux.close(@intCast(fd_rc));
            return 0;
        }
        return if (open_errno == .ROFS) 1 else 5;
    }

    if (std.mem.eql(u8, args[1], "spawned-cgroup-remount")) {
        // namespace.enter never takes CLONE_NEWCGROUP, so a fresh "cgroup2"
        // mount would see the whole host hierarchy. The filter kills it first.
        const rc = linux.mount("cgroup2", "/nonexistent-cgroup-mount", "cgroup2", 0, 0);
        // The filter kills the process, so this line never runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "spawned-memfd-exec")) {
        // Closed by a `seccomp.build` rule that kills `execveat` whenever its
        // `flags` set `AT_EMPTY_PATH`.
        const self_rc = linux.open("/probe", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(self_rc) != .SUCCESS) {
            std.debug.print("spawned-memfd-exec: open /probe: {s}\n", .{@tagName(linux.errno(self_rc))});
            return 5;
        }
        const self_fd: i32 = @intCast(self_rc);
        defer _ = linux.close(self_fd);

        var bytes: std.ArrayList(u8) = .empty;
        var chunk: [65536]u8 = undefined;
        while (true) {
            const n = linux.read(self_fd, &chunk, chunk.len);
            const read_errno = linux.errno(n);
            if (read_errno == .INTR) continue;
            if (read_errno != .SUCCESS) {
                std.debug.print("spawned-memfd-exec: read /probe: {s}\n", .{@tagName(read_errno)});
                return 5;
            }
            if (n == 0) break;
            bytes.appendSlice(arena, chunk[0..n]) catch return 5;
        }

        // A ruleset that handles the execute right denies it wherever no rule
        // grants it, and /work has no such rule.
        const disk_path: [:0]const u8 = "/work/payload";
        const disk_fd_rc = linux.open(disk_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o755);
        if (linux.errno(disk_fd_rc) != .SUCCESS) {
            std.debug.print("spawned-memfd-exec: create /work/payload: {s}\n", .{@tagName(linux.errno(disk_fd_rc))});
            return 5;
        }
        const disk_fd: i32 = @intCast(disk_fd_rc);
        {
            var written: usize = 0;
            while (written < bytes.items.len) {
                const n = linux.write(disk_fd, bytes.items.ptr + written, bytes.items.len - written);
                if (linux.errno(n) != .SUCCESS) {
                    std.debug.print("spawned-memfd-exec: write /work/payload: {s}\n", .{@tagName(linux.errno(n))});
                    _ = linux.close(disk_fd);
                    return 5;
                }
                written += n;
            }
        }
        _ = linux.close(disk_fd);

        const empty_envp = arena.allocSentinel(?[*:0]const u8, 0, null) catch return 5;
        const disk_argv = arena.allocSentinel(?[*:0]const u8, 2, null) catch return 5;
        disk_argv[0] = arena.dupeZ(u8, "probe") catch return 5;
        disk_argv[1] = arena.dupeZ(u8, "spawned-memfd-direct-should-be-refused") catch return 5;

        const direct_rc = linux.execve(disk_path, disk_argv, empty_envp);
        // execve only returns on failure.
        const direct_errno = linux.errno(direct_rc);
        if (direct_errno != .ACCES) {
            std.debug.print(
                "spawned-memfd-exec: on-disk execve did not fail with EACCES, got {s}\n",
                .{@tagName(direct_errno)},
            );
            return 5;
        }

        // memfd_create makes an anonymous file with no directory entry, so a
        // path based rule has nothing to match. The call itself grants nothing.
        const memfd_name: [:0]const u8 = "chock-probe-memfd";
        const memfd_rc = linux.memfd_create(memfd_name, 0);
        if (linux.errno(memfd_rc) != .SUCCESS) {
            std.debug.print("spawned-memfd-exec: memfd_create: {s}\n", .{@tagName(linux.errno(memfd_rc))});
            return 6;
        }
        const memfd: i32 = @intCast(memfd_rc);
        {
            var written: usize = 0;
            while (written < bytes.items.len) {
                const n = linux.write(memfd, bytes.items.ptr + written, bytes.items.len - written);
                if (linux.errno(n) != .SUCCESS) {
                    std.debug.print("spawned-memfd-exec: write memfd: {s}\n", .{@tagName(linux.errno(n))});
                    return 6;
                }
                written += n;
            }
        }

        const memfd_argv = arena.allocSentinel(?[*:0]const u8, 2, null) catch return 5;
        memfd_argv[0] = arena.dupeZ(u8, "memfd-probe") catch return 5;
        memfd_argv[1] = arena.dupeZ(u8, "spawned-memfd-landed") catch return 5;

        // `AT_EMPTY_PATH` lets `execveat` take an empty path relative to a
        // descriptor, which is the flag the filter reads.
        const exec_rc = linux.execveat(memfd, "", memfd_argv, empty_envp, .{ .SYMLINK_NOFOLLOW = false, .EMPTY_PATH = true });
        std.debug.print("spawned-memfd-exec: execveat on the memfd: {s}\n", .{@tagName(linux.errno(exec_rc))});
        return 6;
    }

    if (std.mem.eql(u8, args[1], "spawned-memfd-landed")) {
        // Seccomp installs once and no execve can shed it, so the ptrace call
        // must still die here.
        const rc = linux.syscall4(.ptrace, 0, 0, 0, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.startsWith(u8, args[1], "spawned-filtered-")) {
        const ports = splitPorts(id_arg) orelse {
            std.debug.print("the two ports a filtered child is given are not two numbers: {s}\n", .{id_arg});
            return 3;
        };
        const granted_port = ports[0];
        const other_port = ports[1];

        if (std.mem.eql(u8, args[1], "spawned-filtered-connect")) {
            // The errno is the whole test: an empty network namespace answers
            // `ENETUNREACH` on its own, filter or no filter.
            const socket_rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
            if (linux.errno(socket_rc) != .SUCCESS) {
                // Making a socket is not what is refused.
                std.debug.print("socket: {t}\n", .{linux.errno(socket_rc)});
                return 3;
            }
            const fd: i32 = @intCast(socket_rc);
            defer _ = linux.close(fd);

            const address = linux.sockaddr.in{
                .port = std.mem.nativeToBig(u16, granted_port),
                .addr = std.mem.nativeToBig(u32, 0x7f000001),
            };
            const rc = linux.connect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in));
            const err = linux.errno(rc);
            if (err == .SUCCESS) return 0; // Reached a host on its own.
            if (err == .PERM) return 1; // The filter refused it, which is the design.
            std.debug.print("connect answered {t}, not EPERM\n", .{err});
            return 5;
        }

        if (std.mem.eql(u8, args[1], "spawned-filtered-grant")) {
            const answer = sandbox.net_broker.ask(
                sandbox.net_broker.fd_number,
                filtered_host,
                granted_port,
            ) catch |err| {
                std.debug.print("ask failed: {s}\n", .{@errorName(err)});
                return 3;
            };
            const handle = switch (answer) {
                .granted => |fd| fd,
                .refused => {
                    std.debug.print("a host the policy permits was refused\n", .{});
                    return 3;
                },
            };
            defer _ = linux.close(handle);

            // The caller accepts on that listener and reads these bytes back.
            const written = linux.write(handle, filtered_token, filtered_token.len);
            if (linux.errno(written) != .SUCCESS or written != filtered_token.len) {
                std.debug.print("the granted descriptor would not carry bytes\n", .{});
                return 3;
            }

            // And it cannot be aimed anywhere else. `EPERM` is the filter. A
            // success is an escape, and anything else must not read as a pass.
            const reaim = tryToReaim(handle, other_port);
            if (reaim == .SUCCESS) return 1;
            if (reaim != .PERM) {
                std.debug.print("re-aiming answered {t}, not EPERM\n", .{reaim});
                return 5;
            }
            return 0;
        }

        if (std.mem.eql(u8, args[1], "spawned-filtered-grant-and-device")) {
            // This program asks the broker and waits for the device node, so it
            // ends well only if one loop served both descriptors of one call.
            const grant_refused: u8 = 3;
            const never_appeared: u8 = 5;
            const read_failed: u8 = 6;
            const wrong_content: u8 = 7;

            const answer = sandbox.net_broker.ask(
                sandbox.net_broker.fd_number,
                filtered_host,
                granted_port,
            ) catch |err| {
                std.debug.print("ask failed: {s}\n", .{@errorName(err)});
                return grant_refused;
            };
            switch (answer) {
                .granted => |fd| _ = linux.close(fd),
                .refused => {
                    std.debug.print("a host the policy permits was refused\n", .{});
                    return grant_refused;
                },
            }

            // A bind mount needs its target to exist first, so the helper makes
            // an empty file and mounts over it. An open with no bytes is early.
            var attempt: usize = 0;
            var opened = false;
            while (attempt < 200) : (attempt += 1) {
                const fd_rc = linux.open(device_probe_path, .{ .ACCMODE = .RDONLY }, 0);
                if (linux.errno(fd_rc) == .SUCCESS) {
                    opened = true;
                    const fd: i32 = @intCast(fd_rc);
                    var buffer: [64]u8 = undefined;
                    const n = linux.read(fd, &buffer, buffer.len);
                    _ = linux.close(fd);
                    if (linux.errno(n) != .SUCCESS) return read_failed;
                    if (n != 0) {
                        return if (std.mem.eql(u8, buffer[0..n], device_probe_content)) 0 else wrong_content;
                    }
                }
                var pause: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
                _ = linux.nanosleep(&pause, null);
            }
            return if (opened) wrong_content else never_appeared;
        }

        if (std.mem.eql(u8, args[1], "spawned-filtered-refused")) {
            // A refusal must tell this process nothing, so the descriptor
            // table is the whole check.
            const before = openDescriptorCount();
            const answer = sandbox.net_broker.ask(
                sandbox.net_broker.fd_number,
                filtered_refused_host,
                granted_port,
            ) catch |err| {
                std.debug.print("ask failed: {s}\n", .{@errorName(err)});
                return 3;
            };
            switch (answer) {
                .granted => |fd| {
                    _ = linux.close(fd);
                    return 1; // A host the policy refuses was reached.
                },
                .refused => {},
            }
            if (openDescriptorCount() != before) {
                std.debug.print("a refusal changed this process's descriptor table\n", .{});
                return 5;
            }

            // A permitted host on the same socket is still granted.
            const good = sandbox.net_broker.ask(
                sandbox.net_broker.fd_number,
                filtered_host,
                granted_port,
            ) catch |err| {
                std.debug.print("the second ask failed: {s}\n", .{@errorName(err)});
                return 3;
            };
            switch (good) {
                .granted => |fd| {
                    _ = linux.close(fd);
                    return 0;
                },
                .refused => {
                    std.debug.print("a host the policy permits was refused too\n", .{});
                    return 5;
                },
            }
        }

        if (std.mem.eql(u8, args[1], "spawned-filtered-budget")) {
            // Two asks past the end and not one: the first usually reaches the
            // socket before the close, so only the second meets a gone peer.
            var made: usize = 0;
            var gone_at: ?usize = null;
            while (made <= sandbox.net_broker.max_requests + 1) : (made += 1) {
                const answer = sandbox.net_broker.ask(
                    sandbox.net_broker.fd_number,
                    filtered_refused_host,
                    granted_port,
                ) catch |err| {
                    if (err != error.BrokerGone) {
                        std.debug.print("ask {d} failed with {s}\n", .{ made, @errorName(err) });
                        return 5;
                    }
                    if (gone_at == null) {
                        if (made != sandbox.net_broker.max_requests) {
                            std.debug.print("the far end went at ask {d}\n", .{made});
                            return 5;
                        }
                        gone_at = made;
                    }
                    continue;
                };
                if (gone_at != null) {
                    std.debug.print("the far end answered again after it had gone\n", .{});
                    return 5;
                }
                switch (answer) {
                    .granted => |fd| {
                        _ = linux.close(fd);
                        return 1;
                    },
                    .refused => {},
                }
            }
            if (gone_at == null) {
                std.debug.print("the far end answered past its own budget\n", .{});
                return 5;
            }
            return 0;
        }

        if (std.mem.eql(u8, args[1], "spawned-filtered-ask")) {
            const answer = sandbox.net_broker.ask(
                sandbox.net_broker.fd_number,
                filtered_host,
                granted_port,
            ) catch |err| {
                std.debug.print("ask failed: {s}\n", .{@errorName(err)});
                return 3;
            };
            switch (answer) {
                .granted => |fd| {
                    _ = linux.close(fd);
                    return 0;
                },
                .refused => return 1,
            }
        }

        if (std.mem.eql(u8, args[1], "spawned-filtered-ask-two")) {
            // The second ask must not take the first one's answer.
            const first = sandbox.net_broker.ask(
                sandbox.net_broker.fd_number,
                filtered_host,
                granted_port,
            ) catch |err| {
                std.debug.print("first ask failed: {s}\n", .{@errorName(err)});
                return 3;
            };
            const first_granted = switch (first) {
                .granted => |fd| blk: {
                    _ = linux.close(fd);
                    break :blk true;
                },
                .refused => false,
            };

            const second = sandbox.net_broker.ask(
                sandbox.net_broker.fd_number,
                second_filtered_host,
                granted_port,
            ) catch |err| {
                std.debug.print("second ask failed: {s}\n", .{@errorName(err)});
                return 3;
            };
            const second_granted = switch (second) {
                .granted => |fd| blk: {
                    _ = linux.close(fd);
                    break :blk true;
                },
                .refused => false,
            };

            if (first_granted and !second_granted) return 0;
            std.debug.print(
                "first granted {} second granted {}\n",
                .{ first_granted, second_granted },
            );
            return 1;
        }

        std.debug.print("unknown filtered network operation: {s}\n", .{args[1]});
        return 2;
    }

    if (std.mem.eql(u8, args[1], "spawned-landlock-read")) {
        // spawned_landlock_target is bound into the sandbox root by the
        // spawn-landlock-escape operation below, but no rule ever names it.
        const fd = linux.open(spawned_landlock_target, .{ .ACCMODE = .RDONLY }, 0);
        const open_errno = linux.errno(fd);
        if (open_errno == .SUCCESS) {
            _ = linux.close(@intCast(fd));
            return 0; // Opened a path no rule named. The ruleset never applied.
        }
        // A path no rule names is refused with EACCES.
        return if (open_errno == .ACCES) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "spawned-fork-bomb")) {
        // Every child blocks for ever on a pipe nobody writes to, so it stays a
        // live process and counts against `pids.max` and `RLIMIT_NPROC`.
        var fds: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return 3;

        var made: u8 = 0;
        while (made < fork_bomb_cap) {
            const rc = linux.fork();
            if (linux.errno(rc) != .SUCCESS) break;
            if (rc == 0) {
                var byte: [1]u8 = undefined;
                while (true) _ = linux.read(fds[0], &byte, 1);
            }
            made += 1;
        }
        return made;
    }
    if (std.mem.eql(u8, args[1], "spawned-mem-bomb")) {
        // Every block is written to, not only asked for, because `memory.max`
        // counts resident pages and `RLIMIT_AS` counts a mapping.
        var touched: u8 = 0;
        while (touched < mem_bomb_cap) {
            const block = arena.alloc(u8, mem_bomb_block_bytes) catch break;
            @memset(block, 1);
            touched += 1;
        }
        return touched;
    }
    if (std.mem.eql(u8, args[1], "spawned-fd-bomb")) {
        // `/probe` is the one path a rule permits, and nothing is closed.
        var opened: u8 = 0;
        while (opened < fd_bomb_cap) {
            const rc = linux.open("/probe", .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(rc) != .SUCCESS) break;
            opened += 1;
        }
        return opened;
    }
    if (std.mem.eql(u8, args[1], "spawned-disk-file-bomb")) {
        // The attack `RLIMIT_FSIZE` cannot see: many small files.
        var made: u8 = 0;
        while (made < disk_file_cap) {
            var name_buffer: [std.fs.max_path_bytes]u8 = undefined;
            const name = std.fmt.bufPrintZ(&name_buffer, "{s}/f{d}", .{ scratch_target, made }) catch return 3;
            const fd_rc = linux.open(name.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
            if (linux.errno(fd_rc) != .SUCCESS) break;
            const fd: i32 = @intCast(fd_rc);
            const payload = [_]u8{'d'} ** disk_file_bytes;
            const written = linux.write(fd, &payload, payload.len);
            _ = linux.close(fd);
            if (linux.errno(written) != .SUCCESS) break;
            made += 1;
        }
        return made;
    }
    if (std.mem.eql(u8, args[1], "spawned-disk-one-bomb")) {
        // In the scratch area, so `RLIMIT_FSIZE` meets a tmpfs.
        var name_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const name = std.fmt.bufPrintZ(&name_buffer, "{s}/one", .{scratch_target}) catch return 3;
        const fd_rc = linux.open(name.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        if (linux.errno(fd_rc) != .SUCCESS) return 3;
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);

        var blocks: u8 = 0;
        while (blocks < disk_one_cap) {
            const payload = [_]u8{'o'} ** disk_one_block_bytes;
            const written = linux.write(fd, &payload, payload.len);
            if (linux.errno(written) != .SUCCESS) break;
            if (written != payload.len) break;
            blocks += 1;
        }
        return blocks;
    }
    if (std.mem.eql(u8, args[1], "spawned-approval-socket")) {
        // Anything that reaches the approval socket can approve an action.
        const path_z = arena.dupeZ(u8, id_arg) catch return 3;
        const fd = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM, 0);
        // A network namespace still permits a unix socket.
        if (linux.errno(fd) != .SUCCESS) return 5;
        var addr = std.mem.zeroes(linux.sockaddr.un);
        addr.family = linux.AF.UNIX;
        if (path_z.len >= addr.path.len) return 3;
        @memcpy(addr.path[0..path_z.len], path_z);
        const rc = linux.connect(@intCast(fd), @ptrCast(&addr), @sizeOf(linux.sockaddr.un));
        const connect_errno = linux.errno(rc);
        if (connect_errno == .SUCCESS) {
            _ = linux.close(@intCast(fd));
            return 0;
        }
        // The path is not in this mount tree, so the refusal must be ENOENT.
        if (connect_errno != .NOENT) {
            std.debug.print(
                "connect to the approval socket did not fail with ENOENT, got: {s}\n",
                .{@tagName(connect_errno)},
            );
            return 5;
        }
        return 1;
    }
    if (std.mem.eql(u8, args[1], "spawned-connect")) {
        const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
        if (linux.errno(fd) != .SUCCESS) return 5;
        var addr = std.mem.zeroes(linux.sockaddr.in);
        addr.family = linux.AF.INET;
        addr.port = std.mem.nativeToBig(u16, 53);
        // 1.1.1.1
        addr.addr = std.mem.nativeToBig(u32, 0x01010101);
        const rc = linux.connect(@intCast(fd), @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
        const connect_errno = linux.errno(rc);
        if (connect_errno == .SUCCESS) return 0; // Reached the host. The namespace never applied.
        return if (connect_errno == .NETUNREACH) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "spawned-signal-host")) {
        // A fresh pid namespace has no member under the pid id_arg names.
        const target = std.fmt.parseInt(linux.pid_t, id_arg, 10) catch {
            std.debug.print("spawned-signal-host: bad pid argument\n", .{});
            return 5;
        };
        // The kernel fails to find the task before it reads a permission.
        const rc = linux.kill(target, .KILL);
        const kill_errno = linux.errno(rc);
        if (kill_errno == .SUCCESS) return 0; // Reached the host process. The pid namespace never applied.
        return if (kill_errno == .SRCH) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "spawned-shm-attach")) {
        // id_arg is a segment made on the host, outside every namespace.
        const shmid = std.fmt.parseInt(usize, id_arg, 10) catch {
            std.debug.print("spawned-shm-attach: bad shmid argument\n", .{});
            return 5;
        };
        const rc = linux.syscall3(.shmat, shmid, 0, 0);
        const shmat_errno = linux.errno(rc);
        if (shmat_errno == .SUCCESS) return 0; // Attached the host segment. The ipc namespace never applied.
        // An id this namespace has no entry for is refused with EINVAL.
        return if (shmat_errno == .INVAL) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "spawned-report-pid")) {
        // The first process inside a new pid namespace is numbered 1.
        var buffer: [16]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "{d}\n", .{linux.getpid()}) catch unreachable;
        _ = linux.write(std.posix.STDOUT_FILENO, line.ptr, line.len);
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-device-place")) {
        // The helper places the node whenever this program reaches its own
        // execve, so this polls, bounded, rather than assume a winner.
        const never_appeared: u8 = 5;
        const read_failed: u8 = 6;
        // A bind mount needs its target to exist first, so the helper makes an
        // empty file and mounts over it. An open with no bytes is early.
        var attempt: usize = 0;
        var opened = false;
        while (attempt < 200) : (attempt += 1) {
            const fd_rc = linux.open(device_probe_path, .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(fd_rc) == .SUCCESS) {
                opened = true;
                const fd: i32 = @intCast(fd_rc);
                var buffer: [64]u8 = undefined;
                const n = linux.read(fd, &buffer, buffer.len);
                _ = linux.close(fd);
                if (linux.errno(n) != .SUCCESS) return read_failed;
                if (n != 0) {
                    return if (std.mem.eql(u8, buffer[0..n], device_probe_content)) 0 else 1;
                }
            }
            var pause: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
            _ = linux.nanosleep(&pause, null);
        }
        return if (opened) 1 else never_appeared;
    }
    if (std.mem.eql(u8, args[1], "spawned-device-hidden-denied")) {
        // Landlock never named the hidden tree, so no path under it opens, even
        // though the same node is readable at `device_probe_path`.
        const never_appeared: u8 = 5;
        const hidden_still_readable: u8 = 6;
        var attempt: usize = 0;
        var appeared = false;
        while (attempt < 200) : (attempt += 1) {
            const fd_rc = linux.open(device_probe_path, .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(fd_rc) == .SUCCESS) {
                _ = linux.close(@intCast(fd_rc));
                appeared = true;
                break;
            }
            var pause: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
            _ = linux.nanosleep(&pause, null);
        }
        if (!appeared) return never_appeared;

        var path_buf: [256]u8 = undefined;
        const hidden_path = std.fmt.bufPrintZ(
            &path_buf,
            "{s}/{s}",
            .{ device_tree_inside, device_probe_source },
        ) catch return never_appeared;

        const hidden_rc = linux.open(hidden_path.ptr, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(hidden_rc) == .SUCCESS) {
            _ = linux.close(@intCast(hidden_rc));
            return hidden_still_readable;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-hold-until-closed")) {
        // Blocks until the caller closes the write end of `Config.stdin_fd`.
        var buffer: [8]u8 = undefined;
        while (true) {
            const n = linux.read(std.posix.STDIN_FILENO, &buffer, buffer.len);
            switch (linux.errno(n)) {
                .SUCCESS => if (n == 0) return 0,
                .INTR => continue,
                else => return 5,
            }
        }
    }
    if (std.mem.eql(u8, args[1], "spawned-default-signal")) {
        _ = linux.kill(linux.getpid(), .TERM);
        return 8;
    }
    if (std.mem.eql(u8, args[1], "spawned-keeper-reaps")) {
        var pipe: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })) != .SUCCESS) return 4;

        const parent_rc = linux.fork();
        if (linux.errno(parent_rc) != .SUCCESS) return 5;
        const parent_pid: linux.pid_t = @intCast(parent_rc);
        if (parent_pid == 0) {
            _ = linux.close(pipe[0]);
            const orphan_rc = linux.fork();
            if (linux.errno(orphan_rc) != .SUCCESS) linux.exit(6);
            const orphan_pid: linux.pid_t = @intCast(orphan_rc);
            if (orphan_pid == 0) linux.exit(0);
            const pid_bytes = std.mem.asBytes(&orphan_pid);
            if (linux.errno(linux.write(pipe[1], pid_bytes.ptr, pid_bytes.len)) != .SUCCESS) {
                linux.exit(7);
            }
            linux.exit(0);
        }

        _ = linux.close(pipe[1]);
        var orphan_pid: linux.pid_t = undefined;
        const pid_bytes = std.mem.asBytes(&orphan_pid);
        const read_rc = linux.read(pipe[0], pid_bytes.ptr, pid_bytes.len);
        _ = linux.close(pipe[0]);
        if (linux.errno(read_rc) != .SUCCESS or read_rc != @sizeOf(linux.pid_t)) return 8;

        var status: u32 = undefined;
        var wait_rc = linux.waitpid(parent_pid, &status, 0);
        while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(parent_pid, &status, 0);
        if (linux.errno(wait_rc) != .SUCCESS or !linux.W.IFEXITED(status) or
            linux.W.EXITSTATUS(status) != 0)
        {
            return 9;
        }

        var tries: usize = 0;
        while (tries < 2000) : (tries += 1) {
            const exists_rc = linux.kill(orphan_pid, @enumFromInt(0));
            if (linux.errno(exists_rc) == .SRCH) return 0;
            if (linux.errno(exists_rc) != .SUCCESS) return 10;
            var pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
            _ = linux.nanosleep(&pause, null);
        }
        return 11;
    }
    if (std.mem.eql(u8, args[1], "spawned-count-opens")) {
        // `/probe` is the one path that is certainly there and readable.
        var made: usize = 0;
        while (made < opens_in_probe) : (made += 1) {
            const rc = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(rc) != .SUCCESS) return 5;
            _ = linux.close(@intCast(rc));
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-name-paths")) {
        // This program is statically linked, so nothing but these calls opens
        // anything. The kernel tells the reader before it runs the call.
        var made: usize = 0;
        while (made < 3) : (made += 1) {
            const rc = linux.openat(linux.AT.FDCWD, named_ungranted, .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(rc) == .SUCCESS) _ = linux.close(@intCast(rc));
        }
        const second = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(second) != .SUCCESS) return 5;
        _ = linux.close(@intCast(second));

        const inside = linux.openat(linux.AT.FDCWD, named_granted, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(inside) == .SUCCESS) _ = linux.close(@intCast(inside));
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-kill-the-reader")) {
        // This process is process 2 of its own pid namespace and the reader is
        // process 3, so an ordinary signal reaches it. The supervisor gave up
        // its copy of the descriptor, so the kernel then answers held calls with
        // ENOSYS.
        const before = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(before) != .SUCCESS) return 5;
        _ = linux.close(@intCast(before));

        // An alarm, because a supervisor that kept its own copy of the
        // descriptor leaves the next open held for ever.
        const on_alarm = std.posix.Sigaction{
            .handler = .{ .handler = endOnAlarm },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        if (linux.errno(linux.sigaction(.ALRM, &on_alarm, null)) != .SUCCESS) return 10;

        // Whole seconds, so the unit of the sub second field does not matter.
        const alarm: linux.itimerspec = .{
            .it_interval = .{ .sec = 0, .nsec = 0 },
            .it_value = .{ .sec = 10, .nsec = 0 },
        };
        if (linux.errno(linux.setitimer(@intFromEnum(linux.ITIMER.REAL), &alarm, null)) != .SUCCESS)
            return 9;

        if (linux.errno(linux.kill(reader_pid_in_namespace, std.posix.SIG.KILL)) != .SUCCESS) return 6;

        // The kill goes to another process, so this loop waits, bounded.
        var tries: usize = 0;
        while (tries < 1000) : (tries += 1) {
            const after = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
            switch (linux.errno(after)) {
                .SUCCESS => {
                    _ = linux.close(@intCast(after));
                    var pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
                    _ = linux.nanosleep(&pause, null);
                },
                .NOSYS => return 0,
                else => return 7,
            }
        }
        return 8;
    }
    if (std.mem.eql(u8, args[1], "spawned-stop-the-reader")) {
        // This trapped call cannot finish before R exists and serves it.
        const before = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(before) != .SUCCESS) return 5;
        _ = linux.close(@intCast(before));
        if (linux.errno(linux.kill(reader_pid_in_namespace, .STOP)) != .SUCCESS) return 6;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-leave-daemon")) {
        // The forked process still carries the filter, so a supervisor that
        // waited for the filter would hold the tool call.
        const forked = linux.fork();
        if (linux.errno(forked) != .SUCCESS) return 5;
        if (forked == 0) {
            // B must exit before this call: a reader that ignores B's pidfd
            // would serve and record this open.
            var pause: linux.timespec = .{ .sec = 0, .nsec = 250_000_000 };
            _ = linux.nanosleep(&pause, null);
            const opened = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(opened) == .SUCCESS) _ = linux.close(@intCast(opened));
            return 0;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-caps-drop")) {
        // An ordinary `execve` of a program with no file capability already
        // clears effective, permitted and inheritable, while `CapBnd` carries
        // the full set through unchanged, so `capget` is the wrong thing to
        // read. `PR_CAPBSET_READ` answers through `prctl`'s own return value.
        var cap: usize = 0;
        while (cap <= linux.CAP.LAST_CAP) : (cap += 1) {
            const rc = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), cap, 0, 0, 0);
            const cap_errno = linux.errno(rc);
            if (cap_errno == .INVAL) break; // A kernel older than CAP.LAST_CAP: nothing above this exists.
            if (cap_errno != .SUCCESS) return 5;
            if (rc != 0) return 1; // Still in the bounding set. The drop did not run, or did not finish.
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-stdin-devnull")) {
        // This operation does no setup, so descriptor 0 is spawn's own doing.
        var stx: linux.Statx = undefined;
        const rc = linux.statx(std.posix.STDIN_FILENO, "", linux.AT.EMPTY_PATH, linux.STATX.BASIC_STATS, &stx);
        if (linux.errno(rc) != .SUCCESS) return 5;
        const is_char_device = (stx.mode & linux.S.IFMT) == linux.S.IFCHR;
        return if (is_char_device) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "spawned-stdin-pipe")) {
        // A helper gets the harness's pipe on descriptor 0 and nothing else.
        var stx: linux.Statx = undefined;
        const stat_rc = linux.statx(std.posix.STDIN_FILENO, "", linux.AT.EMPTY_PATH, linux.STATX.BASIC_STATS, &stx);
        if (linux.errno(stat_rc) != .SUCCESS) return 5;

        // 1. A pipe, where /dev/null and a terminal are character devices.
        if ((stx.mode & linux.S.IFMT) != linux.S.IFIFO) {
            std.debug.print("spawned-stdin-pipe: descriptor 0 is not a pipe\n", .{});
            return 1;
        }

        // 2. Not a terminal, which is the injection route: TIOCSTI needs
        //    descriptor 0 to be one, and a pipe answers ENOTTY.
        var termios: linux.termios = undefined;
        if (linux.errno(linux.tcgetattr(std.posix.STDIN_FILENO, &termios)) == .SUCCESS) {
            std.debug.print("spawned-stdin-pipe: descriptor 0 is a terminal\n", .{});
            return 1;
        }

        // 3. The bytes are the caller's own, so the pipe is too.
        var buffer: [stdin_pipe_token.len]u8 = undefined;
        var filled: usize = 0;
        while (filled < buffer.len) {
            const rc = linux.read(std.posix.STDIN_FILENO, buffer[filled..].ptr, buffer.len - filled);
            const read_errno = linux.errno(rc);
            if (read_errno == .INTR) continue;
            if (read_errno != .SUCCESS) return 5;
            if (rc == 0) break;
            filled += rc;
        }
        if (!std.mem.eql(u8, buffer[0..filled], stdin_pipe_token)) {
            std.debug.print("spawned-stdin-pipe: descriptor 0 carried other bytes\n", .{});
            return 1;
        }

        // 4. A closed write end reads as end of file, which works only
        //    because every copy of it is closed.
        var extra: [1]u8 = undefined;
        const eof_rc = linux.read(std.posix.STDIN_FILENO, &extra, 1);
        if (linux.errno(eof_rc) != .SUCCESS or eof_rc != 0) {
            std.debug.print("spawned-stdin-pipe: descriptor 0 never reached end of file\n", .{});
            return 1;
        }

        // 5. The exemption is one descriptor wide: a directory descriptor on
        //    the host root must be gone. F_GETFD answers EBADF for that.
        const escape_fd = std.fmt.parseInt(i32, id_arg, 10) catch return 5;
        if (linux.errno(linux.fcntl(escape_fd, linux.F.GETFD, 0)) != .BADF) {
            std.debug.print("spawned-stdin-pipe: an inherited descriptor survived\n", .{});
            return 1;
        }

        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-open-fd-set")) {
        // An already open descriptor goes through no path resolution again, so
        // neither Landlock nor the mount namespace can revoke one.
        const filtered = std.mem.eql(u8, id_arg, "filtered");
        if (!filtered and !std.mem.eql(u8, id_arg, "plain")) return 5;

        var fd: i32 = 0;
        while (fd < open_fd_set_scan_limit) : (fd += 1) {
            // `F_GETFD` answers `EBADF` for a number that names nothing, so
            // this needs no `/proc`.
            const is_open = linux.errno(linux.fcntl(fd, linux.F.GETFD, 0)) == .SUCCESS;
            const belongs = fd <= std.posix.STDERR_FILENO or
                (filtered and fd == sandbox.net_broker.fd_number);
            if (is_open == belongs) continue;
            if (is_open) {
                std.debug.print("spawned-open-fd-set: descriptor {d} crossed execve\n", .{fd});
            } else {
                std.debug.print("spawned-open-fd-set: descriptor {d} did not reach the program\n", .{fd});
            }
            return 1;
        }

        // A log file on descriptor 0 keeps the set the same size and leaks.
        if (fileTypeOf(std.posix.STDIN_FILENO) != linux.S.IFCHR) {
            std.debug.print("spawned-open-fd-set: descriptor 0 is not a character device\n", .{});
            return 1;
        }
        if (filtered and fileTypeOf(sandbox.net_broker.fd_number) != linux.S.IFSOCK) {
            std.debug.print("spawned-open-fd-set: the broker descriptor is not a socket\n", .{});
            return 1;
        }

        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-proc-mask")) {
        // The list comes from `namespace.masked_proc_entries` itself, so a name
        // added there is covered here on the day it is added.
        var checked: usize = 0;
        for (sandbox.namespace.masked_proc_entries) |name| {
            var path_buffer: [64]u8 = undefined;
            const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{s}", .{name}) catch return 5;

            const fd_rc = linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0);
            const open_errno = linux.errno(fd_rc);
            // A kernel built without the option that makes this file.
            if (open_errno == .NOENT) continue;
            if (open_errno != .SUCCESS) {
                std.debug.print("spawned-proc-mask: open {s}: {s}\n", .{ path, @tagName(open_errno) });
                return 5;
            }
            const fd: i32 = @intCast(fd_rc);
            defer _ = linux.close(fd);

            var buffer: [256]u8 = undefined;
            const read_rc = linux.read(fd, &buffer, buffer.len);
            if (linux.errno(read_rc) != .SUCCESS) {
                std.debug.print("spawned-proc-mask: read {s}: {s}\n", .{ path, @tagName(linux.errno(read_rc)) });
                return 5;
            }
            if (read_rc != 0) {
                std.debug.print("spawned-proc-mask: {s} gave {d} bytes\n", .{ path, read_rc });
                return 1;
            }
            checked += 1;
        }
        // `cmdline`, `version` and `kallsyms` are in every kernel, so a run
        // that masked nothing had a broken list.
        if (checked < 3) {
            std.debug.print("spawned-proc-mask: only {d} entries existed to check\n", .{checked});
            return 5;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-proc-live")) {
        // Masking and `/proc/self` can break each other: a procfs that went
        // missing makes every read in spawned-proc-mask return zero.
        var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const link_rc = linux.readlink("/proc/self/exe", &link_buffer, link_buffer.len);
        if (linux.errno(link_rc) != .SUCCESS) {
            std.debug.print("spawned-proc-live: /proc/self/exe: {s}\n", .{@tagName(linux.errno(link_rc))});
            return 1;
        }
        if (!std.mem.eql(u8, link_buffer[0..link_rc], "/probe")) {
            std.debug.print("spawned-proc-live: /proc/self/exe gave {s}\n", .{link_buffer[0..link_rc]});
            return 1;
        }

        // A file no mask names must hold bytes, or the procfs is empty.
        const fd_rc = linux.open("/proc/uptime", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(fd_rc) != .SUCCESS) {
            std.debug.print("spawned-proc-live: open /proc/uptime: {s}\n", .{@tagName(linux.errno(fd_rc))});
            return 5;
        }
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);
        var buffer: [256]u8 = undefined;
        const read_rc = linux.read(fd, &buffer, buffer.len);
        if (linux.errno(read_rc) != .SUCCESS) {
            std.debug.print("spawned-proc-live: read /proc/uptime: {s}\n", .{@tagName(linux.errno(read_rc))});
            return 5;
        }
        if (read_rc == 0) {
            std.debug.print("spawned-proc-live: /proc/uptime was empty\n", .{});
            return 5;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-forge-exit")) {
        // An exit code out of the range an older design read as proof the
        // sandbox never came up.
        writeTestFile(arena, "/work/output.txt", "chock forge-exit probe content\n") catch |err| {
            std.debug.print("spawned-forge-exit: could not write the marker: {s}\n", .{@errorName(err)});
            return 5;
        };
        return 111;
    }
    if (std.mem.eql(u8, args[1], "spawned-loop-write")) {
        // If PDEATHSIG never arms, this process orphans and goes on writing.
        while (true) {
            const fd = linux.open("/work/heartbeat.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o644);
            if (linux.errno(fd) == .SUCCESS) {
                const handle: i32 = @intCast(fd);
                _ = linux.write(handle, "x", 1);
                _ = linux.close(handle);
            }
            _ = linux.nanosleep(&.{ .sec = 0, .nsec = 5_000_000 }, null);
        }
    }

    if (std.mem.eql(u8, args[1], "spawned-fork-loop-write")) {
        // A cancel reaches the one process `spawn` forked, which is neither
        // this one nor the child below. The marker says the fork worked.
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) {
            std.debug.print("spawned-fork-loop-write: fork failed\n", .{});
            return 5;
        }

        if (@as(linux.pid_t, @intCast(child)) == 0) {
            while (true) {
                const fd = linux.open("/work/heartbeat.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o644);
                if (linux.errno(fd) == .SUCCESS) {
                    const handle: i32 = @intCast(fd);
                    _ = linux.write(handle, "x", 1);
                    _ = linux.close(handle);
                }
                _ = linux.nanosleep(&.{ .sec = 0, .nsec = 5_000_000 }, null);
            }
        }

        const marker = linux.open("/work/forked.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o644);
        if (linux.errno(marker) == .SUCCESS) {
            const handle: i32 = @intCast(marker);
            _ = linux.write(handle, "f", 1);
            _ = linux.close(handle);
        }

        // Here only so the grandchild has a parent a cancel does not name.
        while (true) _ = linux.nanosleep(&.{ .sec = 3600, .nsec = 0 }, null);
    }

    if (std.mem.eql(u8, args[1], "spawned-setsid-fork-loop-write")) {
        // The grandchild calls setsid() first, so it leaves the process group
        // `Sandbox.spawn` put it in. Neither teardown reads a group:
        // `PR_SET_PDEATHSIG` fires on a death, and `cgroup.kill` on membership.
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) {
            std.debug.print("spawned-setsid-fork-loop-write: fork failed\n", .{});
            return 5;
        }

        if (@as(linux.pid_t, @intCast(child)) == 0) {
            // setsid fails with EPERM for a process that already leads a group,
            // which the first child of a fork never does.
            const setsid_rc = linux.setsid();
            if (linux.errno(setsid_rc) != .SUCCESS) {
                std.debug.print(
                    "spawned-setsid-fork-loop-write: setsid: {s}\n",
                    .{@tagName(linux.errno(setsid_rc))},
                );
                return 5;
            }
            writeTestFile(arena, "/work/setsid-ok", "ok\n") catch |err| {
                std.debug.print(
                    "spawned-setsid-fork-loop-write: could not write the setsid marker: {s}\n",
                    .{@errorName(err)},
                );
                return 5;
            };

            while (true) {
                const fd = linux.open("/work/heartbeat.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o644);
                if (linux.errno(fd) == .SUCCESS) {
                    const handle: i32 = @intCast(fd);
                    _ = linux.write(handle, "x", 1);
                    _ = linux.close(handle);
                }
                _ = linux.nanosleep(&.{ .sec = 0, .nsec = 5_000_000 }, null);
            }
        }

        const marker = linux.open("/work/forked.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o644);
        if (linux.errno(marker) == .SUCCESS) {
            const handle: i32 = @intCast(marker);
            _ = linux.write(handle, "f", 1);
            _ = linux.close(handle);
        }

        // Here only so the grandchild has a parent a cancel does not name.
        while (true) _ = linux.nanosleep(&.{ .sec = 3600, .nsec = 0 }, null);
    }

    if (std.mem.eql(u8, args[1], "spawned-signal-group")) {
        // `kill(0, sig)` names the caller's own process group. A process in a
        // fresh pid namespace reads getpgid(0) as 0 and still reaches outside.
        const rc = linux.kill(0, .USR1);
        const kill_errno = linux.errno(rc);
        if (kill_errno != .SUCCESS) {
            std.debug.print("spawned-signal-group: kill(0, USR1): {s}\n", .{@tagName(kill_errno)});
            return 5;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-group-press")) {
        // A terminal signals the whole foreground process group. It catches the
        // signal rather than dying, so arrival and death read apart.
        catchSignal(.USR1);
        writeTestFile(arena, "/work/started", "started\n") catch |err| {
            std.debug.print("spawned-group-press: could not write the marker: {s}\n", .{@errorName(err)});
            return 5;
        };

        // The caller presses first and writes this second.
        if (!waitForPath("/work/go")) {
            std.debug.print("spawned-group-press: the caller never wrote /work/go\n", .{});
            return 4;
        }
        return if (caller_signal_seen.load(.monotonic)) 1 else 0;
    }

    if (std.mem.eql(u8, args[1], "read-home")) {
        // A setup failure must exit 3: 1 and 5 are what a working refusal is.
        enterTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        // The home directory is not in the mount tree.
        const fd = linux.open("/home", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        const open_errno = linux.errno(fd);
        if (open_errno == .SUCCESS) _ = linux.close(@intCast(fd));
        if (open_errno == .SUCCESS) return 0;
        // /home was never created, so opening it must fail with ENOENT.
        return if (open_errno == .NOENT) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "cgroup-surface")) {
        // The cgroup Chock builds is never bound into this mount tree, and no
        // path to a file means no way to widen it.
        enterTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        const fd = linux.open("/sys/fs/cgroup", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        const open_errno = linux.errno(fd);
        if (open_errno == .SUCCESS) _ = linux.close(@intCast(fd));
        if (open_errno == .SUCCESS) return 0;
        return if (open_errno == .NOENT) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "write-readonly")) {
        enterTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        const fd = linux.open(
            "/nix/store/chock-probe",
            .{ .ACCMODE = .WRONLY, .CREAT = true },
            0o644,
        );
        const open_errno = linux.errno(fd);
        if (open_errno == .SUCCESS) _ = linux.close(@intCast(fd));
        if (open_errno == .SUCCESS) return 0;
        // A read only mount refuses a new file with EROFS, not EPERM or EACCES.
        return if (open_errno == .ROFS) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "write-readonly-submount")) {
        enterSubmountTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        const fd = linux.open(
            "/guarded/sub/chock-probe",
            .{ .ACCMODE = .WRONLY, .CREAT = true },
            0o644,
        );
        const open_errno = linux.errno(fd);
        if (open_errno == .SUCCESS) _ = linux.close(@intCast(fd));
        if (open_errno == .SUCCESS) return 0;
        // The submount must answer the same EROFS a direct bind gives.
        return if (open_errno == .ROFS) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "delete-mounted-file")) {
        enterTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        // A file that is a mount point cannot be unlinked: EBUSY.
        const unlink_errno = linux.errno(linux.unlink("/work/chock.zon"));
        if (unlink_errno == .SUCCESS) return 0;
        return if (unlink_errno == .BUSY) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "file-bind-content")) {
        enterFileOverFileTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };

        // The target must hold the source bytes and not an empty directory.
        var read_buffer: [64]u8 = undefined;
        var matched = false;
        const fd = linux.open("/marker", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(fd) == .SUCCESS) {
            const handle: i32 = @intCast(fd);
            const read_rc = linux.read(handle, &read_buffer, read_buffer.len);
            _ = linux.close(handle);
            if (linux.errno(read_rc) == .SUCCESS) {
                matched = std.mem.eql(u8, read_buffer[0..read_rc], file_over_file_content);
            }
        }

        return if (matched) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "deny-symlink-outside")) {
        // `id_arg` is a directory nothing in this mount tree names, so a change
        // there means the bind followed a symlink out of the project.
        const secret_content = "chock outside secret content\n";
        const secret_path = try std.fs.path.join(arena, &.{ id_arg, "secret" });
        try writeTestFile(arena, secret_path, secret_content);
        const secret_z = try arena.dupeZ(u8, secret_path);

        // `.env`, inside the project, aimed outside it. `deny.zig`'s own
        // `check` accepts this shape, because it never stats a link's target.
        const work = try std.fs.path.join(arena, &.{ root_arg, "work" });
        try makeTestDir(arena, work);
        const env_path = try std.fs.path.join(arena, &.{ work, ".env" });
        const env_z = try arena.dupeZ(u8, env_path);
        if (linux.errno(linux.symlink(secret_z.ptr, env_z.ptr)) != .SUCCESS) return 3;

        enterOrEndUnmeasured(.{ .network = .none, .mount = true });
        const build_result = sandbox.namespace.buildRoot(arena, root_arg, &.{
            .{ .bind = .{ .source = work, .target = "/work", .read_only = false } },
            .{ .deny = .{ .target = "/work/.env" } },
        }, null);

        // Still reachable by that name, because `buildRoot` never pivots. The
        // buffer holds the whole deny notice, or the read truncates.
        var read_buffer: [sandbox.namespace.deny_notice.len]u8 = undefined;
        var read_content: []const u8 = &.{};
        const read_fd = linux.open(secret_z.ptr, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(read_fd) == .SUCCESS) {
            const handle: i32 = @intCast(read_fd);
            const read_rc = linux.read(handle, &read_buffer, read_buffer.len);
            _ = linux.close(handle);
            if (linux.errno(read_rc) == .SUCCESS) read_content = read_buffer[0..read_rc];
        }
        const escaped = std.mem.eql(u8, read_content, sandbox.namespace.deny_notice);

        // Exit 1 is the fault: the bind landed outside.
        if (escaped) return 1;
        if (build_result) |_| return 5 else |err| return if (err == error.DenyTargetIsSymlink) 0 else 5;
    }
    if (std.mem.eql(u8, args[1], "bind-source-symlink")) {
        // `chock.zon`'s own shape: the agent can write to that tree between
        // tool calls, so `ln -s <host path> chock.zon` is this bind source.
        const secret_content = "chock host secret via a symlinked bind source\n";
        const secret_path = try std.fs.path.join(arena, &.{ id_arg, "secret" });
        try writeTestFile(arena, secret_path, secret_content);
        const secret_z = try arena.dupeZ(u8, secret_path);

        const link_path = try std.fs.path.join(arena, &.{ root_arg, "link-chock-zon" });
        const link_z = try arena.dupeZ(u8, link_path);
        if (linux.errno(linux.symlink(secret_z.ptr, link_z.ptr)) != .SUCCESS) return 3;

        enterOrEndUnmeasured(.{ .network = .none, .mount = true });
        const build_result = sandbox.namespace.buildRoot(arena, root_arg, &.{
            .{ .bind = .{ .source = link_path, .target = "/work/chock.zon", .read_only = true } },
        }, null);

        // Still reachable by that absolute name, because `buildRoot` never
        // pivots. A bind that followed the link holds the host secret here.
        const target_path = try std.fs.path.join(arena, &.{ root_arg, "work/chock.zon" });
        const target_z = try arena.dupeZ(u8, target_path);
        var read_buffer: [secret_content.len]u8 = undefined;
        var read_content: []const u8 = &.{};
        const read_fd = linux.open(target_z.ptr, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(read_fd) == .SUCCESS) {
            const handle: i32 = @intCast(read_fd);
            const read_rc = linux.read(handle, &read_buffer, read_buffer.len);
            _ = linux.close(handle);
            if (linux.errno(read_rc) == .SUCCESS) read_content = read_buffer[0..read_rc];
        }
        const escaped = std.mem.eql(u8, read_content, secret_content);

        // Exit 1 is the fault: the bind landed on the host secret.
        if (escaped) return 1;
        if (build_result) |_| return 5 else |err| return if (err == error.BindSourceIsSymlink) 0 else 5;
    }
    if (std.mem.eql(u8, args[1], "deny-intermediate-symlink")) {
        // `id_arg` is an empty directory no mount names, so `creds/token`
        // appearing there means a `mkdirat` walked the symlink below.
        const work = try std.fs.path.join(arena, &.{ root_arg, "work" });
        try makeTestDir(arena, work);

        // The intermediate component of a `deny_read` entry. `deny.zig`'s own
        // `check` is a string check and cannot see that `link` is a link.
        const link_path = try std.fs.path.join(arena, &.{ work, "link" });
        const link_z = try arena.dupeZ(u8, link_path);
        const outside_z = try arena.dupeZ(u8, id_arg);
        if (linux.errno(linux.symlink(outside_z.ptr, link_z.ptr)) != .SUCCESS) return 3;

        enterOrEndUnmeasured(.{ .network = .none, .mount = true });
        const build_result = sandbox.namespace.buildRoot(arena, root_arg, &.{
            .{ .bind = .{ .source = work, .target = "/work", .read_only = false } },
            .{ .deny = .{ .target = "/work/link/creds/token" } },
        }, null);

        // Still reachable by that name, because `buildRoot` never pivots. A
        // followed component leaves the deny notice outside the root.
        const outside_token_path = try std.fs.path.join(arena, &.{ id_arg, "creds/token" });
        const outside_token_z = try arena.dupeZ(u8, outside_token_path);
        var read_buffer: [sandbox.namespace.deny_notice.len]u8 = undefined;
        var read_content: []const u8 = &.{};
        const read_fd = linux.open(outside_token_z.ptr, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(read_fd) == .SUCCESS) {
            const handle: i32 = @intCast(read_fd);
            const read_rc = linux.read(handle, &read_buffer, read_buffer.len);
            _ = linux.close(handle);
            if (linux.errno(read_rc) == .SUCCESS) read_content = read_buffer[0..read_rc];
        }
        const escaped = read_content.len > 0;

        // Exit 1 is the fault: a file was made outside the sandbox root.
        if (escaped) return 1;
        if (build_result) |_| return 5 else |err| return if (err == error.DenyTargetIsSymlink) 0 else 5;
    }

    // Every operation above ran inside the namespaces with no seccomp filter.
    // Every operation below runs with the filter and enters no namespace.
    if (std.mem.eql(u8, args[1], "ptrace")) {
        const rc = linux.syscall4(.ptrace, 0, 0, 0, 0);
        // The filter kills the process, so this line never runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "umount-protected")) {
        // The path need not be a real mount point, because the filter kills the
        // call first. A user namespace can otherwise unmount a read only bind.
        const rc = linux.umount2("/work/chock.zon", linux.MNT.DETACH);
        // The filter kills the process, so this line never runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "open-tree-attr-protected")) {
        // open_tree_attr is open_tree and mount_setattr in one call, added in
        // kernel 6.15. Without OPEN_TREE_CLONE it acts on the live mount.
        const MountAttr = extern struct {
            attr_set: u64 = 0,
            attr_clr: u64 = 0,
            propagation: u64 = 0,
            userns_fd: u64 = 0,
        };
        const mount_attr_rdonly: u64 = 0x00000001;
        var attr = MountAttr{ .attr_clr = mount_attr_rdonly };
        const path: [*:0]const u8 = "/work/chock.zon";
        const rc = linux.syscall5(
            .open_tree_attr,
            @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
            @intFromPtr(path),
            0,
            @intFromPtr(&attr),
            @sizeOf(MountAttr),
        );
        // The filter kills the process, so this line never runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "userfaultfd")) {
        const rc = linux.syscall1(.userfaultfd, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "add-key")) {
        // The filter must refuse add_key whichever keyring is current, and this
        // probe joins no fresh one.
        const key_type = "user";
        const description = "chock-probe-add-key";
        const payload = "chock-probe-payload";
        const key_spec_session_keyring: usize = @bitCast(@as(isize, -3));
        const rc = linux.syscall5(
            .add_key,
            @intFromPtr(key_type.ptr),
            @intFromPtr(description.ptr),
            @intFromPtr(payload.ptr),
            payload.len,
            key_spec_session_keyring,
        );
        // The filter kills the process, so this line never runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "io-uring-setup")) {
        // io_uring is the standard way around a syscall filter: the operations
        // go in a ring and kernel workers make the calls.
        var params: linux.io_uring_params = std.mem.zeroes(linux.io_uring_params);
        const rc = linux.io_uring_setup(1, &params);
        return ringRefusal(rc);
    }
    if (std.mem.eql(u8, args[1], "io-uring-enter")) {
        // This probe holds no ring: the filter must refuse before the kernel
        // reads the descriptor, or a handed over ring stays usable.
        const rc = linux.syscall6(.io_uring_enter, @bitCast(@as(isize, -1)), 1, 0, 0, 0, 0);
        return ringRefusal(rc);
    }
    if (std.mem.eql(u8, args[1], "io-uring-register")) {
        // Refused for the same reason as io_uring_enter above.
        const rc = linux.syscall4(.io_uring_register, @bitCast(@as(isize, -1)), 0, 0, 0);
        return ringRefusal(rc);
    }
    if (std.mem.eql(u8, args[1], "io-uring-then-work")) {
        // A run time asks for a ring, reads the refusal, and carries on with
        // its thread pool. A kill leaves no line after the call to run.
        var params: linux.io_uring_params = std.mem.zeroes(linux.io_uring_params);
        const rc = linux.io_uring_setup(1, &params);
        if (linux.errno(rc) != .PERM) return 4;
        // Work after the refusal, so the exit status says it stayed alive.
        if (linux.getpid() <= 0) return 4;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "getpid")) {
        // A call the filter must allow, so the filter is not a deny all.
        _ = linux.getpid();
        return 0;
    }

    if (std.mem.eql(u8, args[1], "landlock-write-outside") or
        std.mem.eql(u8, args[1], "landlock-write-inside"))
    {
        // A setup failure must exit 3: 1 and 0 are what a working sandbox is.
        const inside = enterLandlockWriteTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };

        const parent = if (std.mem.eql(u8, args[1], "landlock-write-inside"))
            inside
        else
            outsideDir(arena, root_arg) catch |err| {
                std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
                return 3;
            };
        const target = std.fmt.allocPrint(arena, "{s}/file", .{parent}) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        const target_z = arena.dupeZ(u8, target) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };

        const fd = linux.open(target_z, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
        if (linux.errno(fd) != .SUCCESS) return 1;
        _ = linux.close(@intCast(fd));
        return 0;
    }
    if (std.mem.eql(u8, args[1], "landlock-truncate-outside") or
        std.mem.eql(u8, args[1], "landlock-truncate-inside"))
    {
        // A ruleset that does not handle truncate leaves it permitted
        // everywhere, even outside every granted directory.
        const paths = enterLandlockTruncateTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };

        const target = if (std.mem.eql(u8, args[1], "landlock-truncate-inside"))
            paths.inside_file
        else
            paths.outside_file;

        const rc = linux.syscall2(.truncate, @intFromPtr(target.ptr), 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "spawn-ptrace")) {
        // Only the seccomp filter spawn installs can be in the way.
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-ptrace" }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-vsock")) {
        // `.network = .none` on purpose: the domain check kills the call first.
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-vsock" }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-setns-proc1")) {
        // /proc is mounted read only, so the target is really reachable.
        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, sandbox.namespace.Mount, &.{
            base.mounts,
            &.{.{ .proc = .{} }},
        });
        const rules = try std.mem.concat(arena, sandbox.Config.Rule, &.{
            base.rules,
            &.{.{ .path = "/proc", .access = sandbox.landlock.AccessFs.read_only }},
        });
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-setns-proc1" }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-proc-self-mem-write-landlock")) {
        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, sandbox.namespace.Mount, &.{
            base.mounts,
            &.{.{ .proc = .{} }},
        });
        const rules = try std.mem.concat(arena, sandbox.Config.Rule, &.{
            base.rules,
            &.{.{ .path = "/proc", .access = sandbox.landlock.AccessFs.read_only }},
        });
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-proc-self-mem-write-landlock" }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-proc-self-mem-write-mount")) {
        // /proc granted write under Landlock, so only the mount flag is left.
        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, sandbox.namespace.Mount, &.{
            base.mounts,
            &.{.{ .proc = .{} }},
        });
        const rules = try std.mem.concat(arena, sandbox.Config.Rule, &.{
            base.rules,
            &.{.{
                .path = "/proc",
                .access = .{ .execute = true, .write_file = true, .read_file = true, .read_dir = true },
            }},
        });
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-proc-self-mem-write-mount" }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-cgroup-remount")) {
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-cgroup-remount" }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-memfd-exec")) {
        // /work is granted every right except execute, for the control.
        const base = try baseEscapeConfig(arena);
        const work = try std.fs.path.join(arena, &.{ root_arg, "work" });
        try makeTestDir(arena, work);
        const mounts = try std.mem.concat(arena, sandbox.namespace.Mount, &.{
            base.mounts,
            &.{.{ .bind = .{ .source = work, .target = "/work", .read_only = false } }},
        });
        const rules = try std.mem.concat(arena, sandbox.Config.Rule, &.{
            base.rules,
            &.{.{
                .path = "/work",
                .access = .{ .write_file = true, .read_file = true, .read_dir = true, .make_reg = true },
            }},
        });
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-memfd-exec" }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-handle-escape")) {
        const base = try baseEscapeConfig(arena);
        const work = try std.fs.path.join(arena, &.{ root_arg, "work" });
        try makeTestDir(arena, work);
        const mounts = try std.mem.concat(arena, sandbox.namespace.Mount, &.{
            base.mounts,
            &.{.{ .bind = .{ .source = work, .target = "/work", .read_only = false } }},
        });
        const rules = try std.mem.concat(arena, sandbox.Config.Rule, &.{
            base.rules,
            &.{.{
                .path = "/work",
                .access = .{ .write_file = true, .read_file = true, .read_dir = true, .make_reg = true },
            }},
        });
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-handle-escape" }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.startsWith(u8, args[1], "spawn-fork-bomb") or
        std.mem.startsWith(u8, args[1], "spawn-mem-bomb") or
        std.mem.startsWith(u8, args[1], "spawn-fd-bomb"))
    {
        // The one layer about appetite rather than reach. Each operation has an
        // `-unbounded` twin under `Limits.none` that `escape.zig` compares.
        const unbounded = std.mem.endsWith(u8, args[1], "-unbounded");
        // About the cgroup and not the floor: with `mapped_memory_bytes` off,
        // only `memory.max` can stop the program, and it sends a bare SIGKILL.
        const cgroup_only = std.mem.endsWith(u8, args[1], "-cgroup");
        const base = try baseEscapeConfig(arena);

        const which: enum { fork, memory, files } = if (std.mem.startsWith(u8, args[1], "spawn-fork-bomb"))
            .fork
        else if (std.mem.startsWith(u8, args[1], "spawn-mem-bomb"))
            .memory
        else
            .files;

        // The bounded runs narrow one field of the library's own defaults.
        const limits: sandbox.Sandbox.Limits = if (unbounded)
            sandbox.Sandbox.Limits.none
        else switch (which) {
            .fork => .{ .processes = fork_bomb_limit },
            // Both fields, because a machine with no cgroup v2 has no ceiling.
            .memory => .{
                .memory_bytes = mem_bomb_limit,
                .mapped_memory_bytes = if (cgroup_only) null else mem_bomb_limit,
            },
            .files => .{ .open_files = fd_bomb_limit },
        };

        const target = switch (which) {
            .fork => "spawned-fork-bomb",
            .memory => "spawned-mem-bomb",
            .files => "spawned-fd-bomb",
        };
        const cap = switch (which) {
            .fork => fork_bomb_cap,
            .memory => mem_bomb_cap,
            .files => fd_bomb_cap,
        };

        var report: sandbox.Sandbox.LimitsReport = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .limits = limits,
            .limits_report = &report,
        }, &.{ "/probe", target }, null, null);

        // `killed_by` tells a `memory.max` kill from a cancel. A machine with
        // no cgroup v2 tree is one this project supports, so say so before
        // reading the outcome, and not after.
        if (cgroup_only and !report.cgroup.applied()) {
            return @intFromEnum(LimitOutcome.no_cgroup);
        }

        const named = report.killed_by != null or report.events.fork_refusals > 0;
        return limitOutcome(term, cap, named);
    }
    if (std.mem.startsWith(u8, args[1], "spawn-disk-")) {
        // The row no rlimit and no cgroup covers: `RLIMIT_FSIZE` bounds one
        // file, and ten thousand one byte files still fill a filesystem. The
        // `-unbounded` twin differs in the cap and in nothing else.
        const unbounded = std.mem.endsWith(u8, args[1], "-unbounded");
        const many_files = std.mem.startsWith(u8, args[1], "spawn-disk-files");
        const config = try diskEscapeConfig(arena);

        const limits: sandbox.Sandbox.Limits = if (unbounded)
            sandbox.Sandbox.Limits.none
        else if (many_files)
            .{ .scratch_bytes = disk_file_limit }
        else
            // The scratch cap is far above what this program writes.
            .{ .file_size_bytes = disk_one_file_limit, .scratch_bytes = disk_one_scratch_limit };

        const target = if (many_files) "spawned-disk-file-bomb" else "spawned-disk-one-bomb";
        const cap = if (many_files) disk_file_cap else disk_one_cap;

        var report: sandbox.Sandbox.LimitsReport = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = config.mounts,
            .rules = config.rules,
            .scratch = config.scratch,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .limits = limits,
            .limits_report = &report,
        }, &.{ "/probe", target }, null, null);

        // Nothing in the kernel counts a full filesystem, so `killed_by` is
        // what makes a full scratch area read as a limit.
        const named = report.killed_by != null;
        return limitOutcome(term, cap, named);
    }
    if (std.mem.eql(u8, args[1], "spawn-approval-socket")) {
        // The path lies outside `root_arg`, so no mount in this list names it.
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-approval-socket", id_arg }, null, null);

        return reportChildTerm(term);
    }

    if (std.mem.startsWith(u8, args[1], "spawn-routed-glibc")) {
        // The three shapes of host `/etc` a real machine has, through one
        // function, so only that directory differs.
        const shape: HostileEtc.Shape = if (std.mem.endsWith(u8, args[1], "-linked"))
            .linked
        else if (std.mem.endsWith(u8, args[1], "-absent"))
            .absent
        else
            .regular;
        return routedGlibc(arena, root_arg, shape);
    }
    if (std.mem.eql(u8, args[1], "spawn-routed-trust-store")) {
        return routedTrustStore(arena, root_arg);
    }
    if (std.mem.startsWith(u8, args[1], "spawn-routed-")) {
        // The far side dials this listener, and the program never sees it.
        const granted = listenLoopback() catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        defer _ = linux.close(granted.fd);
        const ports = try filteredPorts(arena, granted.port, granted.port);

        if (std.mem.eql(u8, args[1], "spawn-routed-reach")) {
            const run = try routedEscape(
                arena,
                root_arg,
                "routed-reach",
                ports,
                filtered_policy,
                &.{"main"},
                filtered_public_address,
                granted.port,
            );
            if (run.term != .exited or run.term.exited != 0) return reportChildTerm(run.term);

            // The bytes are the proof and the exit code is not.
            var buffer: [64]u8 = undefined;
            const carried = granted.readFirst(&buffer) orelse {
                std.debug.print("a permitted host was reported reached and nothing arrived\n", .{});
                return 5;
            };
            if (!std.mem.eql(u8, carried, filtered_token)) {
                std.debug.print("the connection carried the wrong bytes\n", .{});
                return 5;
            }
            // One lookup and one dial, neither twice. A second dial means the
            // name was resolved again, which is what a rebinding attack needs.
            if (run.lookups != 1 or run.dials != 1 or run.granted != 1) {
                std.debug.print(
                    "a routed call did {d} lookups, {d} dials and {d} grants\n",
                    .{ run.lookups, run.dials, run.granted },
                );
                return 5;
            }
            return 0;
        }

        if (std.mem.eql(u8, args[1], "spawn-routed-refused-name")) {
            const run = try routedEscape(
                arena,
                root_arg,
                "routed-refused-name",
                ports,
                filtered_policy,
                &.{"main"},
                filtered_public_address,
                granted.port,
            );
            // A lookup before the refusal would carry a message to that zone.
            if (run.lookups != 0 or run.dials != 0) {
                std.debug.print("a refused name was resolved anyway\n", .{});
                return 5;
            }
            if (granted.hasPending()) {
                std.debug.print("a refused name reached the listener\n", .{});
                return 5;
            }
            return reportChildTerm(run.term);
        }

        if (std.mem.eql(u8, args[1], "spawn-routed-own-resolver")) {
            const run = try routedEscape(
                arena,
                root_arg,
                "routed-own-resolver",
                ports,
                filtered_policy,
                &.{"main"},
                filtered_public_address,
                granted.port,
            );
            // One lookup, so a sandbox where no UDP worked cannot pass here.
            if (run.lookups != 1 or run.dials != 0) {
                std.debug.print(
                    "a child with its own resolver did {d} lookups and {d} dials\n",
                    .{ run.lookups, run.dials },
                );
                return 5;
            }
            if (granted.hasPending()) {
                std.debug.print("a child with its own resolver reached the listener\n", .{});
                return 5;
            }
            return reportChildTerm(run.term);
        }

        if (std.mem.eql(u8, args[1], "spawn-routed-hardcoded") or
            std.mem.eql(u8, args[1], "spawn-routed-metadata") or
            std.mem.eql(u8, args[1], "spawn-routed-flush"))
        {
            const op = args[1]["spawn-".len..];
            const run = try routedEscape(
                arena,
                root_arg,
                op,
                ports,
                filtered_policy,
                &.{"main"},
                filtered_public_address,
                granted.port,
            );
            // Nothing was asked of the far side, so only the kernel refused.
            if (run.lookups != 0 or run.dials != 0) {
                std.debug.print("a child that resolved nothing still used the seam\n", .{});
                return 5;
            }
            if (granted.hasPending()) {
                std.debug.print("a child that resolved nothing reached the listener\n", .{});
                return 5;
            }
            return reportChildTerm(run.term);
        }

        std.debug.print("unknown routed operation: {s}\n", .{args[1]});
        return 2;
    }

    if (std.mem.eql(u8, args[1], "spawn-device-place")) {
        // A file written into the hidden tree after the helper bound it in
        // crosses as a path, and the program reads the bytes back.
        const run = try deviceEscape(arena, root_arg, "spawned-device-place", &.{}, &.{}, &.{}, null);
        if (run.served != 1) {
            std.debug.print("the multiplexed loop drained {d} changes, not 1\n", .{run.served});
            return 5;
        }
        return reportChildTerm(run.term);
    }

    if (std.mem.eql(u8, args[1], "spawn-device-hidden-denied")) {
        // Only the placed node is readable, and never the hidden tree.
        const run = try deviceEscape(arena, root_arg, "spawned-device-hidden-denied", &.{}, &.{}, &.{}, null);
        if (run.served != 1) {
            std.debug.print("the multiplexed loop drained {d} changes, not 1\n", .{run.served});
            return 5;
        }
        return reportChildTerm(run.term);
    }

    if (std.mem.eql(u8, args[1], "spawn-device-with-broker")) {
        // The sandboxed program asks the broker and waits for the device node,
        // so it ends well only if one loop served both descriptors.
        const granted = listenLoopback() catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        defer _ = linux.close(granted.fd);
        const other = listenLoopback() catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        defer _ = linux.close(other.fd);
        const ports = try filteredPorts(arena, granted.port, other.port);

        const policy = try chock_policy.table.Table.parse(arena, filtered_policy, null);
        var io_impl: std.Io.Threaded = .init_single_threaded;
        var transport = ProbeTransport{ .resolves_to = filtered_public_address, .port = granted.port };
        var network = chock_broker.network.Network{
            .gpa = arena,
            .io = io_impl.io(),
            .table = policy,
            .chain = &.{"main"},
            .agent_kind = "main",
            .model = "main",
            .tool = "mcp",
            .transport = transport.transport(),
        };

        const run = try deviceEscape(
            arena,
            root_arg,
            "spawned-filtered-grant-and-device",
            &.{ports},
            &.{},
            &.{},
            network.netBroker(),
        );

        // Both counts on one line, because the caller reads an exit status.
        if (run.served != 1 or network.granted != 1 or network.refused != 0) {
            std.debug.print(
                "the multiplexed loop drained {d} of 1 device changes, and the broker granted {d} of 1 and refused {d} of 0\n",
                .{ run.served, network.granted, network.refused },
            );
            return 5;
        }
        return reportChildTerm(run.term);
    }

    if (std.mem.eql(u8, args[1], "spawn-device-children") or
        std.mem.eql(u8, args[1], "spawn-device-children-none"))
    {
        // A session with no `device_source` forks no helper, so D is the only
        // difference between the two runs.
        const with_device = std.mem.eql(u8, args[1], "spawn-device-children");
        const result = childCountEscape(arena, root_arg, with_device) catch |err| {
            // A host that refuses the namespaces forks no A, so there is no
            // child list to count.
            endIfNothingMeasured(err);
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        var buffer: [16]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "{d}\n", .{result.children}) catch unreachable;
        _ = linux.write(std.posix.STDOUT_FILENO, line.ptr, line.len);
        return reportChildTerm(result.term);
    }

    if (std.mem.startsWith(u8, args[1], "spawn-filtered-")) {
        const granted = listenLoopback() catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        defer _ = linux.close(granted.fd);
        const other = listenLoopback() catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        defer _ = linux.close(other.fd);

        const ports = try filteredPorts(arena, granted.port, other.port);

        if (std.mem.eql(u8, args[1], "spawn-filtered-connect")) {
            const run = try filteredEscape(
                arena,
                root_arg,
                "spawned-filtered-connect",
                ports,
                filtered_policy,
                &.{"main"},
                filtered_public_address,
                granted.port,
            );
            // Nothing was asked of the broker, resolved, or dialled.
            if (run.lookups != 0 or run.dials != 0) {
                std.debug.print("the child that opened its own connection also used the broker\n", .{});
                return 5;
            }
            // The child says what it decided, and the backlogs say what really
            // happened on the wire.
            if (granted.hasPending() or other.hasPending()) {
                std.debug.print("a filtered process reached a listener on its own\n", .{});
                return 5;
            }
            return reportChildTerm(run.term);
        }

        if (std.mem.eql(u8, args[1], "spawn-filtered-grant")) {
            const run = try filteredEscape(
                arena,
                root_arg,
                "spawned-filtered-grant",
                ports,
                filtered_policy,
                &.{"main"},
                filtered_public_address,
                granted.port,
            );
            if (run.granted != 1 or run.refused != 0) {
                std.debug.print("the broker granted {d} and refused {d}\n", .{ run.granted, run.refused });
                return 5;
            }
            // The child's own bytes, on the listener this process dialled.
            var buffer: [64]u8 = undefined;
            const arrived = granted.readFirst(&buffer) orelse {
                std.debug.print("nothing arrived on the listener the broker dialled\n", .{});
                return 5;
            };
            if (!std.mem.eql(u8, arrived, filtered_token)) {
                std.debug.print("the listener read {s}, not the token\n", .{arrived});
                return 5;
            }
            // The half an exit code cannot carry: a re-aim that worked would
            // fill this backlog.
            if (other.hasPending()) {
                std.debug.print("a granted descriptor was aimed at another host\n", .{});
                return 5;
            }
            return reportChildTerm(run.term);
        }

        if (std.mem.eql(u8, args[1], "spawn-filtered-refused")) {
            const run = try filteredEscape(
                arena,
                root_arg,
                "spawned-filtered-refused",
                ports,
                filtered_policy,
                &.{"main"},
                filtered_public_address,
                granted.port,
            );
            if (run.refused != 1 or run.granted != 1) {
                std.debug.print("the broker granted {d} and refused {d}\n", .{ run.granted, run.refused });
                return 5;
            }
            // An uncovered name is not even a message to its own zone.
            if (run.lookups != 1 or run.dials != 1) {
                std.debug.print("the broker looked up {d} names and dialled {d}\n", .{ run.lookups, run.dials });
                return 5;
            }
            if (other.hasPending()) {
                std.debug.print("a refused host reached a listener\n", .{});
                return 5;
            }
            return reportChildTerm(run.term);
        }

        if (std.mem.eql(u8, args[1], "spawn-filtered-chain-root") or
            std.mem.eql(u8, args[1], "spawn-filtered-chain-subagent"))
        {
            const root_only = std.mem.eql(u8, args[1], "spawn-filtered-chain-root");
            const chain: []const []const u8 = if (root_only) &.{"fetcher"} else &.{ "main", "fetcher" };
            const run = try filteredEscape(
                arena,
                root_arg,
                "spawned-filtered-ask",
                ports,
                filtered_deny_parent_policy,
                chain,
                filtered_public_address,
                granted.port,
            );
            return reportChildTerm(run.term);
        }

        if (std.mem.eql(u8, args[1], "spawn-filtered-budget")) {
            const run = try filteredEscape(
                arena,
                root_arg,
                "spawned-filtered-budget",
                ports,
                filtered_policy,
                &.{"main"},
                filtered_public_address,
                granted.port,
            );
            // The far end answered its budget and stopped, and every answer
            // was a refusal that resolved and dialled nothing.
            if (run.refused != sandbox.net_broker.max_requests or run.granted != 0) {
                std.debug.print("the broker granted {d} and refused {d}\n", .{ run.granted, run.refused });
                return 5;
            }
            if (run.lookups != 0 or run.dials != 0) {
                std.debug.print("the broker looked up {d} names and dialled {d}\n", .{ run.lookups, run.dials });
                return 5;
            }
            return reportChildTerm(run.term);
        }

        // The policy says yes and `addressIsReachable` says no, so that check
        // runs inside a real spawn.
        if (std.mem.eql(u8, args[1], "spawn-filtered-loopback")) {
            const run = try filteredEscape(
                arena,
                root_arg,
                "spawned-filtered-ask",
                ports,
                filtered_policy,
                &.{"main"},
                .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
                granted.port,
            );
            // The name resolved and nothing was dialled, so the address check
            // is what refused it.
            if (run.lookups != 1 or run.dials != 0) {
                std.debug.print("the broker looked up {d} names and dialled {d}\n", .{ run.lookups, run.dials });
                return 5;
            }
            return reportChildTerm(run.term);
        }

        // `ask_policy` names no rule, so the table answers `ask` and routes the
        // connection through a `Broker.request` inside this spawn's own loop.
        if (std.mem.eql(u8, args[1], "spawn-filtered-ask-grant")) {
            const run = try askingEscape(
                arena,
                root_arg,
                "spawned-filtered-ask",
                ports,
                filtered_public_address,
                granted.port,
                &.{.approved_by_user},
                true,
                null,
            );
            if (run.granted != 1 or run.refused != 0) {
                std.debug.print("the broker granted {d} and refused {d}\n", .{ run.granted, run.refused });
                return 5;
            }
            if (run.requests != 1 or run.responses != 1) {
                std.debug.print("the log holds {d} requests and {d} responses\n", .{ run.requests, run.responses });
                return 5;
            }
            if (run.verdict != .intact) {
                std.debug.print("the log's own chain read back as {s}\n", .{@tagName(run.verdict)});
                return 5;
            }
            if (!run.turn_intact) {
                std.debug.print("the turn that was already in flight did not come back intact\n", .{});
                return 5;
            }
            return reportChildTerm(run.term);
        }

        // A refusal must reach the log and the child as faithfully as a grant.
        if (std.mem.eql(u8, args[1], "spawn-filtered-ask-refuse")) {
            const run = try askingEscape(
                arena,
                root_arg,
                "spawned-filtered-ask",
                ports,
                filtered_public_address,
                granted.port,
                &.{.refused_by_user},
                true,
                null,
            );
            if (run.granted != 0 or run.refused != 1) {
                std.debug.print("the broker granted {d} and refused {d}\n", .{ run.granted, run.refused });
                return 5;
            }
            if (run.requests != 1 or run.responses != 1) {
                std.debug.print("the log holds {d} requests and {d} responses\n", .{ run.requests, run.responses });
                return 5;
            }
            if (run.verdict != .intact) {
                std.debug.print("the log's own chain read back as {s}\n", .{@tagName(run.verdict)});
                return 5;
            }
            if (!run.turn_intact) {
                std.debug.print("the turn that was already in flight did not come back intact\n", .{});
                return 5;
            }
            return reportChildTerm(run.term);
        }

        // `askTheHuman`'s own deadline ends the wait and writes `expired`, so
        // the question neither hangs nor looks like a refusal.
        if (std.mem.eql(u8, args[1], "spawn-filtered-ask-timeout")) {
            const run = try askingEscape(
                arena,
                root_arg,
                "spawned-filtered-ask",
                ports,
                filtered_public_address,
                granted.port,
                &.{.approved_by_user},
                false,
                null,
            );
            if (run.granted != 0 or run.refused != 1) {
                std.debug.print("the broker granted {d} and refused {d}\n", .{ run.granted, run.refused });
                return 5;
            }
            // The deadline writes `expired`, so the question does not sit open.
            if (run.requests != 1 or run.responses != 1) {
                std.debug.print("the log holds {d} requests and {d} responses\n", .{ run.requests, run.responses });
                return 5;
            }
            if (run.verdict != .intact) {
                std.debug.print("the log's own chain read back as {s}\n", .{@tagName(run.verdict)});
                return 5;
            }
            if (!run.turn_intact) {
                std.debug.print("the turn that was already in flight did not come back intact\n", .{});
                return 5;
            }
            return reportChildTerm(run.term);
        }

        // A cancelled wait leaves the question open, and the call still ends.
        if (std.mem.eql(u8, args[1], "spawn-filtered-ask-cancel")) {
            const run = try askingEscape(
                arena,
                root_arg,
                "spawned-filtered-ask",
                ports,
                filtered_public_address,
                granted.port,
                &.{.approved_by_user},
                false,
                1,
            );
            if (run.granted != 0 or run.refused != 1) {
                std.debug.print("the broker granted {d} and refused {d}\n", .{ run.granted, run.refused });
                return 5;
            }
            if (run.requests != 1 or run.responses != 0) {
                std.debug.print("the log holds {d} requests and {d} responses\n", .{ run.requests, run.responses });
                return 5;
            }
            if (run.verdict != .intact) {
                std.debug.print("the log's own chain read back as {s}\n", .{@tagName(run.verdict)});
                return 5;
            }
            if (!run.turn_intact) {
                std.debug.print("the turn that was already in flight did not come back intact\n", .{});
                return 5;
            }
            return reportChildTerm(run.term);
        }

        // Two hosts in one `Sandbox.spawn`, each with its own answer, in order.
        if (std.mem.eql(u8, args[1], "spawn-filtered-ask-two")) {
            const run = try askingEscape(
                arena,
                root_arg,
                "spawned-filtered-ask-two",
                ports,
                filtered_public_address,
                granted.port,
                &.{ .approved_by_user, .refused_by_user },
                true,
                null,
            );
            if (run.granted != 1 or run.refused != 1) {
                std.debug.print("the broker granted {d} and refused {d}\n", .{ run.granted, run.refused });
                return 5;
            }
            if (run.requests != 2 or run.responses != 2) {
                std.debug.print("the log holds {d} requests and {d} responses\n", .{ run.requests, run.responses });
                return 5;
            }
            if (run.verdict != .intact) {
                std.debug.print("the log's own chain read back as {s}\n", .{@tagName(run.verdict)});
                return 5;
            }
            if (!run.turn_intact) {
                std.debug.print("the turn that was already in flight did not come back intact\n", .{});
                return 5;
            }
            return reportChildTerm(run.term);
        }

        std.debug.print("unknown filtered network operation: {s}\n", .{args[1]});
        return 2;
    }

    if (std.mem.eql(u8, args[1], "spawn-landlock-escape")) {
        // A plain subdirectory of root, carried in by the same recursive bind
        // as the rest, so only the ruleset can refuse the read.
        const unguarded = try std.fs.path.join(arena, &.{ root_arg, "unguarded" });
        try makeTestDir(arena, unguarded);
        const marker = try std.fs.path.join(arena, &.{ unguarded, "marker" });
        try writeTestFile(arena, marker, "chock landlock escape probe content\n");

        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-landlock-read" }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-network-escape")) {
        // `.network` is left off, so the default on Sandbox.Config decides.
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
        }, &.{ "/probe", "spawned-connect" }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-signal-host")) {
        // id_arg is the pid of a real process the caller made outside every
        // namespace, so a refusal is not about an unused number.
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-signal-host", id_arg }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-shm-attach")) {
        // id_arg is a real segment the caller made outside every namespace.
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-shm-attach", id_arg }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-report-pid")) {
        // The program does no setup, so the number it prints is a fact about
        // the pid namespace spawn's applyLayers built.
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-report-pid" }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-default-signal")) {
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-default-signal" }, null, null);

        return switch (term) {
            .signal => |signal| if (signal == .TERM) 0 else 5,
            else => 6,
        };
    }
    if (std.mem.eql(u8, args[1], "spawn-keeper-reaps")) {
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-keeper-reaps" }, null, null);
        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-supervisor-audit")) {
        // The supervisor holds the provider credential while it waits, and puts
        // a seccomp filter on itself for that reason. The install is best
        // effort, so this reads the record back rather than trust it.
        const base = try baseEscapeConfig(arena);
        var audit: sandbox.Sandbox.SupervisorAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .supervisor_audit = &audit,
        }, &.{ "/probe", "spawned-report-pid" }, null, null);

        // The program has to have run, or the counts are about nothing.
        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }

        // Every layer the supervisor puts on itself, and the status carries
        // which one as well as what went wrong.
        const watched = [_]sandbox.Sandbox.LayerName{ .capabilities, .landlock, .seccomp };
        for (watched, 0..) |layer, index| {
            const base_status: u8 = @intCast(10 + index * 4);
            const counts = audit.counts(layer);
            // Nothing said is a failure: this machine builds sandboxes.
            if (counts.unreported != 0) return base_status;
            // The supervisor could not put the layer on, which is what the
            // record exists for.
            if (counts.unconfined != 0) return base_status + 1;
            if (counts.confined != 1) return base_status + 2;
            if (counts.first_fault != null) return base_status + 3;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-syscall-audit-daemon")) {
        // The program leaves a process behind that still carries the filter.
        // The supervisor watches the program, so this call comes back at once.
        const base = try baseEscapeConfig(arena);
        var audit: sandbox.Sandbox.SyscallAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .seccomp_options = .{ .traps = sandbox.seccomp.TrapSet.initFull() },
            .syscall_audit = &audit,
            .path_audit = true,
        }, &.{ "/probe", "spawned-leave-daemon" }, null, null);

        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }
        if (audit.paths.readers_absent != 0 or audit.paths.readers_unreported != 0) return 5;
        const openat_slot = @intFromEnum(sandbox.seccomp.TrapCall.openat);
        if (audit.counts().calls[openat_slot] != 0) return 6;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-path-audit") or
        std.mem.eql(u8, args[1], "spawn-path-audit-off"))
    {
        // A third process, forked inside the sandboxed program's own pid
        // namespace, copies the path argument out of the held call before it
        // answers. The second name runs the same program with no path audit.
        const auditing = std.mem.eql(u8, args[1], "spawn-path-audit");
        const base = try baseEscapeConfig(arena);
        var audit: sandbox.Sandbox.SyscallAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .seccomp_options = .{ .traps = sandbox.seccomp.TrapSet.initFull() },
            .syscall_audit = &audit,
            .path_audit = auditing,
        }, &.{ "/probe", "spawned-name-paths" }, null, null);

        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }

        const slot = @intFromEnum(sandbox.seccomp.TrapCall.openat);
        const seen = &audit.paths.seen;
        if (!auditing) {
            // Nothing was asked for, so a count above zero came from elsewhere.
            if (seen.kept != 0) return 5;
            if (seen.granted[slot] != 0 or seen.ungranted[slot] != 0) return 6;
            if (audit.paths.readers_unreported != 0 or audit.paths.readers_absent != 0) return 7;
            // The counting still works with no path audit.
            if (audit.counts().calls[slot] == 0) return 8;
            return 0;
        }

        // The reader reached its loop and reported its end. The keeper holds
        // process 1, so B's exit cannot kill the reader during its report.
        if (audit.paths.readers_absent != 0) return 9;
        if (audit.paths.readers_unreported != 0) return 10;

        // Two granted paths were opened, so a zero is a misclassification.
        if (seen.granted[slot] == 0) return 11;

        var named_the_secret = false;
        var named_a_grant = false;
        var kept: u32 = 0;
        while (kept < seen.kept) : (kept += 1) {
            const name = seen.name(kept);
            if (std.mem.eql(u8, name, named_ungranted)) named_the_secret = true;
            if (std.mem.startsWith(u8, name, named_granted)) named_a_grant = true;
        }
        // The ungranted path was named three times, so the set holds it once.
        if (!named_the_secret) return 12;
        // Not one of the opens under a granted tree is named.
        if (named_a_grant) return 13;
        // Three attempts on the one ungranted path and nothing else: the
        // program is statically linked, so it makes only two other opens.
        if (seen.ungranted[slot] != 3) return 14;
        if (seen.kept != 1) return 15;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-path-audit-dynamic")) {
        // A dynamic loader runs before the program's first line and opens
        // dozens of granted files, so only the ungranted name is kept.
        const base = try baseEscapeConfig(arena);
        const mounts = try arena.alloc(sandbox.namespace.Mount, base.mounts.len + 1);
        @memcpy(mounts[0..base.mounts.len], base.mounts);
        mounts[base.mounts.len] = .{ .bind = .{
            .source = try absolutePath(arena, dynamic_probe_path),
            .target = "/dynamic",
            .read_only = true,
        } };
        const rules = try arena.alloc(sandbox.Config.Rule, base.rules.len + 1);
        @memcpy(rules[0..base.rules.len], base.rules);
        // A file and not a directory, so `read_only_file` and never
        // `read_only`: the kernel refuses a directory right over a file.
        rules[base.rules.len] = .{
            .path = "/dynamic",
            .access = sandbox.landlock.AccessFs.read_only_file,
        };

        var audit: sandbox.Sandbox.SyscallAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .seccomp_options = .{ .traps = sandbox.seccomp.TrapSet.initFull() },
            .syscall_audit = &audit,
            .path_audit = true,
        }, &.{"/dynamic"}, null, null);

        // A dynamic program that cannot find its interpreter dies before
        // `main`, and the counts would be about that.
        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }

        const slot = @intFromEnum(sandbox.seccomp.TrapCall.openat);
        const seen = &audit.paths.seen;
        if (audit.paths.readers_absent != 0) return 5;
        if (audit.paths.readers_unreported != 0) return 6;

        // The program opens one ungranted path, so every granted open here
        // belongs to the dynamic loader.
        if (seen.granted[slot] == 0) return 7;

        // A name count above one is the loader's own opens taking the slots.
        if (seen.kept != 1) return 8;
        if (!std.mem.eql(u8, seen.name(0), named_ungranted)) return 9;
        if (seen.name_call[0] != slot) return 10;
        // Nothing was lost to the cap, so the count above is a whole answer.
        if (seen.ungranted_unnamed[slot] != 0) return 11;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-path-audit-killed")) {
        // The supervisor holds no copy of the notification descriptor, so the
        // reader's death makes the kernel answer held calls with ENOSYS.
        const base = try baseEscapeConfig(arena);
        var audit: sandbox.Sandbox.SyscallAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .seccomp_options = .{ .traps = sandbox.seccomp.TrapSet.initFull() },
            .syscall_audit = &audit,
            .path_audit = true,
        }, &.{ "/probe", "spawned-kill-the-reader" }, null, null);

        // The program says whether the kernel answered ENOSYS.
        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }
        // The reader reached its loop, so it was killed and never absent.
        if (audit.paths.readers_absent != 0) return 5;
        // A reader that was killed wrote no report, and the session counts it.
        if (audit.paths.readers_unreported != 1) return 6;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-path-audit-stopped")) {
        const on_alarm = std.posix.Sigaction{
            .handler = .{ .handler = endOnAlarm },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        if (linux.errno(linux.sigaction(.ALRM, &on_alarm, null)) != .SUCCESS) return 10;
        const alarm: linux.itimerspec = .{
            .it_interval = .{ .sec = 0, .nsec = 0 },
            .it_value = .{ .sec = 3, .nsec = 0 },
        };
        if (linux.errno(linux.setitimer(@intFromEnum(linux.ITIMER.REAL), &alarm, null)) != .SUCCESS)
            return 11;

        const base = try baseEscapeConfig(arena);
        var audit: sandbox.Sandbox.SyscallAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .seccomp_options = .{ .traps = sandbox.seccomp.TrapSet.initFull() },
            .syscall_audit = &audit,
            .path_audit = true,
        }, &.{ "/probe", "spawned-stop-the-reader" }, null, null);

        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }
        if (audit.paths.readers_absent != 0) return 5;
        if (audit.paths.readers_unreported != 0) return 6;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-syscall-audit") or
        std.mem.eql(u8, args[1], "spawn-syscall-audit-off"))
    {
        // The process that runs the program hands the notification descriptor
        // to the supervisor. The second name is the control, with no trap set.
        const watching = std.mem.eql(u8, args[1], "spawn-syscall-audit");
        const base = try baseEscapeConfig(arena);
        var audit: sandbox.Sandbox.SyscallAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .seccomp_options = .{
                .traps = if (watching)
                    sandbox.seccomp.TrapSet.initFull()
                else
                    sandbox.seccomp.TrapSet.initEmpty(),
            },
            .syscall_audit = &audit,
        }, &.{ "/probe", "spawned-count-opens" }, null, null);

        // The deadlock check as well: a stalled handover never reaches here.
        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }

        const counts = audit.counts();
        const opens = counts.calls[@intFromEnum(sandbox.seccomp.TrapCall.openat)];
        const execs = counts.calls[@intFromEnum(sandbox.seccomp.TrapCall.execve)];
        const dirs = counts.calls[@intFromEnum(sandbox.seccomp.TrapCall.getdents64)];
        const connects = counts.calls[@intFromEnum(sandbox.seccomp.TrapCall.connect)];

        if (!watching) {
            // Nothing was asked for, so a count above zero comes from
            // somewhere other than the filter.
            if (counts.observed != 0 or counts.unobserved != 0) return 5;
            if (opens != 0 or execs != 0 or dirs != 0 or connects != 0) return 6;
            return 0;
        }

        // The supervisor could not watch the call, which the record exists for.
        if (counts.unobserved != 0) return 7;
        if (counts.observed != 1) return 8;
        // That one `execve` is the call the handover had to finish before.
        if (execs != 1) return 9;
        // At least what the program made: the loader opens more on the way in.
        if (opens < opens_in_probe) return 10;
        // The program asked for neither, so a count above zero is misfiled.
        if (dirs != 0 or connects != 0) return 11;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-open-fd-set") or
        std.mem.eql(u8, args[1], "spawn-open-fd-set-filtered"))
    {
        // None is marked close-on-exec, or the kernel does the revoking.
        const filtered = std.mem.eql(u8, args[1], "spawn-open-fd-set-filtered");
        const base = try baseEscapeConfig(arena);
        const held = try HarnessDescriptors.open(arena, root_arg);
        if (held.openCount() < required_harness_descriptors) {
            std.debug.print("spawn-open-fd-set: this machine gave too few descriptors to check\n", .{});
            return 5;
        }

        var refuser = RefusingBroker{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = if (filtered) .filtered else .none,
            .net_broker = if (filtered) refuser.broker() else null,
        }, &.{
            "/probe",
            "spawned-open-fd-set",
            if (filtered) "filtered" else "plain",
        }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-caps-drop")) {
        // The program does no setup, so an empty bounding set is a fact about
        // spawn's own applyLayers.
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-caps-drop" }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-stdin-devnull")) {
        // The program does no setup, so what statx answers for descriptor 0 is
        // what spawn's own child put there.
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-stdin-devnull" }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-stdin-pipe")) {
        // A real pipe named in `Config.stdin_fd`. See `spawned-stdin-pipe`.
        var pipe_fds: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&pipe_fds, .{})) != .SUCCESS) return 5;
        const read_fd = pipe_fds[0];
        const write_fd = pipe_fds[1];

        // Written before the sandbox is built, and far below any pipe buffer,
        // so nothing here reads and writes at once.
        const written = linux.write(write_fd, stdin_pipe_token, stdin_pipe_token.len);
        if (linux.errno(written) != .SUCCESS or written != stdin_pipe_token.len) return 5;
        // Closed now, so the program reads end of file after the token.
        _ = linux.close(write_fd);

        // The leak `closeInheritedFds` revokes, which naming one descriptor to
        // keep must not spare.
        const escape_rc = linux.open("/", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        if (linux.errno(escape_rc) != .SUCCESS) return 5;
        const escape_fd: i32 = @intCast(escape_rc);
        const escape_text = try std.fmt.allocPrint(arena, "{d}", .{escape_fd});

        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .stdin_fd = read_fd,
        }, &.{ "/probe", "spawned-stdin-pipe", escape_text }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-setup-fault-named-stderr")) {
        // The pipe named in `Config.stderr_fd` is copied to descriptor 1 and
        // descriptor 2 is left alone, so the test sees which one got the line.
        var pipe_fds: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&pipe_fds, .{})) != .SUCCESS) return 5;
        const read_fd = pipe_fds[0];
        const write_fd = pipe_fds[1];

        const absent = try absentRoot(arena, root_arg);
        if (sandbox.spawn(arena, .{
            .root = absent,
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
            .stderr_fd = write_fd,
        }, &.{"/probe"}, null, null)) |_| {
            // A sandbox that came up on a root that is not there is its own
            // answer.
            return 5;
        } else |err| {
            endIfNothingMeasured(err);
            if (err != error.MountTreeFailed) return 5;
        }

        // Closed so the read below reaches end of file. `spawn` has returned,
        // so every other copy is gone.
        _ = linux.close(write_fd);
        var buffer: [512]u8 = undefined;
        const arrived = readToEnd(read_fd, &buffer);
        _ = linux.close(read_fd);

        const wrote = linux.write(std.posix.STDOUT_FILENO, arrived.ptr, arrived.len);
        if (linux.errno(wrote) != .SUCCESS or wrote != arrived.len) return 5;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-setup-fault-closed-stderr")) {
        // The pipe named in `Config.stderr_fd` has its read end closed before
        // `spawn` is called, so writing the reason answers `EPIPE` and raises
        // `SIGPIPE`. `spawn` must still answer the error and not a `Term`, which
        // holds because the record reaches the setup pipe before the text.
        //
        // The kernel discards a default action signal for the process 1 of a
        // namespace, so this failure has to be one the middle process meets.
        var pipe_fds: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&pipe_fds, .{})) != .SUCCESS) return 5;
        _ = linux.close(pipe_fds[0]);
        const write_fd = pipe_fds[1];

        if (sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
            .scratch = &.{
                .{ .target = "/run/chock/one" },
                .{ .target = "/run/chock/two" },
                .{ .target = "/run/chock/three" },
                .{ .target = "/run/chock/four" },
                .{ .target = "/run/chock/five" },
            },
            .stderr_fd = write_fd,
        }, &.{"/probe"}, null, null)) |_| {
            return 5;
        } else |err| {
            endIfNothingMeasured(err);
            if (err != error.ScratchMountFailed) return 5;
        }
        _ = linux.close(write_fd);
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-setup-fault-default-stderr")) {
        // With nothing named in `Config.stderr_fd`, the reason must land on
        // descriptor 2, which nothing else here writes to.
        const absent = try absentRoot(arena, root_arg);
        if (sandbox.spawn(arena, .{
            .root = absent,
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
        }, &.{"/probe"}, null, null)) |_| {
            return 5;
        } else |err| {
            endIfNothingMeasured(err);
            if (err != error.MountTreeFailed) return 5;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-proc-mask") or std.mem.eql(u8, args[1], "spawn-proc-live")) {
        // The mask is made by `buildRoot`, which only runs inside spawn's own
        // child, and a procfs mounted anywhere else would be the host's.
        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, sandbox.namespace.Mount, &.{
            base.mounts,
            &.{.{ .proc = .{} }},
        });
        // A mount with no rule is present and unreachable.
        const rules = try std.mem.concat(arena, sandbox.Config.Rule, &.{
            base.rules,
            &.{.{ .path = "/proc", .access = sandbox.landlock.AccessFs.read_only }},
        });

        const inner: []const u8 = if (std.mem.eql(u8, args[1], "spawn-proc-mask"))
            "spawned-proc-mask"
        else
            "spawned-proc-live";

        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", inner }, null, null);

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-forge-exit")) {
        // If spawn read the forged exit code as a setup failure it would empty
        // the root, and the file the program wrote would be gone.
        const work = try std.fs.path.join(arena, &.{ root_arg, "work" });
        try makeTestDir(arena, work);

        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, sandbox.namespace.Mount, &.{
            base.mounts,
            &.{.{ .bind = .{ .source = work, .target = "/work", .read_only = false } }},
        });
        const rules = try std.mem.concat(arena, sandbox.Config.Rule, &.{
            base.rules,
            &.{.{ .path = "/work", .access = sandbox.landlock.AccessFs.read_write }},
        });

        const term = sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-forge-exit" }, null, null) catch |err| {
            // The fault: spawn read a forged exit code as a setup failure.
            endIfNothingMeasured(err);
            std.debug.print("spawn-forge-exit: spawn reported a setup failure: {s}\n", .{@errorName(err)});
            return 3;
        };

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-signal-middle") or
        std.mem.eql(u8, args[1], "spawn-signal-middle-forked") or
        std.mem.eql(u8, args[1], "spawn-signal-middle-setsid"))
    {
        // spawn is synchronous, so a thread of its own is the only way to hand
        // the forked pid back while spawn is still blocked.
        const inner: []const u8 = if (std.mem.eql(u8, args[1], "spawn-signal-middle-forked"))
            "spawned-fork-loop-write"
        else if (std.mem.eql(u8, args[1], "spawn-signal-middle-setsid"))
            "spawned-setsid-fork-loop-write"
        else
            "spawned-loop-write";

        const work = try std.fs.path.join(arena, &.{ root_arg, "work" });
        try makeTestDir(arena, work);

        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, sandbox.namespace.Mount, &.{
            base.mounts,
            &.{.{ .bind = .{ .source = work, .target = "/work", .read_only = false } }},
        });
        const rules = try std.mem.concat(arena, sandbox.Config.Rule, &.{
            base.rules,
            &.{.{ .path = "/work", .access = sandbox.landlock.AccessFs.read_write }},
        });

        const SpawnCtx = struct {
            allocator: std.mem.Allocator,
            root: []const u8,
            mounts: []const sandbox.namespace.Mount,
            rules: []const sandbox.Config.Rule,
            inner: []const u8,
            middle: sandbox.Middle = .{},
            term: std.process.Child.Term = undefined,
            spawn_err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.term = sandbox.spawn(self.allocator, .{
                    .root = self.root,
                    .mounts = self.mounts,
                    .rules = self.rules,
                    .cwd = "/",
                    .env = &.{},
                    .network = .none,
                }, &.{ "/probe", self.inner }, null, &self.middle) catch |err| {
                    self.spawn_err = err;
                    return;
                };
            }
        };
        var ctx = SpawnCtx{
            .allocator = arena,
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .inner = inner,
        };

        const thread = std.Thread.spawn(.{}, SpawnCtx.run, .{&ctx}) catch |err| {
            std.debug.print("{s}: could not start the spawn thread: {s}\n", .{ args[1], @errorName(err) });
            return 3;
        };

        // spawn fills the handle in right after its first fork, so two seconds
        // is generous and never a wait that could hang the suite.
        var waited_ns: u64 = 0;
        while (ctx.middle.pid == 0 and waited_ns < 2_000_000_000) : (waited_ns += 1_000_000) {
            _ = linux.nanosleep(&.{ .sec = 0, .nsec = 1_000_000 }, null);
        }
        if (ctx.middle.pid == 0) {
            // The join first, because that is what makes the read safe.
            thread.join();
            if (ctx.spawn_err) |err| endIfNothingMeasured(err);
            std.debug.print("{s}: never learned the middle process\n", .{args[1]});
            return 3;
        }

        var pid_line_buf: [16]u8 = undefined;
        const pid_line = std.fmt.bufPrint(&pid_line_buf, "{d}\n", .{ctx.middle.pid}) catch unreachable;
        _ = linux.write(std.posix.STDOUT_FILENO, pid_line.ptr, pid_line.len);

        thread.join();
        // The caller of `spawn` owns the handle. After the join, never before.
        sandbox.closeMiddle(&ctx.middle);
        if (ctx.spawn_err) |err| {
            endIfNothingMeasured(err);
            std.debug.print("{s}: spawn reported a setup failure: {s}\n", .{ args[1], @errorName(err) });
            return 3;
        }

        return reportChildTerm(ctx.term);
    }

    if (std.mem.eql(u8, args[1], "spawn-signal-group")) {
        // A group of its own, so a sandbox that signals its caller's group
        // reaches no further than this process.
        if (linux.errno(linux.setpgid(0, 0)) != .SUCCESS) {
            std.debug.print("spawn-signal-group: setpgid failed\n", .{});
            return 3;
        }
        catchSignal(.USR1);

        // The handler has to be live before spawn forks, or "no signal
        // arrived" below is true for the wrong reason.
        std.posix.raise(.USR1) catch |err| {
            std.debug.print("spawn-signal-group: could not raise USR1: {s}\n", .{@errorName(err)});
            return 3;
        };
        if (!caller_signal_seen.load(.monotonic)) {
            std.debug.print("spawn-signal-group: the handler never ran on a raise here\n", .{});
            return 3;
        }
        caller_signal_seen.store(false, .monotonic);

        const base = try baseEscapeConfig(arena);
        _ = sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-signal-group" }, null, null) catch |err| {
            endIfNothingMeasured(err);
            std.debug.print("spawn-signal-group: spawn reported a setup failure: {s}\n", .{@errorName(err)});
            return 3;
        };

        // The Term is dropped on purpose: a contained call ends the sandbox's
        // own group, so what separates the outcomes is this process.
        return if (caller_signal_seen.load(.monotonic)) 1 else 0;
    }

    if (std.mem.eql(u8, args[1], "spawn-group-press")) {
        // A group of its own, so the press never reaches the test runner.
        if (linux.errno(linux.setpgid(0, 0)) != .SUCCESS) {
            std.debug.print("spawn-group-press: setpgid failed\n", .{});
            return 3;
        }
        catchSignal(.USR1);

        const config = try workEscapeConfig(arena, root_arg);
        var ctx = ThreadedSpawn{
            .allocator = arena,
            .root = root_arg,
            .mounts = config.mounts,
            .rules = config.rules,
            .argv = &.{ "/probe", "spawned-group-press" },
        };
        const thread = std.Thread.spawn(.{}, ThreadedSpawn.run, .{&ctx}) catch |err| {
            std.debug.print("spawn-group-press: could not start the spawn thread: {s}\n", .{@errorName(err)});
            return 3;
        };
        // Registered before the join, so it runs after it: the handle must
        // outlive the call it names.
        defer ctx.closeHandle();
        defer thread.join();

        const started_path = try std.fmt.allocPrintSentinel(arena, "{s}/work/started", .{root_arg}, 0);
        const go_path = try std.fmt.allocPrintSentinel(arena, "{s}/work/go", .{root_arg}, 0);
        if (!waitForPath(started_path)) {
            ctx.endIfSandboxRefused();
            std.debug.print("spawn-group-press: the sandboxed program never started\n", .{});
            ctx.killCall();
            return 3;
        }

        // A terminal signals the whole foreground group, never one process.
        if (linux.errno(linux.kill(0, .USR1)) != .SUCCESS) {
            std.debug.print("spawn-group-press: the press itself failed\n", .{});
            ctx.killCall();
            return 3;
        }

        // It ran to here, so the press did not kill the call.
        writeTestFile(arena, go_path, "go\n") catch |err| {
            std.debug.print("spawn-group-press: could not write go: {s}\n", .{@errorName(err)});
            ctx.killCall();
            return 3;
        };

        if (!ctx.waitForDone()) {
            ctx.endIfSandboxRefused();
            std.debug.print("spawn-group-press: the call never finished\n", .{});
            ctx.killCall();
            return 3;
        }
        if (ctx.spawn_err) |err| {
            endIfNothingMeasured(err);
            std.debug.print("spawn-group-press: spawn reported a setup failure: {s}\n", .{@errorName(err)});
            return 3;
        }
        // The press has to have arrived somewhere.
        if (!caller_signal_seen.load(.monotonic)) {
            std.debug.print("spawn-group-press: the press reached nothing at all\n", .{});
            return 3;
        }

        switch (ctx.term) {
            .exited => |code| return if (code <= 1) code else 5,
            else => {
                std.debug.print("spawn-group-press: the call died: {any}\n", .{ctx.term});
                return 5;
            },
        }
    }

    if (std.mem.eql(u8, args[1], "spawn-signal-middle-handled")) {
        // A SIGTERM handler installed before spawn, as `chock run` does. The
        // process spawn forks keeps it and can catch the cancelling signal.
        catchSignal(.TERM);

        // Prove the handler is live here first, or a `catchSignal` that did
        // nothing makes the whole operation pass.
        std.posix.raise(.TERM) catch |err| {
            std.debug.print("spawn-signal-middle-handled: could not raise TERM: {s}\n", .{@errorName(err)});
            return 3;
        };
        if (!caller_signal_seen.load(.monotonic)) {
            std.debug.print("spawn-signal-middle-handled: the handler never ran on a raise here\n", .{});
            return 3;
        }
        caller_signal_seen.store(false, .monotonic);

        const config = try workEscapeConfig(arena, root_arg);
        var ctx = ThreadedSpawn{
            .allocator = arena,
            .root = root_arg,
            .mounts = config.mounts,
            .rules = config.rules,
            .argv = &.{ "/probe", "spawned-loop-write" },
        };
        const thread = std.Thread.spawn(.{}, ThreadedSpawn.run, .{&ctx}) catch |err| {
            std.debug.print("spawn-signal-middle-handled: could not start the spawn thread: {s}\n", .{@errorName(err)});
            return 3;
        };
        // Registered before the join, so it runs after it: the handle must
        // outlive the call it names.
        defer ctx.closeHandle();
        defer thread.join();

        // A non zero pid is how `spawn` says the handle is there to read.
        if (ctx.waitForMiddlePid() == 0) {
            ctx.endIfSandboxRefused();
            std.debug.print("spawn-signal-middle-handled: never learned the middle process\n", .{});
            return 3;
        }

        // Wait for the program, so the signal has something to cancel.
        const heartbeat_path = try std.fmt.allocPrintSentinel(arena, "{s}/work/heartbeat.txt", .{root_arg}, 0);
        if (!waitForPath(heartbeat_path)) {
            ctx.endIfSandboxRefused();
            std.debug.print("spawn-signal-middle-handled: the sandboxed program never started\n", .{});
            ctx.killCall();
            return 3;
        }

        // SIGTERM to the process spawn forked, through the handle, never to
        // the sandboxed program.
        sandbox.signalMiddle(ctx.middle.fd, .TERM) catch |err| {
            std.debug.print("spawn-signal-middle-handled: could not signal the middle process: {s}\n", .{@errorName(err)});
            ctx.killCall();
            return 3;
        };

        if (!ctx.waitForDone()) {
            // The middle process caught this process's own handler and stayed
            // alive, so spawn is still blocked on it.
            ctx.endIfSandboxRefused();
            std.debug.print("spawn-signal-middle-handled: the call outlived its own cancellation\n", .{});
            ctx.killCall();
            return 1;
        }
        if (ctx.spawn_err) |err| {
            endIfNothingMeasured(err);
            std.debug.print("spawn-signal-middle-handled: spawn reported a setup failure: {s}\n", .{@errorName(err)});
            return 3;
        }

        switch (ctx.term) {
            .signal => |sig| {
                if (sig != .TERM) {
                    std.debug.print("spawn-signal-middle-handled: died from {s}\n", .{@tagName(sig)});
                    return 5;
                }
                return 0;
            },
            else => {
                std.debug.print("spawn-signal-middle-handled: ended as {any}\n", .{ctx.term});
                return 5;
            },
        }
    }

    // personality(READ_IMPLIES_EXEC) adds PROT_EXEC to every later mapping,
    // after seccomp has read the prot argument.
    if (std.mem.eql(u8, args[1], "personality-rwx")) {
        const read_implies_exec: usize = 0x0400000;
        const rc = linux.syscall1(.personality, read_implies_exec);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    // 0xffffffff only reads the current personality and changes nothing, so the
    // filter must let it through.
    if (std.mem.eql(u8, args[1], "personality-read")) {
        const read_current: usize = 0xffffffff;
        const rc = linux.syscall1(.personality, read_current);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    const prot_read: u32 = 0x1;
    const prot_write: u32 = 0x2;
    const prot_exec: u32 = 0x4;
    const map_private_anon: u32 = 0x02 | 0x20;

    // Zig 0.16's mmap and mprotect take the PROT and MAP flags as packed
    // structs, while the filter reads the same bits off the raw argument.
    if (std.mem.eql(u8, args[1], "mmap-wx")) {
        const prot: linux.PROT = @bitCast(prot_write | prot_exec);
        const flags: linux.MAP = @bitCast(map_private_anon);
        const rc = linux.mmap(null, 4096, prot, flags, -1, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "ptrace-relaxed")) {
        // The relaxed setting turns off one rule, so this must still die.
        const rc = linux.syscall4(.ptrace, 0, 0, 0, 0);
        // The filter kills the process, so this line never runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "io-uring-setup-relaxed")) {
        // Refused with EPERM under the relaxed filter too: it names one rule.
        var params: linux.io_uring_params = std.mem.zeroes(linux.io_uring_params);
        const rc = linux.io_uring_setup(1, &params);
        return ringRefusal(rc);
    }
    if (std.mem.eql(u8, args[1], "mmap-wx-relaxed")) {
        // Under the filter a project with a just in time compiler gets, this
        // must succeed, and every other rule stays unchanged.
        const prot: linux.PROT = @bitCast(prot_write | prot_exec);
        const flags: linux.MAP = @bitCast(map_private_anon);
        const rc = linux.mmap(null, 4096, prot, flags, -1, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "mmap-then-exec")) {
        const rw: linux.PROT = @bitCast(prot_read | prot_write);
        const flags: linux.MAP = @bitCast(map_private_anon);
        const rc = linux.mmap(null, 4096, rw, flags, -1, 0);
        if (linux.errno(rc) != .SUCCESS) return 1;
        const addr: [*]u8 = @ptrFromInt(rc);
        addr[0] = 0xc0; // Write to the page while it is not executable.
        const rx: linux.PROT = @bitCast(prot_read | prot_exec);
        const rc2 = linux.mprotect(addr, 4096, rx);
        return if (linux.errno(rc2) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "pkey-wx")) {
        const rw: linux.PROT = @bitCast(prot_read | prot_write);
        const flags: linux.MAP = @bitCast(map_private_anon);
        const rc = linux.mmap(null, 4096, rw, flags, -1, 0);
        if (linux.errno(rc) != .SUCCESS) return 1;
        const rc2 = linux.syscall4(.pkey_mprotect, rc, 4096, prot_write | prot_exec, 0);
        return if (linux.errno(rc2) == .SUCCESS) 0 else 1;
    }

    // shmat has no prot argument, so SHM_EXEC in shmflg is the flag the filter
    // must refuse.
    if (std.mem.eql(u8, args[1], "shmat-exec")) {
        const shmid = createShmSegment() catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        defer removeShmSegment(shmid);
        const shm_exec: usize = 0x8000;
        const rc = linux.syscall3(.shmat, shmid, 0, shm_exec);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    // An attach with no SHM_EXEC flag must still work.
    if (std.mem.eql(u8, args[1], "shmat-plain")) {
        const shmid = createShmSegment() catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        defer removeShmSegment(shmid);
        const rc = linux.syscall3(.shmat, shmid, 0, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    // Inside a routed sandbox. Each of these runs as the sandboxed program,
    // with no netbroker descriptor and no knowledge that a router exists.

    if (std.mem.eql(u8, args[1], "routed-trust-store")) {
        // The overlay reads through to the host's own file. `id_arg` is
        // `<hash>:<real>`, the Wyhash and whether the bytes are real.
        const colon = std.mem.indexOfScalar(u8, id_arg, ':') orelse {
            std.debug.print("the trust store argument has no separator\n", .{});
            return 2;
        };
        const want = std.fmt.parseInt(u64, id_arg[0..colon], 16) catch {
            std.debug.print("the trust store argument has no hash\n", .{});
            return 2;
        };
        const real = std.mem.eql(u8, id_arg[colon + 1 ..], "1");

        const found = readWholeFile(arena, HostileEtc.trust_store_path) catch |err| {
            std.debug.print(
                "the trust store was not readable inside the sandbox: {s}\n",
                .{@errorName(err)},
            );
            return 1;
        };
        const got = std.hash.Wyhash.hash(0, found);
        if (got != want) {
            std.debug.print(
                "the trust store inside the sandbox is not the host's: {d} bytes, hash {x}\n",
                .{ found.len, got },
            );
            return 5;
        }
        // `ownDirectory` mounts its upper layer on a tmpfs under the sandbox
        // root and detaches it, so a name still there is one nobody asked for.
        if (pathExists(owned_backing_inside)) {
            std.debug.print("the sandbox was left holding {s}\n", .{owned_backing_inside});
            return 5;
        }

        if (!real) return 0;

        // A file that reads back byte for byte and parses into an empty trust
        // store is a pass that means nothing.
        var io_impl: std.Io.Threaded = .init_single_threaded;
        const io = io_impl.io();
        var bundle: std.crypto.Certificate.Bundle = .empty;
        defer bundle.deinit(arena);
        bundle.rescan(arena, io, std.Io.Clock.real.now(io)) catch |err| {
            std.debug.print("the trust store did not parse: {s}\n", .{@errorName(err)});
            return 5;
        };
        if (bundle.map.count() == 0) {
            std.debug.print("the trust store parsed and holds no certificate\n", .{});
            return 5;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "routed-reach")) {
        // Nothing here knows about Chock, which is what npm and curl do.
        switch (askResolver(filtered_host, dns_type_a)) {
            .address => |bytes| {
                const fd = connectToAddress(bytes, routed_port) catch |err| {
                    std.debug.print("a permitted host was not reachable: {s}\n", .{@errorName(err)});
                    return 5;
                };
                defer _ = linux.close(fd);
                const wrote = linux.write(fd, filtered_token, filtered_token.len);
                if (linux.errno(wrote) != .SUCCESS or wrote != filtered_token.len) {
                    std.debug.print("the connection carried nothing\n", .{});
                    return 5;
                }
                return 0;
            },
            else => |other| {
                std.debug.print("a permitted host did not resolve: {s}\n", .{@tagName(other)});
                return 5;
            },
        }
    }
    if (std.mem.eql(u8, args[1], "routed-flush")) {
        // The ruleset is worth nothing if what runs under it can take it away.
        // The errno is the test: `EPERM` is the capability being gone, and any
        // other answer means the batch was refused for its shape.
        const answer = askToDeleteRuleset() orelse {
            std.debug.print("the kernel could not be asked about the ruleset at all\n", .{});
            return 3;
        };
        if (answer == .SUCCESS) {
            std.debug.print("the sandboxed program deleted the ruleset\n", .{});
            return 1;
        }
        if (answer != .PERM) {
            std.debug.print("deleting the ruleset was refused with {t}\n", .{answer});
            return 5;
        }
        // A refusal is also what a machine with no table answers, so the
        // unhanded address is tried again here.
        const fd = connectToAddress(.{ 93, 184, 216, 34 }, routed_port) catch return 0;
        _ = linux.close(fd);
        std.debug.print("an unhanded address was reachable after the refused delete\n", .{});
        return 1;
    }
    if (std.mem.eql(u8, args[1], "routed-refused-name")) {
        // `REFUSED` and not an empty answer, or a program reads the name as a
        // host that does not exist.
        switch (askResolver(filtered_refused_host, dns_type_a)) {
            .refused => return 0,
            else => |other| {
                std.debug.print("a refused host answered {s}\n", .{@tagName(other)});
                return 1;
            },
        }
    }
    if (std.mem.eql(u8, args[1], "routed-hardcoded")) {
        // The policy permits the host this address belongs to and the resolver
        // was never asked, so only the kernel can refuse it.
        const bytes = [4]u8{ 93, 184, 216, 34 };
        const fd = connectToAddress(bytes, routed_port) catch return 0;
        _ = linux.close(fd);
        std.debug.print("an address that was never handed out was reachable\n", .{});
        return 1;
    }
    if (std.mem.eql(u8, args[1], "routed-metadata")) {
        // The cloud metadata address, which answers with the machine's own
        // credentials on three large providers.
        const fd = connectToAddress(.{ 169, 254, 169, 254 }, 80) catch return 0;
        _ = linux.close(fd);
        std.debug.print("the metadata service was reachable\n", .{});
        return 1;
    }
    if (std.mem.eql(u8, args[1], "routed-own-resolver")) {
        // The query is a UDP packet to an address outside the allow set. The
        // sandbox's own resolver is asked first, or no UDP proves nothing.
        switch (askResolver(filtered_host, dns_type_a)) {
            .address => {},
            else => |other| {
                std.debug.print("the sandbox's own resolver answered {s}\n", .{@tagName(other)});
                return 5;
            },
        }
        const sock_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(sock_rc) != .SUCCESS) return 3;
        const fd: i32 = @intCast(sock_rc);
        defer _ = linux.close(fd);

        const timeout = linux.timeval{ .sec = 2, .usec = 0 };
        _ = linux.setsockopt(
            fd,
            linux.SOL.SOCKET,
            linux.SO.RCVTIMEO,
            @ptrCast(&timeout),
            @sizeOf(linux.timeval),
        );

        var query: [512]u8 = undefined;
        const length = buildDnsQuery(&query, 0x1111, filtered_host, dns_type_a) orelse return 3;
        const where = linux.sockaddr.in{
            .port = std.mem.nativeToBig(u16, 53),
            .addr = @bitCast([4]u8{ 8, 8, 8, 8 }),
        };
        const sent = linux.sendto(
            fd,
            &query,
            length,
            0,
            @ptrCast(&where),
            @sizeOf(linux.sockaddr.in),
        );
        // The send itself is what fails, and the errno is the test: the guard
        // chain answers `EPERM` because it rejects rather than drops. A chain
        // that dropped would leave the program waiting out its own timeout.
        if (linux.errno(sent) != .PERM) {
            std.debug.print(
                "a query to a resolver of the program's own was answered {t}\n",
                .{linux.errno(sent)},
            );
            return 1;
        }

        // And nothing comes back, which the errno alone does not carry.
        var reply: [512]u8 = undefined;
        const got = linux.recvfrom(fd, &reply, reply.len, 0, null, null);
        if (linux.errno(got) == .SUCCESS) {
            std.debug.print("a resolver of the program's own was answered\n", .{});
            return 1;
        }
        return 0;
    }

    std.debug.print("unknown operation: {s}\n", .{args[1]});
    return 2;
}
