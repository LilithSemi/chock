//! One dangerous operation per run. A test starts this program and reads the result.
//!
//! Exit codes:
//!   0 - the operation succeeded, or was blocked in the way the test expects.
//!   1 - the kernel refused the operation, with the specific errno the design
//!       predicts. The sandbox layer stopped it for the reason it claims to.
//!   2 - the operation name given on the command line is unknown.
//!   3 - the sandbox setup itself failed, before the probed operation ran.
//!   4 - a netns-connect check could not prove the network namespace was entered.
//!   5 - the kernel refused the operation, but not with the errno the design
//!       predicts. Something else is broken, and this must not read as a pass.
//!  63 - this machine would not give the sandbox its namespaces, so nothing
//!       this operation is about was measured. **Not a pass and not a
//!       failure**: the caller skips and says why. See
//!       `namespace.nothing_measured_exit_status`.
//! A death by SIGSYS means the seccomp filter killed the process, which is a pass for
//! a call in `blocked_calls`.

const std = @import("std");
const sandbox = @import("chock-sandbox");
/// The real network broker, and the real policy table it reads. **Not a stand
/// in.** See `filteredEscape` for what does stand in, which is the transport
/// alone, and for why the decision path has to be the one that ships.
const chock_broker = @import("chock-broker");
const chock_policy = @import("chock-policy");
/// A real session log, in memory, for `askingEscape`: the reentrancy proof
/// needs a real `Broker.request`, and `Broker.request` needs a real
/// `chock_proto.storage.Storage` to write the question and the answer into.
/// `Memory` touches no file and ignores the `io` it is handed. `Network.io`
/// itself is a real, threadless `std.Io`: see its own construction comment
/// in `filteredEscape` and `askingEscape` for what reads it and why a
/// threaded implementation is still the one thing that may not be built
/// here.
const chock_proto = @import("chock-proto");
/// Where the dynamically linked program is on this machine, as a build time
/// constant. See `spawn-path-audit-dynamic`.
const dynamic_probe_path = @import("dynamic_probe_path").dynamic_probe_path;
const linux = std.os.linux;

/// What `spawn-stdin-pipe` writes into the pipe it names in `Config.stdin_fd`,
/// and what `spawned-stdin-pipe` must read back on descriptor 0. A fixed
/// string, so the check is that these exact bytes arrived and not merely that
/// something did.
const stdin_pipe_token = "chock-helper-request";

/// How many times `spawned-count-opens` opens a file. A fixed number, so the
/// supervisor's count is checked against a floor this test set rather than
/// against whatever happened.
const opens_in_probe = 17;

/// The path nothing in the sandbox's own configuration grants, which
/// `spawned-name-paths` names and `spawn-path-audit` then looks for in the
/// record. **Nothing is ever there**: the kernel tells the reader before it
/// runs the call, so a path that does not exist is recorded exactly as one
/// that does.
const named_ungranted = "/etc/chock-probe-secret";

/// A path the configuration does grant, which the same program opens. It must
/// be counted and never named. `baseEscapeConfig` mounts this tree, so it is a
/// grant of that run and not a workspace.
const named_granted = "/nix/store";

/// End `spawned-kill-the-reader` when its own alarm goes off. **One system
/// call and nothing else**, because this runs in a signal handler.
///
/// The status says which fault it was: the sandboxed program was held inside a
/// call that nothing answered, which is the shape a supervisor that kept its
/// own copy of the notification descriptor leaves behind.
fn endOnAlarm(_: std.posix.SIG) callconv(.c) void {
    linux.exit(alarm_exit_status);
}

/// What `endOnAlarm` ends with. Not zero, so the caller reads it as the
/// failure it is.
const alarm_exit_status = 9;

/// Where the path reader is, as the sandboxed program sees it. The supervisor
/// forks the program first, so the program is process 1 of the new pid
/// namespace, and forks the reader second, so the reader is process 2.
const reader_pid_in_namespace: linux.pid_t = 2;

/// End this program with `nothing_measured_exit_status` when `err` is the
/// sandbox refusing to be built at all.
///
/// **For the operations that read `spawn`'s own error rather than letting it
/// out.** Several here expect a setup failure and check which one it was, so
/// the error never reaches `main`; a machine with no namespace would give
/// them the wrong failure and they would report a real fault. Returns for
/// every other error, so a genuine setup fault keeps the exit code that says
/// so. Nothing is printed, for the reason `enterOrEndUnmeasured` gives.
fn endIfNothingMeasured(err: anyerror) void {
    if (err != error.NamespaceFailed) return;
    std.process.exit(sandbox.namespace.nothing_measured_exit_status);
}

/// Enter the namespaces, or end this program with
/// `nothing_measured_exit_status`.
///
/// **A machine that will not give a user namespace measures nothing here.**
/// Every operation that reaches this line is about a boundary that lives
/// inside the namespaces, so a run that cannot make them proves neither that
/// the boundary holds nor that it leaks. The caller reads the status and
/// skips. See `namespace.nothing_measured_exit_status`.
///
/// **Nothing is printed, on purpose.** `build.zig`'s own `failOnTestStderr`
/// fails the build when a test binary writes to standard error, and a caller
/// that lets this program inherit its own descriptors would carry these bytes
/// there. The exit status is the whole answer.
fn enterOrEndUnmeasured(options: sandbox.namespace.Options) void {
    sandbox.namespace.enter(options, null) catch {
        std.process.exit(sandbox.namespace.nothing_measured_exit_status);
    };
}

/// Build a sandbox root with one writable workspace and one read only file.
/// `root` is scratch space the caller already made and owns the cleanup of;
/// this probe never invents a location of its own. Every setup failure ends
/// the process, because a probe that continues after a failed layer tests
/// nothing.
fn enterTestRoot(arena: std.mem.Allocator, root: []const u8) !void {
    // The tree is built outside the namespace, while the paths are still
    // writable. `root` itself already exists; only the workspace under it
    // is new.
    const work = try std.fs.path.join(arena, &.{ root, "work" });
    try makeTestDir(arena, work);

    // A file that a read only bind mount protects, as chock.zon is protected.
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

// Zig 0.16 moved directory creation and file writes behind std.Io.Dir, which needs
// an Io instance this probe does not carry. namespace.zig has the same restriction
// and calls the kernel directly, so this test helper does the same.
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

    // One write must carry the whole file. Nothing here writes enough for a partial
    // write to be a realistic outcome, so a short write is treated as a failure.
    const written = linux.write(fd, contents.ptr, contents.len);
    if (linux.errno(written) != .SUCCESS or written != contents.len) return error.SetupFailed;
}

/// `path` as an absolute path, resolved against this process's own working
/// directory when it is relative.
///
/// **A build time path from `addOptionPath` is relative to the build root.**
/// That is enough for a caller that only spawns the program, because the test
/// that spawns it runs from the build root. It is not enough for a bind mount
/// source: the kernel resolves that inside a process that has already begun
/// building a root of its own, so a relative source names something else or
/// nothing. See `spawn-path-audit-dynamic`.
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

/// Read the path of this running binary through /proc/self/exe. Used only by
/// the spawn-ptrace probe, which binds its own binary into a fresh sandbox root
/// and execs it again from inside. `std.fs.selfExePathAlloc` does not exist in
/// this Zig version, so the link is read directly, the same way every other
/// path in this file reaches the kernel.
fn selfExePath(arena: std.mem.Allocator) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const rc = linux.readlink("/proc/self/exe", &buffer, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.SetupFailed;
    return arena.dupe(u8, buffer[0..rc]);
}

/// Read `fd` until end of file, into `buffer`, and answer what arrived.
///
/// For the two setup fault operations, which have to say what one descriptor
/// received and not only that something did. A read of zero, or any failure
/// that is not `EINTR`, ends the loop: both mean nothing more is coming, and
/// the caller compares what it got either way.
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

/// A sandbox that cannot be built, for the two setup fault operations.
///
/// `root` is a path under the caller's own scratch directory that was never
/// made, so `namespace.buildRoot` fails on it inside `spawn`'s own child and
/// the setup failure path runs. Nothing on the host is touched: the directory
/// is not there to touch.
fn absentRoot(arena: std.mem.Allocator, root: []const u8) ![]const u8 {
    return std.fs.path.join(arena, &.{ root, "absent" });
}

/// The mount tree and Landlock rules every "spawn-" operation shares: the nix
/// store so the exec inside the sandbox can find its shared libraries, and this
/// binary bound in as /probe so the sandboxed child can run itself again.
fn baseEscapeConfig(arena: std.mem.Allocator) !struct {
    mounts: []const sandbox.namespace.Mount,
    rules: []const sandbox.Config.Rule,
} {
    const self_path = try selfExePath(arena);
    const mounts = try arena.dupe(sandbox.namespace.Mount, &.{
        .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } },
        .{ .bind = .{ .source = self_path, .target = "/probe", .read_only = true } },
    });
    const rules = try arena.dupe(sandbox.Config.Rule, &.{
        .{ .path = "/nix/store", .access = sandbox.landlock.AccessFs.read_only },
        // The Landlock ruleset handles the execute right for every path, not
        // only the ones named here, so without this rule execve on /probe
        // itself is refused with EACCES before the probed operation ever runs.
        //
        // /probe is a file, not a directory, so its rule cannot carry
        // read_only's read_dir bit: landlock_add_rule returns EINVAL for a
        // directory-only right on a non-directory path.
        .{ .path = "/probe", .access = .{ .execute = true, .read_file = true } },
    });
    return .{ .mounts = mounts, .rules = rules };
}

/// The host every filtered probe asks for. Under the class the policy below
/// permits, so a request for it is a request the table really answers `allow`
/// to.
const filtered_host = "api.anthropic.com";

/// A host the policy below does not permit, under no class it names.
const filtered_refused_host = "secret.evil.test";

/// The policy every filtered probe runs under.
///
/// `main` may reach anything under `anthropic.com`, on any port, and `fetcher`
/// may too. The port has to stay open here, because the ports these probes use
/// are ephemeral ones the kernel chooses at run time and no rule could name
/// them.
///
/// **`main` is denied under `deny_parent` below and not here.** Two sources,
/// so the subagent probes compare a fold against a rule and not against a
/// missing rule.
const filtered_policy: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.connect.com.anthropic.*", .decision = .allow },
    \\        },
    \\    },
    \\}
;

/// The same, with the parent kind refused. A subagent whose own kind is
/// permitted still cannot reach the host under this, because `evaluateChain`
/// takes the intersection over the whole chain.
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

/// A listening socket on the loopback interface, with the port the kernel
/// chose.
const Listener = struct {
    fd: i32,
    port: u16,

    /// True when something has connected and nobody has accepted it yet.
    /// **This is how a probe proves a connection did not happen**, which is
    /// the half of an escape test that an exit code cannot carry.
    fn hasPending(self: Listener) bool {
        var fds = [1]linux.pollfd{.{ .fd = self.fd, .events = linux.POLL.IN, .revents = 0 }};
        const ready = linux.poll(&fds, 1, 0);
        return linux.errno(ready) == .SUCCESS and ready > 0;
    }

    /// Accept one connection and read what was written into it. Null when
    /// nothing connected.
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

/// Listen on `127.0.0.1` on a port the kernel chooses.
///
/// A backlog and no accept: the kernel completes the handshake into that
/// backlog, so a connect succeeds while this process is still inside
/// `Sandbox.spawn` and cannot accept anything.
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

/// Connect to `127.0.0.1` on `port`, from this process, outside every
/// namespace.
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

/// The one stand-in of the filtered probes: where a name resolves to, and
/// where a connection really goes.
///
/// `lookup` answers with `resolves_to`, which is an address on the public
/// internet for every probe but one, so `addressIsReachable` runs for real and
/// really does permit it. `dial` ignores that address and connects to a
/// listening socket on the loopback interface, because **no test may reach the
/// network**.
const ProbeTransport = struct {
    /// What a name resolves to. Every host resolves to this, including the one
    /// the policy refuses, so a refusal can never be a name that failed to
    /// resolve.
    resolves_to: chock_broker.network.Transport.Address,
    /// Where a connection really goes.
    port: u16,
    /// How many names were resolved. **Zero for a host the policy refused**,
    /// which is the DNS claim of `chock_broker.network`'s own top comment,
    /// proven here through a real spawn.
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

/// What one filtered spawn came back with, for the operation that started it.
const FilteredRun = struct {
    term: std.process.Child.Term,
    lookups: usize,
    dials: usize,
    granted: usize,
    refused: usize,
};

/// Run `/probe <op> <ports>` inside a real filtered sandbox, with the real
/// network broker answering.
///
/// `chain` is the spawn chain the policy is folded over. `resolves_to` is what
/// every name answers with. `dial_port` is where a granted connection really
/// goes.
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

    // A real, threadless `Io`. `std.Io.Threaded.init_single_threaded` never
    // spawns a worker thread, by its own doc comment, so it keeps this
    // probe single threaded across `Sandbox.spawn`'s own `fork()` below.
    var io_impl: std.Io.Threaded = .init_single_threaded;

    var transport = ProbeTransport{ .resolves_to = resolves_to, .port = dial_port };
    var network = chock_broker.network.Network{
        .gpa = arena,
        // **Genuinely read, not a claim that nothing here reads it.**
        // `finishConnect` (`lib/chock-broker/network.zig`) passes `self.io`
        // to `transport.lookup` and `transport.dial` on every allowed
        // connection, and `askPermits` reads it too whenever a caller sets
        // `.asker`. `ProbeTransport` still ignores the value it is given,
        // the same way it always did, but that is `ProbeTransport`'s own
        // property and not a reason for this field to hold `undefined`.
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

/// No rule at all, which `Table.evaluateChain` answers with `ask` for any
/// action. Every asking probe below uses this, so the table's own default is
/// what routes the connection to `Broker.request` rather than a rule an
/// author happened to spell `.ask`.
const ask_policy: [:0]const u8 =
    \\.{ .policy = .{ .rules = .{} } }
;

/// A second host, distinct from `filtered_host`, for the probe operation that
/// asks about two hosts inside the same `Sandbox.spawn`. Two names, so the
/// second reentrant `Broker.request` is a different question and not the
/// same one answered twice.
const second_filtered_host = "second.example.com";

/// The id of the most recent `approval.request` in the log that has no
/// `approval.response` naming it yet, or null when every question asked so
/// far has already been answered.
///
/// One open request at a time is the only shape this probe ever produces: the
/// sandboxed child asks, blocks for the answer, and only then asks again, so
/// there is never a second question in flight to confuse this with the first.
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

/// A `Broker.Waiter` that answers, refuses to answer, or reports a
/// cancellation, entirely in process. **This is the reentrancy under test.**
/// `Broker.request` calls `wait` from inside `Waiter.wait`'s own caller,
/// `askTheHuman`, which itself runs from inside `serveBroker`'s poll loop,
/// itself inside this probe's one and only call to `Sandbox.spawn`. This type
/// stands in for the person who would otherwise answer through
/// `lib/chock-broker/socket.zig`: a real arbiter, played by code that never
/// touches `std.Io` and never starts a thread, for the same reason
/// `ProbeTransport` does not. `nowMs` and `wait` both ignore the `io` they
/// are handed, and do not need it: this probe's own `network.io` is a real,
/// threadless `std.Io`, and this arbiter is free to ignore its own copy of
/// that value without hiding a trap the way `undefined` once did.
///
/// **This proves the log, lock and turn mechanics, not the production socket
/// waiter.** `lib/chock-broker/socket.zig`'s own `Waiter` does real socket
/// I/O through `std.Io`, and nothing here stands in for that half. It does
/// not need to, to answer this task's question: nothing shipped calls
/// `Broker.request` from inside a running `Sandbox.spawn` today, so there is
/// no production configuration yet for that waiter to be tested in. The day
/// there is, it is a smaller, more confident step for this proof already
/// existing, not a step this proof has already taken.
const AskArbiter = struct {
    gpa: std.mem.Allocator,
    store: chock_proto.storage.Storage,
    locked: *chock_broker.network.Locked,
    now_ms: i64 = 1_700_000_000_000,
    waits: usize = 0,
    /// What this arbiter answers the first, second, and later open requests
    /// it sees with, in order. The last entry repeats for every request past
    /// the end, so a single element answers every one of them the same way.
    /// Used to prove two different questions in the same `Sandbox.spawn` each
    /// get the answer meant for them and not the other one's: see
    /// `spawned-filtered-ask-two`.
    decisions: []const chock_proto.event.ApprovalDecision = &.{.approved_by_user},
    /// How many requests this arbiter has already answered. Indexes
    /// `decisions`, capped at its last entry.
    answered: usize = 0,
    /// False for the "nobody is there" case: every open request is left
    /// exactly as it is, so `askTheHuman`'s own deadline, and nothing this
    /// type does, is what ends the wait.
    answers: bool = true,
    /// The wait count at which this arbiter instead reports a cancellation
    /// and answers nothing. Null: never cancels.
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

/// What one `askingEscape` run came back with, for the operation that started
/// it to check against what it expected.
const AskingRun = struct {
    term: std.process.Child.Term,
    granted: usize,
    refused: usize,
    /// How many `approval.request` events the log holds.
    requests: usize,
    /// How many `approval.response` events the log holds.
    responses: usize,
    /// What a full read of the log's own hash chain found.
    verdict: chock_proto.chain.Verdict,
    /// True when the `tool.call` this run wrote before `Sandbox.spawn`, every
    /// `approval.request` and `approval.response` the spawn caused, and the
    /// `tool.result` this run wrote after it, all appear in exactly that
    /// order by id. **This is the turn that was already in flight**, and the
    /// proof that a real reentrant `Broker.request` left it intact.
    turn_intact: bool,
};

/// Run `/probe <op> <ports>` inside a real filtered sandbox, with the real
/// network broker answering, and a real `Broker.request` wired in for the
/// `ask` decision: see `chock_broker.network.Network.asker`.
///
/// A real session log, held in memory, brackets the call with a `tool.call`
/// and a `tool.result` the way `Loop.runTool` brackets a real tool call, so a
/// reader of the log afterward can tell whether the turn that was in flight
/// survived the reentrant call the sandboxed child caused in the middle of it.
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

    // **What forces `askPermits` to read `self.io` for real.** Every
    // production caller wires `approval_wait_ns`, through
    // `src/run.zig`'s own `ToolNetwork`: see `Asker.approval_wait_ns`'s own
    // comment. Leaving it null here would let `askPermits` skip the read
    // `self.io` was measured to segfault on, on 2026-09-05, and this probe
    // would go back to proving nothing about it.
    var approval_wait_ns: std.atomic.Value(u64) = .init(0);

    // A real, threadless `Io`. `std.Io.Threaded.init_single_threaded` never
    // spawns a worker thread, by its own doc comment, so it stays correct
    // here too: this process has already forked, or is about to, inside
    // `Sandbox.spawn` below.
    var io_impl: std.Io.Threaded = .init_single_threaded;

    var transport = ProbeTransport{ .resolves_to = resolves_to, .port = dial_port };
    var network = chock_broker.network.Network{
        .gpa = arena,
        // **Genuinely read, not a claim that nothing here reads it.** That
        // claim used to be true only by accident: `askPermits`
        // (`lib/chock-broker/network.zig`) reads `self.io` whenever a
        // caller's `approval_wait_ns` is set, and a version of it that read
        // `self.io` unconditionally segfaulted this probe on 2026-09-05, at
        // this exact `undefined` value. `finishConnect` also passes it to
        // `transport.lookup` and `transport.dial` on every allowed
        // connection. `ProbeTransport` and `AskArbiter` both still ignore
        // the value they are given, the same way they always did, but that
        // is their own property and not a reason for this field to hold
        // `undefined`.
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

/// An address on the public internet, so `addressIsReachable` permits it for
/// real. Every filtered probe but `spawn-filtered-loopback` uses this.
const filtered_public_address: chock_broker.network.Transport.Address =
    .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } };

/// The token a filtered child writes into a granted connection, so the
/// operation that started it can prove the descriptor really carried the
/// connection the broker opened.
const filtered_token = "the-broker-opened-this";

/// The two ports a filtered child is given, as `"<granted>,<other>"`.
fn filteredPorts(arena: std.mem.Allocator, granted: u16, other: u16) ![]const u8 {
    return std.fmt.allocPrint(arena, "{d},{d}", .{ granted, other });
}

/// Read `"<a>,<b>"` back inside the sandbox.
fn splitPorts(text: []const u8) ?struct { u16, u16 } {
    const comma = std.mem.indexOfScalar(u8, text, ',') orelse return null;
    const first = std.fmt.parseInt(u16, text[0..comma], 10) catch return null;
    const second = std.fmt.parseInt(u16, text[comma + 1 ..], 10) catch return null;
    return .{ first, second };
}

/// Try to point `fd` at `127.0.0.1:port`, the way an escape would.
///
/// Two calls and not one, because a connected TCP socket refuses a plain
/// re-connect with `EISCONN` and only gives way after an `AF_UNSPEC`
/// disconnect. Measured on 2026-08-23: with `connect` allowed, the disconnect
/// answered 0 and the re-connect answered 0, so this really is a way to aim a
/// granted descriptor somewhere else.
///
/// Gives back the errno of whichever call refused, or `.SUCCESS` when the
/// socket was aimed somewhere else.
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

/// How many descriptors this process holds, read out of `/proc/self/fd`.
///
/// **This is how a filtered child proves a refusal gave it nothing.** An exit
/// code says what the child decided; the descriptor table says what the child
/// was actually handed, and a descriptor that arrived would land on a free
/// number whatever the reply said.
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

/// Where the disk probes below put their scratch area, inside the sandbox.
/// Under `runtime_prefix` because that is the one directory of a sandbox root
/// that belongs to Chock rather than to the project: see `Sandbox.runtime_prefix`.
const scratch_target = sandbox.runtime_prefix ++ "/scratch";

/// `baseEscapeConfig` plus one capped scratch area, and the Landlock rule that
/// makes it writable. **Both, or the area is one the program cannot use**: an
/// area no rule names is refused by Landlock before the cap ever matters, and a
/// rule with no area behind it is refused at `landlock_add_rule` because the
/// path does not exist.
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

/// How many children `spawned-fork-bomb` will make before it stops on its
/// own. The unbounded run reaches exactly this.
const fork_bomb_cap: u8 = 64;
/// The process limit the bounded fork bomb run gets. Well under the cap, so
/// the two runs cannot be confused.
const fork_bomb_limit: u64 = 8;

/// How many 8 MiB blocks `spawned-mem-bomb` will touch before it stops on its
/// own. 64 blocks is 512 MiB, which is a bounded amount of work for the
/// unbounded run and far past the limit the bounded run gets.
const mem_bomb_cap: u8 = 64;
/// One block, in bytes. Touched, not only mapped: an untouched mapping is
/// exactly the thing `RLIMIT_AS` would have refused and `memory.max` would
/// not, and this probe has to exercise the real one.
const mem_bomb_block_bytes: usize = 8 << 20;
/// The memory limit the bounded run gets, for both the resident ceiling and
/// the mapped ceiling, so this probe proves something on a machine with no
/// cgroups as well as on one with them.
const mem_bomb_limit: u64 = 128 << 20;

/// How many extra descriptors `spawned-fd-bomb` will open before it stops on
/// its own.
const fd_bomb_cap: u8 = 200;
/// The descriptor limit the bounded run gets.
const fd_bomb_limit: u64 = 32;

/// How many small files `spawned-disk-file-bomb` will make before it stops on
/// its own. The unbounded run reaches exactly this.
const disk_file_cap: u8 = 250;
/// How many bytes each of those files carries. Small on purpose: **the attack
/// is the number of files and not the size of any one of them**, which is
/// exactly what `RLIMIT_FSIZE` cannot see.
const disk_file_bytes: usize = 4096;

/// The scratch cap the bounded file bomb run gets.
///
/// **Chosen against the page size and never against a number of files.**
/// Measured on 2026-08-22: a file costs a whole page whatever is in it, so a
/// cap of 512 KiB holds 8 files on this machine, whose pages are 64 KiB, and
/// 128 files on an ordinary 4 KiB page machine. Both are far under
/// `disk_file_cap`, so the bounded run and the unbounded run cannot be
/// confused on either. A cap chosen so that a 4 KiB page machine fitted more
/// than `disk_file_cap` files would make this test pass for the wrong reason
/// there and nowhere else, which is the worst kind of test to own.
const disk_file_limit: u64 = 512 << 10;

/// How many 64 KiB blocks `spawned-disk-one-bomb` will write into one file
/// before it stops on its own. The unbounded run reaches exactly this, which is
/// 12.8 MiB of work.
const disk_one_cap: u8 = 200;
/// One block of that file, in bytes.
const disk_one_block_bytes: usize = 64 << 10;
/// The one file limit the bounded run of the enormous file gets. Well under
/// what `disk_one_cap` blocks come to.
const disk_one_file_limit: u64 = 1 << 20;
/// The scratch cap that run gets.
///
/// **It must be larger than everything `spawned-disk-one-bomb` can write, and
/// that was measured rather than assumed.** At 8 MiB it was not: the program's
/// own ceiling is `disk_one_cap` blocks, which is 12.8 MiB, so the area filled
/// first and **the run passed with `RLIMIT_FSIZE` deleted from the library**.
/// The mutation check caught it, which is the whole reason to run one rather
/// than write one down. 64 MiB is five times what the program can write, so the
/// area can never be the thing that stops it and the file size limit is the
/// only bound left.
///
/// It also has to stay under `rlimits.Limits.scratchFitsUnderMemory`, which the
/// default memory ceiling of 2 GiB leaves ample room for.
const disk_one_scratch_limit: u64 = 64 << 20;

/// What a bounded or unbounded limit run ended as, encoded so that
/// `escape.zig` can read it off the probe's own exit status with no pipe.
///
/// **`stopped_legibly` and `stopped_quietly` are different on purpose.** The
/// project's rule is that a confusing failure costs turns and a plain refusal
/// costs one, so a limit that stopped a program must also be able to say
/// which limit it was. `stopped_legibly` means `Sandbox.LimitsReport` named
/// it; `stopped_quietly` means something stopped the program and the report
/// could not say what, which is what a machine with no cgroups gets for
/// memory.
const LimitOutcome = enum(u8) {
    stopped_legibly = 10,
    stopped_quietly = 11,
    /// The program ran to its own internal cap. **Nothing bounded it.**
    not_stopped = 12,
    /// The program ended in a way this probe cannot read.
    unreadable = 13,
    /// The cgroup layer did not apply on this machine, so the run that was
    /// about the cgroup specifically proved nothing and the test that asked
    /// for it skips. **Only the `-cgroup` operations ever answer this**, and
    /// they answer it before they read the outcome at all, so a cgroup that
    /// applied and then bounded nothing is still a failure and not a skip.
    no_cgroup = 14,
};

/// Read one limit run's outcome off the `Term` the inner sandbox ended with.
///
/// `cap` is the program's own internal ceiling, and reaching it is the one
/// outcome that means no limit did anything. `named` is whether
/// `Sandbox.LimitsReport` could say which limit it was.
fn limitOutcome(term: std.process.Child.Term, cap: u8, named: bool) u8 {
    return @intFromEnum(switch (term) {
        .exited => |code| blk: {
            if (code >= cap) break :blk LimitOutcome.not_stopped;
            // A count below the program's own cap means a syscall was
            // refused: a fork that answered EAGAIN, an allocation that
            // answered ENOMEM, an open that answered EMFILE.
            break :blk if (named) LimitOutcome.stopped_legibly else LimitOutcome.stopped_quietly;
        },
        // Killed. `memory.max` does this, and so does the cpu limit.
        .signal => if (named) LimitOutcome.stopped_legibly else LimitOutcome.stopped_quietly,
        else => LimitOutcome.unreadable,
    });
}

/// Turn the Term of a process spawned through sandbox.spawn into this process's
/// own exit status, so the test that started this probe can read the inner
/// sandbox's outcome straight off this probe's own Term.
/// How far `spawned-open-fd-set` reads the descriptor table.
///
/// A leaked descriptor is one the kernel gave the lowest free number to, in a
/// process whose whole table is the three standard streams plus what `spawn`
/// itself opens, so every number a leak can land on is far below this. The
/// bound is here because a loop with no end is not a test.
const open_fd_set_scan_limit: i32 = 1024;

/// The file type bits of whatever `fd` names, or 0 when it cannot be read.
/// Zero matches no `S.IF*` constant, so a `statx` that failed reads as a
/// mismatch and never as the type the caller hoped for.
fn fileTypeOf(fd: i32) u32 {
    var stx: linux.Statx = undefined;
    const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, linux.STATX.BASIC_STATS, &stx);
    if (linux.errno(rc) != .SUCCESS) return 0;
    return stx.mode & linux.S.IFMT;
}

/// A `NetBroker` that refuses every request, for `spawn-open-fd-set-filtered`.
///
/// That operation is about which descriptors reach the program, not about
/// what the broker answers, and the program it spawns never asks. Refusing is
/// the answer that needs no host, no policy table, and no transport.
const RefusingBroker = struct {
    fn connectFn(_: *anyopaque, _: []const u8, _: u16) sandbox.NetBroker.Grant {
        return .refused;
    }

    const vtable = sandbox.NetBroker.VTable{ .connect = connectFn };

    fn broker(self: *RefusingBroker) sandbox.NetBroker {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

/// The descriptors a real harness is holding when it spawns a tool call, in
/// the shapes that would each be a different kind of escape.
///
/// Every one is opened without `FD_CLOEXEC`, because a descriptor that was
/// already close-on-exec proves nothing: the point is that `spawn` revokes a
/// descriptor whose owner never marked it. `io_uring` is the one entry that
/// may be absent, because a kernel can be built without it and a machine can
/// forbid it; `openCount` says how many were really opened, so the caller can
/// refuse to run a check that would pass because nothing was there.
const HarnessDescriptors = struct {
    /// The session log.
    log: i32,
    /// The credential store, which never touches a filesystem.
    credential: i32,
    /// A control channel to another process in the harness.
    control: [2]i32,
    /// An epoll ring.
    epoll: i32,
    /// An io_uring ring, or -1 on a machine that would not make one.
    ring: i32,
    /// The provider's own network connection.
    upstream: i32,
    /// The workspace git directory, reached as a directory descriptor, which
    /// is the shape that still reaches the host tree after `pivot_root`.
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

    /// How many of the shapes above this machine really gave. A check that
    /// found nothing open would pass with every layer gone, so the caller
    /// reads this rather than assuming.
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

/// The number of `HarnessDescriptors` entries that must be open before a
/// descriptor check means anything. Seven of the eight, because `io_uring` is
/// the one a machine is allowed to refuse.
const required_harness_descriptors: usize = 7;

fn reportChildTerm(term: std.process.Child.Term) u8 {
    switch (term) {
        .signal => |sig| {
            // Re-raising should end this process by the same signal, so the
            // failure to raise is the only outcome that can still reach the
            // return below. Name it, so that path is never silent.
            std.posix.raise(sig) catch |err| {
                std.debug.print("could not re-raise {s}: {s}\n", .{ @tagName(sig), @errorName(err) });
            };
            return 1;
        },
        .exited => |code| return code,
        else => return 2,
    }
}

/// Set by `onCallerSignal` when a caught signal reaches this process. Read by
/// the three signal operations below, each of which has to tell "the signal
/// was delivered here" from "the signal went nowhere at all".
var caller_signal_seen: std.atomic.Value(bool) = .init(false);

/// A handler that does one thing and one thing only, the same rule
/// `src/interrupt.zig` follows: a handler runs between any two instructions of
/// the program it interrupts, so it takes no lock and reaches no allocator.
fn onCallerSignal(_: std.posix.SIG) callconv(.c) void {
    caller_signal_seen.store(true, .monotonic);
}

/// Catch `sig` instead of dying from it, and record that it arrived.
///
/// **A process that dies cannot report anything**, and the signal operations
/// below have to survive a signal aimed at their own group so they can say
/// afterwards whether it arrived. The default action of every signal they use
/// ends a process, so without this the report would be the death itself,
/// which is the same outcome for two different reasons.
fn catchSignal(sig: std.posix.SIG) void {
    const action = std.posix.Sigaction{
        .handler = .{ .handler = onCallerSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(sig, &action, null);
}

/// How long a probe waits for a condition that a working build reaches in
/// milliseconds, and how often it looks. Reaching the bound is a bug
/// detector, never an expected wait: every caller of it treats the bound as a
/// failure with its own exit code, so a broken build fails the test rather
/// than hanging the suite.
const probe_wait_bound_ns: u64 = 10 * std.time.ns_per_s;
const probe_wait_step_ns: u64 = 1 * std.time.ns_per_ms;

/// True when `path` names something the kernel can stat. Used to wait for a
/// marker file another process writes, which is how the operations below stay
/// in step with each other without a fixed sleep guessed to be long enough.
fn pathExists(path: [:0]const u8) bool {
    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, path, 0, .{ .TYPE = true }, &stx);
    return linux.errno(rc) == .SUCCESS;
}

/// Wait, bounded, for `path` to appear. False when the bound ran out first.
fn waitForPath(path: [:0]const u8) bool {
    var waited: u64 = 0;
    while (waited < probe_wait_bound_ns) : (waited += probe_wait_step_ns) {
        if (pathExists(path)) return true;
        _ = linux.nanosleep(&.{ .sec = 0, .nsec = @intCast(probe_wait_step_ns) }, null);
    }
    return pathExists(path);
}

/// One `sandbox.spawn` call, running on a thread of its own so the thread
/// that started it can still act while `spawn` is blocked on the sandboxed
/// program. `spawn` is synchronous, so this is the only way an operation can
/// both learn the pid of the process `spawn` forked and do something with it
/// before the whole call finishes: the same shape `lib/chock-core/tools.zig`
/// uses for the same reason.
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

    /// Wait, bounded, for `spawn` to fill in the pid of the process it forked.
    /// 0 when the bound ran out first, which `spawn` reaches within
    /// microseconds of its first fork, so it never happens in a working build.
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

    /// Wait, bounded, for the call to finish. False when the bound ran out
    /// first, which is a real answer and not only a broken build: a `spawn`
    /// that never returns after the process it forked was signalled is
    /// exactly the fault `spawn-signal-middle-handled` looks for.
    fn waitForDone(self: *ThreadedSpawn) bool {
        var waited: u64 = 0;
        while (waited < probe_wait_bound_ns) : (waited += probe_wait_step_ns) {
            if (self.done.load(.acquire)) return true;
            _ = linux.nanosleep(&.{ .sec = 0, .nsec = @intCast(probe_wait_step_ns) }, null);
        }
        return self.done.load(.acquire);
    }

    /// End this program with `nothing_measured_exit_status` when the call
    /// ended because the sandbox could not be built at all.
    ///
    /// **Read in every branch that gives up on a bounded wait.** A sandbox
    /// that never came up starts no program, writes no file and signals
    /// nobody, so each of those waits runs out and reports a fault of its own
    /// long before the `spawn_err` check further down is ever reached. See
    /// this file's own `endIfNothingMeasured`.
    fn endIfSandboxRefused(self: *ThreadedSpawn) void {
        if (!self.done.load(.acquire)) return;
        if (self.spawn_err) |err| endIfNothingMeasured(err);
    }

    /// End every process of the call, whatever state it is in. Called on
    /// every failure path, so a broken build never leaves a sandboxed program
    /// running after the suite has moved on. SIGKILL, because a failure path
    /// here has already stopped believing anything answers a polite signal.
    ///
    /// Through the handle, which reaches the middle process only and still
    /// ends the whole call: see `sandbox.spawn`'s own doc comment. A `kill` on
    /// the negated number would be the very fault `sandbox.Middle` exists to
    /// remove, and a probe is not exempt from it.
    fn killCall(self: *ThreadedSpawn) void {
        if (@atomicLoad(linux.pid_t, &self.middle.pid, .acquire) == 0) return;
        sandbox.signalMiddle(self.middle.fd, .KILL) catch {};
    }

    /// Give the handle up. Only after `spawn` has returned: see
    /// `sandbox.Middle`.
    fn closeHandle(self: *ThreadedSpawn) void {
        sandbox.closeMiddle(&self.middle);
    }
};

/// The mount tree and Landlock rules a spawn operation needs when the
/// sandboxed program has to write into `root/work` and read what the caller
/// writes there. `baseEscapeConfig` on its own gives no writable path.
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

/// The content written to the source file in enterFileOverFileTestRoot, and
/// checked back out of the bound target afterward.
const file_over_file_content = "chock file over file probe content\n";

/// The path spawned-landlock-read tries to open. spawn-landlock-escape writes a
/// file here, inside the root it hands to sandbox.spawn, but never names it in
/// the rules it hands along beside it, so only a missing Landlock layer could
/// let the read through.
const spawned_landlock_target = "/unguarded/marker";

/// Build a sandbox root that binds a file onto a target path which does not
/// exist anywhere in the root yet. This is different from enterTestRoot's
/// chock.zon case, where source and target are the same already-existing path.
/// A fresh target is what exercises the real bug: makePath used to always
/// create a directory for a mount target, so a file bound onto a target that did
/// not already exist failed with ENOTDIR. chock.zon itself is protected this
/// way in a real project, source and target both files, so this has to work.
fn enterFileOverFileTestRoot(arena: std.mem.Allocator, root: []const u8) !void {
    const source = try std.fs.path.join(arena, &.{ root, "source-file" });
    try writeTestFile(arena, source, file_over_file_content);

    enterOrEndUnmeasured(.{ .network = .none, .mount = true });
    try sandbox.namespace.buildRoot(arena, root, &.{
        .{ .bind = .{ .source = source, .target = "/marker", .read_only = false } },
    }, null);
    try sandbox.namespace.pivotInto(arena, root, null);
}

/// Build a sandbox root with one directory, "guarded", bound read only, with a
/// tmpfs mounted inside it before the read only mark is applied.
///
/// This is the order a reviewer used to prove that a plain remount is not
/// recursive: mount something under a directory, mark the directory read only,
/// then show the thing underneath is still writable. The submount has to exist
/// under "guarded" before buildRoot binds "guarded" onto itself, because a bind
/// mount only carries along the submounts that already exist under its source at
/// the moment it runs, not ones added later.
///
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

/// Create a private shared memory segment of one page.
fn createShmSegment() !usize {
    const ipc_private: usize = 0;
    const ipc_creat: usize = 0o1000;
    const size: usize = 4096;
    const shmid = linux.syscall3(.shmget, ipc_private, size, ipc_creat | 0o600);
    if (linux.errno(shmid) != .SUCCESS) return error.ShmgetFailed;
    return shmid;
}

/// Mark a shared memory segment for removal. The kernel destroys a segment with
/// IPC_RMID the moment it has zero attaches, so this must run after the shmat
/// attempt, not before: calling it right after shmget, while nattch is still
/// zero, destroys the segment on the spot and turns a later shmat into EINVAL,
/// no matter what shmflg asked for.
fn removeShmSegment(shmid: usize) void {
    const ipc_rmid: usize = 0;
    _ = linux.syscall3(.shmctl, shmid, ipc_rmid, 0);
}

/// The directory outside every Landlock rule, for the write and truncate
/// probes below. A subdirectory of `root`, the scratch space the caller
/// already made and owns the cleanup of.
fn outsideDir(arena: std.mem.Allocator, root: []const u8) ![:0]const u8 {
    return std.fmt.allocPrintSentinel(arena, "{s}/outside", .{root}, 0);
}

/// Build one directory a Landlock rule permits, and one directory it never
/// names, both under `root`, then restrict this process to the ruleset.
/// Returns the permitted directory, allocated from the arena so it survives
/// after this returns. Every setup failure here must reach the caller as an
/// error, never a bare process exit, so a broken ruleset cannot be mistaken
/// for a working one that correctly refused the probed operation.
fn enterLandlockWriteTestRoot(arena: std.mem.Allocator, root: []const u8) ![:0]const u8 {
    const inside = try std.fmt.allocPrintSentinel(arena, "{s}/inside", .{root}, 0);
    try makeTestDir(arena, inside);
    try makeTestDir(arena, try outsideDir(arena, root));

    const abi = try sandbox.landlock.probeAbi();
    var ruleset = try sandbox.landlock.Ruleset.init(abi, null);
    // Permit one directory only. Every other path is refused.
    try ruleset.allowPath(inside, sandbox.landlock.AccessFs.read_write, null);
    try ruleset.restrictSelf(null);
    // The kernel keeps its own reference to the ruleset once restrictSelf
    // succeeds, so the fd this process held is no longer needed.
    ruleset.deinit();
    return inside;
}

/// Same permitted/forbidden directory split as enterLandlockWriteTestRoot, but
/// each directory also gets a file with content, since truncate needs a file
/// that already exists to prove anything.
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
    // Permit one directory only. Every other path is refused.
    try ruleset.allowPath(inside, sandbox.landlock.AccessFs.read_write, null);
    try ruleset.restrictSelf(null);
    ruleset.deinit();
    return .{ .inside_file = inside_file, .outside_file = outside_file };
}

/// What one of the three io_uring operations reports for the raw syscall
/// result `rc`. 1 is the pass, and it means the filter answered `EPERM`.
///
/// **The errno has to be read, and a plain "the call failed" would prove
/// nothing here.** Two of the three probes hand the kernel the descriptor -1,
/// so a filter that let the call through would still fail, with `EBADF`, and a
/// test that only asked whether the call failed would pass with no filter at
/// all. A machine whose kernel has no io_uring answers `ENOSYS` for the same
/// reason. Only `EPERM` is the filter.
fn ringRefusal(rc: usize) u8 {
    return switch (linux.errno(rc)) {
        // The ring was made, or the operation ran. The filter is not there.
        .SUCCESS => 0,
        // The filter refused it, and the process is still alive to say so.
        .PERM => 1,
        // Refused by something that is not this filter. Its own status, so it
        // can never be read as the pass above.
        else => 4,
    };
}

// Zig 0.16 removed std.process.argsAlloc. A hosted main can instead take
// std.process.Init.Minimal as its first parameter, and the runtime fills it in.
pub fn main(init: std.process.Init.Minimal) !u8 {
    return runOperation(init) catch |err| {
        // **The machine, and not the boundary.** Every operation here that
        // calls `Sandbox.spawn` reaches this error the same way: the sandbox
        // could not be built at all, so nothing the operation is about ever
        // ran. Reported as its own exit status rather than as this program's
        // ordinary error exit, which is a real failure and must stay one.
        // Nothing is printed, for the reason `enterOrEndUnmeasured` gives.
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
    // "spawn-ptrace", "spawn-landlock-escape", and "spawn-network-escape" belong here
    // for a different reason: each one forks and lets sandbox.spawn build the whole
    // sandbox, including its own call to unshare, inside that child. A seccomp filter
    // installed here on this process would be inherited across the fork, since a
    // filter can never be removed, and would kill the child's unshare before
    // Sandbox.spawn ever reached the point of installing its own filter after the
    // mount tree and Landlock rules. The test would then still see a death by SIGSYS,
    // but for the wrong reason, and would no longer prove the ordering it claims to
    // prove.
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
        std.mem.eql(u8, args[1], "spawn-stdin-devnull") or
        std.mem.eql(u8, args[1], "spawn-stdin-pipe") or
        std.mem.eql(u8, args[1], "spawn-proc-mask") or
        std.mem.eql(u8, args[1], "spawn-proc-live") or
        std.mem.eql(u8, args[1], "spawn-caps-drop") or
        // Both descriptor set runs, for the reason every "spawn-" operation
        // above is here: each forks and lets `sandbox.spawn` build the whole
        // sandbox inside that child, and a filter installed on this process
        // first would be inherited and would kill that child's own `unshare`.
        std.mem.eql(u8, args[1], "spawn-open-fd-set") or
        std.mem.eql(u8, args[1], "spawn-open-fd-set-filtered") or
        // The supervisor audit run, for the same reason: it forks and lets
        // `sandbox.spawn` build the whole sandbox in that child, and a filter
        // installed on this process first would be inherited and would kill
        // that child's own `unshare`.
        std.mem.eql(u8, args[1], "spawn-supervisor-audit") or
        // The two system call audit runs, for the same reason again: each one
        // forks and lets `sandbox.spawn` build the whole sandbox in that
        // child, and a filter installed on this process first would be
        // inherited and would kill that child's own `unshare`.
        std.mem.eql(u8, args[1], "spawn-syscall-audit") or
        std.mem.eql(u8, args[1], "spawn-syscall-audit-off") or
        std.mem.eql(u8, args[1], "spawn-syscall-audit-daemon") or
        // The four path audit runs, for the same reason again.
        std.mem.eql(u8, args[1], "spawn-path-audit") or
        std.mem.eql(u8, args[1], "spawn-path-audit-off") or
        std.mem.eql(u8, args[1], "spawn-path-audit-dynamic") or
        std.mem.eql(u8, args[1], "spawn-path-audit-killed") or
        // Plan 23 task 1, the six red team primitives. Each belongs here for
        // the same reason as spawn-ptrace above: sandbox.spawn's own
        // unshare must run without a filter already installed on this
        // process, or it would die before the layer under test ever went on.
        std.mem.eql(u8, args[1], "spawn-signal-middle-setsid") or
        std.mem.eql(u8, args[1], "spawn-memfd-exec") or
        std.mem.eql(u8, args[1], "spawn-handle-escape") or
        std.mem.eql(u8, args[1], "spawn-vsock") or
        std.mem.eql(u8, args[1], "spawn-proc-self-mem-write-landlock") or
        std.mem.eql(u8, args[1], "spawn-proc-self-mem-write-mount") or
        std.mem.eql(u8, args[1], "spawn-setns-proc1") or
        std.mem.eql(u8, args[1], "spawn-cgroup-remount") or
        std.mem.eql(u8, args[1], "cgroup-surface") or
        // The two setup fault operations. Each one lets `Sandbox.spawn` fail
        // to build a sandbox in a child of its own, so each belongs here for
        // the reason above: a filter installed on this process first would be
        // inherited across that fork and would kill the child's own `unshare`
        // before the mount step this operation is about could ever run.
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
        // The filtered network operations. Each one makes its own listening
        // sockets, parses its own policy, and spawns a real sandbox with a
        // real broker answering it. See `filteredEscape`.
        std.mem.startsWith(u8, args[1], "spawn-filtered-") or
        // The three resource limit runs, each in a bounded and an unbounded
        // form. They belong here for the reason every other "spawn-" operation
        // does: each one forks and lets sandbox.spawn build the whole sandbox
        // inside that child, and a seccomp filter installed on this process
        // first would be inherited and would kill that child's own unshare.
        std.mem.eql(u8, args[1], "spawn-fork-bomb") or
        std.mem.eql(u8, args[1], "spawn-fork-bomb-unbounded") or
        std.mem.eql(u8, args[1], "spawn-mem-bomb") or
        std.mem.eql(u8, args[1], "spawn-mem-bomb-unbounded") or
        std.mem.eql(u8, args[1], "spawn-mem-bomb-cgroup") or
        std.mem.eql(u8, args[1], "spawn-fd-bomb") or
        std.mem.eql(u8, args[1], "spawn-fd-bomb-unbounded") or
        // The two disk runs, in the same two forms and for the same reason.
        std.mem.startsWith(u8, args[1], "spawn-disk-");

    // The Landlock write and truncate probes build two plain directories of their
    // own, "inside" and "outside" a granted ruleset, but never a mount tree: no
    // namespace is entered for them, so they are not part of builds_own_root above,
    // which is about which operations must skip the seccomp filter. They still need
    // scratch space from the caller, the same as every builds_own_root operation.
    const needs_scratch_root = builds_own_root or
        std.mem.eql(u8, args[1], "landlock-write-outside") or
        std.mem.eql(u8, args[1], "landlock-write-inside") or
        std.mem.eql(u8, args[1], "landlock-truncate-outside") or
        std.mem.eql(u8, args[1], "landlock-truncate-inside");

    // "spawn-signal-host", "spawn-shm-attach", and their "spawned-" targets carry one
    // more argument: a host pid or a host shmid that the caller (escape.zig, or this
    // same probe one layer up) made outside every namespace. "session-keyring-fresh"
    // carries one too: the description of a key escape.zig planted in its own session
    // keyring. None of these operations can pick a meaningful target on its own; each
    // has to be handed one that is real.
    const needs_id_arg = std.mem.eql(u8, args[1], "spawn-signal-host") or
        std.mem.eql(u8, args[1], "spawned-signal-host") or
        std.mem.eql(u8, args[1], "spawn-shm-attach") or
        std.mem.eql(u8, args[1], "spawned-shm-attach") or
        // The approval socket lives beside the session log, on a path no
        // mount list names. Neither of these two can
        // invent that path: escape.zig makes a real socket, proves the host can
        // reach it, and hands the path down.
        std.mem.eql(u8, args[1], "spawn-approval-socket") or
        std.mem.eql(u8, args[1], "spawned-approval-socket") or
        // A directory outside the sandbox root entirely, made by escape.zig
        // with its own scratchRoot, so the file this probe puts a symlink's
        // target at is provably not part of the sandbox's own mount tree.
        std.mem.eql(u8, args[1], "deny-symlink-outside") or
        std.mem.eql(u8, args[1], "bind-source-symlink") or
        std.mem.eql(u8, args[1], "deny-intermediate-symlink") or
        // The descriptor the caller left open on the host root. Only the
        // caller knows which number it landed on, and the whole point of the
        // check is that the number names nothing by the time it is read.
        std.mem.eql(u8, args[1], "spawned-stdin-pipe") or
        // Which set the child must find: "plain" for a sandbox with no
        // network, "filtered" for one with the broker socket. The child
        // cannot read the network mode of the sandbox it woke up in, so the
        // operation that spawned it says which answer is right.
        std.mem.eql(u8, args[1], "spawned-open-fd-set") or
        // The two ports a filtered child is given: the one a granted
        // connection really goes to, and the one it must not be able to
        // reach. Both are ephemeral, so no rule and no constant could name
        // them and the operation that spawned this one has to pass them down.
        std.mem.startsWith(u8, args[1], "spawned-filtered-") or
        std.mem.eql(u8, args[1], "session-keyring-fresh");

    // A needs_scratch_root operation reads its scratch root off the command line,
    // right after the operation name: the caller already knows where that should
    // live, through std.testing.tmpDir, so this probe never invents a location of
    // its own, the way it once built one from its own pid. An id argument, when
    // there is one, always comes right after that.
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

    // A "spawned-" operation does no setup at all, not even its own filter. It is
    // only ever reached by exec, as the child of a real Sandbox.spawn call, so every
    // layer it can run into was already put there by that call's applyLayers. This is
    // the property Finding 1 needs: a "spawned-" operation must have no path of its
    // own to the outcome it checks, or a mutation that deletes a whole layer from
    // applyLayers could still pass by the operation's own doing, the same bug that
    // made the old "spawn-ptrace" probe worthless as a test.
    const spawned = std.mem.startsWith(u8, args[1], "spawned-");

    // A "netns-" operation must enter the namespaces instead of installing the filter.
    // `unshare` is in the seccomp filter's blocked call list, so installing the filter
    // first would kill the probe with SIGSYS before it could ever reach unshare.
    //
    // "read-home", "write-readonly", "delete-mounted-file", and
    // "write-readonly-submount" also need the namespaces and not the filter: mount
    // and pivot_root are blocked calls too, and the mount tree they probe would not
    // exist under seccomp. They enter the namespaces themselves inside
    // enterTestRoot or enterSubmountTestRoot, with different options than the
    // netns- path uses, so this block must not call enter for them, or the second
    // unshare would run inside a namespace the first one already built.
    //
    if (spawned) {
        // Nothing to set up. See the comment on `spawned` above.
    } else if (std.mem.startsWith(u8, args[1], "netns-")) {
        // A setup failure is not the same fact as the kernel refusing the probed
        // operation. It has an exit code of its own, so a broken `unshare` cannot
        // be mistaken for a network namespace that did its job, and it names the
        // call and the errno, so the failure is never silent.
        enterOrEndUnmeasured(.{});
    } else if (std.mem.eql(u8, args[1], "session-keyring-fresh")) {
        // Nothing to set up here either: this operation calls the join directly
        // below and reads the result straight back. No seccomp filter goes on,
        // because the read-back has to call request_key, one of the very calls
        // Finding 1 also adds to blocked_calls, and installing the filter here
        // would kill this process before it could ever prove anything.
    } else if (!builds_own_root) {
        // Several operations below expect a plain exit code of 1 as their
        // "refused" pass, with no signal involved: mmap-wx, pkey-wx,
        // personality-rwx, shmat-exec, and landlock-write-outside. A bare try
        // here would turn a broken filter build into exactly that same exit
        // code 1, and the test would read a setup bug as a pass. Give this its
        // own exit code instead, the same as every other setup step in this
        // file.
        //
        // **One operation asks for the other filter**, the one a project that
        // needs a just in time compiler gets. See
        // `chock_policy.hardening`: the write and execute rule is the only
        // part of the filter a project can give up, and the operation below
        // measures what that really does to a running process.
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
        // A failed connect alone proves nothing on a machine with no route at all,
        // that would pass with no namespace entered. Read the routing table inside
        // the namespace first, and require it to hold no route.
        //
        // /proc/net/route always prints a header line starting with "Iface" when it
        // prints anything at all, but this kernel prints zero bytes, not even the
        // header, while `lo` is down, which is the state `namespace.enter` leaves
        // it in. So the check below skips the header if present and counts only
        // the data rows, rather than assuming a fixed line count.
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

        // The routing table is empty. Now prove the same thing from the connect
        // side: the failure must be ENETUNREACH specifically, not some other fault
        // that would also return a nonzero exit code but proves nothing about the
        // namespace.
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
        // A network namespace must still permit a unix socket, so that a local pipe and
        // a client socket keep working.
        const fd = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM, 0);
        return if (linux.errno(fd) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "netns-af-packet")) {
        // Plan 23's AF_PACKET escape. This moves whole link layer frames and
        // answers to no route at all: netns-connect above proves the
        // routing table is empty, but an AF_PACKET socket never consults
        // it. What this namespace can still hold back is which interfaces
        // exist inside it, so the proof here is not "the socket refused"
        // but "the socket exists and there is still nowhere for it to send
        // a frame".
        const eth_p_all: u16 = 0x0003;
        const fd_rc = linux.socket(linux.AF.PACKET, linux.SOCK.RAW, std.mem.nativeToBig(u16, eth_p_all));
        if (linux.errno(fd_rc) != .SUCCESS) {
            // Not the predicted outcome: a capability refusal here would be
            // a different story than the one this operation exists to
            // tell. Report plainly rather than silently agreeing with it.
            std.debug.print("netns-af-packet: socket(AF_PACKET): {s}\n", .{@tagName(linux.errno(fd_rc))});
            return 4;
        }
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);

        // The routing table is not what confines this. The interface list
        // is: /proc/net/dev is namespace aware regardless of which mount
        // serves the file, the same property netns-connect's own reading of
        // /proc/net/route relies on. Anything in this namespace beyond "lo"
        // would mean this operation is not measuring what it claims to.
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
            // Both header lines carry a colon of their own kind, so this
            // reads the interface name off the part before ':' and skips a
            // line that never had one.
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

        // The socket exists and there is exactly one interface in this
        // namespace: lo, which namespace.enter leaves down. Ask the kernel
        // for its index and try to move a frame through it. ENETDOWN, not a
        // route failure and not a permission failure, is the actual reason
        // nothing goes anywhere: this network namespace was never given a
        // second interface to fail over to, whatever this socket family can
        // otherwise reach past a route table.
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
        // Prove Finding 1's join actually replaces the session keyring, not just
        // that request_key returns something. id_arg is the description of a
        // key escape.zig planted in its own session keyring, the same one this
        // process inherited across the fork before the join runs. A search that
        // still finds it would mean the join changed nothing and the host's
        // session keyring is still reachable from in here.
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
        // A fresh keyring holds no key under this description, so the kernel must
        // refuse with ENOKEY specifically, not some other fault that would also be
        // nonzero but prove nothing.
        return if (find_errno == .NOKEY) 1 else 5;
    }

    // The operations below are the "spawned-" ones. No code above this point ran
    // for them: no filter, no namespace, no ruleset. They only exist to be the
    // exec target of a real Sandbox.spawn call, from one of the "spawn-" operations
    // further down, so whatever they hit is entirely the doing of that call's
    // applyLayers. This is what Finding 1 needs: deleting any one layer from
    // applyLayers must change the outcome one of these sees, because nothing else
    // in this process could have produced it.
    if (std.mem.eql(u8, args[1], "spawned-handle-escape")) {
        // Plan 23's file handle escape. `name_to_handle_at` turns an
        // ordinary path this operation already has read access to into an
        // opaque handle with no path encoded in it at all, and
        // `open_by_handle_at` reopens that handle through any descriptor on
        // the same mount. If that second step worked, Landlock's path
        // based rules would have nothing left to check: the object this
        // reopens carries no path for a rule to match, whatever rule this
        // sandbox's Landlock ruleset granted or refused for it.
        //
        // The control this operation proves first: /work grants ordinary
        // read and write access, so an open by path succeeds and the write
        // below lands.
        const target: [:0]const u8 = "/work/handle-target";
        const write_fd_rc = linux.open(target, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        if (linux.errno(write_fd_rc) != .SUCCESS) {
            std.debug.print("spawned-handle-escape: create /work/handle-target: {s}\n", .{@tagName(linux.errno(write_fd_rc))});
            return 5;
        }
        const write_fd: i32 = @intCast(write_fd_rc);
        _ = linux.write(write_fd, "handle\n", 7);
        _ = linux.close(write_fd);

        // The handle itself. `name_to_handle_at` needs no capability of its
        // own: it only encodes what a normal path lookup already reached.
        // Reaching this line at all proves the mechanism is real and not
        // silently refused before it starts.
        var raw: [136]u8 align(@alignOf(linux.file_handle)) = undefined;
        const handle: *linux.file_handle = @ptrCast(&raw);
        handle.handle_bytes = 128;
        var mount_id: i32 = undefined;
        const encode_rc = linux.name_to_handle_at(linux.AT.FDCWD, target, handle, &mount_id, 0);
        if (linux.errno(encode_rc) != .SUCCESS) {
            std.debug.print("spawned-handle-escape: name_to_handle_at: {s}\n", .{@tagName(linux.errno(encode_rc))});
            return 5;
        }

        // A descriptor on the same mount, opened by path and not by
        // handle, the way any process that reached this far already
        // could. Not `O_PATH`: `open_by_handle_at`'s own mount descriptor
        // check rejects one, since a path only descriptor carries no file
        // operations for it to read.
        const mount_fd_rc = linux.open("/work", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        if (linux.errno(mount_fd_rc) != .SUCCESS) {
            std.debug.print("spawned-handle-escape: open /work: {s}\n", .{@tagName(linux.errno(mount_fd_rc))});
            return 5;
        }
        const mount_fd: i32 = @intCast(mount_fd_rc);

        // The attack. No path is named here at all: everything a Landlock
        // rule could ever have matched against is gone.
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
        // A seccomp filter that is actually installed kills this process before this
        // line runs. Reaching it at all means the filter spawn was supposed to
        // install never came up.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "spawned-vsock")) {
        // The vsock escape. A seccomp filter that is actually installed
        // kills this process here, on the domain argument alone, before the
        // kernel ever decides whether this host even has a vsock transport
        // to offer. That is on purpose: the rule must not depend on this
        // host being a VM guest today, only on the domain the caller asked
        // for.
        const rc = linux.socket(linux.AF.VSOCK, linux.SOCK.STREAM, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "spawned-setns-proc1")) {
        // Plan 23's proc/1/ns/mnt escape. Control first: the path has to be
        // reachable at all, or a refusal below would be the open failing and
        // not the filter. /proc/1 here names this sandbox's own leader, not
        // the host's real init: buildProcMount mounts a fresh procfs after
        // the pid namespace already exists, and the kernel gives a procfs
        // mounted from inside a pid namespace the view of that namespace.
        // /proc/1/ns/mnt is not one of namespace.masked_proc_entries either:
        // that list masks global files, and this one is per pid.
        const fd_rc = linux.open("/proc/1/ns/mnt", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(fd_rc) != .SUCCESS) {
            std.debug.print("spawned-setns-proc1: open /proc/1/ns/mnt: {s}\n", .{@tagName(linux.errno(fd_rc))});
            return 5;
        }
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);

        // The attack. setns sits on blocked_calls unconditionally, the same
        // as unshare, so the filter has no need to read the fd this carries
        // or ask which namespace it names.
        const rc = linux.setns(fd, 0);
        // The filter kills the process, so this line never runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "spawned-proc-self-mem-write-landlock")) {
        // Plan 23's /proc/self/mem escape, the ordinary configuration: /proc
        // is mounted read only under Landlock, the same rule spawn-proc-mask
        // and spawn-proc-live use. Neither ptrace nor process_vm_writev is
        // called here, so neither of those two blocked calls has anything to
        // say about this: a write to /proc/self/mem goes through open() and
        // write() on a regular file, syscalls no correct tool could do
        // without.
        //
        // **Measured, not guessed.** The predicted refusal was Landlock's
        // EACCES, since the ruleset here grants /proc no write_file right at
        // all. The kernel actually answers EROFS: on this kernel the
        // read-only check `buildProcMount`'s own `markReadOnly` puts on the
        // whole mount is what an O_WRONLY open reaches first, before
        // Landlock's write_file check ever gets a say. See
        // `spawned-proc-self-mem-write-mount` below, which removes Landlock
        // from the question entirely and gets the same answer.
        const fd_rc = linux.open("/proc/self/mem", .{ .ACCMODE = .WRONLY }, 0);
        const open_errno = linux.errno(fd_rc);
        if (open_errno == .SUCCESS) {
            _ = linux.close(@intCast(fd_rc));
            return 0;
        }
        return if (open_errno == .ROFS) 1 else 5;
    }

    if (std.mem.eql(u8, args[1], "spawned-proc-self-mem-write-mount")) {
        // The same attack, with Landlock's write_file right granted on
        // /proc on purpose, so a refusal here cannot be Landlock's doing at
        // all. This does not weaken anything a real caller configures: no
        // production caller grants write on /proc, and this operation
        // exists only to prove the mount's own read only flag refuses the
        // write on its own, with no help from Landlock.
        const fd_rc = linux.open("/proc/self/mem", .{ .ACCMODE = .WRONLY }, 0);
        const open_errno = linux.errno(fd_rc);
        if (open_errno == .SUCCESS) {
            _ = linux.close(@intCast(fd_rc));
            return 0;
        }
        return if (open_errno == .ROFS) 1 else 5;
    }

    if (std.mem.eql(u8, args[1], "spawned-cgroup-remount")) {
        // Plan 23's cgroup escape, the mount half. namespace.enter never
        // takes CLONE_NEWCGROUP, so a fresh "cgroup2" mount would be a view
        // of the entire host hierarchy, one directory per cgroup and not
        // only this session's own: no cgroup namespace stands behind this
        // refusal the way a pid namespace or a mount namespace would. The
        // target does not need to exist, the same as umount-protected and
        // open-tree-attr-protected above: mount sits on blocked_calls
        // unconditionally, so the filter kills this before the kernel ever
        // looks at the path.
        const rc = linux.mount("cgroup2", "/nonexistent-cgroup-mount", "cgroup2", 0, 0);
        // The filter kills the process, so this line never runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "spawned-memfd-exec")) {
        // Plan 23's memfd escape, now closed by a `seccomp.build` rule that
        // kills `execveat` whenever its `flags` argument sets
        // `AT_EMPTY_PATH`, the flag that lets it run a bare descriptor with
        // no path at all. Read this program's own bytes, the way an
        // attacker who already landed a first stage would: nothing here
        // needs a payload the test could not have made itself.
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

        // The control. The same bytes, written to a real path under /work,
        // where the Landlock ruleset this operation is spawned under grants
        // no execute right. A ruleset that handles the execute right denies
        // it by default on every path with no rule granting it, so this has
        // to fail before the memfd attempt below can mean anything.
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

        // The attack. The same bytes, the same Landlock ruleset, and this
        // time no path at all: memfd_create makes an anonymous file with no
        // directory entry, so there is nothing for a path based rule to
        // match against. `memfd_create` itself stays off `seccomp.blocked_calls`:
        // it grants nothing by itself, and this operation's own control
        // above already needed it working.
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

        // `AT_EMPTY_PATH` is what makes this the attack: it is what lets
        // `execveat` accept an empty path string at all, relative to a
        // descriptor rather than a directory. The seccomp filter reads this
        // exact flag on this exact call and kills the process before the
        // kernel acts on it, so this line does not return.
        const exec_rc = linux.execveat(memfd, "", memfd_argv, empty_envp, .{ .SYMLINK_NOFOLLOW = false, .EMPTY_PATH = true });
        std.debug.print("spawned-memfd-exec: execveat on the memfd: {s}\n", .{@tagName(linux.errno(exec_rc))});
        return 6;
    }

    if (std.mem.eql(u8, args[1], "spawned-memfd-landed")) {
        // Unreachable through spawned-memfd-exec today: the execveat call
        // that would land here now dies first, on the AT_EMPTY_PATH rule.
        // Kept for what it still proves if that rule is ever the one that
        // regresses: landing here at all would still not be an escape from
        // anything else this sandbox promises. Seccomp installs once and
        // cannot be shed by any execve, whatever image replaces this one's,
        // so the same ptrace call spawned-ptrace makes above must still die
        // here too.
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
            // A filtered process opening a connection of its own. **The
            // errno is the whole test**: an empty network namespace answers
            // `ENETUNREACH` on its own, so a probe that only checked for a
            // failure would pass with the filter deleted.
            const socket_rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
            if (linux.errno(socket_rc) != .SUCCESS) {
                // Making a socket is not what is refused, and a filter that
                // refused it would be one this design never asked for.
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
            // Ask, use, and then try to aim the answer somewhere else.
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

            // **The descriptor really carries the connection.** The operation
            // that spawned this one accepts on that listener afterwards and
            // reads these bytes back, so a grant that handed over some other
            // descriptor cannot pass.
            const written = linux.write(handle, filtered_token, filtered_token.len);
            if (linux.errno(written) != .SUCCESS or written != filtered_token.len) {
                std.debug.print("the granted descriptor would not carry bytes\n", .{});
                return 3;
            }

            // And it cannot be aimed anywhere else. `EPERM` is the filter; a
            // success is an escape; anything else means something other than
            // the filter refused it and must not read as a pass.
            const reaim = tryToReaim(handle, other_port);
            if (reaim == .SUCCESS) return 1;
            if (reaim != .PERM) {
                std.debug.print("re-aiming answered {t}, not EPERM\n", .{reaim});
                return 5;
            }
            return 0;
        }

        if (std.mem.eql(u8, args[1], "spawned-filtered-refused")) {
            // **What a refusal tells this process, which must be nothing.**
            // The descriptor table before and after is the whole check: a
            // refusal that carried a descriptor would raise the count, and a
            // refusal that carried a reason would have to arrive somewhere
            // this process could read.
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

            // And a permitted host on the same socket is still granted, so
            // the refusal above is the policy and not a broken channel. This
            // is what stops the test passing against a broker that refuses
            // everything.
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
            // Ask one more time than the far end will answer, and require the
            // extra one to be the end of the stream.
            //
            // **Two facts in one run.** The far end really does stop at
            // `max_requests`, so a sandboxed process cannot make it work
            // without bound. And an ask past that point answers: it does not
            // leave this process blocked until the call's own deadline, and it
            // does not end this process with a bare signal number.
            //
            // Every ask is for a host the policy refuses, so nothing is
            // resolved and nothing is dialled: this run costs the far end its
            // budget in policy reads and nothing else.
            // **Two asks past the end and not one.** The first one past the
            // budget usually reaches the socket before the far end's close
            // does, so its bytes go into a buffer and the end of the stream
            // arrives on the read. The second is sent when the peer is
            // certainly gone, so it is the one that exercises a send onto a
            // closed socket rather than a read of a closed one.
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
            // The plainest one: ask for the permitted host and say whether it
            // was granted. Used by the operations that vary the policy rather
            // than the sandbox.
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
            // Two different hosts, one after another, on the same broker
            // pair. The second ask must not be answered by whatever answered
            // the first, and must not be lost because the first one already
            // ran a full reentrant `Broker.request`.
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

            // The first is answered yes and the second is answered no, so a
            // pass here needs both answers to have landed on the right
            // question and neither to have been skipped or duplicated.
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
        // spawn-landlock-escape operation below, through the recursive bind that
        // carries root's own content, but no Landlock rule ever names it.
        const fd = linux.open(spawned_landlock_target, .{ .ACCMODE = .RDONLY }, 0);
        const open_errno = linux.errno(fd);
        if (open_errno == .SUCCESS) {
            _ = linux.close(@intCast(fd));
            return 0; // Opened a path no rule named. The ruleset never applied.
        }
        // A path that no rule names is refused with EACCES, the same as every other
        // Landlock refusal in this file.
        return if (open_errno == .ACCES) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "spawned-fork-bomb")) {
        // A fork bomb, capped from the inside so the unbounded run is bounded
        // work on the machine running the tests. Every child blocks for ever
        // on a pipe nobody writes to, so it stays a live process and really
        // counts against `pids.max` and `RLIMIT_NPROC`. A child that exited
        // would count too, as a zombie, but only until something reaped it,
        // and "only until" is not a property a test should rest on.
        //
        // This process is process 1 of its own pid namespace, so when it
        // returns the kernel kills every child it left behind. Nothing here
        // has to clean up, and nothing can outlive the call.
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
        // An allocation that never stops, capped from the inside. **Every
        // block is written to, not only asked for.** An untouched mapping is
        // exactly what makes `RLIMIT_AS` refuse programs it should not, and a
        // probe that only mapped memory would prove nothing about
        // `memory.max`, which counts resident pages.
        var touched: u8 = 0;
        while (touched < mem_bomb_cap) {
            const block = arena.alloc(u8, mem_bomb_block_bytes) catch break;
            @memset(block, 1);
            touched += 1;
        }
        return touched;
    }
    if (std.mem.eql(u8, args[1], "spawned-fd-bomb")) {
        // Descriptor exhaustion, capped from the inside. `/probe` is this
        // same binary, bound into the sandbox read only by
        // `baseEscapeConfig`, and it is the one path a Landlock rule permits
        // this process to read. Nothing is closed: the point is to hold them.
        var opened: u8 = 0;
        while (opened < fd_bomb_cap) {
            const rc = linux.open("/probe", .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(rc) != .SUCCESS) break;
            opened += 1;
        }
        return opened;
    }
    if (std.mem.eql(u8, args[1], "spawned-disk-file-bomb")) {
        // **The attack `RLIMIT_FSIZE` cannot see**: many small files. Every
        // one of them is far under any file size limit, and together they fill
        // whatever filesystem they land on. Capped from the inside so the
        // unbounded run is bounded work on the machine running the tests.
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
        // One enormous file, in the scratch area rather than in the workspace.
        // **A tmpfs is a filesystem this project had never put `RLIMIT_FSIZE`
        // against**, and a limit that stopped a write on one filesystem and
        // not on another would be a hole nobody would find by reading.
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
        // The approval socket. Anything that can reach it can approve an
        // action, so a tool call must not be able to.
        // The path is a real, listening socket on the host: escape.zig made it
        // and proved it can connect to it itself a moment ago. This process is
        // inside a real Sandbox.spawn whose mount list names the store and this
        // program and nothing else.
        const path_z = arena.dupeZ(u8, id_arg) catch return 3;
        const fd = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM, 0);
        // A network namespace still permits a unix socket, which the
        // netns-loopback operation already proves, so failing here would mean
        // something other than the mount tree stopped this and would prove
        // nothing about the path.
        if (linux.errno(fd) != .SUCCESS) return 5;
        var addr = std.mem.zeroes(linux.sockaddr.un);
        addr.family = linux.AF.UNIX;
        if (path_z.len >= addr.path.len) return 3;
        @memcpy(addr.path[0..path_z.len], path_z);
        const rc = linux.connect(@intCast(fd), @ptrCast(&addr), @sizeOf(linux.sockaddr.un));
        const connect_errno = linux.errno(rc);
        if (connect_errno == .SUCCESS) {
            _ = linux.close(@intCast(fd));
            // Reached the session's approval socket from inside a tool call.
            return 0;
        }
        // The path does not exist in this mount tree at all, so the refusal
        // must be ENOENT specifically. Any other errno would also be nonzero
        // and would say something different happened.
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
        // id_arg is the pid of a process spawn-signal-host made on the host, outside
        // every namespace, and confirmed alive there both before and after this call.
        // A fresh pid namespace has no member under that number: not this process,
        // which is 1, and nothing else, since nothing else was ever forked in it.
        const target = std.fmt.parseInt(linux.pid_t, id_arg, 10) catch {
            std.debug.print("spawned-signal-host: bad pid argument\n", .{});
            return 5;
        };
        // SIGKILL, the same signal the real attack sent to a host victim. The kernel
        // must fail to find a task under this number before it can even ask whether
        // the signal is permitted, so the errno reports a missing process, not a
        // refused permission.
        const rc = linux.kill(target, .KILL);
        const kill_errno = linux.errno(rc);
        if (kill_errno == .SUCCESS) return 0; // Reached the host process. The pid namespace never applied.
        return if (kill_errno == .SRCH) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "spawned-shm-attach")) {
        // id_arg is the id of a segment spawn-shm-attach created on the host, outside
        // every namespace, with a marker written into it.
        const shmid = std.fmt.parseInt(usize, id_arg, 10) catch {
            std.debug.print("spawned-shm-attach: bad shmid argument\n", .{});
            return 5;
        };
        const rc = linux.syscall3(.shmat, shmid, 0, 0);
        const shmat_errno = linux.errno(rc);
        if (shmat_errno == .SUCCESS) return 0; // Attached the host segment. The ipc namespace never applied.
        // An id namespace holds no table entry for, so shmat refuses it with EINVAL,
        // the same errno a shmid that was never valid at all would give.
        return if (shmat_errno == .INVAL) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "spawned-report-pid")) {
        // The direct proof CLONE_NEWPID took effect: this process is the first one the
        // kernel ever created inside the new namespace, so it is numbered 1, never a
        // host scale number. Written to standard output: closeInheritedFds never
        // touches fd 0, 1, or 2, so this line reaches the test through the same pipe
        // the test set up before spawn ever ran.
        var buffer: [16]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "{d}\n", .{linux.getpid()}) catch unreachable;
        _ = linux.write(std.posix.STDOUT_FILENO, line.ptr, line.len);
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-count-opens")) {
        // Make a fixed number of one observed call, and none of two others.
        // The supervisor's histogram is read by `spawn-syscall-audit`, which
        // is the process that holds it: this process cannot see it at all.
        //
        // `/probe` is the one path that is certainly there and certainly
        // readable: `baseEscapeConfig` binds it and gives it a read rule.
        var made: usize = 0;
        while (made < opens_in_probe) : (made += 1) {
            const rc = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(rc) != .SUCCESS) return 5;
            _ = linux.close(@intCast(rc));
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-name-paths")) {
        // One name the configuration grants nothing for, opened three times,
        // and two names it does grant. The grant set for this run is the mount
        // list `baseEscapeConfig` builds, which is `/nix/store` and `/probe`,
        // so the one name below is the only one a reader of the record wants.
        // **This program is statically linked**, so nothing but these calls
        // opens anything at all, and the counts the caller checks are exact
        // rather than a floor.
        //
        // **The opens do not have to succeed.** The kernel holds the call and
        // tells the reader before it runs the call at all, so a path that is
        // not there is recorded exactly as one that is. That is the point: an
        // attempt on a path the sandbox does not hold is the interesting event.
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
        // **Killing your own auditor breaks your own opens.** This process is
        // process 1 of its own pid namespace and the reader is process 2 of
        // the same one, so this process can reach it with an ordinary signal.
        // The supervisor gave up its copy of the notification descriptor when
        // the reader took it, so the reader's death releases the listener and
        // the kernel answers every held call with ENOSYS from that moment.
        //
        // The open below succeeded before the kill: see `spawned-name-paths`,
        // which opens the same path under a live reader.
        const before = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(before) != .SUCCESS) return 5;
        _ = linux.close(@intCast(before));

        // **An alarm, because the failure this test is about is a wait with no
        // end.** With the supervisor still holding a copy of the notification
        // descriptor, the first open after the kill is held by the kernel for
        // an answer nobody will ever give, and this process would never reach
        // the loop below at all. A test that hangs when the code it guards is
        // broken is worth no more than a test that skips, so the kernel ends
        // this process instead and the caller reads a program killed by a
        // signal rather than waiting for the whole suite.
        //
        // **A handler, and not the default action.** This process is process 1
        // of its own pid namespace, and the kernel discards every signal whose
        // action is the default for such a process. Measured on 2026-09-11: an
        // alarm with the default action left this run waiting with no end at
        // all. A handler is delivered, so the alarm ends this process the way
        // it was meant to.
        const on_alarm = std.posix.Sigaction{
            .handler = .{ .handler = endOnAlarm },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        if (linux.errno(linux.sigaction(.ALRM, &on_alarm, null)) != .SUCCESS) return 10;

        // `setitimer` counts whole seconds here, so the sub second field is
        // zero and the unit the kernel reads for it does not matter.
        const alarm: linux.itimerspec = .{
            .it_interval = .{ .sec = 0, .nsec = 0 },
            .it_value = .{ .sec = 10, .nsec = 0 },
        };
        if (linux.errno(linux.setitimer(@intFromEnum(linux.ITIMER.REAL), &alarm, null)) != .SUCCESS)
            return 9;

        if (linux.errno(linux.kill(reader_pid_in_namespace, std.posix.SIG.KILL)) != .SUCCESS) return 6;

        // The kill is delivered to another process, so this loop is what
        // waits for it to take effect. Bounded as well as alarmed, so a build
        // where the reader never dies fails rather than hanging.
        var tries: usize = 0;
        while (tries < 1000) : (tries += 1) {
            const after = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
            switch (linux.errno(after)) {
                .SUCCESS => {
                    _ = linux.close(@intCast(after));
                    var pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
                    _ = linux.nanosleep(&pause, null);
                },
                // The one answer this whole test is about.
                .NOSYS => return 0,
                else => return 7,
            }
        }
        return 8;
    }
    if (std.mem.eql(u8, args[1], "spawned-leave-daemon")) {
        // Fork a process that outlives this one, then end. The supervisor must
        // not wait for that process: it still carries the filter, so a
        // supervisor that waited for the filter to be released would hold the
        // tool call for as long as the leftover process ran.
        const forked = linux.fork();
        if (linux.errno(forked) != .SUCCESS) return 5;
        if (forked == 0) {
            // Long enough that a supervisor which waited for this would be
            // plainly stuck, and still finite, so a fault here ends rather
            // than holding the whole test run.
            var left: usize = 60;
            while (left > 0) : (left -= 1) {
                var second: linux.timespec = .{ .sec = 1, .nsec = 0 };
                _ = linux.nanosleep(&second, null);
            }
            return 0;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-caps-drop")) {
        // The property under test is the **bounding set**, and only the
        // bounding set. `capget`'s three sets are the wrong thing to read
        // here: an ordinary `execve`, of a program with no file capability
        // and no inheritable set carried into it, already clears effective,
        // permitted, and inheritable to zero on every kernel, with no help
        // from this project at all. Measured directly, outside this project:
        // a plain `execl` from inside the same kind of unprivileged user
        // namespace `namespace.enter` builds reads
        // `CapPrm = CapEff = CapInh = 0` in the child on its own, while
        // `CapBnd` carries the full set through the very same `exec`
        // unchanged. The bounding set is the one capability record `exec`
        // never resets by itself, and it is the one `capabilities.dropAll`
        // exists to close: see that file's own top comment.
        //
        // `PR_CAPBSET_READ` answers 1 or 0 as `prctl`'s own return value,
        // never through a pointer, for whether `cap` is still in this
        // process's bounding set. A single capability still present there,
        // after a real `Sandbox.spawn`'s own `applyLayers` ran and this
        // program was already `execve`'d, is the whole failure.
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
        // Finding 2: spawn must give the sandboxed process /dev/null on descriptor
        // 0, never a terminal. statx proves it directly: /dev/null is a character
        // device, and neither a terminal nor a pipe nor a socket is ever one.
        // spawned-stdin-devnull does no setup of its own, so whatever descriptor 0
        // turns out to be is entirely spawn's own doing, before applyLayers ever ran.
        var stx: linux.Statx = undefined;
        const rc = linux.statx(std.posix.STDIN_FILENO, "", linux.AT.EMPTY_PATH, linux.STATX.BASIC_STATS, &stx);
        if (linux.errno(rc) != .SUCCESS) return 5;
        const is_char_device = (stx.mode & linux.S.IFMT) == linux.S.IFCHR;
        return if (is_char_device) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "spawned-stdin-pipe")) {
        // The other half of `Config.stdin_fd`: a helper the harness itself
        // starts really does get the harness's pipe on descriptor 0, and it
        // gets that pipe and nothing else.
        //
        // Five facts, and every one of them is a separate way the field could
        // be wrong. spawned-stdin-pipe does no setup of its own, so each of
        // them is entirely `spawn`'s doing.
        var stx: linux.Statx = undefined;
        const stat_rc = linux.statx(std.posix.STDIN_FILENO, "", linux.AT.EMPTY_PATH, linux.STATX.BASIC_STATS, &stx);
        if (linux.errno(stat_rc) != .SUCCESS) return 5;

        // 1. Descriptor 0 is a pipe. /dev/null and a terminal are both
        //    character devices, so this one comparison tells the new
        //    behaviour from the old and from the hazard at once.
        if ((stx.mode & linux.S.IFMT) != linux.S.IFIFO) {
            std.debug.print("spawned-stdin-pipe: descriptor 0 is not a pipe\n", .{});
            return 1;
        }

        // 2. It is not a terminal, which is the injection route
        //    `redirectStdinToDevNull`'s own comment names: TIOCSTI needs
        //    descriptor 0 to be one. A pipe answers ENOTTY to every terminal
        //    ioctl, and tcgetattr is the cheapest of them.
        var termios: linux.termios = undefined;
        if (linux.errno(linux.tcgetattr(std.posix.STDIN_FILENO, &termios)) == .SUCCESS) {
            std.debug.print("spawned-stdin-pipe: descriptor 0 is a terminal\n", .{});
            return 1;
        }

        // 3. What arrives is exactly the bytes the caller wrote, so the
        //    descriptor really is the caller's own pipe and not some other
        //    pipe that happens to be there.
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

        // 4. A closed write end reads as end of file, never as a wait with no
        //    end. This is what lets a helper learn its owner is finished with
        //    it, and it only works because every copy of the write end is
        //    closed: the caller's own, and the one A holds after the second
        //    fork.
        var extra: [1]u8 = undefined;
        const eof_rc = linux.read(std.posix.STDIN_FILENO, &extra, 1);
        if (linux.errno(eof_rc) != .SUCCESS or eof_rc != 0) {
            std.debug.print("spawned-stdin-pipe: descriptor 0 never reached end of file\n", .{});
            return 1;
        }

        // 5. **The exemption is one descriptor wide.** The caller left a
        //    directory descriptor on the host root open across the spawn, the
        //    exact shape `closeInheritedFds` exists to revoke, and it must be
        //    gone here even though the caller named a descriptor to keep.
        //    F_GETFD answers EBADF on a closed descriptor.
        const escape_fd = std.fmt.parseInt(i32, id_arg, 10) catch return 5;
        if (linux.errno(linux.fcntl(escape_fd, linux.F.GETFD, 0)) != .BADF) {
            std.debug.print("spawned-stdin-pipe: an inherited descriptor survived\n", .{});
            return 1;
        }

        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-open-fd-set")) {
        // **The exact set of descriptors that survived `execve`, and nothing
        // else.** An already open descriptor goes through no path resolution
        // again, so neither Landlock nor the mount namespace can revoke one:
        // a single descriptor that crosses is a hole through both layers at
        // once. `spawned-open-fd-set` does no setup of its own, so what it
        // finds open is entirely what `spawn` left it.
        //
        // **Exact, and not "the one the caller named is gone".** The other
        // check of this property, `spawned-stdin-pipe`'s own fifth, reads one
        // descriptor number the caller chose, so it stays green for a
        // descriptor `spawn` itself grew later. This one names the whole set,
        // so a new pipe, socket, or ring that reaches the program has to be
        // written down here before the suite goes green again.
        const filtered = std.mem.eql(u8, id_arg, "filtered");
        if (!filtered and !std.mem.eql(u8, id_arg, "plain")) return 5;

        var fd: i32 = 0;
        while (fd < open_fd_set_scan_limit) : (fd += 1) {
            // `F_GETFD` answers `EBADF` for a number that names nothing, so
            // it reads the table without `/proc`, which the sandbox a real
            // tool call runs in does not mount.
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

        // What each survivor is, and not only that a number is taken. A
        // regression that put the caller's own log file on descriptor 0 would
        // keep the set the same size and would still be the leak this
        // operation is about.
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
        // Every name on the list, not one of them. A masking loop that stopped
        // after the first entry, or that skipped one spelling, passes a test
        // that reads a single file and fails this one. The list comes from
        // `namespace.masked_proc_entries` itself, so a name added there is
        // covered here on the day it is added.
        var checked: usize = 0;
        for (sandbox.namespace.masked_proc_entries) |name| {
            var path_buffer: [64]u8 = undefined;
            const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{s}", .{name}) catch return 5;

            const fd_rc = linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0);
            const open_errno = linux.errno(fd_rc);
            // A kernel built without the option that makes this file. Nothing
            // to read and nothing to prove.
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
        // that masked nothing at all had a broken list rather than a spare
        // kernel, and must not read as a pass.
        if (checked < 3) {
            std.debug.print("spawned-proc-mask: only {d} entries existed to check\n", .{checked});
            return 5;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-proc-live")) {
        // The other half of the pair. Masking and `/proc/self` can break each
        // other: a mask over the wrong path takes away `/proc/self/exe`, which
        // is the reason `/proc` is mounted at all, and a procfs that went
        // missing or that something empty was mounted over would make every
        // read in spawned-proc-mask return zero bytes for the wrong reason.
        var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const link_rc = linux.readlink("/proc/self/exe", &link_buffer, link_buffer.len);
        if (linux.errno(link_rc) != .SUCCESS) {
            std.debug.print("spawned-proc-live: /proc/self/exe: {s}\n", .{@tagName(linux.errno(link_rc))});
            return 1;
        }
        // The path this probe was execed as, and nothing else: a link that
        // resolved to something else would mean this is not this process's
        // own procfs.
        if (!std.mem.eql(u8, link_buffer[0..link_rc], "/probe")) {
            std.debug.print("spawned-proc-live: /proc/self/exe gave {s}\n", .{link_buffer[0..link_rc]});
            return 1;
        }

        // A global file that no mask names. It has to hold bytes, or the
        // whole procfs is empty and the mask proves nothing.
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
        // Finding 1: do real work, then pick an exit code from the range the
        // old design used to treat as proof the sandbox itself never came up
        // (111 was namespace_failed). spawned-forge-exit does no setup of its
        // own, so the only way this code could ever be read as a setup failure
        // is if spawn itself still trusted an exit code for that, which it must
        // not: the caller's own program controls every byte of its own exit
        // status, and this is that attack, played out directly.
        writeTestFile(arena, "/work/output.txt", "chock forge-exit probe content\n") catch |err| {
            std.debug.print("spawned-forge-exit: could not write the marker: {s}\n", .{@errorName(err)});
            return 5;
        };
        return 111;
    }
    if (std.mem.eql(u8, args[1], "spawned-loop-write")) {
        // Finding 2: keep appending to a marker file until something kills this
        // process. If PDEATHSIG never arms, or the race window between the
        // second fork and armPdeathsig's own prctl call swallows it, this
        // process becomes an orphan and keeps growing this file forever after
        // the middle process spawn forked is gone. spawned-loop-write does no
        // setup of its own, so its only job is to keep producing a side effect
        // a test can watch stop.
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
        // **A tool call that started something of its own.** A cancel reaches
        // one process, the one `spawn` forked, and that process is neither
        // this one nor the child forked below. This operation is what makes
        // the difference visible: nothing this process writes is the heartbeat
        // the caller watches, so a heartbeat that keeps growing after the
        // cancel is a leaked grandchild and nothing else.
        //
        // The marker says the fork itself worked. Without it, a fork that
        // failed would leave no heartbeat at all, and a test watching for the
        // heartbeat to stop would pass for the wrong reason.
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

        // This process writes nothing else, ever. It is here only so the
        // grandchild has a parent that a cancel does not name either.
        while (true) _ = linux.nanosleep(&.{ .sec = 3600, .nsec = 0 }, null);
    }

    if (std.mem.eql(u8, args[1], "spawned-setsid-fork-loop-write")) {
        // Plan 23's setsid escape. Same shape as spawned-fork-loop-write
        // above, except the grandchild calls setsid() before it starts
        // writing: it leaves the process group `Sandbox.spawn` put it in
        // and becomes the leader of a session of its own. `kill(0, sig)` no
        // longer names it and a terminal's own Ctrl-C no longer reaches it,
        // the same gap spawned-signal-group and spawned-group-press exist
        // to close for a plain fork. Neither of the two mechanisms that
        // actually tear this sandbox down reads a process group or a
        // session: `PR_SET_PDEATHSIG` fires on the death of the process
        // that armed it, and `cgroup.kill` reaches every process in the
        // cgroup by membership, not by group.
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) {
            std.debug.print("spawned-setsid-fork-loop-write: fork failed\n", .{});
            return 5;
        }

        if (@as(linux.pid_t, @intCast(child)) == 0) {
            // setsid fails with EPERM for a process that is already a
            // process group leader, which the first child of a fork never
            // is: its pid is fresh and nothing has made it a leader yet.
            // The marker below is the control: a run that never wrote it
            // ran the attack, and a heartbeat that later stopped anyway
            // would prove nothing about the teardown this operation exists
            // to measure.
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

        // This process writes nothing else, ever. It is here only so the
        // grandchild has a parent that a cancel does not name either.
        while (true) _ = linux.nanosleep(&.{ .sec = 3600, .nsec = 0 }, null);
    }

    if (std.mem.eql(u8, args[1], "spawned-signal-group")) {
        // The attack the pid namespace does not answer on its own. A signal to
        // a pid number is refused in here, which spawned-signal-host already
        // proves, but `kill(0, sig)` names no number at all: it names the
        // caller's own process group, which the kernel holds as an object.
        // Measured on 2026-08-21: a process in a fresh pid namespace reads
        // getpgid(0) as 0, because its group has no number there, and this
        // same call still reached a process outside the namespace.
        //
        // SIGUSR1, because spawn-signal-group above catches it and reports
        // whether it arrived. Reporting from here is not possible: this
        // process cannot see the group it is in, which is the whole point.
        const rc = linux.kill(0, .USR1);
        const kill_errno = linux.errno(rc);
        if (kill_errno != .SUCCESS) {
            std.debug.print("spawned-signal-group: kill(0, USR1): {s}\n", .{@tagName(kill_errno)});
            return 5;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-group-press")) {
        // The Ctrl-C half. A terminal sends its signal to the whole foreground
        // process group, so this process must be in a group the caller's own
        // press cannot name. It catches the signal rather than dying from it,
        // because "the press arrived here" and "this process died" have to be
        // two different answers: process 1 of a pid namespace ignores every
        // signal whose action is the default one, so a death is not a thing
        // this process can be relied on to have.
        catchSignal(.USR1);
        writeTestFile(arena, "/work/started", "started\n") catch |err| {
            std.debug.print("spawned-group-press: could not write the marker: {s}\n", .{@errorName(err)});
            return 5;
        };

        // The caller presses first and writes this second, so a run that
        // reaches here has already had every chance to be signalled.
        if (!waitForPath("/work/go")) {
            std.debug.print("spawned-group-press: the caller never wrote /work/go\n", .{});
            return 4;
        }
        return if (caller_signal_seen.load(.monotonic)) 1 else 0;
    }

    if (std.mem.eql(u8, args[1], "read-home")) {
        // A setup failure must exit 3, never 1 or 5. Those two are what the test
        // asserts for a working sandbox that correctly refuses the read, so a
        // setup bug that reused either would read as a passing test instead of a
        // broken probe.
        enterTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        // The home directory is not in the mount tree, so it does not exist here.
        const fd = linux.open("/home", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        const open_errno = linux.errno(fd);
        if (open_errno == .SUCCESS) _ = linux.close(@intCast(fd));
        if (open_errno == .SUCCESS) return 0;
        // Exit 1 only for the specific reason the design predicts: /home was
        // never created, so opening it must fail with ENOENT. Any other errno
        // means something else broke, and must not be mistaken for the sandbox
        // doing its job.
        return if (open_errno == .NOENT) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "cgroup-surface")) {
        // Plan 23's cgroup escape, the surface half. The cgroup Chock builds
        // for this call, and writes memory.max, pids.max and
        // memory.swap.max into, is never bound into this mount tree. A
        // process with no path to a file cannot widen what the file holds,
        // whatever write permission it would otherwise have, so nothing
        // else needs proving once this is: there is no cgroupfs mount here
        // at all.
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
        // The submount must be read only too, refused with the same EROFS a
        // direct read only bind gives, not merely some other failure.
        return if (open_errno == .ROFS) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "delete-mounted-file")) {
        enterTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        // A file that is a mount point cannot be unlinked. The kernel returns EBUSY.
        const unlink_errno = linux.errno(linux.unlink("/work/chock.zon"));
        if (unlink_errno == .SUCCESS) return 0;
        return if (unlink_errno == .BUSY) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "file-bind-content")) {
        enterFileOverFileTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };

        // Read the target back and compare it with the content written to the
        // source before the bind, proving the target really is the source file,
        // not an empty directory that a file bind failed to cover.
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
        // `id_arg` is a directory escape.zig made with its own scratchRoot,
        // wholly separate from `root_arg`: not a subdirectory of it, not
        // bind mounted into it, nothing this sandbox's own mount tree names.
        // A file put there and read back afterward is the proof this probe
        // needs: `applyDenyMounts` never touches anything outside the
        // sandbox root it was handed, so a change here can only mean the
        // bind mount followed a symlink out of the project.
        const secret_content = "chock outside secret content\n";
        const secret_path = try std.fs.path.join(arena, &.{ id_arg, "secret" });
        try writeTestFile(arena, secret_path, secret_content);
        const secret_z = try arena.dupeZ(u8, secret_path);

        // `.env`, inside the project, aimed outside it. `deny.zig`'s own
        // `check` accepts this shape today: it never stats a symlink's
        // target, so a project may name a link exactly like this one under
        // `deny_read` and have it accepted.
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

        // The secret's own real path, read back exactly as this probe wrote
        // it. Still reachable by that same absolute name here: `buildRoot`
        // never calls `pivot_root`, so nothing has detached the host tree
        // yet. If the bind landed on it, this now holds the deny notice
        // instead of what was written above. The buffer has to hold the
        // whole notice, not only the secret: a buffer sized to the shorter
        // string would truncate the read and could never compare equal to
        // the longer one, which reads as "not escaped" whether or not it was.
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

        // Exit 1 is the fault this probe exists to catch: the bind landed
        // outside, whatever buildRoot itself went on to answer. Exit 0 is a
        // clean refusal, `error.DenyTargetIsSymlink`, with the secret left
        // exactly as this probe wrote it. Anything else is exit 5: neither
        // the fault nor the fix this probe was written to tell apart.
        if (escaped) return 1;
        if (build_result) |_| return 5 else |err| return if (err == error.DenyTargetIsSymlink) 0 else 5;
    }
    if (std.mem.eql(u8, args[1], "bind-source-symlink")) {
        // `id_arg` is a directory escape.zig made with its own scratchRoot,
        // wholly separate from `root_arg`: not a subdirectory of it, not bind
        // mounted into it, nothing this sandbox's own mount tree names. A
        // file put there and read back through the sandbox's own bind target
        // is the proof this probe needs.
        //
        // This is `chock.zon`'s own shape: the file is read out of the
        // agent's own checkout, a tree the agent can write to between tool
        // calls, and `ln -s <host path> chock.zon` there is exactly the bind
        // source this probe builds by hand.
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

        // The bind target's own real path, read back exactly as `buildRoot`
        // left it. Still reachable by that same absolute name here:
        // `buildRoot` never calls `pivot_root`, so nothing has detached the
        // host tree yet. If the bind followed the symlinked source, this now
        // holds the host secret instead of nothing at all.
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

        // Exit 1 is the fault this probe exists to catch: the bind landed on
        // the host secret, whatever buildRoot itself went on to answer.
        // Exit 0 is a clean refusal, `error.BindSourceIsSymlink`. Anything
        // else is exit 5: neither the fault nor the fix this probe was
        // written to tell apart.
        if (escaped) return 1;
        if (build_result) |_| return 5 else |err| return if (err == error.BindSourceIsSymlink) 0 else 5;
    }
    if (std.mem.eql(u8, args[1], "deny-intermediate-symlink")) {
        // `id_arg` is a directory escape.zig made with its own scratchRoot,
        // wholly separate from `root_arg`, and empty. Nothing under it is
        // ever created by any mount this sandbox root names, so `creds/token`
        // appearing there afterward is the proof this probe needs: the old
        // by name `mkdirat` and `openat` calls in `createDenyTarget` would
        // have made it right there, the moment the symlink below was walked
        // as an ordinary directory instead of refused.
        const work = try std.fs.path.join(arena, &.{ root_arg, "work" });
        try makeTestDir(arena, work);

        // `work/link`, inside the project, aimed outside it: the
        // intermediate component of a `deny_read` entry such as
        // `link/creds/token`. `deny.zig`'s own `check` accepts this shape
        // today, the same way it accepts a symlink at the leaf: it is a
        // string check and cannot see that `link` is not a directory.
        const link_path = try std.fs.path.join(arena, &.{ work, "link" });
        const link_z = try arena.dupeZ(u8, link_path);
        const outside_z = try arena.dupeZ(u8, id_arg);
        if (linux.errno(linux.symlink(outside_z.ptr, link_z.ptr)) != .SUCCESS) return 3;

        enterOrEndUnmeasured(.{ .network = .none, .mount = true });
        const build_result = sandbox.namespace.buildRoot(arena, root_arg, &.{
            .{ .bind = .{ .source = work, .target = "/work", .read_only = false } },
            .{ .deny = .{ .target = "/work/link/creds/token" } },
        }, null);

        // The path the symlink names, read back exactly as `buildRoot` left
        // it. Still reachable by that same absolute name here: `buildRoot`
        // never calls `pivot_root`, so nothing has detached the host tree
        // yet. If an intermediate symlink component was followed, this now
        // exists and holds the deny notice, created and covered outside the
        // sandbox root entirely.
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

        // Exit 1 is the fault this probe exists to catch: a file was created
        // outside the sandbox root, whatever buildRoot itself went on to
        // answer. Exit 0 is a clean refusal, `error.DenyTargetIsSymlink`,
        // with nothing created outside at all. Anything else is exit 5:
        // neither the fault nor the fix this probe was written to tell
        // apart.
        if (escaped) return 1;
        if (build_result) |_| return 5 else |err| return if (err == error.DenyTargetIsSymlink) 0 else 5;
    }

    // The netns-connect, netns-loopback, read-home, write-readonly,
    // write-readonly-submount, delete-mounted-file, file-bind-content,
    // deny-symlink-outside, bind-source-symlink, and deny-intermediate-symlink
    // checks above ran inside the namespaces, with no seccomp filter
    // installed. Every operation below this line runs with the filter
    // installed, and did not enter any namespace.
    if (std.mem.eql(u8, args[1], "ptrace")) {
        const rc = linux.syscall4(.ptrace, 0, 0, 0, 0);
        // The filter kills the process, so this line never runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "umount-protected")) {
        // The path does not need to be a real mount point. The filter must kill the
        // call before the kernel ever looks at the path. Without this rule, a process
        // in its own user namespace could unmount the read only bind mount that
        // protects a file such as chock.zon, then open it for write and change it.
        const rc = linux.umount2("/work/chock.zon", linux.MNT.DETACH);
        // The filter kills the process, so this line never runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "open-tree-attr-protected")) {
        // open_tree_attr is open_tree and mount_setattr combined into one call, added
        // in kernel 6.15. Without OPEN_TREE_CLONE it acts on the live mount, so
        // clearing MOUNT_ATTR_RDONLY here undoes the read only bind that protects a
        // file such as chock.zon, the same way a bare mount_setattr can. The path
        // does not need to be a real mount point, the same as umount-protected above:
        // the filter must kill the call before the kernel ever looks at the path.
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
        // Finding 1: the filter must refuse add_key outright, the same way it
        // refuses ptrace, with no dependence on which session keyring is current.
        // This probe does not join a fresh one itself; the filter has to stop the
        // call regardless.
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
        // Finding 3. io_uring is the standard way around a syscall filter: the
        // operations go in a ring and kernel workers do them, so the thread that
        // asked never makes the call the filter reads. The filter has to refuse the
        // ring itself, because it cannot read what goes into one.
        //
        // The arguments are the ones a real caller sends, so this call would set up a
        // ring if the filter let it through. Anything less would pass this probe for
        // the wrong reason.
        var params: linux.io_uring_params = std.mem.zeroes(linux.io_uring_params);
        const rc = linux.io_uring_setup(1, &params);
        return ringRefusal(rc);
    }
    if (std.mem.eql(u8, args[1], "io-uring-enter")) {
        // The call that submits the operations. This probe holds no ring, the same
        // way umount-protected above names no real mount point: the filter must
        // refuse the call before the kernel ever looks at the descriptor. A filter
        // that refused only io_uring_setup would leave a ring another process set up
        // and handed over still usable.
        const rc = linux.syscall6(.io_uring_enter, @bitCast(@as(isize, -1)), 1, 0, 0, 0, 0);
        return ringRefusal(rc);
    }
    if (std.mem.eql(u8, args[1], "io-uring-register")) {
        // The call that gives a ring its buffers, its files, and its eventfd. Refused
        // for the same reason as io_uring_enter above, and with no ring here either.
        const rc = linux.syscall4(.io_uring_register, @bitCast(@as(isize, -1)), 0, 0, 0);
        return ringRefusal(rc);
    }
    if (std.mem.eql(u8, args[1], "io-uring-then-work")) {
        // **What the fix is actually for.** A run time probes for a ring, reads the
        // refusal, and carries on with the thread pool it used before io_uring
        // existed. That is what libuv does on a kernel older than 5.1, and it is what
        // Node does at startup. This probe is the same shape: ask for a ring, expect
        // to be refused, and then do ordinary work and exit cleanly.
        //
        // A kill leaves no line after the call to run, so this operation cannot pass
        // under a filter that kills, whatever the errno rule says.
        var params: linux.io_uring_params = std.mem.zeroes(linux.io_uring_params);
        const rc = linux.io_uring_setup(1, &params);
        if (linux.errno(rc) != .PERM) return 4;
        // Ordinary work after the refusal, so the exit status says the process was
        // still alive and still able to make a syscall.
        if (linux.getpid() <= 0) return 4;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "getpid")) {
        // A call that the filter must allow. This proves the filter is not a deny all.
        _ = linux.getpid();
        return 0;
    }

    if (std.mem.eql(u8, args[1], "landlock-write-outside") or
        std.mem.eql(u8, args[1], "landlock-write-inside"))
    {
        // A setup failure here must exit 3, never 1 or 0. Those two are what
        // the corresponding tests assert for a working sandbox, so a setup bug
        // must never be read as either one.
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
        // Proves the fix for the bug a reviewer found: a ruleset that does not
        // handle truncate leaves truncate permitted everywhere, so a file
        // outside every granted directory could still be emptied. A setup
        // failure here must exit 3, never 1 or 0, for the same reason as the
        // write probe above.
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
        // Run this same program through the whole sandbox, and let it call ptrace.
        // Only the seccomp filter spawn installs can be standing in the way, since
        // spawned-ptrace does no setup of its own. See the comment on `spawned`.
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
        // The vsock escape. See `spawned-vsock`. `.network = .none` on
        // purpose: the point of this operation is that the domain check
        // kills the call before any network namespace question is ever
        // reached, so the network mode a real caller picks makes no
        // difference to the outcome.
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
        // Plan 23's proc/1/ns/mnt escape. /proc is mounted read only, the
        // same as spawn-proc-mask and spawn-proc-live, so the target this
        // operation opens really is reachable and the attack is not refused
        // for the incidental reason that the path does not exist.
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
        // The ordinary configuration: /proc read only under Landlock. See
        // `spawned-proc-self-mem-write-landlock`.
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
        // The isolating configuration: /proc granted write under Landlock
        // too, so only the mount's own read only flag is left. See
        // `spawned-proc-self-mem-write-mount`.
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
        // Plan 23's cgroup escape, the mount half. See
        // `spawned-cgroup-remount`.
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
        // Plan 23's memfd escape. /work is granted every ordinary right
        // except execute, so an on-disk execve there is the control this
        // operation's own inner half proves refused before it ever tries
        // the memfd. See `spawned-memfd-exec`.
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
        // Plan 23's file handle escape. See `spawned-handle-escape`.
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
        // The three resource limit runs. **The layer these prove is the only
        // one in this sandbox that is about appetite rather than reach**: the
        // namespaces, Landlock and seccomp all let a fork bomb through.
        //
        // Each operation has an `-unbounded` twin that runs the same program
        // under `Limits.none`. `escape.zig` runs both and compares them, so a
        // limit deleted from the library changes the bounded run's answer
        // into the unbounded one's and the test fails. See `LimitOutcome`.
        const unbounded = std.mem.endsWith(u8, args[1], "-unbounded");
        // The one run that is about the cgroup and not about the floor. It
        // leaves `mapped_memory_bytes` off, so `RLIMIT_DATA` refuses nothing
        // and only `memory.max` can stop the program. That matters for the
        // legibility half: the rlimit floor stops an allocation by refusing
        // an `mmap`, which the program itself reports, while `memory.max`
        // stops it with a bare `SIGKILL` that reads exactly like a cancel.
        // **The second one is the failure that needs a report to be legible
        // at all**, so it needs a run of its own to prove.
        const cgroup_only = std.mem.endsWith(u8, args[1], "-cgroup");
        const base = try baseEscapeConfig(arena);

        const which: enum { fork, memory, files } = if (std.mem.startsWith(u8, args[1], "spawn-fork-bomb"))
            .fork
        else if (std.mem.startsWith(u8, args[1], "spawn-mem-bomb"))
            .memory
        else
            .files;

        // The bounded runs start from the library's own defaults and narrow
        // exactly the one field each is about, so what runs here is the shape
        // a real tool call gets and not a special case built for a test.
        const limits: sandbox.Sandbox.Limits = if (unbounded)
            sandbox.Sandbox.Limits.none
        else switch (which) {
            .fork => .{ .processes = fork_bomb_limit },
            // Both memory fields, because a machine with no cgroup v2 has no
            // resident ceiling at all and this run still has to prove
            // something there. See lib/chock-sandbox/linux/rlimits.zig.
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

        // Whether the report could name what stopped the program, which is
        // the half of this that is about a person being able to read the
        // failure rather than about the failure happening at all. A kill by
        // `memory.max` is a bare SIGKILL and reads exactly like a cancel;
        // `killed_by` is what tells them apart. A fork refused by `pids.max`
        // is not a kill at all, and `events.fork_refusals` is what makes it
        // visible.
        // A machine with no cgroup v2 tree, or one that delegates nothing, is
        // a machine this project supports. Say so before reading the outcome,
        // so that a test asking about the cgroup skips there **and a cgroup
        // that did apply and then bounded nothing still fails**.
        if (cgroup_only and !report.cgroup.applied()) {
            return @intFromEnum(LimitOutcome.no_cgroup);
        }

        const named = report.killed_by != null or report.events.fork_refusals > 0;
        return limitOutcome(term, cap, named);
    }
    if (std.mem.startsWith(u8, args[1], "spawn-disk-")) {
        // The two disk runs. **The row of the resource limit table that no
        // rlimit and no cgroup covers**: `RLIMIT_FSIZE` bounds one file, and
        // ten thousand files of one byte each still fill a filesystem. See
        // `lib/chock-sandbox/linux/namespace.zig`'s own `Scratch`.
        //
        // Each operation has an `-unbounded` twin that runs the same program
        // under `Limits.none`, which still mounts a scratch area and gives it
        // no `size=` of its own, so the two runs differ in the cap and in
        // nothing else.
        const unbounded = std.mem.endsWith(u8, args[1], "-unbounded");
        const many_files = std.mem.startsWith(u8, args[1], "spawn-disk-files");
        const config = try diskEscapeConfig(arena);

        const limits: sandbox.Sandbox.Limits = if (unbounded)
            sandbox.Sandbox.Limits.none
        else if (many_files)
            .{ .scratch_bytes = disk_file_limit }
        else
            // The enormous file run. The scratch cap is deliberately far above
            // what this program writes, so the area cannot be what stops it and
            // `RLIMIT_FSIZE` is the only thing left that can.
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

        // **`killed_by` is what makes a full scratch area readable as a limit
        // rather than as the user's disk being full.** Nothing in the kernel
        // counts a full filesystem, so this is read from the area itself: see
        // `LimitsReport.scratch_full`.
        const named = report.killed_by != null;
        return limitOutcome(term, cap, named);
    }
    if (std.mem.eql(u8, args[1], "spawn-approval-socket")) {
        // Run this same program through the whole sandbox and let it try to
        // reach the session's own approval socket. The path is one escape.zig
        // made and can reach itself, and it is outside `root_arg`, so nothing
        // in the mount list this hands to spawn names it. See
        // `spawned-approval-socket`.
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
            // Nothing was ever asked of the broker, so nothing was resolved
            // and nothing was dialled: the child never got as far as asking.
            if (run.lookups != 0 or run.dials != 0) {
                std.debug.print("the child that opened its own connection also used the broker\n", .{});
                return 5;
            }
            // **And it reached neither listener.** This is the independent
            // observation: the child says what it decided, and the backlogs
            // say what really happened on the wire. A connect that succeeded
            // fills the first backlog, and the child would report that too, so
            // the two disagreeing means something other than the filter is at
            // work and must never read as a pass.
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
            // **The descriptor really carried the connection the broker
            // opened.** These are the bytes the child wrote, arriving on the
            // listener this process dialled, which no forged descriptor could
            // produce.
            var buffer: [64]u8 = undefined;
            const arrived = granted.readFirst(&buffer) orelse {
                std.debug.print("nothing arrived on the listener the broker dialled\n", .{});
                return 5;
            };
            if (!std.mem.eql(u8, arrived, filtered_token)) {
                std.debug.print("the listener read {s}, not the token\n", .{arrived});
                return 5;
            }
            // **And nothing reached the other listener.** This is the half an
            // exit code cannot carry: with the filter deleted, the child's own
            // re-aim connects here and this backlog is not empty. The child
            // reports that escape as exit 1 by itself, so a full backlog with
            // a child that reported a pass is a third thing again, and it is
            // never one.
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
            // One refusal and one grant, which is what the child asked for.
            if (run.refused != 1 or run.granted != 1) {
                std.debug.print("the broker granted {d} and refused {d}\n", .{ run.granted, run.refused });
                return 5;
            }
            // **The refused host was never resolved**, so a name the policy
            // does not cover is not even a message to whoever runs its zone.
            // One lookup, for the permitted host that followed it.
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

        // The subagent pair. The same host, the same policy source, and two
        // spawn chains: one that is the root, and one that is a subagent under
        // a parent the policy refuses.
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
            // The far end answered exactly its own budget and then stopped,
            // and every one of those answers was a refusal that resolved
            // nothing and dialled nothing.
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

        // A permitted name whose address is this machine. The policy says yes
        // and `addressIsReachable` says no, so this pins that the address
        // check really runs inside a spawn and not only in a unit test.
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
            // The name was resolved, because the policy permitted it, and
            // nothing was dialled. That is what says the address check is what
            // refused it.
            if (run.lookups != 1 or run.dials != 0) {
                std.debug.print("the broker looked up {d} names and dialled {d}\n", .{ run.lookups, run.dials });
                return 5;
            }
            return reportChildTerm(run.term);
        }

        // **The reentrancy proof.** `ask_policy` names no rule, so the table
        // answers `ask` for the one host the child asks about, and that is
        // what routes the connection through a real `Broker.request`, called
        // from inside this very `Sandbox.spawn`'s own `serveBroker` loop. An
        // arbiter played entirely in process approves it, and the checks
        // below are the four things section C2 of the plan asks a real run to
        // prove. The request and its answer are both in the log, in order,
        // with a real id. The turn that was already in flight is still
        // intact. The hash chain never broke. The sandboxed call finished
        // normally rather than hanging or crashing.
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

        // The same proof, with the arbiter saying no instead of yes. A
        // refusal must reach the log and the sandboxed child exactly as
        // faithfully as a grant does.
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

        // Nobody answers. `askTheHuman`'s own deadline is what ends the wait,
        // and it writes the `expired` answer itself: an unanswered question
        // must not hang the sandboxed call forever, and it must not look like
        // a person said no.
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
            // The deadline itself writes one answer, `expired`, so the
            // question does not sit open the way a cancellation leaves it.
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

        // The wait itself is cancelled, the way a signal reaching this
        // process while it waits would report through `Waiter.wait`. The
        // question must stay open with no answer, the same state a crash
        // leaves, and the call must still end rather than hang.
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

        // Two different hosts, asked one after the other inside the same
        // `Sandbox.spawn`. The first re-entry into `Broker.request` might
        // work and the second might not, which is exactly what this pins:
        // both must reach the log, in order, each answered the way this
        // arbiter meant to answer it and not the other one's decision.
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
        // Run this same program through the whole sandbox, and let it read a path
        // that no Landlock rule names. The path exists because it is a plain
        // subdirectory of root, carried into the sandbox by the same recursive
        // bind that carries every other part of root, so nothing hides it from a
        // process that never got restricted. Only the ruleset spawn applies can
        // still refuse the read, since spawned-landlock-read does no setup of its
        // own. See the comment on `spawned`.
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
        // Run this same program through the whole sandbox, and let it try to
        // connect out. `.network` is left off this Config on purpose, so the
        // default Finding 2 puts on Sandbox.Config decides: `.none`, not the
        // host's network. Only the network namespace spawn enters can refuse the
        // connect, since spawned-connect does no setup of its own. See the
        // comment on `spawned`.
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
        // id_arg is the pid of a real process the caller (escape.zig) made outside
        // every namespace, so that a refusal here proves the pid namespace hides an
        // actual host process, not merely that some unused number was tried. Only the
        // pid namespace spawn enters can refuse the signal, since spawned-signal-host
        // does no setup of its own. See the comment on `spawned`.
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
        // id_arg is the id of a segment the caller made outside every namespace,
        // with a marker written into it, the same shape as the shared memory half of
        // the real escape this proves closed. Only the ipc namespace spawn enters can
        // refuse the attach, since spawned-shm-attach does no setup of its own. See
        // the comment on `spawned`.
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
        // Run this same program through the whole sandbox, and let it print its own
        // pid. spawned-report-pid does no setup of its own, so the number it prints
        // is entirely a fact about the pid namespace spawn's applyLayers built.
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
    if (std.mem.eql(u8, args[1], "spawn-supervisor-audit")) {
        // **The whole chain, through a real spawn.** The supervisor process is
        // the one that holds the provider credential while it waits for the
        // sandboxed program, and it puts a seccomp filter on itself for that
        // reason. That install is best effort, so a failure used to reach
        // standard error and nothing else. This asks the record instead: it
        // runs one ordinary sandboxed program and reads back what the
        // supervisor said about its own filter.
        //
        // The exit status is the answer, because nothing here may print: the
        // audit lives in this process's own memory and the test process cannot
        // read it any other way.
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

        // The program itself has to have run, or the counts below are about
        // nothing.
        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }

        const counts = audit.counts();
        // **Nothing said is its own answer, and it is a failure here.** This
        // machine builds sandboxes, so the supervisor reached the point where
        // it confines itself, and a silent one means the record never left it.
        if (counts.unreported != 0) return 5;
        // The supervisor could not filter itself on a machine that gave it a
        // whole sandbox. Real, and this is the case the record exists for, so
        // it gets a status of its own rather than sharing one.
        if (counts.unconfined != 0) return 6;
        if (counts.confined != 1) return 7;
        if (counts.first_fault != null) return 8;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-syscall-audit-daemon")) {
        // **The no hang case.** The program ends and leaves a process behind
        // that still carries the filter. The supervisor watches the program
        // and not the filter, so this call has to come back at once.
        //
        // Nothing is asserted about the counts here. The one fact under test
        // is that `spawn` returns at all.
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .seccomp_options = .{ .traps = sandbox.seccomp.TrapSet.initFull() },
        }, &.{ "/probe", "spawned-leave-daemon" }, null, null);

        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-path-audit") or
        std.mem.eql(u8, args[1], "spawn-path-audit-off"))
    {
        // **The whole chain again, one level deeper.** The counting run above
        // says `openat` happened. This run says what was named. A third
        // process, forked inside the sandboxed program's own pid namespace,
        // holds the notification descriptor and copies the path argument out
        // of the held call before it answers.
        //
        // The second name is the control: the identical program runs with no
        // path audit asked for, and nothing may be recorded.
        //
        // The exit status is the answer, because nothing here may print: the
        // audit lives in this process's own memory.
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
            // Nothing was asked for, so nothing may be there. A count above
            // zero would mean the record comes from somewhere other than a
            // reader this config asked for.
            if (seen.kept != 0) return 5;
            if (seen.granted[slot] != 0 or seen.ungranted[slot] != 0) return 6;
            if (audit.paths.readers_unreported != 0 or audit.paths.readers_absent != 0) return 7;
            // The counting still works with no path audit, which is the
            // promise that the default costs nothing.
            if (audit.counts().calls[slot] == 0) return 8;
            return 0;
        }

        // The reader reached its loop. **That is asserted and the way it
        // ended is not**, and this is the one place in the suite that says
        // why. The observed program is process 1 of a pid namespace, so the
        // kernel kills the reader the instant that program exits, and on a
        // busy machine that kill beats the reader's own report: measured on
        // 2026-09-11, with the supervisor and the program pinned to one busy
        // processor, 27 healthy runs in 30 ended with no report. **Nothing is
        // lost when that happens**, because the kill comes from inside the
        // program's own exit, so the program makes no further call. The same
        // measurement, with this check taken out, found a complete record in
        // 19 of 19 such runs.
        //
        // So the completeness of the record is what is asserted below, and
        // that is the fact the reader exists to produce. See
        // `notify.PathRecord.reader_unreported` for why the supervisor cannot
        // say which of the two endings it got.
        if (audit.paths.readers_absent != 0) return 9;

        // The program opened two paths the configuration grants on purpose,
        // so a zero here means the classification put them on the wrong side
        // or the reader read nothing at all.
        if (seen.granted[slot] == 0) return 11;

        var named_the_secret = false;
        var named_a_grant = false;
        var kept: u32 = 0;
        while (kept < seen.kept) : (kept += 1) {
            const name = seen.name(kept);
            if (std.mem.eql(u8, name, named_ungranted)) named_the_secret = true;
            if (std.mem.startsWith(u8, name, named_granted)) named_a_grant = true;
        }
        // **The one fact this whole feature exists for.** A path the
        // configuration granted nothing for is named, and the program named it
        // three times, so the set holds it once.
        if (!named_the_secret) return 12;
        // **The other half, and the one that keeps the record small.** Not one
        // of the opens under a granted tree is named.
        if (named_a_grant) return 13;
        // The three attempts on the one ungranted path, and nothing else: the
        // program is statically linked, so the two granted opens are the only
        // others it makes.
        if (seen.ungranted[slot] != 3) return 14;
        if (seen.kept != 1) return 15;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-path-audit-dynamic")) {
        // **The case the statically linked probe cannot reach.** A dynamic
        // loader runs before the program's own first line and opens dozens of
        // files. Every one of them is under the toolchain tree, which this
        // configuration declares as a mount, so a record split on the grant
        // counts them and keeps the names for the one path nobody granted.
        //
        // Measured on 2026-09-11 on this machine: this program made 3 opens,
        // of which 2 were the loader's and granted, 1 was the path below and
        // ungranted, and the record kept exactly that one name.
        //
        // **Measured again with a real `git status` in place of this program**,
        // and a cap raised to hold every name, because a program this small
        // loads one library and a real one loads several: 115 opens, of which
        // 17 were granted, 98 were relative, and none were ungranted, so the
        // record kept no name at all. The same run split on the workspace kept
        // 9 names, and 8 of them were the loader's own toolchain paths, so the
        // shipped cap of 8 would have held nothing else.
        //
        // The exit status is the answer, because nothing here may print.
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
        // `read_only`: the kernel refuses a directory right over a file. The
        // same reason `baseEscapeConfig` spells out for `/probe`.
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

        // **The program has to have run all the way through its loader.** A
        // dynamic program that could not find its interpreter dies before
        // `main`, and the counts below would then be about a loader failure
        // rather than about a program that ran.
        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }

        const slot = @intFromEnum(sandbox.seccomp.TrapCall.openat);
        const seen = &audit.paths.seen;
        // The reader reached its loop. The way it ended is not asserted, for
        // the reason `spawn-path-audit` above spells out: the pid namespace
        // teardown races the reader's own report and wins on a busy machine,
        // and the record is complete either way. The checks below are what
        // prove the reader did its job.
        if (audit.paths.readers_absent != 0) return 5;

        // **The loader really ran, and its opens are the granted ones.** The
        // program itself opens exactly one path and that path is ungranted, so
        // every granted open here belongs to the dynamic loader. Measured on
        // 2026-09-11 on this machine: two, both under the toolchain tree.
        if (seen.granted[slot] == 0) return 7;

        // **The one fact this split exists for.** The set holds the one path
        // nothing granted, and holds nothing else. A name count above one is
        // the defect coming back: the loader's opens taking the slots.
        if (seen.kept != 1) return 8;
        if (!std.mem.eql(u8, seen.name(0), named_ungranted)) return 9;
        if (seen.name_call[0] != slot) return 10;
        // Nothing was lost to the cap, which is what makes the name count
        // above a whole answer rather than the first eight of a longer list.
        if (seen.ungranted_unnamed[slot] != 0) return 11;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-path-audit-killed")) {
        // **The fail closed half.** The sandboxed program kills the reader
        // that is watching it. The supervisor has no copy of the notification
        // descriptor left, so the kernel answers every held call with ENOSYS
        // from that moment, and the program proves it by reading that errno
        // back. This process then reads the record and finds the loss written
        // down rather than passed over.
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

        // The program itself says whether the kernel answered ENOSYS. Any
        // other status is that check failing and not this one.
        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }
        // The reader reached its loop, so what is counted below is a reader
        // that was killed and not one that never ran.
        if (audit.paths.readers_absent != 0) return 5;
        // **The warning a session gets.** A reader that was killed wrote no
        // report, and the session counts that. **It is not proof of a kill**:
        // the ordinary teardown leaves the same record on a busy machine. What
        // proves the kill here is the program's own exit status above, which
        // says the kernel answered its next held call `ENOSYS`. See
        // `notify.PathRecord.reader_unreported`.
        if (audit.paths.readers_unreported != 1) return 6;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-syscall-audit") or
        std.mem.eql(u8, args[1], "spawn-syscall-audit-off"))
    {
        // **The whole chain, through a real spawn.** A filter with a trap set
        // goes on in the process that runs the program, that process hands the
        // notification descriptor to the supervisor, and the supervisor counts
        // what the kernel tells it. This runs a program that makes a known
        // number of one observed call and none of two others, then reads the
        // counts back.
        //
        // The second name runs the identical program with **no** trap set at
        // all. That run is the control: it says the numbers come from the
        // observation and not from somewhere else, and it says the default
        // costs nothing.
        //
        // The exit status is the answer, because nothing here may print: the
        // audit lives in this process's own memory.
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

        // The program itself has to have run, or the counts below are about
        // nothing. **This is also the deadlock check.** A handover that stopped
        // either process would never reach this line at all.
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
            // Nothing was asked for, so nothing was watched and nothing was
            // counted. A count above zero here would mean the numbers come
            // from somewhere other than the filter.
            if (counts.observed != 0 or counts.unobserved != 0) return 5;
            if (opens != 0 or execs != 0 or dirs != 0 or connects != 0) return 6;
            return 0;
        }

        // The supervisor could not watch the call on a machine that gave it a
        // whole sandbox. Real, and the case the record exists for, so it gets
        // a status of its own.
        if (counts.unobserved != 0) return 7;
        if (counts.observed != 1) return 8;
        // **Exactly one, and this is the number that proves the hard part.**
        // That one `execve` is the sandboxed process's own, the call the
        // handover had to be finished before. A count of zero means it was
        // never held; a count above one means something else ran.
        if (execs != 1) return 9;
        // At least what the program made. The loader opens more on the way
        // in, and that number is a property of this machine.
        if (opens < opens_in_probe) return 10;
        // The program asked for neither, so a count above zero means the
        // histogram is putting numbers under the wrong name.
        if (dirs != 0 or connects != 0) return 11;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-open-fd-set") or
        std.mem.eql(u8, args[1], "spawn-open-fd-set-filtered"))
    {
        // Hold every shape of descriptor a real harness holds, then run this
        // same program through the whole sandbox and let it name the set that
        // reached it. See `spawned-open-fd-set` for what it checks.
        //
        // **The descriptors are opened before `spawn`, and none is marked
        // close-on-exec.** That is the leak the whole pass exists to revoke,
        // and a descriptor the caller had already marked would be revoked by
        // the kernel instead of by anything this project wrote.
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
        // Run this same program through the whole sandbox, and let it read its
        // own capability bounding set. spawned-caps-drop does no setup of its
        // own, so whether it comes back empty is entirely a fact about spawn's
        // own applyLayers.
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
        // Run this same program through the whole sandbox, and let it statx its own
        // descriptor 0. spawned-stdin-devnull does no setup of its own, so the
        // answer it gets is entirely a fact about what spawn's own child put on
        // that descriptor before applyLayers ever ran.
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
        // Run this same program through the whole sandbox with a real pipe
        // named in `Config.stdin_fd`, and let it look at its own descriptor 0.
        // See `spawned-stdin-pipe` above for the five facts it checks.
        var pipe_fds: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&pipe_fds, .{})) != .SUCCESS) return 5;
        const read_fd = pipe_fds[0];
        const write_fd = pipe_fds[1];

        // The whole request, written before the sandbox is built, so nothing
        // here has to read and write at the same time. The token is far below
        // any pipe buffer, so this one write is the whole of it.
        const written = linux.write(write_fd, stdin_pipe_token, stdin_pipe_token.len);
        if (linux.errno(written) != .SUCCESS or written != stdin_pipe_token.len) return 5;
        // Closed now, so the sandboxed program reads end of file after the
        // token. Every other copy of this end is closed by `spawn` itself: see
        // `spawned-stdin-pipe`'s own fourth check.
        _ = linux.close(write_fd);

        // A descriptor on the host root, open across the spawn. This is the
        // leak `closeInheritedFds` exists to revoke, and it is here to prove
        // that naming one descriptor to keep does not keep this one too.
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
        // A sandbox that cannot come up, with a pipe of this process's own
        // named in `Config.stderr_fd`. What this proves is where the reason
        // went: the pipe is copied to descriptor 1, and descriptor 2 is left
        // untouched, so the test can read the whole of each and see that the
        // caller's descriptor got the line and the terminal got nothing.
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
            // A sandbox that came up on a root that is not there would make
            // every check below meaningless, so it is its own answer.
            return 5;
        } else |err| {
            endIfNothingMeasured(err);
            if (err != error.MountTreeFailed) return 5;
        }

        // This process's own copy of the write end, closed so the read below
        // reaches end of file rather than waiting on a writer that is this
        // process. Every other copy is already gone: `spawn` has returned, so
        // both processes it forked have ended.
        _ = linux.close(write_fd);
        var buffer: [512]u8 = undefined;
        const arrived = readToEnd(read_fd, &buffer);
        _ = linux.close(read_fd);

        const wrote = linux.write(std.posix.STDOUT_FILENO, arrived.ptr, arrived.len);
        if (linux.errno(wrote) != .SUCCESS or wrote != arrived.len) return 5;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-setup-fault-closed-stderr")) {
        // A setup failure whose reason cannot be written anywhere: the pipe
        // named in `Config.stderr_fd` has its read end closed before `spawn` is
        // ever called, so the write of the reason answers `EPIPE` and raises
        // `SIGPIPE`, whose default action ends the process that was writing it.
        //
        // **`spawn` must still answer the error, and not a `Term`.** What makes
        // that true is the order inside the `die` family: the record reaches
        // the setup pipe before the text is attempted. Written the other way
        // round, the process dies before the record exists, `spawn` reads end
        // of file with no data, which is exactly how a successful `execve`
        // reports itself, and answers for a program that never ran.
        //
        // **The failure has to be one the middle process meets, and this is
        // why the config asks for five scratch areas.** A failure inside the
        // sandboxed process, such as the mount tree the two operations above
        // use, cannot show this at all: that process is process 1 of a fresh
        // pid namespace, and the kernel discards a signal with a default action
        // for the process 1 of a namespace, so `SIGPIPE` there is ignored and
        // the record is written whatever the order is. Measured on 2026-08-24.
        // The scratch area count is checked in the middle process, before the
        // second fork, and that process is process 1 of nothing.
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
        // The same sandbox that cannot come up, with nothing named in
        // `Config.stderr_fd`. The reason must land on this process's own
        // descriptor 2, which is what every caller of `spawn` got before that
        // field governed a setup failure at all, and this operation writes
        // nothing else there.
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
        // Run this same program through the whole sandbox, with a procfs of
        // the sandbox's own, and let it read what is in there. Both halves
        // need a real `Sandbox.spawn`: the mask is made by `buildRoot`, which
        // only ever runs inside spawn's own child, and a procfs mounted
        // anywhere else would be the host's.
        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, sandbox.namespace.Mount, &.{
            base.mounts,
            &.{.{ .proc = .{} }},
        });
        // A mount with no rule is present and unreachable, so without this
        // every read below is refused by Landlock instead of answering.
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
        // Finding 1 proof. Build a root with one writable directory bound in, run
        // spawned-forge-exit through the whole sandbox, and let it write there
        // before it picks a forged exit code. If spawn ever read that code as a
        // setup failure, it would call removeContentsBestEffort on this same root and
        // the file below would be gone by the time this checks for it.
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
            // The one wrong outcome this whole operation exists to catch: spawn
            // mistook the caller's own forged exit code for a setup failure.
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
        // Finding 2 proof. Run sandbox.spawn on its own thread, so this thread
        // can hand the pid of the process spawn forked back to the caller over
        // standard output while spawn is still blocked waiting for the
        // sandboxed program, the same shape a real caller sees: spawn is
        // synchronous, so there is no other way to learn that pid before the
        // whole call finishes.
        //
        // The three forms differ only in what runs inside the sandbox. The
        // plain one runs a program that writes the heartbeat itself. **The
        // `-forked` one runs a program that forks and lets its own child
        // write it**, so the caller's one signal has to reach a process it
        // never named and cannot see: a tool call that started a build is
        // that shape, and a cancel that left the build running would be a
        // leak the plain form cannot detect. See `spawned-fork-loop-write`.
        // **The `-setsid` one is the same shape again, except the forked
        // child leaves its process group and its session before it starts
        // writing**, which is plan 23's setsid escape: a process that
        // `kill(0, sig)` no longer names and a terminal's own Ctrl-C no
        // longer reaches. See `spawned-setsid-fork-loop-write`.
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

        // spawn fills the handle in right after its first fork, before it does
        // anything that can block for long, so a two second bound is generous,
        // never a wait that could hang the suite if something is badly broken.
        var waited_ns: u64 = 0;
        while (ctx.middle.pid == 0 and waited_ns < 2_000_000_000) : (waited_ns += 1_000_000) {
            _ = linux.nanosleep(&.{ .sec = 0, .nsec = 1_000_000 }, null);
        }
        if (ctx.middle.pid == 0) {
            // **The join first, and the read after it.** A sandbox that never
            // came up publishes no pid, so this branch is the one a machine
            // with no namespace takes, and the `spawn_err` check further down
            // is never reached from here. The join is what makes reading the
            // field safe, and the thread is already finished in this case.
            thread.join();
            if (ctx.spawn_err) |err| endIfNothingMeasured(err);
            std.debug.print("{s}: never learned the middle process\n", .{args[1]});
            return 3;
        }

        var pid_line_buf: [16]u8 = undefined;
        const pid_line = std.fmt.bufPrint(&pid_line_buf, "{d}\n", .{ctx.middle.pid}) catch unreachable;
        _ = linux.write(std.posix.STDOUT_FILENO, pid_line.ptr, pid_line.len);

        thread.join();
        // The caller of `spawn` owns the handle, and this operation is that
        // caller: see `sandbox.Middle`. After the join, never before.
        sandbox.closeMiddle(&ctx.middle);
        if (ctx.spawn_err) |err| {
            endIfNothingMeasured(err);
            std.debug.print("{s}: spawn reported a setup failure: {s}\n", .{ args[1], @errorName(err) });
            return 3;
        }

        return reportChildTerm(ctx.term);
    }

    if (std.mem.eql(u8, args[1], "spawn-signal-group")) {
        // A process group of this operation's own, before anything else runs.
        // The fault this looks for is a sandbox that can still signal its
        // caller's group, and a detection that took the whole test runner down
        // with it would be worse than the fault: this bounds the blast radius
        // to this process and the sandbox it starts.
        if (linux.errno(linux.setpgid(0, 0)) != .SUCCESS) {
            std.debug.print("spawn-signal-group: setpgid failed\n", .{});
            return 3;
        }
        catchSignal(.USR1);

        // The handler has to be live in this process before spawn forks from
        // it, or "no signal arrived" below would be true for the wrong reason.
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

        // The Term is not the answer here and is deliberately dropped. A
        // contained call ends the sandbox's own group, which the process spawn
        // forked belongs to, so the Term is a signal death either way; the
        // only fact that separates the two outcomes is whether this process,
        // outside that group, was reached.
        return if (caller_signal_seen.load(.monotonic)) 1 else 0;
    }

    if (std.mem.eql(u8, args[1], "spawn-group-press")) {
        // A group of this operation's own, standing in for a session's
        // foreground process group, and for the same reason
        // spawn-signal-group takes one: the press below must never reach the
        // test runner.
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
        // outlive the call it names. See `sandbox.Middle`.
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

        // The press. This is what a terminal does with Ctrl-C: it signals the
        // whole foreground process group, by group and never by process.
        if (linux.errno(linux.kill(0, .USR1)) != .SUCCESS) {
            std.debug.print("spawn-group-press: the press itself failed\n", .{});
            ctx.killCall();
            return 3;
        }

        // Let the sandboxed program finish, now that it has had every chance
        // to be signalled. It ran to here, which is the fact this operation is
        // about: the call was not killed by the press.
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
        // The press has to have been delivered somewhere, or every check
        // above passes for the wrong reason.
        if (!caller_signal_seen.load(.monotonic)) {
            std.debug.print("spawn-group-press: the press reached nothing at all\n", .{});
            return 3;
        }

        switch (ctx.term) {
            // spawned-group-press exits 1 when the press reached it, and 0
            // when it did not. Both are its own answer about itself, carried
            // out through its exit status.
            .exited => |code| return if (code <= 1) code else 5,
            else => {
                std.debug.print("spawn-group-press: the call died: {any}\n", .{ctx.term});
                return 5;
            },
        }
    }

    if (std.mem.eql(u8, args[1], "spawn-signal-middle-handled")) {
        // The same cancellation Finding 2 proves works, with one thing added:
        // this process has a SIGTERM handler of its own installed before it
        // ever calls spawn, exactly as `chock run` does. The process spawn
        // forks is a fork of this one, so it kept that handler, and a handler
        // that runs there catches the cancelling signal and refuses to die.
        catchSignal(.TERM);

        // Prove the handler is live in this process first. Without this, a
        // `catchSignal` that quietly did nothing would make the whole
        // operation pass while pinning nothing at all.
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
        // outlive the call it names. See `sandbox.Middle`.
        defer ctx.closeHandle();
        defer thread.join();

        // A non zero pid is how `spawn` says the handle beside it is there to
        // read: see `sandbox.Middle`. Nothing here ever signals the number.
        if (ctx.waitForMiddlePid() == 0) {
            ctx.endIfSandboxRefused();
            std.debug.print("spawn-signal-middle-handled: never learned the middle process\n", .{});
            return 3;
        }

        // Wait for the sandboxed program to really be running, so the signal
        // below cannot land before there is anything to cancel.
        const heartbeat_path = try std.fmt.allocPrintSentinel(arena, "{s}/work/heartbeat.txt", .{root_arg}, 0);
        if (!waitForPath(heartbeat_path)) {
            ctx.endIfSandboxRefused();
            std.debug.print("spawn-signal-middle-handled: the sandboxed program never started\n", .{});
            ctx.killCall();
            return 3;
        }

        // The cancellation `lib/chock-core/tools.zig` makes when a tool call
        // runs past its deadline: SIGTERM to the process spawn forked, never
        // to the sandboxed program, for the reason spawn's own doc comment
        // gives. Through the handle, and by the same call that file makes.
        sandbox.signalMiddle(ctx.middle.fd, .TERM) catch |err| {
            std.debug.print("spawn-signal-middle-handled: could not signal the middle process: {s}\n", .{@errorName(err)});
            ctx.killCall();
            return 3;
        };

        if (!ctx.waitForDone()) {
            // The fault itself. The middle process caught this process's own
            // handler and stayed alive, so the call was never cancelled at
            // all and spawn is still blocked on it.
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

    // personality(READ_IMPLIES_EXEC) makes the kernel add PROT_EXEC to every later
    // mapping on its own, after seccomp has already looked at the prot argument. The
    // filter must refuse this call so that trick cannot defeat the write exclusive
    // execute rule below.
    if (std.mem.eql(u8, args[1], "personality-rwx")) {
        const read_implies_exec: usize = 0x0400000;
        const rc = linux.syscall1(.personality, read_implies_exec);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    // 0xffffffff only reads the current personality and changes nothing. The filter
    // must let this through, or an ordinary read of the current value would break.
    if (std.mem.eql(u8, args[1], "personality-read")) {
        const read_current: usize = 0xffffffff;
        const rc = linux.syscall1(.personality, read_current);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    const prot_read: u32 = 0x1;
    const prot_write: u32 = 0x2;
    const prot_exec: u32 = 0x4;
    const map_private_anon: u32 = 0x02 | 0x20;

    // Zig 0.16's linux.mmap and linux.mprotect take the PROT and MAP flags as packed
    // structs, not plain integers. The seccomp filter reads the same bits off the raw
    // syscall argument, so a bit cast from the plain u32 keeps the two views in sync.
    if (std.mem.eql(u8, args[1], "mmap-wx")) {
        const prot: linux.PROT = @bitCast(prot_write | prot_exec);
        const flags: linux.MAP = @bitCast(map_private_anon);
        const rc = linux.mmap(null, 4096, prot, flags, -1, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "ptrace-relaxed")) {
        // A blocked call under the relaxed filter. **The setting turns off one
        // rule and nothing else**, so this must still die exactly as `ptrace`
        // above does. Without this, a mistake that dropped the whole filter
        // when a project asked for a just in time compiler would pass every
        // other test in this file.
        const rc = linux.syscall4(.ptrace, 0, 0, 0, 0);
        // The filter kills the process, so this line never runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "io-uring-setup-relaxed")) {
        // io_uring under the relaxed filter. It is refused with EPERM there
        // too: the setting names one rule, and this is not that rule.
        var params: linux.io_uring_params = std.mem.zeroes(linux.io_uring_params);
        const rc = linux.io_uring_setup(1, &params);
        return ringRefusal(rc);
    }
    if (std.mem.eql(u8, args[1], "mmap-wx-relaxed")) {
        // The same call `mmap-wx` above makes, under the filter a project that
        // asked for a just in time compiler gets. It must succeed, and the
        // process must still be alive to say so.
        //
        // **This is the whole of what the setting does.** Every other rule of
        // the filter is unchanged, which the test beside this one states by
        // running a blocked call under the same relaxed filter.
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

    // shmat has no prot argument, so the write and execute rule above never sees this
    // request. SHM_EXEC in shmflg is what asks the kernel to attach the segment
    // executable, and the filter must refuse only that flag combination.
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
    // An attach with no SHM_EXEC flag must still work, so the rule above does not
    // refuse an ordinary shared memory attach along with the executable one.
    if (std.mem.eql(u8, args[1], "shmat-plain")) {
        const shmid = createShmSegment() catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        defer removeShmSegment(shmid);
        const rc = linux.syscall3(.shmat, shmid, 0, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    std.debug.print("unknown operation: {s}\n", .{args[1]});
    return 2;
}
