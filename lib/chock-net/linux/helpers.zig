//! The helpers Chock runs beside a sandbox and the channels they talk over.
//! Palisade forks each helper, sets its user and capability, installs its filter
//! and sends its ready byte. What a helper does with the kernel is here.

const std = @import("std");
const linux = std.os.linux;
const palisade = @import("palisade");

const links = @import("../links.zig");
const netbroker = @import("netbroker.zig");
const routerlink = @import("routerlink.zig");
const router = @import("router.zig");
const devicelink = @import("devicelink.zig");
const nftables = @import("nftables.zig");
const roles = @import("roles.zig");

const Channel = palisade.Sandbox.Channel;
const Helper = palisade.Sandbox.Helper;
const seccomp = palisade.linux.seccomp;

/// The sandboxed program asks for a host and gets a connected descriptor back,
/// so this channel hands a real host socket in.
pub const Broker = struct {
    seam: links.NetBroker,

    pub fn channel(self: *Broker) Channel {
        return .{
            .ptr = self,
            .serve = .{ .call = serveFn, .max_requests = netbroker.max_requests },
            .hands_host_descriptor = true,
        };
    }

    fn serveFn(ptr: *anyopaque, channel_fd: i32) Channel.ServeResult {
        const self: *Broker = @ptrCast(@alignCast(ptr));
        return switch (netbroker.serveOne(channel_fd, self.seam)) {
            .served, .nothing => .more,
            .peer_gone => .done,
        };
    }
};

/// The router runs inside the sandbox's network namespace and answers DNS and
/// relays TCP there. The sandboxed program never holds this channel: the router
/// helper does, and asks the host to resolve and to open on its behalf.
pub const Router = struct {
    seam: links.NetRouter,
    /// The helper's end of Chock's own control socket. Palisade closes its ready
    /// pipe before `run`, so this is how the helper learns the host has gone and
    /// how its counts get back.
    control_fd: i32,
    table: nftables.Session = undefined,
    /// A field and not a local in `prepare`: `policy()` and `host()` hand the
    /// router a pointer to it, and it caches the last reply, so it has to live
    /// as long as the helper does.
    client: routerlink.Client = undefined,
    instance: router.Router = undefined,
    kept: [1]i32 = undefined,

    pub fn channel(self: *Router) Channel {
        return .{
            .ptr = self,
            .serve = .{ .call = serveFn, .max_requests = routerlink.max_requests },
            .hands_host_descriptor = false,
        };
    }

    pub fn helper(self: *Router, index: usize) Helper {
        self.kept = .{self.control_fd};
        return .{
            .ptr = self,
            .prepare = prepareFn,
            .run = runFn,
            .allowed = roles.router_calls,
            .keep_fds = &self.kept,
            .keep_capability = linux.CAP.NET_ADMIN,
            .channel = index,
        };
    }

    fn serveFn(ptr: *anyopaque, channel_fd: i32) Channel.ServeResult {
        const self: *Router = @ptrCast(@alignCast(ptr));
        return switch (routerlink.serveOne(channel_fd, self.seam)) {
            .served, .nothing => .more,
            .peer_gone => .done,
        };
    }

    /// Runs before the filter and before the user changes, which is what this
    /// needs: the table is netlink, and the resolver binds port 53.
    ///
    /// Palisade waits for the ready byte before it starts the program, so the
    /// redirect rules are in place before anything inside can call connect.
    fn prepareFn(ptr: *anyopaque, channel_fd: ?i32, stderr_fd: i32) bool {
        const self: *Router = @ptrCast(@alignCast(ptr));
        const fd = channel_fd orelse return false;

        var table_diag: ?nftables.Diagnostic = null;
        self.table = nftables.Session.open(&table_diag) catch |err| {
            sayNetworkFault(stderr_fd, err);
            return false;
        };
        self.table.install(&table_diag) catch |err| {
            sayNetworkFault(stderr_fd, err);
            return false;
        };

        self.client = .{ .fd = fd, .session = self.table };
        var diag: ?router.Diagnostic = null;
        self.instance.open(
            .{ .policy = self.client.policy(), .host = self.client.host() },
            &diag,
        ) catch return false;
        return true;
    }

    fn sayNetworkFault(stderr_fd: i32, err: anyerror) void {
        if (err == error.KernelModuleMissing) {
            writeStderr(stderr_fd, links.missing_module_notice);
        }
    }

    fn runFn(ptr: *anyopaque, channel_fd: ?i32, stderr_fd: i32) u8 {
        const self: *Router = @ptrCast(@alignCast(ptr));
        _ = .{ channel_fd, stderr_fd };

        var last_counts = self.instance.counts;
        sendCounts(self.control_fd, &self.instance.counts);
        while (!peerHasGone(self.control_fd)) {
            self.instance.step(monotonicMilliseconds(), idle_step_ms, null) catch return 1;
            if (!std.meta.eql(last_counts, self.instance.counts)) {
                last_counts = self.instance.counts;
                sendCounts(self.control_fd, &self.instance.counts);
            }
        }

        var drained: usize = 0;
        while (drained < drain_steps) : (drained += 1) {
            self.instance.step(monotonicMilliseconds(), drain_step_ms, null) catch break;
            if (self.instance.pendingBytes() == 0) break;
        }
        return 0;
    }
};

const idle_step_ms: i32 = 20;
const drain_steps: usize = 16;
const drain_step_ms: i32 = 2;

const CountsRecord = struct {
    magic: u64 = counts_magic,
    counts: router.Counts,
};

const counts_magic: u64 = 0x43_4f_55_4e_54_53_31_00;

/// `MSG.DONTWAIT` beside `MSG.NOSIGNAL` is load bearing: counts are advisory, so
/// a full socket must never block the serve loop.
fn sendCounts(control_fd: i32, counts: *const router.Counts) void {
    const record = CountsRecord{ .counts = counts.* };
    const bytes = std.mem.asBytes(&record);
    _ = linux.sendto(
        control_fd,
        bytes.ptr,
        bytes.len,
        linux.MSG.NOSIGNAL | linux.MSG.DONTWAIT,
        null,
        0,
    );
}

/// Reads the newest record the router sent and says what it did. The host end of
/// the control socket, so this runs in the parent.
pub fn reportRouterCounts(control_fd: i32, stderr_fd: i32) void {
    var newest: ?router.Counts = null;
    while (true) {
        var record: CountsRecord = undefined;
        const bytes = std.mem.asBytes(&record);
        const rc = linux.recvfrom(control_fd, bytes.ptr, bytes.len, linux.MSG.DONTWAIT, null, null);
        if (linux.errno(rc) != .SUCCESS or rc != bytes.len) break;
        if (record.magic != counts_magic) break;
        newest = record.counts;
    }
    const counts = newest orelse {
        writeStderr(stderr_fd, "sandbox: the router said nothing about its work\n");
        return;
    };
    var room: [320]u8 = undefined;
    const said = std.fmt.bufPrint(
        &room,
        "sandbox: router queries {d} answered {d} refused_names {d} refused_types {d} " ++
            "empty {d} allow_failures {d} malformed {d}; accepted {d} linked {d} " ++
            "no_destination {d} refused_destinations {d} no_link {d} no_upstream {d}\n",
        .{
            counts.queries,              counts.answered,
            counts.refused_names,        counts.refused_types,
            counts.empty_answers,        counts.allow_failures,
            counts.malformed_queries,    counts.accepted,
            counts.linked,               counts.without_destination,
            counts.refused_destinations, counts.without_link,
            counts.without_upstream,
        },
    ) catch return;
    writeStderr(stderr_fd, said);
}

/// The host pushes device changes in: nothing inside the sandbox asks for one.
pub const Devices = struct {
    source: links.DeviceSource,
    tree: links.DeviceTree,
    root: []const u8,
    wakeup_fd: i32 = -1,

    pub fn channel(self: *Devices) Channel {
        self.wakeup_fd = self.source.vtable.wakeup(self.source.ptr);
        return .{
            .ptr = self,
            .wakeup = .{ .fd = self.wakeup_fd, .drain = drainFn },
            .hands_host_descriptor = false,
        };
    }

    pub fn helper(self: *Devices, index: usize) Helper {
        return .{
            .ptr = self,
            .prepare = prepareFn,
            .run = runFn,
            .allowed = roles.device_calls,
            .keep_capability = linux.CAP.SYS_ADMIN,
            .channel = index,
        };
    }

    fn drainFn(ptr: *anyopaque, channel_fd: i32) Channel.ServeResult {
        const self: *Devices = @ptrCast(@alignCast(ptr));
        while (self.source.vtable.next(self.source.ptr)) |change| {
            if (sendChange(channel_fd, change)) continue;
            return .done;
        }
        return .more;
    }

    fn prepareFn(ptr: *anyopaque, channel_fd: ?i32, stderr_fd: i32) bool {
        const self: *Devices = @ptrCast(@alignCast(ptr));
        _ = .{ channel_fd, stderr_fd };
        var buffer: [path_capacity]u8 = undefined;
        return bindDeviceTree(&buffer, self.root, self.tree.inside, self.tree.host);
    }

    fn runFn(ptr: *anyopaque, channel_fd: ?i32, stderr_fd: i32) u8 {
        const self: *Devices = @ptrCast(@alignCast(ptr));
        const fd = channel_fd orelse return 1;

        var state = SeamState{ .hidden = self.tree.inside, .stderr_fd = stderr_fd };
        const seam = state.seam();

        while (true) {
            var fds = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
            const ready = linux.ppoll(&fds, fds.len, null, null);
            switch (linux.errno(ready)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return 1,
            }

            if (fds[0].revents & linux.POLL.IN != 0) {
                switch (devicelink.serveOne(fd, seam)) {
                    .placed, .place_failed, .dropped, .drop_failed, .nothing => continue,
                    .peer_gone => return 0,
                }
            }
            if (fds[0].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0) return 0;
        }
    }
};

fn sendChange(fd: i32, change: links.DeviceSource.Change) bool {
    switch (change) {
        .place => |one| {
            devicelink.sendPlace(fd, one.kind, one.source, one.target) catch return false;
            return true;
        },
        .drop => |one| {
            devicelink.sendDrop(fd, one.target) catch return false;
            return true;
        },
    }
}

const kind_file: u8 = 0;

const path_capacity: usize = std.fs.max_path_bytes;

const PlaceError = error{
    UnsupportedKind,
    PathUnusable,
    MkdirFailed,
    MknodFailed,
    MountFailed,
};

fn buildTarget(buffer: []u8, root: []const u8, path: []const u8) ?[:0]u8 {
    if (path.len <= 1 or path[0] != '/' or path[path.len - 1] == '/') return null;

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return null;
    }

    if (root.len + path.len >= buffer.len) return null;
    @memcpy(buffer[0..root.len], root);
    @memcpy(buffer[root.len..][0..path.len], path);
    buffer[root.len + path.len] = 0;
    return buffer[0 .. root.len + path.len :0];
}

fn buildSource(buffer: []u8, hidden: []const u8, source: []const u8) ?[:0]u8 {
    if (source.len == 0) return null;

    var it = std.mem.splitScalar(u8, source, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, "..")) return null;
    }

    const total = hidden.len + 1 + source.len;
    if (total >= buffer.len) return null;
    @memcpy(buffer[0..hidden.len], hidden);
    buffer[hidden.len] = '/';
    @memcpy(buffer[hidden.len + 1 ..][0..source.len], source);
    buffer[total] = 0;
    return buffer[0..total :0];
}

fn makeParents(buffer: []u8, full_len: usize) bool {
    var i: usize = 1;
    while (i < full_len) : (i += 1) {
        if (buffer[i] != '/') continue;
        buffer[i] = 0;
        const rc = linux.mkdirat(linux.AT.FDCWD, @ptrCast(buffer.ptr), 0o755);
        buffer[i] = '/';
        switch (linux.errno(rc)) {
            .SUCCESS, .EXIST => {},
            else => return false,
        }
    }
    return true;
}

fn bindDeviceTree(buffer: []u8, root: []const u8, inside: []const u8, host: []const u8) bool {
    const target = buildTarget(buffer, root, inside) orelse return false;
    if (!makeParents(buffer, target.len)) return false;
    const mkdir_rc = linux.mkdirat(linux.AT.FDCWD, target.ptr, 0o755);
    switch (linux.errno(mkdir_rc)) {
        .SUCCESS, .EXIST => {},
        else => return false,
    }

    var host_buffer: [path_capacity]u8 = undefined;
    const host_z = std.fmt.bufPrintSentinel(&host_buffer, "{s}", .{host}, 0) catch return false;

    const mount_rc = linux.mount(host_z.ptr, target.ptr, null, linux.MS.BIND, 0);
    return linux.errno(mount_rc) == .SUCCESS;
}

fn placeDevice(
    target_buffer: []u8,
    source_buffer: []u8,
    hidden: []const u8,
    kind: u8,
    source: []const u8,
    target: []const u8,
) PlaceError!void {
    if (kind != kind_file) return error.UnsupportedKind;

    const target_z = buildTarget(target_buffer, "", target) orelse return error.PathUnusable;

    if (!makeParents(target_buffer, target_z.len)) return error.MkdirFailed;

    const mknod_rc = linux.mknodat(linux.AT.FDCWD, target_z.ptr, linux.S.IFREG | 0o600, 0);
    if (linux.errno(mknod_rc) != .SUCCESS) return error.MknodFailed;

    const source_z = buildSource(source_buffer, hidden, source) orelse return error.PathUnusable;

    const mount_rc = linux.mount(source_z.ptr, target_z.ptr, null, linux.MS.BIND, 0);
    if (linux.errno(mount_rc) != .SUCCESS) return error.MountFailed;
}

fn dropDevice(buffer: []u8, path: []const u8) PlaceError!void {
    const target = buildTarget(buffer, "", path) orelse return error.PathUnusable;
    const rc = linux.umount2(target.ptr, 0);
    if (linux.errno(rc) != .SUCCESS) return error.MountFailed;
}

fn reportFault(stderr_fd: i32, verb: []const u8, path: []const u8, err: PlaceError) void {
    var line_buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "sandbox: device {s} failed for {s}: {t}\n",
        .{ verb, path, err },
    ) catch return;
    _ = linux.write(stderr_fd, line.ptr, line.len);
}

const SeamState = struct {
    hidden: []const u8,
    stderr_fd: i32,

    fn seam(self: *SeamState) devicelink.DeviceSeam {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = devicelink.DeviceSeam.VTable{ .place = placeFn, .drop = dropFn };

    fn placeFn(ptr: *anyopaque, kind: u8, source: []const u8, target: []const u8) devicelink.DeviceSeam.Result {
        const self: *SeamState = @ptrCast(@alignCast(ptr));
        var target_buffer: [path_capacity]u8 = undefined;
        var source_buffer: [path_capacity]u8 = undefined;
        placeDevice(&target_buffer, &source_buffer, self.hidden, kind, source, target) catch |err| {
            reportFault(self.stderr_fd, "place", target, err);
            return .failed;
        };
        return .done;
    }

    fn dropFn(ptr: *anyopaque, path: []const u8) devicelink.DeviceSeam.Result {
        const self: *SeamState = @ptrCast(@alignCast(ptr));
        var buffer: [path_capacity]u8 = undefined;
        dropDevice(&buffer, path) catch |err| {
            reportFault(self.stderr_fd, "drop", path, err);
            return .failed;
        };
        return .done;
    }
};

fn peerHasGone(fd: i32) bool {
    var watched = [1]linux.pollfd{.{ .fd = fd, .events = 0, .revents = 0 }};
    const rc = linux.poll(&watched, watched.len, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    return watched[0].revents & (linux.POLL.HUP | linux.POLL.ERR | linux.POLL.NVAL) != 0;
}

fn monotonicMilliseconds() i64 {
    var now: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &now)) != .SUCCESS) return 0;
    return @as(i64, now.sec) * std.time.ms_per_s +
        @divTrunc(@as(i64, now.nsec), std.time.ns_per_ms);
}

fn writeStderr(stderr_fd: i32, line: []const u8) void {
    _ = linux.write(stderr_fd, line.ptr, line.len);
}

/// Storage for the channels and helpers a call's links become. It has to outlive
/// the spawn, so the caller holds it: a channel names a pointer into it.
pub const Lowered = struct {
    broker: Broker = undefined,
    router: Router = undefined,
    devices: Devices = undefined,
    channels: [palisade.Sandbox.max_channels]Channel = undefined,
    helpers: [2]Helper = undefined,
    /// The host end of the router's control socket. Chock reads the counts off
    /// it and closes it after the call.
    router_control_fd: i32 = -1,
    owned: [1]palisade.linux.namespace.OwnedDirectory = undefined,
    /// The caller's rules plus the resolver reads, when the call is routed.
    rules: []palisade.Sandbox.Rule = &.{},

    pub const Error = error{ SocketFailed, OutOfMemory };

    /// Fills `config.channels` and `config.helpers` from `set`. The broker is the
    /// only link the sandboxed program holds itself; the other two belong to a
    /// helper, so each of those adds a channel and a helper together.
    pub fn apply(
        self: *Lowered,
        gpa: std.mem.Allocator,
        config: *palisade.Sandbox.Config,
        set: links.Set,
    ) Error!void {
        var channels: usize = 0;
        var helpers: usize = 0;

        if (set.net_broker) |seam| {
            self.broker = .{ .seam = seam };
            self.channels[channels] = self.broker.channel();
            channels += 1;
        }

        if (set.net_router) |seam| {
            // A routed call reads its own resolver files, so it takes /etc for
            // itself, writes them there, and is granted the reads to match.
            config.substitutions = &links.resolver_substitutions;
            self.owned = .{links.owned_etc};
            config.owned_directories = &self.owned;

            const rules = gpa.alloc(
                palisade.Sandbox.Rule,
                config.rules.len + links.resolver_reads.len,
            ) catch return error.OutOfMemory;
            @memcpy(rules[0..config.rules.len], config.rules);
            for (links.resolver_reads, rules[config.rules.len..]) |path, *rule| {
                rule.* = .{
                    .path = path,
                    .access = palisade.linux.landlock.AccessFs.read_only_file,
                };
            }
            self.rules = rules;
            config.rules = rules;

            var pair: [2]i32 = undefined;
            const made = linux.socketpair(
                linux.AF.UNIX,
                linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
                0,
                &pair,
            );
            if (linux.errno(made) != .SUCCESS) return error.SocketFailed;
            self.router_control_fd = pair[0];
            self.router = .{ .seam = seam, .control_fd = pair[1] };
            self.channels[channels] = self.router.channel();
            self.helpers[helpers] = self.router.helper(channels);
            channels += 1;
            helpers += 1;
        }

        if (set.device_source) |source| {
            if (set.device_tree) |tree| {
                self.devices = .{ .source = source, .tree = tree, .root = config.root };
                self.channels[channels] = self.devices.channel();
                self.helpers[helpers] = self.devices.helper(channels);
                channels += 1;
                helpers += 1;
            }
        }

        config.channels = self.channels[0..channels];
        config.helpers = self.helpers[0..helpers];
    }

    /// Says what the router did and drops what it held. Call once, after spawn.
    pub fn finish(self: *Lowered, gpa: std.mem.Allocator, stderr_fd: i32) void {
        if (self.rules.len != 0) {
            gpa.free(self.rules);
            self.rules = &.{};
        }
        if (self.router_control_fd < 0) return;
        reportRouterCounts(self.router_control_fd, stderr_fd);
        _ = linux.close(self.router_control_fd);
        self.router_control_fd = -1;
    }
};

const testing = std.testing;

test "buildTarget joins root and path, and refuses what a device helper must never resolve" {
    var buffer: [64]u8 = undefined;
    const joined = buildTarget(&buffer, "/root", "/dev/tty0").?;
    try testing.expectEqualStrings("/root/dev/tty0", joined);

    try testing.expectEqual(@as(?[:0]u8, null), buildTarget(&buffer, "/root", "dev/tty0"));
    try testing.expectEqual(@as(?[:0]u8, null), buildTarget(&buffer, "/root", "/dev/../etc/shadow"));
    try testing.expectEqual(@as(?[:0]u8, null), buildTarget(&buffer, "/root", "/dev/"));
    try testing.expectEqual(@as(?[:0]u8, null), buildTarget(&buffer, "/root", "/"));
}

test "buildSource joins hidden and source, and refuses a source that escapes the hidden tree" {
    var buffer: [64]u8 = undefined;
    const joined = buildSource(&buffer, "/.hidden", "tty0").?;
    try testing.expectEqualStrings("/.hidden/tty0", joined);

    try testing.expectEqual(@as(?[:0]u8, null), buildSource(&buffer, "/.hidden", ""));
    try testing.expectEqual(@as(?[:0]u8, null), buildSource(&buffer, "/.hidden", "../etc/shadow"));
    try testing.expectEqual(@as(?[:0]u8, null), buildSource(&buffer, "/.hidden", "a//b"));
}

test "a kind this helper does not implement is refused before anything is touched" {
    var target_buffer: [64]u8 = undefined;
    var source_buffer: [64]u8 = undefined;
    try testing.expectError(error.UnsupportedKind, placeDevice(
        &target_buffer,
        &source_buffer,
        "/.hidden",
        kind_file + 7,
        "tty0",
        "/dev/tty0",
    ));
}
