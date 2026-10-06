//! The host half of the microVM driver: one Sandbox.Driver over a stream into a guest.
//! A guest is a layer, not an alternative: this driver builds no boundary of its own and runs the Linux driver inside the guest.
const std = @import("std");

const iface = @import("../Sandbox.zig");
const shares_mod = @import("shares.zig");
const wire = @import("wire.zig");

pub const driver_name = "microvm";

pub const max_refusal_bytes: usize = 256;

/// Written out, not read from `../linux/driver.zig`: importing it here would pull Linux-only signal code into another platform's build.
pub const guarantees: iface.Guarantees = iface.Guarantees.initMany(&.{
    .network_isolated,
    .signal_isolated,
    .ipc_isolated,
    .path_restricted,
    .syscall_restricted,
    .workspace_mounted,
});

/// All five, whatever the host is: a Linux guest has its own kernel, so this closes the Darwin gap.
pub const expresses: iface.Expresses = .{
    .moved_paths = true,
    .scratch_area = true,
    .procfs = true,
    .cgroup_placement = true,
    .device_passthrough = true,
};

/// Calls are serialised: one guest holds one stream, so answering two at once would interleave their requests.
pub const Guest = struct {
    stream: std.Io.File,
    io: std.Io,
    shares: shares_mod.Set,
    fault: ?Fault = null,

    read_buffer: []u8,
    write_buffer: []u8,
    why_buffer: [max_refusal_bytes + std.fs.max_path_bytes]u8 = undefined,
    gone_buffer: [max_refusal_bytes]u8 = undefined,
    /// Copied, never borrowed: a `shares.Fault` names a path in the config, which the caller frees as soon as `spawn` returns.
    share_buffer: [std.fs.max_path_bytes]u8 = undefined,
    lock: std.Io.Mutex = .init,
    /// Read from another thread: a guest resolving a name arrives on Mirage's own control socket, polled while `spawn` blocks here.
    router_lock: std.Io.Mutex = .init,
    net_router: ?iface.NetRouter = null,
    refusal_buffer: [max_refusal_bytes]u8 = undefined,

    pub const Fault = union(enum) {
        share: shares_mod.Fault,
        not_expressible: NotExpressible,
        refused: []const u8,
        gone: []const u8,
    };

    pub const NotExpressible = enum {
        supplied_cgroup,
        device_tree,

        pub fn sentence(self: NotExpressible) []const u8 {
            return switch (self) {
                .supplied_cgroup => "a cgroup the host opened names a directory of the host's, " ++
                    "and a guest places a call in one of its own",
                .device_tree => "a host device node is not in a guest",
            };
        }
    };

    /// Read right after `spawn` returns, on the same thread: calls are serialised, so a later one overwrites this.
    pub fn why(self: *Guest) ?[]const u8 {
        const fault = self.fault orelse return null;
        return switch (fault) {
            .share => |one| std.fmt.bufPrint(
                &self.why_buffer,
                "the guest cannot reach \"{s}\", because {s}",
                .{ one.path(), one.sentence() },
            ) catch one.sentence(),
            .not_expressible => |one| one.sentence(),
            .refused => |said| said,
            .gone => |step| std.fmt.bufPrint(
                &self.why_buffer,
                "the stream to the guest broke while {s}",
                .{step},
            ) catch "the guest is gone",
        };
    }

    pub fn routerNow(self: *Guest) ?iface.NetRouter {
        self.router_lock.lockUncancelable(self.io);
        defer self.router_lock.unlock(self.io);
        return self.net_router;
    }

    fn holdRouter(self: *Guest, one: ?iface.NetRouter) void {
        self.router_lock.lockUncancelable(self.io);
        defer self.router_lock.unlock(self.io);
        self.net_router = one;
    }

    fn keepShareFault(self: *Guest, said: shares_mod.Fault) shares_mod.Fault {
        const path = said.path();
        const kept = @min(path.len, self.share_buffer.len);
        @memcpy(self.share_buffer[0..kept], path[0..kept]);
        const held = self.share_buffer[0..kept];
        return switch (said) {
            .not_offered => .{ .not_offered = held },
            .needs_writing => .{ .needs_writing = held },
            .host_device => .{ .host_device = held },
        };
    }

    pub fn driver(self: *Guest) iface.Driver {
        return .{
            .ptr = self,
            .vtable = &vtable,
            .name = driver_name,
            .guarantees = guarantees,
            .expresses = expresses,
        };
    }

    const vtable: iface.Driver.VTable = .{
        .spawn = spawnThunk,
        .signalMiddle = signalThunk,
        .closeMiddle = closeThunk,
        .joinFreshSessionKeyring = keyringThunk,
        .whyLast = whyThunk,
    };

    fn whyThunk(ptr: *anyopaque) ?[]const u8 {
        const self: *Guest = @ptrCast(@alignCast(ptr));
        return self.why();
    }

    fn spawnThunk(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        config: iface.Config,
        argv: []const []const u8,
        landlock_report: ?*iface.LandlockReport,
        middle: ?*iface.Middle,
    ) iface.SpawnError!std.process.Child.Term {
        const self: *Guest = @ptrCast(@alignCast(ptr));
        return self.spawn(allocator, config, argv, landlock_report, middle);
    }

    /// One write of a constant, because a caller may be inside a signal handler.
    fn signalThunk(ptr: *anyopaque, fd: std.posix.fd_t, sig: std.posix.SIG) iface.SignalError!void {
        _ = ptr;
        if (fd < 0) return error.NoHandle;
        const line = switch (@intFromEnum(sig)) {
            @intFromEnum(std.posix.SIG.KILL) => wire.cancel_kill,
            @intFromEnum(std.posix.SIG.TERM) => wire.cancel_terminate,
            else => return error.NoHandle,
        };
        // May run inside a signal handler, so this is the raw syscall with no allocation.
        const wrote = std.posix.system.write(fd, line.ptr, line.len);
        if (@as(isize, @bitCast(wrote)) < 0) return error.Gone;
    }

    /// Closes nothing: the descriptor is the stream itself, which outlives every call on it.
    fn closeThunk(ptr: *anyopaque, middle: *iface.Middle) void {
        _ = ptr;
        middle.fd = -1;
        @atomicStore(std.posix.pid_t, &middle.pid, 0, .release);
    }

    fn keyringThunk(ptr: *anyopaque, stderr_fd: std.posix.fd_t) iface.KeyringError!void {
        _ = ptr;
        _ = stderr_fd;
        // The guest joins its own keyring inside; a host side join here would not be the point.
        return error.Refused;
    }

    /// Reads any number of output frames, then the answer: a refusal sends no frames, so a fixed count would hang.
    fn readBack(
        self: *Guest,
        arena: std.mem.Allocator,
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
        out_fd: std.posix.fd_t,
        err_fd: std.posix.fd_t,
        frames: *usize,
    ) (wire.ReadError || std.mem.Allocator.Error)!std.json.Parsed(wire.Answer) {
        while (true) {
            const line = try wire.readLine(reader);
            if (wire.frameIn(arena, line)) |frame| {
                frames.* += 1;
                const to = if (frame.err) err_fd else out_fd;
                self.passBytes(reader, to, frame.output) catch return error.Ended;
                continue;
            }
            if (wire.resolveIn(arena, line)) |asked| {
                defer asked.deinit();
                self.answerResolve(arena, writer, asked.value) catch return error.Ended;
                continue;
            }
            return wire.parseLine(wire.Answer, arena, line);
        }
    }

    /// The host resolves, the guest never does, so a guest cannot ask for one host and be handed another.
    fn answerResolve(
        self: *Guest,
        arena: std.mem.Allocator,
        writer: *std.Io.Writer,
        asked: wire.Resolve,
    ) !void {
        const router = self.routerNow() orelse
            return wire.write(writer, wire.Resolved{ .refused = true });

        const want: iface.NetRouter.Family = if (asked.ipv6) .ipv6 else .ipv4;
        switch (router.resolve(asked.resolve, want)) {
            .granted => |address| {
                var room: [wire.max_reaching_text]u8 = undefined;
                const text = wire.writeAddress(&room, address);
                try wire.write(writer, wire.Resolved{ .address = try arena.dupe(u8, text) });
            },
            .refused => try wire.write(writer, wire.Resolved{ .refused = true }),
            .unresolved => try wire.write(writer, wire.Resolved{}),
        }
    }

    fn passBytes(
        self: *Guest,
        reader: *std.Io.Reader,
        fd: std.posix.fd_t,
        count: u64,
    ) !void {
        _ = self;
        var left = count;
        var chunk: [64 * 1024]u8 = undefined;
        while (left > 0) {
            const want: usize = @intCast(@min(left, chunk.len));
            try reader.readSliceAll(chunk[0..want]);
            var sent: usize = 0;
            while (sent < want) {
                const wrote = std.posix.system.write(fd, chunk[sent..].ptr, want - sent);
                const signed: isize = @bitCast(wrote);
                if (signed <= 0) return error.Gone;
                sent += @intCast(signed);
            }
            left -= want;
        }
    }

    pub fn spawn(
        self: *Guest,
        allocator: std.mem.Allocator,
        config: iface.Config,
        argv: []const []const u8,
        landlock_report: ?*iface.LandlockReport,
        middle: ?*iface.Middle,
    ) iface.SpawnError!std.process.Child.Term {
        // Filled before the lock, not after: a call queued behind another must already have a middle.
        // Copied before the middle is filled and closed at the end, so a closed descriptor number is never reused under us.
        const out_fd = dupOne(config.stdout_fd) orelse {
            self.fault = .{ .gone = "copying the caller's own output descriptor" };
            return error.GuestGone;
        };
        defer closeOne(out_fd);
        const err_fd = dupOne(config.stderr_fd) orelse {
            self.fault = .{ .gone = "copying the caller's own error descriptor" };
            return error.GuestGone;
        };
        defer closeOne(err_fd);

        if (middle) |slot| {
            slot.fd = self.stream.handle;
            @atomicStore(std.posix.pid_t, &slot.pid, iface.Middle.elsewhere, .release);
        }

        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);

        self.fault = null;

        self.holdRouter(config.net_router);
        defer self.holdRouter(null);

        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        if (config.containment == .supplied) {
            self.fault = .{ .not_expressible = .supplied_cgroup };
            return error.GuestCannotExpress;
        }
        if (config.device_tree != null) {
            self.fault = .{ .not_expressible = .device_tree };
            return error.GuestCannotExpress;
        }

        var share_fault: ?shares_mod.Fault = null;
        const moved = shares_mod.translate(
            arena,
            config,
            self.shares,
            &share_fault,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NotPlaceable => {
                self.fault = .{ .share = self.keepShareFault(share_fault.?) };
                return error.GuestCannotPlacePath;
            },
        };

        const request = wire.requestFor(arena, moved, argv) catch
            return error.OutOfMemory;
        // requestFor already handled the two checked cases; reaching here with none means a third was added without a check.
        const asked = request orelse {
            self.fault = .{ .not_expressible = .supplied_cgroup };
            return error.GuestCannotExpress;
        };

        var timed = asked;
        timed.now_ns = std.math.cast(i64, std.Io.Timestamp.now(self.io, .real).nanoseconds) orelse 0;

        var writer = self.stream.writerStreaming(self.io, self.write_buffer);
        wire.write(&writer.interface, timed) catch {
            self.fault = .{ .gone = "writing the request" };
            return error.GuestGone;
        };

        var reader = self.stream.readerStreaming(self.io, self.read_buffer);
        var frames: usize = 0;
        const parsed = self.readBack(
            arena,
            &reader.interface,
            &writer.interface,
            out_fd,
            err_fd,
            &frames,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Ended => {
                self.fault = .{ .gone = "reading what the guest sent back: it closed the stream" };
                return error.GuestGone;
            },
            error.Broke => {
                const named = if (reader.err) |one| @errorName(one) else "no reason kept";
                self.fault = .{ .gone = std.fmt.bufPrint(
                    &self.gone_buffer,
                    "reading what the guest sent back: the read failed with {s}",
                    .{named},
                ) catch "reading what the guest sent back: the read itself failed" };
                return error.GuestGone;
            },
            error.TooLong, error.Unreadable => {
                self.fault = .{ .refused = "the guest said something this build cannot read" };
                return error.GuestRefused;
            },
        };
        if (parsed.value.landlock) |said| {
            if (landlock_report) |slot| slot.abi = @intCast(said.abi);
        }

        // Zero frames with the call having ended means a guest built before frames existed, not a silent program.
        if (parsed.value.ended != null and frames == 0) {
            self.fault = .{ .refused = "the guest is an older build than this host: it ran the " ++
                "call and sent nothing back. Rebuild the initrd." };
            return error.GuestRefused;
        }

        const ended = parsed.value.ended orelse {
            // Copied with the caller's own allocator: a Fault pointing into the arena would name freed bytes.
            const said = parsed.value.refusal orelse "the guest gave no reason";
            const kept = @min(said.len, self.refusal_buffer.len);
            @memcpy(self.refusal_buffer[0..kept], said[0..kept]);
            self.fault = .{ .refused = self.refusal_buffer[0..kept] };
            return error.GuestRefused;
        };

        return switch (ended) {
            .exited => |code| .{ .exited = code },
            .signalled => |sig| .{ .signal = @enumFromInt(sig) },
            .stopped => |sig| .{ .stopped = @enumFromInt(sig) },
            .unknown => |code| .{ .unknown = code },
        };
    }
};

fn closeOne(fd: std.posix.fd_t) void {
    _ = std.posix.system.close(fd);
}

/// Null when the kernel refused. Linux answers an unsigned carrying the errno, so both platforms are read as signed first.
fn dupOne(fd: std.posix.fd_t) ?std.posix.fd_t {
    const made = std.posix.system.dup(fd);
    const signed: isize = if (@typeInfo(@TypeOf(made)).int.signedness == .signed)
        @intCast(made)
    else
        @bitCast(made);
    if (signed < 0) return null;
    return @intCast(signed);
}

const testing = std.testing;

test "the driver promises what the driver inside a guest promises, and expresses all five" {
    inline for (@typeInfo(iface.Expresses).@"struct".fields) |field| {
        try testing.expect(@field(expresses, field.name));
    }

    const darwin_driver = @import("../darwin/driver.zig");
    inline for (@typeInfo(iface.Expresses).@"struct".fields) |field| {
        try testing.expect(!@field(darwin_driver.expresses, field.name));
    }

    if (@import("builtin").os.tag != .linux) return;
    const linux_driver = @import("../linux/driver.zig");
    try testing.expectEqual(linux_driver.guarantees, guarantees);
    try testing.expectEqual(linux_driver.expresses, expresses);
}

test "every reason a guest cannot be asked for something has words of its own" {
    inline for (@typeInfo(Guest.NotExpressible).@"enum".fields) |field| {
        const one = @field(Guest.NotExpressible, field.name);
        try testing.expect(one.sentence().len != 0);
    }
}

/// A guest whose stream is never touched: every test below must refuse before reaching it.
fn unreachableGuest(set: shares_mod.Set) Guest {
    return .{
        .stream = .{ .handle = -1, .flags = .{ .nonblocking = false } },
        .io = testing.io,
        .shares = set,
        .read_buffer = &.{},
        .write_buffer = &.{},
    };
}

const one_share = shares_mod.Set{
    .root = "/mnt/shares",
    .shares = &.{
        .{ .name = "store", .host_path = "/nix/store", .writable = false },
        .{ .name = "workspace", .host_path = "/work", .writable = true },
    },
};

const plain = iface.Config{
    .root = "/sandbox",
    .mounts = &.{},
    .rules = &.{},
    .cwd = "/",
    .env = &.{},
};

test "a config a guest cannot be asked for never reaches the wire" {
    var guest = unreachableGuest(one_share);

    var supplied = plain;
    supplied.containment = .{ .supplied = .{ .fd = 7 } };
    try testing.expectError(
        error.GuestCannotExpress,
        guest.spawn(testing.allocator, supplied, &.{"/bin/true"}, null, null),
    );
    try testing.expectEqual(Guest.NotExpressible.supplied_cgroup, guest.fault.?.not_expressible);
}

test "a path no share holds is refused before the wire, and names the path" {
    var guest = unreachableGuest(one_share);

    var reaching = plain;
    reaching.mounts = &.{.{ .bind = .{ .source = "/home/ross/.ssh", .target = "/keys" } }};

    try testing.expectError(
        error.GuestCannotPlacePath,
        guest.spawn(testing.allocator, reaching, &.{"/bin/true"}, null, null),
    );
    try testing.expectEqualStrings("/home/ross/.ssh", guest.fault.?.share.not_offered);
}

test "a mount that writes into a read only share is refused before the wire" {
    var guest = unreachableGuest(one_share);

    var writing = plain;
    writing.mounts = &.{.{ .bind = .{
        .source = "/nix/store/aaa-out",
        .target = "/out",
        .read_only = false,
    } }};

    try testing.expectError(
        error.GuestCannotPlacePath,
        guest.spawn(testing.allocator, writing, &.{"/bin/true"}, null, null),
    );
    try testing.expectEqualStrings("/nix/store/aaa-out", guest.fault.?.share.needs_writing);
}

test "a cancel is one line on the stream, and nothing joins a keyring on a guest's behalf" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    var guest = unreachableGuest(one_share);
    const as_driver = guest.driver();

    try testing.expectError(error.Refused, as_driver.joinFreshSessionKeyring(2));
    try testing.expectError(error.NoHandle, as_driver.signalMiddle(-1, .TERM));

    var pair: [2]std.posix.fd_t = undefined;
    const made = std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &pair);
    if (std.os.linux.errno(made) != .SUCCESS) return error.SkipZigTest;
    const other = std.Io.File{ .handle = pair[1], .flags = .{ .nonblocking = false } };
    defer other.close(testing.io);

    try as_driver.signalMiddle(pair[0], .TERM);
    try as_driver.signalMiddle(pair[0], .KILL);
    try testing.expectError(error.NoHandle, as_driver.signalMiddle(pair[0], .HUP));

    var read_into: [64]u8 = undefined;
    const got = try std.posix.read(pair[1], &read_into);
    try testing.expectEqualStrings(wire.cancel_terminate ++ wire.cancel_kill, read_into[0..got]);

    var middle: iface.Middle = .{ .fd = pair[0], .pid = iface.Middle.elsewhere };
    as_driver.closeMiddle(&middle);
    try testing.expectEqual(@as(std.posix.fd_t, -1), middle.fd);
    try testing.expectEqual(@as(std.posix.pid_t, 0), middle.pid);
    defer std.Io.File.close(.{ .handle = pair[0], .flags = .{ .nonblocking = false } }, testing.io);

    try testing.expectEqualStrings(driver_name, as_driver.name);
}

test "the two output frames reach the two descriptors the caller gave" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    var guest = unreachableGuest(one_share);

    var out_pair: [2]std.posix.fd_t = undefined;
    var err_pair: [2]std.posix.fd_t = undefined;
    for ([_]*[2]std.posix.fd_t{ &out_pair, &err_pair }) |pair| {
        const made = std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, pair);
        if (std.os.linux.errno(made) != .SUCCESS) return error.SkipZigTest;
    }
    defer for ([_]std.posix.fd_t{ out_pair[0], out_pair[1], err_pair[0], err_pair[1] }) |fd| {
        closeOne(fd);
    };

    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(testing.allocator);
    var into = std.Io.Writer.Allocating.fromArrayList(testing.allocator, &framed);
    try wire.write(&into.writer, wire.Output{ .output = 5, .err = false });
    try into.writer.writeAll("hello");
    try wire.write(&into.writer, wire.Output{ .output = 3, .err = true });
    try into.writer.writeAll("bad");

    try wire.write(&into.writer, wire.Answer{ .ended = .{ .exited = 0 } });
    framed = into.toArrayList();

    var reader = std.Io.Reader.fixed(framed.items);
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var frames: usize = 0;
    var nowhere: [64]u8 = undefined;
    var discard = std.Io.Writer.fixed(&nowhere);
    const answer = try guest.readBack(
        arena_state.allocator(),
        &reader,
        &discard,
        out_pair[0],
        err_pair[0],
        &frames,
    );
    defer answer.deinit();
    try testing.expectEqual(@as(usize, 2), frames);

    var said: [64]u8 = undefined;
    try testing.expectEqualStrings("hello", said[0..try std.posix.read(out_pair[1], &said)]);
    try testing.expectEqualStrings("bad", said[0..try std.posix.read(err_pair[1], &said)]);
}

test "a frame naming more than the guest sent is the guest being gone" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    var guest = unreachableGuest(one_share);

    var pair: [2]std.posix.fd_t = undefined;
    const made = std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &pair);
    if (std.os.linux.errno(made) != .SUCCESS) return error.SkipZigTest;
    defer closeOne(pair[0]);
    defer closeOne(pair[1]);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var frames: usize = 0;
    var reader = std.Io.Reader.fixed("{\"output\":8}\nab");
    var nowhere: [64]u8 = undefined;
    var discard = std.Io.Writer.fixed(&nowhere);
    try testing.expectError(
        error.Ended,
        guest.readBack(arena_state.allocator(), &reader, &discard, pair[0], pair[0], &frames),
    );
}

test "a guest that ran the call and sent nothing back is named as an older build" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    var pair: [2]std.posix.fd_t = undefined;
    const made = std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &pair);
    if (std.os.linux.errno(made) != .SUCCESS) return error.SkipZigTest;
    defer closeOne(pair[0]);
    defer closeOne(pair[1]);

    var out_buffer: [256]u8 = undefined;
    const other = std.Io.File{ .handle = pair[1], .flags = .{ .nonblocking = false } };
    var writing = other.writer(testing.io, &out_buffer);
    try wire.write(&writing.interface, wire.Answer{ .ended = .{ .exited = 0 } });

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var guest = Guest{
        .stream = .{ .handle = pair[0], .flags = .{ .nonblocking = false } },
        .io = testing.io,
        .shares = one_share,
        .read_buffer = &read_buffer,
        .write_buffer = &write_buffer,
    };

    try testing.expectError(
        error.GuestRefused,
        guest.spawn(testing.allocator, plain, &.{"/bin/true"}, null, null),
    );
    try testing.expect(std.mem.indexOf(u8, guest.why().?, "Rebuild the initrd") != null);
}
