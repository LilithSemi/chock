//! The host half of the microVM driver: one `Sandbox.Driver` over a stream into
//! a guest.
//!
//! **A guest is a layer and not an alternative.** This driver builds no boundary
//! of its own. It rewrites a `Config`'s host paths to where the guest sees them,
//! sends the geometry, and the guest runs `lib/chock-sandbox/linux/driver.zig` on
//! it. So `guarantees` here is the Linux driver's set, because that is the code
//! that will run, and `expresses` is all five whatever the host is.
//!
//! ## The stream is one, and the guest opened it
//!
//! `chock guest` dials the host once when the guest comes up. A caller holds that
//! stream for the life of the session, so a tool call costs no connection. One
//! request and one answer a call, in order, because there is one guest and one
//! loop in it.
//!
//! ## What this refuses, and never quietly narrows
//!
//! * A path no share holds, or a mount that writes into a read only share. See
//!   `shares.zig`: answering either would put a failure inside a tool call that
//!   nobody could trace back to here.
//! * A supplied cgroup, because the descriptor names a directory of the host's.
//! * A device tree, because a host device node is not in a guest.
//! * A `Middle`, because the process to signal is in the guest and this driver
//!   holds no handle on it. A caller that asked for one is told so rather than
//!   handed a handle that signals nothing.

const std = @import("std");

const iface = @import("../Sandbox.zig");
const shares_mod = @import("shares.zig");
const wire = @import("wire.zig");

pub const driver_name = "microvm";

/// The most of a guest's refusal that is kept. Past this it is cut: the words are
/// for a person to read, and a guest that sent a page of them is a guest saying
/// one thing badly.
pub const max_refusal_bytes: usize = 256;

/// What the guest promises, which is what the driver inside it promises.
///
/// **Written out and not read from `../linux/driver.zig`.** Importing that module
/// here pulls its signal code into a build for another platform, where
/// `std.posix.SIG` is the C one and not the Linux one, and four of its own lines
/// stop compiling. The test at the bottom pins both lists to that driver's own, on
/// the platform where they can be compared.
pub const guarantees: iface.Guarantees = iface.Guarantees.initMany(&.{
    .network_isolated,
    .signal_isolated,
    .ipc_isolated,
    .path_restricted,
    .syscall_restricted,
    .workspace_mounted,
});

/// All five, whatever the host is. **This is the Darwin gap closing**: a Mac has
/// no bind mount, and a Linux guest on a Mac has one, because the guest has a
/// kernel of its own.
pub const expresses: iface.Expresses = .{
    .moved_paths = true,
    .scratch_area = true,
    .procfs = true,
    .cgroup_placement = true,
    .device_passthrough = true,
};

/// One guest, as a driver. The caller owns the stream and closes it.
///
/// **Calls are serialised.** One guest holds one stream and `chock guest` answers
/// one request at a time, so two tool calls writing at once would interleave two
/// requests into one line. A background task therefore waits for a foreground call
/// here where it would have run beside it under the native driver. That is a real
/// difference and not a detail: a guest that answered several at once would need a
/// stream each, which `Client.channel` can give and this does not yet ask for.
pub const Guest = struct {
    /// The stream `chock guest` opened. Read and written in order, one request
    /// and one answer a call.
    stream: std.Io.File,
    io: std.Io,
    /// Every directory the host offered this guest, and where they appear in it.
    shares: shares_mod.Set,
    /// Filled in with the last refusal, for a caller that wants to say more than
    /// the error name. Borrows the config's own strings.
    fault: ?Fault = null,

    read_buffer: []u8,
    write_buffer: []u8,
    /// Where `why` writes. Its own buffer and not the refusal's: a share fault
    /// names a path and the guest's own words are already in that one.
    why_buffer: [max_refusal_bytes + std.fs.max_path_bytes]u8 = undefined,
    /// Where the words of a broken stream are kept, which `why` then reads.
    gone_buffer: [max_refusal_bytes]u8 = undefined,
    /// Where the path of a share fault is copied.
    ///
    /// **Copied and never borrowed.** A `shares.Fault` names a path out of the
    /// config, and a caller frees that config as soon as `spawn` returns: the
    /// fault then named freed memory, and the message a person read was the
    /// allocator's own fill pattern where the path should have been.
    share_buffer: [std.fs.max_path_bytes]u8 = undefined,
    /// Held for the whole of one call. See this type's own doc comment.
    lock: std.Io.Mutex = .init,
    /// How the call running now may reach the network, or null between calls.
    ///
    /// **Read from another thread.** A guest reaching for a name arrives on
    /// Mirage's own control socket, which is not this stream, so whoever polls
    /// that answers it while `spawn` is blocked here. Calls are serialised, so
    /// there is one call to answer for and never a choice of which.
    router_lock: std.Io.Mutex = .init,
    net_router: ?iface.NetRouter = null,
    /// What a guest's refusal is copied into. **A buffer and not an allocation**:
    /// a `Fault` that pointed into the arena of the call would name freed bytes,
    /// and one that owned memory would need a `deinit` a driver has no place for.
    refusal_buffer: [max_refusal_bytes]u8 = undefined,

    pub const Fault = union(enum) {
        /// A host path could not be placed in the guest.
        share: shares_mod.Fault,
        /// The config holds something no guest can be asked for.
        not_expressible: NotExpressible,
        /// The guest answered a refusal. It points into the guest's own
        /// `refusal_buffer`, so it is good until the next call and no longer.
        refused: []const u8,
        /// The stream is gone, so the guest is. It says at which step, because
        /// the four are four different faults.
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

    /// Why the last call refused, in words. Null when the last one ran.
    ///
    /// **Read right after `spawn` came back and on the same thread.** Calls are
    /// serialised, so a later one overwrites this.
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

    /// How the call running now may reach the network. Null between calls, which
    /// is a refusal: nothing is running to reach on behalf of.
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

    /// The same fault, naming a path this holds rather than the config's.
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

    /// Ask the guest to end the call it is running. `fd` is the descriptor
    /// `spawn` put in the middle, which is this driver's own copy of the stream.
    ///
    /// **One write of a constant**, because a caller may be inside a signal
    /// handler. The guest is not reading the stream while it runs a call, so the
    /// bytes wait in the socket until its watcher polls.
    fn signalThunk(ptr: *anyopaque, fd: std.posix.fd_t, sig: std.posix.SIG) iface.SignalError!void {
        _ = ptr;
        if (fd < 0) return error.NoHandle;
        const line = switch (@intFromEnum(sig)) {
            @intFromEnum(std.posix.SIG.KILL) => wire.cancel_kill,
            @intFromEnum(std.posix.SIG.TERM) => wire.cancel_terminate,
            // The tool path sends those two and nothing else. A third would need
            // a constant of its own rather than a line built here.
            else => return error.NoHandle,
        };
        // The platform's own call, because a caller may be in a signal handler
        // and the negative return is the whole of the error handling needed. On
        // Linux the result carries the errno, so both are read as a signed one.
        const wrote = std.posix.system.write(fd, line.ptr, line.len);
        if (@as(isize, @bitCast(wrote)) < 0) return error.Gone;
    }

    /// **Closes nothing.** The descriptor in the middle is the stream itself,
    /// which outlives every call on it. Clearing the two fields is what says the
    /// call is over, and a cancel that reads the slot after this reaches nobody.
    fn closeThunk(ptr: *anyopaque, middle: *iface.Middle) void {
        _ = ptr;
        middle.fd = -1;
        @atomicStore(std.posix.pid_t, &middle.pid, 0, .release);
    }

    fn keyringThunk(ptr: *anyopaque, stderr_fd: std.posix.fd_t) iface.KeyringError!void {
        _ = ptr;
        _ = stderr_fd;
        // The guest joins its own, inside, as part of running the driver. A host
        // side join would put this process on a keyring, which is not the point.
        return error.Refused;
    }

    /// Read what the guest sends back: any number of output frames, then the
    /// answer. Each frame's bytes go to the descriptor the caller gave, in
    /// chunks, which a caller drains while this runs.
    ///
    /// **The answer is whatever line is not a frame.** A refusal sends no frames
    /// at all, because the call never ran, so a fixed count would hang on one.
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

    /// Resolve a name for the guest's own router, through the seam the call was
    /// given. **The host resolves and the guest never does**, so a guest cannot
    /// ask for one host and be handed another.
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
        // **Filled before the lock and not after it.** A caller waits a bounded
        // time for a middle and gives up when none arrives, so a call queued
        // behind another must already have one. The cost is that a cancel while
        // two are queued reaches the one that is running: there is one guest and
        // one stream, which is the same reason calls are serialised at all.
        // **Copied before the middle is filled and closed at the end.** A caller
        // closes its own end of the pipe as soon as the middle says a call began,
        // and writing to a number that was closed reaches whatever reopened it.
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

        // What answers a guest reaching out while this call runs.
        self.holdRouter(config.net_router);
        defer self.holdRouter(null);

        // **An arena for the whole call.** The rewritten paths and the request's
        // own arrays live exactly as long as the one request that is written from
        // them, and the answer is a value.
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
        // `requestFor` answers null for the two things checked above, so reaching
        // here with none means this build grew a third and did not say so.
        const asked = request orelse {
            self.fault = .{ .not_expressible = .supplied_cgroup };
            return error.GuestCannotExpress;
        };

        // **Streaming and never positional.** A stream is a socket, a socket is
        // never seekable, and the positional path only falls back for `ESPIPE`:
        // any other errno from the probe becomes a read that failed, which the
        // caller then reads as a guest that is gone.
        // The host's clock, because the guest has none. See `wire.Request.now_ns`.
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

        // A guest that ran a call and sent no output at all is one built before
        // the frames existed. Saying so beats an empty answer that reads as a
        // program which printed nothing.
        if (parsed.value.ended != null and frames == 0) {
            self.fault = .{ .refused = "the guest is an older build than this host: it ran the " ++
                "call and sent nothing back. Rebuild the initrd." };
            return error.GuestRefused;
        }

        const ended = parsed.value.ended orelse {
            // A guest that could not run the call says why and reports no code.
            // Copied out of the arena with the caller's own allocator: a `Fault`
            // that pointed into the arena would name freed bytes.
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

/// Close one descriptor, whichever platform this is.
fn closeOne(fd: std.posix.fd_t) void {
    _ = std.posix.system.close(fd);
}

/// `dup`, whichever platform this is. Null when the kernel refused. Linux answers
/// a `usize` carrying the errno and the C layer a signed one, so both are read as
/// a signed value before the sign is looked at.
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

    // And the whole point: a Mac's native driver expresses none of them.
    const darwin_driver = @import("../darwin/driver.zig");
    inline for (@typeInfo(iface.Expresses).@"struct".fields) |field| {
        try testing.expect(!@field(darwin_driver.expresses, field.name));
    }

    // **The two lists above are pinned here and nowhere else.** Only a Linux build
    // can compare them, so only a Linux build does: a guarantee added to that
    // driver and forgotten here fails this, and another platform is not where that
    // would be caught anyway.
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

/// A guest whose stream is never touched. Every test below refuses before it
/// would be, which is the point: a config a guest cannot be asked for must not
/// reach the wire at all.
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

    // Each of these would otherwise be written to a stream whose handle is -1,
    // so a test that got past the check would fail on the write instead.
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
    // No handle is no cancel, and a signal with no constant of its own is too.
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

    // Closing a middle leaves the stream open: it is the stream.
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

    // What the guest writes: a frame a descriptor, in that order.
    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(testing.allocator);
    var into = std.Io.Writer.Allocating.fromArrayList(testing.allocator, &framed);
    try wire.write(&into.writer, wire.Output{ .output = 5, .err = false });
    try into.writer.writeAll("hello");
    try wire.write(&into.writer, wire.Output{ .output = 3, .err = true });
    try into.writer.writeAll("bad");

    // An answer after the frames, because that is what ends the read.
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

    // Eight promised and two sent: a short read here must not be taken as an
    // answer, because the bytes after it would be read as one.
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

    // What a guest built before the frames existed answers: a term and no output.
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
