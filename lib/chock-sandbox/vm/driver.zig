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

const linux_driver = @import("../linux/driver.zig");

pub const driver_name = "microvm";

/// The most of a guest's refusal that is kept. Past this it is cut: the words are
/// for a person to read, and a guest that sent a page of them is a guest saying
/// one thing badly.
pub const max_refusal_bytes: usize = 256;

/// What the guest promises, which is what the driver inside it promises. Read
/// from the Linux driver rather than written again: a guarantee added there is
/// one a guest gets, and a second list would drift.
pub const guarantees: iface.Guarantees = linux_driver.guarantees;

/// All five, whatever the host is. **This is the Darwin gap closing**: a Mac has
/// no bind mount, and a Linux guest on a Mac has one, because the guest has a
/// kernel of its own.
pub const expresses: iface.Expresses = linux_driver.expresses;

/// One guest, as a driver. The caller owns the stream and closes it.
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
        /// The stream is gone, so the guest is.
        gone,
    };

    pub const NotExpressible = enum {
        supplied_cgroup,
        device_tree,
        middle_handle,

        pub fn sentence(self: NotExpressible) []const u8 {
            return switch (self) {
                .supplied_cgroup => "a cgroup the host opened names a directory of the host's, " ++
                    "and a guest places a call in one of its own",
                .device_tree => "a host device node is not in a guest",
                .middle_handle => "the process to signal is in the guest, and this driver holds " ++
                    "no handle on it",
            };
        }
    };

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
    };

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

    fn signalThunk(ptr: *anyopaque, fd: std.posix.fd_t, sig: std.posix.SIG) iface.SignalError!void {
        _ = ptr;
        _ = fd;
        _ = sig;
        // Nothing to signal: `spawn` here asked for no handle, so no caller holds
        // one to pass back.
        return error.NoHandle;
    }

    fn closeThunk(ptr: *anyopaque, middle: *iface.Middle) void {
        _ = ptr;
        middle.fd = -1;
    }

    fn keyringThunk(ptr: *anyopaque, stderr_fd: std.posix.fd_t) iface.KeyringError!void {
        _ = ptr;
        _ = stderr_fd;
        // The guest joins its own, inside, as part of running the driver. A host
        // side join would put this process on a keyring, which is not the point.
        return error.Refused;
    }

    pub fn spawn(
        self: *Guest,
        allocator: std.mem.Allocator,
        config: iface.Config,
        argv: []const []const u8,
        landlock_report: ?*iface.LandlockReport,
        middle: ?*iface.Middle,
    ) iface.SpawnError!std.process.Child.Term {
        self.fault = null;

        // **An arena for the whole call.** The rewritten paths and the request's
        // own arrays live exactly as long as the one request that is written from
        // them, and the answer is a value.
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        if (middle != null) {
            self.fault = .{ .not_expressible = .middle_handle };
            return error.Unexpected;
        }
        if (config.containment == .supplied) {
            self.fault = .{ .not_expressible = .supplied_cgroup };
            return error.Unexpected;
        }
        if (config.device_tree != null) {
            self.fault = .{ .not_expressible = .device_tree };
            return error.Unexpected;
        }

        var share_fault: ?shares_mod.Fault = null;
        const moved = shares_mod.translate(
            arena,
            config,
            self.shares,
            &share_fault,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.Unexpected,
            error.NotPlaceable => {
                self.fault = .{ .share = share_fault.? };
                return error.Unexpected;
            },
        };

        const request = wire.requestFor(arena, moved, argv) catch
            return error.Unexpected;
        // `requestFor` answers null for the two things checked above, so reaching
        // here with none means this build grew a third and did not say so.
        const asked = request orelse {
            self.fault = .{ .not_expressible = .supplied_cgroup };
            return error.Unexpected;
        };

        var writer = self.stream.writer(self.io, self.write_buffer);
        wire.write(&writer.interface, asked) catch {
            self.fault = .gone;
            return error.Unexpected;
        };

        var reader = self.stream.reader(self.io, self.read_buffer);
        const parsed = wire.read(wire.Answer, arena, &reader.interface) catch |err| switch (err) {
            error.OutOfMemory => return error.Unexpected,
            error.Ended => {
                self.fault = .gone;
                return error.Unexpected;
            },
            error.TooLong, error.Unreadable => {
                self.fault = .{ .refused = "the guest said something this build cannot read" };
                return error.Unexpected;
            },
        };
        if (parsed.value.landlock) |said| {
            if (landlock_report) |slot| slot.abi = @intCast(said.abi);
        }

        const ended = parsed.value.ended orelse {
            // A guest that could not run the call says why and reports no code.
            // Copied out of the arena with the caller's own allocator: a `Fault`
            // that pointed into the arena would name freed bytes.
            const said = parsed.value.refusal orelse "the guest gave no reason";
            const kept = @min(said.len, self.refusal_buffer.len);
            @memcpy(self.refusal_buffer[0..kept], said[0..kept]);
            self.fault = .{ .refused = self.refusal_buffer[0..kept] };
            return error.Unexpected;
        };

        return switch (ended) {
            .exited => |code| .{ .exited = code },
            .signalled => |sig| .{ .signal = @enumFromInt(sig) },
            .stopped => |sig| .{ .stopped = @enumFromInt(sig) },
            .unknown => |code| .{ .unknown = code },
        };
    }
};

const testing = std.testing;

test "the driver promises what the driver inside a guest promises, and expresses all five" {
    // Read from the Linux driver rather than written again here, so a guarantee
    // added there is one a guest is said to have.
    try testing.expectEqual(linux_driver.guarantees, guarantees);
    inline for (@typeInfo(iface.Expresses).@"struct".fields) |field| {
        try testing.expect(@field(expresses, field.name));
    }

    // And the whole point: a Mac's native driver expresses none of them.
    const darwin_driver = @import("../darwin/driver.zig");
    inline for (@typeInfo(iface.Expresses).@"struct".fields) |field| {
        try testing.expect(!@field(darwin_driver.expresses, field.name));
    }
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
    var wants_handle: iface.Middle = .{};
    try testing.expectError(
        error.Unexpected,
        guest.spawn(testing.allocator, plain, &.{"/bin/true"}, null, &wants_handle),
    );
    try testing.expectEqual(Guest.NotExpressible.middle_handle, guest.fault.?.not_expressible);

    var supplied = plain;
    supplied.containment = .{ .supplied = .{ .fd = 7 } };
    try testing.expectError(
        error.Unexpected,
        guest.spawn(testing.allocator, supplied, &.{"/bin/true"}, null, null),
    );
    try testing.expectEqual(Guest.NotExpressible.supplied_cgroup, guest.fault.?.not_expressible);
}

test "a path no share holds is refused before the wire, and names the path" {
    var guest = unreachableGuest(one_share);

    var reaching = plain;
    reaching.mounts = &.{.{ .bind = .{ .source = "/home/ross/.ssh", .target = "/keys" } }};

    try testing.expectError(
        error.Unexpected,
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
        error.Unexpected,
        guest.spawn(testing.allocator, writing, &.{"/bin/true"}, null, null),
    );
    try testing.expectEqualStrings("/nix/store/aaa-out", guest.fault.?.share.needs_writing);
}

test "nothing here signals into a guest, and nothing joins a keyring on its behalf" {
    var guest = unreachableGuest(one_share);
    const as_driver = guest.driver();

    // A caller that held a handle would be holding one that signals nothing, so
    // the refusal is the honest answer.
    try testing.expectError(error.NoHandle, as_driver.signalMiddle(3, .TERM));
    try testing.expectError(error.Refused, as_driver.joinFreshSessionKeyring(2));

    var middle: iface.Middle = .{ .fd = 5 };
    as_driver.closeMiddle(&middle);
    try testing.expectEqual(@as(std.posix.fd_t, -1), middle.fd);

    try testing.expectEqualStrings(driver_name, as_driver.name);
}
