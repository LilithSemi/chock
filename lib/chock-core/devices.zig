//! The host side of a device passthrough: watch for a USB device or a tty,
//! resolve what it is, ask policy, and say where its node should land inside
//! the sandbox. Nothing here opens the device and nothing here holds a
//! descriptor: `lib/chock-sandbox/linux/devicelink.zig` carries a path, never
//! a descriptor, and this file is what decides that path. See that file's
//! own top comment for why authority moved from a descriptor to a path, and
//! `.superpowers/sdd/task-4b-report.md` for the measurements that forced it.
//!
//! ## Three rules, each measured, each wrong rather than merely missing if
//! ## broken
//!
//! **Branch on `devtype()` before walking up.** `udev.Device.parentWithSubsystem`
//! starts at the PARENT, so calling it unconditionally on a `usb_device`
//! itself skips past the device and answers with its hub's identity instead.
//! Measured: a device that was really `1235:8211` came back `174c:2074`, the
//! upstream hub. Every device behind that hub would then share the hub's
//! policy key. `resolveIdentity` reads `idVendor`, `idProduct` and `serial`
//! off the event device itself when `devtype()` already says `usb_device`,
//! and only otherwise walks up. See its own doc comment.
//!
//! **Drain the monitor before touching sysfs.** A full netlink queue drops
//! the NEWEST datagram, not the oldest, so a drain that pauses to read a
//! sysfs attribute for one event can lose the tail of a burst, and what
//! arrives afterward is a seqnum-contiguous prefix that looks perfectly
//! healthy. `drainInto` does exactly one thing, read every pending event into
//! a buffer, and calls nothing that touches a filesystem. Identity is
//! resolved afterward, over the buffer `drainInto` filled. `Monitor.overflows()`
//! is the one signal that loss happened at all: it counts overflow REPORTS
//! and never a number of events, so `OverflowTracker` reads any change in it
//! as "re-enumerate sysfs", never as a count to reconcile against.
//!
//! **Never re-resolve identity on a remove.** A remove uevent carries
//! `DEVPATH` and no vendor, product, or serial, and by the time it arrives
//! the device's own sysfs directory is already gone. Walking up from a
//! deleted device answers with whatever ancestor is still there, which reads
//! exactly like a real identity and is not one: measured `045b:0209` for a
//! device that was `1209:c0ca`. `Registry` remembers what an arrival placed,
//! keyed by `DEVPATH`, and a remove is answered from that map alone.
//! `process`'s remove branch never calls `resolveIdentity`, and its own
//! signature makes that the only thing it could do: it never receives an
//! allocator or a seam.
//!
//! ## Ownership, stated once
//!
//! `Identity.vendor`, `.product` and `.serial` are duped with the allocator
//! `resolveIdentity` is given: the value the device's own `getSysattr` cache
//! returns lives in that device's arena, and the walk-up branch deinits the
//! ancestor it read them from before returning. `freeIdentity` releases them.
//! `Arrival.source` and `.target` are read straight off the event device's
//! own properties and are not duped: they are valid for as long as the
//! caller keeps that one `Device` alive, the same lifetime `evaluateArrival`
//! itself already needed to read them. `Outcome.drop`'s path IS duped, by
//! `Registry.remember`, because the whole point of remembering it is that
//! the `Device` a remove event carries is not the `Device` an arrival's
//! `Arrival.target` was read from. The caller frees it after sending the
//! `Drop`.
//!
//! ## Who asks policy, and who does not
//!
//! `chock-core` imports no `chock-broker`: the policy table is the broker's
//! own state, moved into a process of its own, the same reason
//! `lib/chock-core/arbiter.zig` is a seam and not a call to
//! `chock_policy.table.Table` directly. `PolicySeam` is this file's version
//! of that same seam. A later wiring task fills it in, most plausibly by
//! routing a device action through the same mid-session ask a tool call
//! already gets, since a device arrives while a person is there to answer
//! for it. This file only names the question it needs answered.

const std = @import("std");
const udev = @import("udev");
const chock_policy = @import("chock-policy");

const policy_devices = chock_policy.devices;

/// Re-exported so a caller of this file need not import `chock-policy`
/// itself just to name the type `resolveIdentity` returns.
pub const Identity = policy_devices.Identity;

// ---------------------------------------------------------------------------
// Rule 1: branch on devtype() before walking up.
// ---------------------------------------------------------------------------

/// Which `chock_policy.devices.Subsystem` `dev`'s own event names, or null
/// when it names neither. Read from the uevent's own `SUBSYSTEM` property,
/// never from the `subsystem` symlink `udev.Device.subsystem()` resolves:
/// that call is the walk-up branch's own business, not this file's naming
/// question.
fn policySubsystem(dev: *const udev.Device) ?policy_devices.Subsystem {
    const sub = dev.getProperty("SUBSYSTEM") orelse return null;
    if (std.mem.eql(u8, sub, "tty")) return .tty;
    if (std.mem.eql(u8, sub, "usb")) return .usb;
    return null;
}

/// Read `idVendor`, `idProduct` and `serial` off `dev` itself and dupe them
/// with `allocator`. Null when either of the two required attributes is
/// absent: an identity missing a vendor or a product cannot name an action,
/// so there is nothing later code could do with it either.
fn identityFromUsbDevice(
    allocator: std.mem.Allocator,
    dev: *udev.Device,
    subsystem: policy_devices.Subsystem,
) !?Identity {
    const vendor = (try dev.getSysattr("idVendor")) orelse return null;
    const product = (try dev.getSysattr("idProduct")) orelse return null;
    const serial = (try dev.getSysattr("serial")) orelse "";

    const owned_vendor = try allocator.dupe(u8, vendor);
    errdefer allocator.free(owned_vendor);
    const owned_product = try allocator.dupe(u8, product);
    errdefer allocator.free(owned_product);
    const owned_serial: []const u8 = if (serial.len > 0) try allocator.dupe(u8, serial) else "";

    return .{
        .subsystem = subsystem,
        .vendor = owned_vendor,
        .product = owned_product,
        .serial = owned_serial,
    };
}

/// The identity of the device `dev`'s event names. Null when `dev` names a
/// subsystem this file does not resolve, or when no `usb_device` can be
/// found for it at all, on the bus or above it.
///
/// **This is rule 1.** When `dev.devtype()` already answers `usb_device`,
/// the attributes are read off `dev` itself. Only otherwise does this call
/// `dev.parentWithSubsystem("usb", "usb_device")`, which starts at the
/// PARENT: calling it on a `usb_device` would skip past the device this
/// event is about and answer with its hub's identity instead, the measured
/// fault this file's own top comment names. A `tty` event, or a `usb`
/// interface event, is never itself a `usb_device`, so both always take the
/// walk-up branch, and it stops at the nearest ancestor that matches, not at
/// whatever is furthest up, so an interface's own parent device answers
/// before its hub ever does.
///
/// The caller owns what comes back: see this file's own top comment,
/// "Ownership, stated once".
pub fn resolveIdentity(allocator: std.mem.Allocator, dev: *udev.Device) !?Identity {
    const subsystem = policySubsystem(dev) orelse return null;

    if (dev.devtype()) |devtype| {
        if (std.mem.eql(u8, devtype, "usb_device")) {
            return identityFromUsbDevice(allocator, dev, subsystem);
        }
    }

    var ancestor = (try dev.parentWithSubsystem("usb", "usb_device")) orelse return null;
    defer ancestor.deinit();
    return identityFromUsbDevice(allocator, &ancestor, subsystem);
}

/// Release what `resolveIdentity` allocated. `id.serial` is freed only when
/// it is non-empty: an empty `serial` is the static literal `""` and was
/// never duped, the same rule `identityFromUsbDevice` used to decide whether
/// to dupe it in the first place.
pub fn freeIdentity(allocator: std.mem.Allocator, id: *const Identity) void {
    allocator.free(id.vendor);
    allocator.free(id.product);
    if (id.serial.len > 0) allocator.free(id.serial);
}

// ---------------------------------------------------------------------------
// Who decides whether a resolved action may reach the sandbox.
// ---------------------------------------------------------------------------

/// Who answers "may `action` reach the sandbox". See this file's own top
/// comment, "Who asks policy, and who does not", for why this is a seam and
/// not a call to `chock_policy.table.Table`.
pub const PolicySeam = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        permitted: *const fn (ptr: *anyopaque, action: []const u8) bool,
    };

    pub fn permitted(self: PolicySeam, action: []const u8) bool {
        return self.vtable.permitted(self.ptr, action);
    }
};

// ---------------------------------------------------------------------------
// A permitted arrival: the path to place, relative to the hidden tree, and
// where it should land.
// ---------------------------------------------------------------------------

/// What a permitted arrival tells the in-sandbox helper, over
/// `lib/chock-sandbox/linux/devicelink.zig`'s own `sendPlace`. Never an
/// absolute host path and never a descriptor: `source` is relative to the
/// hidden tree `Sandbox.Config.device_tree` names, exactly what `sendPlace`
/// already expects.
pub const Arrival = struct {
    /// The action policy was asked about. Borrowed from the caller's own
    /// `action_buffer`.
    action: []const u8,
    /// The node's path relative to the hidden device tree, for example
    /// `bus/usb/001/005`. Borrowed from `dev`'s own properties: see this
    /// file's top comment, "Ownership, stated once".
    source: []const u8,
    /// Where the node should appear inside the sandbox, for example
    /// `/dev/bus/usb/001/005`. Borrowed the same way `source` is.
    target: []const u8,
};

/// Resolve `dev`'s identity, build its action name into `action_buffer`, and
/// ask `seam` whether it may reach the sandbox. Null whenever any step
/// answers no: no devnode to place, no identity, no usable action name, or a
/// seam that refuses. `action_buffer` must hold
/// `chock_policy.devices.max_action_bytes`.
///
/// **Source and target both come from `dev`'s own event**, never from
/// whatever `resolveIdentity` may have walked up to for the vendor and
/// product. A tty child's own node is what has to be placed, even when its
/// identity was read off the usb device above it.
pub fn evaluateArrival(
    allocator: std.mem.Allocator,
    dev: *udev.Device,
    seam: PolicySeam,
    action_buffer: []u8,
) !?Arrival {
    const source = dev.getProperty("DEVNAME") orelse return null;
    const target = dev.devnode() orelse return null;

    var id = (try resolveIdentity(allocator, dev)) orelse return null;
    defer freeIdentity(allocator, &id);

    const action = policy_devices.actionInto(action_buffer, id) orelse return null;
    if (!seam.permitted(action)) return null;

    return .{ .action = action, .source = source, .target = target };
}

// ---------------------------------------------------------------------------
// Rule 2: drain the monitor before touching sysfs, and track overflow.
// ---------------------------------------------------------------------------

/// Read every pending event off `source` into `out`, and do nothing else.
/// **This is rule 2's first half.** `source.receiveDevice()` is the only
/// call this function makes. Resolving an identity, which reads sysfs, is a
/// separate step over the buffer this fills, never interleaved with the
/// drain itself. See this file's own top comment for the measurement that
/// requires the split.
///
/// Generic over `source` and `out` so a caller can drive this with a real
/// `*udev.Monitor` into a `*std.ArrayList(udev.Device)`, and a test can drive
/// it with a fake that proves nothing but `receiveDevice` was ever called.
pub fn drainInto(source: anytype, allocator: std.mem.Allocator, out: anytype) !void {
    while (try source.receiveDevice()) |item| {
        try out.append(allocator, item);
    }
}

/// Turns `Monitor.overflows()` into "re-enumerate sysfs or not". **This is
/// rule 2's second half.** `overflows()` counts overflow REPORTS and never a
/// number of lost events, so this tracker reads any change from what it last
/// saw as loss, poll it after every drain, and never tries to reconcile a
/// count. See `Monitor.overflows`'s own doc comment in udev.zig for the
/// measurement backing that reading.
pub const OverflowTracker = struct {
    last: u64 = 0,

    /// True the first time `overflows` differs from what this tracker last
    /// saw, which means re-enumerate sysfs. False for a repeat of the same
    /// value, which means nothing new was lost since the last drain this
    /// tracker was told about.
    pub fn observe(self: *OverflowTracker, overflows: u64) bool {
        if (overflows == self.last) return false;
        self.last = overflows;
        return true;
    }
};

// ---------------------------------------------------------------------------
// Rule 3: never re-resolve identity on a remove.
// ---------------------------------------------------------------------------

/// `DEVPATH` to what an arrival placed for it. **This is rule 3.** A remove
/// is answered from this map alone: see `process`'s own doc comment for why
/// its remove branch cannot call `resolveIdentity` even by mistake.
pub const Registry = struct {
    map: std.StringHashMapUnmanaged(Injected) = .empty,

    pub const Injected = struct {
        /// Where the node was placed. Owned by the registry: `remember`
        /// dupes it, and `forget` hands ownership to its caller.
        target: []const u8,
    };

    /// Free every remembered `DEVPATH` and target. A `Registry` still
    /// holding entries at the end of a session named a device that was
    /// never removed before the session ended, which is ordinary, not a
    /// fault: nothing here asserts the map is empty first.
    pub fn deinit(self: *Registry, allocator: std.mem.Allocator) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.target);
        }
        self.map.deinit(allocator);
    }

    /// Record that `devpath` now owns a node at `target`. Both are duped:
    /// the `Device` they were read from, in the caller's own arrival
    /// handling, need not outlive this call. A `devpath` already
    /// remembered has its old target replaced and freed, which is the
    /// ordinary case a `change` uevent on an already-placed device gives.
    pub fn remember(self: *Registry, allocator: std.mem.Allocator, devpath: []const u8, target: []const u8) !void {
        const owned_target = try allocator.dupe(u8, target);
        errdefer allocator.free(owned_target);

        const found = try self.map.getOrPut(allocator, devpath);
        if (found.found_existing) {
            allocator.free(found.value_ptr.target);
        } else {
            found.key_ptr.* = allocator.dupe(u8, devpath) catch |err| {
                _ = self.map.remove(devpath);
                return err;
            };
        }
        found.value_ptr.* = .{ .target = owned_target };
    }

    /// The target `devpath` was remembered at, taking it out of the map, or
    /// null when `devpath` was never remembered. **This function's own
    /// signature is the proof of rule 3**: it takes a plain string and
    /// nothing that could resolve one, no allocator for a fresh `Identity`,
    /// no `udev.Device`, no `PolicySeam`. There is nothing here to
    /// re-resolve with even if a future edit tried. Ownership of the
    /// returned slice passes to the caller, who frees it with the same
    /// allocator after sending the `Drop`.
    pub fn forget(self: *Registry, allocator: std.mem.Allocator, devpath: []const u8) ?[]const u8 {
        const entry = self.map.fetchRemove(devpath) orelse return null;
        allocator.free(entry.key);
        return entry.value.target;
    }
};

// ---------------------------------------------------------------------------
// Tying the three rules together over one buffered, already-drained event.
// ---------------------------------------------------------------------------

/// What one buffered event, already read by `drainInto`, produced.
pub const Outcome = union(enum) {
    /// A permitted arrival. Send this over `devicelink.sendPlace`.
    place: Arrival,
    /// An arrival this file could not place: no devnode, no identity, no
    /// usable action name, or a seam that refused. Nothing is sent.
    refused,
    /// A device that was remembered and is now gone. Send this over
    /// `devicelink.sendDrop`, then free it with the allocator `process` was
    /// given: see `Registry.forget`'s own doc comment.
    drop: []const u8,
    /// Neither an add nor a remove this file understands, or a remove for a
    /// `DEVPATH` nobody remembered placing.
    nothing,
};

/// Handle one event out of `drainInto`'s buffer: place a permitted arrival,
/// or drop a device that was remembered and is now gone.
///
/// **The remove branch never calls `resolveIdentity`.** It reads `ACTION`
/// and `DEVPATH`, both plain uevent properties present on a remove the same
/// as on an add, and answers straight out of `registry`. This is rule 3: see
/// this file's own top comment and `Registry.forget`'s.
pub fn process(
    allocator: std.mem.Allocator,
    registry: *Registry,
    seam: PolicySeam,
    dev: *udev.Device,
    action_buffer: []u8,
) !Outcome {
    const uevent_action = dev.getProperty("ACTION") orelse return .nothing;
    const devpath = dev.getProperty("DEVPATH") orelse return .nothing;

    if (std.mem.eql(u8, uevent_action, "remove")) {
        const target = registry.forget(allocator, devpath) orelse return .nothing;
        return .{ .drop = target };
    }

    if (!std.mem.eql(u8, uevent_action, "add")) return .nothing;

    const arrival = (try evaluateArrival(allocator, dev, seam, action_buffer)) orelse return .refused;
    try registry.remember(allocator, devpath, arrival.target);
    return .{ .place = arrival };
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Write one fake sysfs device directory at `rel`, under `tmp`. `rel` may be
/// nested, for example `devices/hub0/dev0`, so a caller builds a whole
/// topology by writing each level in order, parent first: `udev.Device.parent`
/// walks up by directory name and stops at the first ancestor that has its
/// own `uevent` file, so an intermediate directory with none is skipped
/// rather than mistaken for a device.
///
/// `subsystem` names the basename the `subsystem` symlink resolves to, the
/// same as `udev.zig`'s own `testfs.zig` does. That file is test-only
/// infrastructure of the dependency's own and is not exported to a
/// consumer, so this is a small reimplementation rather than a second
/// import of it. Returns the absolute path, allocated with
/// `testing.allocator`. The caller frees it.
fn writeFakeDevice(
    tmp: *testing.TmpDir,
    rel: []const u8,
    subsystem: []const u8,
    uevent: []const u8,
    attrs: []const [2][]const u8,
) ![]u8 {
    const io = testing.io;

    try tmp.dir.createDirPath(io, rel);

    var uevent_buf: [std.fs.max_path_bytes]u8 = undefined;
    const uevent_rel = try std.fmt.bufPrint(&uevent_buf, "{s}/uevent", .{rel});
    try tmp.dir.writeFile(io, .{ .sub_path = uevent_rel, .data = uevent });

    var sym_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sym_rel = try std.fmt.bufPrint(&sym_buf, "{s}/subsystem", .{rel});
    var tgt_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tgt = try std.fmt.bufPrint(&tgt_buf, "../../bus/{s}", .{subsystem});
    try tmp.dir.symLink(io, tgt, sym_rel, .{});

    for (attrs) |attr| {
        var attr_buf: [std.fs.max_path_bytes]u8 = undefined;
        const attr_rel = try std.fmt.bufPrint(&attr_buf, "{s}/{s}", .{ rel, attr[0] });
        try tmp.dir.writeFile(io, .{ .sub_path = attr_rel, .data = attr[1] });
    }

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n = try tmp.dir.realPathFile(io, rel, &rp_buf);
    return testing.allocator.dupe(u8, rp_buf[0..rp_n]);
}

test "resolveIdentity reads the arriving device's own attributes, and an interface below it walks up to it, never past it to the hub" {
    // Measured 2026-09-16: calling `parentWithSubsystem` unconditionally on a
    // `usb_device` itself answered `174c:2074`, the upstream hub, for a
    // device that was really `1235:8211`. This fixture is that exact shape:
    // a hub, a real device below it, and an interface below that, so both of
    // `resolveIdentity`'s branches are exercised against the one topology
    // the bug came from.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = udev.Context.init(testing.allocator, testing.io);
    defer ctx.deinit();

    const hub_path = try writeFakeDevice(
        &tmp,
        "devices/hub0",
        "usb",
        "SUBSYSTEM=usb\nDEVTYPE=usb_device\n",
        &.{ .{ "idVendor", "174c\n" }, .{ "idProduct", "2074\n" } },
    );
    defer testing.allocator.free(hub_path);

    const device_path = try writeFakeDevice(
        &tmp,
        "devices/hub0/dev0",
        "usb",
        "SUBSYSTEM=usb\nDEVTYPE=usb_device\nDEVNAME=bus/usb/001/005\n",
        &.{ .{ "idVendor", "1235\n" }, .{ "idProduct", "8211\n" }, .{ "serial", "ABC123\n" } },
    );
    defer testing.allocator.free(device_path);

    const iface_path = try writeFakeDevice(
        &tmp,
        "devices/hub0/dev0/dev0-if0",
        "usb",
        "SUBSYSTEM=usb\nDEVTYPE=usb_interface\n",
        &.{},
    );
    defer testing.allocator.free(iface_path);

    // The device itself: rule 1's self branch. Must answer the device's own
    // identity, never the hub's.
    var device = try udev.Device.fromSyspath(&ctx, device_path);
    defer device.deinit();
    var id = (try resolveIdentity(testing.allocator, &device)).?;
    defer freeIdentity(testing.allocator, &id);
    try testing.expectEqual(policy_devices.Subsystem.usb, id.subsystem);
    try testing.expectEqualStrings("1235", id.vendor);
    try testing.expectEqualStrings("8211", id.product);
    try testing.expectEqualStrings("ABC123", id.serial);

    // The interface below it: rule 1's walk-up branch. Must stop at dev0,
    // the nearest usb_device ancestor, and never overshoot to hub0.
    var iface = try udev.Device.fromSyspath(&ctx, iface_path);
    defer iface.deinit();
    var iface_id = (try resolveIdentity(testing.allocator, &iface)).?;
    defer freeIdentity(testing.allocator, &iface_id);
    try testing.expectEqualStrings("1235", iface_id.vendor);
    try testing.expectEqualStrings("8211", iface_id.product);
}

test "a tty child names the tty subsystem, and still carries the usb device's own vendor and product" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = udev.Context.init(testing.allocator, testing.io);
    defer ctx.deinit();

    const device_path = try writeFakeDevice(
        &tmp,
        "devices/hub0/dev0",
        "usb",
        "SUBSYSTEM=usb\nDEVTYPE=usb_device\n",
        &.{ .{ "idVendor", "1209" }, .{ "idProduct", "c0ca" } },
    );
    defer testing.allocator.free(device_path);

    const tty_path = try writeFakeDevice(
        &tmp,
        "devices/hub0/dev0/dev0-if0/tty/ttyUSB0",
        "tty",
        "SUBSYSTEM=tty\nDEVNAME=ttyUSB0\n",
        &.{},
    );
    defer testing.allocator.free(tty_path);

    var tty_dev = try udev.Device.fromSyspath(&ctx, tty_path);
    defer tty_dev.deinit();
    var id = (try resolveIdentity(testing.allocator, &tty_dev)).?;
    defer freeIdentity(testing.allocator, &id);

    try testing.expectEqual(policy_devices.Subsystem.tty, id.subsystem);
    try testing.expectEqualStrings("1209", id.vendor);
    try testing.expectEqualStrings("c0ca", id.product);
}

test "resolveIdentity answers null for a subsystem this file does not resolve" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = udev.Context.init(testing.allocator, testing.io);
    defer ctx.deinit();

    const path = try writeFakeDevice(
        &tmp,
        "devices/eth0",
        "net",
        "SUBSYSTEM=net\n",
        &.{},
    );
    defer testing.allocator.free(path);

    var dev = try udev.Device.fromSyspath(&ctx, path);
    defer dev.deinit();
    try testing.expectEqual(@as(?Identity, null), try resolveIdentity(testing.allocator, &dev));
}

const StubSeam = struct {
    answer: bool,
    asked: usize = 0,
    last_action: [policy_devices.max_action_bytes]u8 = undefined,
    last_action_len: usize = 0,

    fn seam(self: *StubSeam) PolicySeam {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = PolicySeam.VTable{ .permitted = permittedFn };

    fn permittedFn(ptr: *anyopaque, action: []const u8) bool {
        const self: *StubSeam = @ptrCast(@alignCast(ptr));
        self.asked += 1;
        @memcpy(self.last_action[0..action.len], action);
        self.last_action_len = action.len;
        return self.answer;
    }

    fn sawAction(self: *const StubSeam) []const u8 {
        return self.last_action[0..self.last_action_len];
    }
};

test "evaluateArrival asks the seam with the built action name, and a refusal produces nothing to place" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = udev.Context.init(testing.allocator, testing.io);
    defer ctx.deinit();

    const path = try writeFakeDevice(
        &tmp,
        "devices/dev0",
        "usb",
        "SUBSYSTEM=usb\nDEVTYPE=usb_device\nDEVNAME=bus/usb/001/005\n",
        &.{ .{ "idVendor", "1d50" }, .{ "idProduct", "6018" } },
    );
    defer testing.allocator.free(path);

    var dev = try udev.Device.fromSyspath(&ctx, path);
    defer dev.deinit();

    var buffer: [policy_devices.max_action_bytes]u8 = undefined;

    var denying = StubSeam{ .answer = false };
    const refused = try evaluateArrival(testing.allocator, &dev, denying.seam(), &buffer);
    try testing.expectEqual(@as(?Arrival, null), refused);
    try testing.expectEqual(@as(usize, 1), denying.asked);
    try testing.expectEqualStrings("device.usb.1d50.6018", denying.sawAction());

    var allowing = StubSeam{ .answer = true };
    const arrival = (try evaluateArrival(testing.allocator, &dev, allowing.seam(), &buffer)).?;
    try testing.expectEqualStrings("device.usb.1d50.6018", arrival.action);
    try testing.expectEqualStrings("bus/usb/001/005", arrival.source);
    try testing.expectEqualStrings("/dev/bus/usb/001/005", arrival.target);
}

/// A fake `Monitor` for `drainInto`: yields a fixed slice, one item per
/// call, then null. `resolves` counts a call the drain must never make, so
/// the test can tell a drain that stayed pure from one that quietly started
/// reading identity mid-loop.
const FakeItem = struct {
    id: u32,
    resolves: *usize,

    fn touchSysfs(self: FakeItem) void {
        self.resolves.* += 1;
    }
};

const FakeSource = struct {
    items: []const FakeItem,
    idx: usize = 0,

    fn receiveDevice(self: *FakeSource) !?FakeItem {
        if (self.idx >= self.items.len) return null;
        defer self.idx += 1;
        return self.items[self.idx];
    }
};

test "drainInto reads every pending event before anything touches sysfs" {
    var resolves: usize = 0;
    var src = FakeSource{ .items = &.{
        .{ .id = 1, .resolves = &resolves },
        .{ .id = 2, .resolves = &resolves },
        .{ .id = 3, .resolves = &resolves },
    } };

    var out: std.ArrayList(FakeItem) = .empty;
    defer out.deinit(testing.allocator);

    try drainInto(&src, testing.allocator, &out);

    // Every event was buffered, and nothing touched sysfs while that
    // happened: `drainInto`'s own body calls only `receiveDevice`.
    try testing.expectEqual(@as(usize, 3), out.items.len);
    try testing.expectEqual(@as(usize, 0), resolves);

    // Only now, over the buffer, does anything read what stands in for
    // sysfs here.
    for (out.items) |item| item.touchSysfs();
    try testing.expectEqual(@as(usize, 3), resolves);
}

test "OverflowTracker reads any change as loss, and a repeat as nothing new" {
    // Measured: 9 seqnum gaps were seen with zero real loss, and 679 of 900
    // events were lost with zero seqnum gaps. `overflows()` is the only
    // signal that holds, and it is a report count, not an event count, so
    // this tracker must never try to diff two counts into "how many".
    var tracker = OverflowTracker{};
    try testing.expect(!tracker.observe(0));
    try testing.expect(!tracker.observe(0));
    try testing.expect(tracker.observe(1));
    try testing.expect(!tracker.observe(1));
    try testing.expect(tracker.observe(4));
}

test "Registry answers a remove from what was remembered, and an unknown DEVPATH is inert" {
    var registry = Registry{};
    defer registry.deinit(testing.allocator);

    // An unrecognised remove: nothing was ever placed for it, so there is
    // nothing to drop.
    try testing.expectEqual(@as(?[]const u8, null), registry.forget(testing.allocator, "/devices/never-seen"));

    try registry.remember(testing.allocator, "/devices/hub0/dev0", "/dev/bus/usb/001/005");

    const target = registry.forget(testing.allocator, "/devices/hub0/dev0").?;
    defer testing.allocator.free(target);
    try testing.expectEqualStrings("/dev/bus/usb/001/005", target);

    // Forgotten once, gone: a second remove for the same path finds nothing,
    // the same as one that was never placed.
    try testing.expectEqual(@as(?[]const u8, null), registry.forget(testing.allocator, "/devices/hub0/dev0"));
}

test "process places a permitted arrival, then drops it by DEVPATH alone once sysfs for it is gone" {
    // The end to end shape of rule 3: place while the device is really
    // there, delete its sysfs directory the way a real unplug does, then
    // answer the remove from `Registry` alone. If `process`'s remove branch
    // ever called `resolveIdentity` here, it would try to read sysfs that
    // this test has already removed and the whole test would error rather
    // than pass.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = udev.Context.init(testing.allocator, testing.io);
    defer ctx.deinit();

    const devpath = "/devices/hub0/dev0";

    const device_path = try writeFakeDevice(
        &tmp,
        "devices/hub0/dev0",
        "usb",
        "ACTION=add\nDEVPATH=" ++ devpath ++ "\nSUBSYSTEM=usb\nDEVTYPE=usb_device\nDEVNAME=bus/usb/001/005\n",
        &.{ .{ "idVendor", "1d50" }, .{ "idProduct", "6018" } },
    );
    defer testing.allocator.free(device_path);

    var registry = Registry{};
    defer registry.deinit(testing.allocator);
    var seam = StubSeam{ .answer = true };
    var buffer: [policy_devices.max_action_bytes]u8 = undefined;

    var arrive_dev = try udev.Device.fromSyspath(&ctx, device_path);
    defer arrive_dev.deinit();

    const placed = try process(testing.allocator, &registry, seam.seam(), &arrive_dev, &buffer);
    switch (placed) {
        .place => |arrival| {
            try testing.expectEqualStrings("bus/usb/001/005", arrival.source);
            try testing.expectEqualStrings("/dev/bus/usb/001/005", arrival.target);
        },
        else => try testing.expect(false),
    }

    // Delete the fixture entirely: a remove uevent arrives after the device
    // is already physically gone, and this proves the remove path needs
    // nothing left to read.
    try tmp.dir.deleteTree(testing.io, "devices/hub0");

    // A remove uevent, built straight from properties the way a real one
    // arrives over netlink: NUL-separated "KEY=VALUE" tokens, no syspath
    // needed, since `Device.fromProps` never reads one.
    const remove_props = "ACTION=remove\x00DEVPATH=" ++ devpath ++ "\x00";
    var remove_dev = try udev.Device.fromProps(&ctx, devpath, .{ .data = remove_props });
    defer remove_dev.deinit();

    const dropped = try process(testing.allocator, &registry, seam.seam(), &remove_dev, &buffer);
    switch (dropped) {
        .drop => |target| {
            defer testing.allocator.free(target);
            try testing.expectEqualStrings("/dev/bus/usb/001/005", target);
        },
        else => try testing.expect(false),
    }

    // The seam was asked exactly once, for the arrival: a remove never asks
    // policy at all, which is consistent with never resolving an identity
    // for one either.
    try testing.expectEqual(@as(usize, 1), seam.asked);
}
