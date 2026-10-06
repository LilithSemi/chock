//! The host side of device passthrough: watch for a USB device or a tty,
//! resolve what it is, ask policy, and say where its node should land
//! inside the sandbox.

const std = @import("std");
const udev = @import("udev");
const chock_policy = @import("chock-policy");
const chock_sandbox = @import("chock-sandbox");

const linux = std.os.linux;

const policy_devices = chock_policy.devices;

pub const Identity = policy_devices.Identity;

fn policySubsystem(dev: *const udev.Device) ?policy_devices.Subsystem {
    const sub = dev.getProperty("SUBSYSTEM") orelse return null;
    if (std.mem.eql(u8, sub, "tty")) return .tty;
    if (std.mem.eql(u8, sub, "usb")) return .usb;
    return null;
}

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

pub fn freeIdentity(allocator: std.mem.Allocator, id: *const Identity) void {
    allocator.free(id.vendor);
    allocator.free(id.product);
    if (id.serial.len > 0) allocator.free(id.serial);
}

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

pub const Arrival = struct {
    action: []const u8,
    source: []const u8,
    target: []const u8,
};

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

pub fn drainInto(source: anytype, allocator: std.mem.Allocator, out: anytype) !void {
    while (try source.receiveDevice()) |item| {
        try out.append(allocator, item);
    }
}

pub const OverflowTracker = struct {
    last: u64 = 0,

    pub fn observe(self: *OverflowTracker, overflows: u64) bool {
        if (overflows == self.last) return false;
        self.last = overflows;
        return true;
    }
};

pub const Registry = struct {
    map: std.StringHashMapUnmanaged(Injected) = .empty,

    pub const Injected = struct {
        target: []const u8,
    };

    pub fn deinit(self: *Registry, allocator: std.mem.Allocator) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.target);
        }
        self.map.deinit(allocator);
    }

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

    pub fn forget(self: *Registry, allocator: std.mem.Allocator, devpath: []const u8) ?[]const u8 {
        const entry = self.map.fetchRemove(devpath) orelse return null;
        allocator.free(entry.key);
        return entry.value.target;
    }
};

pub const Outcome = union(enum) {
    place: Arrival,
    refused,
    drop: []const u8,
    nothing,
};

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

pub const file_name = "chock.zon";

pub const max_file_bytes = 1 << 20;

pub const max_devices = 8;

pub const Settings = struct {
    action: []const u8,
};

const WireDevice = struct {
    action: []const u8 = "",
};

pub const ParseError = error{
    OutOfMemory,
    InvalidDevices,
};

pub const LoadError = ParseError || error{
    DevicesFileTooLarge,
    ReadFailed,
};

pub const Diagnostic = union(enum) {
    file_not_zon: std.zon.parse.Diagnostics,
    block_not_valid: std.zon.parse.Diagnostics,
    not_a_struct_literal,
    too_many_devices: usize,
    empty_action,
    action_too_long,
    duplicate_action,
    file_too_large: usize,
    read_failed: anyerror,

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .file_not_zon, .block_not_valid => |*zon_diag| zon_diag.deinit(gpa),
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .file_not_zon => |*zon_diag| try writer.print(
                "{s} is not valid:\n{f}",
                .{ file_name, zon_diag },
            ),
            .block_not_valid => |*zon_diag| try writer.print(
                "{s}: the devices block is not valid:\n{f}",
                .{ file_name, zon_diag },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{file_name},
            ),
            .too_many_devices => |count| try writer.print(
                "{s}: the devices block names {d} devices, and this build allows {d}",
                .{ file_name, count, max_devices },
            ),
            .empty_action => try writer.print(
                "{s}: a devices entry names no action",
                .{file_name},
            ),
            .action_too_long => try writer.print(
                "{s}: a devices entry's action is longer than any real device's ever is",
                .{file_name},
            ),
            .duplicate_action => try writer.print(
                "{s}: the devices block names the same action twice",
                .{file_name},
            ),
            .file_too_large => |limit| try writer.print(
                "{s}: the file is larger than {d} bytes, so it was not read",
                .{ file_name, limit },
            ),
            .read_failed => |err| try writer.print(
                "{s}: the file could not be read: {t}",
                .{ file_name, err },
            ),
        }
    }
};

fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!?[]const Settings {
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    var ast_owned = true;
    defer if (ast_owned) ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
    var zoir_owned = true;
    defer if (zoir_owned) zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        if (note(diag, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidDevices;
    }

    const node = try findBlockNode(zoir, diag) orelse return null;

    var zon_diag: std.zon.parse.Diagnostics = .{};
    ast_owned = false;
    zoir_owned = false;
    var zon_diag_owned = true;
    defer if (zon_diag_owned) zon_diag.deinit(gpa);

    const wire = std.zon.parse.fromZoirNodeAlloc(
        []const WireDevice,
        gpa,
        ast,
        zoir,
        node,
        &zon_diag,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            if (note(diag, .{ .block_not_valid = zon_diag })) zon_diag_owned = false;
            return error.InvalidDevices;
        },
    };
    defer std.zon.parse.free(gpa, wire);

    if (wire.len == 0) return null;
    if (wire.len > max_devices) {
        _ = note(diag, .{ .too_many_devices = wire.len });
        return error.InvalidDevices;
    }

    for (wire, 0..) |one, index| {
        if (one.action.len == 0) {
            _ = note(diag, .empty_action);
            return error.InvalidDevices;
        }
        if (one.action.len > policy_devices.max_action_bytes) {
            _ = note(diag, .action_too_long);
            return error.InvalidDevices;
        }
        for (wire[index + 1 ..]) |other| {
            if (!std.mem.eql(u8, one.action, other.action)) continue;
            _ = note(diag, .duplicate_action);
            return error.InvalidDevices;
        }
    }

    const out = try gpa.alloc(Settings, wire.len);
    var made: usize = 0;
    errdefer {
        for (out[0..made]) |one| gpa.free(one.action);
        gpa.free(out);
    }
    for (wire, out) |one, *slot| {
        slot.* = .{ .action = try gpa.dupe(u8, one.action) };
        made += 1;
    }
    return out;
}

pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) LoadError!?[]const Settings {
    const path = try std.fs.path.join(gpa, &.{ project_root, file_name });
    defer gpa.free(path);

    const source = std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(max_file_bytes),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileNotFound, error.NotDir => return null,
        error.StreamTooLong => {
            _ = note(diag, .{ .file_too_large = max_file_bytes });
            return error.DevicesFileTooLarge;
        },
        else => {
            _ = note(diag, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, diag);
}

fn findBlockNode(zoir: std.zig.Zoir, diag: ?*?Diagnostic) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), "devices")) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidDevices;
        },
    }
}

fn freeSettings(gpa: std.mem.Allocator, settings: []const Settings) void {
    for (settings) |one| gpa.free(one.action);
    gpa.free(settings);
}

test "a project that names no device has no settings, and no block is the same answer" {
    const gpa = testing.allocator;

    try testing.expect(try parse(gpa, ".{}", null) == null);
    try testing.expect(try parse(gpa, ".{ .subagents = .{ .max_width = 2 } }", null) == null);
    try testing.expect(try parse(gpa, ".{ .devices = .{} }", null) == null);
}

test "the action comes from the file exactly as written, and never from a resolved identity" {
    const gpa = testing.allocator;
    const settings = (try parse(
        gpa,
        \\.{
        \\    .devices = .{
        \\        .{ .action = "device.usb.1d50.6018" },
        \\        .{ .action = "device.tty.serial.DF62585783282137" },
        \\    },
        \\}
    ,
        null,
    )).?;
    defer freeSettings(gpa, settings);

    try testing.expectEqual(@as(usize, 2), settings.len);
    try testing.expectEqualStrings("device.usb.1d50.6018", settings[0].action);
    try testing.expectEqualStrings("device.tty.serial.DF62585783282137", settings[1].action);
}

test "an entry with no action, two entries naming the same action, and too many entries all refuse" {
    const gpa = testing.allocator;

    try testing.expectError(error.InvalidDevices, parse(gpa, ".{ .devices = .{ .{} } }", null));

    try testing.expectError(error.InvalidDevices, parse(
        gpa,
        \\.{ .devices = .{
        \\    .{ .action = "device.usb.1d50.6018" },
        \\    .{ .action = "device.usb.1d50.6018" },
        \\} }
    ,
        null,
    ));

    var too_many: std.ArrayList(u8) = .empty;
    defer too_many.deinit(gpa);
    try too_many.appendSlice(gpa, ".{ .devices = .{ ");
    for (0..max_devices + 1) |i| {
        const entry = try std.fmt.allocPrint(gpa, ".{{ .action = \"device.usb.1d50.{d:0>4}\" }},", .{i});
        defer gpa.free(entry);
        try too_many.appendSlice(gpa, entry);
    }
    try too_many.appendSlice(gpa, "} }");
    const source = try gpa.dupeZ(u8, too_many.items);
    defer gpa.free(source);
    try testing.expectError(error.InvalidDevices, parse(gpa, source, null));
}

test "a diagnostic names which entry was wrong, and owns nothing when the file was fine" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    try testing.expectError(error.InvalidDevices, parse(gpa, ".{ .devices = .{ .{} } }", &diag));
    try testing.expectEqual(Diagnostic.empty_action, diag.?);
}

pub const HostSource = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    seam: PolicySeam,
    mutex: std.Io.Mutex,
    queue: std.ArrayList(chock_sandbox.Sandbox.DeviceSource.Change),
    index: usize,
    signal: [2]i32,

    pub fn init(gpa: std.mem.Allocator, io: std.Io, seam: PolicySeam) HostSource {
        return .{
            .gpa = gpa,
            .io = io,
            .seam = seam,
            .mutex = .init,
            .queue = .empty,
            .index = 0,
            .signal = .{ -1, -1 },
        };
    }

    pub fn deviceSource(self: *HostSource) chock_sandbox.Sandbox.DeviceSource {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn deinit(self: *HostSource) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.freeQueueLocked();
        self.queue.deinit(self.gpa);
        for (self.signal) |fd| {
            if (fd >= 0) _ = linux.close(fd);
        }
        self.signal = .{ -1, -1 };
    }

    fn freeQueueLocked(self: *HostSource) void {
        for (self.queue.items) |change| switch (change) {
            .place => |p| {
                self.gpa.free(p.source);
                self.gpa.free(p.target);
            },
            .drop => |d| self.gpa.free(d.target),
        };
        self.queue.clearRetainingCapacity();
    }

    const vtable = chock_sandbox.Sandbox.DeviceSource.VTable{
        .wakeup = wakeupFn,
        .next = nextFn,
    };

    fn wakeupFn(ptr: *anyopaque) i32 {
        const self: *HostSource = @ptrCast(@alignCast(ptr));

        if (self.signal[0] < 0) {
            var pipe: [2]i32 = undefined;
            if (linux.errno(linux.pipe2(&pipe, .{ .NONBLOCK = true, .CLOEXEC = true })) != .SUCCESS) return -1;
            self.signal = pipe;
        }

        self.mutex.lockUncancelable(self.io);
        self.freeQueueLocked();
        self.index = 0;
        self.mutex.unlock(self.io);

        self.scan();

        self.mutex.lockUncancelable(self.io);
        const has_work = self.queue.items.len != 0;
        self.mutex.unlock(self.io);
        if (has_work) {
            const byte: [1]u8 = .{'x'};
            _ = linux.write(self.signal[1], &byte, 1);
        }
        return self.signal[0];
    }

    fn scan(self: *HostSource) void {
        var ctx = udev.Context.init(self.gpa, self.io);
        defer ctx.deinit();

        var en = udev.Enumerate.init(&ctx);
        defer en.deinit();
        en.addMatchSubsystem("usb") catch return;
        en.addMatchSubsystem("tty") catch return;
        en.scanDevices() catch return;

        var buffer: [policy_devices.max_action_bytes]u8 = undefined;
        var it = en.devices();
        while (it.next()) |syspath| {
            var dev = udev.Device.fromSyspath(&ctx, syspath) catch continue;
            defer dev.deinit();

            const arrival = (evaluateArrival(self.gpa, &dev, self.seam, &buffer) catch continue) orelse continue;
            const source = self.gpa.dupe(u8, arrival.source) catch continue;
            const target = self.gpa.dupe(u8, arrival.target) catch {
                self.gpa.free(source);
                continue;
            };
            const change: chock_sandbox.Sandbox.DeviceSource.Change = .{
                .place = .{ .kind = 0, .source = source, .target = target },
            };
            self.mutex.lockUncancelable(self.io);
            self.queue.append(self.gpa, change) catch {
                self.mutex.unlock(self.io);
                self.gpa.free(source);
                self.gpa.free(target);
                continue;
            };
            self.mutex.unlock(self.io);
        }
    }

    fn nextFn(ptr: *anyopaque) ?chock_sandbox.Sandbox.DeviceSource.Change {
        const self: *HostSource = @ptrCast(@alignCast(ptr));
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.index >= self.queue.items.len) {
            var discard: [8]u8 = undefined;
            _ = linux.read(self.signal[0], &discard, discard.len);
            return null;
        }
        defer self.index += 1;
        return self.queue.items[self.index];
    }
};

const testing = std.testing;

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

    var device = try udev.Device.fromSyspath(&ctx, device_path);
    defer device.deinit();
    var id = (try resolveIdentity(testing.allocator, &device)).?;
    defer freeIdentity(testing.allocator, &id);
    try testing.expectEqual(policy_devices.Subsystem.usb, id.subsystem);
    try testing.expectEqualStrings("1235", id.vendor);
    try testing.expectEqualStrings("8211", id.product);
    try testing.expectEqualStrings("ABC123", id.serial);

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

    try testing.expectEqual(@as(usize, 3), out.items.len);
    try testing.expectEqual(@as(usize, 0), resolves);

    for (out.items) |item| item.touchSysfs();
    try testing.expectEqual(@as(usize, 3), resolves);
}

test "OverflowTracker reads any change as loss, and a repeat as nothing new" {
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

    try testing.expectEqual(@as(?[]const u8, null), registry.forget(testing.allocator, "/devices/never-seen"));

    try registry.remember(testing.allocator, "/devices/hub0/dev0", "/dev/bus/usb/001/005");

    const target = registry.forget(testing.allocator, "/devices/hub0/dev0").?;
    defer testing.allocator.free(target);
    try testing.expectEqualStrings("/dev/bus/usb/001/005", target);

    try testing.expectEqual(@as(?[]const u8, null), registry.forget(testing.allocator, "/devices/hub0/dev0"));
}

test "process places a permitted arrival, then drops it by DEVPATH alone once sysfs for it is gone" {
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

    try tmp.dir.deleteTree(testing.io, "devices/hub0");

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

    try testing.expectEqual(@as(usize, 1), seam.asked);
}
