//! `chock_core.devices` against a real kernel `udev.Monitor`, a real
//! `udev.Enumerate` and real sysfs. No device is plugged in during this run.

const std = @import("std");
const builtin = @import("builtin");
const udev = @import("udev");
const chock_core = @import("chock-core");

const testing = std.testing;

test "drainInto compiles against a real udev.Monitor and drains it with no error" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ctx = udev.Context.init(testing.allocator, testing.io);
    defer ctx.deinit();

    var monitor = udev.Monitor.initNetlink(&ctx, .kernel) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer monitor.deinit();

    var buffered: std.ArrayList(udev.Device) = .empty;
    defer {
        for (buffered.items) |*dev| dev.deinit();
        buffered.deinit(testing.allocator);
    }

    try chock_core.devices.drainInto(&monitor, testing.allocator, &buffered);

    var tracker = chock_core.devices.OverflowTracker{};
    try testing.expect(!tracker.observe(monitor.overflows()));
}

const DenyingSeam = struct {
    fn seam() chock_core.devices.PolicySeam {
        return .{ .ptr = undefined, .vtable = &vtable };
    }
    const vtable = chock_core.devices.PolicySeam.VTable{ .permitted = permittedFn };
    fn permittedFn(_: *anyopaque, _: []const u8) bool {
        return false;
    }
};

test "HostSource compiles against a real udev.Enumerate and a real signal pipe with no error" {
    // The seam denies everything, so this does not depend on what is plugged in.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var source = chock_core.devices.HostSource.init(testing.allocator, testing.io, DenyingSeam.seam());
    defer source.deinit();

    const device_source = source.deviceSource();
    const fd = device_source.vtable.wakeup(device_source.ptr);
    try testing.expect(fd >= 0);

    try testing.expectEqual(@as(?@import("chock-sandbox").Sandbox.DeviceSource.Change, null), device_source.vtable.next(device_source.ptr));
}
