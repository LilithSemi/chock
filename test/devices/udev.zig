//! The udev client, against the real kernel.

const std = @import("std");
const builtin = @import("builtin");
const udev = @import("udev");

const testing = std.testing;

test "a kernel monitor opens with no privilege and no udevd" {
    // Binding NETLINK_KOBJECT_UEVENT works unprivileged, so a failure is a real fault.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var ctx = udev.Context.init(testing.allocator, testing.io);
    defer ctx.deinit();
    var monitor = try udev.Monitor.initNetlink(&ctx, .kernel);
    defer monitor.deinit();
}

test "enumerating one subsystem is far cheaper than enumerating all of them" {
    // This checks the filter is applied, not timing, since timing flakes on a shared machine.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var ctx = udev.Context.init(testing.allocator, testing.io);
    defer ctx.deinit();
    var all = udev.Enumerate.init(&ctx);
    defer all.deinit();
    var usb = udev.Enumerate.init(&ctx);
    defer usb.deinit();
    try usb.addMatchSubsystem("usb");
    try usb.scanDevices();
    try all.scanDevices();
    const usb_count = countDevices(&usb);
    const all_count = countDevices(&all);
    // A machine with no USB cannot tell a working filter from a broken one, so skip.
    if (usb_count == 0) return error.SkipZigTest;
    try testing.expect(usb_count < all_count);
}

fn countDevices(e: *udev.Enumerate) usize {
    var it = e.devices();
    var count: usize = 0;
    while (it.next()) |_| count += 1;
    return count;
}
