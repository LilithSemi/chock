//! The udev client, against the real kernel. It shows the dependency can open a
//! netlink monitor and enumerate devices with no daemon and no privilege. It
//! builds no naming and no policy.

const std = @import("std");
const builtin = @import("builtin");
const udev = @import("udev");

const testing = std.testing;

test "a kernel monitor opens with no privilege and no udevd" {
    // Binding NETLINK_KOBJECT_UEVENT group 1 works as an unprivileged user with
    // an empty capability set, so a failure here is a real fault and not a
    // machine that has no udevd.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var ctx = udev.Context.init(testing.allocator, testing.io);
    defer ctx.deinit();
    var monitor = try udev.Monitor.initNetlink(&ctx, .kernel);
    defer monitor.deinit();
}

test "enumerating one subsystem is far cheaper than enumerating all of them" {
    // This asserts the filter is applied, not the timing, because a timing
    // assertion on a shared machine is a flake.
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
    // A machine with no USB cannot tell a working filter from one that matches
    // nothing, so that is a skip and never a pass.
    if (usb_count == 0) return error.SkipZigTest;
    try testing.expect(usb_count < all_count);
}

fn countDevices(e: *udev.Enumerate) usize {
    var it = e.devices();
    var count: usize = 0;
    while (it.next()) |_| count += 1;
    return count;
}
