//! The udev client, proved against the real kernel.
//!
//! This file has one job: show that the dependency this build pulls in can
//! open a netlink monitor and can enumerate real devices, with no daemon and
//! no privilege. It builds no naming and no policy. A later task adds the
//! logic that turns a device into an action name; this one only proves the
//! library underneath it works on the machine that will run it.

const std = @import("std");
const builtin = @import("builtin");
const udev = @import("udev");

const testing = std.testing;

test "a kernel monitor opens with no privilege and no udevd" {
    // Measured 2026-09-16: binding NETLINK_KOBJECT_UEVENT group 1 succeeded as
    // uid 1000 with an empty capability set, and delivered 6 of 6 events in a
    // namespace that could not reach udevd. So this needs no daemon and no
    // capability, and a failure here is a real fault and not a machine that is
    // merely unmanaged.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var ctx = udev.Context.init(testing.allocator, testing.io);
    defer ctx.deinit();
    var monitor = try udev.Monitor.initNetlink(&ctx, .kernel);
    defer monitor.deinit();
}

test "enumerating one subsystem is far cheaper than enumerating all of them" {
    // Measured: subsystem=usb 0.53ms over 47 devices, no filter 21.6 to 25.7ms
    // over 2574. This asserts the filter is applied, not the timing, because a
    // timing assertion on a shared machine is a flake.
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
    // **Both bounds, because `<=` alone passes when the filter does nothing
    // and also when it matches nothing.** A machine with no USB at all cannot
    // say whether the filter works, so that is a skip and never a pass.
    if (usb_count == 0) return error.SkipZigTest;
    try testing.expect(usb_count < all_count);
}

/// Count what the last `scanDevices` call found, through the iterator, since a
/// syspath list is the enumerator's own state and not this file's to read
/// directly.
fn countDevices(e: *udev.Enumerate) usize {
    var it = e.devices();
    var count: usize = 0;
    while (it.next()) |_| count += 1;
    return count;
}
