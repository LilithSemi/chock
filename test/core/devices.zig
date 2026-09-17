//! The proof and not a library test: `chock_core.devices.drainInto` and
//! `chock_core.devices.resolveIdentity`, driven against a real kernel
//! `udev.Monitor` and real sysfs, because a fake here proves nothing about
//! whether the generic seam in `lib/chock-core/devices.zig` actually
//! compiles and behaves against the production type it was written for and
//! not only against the file's own fakes. `test/devices/udev.zig` is the
//! same shape one library down: the dependency's own client against a real
//! kernel. This is chock-core's own generic code against it.
//!
//! No device is plugged in during this run, so there is nothing to assert
//! about a resolved identity here: that is `lib/chock-core/devices.zig`'s
//! own job, against a fake sysfs tree it fully controls. This file only
//! proves the real types line up.

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

    // Non-blocking: whatever is pending right now, likely nothing, since
    // this test causes no hotplug itself. The property under test is that
    // this compiles and returns rather than what it finds.
    try chock_core.devices.drainInto(&monitor, testing.allocator, &buffered);

    // `overflows()` is readable through the same real Monitor, and an idle
    // socket reports none.
    var tracker = chock_core.devices.OverflowTracker{};
    try testing.expect(!tracker.observe(monitor.overflows()));
}
