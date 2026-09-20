//! The policy action for a device, named by its identity and never by its
//! path. `/dev/ttyUSB0` changes with plug order and after a reboot, so a rule
//! written against it stops being true the next time the device is plugged in.

const std = @import("std");
const testing = std.testing;
const table = @import("table.zig");

pub const labelIsUsable = table.labelIsUsable;

/// Many USB-to-serial chips share one vendor and product id across every unit a
/// factory made, so the serial is what tells two of them apart when the bus
/// gives one.
pub const Subsystem = enum { usb, tty };

pub const Identity = struct {
    subsystem: Subsystem,
    vendor: []const u8,
    product: []const u8,
    serial: []const u8,
};

const action_prefix = "device";
const usb_segment = "usb";
const tty_segment = "tty";
const serial_segment = "serial";

pub const policy_tool = "device";

/// `usb` and a tty with no serial both spell `device.<bus>.<vendor>.<product>`,
/// two labels. A tty with a serial spells one. The first shape is longer.
pub const max_action_bytes = action_prefix.len + 1 +
    @max(usb_segment.len, tty_segment.len) + 1 +
    table.max_label_bytes + 1 + table.max_label_bytes;

/// The policy action for `id`, written into `buffer`. Null when a field the
/// name needs is not a name `labelIsUsable` accepts, or when the name does not
/// fit.
///
/// A tty with a serial is named by the serial alone, so `id.vendor` and
/// `id.product` are not read into the name and need not be usable names.
///
/// Allocates nothing, so a caller can build a key inside a loop.
pub fn actionInto(buffer: []u8, id: Identity) ?[]const u8 {
    switch (id.subsystem) {
        .usb => {
            if (!labelIsUsable(id.vendor) or !labelIsUsable(id.product)) return null;
            return std.fmt.bufPrint(buffer, action_prefix ++ "." ++ usb_segment ++ ".{s}.{s}", .{
                id.vendor,
                id.product,
            }) catch null;
        },
        .tty => {
            if (id.serial.len > 0) {
                if (!labelIsUsable(id.serial)) return null;
                return std.fmt.bufPrint(
                    buffer,
                    action_prefix ++ "." ++ tty_segment ++ "." ++ serial_segment ++ ".{s}",
                    .{id.serial},
                ) catch null;
            }
            if (!labelIsUsable(id.vendor) or !labelIsUsable(id.product)) return null;
            return std.fmt.bufPrint(buffer, action_prefix ++ "." ++ tty_segment ++ ".{s}.{s}", .{
                id.vendor,
                id.product,
            }) catch null;
        },
    }
}

test "a device's action name is its identity and never its path" {
    var buffer: [max_action_bytes]u8 = undefined;

    try testing.expectEqualStrings("device.usb.1d50.6018", actionInto(&buffer, .{
        .subsystem = .usb,
        .vendor = "1d50",
        .product = "6018",
        .serial = "",
    }).?);

    try testing.expectEqualStrings("device.tty.serial.DF62585783282137", actionInto(&buffer, .{
        .subsystem = .tty,
        .vendor = "1209",
        .product = "c0ca",
        .serial = "DF62585783282137",
    }).?);
}

test "bytes that cannot be one label of a rule get no action name" {
    // Null is a refusal and never a pass. A dot separates segments and a `*`
    // names a class, so either would let a device name rules nobody wrote.
    var buffer: [max_action_bytes]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, .{
        .subsystem = .usb,
        .vendor = "1d.50",
        .product = "6018",
        .serial = "",
    }));
    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, .{
        .subsystem = .usb,
        .vendor = "1d50",
        .product = "60*8",
        .serial = "",
    }));
}

test "a tty with no serial is named by its vendor and product" {
    var buffer: [max_action_bytes]u8 = undefined;

    try testing.expectEqualStrings("device.tty.1209.c0ca", actionInto(&buffer, .{
        .subsystem = .tty,
        .vendor = "1209",
        .product = "c0ca",
        .serial = "",
    }).?);

    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, .{
        .subsystem = .tty,
        .vendor = "12.09",
        .product = "c0ca",
        .serial = "",
    }));

    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, .{
        .subsystem = .tty,
        .vendor = "1209",
        .product = "c0*a",
        .serial = "",
    }));
}
