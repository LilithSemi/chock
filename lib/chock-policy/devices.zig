//! The policy action for a device, named by its identity and never by its
//! path. `/dev/ttyUSB0` changes with plug order and after a reboot, so a rule
//! written against it stops being true the next time the device is plugged
//! in. A vendor id, a product id, and where the bus gives one, a serial,
//! survive a reboot and a different port, so those are what a rule is
//! written against instead.
//!
//! This file is pure: no socket, no udev, no hardware. It turns an
//! `Identity` a later task reads off the bus into the action name a policy
//! author writes rules against, the same split `lib/chock-core/mcp.zig`'s
//! `actionInto` makes for an MCP tool call.
//!
//! `lib/chock-policy/defaults.zig` ships no default for `device.*` at all.
//! An action nobody names already answers `ask`, and `ask` is genuinely
//! answerable for a device: it arrives mid-session, when a person is there
//! to be asked. See that file's own comment above `rules` for why a shipped
//! `deny` was tried and rejected.

const std = @import("std");
const testing = std.testing;
const table = @import("table.zig");

/// True when `bytes` can be one label of an action name. A re-export and not
/// a second copy: the rule lives at `chock_policy.table.labelIsUsable`, which
/// `lib/chock-core/mcp.zig`'s `nameIsUsable` also calls through to. See that
/// function's own doc comment for why chock-policy is where the rule had to
/// end up.
pub const labelIsUsable = table.labelIsUsable;

/// The bus a device identity was read off. `usb` covers a USB device read
/// through udev's own vendor and product ids. `tty` covers a serial adapter,
/// which may carry a serial of its own and may not: many USB-to-serial
/// chips share one vendor and product id across every unit a factory made,
/// so the serial is what tells two of them apart when the bus gives one.
pub const Subsystem = enum { usb, tty };

/// The bus identity of one device, read off udev and never off a path.
pub const Identity = struct {
    subsystem: Subsystem,
    /// Lower case hex, no `0x`. `"1d50"`.
    vendor: []const u8,
    /// Lower case hex, no `0x`. `"6018"`.
    product: []const u8,
    /// The bus serial, or empty when the device carries none.
    serial: []const u8,
};

const action_prefix = "device";
const usb_segment = "usb";
const tty_segment = "tty";
const serial_segment = "serial";

/// The `tool` a device action is evaluated under, the same role
/// `chock_core.lsp_driver.policy_tool` plays for a language server. A rule
/// author writes `.tool = "device"` to state a row about every device action
/// at once, and `src/run.zig`'s own seam passes this alongside the action
/// `actionInto` built, so `evaluateChain` sees both.
pub const policy_tool = "device";

/// The longest action name `actionInto` can build. `usb` and a tty with no
/// serial both spell `device.<bus>.<vendor>.<product>`, two labels of
/// `table.max_label_bytes` each. A tty with a serial spells
/// `device.tty.serial.<serial>`, one label. The first shape is longer, so it
/// is the one this bounds against.
pub const max_action_bytes = action_prefix.len + 1 +
    @max(usb_segment.len, tty_segment.len) + 1 +
    table.max_label_bytes + 1 + table.max_label_bytes;

/// The policy action for `id`, written into `buffer`. Null when a field the
/// name needs is not a name `labelIsUsable` accepts, or when the name does
/// not fit.
///
/// ```
/// usb, vendor 1d50, product 6018            ->  device.usb.1d50.6018
/// tty, serial DF62585783282137              ->  device.tty.serial.DF62585783282137
/// tty, vendor 1209, product c0ca, no serial ->  device.tty.1209.c0ca
/// ```
///
/// A tty with a serial is named by the serial alone, because the serial is
/// what makes the device the same one across a reboot when a whole run of
/// chips shares one vendor and product id. `id.vendor` and `id.product` are
/// not read into the name in that case, and need not be names
/// `labelIsUsable` accepts for this call to succeed.
///
/// Allocates nothing, so a caller can build a key inside a loop with a
/// buffer on its stack. `buffer` must hold `max_action_bytes`.
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
    // **/dev/ttyUSB0 is useless as a policy key.** It changes with plug order
    // and after a reboot, so a rule written against it stops being true. The
    // same reason `chock-plan-22-nix-tool` rejected a drv hash.
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
    // Null is a refusal and never a pass: a caller that cannot build a name
    // cannot ask the table. A dot separates segments and a `*` names a class,
    // so either would let a device name rules nobody wrote.
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
    // **The no-serial branch has its own example line and its own segments,
    // so it needs its own test.** A tty and a usb device share the
    // `<vendor>.<product>` shape, but the `tty` segment only comes from this
    // branch, and a copy-paste from the usb branch could silently drop the
    // `labelIsUsable` check on either field without either existing test
    // noticing.
    var buffer: [max_action_bytes]u8 = undefined;

    try testing.expectEqualStrings("device.tty.1209.c0ca", actionInto(&buffer, .{
        .subsystem = .tty,
        .vendor = "1209",
        .product = "c0ca",
        .serial = "",
    }).?);

    // An unusable vendor must still refuse, the same as it does on the usb
    // branch. Skipping this check here would let a dot or a `*` in the
    // vendor split into a segment nobody wrote a rule for.
    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, .{
        .subsystem = .tty,
        .vendor = "12.09",
        .product = "c0ca",
        .serial = "",
    }));

    // Same refusal, on the product this time, so the branch cannot have
    // checked only one of the two fields it reads.
    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, .{
        .subsystem = .tty,
        .vendor = "1209",
        .product = "c0*a",
        .serial = "",
    }));
}
