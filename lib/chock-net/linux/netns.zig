//! The identity Chock gives the sandbox network palisade builds: the device
//! name, the addresses on it, and the prefixes. Palisade takes these as
//! parameters, so the values live here and the mechanism lives there.

const palisade = @import("palisade");

pub const Params = palisade.linux.netns.Params;
pub const Step = palisade.linux.netns.Step;
pub const Diagnostic = palisade.linux.netns.Diagnostic;
pub const Error = palisade.linux.netns.Error;
pub const Session = palisade.linux.netns.Session;
pub const validate = palisade.linux.netns.validate;
pub const kernel_module = palisade.linux.netns.kernel_module;
pub const link_kind = palisade.linux.netns.link_kind;

pub const device_name = "chock0";

pub const address4: [4]u8 = .{ 10, 99, 0, 1 };
pub const prefix4: u8 = 24;

pub const address6: [16]u8 = .{ 0xfd, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
pub const prefix6: u8 = 64;

pub const params: Params = .{
    .device_name = device_name,
    .address4 = address4,
    .prefix4 = prefix4,
    .address6 = address6,
    .prefix6 = prefix6,
};

comptime {
    validate(params) catch @compileError(
        "sandbox: the network parameters this project gives palisade are not valid",
    );
}
