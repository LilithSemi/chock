//! A sandbox for a tool call, behind a driver interface: see `Sandbox.zig`'s own
//! top comment for the shape and for why.

const builtin = @import("builtin");

pub const landlock = @import("chock-sandbox/linux/landlock.zig");
pub const bpf = @import("chock-sandbox/linux/bpf.zig");
pub const seccomp = @import("chock-sandbox/linux/seccomp.zig");
pub const namespace = @import("chock-sandbox/linux/namespace.zig");
pub const notify = @import("chock-sandbox/linux/notify.zig");
pub const net_broker = @import("chock-sandbox/linux/netbroker.zig");
pub const cgroup = @import("chock-sandbox/linux/cgroup.zig");
pub const nftables = @import("chock-sandbox/linux/nftables.zig");
pub const netns = @import("chock-sandbox/linux/netns.zig");
pub const router = @import("chock-sandbox/linux/router.zig");
pub const net_router = @import("chock-sandbox/linux/routerlink.zig");
pub const devicelink = @import("chock-sandbox/linux/devicelink.zig");
pub const after_fork = switch (builtin.os.tag) {
    .macos => @import("chock-sandbox/darwin/afterfork.zig"),
    else => @import("chock-sandbox/linux/afterfork.zig"),
};
pub const Sandbox = @import("chock-sandbox/Sandbox.zig");
pub const spawn = Sandbox.spawn;
pub const Config = Sandbox.Config;

pub const Middle = Sandbox.Middle;
pub const signalMiddle = Sandbox.signalMiddle;
pub const closeMiddle = Sandbox.closeMiddle;
pub const SignalError = Sandbox.SignalError;
pub const NetBroker = Sandbox.NetBroker;
pub const NetRouter = Sandbox.NetRouter;
pub const DeviceSource = Sandbox.DeviceSource;
pub const copyStrings = Sandbox.copyStrings;
pub const runtime_prefix = Sandbox.runtime_prefix;
pub const trust_store_inside = Sandbox.trust_store_inside;
pub const expresses = Sandbox.expresses;

pub const vm_wire = @import("chock-sandbox/vm/wire.zig");
pub const vm_shares = @import("chock-sandbox/vm/shares.zig");
pub const vm_confine = @import("chock-sandbox/vm/confine.zig");
pub const vm_driver = @import("chock-sandbox/vm/driver.zig");
pub const resolvedPath = Sandbox.resolvedPath;
pub const firstGap = Sandbox.firstGap;
pub const LayerGap = Sandbox.LayerGap;

pub const darwin_driver_for_testing = @import("chock-sandbox/darwin/driver.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
