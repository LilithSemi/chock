//! The network a confined call reaches the host through, plus the device link
//! and the guest wire. Palisade confines the call; this is what Chock puts
//! around it.

pub const links = @import("chock-net/links.zig");

pub const NetBroker = links.NetBroker;
pub const NetRouter = links.NetRouter;
pub const DeviceSource = links.DeviceSource;
pub const DeviceTree = links.DeviceTree;
pub const Set = links.Set;
pub const Call = links.Call;

pub const runtime_prefix = links.runtime_prefix;
pub const trust_store_inside = links.trust_store_inside;
pub const cgroup_name_prefix = links.cgroup_name_prefix;
pub const deny_notice = links.deny_notice;
pub const network_modules = links.network_modules;
pub const filter_modules = links.filter_modules;
pub const missing_module_notice = links.missing_module_notice;
pub const resolver_substitutions = links.resolver_substitutions;
pub const owned_etc = links.owned_etc;
pub const resolver_reads = links.resolver_reads;
pub const shapeHash = links.shapeHash;

pub const netns = @import("chock-net/linux/netns.zig");
pub const net_broker = @import("chock-net/linux/netbroker.zig");
pub const nftables = @import("chock-net/linux/nftables.zig");
pub const router = @import("chock-net/linux/router.zig");
pub const net_router = @import("chock-net/linux/routerlink.zig");
pub const devicelink = @import("chock-net/linux/devicelink.zig");
pub const roles = @import("chock-net/linux/roles.zig");

/// What a fork has to put right before it does anything else. Chock forks its
/// own VMM, which palisade does not manage, so these live here.
pub const after_fork = switch (@import("builtin").os.tag) {
    .macos => @import("chock-net/darwin/afterfork.zig"),
    else => @import("chock-net/linux/afterfork.zig"),
};

pub const helpers = @import("chock-net/linux/helpers.zig");
pub const Driver = @import("chock-net/driver.zig").Driver;
pub const clearRootAfterFailure = @import("chock-net/driver.zig").clearRootAfterFailure;

pub const vm_wire = @import("chock-net/vm/wire.zig");
pub const vm_shares = @import("chock-net/vm/shares.zig");
pub const vm_confine = @import("chock-net/vm/confine.zig");
pub const vm_driver = @import("chock-net/vm/driver.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
