//! The Agent Client Protocol, from the agent's side.

pub const jsonrpc = @import("chock-acp/jsonrpc.zig");
pub const common = @import("chock-acp/common.zig");
pub const v1 = @import("chock-acp/v1.zig");
pub const v2 = @import("chock-acp/v2.zig");
pub const update = @import("chock-acp/update.zig");

pub const Version = common.Version;
pub const negotiate = common.negotiate;

test {
    @import("std").testing.refAllDecls(@This());
}
