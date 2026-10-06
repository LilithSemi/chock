//! The policy table and evaluation rules.

pub const table = @import("chock-policy/table.zig");
pub const devices = @import("chock-policy/devices.zig");
pub const subagents = @import("chock-policy/subagents.zig");
pub const ratchet = @import("chock-policy/ratchet.zig");
pub const org = @import("chock-policy/org.zig");
pub const access = @import("chock-policy/access.zig");
pub const hardening = @import("chock-policy/hardening.zig");
pub const apply = @import("chock-policy/apply.zig");
pub const limits = @import("chock-policy/limits.zig");
pub const instructions = @import("chock-policy/instructions.zig");
pub const skills = @import("chock-policy/skills.zig");
pub const search = @import("chock-policy/search.zig");
pub const sandbox = @import("chock-policy/sandbox.zig");
pub const secrets = @import("chock-policy/secrets.zig");
pub const nix = @import("chock-policy/nix.zig");
pub const workspace = @import("chock-policy/workspace.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
