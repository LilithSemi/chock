//! The policy table the broker evaluates, plus the four rules that fold over
//! it: a parent over a child, an organisation over a project, an agent's own
//! promise over itself, and a ceiling over a limit. This library imports no
//! other chock library.

pub const table = @import("chock-policy/table.zig");
pub const devices = @import("chock-policy/devices.zig");
pub const subagents = @import("chock-policy/subagents.zig");
pub const ratchet = @import("chock-policy/ratchet.zig");
pub const org = @import("chock-policy/org.zig");
pub const access = @import("chock-policy/access.zig");
pub const hardening = @import("chock-policy/hardening.zig");
pub const apply = @import("chock-policy/apply.zig");
pub const limits = @import("chock-policy/limits.zig");
pub const nix = @import("chock-policy/nix.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
