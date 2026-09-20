//! The broker does the privileged work an agent cannot do itself. The agent
//! never gets the privilege: Chock does the operation outside the sandbox after
//! the user approves it, and gives the agent the result.

pub const Diagnostic = @import("chock-broker/diagnostic.zig").Diagnostic;

pub const Broker = @import("chock-broker/Broker.zig");

pub const actions = @import("chock-broker/actions.zig");

pub const integrate = @import("chock-broker/integrate.zig");

/// The shim prevents a mistake. It does not prevent an attack.
pub const git_shim = @import("chock-broker/git_shim.zig");

pub const secrets = @import("chock-broker/secrets.zig");

/// A prompt is untrusted text. The helper prevents a mistake and it does not
/// prevent an attack.
pub const askpass = @import("chock-broker/askpass.zig");

pub const agentproxy = @import("chock-broker/agentproxy.zig");

pub const git_remote = @import("chock-broker/git_remote.zig");

pub const review = @import("chock-broker/review.zig");

pub const network = @import("chock-broker/network.zig");

/// `robots.txt` is honoured for convention parity. It is not a boundary.
pub const fetch = @import("chock-broker/fetch.zig");

pub const socket = @import("chock-broker/socket.zig");

pub const handover = @import("chock-broker/handover.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
