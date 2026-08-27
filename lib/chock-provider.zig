//! Model adapters and streaming. Chock uses a neutral internal message type,
//! and an adapter converts at each edge.
//!
//!     provider <-- adapter --> chock message <-- adapter --> served API
//!                                   |
//!                              session log
//!
//! The neutral type is not defined here. It lives in `chock-proto`, because
//! `chockd` folds a session's messages into the same log every other event
//! uses, and a message type kept only for the adapters would give the two a
//! chance to drift apart. `message.zig` re-exports it instead of copying it.

pub const failure = @import("chock-provider/failure.zig");
pub const retry = @import("chock-provider/retry.zig");
pub const message = @import("chock-provider/message.zig");
pub const anthropic = @import("chock-provider/anthropic.zig");
pub const openai = @import("chock-provider/openai.zig");
pub const sse = @import("chock-provider/sse.zig");
pub const Client = @import("chock-provider/Client.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
