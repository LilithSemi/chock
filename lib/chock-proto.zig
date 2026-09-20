//! The event types and the session log. The log is the truth for a session, and
//! the state of a session is a fold over it.

pub const chain = @import("chock-proto/chain.zig");
pub const control = @import("chock-proto/control.zig");
pub const event = @import("chock-proto/event.zig");
pub const log = @import("chock-proto/log.zig");
pub const storage = @import("chock-proto/storage.zig");
pub const state = @import("chock-proto/state.zig");
/// Named `ship` because `export` is a keyword in Zig. The option a person types
/// is `--export-dir`.
pub const ship = @import("chock-proto/ship.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
