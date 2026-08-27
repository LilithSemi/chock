//! The event types and the session log. The log is the truth for a session, and the
//! state of a session is a fold over it.
//!
//! Every event carries the hash of the line before it, so the record is evidence
//! against an edit and not only against a crash. See `chain` for what that
//! defeats and, just as plainly, what it does not.

pub const chain = @import("chock-proto/chain.zig");
/// The daemon's control protocol: the grammar `chock daemon` answers and every
/// client of it speaks. Here rather than in the command because a frontend
/// links it and must get no other way to reach a session.
pub const control = @import("chock-proto/control.zig");
pub const event = @import("chock-proto/event.zig");
pub const log = @import("chock-proto/log.zig");
pub const storage = @import("chock-proto/storage.zig");
pub const state = @import("chock-proto/state.zig");
/// Shipping a log off the machine it was written on. Named `ship` because
/// `export` is a keyword in Zig; the option a person types is `--export-dir`.
pub const ship = @import("chock-proto/ship.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
