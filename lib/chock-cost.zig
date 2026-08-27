//! What a session costs, and what it is allowed to cost.
//!
//! **Free and unknown are different, and collapsing them is wrong in both
//! directions.** Calling unknown free lets a cap be passed with nobody
//! noticing, which is the same class of fault as a policy resolving an
//! unnamed action to allow. Calling free unknown makes a local llama.cpp
//! server, the cheapest way to work, look like the risky one. The type that
//! carries the difference is `chock_proto.event.Cost`, and this library never
//! hands back anything else.
//!
//! Two files, because they answer two different questions:
//!
//! * `prices.zig` says what a model costs. It is data with a version stamp,
//!   it goes stale, and every computed number records which version produced
//!   it, so a wrong price is a fact somebody can find rather than a number
//!   nobody can explain.
//! * `budget.zig` says what a session may spend. It reads the `budget` block
//!   of `chock.zon`, which is already beyond the agent's reach: the
//!   workspace binds the project's own copy back over that path
//!   read only, so **the model cannot raise its own budget**, and
//!   `test/workspace/escape.zig` proves it on a running system.
//!
//! This library imports `chock-proto` for the `Cost` and `Usage` types the
//! log already carries, and nothing else. It reads a file and does
//! arithmetic; it needs no sandbox, no workspace, and no session.

pub const prices = @import("chock-cost/prices.zig");
pub const budget = @import("chock-cost/budget.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
