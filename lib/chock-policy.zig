//! The policy table the broker evaluates. The policy is a static table in
//! `chock.zon`, the key is the agent kind, the model, the tool, and the
//! action, and the value is `allow`, `ask`, or `deny`.
//!
//! This library imports no other chock library. It reads one file and answers
//! one question about one key. `lib/chock-policy/table.zig` holds the schema,
//! the rules for which rule wins, and the two places a child is kept weaker
//! than its parent.
//!
//! `lib/chock-policy/subagents.zig` holds the other half of that rule: how
//! deep and how wide a spawn tree may grow. The table says what an agent may
//! do; the limits say how many agents there may be. Both are read from
//! `chock.zon`, and that file is beyond the agent's reach.
//!
//! `lib/chock-policy/ratchet.zig` holds the one thing an agent may say about
//! policy: a promise that binds itself. Narrowing is free and widening needs
//! authorisation, which is the same rule the subagent intersection already
//! keeps.
//!
//! `lib/chock-policy/org.zig` holds the layer above the project: the policy an
//! organisation gives an installation, which `chock.zon` may only narrow. It
//! is the same rule again, one level up, and `table.Table.org` is where it
//! joins the same intersection. It also holds the one thing in this library
//! that is not a rule: the audit sinks every session of an installation writes,
//! which a project may add to and can never take from.
//!
//! `lib/chock-policy/access.zig` holds the two action names that say which
//! providers and which models a session may use. They are rows on the table
//! above, not a system of their own.

pub const table = @import("chock-policy/table.zig");
pub const subagents = @import("chock-policy/subagents.zig");
pub const ratchet = @import("chock-policy/ratchet.zig");
pub const org = @import("chock-policy/org.zig");
pub const access = @import("chock-policy/access.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
