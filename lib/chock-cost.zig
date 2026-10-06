//! What a session costs, and what it is allowed to cost.

pub const prices = @import("chock-cost/prices.zig");
pub const budget = @import("chock-cost/budget.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
