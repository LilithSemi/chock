//! Configuration and credentials: which providers a user has, and how a
//! secret for one of them is stored and read back.

pub const paths = @import("chock-auth/paths.zig");
pub const config = @import("chock-auth/config.zig");
pub const store = @import("chock-auth/store.zig");
pub const lock = @import("chock-auth/lock.zig");
pub const lookup = @import("chock-auth/lookup.zig");
pub const signing = @import("chock-auth/signing.zig");
pub const search = @import("chock-auth/search.zig");
pub const check = @import("chock-auth/check.zig");

pub const darwin_status = @import("chock-auth/darwin/status.zig");

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
