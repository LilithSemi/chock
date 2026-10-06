//! Where the sandbox sees the workspace. Linux can put a path anywhere, and
//! macOS has no bind mount, so there are exactly two answers.

const builtin = @import("builtin");

pub const Layout = enum {
    remapped,
    in_place,

    /// Comptime, not a flag, since the driver is also chosen at comptime.
    pub fn forHost() Layout {
        return switch (builtin.os.tag) {
            .macos => .in_place,
            else => .remapped,
        };
    }
};
