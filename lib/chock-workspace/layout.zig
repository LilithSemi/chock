//! Where the sandbox sees the workspace. Linux can put a path anywhere, and
//! macOS has no bind mount, so there are exactly two answers.

const builtin = @import("builtin");

pub const Layout = enum {
    remapped,
    /// What a person loses, and it is one thing. An absolute path a program
    /// writes into a file names the checkout, not the project, and the checkout
    /// is deleted when the session ends: `compile_commands.json`, a coverage
    /// report, a `.pyc` header and a debug binary's `DW_AT_comp_dir` each record
    /// the directory the compiler ran in. No tool of Chock's own writes a host
    /// path into a file, and the hand back is a diff of relative paths.
    in_place,

    /// Comptime, and read from the target rather than from a flag, because the
    /// driver is chosen at comptime too and a workspace whose layout disagreed
    /// with its driver would build a mount list that driver refuses.
    pub fn forHost() Layout {
        return switch (builtin.os.tag) {
            .macos => .in_place,
            else => .remapped,
        };
    }
};
