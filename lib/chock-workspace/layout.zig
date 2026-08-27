//! Where the sandbox sees the workspace, which is a different question on each
//! platform and has exactly two answers.
//!
//! **Linux can put a path anywhere. macOS cannot put a path anywhere at all.**
//! A bind mount is what makes a checkout in a scratch directory appear at the
//! project's own path, and macOS has no bind mount and is not getting one. So
//! the mount list this module's two backings build has to say a different
//! thing there: every path stays where it really is, and the tool call works
//! in the checkout under its own real name.
//!
//! **This is a choice about paths and never about copies.** Both backings
//! already make a real copy on Darwin: `worktree.create` runs `git worktree
//! add`, and `darwin/overlay.zig` clones the project with `clonefile(2)`. The
//! agent is in its own tree on macOS exactly as it is on Linux. What macOS
//! cannot do is give that tree the project's own name.
//!
//! See `Layout.in_place`'s own doc comment for what a person loses.

const builtin = @import("builtin");

/// The two shapes a workspace mount list can have.
pub const Layout = enum {
    /// The checkout appears at the project's own path, and Chock's own paths
    /// appear under `Sandbox.runtime_prefix`. Every mount moves a path, so this
    /// needs a mount namespace.
    remapped,
    /// Every path in the sandbox is the host path it really is. The checkout is
    /// reached by the scratch path git made it at, and `.git` by the project's
    /// own real `.git`.
    ///
    /// **What a person loses, and it is one thing.** An absolute path that a
    /// program run by `run_command` writes into a file names the checkout, not
    /// the project, and the checkout is deleted when the session ends. A
    /// `compile_commands.json`, a coverage report, a `.pyc` header and a debug
    /// binary's `DW_AT_comp_dir` each record the directory the compiler ran
    /// in. Every one of those paths resolves correctly while the session runs
    /// and names nothing afterwards.
    ///
    /// **What a person does not lose, read off the tools rather than
    /// assumed.** Every path argument of `read_file`, `list_directory`,
    /// `glob`, `grep`, `write_file` and `edit_file` is documented to the model
    /// as relative to the project root, `glob` and `grep` return their results
    /// relative to it, and `chock-core`'s own `leavesProject` reads both
    /// against `Sandbox.Config.cwd`, which this layout sets to the checkout.
    /// So the model is told one root, spells paths against that root, and is
    /// answered in the same root: no tool of Chock's own writes a host path
    /// into a file. The hand back is a git diff of relative paths, so carrying
    /// the work home reads no absolute path either.
    in_place,

    /// The layout this build's own sandbox driver can express.
    ///
    /// **Comptime, and read from the target rather than from a flag.** The
    /// driver is chosen at comptime for the same reason, in
    /// `lib/chock-sandbox/Sandbox.zig`, and a workspace whose layout disagreed
    /// with its driver would build a mount list that driver refuses.
    pub fn forHost() Layout {
        return switch (builtin.os.tag) {
            .macos => .in_place,
            else => .remapped,
        };
    }
};
