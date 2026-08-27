//! Makes the directory the sandbox mounts, for a git project (`worktree.zig`) and
//! for a project with no git at all (`overlay.zig`). The agent works in a
//! throwaway copy, never the user's own tree, so it cannot damage the real
//! project because it cannot reach the real project at all.
//!
//! This library knows about git and about the one overlay mount. It knows
//! nothing about a user or a network
//! namespace: `chock-sandbox` owns those, and a later task hands a mount list
//! across that boundary to `Sandbox.spawn`. This root file itself must never
//! import `chock-sandbox` directly; `worktree.zig` and `overlay.zig` each do,
//! only for the one `Mount` type both must agree with `Sandbox.spawn` on.

/// Why a workspace call failed, past what its error set can say. One type for
/// the whole module: see its own top comment.
pub const Diagnostic = @import("chock-workspace/diagnostic.zig").Diagnostic;

/// The `deny_read` block of a project's own `chock.zon`: the files the agent
/// may not read. Exported because a caller that wants to say what a session
/// will keep out, before it opens a workspace, reads the same list
/// `Workspace.open` reads.
pub const deny = @import("chock-workspace/deny.zig");
pub const git = @import("chock-workspace/git.zig");
pub const worktree = @import("chock-workspace/worktree.zig");
pub const overlay = @import("chock-workspace/overlay.zig");
pub const Workspace = @import("chock-workspace/Workspace.zig").Workspace;

// The Darwin overlay driver is not re-exported here, unlike
// `lib/chock-sandbox.zig`'s own `darwin_driver_for_testing`. That driver only
// refuses, so it is ordinary portable Zig and a Linux host can compile it.
// `chock-workspace/darwin/overlay.zig` calls `clonefile(2)`, a macOS call no
// other libc has, so `refAllDecls` below would ask a Linux link for a symbol
// that does not exist there. `overlay.zig`'s own "same public shape" test
// still checks both drivers declare the same names, on Linux, without
// compiling either driver's body.

test {
    @import("std").testing.refAllDecls(@This());
}
