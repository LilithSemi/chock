//! Makes the directory the sandbox mounts, for a git project (`worktree.zig`)
//! and for a project with no git at all (`overlay.zig`).

pub const Diagnostic = @import("chock-workspace/diagnostic.zig").Diagnostic;

pub const binds = @import("chock-workspace/binds.zig");
pub const deny = @import("chock-workspace/deny.zig");
pub const git = @import("chock-workspace/git.zig");
pub const worktree = @import("chock-workspace/worktree.zig");
pub const overlay = @import("chock-workspace/overlay.zig");
pub const Workspace = @import("chock-workspace/Workspace.zig").Workspace;

test {
    @import("std").testing.refAllDecls(@This());
}
