//! The public interface of chock-nix: what a project's Nix dev shell says,
//! and what a sandbox has to mount for it.
//!
//! Two rules ask for the same thing from two directions. The first wants
//! every tool call to run with the dev shell's environment, so an agent uses
//! the project's own toolchain rather than whatever the machine happens to
//! have. Red team finding 1 of 2026-08-21 wants the sandbox to stop mounting
//! the host's entire `/nix/store`. **Both
//! answers come out of one evaluation**, and that is what this library is:
//! `nix print-dev-env`, the shell that runs `shellHook`, the transitive
//! closure of what the result refers to, a garbage collector root over it,
//! and a cache keyed on the flake.
//!
//! `provision.zig` is the same operation with a different input: one package
//! name instead of a project's dev shell.
//! It answers with store paths and `bin` directories, which is what
//! `DevShell` already answers with, so a provisioned program joins the
//! session's toolchain by the road that is already there.
//!
//! It imports no other Chock library. A dev shell is read before a session,
//! a workspace, or a sandbox exists, the same way `chock-auth` reads a
//! credential, so nothing here may depend on any of them. It hands back
//! plain strings: `KEY=VALUE` records for the environment and store paths
//! for the mount set. `src/run.zig` turns those into a
//! `sandbox.Config.env` and a `chock_core.tools.Context.store_paths`.
//!
//! **Everything here spawns a process, so it runs in `src/run.zig`'s phase
//! 1 and nowhere else.** Phase 2 builds an `std.Io` that cannot start a
//! thread, on purpose, because the tool path forks. See `src/run.zig`'s own
//! top comment.

const std = @import("std");

/// Why a `nix` call did not give an answer. One type for the whole module:
/// see its own top comment.
pub const Diagnostic = @import("chock-nix/diagnostic.zig").Diagnostic;

pub const DevShell = @import("chock-nix/DevShell.zig");
pub const dev_env = @import("chock-nix/dev_env.zig");
pub const proc = @import("chock-nix/proc.zig");
pub const provision = @import("chock-nix/provision.zig");
pub const store = @import("chock-nix/store.zig");

test {
    std.testing.refAllDecls(@This());
    _ = DevShell;
    _ = dev_env;
    _ = proc;
    _ = provision;
    _ = store;
}
