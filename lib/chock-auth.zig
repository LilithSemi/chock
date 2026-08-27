//! Configuration and credentials: which providers a user has, and how a
//! credential for one of them is found.
//!
//! **Two files, two directories, two owners, and that is what makes Chock
//! work under home-manager.** The Nix store is world readable, and
//! home-manager writes a configuration file as a read only symbolic link into
//! it, replaced on every activation. A program that writes its own credential
//! into a file home-manager manages either cannot write at all, or loses the
//! credential on the next `home-manager switch`.
//!
//! | | Owner | Where | Holds |
//! |---|---|---|---|
//! | configuration | the user, or home-manager | `~/.config/chock` | instance names, kinds, base URLs |
//! | credentials | **Chock alone** | `~/.local/share/chock` | the secret values |
//!
//! **Chock reads the configuration directory and never writes it.**
//!
//! This library imports no other Chock library. `chock login` runs before a
//! session, a workspace, or a sandbox exists, and it must not need any of
//! them.
//!
//! ## The name is the key
//!
//! A user may hold two ai& accounts, two `openai-compat` endpoints, or two
//! Anthropic keys billed to different places, **so a
//! provider instance is keyed by a user chosen name and the kind is a
//! property**. A design that keys anything on the kind cannot hold the second
//! instance, and that fault only appears after somebody has already stored
//! it.
//!
//! ## There is no environment variable for a credential
//!
//! At any stage, including a bootstrap. A variable is visible to every child
//! process, it leaks in from a shell somebody exported into by accident, and
//! it is the exact path the redaction rules exist to catch. Nothing in this
//! library reads one, and `paths.zig` reads the environment only for
//! `HOME` and the XDG directory variables.

pub const paths = @import("chock-auth/paths.zig");
pub const config = @import("chock-auth/config.zig");
pub const store = @import("chock-auth/store.zig");
pub const lock = @import("chock-auth/lock.zig");
pub const lookup = @import("chock-auth/lookup.zig");
pub const signing = @import("chock-auth/signing.zig");
pub const check = @import("chock-auth/check.zig");

/// Imported directly, not only through `store.zig`'s own comptime driver
/// dispatch, so the parts of the Darwin driver that need no Keychain are
/// checked on every host this project builds on: see
/// `chock-auth/darwin/secrets.zig`'s own top comment, and
/// `chock-sandbox.zig`'s own export of the same shape for the same reason.
pub const darwin_driver_for_testing = @import("chock-auth/darwin/secrets.zig");

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
