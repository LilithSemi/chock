//! The public interface of chock-nix: what a project's Nix dev shell says,
//! and the store paths a sandbox has to mount for it.

const std = @import("std");

pub const Diagnostic = @import("chock-nix/diagnostic.zig").Diagnostic;

pub const backend = @import("chock-nix/backend.zig");
pub const build = @import("chock-nix/build.zig");
pub const DevShell = @import("chock-nix/DevShell.zig");
pub const dev_env = @import("chock-nix/dev_env.zig");
pub const eval = @import("chock-nix/eval.zig");
pub const fetch = @import("chock-nix/fetch.zig");
pub const inputs = @import("chock-nix/inputs.zig");
pub const proc = @import("chock-nix/proc.zig");
pub const provision = @import("chock-nix/provision.zig");
pub const store = @import("chock-nix/store.zig");

test {
    std.testing.refAllDecls(@This());
    _ = backend;
    _ = build;
    _ = DevShell;
    _ = dev_env;
    _ = eval;
    _ = fetch;
    _ = inputs;
    _ = proc;
    _ = provision;
    _ = store;
}
