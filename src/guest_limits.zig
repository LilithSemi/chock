//! Bounds shared by host toolchain discovery and microVM share grants.

pub const host_toolchain_candidates: []const []const u8 = &.{
    "/nix/store",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/etc",
    "/opt",
};

/// All host candidates except the mutually exclusive Nix store, plus the six
/// session roots a guest can receive independently of its toolchain.
pub const max_granted_roots: usize = host_toolchain_candidates.len - 1 + 6;
