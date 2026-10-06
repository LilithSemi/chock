//! What the `chock-vmm` module is on a build that cannot run a guest.
//!
//! Mirage needs both a machine and an architecture for the target, so a guest runs
//! on `x86_64-linux`, `aarch64-linux` and `aarch64-darwin` and nowhere else.
//! `available` is false here, and the daemon reads it before it offers a session a
//! guest: see `src/daemon.zig`.

const std = @import("std");

/// False here and true in `src/vmm.zig`, so a caller asks rather than catching a
/// refusal.
pub const available = false;

pub const Options = struct {
    kernel: []const u8 = "",
    initrd: ?[]const u8 = null,
    /// Empty, because nothing on this build boots a guest. `src/vmm.zig` picks the
    /// console name the architecture really has, and a name written out here would
    /// be arm's on every target that cannot run one.
    cmdline: []const u8 = "",
    memory_mb: u64 = 512,
    cpus: u32 = 1,
    session: []const u8 = "",
    port: u32 = 1024,
    shares: []const Share = &.{},
    seconds: ?u64 = null,
    /// No default, the same as `src/vmm.zig` states, so a caller that forgets it
    /// fails to build on this target too and not only on the one that runs a guest.
    control: i32,

    /// The same three fields `chock-sandbox`'s own `vm_shares.Share` states.
    /// Written out rather than imported, because this build has no `chock-sandbox`
    /// import: see `build.zig`.
    pub const Share = struct {
        name: []const u8,
        host_path: []const u8,
        writable: bool,
    };
};

/// The same answer `src/vmm.zig` states, so a caller of `forkHost` writes one
/// thing on both builds.
pub const fork_sets_control: i32 = -1;

/// The same two answers `src/vmm.zig` states, spelled out here for the reason
/// `Options.Share` is: this build imports no `chock-sandbox`. Nothing reaches
/// them at runtime on this target, because nothing starts a guest.
pub fn shareCovers(path: []const u8, root: []const u8) bool {
    if (root.len == 0) return false;
    if (!std.mem.startsWith(u8, path, root)) return false;
    if (path.len == root.len) return true;
    if (root[root.len - 1] == '/') return true;
    return path[root.len] == '/';
}

pub fn shareNameFor(
    allocator: std.mem.Allocator,
    taken: []const Options.Share,
    directory: []const u8,
) std.mem.Allocator.Error![]const u8 {
    _ = taken;
    return allocator.dupe(u8, std.fs.path.basename(directory));
}

/// What the host answers a guest reaching out with.
pub const Reached = union(enum) {
    /// A descriptor already connected where the guest asked. **Ownership crosses**:
    /// this end closes it once the guest has it.
    connected: std.posix.fd_t,
    refused,
};

/// Who decides where a guest may reach. The text is an address written by
/// `chock-sandbox`'s `vm_wire.writeAddress`, and never a name: the guest's own
/// router asked the host to resolve and reaches for what it was given.
pub const Reaches = struct {
    ptr: *anyopaque,
    decide: *const fn (ptr: *anyopaque, text: []const u8, port: u16) Reached,
};

/// Nothing reaches out of a guest that cannot run.
pub fn serveReaching(
    io: std.Io,
    control: std.posix.fd_t,
    reaches: Reaches,
    stopping: *std.atomic.Value(bool),
) void {
    _ = io;
    _ = control;
    _ = reaches;
    _ = stopping;
}

pub const Fault = struct {
    said: []const u8,
    detail: []const u8 = "",
};

pub const ForkError = error{
    NoChannel,
    NoFork,
    /// The answer this build gives. There is no guest to fork a process for.
    NoGuest,
};

pub const SendError = error{ OutOfMemory, Broke };

pub const ReadyError = error{ GuestRefused, GuestGone, GuestSlow };

/// The same shape `src/vmm.zig` states, so a caller compiles on both builds.
/// Nothing here is ever reached: `available` is false, and every caller reads it
/// before it asks for a guest.
pub const Child = struct {
    pid: std.posix.pid_t,
    control: i32,
    sev: Sev = .off,

    /// **The share set is typed and never `anytype`.** Nothing calls this yet, and
    /// an `anytype` parameter is only analysed when something does, so a mirror
    /// that took one could not catch a shape mismatch in the one place it exists
    /// to catch one.
    pub fn sendShares(
        self: *Child,
        allocator: std.mem.Allocator,
        shares: []const Options.Share,
    ) SendError!void {
        _ = self;
        _ = allocator;
        _ = shares;
        return error.Broke;
    }

    pub fn waitReady(self: *Child, io: std.Io, limit_ms: u64) ReadyError!void {
        _ = self;
        _ = io;
        _ = limit_ms;
        return error.GuestGone;
    }

    pub fn fault(self: *Child) ?Fault {
        _ = self;
        return .{ .said = "this build runs no guest" };
    }

    pub fn stop(self: *Child) void {
        _ = self;
    }

    pub fn wait(self: *Child) u8 {
        _ = self;
        return 1;
    }
};

/// There is no guest on a build that cannot run one, so there is no process to
/// fork for it.
pub fn forkHost(io: std.Io, options: Options, console_fd: std.posix.fd_t) ForkError!Child {
    _ = io;
    _ = options;
    _ = console_fd;
    return error.NoGuest;
}

pub const Attached = struct {
    control: std.posix.fd_t,
    stream: std.posix.fd_t,
};

pub const AttachError = error{
    NoGuest,
    ShareRefused,
    NoStream,
};

/// There is no guest on a build that cannot run one, so there is nothing to reach.
pub fn attach(
    io: std.Io,
    socket_path: []const u8,
    shares: anytype,
    port: u32,
    refused: anytype,
) AttachError!Attached {
    _ = io;
    _ = socket_path;
    _ = shares;
    _ = port;
    _ = refused;
    return error.NoGuest;
}
