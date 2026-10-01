//! What the `chock-vmm` module is on a build that cannot run a guest.
//!
//! Mirage's machine setup is KVM and the device layout it states is aarch64's, so
//! a guest runs on Linux on that architecture and nowhere else yet. `available` is
//! false here, and the daemon reads it before it offers a session a guest: see
//! `src/daemon.zig`.

const std = @import("std");

/// False here and true in `src/vmm.zig`, so a caller asks rather than catching a
/// refusal.
pub const available = false;

pub const Options = struct {
    kernel: []const u8 = "",
    initrd: ?[]const u8 = null,
    cmdline: []const u8 = "console=ttyAMA0 loglevel=7 init=/init",
    memory_mb: u64 = 512,
    cpus: u32 = 1,
    session: []const u8 = "",
    port: u32 = 1024,
    shares: []const Share = &.{},
    seconds: ?u64 = null,
    ready: ?*std.atomic.Value(bool) = null,
    stopping: ?*std.atomic.Value(bool) = null,

    pub const Share = struct {
        name: []const u8,
        at: []const u8,
        writable: bool = false,
    };
};

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

pub fn host(
    gpa: std.mem.Allocator,
    io: std.Io,
    options: Options,
    out: *std.Io.Writer,
    fault: *?Fault,
) anyerror!u8 {
    _ = gpa;
    _ = io;
    _ = options;
    _ = out;
    fault.* = .{ .said = "this build runs no guest" };
    return 1;
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
) AttachError!Attached {
    _ = io;
    _ = socket_path;
    _ = shares;
    _ = port;
    return error.NoGuest;
}
