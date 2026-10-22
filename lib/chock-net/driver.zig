//! Chock's two drivers, and what each one needs out of a call's links. Palisade's
//! own driver takes channels and helpers, so the links are lowered into those.
//! The guest driver takes the router as it is: it answers resolve requests on the
//! guest's behalf while the call runs.

const std = @import("std");
const builtin = @import("builtin");
const palisade = @import("palisade");

const links = @import("links.zig");
const guest = @import("vm/driver.zig");
const helpers = @import("linux/helpers.zig");

const Term = palisade.Sandbox.Term;
const Run = palisade.Sandbox.Run;
const SpawnError = palisade.Sandbox.SpawnError;

/// How many components a root must have before anything will delete inside it.
/// The in-place layout gives a config `root = "/"`, because macOS cannot pivot
/// into a root of its own, and a one component path is a directory the whole
/// system shares. Neither is ever a sandbox root worth clearing.
const least_root_components = 2;

fn clearableRoot(root: []const u8) bool {
    if (!std.fs.path.isAbsolute(root)) return false;
    var components: usize = 0;
    var parts = std.mem.tokenizeScalar(u8, root, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return false;
        components += 1;
    }
    return components >= least_root_components;
}

/// Palisade deletes nothing under `root`: a failed setup can leave empty mount
/// points and its own `.palisade-*` files behind, and the next call needs the
/// root fit to use. Clearing them is the caller's, so the tool runner calls this
/// when a spawn fails.
pub fn clearRootAfterFailure(io: std.Io, root: []const u8) void {
    if (!clearableRoot(root)) return;

    var dir = std.Io.Dir.openDirAbsolute(io, root, .{ .iterate = true }) catch return;
    defer dir.close(io);

    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        dir.deleteTree(io, entry.name) catch continue;
    }
}

const testing = std.testing;

test "nothing clears a root the in place layout gives, or one the system shares" {
    try testing.expect(!clearableRoot("/"));
    try testing.expect(!clearableRoot("/tmp"));
    try testing.expect(!clearableRoot("relative/path.root"));
    try testing.expect(!clearableRoot("/sessions/../../etc"));

    try testing.expect(clearableRoot("/tmp/sess1.root"));
    try testing.expect(clearableRoot("/home/someone/.local/share/chock/abc.root"));
}

pub const Driver = union(enum) {
    native: palisade.Sandbox.Driver,
    guest: *guest.Guest,

    pub const native_driver: Driver = .{ .native = palisade.Sandbox.native };

    pub fn spawn(
        self: Driver,
        gpa: std.mem.Allocator,
        call: links.Call,
        argv: []const []const u8,
        run: Run,
    ) SpawnError!Term {
        switch (self) {
            .native => |one| {
                if (builtin.os.tag != .linux) return one.spawn(gpa, call.config, argv, run);

                var lowered: helpers.Lowered = .{};
                var config = call.config;
                lowered.apply(gpa, &config, call.links) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.SocketFailed => return error.ChannelFailed,
                };
                // The counts go to the call's own stderr, where the rest of this
                // call's sandbox diagnosis goes.
                defer lowered.finish(gpa, config.stderr_fd);
                return one.spawn(gpa, config, argv, run);
            },
            .guest => |one| return one.spawnLinked(gpa, call.config, argv, run, call.links),
        }
    }

    /// The palisade driver a `Handle` records, so `signal` and `close` reach the
    /// right one.
    pub fn asPalisade(self: Driver) palisade.Sandbox.Driver {
        return switch (self) {
            .native => |one| one,
            .guest => |one| one.driver(),
        };
    }

    pub fn name(self: Driver) []const u8 {
        return self.asPalisade().name;
    }

    pub fn guarantees(self: Driver) palisade.Sandbox.Guarantees {
        return self.asPalisade().guarantees;
    }

    pub fn expresses(self: Driver) palisade.Sandbox.Expresses {
        return self.asPalisade().expresses;
    }

    pub fn whyLast(self: Driver) ?[]const u8 {
        return self.asPalisade().whyLast();
    }

    pub fn joinFreshSessionKeyring(self: Driver, stderr_fd: i32) palisade.Sandbox.KeyringError!void {
        return self.asPalisade().joinFreshSessionKeyring(stderr_fd);
    }
};
