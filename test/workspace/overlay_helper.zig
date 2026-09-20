//! Enters a user and mount namespace, mounts a real overlay, and performs
//! file operations against the merged view. A rootless overlay mount needs its
//! own mount namespace, and entering a user namespace needs a single threaded
//! caller, so this cannot run inside the zig test binary. build.zig gives this
//! binary's path to the test that starts it.
//!
//! Every file operation past the mount uses a raw syscall, because `std.Io.Dir`
//! needs a threaded `Io` this program cannot carry.
//!
//! Command line: <project> <upper> <work> <merged> [op ...]
//!
//! Each op is one of, split on ':':
//!   W:<relpath>:<content>   write <content> to merged/<relpath>, replacing it
//!   D:<relpath>              delete merged/<relpath>
//!   L:<relpath>:<target>    make merged/<relpath> a symbolic link to <target>
//!   M:<relpath>              make merged/<relpath> a directory
//!   F:<relpath>              make merged/<relpath> a named pipe
//!   R:<relpath>              remove the (already empty) directory merged/<relpath>
//!
//! `<content>` and `<target>` run to the end of the op string, so they may
//! hold a further ':' of their own. Only `<relpath>` may not.
//!
//! Exit codes:
//!   0 - every step succeeded.
//!   1 - too few arguments.
//!   3 - this kernel does not support a rootless overlay mount.
//!   4 - the overlay mount failed for another reason.
//!   5 - a component of the overlay's own paths could not be read.
//!   6 - an op failed, or named an operation this program does not know.
//!  63 - this machine would not give a user namespace, so nothing ran. Not a
//!       pass and not a failure: the caller skips and says why. See
//!       `namespace.nothing_measured_exit_status`.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("chock-sandbox");
const chock_workspace = @import("chock-workspace");
const Overlay = chock_workspace.overlay.Overlay;

pub fn main(init: std.process.Init.Minimal) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.args.toSlice(arena);
    if (args.len < 5) {
        std.debug.print("usage: overlay-helper <project> <upper> <work> <merged> [op ...]\n", .{});
        return 1;
    }

    // Borrowed from argv and never freed. `Overlay.mounts` only reads them.
    const ov = Overlay{
        .project = @constCast(args[1]),
        .upper = @constCast(args[2]),
        .work = @constCast(args[3]),
        .merged = @constCast(args[4]),
    };

    // Nothing is printed here. `build.zig`'s `failOnTestStderr` fails the
    // build on any byte a test binary writes to standard error.
    sandbox.namespace.enter(.{}, null) catch {
        return sandbox.namespace.nothing_measured_exit_status;
    };

    const described = ov.mounts(arena) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Unexpected => {
            std.debug.print("building the overlay descriptor failed\n", .{});
            return 4;
        },
        // These belong to the Darwin driver, to `adopt`, and to `carryOut`.
        error.NoOverlayFilesystem,
        error.ScratchOnAnotherVolume,
        error.ScratchAlreadyExists,
        error.NoOverlayToAdopt,
        error.WorkAlreadyCarriedOut,
        => unreachable,
    };
    const overlay_mount = switch (described[0]) {
        .overlay => |o| o,
        // `Overlay.mounts` always returns exactly one overlay entry.
        .bind, .proc, .deny => unreachable,
    };

    sandbox.namespace.mountOverlay(arena, .{
        .lower = overlay_mount.lower,
        .upper = overlay_mount.upper,
        .work = overlay_mount.work,
        .target = ov.merged,
    }, null) catch |err| switch (err) {
        error.OverlayNotSupported => {
            std.debug.print("this kernel does not support a rootless overlay mount\n", .{});
            return 3;
        },
        error.NotPermitted => {
            std.debug.print("a component of the overlay's own paths could not be read\n", .{});
            return 5;
        },
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            std.debug.print("mounting the overlay failed: {s}\n", .{@errorName(err)});
            return 4;
        },
    };

    for (args[5..]) |op| {
        applyOp(arena, ov.merged, op) catch |err| {
            std.debug.print("op '{s}' failed: {s}\n", .{ op, @errorName(err) });
            return 6;
        };
    }

    return 0;
}

const OpError = error{ UnknownOp, MissingField, OutOfMemory, OpFailed };

/// Apply one op string, documented at the top of this file, against `merged`.
fn applyOp(allocator: std.mem.Allocator, merged: []const u8, op: []const u8) OpError!void {
    var parts = std.mem.splitScalar(u8, op, ':');
    const kind = parts.next() orelse return error.UnknownOp;
    const rel_path = parts.next() orelse return error.MissingField;
    const target_path = std.fs.path.join(allocator, &.{ merged, rel_path }) catch return error.OutOfMemory;

    if (std.mem.eql(u8, kind, "W")) {
        try writeFileRaw(allocator, target_path, parts.rest());
    } else if (std.mem.eql(u8, kind, "D")) {
        try deleteFileRaw(allocator, target_path);
    } else if (std.mem.eql(u8, kind, "L")) {
        try symlinkRaw(allocator, parts.rest(), target_path);
    } else if (std.mem.eql(u8, kind, "M")) {
        try mkdirRaw(allocator, target_path);
    } else if (std.mem.eql(u8, kind, "F")) {
        try mkfifoRaw(allocator, target_path);
    } else if (std.mem.eql(u8, kind, "R")) {
        try rmdirRaw(allocator, target_path);
    } else {
        return error.UnknownOp;
    }
}

fn writeFileRaw(allocator: std.mem.Allocator, path: []const u8, contents: []const u8) OpError!void {
    const path_z = allocator.dupeZ(u8, path) catch return error.OutOfMemory;
    const fd_rc = linux.open(path_z.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (linux.errno(fd_rc) != .SUCCESS) return error.OpFailed;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);
    if (contents.len == 0) return;
    const written = linux.write(fd, contents.ptr, contents.len);
    if (linux.errno(written) != .SUCCESS or written != contents.len) return error.OpFailed;
}

fn deleteFileRaw(allocator: std.mem.Allocator, path: []const u8) OpError!void {
    const path_z = allocator.dupeZ(u8, path) catch return error.OutOfMemory;
    if (linux.errno(linux.unlink(path_z.ptr)) != .SUCCESS) return error.OpFailed;
}

fn symlinkRaw(allocator: std.mem.Allocator, link_target: []const u8, link_path: []const u8) OpError!void {
    const target_z = allocator.dupeZ(u8, link_target) catch return error.OutOfMemory;
    const path_z = allocator.dupeZ(u8, link_path) catch return error.OutOfMemory;
    if (linux.errno(linux.symlink(target_z.ptr, path_z.ptr)) != .SUCCESS) return error.OpFailed;
}

fn mkdirRaw(allocator: std.mem.Allocator, path: []const u8) OpError!void {
    const path_z = allocator.dupeZ(u8, path) catch return error.OutOfMemory;
    if (linux.errno(linux.mkdir(path_z.ptr, 0o755)) != .SUCCESS) return error.OpFailed;
}

fn mkfifoRaw(allocator: std.mem.Allocator, path: []const u8) OpError!void {
    const path_z = allocator.dupeZ(u8, path) catch return error.OutOfMemory;
    if (linux.errno(linux.mknod(path_z.ptr, linux.S.IFIFO | 0o644, 0)) != .SUCCESS) return error.OpFailed;
}

fn rmdirRaw(allocator: std.mem.Allocator, path: []const u8) OpError!void {
    const path_z = allocator.dupeZ(u8, path) catch return error.OutOfMemory;
    if (linux.errno(linux.rmdir(path_z.ptr)) != .SUCCESS) return error.OpFailed;
}
