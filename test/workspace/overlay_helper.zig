//! Enters a user and mount namespace, mounts a real overlay, and performs one
//! or more file operations against the merged view. `lib/chock-workspace/overlay.zig`'s
//! own tests start this program and read its exit status, the same pattern
//! `test/sandbox/escape.zig` uses to run `test/sandbox/probe.zig`: a real
//! overlay mount needs `CAP_SYS_ADMIN` over its own mount namespace, and
//! entering a user namespace needs a single threaded caller, so this cannot
//! run inside the zig test binary itself. See build.zig for how this binary's
//! path reaches that test.
//!
//! This program calls the very same `Overlay.mounts` the library ships, by
//! importing the `chock-workspace` module, to get the overlay descriptor it
//! carries, `lower`, `upper`, and `work`, rather than a second copy that
//! could drift from it. `Overlay.mounts` only describes the overlay now; it
//! performs no mount of its own, so this program calls `chock-sandbox`'s own
//! `namespace.mountOverlay` directly to get a real mount, the same call
//! `chock-sandbox`'s own `buildRoot` makes for the overlay kind. It mounts at
//! `ov.merged`, a scratch directory kept apart from the project on purpose,
//! never at the descriptor's own `target` (the project's real path): every
//! test below reads the project, on the host, untouched, and compares it
//! against what actually landed under the overlay, so the two must stay
//! apart. The `Overlay` value this program builds borrows its four paths
//! straight from argv rather than owning fresh copies: this process never
//! calls `Overlay.deinit`, because it is about to exit and the kernel
//! reclaims everything anyway.
//!
//! Every file operation past the mount itself uses a raw syscall, never
//! `std.Io`: Zig 0.16 moved directory creation and file writes behind
//! `std.Io.Dir`, which needs a threaded `Io` implementation this program
//! cannot carry, because `sandbox.namespace.enter` needs a single threaded
//! caller. `test/sandbox/probe.zig` follows the same rule for the same reason.
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
//! hold a further ':' of their own; only `<relpath>` may not.
//!
//! Exit codes:
//!   0 - every step succeeded.
//!   1 - too few arguments.
//!   3 - the overlay mount was refused because this kernel does not support a
//!       rootless overlay mount. See namespace.zig's own error.OverlayNotSupported.
//!   4 - the overlay mount failed for another reason.
//!   5 - a component of the overlay's own paths (project, upper, or work)
//!       could not be read.
//!   6 - an op failed, or named an operation this program does not know.
//!  63 - this machine would not give a user namespace, so nothing here was
//!       measured. **Not a pass and not a failure**: the caller skips and says
//!       why. See `namespace.nothing_measured_exit_status`, which every helper
//!       program in this suite answers with for the same reason.

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

    // Borrowed, not owned: see this file's own top comment. Overlay.mounts
    // only ever reads these fields.
    const ov = Overlay{
        .project = @constCast(args[1]),
        .upper = @constCast(args[2]),
        .work = @constCast(args[3]),
        .merged = @constCast(args[4]),
    };

    // **Nothing is printed here.** This program's standard error is the test
    // binary's own, and `build.zig`'s `failOnTestStderr` fails the build on
    // any byte a test binary writes there. The exit status carries the fact,
    // and the caller turns it into a skip.
    sandbox.namespace.enter(.{}, null) catch {
        return sandbox.namespace.nothing_measured_exit_status;
    };

    const described = ov.mounts(arena) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Unexpected => {
            std.debug.print("building the overlay descriptor failed\n", .{});
            return 4;
        },
        // Overlay.mounts only ever builds one Mount.overlay entry from the
        // four paths already on `ov`; it never touches a driver, so this
        // program, which only ever runs on Linux, can never actually see any
        // of the errors only the Darwin driver's own create returns. See
        // chock-workspace/overlay.zig's own top comment.
        error.NoOverlayFilesystem,
        error.ScratchOnAnotherVolume,
        error.ScratchAlreadyExists,
        => unreachable,
    };
    const overlay_mount = switch (described[0]) {
        .overlay => |o| o,
        // Overlay.mounts always returns exactly one .overlay entry, never a
        // bind and never a procfs: this program would be testing a different
        // function's bug, not this one's, if that were ever not true.
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

/// Apply one op string, documented at this file's own top comment, against
/// `merged`.
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
