//! The language server end to end through a real sandbox. Linux only. Every
//! sandbox call runs in a probe process, because `Sandbox.spawn` forks and
//! `fork` carries only the calling thread.

const std = @import("std");

// build.zig builds each probe and gives its path here, because the test runner panics on unknown argv.
const probe_path = @import("lsp_probe_path").lsp_probe_path;

const zls_probe_path = @import("lsp_probe_path").lsp_zls_probe_path;
const zls_path: ?[]const u8 = @import("lsp_probe_path").zls_path;

const sandbox = @import("chock-sandbox");

/// A boundary that was never reached is not a boundary that held, so a machine that refuses a sandbox skips.
fn skipIfNothingMeasured(term: std.process.Child.Term) !void {
    const code = switch (term) {
        .exited => |c| c,
        else => return,
    };
    if (code == sandbox.namespace.nothing_measured_exit_status) return error.SkipZigTest;
}

/// `std.testing.tmpDir` hands back a directory only a relative path reaches.
fn absoluteDirPath(buffer: []u8, dir: std.Io.Dir) ![]u8 {
    const len = dir.realPath(std.testing.io, buffer) catch return error.RealPathFailed;
    return buffer[0..len];
}

test "a real language server in a real sandbox puts a real diagnostic in a tool result" {
    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();
    var work_tmp = std.testing.tmpDir(.{});
    defer work_tmp.cleanup();

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var work_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absoluteDirPath(&root_buffer, root_tmp.dir);
    const work = try absoluteDirPath(&work_buffer, work_tmp.dir);

    // `Sandbox.spawn` builds a mount tree under the root and removes it again, so the workspace cannot be it.
    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ probe_path, "drive", root, work },
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(std.testing.io);
    try skipIfNothingMeasured(term);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a real zls in a real sandbox reports a real Zig error, in the right place" {
    // Either half of the column conversion alone gets this right, so neither is pinned here.
    const zls = zls_path orelse return error.SkipZigTest;

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();
    var work_tmp = std.testing.tmpDir(.{});
    defer work_tmp.cleanup();

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var work_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absoluteDirPath(&root_buffer, root_tmp.dir);
    const work = try absoluteDirPath(&work_buffer, work_tmp.dir);

    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ zls_probe_path, "drive", root, work, zls },
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(std.testing.io);
    try skipIfNothingMeasured(term);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}
