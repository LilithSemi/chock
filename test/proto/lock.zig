//! The one log lock test that needs a real second process. flock locks an open
//! file description, so two `Log` values in one test binary would contend for
//! real and show nothing about two processes.

const std = @import("std");
const chock_proto = @import("chock-proto");

// The default test runner panics on argv it does not know, so the helper path is
// embedded at build time through an options module.
const lock_helper_path = @import("lock_helper_path").lock_helper_path;

/// Goes through `std.Io`. A raw `std.os.linux.read` sends a Linux syscall number
/// that means something else on macOS, and answered a plausible count for work
/// it never did.
fn readOneByte(io: std.Io, file: std.Io.File) bool {
    var byte: [1]u8 = undefined;
    while (true) {
        const count = file.readStreaming(io, &.{&byte}) catch return false;
        if (count == 0) continue;
        return count == 1;
    }
}

test "a second process cannot take the lock while the first holds it" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try chock_proto.log.absoluteDirPath(std.testing.io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/second-process-lock", .{dir_path});

    // Make the file and its header first, or the helper's open races this one.
    {
        var seed = try chock_proto.log.Log.open(std.testing.io, path, "01TESTSESSION");
        seed.close(std.testing.io);
    }

    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ lock_helper_path, path },
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
    });

    // Wait for the helper, or this runs ahead of its own flock call.
    try std.testing.expect(readOneByte(std.testing.io, child.stdout.?));

    var second = try chock_proto.log.Log.open(std.testing.io, path, "01TESTSESSION");
    defer second.close(std.testing.io);
    try std.testing.expectError(error.Busy, second.lock(std.testing.io));

    try child.stdin.?.writeStreamingAll(std.testing.io, "g");

    const term = try child.wait(std.testing.io);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

const scanned_roots = [_][]const u8{ "lib", "src", "test" };

const spawned_programs = [_][]const u8{
    // `main` points `src/tty.zig`'s streams at the descriptors the process started
    // with, so it is the one file that may name the real standard error.
    "src/main.zig",
    "test/sandbox/probe.zig",
    "test/workspace/escape_probe.zig",
    "test/workspace/overlay_helper.zig",
    "test/core/tools_probe.zig",
    "test/core/lsp_probe.zig",
    "test/core/lsp_zls_probe.zig",
    "test/core/tree_child.zig",
    "test/core/subagent_child.zig",
    "test/proto/lock_helper.zig",
};

/// A closed list of spellings, and the rule is wider: a line that writes there
/// without naming it walks past. Each string is built from pieces so this file
/// does not hold the text it looks for.
const banned_calls = [_][]const u8{
    "std.debug." ++ "print(",
    "stderr" ++ "()",
};

/// `\\` matters because `test/core/tools.zig` holds the source of a small
/// program it compiles inside the sandbox, and that program does print.
fn isCommentOrStringLine(line: []const u8) bool {
    const text = std.mem.trimStart(u8, line, " \t");
    return std.mem.startsWith(u8, text, "//") or std.mem.startsWith(u8, text, "\\\\");
}

fn isSpawnedProgram(path: []const u8) bool {
    for (spawned_programs) |name| {
        if (std.mem.eql(u8, name, path)) return true;
    }
    return false;
}

test "no source line outside main names standard error, which is the spelling half of the rule" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var found: std.ArrayList(u8) = .empty;
    defer found.deinit(allocator);

    for (scanned_roots) |root| {
        var dir = std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch
            return error.TheSourceTreeIsNotWhereThisTestWasStarted;
        defer dir.close(io);

        var walker = try dir.walk(allocator);
        defer walker.deinit();

        while (try walker.next(io)) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.path, ".zig")) continue;

            const path = try std.fs.path.join(allocator, &.{ root, entry.path });
            defer allocator.free(path);
            if (isSpawnedProgram(path)) continue;

            const text = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(4 * 1024 * 1024));
            defer allocator.free(text);

            var number: usize = 0;
            var lines = std.mem.splitScalar(u8, text, '\n');
            while (lines.next()) |line| {
                number += 1;
                if (isCommentOrStringLine(line)) continue;
                for (banned_calls) |call| {
                    if (std.mem.indexOf(u8, line, call) == null) continue;
                    try found.print(allocator, "{s}:{d} names standard error\n", .{ path, number });
                }
            }
        }
    }

    try std.testing.expectEqualStrings("", found.items);
}
