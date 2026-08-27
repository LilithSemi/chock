//! The one log lock test that needs a real second process. flock locks an open file
//! description, not a path and not a process, so two Log values inside this one test
//! binary, each from its own open call, would already be two separate descriptions
//! that contend for real. That would not tell apart a genuine second process from a
//! second open in the same process, and the property /daemonize depends on is
//! specifically that a second process cannot take a session another process owns. See
//! lock_helper.zig for the process this spawns, and lib/chock-proto/log.zig for the
//! two lock tests that do not need one.

const std = @import("std");
const chock_proto = @import("chock-proto");

// Zig 0.16 removed std.process.argsWithAllocator, and the default test runner panics
// on any argv it does not recognize, so the helper's path cannot travel as a CLI
// argument. It is embedded at build time instead, through an options module built
// with addOptionPath, the same mechanism test/sandbox/escape.zig uses for its probe.
const lock_helper_path = @import("lock_helper_path").lock_helper_path;

/// Read exactly one byte from `file`, blocking until it arrives or the pipe ends.
/// Returns whether a byte was actually read, so the caller can assert on that instead
/// of only on "the read call did not error".
///
/// This goes through `std.Io`, not through a raw syscall. It used to call
/// `std.os.linux.read` directly, which is a Linux syscall number sent through the
/// host's own trap instruction. On macOS the trap reaches the kernel but the syscall
/// number means something else entirely, so the call returned a plausible looking
/// count for work it never did, and this helper reported "no byte" for a helper
/// process that was in fact healthy. `std.Io` calls the right thing on every target.
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

    // Create the file and its header from this process first. Otherwise the helper's
    // own open would be the one creating it, racing this process's own open below
    // against whatever ensureHeader the helper is doing at the same moment.
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

    // Block until the helper says it holds the lock. Trying our own lock before this
    // byte arrives could race ahead of the helper's own flock call and prove nothing.
    try std.testing.expect(readOneByte(std.testing.io, child.stdout.?));

    // The direct proof: a second, genuinely different process already holds this
    // log's lock, so this process's own attempt must be refused at once, not block
    // and not silently succeed.
    var second = try chock_proto.log.Log.open(std.testing.io, path, "01TESTSESSION");
    defer second.close(std.testing.io);
    try std.testing.expectError(error.Busy, second.lock(std.testing.io));

    // Let the helper finish: it releases the lock through its own close and exits.
    try child.stdin.?.writeStreamingAll(std.testing.io, "g");

    const term = try child.wait(std.testing.io);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

/// Where the sources this test reads are, relative to the working directory.
/// A run step of `zig build` starts in the build root, which is why these are
/// relative and why the failure below is a failure and never a skip: a
/// directory that is not there means this test was started by hand from
/// somewhere else, and a silent skip would make it a test nobody runs.
/// **`src` is here now.** It was left out while the tests in it put many lines
/// on standard error: a command function called with no streams set falls back
/// there, which is what `src/tty.zig`'s own `streams` documents. Those tests
/// now open a `tty.Capture` of their own and read what the command wrote, so
/// the rule holds for `src` the same way it holds for the other two.
const scanned_roots = [_][]const u8{ "lib", "src", "test" };

/// The files this rule is not about: a program rather than a test.
///
/// **Most of these are under `test/` and are not test binaries at all.** Each
/// is a separate executable that `build.zig` builds with `addExecutable` and
/// that a test starts as a child process.
///
/// **A program a test starts may write to standard error, and several must.**
/// What matters is whether the test that starts it lets that output through.
/// Each of these is spawned with `stderr` set to `ignore` or `inherit` by the
/// test that drives it, and the choice is made there, one spawn at a time:
/// a program whose diagnostics only appear when the test is already failing
/// keeps `inherit`, and one that speaks while a test passes is silenced. See
/// `test/broker/support.zig`'s own `runProbe` for the reasoning in full.
///
/// **One of them is Chock's own `main`**, for a reason of its own: see the
/// comment on that entry.
const spawned_programs = [_][]const u8{
    // **The program's own entry point, and the one file that may name the real
    // standard error.** `main` is what points `src/tty.zig`'s two streams at
    // the descriptors the process was started with, and every other line in
    // this project goes through those streams rather than around them. A rule
    // that forbade the wiring itself would leave the program with nowhere to
    // write at all.
    //
    // **This is not an exemption for the tests in that file.** They are
    // compiled into the same binary as every other test and they write nothing
    // to standard error: see `src/tty.zig`'s own `Capture`, which is what they
    // use instead. What is excused here is two lines of `main`, and the check
    // that keeps them honest is `test/cli/streams.zig`, which starts the built
    // binary and reads its two streams apart.
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

/// The two ways a file in this project **names** standard error.
///
/// **This is a closed list of spellings and the rule is not.** A line that
/// writes there without naming it walks past: `tty.print` called with no
/// stream set falls back to the real descriptor by itself, and so does any
/// writer with a fallback. Two more spellings here would not close that, and
/// would make this look like the whole rule. `build.zig`'s `quiet test
/// binaries` step is what measures the bytes.
///
/// **Each is built from pieces on purpose.** Written whole, this test's own
/// source would hold the very text it looks for, and the test would fail on
/// itself.
const banned_calls = [_][]const u8{
    "std.debug." ++ "print(",
    "stderr" ++ "()",
};

/// True when `line` is a comment or a line of a multiline string literal.
/// Zig writes both with a two character opener as the first thing on the
/// line, so this needs no parser: `//` names a comment, and `\\` names a line
/// of a multiline string. The second matters because
/// `test/core/tools.zig` holds the source of a small program it compiles
/// inside the sandbox, and that program does print.
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

    // Every offending line, collected and compared against nothing at the
    // end. `expectEqualStrings` prints both sides, so the failure names each
    // file and line rather than only the first one, and this test breaks its
    // own rule nowhere.
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
