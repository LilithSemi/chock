//! Two terminals, one project, one image cache.
//!
//! **The ordinary case, and it used to break.** An image cache is shared on
//! purpose: that is what makes the second session on a project cheap. Before
//! `lib/chock-container/lock.zig`, each cold session removed and rebuilt the
//! tree, the tar and the stamp at constant names, so two of them fought over
//! what the other was reading. Measured on 2026-08-25 with the helper this file
//! starts, on Linux 6.18.42, aarch64, Docker 29.7.2:
//!
//! * `alpine:3.20`, four way, 25 iterations: **54 of 100 sessions failed**, and
//!   46 extractions happened where 25 were wanted.
//! * `alpine:3.20`, eight way, 25 iterations: **159 of 200 sessions failed**.
//! * `debian:bookworm-slim`, four way, 10 iterations: no session failed and
//!   **all 40 extracted**, each one writing over the others. The cache bought
//!   nothing at all.
//!
//! With the lock, every one of those runs is 0 failures and exactly one
//! extraction per iteration.
//!
//! ## The second fault: a session that is already running
//!
//! The extract lock covers the moment of the extraction, not the length of a
//! session. A session runs for an hour with every tool call binding the
//! extracted tree. A second session computes a **different** digest for the same
//! reference, because the tag moved or the other container runtime is in use,
//! takes the extract lock legitimately, and removes the tree the first one is
//! still binding. Measured on 2026-08-25, same machine, with the holding mode
//! of the helper:
//!
//! * one session holding `alpine:3.20` for four seconds, a second session on
//!   the same directory resolving to `python:3.12-alpine`, 50 iterations:
//!   **50 of 50 holders lost their tree**, and every mover extracted over it.
//!
//! With the shared use lock, the same 50 runs are 0 holders broken and 50
//! movers refused. The moved tag was measured as a real moved tag as well:
//! `docker tag` moved one reference from `alpine:3.20` to
//! `python:3.12-alpine` under a live session, and the second session was
//! refused by name rather than replacing the tree.
//!
//! **Real processes and not two calls in one test binary.** `flock` locks an
//! open file description, so two `Image.load` calls inside this binary would
//! contend correctly and prove nothing about two `chock run` commands.
//!
//! ## What makes a test here skip
//!
//! No container runtime, or the test image not on the disk. See
//! `test/container/real_runtime.zig`: nothing here fetches, for the same reason
//! a session does not.

const std = @import("std");

// Zig 0.16's default test runner panics on an argv it does not recognize, so
// the helper's path is a build time constant. Every probe in this project is
// wired this way.
const helper_path = @import("load_helper_path").load_helper_path;

const test_image = "alpine:3.20";

/// A second image, so that one cache directory can be asked for two digests.
///
/// **This is the moved tag, in the only respect that matters.** A cache
/// directory is named after the reference, so in real use two digests reach one
/// directory when a tag moves or when the other runtime is used. Both of those
/// arrive at `Image.load` as exactly this: one directory, one stamp on the
/// disk, and an inspection that answers a different identifier. A test that
/// moved a real tag would have to write to the machine's own image store, and
/// it would measure nothing this does not.
const other_image = "python:3.12-alpine";

/// The helper's exit statuses. Kept in step with `test/container/load_helper.zig`
/// by name.
const from_cache = 0;
const extracted = 1;
const refused = 2;
const no_runtime = 5;

/// Start one session on `cache_dir`, which keeps the image for `hold_ms` and
/// reads its mount set the whole time. Zero loads and leaves at once.
fn startHolding(
    io: std.Io,
    cache_dir: []const u8,
    reference: []const u8,
    hold_ms: u64,
) !std.process.Child {
    var buffer: [32]u8 = undefined;
    const held = try std.fmt.bufPrint(&buffer, "{d}", .{hold_ms});
    return std.process.spawn(io, .{
        .argv = &.{ helper_path, cache_dir, reference, held },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
}

/// Start one session on `cache_dir`.
fn start(io: std.Io, cache_dir: []const u8) !std.process.Child {
    return std.process.spawn(io, .{
        .argv = &.{ helper_path, cache_dir, test_image },
        .stdin = .ignore,
        // A test binary that writes to standard error fails this build whatever
        // it exited with. See `test/proto/lock.zig`.
        .stdout = .ignore,
        .stderr = .ignore,
    });
}

fn statusOf(io: std.Io, child: *std.process.Child) !u8 {
    return switch (try child.wait(io)) {
        .exited => |code| code,
        else => 255,
    };
}

/// One session on a cache directory of its own, to learn whether this machine
/// can run these tests at all.
fn runnableOrSkip(io: std.Io) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(io, &buffer);

    var child = start(io, buffer[0..length]) catch return error.SkipZigTest;
    switch (try statusOf(io, &child)) {
        no_runtime, refused => return error.SkipZigTest,
        extracted => {},
        else => return error.TestUnexpectedResult,
    }
}

/// The same question for `other_image`, which only the holding tests need.
fn otherRunnableOrSkip(io: std.Io) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(io, &buffer);

    var child = startHolding(io, buffer[0..length], other_image, 0) catch return error.SkipZigTest;
    switch (try statusOf(io, &child)) {
        no_runtime, refused => return error.SkipZigTest,
        extracted => {},
        else => return error.TestUnexpectedResult,
    }
}

/// Wait until the first session has really taken the image, so that the second
/// one is the second one.
///
/// **Without this the two sessions are in no order at all**, and a run where the
/// second one arrives first measures the opposite arrangement and reads as a
/// failure. The stamp is the signal because the session writes it at the end of
/// its extraction, and it takes the use lock before the extraction starts, so a
/// stamp on the disk means the tree is already held.
fn heldOrTimeout(io: std.Io, dir: std.Io.Dir) !void {
    var waited_ms: u64 = 0;
    while (waited_ms < start_bound_ms) : (waited_ms += poll_ms) {
        if (dir.statFile(io, "stamp", .{})) |_| return else |_| {}
        try std.Io.sleep(io, .fromMilliseconds(poll_ms), .awake);
    }
    return error.SessionNeverStarted;
}

/// Long enough for the slowest of these images. `alpine:3.20` extracts in half
/// a second, measured on 2026-08-25.
const start_bound_ms: u64 = 120 * std.time.ms_per_s;
const poll_ms: u64 = 25;

/// How long the first session keeps its image. It only has to outlast the
/// second session's inspection and refusal, which is one runtime command.
const default_hold_ms: u64 = 3 * std.time.ms_per_s;

/// Start `count` cold sessions on one empty cache directory and answer how many
/// of them extracted the image.
fn raceOnce(allocator: std.mem.Allocator, io: std.Io, count: usize) !usize {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(io, &buffer);
    const cache_dir = buffer[0..length];

    const children = try allocator.alloc(std.process.Child, count);
    defer allocator.free(children);

    // Every one is started before any one is waited for. A test that waited on
    // the first before starting the second would be a sequential run, which is
    // what proves nothing about this fault.
    for (children) |*child| child.* = try start(io, cache_dir);

    var extractions: usize = 0;
    var failures: usize = 0;
    for (children) |*child| {
        switch (try statusOf(io, child)) {
            extracted => extractions += 1,
            from_cache => {},
            else => failures += 1,
        }
    }

    try std.testing.expectEqual(@as(usize, 0), failures);
    return extractions;
}

test "four cold sessions on one image cache all work, and only one of them extracts" {
    // **Both halves matter.** No failure is the fault this fixes. One
    // extraction is the reason the fix is a lock and not a directory per
    // session: a name per session would pass the first half and make every
    // session pay for the image again.
    //
    // Mutation check: take the lock out of `Image.load` and this fails on the
    // first half, 54 sessions in 100 measured. Name the extraction per process
    // instead and it fails on the second.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    try runnableOrSkip(io);

    for (0..2) |_| {
        try std.testing.expectEqual(@as(usize, 1), try raceOnce(allocator, io, 4));
    }
}

test "eight cold sessions on one image cache still extract exactly once" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    try runnableOrSkip(io);

    try std.testing.expectEqual(@as(usize, 1), try raceOnce(allocator, io, 8));
}

test "a session that is running keeps its files when a second session needs different ones" {
    // **The fault this test exists for.** The first session is doing what every
    // session does: holding one mount set and reading it, tool call after tool
    // call. The second one resolves the same cache directory to another digest,
    // which in real use is a tag that moved or the other container runtime.
    // Before the use lock it removed the tree and the first session lost every
    // tool call it had left. Measured 50 of 50 holders broken. See this file's
    // own top comment.
    //
    // Mutation check: take the use lock out of `Image.load` and the first
    // expectation fails with `tree_broken`, because the mover extracts over the
    // holder. Make the use lock exclusive for readers as well and the next test
    // fails instead, because two ordinary sessions could no longer share.
    const io = std.testing.io;
    try runnableOrSkip(io);
    try otherRunnableOrSkip(io);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(io, &buffer);
    const cache_dir = buffer[0..length];

    var holder = try startHolding(io, cache_dir, test_image, default_hold_ms);
    try heldOrTimeout(io, tmp.dir);

    var mover = try startHolding(io, cache_dir, other_image, 0);
    const moved = try statusOf(io, &mover);
    const held = try statusOf(io, &holder);

    // The first session read its own tree for the whole time it was there.
    try std.testing.expectEqual(@as(u8, extracted), held);
    // And the second one was told at its first second, with a sentence naming
    // the image. A refusal is not a failure: nothing was half done.
    try std.testing.expectEqual(@as(u8, refused), moved);

    // **And the wait really ends.** A lock held past the session that took it
    // would leave the image unusable for good, which would be a worse fault
    // than the one this fixes.
    var after = try startHolding(io, cache_dir, other_image, 0);
    try std.testing.expectEqual(@as(u8, extracted), try statusOf(io, &after));
}

test "two sessions on the same image both run at once, which is what the shared cache is for" {
    // **The cost of the fix, pinned so it cannot grow.** The use lock is shared
    // and not exclusive exactly so that the second terminal on a project starts
    // at once instead of waiting out the first session. A lock that refused
    // this would pass the test above and make Chock unusable in two windows.
    const io = std.testing.io;
    try runnableOrSkip(io);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(io, &buffer);
    const cache_dir = buffer[0..length];

    var holder = try startHolding(io, cache_dir, test_image, default_hold_ms);
    try heldOrTimeout(io, tmp.dir);

    // Same image, warm cache, while the first session is still running.
    var second = try startHolding(io, cache_dir, test_image, 0);
    try std.testing.expectEqual(@as(u8, from_cache), try statusOf(io, &second));
    try std.testing.expectEqual(@as(u8, extracted), try statusOf(io, &holder));
}
