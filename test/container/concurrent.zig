//! Two terminals, one project, one image cache. The sessions are real child
//! processes because flock locks an open file description. A test skips with no
//! container runtime or no image on the disk, and nothing here fetches.

const std = @import("std");

// The default test runner panics on argv it does not know, so the helper path is
// a build time constant.
const helper_path = @import("load_helper_path").load_helper_path;

const test_image = "alpine:3.20";

/// A cache directory is named after the reference, so two digests reach one when
/// a tag moves or the other runtime is used.
const other_image = "python:3.12-alpine";

/// The helper's exit statuses, kept in step with `test/container/load_helper.zig`.
const from_cache = 0;
const extracted = 1;
const refused = 2;
const no_runtime = 5;

/// A `hold_ms` of zero loads and leaves at once.
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

fn start(io: std.Io, cache_dir: []const u8) !std.process.Child {
    return std.process.spawn(io, .{
        .argv = &.{ helper_path, cache_dir, test_image },
        .stdin = .ignore,
        // A test binary that writes to standard error fails this build.
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

/// The stamp is the signal, because a session takes the use lock before it
/// starts to extract.
fn heldOrTimeout(io: std.Io, dir: std.Io.Dir) !void {
    var waited_ms: u64 = 0;
    while (waited_ms < start_bound_ms) : (waited_ms += poll_ms) {
        if (dir.statFile(io, "stamp", .{})) |_| return else |_| {}
        try std.Io.sleep(io, .fromMilliseconds(poll_ms), .awake);
    }
    return error.SessionNeverStarted;
}

const start_bound_ms: u64 = 120 * std.time.ms_per_s;
const poll_ms: u64 = 25;

const default_hold_ms: u64 = 3 * std.time.ms_per_s;

fn raceOnce(allocator: std.mem.Allocator, io: std.Io, count: usize) !usize {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(io, &buffer);
    const cache_dir = buffer[0..length];

    const children = try allocator.alloc(std.process.Child, count);
    defer allocator.free(children);

    // Every one is started before any one is waited for, or this is sequential.
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

    try std.testing.expectEqual(@as(u8, extracted), held);
    try std.testing.expectEqual(@as(u8, refused), moved);

    var after = try startHolding(io, cache_dir, other_image, 0);
    try std.testing.expectEqual(@as(u8, extracted), try statusOf(io, &after));
}

test "two sessions on the same image both run at once, which is what the shared cache is for" {
    const io = std.testing.io;
    try runnableOrSkip(io);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(io, &buffer);
    const cache_dir = buffer[0..length];

    var holder = try startHolding(io, cache_dir, test_image, default_hold_ms);
    try heldOrTimeout(io, tmp.dir);

    var second = try startHolding(io, cache_dir, test_image, 0);
    try std.testing.expectEqual(@as(u8, from_cache), try statusOf(io, &second));
    try std.testing.expectEqual(@as(u8, extracted), try statusOf(io, &holder));
}
