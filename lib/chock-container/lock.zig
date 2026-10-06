//! The two locks a session takes on an image cache directory: `file_name`
//! for one change, `use_file_name` for one session.

const std = @import("std");

/// Taken exclusively. Nothing deletes it: `flock` ties to the inode.
pub const file_name = "extract.lock";

/// Shared for a session, exclusive while replacing the tree. Removed by
/// nothing, like `file_name`.
pub const use_file_name = "use.lock";

/// Not evidence of a stale lock.
pub const default_wait_ns: u64 = 10 * std.time.ns_per_min;

/// A bounded wait is a poll.
pub const default_poll_ns: u64 = 50 * std.time.ns_per_ms;

pub const Options = struct {
    name: []const u8 = file_name,
    /// `shared`: many at once. `exclusive`: the replacer.
    mode: std.Io.File.Lock = .exclusive,
    /// Zero asks once, no wait.
    wait_ns: u64 = default_wait_ns,
    poll_ns: u64 = default_poll_ns,
};

pub const Held = struct {
    file: std.Io.File,

    pub fn release(self: *Held, io: std.Io) void {
        self.file.unlock(io);
        self.file.close(io);
        self.* = undefined;
    }

    pub fn downgrade(self: *Held, io: std.Io) !void {
        return self.file.downgradeLock(io);
    }
};

pub const Answer = union(enum) {
    held: Held,
    busy: i64,
    unusable: anyerror,
};

/// Answers rather than fails.
pub fn take(io: std.Io, cache_dir: []const u8, options: Options) Answer {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buffer, "{s}/{s}", .{ cache_dir, options.name }) catch |err|
        return .{ .unusable = err };

    // Never truncating.
    var file = std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = false }) catch |err|
        return .{ .unusable = err };

    const started = std.Io.Clock.Timestamp.now(io, .awake);
    const deadline = started.addDuration(.{
        // `.awake`: ignores NTP steps.
        .raw = .fromNanoseconds(@intCast(options.wait_ns)),
        .clock = .awake,
    });

    while (true) {
        const acquired = file.tryLock(io, options.mode) catch |err| {
            file.close(io);
            return .{ .unusable = err };
        };
        if (acquired) return .{ .held = .{ .file = file } };

        const now = std.Io.Clock.Timestamp.now(io, .awake);
        if (now.compare(.gte, deadline)) {
            file.close(io);
            return .{ .busy = started.durationTo(now).raw.toSeconds() };
        }

        std.Io.sleep(io, .fromNanoseconds(@intCast(options.poll_ns)), .awake) catch |err| {
            file.close(io);
            return .{ .unusable = err };
        };
    }
}

const testing = std.testing;

fn pathOf(buffer: []u8, dir: std.Io.Dir) ![]const u8 {
    const length = try dir.realPath(testing.io, buffer);
    return buffer[0..length];
}

test "one taker holds it and a second one waits, then says how long it waited" {
    // Two contenders: each open is independent.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try pathOf(&buffer, tmp.dir);

    var first = switch (take(testing.io, dir, .{})) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };

    switch (take(testing.io, dir, .{ .wait_ns = 20 * std.time.ns_per_ms })) {
        .held => return error.TestUnexpectedResult,
        .unusable => return error.TestUnexpectedResult,
        .busy => |seconds| try testing.expect(seconds >= 0),
    }

    first.release(testing.io);
    var second = switch (take(testing.io, dir, .{})) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    second.release(testing.io);
}

test "a caller that will not wait is told at once" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try pathOf(&buffer, tmp.dir);

    var held = switch (take(testing.io, dir, .{})) {
        .held => |value| value,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    defer held.release(testing.io);

    const started = std.Io.Clock.Timestamp.now(testing.io, .awake);
    switch (take(testing.io, dir, .{ .wait_ns = 0 })) {
        .busy => {},
        .held, .unusable => return error.TestUnexpectedResult,
    }
    const waited = started.durationTo(std.Io.Clock.Timestamp.now(testing.io, .awake));
    try testing.expect(waited.raw.toMilliseconds() < 500);
}

test "a directory that is not there cannot be locked, and says so instead of waiting" {
    switch (take(testing.io, "/chock-no-such-cache-directory", .{})) {
        .unusable => {},
        .held, .busy => return error.TestUnexpectedResult,
    }
}

test "neither lock is one of the names an extraction removes" {
    for ([_][]const u8{ "stamp", "rootfs", "image.tar" }) |removed| {
        try testing.expect(!std.mem.eql(u8, file_name, removed));
        try testing.expect(!std.mem.eql(u8, use_file_name, removed));
    }
    try testing.expect(!std.mem.eql(u8, file_name, use_file_name));
}

test "two sessions hold the use lock at once, and a writer waits for both of them" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try pathOf(&buffer, tmp.dir);

    const reading = Options{ .name = use_file_name, .mode = .shared, .wait_ns = 0 };
    const writing = Options{ .name = use_file_name, .mode = .exclusive, .wait_ns = 0 };

    var first = switch (take(testing.io, dir, reading)) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    var second = switch (take(testing.io, dir, reading)) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };

    switch (take(testing.io, dir, writing)) {
        .busy => {},
        .held, .unusable => return error.TestUnexpectedResult,
    }

    first.release(testing.io);
    switch (take(testing.io, dir, writing)) {
        .busy => {},
        .held, .unusable => return error.TestUnexpectedResult,
    }

    second.release(testing.io);
    var writer = switch (take(testing.io, dir, writing)) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    defer writer.release(testing.io);
}

test "a writer that is finished downgrades, and a reader gets in at once" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try pathOf(&buffer, tmp.dir);

    var writer = switch (take(testing.io, dir, .{
        .name = use_file_name,
        .mode = .exclusive,
        .wait_ns = 0,
    })) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    defer writer.release(testing.io);

    const reading = Options{ .name = use_file_name, .mode = .shared, .wait_ns = 0 };
    switch (take(testing.io, dir, reading)) {
        .busy => {},
        .held, .unusable => return error.TestUnexpectedResult,
    }

    try writer.downgrade(testing.io);

    var reader = switch (take(testing.io, dir, reading)) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    reader.release(testing.io);
}

test "the two locks do not exclude each other, because they are two files" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try pathOf(&buffer, tmp.dir);

    var extracting = switch (take(testing.io, dir, .{ .wait_ns = 0 })) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    defer extracting.release(testing.io);

    var using = switch (take(testing.io, dir, .{
        .name = use_file_name,
        .mode = .exclusive,
        .wait_ns = 0,
    })) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    using.release(testing.io);
}
