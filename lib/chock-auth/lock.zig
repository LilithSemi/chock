//! The lock one `chock login` takes before it changes a file in the credential

const std = @import("std");

pub const default_wait_ns: u64 = 5 * std.time.ns_per_s;

pub const default_poll_ns: u64 = 10 * std.time.ns_per_ms;

pub const Options = struct {
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
};

pub const Answer = union(enum) {
    held: Held,
    busy: i64,
    unusable: anyerror,
};

pub fn take(io: std.Io, data_dir: []const u8, file_name: []const u8, options: Options) Answer {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buffer, "{s}/{s}", .{ data_dir, file_name }) catch |err|
        return .{ .unusable = err };

    // Never truncating: the content is nothing, and a lock that emptied a file would have a side effect. The mode matches the rest of the store, so a lock file is not the one thing in a 0700 directory that another account may open.
    var file = std.Io.Dir.createFileAbsolute(io, path, .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    }) catch |err| return .{ .unusable = err };

    const started = std.Io.Clock.Timestamp.now(io, .awake);
    const deadline = started.addDuration(.{
        // Uses .awake rather than .real, so a wait does not end early or run forever when NTP steps the wall clock.
        .raw = .fromNanoseconds(@intCast(options.wait_ns)),
        .clock = .awake,
    });

    while (true) {
        const acquired = file.tryLock(io, .exclusive) catch |err| {
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
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try pathOf(&buffer, tmp.dir);

    var first = switch (take(testing.io, dir, "a.lock", .{})) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };

    switch (take(testing.io, dir, "a.lock", .{ .wait_ns = 20 * std.time.ns_per_ms })) {
        .held, .unusable => return error.TestUnexpectedResult,
        .busy => |seconds| try testing.expect(seconds >= 0),
    }

    var other = switch (take(testing.io, dir, "b.lock", .{ .wait_ns = 0 })) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    other.release(testing.io);

    first.release(testing.io);
    var second = switch (take(testing.io, dir, "a.lock", .{})) {
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

    var held = switch (take(testing.io, dir, "a.lock", .{})) {
        .held => |value| value,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    defer held.release(testing.io);

    const started = std.Io.Clock.Timestamp.now(testing.io, .awake);
    switch (take(testing.io, dir, "a.lock", .{ .wait_ns = 0 })) {
        .busy => {},
        .held, .unusable => return error.TestUnexpectedResult,
    }
    const waited = started.durationTo(std.Io.Clock.Timestamp.now(testing.io, .awake));
    try testing.expect(waited.raw.toMilliseconds() < 500);
}

test "a directory that is not there cannot be locked, and says so instead of waiting" {
    switch (take(testing.io, "/chock-no-such-data-directory", "a.lock", .{})) {
        .unusable => {},
        .held, .busy => return error.TestUnexpectedResult,
    }
}

test "the lock file others may not read" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try pathOf(&buffer, tmp.dir);

    var held = switch (take(testing.io, dir, "a.lock", .{})) {
        .held => |value| value,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    defer held.release(testing.io);

    const stat = try tmp.dir.statFile(testing.io, "a.lock", .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o7777);
}

test "the bound is short enough for a person at a prompt" {
    try testing.expect(default_wait_ns <= 30 * std.time.ns_per_s);
    try testing.expect(default_poll_ns < default_wait_ns);
}
