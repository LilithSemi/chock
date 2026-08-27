//! The two locks a session takes on an image cache directory.
//!
//! **An image cache is shared on purpose**: that is what makes the second
//! session on a project cheap. So the answer to two sessions racing is not a
//! name of their own, which would defeat the cache and make every session
//! extract the image again. It is a lock, and one session removes and rebuilds
//! the tree while every other one waits for the whole extraction and then reads
//! what it wrote.
//!
//! `flock(2)`, through `std.Io.File.tryLock`, for the reason
//! `lib/chock-proto/log.zig` uses it for a session: the kernel releases it the
//! moment its holder exits, however it exits, so a session that is killed
//! leaves no stale lock for the next one to time out on. A lock file with a pid
//! in it would need somebody to clean it up, and nobody would.
//!
//! **The wait is bounded.** A wait with no bound is how a session hangs with
//! nothing on screen. See `default_wait_ns` for the size and the measurement
//! behind it, and `Answer.busy` for what a session that runs out of it says.
//!
//! ## Two locks, and why one is not enough
//!
//! `file_name` covers the moment of the change. `use_file_name` covers the
//! length of a session. They are different files because they answer different
//! questions, and one file cannot answer both:
//!
//! * A session that only reads the cache must not wait for a session that is
//!   already running. If reading took the same exclusive lock, the second
//!   terminal on a project would stand still for as long as the first one runs,
//!   which is the very cost the shared cache exists to avoid.
//! * A session that is running must not have its tree removed under it. So the
//!   reader has to hold something for its whole length, and that something has
//!   to be shared, or two ordinary sessions could not run at once.
//!
//! **Every acquisition of `use_file_name`, in either mode, happens while the
//! holder has `file_name` exclusively.** That is what makes the pair safe
//! without any claim about `flock` converting a lock atomically: a mode change
//! on the use lock cannot be seen by another process, because every other
//! process that would look is waiting on the extract lock. Release is the one
//! thing that happens outside, and releasing a shared lock harms nobody.

const std = @import("std");

/// The lock file inside an image's cache directory. Taken exclusively, and
/// held only across the stamp check and the extraction.
///
/// **Nothing ever deletes it.** `flock` locks an open file description, so a
/// file that is removed and made again hands the next session a different inode
/// and no exclusion at all. `Image.extract` removes the stamp, the tree and the
/// tar, and this name is none of those.
pub const file_name = "extract.lock";

/// The lock file that says a session is using the extracted tree right now.
/// Taken shared for the whole length of a session, and exclusively by the
/// session that is about to remove the tree and write another one.
///
/// **This is the one the session itself depends on.** `file_name` alone stops
/// two extractions from tearing each other. It does nothing for the session
/// that already has a mount set and is still binding it an hour later. See this
/// file's own top comment for why the two are separate files, and `Image.load`
/// for the order they are taken in.
///
/// Removed by nothing, for the same reason `file_name` is not.
pub const use_file_name = "use.lock";

/// How long a session waits for the one that is extracting.
///
/// **Long, because the thing being waited for is genuinely slow.** Measured on
/// 2026-08-25: `docker export` writes the 96 MB tar of `debian:bookworm-slim`
/// in 3.8 seconds, and the whole extraction of `alpine:3.20` takes 0.5. An
/// image a hundred times the size of Debian's still finishes well inside this.
///
/// Reaching this bound means the other session is still working, or its runtime
/// is wedged. It does not mean a lock was left behind: the kernel releases
/// `flock` when the holder dies.
pub const default_wait_ns: u64 = 10 * std.time.ns_per_min;

/// How often a waiting session asks again. `std.Io` has no timed lock, so a
/// bounded wait is a poll. 50 ms adds nothing measurable to an extraction of
/// seconds and costs 20 wakes a second while waiting.
pub const default_poll_ns: u64 = 50 * std.time.ns_per_ms;

pub const Options = struct {
    /// Which file inside the cache directory. See `file_name` and
    /// `use_file_name`, which are the only two this project takes.
    name: []const u8 = file_name,
    /// **`shared` is what a session holds for its whole length**, and several
    /// sessions hold it at once. `exclusive` is what the one session that
    /// removes and rebuilds the tree takes.
    mode: std.Io.File.Lock = .exclusive,
    /// Zero asks once and does not wait, which is how a caller learns it is
    /// about to wait and can say so before it does.
    wait_ns: u64 = default_wait_ns,
    poll_ns: u64 = default_poll_ns,
};

/// A lock this process holds. Release it with `release`.
///
/// **A holder that is killed still releases it.** The kernel drops every
/// `flock` an open file description holds when the process ends, however it
/// ends, so a session that is interrupted, faults, or is killed with `SIGKILL`
/// leaves nothing behind for the next one. That is the property this whole
/// arrangement rests on. A lock held for the length of a session, with no such
/// property, would need a reaper, and one reaper that missed would make the
/// image unusable for good.
pub const Held = struct {
    file: std.Io.File,

    pub fn release(self: *Held, io: std.Io) void {
        self.file.unlock(io);
        self.file.close(io);
        self.* = undefined;
    }

    /// Turn an exclusive lock into a shared one, keeping it held throughout.
    ///
    /// **What the session that extracted does last.** It took the use lock
    /// exclusively so that it could remove the old tree. From the moment the
    /// new one is written it is an ordinary reader, and holding the lock
    /// exclusively any longer would refuse every other session for the length
    /// of this one.
    pub fn downgrade(self: *Held, io: std.Io) !void {
        return self.file.downgradeLock(io);
    }
};

/// What one `take` produced.
///
/// **`busy` and `unusable` are facts about the machine, not faults of this
/// module**, and each one is a different sentence for a person: one says
/// another session is working, the other says this directory cannot be used.
pub const Answer = union(enum) {
    held: Held,
    /// The bound ran out while somebody else held it. The seconds waited.
    busy: i64,
    /// The lock file could not be opened or asked about.
    unusable: anyerror,
};

/// Take the lock on `cache_dir`, waiting up to `options.wait_ns` for it.
///
/// **This answers rather than fails.** Every way it can end is a sentence the
/// caller owns, so there is no error set and no way for a caller to report a
/// wait as a crash.
pub fn take(io: std.Io, cache_dir: []const u8, options: Options) Answer {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buffer, "{s}/{s}", .{ cache_dir, options.name }) catch |err|
        return .{ .unusable = err };

    // Never truncating: the file's content is nothing, and a lock that emptied
    // a file would be a lock with a side effect.
    var file = std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = false }) catch |err|
        return .{ .unusable = err };

    const started = std.Io.Clock.Timestamp.now(io, .awake);
    const deadline = started.addDuration(.{
        // `.awake`, so a wait does not end early or never end when NTP steps
        // the wall clock. The choice `chock-core`'s own deadlines make.
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

/// An absolute path to a temporary directory, in `buffer`.
fn pathOf(buffer: []u8, dir: std.Io.Dir) ![]const u8 {
    const length = try dir.realPath(testing.io, buffer);
    return buffer[0..length];
}

test "one taker holds it and a second one waits, then says how long it waited" {
    // Two `take` calls in one process are two real contenders: `flock` locks an
    // open file description, and each `createFileAbsolute` makes its own. The
    // measurement that two `chock run` commands really contend is
    // `test/container/concurrent.zig`, with real processes.
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

    // And the moment the first one lets go, the next one gets it. This is the
    // whole behaviour a waiting session depends on.
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

    // Zero is what a caller asks with when it wants to print a line before
    // anybody waits.
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
    // `Image.extract` removes the stamp, the tree and the tar. A lock file
    // caught by one of those would be a lock that stops working exactly when it
    // is needed.
    for ([_][]const u8{ "stamp", "rootfs", "image.tar" }) |removed| {
        try testing.expect(!std.mem.eql(u8, file_name, removed));
        try testing.expect(!std.mem.eql(u8, use_file_name, removed));
    }
    // And they are two files, which is the whole reason a reader does not wait
    // for a session that is already running.
    try testing.expect(!std.mem.eql(u8, file_name, use_file_name));
}

test "two sessions hold the use lock at once, and a writer waits for both of them" {
    // **The ordinary case is two readers.** A shared lock that excluded a
    // second reader would stop two terminals working on one project, which is
    // the thing the shared cache is for.
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

    // The session that wants to replace the tree. Both readers are still on it.
    switch (take(testing.io, dir, writing)) {
        .busy => {},
        .held, .unusable => return error.TestUnexpectedResult,
    }

    // One reader leaving is not enough, and that is the point: the tree stays
    // until the last session using it has gone.
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
    // Mutation check: leave the writer's lock exclusive and the reader below
    // is refused, so every session after an extraction would be refused too.
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
