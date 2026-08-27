//! The lock one `chock login` takes before it changes a file in the credential
//! store.
//!
//! **Two logins at once is ordinary**, and both files the store keeps are read,
//! changed and written whole. Without exclusion the two runs read the same
//! index, each drops what the other added, and the temporary files they write
//! through can reach one inode and publish a mixture that parses as neither.
//! The answer is a lock, because the files are shared on purpose: a name of
//! their own would give each run its own store.
//!
//! `flock(2)`, through `std.Io.File.tryLock`, for the reason
//! `lib/chock-proto/log.zig` uses it for a session and
//! `lib/chock-container/lock.zig` uses it for an image cache: **the kernel
//! releases it the moment its holder exits, however it exits**, so a login that
//! is killed at its prompt leaves no stale lock for the next one to time out
//! on. A lock file holding a pid would need somebody to clean it up, and nobody
//! would.
//!
//! **One lock file for each file it guards, and never one for the store.** A
//! `Store.put` writes the credential file through the driver and then the
//! index, so a single lock would have to be taken twice in one process.
//! `flock` locks an open file description, so the second take would wait on a
//! lock this very process holds and would never get it.
//!
//! **They nest, and always in one order.** `Store.put` holds the index's for
//! the whole of its own write and the driver takes the credential file's
//! inside that, because the two files are one store and a login that took only
//! one of them could leave an entry from itself beside a credential from
//! somebody else. Nothing takes them the other way about: `signing.zig` reaches
//! the driver directly and takes the credential file's alone.
//!
//! **The wait is short.** See `default_wait_ns`.

const std = @import("std");

/// How long a login waits for another one.
///
/// **Short, because what is being waited for is short.** Everything under a
/// lock here is one read of a file of a few hundred bytes, one serialize, and
/// one rename: well under a millisecond, so eight logins at once clear in about
/// ten. Five seconds is hundreds of times that margin and still an answer a
/// person gets while they are still looking at the terminal.
///
/// **This is deliberately not `lib/chock-container/lock.zig`'s ten minutes.**
/// That lock is held over `docker export`, which writes 96 MB in about four
/// seconds and could be given a far larger image, so a long wait is right
/// there. `chock login` is a person at a prompt, and a command that says
/// nothing for minutes reads as a command that has hung.
///
/// **The person's own prompt is never held under this lock.** The credential is
/// read and the provider is asked before `Store.put` is called at all, so the
/// minutes a person spends at a terminal are outside every lock here. That is
/// the wait this bound could never cover.
///
/// **One prompt can be held under it, and it is the Keychain's.**
/// `Store.put` now runs the driver inside the index's lock, because the
/// credential and the index are one store: see the body of `Store.put`. On
/// Linux the driver is a file write and this bound is untouched. On Darwin
/// `security` can ask a person to unlock the Keychain, and a login that is
/// waiting on that answer holds this lock while it waits. A second login then
/// reaches the bound and is told another login is running, which is true, and
/// it can be run again. The state that replaces is a store that held two
/// logins at once and said nothing.
///
/// So reaching this bound means another login is genuinely mid write, or is at
/// a Keychain the machine's owner has locked, or the machine is wedged.
pub const default_wait_ns: u64 = 5 * std.time.ns_per_s;

/// How often a waiting login asks again. `std.Io` has no timed lock, so a
/// bounded wait is a poll. 10 ms is short beside the five second bound and
/// costs 100 wakes a second only while somebody is actually waiting.
pub const default_poll_ns: u64 = 10 * std.time.ns_per_ms;

pub const Options = struct {
    /// Zero asks once and does not wait, which is what a caller uses to learn
    /// it is about to wait.
    wait_ns: u64 = default_wait_ns,
    poll_ns: u64 = default_poll_ns,
};

/// A lock this process holds. Release it with `release`.
pub const Held = struct {
    file: std.Io.File,

    pub fn release(self: *Held, io: std.Io) void {
        self.file.unlock(io);
        self.file.close(io);
        self.* = undefined;
    }
};

/// What one `take` produced.
///
/// **`busy` and `unusable` are facts about the machine, not faults of this
/// module**, and each one is a different sentence for a person: one says
/// another login is writing, the other says this directory cannot be used.
pub const Answer = union(enum) {
    held: Held,
    /// The bound ran out while somebody else held it. The seconds waited.
    busy: i64,
    /// The lock file could not be opened or asked about.
    unusable: anyerror,
};

/// Take the lock named `file_name` in `data_dir`, waiting up to
/// `options.wait_ns` for it.
///
/// **This answers rather than fails.** Every way it can end is a sentence the
/// caller owns, so there is no error set and no way for a caller to report a
/// wait as a crash.
///
/// **Nothing ever deletes a lock file.** `flock` locks an open file
/// description, so a file removed and made again hands the next login a
/// different inode and no exclusion at all.
pub fn take(io: std.Io, data_dir: []const u8, file_name: []const u8, options: Options) Answer {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buffer, "{s}/{s}", .{ data_dir, file_name }) catch |err|
        return .{ .unusable = err };

    // Never truncating: the content is nothing, and a lock that emptied a file
    // would be a lock with a side effect. The mode matches the rest of the
    // store, so a lock file cannot be the one thing in a 0700 directory that
    // another account may open.
    var file = std.Io.Dir.createFileAbsolute(io, path, .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    }) catch |err| return .{ .unusable = err };

    const started = std.Io.Clock.Timestamp.now(io, .awake);
    const deadline = started.addDuration(.{
        // `.awake`, so a wait does not end early or never end when NTP steps
        // the wall clock.
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
    // Two `take` calls in one process are two real contenders: `flock` locks an
    // open file description, and each `createFileAbsolute` makes its own. The
    // measurement that two `chock login` commands really contend is
    // `test/auth/concurrent.zig`, with real processes.
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

    // A second name is a second lock. This is what lets `Store.put` guard the
    // credential file and the index without one wait ever being on the other.
    var other = switch (take(testing.io, dir, "b.lock", .{ .wait_ns = 0 })) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    other.release(testing.io);

    // And the moment the first one lets go, the next one gets it. This is the
    // whole behaviour a waiting login depends on.
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
    // The number itself, pinned. A later edit that reached for the ten minutes
    // an image cache waits would make a login look hung.
    try testing.expect(default_wait_ns <= 30 * std.time.ns_per_s);
    try testing.expect(default_poll_ns < default_wait_ns);
}
