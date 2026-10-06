//! When to send a refused request again, and how long to wait first.

const std = @import("std");
const failure = @import("failure.zig");

pub const Policy = struct {
    max_attempts: usize = 6,
    first_wait_ms: u64 = 2_000,
    max_wait_ms: u64 = 60_000,
    max_retry_after_ms: u64 = 300_000,
    retry_after_spread_ms: u64 = 1_000,
};

pub const Stop = enum {
    not_retryable,
    attempts_spent,
    wait_too_long,
};

pub const Decision = union(enum) {
    wait_ms: u64,
    stop: Stop,
};

pub const jitter_scale: u64 = 1024;

pub fn jitterFrom(io: std.Io) u64 {
    var bytes: [8]u8 = undefined;
    io.random(&bytes);
    return std.mem.readInt(u64, &bytes, .little) % jitter_scale;
}

pub fn waitMs(policy: Policy, attempts_made: usize, retry_after_s: ?u64, jitter: u64) u64 {
    std.debug.assert(attempts_made >= 1);
    std.debug.assert(jitter < jitter_scale);

    if (retry_after_s) |seconds| {
        const asked = std.math.mul(u64, seconds, 1000) catch policy.max_retry_after_ms;
        return asked +| policy.retry_after_spread_ms * jitter / jitter_scale;
    }

    var step = policy.first_wait_ms;
    var doubled: usize = 1;
    while (doubled < attempts_made and step < policy.max_wait_ms) : (doubled += 1) {
        step = std.math.mul(u64, step, 2) catch policy.max_wait_ms;
    }
    step = @min(step, policy.max_wait_ms);

    const half = step / 2;
    return half + half * jitter / jitter_scale;
}

pub fn decide(
    policy: Policy,
    class: failure.Class,
    attempts_made: usize,
    retry_after_s: ?u64,
    jitter: u64,
) Decision {
    switch (class) {
        // Compaction answers context_overflow and nothing answers permanent: neither may ever reach a wait, since retrying either cannot work.
        .context_overflow, .permanent => return .{ .stop = .not_retryable },
        .rate_limited, .transient => {},
    }

    if (attempts_made >= policy.max_attempts) return .{ .stop = .attempts_spent };

    if (retry_after_s) |seconds| {
        const asked = std.math.mul(u64, seconds, 1000) catch return .{ .stop = .wait_too_long };
        if (asked > policy.max_retry_after_ms) return .{ .stop = .wait_too_long };
    }

    return .{ .wait_ms = waitMs(policy, attempts_made, retry_after_s, jitter) };
}

pub fn retryAfterSeconds(value: []const u8) ?u64 {
    const text = std.mem.trim(u8, value, " \t");
    if (text.len == 0) return null;
    for (text) |character| {
        if (!std.ascii.isDigit(character)) return null;
    }
    return std.fmt.parseInt(u64, text, 10) catch null;
}

pub const Sleeper = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        sleep: *const fn (ptr: *anyopaque, io: std.Io, wait_ms: u64) void,
    };

    pub fn sleep(self: Sleeper, io: std.Io, wait_ms: u64) void {
        self.vtable.sleep(self.ptr, io, wait_ms);
    }
};

pub const SystemSleeper = struct {
    var anchor: u8 = 0;

    pub fn sleeper() Sleeper {
        return .{ .ptr = &anchor, .vtable = &vtable };
    }

    const vtable = Sleeper.VTable{ .sleep = sleepFn };

    fn sleepFn(ptr: *anyopaque, io: std.Io, wait_ms: u64) void {
        _ = ptr;
        std.Io.sleep(io, .fromMilliseconds(@intCast(wait_ms)), .awake) catch |err| switch (err) {
            error.Canceled => {},
        };
    }
};

const testing = std.testing;

test "a rate limit and a server fault are retried, and an overflow and a bad request are not" {
    const policy = Policy{};

    try testing.expect(decide(policy, .rate_limited, 1, null, 0) == .wait_ms);
    try testing.expect(decide(policy, .transient, 1, null, 0) == .wait_ms);

    try testing.expectEqual(Stop.not_retryable, decide(policy, .context_overflow, 1, null, 0).stop);
    try testing.expectEqual(Stop.not_retryable, decide(policy, .permanent, 1, null, 0).stop);
}

test "the wait is exactly what Retry-After asked for, plus jitter that only ever adds" {
    const policy = Policy{ .retry_after_spread_ms = 1_000 };

    try testing.expectEqual(@as(u64, 12_000), waitMs(policy, 1, 12, 0));
    try testing.expectEqual(@as(u64, 12_500), waitMs(policy, 1, 12, jitter_scale / 2));
    try testing.expectEqual(@as(u64, 12_999), waitMs(policy, 1, 12, jitter_scale - 1));

    try testing.expectEqual(@as(u64, 12_000), waitMs(policy, 4, 12, 0));
}

test "with no Retry-After the step doubles, is never zero, and stops at the ceiling" {
    const policy = Policy{ .first_wait_ms = 2_000, .max_wait_ms = 60_000 };

    try testing.expectEqual(@as(u64, 1_000), waitMs(policy, 1, null, 0));
    try testing.expectEqual(@as(u64, 1_999), waitMs(policy, 1, null, jitter_scale - 1));

    try testing.expectEqual(@as(u64, 2_000), waitMs(policy, 2, null, 0));
    try testing.expectEqual(@as(u64, 4_000), waitMs(policy, 3, null, 0));
    try testing.expectEqual(@as(u64, 8_000), waitMs(policy, 4, null, 0));

    try testing.expectEqual(@as(u64, 30_000), waitMs(policy, 40, null, 0));
    try testing.expectEqual(@as(u64, 59_970), waitMs(policy, 40, null, jitter_scale - 1));
}

test "the attempts are bounded, and a policy of one attempt never retries at all" {
    const policy = Policy{ .max_attempts = 3 };

    try testing.expect(decide(policy, .rate_limited, 1, null, 0) == .wait_ms);
    try testing.expect(decide(policy, .rate_limited, 2, null, 0) == .wait_ms);
    try testing.expectEqual(Stop.attempts_spent, decide(policy, .rate_limited, 3, null, 0).stop);
    try testing.expectEqual(Stop.attempts_spent, decide(policy, .rate_limited, 9, null, 0).stop);

    const once = Policy{ .max_attempts = 1 };
    try testing.expectEqual(Stop.attempts_spent, decide(once, .rate_limited, 1, null, 0).stop);
}

test "a Retry-After longer than the policy holds for ends the session instead of being clamped" {
    const policy = Policy{ .max_retry_after_ms = 300_000 };

    try testing.expect(decide(policy, .rate_limited, 1, 300, 0) == .wait_ms);
    try testing.expectEqual(Stop.wait_too_long, decide(policy, .rate_limited, 1, 301, 0).stop);
    try testing.expectEqual(
        Stop.wait_too_long,
        decide(policy, .rate_limited, 1, std.math.maxInt(u64), 0).stop,
    );
}

test "Retry-After is read as seconds, and a date form reads as nothing rather than as a guess" {
    try testing.expectEqual(@as(?u64, 30), retryAfterSeconds("30"));
    try testing.expectEqual(@as(?u64, 0), retryAfterSeconds("0"));
    try testing.expectEqual(@as(?u64, 5), retryAfterSeconds("  5 "));

    // RFC 9110 allows a date here. Reading one would need a clock and a date parser, and the backoff already answers the question, so a date reads as null and the exponential step is what waits.
    try testing.expectEqual(@as(?u64, null), retryAfterSeconds("Wed, 21 Oct 2015 07:28:00 GMT"));
    try testing.expectEqual(@as(?u64, null), retryAfterSeconds(""));
    try testing.expectEqual(@as(?u64, null), retryAfterSeconds("-1"));
    try testing.expectEqual(@as(?u64, null), retryAfterSeconds("2.5"));
    try testing.expectEqual(@as(?u64, null), retryAfterSeconds("9" ** 30));
}

test "a jitter value is always inside the scale the arithmetic assumes" {
    var seen_any = false;
    for (0..64) |_| {
        const value = jitterFrom(testing.io);
        try testing.expect(value < jitter_scale);
        seen_any = true;
    }
    try testing.expect(seen_any);
}
