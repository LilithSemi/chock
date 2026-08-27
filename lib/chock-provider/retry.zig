//! When to send a refused request again, and how long to wait first.
//!
//! `failure.zig` says what a refusal **is**. This file says what to **do**
//! about it, for the two classes a wait can fix: `rate_limited` and
//! `transient`. A `context_overflow` and a `permanent` refusal never reach a
//! wait, because no wait makes either of them succeed.
//!
//! **This is not compaction, and the two must not be joined.** A limit on
//! input tokens per minute is partly a context size problem, so folding the
//! context would also make the next request less likely to be refused. That
//! does not make a 429 a compaction trigger: it is a transport failure that a
//! wait fixes, and a harness that compacted on one would throw away turns
//! nothing was wrong with. Keeping the two apart is the whole reason
//! `failure.Class` has four members.
//!
//! ## Why this file exists
//!
//! A session measured on 2026-08-22 ended on
//! `status 429 (rate_limited): ... would exceed your rate limit of 500,000
//! input tokens per minute`. The classification was right, the message was
//! right, and nothing waited, so 105 changed files went with it. ai& sends
//! `Retry-After` on a 429, and its own documentation asks for backoff with
//! jitter.
//!
//! ## Three rules
//!
//! * **`Retry-After` wins when the provider sends one.** The provider knows
//!   its own window and this reader does not. See `waitMs`.
//! * **A retry that hammers is worse than a failure.** The measured limit was
//!   on input tokens per minute, so the same large request sent again at once
//!   meets the same limit and spends the attempt for nothing. Every wait this
//!   file returns is therefore at least half of the step it grew to: see
//!   `waitMs` on why the jitter adds and never subtracts.
//! * **The attempts are bounded.** When they run out the session ends and says
//!   how many were made and what the provider last said. A retry with no bound
//!   is a session that never ends.

const std = @import("std");
const failure = @import("failure.zig");

/// How many times to send one request, and how long to wait between two
/// attempts.
///
/// The defaults span one minute of waiting altogether, which is deliberate:
/// the limit this file was written for was a **per minute** one, so a policy
/// that gave up after a few seconds would give up while the window that
/// refused it was still open.
///
/// `max_attempts` of 1 turns the retry off, which is what a caller that wants
/// the old behaviour asks for and what the test named for it uses.
pub const Policy = struct {
    /// How many times one request is sent altogether, the first attempt
    /// included. Six, with the waits below, is about one minute of waiting in
    /// the worst case.
    max_attempts: usize = 6,
    /// The step the backoff starts from. Doubles at each attempt.
    first_wait_ms: u64 = 2_000,
    /// The largest step the doubling reaches. A minute, because the limit
    /// being waited out is measured in minutes.
    max_wait_ms: u64 = 60_000,
    /// The longest `Retry-After` this policy holds for. A provider that asks
    /// for longer than this is answered by ending the session and saying so:
    /// see `Stop.wait_too_long`. **Clamping it instead would send the request
    /// again inside a window the provider said was still shut**, which is the
    /// hammering this file exists to prevent.
    max_retry_after_ms: u64 = 300_000,
    /// How much a wait built from `Retry-After` may add on top of it. Only
    /// ever added, never taken off: the provider named a time and a wait
    /// shorter than that time is not honouring it. It exists so that many
    /// sessions refused in the same second do not all come back in the same
    /// later second.
    retry_after_spread_ms: u64 = 1_000,
};

/// Why a refused request is not sent again.
pub const Stop = enum {
    /// No wait makes this succeed: a `context_overflow`, which compaction
    /// answers, or a `permanent` refusal, which nothing answers.
    not_retryable,
    /// Every attempt `Policy.max_attempts` allows has been made.
    attempts_spent,
    /// The provider asked for a longer wait than `Policy.max_retry_after_ms`.
    wait_too_long,
};

/// What to do about one refused request. **A union and no boolean**, the same
/// rule `failure.Class` follows: a caller has to name the case it handles.
pub const Decision = union(enum) {
    /// Send the same request again, after this many milliseconds.
    wait_ms: u64,
    /// Do not send it again. The session ends, and `Stop` says why.
    stop: Stop,
};

/// How finely the jitter divides the amount it can add. A jitter value is any
/// number below this, read as that fraction of the whole.
///
/// A fraction and not a random number generator, so that every wait this file
/// returns is a pure function of its arguments and a test can pin the exact
/// millisecond. `jitterFrom` is where the randomness comes from, and it is the
/// one function here that reads anything outside its arguments.
pub const jitter_scale: u64 = 1024;

/// A jitter value for one wait, read from the same source of randomness a
/// session identifier uses.
///
/// Kept apart from `waitMs` and `decide` on purpose: those two stay pure, so
/// the arithmetic below is testable without a clock and without a seed.
pub fn jitterFrom(io: std.Io) u64 {
    var bytes: [8]u8 = undefined;
    io.random(&bytes);
    // A remainder, not `uintLessThan`: rejection sampling can loop, and the
    // bias of a remainder over 1024 is meaningless for a nap.
    return std.mem.readInt(u64, &bytes, .little) % jitter_scale;
}

/// How long to wait before attempt number `attempts_made + 1`.
///
/// **`retry_after_s` decides when the provider sent one.** The wait is then
/// exactly that long, plus at most `Policy.retry_after_spread_ms` of jitter on
/// top. The jitter only ever adds: a wait shorter than the time the provider
/// named is not honouring it, and it is a second request inside a window that
/// is still shut.
///
/// **With no `Retry-After`, the step doubles from `Policy.first_wait_ms` and
/// stops at `Policy.max_wait_ms`.** The jitter then takes the step's own
/// second half: the wait is between half the step and the whole step, never
/// less. This is "equal jitter" and not "full jitter", which can return zero,
/// and a wait of zero is the hammering this file exists to prevent.
///
/// `attempts_made` is how many times the request has already been sent, so it
/// is 1 for the first wait. `jitter` is below `jitter_scale`.
pub fn waitMs(policy: Policy, attempts_made: usize, retry_after_s: ?u64, jitter: u64) u64 {
    std.debug.assert(attempts_made >= 1);
    std.debug.assert(jitter < jitter_scale);

    if (retry_after_s) |seconds| {
        const asked = std.math.mul(u64, seconds, 1000) catch policy.max_retry_after_ms;
        return asked +| policy.retry_after_spread_ms * jitter / jitter_scale;
    }

    // The doubling, with two stopping points: the attempt count, and the
    // ceiling. Either one alone bounds this loop.
    var step = policy.first_wait_ms;
    var doubled: usize = 1;
    while (doubled < attempts_made and step < policy.max_wait_ms) : (doubled += 1) {
        step = std.math.mul(u64, step, 2) catch policy.max_wait_ms;
    }
    step = @min(step, policy.max_wait_ms);

    const half = step / 2;
    return half + half * jitter / jitter_scale;
}

/// What to do about a refusal of class `class`, after `attempts_made` sends of
/// the same request.
///
/// `retry_after_s` is what the provider's own `Retry-After` header said, or
/// null when it sent none or sent one in a form this library does not read:
/// see `retryAfterSeconds`.
pub fn decide(
    policy: Policy,
    class: failure.Class,
    attempts_made: usize,
    retry_after_s: ?u64,
    jitter: u64,
) Decision {
    switch (class) {
        // Compaction answers the first and nothing answers the second. See
        // this file's own top comment on why the overflow does not come here.
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

/// Read one `Retry-After` header value as a number of seconds.
///
/// **Only the delta-seconds form is read.** RFC 9110 allows an HTTP date
/// there as well, and reading one needs a clock and a date parser to answer a
/// question the backoff already answers on its own. A date therefore reads as
/// null, and the wait falls back to the exponential step, which is a wait and
/// never a hammer. Every provider Chock talks to sends the seconds form.
pub fn retryAfterSeconds(value: []const u8) ?u64 {
    const text = std.mem.trim(u8, value, " \t");
    if (text.len == 0) return null;
    for (text) |character| {
        if (!std.ascii.isDigit(character)) return null;
    }
    return std.fmt.parseInt(u64, text, 10) catch null;
}

/// The wait between two attempts at the same request, and the seam a test
/// drives instead of a real clock.
///
/// The same shape `chock_broker.Broker.Waiter` uses, and for the same reason:
/// a test that measured elapsed time would be slow and would still prove
/// nothing about the number it was given.
///
/// **`sleep` reports nothing and cannot fail.** A wait somebody canceled ends
/// early, and the caller reads its own cancellation at the next safe point,
/// which is where every other cancellation in a session is read. A `Sleeper`
/// that could refuse would be a second place a session can be stopped.
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

/// The real `Sleeper`: the machine's own monotonic clock.
///
/// `.awake` and not `.real`, because a nap is a length of time and not a point
/// in one, which is the same choice `Broker.SystemWaiter` makes.
pub const SystemSleeper = struct {
    /// This sleeper keeps no state. `Sleeper.ptr` must still hold a pointer,
    /// so it holds the address of this one byte. Nothing reads the byte.
    var anchor: u8 = 0;

    pub fn sleeper() Sleeper {
        return .{ .ptr = &anchor, .vtable = &vtable };
    }

    const vtable = Sleeper.VTable{ .sleep = sleepFn };

    fn sleepFn(ptr: *anyopaque, io: std.Io, wait_ms: u64) void {
        _ = ptr;
        std.Io.sleep(io, .fromMilliseconds(@intCast(wait_ms)), .awake) catch |err| switch (err) {
            // The caller reads its own cancellation at its next safe point.
            // See `Sleeper`'s own doc comment.
            error.Canceled => {},
        };
    }
};

const testing = std.testing;

test "a rate limit and a server fault are retried, and an overflow and a bad request are not" {
    const policy = Policy{};

    // The two a wait fixes.
    try testing.expect(decide(policy, .rate_limited, 1, null, 0) == .wait_ms);
    try testing.expect(decide(policy, .transient, 1, null, 0) == .wait_ms);

    // **The pair this whole mechanism must keep apart.** A context overflow
    // goes to compaction, and sending it again cannot work, so it must never
    // reach a wait. A permanent refusal is the same fact for a different
    // reason.
    try testing.expectEqual(Stop.not_retryable, decide(policy, .context_overflow, 1, null, 0).stop);
    try testing.expectEqual(Stop.not_retryable, decide(policy, .permanent, 1, null, 0).stop);
}

test "the wait is exactly what Retry-After asked for, plus jitter that only ever adds" {
    // **The rule of `Retry-After`.** The provider knows its own
    // window. A wait shorter than the one it named is a second request inside
    // a window that is still shut.
    const policy = Policy{ .retry_after_spread_ms = 1_000 };

    // No jitter is the naked promise: 12 seconds asked for, 12 seconds waited.
    try testing.expectEqual(@as(u64, 12_000), waitMs(policy, 1, 12, 0));
    // Half of the spread, and the whole of it, both land above the asked time
    // and never below it.
    try testing.expectEqual(@as(u64, 12_500), waitMs(policy, 1, 12, jitter_scale / 2));
    try testing.expectEqual(@as(u64, 12_999), waitMs(policy, 1, 12, jitter_scale - 1));

    // And the attempt number does not shorten it. A provider that asked for
    // 12 seconds on the fourth attempt still gets 12 seconds.
    try testing.expectEqual(@as(u64, 12_000), waitMs(policy, 4, 12, 0));
}

test "with no Retry-After the step doubles, is never zero, and stops at the ceiling" {
    const policy = Policy{ .first_wait_ms = 2_000, .max_wait_ms = 60_000 };

    // Equal jitter: the wait is between half the step and the whole step.
    // **Never zero**, which is what separates this from full jitter and is
    // the whole of "a retry that hammers is worse than a failure".
    try testing.expectEqual(@as(u64, 1_000), waitMs(policy, 1, null, 0));
    try testing.expectEqual(@as(u64, 1_999), waitMs(policy, 1, null, jitter_scale - 1));

    try testing.expectEqual(@as(u64, 2_000), waitMs(policy, 2, null, 0));
    try testing.expectEqual(@as(u64, 4_000), waitMs(policy, 3, null, 0));
    try testing.expectEqual(@as(u64, 8_000), waitMs(policy, 4, null, 0));

    // The ceiling holds, however many attempts are asked about.
    try testing.expectEqual(@as(u64, 30_000), waitMs(policy, 40, null, 0));
    try testing.expectEqual(@as(u64, 59_970), waitMs(policy, 40, null, jitter_scale - 1));
}

test "the attempts are bounded, and a policy of one attempt never retries at all" {
    const policy = Policy{ .max_attempts = 3 };

    try testing.expect(decide(policy, .rate_limited, 1, null, 0) == .wait_ms);
    try testing.expect(decide(policy, .rate_limited, 2, null, 0) == .wait_ms);
    // The third send was the last one this policy allows.
    try testing.expectEqual(Stop.attempts_spent, decide(policy, .rate_limited, 3, null, 0).stop);
    try testing.expectEqual(Stop.attempts_spent, decide(policy, .rate_limited, 9, null, 0).stop);

    // One attempt is the old behaviour: refused once, ended.
    const once = Policy{ .max_attempts = 1 };
    try testing.expectEqual(Stop.attempts_spent, decide(once, .rate_limited, 1, null, 0).stop);
}

test "a Retry-After longer than the policy holds for ends the session instead of being clamped" {
    // Clamping would send the request again inside a window the provider said
    // was still shut, which is the hammering this file exists to prevent.
    const policy = Policy{ .max_retry_after_ms = 300_000 };

    try testing.expect(decide(policy, .rate_limited, 1, 300, 0) == .wait_ms);
    try testing.expectEqual(Stop.wait_too_long, decide(policy, .rate_limited, 1, 301, 0).stop);
    // A value large enough to overflow the multiply is the same answer, not a
    // crash and not a wait of nothing.
    try testing.expectEqual(
        Stop.wait_too_long,
        decide(policy, .rate_limited, 1, std.math.maxInt(u64), 0).stop,
    );
}

test "Retry-After is read as seconds, and a date form reads as nothing rather than as a guess" {
    try testing.expectEqual(@as(?u64, 30), retryAfterSeconds("30"));
    try testing.expectEqual(@as(?u64, 0), retryAfterSeconds("0"));
    try testing.expectEqual(@as(?u64, 5), retryAfterSeconds("  5 "));

    // RFC 9110 allows a date here. Reading one needs a clock and a date
    // parser, and the backoff already answers the question, so a date reads as
    // null and the exponential step is what waits.
    try testing.expectEqual(@as(?u64, null), retryAfterSeconds("Wed, 21 Oct 2015 07:28:00 GMT"));
    try testing.expectEqual(@as(?u64, null), retryAfterSeconds(""));
    try testing.expectEqual(@as(?u64, null), retryAfterSeconds("-1"));
    try testing.expectEqual(@as(?u64, null), retryAfterSeconds("2.5"));
    // Larger than a u64 holds. Null, never a wrapped number.
    try testing.expectEqual(@as(?u64, null), retryAfterSeconds("9" ** 30));
}

test "a jitter value is always inside the scale the arithmetic assumes" {
    // `waitMs` asserts this, so a source that could answer outside the scale
    // would be a crash in a release build's absence of that assert.
    var seen_any = false;
    for (0..64) |_| {
        const value = jitterFrom(testing.io);
        try testing.expect(value < jitter_scale);
        seen_any = true;
    }
    try testing.expect(seen_any);
}
