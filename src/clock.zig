//! What time it is, and which offset the person running this session states a
//! time in. See `lib/chock-core/notices.zig`: the loop tells the agent the
//! time, and this is where the two numbers that notice needs come from.
//!
//! **Local time and UTC answer different questions, so both are carried.**
//! Whether somebody is awake to answer an approval is a local question.
//! Lining a session up with a log is a UTC one. A model that had to convert
//! between them would get it wrong silently.
//!
//! **The offset is read from the operating system's own database and never
//! guessed.** `/etc/localtime` is a TZif file on Linux and on macOS alike, and
//! `std.tz` already parses one, so this file only picks the rule that applies
//! right now. A machine with no such file gets UTC, which is the honest answer
//! for a machine that did not say: see `notices.Clock.utc_offset_minutes`.

const std = @import("std");
const chock_core = @import("chock-core");

/// Where the operating system keeps the rules for the machine's own zone.
const localtime_path = "/etc/localtime";

/// The largest `/etc/localtime` this reads. A zone file is a few kilobytes;
/// anything past this is not one, and a bound stops a wrong path from being
/// read into memory without limit.
const max_zone_bytes: usize = 512 * 1024;

/// Reads the machine's real clock and states a local time in the offset this
/// machine uses. One per session, built in `src/run.zig` before the loop
/// starts.
pub const Real = struct {
    io: std.Io,
    /// Minutes east of UTC. Zero when the zone could not be read.
    offset_minutes: i32 = 0,

    pub fn clock(self: *const Real) chock_core.notices.Clock {
        return .{
            .ctx = @constCast(self),
            .nowMs = nowMs,
            .utc_offset_minutes = self.offset_minutes,
        };
    }

    fn nowMs(ctx: ?*anyopaque) i64 {
        const self: *const Real = @ptrCast(@alignCast(ctx.?));
        return std.Io.Timestamp.now(self.io, .real).toMilliseconds();
    }
};

/// How far the machine's own zone is from UTC at `at_ms`, in minutes east.
///
/// **Read at a moment, and not once for the zone**, because a zone that keeps
/// summer time is two different offsets in one year, and a session that starts
/// in one and runs into the other would otherwise state the wrong time from
/// then on.
///
/// Zero for anything this cannot read: an absent file, a file that is not
/// TZif, or a zone with no rule covering `at_ms`. **A wrong offset is worse
/// than none**, because the question a local time answers is whether a person
/// is asleep.
pub fn localOffsetMinutes(gpa: std.mem.Allocator, io: std.Io, at_ms: i64) i32 {
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        localtime_path,
        gpa,
        .limited(max_zone_bytes),
    ) catch return 0;
    defer gpa.free(bytes);

    var reader: std.Io.Reader = .fixed(bytes);
    var zone = std.tz.Tz.parse(gpa, &reader) catch return 0;
    defer zone.deinit();

    const seconds = @divFloor(at_ms, 1000);
    const offset_seconds = offsetSecondsAt(zone.transitions, seconds) orelse return 0;
    return @intCast(@divTrunc(offset_seconds, 60));
}

/// The offset in seconds that applies at `seconds`, or null when no rule in
/// `transitions` covers it.
///
/// **The rule that applies is the last one that started at or before the
/// moment asked about.** A transition list is in order, so this is the last
/// entry whose own time is not in the future.
///
/// Its own function, taking the list rather than a file, so that a test can
/// name two rules and a moment and pin which one is chosen. That choice is the
/// only part of this file that can be wrong in a way a person would not see.
pub fn offsetSecondsAt(transitions: []const std.tz.Transition, seconds: i64) ?i32 {
    var found: ?i32 = null;
    for (transitions) |transition| {
        if (transition.ts > seconds) break;
        found = transition.timetype.offset;
    }
    return found;
}

const testing = std.testing;

test "the offset that applies is the last rule that started, and a moment before them all has none" {
    var winter = std.tz.Timetype{ .offset = 3600, .flags = 0, .name_data = "CET\x00\x00\x00".* };
    var summer = std.tz.Timetype{ .offset = 7200, .flags = 1, .name_data = "CEST\x00\x00".* };

    const transitions = [_]std.tz.Transition{
        .{ .ts = 1000, .timetype = &winter },
        .{ .ts = 2000, .timetype = &summer },
        .{ .ts = 3000, .timetype = &winter },
    };

    // Before every rule: nothing applies, and nothing is guessed.
    try testing.expect(offsetSecondsAt(&transitions, 999) == null);

    // On the moment a rule starts, and between two of them.
    try testing.expectEqual(@as(i32, 3600), offsetSecondsAt(&transitions, 1000).?);
    try testing.expectEqual(@as(i32, 3600), offsetSecondsAt(&transitions, 1999).?);
    try testing.expectEqual(@as(i32, 7200), offsetSecondsAt(&transitions, 2000).?);
    // Summer ends, so the offset goes back. A reader that took the first rule,
    // or the largest one, would be wrong here and right everywhere else.
    try testing.expectEqual(@as(i32, 3600), offsetSecondsAt(&transitions, 5000).?);

    // A zone with no rules at all gives no offset.
    try testing.expect(offsetSecondsAt(&.{}, 5000) == null);
}
