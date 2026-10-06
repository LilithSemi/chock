//! What time it is, and the offset the running session states it in.
//! Chock reads both local time and UTC, because they answer different questions.

const std = @import("std");
const chock_core = @import("chock-core");

const localtime_path = "/etc/localtime";

const max_zone_bytes: usize = 512 * 1024;

pub const Real = struct {
    io: std.Io,
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

    try testing.expect(offsetSecondsAt(&transitions, 999) == null);

    try testing.expectEqual(@as(i32, 3600), offsetSecondsAt(&transitions, 1000).?);
    try testing.expectEqual(@as(i32, 3600), offsetSecondsAt(&transitions, 1999).?);
    try testing.expectEqual(@as(i32, 7200), offsetSecondsAt(&transitions, 2000).?);
    try testing.expectEqual(@as(i32, 3600), offsetSecondsAt(&transitions, 5000).?);

    try testing.expect(offsetSecondsAt(&.{}, 5000) == null);
}
