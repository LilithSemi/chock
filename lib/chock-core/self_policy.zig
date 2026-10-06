//! The bridge between a promise as the session log holds it and a
//! promise as the ratchet reads it.

const std = @import("std");
const chock_proto = @import("chock-proto");
const chock_policy = @import("chock-policy");

const event = chock_proto.event;
const ratchet = chock_policy.ratchet;

pub fn restrictionsFrom(
    allocator: std.mem.Allocator,
    folded: []const event.SelfRestriction,
) std.mem.Allocator.Error![]ratchet.Restriction {
    const out = try allocator.alloc(ratchet.Restriction, folded.len);
    for (folded, out) |from, *slot| {
        slot.* = .{
            .action = from.action,
            .ceiling = ratchet.ceilingFromLog(from.ceiling.wireName()),
            .reason = from.reason,
        };
    }
    return out;
}

pub fn wireCeiling(decision: chock_policy.table.Decision) event.PolicyCeiling {
    return switch (decision) {
        .deny => .deny,
        .agent_then_human => .agent_then_human,
        .ask => .ask,
        .agent_review => .agent_review,
        .allow => .allow,
    };
}

const testing = std.testing;

test "every ceiling the wire carries reads back as the decision of the same name" {
    const gpa = testing.allocator;

    const wire = [_]event.PolicyCeiling{ .deny, .agent_then_human, .ask, .agent_review, .allow };
    const want = [_]chock_policy.table.Decision{ .deny, .agent_then_human, .ask, .agent_review, .allow };
    try testing.expectEqual(
        @typeInfo(chock_policy.table.Decision).@"enum".fields.len,
        wire.len,
    );
    try testing.expectEqual(wire.len + 1, @typeInfo(event.PolicyCeiling).@"union".fields.len);

    var restrictions: [wire.len]event.SelfRestriction = undefined;
    for (wire, &restrictions) |ceiling, *slot| {
        slot.* = .{ .action = "git.push", .ceiling = ceiling, .reason = "why" };
    }

    const read = try restrictionsFrom(gpa, &restrictions);
    defer gpa.free(read);
    for (read, want, wire) |one, wanted, ceiling| {
        try testing.expectEqual(wanted, one.ceiling);
        try testing.expectEqualStrings(@tagName(wanted), ceiling.wireName());
        try testing.expectEqualStrings("git.push", one.action);
        try testing.expectEqualStrings("why", one.reason);
        try testing.expectEqualStrings(ceiling.wireName(), wireCeiling(wanted).wireName());
        try testing.expectEqual(wanted, ratchet.ceilingFromLog(wireCeiling(wanted).wireName()));
    }
}

test "a ceiling from a newer writer crosses over as deny, never as permission" {
    const gpa = testing.allocator;

    const restrictions = [_]event.SelfRestriction{
        .{ .action = "net.fetch", .ceiling = .{ .unknown = "ask_two_people" }, .reason = "newer" },
        .{ .action = "git.push", .ceiling = .ask, .reason = "older" },
    };
    const read = try restrictionsFrom(gpa, &restrictions);
    defer gpa.free(read);

    try testing.expectEqual(chock_policy.table.Decision.deny, read[0].ceiling);
    try testing.expectEqual(chock_policy.table.Decision.ask, read[1].ceiling);

    const none = try restrictionsFrom(gpa, &.{});
    defer gpa.free(none);
    try testing.expectEqual(@as(usize, 0), none.len);
    try testing.expectEqual(
        chock_policy.table.Decision.allow,
        ratchet.ceilingFor(none, "net.fetch"),
    );
}
