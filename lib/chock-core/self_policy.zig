//! The one bridge between a promise as the session log holds it and a promise
//! as the ratchet reads it.
//!
//! `chock_proto.event.SelfRestriction` is the wire form, folded by
//! `chock_proto.state.SelfPolicy`. `chock_policy.ratchet.Restriction` is the
//! form the rule is written over. `chock-policy` imports no other chock
//! library, on purpose, so the two cannot be one type and something has to
//! carry each promise across.
//!
//! **It is one function, in one file, because two callers need it and neither
//! may own it.** `lib/chock-core/Loop.zig` reads the promises to decide whether
//! a new one narrows or widens, and `src/run.zig` reads the same promises to
//! hand them to the broker at the end of the session. A second copy of this
//! conversion is a second answer to what a ceiling this build cannot read
//! means, and that answer is the one thing here that must not be got wrong:
//! see `chock_policy.ratchet.ceilingFromLog`.

const std = @import("std");
const chock_proto = @import("chock-proto");
const chock_policy = @import("chock-policy");

const event = chock_proto.event;
const ratchet = chock_policy.ratchet;

/// Every promise of `folded`, in the form the ratchet reads. The caller owns
/// the slice; every string in it still belongs to the session that was folded.
///
/// **A ceiling this build does not know becomes `deny`**, which is
/// `ratchet.ceilingFromLog`'s rule and not one of this file's. A promise
/// written by a later Chock is still a promise, and the reading that keeps it
/// is the narrow one.
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

/// The wire spelling of one ceiling, for a promise about to be written into
/// the log.
///
/// **An exhaustive switch and not a name lookup**, so a member added to
/// `Decision` and not to `event.PolicyCeiling`, or the other way round, fails
/// the build here. The two vocabularies are written out twice because neither
/// library may import the other, and this is the one place that would silently
/// paper over the difference.
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
    // Every member of the wire union except `unknown`, which is not a ceiling
    // a writer picks.
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
        // The round trip: what is written is what is read back. A promise that
        // changed meaning on its way through the log would be a promise the
        // agent never made.
        try testing.expectEqualStrings(ceiling.wireName(), wireCeiling(wanted).wireName());
        try testing.expectEqual(wanted, ratchet.ceilingFromLog(wireCeiling(wanted).wireName()));
    }
}

test "a ceiling from a newer writer crosses over as deny, never as permission" {
    // The one rule of this conversion that can be got wrong in a way nothing
    // else would catch. A promise this build cannot measure has to be read as
    // the narrowest thing there is, or a session could widen its own word by
    // being resumed under an older Chock.
    const gpa = testing.allocator;

    const restrictions = [_]event.SelfRestriction{
        .{ .action = "net.fetch", .ceiling = .{ .unknown = "ask_two_people" }, .reason = "newer" },
        .{ .action = "git.push", .ceiling = .ask, .reason = "older" },
    };
    const read = try restrictionsFrom(gpa, &restrictions);
    defer gpa.free(read);

    try testing.expectEqual(chock_policy.table.Decision.deny, read[0].ceiling);
    // The one beside it is untouched, so the line above is about the unknown
    // name and not about this function denying everything.
    try testing.expectEqual(chock_policy.table.Decision.ask, read[1].ceiling);

    // And a session that promised nothing converts to nothing, which is the
    // ordinary case and must not allocate a promise out of thin air.
    const none = try restrictionsFrom(gpa, &.{});
    defer gpa.free(none);
    try testing.expectEqual(@as(usize, 0), none.len);
    try testing.expectEqual(
        chock_policy.table.Decision.allow,
        ratchet.ceilingFor(none, "net.fetch"),
    );
}
