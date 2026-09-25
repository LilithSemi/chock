//! What the freedesktop secret service refused with, and what a person does
//! about it.
//!
//! Split from the driver so `store.zig` can name it on every platform. The
//! driver beside it imports the D-Bus library, which is a Linux only
//! dependency, so a macOS build cannot reach through it to read this.

const std = @import("std");

pub const Fault = enum {
    no_session_bus,
    service_unavailable,
    collection_locked,
    call_failed,
    bad_reply,
};

/// One sentence a person can act on, or null when the fault is all there is.
/// Mirrors `darwin/status.zig`.
pub fn adviceFor(fault_kind: Fault) ?[]const u8 {
    return switch (fault_kind) {
        .no_session_bus => "no D-Bus session bus is reachable. A machine reached only over ssh, or a " ++
            "service account, usually has none: use a desktop session, or set the credentials store " ++
            "to file instead.",
        .service_unavailable => "the freedesktop secret service is not running on the session bus. " ++
            "Start gnome-keyring, or another secret service implementation, and try again.",
        .collection_locked => "the default collection is locked and this session cannot unlock it: " ++
            "nobody is there to answer a prompt. A desktop login unlocks it, and so does " ++
            "secret-tool unlock --collection default. A machine reached only over ssh usually cannot.",
        .call_failed, .bad_reply => null,
    };
}

const testing = std.testing;

test "the three faults a person can act on each say something different" {
    const actionable = [_]Fault{ .no_session_bus, .service_unavailable, .collection_locked };
    for (actionable) |one| try testing.expect(adviceFor(one) != null);

    for (actionable, 0..) |one, i| {
        for (actionable[i + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, adviceFor(one).?, adviceFor(other).?));
        }
    }
}

test "a fault with nothing to advise says nothing rather than guessing" {
    try testing.expectEqual(@as(?[]const u8, null), adviceFor(.call_failed));
    try testing.expectEqual(@as(?[]const u8, null), adviceFor(.bad_reply));
}

test "the locked collection names both ways out, and neither is a prompt" {
    const locked = adviceFor(.collection_locked).?;
    try testing.expect(std.mem.indexOf(u8, locked, "desktop login") != null);
    try testing.expect(std.mem.indexOf(u8, locked, "secret-tool") != null);
    // The driver never calls Prompt, so the advice must not send a reader
    // looking for one.
    try testing.expect(std.mem.indexOf(u8, locked, "answer the prompt") == null);
}

test "no session bus points at the store that needs none" {
    const absent = adviceFor(.no_session_bus).?;
    try testing.expect(std.mem.indexOf(u8, absent, "file") != null);
}
