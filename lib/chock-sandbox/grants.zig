//! Whether one path is at or below another, and whether a set of paths holds
//! it.
//!
//! **One judgement, in one place.** `Sandbox.firstGap` asks it of a Landlock
//! rule against the mount set. `linux/notify.zig` asks it of a path a
//! sandboxed program named, against that same mount set. The two answers have
//! to agree, because they are about the same boundary, and a second spelling
//! of a comparison is how two answers quietly stop agreeing. This project has
//! already paid for one judgement written twice: see `Sandbox.LayerGap`.
//!
//! Every path this compares is a **spelling** and never a file. Nothing here
//! opens anything, resolves a symbolic link, or asks the kernel a question.

const std = @import("std");

/// True when `parent` is `child`, or is a directory that holds `child`.
///
/// This is the reach of one `LANDLOCK_RULE_PATH_BENEATH` rule and the reach of
/// one mount, which are the same shape: both cover the named path and
/// everything below it. The comparison is on the spelling alone. Every mount
/// target, scratch area and rule path in this project is an absolute path with
/// no trailing separator and no `.` or `..` component, because each one is
/// built by `std.fs.path.join` or written out as a literal.
pub fn holds(parent: []const u8, child: []const u8) bool {
    if (parent.len == 0 or child.len == 0) return false;
    if (std.mem.eql(u8, parent, "/")) return true;
    if (!std.mem.startsWith(u8, child, parent)) return false;
    return child.len == parent.len or child[parent.len] == '/';
}

/// True when any member of `set` holds `child`. An empty set holds nothing.
pub fn setHolds(set: []const []const u8, child: []const u8) bool {
    for (set) |parent| {
        if (holds(parent, child)) return true;
    }
    return false;
}

test "a path below a parent is held, and a name that only starts the same way is not" {
    // **The separator check is the whole comparison.** Written with
    // `startsWith` alone, `/work` would hold `/work-of-someone-else`, and a
    // Landlock rule would read as covered by a mount that covers nothing of
    // it, and a path a program named outside every mount would read as one
    // inside.
    //
    // Mutation check: drop the final line's separator test and the fourth
    // expectation below fails.
    try std.testing.expect(holds("/work", "/work/src/main.zig"));
    try std.testing.expect(holds("/work", "/work"));
    try std.testing.expect(!holds("/work", "/etc/passwd"));
    try std.testing.expect(!holds("/work", "/work-of-someone-else/key"));
    // The root holds everything, which is the reach a rule on `/` really has.
    try std.testing.expect(holds("/", "/anything/at/all"));
    // Neither side may be empty. An empty parent would otherwise hold every
    // path through `startsWith`.
    try std.testing.expect(!holds("", "/anything"));
    try std.testing.expect(!holds("/work", ""));
}

test "a set holds a path when one of its members does, and an empty set holds none" {
    // Mutation check: make `setHolds` give back `true` for an empty set and
    // the last expectation fails.
    const set = [_][]const u8{ "/nix/store", "/work" };
    try std.testing.expect(setHolds(&set, "/nix/store/abc-glibc/lib/libc.so.6"));
    try std.testing.expect(setHolds(&set, "/work/build.zig"));
    try std.testing.expect(!setHolds(&set, "/etc/shadow"));
    try std.testing.expect(!setHolds(&.{}, "/work/build.zig"));
}
