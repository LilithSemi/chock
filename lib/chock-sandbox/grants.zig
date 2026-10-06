//! Whether one path is at or below another, and whether a set of paths holds
//! it.

const std = @import("std");

pub fn holds(parent: []const u8, child: []const u8) bool {
    if (parent.len == 0 or child.len == 0) return false;
    if (std.mem.eql(u8, parent, "/")) return true;
    if (!std.mem.startsWith(u8, child, parent)) return false;
    return child.len == parent.len or child[parent.len] == '/';
}

pub fn setHolds(set: []const []const u8, child: []const u8) bool {
    for (set) |parent| {
        if (holds(parent, child)) return true;
    }
    return false;
}

test "a path below a parent is held, and a name that only starts the same way is not" {
    try std.testing.expect(holds("/work", "/work/src/main.zig"));
    try std.testing.expect(holds("/work", "/work"));
    try std.testing.expect(!holds("/work", "/etc/passwd"));
    try std.testing.expect(!holds("/work", "/work-of-someone-else/key"));
    try std.testing.expect(holds("/", "/anything/at/all"));
    try std.testing.expect(!holds("", "/anything"));
    try std.testing.expect(!holds("/work", ""));
}

test "a set holds a path when one of its members does, and an empty set holds none" {
    const set = [_][]const u8{ "/nix/store", "/work" };
    try std.testing.expect(setHolds(&set, "/nix/store/abc-glibc/lib/libc.so.6"));
    try std.testing.expect(setHolds(&set, "/work/build.zig"));
    try std.testing.expect(!setHolds(&set, "/etc/shadow"));
    try std.testing.expect(!setHolds(&.{}, "/work/build.zig"));
}
