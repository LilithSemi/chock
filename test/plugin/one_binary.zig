//! The build installs exactly one artifact, and it is `chock`. `build.zig`
//! walks its own install step and gives the names as `install_names.installed`,
//! because `zig build test` puts nothing in `zig-out/bin` and a stale directory
//! there shows programs this build no longer makes.

const std = @import("std");

const install_names = @import("install_names");

const testing = std.testing;

test "the build installs one artifact, and it is chock" {
    try testing.expectEqual(@as(usize, 1), install_names.installed.len);
    try testing.expectEqualStrings("chock", install_names.installed[0]);
}

test "no installed artifact is a helper program of its own" {
    var found: std.ArrayList(u8) = .empty;
    defer found.deinit(testing.allocator);

    for (install_names.installed) |name| {
        for ([_][]const u8{ "plugin", "host", "helper", "probe" }) |word| {
            if (std.mem.indexOf(u8, name, word) == null) continue;
            try found.print(testing.allocator, "{s} is installed beside chock\n", .{name});
        }
    }

    try testing.expectEqualStrings("", found.items);
}
