const std = @import("std");

const tty = @import("tty.zig");

pub const Kind = enum {
    config,
    data,
    state,
};

pub fn report(command: []const u8, kind: Kind) void {
    const variable = switch (kind) {
        .config => "XDG_CONFIG_HOME",
        .data => "XDG_DATA_HOME",
        .state => "XDG_STATE_HOME",
    };
    const directory = switch (kind) {
        .config => "configuration",
        .data => "data",
        .state => "state",
    };
    tty.print(
        .err,
        "chock {s}: set HOME or an absolute {s} to select the {s} directory\n",
        .{ command, variable, directory },
    );
}

test "directory guidance names the command, variable, and directory" {
    var capture: tty.Capture = undefined;
    capture.start(std.testing.io, std.testing.allocator);
    defer capture.stop(std.testing.io);

    report("models", .config);
    try std.testing.expectEqualStrings(
        "chock models: set HOME or an absolute XDG_CONFIG_HOME to select the configuration directory\n",
        capture.err(),
    );
}
