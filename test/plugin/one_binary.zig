//! One binary, and this file is what says so.
//!
//! **Chock is a static binary that links no libc, and Zig cross compiles it.**
//! That is the hard part of shipping to somebody who does not run Nix, and it
//! is already true. A second installed program throws it away: it has to be
//! found at run time, on a machine nobody here can see, and the way it was
//! found was to look in the directory `chock` itself is in. So any install that
//! moved one file and not the other lost every plugin, and said so in a warning
//! on standard error.
//!
//! The fix was to fold the plugin host into `chock` under a hidden word, and a
//! fold is not something that stays folded. `b.installArtifact` is one line,
//! nothing about writing it looks wrong, and what it costs shows up on somebody
//! else's machine months later. **So the install list is a measurement, not a
//! habit.**
//!
//! ## What this reads, and why it is not `zig-out/bin`
//!
//! `build.zig` walks its own install step, collects the name of every artifact
//! that is installed, and hands the list over as `install_names.installed`.
//! Listing `zig-out/bin` instead would be wrong in both directions: `zig build
//! test` installs nothing, so a clean tree would show none, and a directory left
//! over from an older build would show a program this build no longer produces.
//!
//! The plugin host is still a process of its own, and `test/plugin/engine.zig`
//! is where that is measured: it starts `chock` under
//! `chock_core.plugin_host.verb` and reads a real guest's real answer back.

const std = @import("std");

const install_names = @import("install_names");

const testing = std.testing;

test "the build installs one artifact, and it is chock" {
    // Mutation check: add `b.installArtifact` for anything at all in
    // `build.zig` and this fails by name.
    try testing.expectEqual(@as(usize, 1), install_names.installed.len);
    try testing.expectEqualStrings("chock", install_names.installed[0]);
}

test "no installed artifact is a helper program of its own" {
    // The specific thing that came back would come back under a name of its
    // own, so it is worth refusing by shape as well as by count. A build that
    // installed `chock` and one helper fails the test above too, but only by a
    // number: this one names the file.
    //
    // Mutation check: install a second program with `plugin`, `host`, `helper`
    // or `probe` in its name and this names it.
    //
    // Collected and compared against nothing at the end, the way
    // `test/proto/lock.zig` does it: `expectEqualStrings` prints both sides, so
    // the failure names the program rather than only saying that a count moved,
    // and nothing is written to standard error to say it.
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
