//! `nix_build` against the `nix` on this machine.
//!
//! Every other test of a build answers `nix` from a table, which is what
//! `lib/chock-nix/provision.zig` argues for: a test that builds a derivation
//! is not a test, it is a build. **A table still says what somebody thought
//! `nix` does.** This file is the one place a real `nix` process answers, so
//! the two facts a stand-in cannot pin are pinned here: that the argument
//! vector this project writes is one `nix` accepts, and that what `nix` wrote
//! when it would not build reaches the model as a sentence rather than as an
//! error name.
//!
//! **A machine with no `nix` skips.** `build.zig` finds the program once and
//! passes an empty string when there is none, the same way `test/broker` is
//! told where `git` is. A `nix` that cannot run at all skips too: a build
//! nothing tried is not a build that held.

const std = @import("std");
const chock_nix = @import("chock-nix");

/// Where `nix` is, from `build.zig`. Empty on a machine with none. Zig 0.16's
/// test runner takes no argument, so this is a build time constant.
const nix_path = @import("nix_path").nix_path;

const testing = std.testing;

/// A session that has evaluated one derivation, which is what a build has to
/// have behind it. The engine is the real one, so the derivation path is the
/// one Nix itself computes.
fn producingDriver(allocator: std.mem.Allocator) !chock_nix.backend.Driver {
    var driver = chock_nix.backend.Driver.init(allocator, chock_nix.build.evaluating);
    errdefer driver.deinit();

    var session = try chock_nix.eval.Session.init(allocator, .{ .store_writes = true, .store_backend = driver.backend() });
    defer session.deinit();

    var buffer: [512]u8 = undefined;
    const answer = try session.answer(&buffer,
        \\derivation { name = "x"; builder = "/bin/sh"; system = "x86_64-linux"; }
    );
    try session.ensureDerivation(answer.derivation_path.?);
    return driver;
}

/// The one derivation `producingDriver` produced.
fn drvPathOf(driver: *chock_nix.backend.Driver) ?[]const u8 {
    var keys = driver.paths.keyIterator();
    while (keys.next()) |key| {
        if (std.mem.endsWith(u8, key.*, ".drv")) return key.*;
    }
    return null;
}

test "a real nix that will not build answers in its own words, and the model reads a sentence" {
    if (nix_path.len == 0) return error.SkipZigTest;

    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var driver = try producingDriver(gpa);
    defer driver.deinit();
    const drv = drvPathOf(&driver).?;

    // The host's own environment is not reachable from a test, so `nix` gets
    // an empty one. It refuses this request long before it wants a daemon or
    // a store, and the refusal is the point.
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();

    var host = chock_nix.provision.Host{ .nix_program = nix_path, .env = &env };

    const installable = "/nonexistent-flake-for-this-test#packages.x86_64-linux.default";
    const answer = chock_nix.build.realise(arena, io, host.runner(), &driver, .{
        .derivation_path = drv,
        .installable = installable,
    }) catch |err| switch (err) {
        // This machine has a `nix` that will not start. Nothing was tried, so
        // nothing is claimed.
        error.RunnerFailed => return error.SkipZigTest,
        else => return err,
    };

    try testing.expect(answer == .refused);
    // What the model reads names the thing it asked for. A bare error name
    // would leave it sending the same attribute again.
    try testing.expect(std.mem.indexOf(u8, answer.refused, installable) != null);
    try testing.expect(answer.refused.len > installable.len);
}

test "a build of a path this session never produced never reaches the nix on this machine" {
    if (nix_path.len == 0) return error.SkipZigTest;

    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A driver that evaluated nothing. Every other part of this call is the
    // real one, including the `nix` it would run.
    var driver = chock_nix.backend.Driver.init(gpa, chock_nix.build.evaluating);
    defer driver.deinit();

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var host = chock_nix.provision.Host{ .nix_program = nix_path, .env = &env };

    const other = "/nix/store/11111111111111111111111111111111-other.drv";
    const answer = try chock_nix.build.realise(arena, io, host.runner(), &driver, .{
        .derivation_path = other,
        .installable = "/nonexistent-flake-for-this-test#packages.x86_64-linux.default",
    });

    try testing.expect(answer == .refused);
    // The driver's own words, which name the path and say what was wrong with
    // it. Nix says nothing like this, so a refusal holding it is proof the
    // process was never started.
    try testing.expect(std.mem.indexOf(u8, answer.refused, other) != null);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "did not produce") != null);
}
