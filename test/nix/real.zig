//! `nix_build` against the `nix` and the Nix store on this machine.
//!
//! Every other test of a build answers `nix` from a table and writes its
//! objects nowhere, which is what `lib/chock-nix/provision.zig` argues for: a
//! test that builds a derivation is not a test, it is a build. **A table
//! still says what somebody thought `nix` does.** This file is the one place
//! a real `nix` process and a real store answer, so the facts a stand-in
//! cannot pin are pinned here: that the derivation this session evaluated
//! lands in the host store at the path fix computed for it, that the argument
//! vector this project writes is one `nix` accepts, and that what `nix` wrote
//! when it would not build reaches the model as a sentence.
//!
//! **A machine with no `nix` skips, and so does one with no daemon.**
//! `build.zig` finds the program once and passes an empty string when there
//! is none, the same way `test/broker` is told where `git` is. A store this
//! cannot write to is a reason to skip: a build nothing tried is not a build
//! that held.

const std = @import("std");
const chock_nix = @import("chock-nix");

/// Where `nix` is, from `build.zig`. Empty on a machine with none. Zig 0.16's
/// test runner takes no argument, so this is a build time constant.
const nix_path = @import("nix_path").nix_path;

const testing = std.testing;

/// The system of every derivation here.
///
/// **No machine is this**, so a `nix` that is asked to build one of them
/// refuses for a reason it states itself, and no builder of ours ever runs on
/// the machine the tests are on.
const no_such_system = "chock-test-not-a-system";

/// One derivation this session evaluated, with its closure written through
/// `driver`'s seam. The evaluator is the real one, so the path is the one Nix
/// itself computes.
fn evaluateDerivation(
    allocator: std.mem.Allocator,
    driver: *chock_nix.backend.Driver,
    name: []const u8,
) ![]const u8 {
    var session = try chock_nix.eval.Session.init(allocator, .{
        .store_writes = true,
        .store_backend = driver.backend(),
    });
    defer session.deinit();

    const expression = try std.fmt.allocPrint(
        allocator,
        "derivation {{ name = \"{s}\"; builder = \"/bin/sh\"; system = \"{s}\"; }}",
        .{ name, no_such_system },
    );
    defer allocator.free(expression);

    var buffer: [512]u8 = undefined;
    const answer = try session.answer(&buffer, expression);
    try session.ensureDerivation(answer.derivation_path.?);
    return drvPathOf(driver).?;
}

/// The one derivation path `driver` holds.
fn drvPathOf(driver: *chock_nix.backend.Driver) ?[]const u8 {
    var keys = driver.paths.keyIterator();
    while (keys.next()) |key| {
        if (std.mem.endsWith(u8, key.*, ".drv")) return key.*;
    }
    return null;
}

test "the derivation this session evaluated is in the host store, at the path fix computed" {
    const gpa = testing.allocator;

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // This machine has no daemon to write to, so there is nothing to claim.
    var store_writer = chock_nix.build.DaemonWriter.connect(
        gpa,
        io,
        chock_nix.build.default_daemon_socket,
    ) catch return error.SkipZigTest;
    defer store_writer.deinit();

    var budget: chock_nix.build.Budget = .{};
    var writing = chock_nix.build.Writing{
        .writer = store_writer.writer(),
        .budget = &budget,
    };

    var driver = chock_nix.backend.Driver.init(gpa, writing.seam());
    defer driver.deinit();

    const drv = evaluateDerivation(gpa, &driver, "chock-store-write-probe") catch
        return error.SkipZigTest;

    // The seam refuses a path the store answered with that is not the one fix
    // computed, so a produced path is one both agree on. What is left to ask
    // is the store itself, through the connection that wrote it.
    try testing.expect(driver.produced(drv));
    try testing.expect(try store_writer.store.isValidPath(drv));
    try testing.expect(budget.written_bytes != 0);
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

    var store_writer = chock_nix.build.DaemonWriter.connect(
        gpa,
        io,
        chock_nix.build.default_daemon_socket,
    ) catch return error.SkipZigTest;
    defer store_writer.deinit();

    var budget: chock_nix.build.Budget = .{};
    var writing = chock_nix.build.Writing{
        .writer = store_writer.writer(),
        .budget = &budget,
    };

    var driver = chock_nix.backend.Driver.init(gpa, writing.seam());
    defer driver.deinit();
    const drv = evaluateDerivation(gpa, &driver, "chock-refused-build-probe") catch
        return error.SkipZigTest;

    // The host's own environment is not reachable from a test, so `nix` gets
    // an empty one. It refuses this derivation because no machine is its
    // system, and the refusal is the point.
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

    // A driver that evaluated nothing and wrote nothing. Every other part of
    // this call is the real one, including the `nix` it would run.
    var driver = chock_nix.backend.Driver.init(gpa, chock_nix.backend.Seam.refusing);
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
