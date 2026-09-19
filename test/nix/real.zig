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

/// One fixed output derivation, which is the kind Nix builds with the network
/// open to it. The URL is a host nothing here ever reaches: the point is that
/// the real `nix derivation show -r` names it and the reader finds it.
fn evaluateFetchDerivation(
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
        "derivation {{ name = \"{s}\"; builder = \"/bin/sh\"; system = \"{s}\"; " ++
            "outputHashMode = \"flat\"; outputHashAlgo = \"sha256\"; " ++
            "outputHash = \"{s}\"; url = \"{s}\"; }}",
        .{ name, no_such_system, "0" ** 64, probe_url },
    );
    defer allocator.free(expression);

    var buffer: [512]u8 = undefined;
    const answer = try session.answer(&buffer, expression);
    try session.ensureDerivation(answer.derivation_path.?);
    return drvPathOf(driver).?;
}

/// The URL the fixed output probe fetches from, and the host inside it.
const probe_url = "https://files.chock-test.invalid/probe.tar.gz";
const probe_host = "files.chock-test.invalid";

/// A `chock_nix.fetch.Gate` that answers the same way about every host and
/// records what it was asked.
const RecordingGate = struct {
    gpa: std.mem.Allocator,
    permitted: bool,
    asked: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *RecordingGate) void {
        for (self.asked.items) |one| self.gpa.free(one);
        self.asked.deinit(self.gpa);
    }

    fn gate(self: *RecordingGate) chock_nix.fetch.Gate {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_nix.fetch.Gate.VTable{ .permit = permitFn };

    fn permitFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        one: chock_nix.fetch.Fetch,
    ) std.mem.Allocator.Error!chock_nix.fetch.Verdict {
        const self: *RecordingGate = @ptrCast(@alignCast(ptr));
        try self.asked.append(self.gpa, try self.gpa.dupe(u8, one.host));
        if (self.permitted) return .permitted;
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} fetches {s} from {s}, and no rule allows it",
            .{ one.subject, one.url, one.host },
        ) };
    }
};

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

    // Nothing of this closure fetches, so this gate is never asked. It is here
    // rather than the refusing one so that a reader that found a host would
    // fail the test below rather than pass it for the wrong reason.
    var gate = RecordingGate{ .gpa = gpa, .permitted = true };
    defer gate.deinit();

    const installable = "/nonexistent-flake-for-this-test#packages.x86_64-linux.default";
    const answer = chock_nix.build.realise(
        arena,
        io,
        host.runner(),
        &driver,
        gate.gate(),
        .{ .derivation_path = drv, .installable = installable },
    ) catch |err| switch (err) {
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
    try testing.expectEqual(@as(usize, 0), gate.asked.items.len);
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
    const answer = try chock_nix.build.realise(
        arena,
        io,
        host.runner(),
        &driver,
        chock_nix.fetch.Gate.refusing,
        .{
            .derivation_path = other,
            .installable = "/nonexistent-flake-for-this-test#packages.x86_64-linux.default",
        },
    );

    try testing.expect(answer == .refused);
    // The driver's own words, which name the path and say what was wrong with
    // it. Nix says nothing like this, so a refusal holding it is proof the
    // process was never started.
    try testing.expect(std.mem.indexOf(u8, answer.refused, other) != null);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "did not produce") != null);
}

test "a real closure holding a fixed output derivation names its host, and a no stops the build" {
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
    const drv = evaluateFetchDerivation(gpa, &driver, "chock-fetch-probe") catch
        return error.SkipZigTest;

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var host = chock_nix.provision.Host{ .nix_program = nix_path, .env = &env };

    // **What a table cannot pin.** The JSON is written by the `nix` on this
    // machine, and the reader has to find the output hash and the URL in the
    // shape that `nix` really writes.
    var gate = RecordingGate{ .gpa = gpa, .permitted = false };
    defer gate.deinit();

    const installable = "/nonexistent-flake-for-this-test#packages.x86_64-linux.default";
    const answer = chock_nix.build.realise(
        arena,
        io,
        host.runner(),
        &driver,
        gate.gate(),
        .{ .derivation_path = drv, .installable = installable },
    ) catch |err| switch (err) {
        error.RunnerFailed => return error.SkipZigTest,
        else => return err,
    };

    try testing.expectEqual(@as(usize, 1), gate.asked.items.len);
    try testing.expectEqualStrings(probe_host, gate.asked.items[0]);

    try testing.expect(answer == .refused);
    // The host is in the words, so the model can ask for that host rather than
    // send the same attribute again.
    try testing.expect(std.mem.indexOf(u8, answer.refused, probe_host) != null);
    try testing.expect(std.mem.indexOf(u8, answer.refused, installable) != null);
}

/// Run `nix` with these arguments on this machine and answer what it wrote on
/// standard output, with the trailing newline off. Null when it refused.
fn nixSaid(
    arena: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
) ?[]const u8 {
    var env = std.process.Environ.Map.init(arena);
    var host = chock_nix.provision.Host{ .nix_program = nix_path, .env = &env };
    const output = host.runner().run(arena, io, args) catch return null;
    if (!output.succeeded()) return null;
    return std.mem.trimEnd(u8, output.stdout, "\n");
}

fn writeAt(io: std.Io, dir: std.Io.Dir, name: []const u8, text: []const u8) !void {
    var file = try dir.createFile(io, name, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, text);
}

test "a flake input that is in the store already is evaluated with no fetcher at all" {
    // **The whole of the input mechanism, against the real thing.** A tree is
    // put in the host store, its NAR hash is read from the same `nix`, and a
    // lock pins an input to that hash. The lock's forge coordinates are never
    // reached: fix takes the store path the hash names, because the seam says
    // that path is valid. The second half of the test takes the path off the
    // seam and the same evaluation stops with no fetcher, which is what proves
    // the store hit and not the network is what answered.
    if (nix_path.len == 0) return error.SkipZigTest;

    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "dep");
    try tmp.dir.createDirPath(io, "root");

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const base = path_buffer[0..try tmp.dir.realPath(io, &path_buffer)];
    const dep_path = try std.fs.path.join(arena, &.{ base, "dep" });
    const root_path = try std.fs.path.join(arena, &.{ base, "root" });

    {
        var dep = try tmp.dir.openDir(io, "dep", .{});
        defer dep.close(io);
        try writeAt(io, dep, "flake.nix", "{ outputs = { self }: { value = 7; }; }\n");
    }

    // The store path and the hash come from the same `nix`, so the test never
    // computes either of them itself.
    const store_path = nixSaid(arena, io, &.{ "store", "add", "--name", "source", "--mode", "nar", dep_path }) orelse
        return error.SkipZigTest;
    const nar_hash = nixSaid(arena, io, &.{ "hash", "path", "--type", "sha256", "--sri", dep_path }) orelse
        return error.SkipZigTest;

    {
        var root = try tmp.dir.openDir(io, "root", .{});
        defer root.close(io);
        try writeAt(io, root, "flake.nix",
            \\{
            \\  inputs.dep.url = "github:chock/not-reached";
            \\  outputs = { self, dep }: {
            \\    drv = derivation {
            \\      name = "chock-input-probe";
            \\      builder = "/bin/sh";
            \\      system = "chock-test-not-a-system";
            \\      value = toString dep.value;
            \\    };
            \\  };
            \\}
            \\
        );
        try writeAt(io, root, "flake.lock", try std.fmt.allocPrint(arena,
            \\{{
            \\  "nodes": {{
            \\    "dep": {{
            \\      "locked": {{ "type": "github", "owner": "chock", "repo": "not-reached",
            \\        "rev": "0000000000000000000000000000000000000000", "narHash": "{s}",
            \\        "lastModified": 0 }},
            \\      "original": {{ "type": "github", "owner": "chock", "repo": "not-reached" }}
            \\    }},
            \\    "root": {{ "inputs": {{ "dep": "dep" }} }}
            \\  }},
            \\  "root": "root",
            \\  "version": 7
            \\}}
            \\
        , .{nar_hash}));
    }

    const expression = try chock_nix.build.expressionFor(arena, root_path, &.{"drv"});

    var store_writer = chock_nix.build.DaemonWriter.connect(
        gpa,
        io,
        chock_nix.build.default_daemon_socket,
    ) catch return error.SkipZigTest;
    defer store_writer.deinit();

    {
        var budget: chock_nix.build.Budget = .{};
        var writing = chock_nix.build.Writing{
            .writer = store_writer.writer(),
            .budget = &budget,
            .fetched_paths = &.{store_path},
        };
        var driver = chock_nix.backend.Driver.init(gpa, writing.seam());
        defer driver.deinit();

        var session = try chock_nix.eval.Session.init(gpa, .{
            .roots = &.{root_path},
            .io = io,
            .store_backend = driver.backend(),
            .store_writes = true,
            .flakes = true,
        });
        defer session.deinit();

        var buffer: [512]u8 = undefined;
        const answer = session.answer(&buffer, expression) catch return error.SkipZigTest;
        try testing.expect(answer.derivation_path != null);
    }

    // The same flake, the same lock, and nothing saying the input's path is
    // there. The evaluator has no fetcher, so it stops rather than reaching
    // the forge the lock names.
    {
        var budget: chock_nix.build.Budget = .{};
        var writing = chock_nix.build.Writing{
            .writer = store_writer.writer(),
            .budget = &budget,
        };
        var driver = chock_nix.backend.Driver.init(gpa, writing.seam());
        defer driver.deinit();

        var session = try chock_nix.eval.Session.init(gpa, .{
            .roots = &.{root_path},
            .io = io,
            .store_backend = driver.backend(),
            .store_writes = true,
            .flakes = true,
        });
        defer session.deinit();

        var buffer: [512]u8 = undefined;
        try testing.expectError(error.FetchIoUnavailable, session.answer(&buffer, expression));
    }
}
