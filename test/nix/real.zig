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

    const vtable = chock_nix.fetch.Gate.VTable{
        .permit = permitFn,
        .allows_by_rule = allowsNothing,
    };

    /// This gate reads no rule, so every host it is given is asked about.
    fn allowsNothing(_: *anyopaque, _: chock_nix.fetch.Fetch) bool {
        return false;
    }

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

/// A real mirrors list of this machine's own store, and the first `https`
/// mirror it names for the `gnu` site. Null when the store holds none, which
/// is a reason to skip: a file nothing read is not a file that was read.
///
/// **Found and not written.** A mirrors list this test made up would pin what
/// somebody thought nixpkgs writes, and the whole point of this file is that
/// the bytes are nixpkgs' own.
fn findMirrorsList(arena: std.mem.Allocator, io: std.Io) !?struct {
    path: []const u8,
    first_gnu_host: []const u8,
} {
    var store = std.Io.Dir.cwd().openDir(io, "/nix/store", .{ .iterate = true }) catch return null;
    defer store.close(io);

    var walk = store.iterate();
    while (walk.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, "-mirrors-list")) continue;

        const path = try std.fmt.allocPrint(arena, "/nix/store/{s}", .{entry.name});
        const text = std.Io.Dir.cwd().readFileAlloc(
            io,
            path,
            arena,
            .limited(chock_nix.fetch.max_mirrors_bytes),
        ) catch continue;

        const host = firstGnuHost(text) orelse continue;
        return .{ .path = path, .first_gnu_host = host };
    }
    return null;
}

/// The host of the first `https` mirror the `gnu` site names in `text`, read
/// by hand so that this test does not answer with the very parser it checks.
fn firstGnuHost(text: []const u8) ?[]const u8 {
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "_mirror_gnu=") == null and
            !std.mem.startsWith(u8, line, "gnu=")) continue;

        const mark = std.mem.indexOf(u8, line, "https://") orelse continue;
        const rest = line[mark + "https://".len ..];
        const end = std.mem.indexOfAny(u8, rest, "/ )") orelse rest.len;
        if (end == 0) continue;
        return rest[0..end];
    }
    return null;
}

/// One fixed output derivation that fetches through the `gnu` mirror site and
/// names a real mirrors list of this machine.
fn evaluateMirrorDerivation(
    allocator: std.mem.Allocator,
    driver: *chock_nix.backend.Driver,
    mirrors_path: []const u8,
) ![]const u8 {
    var session = try chock_nix.eval.Session.init(allocator, .{
        .store_writes = true,
        .store_backend = driver.backend(),
    });
    defer session.deinit();

    const expression = try std.fmt.allocPrint(
        allocator,
        "derivation {{ name = \"chock-mirror-probe\"; builder = \"/bin/sh\"; " ++
            "system = \"{s}\"; outputHashMode = \"flat\"; outputHashAlgo = \"sha256\"; " ++
            "outputHash = \"{s}\"; url = \"mirror://gnu/hello/hello-2.12.3.tar.gz\"; " ++
            "mirrorsFile = \"{s}\"; }}",
        .{ no_such_system, "0" ** 64, mirrors_path },
    );
    defer allocator.free(expression);

    var buffer: [512]u8 = undefined;
    const answer = try session.answer(&buffer, expression);
    try session.ensureDerivation(answer.derivation_path.?);
    return drvPathOf(driver).?;
}

test "a real mirrors list of this store turns the gnu site into one host, and a no names both" {
    if (nix_path.len == 0) return error.SkipZigTest;

    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const found = (try findMirrorsList(arena, io)) orelse return error.SkipZigTest;

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
    const drv = evaluateMirrorDerivation(gpa, &driver, found.path) catch
        return error.SkipZigTest;

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var host = chock_nix.provision.Host{ .nix_program = nix_path, .env = &env };

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

    // One question for a site that names eight mirrors, and it is the first
    // one the real file holds.
    try testing.expectEqual(@as(usize, 1), gate.asked.items.len);
    try testing.expectEqualStrings(found.first_gnu_host, gate.asked.items[0]);

    try testing.expect(answer == .refused);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "gnu") != null);
    try testing.expect(std.mem.indexOf(u8, answer.refused, found.first_gnu_host) != null);
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

/// A flake in a temporary directory whose one input is pinned by the NAR hash
/// of a tree this test put in the host store itself.
///
/// **The lock is not invented.** The hash is read from the same `nix` that
/// added the tree, so it really names that store path. The forge coordinates
/// in it are never reached: everything here answers out of the store, which is
/// what each test below proves in its own way.
const Project = struct {
    root: []const u8,
    /// What the lock pins the input to.
    input_path: []const u8,

    fn make(arena: std.mem.Allocator, io: std.Io, tmp: *std.testing.TmpDir) !?Project {
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

        const store_path = nixSaid(arena, io, &.{ "store", "add", "--name", "source", "--mode", "nar", dep_path }) orelse
            return null;
        const nar_hash = nixSaid(arena, io, &.{ "hash", "path", "--type", "sha256", "--sri", dep_path }) orelse
            return null;

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

        return .{ .root = root_path, .input_path = store_path };
    }

    /// The lock, read back the way `chock run` reads a project's own.
    fn lock(self: Project, arena: std.mem.Allocator, io: std.Io) ![]const u8 {
        const path = try std.fs.path.join(arena, &.{ self.root, "flake.lock" });
        return std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 20));
    }

    /// The reference `nix` is given. **`path:` and not the bare path**: a
    /// temporary directory of this suite sits inside this project's own git
    /// tree, and a bare path would have `nix` read that tree instead. A real
    /// project root is the root of its own tree, so `chock run` passes it bare.
    fn reference(self: Project, arena: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(arena, "path:{s}", .{self.root});
    }
};

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
    const project = (try Project.make(arena, io, &tmp)) orelse return error.SkipZigTest;

    const expression = try chock_nix.build.expressionFor(arena, project.root, &.{"drv"});

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
            .fetched_paths = &.{project.input_path},
        };
        var driver = chock_nix.backend.Driver.init(gpa, writing.seam());
        defer driver.deinit();

        var session = try chock_nix.eval.Session.init(gpa, .{
            .roots = &.{project.root},
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
            .roots = &.{project.root},
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

test "an evaluation that wanted an input asks about its hosts, and evaluates after a yes" {
    // **The retry, end to end, against a real `nix`.** The first evaluation
    // has nothing on the seam, so it stops the way a session that could ask
    // nobody at startup stops. The gate is then put every host the lock names,
    // says yes, and `nix flake archive` answers out of the store. The same
    // expression evaluates on the second pass with those paths on the seam.
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
    const project = (try Project.make(arena, io, &tmp)) orelse return error.SkipZigTest;
    const expression = try chock_nix.build.expressionFor(arena, project.root, &.{"drv"});
    const lock_bytes = try project.lock(arena, io);

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

    {
        var session = try chock_nix.eval.Session.init(gpa, .{
            .roots = &.{project.root},
            .io = io,
            .store_backend = driver.backend(),
            .store_writes = true,
            .flakes = true,
        });
        defer session.deinit();
        var buffer: [512]u8 = undefined;
        try testing.expectError(error.FetchIoUnavailable, session.answer(&buffer, expression));
    }

    var env = std.process.Environ.Map.init(arena);
    var host = chock_nix.provision.Host{ .nix_program = nix_path, .env = &env };

    var gate = RecordingGate{ .gpa = gpa, .permitted = true };
    defer gate.deinit();

    const answer = chock_nix.inputs.fetchAll(
        arena,
        io,
        host.runner(),
        gate.gate(),
        try project.reference(arena),
        lock_bytes,
    ) catch return error.SkipZigTest;
    if (answer != .fetched) return error.SkipZigTest;

    // Every host the one forge input is really fetched from, asked once each.
    try testing.expectEqual(@as(usize, 2), gate.asked.items.len);
    try testing.expectEqualStrings("api.github.com", gate.asked.items[0]);
    try testing.expectEqualStrings("codeload.github.com", gate.asked.items[1]);

    var holds_input = false;
    for (answer.fetched) |one| {
        if (std.mem.eql(u8, one, project.input_path)) holds_input = true;
    }
    try testing.expect(holds_input);

    // The second pass, with what the yes fetched on the seam.
    writing.fetched_paths = answer.fetched;
    var session = try chock_nix.eval.Session.init(gpa, .{
        .roots = &.{project.root},
        .io = io,
        .store_backend = driver.backend(),
        .store_writes = true,
        .flakes = true,
    });
    defer session.deinit();
    var buffer: [512]u8 = undefined;
    const evaluated = try session.answer(&buffer, expression);
    try testing.expect(evaluated.derivation_path != null);
}

test "a no refuses the fetch, and no second host is asked about" {
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
    const project = (try Project.make(arena, io, &tmp)) orelse return error.SkipZigTest;
    const lock_bytes = try project.lock(arena, io);

    var env = std.process.Environ.Map.init(arena);
    var host = chock_nix.provision.Host{ .nix_program = nix_path, .env = &env };

    var gate = RecordingGate{ .gpa = gpa, .permitted = false };
    defer gate.deinit();

    const answer = try chock_nix.inputs.fetchAll(
        arena,
        io,
        host.runner(),
        gate.gate(),
        try project.reference(arena),
        lock_bytes,
    );

    // **The first no is the answer.** Nothing was fetched, and the second host
    // of the same input is never put to anybody: a person who said no is not
    // asked again inside one call.
    try testing.expect(answer == .refused);
    try testing.expectEqual(@as(usize, 1), gate.asked.items.len);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "api.github.com") != null);
}
