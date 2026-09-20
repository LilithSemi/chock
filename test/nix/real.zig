//! `nix_build` against the `nix` and the Nix store on this machine. Every
//! other test answers `nix` from a table, so this is the one place a real
//! process and a real store answer. No `nix` or no daemon means a skip.

const std = @import("std");
const chock_nix = @import("chock-nix");

/// Where `nix` is, from `build.zig`. Empty on a machine with none. The Zig
/// 0.16 test runner takes no argument, so this is a build time constant.
const nix_path = @import("nix_path").nix_path;

const testing = std.testing;

/// No machine is this system, so `nix` refuses to build and no builder of ours
/// runs on the machine the tests are on.
const no_such_system = "chock-test-not-a-system";

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

/// A fixed output derivation. The URL names a host nothing here ever reaches.
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

const probe_url = "https://files.chock-test.invalid/probe.tar.gz";
const probe_host = "files.chock-test.invalid";

const RecordingGate = struct {
    gpa: std.mem.Allocator,
    permitted: bool,
    asked: std.ArrayList([]const u8) = .empty,
    opaque_asked: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *RecordingGate) void {
        for (self.asked.items) |one| self.gpa.free(one);
        self.asked.deinit(self.gpa);
        for (self.opaque_asked.items) |one| self.gpa.free(one);
        self.opaque_asked.deinit(self.gpa);
    }

    fn gate(self: *RecordingGate) chock_nix.fetch.Gate {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_nix.fetch.Gate.VTable{
        .permit_all = permitAllFn,
        .permit_opaque = permitOpaqueFn,
        .rule_for = settlesNothing,
        .permit_site = permitSiteFn,
    };

    fn permitOpaqueFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        subjects: []const []const u8,
    ) std.mem.Allocator.Error!chock_nix.fetch.Verdict {
        const self: *RecordingGate = @ptrCast(@alignCast(ptr));
        try self.opaque_asked.append(self.gpa, try self.gpa.dupe(u8, subjects[0]));
        if (self.permitted) return .permitted;
        return .{ .refused = try allocator.dupe(u8, "no rule allows a fetch with no url") };
    }

    fn settlesNothing(_: *anyopaque, _: chock_nix.fetch.Fetch) chock_nix.fetch.RuleAnswer {
        return .unsettled;
    }

    fn permitSiteFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        _: chock_nix.fetch.MirrorSite,
        chosen: chock_nix.fetch.Fetch,
    ) std.mem.Allocator.Error!chock_nix.fetch.Verdict {
        const self: *RecordingGate = @ptrCast(@alignCast(ptr));
        try self.asked.append(self.gpa, try self.gpa.dupe(u8, chosen.host));
        if (self.permitted) return .permitted;
        return .{ .refused = try allocator.dupe(u8, "no rule allows this mirror set") };
    }

    fn permitAllFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        wanted: []const chock_nix.fetch.Fetch,
    ) std.mem.Allocator.Error!chock_nix.fetch.Verdict {
        const self: *RecordingGate = @ptrCast(@alignCast(ptr));
        for (wanted) |one| try self.asked.append(self.gpa, try self.gpa.dupe(u8, one.host));
        if (self.permitted) return .permitted;
        const one = wanted[0];
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} fetches {s} from {s}, and no rule allows it",
            .{ one.subject, one.url, one.host },
        ) };
    }
};

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

    // A machine with no daemon to write to can claim nothing.
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

    // The host's own environment is not reachable from a test, so `nix` gets an empty one.
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();

    var host = chock_nix.provision.Host{ .nix_program = nix_path, .env = &env };

    // Nothing of this closure fetches, so a permitting gate makes a reader that found a host fail below.
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
        // A `nix` that will not start tried nothing, so it claims nothing.
        error.RunnerFailed => return error.SkipZigTest,
        else => return err,
    };

    try testing.expect(answer == .refused);
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
    // Nix says nothing like this, so a refusal holding it never started `nix`.
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
    try testing.expect(std.mem.indexOf(u8, answer.refused, probe_host) != null);
    try testing.expect(std.mem.indexOf(u8, answer.refused, installable) != null);
}

/// A real mirrors list found in this machine's store, never one this test
/// wrote, so the bytes are nixpkgs' own. Null is a reason to skip.
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

/// Read by hand, so this test does not answer with the parser it checks.
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

    try testing.expectEqual(@as(usize, 1), gate.asked.items.len);
    try testing.expectEqualStrings(found.first_gnu_host, gate.asked.items[0]);

    try testing.expect(answer == .refused);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "gnu") != null);
    try testing.expect(std.mem.indexOf(u8, answer.refused, found.first_gnu_host) != null);
}

/// A real nixpkgs `fetchurl` derivation of this store. One whose mirrors list
/// is absent is preferred, because that is the case that makes the reader
/// realise anything. Null is a reason to skip.
fn findFetchDerivation(arena: std.mem.Allocator, io: std.Io) !?[]const u8 {
    const endings = [_][]const u8{
        ".tar.gz.drv",
        ".tar.xz.drv",
        ".tar.bz2.drv",
        ".cabal.drv",
        ".zip.drv",
    };

    var store = std.Io.Dir.cwd().openDir(io, "/nix/store", .{ .iterate = true }) catch return null;
    defer store.close(io);

    var any: ?[]const u8 = null;
    var walk = store.iterate();
    while (walk.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        const named = for (endings) |ending| {
            if (std.mem.endsWith(u8, entry.name, ending)) break true;
        } else false;
        if (!named) continue;

        const path = try std.fmt.allocPrint(arena, "/nix/store/{s}", .{entry.name});
        const text = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 20)) catch
            continue;
        if (std.mem.indexOf(u8, text, "mirrorsFile") == null and
            std.mem.indexOf(u8, text, "mirrorsListFile") == null) continue;

        const mirrors = mirrorsPathIn(text) orelse {
            if (any == null) any = path;
            continue;
        };
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        _ = std.Io.Dir.cwd().realPathFile(io, mirrors, &buffer) catch return path;
        if (any == null) any = path;
    }
    return any;
}

/// Read out of the ATerm a `.drv` file is written in.
fn mirrorsPathIn(text: []const u8) ?[]const u8 {
    const ending = "-mirrors-list";
    const at = std.mem.indexOf(u8, text, ending) orelse return null;
    const before = std.mem.lastIndexOf(u8, text[0..at], "/nix/store/") orelse return null;
    return text[before .. at + ending.len];
}

test "a real fetchurl derivation has its mirrors list read, realised first when it is absent" {
    // The closure a derivation names is `.drv` files, and a mirrors list is
    // itself a derivation, so on an ordinary store its output is not there.
    if (nix_path.len == 0) return error.SkipZigTest;

    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const drv = (try findFetchDerivation(arena, io)) orelse return error.SkipZigTest;

    // An empty environment is enough: `nix` still finds the store and the daemon.
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var host = chock_nix.provision.Host{ .nix_program = nix_path, .env = &env };

    const closure = chock_nix.fetch.fetchesOf(arena, io, host.runner(), drv) catch |err| switch (err) {
        error.RunnerFailed => return error.SkipZigTest,
        else => return err,
    };
    if (closure == .nix_said) return error.SkipZigTest;

    try testing.expect(closure == .reached);
    try testing.expect(closure.reached.reads_mirrors);
    try testing.expect(closure.reached.hashed.len != 0);
    try testing.expect(closure.reached.hashed[0].target != null);
}

/// What `nix` wrote on standard output. Null when it refused.
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

/// A flake whose one input is pinned by the NAR hash of a tree this test put
/// in the host store. The hash is read from the same `nix` that added the tree,
/// and the forge coordinates in the lock are never reached.
const Project = struct {
    root: []const u8,
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

    fn lock(self: Project, arena: std.mem.Allocator, io: std.Io) ![]const u8 {
        const path = try std.fs.path.join(arena, &.{ self.root, "flake.lock" });
        return std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 20));
    }

    /// `path:` and not the bare path. A temporary directory of this suite sits
    /// inside this project's own git tree, and a bare path would have `nix`
    /// read that tree instead. `chock run` passes a real root bare.
    fn reference(self: Project, arena: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(arena, "path:{s}", .{self.root});
    }
};

test "a flake input that is in the store already is evaluated with no fetcher at all" {
    // The second half takes the path off the seam, which is what proves the
    // store and not the network answered the first half.
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

    try testing.expectEqual(@as(usize, 2), gate.asked.items.len);
    try testing.expectEqualStrings("api.github.com", gate.asked.items[0]);
    try testing.expectEqualStrings("codeload.github.com", gate.asked.items[1]);

    var holds_input = false;
    for (answer.fetched) |one| {
        if (std.mem.eql(u8, one, project.input_path)) holds_input = true;
    }
    try testing.expect(holds_input);

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

test "a no refuses the fetch, and every host of the lock was in the one question" {
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

    try testing.expect(answer == .refused);
    try testing.expect(gate.asked.items.len > 1);
    try testing.expectEqualStrings("api.github.com", gate.asked.items[0]);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "api.github.com") != null);
}
