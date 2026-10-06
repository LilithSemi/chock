//! The model asks for a program by name, and Chock resolves it with Nix
//! before the call runs.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const proc = @import("proc.zig");
const store = @import("store.zig");

pub const Error = std.mem.Allocator.Error || error{
    RunnerFailed,
};

pub const default_registry = "nixpkgs";

pub const max_name_bytes: usize = 128;

pub const NameError = error{
    NameEmpty,
    NameTooLong,
    NameNotAPackage,
};

fn isNameCharacter(character: u8) bool {
    if (std.ascii.isAlphanumeric(character)) return true;
    return switch (character) {
        '-', '_', '+', '.' => true,
        else => false,
    };
}

pub fn checkName(name: []const u8) NameError!void {
    if (name.len == 0) return error.NameEmpty;
    if (name.len > max_name_bytes) return error.NameTooLong;
    if (!std.ascii.isAlphanumeric(name[0])) return error.NameNotAPackage;
    if (name[name.len - 1] == '.') return error.NameNotAPackage;
    for (name) |character| {
        if (!isNameCharacter(character)) return error.NameNotAPackage;
    }
    if (std.mem.indexOf(u8, name, "..") != null) return error.NameNotAPackage;
}

pub fn installableFor(
    allocator: std.mem.Allocator,
    registry: []const u8,
    program: []const u8,
) std.mem.Allocator.Error![]u8 {
    std.debug.assert(registry.len != 0);
    checkName(program) catch unreachable;
    return std.fmt.allocPrint(allocator, "{s}#{s}", .{ registry, program });
}

pub const Variable = struct {
    name: []const u8,
    value: []const u8,
};

pub const Runner = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        run: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            args: []const []const u8,
            pins: []const Variable,
        ) Error!proc.Output,
    };

    pub fn run(
        self: Runner,
        allocator: std.mem.Allocator,
        io: std.Io,
        args: []const []const u8,
    ) Error!proc.Output {
        return self.vtable.run(self.ptr, allocator, io, args, &.{});
    }

    pub fn runPinned(
        self: Runner,
        allocator: std.mem.Allocator,
        io: std.Io,
        args: []const []const u8,
        pins: []const Variable,
    ) Error!proc.Output {
        return self.vtable.run(self.ptr, allocator, io, args, pins);
    }
};

pub const Host = struct {
    nix_program: []const u8,
    env: *const std.process.Environ.Map,
    diag: ?*?Diagnostic = null,

    pub fn runner(self: *const Host) Runner {
        return .{ .ptr = @constCast(self), .vtable = &vtable };
    }

    const vtable = Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        args: []const []const u8,
        pins: []const Variable,
    ) Error!proc.Output {
        const self: *Host = @ptrCast(@alignCast(ptr));

        const sink = diagnostic.sinkOf(allocator, self.diag);

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(allocator);
        try argv.append(allocator, self.nix_program);
        try argv.appendSlice(allocator, args);

        // The host's own environment stays whole, so nix still reads the user's configuration and registry. A pin is added on top of it and lives only as long as this one call.
        var pinned: ?std.process.Environ.Map = if (pins.len == 0) null else try pinnedEnv(
            allocator,
            self.env,
            pins,
        );
        defer if (pinned) |*one| one.deinit();

        return proc.run(allocator, io, .{
            .argv = argv.items,
            .env = if (pinned) |*one| one else self.env,
            // The same bound store.closureOf gives its own nix path-info: a closure of thirty thousand paths sits far below this, and a nix that writes without end must not take the session's memory with it.
            .max_output_bytes = 10 * 1024 * 1024,
            .diag = sink,
        }) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => {
                _ = diagnostic.note(sink, .{ .nix_not_runnable = err });
                return error.RunnerFailed;
            },
        };
    }
};

fn pinnedEnv(
    allocator: std.mem.Allocator,
    base: *const std.process.Environ.Map,
    pins: []const Variable,
) std.mem.Allocator.Error!std.process.Environ.Map {
    var copy = std.process.Environ.Map.init(allocator);
    errdefer copy.deinit();
    for (base.keys(), base.values()) |name, value| try copy.put(name, value);
    for (pins) |one| try copy.put(one.name, one.value);
    return copy;
}

pub const Request = struct {
    program: []const u8,
    registry: []const u8 = default_registry,
};

pub const Provided = struct {
    program: []const u8,
    installable: []const u8,
    bin_dirs: []const []const u8,
    store_paths: []const []const u8,
};

pub const Answer = union(enum) {
    provided: Provided,
    refused: []const u8,
};

pub fn resolve(
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: Runner,
    request: Request,
) Error!Answer {
    checkName(request.program) catch |err| return .{ .refused = try nameRefusal(allocator, request.program, err) };

    const installable = try installableFor(allocator, request.registry, request.program);

    const built = try runner.run(allocator, io, &.{
        "build",
        "--no-link",
        "--print-out-paths",
        installable,
    });
    if (!built.succeeded()) {
        return .{ .refused = try explainFailure(allocator, request, built.stderr) };
    }

    const out_paths = try store.parsePathList(allocator, built.stdout);
    if (out_paths.len == 0) {
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} was built and produced no output path, so there is nothing to add to the " ++
                "toolchain. Name a package rather than a flake output that builds nothing.",
            .{installable},
        ) };
    }

    var said: []const u8 = "";
    const mounts = try mountsFor(allocator, io, runner, out_paths, &said) orelse {
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} was built and what it needs could not be read, so it was not added to the " ++
                "toolchain. Nix said: {s}",
            .{ installable, said },
        ) };
    };

    return .{ .provided = .{
        .program = request.program,
        .installable = installable,
        .bin_dirs = mounts.bin_dirs,
        .store_paths = mounts.store_paths,
    } };
}

pub const Mounts = struct {
    bin_dirs: []const []const u8,
    store_paths: []const []const u8,
};

pub fn mountsFor(
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: Runner,
    out_paths: []const []const u8,
    said: *[]const u8,
) Error!?Mounts {
    var closure_args: std.ArrayList([]const u8) = .empty;
    defer closure_args.deinit(allocator);
    try closure_args.appendSlice(allocator, &.{ "path-info", "-r", "--" });
    for (out_paths) |path| try closure_args.append(allocator, path);

    const listed = try runner.run(allocator, io, closure_args.items);
    if (!listed.succeeded()) {
        said.* = lastLine(listed.stderr);
        return null;
    }

    const bin_dirs = try allocator.alloc([]const u8, out_paths.len);
    for (out_paths, bin_dirs) |path, *slot| {
        slot.* = try std.fmt.allocPrint(allocator, "{s}/bin", .{path});
    }

    return .{
        .bin_dirs = bin_dirs,
        .store_paths = try store.parsePathList(allocator, listed.stdout),
    };
}

fn nameRefusal(
    allocator: std.mem.Allocator,
    program: []const u8,
    err: NameError,
) std.mem.Allocator.Error![]u8 {
    return switch (err) {
        error.NameEmpty => allocator.dupe(u8, "no program was named, so nothing was provisioned. " ++
            "Give the name of one package, such as \"ripgrep\"."),
        error.NameTooLong => std.fmt.allocPrint(
            allocator,
            "that name is {d} bytes and a package name may be at most {d}, so nothing was " ++
                "provisioned. Name one package.",
            .{ program.len, max_name_bytes },
        ),
        error.NameNotAPackage => std.fmt.allocPrint(
            allocator,
            "\"{s}\" is not a package name, so nothing was provisioned. A name holds letters, " ++
                "digits, \"-\", \"_\", \"+\" and \".\", and starts with a letter or a digit. It " ++
                "is not a path, a URL, or a flake reference: name the package alone, such as " ++
                "\"ripgrep\" or \"python3Packages.requests\".",
            .{program},
        ),
    };
}

pub fn explainFailure(
    allocator: std.mem.Allocator,
    request: Request,
    stderr: []const u8,
) std.mem.Allocator.Error![]u8 {
    if (saysNoSuchPackage(stderr)) {
        const suggestion = suggestionIn(stderr);
        return std.fmt.allocPrint(
            allocator,
            "there is no package called \"{s}\" in {s}, so nothing was provisioned. The package " ++
                "is often named differently from the program: the program \"rg\" is the package " ++
                "\"ripgrep\". Try the package name, or do the work with a program the toolchain " ++
                "already has.{s}{s}",
            .{
                request.program,
                request.registry,
                if (suggestion.len == 0) "" else " Nix said: ",
                suggestion,
            },
        );
    }
    if (saysNoDaemon(stderr)) {
        return std.fmt.allocPrint(
            allocator,
            "the Nix daemon could not be reached, so \"{s}\" was not provisioned and no other " ++
                "program can be either in this session. Do the work with a program the toolchain " ++
                "already has, and tell the user that provisioning is not available.",
            .{request.program},
        );
    }
    if (saysNoNetwork(stderr)) {
        return std.fmt.allocPrint(
            allocator,
            "\"{s}\" could not be downloaded or built, so nothing was provisioned. This is the " ++
                "machine and not your request: do the work with a program the toolchain already " ++
                "has.",
            .{request.program},
        );
    }
    return std.fmt.allocPrint(
        allocator,
        "\"{s}\" could not be built, so nothing was provisioned. Nix said: {s}",
        .{ request.program, lastLine(stderr) },
    );
}

fn saysNoSuchPackage(stderr: []const u8) bool {
    const spellings = [_][]const u8{
        "does not provide attribute",
        "attribute '",
        "flake output attribute",
        "cannot find flake attribute",
    };
    for (spellings) |spelling| {
        if (std.mem.indexOf(u8, stderr, spelling) == null) continue;
        if (std.mem.eql(u8, spelling, "attribute '")) {
            if (std.mem.indexOf(u8, stderr, "missing") == null) continue;
        }
        return true;
    }
    return false;
}

fn suggestionIn(stderr: []const u8) []const u8 {
    const marker = "Did you mean";
    const at = std.mem.indexOf(u8, stderr, marker) orelse return "";
    const rest = stderr[at..];
    const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
    const line = std.mem.trim(u8, rest[0..end], " \t\r");
    if (line.len > max_raw_bytes) return line[0..max_raw_bytes];
    return line;
}

pub fn saysNoDaemon(stderr: []const u8) bool {
    const spellings = [_][]const u8{
        "cannot connect to socket",
        "cannot open connection to remote store",
        "daemon socket",
        "Connection refused",
    };
    for (spellings) |spelling| {
        if (std.mem.indexOf(u8, stderr, spelling) != null) return true;
    }
    return false;
}

pub fn saysNoNetwork(stderr: []const u8) bool {
    const spellings = [_][]const u8{
        "unable to download",
        "Temporary failure in name resolution",
        "Could not resolve host",
        "unable to load seed",
    };
    for (spellings) |spelling| {
        if (std.mem.indexOf(u8, stderr, spelling) != null) return true;
    }
    return false;
}

pub const max_raw_bytes: usize = 400;

pub fn lastLine(stderr: []const u8) []const u8 {
    var found: []const u8 = "nothing";
    var lines = std.mem.splitScalar(u8, stderr, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        found = line;
    }
    if (found.len > max_raw_bytes) return found[0..max_raw_bytes];
    return found;
}

const testing = std.testing;

const FakeRunner = struct {
    replies: []const Reply,
    seen: std.ArrayList([]const []const u8) = .empty,
    gpa: std.mem.Allocator,
    calls: usize = 0,
    last_pins: usize = 0,

    const Reply = struct {
        code: u8 = 0,
        stdout: []const u8 = "",
        stderr: []const u8 = "",
    };

    fn runner(self: *FakeRunner) Runner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        args: []const []const u8,
        pins: []const Variable,
    ) Error!proc.Output {
        _ = io;
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));
        std.debug.assert(self.calls < self.replies.len);
        self.last_pins = pins.len;

        const copy = try self.gpa.alloc([]const u8, args.len);
        for (args, copy) |from, *to| to.* = try self.gpa.dupe(u8, from);
        try self.seen.append(self.gpa, copy);

        const reply = self.replies[self.calls];
        self.calls += 1;
        return .{
            .term = .{ .exited = reply.code },
            .stdout = try allocator.dupe(u8, reply.stdout),
            .stderr = try allocator.dupe(u8, reply.stderr),
        };
    }

    fn deinit(self: *FakeRunner) void {
        for (self.seen.items) |args| {
            for (args) |one| self.gpa.free(one);
            self.gpa.free(args);
        }
        self.seen.deinit(self.gpa);
    }
};

test "a name that is not a package name is refused before nix is run at all" {
    const gpa = testing.allocator;

    try testing.expectError(error.NameNotAPackage, checkName("github:someone/evil#payload"));
    try testing.expectError(error.NameNotAPackage, checkName("https://example.invalid/flake"));
    try testing.expectError(error.NameNotAPackage, checkName("../../../etc/shadow"));
    try testing.expectError(error.NameNotAPackage, checkName("/nix/store/aaa-thing"));
    try testing.expectError(error.NameNotAPackage, checkName("-L"));
    try testing.expectError(error.NameNotAPackage, checkName("ripgrep --option"));
    try testing.expectError(error.NameNotAPackage, checkName("python3Packages..requests"));
    try testing.expectError(error.NameNotAPackage, checkName("ripgrep."));
    try testing.expectError(error.NameEmpty, checkName(""));
    try testing.expectError(error.NameTooLong, checkName("a" ** (max_name_bytes + 1)));

    try checkName("ripgrep");
    try checkName("python3Packages.requests");
    try checkName("gcc14");
    try checkName("gtk+");
    try checkName("nodejs_22");

    var fake = FakeRunner{ .gpa = gpa, .replies = &.{} };
    defer fake.deinit();
    const answer = try resolve(gpa, testing.io, fake.runner(), .{ .program = "github:someone/evil#payload" });
    defer gpa.free(answer.refused);
    try testing.expectEqual(@as(usize, 0), fake.calls);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "is not a package name") != null);
}

test "resolve builds the registry attribute and mounts the whole closure" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const replies = [_]FakeRunner.Reply{
        .{ .stdout = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ripgrep-14.1.1\n" },
        .{ .stdout =
        \\/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ripgrep-14.1.1
        \\/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-glibc-2.42
        \\
        },
    };
    var fake = FakeRunner{ .gpa = gpa, .replies = &replies };
    defer fake.deinit();

    const answer = try resolve(arena, testing.io, fake.runner(), .{ .program = "ripgrep" });
    const provided = answer.provided;

    try testing.expectEqualStrings("nixpkgs#ripgrep", provided.installable);

    try testing.expectEqual(@as(usize, 2), fake.seen.items.len);
    const build = fake.seen.items[0];
    try testing.expectEqualStrings("build", build[0]);
    try testing.expectEqualStrings("--no-link", build[1]);
    try testing.expectEqualStrings("--print-out-paths", build[2]);
    try testing.expectEqualStrings("nixpkgs#ripgrep", build[3]);

    const closure = fake.seen.items[1];
    try testing.expectEqualStrings("path-info", closure[0]);
    try testing.expectEqualStrings("-r", closure[1]);
    try testing.expectEqualStrings("--", closure[2]);
    try testing.expectEqualStrings("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ripgrep-14.1.1", closure[3]);

    try testing.expectEqual(@as(usize, 2), provided.store_paths.len);
    try testing.expectEqualStrings("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-glibc-2.42", provided.store_paths[1]);

    try testing.expectEqual(@as(usize, 1), provided.bin_dirs.len);
    try testing.expectEqualStrings(
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ripgrep-14.1.1/bin",
        provided.bin_dirs[0],
    );
}

test "a package with two outputs puts both bin directories on the path" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const replies = [_]FakeRunner.Reply{
        .{ .stdout =
        \\/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-thing-1
        \\/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-thing-1-man
        },
        .{ .stdout = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-thing-1" },
    };
    var fake = FakeRunner{ .gpa = gpa, .replies = &replies };
    defer fake.deinit();

    const answer = try resolve(arena, testing.io, fake.runner(), .{ .program = "thing" });
    try testing.expectEqual(@as(usize, 2), answer.provided.bin_dirs.len);
    try testing.expectEqual(@as(usize, 5), fake.seen.items[1].len);
}

test "a registry the project chose is the one that is searched" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const replies = [_]FakeRunner.Reply{
        .{ .stdout = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tool-1" },
        .{ .stdout = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tool-1" },
    };
    var fake = FakeRunner{ .gpa = gpa, .replies = &replies };
    defer fake.deinit();

    const answer = try resolve(arena, testing.io, fake.runner(), .{
        .program = "tool",
        .registry = "git+file:///srv/our-nixpkgs",
    });
    try testing.expectEqualStrings("git+file:///srv/our-nixpkgs#tool", answer.provided.installable);
}

test "a missing attribute is one sentence naming the package, not a nix trace" {
    const gpa = testing.allocator;

    const raw =
        \\error: flake 'flake:nixpkgs' does not provide attribute 'packages.aarch64-linux.rg', 'defaultPackage.aarch64-linux.rg', 'legacyPackages.aarch64-linux.rg' or 'rg'
        \\       Did you mean one of erg, gg, mg, rc or reg?
    ;
    const text = try explainFailure(gpa, .{ .program = "rg" }, raw);
    defer gpa.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "no package called \"rg\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "nixpkgs") != null);
    try testing.expect(std.mem.indexOf(u8, text, "ripgrep") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Did you mean one of erg") != null);
    try testing.expect(std.mem.indexOf(u8, text, "legacyPackages") == null);
}

test "a missing attribute with no near names says so without a dangling sentence" {
    const gpa = testing.allocator;
    const raw = "error: flake 'flake:nixpkgs' does not provide attribute 'qqqq' or 'qqqq'";
    const text = try explainFailure(gpa, .{ .program = "qqqq" }, raw);
    defer gpa.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "no package called \"qqqq\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Nix said") == null);
    try testing.expect(std.mem.endsWith(u8, text, "already has."));
}

test "a daemon that is not there says provisioning is off, not that the package is wrong" {
    const gpa = testing.allocator;
    const raw = "error: cannot connect to socket at '/nix/var/nix/daemon-socket/socket': Connection refused";
    const text = try explainFailure(gpa, .{ .program = "ripgrep" }, raw);
    defer gpa.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "daemon could not be reached") != null);
    try testing.expect(std.mem.indexOf(u8, text, "no other program can be either") != null);
    try testing.expect(std.mem.indexOf(u8, text, "no package called") == null);
}

test "a failure nobody has a sentence for gives one line and never the whole trace" {
    const gpa = testing.allocator;

    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(gpa);
    var line: usize = 0;
    while (line < 200) : (line += 1) {
        try raw.appendSlice(gpa, "       … while evaluating a very long trace line that nobody reads\n");
    }
    try raw.appendSlice(gpa, "error: builder for '/nix/store/xxx.drv' failed with exit code 2\n");

    const text = try explainFailure(gpa, .{ .program = "thing" }, raw.items);
    defer gpa.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "failed with exit code 2") != null);
    try testing.expect(text.len < max_raw_bytes + 200);
    try testing.expect(std.mem.indexOf(u8, text, "while evaluating") == null);
}

test "a build that produces no output path is a refusal and not an empty toolchain entry" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const replies = [_]FakeRunner.Reply{.{ .stdout = "\n\n" }};
    var fake = FakeRunner{ .gpa = gpa, .replies = &replies };
    defer fake.deinit();

    const answer = try resolve(arena_state.allocator(), testing.io, fake.runner(), .{ .program = "empty" });

    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "produced no output path") != null);
}

test "the installable is always the registry and the name, and asserts the check ran" {
    const gpa = testing.allocator;
    const text = try installableFor(gpa, "nixpkgs", "ripgrep");
    defer gpa.free(text);
    try testing.expectEqualStrings("nixpkgs#ripgrep", text);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "#"));
}
