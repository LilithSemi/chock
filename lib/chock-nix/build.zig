//! The agent names an attribute to build, and the host builds it.
//!
//! ## A build is brokered, and it never happens inside the sandbox
//!
//! The sandbox has no daemon socket, no network and no writable cache
//! directory, so a real build cannot run there at all. What runs there is the
//! program afterwards. So the shape is the one `provision.zig` already has:
//! `nix` runs on the host, outside every sandbox, and answers with store
//! paths and `bin` directories, which is what a sandbox mounts and what goes
//! on the `PATH` of the next tool call.
//!
//! ## The produced set, and what it is worth
//!
//! A hand written derivation can name any builder, so a build of a path
//! nobody evaluated here would be host code execution with a content hash in
//! front of it. `backend.Driver` answers that: it records what an evaluation
//! put in the store and refuses a build of anything else.
//!
//! **What that proves is that this session evaluated this attribute**, so the
//! request did not arrive out of nowhere and the model cannot name a store
//! path of its own choosing.
//!
//! **What it does not prove is that the host builds the bytes this session
//! evaluated.** The driver is handed a derivation path, and the host is then
//! told to realise `<reference>#<attribute>`. Those are two objects. fix and
//! the host's own Nix can read one attribute differently, and a reference
//! that is not pinned can move between the moment of the evaluation and the
//! moment of the build. Closing that means realising the derivation path
//! itself, which needs the derivation written into the host's store first,
//! and nothing here does that. The gap is open and it is stated rather than
//! papered over.
//!
//! **This file adds no second check.** It calls `Driver.build`, which is the
//! same function the evaluator's own build goes through, so there is one
//! answer to what this session produced. A check written beside that one
//! could answer differently, and the weaker of the two would then be the real
//! rule.
//!
//! ## The seam that can build is installed last
//!
//! An evaluation runs against `evaluating`, which writes no object and
//! authorises no build, so import from derivation is refused there exactly as
//! it is for an ordinary `nix_eval`. `realise` installs the seam that runs
//! `nix` only after a person or the policy has answered, and takes it off
//! again when the build is over. An evaluation therefore cannot reach a
//! build, whatever the expression says.
//!
//! ## Nothing here talks to Nix
//!
//! `provision.Runner` is the seam, and the same one: the real runner spawns
//! `nix`, and the one the tests use answers from a table. A test that builds
//! a derivation is not a test, it is a build.

const std = @import("std");

const backend = @import("backend.zig");
const proc = @import("proc.zig");
const provision = @import("provision.zig");
const store = @import("store.zig");

pub const Error = provision.Error;

/// What `nix` said when it would not build. Never leaves this file: `realise`
/// turns it into a sentence the model reads.
const NixRefused = error{NixRefusedTheBuild};

/// The most attributes one path may hold, and the longest one attribute may
/// be. A real path is three deep and its names are words.
pub const max_segments: usize = 8;
pub const max_segment_bytes: usize = 128;

/// The longest flake reference this accepts. A reference is a URL, and one
/// far longer than this names nothing a project really has.
pub const max_flake_ref_bytes: usize = 512;

/// Why a request was refused before anything was evaluated or built.
pub const RequestError = error{
    AttrPathEmpty,
    AttrPathTooDeep,
    /// A segment is empty, too long, or holds a character an attribute name
    /// may not have here. See `checkSegment`.
    AttrNotAName,
    FlakeRefEmpty,
    FlakeRefTooLong,
    /// The reference holds a character that would not survive being written
    /// into an expression or an argument. See `checkFlakeRef`.
    FlakeRefNotAReference,
};

/// True when `character` may appear in an attribute name here.
///
/// Letters, digits, `-`, `_` and `+`. **A dot is refused, and that is the one
/// exclusion worth stating**: the same attribute path is written twice, once
/// as an expression and once as the fragment of an installable, and a dot in
/// a name is a level boundary in the second spelling. A name that means two
/// things in two places is a name this file will not build.
fn isNameCharacter(character: u8) bool {
    if (std.ascii.isAlphanumeric(character)) return true;
    return switch (character) {
        '-', '_', '+' => true,
        else => false,
    };
}

/// Check one attribute name.
fn checkSegment(segment: []const u8) RequestError!void {
    if (segment.len == 0 or segment.len > max_segment_bytes) return error.AttrNotAName;
    if (!std.ascii.isAlphanumeric(segment[0])) return error.AttrNotAName;
    for (segment) |character| {
        if (!isNameCharacter(character)) return error.AttrNotAName;
    }
}

/// Check the whole attribute path the model sent.
pub fn checkAttrPath(attr_path: []const []const u8) RequestError!void {
    if (attr_path.len == 0) return error.AttrPathEmpty;
    if (attr_path.len > max_segments) return error.AttrPathTooDeep;
    for (attr_path) |segment| try checkSegment(segment);
}

/// Check a flake reference.
///
/// A reference is written into a Nix string literal and into an argument of
/// `nix`, so a quote, a backslash, a dollar sign, a `#` and any whitespace are
/// refused. What is left is a URL: letters, digits, and the punctuation a
/// reference really uses.
pub fn checkFlakeRef(flake_ref: []const u8) RequestError!void {
    if (flake_ref.len == 0) return error.FlakeRefEmpty;
    if (flake_ref.len > max_flake_ref_bytes) return error.FlakeRefTooLong;
    if (flake_ref[0] == '-') return error.FlakeRefNotAReference;
    for (flake_ref) |character| {
        if (std.ascii.isAlphanumeric(character)) continue;
        switch (character) {
            ':', '/', '.', '-', '_', '+', '~', '@', '%', '?', '=', '&', ',' => {},
            else => return error.FlakeRefNotAReference,
        }
    }
}

/// The installable `<flake ref>#<attribute>.<attribute>`, which is what `nix`
/// realises. The caller owns the result.
///
/// **Both arguments must already have passed their check**, which is
/// asserted: this is the one place they become arguments to `nix`, and a
/// caller that skipped the check is a programmer error.
pub fn installableFor(
    allocator: std.mem.Allocator,
    flake_ref: []const u8,
    attr_path: []const []const u8,
) std.mem.Allocator.Error![]u8 {
    checkFlakeRef(flake_ref) catch unreachable;
    checkAttrPath(attr_path) catch unreachable;

    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    try text.appendSlice(allocator, flake_ref);
    try text.append(allocator, '#');
    for (attr_path, 0..) |segment, index| {
        if (index != 0) try text.append(allocator, '.');
        try text.appendSlice(allocator, segment);
    }
    return text.toOwnedSlice(allocator);
}

/// The expression that evaluates to the same thing the installable names, for
/// the evaluator inside Chock. The caller owns the result.
///
/// ```
/// (builtins.getFlake "/work")."packages"."x86_64-linux"."default"
/// ```
///
/// Every attribute is quoted, so the expression selects exactly the names the
/// caller sent and never reads a dot as a boundary of its own.
pub fn expressionFor(
    allocator: std.mem.Allocator,
    flake_ref: []const u8,
    attr_path: []const []const u8,
) std.mem.Allocator.Error![]u8 {
    checkFlakeRef(flake_ref) catch unreachable;
    checkAttrPath(attr_path) catch unreachable;

    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    try text.print(allocator, "(builtins.getFlake \"{s}\")", .{flake_ref});
    for (attr_path) |segment| try text.print(allocator, ".\"{s}\"", .{segment});
    return text.toOwnedSlice(allocator);
}

const no_context: u8 = 0;

/// The store seam an evaluation for a build runs against.
///
/// `add_object` answers the path the store itself computed and keeps no
/// bytes. That is all the produced set needs, and the host's own `nix` writes
/// the real object when it builds. **There is no `build_paths` here**, so an
/// evaluation that reaches for one, which is what import from derivation
/// does, is refused with the path named, exactly as an ordinary evaluation
/// is.
pub const evaluating: backend.Seam = .{
    .context = @constCast(&no_context),
    .vtable = &evaluating_vtable,
};

const evaluating_vtable: backend.Seam.VTable = .{
    .is_valid_path = evaluatingIsValidPath,
    .add_object = evaluatingAddObject,
};

/// This store holds nothing, which is the truth about a seam that keeps no
/// bytes. An evaluation that asks then writes the object rather than assuming
/// it is there already, which is the answer that fills the produced set.
fn evaluatingIsValidPath(_: *anyopaque, _: []const u8) anyerror!bool {
    return false;
}

fn evaluatingAddObject(
    _: *anyopaque,
    allocator: std.mem.Allocator,
    object: backend.AddObject,
) anyerror![]u8 {
    return allocator.dupe(u8, object.expectedPath());
}

/// The store seam that really builds, on the host.
///
/// **It builds the installable and not the derivation path it is handed.**
/// The evaluation that produced that path kept no bytes, so the derivation is
/// not in the host's store to name, and `nix` instantiates the same attribute
/// of the same flake for itself. So what `nix` builds here is not proven to
/// be what this session evaluated: see this file's own top comment, which
/// says what the produced set is worth and what it is not.
pub const Host = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: provision.Runner,
    /// `<flake ref>#<attribute path>`, from `installableFor`.
    installable: []const u8,
    /// What `nix` wrote when it would not build, borrowed from `allocator`.
    said: []const u8 = "",
    /// The outputs the build produced, empty until it has.
    out_paths: []const []const u8 = &.{},

    pub fn seam(self: *Host) backend.Seam {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: backend.Seam.VTable = .{ .build_paths = buildPaths };

    fn buildPaths(
        context: *anyopaque,
        _: []const []const u8,
        _: ?backend.BuildSink,
        _: backend.BuildMode,
    ) anyerror!void {
        const self: *Host = @ptrCast(@alignCast(context));
        const built = try self.runner.run(self.allocator, self.io, &.{
            "build",
            // No result symbolic link, for the reason `provision.resolve`
            // gives: the root a session needs is made by its caller, and a
            // `result` link in the user's project directory is litter.
            "--no-link",
            "--print-out-paths",
            self.installable,
        });
        if (!built.succeeded()) {
            self.said = provision.lastLine(built.stderr);
            return NixRefused.NixRefusedTheBuild;
        }
        self.out_paths = try store.parsePathList(self.allocator, built.stdout);
    }
};

/// One thing to realise.
pub const Request = struct {
    /// The derivation the evaluation of this very attribute produced. The
    /// driver refuses a build of anything it did not produce, which is what
    /// says this request came from an evaluation of this session's own. It is
    /// not a promise about the bytes the host then builds: see this file's
    /// own top comment.
    derivation_path: []const u8,
    /// What `nix` realises, from `installableFor`.
    installable: []const u8,
};

/// A build that happened.
pub const Built = struct {
    /// What the sandbox mounts and what goes on the `PATH`, in the shape a
    /// provisioned program already answers with, so a built package joins the
    /// session's toolchain by the road that is already there.
    provided: provision.Provided,
    /// The build's own outputs, which is what the model is told about.
    out_paths: []const []const u8,
};

/// What one `realise` produced: a build, or one sentence saying why not.
///
/// A refusal is a fact about the request that the model reads and can act on,
/// the same way `provision.Answer` treats a package that is not there.
pub const Answer = union(enum) {
    built: Built,
    refused: []const u8,
};

/// Build `request` on the host, if `driver` produced its derivation.
///
/// **Give this an arena**, the same convention `provision.resolve` follows:
/// every string of the answer comes from `allocator`, and so does everything
/// the `nix` commands wrote.
pub fn realise(
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: provision.Runner,
    driver: *backend.Driver,
    request: Request,
) Error!Answer {
    var host: Host = .{
        .allocator = allocator,
        .io = io,
        .runner = runner,
        .installable = request.installable,
    };

    // Installed here and taken off below, so nothing that runs before or
    // after this call can reach a build through this driver.
    driver.seam = host.seam();
    defer driver.seam = backend.Seam.refusing;

    driver.build(&.{request.derivation_path}, .normal) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.RunnerFailed => return error.RunnerFailed,
        // The driver's own words, which name the path. Nothing ran.
        error.BuildRefused => return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} was not built, and nothing ran: {s}",
            .{ request.installable, driver.lastError() orelse "the build was refused" },
        ) },
        NixRefused.NixRefusedTheBuild => return .{
            .refused = try explainFailure(allocator, request.installable, host.said),
        },
        else => return error.RunnerFailed,
    };

    if (host.out_paths.len == 0) return .{ .refused = try std.fmt.allocPrint(
        allocator,
        "{s} was built and produced no output path, so there is nothing to use. Name an " ++
            "attribute that is a package rather than one that builds nothing.",
        .{request.installable},
    ) };

    var said: []const u8 = "";
    const mounts = try provision.mountsFor(allocator, io, runner, host.out_paths, &said) orelse
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} was built and what it needs could not be read, so it is not available. Nix " ++
                "said: {s}",
            .{ request.installable, said },
        ) };

    return .{ .built = .{
        .provided = .{
            .program = request.installable,
            .installable = request.installable,
            .bin_dirs = mounts.bin_dirs,
            .store_paths = mounts.store_paths,
        },
        .out_paths = host.out_paths,
    } };
}

/// One sentence for a request this file refuses before it evaluates anything.
pub fn requestRefusal(
    allocator: std.mem.Allocator,
    err: RequestError,
) std.mem.Allocator.Error![]u8 {
    return switch (err) {
        error.AttrPathEmpty => allocator.dupe(u8, "nothing was built: no attribute was named. " ++
            "Send the attribute path as a list, such as [\"packages\", \"x86_64-linux\", " ++
            "\"default\"]."),
        error.AttrPathTooDeep => std.fmt.allocPrint(
            allocator,
            "nothing was built: an attribute path may hold at most {d} names. Name the " ++
                "package itself.",
            .{max_segments},
        ),
        error.AttrNotAName => std.fmt.allocPrint(
            allocator,
            "nothing was built: one of those is not an attribute name. A name holds letters, " ++
                "digits, \"-\", \"_\" and \"+\", starts with a letter or a digit, and is at " ++
                "most {d} bytes. Send one name per entry of the list rather than one dotted " ++
                "string.",
            .{max_segment_bytes},
        ),
        error.FlakeRefEmpty => allocator.dupe(u8, "nothing was built: the flake reference is " ++
            "empty. Leave it out to build from the project you are working in."),
        error.FlakeRefTooLong => std.fmt.allocPrint(
            allocator,
            "nothing was built: a flake reference may be at most {d} bytes.",
            .{max_flake_ref_bytes},
        ),
        error.FlakeRefNotAReference => allocator.dupe(u8, "nothing was built: that is not a " ++
            "flake reference. A reference is a URL such as \"github:NixOS/nixpkgs\" or a path, " ++
            "with no quote, no space and no \"#\": name the attribute in the attribute path " ++
            "instead."),
    };
}

/// Why `nix` would not build, in the words of what to do next.
///
/// The two machine faults are told apart from a request fault, because they
/// are not the model's to fix and a model that reads them as its own mistake
/// sends a second attribute. Anything else is the last line Nix wrote, which
/// is where Nix puts its own message.
fn explainFailure(
    allocator: std.mem.Allocator,
    installable: []const u8,
    said: []const u8,
) std.mem.Allocator.Error![]u8 {
    if (provision.saysNoDaemon(said)) return std.fmt.allocPrint(
        allocator,
        "the Nix daemon could not be reached, so {s} was not built and nothing else can be " ++
            "either in this session. Do the work with what the toolchain already has, and tell " ++
            "the user that a build is not available.",
        .{installable},
    );
    if (provision.saysNoNetwork(said)) return std.fmt.allocPrint(
        allocator,
        "{s} could not be downloaded or built, and that is the machine rather than your " ++
            "request. Do the work with what the toolchain already has.",
        .{installable},
    );
    return std.fmt.allocPrint(
        allocator,
        "{s} was not built. Nix said: {s}",
        .{ installable, said },
    );
}

const testing = std.testing;

/// A `provision.Runner` that runs nothing, so every test here reaches no
/// daemon, no network and no store.
const FakeRunner = struct {
    gpa: std.mem.Allocator,
    replies: []const Reply,
    calls: usize = 0,
    seen: std.ArrayList([]const []const u8) = .empty,

    const Reply = struct {
        code: u8 = 0,
        stdout: []const u8 = "",
        stderr: []const u8 = "",
    };

    fn deinit(self: *FakeRunner) void {
        for (self.seen.items) |args| {
            for (args) |one| self.gpa.free(one);
            self.gpa.free(args);
        }
        self.seen.deinit(self.gpa);
    }

    fn runner(self: *FakeRunner) provision.Runner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = provision.Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        _: std.Io,
        args: []const []const u8,
    ) provision.Error!proc.Output {
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));

        const copy = try self.gpa.alloc([]const u8, args.len);
        errdefer self.gpa.free(copy);
        for (args, copy) |one, *slot| slot.* = try self.gpa.dupe(u8, one);
        try self.seen.append(self.gpa, copy);

        const reply = self.replies[self.calls];
        self.calls += 1;
        return .{
            .term = .{ .exited = reply.code },
            .stdout = try allocator.dupe(u8, reply.stdout),
            .stderr = try allocator.dupe(u8, reply.stderr),
        };
    }
};

const example_drv = "/nix/store/00000000000000000000000000000000-example.drv";
const example_out = "/nix/store/11111111111111111111111111111111-example";

/// A driver that produced `example_drv`, through the seam an evaluation for a
/// build really runs against.
fn producingDriver(allocator: std.mem.Allocator) !backend.Driver {
    var driver = backend.Driver.init(allocator, evaluating);
    errdefer driver.deinit();

    const expr_mod = @import("expr");
    var engine = try expr_mod.Engine.init(allocator, .{ .worker_count = 1 });
    defer engine.deinit();
    try engine.setPureEval(true, &.{});
    try engine.setStoreBackend(driver.backend());
    engine.enableStoreWrites();

    const value = try engine.evaluate(
        \\derivation { name = "x"; builder = "/bin/sh"; system = "x86_64-linux"; }
    );
    const path = (try engine.derivationDrvPath(value)).?;
    try engine.ensureDerivationClosure(path);
    return driver;
}

test "an attribute path and a flake reference build one installable and one expression" {
    const gpa = testing.allocator;
    const attr_path = [_][]const u8{ "packages", "x86_64-linux", "default" };

    const installable = try installableFor(gpa, "/work", &attr_path);
    defer gpa.free(installable);
    try testing.expectEqualStrings("/work#packages.x86_64-linux.default", installable);

    const expression = try expressionFor(gpa, "/work", &attr_path);
    defer gpa.free(expression);
    try testing.expectEqualStrings(
        "(builtins.getFlake \"/work\").\"packages\".\"x86_64-linux\".\"default\"",
        expression,
    );
}

test "an attribute name that is not a name is refused before anything is evaluated" {
    // The dot is the one that matters: `packages.a.b` as a single entry would
    // be two levels in the installable and one in the expression, so the two
    // spellings of one request would stop meaning the same thing.
    try testing.expectError(error.AttrNotAName, checkAttrPath(&.{"a.b"}));
    try testing.expectError(error.AttrNotAName, checkAttrPath(&.{"has space"}));
    try testing.expectError(error.AttrNotAName, checkAttrPath(&.{"-option"}));
    try testing.expectError(error.AttrNotAName, checkAttrPath(&.{"/nix/store/x"}));
    try testing.expectError(error.AttrPathEmpty, checkAttrPath(&.{}));
    try checkAttrPath(&.{ "packages", "x86_64-linux", "default" });
}

test "a flake reference that would break out of a string or an argument is refused" {
    try testing.expectError(error.FlakeRefNotAReference, checkFlakeRef("a\"b"));
    try testing.expectError(error.FlakeRefNotAReference, checkFlakeRef("a\\b"));
    try testing.expectError(error.FlakeRefNotAReference, checkFlakeRef("${x}"));
    try testing.expectError(error.FlakeRefNotAReference, checkFlakeRef("nixpkgs#hello"));
    try testing.expectError(error.FlakeRefNotAReference, checkFlakeRef("--option"));
    try checkFlakeRef("github:NixOS/nixpkgs");
    try checkFlakeRef("/home/someone/project");
}

test "a build of a derivation this session evaluated runs, and the produced set is what authorised it" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var driver = try producingDriver(gpa);
    defer driver.deinit();

    // The whole of the gate: drop the `ensureDerivationClosure` call in
    // `producingDriver` and this build is refused instead of run.
    const drv = drvPathOf(&driver).?;
    try testing.expect(driver.produced(drv));

    var fake = FakeRunner{ .gpa = gpa, .replies = &.{
        .{ .stdout = example_out ++ "\n" },
        .{ .stdout = example_out ++ "\n/nix/store/22222222222222222222222222222222-libc\n" },
    } };
    defer fake.deinit();

    const answer = try realise(arena, testing.io, fake.runner(), &driver, .{
        .derivation_path = drv,
        .installable = "/work#packages.x86_64-linux.default",
    });

    try testing.expect(answer == .built);
    const built = answer.built;
    try testing.expectEqualStrings(example_out, built.out_paths[0]);
    try testing.expectEqual(@as(usize, 2), built.provided.store_paths.len);
    try testing.expectEqualStrings(example_out ++ "/bin", built.provided.bin_dirs[0]);

    // What was really asked of `nix`, rather than that something was.
    try testing.expectEqualStrings("build", fake.seen.items[0][0]);
    try testing.expectEqualStrings("--print-out-paths", fake.seen.items[0][2]);
    try testing.expectEqualStrings("/work#packages.x86_64-linux.default", fake.seen.items[0][3]);
    try testing.expectEqualStrings("path-info", fake.seen.items[1][0]);

    // The seam that can build is off again, so nothing after this reaches one.
    try testing.expect(driver.seam.vtable.build_paths == null);
}

/// The one path `driver` produced, for a test that needs the derivation path
/// the evaluator computed rather than one written out by hand.
fn drvPathOf(driver: *backend.Driver) ?[]const u8 {
    var keys = driver.paths.keyIterator();
    while (keys.next()) |key| {
        if (std.mem.endsWith(u8, key.*, ".drv")) return key.*;
    }
    return null;
}

test "a build of a store path this session never produced is refused by name, and nix is never run" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var driver = backend.Driver.init(gpa, evaluating);
    defer driver.deinit();

    // A reply is here so that a runner that was reached would answer rather
    // than trap, and the assertion below is that it was not reached.
    var fake = FakeRunner{ .gpa = gpa, .replies = &.{.{ .stdout = example_out ++ "\n" }} };
    defer fake.deinit();

    const answer = try realise(arena, testing.io, fake.runner(), &driver, .{
        .derivation_path = example_drv,
        .installable = "/work#packages.x86_64-linux.default",
    });

    try testing.expectEqual(@as(usize, 0), fake.calls);
    try testing.expect(answer == .refused);
    // A model that reads a refusal with no subject sends the same request
    // again, so the path it asked for has to be in the words.
    try testing.expect(std.mem.indexOf(u8, answer.refused, example_drv) != null);
}

test "a nix that refused the build answers one sentence, and the machine faults are told apart" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var driver = try producingDriver(gpa);
    defer driver.deinit();
    const drv = drvPathOf(&driver).?;

    var fake = FakeRunner{ .gpa = gpa, .replies = &.{
        .{ .code = 1, .stderr = "error: builder for '/nix/store/x.drv' failed with exit code 2" },
    } };
    defer fake.deinit();

    const answer = try realise(arena, testing.io, fake.runner(), &driver, .{
        .derivation_path = drv,
        .installable = "/work#packages.x86_64-linux.default",
    });
    try testing.expect(answer == .refused);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "failed with exit code 2") != null);

    var no_daemon = FakeRunner{ .gpa = gpa, .replies = &.{
        .{ .code = 1, .stderr = "error: cannot connect to socket at '/nix/var/nix/daemon-socket'" },
    } };
    defer no_daemon.deinit();

    const stopped = try realise(arena, testing.io, no_daemon.runner(), &driver, .{
        .derivation_path = drv,
        .installable = "/work#packages.x86_64-linux.default",
    });
    try testing.expect(stopped == .refused);
    try testing.expect(std.mem.indexOf(u8, stopped.refused, "daemon could not be reached") != null);
}

test "the seam an evaluation runs against writes no object and authorises no build" {
    const gpa = testing.allocator;
    var driver = backend.Driver.init(gpa, evaluating);
    defer driver.deinit();

    // Import from derivation reaches `build_paths`, and this seam has none,
    // so an evaluation cannot build its own input however it is written.
    try testing.expect(evaluating.vtable.build_paths == null);
    try testing.expect(evaluating.vtable.read_file == null);
    try testing.expectError(
        backend.Error.BuildRefused,
        driver.build(&.{example_drv}, .normal),
    );
}
