//! The model asks for a program by name, Chock resolves the program with Nix,
//! and the program joins the toolchain the sandbox carries.
//!
//! ## The same operation as the dev shell, with a different input
//!
//! `lib/chock-nix/DevShell.zig` already turns a project into two answers: the
//! environment a tool call runs with, and the store paths the sandbox mounts.
//! Provisioning is that operation with one package as its input instead of a
//! flake's dev shell, so it takes the same road: realise, ask for the
//! transitive closure, and hand back store paths. `store.parsePathList` is
//! shared with `store.closureOf` for that reason, and the mount set a
//! provisioned package produces is the same kind of value
//! `DevShell.store_paths` is.
//!
//! ## The model names a program. The project names where programs come from
//!
//! **This is the whole of the safety argument and it is a property of the
//! types here.** `Request.program` is checked by `checkName` before anything
//! is built, and the rule refuses every character that could make it
//! something other than a name: no `#`, so it cannot select another flake's
//! attribute; no `:`, so it cannot be a URL; no `/`, so it cannot be a path
//! or a store path; no whitespace and no `-` in the first position, so it
//! cannot be read as an option. `Request.registry` is where those names are
//! looked up, and it comes from the project's configuration and never from
//! the model.
//!
//! So the installable this builds is always `<registry>#<name>`, and the
//! worst a model can ask for is a package that the registry does not have.
//! That answers with a plain refusal, which is the point of the whole file.
//!
//! ## Nothing here talks to Nix
//!
//! `Runner` is the seam. The real one runs `nix`; the one the tests use
//! answers from a table. **A test that builds a derivation is not a test, it
//! is a build**, so every rule in this file is pinned with no daemon, no
//! network, and no store: the name rule, the installable, the two commands,
//! the closure, the `bin` directories, and each refusal message.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const proc = @import("proc.zig");
const store = @import("store.zig");

pub const Error = std.mem.Allocator.Error || error{
    /// The `nix` command could not be run at all. Distinct from a `nix` that
    /// ran and refused: that is a `Answer.refused`, which the model reads.
    RunnerFailed,
};

/// Where a program name is resolved when the project's configuration says
/// nothing. The flake registry entry every Nix installation has.
pub const default_registry = "nixpkgs";

/// The longest program name this accepts. A package name is a word. This
/// bounds a model that sends a paragraph.
pub const max_name_bytes: usize = 128;

/// Why a program name was refused before anything was built.
pub const NameError = error{
    NameEmpty,
    NameTooLong,
    /// The name holds a character a package name may not have. See
    /// `checkName`, which lists every character that is allowed and says why
    /// the rest are not.
    NameNotAPackage,
};

/// True when `character` may appear in a package name.
///
/// Letters, digits, `-`, `_`, `+`, and `.`. The dot is here so an attribute
/// path such as `python3Packages.requests` works, which is how a real
/// registry names half of what a model asks for. Every other character is
/// refused, and the three that matter are `#`, `:` and `/`: those are what
/// would turn a name into another flake, a URL, or a path.
fn isNameCharacter(character: u8) bool {
    if (std.ascii.isAlphanumeric(character)) return true;
    return switch (character) {
        '-', '_', '+', '.' => true,
        else => false,
    };
}

/// Check a program name against the rule this file's own top comment states.
///
/// The first character must be a letter or a digit. A leading `-` would be
/// read by `nix` as an option, and a leading `.` is not a package name.
pub fn checkName(name: []const u8) NameError!void {
    if (name.len == 0) return error.NameEmpty;
    if (name.len > max_name_bytes) return error.NameTooLong;
    if (!std.ascii.isAlphanumeric(name[0])) return error.NameNotAPackage;
    if (name[name.len - 1] == '.') return error.NameNotAPackage;
    for (name) |character| {
        if (!isNameCharacter(character)) return error.NameNotAPackage;
    }
    // An empty attribute between two dots names nothing, and it is the one
    // shape the character rule alone still lets through.
    if (std.mem.indexOf(u8, name, "..") != null) return error.NameNotAPackage;
}

/// The installable `<registry>#<program>`. The caller owns the result.
///
/// **`program` must already have passed `checkName`**, which is asserted:
/// building this string is the one place a name becomes an argument to `nix`,
/// and a caller that skipped the check is a programmer error, not a runtime
/// fault.
pub fn installableFor(
    allocator: std.mem.Allocator,
    registry: []const u8,
    program: []const u8,
) std.mem.Allocator.Error![]u8 {
    std.debug.assert(registry.len != 0);
    checkName(program) catch unreachable;
    return std.fmt.allocPrint(allocator, "{s}#{s}", .{ registry, program });
}

/// What runs `nix`.
///
/// **A seam, because the thing on the other side of it is the Nix daemon.**
/// `run` is given the arguments after the program, so the argument vector
/// this file builds is the value a test reads, and the absolute path of `nix`
/// is the real runner's business. The same shape `lib/chock-core/tasks.zig`
/// gives its own `Runner`, and for the same reason.
pub const Runner = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Run `nix` with these arguments and answer what it produced. The
        /// output is owned by `allocator`.
        run: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            args: []const []const u8,
        ) Error!proc.Output,
    };

    pub fn run(
        self: Runner,
        allocator: std.mem.Allocator,
        io: std.Io,
        args: []const []const u8,
    ) Error!proc.Output {
        return self.vtable.run(self.ptr, allocator, io, args);
    }
};

/// The `Runner` that really runs `nix`, on the host, outside every sandbox.
///
/// **Never inside the sandbox.** The sandbox has no network and no daemon
/// socket, so an evaluation there fails. This runs where `DevShell.load` runs,
/// which is a caller that holds an `std.Io` able to spawn a process.
pub const Host = struct {
    /// The absolute path of `nix`, from `proc.resolve`.
    nix_program: []const u8,
    /// The environment `nix` itself runs with. The host's own, so `nix` reads
    /// the user's own configuration and the user's own registry.
    env: *const std.process.Environ.Map,
    /// Where a fault past what `Error` can say is left. A field of the host
    /// and not a parameter, because `Runner.VTable` is the seam a test
    /// replaces and a diagnostic is this one implementation's business.
    ///
    /// **What it points at is held by the allocator `resolve` is given**, and
    /// the caller releases it with the same one.
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
    ) Error!proc.Output {
        const self: *Host = @ptrCast(@alignCast(ptr));

        // `allocator` holds the answer of this call and the message with it.
        // `resolve`'s own caller passes one allocator for both and releases
        // the diagnostic with it: see `chock-nix/diagnostic.zig`.
        const sink = diagnostic.sinkOf(allocator, self.diag);

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(allocator);
        try argv.append(allocator, self.nix_program);
        try argv.appendSlice(allocator, args);

        return proc.run(allocator, io, .{
            .argv = argv.items,
            .env = self.env,
            // The same bound `store.closureOf` gives its own `nix path-info`:
            // a closure of thirty thousand paths is far below this, and a
            // `nix` that writes without end must not take the session's
            // memory with it.
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

/// One program to provision.
pub const Request = struct {
    /// The program the model asked for. Checked by `checkName` before it
    /// becomes an argument to anything.
    program: []const u8,
    /// The flake the name is looked up in. **From the project, never from
    /// the model**: see this file's own top comment.
    registry: []const u8 = default_registry,
};

/// A program that is now part of the session's toolchain. Every string is
/// owned by the allocator `resolve` was given.
pub const Provided = struct {
    /// The program that was asked for.
    program: []const u8,
    /// The installable that was realised, for the log and for the user.
    installable: []const u8,
    /// The directories that go on the `PATH` a tool call resolves `argv[0]`
    /// against: one per output the build produced. **Not checked against the
    /// disk**, because `lib/chock-core/tools.zig`'s own `resolveOnPath`
    /// already treats a directory it cannot read as an entry that does not
    /// have the program, so an output with no `bin` costs one failed stat and
    /// nothing else.
    bin_dirs: []const []const u8,
    /// The build's own outputs and everything they refer to, transitively.
    /// This is what the sandbox mounts. Sorted, with no repeats.
    store_paths: []const []const u8,
};

/// What one `resolve` produced: a program, or one sentence saying why not.
///
/// **A refusal is not an `Error`.** It is a fact about the request that the
/// model reads and can act on, the same way `lib/chock-core/tools.zig` treats
/// a program that is not found. Only a fault that says nothing about the
/// request reaches the caller as an error.
pub const Answer = union(enum) {
    provided: Provided,
    refused: []const u8,
};

/// Realise `request.program` and answer what the sandbox must mount for it.
///
/// Two commands, in this order:
///
/// 1. `nix build --no-link --print-out-paths <registry>#<program>`, which
///    realises the package and writes its outputs.
/// 2. `nix path-info -r -- <outputs>`, which is the closure. **The outputs
///    alone are not a mount set**: a program needs its dynamic linker, its
///    libc, and every library those pull in. `lib/chock-nix/store.zig` says
///    this at length, and it is the same fact here.
///
/// **Give this an arena.** Every string of the answer comes from `allocator`,
/// and so does everything the two commands wrote, which a refusal reads and a
/// success throws away. That is the same convention `DevShell.load` follows,
/// for the same reason: the answer is held for the length of a session and
/// freeing it one string at a time buys nothing.
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
        // No result symbolic link: the garbage collector root a session needs
        // is made by its caller, beside the dev shell's own, and a `result`
        // link in the user's project directory is litter.
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

    var closure_args: std.ArrayList([]const u8) = .empty;
    defer closure_args.deinit(allocator);
    try closure_args.appendSlice(allocator, &.{ "path-info", "-r", "--" });
    for (out_paths) |path| try closure_args.append(allocator, path);

    const listed = try runner.run(allocator, io, closure_args.items);
    if (!listed.succeeded()) {
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} was built and what it needs could not be read, so it was not added to the " ++
                "toolchain. Nix said: {s}",
            .{ installable, lastLine(listed.stderr) },
        ) };
    }

    const closure = try store.parsePathList(allocator, listed.stdout);

    const bin_dirs = try allocator.alloc([]const u8, out_paths.len);
    for (out_paths, bin_dirs) |path, *slot| {
        slot.* = try std.fmt.allocPrint(allocator, "{s}/bin", .{path});
    }

    return .{ .provided = .{
        .program = request.program,
        .installable = installable,
        .bin_dirs = bin_dirs,
        .store_paths = closure,
    } };
}

/// One sentence for a name this file refuses before it builds anything.
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

/// The three failures that really happen, in the words of what to do next.
///
/// `error: attribute 'foo' missing`, passed through raw, is a confusing
/// failure: it names an attribute the model never wrote
/// and says nothing about the request. Each case here names the request and
/// one action.
///
/// Anything else falls through to the last line Nix wrote, which is where Nix
/// puts its own message, with the whole trace left out. **A refusal costs one
/// turn and a confusing failure costs several**, so the last resort is still
/// one line.
pub fn explainFailure(
    allocator: std.mem.Allocator,
    request: Request,
    stderr: []const u8,
) std.mem.Allocator.Error![]u8 {
    if (saysNoSuchPackage(stderr)) {
        // Nix writes its own list of near names, measured against a real
        // registry, and it is the most useful sentence in the whole trace.
        // Carried through when there is one: it is the difference between a
        // model that guesses a second name and one that reads a real one.
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

/// True when Nix said the attribute is not there. Every spelling Nix uses for
/// it, because the message changed between versions and a reader that knows
/// only one spelling degrades to the raw trace on the next release.
fn saysNoSuchPackage(stderr: []const u8) bool {
    const spellings = [_][]const u8{
        "does not provide attribute",
        "attribute '",
        "flake output attribute",
        "cannot find flake attribute",
    };
    for (spellings) |spelling| {
        if (std.mem.indexOf(u8, stderr, spelling) == null) continue;
        // `attribute '...'` alone appears in messages that are not about a
        // missing package, so it counts only beside a word that says missing.
        if (std.mem.eql(u8, spelling, "attribute '")) {
            if (std.mem.indexOf(u8, stderr, "missing") == null) continue;
        }
        return true;
    }
    return false;
}

/// Nix's own "Did you mean" line, trimmed and bounded, or an empty slice when
/// it wrote none. Measured against a real registry on 2026-08-22: `nix build
/// nixpkgs#rg` answers "Did you mean one of erg, gg, mg, rc or reg?" under the
/// error, and that line is worth more to a model than the rest of the trace
/// put together.
fn suggestionIn(stderr: []const u8) []const u8 {
    const marker = "Did you mean";
    const at = std.mem.indexOf(u8, stderr, marker) orelse return "";
    const rest = stderr[at..];
    const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
    const line = std.mem.trim(u8, rest[0..end], " \t\r");
    if (line.len > max_raw_bytes) return line[0..max_raw_bytes];
    return line;
}

/// True when Nix could not reach its daemon.
fn saysNoDaemon(stderr: []const u8) bool {
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

/// True when Nix could not fetch what it needed.
fn saysNoNetwork(stderr: []const u8) bool {
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

/// How much of one raw Nix line reaches the model. A trace line can be a
/// whole file of Nix source; this keeps the sentence a sentence.
pub const max_raw_bytes: usize = 400;

/// The last line that says anything, bounded at `max_raw_bytes`. Nix writes
/// its own message last and its trace before it, so this is the line a person
/// reads first.
fn lastLine(stderr: []const u8) []const u8 {
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

/// A `Runner` that runs nothing. Every test in this file uses one, which is
/// the point of the seam: none of them reaches the network, the Nix daemon,
/// or the store.
const FakeRunner = struct {
    /// What the next call answers, in order. A call past the end is a
    /// programmer error in the test itself.
    replies: []const Reply,
    /// The arguments of every call made, so a test reads what was really
    /// asked for rather than trusting that it was.
    seen: std.ArrayList([]const []const u8) = .empty,
    gpa: std.mem.Allocator,
    calls: usize = 0,

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
    ) Error!proc.Output {
        _ = io;
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));
        std.debug.assert(self.calls < self.replies.len);

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

    // Each of these would be something other than a name once it reached
    // `nix`: another flake, a URL, a path, a store path, an option, and an
    // attribute path with a hole in it.
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

    // And an ordinary name passes, or the rule would refuse everything.
    try checkName("ripgrep");
    try checkName("python3Packages.requests");
    try checkName("gcc14");
    try checkName("gtk+");
    try checkName("nodejs_22");

    // Proof that nothing was run: a fake with no replies at all asserts on
    // its first call, so a `resolve` that reached the runner would fail here.
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

    // The installable is the project's registry and the model's name, joined
    // by Chock. The model never wrote a `#`.
    try testing.expectEqualStrings("nixpkgs#ripgrep", provided.installable);

    try testing.expectEqual(@as(usize, 2), fake.seen.items.len);
    const build = fake.seen.items[0];
    try testing.expectEqualStrings("build", build[0]);
    try testing.expectEqualStrings("--no-link", build[1]);
    try testing.expectEqualStrings("--print-out-paths", build[2]);
    try testing.expectEqualStrings("nixpkgs#ripgrep", build[3]);

    // The second asks what the output needs. **The output alone is not a
    // mount set**: a program with no libc in the tree starts and dies in its
    // interpreter.
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
    // Every output is asked about and every output's `bin` is offered. A
    // package that puts its programs in a second output, which `git` and
    // `openssl` both do, would otherwise be provisioned and still not found.
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

    // The registry is the project's, so a project that pins its own nixpkgs
    // gets programs from the same one its dev shell came from. The model has
    // no way to name this: `Request.registry` is not read from a tool call.
    const answer = try resolve(arena, testing.io, fake.runner(), .{
        .program = "tool",
        .registry = "git+file:///srv/our-nixpkgs",
    });
    try testing.expectEqualStrings("git+file:///srv/our-nixpkgs#tool", answer.provided.installable);
}

test "a missing attribute is one sentence naming the package, not a nix trace" {
    const gpa = testing.allocator;

    // The real message, byte for byte, from `nix build nixpkgs#rg` on
    // 2026-08-22. Passed through raw it names an attribute the model never
    // wrote and buries the one line that helps.
    const raw =
        \\error: flake 'flake:nixpkgs' does not provide attribute 'packages.aarch64-linux.rg', 'defaultPackage.aarch64-linux.rg', 'legacyPackages.aarch64-linux.rg' or 'rg'
        \\       Did you mean one of erg, gg, mg, rc or reg?
    ;
    const text = try explainFailure(gpa, .{ .program = "rg" }, raw);
    defer gpa.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "no package called \"rg\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "nixpkgs") != null);
    try testing.expect(std.mem.indexOf(u8, text, "ripgrep") != null);
    // Nix's own near names are kept, because they are measured against the
    // real registry and a guess is not.
    try testing.expect(std.mem.indexOf(u8, text, "Did you mean one of erg") != null);
    try testing.expect(std.mem.indexOf(u8, text, "legacyPackages") == null);
}

test "a missing attribute with no near names says so without a dangling sentence" {
    const gpa = testing.allocator;
    const raw = "error: flake 'flake:nixpkgs' does not provide attribute 'qqqq' or 'qqqq'";
    const text = try explainFailure(gpa, .{ .program = "qqqq" }, raw);
    defer gpa.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "no package called \"qqqq\"") != null);
    // No trailing "Nix said:" with nothing after it, which is what a
    // formatter that always printed the field would leave.
    try testing.expect(std.mem.indexOf(u8, text, "Nix said") == null);
    try testing.expect(std.mem.endsWith(u8, text, "already has."));
}

test "a daemon that is not there says provisioning is off, not that the package is wrong" {
    const gpa = testing.allocator;
    const raw = "error: cannot connect to socket at '/nix/var/nix/daemon-socket/socket': Connection refused";
    const text = try explainFailure(gpa, .{ .program = "ripgrep" }, raw);
    defer gpa.free(text);

    // The distinction earns its place: a model told "there is no package
    // called ripgrep" would try three more names, and each one costs a turn.
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
    // Bounded, and the trace above it is gone. A model handed two hundred
    // lines of Nix learns nothing and pays for every token of it.
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

    // One command, and no second one: there is nothing to ask the closure of.
    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "produced no output path") != null);
}

test "the installable is always the registry and the name, and asserts the check ran" {
    const gpa = testing.allocator;
    const text = try installableFor(gpa, "nixpkgs", "ripgrep");
    defer gpa.free(text);
    try testing.expectEqualStrings("nixpkgs#ripgrep", text);
    // Exactly one `#`, so nothing after it can select a different flake.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "#"));
}
