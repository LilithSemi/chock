//! The packages a project declares, resolved on the host and left where the
//! build already looks for them.
//!
//! ## The fault this removes
//!
//! **An agent ran `zig build` inside the sandbox and it failed for want of a
//! network.** The sandbox's network is `none`, which is the point of the
//! whole project, and a project that names a dependency by URL cannot build
//! until somebody has fetched it. This blocks the case Chock exists for,
//! which is Chock working on Chock: its own `build.zig.zon` names `phantom`
//! and `vulcan` by URL.
//!
//! ## The shape, which is `provide_tool`'s own
//!
//! `lib/chock-nix/provision.zig` answers the same question for a program: the
//! harness does the network work **on the host**, where the network and the
//! policy live, and the result appears inside the sandbox. This is that
//! mechanism with a manifest as its input instead of a package name.
//!
//! **Everything not named in the manifest stays unreachable.** The manifest
//! carries a hash for every dependency and the fetcher checks it, so a wrong
//! package cannot be substituted for a right one, and a package the project
//! did not declare is never fetched at all.
//!
//! ## Where Zig really puts a package, measured
//!
//! Measured against Zig 0.16.0 on 2026-08-24, because the layout changed and
//! the old belief that a package lives in the global cache is now wrong:
//!
//! | Directory | What is in it | Whose it is |
//! |---|---|---|
//! | `<project>/zig-pkg/<name>-<version>-<hash>` | the **unpacked** package a build reads | the project |
//! | `<global cache>/p/<name>-<version>-<hash>.tar.gz` | the **downloaded tarball**, and nothing else | the machine |
//!
//! Four facts follow from that, each measured rather than reasoned:
//!
//! 1. **A build with `zig-pkg` filled in needs neither the network nor the
//!    global cache.** With the download cache emptied and the source URL
//!    unreachable, `zig build` still finished and wrote its artefact.
//! 2. **`zig build --fetch=all` fills `zig-pkg` from the tarball cache with
//!    no access to the source.** The hash in the manifest is what makes that
//!    lookup possible, so it is also the check.
//! 3. **`zig build --fetch=all` never compiles or runs `build.zig`.** Proved
//!    with a `build.zig` that does not compile: the fetch still exited 0.
//!    That matters more than it looks. `build.zig` is a file the agent can
//!    write, and this command runs **outside** every sandbox, so a fetch that
//!    ran the build script would be the agent choosing what the host runs.
//! 4. **`zig fetch <url>` is the wrong command.** It has no expected hash, so
//!    it goes to the source every time and never reuses the tarball cache:
//!    measured, with the tarball present in `p/` and the source moved away,
//!    it failed. It also resolves one URL rather than the manifest's tree.
//!
//! `zig-pkg` is Zig's own name for that directory, it is hardcoded in the
//! compiler, and no option overrides it.
//!
//! ## Two directories, two lifetimes, and that is the design
//!
//! `zig-pkg` is **inside the project**, so it is inside the workspace, so it
//! is per session: the workspace is built again for every session and Zig's
//! own `.gitignore` line keeps it out of a git worktree. The tarball cache is
//! inside this project's toolchain cache, which outlives the session: see
//! `lib/chock-core/cache.zig`.
//!
//! So the second session and every session after it does the unpacking with
//! no network at all, and only the first one downloads.
//!
//! ## Automatic at session start
//!
//! **What automatic does not cover**: an agent that adds a dependency to the
//! manifest part way through a session. That needs a tool, it belongs in the
//! `provide_tool` family, and it is not built here.
//!
//! ## Why not Nix, in a project that leans on Nix everywhere else
//!
//! Because Nix cannot put a package where Zig looks. The manifest's hash is
//! Zig's own multihash over the unpacked tree, not a Nix hash, and a Nix
//! fetch produces a store path, which is not a `zig-pkg` entry and is not a
//! `p/` tarball. Chock would have to unpack it into `zig-pkg` itself and
//! hash it itself, which is re-implementing the one part that already exists
//! and is already the check. `flake.nix` remains the right place for what a
//! project needs **every** time; this is for what a project's own manifest
//! declares.

const std = @import("std");

const cache = @import("cache.zig");
const diagnostic = @import("diagnostic.zig");
/// Why a piece of the loop's own scaffolding could not be made or kept. One
/// type for the whole module: see `chock-core/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;
/// Where a fault goes, and who owns the string it names. See
/// `chock-core/diagnostic.zig`.
pub const Sink = diagnostic.Sink;
/// Build a `Sink` from an allocator and the slot a caller passed. Release the
/// message with that same allocator: see `Diagnostic.deinit`.
pub const sinkOf = diagnostic.sinkOf;

pub const Error = std.mem.Allocator.Error || error{
    /// `zig` could not be run at all. Distinct from a `zig` that ran and
    /// failed: that is an `Answer.refused`, which a person and the agent both
    /// read.
    RunnerFailed,
};

/// The file a Zig project declares its dependencies in.
pub const manifest_name = "build.zig.zon";

/// The file the fetch is pointed at, beside the manifest. Zig puts `zig-pkg`
/// beside this file and never beside the current directory, which is what
/// makes the resolution independent of where the harness happens to stand.
pub const build_file_name = "build.zig";

/// Where Zig unpacks a package, relative to the project. **Zig's own name,
/// hardcoded in the compiler**: no option overrides it, so this is a fact to
/// record and never a choice to make.
pub const package_leaf = "zig-pkg";

/// Where the downloaded tarballs go, relative to this project's toolchain
/// cache directory.
///
/// **Derived from `cache.xdg_cache_leaf` and never spelled out again**, so
/// this is the very directory a `run_command` call's own `XDG_CACHE_HOME`
/// names inside the sandbox. A session that fetches on the host and a build
/// that runs in the sandbox therefore share one download cache, and a second
/// spelling of the path is how the two would quietly stop agreeing.
pub const download_cache_leaf = cache.xdg_cache_leaf ++ "/zig";

/// How much of a manifest is read before the question is given up on. A
/// `build.zig.zon` is a few hundred bytes and this is a bound against a file
/// that is not one at all.
pub const max_manifest_bytes: usize = 1024 * 1024;

/// How much of what `zig` wrote is kept. A fetch failure is a few lines and
/// this bounds a compiler that writes without end.
pub const max_stderr_bytes: usize = 1024 * 1024;

/// How much of what `zig` wrote reaches the message a person and the agent
/// read.
pub const max_raw_bytes: usize = 600;

/// How many of `zig`'s own lines reach that message. **The first lines and
/// not the last**: Zig writes the error first and its notes after it, which
/// is the other way round from Nix. See `firstLines`.
pub const max_raw_lines: usize = 6;

/// Whether this project has anything to resolve at all.
pub const Declared = enum {
    /// There is no manifest, or the manifest declares no dependency. Nothing
    /// is run and nothing is fetched.
    none,
    /// The manifest declares at least one dependency, or it could not be read
    /// and only `zig` can say. See `declaredIn` for why an unreadable
    /// manifest answers this way.
    some,
};

/// The host path of the directory Zig unpacks this project's packages into.
/// The caller owns the result.
pub fn packageDirFor(
    allocator: std.mem.Allocator,
    project_dir: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ project_dir, package_leaf });
}

/// The host path of the directory the downloaded tarballs go in. The caller
/// owns the result.
pub fn downloadCacheFor(
    allocator: std.mem.Allocator,
    cache_dir: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ cache_dir, download_cache_leaf });
}

/// Whether `project_dir` declares a dependency, read from its own manifest.
///
/// **A missing manifest is `none` and an unreadable one is `some`.** The two
/// are different questions. A project with no `build.zig.zon` is not a Zig
/// project and must pay nothing at all for this file to exist. A manifest
/// that is there and cannot be read is a project Chock has no answer about,
/// and `zig` reading it and saying so is worth more than silence.
pub fn declaredIn(
    allocator: std.mem.Allocator,
    io: std.Io,
    project_dir: []const u8,
) Declared {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ project_dir, manifest_name }) catch
        return .none;

    const text = std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(max_manifest_bytes),
    ) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return .none,
        else => return .some,
    };
    defer allocator.free(text);

    return if (declaresAny(text)) .some else .none;
}

/// True when this manifest text has a `.dependencies` block with anything in
/// it.
///
/// **A reader and not a parser.** The question is only whether the block is
/// empty, the cost of a wrong yes is one `zig` run that says nothing is to be
/// done, and the cost of a wrong no is a build that fails: so this is written
/// to be wrong towards yes. A `.dependencies` inside a string would be read
/// as the real thing, which costs that one run.
fn declaresAny(text: []const u8) bool {
    const name = "." ++ "dependencies";
    var at: usize = 0;
    while (std.mem.indexOfPos(u8, text, at, name)) |found| {
        at = found + name.len;

        // The character before the dot must not continue an identifier, or
        // this is the tail of a longer name and not the field.
        if (found != 0 and isIdentifierCharacter(text[found - 1])) continue;

        var index = skipBlank(text, at);
        if (index >= text.len or text[index] != '=') continue;
        index = skipBlank(text, index + 1);
        if (!std.mem.startsWith(u8, text[index..], ".{")) continue;

        index = skipBlank(text, index + 2);
        return index < text.len and text[index] != '}';
    }
    return false;
}

fn isIdentifierCharacter(character: u8) bool {
    return std.ascii.isAlphanumeric(character) or character == '_';
}

/// The first index at or after `from` that is neither whitespace nor part of
/// a line comment.
fn skipBlank(text: []const u8, from: usize) usize {
    var index = from;
    while (index < text.len) {
        if (std.ascii.isWhitespace(text[index])) {
            index += 1;
            continue;
        }
        if (std.mem.startsWith(u8, text[index..], "//")) {
            const end = std.mem.indexOfScalarPos(u8, text, index, '\n') orelse return text.len;
            index = end + 1;
            continue;
        }
        return index;
    }
    return text.len;
}

/// The arguments after the program, for one resolution. The caller owns the
/// slice and every string in it.
///
/// **`--fetch=all` and not the default `needed`.** The default leaves a lazy
/// dependency to be fetched when the build script asks for it, which is
/// inside the sandbox, where there is no network. Everything the manifest
/// declares is fetched here or it cannot be fetched at all.
///
/// **`--build-file` and not a working directory.** Zig puts `zig-pkg` beside
/// the build file, measured, so the answer does not depend on where the
/// harness stands when it runs this.
pub fn argvFor(
    allocator: std.mem.Allocator,
    request: Request,
) std.mem.Allocator.Error![]const []const u8 {
    var args: std.ArrayList([]const u8) = .empty;
    errdefer args.deinit(allocator);

    try args.append(allocator, "build");
    try args.append(allocator, "--fetch=all");
    try args.append(allocator, "--build-file");
    try args.append(allocator, try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ request.project_dir, build_file_name },
    ));
    try args.append(allocator, "--global-cache-dir");
    try args.append(allocator, try downloadCacheFor(allocator, request.cache_dir));
    return args.toOwnedSlice(allocator);
}

/// What one `Runner` call produced.
///
/// **Standard output is not here, because it is not read.** A fetch that
/// works writes nothing at all, and a fetch that fails writes to standard
/// error. Piping one stream rather than two is also what lets `Host` read it
/// with no concurrency: two pipes read one after the other is the shape that
/// deadlocks when the second one fills.
pub const Output = struct {
    term: std.process.Child.Term,
    stderr: []u8,

    pub fn deinit(self: *Output, allocator: std.mem.Allocator) void {
        allocator.free(self.stderr);
        self.* = undefined;
    }

    /// True when `zig` exited 0.
    pub fn succeeded(self: Output) bool {
        return switch (self.term) {
            .exited => |code| code == 0,
            else => false,
        };
    }
};

/// What runs `zig`.
///
/// **A seam, because the thing on the other side of it is a compiler and a
/// network.** `run` is given the arguments after the program, so the argument
/// vector this file builds is the value a test reads, and the absolute path
/// of `zig` is the real runner's business.
pub const Runner = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Run `zig` with these arguments and answer what it produced. The
        /// output is owned by `allocator`.
        run: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            args: []const []const u8,
        ) Error!Output,
    };

    pub fn run(
        self: Runner,
        allocator: std.mem.Allocator,
        io: std.Io,
        args: []const []const u8,
    ) Error!Output {
        return self.vtable.run(self.ptr, allocator, io, args);
    }
};

/// The `Runner` that really runs `zig`, on the host, outside every sandbox.
///
/// **Never inside the sandbox.** The sandbox has no network, which is the
/// whole reason this file exists. This runs where `DevShell.load` runs, which
/// is a caller that holds an `std.Io` able to spawn a process.
pub const Host = struct {
    /// The absolute path of `zig`. **The dev shell's own**, so the compiler
    /// that resolves the packages is the compiler that builds with them: two
    /// versions of Zig do not agree about a manifest.
    program: []const u8,
    /// The environment `zig` itself runs with. The host's own, so a proxy or
    /// a certificate bundle the user configured is the one the fetch uses.
    env: *const std.process.Environ.Map,
    /// Where a fault past what `Error` can say is left, and who owns the
    /// message. A field of the host and not a parameter, because
    /// `Runner.VTable` is the seam a test replaces and a diagnostic is this
    /// one implementation's business.
    ///
    /// **Not the working allocator of `runFn`.** That one holds the output of
    /// the call, and a caller is free to make it an arena it drops the moment
    /// the call fails. The message is read after that. See
    /// `chock-core/diagnostic.zig`.
    diag: ?Sink = null,

    pub fn runner(self: *const Host) Runner {
        return .{ .ptr = @constCast(self), .vtable = &vtable };
    }

    const vtable = Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        args: []const []const u8,
    ) Error!Output {
        const self: *Host = @ptrCast(@alignCast(ptr));
        std.debug.assert(std.fs.path.isAbsolute(self.program));

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(allocator);
        try argv.append(allocator, self.program);
        try argv.appendSlice(allocator, args);

        var child = std.process.spawn(io, .{
            .argv = argv.items,
            .environ_map = self.env,
            .stdin = .ignore,
            // Read below on `Output`: one pipe, so one sequential read
            // cannot back up behind a stream nobody is draining.
            .stdout = .ignore,
            .stderr = .pipe,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                diagnostic.notePath(self.diag, .packages_not_resolved, self.program, err);
                return error.RunnerFailed;
            },
        };

        const stderr = readStream(allocator, io, child.stderr.?) catch |err| {
            _ = child.wait(io) catch {};
            switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    diagnostic.notePath(self.diag, .packages_not_resolved, self.program, err);
                    return error.RunnerFailed;
                },
            }
        };
        errdefer allocator.free(stderr);

        const term = child.wait(io) catch |err| {
            diagnostic.notePath(self.diag, .packages_not_resolved, self.program, err);
            return error.RunnerFailed;
        };

        return .{ .term = term, .stderr = stderr };
    }

    fn readStream(allocator: std.mem.Allocator, io: std.Io, file: std.Io.File) ![]u8 {
        var file_reader: std.Io.File.Reader = .initStreaming(file, io, &.{});
        return file_reader.interface.allocRemaining(allocator, .limited(max_stderr_bytes));
    }
};

/// One project to resolve the packages of.
pub const Request = struct {
    /// The host path of the workspace this session works in. **The
    /// workspace and never the user's own project directory**: the workspace
    /// is what the sandbox mounts and the build runs in, and it is where the
    /// unpacked packages have to land.
    project_dir: []const u8,
    /// The host path of this project's toolchain cache, the directory
    /// `cache.makeLayout` built. The downloaded tarballs go below it, so they
    /// outlive the session that fetched them.
    cache_dir: []const u8,
};

/// What one resolution left behind.
pub const Resolved = struct {
    /// Where the unpacked packages are, on the host. Owned by the allocator
    /// `resolve` was given.
    package_dir: []const u8,
    /// How many packages are unpacked there now. **Read from the disk and
    /// never counted from the manifest**: the manifest names the project's
    /// own dependencies and the tree below them is fetched as well, so a
    /// number from the manifest would be a number for nothing.
    ///
    /// Zero is a legitimate answer for a project whose every dependency is a
    /// path into itself, which needs no fetching and gets no entry here.
    packages: usize,
};

/// What one `resolve` produced.
///
/// **A refusal is not an `Error`.** It is a fact about this project that a
/// person and the agent both read and can act on. Only a fault that says
/// nothing about the project reaches the caller as an error.
pub const Answer = union(enum) {
    /// This project declares no dependency, so nothing was run.
    nothing_declared,
    resolved: Resolved,
    refused: []const u8,
};

/// Resolve everything `request.project_dir`'s own manifest declares.
///
/// **Give this an arena.** Every string of the answer comes from `allocator`,
/// and so does everything `zig` wrote, which a refusal reads and a success
/// throws away. The same convention `provision.resolve` follows, for the same
/// reason.
pub fn resolve(
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: Runner,
    request: Request,
) Error!Answer {
    if (declaredIn(allocator, io, request.project_dir) == .none) return .nothing_declared;

    const args = try argvFor(allocator, request);
    const output = try runner.run(allocator, io, args);
    if (!output.succeeded()) return .{ .refused = try explainFailure(allocator, output.stderr) };

    const package_dir = try packageDirFor(allocator, request.project_dir);
    return .{ .resolved = .{
        .package_dir = package_dir,
        .packages = countPackages(io, package_dir),
    } };
}

/// How many packages are unpacked in `package_dir`.
///
/// A directory that cannot be read at all answers zero rather than an error.
/// The fetch has already said it worked, and a count is for the line a person
/// reads, so a count that could not be taken is not a reason to turn a
/// success into a failure.
pub fn countPackages(io: std.Io, package_dir: []const u8) usize {
    var dir = std.Io.Dir.openDirAbsolute(io, package_dir, .{ .iterate = true }) catch return 0;
    defer dir.close(io);

    var total: usize = 0;
    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (entry.kind != .directory) continue;
        total += 1;
    }
    return total;
}

/// One message for a fetch that did not work.
///
/// **It says what happens next and not only what went wrong.** The reader is
/// a person at a terminal and an agent that is about to try a build, and the
/// fact both of them need is that the build will fail and why: the sandbox
/// has no network on purpose, so a dependency that is not resolved now is not
/// resolvable later from inside.
pub fn explainFailure(
    allocator: std.mem.Allocator,
    stderr: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "the dependencies {s} declares could not be resolved, so a build in this session will " ++
            "fail: the sandbox has no network, and nothing fetches a package from inside it. " ++
            "Correct the dependency the manifest names, or work on something that does not " ++
            "need a build. Zig said: {s}",
        .{ manifest_name, firstLines(stderr) },
    );
}

/// The first lines that say anything, bounded twice.
///
/// **The first and not the last**, which is the other way round from
/// `provision.lastLine`. Measured on 2026-08-24: Zig writes
/// `error: unable to discover remote git server capabilities` first and the
/// manifest line and the URL under it, so the head of the output is the part
/// that names the dependency.
fn firstLines(stderr: []const u8) []const u8 {
    var end: usize = 0;
    var lines: usize = 0;
    var at: usize = 0;
    while (at < stderr.len and lines < max_raw_lines) {
        const break_at = std.mem.indexOfScalarPos(u8, stderr, at, '\n') orelse stderr.len;
        const line = std.mem.trim(u8, stderr[at..break_at], " \t\r");
        if (line.len != 0) {
            lines += 1;
            end = break_at;
        }
        at = break_at + 1;
    }
    const kept = std.mem.trim(u8, stderr[0..end], " \t\r\n");
    if (kept.len == 0) return "nothing";
    if (kept.len > max_raw_bytes) return kept[0..max_raw_bytes];
    return kept;
}

const testing = std.testing;

/// A `Runner` that runs nothing. Every test in this file uses one, which is
/// the point of the seam: none of them reaches a compiler, a network, or a
/// cache.
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
    ) Error!Output {
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

/// A project directory with the manifest text a test wants in it.
fn projectWith(tmp: std.testing.TmpDir, buffer: []u8, manifest: ?[]const u8) ![]const u8 {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &path_buffer);
    const project = try std.fmt.bufPrint(buffer, "{s}/project", .{path_buffer[0..length]});
    std.Io.Dir.createDirAbsolute(testing.io, project, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    if (manifest) |text| {
        var manifest_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&manifest_buffer, "{s}/{s}", .{ project, manifest_name });
        var file = try std.Io.Dir.createFileAbsolute(testing.io, path, .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, text);
    }
    return project;
}

test "a project with no manifest, and one whose dependency block is empty, are both nothing to resolve" {
    // The guard that makes this file free for every project that is not a Zig
    // project with dependencies. Without it, session start would spawn a
    // compiler for a directory of shell scripts.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const none = try projectWith(tmp, &buffer, null);
    try testing.expectEqual(Declared.none, declaredIn(testing.allocator, testing.io, none));

    var empty_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const empty = try projectWith(tmp, &empty_buffer,
        \\.{
        \\    .name = .thing,
        \\    .version = "0.1.0",
        \\    .dependencies = .{},
        \\    .paths = .{""},
        \\}
        \\
    );
    try testing.expectEqual(Declared.none, declaredIn(testing.allocator, testing.io, empty));

    // A manifest with no `.dependencies` field at all, which is what `zig
    // init` writes and what a project with no dependency keeps.
    var absent_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const absent = try projectWith(tmp, &absent_buffer,
        \\.{
        \\    .name = .thing,
        \\    .version = "0.1.0",
        \\    .paths = .{""},
        \\}
        \\
    );
    try testing.expectEqual(Declared.none, declaredIn(testing.allocator, testing.io, absent));
}

test "a manifest with one dependency is something to resolve, whatever is written around it" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Chock's own manifest, in shape: a URL and a hash per dependency.
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project = try projectWith(tmp, &buffer,
        \\.{
        \\    .name = .chock,
        \\    .dependencies = .{
        \\        .vulcan = .{
        \\            .url = "git+https://github.com/Midstall/vulcan#a2d2a42",
        \\            .hash = "vulcan-0.0.0-d6EfZJ",
        \\        },
        \\    },
        \\}
        \\
    );
    try testing.expectEqual(Declared.some, declaredIn(testing.allocator, testing.io, project));

    // A comment between the brace and the first entry is still an entry, and
    // a comment in an empty block is still empty. This is the one shape a
    // reader that only looked at the next character would get wrong.
    try testing.expect(declaresAny(".dependencies = .{ // one is coming\n.a = .{} }"));
    try testing.expect(!declaresAny(".dependencies = .{ // none yet\n}"));

    // A field whose name ends in the same letters is not the field.
    try testing.expect(!declaresAny(".build_dependencies = .{ .a = .{} }"));
    // And no block at all is nothing to do.
    try testing.expect(!declaresAny(".{ .name = .thing }"));
}

test "the command fetches every lazy dependency, reads the project's own build file, and caches outside it" {
    const gpa = testing.allocator;

    const args = try argvFor(gpa, .{
        .project_dir = "/work/session/project",
        .cache_dir = "/home/user/.cache/chock/projects/abc",
    });
    defer {
        gpa.free(args[3]);
        gpa.free(args[5]);
        gpa.free(args);
    }

    try testing.expectEqual(@as(usize, 6), args.len);
    try testing.expectEqualStrings("build", args[0]);
    // **`all` and not the default.** A lazy dependency left for the build
    // script is fetched inside the sandbox, where there is no network.
    try testing.expectEqualStrings("--fetch=all", args[1]);
    // The build file, so `zig-pkg` lands beside the project's own manifest
    // whatever directory the harness is standing in.
    try testing.expectEqualStrings("--build-file", args[2]);
    try testing.expectEqualStrings("/work/session/project/build.zig", args[3]);
    // And the tarballs go in the toolchain cache, which outlives the session,
    // rather than in the workspace, which does not.
    try testing.expectEqualStrings("--global-cache-dir", args[4]);
    try testing.expectEqualStrings(
        "/home/user/.cache/chock/projects/abc/home/.cache/zig",
        args[5],
    );
}

test "the unpacked packages are in the workspace and the tarballs are in the toolchain cache" {
    const gpa = testing.allocator;

    const packages = try packageDirFor(gpa, "/work/session/project");
    defer gpa.free(packages);
    try testing.expectEqualStrings("/work/session/project/zig-pkg", packages);
    try testing.expect(std.mem.startsWith(u8, packages, "/work/session/project/"));

    const downloads = try downloadCacheFor(gpa, "/cache/abc");
    defer gpa.free(downloads);
    try testing.expect(!std.mem.startsWith(u8, downloads, "/work/session/project/"));

    // The download cache is the very directory the sandbox's own
    // `XDG_CACHE_HOME` names, built from `cache.zig`'s leaf and never spelled
    // out a second time. A build inside the sandbox and a fetch on the host
    // therefore share one set of tarballs.
    try testing.expect(std.mem.startsWith(u8, download_cache_leaf, cache.xdg_cache_leaf ++ "/"));
    try testing.expectEqualStrings(cache.xdg_cache_dir ++ "/zig", "/run/chock/cache/home/.cache/zig");
}

test "a project that declares no dependency runs no compiler at all" {
    // A fake with no replies asserts on its first call, so a `resolve` that
    // reached the runner would fail here rather than pass quietly.
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project = try projectWith(tmp, &buffer, null);

    var fake = FakeRunner{ .gpa = gpa, .replies = &.{} };
    defer fake.deinit();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const answer = try resolve(arena_state.allocator(), testing.io, fake.runner(), .{
        .project_dir = project,
        .cache_dir = "/cache/abc",
    });
    try testing.expectEqual(Answer.nothing_declared, answer);
    try testing.expectEqual(@as(usize, 0), fake.calls);
}

test "a resolution that worked reports where the packages are and how many there are" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project = try projectWith(tmp, &buffer, ".{ .dependencies = .{ .a = .{} } }");

    // What a real fetch leaves behind: one directory per package, named by
    // the hash the manifest carried. The count is read from here, not from
    // the manifest, because the tree below a dependency is fetched too.
    var packages_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const packages = try std.fmt.bufPrint(&packages_buffer, "{s}/{s}", .{ project, package_leaf });
    try std.Io.Dir.createDirAbsolute(testing.io, packages, .default_dir);
    var first_buffer: [std.fs.max_path_bytes]u8 = undefined;
    try std.Io.Dir.createDirAbsolute(
        testing.io,
        try std.fmt.bufPrint(&first_buffer, "{s}/dep-0.1.0-aaa", .{packages}),
        .default_dir,
    );
    var second_buffer: [std.fs.max_path_bytes]u8 = undefined;
    try std.Io.Dir.createDirAbsolute(
        testing.io,
        try std.fmt.bufPrint(&second_buffer, "{s}/dep-0.2.0-bbb", .{packages}),
        .default_dir,
    );

    const replies = [_]FakeRunner.Reply{.{}};
    var fake = FakeRunner{ .gpa = gpa, .replies = &replies };
    defer fake.deinit();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const answer = try resolve(arena_state.allocator(), testing.io, fake.runner(), .{
        .project_dir = project,
        .cache_dir = "/cache/abc",
    });

    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expectEqualStrings(packages, answer.resolved.package_dir);
    try testing.expectEqual(@as(usize, 2), answer.resolved.packages);
}

test "a dependency that cannot be fetched is a refusal that names the manifest and Zig's own words" {
    const gpa = testing.allocator;

    // The real message, byte for byte, from `zig build --fetch=all` against
    // an unreachable host on 2026-08-24.
    const raw =
        \\/work/project/build.zig.zon:8:20: error: unable to discover remote git server capabilities: NoAddressReturned
        \\            .url = "git+https://chock-no-such-host.invalid/x/y#0000000",
        \\                   ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    ;
    const text = try explainFailure(gpa, raw);
    defer gpa.free(text);

    // The manifest, so a person knows which file to correct.
    try testing.expect(std.mem.indexOf(u8, text, "build.zig.zon") != null);
    // The fact that decides what to do next: this cannot be fixed from
    // inside, because the sandbox has no network on purpose.
    try testing.expect(std.mem.indexOf(u8, text, "sandbox has no network") != null);
    // And Zig's own first line, which is the one that names the dependency.
    try testing.expect(std.mem.indexOf(u8, text, "NoAddressReturned") != null);
    try testing.expect(std.mem.indexOf(u8, text, "chock-no-such-host.invalid") != null);
}

test "a fetch that failed is a refusal and never an error the session start dies on" {
    // A session whose packages could not be fetched still runs: reading code,
    // writing a file and answering a question all work with no dependency
    // resolved at all. Turning this into an `Error` would end the session over
    // a build that may never be asked for.
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project = try projectWith(tmp, &buffer, ".{ .dependencies = .{ .a = .{} } }");

    const replies = [_]FakeRunner.Reply{.{
        .code = 1,
        .stderr = "build.zig.zon:8:20: error: unable to open 'x.tar.gz': FileNotFound\n",
    }};
    var fake = FakeRunner{ .gpa = gpa, .replies = &replies };
    defer fake.deinit();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const answer = try resolve(arena_state.allocator(), testing.io, fake.runner(), .{
        .project_dir = project,
        .cache_dir = "/cache/abc",
    });
    try testing.expect(std.mem.indexOf(u8, answer.refused, "FileNotFound") != null);
}

test "a compiler that writes a whole trace gives back a few lines and never the whole thing" {
    const gpa = testing.allocator;

    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(gpa);
    try raw.appendSlice(gpa, "error: the one line that names the dependency\n");
    var line: usize = 0;
    while (line < 200) : (line += 1) {
        try raw.appendSlice(gpa, "    note: a reference trace line that nobody reads\n");
    }

    const text = try explainFailure(gpa, raw.items);
    defer gpa.free(text);

    // The first line is kept, because Zig writes the error before its notes.
    try testing.expect(std.mem.indexOf(u8, text, "names the dependency") != null);
    // And the trace is not. A model handed two hundred lines learns nothing
    // and pays for every token of it.
    try testing.expect(text.len < max_raw_bytes + 400);
    try testing.expectEqual(@as(usize, max_raw_lines - 1), std.mem.count(u8, text, "note:"));
}
