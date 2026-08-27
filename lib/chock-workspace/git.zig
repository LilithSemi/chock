//! Runs `git` and reads facts out of a repository. This is the only file in Chock
//! that talks to git.
//!
//! Every call goes straight to `execve`, never through a shell: `std.process.spawn`
//! takes `argv` as an array, so a project path holding a space or a quote reaches
//! git as one argument instead of being re-split by a shell that was never asked
//! for.
//!
//! `argv[0]` is passed as the bare name `"git"`. `std.process.SpawnOptions.argv`'s
//! own doc comment says a name with no `/` in it is resolved against PATH "from the
//! parent environment", and that this search never uses `environ_map` even when one
//! is given: it always reads the ambient environment the calling process itself
//! inherited. So `git` resolves correctly whether or not `run` below hands the
//! child a replacement environment, and nothing in this file needs to find git's
//! absolute path by hand.
//!
//! `std.process.spawn`'s `environ_map`, when given, replaces the child's whole
//! environment rather than adding to it, so `run` below still has to build one:
//! this process's own environment, plus `forced_env`. But this file only ever sees
//! an `Io`, an interface with no way to ask "what environment did you start with."
//! `run` therefore takes that environment as a parameter instead of guessing at it:
//! a real caller gets it from `std.process.Init`, and every test here gets it from
//! `std.testing.environ`, both of which the standard library already builds
//! correctly for whichever OS this runs on, POSIX or not.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
/// Why a call here failed, past what `Error` can say. One type for the whole
/// module: see `chock-workspace/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;

pub const Error = error{
    /// `git` was not found on PATH. Step 1 of this task exists to keep this from
    /// ever showing up outside a broken build: see `flake.nix` and
    /// `pkgs/chock/default.nix`, which both put `git` on PATH, for the dev shell
    /// and for `nix build`'s check phase.
    NotFound,
    /// A kernel call needed to run git returned an errno this file has no specific
    /// recovery for.
    Unexpected,
    OutOfMemory,
};

/// What one `run` call produced: the exit status, and everything git wrote to
/// standard output and standard error. Present on both success and failure. A
/// nonzero exit is not turned into a bare `Error`: what git wrote to standard
/// error on a failure is the most useful thing Chock can show the user, and
/// throwing it away for a bare error would lose exactly that.
pub const Output = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: *Output, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        self.* = undefined;
    }
};

/// Environment variables forced on every git call, and why. Applied after `env` is
/// copied in, so they always win even if `env` happened to carry one of these names
/// already.
const forced_env = [_]struct { key: []const u8, value: []const u8 }{
    // A user's own ~/.gitconfig or /etc/gitconfig must not change what git tells
    // Chock. An alias, a color setting, or a core.pager there would change how a
    // command's output reads, and Chock parses that output.
    .{ .key = "GIT_CONFIG_GLOBAL", .value = "/dev/null" },
    .{ .key = "GIT_CONFIG_SYSTEM", .value = "/dev/null" },
    // git must never stop to ask a question. There is nobody in this process to
    // answer one, so a prompt left enabled would hang whatever called run.
    .{ .key = "GIT_TERMINAL_PROMPT", .value = "0" },
};

/// Run `git <argv>` with `cwd` as its working directory. `env` is the environment
/// this call starts from, `forced_env` layered on top: see this file's own doc
/// comment for why `run` cannot gather that environment on its own. `env` is not
/// modified or retained. `run` only reads it.
pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    cwd: []const u8,
    argv: []const []const u8,
    diag: ?*?Diagnostic,
) Error!Output {
    var child_env = try buildEnviron(allocator, env);
    defer child_env.deinit();

    const full_argv = try allocator.alloc([]const u8, argv.len + 1);
    defer allocator.free(full_argv);
    full_argv[0] = "git";
    @memcpy(full_argv[1..], argv);

    var child = std.process.spawn(io, .{
        .argv = full_argv,
        .cwd = .{ .path = cwd },
        .environ_map = &child_env,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch |err| return mapSpawnError(err, diag);

    const streams = try readPipes(allocator, io, &child);
    errdefer {
        allocator.free(streams.stdout);
        allocator.free(streams.stderr);
    }

    const term = child.wait(io) catch |err| {
        diagnostic.noteErr(diag, .git_wait, err);
        return error.Unexpected;
    };

    return .{ .term = term, .stdout = streams.stdout, .stderr = streams.stderr };
}

/// True if `path` is inside a git repository's work tree, false for an ordinary
/// directory. A session can be pointed at any directory, and this is how Chock
/// tells the two apart before it ever tries to build a worktree from one.
pub fn isRepository(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    path: []const u8,
    diag: ?*?Diagnostic,
) Error!bool {
    var output = try run(allocator, io, env, path, &.{ "rev-parse", "--is-inside-work-tree" }, diag);
    defer output.deinit(allocator);
    return switch (output.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

/// The root of the repository `path` sits inside, or null when `path` is not
/// inside a repository at all. A session can start anywhere under a project, in a
/// subdirectory several levels deep, so the root has to be found rather than
/// assumed to be `path` itself. The caller owns the returned slice.
pub fn topLevel(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    path: []const u8,
    diag: ?*?Diagnostic,
) Error!?[]u8 {
    var output = try run(allocator, io, env, path, &.{ "rev-parse", "--show-toplevel" }, diag);
    defer output.deinit(allocator);

    const code = switch (output.term) {
        .exited => |c| c,
        else => return null,
    };
    if (code != 0) return null;

    const trimmed = std.mem.trimEnd(u8, output.stdout, "\n");
    return try allocator.dupe(u8, trimmed);
}

/// Build the child's environment: a copy of `env`, with `forced_env` layered on
/// top. The caller keeps ownership of `env`. This returns a new, independent `Map`
/// the caller of `buildEnviron` must `deinit`.
fn buildEnviron(allocator: std.mem.Allocator, env: *const std.process.Environ.Map) Error!std.process.Environ.Map {
    var child_env = try env.clone(allocator);
    errdefer child_env.deinit();
    for (forced_env) |entry| try child_env.put(entry.key, entry.value);
    return child_env;
}

/// Read both of `child`'s output pipes to their end, without deadlocking if one
/// fills its kernel pipe buffer while the other has nothing to read yet. An
/// earlier version of this function polled both file descriptors with a raw
/// `poll(2)` loop, reading whichever one had something ready. `std.Io` has no
/// `poll`, by name, but it does not need one: `io.concurrent` runs
/// `readStreamAlloc` on `child.stderr` as its own task while this function
/// reads `child.stdout` straight through on the calling task, so the two pipes
/// drain at the same time and neither can back up behind the other, the same
/// guarantee `poll` gave, reached the way `std.Io` names it rather than the way
/// a raw syscall does. `std.Build.WebServer.zig`'s own `readStreamAlloc`, over
/// `std.process.Child.stderr`, is the same shape for the same reason.
fn readPipes(
    allocator: std.mem.Allocator,
    io: std.Io,
    child: *std.process.Child,
) Error!struct { stdout: []u8, stderr: []u8 } {
    var stderr_future = io.concurrent(readStreamAlloc, .{ allocator, io, child.stderr.? }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.Unexpected,
    };
    // If reading stdout below fails, the stderr task must still be resolved,
    // either awaited or canceled, before this function returns: `std.Io`
    // leaves resources attached to a Future until one or the other happens.
    // Canceling it here is a best effort cleanup, the same reasoning every
    // other errdefer in this file gives for a failure that already has its
    // own error to report.
    errdefer if (stderr_future.cancel(io)) |slice| allocator.free(slice) else |_| {};

    const stdout = readStreamAlloc(allocator, io, child.stdout.?) catch |err| return mapStreamError(err);
    const stderr = stderr_future.await(io) catch |err| return mapStreamError(err);

    return .{ .stdout = stdout, .stderr = stderr };
}

/// `readStreamAlloc`'s own error set: `allocRemaining`'s `OutOfMemory` and
/// `StreamTooLong` (never actually reachable here, since `readPipes` reads
/// with `.unlimited`), plus whatever real I/O failure or cancellation
/// `std.Io.File.Reader` names once `error.ReadFailed` has been swapped for it.
const ReadStreamError = std.mem.Allocator.Error || std.Io.File.Reader.Error || error{StreamTooLong};

/// Read `file` to its end and return every byte. The caller owns the returned
/// slice. Runs as the body of `readPipes`'s own concurrent task, over
/// `child.stderr`, and directly, over `child.stdout`; see `readPipes`'s own
/// doc comment.
fn readStreamAlloc(allocator: std.mem.Allocator, io: std.Io, file: std.Io.File) ReadStreamError![]u8 {
    var file_reader: std.Io.File.Reader = .initStreaming(file, io, &.{});
    return file_reader.interface.allocRemaining(allocator, .unlimited) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
        else => |e| return e,
    };
}

/// `readStreamAlloc`'s own error, mapped onto this file's own `Error`:
/// `OutOfMemory` is passed through as is, and everything else, an I/O failure
/// or a cancellation, becomes `error.Unexpected`, the same as every other
/// kernel level failure this file has no specific recovery for.
fn mapStreamError(err: ReadStreamError) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Unexpected,
    };
}

fn mapSpawnError(err: std.process.SpawnError, diag: ?*?Diagnostic) Error {
    return switch (err) {
        error.FileNotFound => error.NotFound,
        error.OutOfMemory => error.OutOfMemory,
        else => |e| {
            diagnostic.noteErr(diag, .git_spawn, e);
            return error.Unexpected;
        },
    };
}

/// The one way `absoluteDirPath` can fail: `std.Io.Dir.realPath` on `dir`
/// returned an error, which only happens for a handle this process does not
/// actually have open.
const AbsoluteDirPathError = error{RealPathFailed};

/// Read the absolute path of an already open directory, through
/// `std.Io.Dir.realPath`. `std.testing.tmpDir` hands back a directory reached
/// only through a relative path, but a test needs an absolute one to pass as
/// `cwd` to `run`, one that does not depend on the test binary's own working
/// directory. Two other copies of this same function live in
/// `lib/chock-proto/log.zig` and `lib/chock-sandbox/Sandbox.zig`. Neither can
/// become a caller of this one: `chock-workspace` must not depend on
/// `chock-proto` or `chock-sandbox`, and `chock-proto`'s own copy explains why
/// its tests do not depend on `chock-sandbox` either. See this file's own doc
/// comment for the same rule applied to `chock-workspace`.
///
/// This used to read `/proc/self/fd/<dir_fd>` by hand, which only exists on
/// Linux. `std.Io.Dir.realPath` covers the same need portably: on Linux it
/// still reads `/proc/self/fd`, and on Darwin it uses `fcntl(F_GETPATH)`, so
/// this function needs no platform branch of its own.
fn absoluteDirPath(io: std.Io, buffer: []u8, dir: std.Io.Dir) AbsoluteDirPathError![:0]u8 {
    const len = dir.realPath(io, buffer) catch return error.RealPathFailed;
    buffer[len] = 0;
    return buffer[0..len :0];
}

/// The environment for a test that made its own scratch git repository (or a
/// scratch plain directory) under `scratch_path`. This project's own checkout is
/// itself a git repository, and `std.testing.tmpDir` makes every scratch directory
/// somewhere underneath it. Without a ceiling, git's own upward search for a `.git`
/// directory would walk straight past a test's freshly made directory and find
/// this project's real one instead, so a test that expects "not a repository"
/// would see this project's repository and fail instead. `GIT_CEILING_DIRECTORIES`
/// stops that search once it would step out of `scratch_path`'s parent. A real
/// caller needs the upward search to work, so this stays out of `run` and every
/// other function above, and lives only here, in test setup.
fn testEnviron(allocator: std.mem.Allocator, scratch_path: []const u8) !std.process.Environ.Map {
    var env = try std.testing.environ.createMap(allocator);
    errdefer env.deinit();
    const ceiling = std.fs.path.dirname(scratch_path) orelse scratch_path;
    try env.put("GIT_CEILING_DIRECTORIES", ceiling);
    return env;
}

/// Create a fresh, empty git repository at `path`, already inside a scratch
/// directory `env` has ceilinged off from this project's own repository.
fn initTestRepo(
    allocator: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    path: [:0]const u8,
) !void {
    var output = try run(allocator, std.testing.io, env, path, &.{"init"}, null);
    defer output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
}

test "isRepository is true for a repository and false for a plain directory" {
    const allocator = std.testing.allocator;

    var repo_tmp = std.testing.tmpDir(.{});
    defer repo_tmp.cleanup();
    var repo_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const repo_path = try absoluteDirPath(std.testing.io, &repo_path_buffer, repo_tmp.dir);
    var repo_env = try testEnviron(allocator, repo_path);
    defer repo_env.deinit();
    try initTestRepo(allocator, &repo_env, repo_path);
    try std.testing.expect(try isRepository(allocator, std.testing.io, &repo_env, repo_path, null));

    var plain_tmp = std.testing.tmpDir(.{});
    defer plain_tmp.cleanup();
    var plain_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const plain_path = try absoluteDirPath(std.testing.io, &plain_path_buffer, plain_tmp.dir);
    var plain_env = try testEnviron(allocator, plain_path);
    defer plain_env.deinit();
    try std.testing.expect(!try isRepository(allocator, std.testing.io, &plain_env, plain_path, null));
}

test "topLevel gives the root of a repository from a directory inside it" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try absoluteDirPath(std.testing.io, &path_buffer, tmp.dir);
    var env = try testEnviron(allocator, root_path);
    defer env.deinit();
    try initTestRepo(allocator, &env, root_path);

    var child_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const child_path = try std.fmt.bufPrintZ(&child_path_buffer, "{s}/child", .{root_path});
    std.Io.Dir.createDirAbsolute(std.testing.io, child_path, .default_dir) catch return error.MkdirFailed;

    // A session can start anywhere under the project, several directories deep,
    // so this asks from the child directory, not the root itself, and pins that
    // the answer is still the root.
    const found = try topLevel(allocator, std.testing.io, &env, child_path, null);
    try std.testing.expect(found != null);
    defer allocator.free(found.?);
    try std.testing.expectEqualStrings(root_path, found.?);
}

test "run reports the exit status and the output of git, and does not use a shell" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const repo_path = try absoluteDirPath(std.testing.io, &path_buffer, tmp.dir);
    var env = try testEnviron(allocator, repo_path);
    defer env.deinit();
    try initTestRepo(allocator, &env, repo_path);

    // A directory name with a space and a quote in it, the kind of name a real
    // project directory can have. A shell splitting this path on the space, or
    // letting the quote close early, would either fail this call or run git in a
    // different, shorter directory than the one asked for.
    var child_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const child_path = try std.fmt.bufPrintZ(&child_path_buffer, "{s}/a name with a space and a 'quote'", .{repo_path});
    std.Io.Dir.createDirAbsolute(std.testing.io, child_path, .default_dir) catch return error.MkdirFailed;
    try std.testing.expect(try isRepository(allocator, std.testing.io, &env, child_path, null));

    // A value with a space and a quote in it: the same reasoning applied to an
    // argument instead of a path.
    const value = "a value with a space and a 'quote'";
    var set_output = try run(allocator, std.testing.io, &env, repo_path, &.{ "config", "test.value", value }, null);
    defer set_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, set_output.term);

    var get_output = try run(allocator, std.testing.io, &env, repo_path, &.{ "config", "--get", "test.value" }, null);
    defer get_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, get_output.term);
    try std.testing.expectEqualStrings(value, std.mem.trimEnd(u8, get_output.stdout, "\n"));
}

test "run reports a failure of git as an error and keeps what git said" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try absoluteDirPath(std.testing.io, &path_buffer, tmp.dir);
    var env = try testEnviron(allocator, path);
    defer env.deinit();

    // No `git init` here: rev-parse on a plain directory is the failure case.
    var output = try run(allocator, std.testing.io, &env, path, &.{ "rev-parse", "--show-toplevel" }, null);
    defer output.deinit(allocator);

    try std.testing.expectEqual(std.process.Child.Term{ .exited = 128 }, output.term);
    // The exact wording is git's own, but this substring is what makes the
    // message useful to a person: which fact git refused to give, not just that
    // it refused. A run that swallowed stderr and returned a bare error would
    // fail this assertion by leaving stderr empty.
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "not a git repository") != null);
}

test "a git that cannot be started names the fault, and it reaches the caller" {
    // The point of the whole change. `error.Unexpected` says a call failed.
    // Only the diagnostic says which call, and what it answered, and before
    // this the library printed both to the terminal and told the caller
    // neither. A `cwd` that is not a directory is the shortest way to a real
    // spawn fault that is not `FileNotFound`.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(std.testing.io, &path_buffer);
    var file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const not_a_dir = try std.fmt.bufPrint(&file_buffer, "{s}/plain", .{path_buffer[0..dir_len]});
    var file = try std.Io.Dir.createFileAbsolute(std.testing.io, not_a_dir, .{});
    file.close(std.testing.io);

    var env = try testEnviron(allocator, path_buffer[0..dir_len]);
    defer env.deinit();

    var diag: ?Diagnostic = null;
    const result = run(allocator, std.testing.io, &env, not_a_dir, &.{"status"}, &diag);
    if (result) |output| {
        var owned = output;
        owned.deinit(allocator);
        // A host whose spawn does not refuse a `cwd` that is a file has
        // nothing here to diagnose, so there is nothing for this test to
        // pin either.
        return error.SkipZigTest;
    } else |err| {
        try std.testing.expectEqual(@as(anyerror, error.Unexpected), err);
        try std.testing.expectEqual(Diagnostic.Call.git_spawn, diag.?.call_failed.call);

        var line_buffer: [128]u8 = undefined;
        const line = try std.fmt.bufPrint(&line_buffer, "{f}", .{&diag.?});
        try std.testing.expect(std.mem.startsWith(u8, line, "starting git failed: "));
    }
}

test "a caller that wants no diagnostic gets the same answer and stores nothing" {
    // The outer optional is what lets a caller opt out, and it must cost
    // nothing: nothing here allocates for a diagnostic in either case.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try absoluteDirPath(std.testing.io, &path_buffer, tmp.dir);

    // Ceilinged off from the checkout Chock itself lives in, the same way
    // every other test here is: a scratch directory under `.zig-cache` is
    // inside a real repository, and git would say so.
    var env = try testEnviron(allocator, path);
    defer env.deinit();

    // A plain directory is not a repository, and that answer is the same
    // whether or not a diagnostic was asked for.
    try std.testing.expect(!try isRepository(allocator, std.testing.io, &env, path, null));
    var diag: ?Diagnostic = null;
    try std.testing.expect(!try isRepository(allocator, std.testing.io, &env, path, &diag));
    try std.testing.expectEqual(@as(?Diagnostic, null), diag);
}
