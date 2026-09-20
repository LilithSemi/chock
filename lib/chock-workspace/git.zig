//! Runs `git` and reads facts out of a repository. This is the only file in
//! Chock that talks to git, and every call goes straight to `execve`.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;

pub const Error = error{
    NotFound,
    Unexpected,
    OutOfMemory,
};

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

/// Applied after `env` is copied in, so they always win even if `env` carried
/// one of these names already.
const forced_env = [_]struct { key: []const u8, value: []const u8 }{
    // A user's own ~/.gitconfig or /etc/gitconfig must not change what git
    // tells Chock. An alias, a colour setting or a core.pager there changes how
    // output reads, and Chock parses that output.
    .{ .key = "GIT_CONFIG_GLOBAL", .value = "/dev/null" },
    .{ .key = "GIT_CONFIG_SYSTEM", .value = "/dev/null" },
    // git must never stop to ask a question. There is nobody in this process
    // to answer one, so a prompt left enabled would hang the caller.
    .{ .key = "GIT_TERMINAL_PROMPT", .value = "0" },
};

/// `argv[0]` is the bare name `"git"`. `std.process.SpawnOptions.argv` resolves
/// a name with no `/` against PATH from the parent environment, never from
/// `environ_map`, so git is found whether or not the child gets a replacement
/// environment.
///
/// `environ_map`, when given, replaces the child's whole environment rather than
/// adding to it. This file only ever sees an `Io`, which cannot be asked what
/// environment it started with, so `env` is a parameter and not a guess.
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

fn buildEnviron(allocator: std.mem.Allocator, env: *const std.process.Environ.Map) Error!std.process.Environ.Map {
    var child_env = try env.clone(allocator);
    errdefer child_env.deinit();
    for (forced_env) |entry| try child_env.put(entry.key, entry.value);
    return child_env;
}

/// Read both of `child`'s output pipes to their end, without deadlocking if one
/// fills its kernel pipe buffer while the other has nothing to read yet.
/// `std.Io` has no `poll` by name and needs none: `io.concurrent` drains stderr
/// as its own task while this one reads stdout straight through.
fn readPipes(
    allocator: std.mem.Allocator,
    io: std.Io,
    child: *std.process.Child,
) Error!struct { stdout: []u8, stderr: []u8 } {
    var stderr_future = io.concurrent(readStreamAlloc, .{ allocator, io, child.stderr.? }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.Unexpected,
    };
    // If reading stdout below fails, the stderr task must still be resolved,
    // either awaited or canceled: `std.Io` leaves resources attached to a
    // Future until one or the other happens.
    errdefer if (stderr_future.cancel(io)) |slice| allocator.free(slice) else |_| {};

    const stdout = readStreamAlloc(allocator, io, child.stdout.?) catch |err| return mapStreamError(err);
    const stderr = stderr_future.await(io) catch |err| return mapStreamError(err);

    return .{ .stdout = stdout, .stderr = stderr };
}

const ReadStreamError = std.mem.Allocator.Error || std.Io.File.Reader.Error || error{StreamTooLong};

fn readStreamAlloc(allocator: std.mem.Allocator, io: std.Io, file: std.Io.File) ReadStreamError![]u8 {
    var file_reader: std.Io.File.Reader = .initStreaming(file, io, &.{});
    return file_reader.interface.allocRemaining(allocator, .unlimited) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
        else => |e| return e,
    };
}

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

/// `std.Io.Dir.realPath` fails only for a handle this process does not have
/// open.
const AbsoluteDirPathError = error{RealPathFailed};

/// `std.testing.tmpDir` hands back a directory reached only through a relative
/// path, and a test needs an absolute one that does not depend on the test
/// binary's own working directory. Two other copies live in
/// `lib/chock-proto/log.zig` and `lib/chock-sandbox/Sandbox.zig`, and neither
/// can call this one, because `chock-workspace` must not depend on either.
///
/// This used to read `/proc/self/fd/<dir_fd>`, which only exists on Linux.
/// `realPath` uses `fcntl(F_GETPATH)` on Darwin, so there is no platform branch
/// here.
fn absoluteDirPath(io: std.Io, buffer: []u8, dir: std.Io.Dir) AbsoluteDirPathError![:0]u8 {
    const len = dir.realPath(io, buffer) catch return error.RealPathFailed;
    buffer[len] = 0;
    return buffer[0..len :0];
}

fn testEnviron(allocator: std.mem.Allocator, scratch_path: []const u8) !std.process.Environ.Map {
    var env = try std.testing.environ.createMap(allocator);
    errdefer env.deinit();
    const ceiling = std.fs.path.dirname(scratch_path) orelse scratch_path;
    try env.put("GIT_CEILING_DIRECTORIES", ceiling);
    return env;
}

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

    var child_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const child_path = try std.fmt.bufPrintZ(&child_path_buffer, "{s}/a name with a space and a 'quote'", .{repo_path});
    std.Io.Dir.createDirAbsolute(std.testing.io, child_path, .default_dir) catch return error.MkdirFailed;
    try std.testing.expect(try isRepository(allocator, std.testing.io, &env, child_path, null));

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

    var output = try run(allocator, std.testing.io, &env, path, &.{ "rev-parse", "--show-toplevel" }, null);
    defer output.deinit(allocator);

    try std.testing.expectEqual(std.process.Child.Term{ .exited = 128 }, output.term);
    // The exact wording is git's own, and this substring is what makes the
    // message readable.
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "not a git repository") != null);
}

test "a git that cannot be started names the fault, and it reaches the caller" {
    // `error.Unexpected` says a call failed and names neither the call nor the
    // fault.
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
        // A host whose spawn does not refuse a `cwd` that is a file gives a
        // different answer, so this reads the class and not the words.
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
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try absoluteDirPath(std.testing.io, &path_buffer, tmp.dir);

    // Ceilinged off from the checkout Chock itself lives in.
    var env = try testEnviron(allocator, path);
    defer env.deinit();

    try std.testing.expect(!try isRepository(allocator, std.testing.io, &env, path, null));
    var diag: ?Diagnostic = null;
    try std.testing.expect(!try isRepository(allocator, std.testing.io, &env, path, &diag));
    try std.testing.expectEqual(@as(?Diagnostic, null), diag);
}
