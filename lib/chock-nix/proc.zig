//! Runs a program on the host and reads what it wrote. Every command
//! `chock-nix` makes runs through here: `nix`, `nix-store`, and the `bash`
//! that sources a dev environment.
//!
//! **This is host work, never sandbox work.** The sandbox has no network and
//! no daemon socket, so a dev shell is evaluated
//! outside it, before a session starts. `src/run.zig` calls this from its own
//! phase 1, the phase whose `std.Io` has a real allocator and can spawn a
//! process at all.
//!
//! `argv[0]` is always an absolute path here, found by `resolve` below,
//! rather than a bare name left for `std.process.spawn` to look up. Two
//! reasons: a missing program then reports as `error.ProgramNotFound` with
//! the name in it, before a child exists, and the same absolute path can be
//! written into a script that a shell runs with an environment of our own,
//! where the host's own `PATH` is not present. See
//! `lib/chock-nix/dev_env.zig`.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;

pub const Error = error{
    ProgramNotFound,
    /// The program wrote more than the caller said it would read. Bounded
    /// on purpose: every one of these commands has a size that is normal
    /// for it, and a `nix` that writes without end must not take the
    /// session's memory with it.
    OutputTooLong,
    /// A kernel call needed to run the program failed in a way this file
    /// has no specific recovery for. Reported, never swallowed.
    Unexpected,
    OutOfMemory,
};

/// What one `run` call produced. A nonzero exit is not an `Error`: what the
/// program wrote to standard error is the most useful thing Chock can show a
/// user whose flake does not evaluate, and a bare error would throw exactly
/// that away. The same reasoning `lib/chock-workspace/git.zig` gives for its
/// own `Output`.
pub const Output = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: *Output, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        self.* = undefined;
    }

    pub fn succeeded(self: Output) bool {
        return switch (self.term) {
            .exited => |code| code == 0,
            else => false,
        };
    }
};

pub const Options = struct {
    /// `argv[0]` must be the absolute path `resolve` returned.
    argv: []const []const u8,
    /// The child's whole environment. Null gives the child this process's
    /// own, which is what `nix` itself wants: it reads the user's own
    /// configuration, and a `nix` that cannot find it behaves differently
    /// from the `nix develop` the same user runs by hand.
    env: ?*const std.process.Environ.Map = null,
    cwd: ?[]const u8 = null,
    /// The bound on each of the two streams separately.
    max_output_bytes: usize = 8 * 1024 * 1024,
    /// Where a fault past what `Error` can say is left, **and who owns what
    /// it points at**. A `Sink` and not a bare slot, because the allocator
    /// above holds this call's output and can be an arena a caller destroys
    /// the moment this call fails: see `chock-nix/diagnostic.zig`. A field of
    /// the options and not a parameter, because this call already takes one
    /// struct and a caller that wants no diagnostic writes nothing at all.
    /// Null costs nothing: nothing here allocates for a diagnostic.
    diag: ?diagnostic.Sink = null,
};

/// Run one program to completion and return its status and its output.
pub fn run(allocator: std.mem.Allocator, io: std.Io, options: Options) Error!Output {
    std.debug.assert(options.argv.len != 0);
    std.debug.assert(std.fs.path.isAbsolute(options.argv[0]));

    var child = std.process.spawn(io, .{
        .argv = options.argv,
        .cwd = if (options.cwd) |dir| .{ .path = dir } else .inherit,
        .environ_map = options.env,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.ProgramNotFound,
        error.OutOfMemory => return error.OutOfMemory,
        else => |e| {
            // The name is copied, not borrowed. `argv[0]` can live in an
            // arena the caller destroys as this error travels up.
            try diagnostic.noteNamed(options.diag, .program_not_started, options.argv[0], e);
            return error.Unexpected;
        },
    };

    const streams = try readPipes(allocator, io, &child, options.max_output_bytes);
    errdefer {
        allocator.free(streams.stdout);
        allocator.free(streams.stderr);
    }

    const term = child.wait(io) catch |err| {
        try diagnostic.noteNamed(options.diag, .program_wait_failed, options.argv[0], err);
        return error.Unexpected;
    };

    return .{ .term = term, .stdout = streams.stdout, .stderr = streams.stderr };
}

/// Read both of `child`'s output pipes to their end at the same time, so
/// neither can back up behind the other once it fills its kernel buffer.
/// `nix print-dev-env` writes tens of kilobytes to standard output while a
/// slow evaluation writes progress to standard error, which is exactly the
/// shape that deadlocks a reader that drains one stream first.
///
/// The same `io.concurrent` shape `lib/chock-workspace/git.zig`'s own
/// `readPipes` uses, and it carries the same requirement: the `std.Io` this
/// runs on must be able to start a task. Phase 1 of `src/run.zig` can; phase
/// 2 deliberately cannot, and nothing in this library runs there.
fn readPipes(
    allocator: std.mem.Allocator,
    io: std.Io,
    child: *std.process.Child,
    limit: usize,
) Error!struct { stdout: []u8, stderr: []u8 } {
    var stderr_future = io.concurrent(readStream, .{ allocator, io, child.stderr.?, limit }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.Unexpected,
    };
    errdefer if (stderr_future.cancel(io)) |slice| allocator.free(slice) else |_| {};

    const stdout = try readStream(allocator, io, child.stdout.?, limit);
    errdefer allocator.free(stdout);
    const stderr = try stderr_future.await(io);

    return .{ .stdout = stdout, .stderr = stderr };
}

fn readStream(allocator: std.mem.Allocator, io: std.Io, file: std.Io.File, limit: usize) Error![]u8 {
    var file_reader: std.Io.File.Reader = .initStreaming(file, io, &.{});
    return file_reader.interface.allocRemaining(allocator, .limited(limit)) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.OutputTooLong,
        else => error.Unexpected,
    };
}

/// The absolute path of `name` on the host's own `PATH`, or
/// `error.ProgramNotFound`. The caller owns the result.
///
/// A directory that shares the name is skipped rather than returned, and a
/// candidate that cannot be read is treated as "this entry does not have
/// it" rather than as a reason to stop looking: the same two rules
/// `lib/chock-core/tools.zig`'s own `resolveOnPath` gives, for the same
/// reasons. That function cannot be called from here, because `chock-nix`
/// imports no other Chock library, and this one answers a different
/// question anyway: it looks on the host, for Chock's own use, and never
/// for a program a model named.
pub fn resolve(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    name: []const u8,
) Error![]u8 {
    const path_value = env.get("PATH") orelse return error.ProgramNotFound;
    var it = std.mem.tokenizeScalar(u8, path_value, ':');
    while (it.next()) |dir| {
        const candidate = try std.fs.path.join(allocator, &.{ dir, name });
        const stat = std.Io.Dir.cwd().statFile(io, candidate, .{}) catch {
            allocator.free(candidate);
            continue;
        };
        if (stat.kind == .directory) {
            allocator.free(candidate);
            continue;
        }
        return candidate;
    }
    return error.ProgramNotFound;
}

test "resolve finds a program on PATH and refuses one that is not there" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const dir_path = buffer[0..len];

    {
        var file = try tmp.dir.createFile(std.testing.io, "a-program", .{});
        defer file.close(std.testing.io);
    }

    var env = std.process.Environ.Map.init(allocator);
    defer env.deinit();
    try env.put("PATH", dir_path);

    const found = try resolve(allocator, std.testing.io, &env, "a-program");
    defer allocator.free(found);
    try std.testing.expect(std.mem.endsWith(u8, found, "/a-program"));

    try std.testing.expectError(
        error.ProgramNotFound,
        resolve(allocator, std.testing.io, &env, "not-a-program"),
    );
}

test "resolve skips a directory that shares the program's name" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const dir_path = buffer[0..len];

    // A directory called `cat` on the first PATH entry, the shape a
    // project's own build output can take. Returning it would hand a
    // caller a path that `execve` can never run.
    try tmp.dir.createDir(std.testing.io, "shadow", .default_dir);
    var shadow = try tmp.dir.openDir(std.testing.io, "shadow", .{});
    defer shadow.close(std.testing.io);
    try shadow.createDir(std.testing.io, "a-program", .default_dir);

    var real = try tmp.dir.openDir(std.testing.io, ".", .{});
    defer real.close(std.testing.io);
    {
        var file = try real.createFile(std.testing.io, "a-program", .{});
        defer file.close(std.testing.io);
    }

    const shadow_first = try std.fmt.allocPrint(allocator, "{s}/shadow:{s}", .{ dir_path, dir_path });
    defer allocator.free(shadow_first);

    var env = std.process.Environ.Map.init(allocator);
    defer env.deinit();
    try env.put("PATH", shadow_first);

    const found = try resolve(allocator, std.testing.io, &env, "a-program");
    defer allocator.free(found);
    try std.testing.expect(std.mem.indexOf(u8, found, "/shadow/") == null);
}

test "a program that cannot be started names the fault, and it reaches the caller" {
    // The point of the whole change. `error.Unexpected` says a spawn failed.
    // Only the diagnostic says which program and what the kernel answered,
    // and before this the library printed both to the terminal and told the
    // caller neither. A directory is an absolute path that is not a program,
    // which is the shortest way to a spawn fault that is not `FileNotFound`.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const a_directory = buffer[0..len];

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(allocator);
    const result = run(allocator, std.testing.io, .{
        .argv = &.{a_directory},
        .diag = diagnostic.sinkOf(allocator, &diag),
    });
    if (result) |output| {
        var owned = output;
        owned.deinit(allocator);
        // A host whose spawn does not refuse a directory has nothing here to
        // diagnose, so there is nothing for this test to pin either.
        return error.SkipZigTest;
    } else |err| {
        try std.testing.expectEqual(@as(anyerror, error.Unexpected), err);
        try std.testing.expectEqualStrings(a_directory, diag.?.program_not_started.name);

        var line_buffer: [std.fs.max_path_bytes + 64]u8 = undefined;
        const line = try std.fmt.bufPrint(&line_buffer, "{f}", .{&diag.?});
        try std.testing.expect(std.mem.startsWith(u8, line, "spawning "));
    }
}

test "a caller that wants no diagnostic gets the same error and stores nothing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);

    const result = run(allocator, std.testing.io, .{ .argv = &.{buffer[0..len]} });
    if (result) |output| {
        var owned = output;
        owned.deinit(allocator);
        return error.SkipZigTest;
    } else |err| {
        try std.testing.expectEqual(@as(anyerror, error.Unexpected), err);
    }
}
