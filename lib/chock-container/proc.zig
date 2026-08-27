//! Runs a program on the host and reads what it wrote. Every command
//! `chock-container` makes runs through here: `podman` and `docker`.
//!
//! `argv[0]` is always an absolute path here, found by `resolve` below, rather
//! than a bare name left for `std.process.spawn` to look up. A missing program
//! then reports as `error.ProgramNotFound` with the name in it, before a child
//! exists, which is what makes a missing runtime a clean refusal.
//!
//! **This file says the same thing `lib/chock-nix/proc.zig` says, and the
//! repeat is deliberate.** `chock-nix` states that it imports no other Chock
//! library, and this library follows the same rule for the same reason: an
//! image is read before a session, a workspace, or a sandbox exists. Importing
//! `chock-nix` to save these lines would make a person with no Nix depend on
//! the Nix library, which is the whole thing this module exists to avoid.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;

pub const Error = error{
    /// The program is not on the host's own `PATH`. **This is the missing
    /// runtime case**, and the caller turns it into a refusal that names what
    /// to install.
    ProgramNotFound,
    /// The program wrote more than the caller said it would read. Bounded on
    /// purpose: every command this library makes has a size that is normal for
    /// it, and a daemon that writes without end must not take the session's
    /// memory with it.
    OutputTooLong,
    /// A kernel call needed to run the program failed in a way this file has
    /// no specific recovery for. Reported, never swallowed.
    Unexpected,
    OutOfMemory,
};

/// What one `run` call produced. A nonzero exit is not an `Error`: what the
/// runtime wrote to standard error is the most useful thing Chock can show a
/// user whose image does not exist, and a bare error would throw exactly that
/// away.
pub const Output = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: *Output, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        self.* = undefined;
    }

    /// True when the program exited 0.
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
    /// The child's whole environment. Null gives the child this process's own,
    /// which is what a runtime wants: it reads the user's own configuration,
    /// and `DOCKER_HOST` or `CONTAINER_HOST` is how a person points at a
    /// rootless daemon. A runtime that cannot find that variable behaves
    /// differently from the one the same user runs by hand.
    env: ?*const std.process.Environ.Map = null,
    cwd: ?[]const u8 = null,
    /// The bound on each of the two streams separately. **A root filesystem
    /// never comes through here.** `Image` asks the runtime to write the tar
    /// to a file with its own `--output` flag, so the largest thing this reads
    /// is one image inspection.
    max_output_bytes: usize = 8 * 1024 * 1024,
    /// Where a fault past what `Error` can say is left, **and who owns what it
    /// carries**. A `Sink` and not a slot, because the allocator this function
    /// is given can be a private arena that is gone before the message is read:
    /// see `chock-container/diagnostic.zig`.
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
            diagnostic.noteNamed(options.diag, .program_not_started, options.argv[0], e) catch {};
            return error.Unexpected;
        },
    };

    const streams = try readPipes(allocator, io, &child, options.max_output_bytes);
    errdefer {
        allocator.free(streams.stdout);
        allocator.free(streams.stderr);
    }

    const term = child.wait(io) catch |err| {
        diagnostic.noteNamed(options.diag, .program_wait_failed, options.argv[0], err) catch {};
        return error.Unexpected;
    };

    return .{ .term = term, .stdout = streams.stdout, .stderr = streams.stderr };
}

/// Read both of `child`'s output pipes to their end at the same time, so
/// neither can back up behind the other once it fills its kernel buffer. A
/// runtime writes an image inspection to standard output while it writes
/// progress to standard error, which is exactly the shape that deadlocks a
/// reader that drains one stream first.
///
/// This carries the same requirement `lib/chock-nix/proc.zig` carries: the
/// `std.Io` this runs on must be able to start a task. Phase 1 of
/// `src/run.zig` can. Phase 2 deliberately cannot, and nothing in this library
/// runs there.
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
/// candidate that cannot be read is treated as "this entry does not have it"
/// rather than as a reason to stop looking. Both rules matter here: a project
/// directory called `docker` on a person's `PATH` would otherwise be handed
/// back as the runtime, and `execve` could never run it.
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

test "resolve finds a runtime on PATH and refuses one that is not installed" {
    // The second half is the case this whole library has to get right. A
    // machine with no podman and no docker must produce a named refusal, and
    // it must produce it before a child process exists.
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const dir_path = buffer[0..len];

    {
        var file = try tmp.dir.createFile(std.testing.io, "podman", .{});
        defer file.close(std.testing.io);
    }

    var env = std.process.Environ.Map.init(allocator);
    defer env.deinit();
    try env.put("PATH", dir_path);

    const found = try resolve(allocator, std.testing.io, &env, "podman");
    defer allocator.free(found);
    try std.testing.expect(std.mem.endsWith(u8, found, "/podman"));

    try std.testing.expectError(
        error.ProgramNotFound,
        resolve(allocator, std.testing.io, &env, "docker"),
    );
}

test "resolve skips a directory that shares the runtime's name" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const dir_path = buffer[0..len];

    // A directory called `docker` on the first PATH entry. A project that
    // holds its container files in one is ordinary, and returning it would
    // hand a caller a path that `execve` can never run.
    try tmp.dir.createDir(std.testing.io, "shadow", .default_dir);
    var shadow = try tmp.dir.openDir(std.testing.io, "shadow", .{});
    defer shadow.close(std.testing.io);
    try shadow.createDir(std.testing.io, "docker", .default_dir);

    var real = try tmp.dir.openDir(std.testing.io, ".", .{});
    defer real.close(std.testing.io);
    {
        var file = try real.createFile(std.testing.io, "docker", .{});
        defer file.close(std.testing.io);
    }

    const shadow_first = try std.fmt.allocPrint(allocator, "{s}/shadow:{s}", .{ dir_path, dir_path });
    defer allocator.free(shadow_first);

    var env = std.process.Environ.Map.init(allocator);
    defer env.deinit();
    try env.put("PATH", shadow_first);

    const found = try resolve(allocator, std.testing.io, &env, "docker");
    defer allocator.free(found);
    try std.testing.expect(std.mem.indexOf(u8, found, "/shadow/") == null);
}

test "a program that cannot be started names the fault, and it reaches the caller" {
    // `error.Unexpected` says a spawn failed. Only the diagnostic says which
    // program and what the kernel answered. A directory is an absolute path
    // that is not a program, which is the shortest way to a spawn fault that is
    // not `FileNotFound`.
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
    }
}
