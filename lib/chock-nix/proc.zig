//! Runs a program on the host and reads what it wrote. Every command

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;

pub const Error = error{
    ProgramNotFound,
    OutputTooLong,
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

    pub fn succeeded(self: Output) bool {
        return switch (self.term) {
            .exited => |code| code == 0,
            else => false,
        };
    }
};

pub const Options = struct {
    argv: []const []const u8,
    env: ?*const std.process.Environ.Map = null,
    cwd: ?[]const u8 = null,
    max_output_bytes: usize = 8 * 1024 * 1024,
    diag: ?diagnostic.Sink = null,
};

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
            // The name is copied, not borrowed: argv[0] can live in an arena the caller destroys as this error travels up.
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
