//! The packages a project declares, resolved on the host and left where
//! the build already looks for them.

const std = @import("std");

const cache = @import("cache.zig");
const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
pub const Sink = diagnostic.Sink;
pub const sinkOf = diagnostic.sinkOf;

pub const Error = std.mem.Allocator.Error || error{
    RunnerFailed,
};

pub const manifest_name = "build.zig.zon";

pub const build_file_name = "build.zig";

pub const package_leaf = "zig-pkg";

pub const download_cache_leaf = cache.xdg_cache_leaf ++ "/zig";

pub const max_manifest_bytes: usize = 1024 * 1024;

pub const max_stderr_bytes: usize = 1024 * 1024;

pub const max_raw_bytes: usize = 600;

pub const max_raw_lines: usize = 6;

pub const Declared = enum {
    none,
    some,
};

pub fn packageDirFor(
    allocator: std.mem.Allocator,
    project_dir: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ project_dir, package_leaf });
}

pub fn downloadCacheFor(
    allocator: std.mem.Allocator,
    cache_dir: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ cache_dir, download_cache_leaf });
}

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

fn declaresAny(text: []const u8) bool {
    const name = "." ++ "dependencies";
    var at: usize = 0;
    while (std.mem.indexOfPos(u8, text, at, name)) |found| {
        at = found + name.len;

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

pub const Output = struct {
    term: std.process.Child.Term,
    stderr: []u8,

    pub fn deinit(self: *Output, allocator: std.mem.Allocator) void {
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

pub const Runner = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
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

pub const Host = struct {
    program: []const u8,
    env: *const std.process.Environ.Map,
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

pub const Request = struct {
    project_dir: []const u8,
    cache_dir: []const u8,
};

pub const Resolved = struct {
    package_dir: []const u8,
    packages: usize,
};

pub const Answer = union(enum) {
    nothing_declared,
    resolved: Resolved,
    refused: []const u8,
};

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

const FakeRunner = struct {
    replies: []const Reply,
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

    try testing.expect(declaresAny(".dependencies = .{ // one is coming\n.a = .{} }"));
    try testing.expect(!declaresAny(".dependencies = .{ // none yet\n}"));

    try testing.expect(!declaresAny(".build_dependencies = .{ .a = .{} }"));
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
    try testing.expectEqualStrings("--fetch=all", args[1]);
    try testing.expectEqualStrings("--build-file", args[2]);
    try testing.expectEqualStrings("/work/session/project/build.zig", args[3]);
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

    try testing.expect(std.mem.startsWith(u8, download_cache_leaf, cache.xdg_cache_leaf ++ "/"));
    try testing.expectEqualStrings(cache.xdg_cache_dir ++ "/zig", "/run/chock/cache/home/.cache/zig");
}

test "a project that declares no dependency runs no compiler at all" {
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

    const raw =
        \\/work/project/build.zig.zon:8:20: error: unable to discover remote git server capabilities: NoAddressReturned
        \\            .url = "git+https://chock-no-such-host.invalid/x/y#0000000",
        \\                   ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    ;
    const text = try explainFailure(gpa, raw);
    defer gpa.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "build.zig.zon") != null);
    try testing.expect(std.mem.indexOf(u8, text, "sandbox has no network") != null);
    try testing.expect(std.mem.indexOf(u8, text, "NoAddressReturned") != null);
    try testing.expect(std.mem.indexOf(u8, text, "chock-no-such-host.invalid") != null);
}

test "a fetch that failed is a refusal and never an error the session start dies on" {
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

    try testing.expect(std.mem.indexOf(u8, text, "names the dependency") != null);
    try testing.expect(text.len < max_raw_bytes + 400);
    try testing.expectEqual(@as(usize, max_raw_lines - 1), std.mem.count(u8, text, "note:"));
}
