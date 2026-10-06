//! `chock cache`: look at the toolchain cache, and empty it.

const std = @import("std");
const chock_core = @import("chock-core");

const session_paths = @import("session.zig");
const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const cache = chock_core.cache;

const usage_text =
    \\Usage: chock cache [list|clear] [options]
    \\
    \\With no subcommand, says what this project's toolchain cache holds.
    \\
    \\The sandbox mounts the cache at
++ " " ++ cache.sandbox_dir ++ ", with HOME and XDG_CACHE_HOME\n" ++
    \\in it, and only for a run_command call. A session that finds the cache over
    \\the bound empties it before it starts.
    \\
    \\Options:
    \\  --project <dir>   The project. Defaults to the current directory.
    \\
++ tty.options_text;

const Options = struct {
    project: ?[]const u8 = null,
    action: Action = .list,
};

const Action = enum { list, clear };

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = exe_path;

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    var env = try environ.createMap(arena);
    defer env.deinit();

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        else => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    const project_root = try resolveProject(arena, io, options.project);
    const dir = session_paths.cacheDir(arena, &env, project_root) catch |err| {
        tty.print(.err, "chock cache: the toolchain cache directory is unknown: {s}\n", .{@errorName(err)});
        return Exit.usage.code();
    };

    return switch (options.action) {
        .list => listCache(arena, io, dir),
        .clear => clearCache(arena, gpa, io, dir),
    };
}

fn listCache(arena: std.mem.Allocator, io: std.Io, dir: []const u8) !u8 {
    if (!cache.exists(io, dir)) {
        tty.print(.plain, "chock cache: this project has no toolchain cache ({s})\n", .{dir});
        return Exit.finished.code();
    }

    const size = cache.measure(arena, io, dir, std.math.maxInt(u64));
    tty.detail("{s}\n\n", .{dir});
    tty.out(.plain, "{d} bytes in {d} files, of at most {d} bytes\n", .{
        size.bytes,
        size.files,
        cache.max_bytes,
    });
    if (size.bytes > cache.max_bytes) {
        tty.print(.warn, "It is over the bound, so the next session empties it.\n", .{});
    }
    return Exit.finished.code();
}

fn clearCache(arena: std.mem.Allocator, gpa: std.mem.Allocator, io: std.Io, dir: []const u8) !u8 {
    if (!cache.exists(io, dir)) {
        tty.print(.warn, "chock cache: this project has no toolchain cache ({s})\n", .{dir});
        return Exit.usage.code();
    }

    // gpa, not arena: the diagnostic holds a path the library built in a
    // frame of its own, and gpa is the allocator that releases it.
    var diag: ?chock_core.Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(gpa);
    const went = cache.clear(arena, io, dir, cache.sinkOf(gpa, &diag)) catch |err| {
        if (diag) |fault| {
            tty.print(.err, "chock cache clear: the cache could not be emptied: {f}\n", .{fault});
        } else {
            tty.print(.err, "chock cache clear: the cache could not be emptied: {s}\n", .{@errorName(err)});
        }
        return Exit.usage.code();
    };
    tty.print(.plain, "chock cache: emptied {d} bytes in {d} files from {s}\n", .{
        went.bytes,
        went.files,
        dir,
    });
    return Exit.finished.code();
}

const ParseError = error{ HelpWanted, BadArguments };

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};
    var index: usize = 0;
    var saw_action = false;

    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;
        if (std.mem.eql(u8, argument, "--project")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.project = args[index];
            continue;
        }
        if (argument.len != 0 and argument[0] == '-') return error.BadArguments;

        if (saw_action) return error.BadArguments;
        options.action = std.meta.stringToEnum(Action, argument) orelse return error.BadArguments;
        saw_action = true;
    }
    return options;
}

fn resolveProject(arena: std.mem.Allocator, io: std.Io, given: ?[]const u8) ![]const u8 {
    if (given) |path| {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return arena.dupe(u8, path);
        defer dir.close(io);
        const len = dir.realPath(io, &buffer) catch return arena.dupe(u8, path);
        return arena.dupe(u8, buffer[0..len]);
    }
    return std.process.currentPathAlloc(io, arena);
}

const testing = std.testing;

test "the command line names an action and nothing else" {
    try testing.expectEqual(Action.list, (try parseOptions(&.{})).action);
    try testing.expectEqual(Action.list, (try parseOptions(&.{"list"})).action);
    try testing.expectEqual(Action.clear, (try parseOptions(&.{"clear"})).action);

    const with_project = try parseOptions(&.{ "--project", "/somewhere", "clear" });
    try testing.expectEqualStrings("/somewhere", with_project.project.?);
    try testing.expectEqual(Action.clear, with_project.action);

    try testing.expectError(error.BadArguments, parseOptions(&.{"empty-everything"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "clear", "clear" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--project"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}

test "clearing a project that has no cache does not report success, and names the directory" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const missing = try std.fmt.allocPrint(arena, "{s}/never-made", .{buffer[0..len]});

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expect((try clearCache(arena, testing.allocator, testing.io, missing)) != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, said.err(), missing) != null);
    try testing.expectEqualStrings("", said.out());

    said.clear();
    try testing.expectEqual(Exit.finished.code(), try listCache(arena, testing.io, missing));
    try testing.expect(std.mem.indexOf(u8, said.err(), missing) != null);
}

test "clearing a cache that holds something empties it and reports what went" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const dir = try std.fmt.allocPrint(arena, "{s}/cache", .{buffer[0..len]});
    try cache.makeLayout(testing.io, dir, null);

    const file = try std.fmt.allocPrint(arena, "{s}/{s}/zig/a.o", .{ dir, cache.xdg_cache_leaf });
    try cache.makeLayout(testing.io, std.fs.path.dirname(file).?, null);
    {
        var handle = try std.Io.Dir.createFileAbsolute(testing.io, file, .{});
        defer handle.close(testing.io);
        try handle.writeStreamingAll(testing.io, "x" ** 32);
    }
    try testing.expectEqual(@as(u64, 32), cache.measure(arena, testing.io, dir, cache.max_bytes).bytes);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqual(Exit.finished.code(), try clearCache(arena, testing.allocator, testing.io, dir));
    try testing.expect(std.mem.indexOf(u8, said.err(), "32 bytes") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), dir) != null);

    try testing.expectEqual(@as(u64, 0), cache.measure(arena, testing.io, dir, cache.max_bytes).bytes);
    try testing.expect(cache.exists(testing.io, dir));
}
