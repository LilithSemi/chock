//! `chock commands`: the commands a person can run by name, the text of one,
//! and a check of a directory of them.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");

const Exit = @import("exit.zig").Exit;
const tty = @import("tty.zig");

const commands = chock_core.commands;

const usage_text =
    \\Usage: chock commands [list]
    \\       chock commands show <name>
    \\       chock commands validate <dir>...
    \\
    \\list      Every command this project and your own configuration hold.
    \\show      The whole text of one, so you can read a repository's command
    \\          before you run it.
    \\validate  Reads each directory the way a session reads it, and says what a
    \\          session would refuse. Exits 2 when there is a problem.
    \\
    \\Run one with chock run /<name>, with anything after the name reaching the
    \\text where it says $ARGUMENTS, $1 to $9.
    \\
    \\Options:
    \\
++ tty.options_text;

const Action = enum { list, show, validate };

const Options = struct {
    action: Action = .list,
    paths: []const []const u8 = &.{},
};

const Kind = enum {
    ok,
    problem,
    note,

    fn word(self: Kind) []const u8 {
        return switch (self) {
            .ok => "ok",
            .problem => "problem",
            .note => "note",
        };
    }

    fn rank(self: Kind) tty.Rank {
        return switch (self) {
            .ok => .plain,
            .problem => .err,
            .note => .warn,
        };
    }
};

const Finding = struct {
    kind: Kind,
    at: []const u8,
    text: []const u8,
};

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = gpa;
    _ = exe_path;

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    var env = try environ.createMap(arena);
    defer env.deinit();

    const options = parseOptions(arena, args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    return switch (options.action) {
        .list => list(arena, io, &env),
        .show => show(arena, io, &env, options.paths[0]),
        .validate => validate(arena, io, options.paths),
    };
}

/// The two places a session looks, read the way a session reads them.
fn found(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
) !commands.Found {
    var roots: std.ArrayList(commands.Root) = .empty;

    if (chock_auth.paths.configDir(arena, env)) |dir| {
        try roots.append(arena, .{
            .layer = .operator,
            .path = try std.fs.path.join(arena, &.{ dir, commands.operator_dir_name }),
        });
    } else |_| {}

    var block = chock_policy.dirs.load(arena, io, ".", .commands, null) catch
        chock_policy.dirs.Block{};
    defer block.deinit(arena);
    for (block.dirs) |name| {
        const path = chock_policy.dirs.resolve(arena, io, ".", .commands, name, null) catch continue;
        try roots.append(arena, .{ .layer = .project, .path = path });
    }

    return commands.discover(arena, io, roots.items);
}

fn list(arena: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map) !u8 {
    const all = try found(arena, io, env);

    for (std.enums.values(commands.Layer)) |which| {
        const entries = try commands.indexEntriesFor(arena, all.commands, which);
        if (entries.len == 0) continue;
        tty.out(.plain, "\n{t}, written by {s}:\n", .{ which, which.wroteIt() });
        for (entries) |one| {
            tty.out(.plain, "  /{s: <20} {s}\n", .{ one.name, one.description });
        }
    }

    for (all.refused) |one| {
        tty.out(.warn, "\n{s} is not a command: {s}\n", .{ one.path, one.fault.sentence() });
    }

    if (all.commands.len == 0) {
        tty.out(.plain, "chock commands: there are none here.\n", .{});
        tty.out(
            .plain,
            "A command is a markdown file in your own {s}/ directory, " ++
                "or in a directory the project's chock.zon names in its commands block.\n",
            .{commands.operator_dir_name},
        );
    }
    return Exit.finished.code();
}

fn show(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    name: []const u8,
) !u8 {
    const all = try found(arena, io, env);
    const one = commands.findIn(all.commands, name) orelse {
        tty.print(.err, "chock commands: there is no command named {s}.\n", .{name});
        return Exit.faulted.code();
    };

    tty.out(.plain, "{s}\n{s}\nwritten by {s}\n", .{
        one.path,
        one.description,
        one.layer.wroteIt(),
    });
    if (one.argument_hint) |hint| tty.out(.plain, "arguments: {s}\n", .{hint});
    tty.out(.plain, "\n{s}\n", .{one.body});
    return Exit.finished.code();
}

fn validate(arena: std.mem.Allocator, io: std.Io, paths: []const []const u8) !u8 {
    const findings = try examine(arena, io, paths);
    for (findings) |one| {
        tty.out(one.kind.rank(), "{s: <8} {s}  {s}\n", .{ one.kind.word(), one.at, one.text });
    }

    const counted = countOf(findings);
    tty.out(.plain, "\nchock commands: {d} command{s}, {d} problem{s}, {d} note{s}\n", .{
        counted.ok,
        plural(counted.ok),
        counted.problem,
        plural(counted.problem),
        counted.note,
        plural(counted.note),
    });
    return exitFor(findings).code();
}

const Counted = struct {
    ok: usize = 0,
    problem: usize = 0,
    note: usize = 0,
};

fn countOf(findings: []const Finding) Counted {
    var counted = Counted{};
    for (findings) |one| switch (one.kind) {
        .ok => counted.ok += 1,
        .problem => counted.problem += 1,
        .note => counted.note += 1,
    };
    return counted;
}

fn exitFor(findings: []const Finding) Exit {
    return if (countOf(findings).problem == 0) .finished else .faulted;
}

fn plural(count: usize) []const u8 {
    return if (count == 1) "" else "s";
}

/// A check says nothing about who wrote a command, so every read takes one
/// layer. The layer shapes the message a session sends and nothing printed here.
const layer: commands.Layer = .project;

fn examine(
    arena: std.mem.Allocator,
    io: std.Io,
    paths: []const []const u8,
) commands.Error![]const Finding {
    var out: std.ArrayList(Finding) = .empty;
    for (paths) |path| try examineOne(arena, io, path, &out);
    return out.toOwnedSlice(arena);
}

fn examineOne(
    arena: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    out: *std.ArrayList(Finding),
) commands.Error!void {
    if (std.mem.endsWith(u8, path, commands.file_suffix)) {
        if (try commands.read(arena, io, layer, path)) |one| {
            switch (one) {
                .command => |it| try addCommand(arena, io, it, out),
                .refused => |it| try addRefused(arena, it, out),
            }
        } else try out.append(arena, .{
            .kind = .problem,
            .at = path,
            .text = "there is nothing readable at that path",
        });
        return;
    }

    const all = try commands.discover(arena, io, &.{.{ .layer = layer, .path = path }});
    if (all.commands.len == 0 and all.refused.len == 0) {
        try out.append(arena, .{
            .kind = .problem,
            .at = path,
            .text = "it holds no " ++ commands.file_suffix ++ " file, so it holds no command",
        });
        return;
    }

    for (all.commands) |one| try addCommand(arena, io, one, out);
    for (all.refused) |one| try addRefused(arena, one, out);
    if (all.left_out != 0) try out.append(arena, .{
        .kind = .problem,
        .at = path,
        .text = try std.fmt.allocPrint(
            arena,
            "it holds {d} commands past the {d} a session reads",
            .{ all.left_out, commands.max_commands },
        ),
    });
}

fn addCommand(
    arena: std.mem.Allocator,
    io: std.Io,
    one: commands.Command,
    out: *std.ArrayList(Finding),
) commands.Error!void {
    try out.append(arena, .{ .kind = .ok, .at = one.path, .text = one.name });

    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        one.path,
        arena,
        .limited(commands.max_file_bytes),
    ) catch return;
    for (try commands.notesIn(arena, bytes)) |note| {
        try out.append(arena, .{
            .kind = .note,
            .at = try std.fmt.allocPrint(arena, "{s}:{d}", .{ one.path, note.line }),
            .text = try said(arena, note.note.sentence(), note.detail),
        });
    }
}

fn addRefused(
    arena: std.mem.Allocator,
    refused: commands.Refused,
    out: *std.ArrayList(Finding),
) commands.Error!void {
    try out.append(arena, .{
        .kind = .problem,
        .at = refused.path,
        .text = try said(arena, refused.fault.sentence(), refused.detail),
    });
}

fn said(
    arena: std.mem.Allocator,
    sentence: []const u8,
    detail: []const u8,
) commands.Error![]const u8 {
    if (detail.len == 0) return sentence;
    return std.fmt.allocPrint(arena, "{s} ({s})", .{ sentence, detail });
}

const ParseError = error{ HelpWanted, BadArguments, OutOfMemory };

fn parseOptions(arena: std.mem.Allocator, args: []const []const u8) ParseError!Options {
    var action: ?Action = null;
    var paths: std.ArrayList([]const u8) = .empty;

    for (args) |argument| {
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) {
            return error.HelpWanted;
        }
        if (argument.len != 0 and argument[0] == '-') return error.BadArguments;

        if (action == null) {
            action = std.meta.stringToEnum(Action, argument) orelse return error.BadArguments;
            continue;
        }
        try paths.append(arena, argument);
    }

    const which = action orelse .list;
    const given = try paths.toOwnedSlice(arena);
    switch (which) {
        .list => if (given.len != 0) return error.BadArguments,
        .show => if (given.len != 1) return error.BadArguments,
        .validate => if (given.len == 0) return error.BadArguments,
    }
    return .{ .action = which, .paths = given };
}

const testing = std.testing;

test "the command line takes a list with nothing else, one name to show, and paths to check" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqual(Action.list, (try parseOptions(arena, &.{})).action);
    try testing.expectEqual(Action.list, (try parseOptions(arena, &.{"list"})).action);

    const one = try parseOptions(arena, &.{ "show", "review" });
    try testing.expectEqual(Action.show, one.action);
    try testing.expectEqualStrings("review", one.paths[0]);

    const many = try parseOptions(arena, &.{ "validate", "a", "b" });
    try testing.expectEqual(Action.validate, many.action);
    try testing.expectEqual(@as(usize, 2), many.paths.len);

    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "list", "extra" }));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"show"}));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "show", "a", "b" }));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"validate"}));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"check"}));
    try testing.expectError(error.HelpWanted, parseOptions(arena, &.{"--help"}));
}

test "a directory of commands reads, and each fault is one problem naming its file" {
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{
        .sub_path = "review.md",
        .data = "---\ndescription: Review it.\n---\nRead the diff.\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "broken.md",
        .data = "---\nversion: 2\n---\nDo it.\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "notes.txt",
        .data = "not a command at all\n",
    });

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];

    const findings = try examine(arena, io, &.{root});
    const counted = countOf(findings);
    try testing.expectEqual(@as(usize, 1), counted.ok);
    try testing.expectEqual(@as(usize, 1), counted.problem);
    try testing.expectEqual(Exit.faulted, exitFor(findings));

    for (findings) |one| switch (one.kind) {
        .ok => try testing.expectEqualStrings("review", one.text),
        .problem => try testing.expect(std.mem.endsWith(u8, one.at, "broken.md")),
        .note => {},
    };
}

test "one file is checked on its own, and a path with nothing at it is a problem" {
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "review.md",
        .data = "---\ndescription: Review it.\nversion: 2\n---\nRead the diff.\n",
    });

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];
    const file = try std.fs.path.join(arena, &.{ root, "review.md" });

    const findings = try examine(arena, io, &.{file});
    const counted = countOf(findings);
    try testing.expectEqual(@as(usize, 1), counted.ok);
    try testing.expectEqual(@as(usize, 1), counted.note);
    try testing.expectEqual(@as(usize, 0), counted.problem);
    try testing.expectEqual(Exit.finished, exitFor(findings));

    const missing = try std.fs.path.join(arena, &.{ root, "nothing-here.md" });
    const none = try examine(arena, io, &.{missing});
    try testing.expectEqual(@as(usize, 1), countOf(none).problem);
}

test "an empty directory is a problem, because a path that points nowhere useful reads as clean" {
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];

    const findings = try examine(arena, io, &.{root});
    try testing.expectEqual(@as(usize, 1), countOf(findings).problem);
    try testing.expectEqual(Exit.faulted, exitFor(findings));
}
