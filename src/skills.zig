//! `chock skills`: read a directory of skills the way a session reads it, and
//! say what it would refuse.

const std = @import("std");
const chock_core = @import("chock-core");

const Exit = @import("exit.zig").Exit;
const tty = @import("tty.zig");

const skills = chock_core.skills;
const training = chock_core.skill_training;

const usage_text =
    \\Usage: chock skills validate <dir>... [options]
    \\       chock skills inspect <skill-dir> [options]
    \\
    \\Checks each directory against the Agent Skills format. A directory holding a
    \\SKILL.md is one skill. Any other directory is read as a layer, holding one
    \\subdirectory for every skill in it.
    \\
    \\Reports a problem for anything a session would refuse, and a note for a line
    \\the reader goes past. Exits 2 when there is a problem, and 0 for notes alone.
    \\Inspect writes the normalized, integrity-bound training.zon contract as JSON.
    \\
    \\Options:
    \\
++ tty.options_text;

/// A read here says nothing about who wrote a skill. The layer shapes the text a
/// prompt gets and nothing this command prints, so every read takes the same one.
const layer: skills.Layer = .project;

const Action = enum { validate, inspect };

const Options = struct {
    action: Action,
    paths: []const []const u8,
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
    _ = exe_path;

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

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
        .validate => validate(arena, io, options.paths),
        .inspect => inspectTraining(arena, gpa, io, options.paths[0]),
    };
}

fn inspectTraining(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !u8 {
    var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch |err| {
        tty.print(.err, "chock skills: {s} could not be opened: {t}\n", .{ path, err });
        return Exit.usage.code();
    };
    defer dir.close(io);
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const absolute = try arena.dupe(u8, buffer[0..try dir.realPath(io, &buffer)]);

    const read_it = try skills.read(arena, io, layer, absolute) orelse {
        tty.print(.err, "chock skills: {s} holds no {s}\n", .{ absolute, skills.file_name });
        return Exit.usage.code();
    };
    if (read_it == .refused) {
        tty.print(.err, "chock skills: {s} is not a valid skill: {s}\n", .{ absolute, read_it.refused.fault.sentence() });
        return Exit.usage.code();
    }
    const inspected = training.inspect(arena, gpa, io, absolute) catch |err| {
        tty.print(.err, "chock skills: {s}/{s} is invalid: {t}\n", .{ absolute, training.file_name, err });
        return Exit.usage.code();
    };
    const json = try std.json.Stringify.valueAlloc(arena, inspected, .{});
    tty.out(.plain, "{s}\n", .{json});
    return Exit.finished.code();
}

fn validate(arena: std.mem.Allocator, io: std.Io, paths: []const []const u8) !u8 {
    const findings = try examine(arena, io, paths);
    for (findings) |one| {
        tty.out(one.kind.rank(), "{s: <8} {s}  {s}\n", .{ one.kind.word(), one.at, one.text });
    }

    const counted = countOf(findings);
    tty.out(.plain, "\nchock skills: {d} skill{s}, {d} problem{s}, {d} note{s}\n", .{
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

fn examine(
    arena: std.mem.Allocator,
    io: std.Io,
    paths: []const []const u8,
) skills.Error![]const Finding {
    var out: std.ArrayList(Finding) = .empty;
    for (paths) |path| try examineOne(arena, io, path, &out);
    return out.toOwnedSlice(arena);
}

fn examineOne(
    arena: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    out: *std.ArrayList(Finding),
) skills.Error!void {
    if (try skills.read(arena, io, layer, path)) |one| {
        switch (one) {
            .skill => |it| try addSkill(arena, io, it, out),
            .refused => |it| try addRefused(arena, it, out),
        }
        return;
    }

    const found = try skills.discover(arena, io, &.{.{ .layer = layer, .path = path }});
    if (found.skills.len == 0 and found.refused.len == 0) {
        try out.append(arena, .{
            .kind = .problem,
            .at = path,
            .text = "it holds no " ++ skills.file_name ++ ", and nor does any directory under it",
        });
        return;
    }

    for (found.skills) |one| try addSkill(arena, io, one, out);
    for (found.refused) |one| try addRefused(arena, one, out);
    if (found.left_out != 0) try out.append(arena, .{
        .kind = .problem,
        .at = path,
        .text = try std.fmt.allocPrint(
            arena,
            "it holds {d} skills past the {d} a session reads, which reach no prompt",
            .{ found.left_out, skills.max_skills },
        ),
    });
}

fn addSkill(
    arena: std.mem.Allocator,
    io: std.Io,
    skill: skills.Skill,
    out: *std.ArrayList(Finding),
) skills.Error!void {
    const file = try fileIn(arena, skill.dir);
    try out.append(arena, .{ .kind = .ok, .at = file, .text = skill.name });

    if (skill.metadata_left_out != 0) try out.append(arena, .{
        .kind = .note,
        .at = file,
        .text = try std.fmt.allocPrint(
            arena,
            "{d} metadata entries past the {d} a session keeps",
            .{ skill.metadata_left_out, skills.max_metadata_entries },
        ),
    });

    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        file,
        arena,
        .limited(skills.max_file_bytes),
    ) catch return;
    for (try skills.notesIn(arena, bytes)) |one| {
        try out.append(arena, .{
            .kind = .note,
            .at = try std.fmt.allocPrint(arena, "{s}:{d}", .{ file, one.line }),
            .text = try said(arena, one.note.sentence(), one.detail),
        });
    }

    _ = training.inspect(arena, arena, io, skill.dir) catch |err| switch (err) {
        error.FileNotFound => return,
        else => {
            try out.append(arena, .{
                .kind = .problem,
                .at = try trainingFileIn(arena, skill.dir),
                .text = try std.fmt.allocPrint(arena, "the training contract is invalid ({t})", .{err}),
            });
            return;
        },
    };
}

fn addRefused(
    arena: std.mem.Allocator,
    refused: skills.Refused,
    out: *std.ArrayList(Finding),
) skills.Error!void {
    try out.append(arena, .{
        .kind = .problem,
        .at = if (refused.fault == .directory_unreadable)
            refused.dir
        else
            try fileIn(arena, refused.dir),
        .text = try said(arena, refused.fault.sentence(), refused.detail),
    });
}

fn fileIn(arena: std.mem.Allocator, dir: []const u8) skills.Error![]const u8 {
    return std.fs.path.join(arena, &.{ dir, skills.file_name });
}

fn trainingFileIn(arena: std.mem.Allocator, dir: []const u8) skills.Error![]const u8 {
    return std.fs.path.join(arena, &.{ dir, training.file_name });
}

fn said(
    arena: std.mem.Allocator,
    sentence: []const u8,
    detail: []const u8,
) skills.Error![]const u8 {
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

    if (paths.items.len == 0) return error.BadArguments;
    if (action.? == .inspect and paths.items.len != 1) return error.BadArguments;
    return .{ .action = action.?, .paths = try paths.toOwnedSlice(arena) };
}

const testing = std.testing;

test "the command line names the action and at least one directory" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const one = try parseOptions(arena, &.{ "validate", "skills" });
    try testing.expectEqual(Action.validate, one.action);
    try testing.expectEqual(@as(usize, 1), one.paths.len);
    try testing.expectEqualStrings("skills", one.paths[0]);

    const many = try parseOptions(arena, &.{ "validate", "skills/a", "skills/b" });
    try testing.expectEqual(@as(usize, 2), many.paths.len);
    try testing.expectEqualStrings("skills/b", many.paths[1]);

    const inspected = try parseOptions(arena, &.{ "inspect", "skills/a" });
    try testing.expectEqual(Action.inspect, inspected.action);
    try testing.expectEqualStrings("skills/a", inspected.paths[0]);

    try testing.expectError(error.BadArguments, parseOptions(arena, &.{}));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"validate"}));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"skills"}));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "check", "skills" }));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "validate", "--loud" }));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "inspect", "a", "b" }));
    try testing.expectError(error.HelpWanted, parseOptions(arena, &.{"--help"}));
    try testing.expectError(error.HelpWanted, parseOptions(arena, &.{ "validate", "a", "-h" }));
}

test "validation reports an invalid training contract beside a valid skill" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeSkill(io, tmp.dir, "review-a-diff", "name: review-a-diff\ndescription: Review one.\n");
    try tmp.dir.writeFile(io, .{
        .sub_path = "review-a-diff/training.zon",
        .data = ".{ .skill = \"another-skill\", .mode = .runtime }\n",
    });

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];
    const findings = try examine(arena, io, &.{root});

    try testing.expectEqual(@as(usize, 1), countOf(findings).problem);
    try testing.expectEqual(Exit.faulted, exitFor(findings));
    for (findings) |one| {
        if (one.kind != .problem) continue;
        try testing.expect(std.mem.endsWith(u8, one.at, "review-a-diff/training.zon"));
        try testing.expect(std.mem.indexOf(u8, one.text, "SkillNameMismatch") != null);
    }
}

fn writeSkill(io: std.Io, dir: std.Io.Dir, name: []const u8, frontmatter: []const u8) !void {
    try dir.createDirPath(io, name);
    var buffer: [1024]u8 = undefined;
    const body = try std.fmt.bufPrint(&buffer, "---\n{s}---\nThe body of {s}.\n", .{
        frontmatter,
        name,
    });
    var sub: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&sub, "{s}/{s}", .{ name, skills.file_name });
    try dir.writeFile(io, .{ .sub_path = path, .data = body });
}

test "a layer of skills is read, and every problem carries the path it is in" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeSkill(io, tmp.dir, "read-a-file", "name: read-a-file\ndescription: How to read one.\n");
    try writeSkill(io, tmp.dir, "half-done", "name: half-done\n");
    try tmp.dir.createDirPath(io, "notes");

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];

    const findings = try examine(arena, io, &.{root});
    const counted = countOf(findings);
    try testing.expectEqual(@as(usize, 1), counted.ok);
    try testing.expectEqual(@as(usize, 1), counted.problem);
    try testing.expectEqual(Exit.faulted, exitFor(findings));

    for (findings) |one| {
        try testing.expect(std.mem.startsWith(u8, one.at, root));
        try testing.expect(std.mem.indexOf(u8, one.at, skills.file_name) != null);
    }
    for (findings) |one| {
        if (one.kind != .problem) continue;
        try testing.expect(std.mem.indexOf(u8, one.at, "half-done") != null);
        try testing.expectEqualStrings(skills.Fault.description_missing.sentence(), one.text);
    }
}

test "a directory that is itself a skill is read as that one skill" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeSkill(io, tmp.dir, "write-a-test", "name: write-a-test\ndescription: How to write one.\n");

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];
    const dir = try std.fs.path.join(arena, &.{ root, "write-a-test" });

    const findings = try examine(arena, io, &.{dir});
    try testing.expectEqual(@as(usize, 1), findings.len);
    try testing.expectEqual(Kind.ok, findings[0].kind);
    try testing.expectEqualStrings("write-a-test", findings[0].text);
    try testing.expectEqual(Exit.finished, exitFor(findings));
}

test "a note names the line it is on and leaves the exit code alone" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeSkill(
        io,
        tmp.dir,
        "tidy-up",
        "name: tidy-up\ndescription: How to tidy up.\nversion: 2\n",
    );

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];

    const findings = try examine(arena, io, &.{root});
    const counted = countOf(findings);
    try testing.expectEqual(@as(usize, 1), counted.ok);
    try testing.expectEqual(@as(usize, 0), counted.problem);
    try testing.expectEqual(@as(usize, 1), counted.note);
    try testing.expectEqual(Exit.finished, exitFor(findings));

    for (findings) |one| {
        if (one.kind != .note) continue;
        try testing.expect(std.mem.endsWith(u8, one.at, ":4"));
        try testing.expect(std.mem.indexOf(u8, one.text, "(version)") != null);
    }
}

test "a directory holding no skill at all is a problem, so a wrong path never reads as clean" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "src");

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];

    const findings = try examine(arena, io, &.{root});
    try testing.expectEqual(@as(usize, 1), findings.len);
    try testing.expectEqual(Kind.problem, findings[0].kind);
    try testing.expectEqualStrings(root, findings[0].at);
    try testing.expect(exitFor(findings).code() != 0);

    const missing = try examine(arena, io, &.{"/nowhere/at/all"});
    try testing.expectEqual(@as(usize, 1), missing.len);
    try testing.expectEqual(Kind.problem, missing[0].kind);
}

test "each kind has its own word, and only a problem decides the exit code" {
    var seen: std.ArrayList([]const u8) = .empty;
    defer seen.deinit(testing.allocator);
    inline for (@typeInfo(Kind).@"enum".field_names) |name| {
        const kind = @field(Kind, name);
        for (seen.items) |one| try testing.expect(!std.mem.eql(u8, one, kind.word()));
        try seen.append(testing.allocator, kind.word());
    }

    const clean = [_]Finding{
        .{ .kind = .ok, .at = "a", .text = "a" },
        .{ .kind = .note, .at = "a:1", .text = "a note" },
    };
    try testing.expectEqual(Exit.finished, exitFor(&clean));

    const broken = clean ++ [_]Finding{.{ .kind = .problem, .at = "b", .text = "a problem" }};
    try testing.expectEqual(Exit.faulted, exitFor(&broken));
    try testing.expect(exitFor(&broken).code() != 0);
}
