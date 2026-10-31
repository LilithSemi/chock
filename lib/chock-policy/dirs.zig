//! A block of a project's own `chock.zon` that names directories under the
//! project: `skills`, `commands`, and `guidance`. The block says only where to look. What
//! may be done with what is found there is decided elsewhere, by `skill.read.*`
//! in the policy table for a skill, and by a person typing its name for a
//! command.
//!
//! Both blocks are read here, with one set of path checks, so a directory that
//! is refused for one is refused for the other.

const std = @import("std");
const limits_mod = @import("limits.zig");

pub const file_name = limits_mod.file_name;

pub const Which = enum {
    skills,
    commands,
    guidance,

    /// The name the block has in the file, which is the name of the tag.
    pub fn blockName(self: Which) []const u8 {
        return @tagName(self);
    }
};

pub const max_file_bytes = 1 << 20;

/// Every entry costs a directory walk where the block is read.
pub const max_dirs: usize = 4;

pub const Block = struct {
    dirs: []const []const u8 = &.{},

    pub fn deinit(self: *Block, gpa: std.mem.Allocator) void {
        for (self.dirs) |one| gpa.free(one);
        gpa.free(self.dirs);
        self.* = undefined;
    }
};

pub const ParseError = error{
    OutOfMemory,
    InvalidBlock,
};

pub const LoadError = ParseError || error{
    FileTooLarge,
    ReadFailed,
};

pub const ResolveError = error{
    OutOfMemory,
    LeavesProject,
    Unreadable,
};

pub const Diagnostic = struct {
    source: []const u8,
    which: Which,
    fault: Fault,

    pub const Named = struct {
        name: []const u8,
        text: []const u8,
    };

    pub const Fault = union(enum) {
        file_not_zon: ZonFailure,
        not_a_struct_literal,
        not_a_list,
        entry_not_a_string: usize,
        path_empty: usize,
        path_not_relative: []const u8,
        path_leaves_project: []const u8,
        too_many_dirs: usize,
        leaves_project: Named,
        unreadable: Named,
        file_too_large: usize,
        read_failed: anyerror,
    };

    /// `arena` backs `diag`'s messages and must outlive it; `deinit` frees both together.
    pub const ZonFailure = struct {
        arena: std.heap.ArenaAllocator,
        diag: std.zon.parse.Diagnostics,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.fault) {
            .file_not_zon => |*zf| zf.arena.deinit(),
            .path_not_relative, .path_leaves_project => |name| gpa.free(name),
            .leaves_project, .unreadable => |named| {
                gpa.free(named.name);
                gpa.free(named.text);
            },
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.fault) {
            .file_not_zon => |*zf| try writer.print(
                "{s} is not valid:\n{f}",
                .{ self.source, zf.diag.fmt(self.source) },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{self.source},
            ),
            .not_a_list => try writer.print(
                "{s}: the {s} block must be a list of directories",
                .{ self.source, self.which.blockName() },
            ),
            .entry_not_a_string => |at| try writer.print(
                "{s}: {s} directory {d} is not a string",
                .{ self.source, self.which.blockName(), at + 1 },
            ),
            .path_empty => |at| try writer.print(
                "{s}: {s} directory {d} is empty, and a path cannot be",
                .{ self.source, self.which.blockName(), at + 1 },
            ),
            .path_not_relative => |name| try writer.print(
                "{s}: the {s} directory {s} must be a path under the project, not an absolute one",
                .{ self.source, self.which.blockName(), name },
            ),
            .path_leaves_project => |name| try writer.print(
                "{s}: the {s} directory {s} reaches outside the project",
                .{ self.source, self.which.blockName(), name },
            ),
            .too_many_dirs => |limit| try writer.print(
                "{s}: the {s} block names more than {d} directories",
                .{ self.source, self.which.blockName(), limit },
            ),
            .leaves_project => |named| try writer.print(
                "{s}: the {s} directory {s} resolves to {s}, which is outside the project",
                .{ self.source, self.which.blockName(), named.name, named.text },
            ),
            .unreadable => |named| try writer.print(
                "{s}: the {s} directory {s} could not be read: {s}",
                .{ self.source, self.which.blockName(), named.name, named.text },
            ),
            .file_too_large => |limit| try writer.print(
                "{s}: the file is larger than {d} bytes, so it was not read",
                .{ self.source, limit },
            ),
            .read_failed => |err| try writer.print(
                "{s}: the file could not be read: {t}",
                .{ self.source, err },
            ),
        }
    }
};

fn note(
    out: ?*?Diagnostic,
    source: []const u8,
    which: Which,
    fault: Diagnostic.Fault,
) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = .{ .source = source, .which = which, .fault = fault };
    return true;
}

pub fn parse(
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    which: Which,
    diag: ?*?Diagnostic,
) ParseError!Block {
    return parseFrom(gpa, source, file_name, which, diag);
}

pub fn parseFrom(
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    source_name: []const u8,
    which: Which,
    diag: ?*?Diagnostic,
) ParseError!Block {
    var ast = std.zig.Ast.parse(gpa, source, .{ .mode = .zon }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = true });
    defer zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        var arena_owned = true;
        defer if (arena_owned) arena.deinit();
        var zon_diag: std.zon.parse.Diagnostics = undefined;
        _ = std.zon.parse.fromZoir(Block, .{
            .arena = arena.allocator(),
            .ast = &ast,
            .zoir = &zoir,
            .diagnostics = &zon_diag,
        }) catch {};
        if (note(diag, source_name, which, .{ .file_not_zon = .{ .arena = arena, .diag = zon_diag } })) {
            arena_owned = false;
        }
        return error.InvalidBlock;
    }

    const node = try findBlock(zoir, source_name, which, diag) orelse return .{};
    return readDirs(gpa, zoir, node, source_name, which, diag);
}

fn findBlock(
    zoir: std.zig.Zoir,
    source_name: []const u8,
    which: Which,
    diag: ?*?Diagnostic,
) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(&zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, at| {
                if (std.mem.eql(u8, name.get(&zoir), which.blockName())) {
                    return fields.vals.at(@intCast(at));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, source_name, which, .not_a_struct_literal);
            return error.InvalidBlock;
        },
    }
}

fn readDirs(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    which: Which,
    diag: ?*?Diagnostic,
) ParseError!Block {
    const items = switch (node.get(&zoir)) {
        .empty_literal => return .{},
        .array_literal => |list| list,
        else => {
            _ = note(diag, source_name, which, .not_a_list);
            return error.InvalidBlock;
        },
    };

    if (items.len > max_dirs) {
        _ = note(diag, source_name, which, .{ .too_many_dirs = max_dirs });
        return error.InvalidBlock;
    }

    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |one| gpa.free(one);
        out.deinit(gpa);
    }

    for (0..items.len) |at| {
        const text = switch (items.at(@intCast(at)).get(&zoir)) {
            .string_literal => |text| text,
            else => {
                _ = note(diag, source_name, which, .{ .entry_not_a_string = at });
                return error.InvalidBlock;
            },
        };
        try checkPath(gpa, text, at, source_name, which, diag);
        try out.append(gpa, try gpa.dupe(u8, text));
    }

    return .{ .dirs = try out.toOwnedSlice(gpa) };
}

/// The cheap half of the check. `resolve` does the half that needs disk.
fn checkPath(
    gpa: std.mem.Allocator,
    text: []const u8,
    at: usize,
    source_name: []const u8,
    which: Which,
    diag: ?*?Diagnostic,
) ParseError!void {
    if (text.len == 0) {
        _ = note(diag, source_name, which, .{ .path_empty = at });
        return error.InvalidBlock;
    }
    if (std.fs.path.isAbsolute(text)) {
        _ = note(diag, source_name, which, .{ .path_not_relative = try gpa.dupe(u8, text) });
        return error.InvalidBlock;
    }
    var walk = std.mem.splitScalar(u8, text, '/');
    while (walk.next()) |part| {
        if (std.mem.eql(u8, part, "..")) {
            _ = note(diag, source_name, which, .{ .path_leaves_project = try gpa.dupe(u8, text) });
            return error.InvalidBlock;
        }
    }
}

pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    which: Which,
    diag: ?*?Diagnostic,
) LoadError!Block {
    const path = try std.fs.path.join(gpa, &.{ project_root, file_name });
    defer gpa.free(path);

    const source = std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(max_file_bytes),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => {
            _ = note(diag, file_name, which, .{ .file_too_large = max_file_bytes });
            return error.FileTooLarge;
        },
        error.FileNotFound, error.NotDir => return .{},
        else => {
            _ = note(diag, file_name, which, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, which, diag);
}

/// The directory on disk, with every link resolved. The caller owns the result.
pub fn resolve(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    which: Which,
    name: []const u8,
    diag: ?*?Diagnostic,
) ResolveError![]u8 {
    const joined = try std.fs.path.join(gpa, &.{ project_root, name });
    defer gpa.free(joined);

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = std.Io.Dir.cwd().realPathFile(io, joined, &buffer) catch {
        _ = note(diag, file_name, which, .{ .unreadable = .{
            .name = try gpa.dupe(u8, name),
            .text = try gpa.dupe(u8, "there is nothing readable at that path"),
        } });
        return error.Unreadable;
    };
    const real = buffer[0..length];

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = std.Io.Dir.cwd().realPathFile(io, project_root, &root_buffer) catch {
        return error.Unreadable;
    };
    const root = root_buffer[0..root_length];

    if (!isInside(real, root)) {
        _ = note(diag, file_name, which, .{ .leaves_project = .{
            .name = try gpa.dupe(u8, name),
            .text = try gpa.dupe(u8, real),
        } });
        return error.LeavesProject;
    }

    return gpa.dupe(u8, real);
}

fn isInside(path: []const u8, root: []const u8) bool {
    if (!std.mem.startsWith(u8, path, root)) return false;
    if (path.len == root.len) return false;
    return path[root.len] == '/';
}

const testing = std.testing;

test "the block is a list of directories, and a file with none gets nothing" {
    const gpa = testing.allocator;

    var block = try parse(gpa, ".{ .skills = .{ \".chock/skills\", \"docs/skills\" } }", .skills, null);
    defer block.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), block.dirs.len);
    try testing.expectEqualStrings(".chock/skills", block.dirs[0]);
    try testing.expectEqualStrings("docs/skills", block.dirs[1]);

    var none = try parse(gpa, ".{ .permissions = .{} }", .skills, null);
    defer none.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), none.dirs.len);

    var empty = try parse(gpa, ".{ .skills = .{} }", .skills, null);
    defer empty.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), empty.dirs.len);
}

test "an absolute path and one that climbs out are both refused by name" {
    const gpa = testing.allocator;

    var absolute: ?Diagnostic = null;
    defer if (absolute) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidBlock,
        parse(gpa, ".{ .skills = .{ \"/etc/skills\" } }", .skills, &absolute),
    );
    try testing.expectEqualStrings("/etc/skills", absolute.?.fault.path_not_relative);

    var climbing: ?Diagnostic = null;
    defer if (climbing) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidBlock,
        parse(gpa, ".{ .skills = .{ \"../../.ssh\" } }", .skills, &climbing),
    );
    try testing.expectEqualStrings("../../.ssh", climbing.?.fault.path_leaves_project);
}

test "more directories than the bound is refused, and the message names the bound" {
    const gpa = testing.allocator;

    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(gpa);
    try source.appendSlice(gpa, ".{ .skills = .{");
    for (0..max_dirs + 1) |at| try source.print(gpa, " \"skills{d}\",", .{at});
    try source.appendSlice(gpa, " } }");
    const text = try source.toOwnedSliceSentinel(gpa, 0);
    defer gpa.free(text);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.InvalidBlock, parse(gpa, text, .skills, &diag));

    var rendered: std.ArrayList(u8) = .empty;
    defer rendered.deinit(gpa);
    try rendered.print(gpa, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, rendered.items, "more than 4 directories") != null);
}

test "a link out of the project is refused even when the path itself reads as ordinary" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "project");
    try tmp.dir.createDirPath(io, "elsewhere/secrets");

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];
    const project = try std.fs.path.join(gpa, &.{ root, "project" });
    defer gpa.free(project);
    const target = try std.fs.path.join(gpa, &.{ root, "elsewhere/secrets" });
    defer gpa.free(target);

    const inside = try std.fs.path.join(gpa, &.{ project, "skills" });
    defer gpa.free(inside);
    try std.Io.Dir.cwd().symLink(io, target, inside, .{ .is_directory = true });

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.LeavesProject,
        resolve(gpa, io, project, .skills, "skills", &diag),
    );
    try testing.expectEqualStrings("skills", diag.?.fault.leaves_project.name);
}

test "a directory inside the project resolves to its real path" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "project/.chock/skills");

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];
    const project = try std.fs.path.join(gpa, &.{ root, "project" });
    defer gpa.free(project);

    const resolved = try resolve(gpa, io, project, .skills, ".chock/skills", null);
    defer gpa.free(resolved);
    try testing.expect(std.mem.startsWith(u8, resolved, project));
    try testing.expect(std.mem.endsWith(u8, resolved, "skills"));
}

test "the same reader takes the commands block, and the message names that block" {
    const gpa = testing.allocator;

    var block = try parse(gpa, ".{ .commands = .{ \".chock/commands\" } }", .commands, null);
    defer block.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), block.dirs.len);
    try testing.expectEqualStrings(".chock/commands", block.dirs[0]);

    // The skills reader takes nothing from a file that names only commands.
    var as_skills = try parse(gpa, ".{ .commands = .{ \".chock/commands\" } }", .skills, null);
    defer as_skills.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), as_skills.dirs.len);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidBlock,
        parse(gpa, ".{ .commands = .{ \"/etc/commands\" } }", .commands, &diag),
    );

    var rendered: std.ArrayList(u8) = .empty;
    defer rendered.deinit(gpa);
    try rendered.print(gpa, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, rendered.items, "the commands directory") != null);
}
