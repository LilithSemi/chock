//! The `skills` block of a project's own `chock.zon`: directories that hold
//! skill directories. A project that ships skills of its own says where they
//! are here, and a project that says nothing has none.
//!
//! It names directories where `instructions.zig` names files, and the rest is
//! the same: a relative path only, no `..`, and every link resolved before the
//! answer is kept, because a repository can ship a link that reads as ordinary
//! and points at the user's home.
//!
//! **The block grants nothing.** It says where to look. What an agent may do
//! with what is found there is `skill.read.*` in the policy table, and
//! `lib/chock-core/skills.zig` states why a skill's own `allowed-tools` is
//! never read as a grant.

const std = @import("std");
const limits_mod = @import("limits.zig");

pub const file_name = limits_mod.file_name;

pub const block_name = "skills";

pub const max_file_bytes = 1 << 20;

/// Every entry is a directory walk at session start, and a project needs one
/// of them. More than this is a project that has spread its skills around.
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
    InvalidSkills,
};

pub const LoadError = ParseError || error{
    SkillsFileTooLarge,
    ReadFailed,
};

pub const ResolveError = error{
    OutOfMemory,
    SkillsLeaveProject,
    SkillsUnreadable,
};

pub const Diagnostic = struct {
    source: []const u8,
    fault: Fault,

    pub const Named = struct {
        name: []const u8,
        text: []const u8,
    };

    pub const Fault = union(enum) {
        file_not_zon: std.zon.parse.Diagnostics,
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

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.fault) {
            .file_not_zon => |*zon_diag| zon_diag.deinit(gpa),
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
            .file_not_zon => |*zon_diag| try writer.print(
                "{s} is not valid:\n{f}",
                .{ self.source, zon_diag },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{self.source},
            ),
            .not_a_list => try writer.print(
                "{s}: the skills block must be a list of directories",
                .{self.source},
            ),
            .entry_not_a_string => |at| try writer.print(
                "{s}: skills directory {d} is not a string",
                .{ self.source, at + 1 },
            ),
            .path_empty => |at| try writer.print(
                "{s}: skills directory {d} is empty, and a path cannot be",
                .{ self.source, at + 1 },
            ),
            .path_not_relative => |name| try writer.print(
                "{s}: the skills directory {s} must be a path under the project, not an absolute one",
                .{ self.source, name },
            ),
            .path_leaves_project => |name| try writer.print(
                "{s}: the skills directory {s} reaches outside the project",
                .{ self.source, name },
            ),
            .too_many_dirs => |limit| try writer.print(
                "{s}: the skills block names more than {d} directories",
                .{ self.source, limit },
            ),
            .leaves_project => |named| try writer.print(
                "{s}: the skills directory {s} resolves to {s}, which is outside the project",
                .{ self.source, named.name, named.text },
            ),
            .unreadable => |named| try writer.print(
                "{s}: the skills directory {s} could not be read: {s}",
                .{ self.source, named.name, named.text },
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

fn note(out: ?*?Diagnostic, source: []const u8, fault: Diagnostic.Fault) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = .{ .source = source, .fault = fault };
    return true;
}

pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!Block {
    return parseFrom(gpa, source, file_name, diag);
}

pub fn parseFrom(
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Block {
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    var ast_owned = true;
    defer if (ast_owned) ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = true });
    var zoir_owned = true;
    defer if (zoir_owned) zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        if (note(diag, source_name, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidSkills;
    }

    const node = try findBlock(zoir, source_name, diag) orelse return .{};
    return readDirs(gpa, zoir, node, source_name, diag);
}

fn findBlock(
    zoir: std.zig.Zoir,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, at| {
                if (std.mem.eql(u8, name.get(zoir), block_name)) {
                    return fields.vals.at(@intCast(at));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, source_name, .not_a_struct_literal);
            return error.InvalidSkills;
        },
    }
}

fn readDirs(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Block {
    const items = switch (node.get(zoir)) {
        .empty_literal => return .{},
        .array_literal => |list| list,
        else => {
            _ = note(diag, source_name, .not_a_list);
            return error.InvalidSkills;
        },
    };

    if (items.len > max_dirs) {
        _ = note(diag, source_name, .{ .too_many_dirs = max_dirs });
        return error.InvalidSkills;
    }

    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |one| gpa.free(one);
        out.deinit(gpa);
    }

    for (0..items.len) |at| {
        const text = switch (items.at(@intCast(at)).get(zoir)) {
            .string_literal => |text| text,
            else => {
                _ = note(diag, source_name, .{ .entry_not_a_string = at });
                return error.InvalidSkills;
            },
        };
        try checkPath(gpa, text, at, source_name, diag);
        try out.append(gpa, try gpa.dupe(u8, text));
    }

    return .{ .dirs = try out.toOwnedSlice(gpa) };
}

/// The cheap half of the check, which needs no disk. `resolve` does the half
/// that does: a name that passes here can still be a link out of the project.
fn checkPath(
    gpa: std.mem.Allocator,
    text: []const u8,
    at: usize,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!void {
    if (text.len == 0) {
        _ = note(diag, source_name, .{ .path_empty = at });
        return error.InvalidSkills;
    }
    if (std.fs.path.isAbsolute(text)) {
        _ = note(diag, source_name, .{ .path_not_relative = try gpa.dupe(u8, text) });
        return error.InvalidSkills;
    }
    var walk = std.mem.splitScalar(u8, text, '/');
    while (walk.next()) |part| {
        if (std.mem.eql(u8, part, "..")) {
            _ = note(diag, source_name, .{ .path_leaves_project = try gpa.dupe(u8, text) });
            return error.InvalidSkills;
        }
    }
}

pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
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
            _ = note(diag, file_name, .{ .file_too_large = max_file_bytes });
            return error.SkillsFileTooLarge;
        },
        error.FileNotFound, error.NotDir => return .{},
        else => {
            _ = note(diag, file_name, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, diag);
}

/// The directory on disk, with every link resolved and the answer held inside
/// the project. The caller owns the result.
pub fn resolve(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    name: []const u8,
    diag: ?*?Diagnostic,
) ResolveError![]u8 {
    const joined = try std.fs.path.join(gpa, &.{ project_root, name });
    defer gpa.free(joined);

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = std.Io.Dir.cwd().realPathFile(io, joined, &buffer) catch {
        _ = note(diag, file_name, .{ .unreadable = .{
            .name = try gpa.dupe(u8, name),
            .text = try gpa.dupe(u8, "there is nothing readable at that path"),
        } });
        return error.SkillsUnreadable;
    };
    const real = buffer[0..length];

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = std.Io.Dir.cwd().realPathFile(io, project_root, &root_buffer) catch {
        return error.SkillsUnreadable;
    };
    const root = root_buffer[0..root_length];

    if (!isInside(real, root)) {
        _ = note(diag, file_name, .{ .leaves_project = .{
            .name = try gpa.dupe(u8, name),
            .text = try gpa.dupe(u8, real),
        } });
        return error.SkillsLeaveProject;
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

    var block = try parse(gpa, ".{ .skills = .{ \".chock/skills\", \"docs/skills\" } }", null);
    defer block.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), block.dirs.len);
    try testing.expectEqualStrings(".chock/skills", block.dirs[0]);
    try testing.expectEqualStrings("docs/skills", block.dirs[1]);

    var none = try parse(gpa, ".{ .permissions = .{} }", null);
    defer none.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), none.dirs.len);

    var empty = try parse(gpa, ".{ .skills = .{} }", null);
    defer empty.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), empty.dirs.len);
}

test "an absolute path and one that climbs out are both refused by name" {
    const gpa = testing.allocator;

    var absolute: ?Diagnostic = null;
    defer if (absolute) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSkills,
        parse(gpa, ".{ .skills = .{ \"/etc/skills\" } }", &absolute),
    );
    try testing.expectEqualStrings("/etc/skills", absolute.?.fault.path_not_relative);

    var climbing: ?Diagnostic = null;
    defer if (climbing) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSkills,
        parse(gpa, ".{ .skills = .{ \"../../.ssh\" } }", &climbing),
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
    try testing.expectError(error.InvalidSkills, parse(gpa, text, &diag));

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
        error.SkillsLeaveProject,
        resolve(gpa, io, project, "skills", &diag),
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

    const resolved = try resolve(gpa, io, project, ".chock/skills", null);
    defer gpa.free(resolved);
    try testing.expect(std.mem.startsWith(u8, resolved, project));
    try testing.expect(std.mem.endsWith(u8, resolved, "skills"));
}
