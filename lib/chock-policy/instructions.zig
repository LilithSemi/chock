//! The `instructions` block of a project's own `chock.zon`: files read at the
//! project layer beside `AGENTS.md`. A project whose instructions already live
//! under another name says so here rather than copying them.

const std = @import("std");
const limits_mod = @import("limits.zig");

pub const file_name = limits_mod.file_name;

pub const block_name = "instructions";

pub const max_file_bytes = 1 << 20;

/// Every entry costs a file read and a block in the prompt, so this is a real
/// bound and not a round number.
pub const max_files: usize = 8;

pub const Block = struct {
    files: []const []const u8 = &.{},

    pub fn deinit(self: *Block, gpa: std.mem.Allocator) void {
        for (self.files) |one| gpa.free(one);
        gpa.free(self.files);
        self.* = undefined;
    }
};

pub const ParseError = error{
    OutOfMemory,
    InvalidInstructions,
};

pub const LoadError = ParseError || error{
    InstructionsFileTooLarge,
    ReadFailed,
};

pub const ResolveError = error{
    OutOfMemory,
    InstructionsLeaveProject,
    InstructionsUnreadable,
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
        too_many_files: usize,
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
                "{s}: the instructions block must be a list of paths",
                .{self.source},
            ),
            .entry_not_a_string => |index| try writer.print(
                "{s}: instruction {d} is not a string",
                .{ self.source, index + 1 },
            ),
            .path_empty => |index| try writer.print(
                "{s}: instruction {d} is empty, and a path cannot be",
                .{ self.source, index + 1 },
            ),
            .path_not_relative => |name| try writer.print(
                "{s}: the instruction {s} must be a path under the project, not an absolute one",
                .{ self.source, name },
            ),
            .path_leaves_project => |name| try writer.print(
                "{s}: the instruction {s} reaches outside the project",
                .{ self.source, name },
            ),
            .too_many_files => |limit| try writer.print(
                "{s}: the instructions block names more than {d} files",
                .{ self.source, limit },
            ),
            .leaves_project => |named| try writer.print(
                "{s}: the instruction {s} resolves to {s}, which is outside the project",
                .{ self.source, named.name, named.text },
            ),
            .unreadable => |named| try writer.print(
                "{s}: the instruction {s} could not be read: {s}",
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
        return error.InvalidInstructions;
    }

    const node = try findBlock(zoir, source_name, diag) orelse return .{};
    return readFiles(gpa, zoir, node, source_name, diag);
}

fn findBlock(
    zoir: std.zig.Zoir,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), block_name)) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, source_name, .not_a_struct_literal);
            return error.InvalidInstructions;
        },
    }
}

fn readFiles(
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
            return error.InvalidInstructions;
        },
    };

    if (items.len > max_files) {
        _ = note(diag, source_name, .{ .too_many_files = max_files });
        return error.InvalidInstructions;
    }

    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |one| gpa.free(one);
        out.deinit(gpa);
    }

    for (0..items.len) |index| {
        const text = switch (items.at(@intCast(index)).get(zoir)) {
            .string_literal => |text| text,
            else => {
                _ = note(diag, source_name, .{ .entry_not_a_string = index });
                return error.InvalidInstructions;
            },
        };
        try checkPath(gpa, text, index, source_name, diag);
        try out.append(gpa, try gpa.dupe(u8, text));
    }

    return .{ .files = try out.toOwnedSlice(gpa) };
}

/// The cheap half of the check, which needs no disk. `resolve` does the half
/// that does: a name that passes here can still be a symbolic link out of the
/// project.
fn checkPath(
    gpa: std.mem.Allocator,
    text: []const u8,
    index: usize,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!void {
    if (text.len == 0) {
        _ = note(diag, source_name, .{ .path_empty = index });
        return error.InvalidInstructions;
    }
    if (std.fs.path.isAbsolute(text)) {
        _ = note(diag, source_name, .{ .path_not_relative = try gpa.dupe(u8, text) });
        return error.InvalidInstructions;
    }
    var walk = std.mem.splitScalar(u8, text, '/');
    while (walk.next()) |part| {
        if (std.mem.eql(u8, part, "..")) {
            _ = note(diag, source_name, .{ .path_leaves_project = try gpa.dupe(u8, text) });
            return error.InvalidInstructions;
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
            return error.InstructionsFileTooLarge;
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

/// The path on disk, with every link resolved and the answer held inside the
/// project. **A repository can ship a link**, so a name that reads as ordinary
/// can point at a key in the user's home, and the prompt is where that would
/// end up. The caller owns the result.
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
        return error.InstructionsUnreadable;
    };
    const real = buffer[0..length];

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = std.Io.Dir.cwd().realPathFile(io, project_root, &root_buffer) catch {
        return error.InstructionsUnreadable;
    };
    const root = root_buffer[0..root_length];

    if (!isInside(real, root)) {
        _ = note(diag, file_name, .{ .leaves_project = .{
            .name = try gpa.dupe(u8, name),
            .text = try gpa.dupe(u8, real),
        } });
        return error.InstructionsLeaveProject;
    }

    return gpa.dupe(u8, real);
}

fn isInside(path: []const u8, root: []const u8) bool {
    if (!std.mem.startsWith(u8, path, root)) return false;
    if (path.len == root.len) return false;
    return path[root.len] == '/';
}

const testing = std.testing;

test "the block is a list of paths, and a file with none gets nothing" {
    const gpa = testing.allocator;

    var block = try parse(gpa, ".{ .instructions = .{ \"CLAUDE.md\", \"docs/agent.md\" } }", null);
    defer block.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), block.files.len);
    try testing.expectEqualStrings("CLAUDE.md", block.files[0]);
    try testing.expectEqualStrings("docs/agent.md", block.files[1]);

    var none = try parse(gpa, ".{ .policy = .{} }", null);
    defer none.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), none.files.len);

    var empty = try parse(gpa, ".{ .instructions = .{} }", null);
    defer empty.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), empty.files.len);
}

test "a path that is absolute or climbs out of the project is refused at read time" {
    const gpa = testing.allocator;

    var absolute: ?Diagnostic = null;
    defer if (absolute) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidInstructions,
        parse(gpa, ".{ .instructions = .{ \"/etc/passwd\" } }", &absolute),
    );
    try testing.expectEqualStrings("/etc/passwd", absolute.?.fault.path_not_relative);

    var climbing: ?Diagnostic = null;
    defer if (climbing) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidInstructions,
        parse(gpa, ".{ .instructions = .{ \"../../.ssh/id_rsa\" } }", &climbing),
    );
    try testing.expectEqualStrings("../../.ssh/id_rsa", climbing.?.fault.path_leaves_project);

    var typed: ?Diagnostic = null;
    defer if (typed) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidInstructions,
        parse(gpa, ".{ .instructions = .{ 3 } }", &typed),
    );
    try testing.expect(typed.?.fault == .entry_not_a_string);
}

test "a link out of the project is refused, because a repository can ship one" {
    const gpa = testing.allocator;

    var outside = testing.tmpDir(.{});
    defer outside.cleanup();
    {
        var file = try outside.dir.createFile(testing.io, "secret", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "a private key\n");
    }
    var outside_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const outside_length = try outside.dir.realPath(testing.io, &outside_buffer);
    const secret = try std.fs.path.join(gpa, &.{ outside_buffer[0..outside_length], "secret" });
    defer gpa.free(secret);

    var project = testing.tmpDir(.{});
    defer project.cleanup();
    {
        var file = try project.dir.createFile(testing.io, "real.md", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "# ordinary\n");
    }
    try project.dir.symLink(testing.io, secret, "notes.md", .{});

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try project.dir.realPath(testing.io, &root_buffer);
    const root = root_buffer[0..root_length];

    // The name is ordinary and the parse accepts it. Only the disk says no.
    var block = try parse(gpa, ".{ .instructions = .{ \"notes.md\" } }", null);
    defer block.deinit(gpa);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InstructionsLeaveProject,
        resolve(gpa, testing.io, root, "notes.md", &diag),
    );
    try testing.expectEqualStrings("notes.md", diag.?.fault.leaves_project.name);

    const kept = try resolve(gpa, testing.io, root, "real.md", null);
    defer gpa.free(kept);
    try testing.expect(std.mem.endsWith(u8, kept, "/real.md"));
}

test "a name with nothing at it is refused rather than read as an absent layer" {
    const gpa = testing.allocator;

    var project = testing.tmpDir(.{});
    defer project.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try project.dir.realPath(testing.io, &root_buffer);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InstructionsUnreadable,
        resolve(gpa, testing.io, root_buffer[0..root_length], "missing.md", &diag),
    );
    try testing.expectEqualStrings("missing.md", diag.?.fault.unreadable.name);
}

test "more names than the bound allows is refused" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(gpa);
    try source.appendSlice(gpa, ".{ .instructions = .{");
    for (0..max_files + 1) |index| {
        const one = try std.fmt.allocPrint(gpa, " \"f{d}.md\",", .{index});
        defer gpa.free(one);
        try source.appendSlice(gpa, one);
    }
    try source.appendSlice(gpa, " } }");
    const text = try source.toOwnedSliceSentinel(gpa, 0);
    defer gpa.free(text);

    try testing.expectError(error.InvalidInstructions, parse(gpa, text, &diag));
    try testing.expectEqual(max_files, diag.?.fault.too_many_files);
}
