//! The `workspace` block of a project's own `chock.zon`: the paths the agent
//! sees which the git worktree at HEAD does not carry. A generated
//! configuration and an automation directory are the two this exists for.

const std = @import("std");

pub const file_name = "chock.zon";

pub const block_name = "workspace";

pub const max_file_bytes = 1 << 20;

/// Every bind costs a mount or a copy at session start, so this is a real
/// bound and not a round number.
pub const max_binds: usize = 32;

/// How a match reaches the agent, and what happens to a change the agent makes
/// to it.
pub const Mode = enum {
    /// A bind mount the agent cannot write to.
    read_only,
    /// A bind mount. A write lands on the user's real file as it is made.
    write,
    /// Copied into the workspace, and written back at the end of the session.
    copy,
    /// Copied into the workspace, and discarded with it.
    temp_copy,

    pub fn wireName(self: Mode) []const u8 {
        return @tagName(self);
    }

    /// Whether the mode carries a change back to the user's own disk. The
    /// `write` field is meaningful for these two and an error on the rest.
    pub fn reachesTheUsersDisk(self: Mode) bool {
        return switch (self) {
            .write, .copy => true,
            .read_only, .temp_copy => false,
        };
    }
};

/// The same three answers the policy table gives, because this is the same
/// question asked in the project's own file.
pub const Write = enum { allow, ask, deny };

pub const Bind = struct {
    name: []const u8,
    mode: Mode,
    /// `ask` when the file names nothing. A project file cannot grant itself
    /// the right to write to the user's disk.
    write: Write = .ask,
    /// Null is the derived answer, which `isRequired` gives.
    required: ?bool = null,

    /// Whether a name that matches nothing stops the session. A person naming
    /// `scripts/release` asked for that path, and a pattern matching nothing
    /// is ordinary.
    pub fn isRequired(self: Bind) bool {
        return self.required orelse !hasGlob(self.name);
    }

    /// The action name the arbiter is asked under, so an organisation can
    /// refuse the mechanism fleet wide and a person can deny one path.
    pub fn actionName(self: Bind, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return std.fmt.allocPrint(gpa, "{s}{s}", .{ action_prefix, self.name });
    }
};

pub const action_prefix = "workspace.bind.";

/// The two characters `matchGlob` acts on. A `[` is an ordinary byte here, and
/// a name holding one is a literal path.
pub fn hasGlob(name: []const u8) bool {
    return std.mem.indexOfAny(u8, name, "*?") != null;
}

pub const Block = struct {
    binds: []const Bind = &.{},

    pub fn deinit(self: *Block, gpa: std.mem.Allocator) void {
        for (self.binds) |one| gpa.free(one.name);
        gpa.free(self.binds);
        self.* = undefined;
    }
};

/// One match, with every link resolved. `read_only` and `write_back` are the
/// caller's own, because the write decision is not this file's to make.
pub const Resolved = struct {
    name: []const u8,
    /// The path under the project root, which is where the sandbox sees it.
    relative: []const u8,
    /// The real path on the host. A mount source is opened `O_NOFOLLOW`, so a
    /// match that is a symbolic link binds as the link and fails. This is the
    /// path to bind.
    host_path: []const u8,
    mode: Mode,
    is_directory: bool,
    read_only: bool = true,
    write_back: bool = false,

    pub fn deinit(self: *Resolved, gpa: std.mem.Allocator) void {
        gpa.free(self.name);
        gpa.free(self.relative);
        gpa.free(self.host_path);
        self.* = undefined;
    }
};

pub fn freeResolved(gpa: std.mem.Allocator, list: []Resolved) void {
    for (list) |*one| one.deinit(gpa);
    gpa.free(list);
}

pub const ParseError = error{
    OutOfMemory,
    InvalidWorkspace,
};

pub const LoadError = ParseError || error{
    WorkspaceFileTooLarge,
    ReadFailed,
};

pub const ResolveError = error{
    OutOfMemory,
    BindLeavesProject,
    BindUnreadable,
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
        block_not_a_struct,
        unknown_block_field: []const u8,
        binds_not_a_list,
        bind_not_a_struct: usize,
        unknown_field: []const u8,
        name_not_a_string: usize,
        name_missing: usize,
        name_empty,
        name_not_relative: []const u8,
        name_leaves_project: []const u8,
        name_is_reserved: []const u8,
        mode_missing: []const u8,
        mode_unknown: Named,
        write_unknown: Named,
        write_on_mode: Named,
        required_not_a_bool: []const u8,
        too_many_binds: usize,
        bind_leaves_project: Named,
        bind_unreadable: Named,
        file_too_large: usize,
        read_failed: anyerror,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.fault) {
            .file_not_zon => |*zon_diag| zon_diag.deinit(gpa),
            .unknown_block_field,
            .unknown_field,
            .name_not_relative,
            .name_leaves_project,
            .name_is_reserved,
            .mode_missing,
            .required_not_a_bool,
            => |name| gpa.free(name),
            .mode_unknown,
            .write_unknown,
            .write_on_mode,
            .bind_leaves_project,
            .bind_unreadable,
            => |named| {
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
            .block_not_a_struct => try writer.print(
                "{s}: the workspace block must hold a struct literal",
                .{self.source},
            ),
            .unknown_block_field => |field| try writer.print(
                "{s}: the workspace block names a field this reader does not know: {s}",
                .{ self.source, field },
            ),
            .binds_not_a_list => try writer.print(
                "{s}: the workspace block's binds field must hold a list of binds",
                .{self.source},
            ),
            .bind_not_a_struct => |index| try writer.print(
                "{s}: bind {d} of the workspace block must hold a struct literal",
                .{ self.source, index },
            ),
            .unknown_field => |field| try writer.print(
                "{s}: a bind in the workspace block names a field this reader does not know: {s}",
                .{ self.source, field },
            ),
            .name_not_a_string => |index| try writer.print(
                "{s}: the name of bind {d} of the workspace block must be a string",
                .{ self.source, index },
            ),
            .name_missing => |index| try writer.print(
                "{s}: bind {d} of the workspace block names no path",
                .{ self.source, index },
            ),
            .name_empty => try writer.print(
                "{s}: a bind in the workspace block names an empty path",
                .{self.source},
            ),
            .name_not_relative => |name| try writer.print(
                "{s}: the bind {s} is an absolute path, and a bind names a path under the project",
                .{ self.source, name },
            ),
            .name_leaves_project => |name| try writer.print(
                "{s}: the bind {s} climbs out of the project, and a bind stays inside it",
                .{ self.source, name },
            ),
            .name_is_reserved => |name| try writer.print(
                "{s}: the bind {s} names a path chock holds for itself, so it cannot be bound",
                .{ self.source, name },
            ),
            .mode_missing => |name| try writer.print(
                "{s}: the bind {s} names no mode, and a bind has no default mode: " ++
                    "write .read_only, .write, .copy or .temp_copy",
                .{ self.source, name },
            ),
            .mode_unknown => |named| try writer.print(
                "{s}: the bind {s} names the mode .{s}, which is not one of " ++
                    ".read_only, .write, .copy and .temp_copy",
                .{ self.source, named.name, named.text },
            ),
            .write_unknown => |named| try writer.print(
                "{s}: the bind {s} names the write policy .{s}, which is not one of " ++
                    ".allow, .ask and .deny",
                .{ self.source, named.name, named.text },
            ),
            .write_on_mode => |named| try writer.print(
                "{s}: the bind {s} names a write field, which the mode .{s} cannot use: " ++
                    "that mode carries no change to your own files",
                .{ self.source, named.name, named.text },
            ),
            .required_not_a_bool => |name| try writer.print(
                "{s}: the required field of the bind {s} must be true or false",
                .{ self.source, name },
            ),
            .too_many_binds => |limit| try writer.print(
                "{s}: the workspace block holds more than {d} binds",
                .{ self.source, limit },
            ),
            .bind_leaves_project => |named| try writer.print(
                "{s}: the bind {s} resolves to {s}, which is outside the project",
                .{ self.source, named.name, named.text },
            ),
            .bind_unreadable => |named| try writer.print(
                "{s}: the bind {s} names {s}, which could not be read",
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

    // `parse_str_lits = true`, the same reason `limits.zig` gives: a name is
    // read straight off `zoir.string_bytes`, and that pool is left empty when
    // the option is false.
    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = true });
    var zoir_owned = true;
    defer if (zoir_owned) zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        if (note(diag, source_name, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidWorkspace;
    }

    const node = try findBlockNode(zoir, source_name, diag) orelse return .{};
    return parseBlock(gpa, zoir, node, source_name, diag);
}

fn findBlockNode(
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
            return error.InvalidWorkspace;
        },
    }
}

fn parseBlock(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Block {
    switch (node.get(zoir)) {
        .empty_literal => return .{},
        .struct_literal => |fields| {
            var binds: ?std.zig.Zoir.Node.Index = null;
            for (fields.names, 0..) |name_id, index| {
                const name = name_id.get(zoir);
                if (!std.mem.eql(u8, name, "binds")) {
                    _ = note(diag, source_name, .{ .unknown_block_field = try gpa.dupe(u8, name) });
                    return error.InvalidWorkspace;
                }
                binds = fields.vals.at(@intCast(index));
            }
            const list = binds orelse return .{};
            return parseBinds(gpa, zoir, list, source_name, diag);
        },
        else => {
            _ = note(diag, source_name, .block_not_a_struct);
            return error.InvalidWorkspace;
        },
    }
}

fn parseBinds(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Block {
    const elements = switch (node.get(zoir)) {
        .empty_literal => return .{},
        .array_literal => |range| range,
        else => {
            _ = note(diag, source_name, .binds_not_a_list);
            return error.InvalidWorkspace;
        },
    };

    if (elements.len > max_binds) {
        _ = note(diag, source_name, .{ .too_many_binds = max_binds });
        return error.InvalidWorkspace;
    }

    var out: std.ArrayList(Bind) = .empty;
    errdefer {
        for (out.items) |one| gpa.free(one.name);
        out.deinit(gpa);
    }

    for (0..elements.len) |index| {
        const bind = try parseBind(gpa, zoir, elements.at(@intCast(index)), index, source_name, diag);
        errdefer gpa.free(bind.name);
        try out.append(gpa, bind);
    }

    return .{ .binds = try out.toOwnedSlice(gpa) };
}

fn parseBind(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    index: usize,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Bind {
    const fields = switch (node.get(zoir)) {
        .struct_literal => |one| one,
        else => {
            _ = note(diag, source_name, .{ .bind_not_a_struct = index });
            return error.InvalidWorkspace;
        },
    };

    var name: ?[]const u8 = null;
    var mode: ?Mode = null;
    var write: ?Write = null;
    var required: ?bool = null;

    for (fields.names, 0..) |name_id, field_index| {
        const field = name_id.get(zoir);
        const value = fields.vals.at(@intCast(field_index));
        if (std.mem.eql(u8, field, "name")) {
            name = switch (value.get(zoir)) {
                .string_literal => |text| text,
                else => {
                    _ = note(diag, source_name, .{ .name_not_a_string = index });
                    return error.InvalidWorkspace;
                },
            };
        } else if (std.mem.eql(u8, field, "mode")) {
            mode = try readEnum(Mode, gpa, zoir, value, name, source_name, diag);
        } else if (std.mem.eql(u8, field, "write")) {
            write = try readEnum(Write, gpa, zoir, value, name, source_name, diag);
        } else if (std.mem.eql(u8, field, "required")) {
            required = switch (value.get(zoir)) {
                .true => true,
                .false => false,
                else => {
                    _ = note(diag, source_name, .{
                        .required_not_a_bool = try gpa.dupe(u8, name orelse ""),
                    });
                    return error.InvalidWorkspace;
                },
            };
        } else {
            _ = note(diag, source_name, .{ .unknown_field = try gpa.dupe(u8, field) });
            return error.InvalidWorkspace;
        }
    }

    const named = name orelse {
        _ = note(diag, source_name, .{ .name_missing = index });
        return error.InvalidWorkspace;
    };
    try checkName(gpa, named, source_name, diag);

    const chosen_mode = mode orelse {
        _ = note(diag, source_name, .{ .mode_missing = try gpa.dupe(u8, named) });
        return error.InvalidWorkspace;
    };

    if (write != null and !chosen_mode.reachesTheUsersDisk()) {
        const owned_name = try gpa.dupe(u8, named);
        const owned_mode = try gpa.dupe(u8, chosen_mode.wireName());
        if (!note(diag, source_name, .{ .write_on_mode = .{ .name = owned_name, .text = owned_mode } })) {
            gpa.free(owned_name);
            gpa.free(owned_mode);
        }
        return error.InvalidWorkspace;
    }

    return .{
        .name = try gpa.dupe(u8, named),
        .mode = chosen_mode,
        .write = write orelse .ask,
        .required = required,
    };
}

/// The field name reaches the message through `Fault`'s own two members for
/// it, so `Enum` is only ever `Mode` or `Write`.
fn readEnum(
    comptime Enum: type,
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    name: ?[]const u8,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Enum {
    const text = switch (node.get(zoir)) {
        .enum_literal => |id| id.get(zoir),
        else => "",
    };
    if (std.meta.stringToEnum(Enum, text)) |value| return value;

    const owned_name = try gpa.dupe(u8, name orelse "");
    const owned_text = try gpa.dupe(u8, text);
    const fault: Diagnostic.Fault = switch (Enum) {
        Mode => .{ .mode_unknown = .{ .name = owned_name, .text = owned_text } },
        Write => .{ .write_unknown = .{ .name = owned_name, .text = owned_text } },
        else => @compileError("readEnum reads a mode or a write policy"),
    };
    if (!note(diag, source_name, fault)) {
        gpa.free(owned_name);
        gpa.free(owned_text);
    }
    return error.InvalidWorkspace;
}

/// The names chock owns inside a workspace. `chock.zon` is bound read only so
/// the agent works under rules it cannot edit, and the whole of `.git` is the
/// backing's own.
const reserved_names = [_][]const u8{ "chock.zon", ".git" };

pub fn checkName(
    gpa: std.mem.Allocator,
    name: []const u8,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!void {
    if (name.len == 0) {
        _ = note(diag, source_name, .name_empty);
        return error.InvalidWorkspace;
    }
    if (std.fs.path.isAbsolute(name)) {
        _ = note(diag, source_name, .{ .name_not_relative = try gpa.dupe(u8, name) });
        return error.InvalidWorkspace;
    }

    var parts = std.mem.tokenizeScalar(u8, name, '/');
    var named: usize = 0;
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, ".")) continue;
        // A `..` anywhere leaves, whatever came before it, the same rule
        // `deny.zig` keeps.
        if (std.mem.eql(u8, part, "..")) {
            _ = note(diag, source_name, .{ .name_leaves_project = try gpa.dupe(u8, name) });
            return error.InvalidWorkspace;
        }
        named += 1;
    }
    if (named == 0) {
        _ = note(diag, source_name, .name_empty);
        return error.InvalidWorkspace;
    }

    for (reserved_names) |reserved| {
        const same = std.mem.eql(u8, name, reserved);
        const nested = std.mem.startsWith(u8, name, reserved) and
            name.len > reserved.len and name[reserved.len] == '/';
        if (same or nested) {
            _ = note(diag, source_name, .{ .name_is_reserved = try gpa.dupe(u8, name) });
            return error.InvalidWorkspace;
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
        error.FileNotFound, error.NotDir => return .{},
        error.StreamTooLong => {
            _ = note(diag, file_name, .{ .file_too_large = max_file_bytes });
            return error.WorkspaceFileTooLarge;
        },
        else => {
            _ = note(diag, file_name, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, diag);
}

/// Turn one match into the path to bind. `relative` is the match as the caller
/// found it under `project_root`, and `project_root` is already a real path.
///
/// A match can be a symbolic link, and a mount source is opened `O_NOFOLLOW`,
/// so the link itself cannot be bound. Every link is resolved here and the
/// resolved path is what comes back. A path that resolves outside the project
/// is refused and named.
pub fn resolve(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    bind: Bind,
    relative: []const u8,
    diag: ?*?Diagnostic,
) ResolveError!Resolved {
    const joined = try std.fs.path.join(gpa, &.{ project_root, relative });
    defer gpa.free(joined);

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = std.Io.Dir.cwd().realPathFile(io, joined, &buffer) catch {
        const owned_name = try gpa.dupe(u8, bind.name);
        const owned_path = try gpa.dupe(u8, joined);
        if (!note(diag, file_name, .{ .bind_unreadable = .{ .name = owned_name, .text = owned_path } })) {
            gpa.free(owned_name);
            gpa.free(owned_path);
        }
        return error.BindUnreadable;
    };
    const real = buffer[0..length];

    if (!under(real, project_root)) {
        const owned_name = try gpa.dupe(u8, bind.name);
        const owned_path = try gpa.dupe(u8, real);
        if (!note(diag, file_name, .{ .bind_leaves_project = .{ .name = owned_name, .text = owned_path } })) {
            gpa.free(owned_name);
            gpa.free(owned_path);
        }
        return error.BindLeavesProject;
    }

    const stat = std.Io.Dir.cwd().statFile(io, real, .{}) catch {
        const owned_name = try gpa.dupe(u8, bind.name);
        const owned_path = try gpa.dupe(u8, real);
        if (!note(diag, file_name, .{ .bind_unreadable = .{ .name = owned_name, .text = owned_path } })) {
            gpa.free(owned_name);
            gpa.free(owned_path);
        }
        return error.BindUnreadable;
    };

    const owned_name = try gpa.dupe(u8, bind.name);
    errdefer gpa.free(owned_name);
    const owned_relative = try gpa.dupe(u8, relative);
    errdefer gpa.free(owned_relative);
    return .{
        .name = owned_name,
        .relative = owned_relative,
        .host_path = try gpa.dupe(u8, real),
        .mode = bind.mode,
        .is_directory = stat.kind == .directory,
    };
}

/// Whether `path` is `root` or sits under it. Both are real paths, so no
/// component of either is a link and a textual answer is the true one.
pub fn under(path: []const u8, root: []const u8) bool {
    if (root.len == 0 or !std.fs.path.isAbsolute(root)) return false;
    if (!std.mem.startsWith(u8, path, root)) return false;
    if (path.len == root.len) return true;
    if (root[root.len - 1] == '/') return true;
    return path[root.len] == '/';
}

const testing = std.testing;

test "a file with no workspace block binds nothing" {
    for ([_][:0]const u8{ ".{}", ".{ .budget = .{ .max_cost = 1.0 } }", ".{ .workspace = .{} }" }) |source| {
        var block = try parse(testing.allocator, source, null);
        defer block.deinit(testing.allocator);
        try testing.expectEqual(@as(usize, 0), block.binds.len);
    }
}

test "the four modes are read, and the rest of the file is left to other readers" {
    const source =
        \\.{
        \\    .budget = .{ .max_cost = 5.0 },
        \\    .workspace = .{
        \\        .binds = .{
        \\            .{ .name = "config.local.*", .mode = .read_only },
        \\            .{ .name = "scripts/release", .mode = .copy, .write = .ask },
        \\            .{ .name = "vendor/cache", .mode = .temp_copy },
        \\            .{ .name = "build/out", .mode = .write, .write = .allow },
        \\        },
        \\    },
        \\}
    ;
    var block = try parse(testing.allocator, source, null);
    defer block.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 4), block.binds.len);
    try testing.expectEqualStrings("config.local.*", block.binds[0].name);
    try testing.expectEqual(Mode.read_only, block.binds[0].mode);
    try testing.expectEqual(Mode.copy, block.binds[1].mode);
    try testing.expectEqual(Write.ask, block.binds[1].write);
    try testing.expectEqual(Mode.temp_copy, block.binds[2].mode);
    try testing.expectEqual(Mode.write, block.binds[3].mode);
    try testing.expectEqual(Write.allow, block.binds[3].write);
}

test "a bind that names no mode is refused, because no mode is the default" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(error.InvalidWorkspace, parse(
        testing.allocator,
        ".{ .workspace = .{ .binds = .{ .{ .name = \"generated\" } } } }",
        &diag,
    ));
    try testing.expectEqualStrings("generated", diag.?.fault.mode_missing);
}

test "the write field defaults to ask, because a project file cannot grant itself a write" {
    var block = try parse(
        testing.allocator,
        ".{ .workspace = .{ .binds = .{ .{ .name = \"out\", .mode = .write } } } }",
        null,
    );
    defer block.deinit(testing.allocator);
    try testing.expectEqual(Write.ask, block.binds[0].write);
}

test "a write field on read_only or temp_copy is a parse error naming the field" {
    for ([_][:0]const u8{
        ".{ .workspace = .{ .binds = .{ .{ .name = \"out\", .mode = .read_only, .write = .allow } } } }",
        ".{ .workspace = .{ .binds = .{ .{ .name = \"out\", .mode = .temp_copy, .write = .deny } } } }",
    }) |source| {
        var diag: ?Diagnostic = null;
        defer if (diag) |*d| d.deinit(testing.allocator);
        try testing.expectError(error.InvalidWorkspace, parse(testing.allocator, source, &diag));
        try testing.expectEqualStrings("out", diag.?.fault.write_on_mode.name);

        var buffer: [256]u8 = undefined;
        const said = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
        try testing.expect(std.mem.indexOf(u8, said, "write field") != null);
    }
}

test "required is derived from the name, and either answer overrides it" {
    var block = try parse(testing.allocator,
        \\.{ .workspace = .{ .binds = .{
        \\    .{ .name = "scripts/release", .mode = .read_only },
        \\    .{ .name = "generated_*", .mode = .read_only },
        \\    .{ .name = "generated/maybe", .mode = .read_only, .required = false },
        \\    .{ .name = "config.local.*", .mode = .read_only, .required = true },
        \\} } }
    , null);
    defer block.deinit(testing.allocator);

    try testing.expect(block.binds[0].isRequired());
    try testing.expect(!block.binds[1].isRequired());
    try testing.expect(!block.binds[2].isRequired());
    try testing.expect(block.binds[3].isRequired());
}

test "a misspelled field inside the block is refused rather than read as a default" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(error.InvalidWorkspace, parse(
        testing.allocator,
        ".{ .workspace = .{ .binds = .{ .{ .name = \"out\", .mode = .copy, .writes = .deny } } } }",
        &diag,
    ));
    try testing.expectEqualStrings("writes", diag.?.fault.unknown_field);

    var block_diag: ?Diagnostic = null;
    defer if (block_diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(error.InvalidWorkspace, parse(
        testing.allocator,
        ".{ .workspace = .{ .bindz = .{} } }",
        &block_diag,
    ));
    try testing.expectEqualStrings("bindz", block_diag.?.fault.unknown_block_field);
}

test "a mode this reader does not know is refused and named" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(error.InvalidWorkspace, parse(
        testing.allocator,
        ".{ .workspace = .{ .binds = .{ .{ .name = \"out\", .mode = .read_write } } } }",
        &diag,
    ));
    try testing.expectEqualStrings("read_write", diag.?.fault.mode_unknown.text);
}

test "a name that climbs out of the project, or is absolute, is refused" {
    for ([_][:0]const u8{
        ".{ .workspace = .{ .binds = .{ .{ .name = \"../secrets\", .mode = .read_only } } } }",
        ".{ .workspace = .{ .binds = .{ .{ .name = \"scripts/../../secrets\", .mode = .read_only } } } }",
    }) |source| {
        var diag: ?Diagnostic = null;
        defer if (diag) |*d| d.deinit(testing.allocator);
        try testing.expectError(error.InvalidWorkspace, parse(testing.allocator, source, &diag));
        try testing.expect(diag.?.fault == .name_leaves_project);
    }

    var absolute: ?Diagnostic = null;
    defer if (absolute) |*d| d.deinit(testing.allocator);
    try testing.expectError(error.InvalidWorkspace, parse(
        testing.allocator,
        ".{ .workspace = .{ .binds = .{ .{ .name = \"/etc/shadow\", .mode = .read_only } } } }",
        &absolute,
    ));
    try testing.expectEqualStrings("/etc/shadow", absolute.?.fault.name_not_relative);
}

test "chock.zon and .git cannot be bound over" {
    for ([_][:0]const u8{
        ".{ .workspace = .{ .binds = .{ .{ .name = \"chock.zon\", .mode = .read_only } } } }",
        ".{ .workspace = .{ .binds = .{ .{ .name = \".git/config\", .mode = .write } } } }",
    }) |source| {
        var diag: ?Diagnostic = null;
        defer if (diag) |*d| d.deinit(testing.allocator);
        try testing.expectError(error.InvalidWorkspace, parse(testing.allocator, source, &diag));
        try testing.expect(diag.?.fault == .name_is_reserved);
    }
}

test "the action name a bind is asked under carries the name as written" {
    const bind = Bind{ .name = "scripts/release", .mode = .copy };
    const action = try bind.actionName(testing.allocator);
    defer testing.allocator.free(action);
    try testing.expectEqualStrings("workspace.bind.scripts/release", action);
}

test "a glob character is the two matchGlob acts on" {
    try testing.expect(hasGlob("config.local.*"));
    try testing.expect(hasGlob("a?c"));
    try testing.expect(!hasGlob("scripts/release"));
    try testing.expect(!hasGlob("a[bc]d"));
}

test "the block comes off the disk, and a project with no file binds nothing" {
    const gpa = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &path_buffer);
    const root = path_buffer[0..length];

    var missing = try load(gpa, testing.io, root, null);
    defer missing.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), missing.binds.len);

    {
        var file = try tmp.dir.createFile(testing.io, file_name, .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(
            testing.io,
            ".{ .workspace = .{ .binds = .{ .{ .name = \"out\", .mode = .temp_copy } } } }",
        );
    }

    var written = try load(gpa, testing.io, root, null);
    defer written.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), written.binds.len);
    try testing.expectEqual(Mode.temp_copy, written.binds[0].mode);
}

test "a symlink match resolves to the real path, and the real path is what is bound" {
    const gpa = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &path_buffer);
    const root = path_buffer[0..length];

    {
        var file = try tmp.dir.createFile(testing.io, "config.local.json", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "CONFIG_X=y\n");
    }
    try tmp.dir.symLink(testing.io, "config.local.json", "config.local.json-alias", .{});

    const bind = Bind{ .name = "config.local.*", .mode = .read_only };
    var resolved = try resolve(gpa, testing.io, root, bind, "config.local.json-alias", null);
    defer resolved.deinit(gpa);

    try testing.expect(std.mem.endsWith(u8, resolved.host_path, "/config.local.json"));
    try testing.expectEqualStrings("config.local.json-alias", resolved.relative);
    try testing.expect(!resolved.is_directory);
}

test "a symlink that resolves outside the project is refused and names the path" {
    const gpa = testing.allocator;

    var outside = testing.tmpDir(.{});
    defer outside.cleanup();
    {
        var file = try outside.dir.createFile(testing.io, "secret", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "token\n");
    }

    var outside_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const outside_length = try outside.dir.realPath(testing.io, &outside_buffer);
    const outside_root = outside_buffer[0..outside_length];
    const target = try std.fs.path.join(gpa, &.{ outside_root, "secret" });
    defer gpa.free(target);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.symLink(testing.io, target, "generated", .{});

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &path_buffer);
    const root = path_buffer[0..length];

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    const bind = Bind{ .name = "generated", .mode = .read_only };
    try testing.expectError(
        error.BindLeavesProject,
        resolve(gpa, testing.io, root, bind, "generated", &diag),
    );
    try testing.expectEqualStrings("generated", diag.?.fault.bind_leaves_project.name);
    try testing.expect(std.mem.endsWith(u8, diag.?.fault.bind_leaves_project.text, "/secret"));
}

test "a directory match is told from a file match" {
    const gpa = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(testing.io, "scripts/release");

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &path_buffer);
    const root = path_buffer[0..length];

    const bind = Bind{ .name = "scripts/release", .mode = .copy };
    var resolved = try resolve(gpa, testing.io, root, bind, "scripts/release", null);
    defer resolved.deinit(gpa);
    try testing.expect(resolved.is_directory);
}

test "a path is under a root only on a component boundary" {
    try testing.expect(under("/home/you/site", "/home/you/site"));
    try testing.expect(under("/home/you/site/a/b", "/home/you/site"));
    try testing.expect(!under("/home/you/site-other/a", "/home/you/site"));
    try testing.expect(!under("/home/you", "/home/you/site"));
    try testing.expect(!under("/home/you/site", "relative"));
}
