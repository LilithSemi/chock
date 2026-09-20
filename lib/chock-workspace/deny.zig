//! The `deny_read` block of a project's own `chock.zon`: the files the agent
//! may not read. The host project's own copy governs, read before the sandbox
//! is built, because bytes that never enter the process cannot be missed.

const std = @import("std");
const diagnostic = @import("diagnostic.zig");

pub const Diagnostic = diagnostic.Diagnostic;

pub const file_name = "chock.zon";

pub const block_name = "deny_read";

/// Every entry costs a `statx` and a mount inside every tool call, so this is a
/// real bound. A project that wants more is asking for a directory, which this
/// design refuses on purpose.
pub const max_paths: usize = 64;

/// Not the cap the other two readers of this file use, which is `1 << 20`, so a
/// `chock.zon` between the two is refused here and accepted there. This reader
/// runs first, and widening a bound on a file the project supplies is a decision
/// of its own.
pub const max_file_bytes: usize = 64 * 1024;

/// A `chock.zon` this file cannot read is refused and never read as an empty
/// block, and that takes two errors and not one: the owner once wrote a policy
/// rule with a stray comma and was told `DenyBlockNotValid` when they had
/// written no `deny_read` block at all. This file has to parse the whole file
/// before it can find the block, so a file level fault must not be blamed on
/// the block.
///
/// The offending entry is not in any of these, because `diagnostic.zig` owns no
/// memory and has no slot to put it in. Each path error names the rule instead.
pub const Error = error{
    OutOfMemory,
    ChockZonNotValid,
    ChockZonTooLarge,
    DenyBlockNotValid,
    DenyPathNotRelative,
    DenyPathLeavesProject,
    DenyPathIsAPattern,
    DenyPathIsChockZon,
    DenyPathIsDirectory,
    TooManyDenyPaths,
    ReadFailed,
};

/// Read the `deny_read` block and give back one absolute path per entry, joined
/// onto `project_root`, which is where a denied file lands inside the sandbox as
/// well as on the host.
///
/// An empty slice for a project with no `chock.zon` and for one whose
/// `chock.zon` names no `deny_read`. Those two are the same answer on purpose.
///
/// A path this cannot find on the host is accepted, and is the case
/// `chock-sandbox`'s own `Mount.Deny` covers by making an empty file to bind
/// over. The caller owns the returned slice and every string in it.
pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) Error![]const []u8 {
    return loadFor(gpa, io, project_root, project_root, diag);
}

pub fn loadFor(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    sandbox_root: []const u8,
    diag: ?*?Diagnostic,
) Error![]const []u8 {
    const entries = try loadEntries(gpa, io, project_root, diag);
    defer free(gpa, entries);
    return joinOnto(gpa, entries, sandbox_root);
}

/// Split from the join so a caller can refuse a bad block before it builds
/// anything: `Workspace.openWithLayout` cannot know where the sandbox will see
/// the project until the backing exists.
pub fn loadEntries(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) Error![]const []u8 {
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
        error.FileNotFound, error.NotDir => return &.{},
        error.StreamTooLong => {
            diagnostic.note(diag, .{ .chock_zon_too_large = max_file_bytes });
            return error.ChockZonTooLarge;
        },
        else => {
            diagnostic.noteErr(diag, .chock_zon_read, err);
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parseEntries(gpa, io, source, project_root, diag);
}

pub fn joinOnto(
    gpa: std.mem.Allocator,
    entries: []const []u8,
    root: []const u8,
) Error![]const []u8 {
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |one| gpa.free(one);
        out.deinit(gpa);
    }
    for (entries) |entry| {
        try out.append(gpa, try std.fs.path.join(gpa, &.{ root, entry }));
    }
    return out.toOwnedSlice(gpa);
}

pub fn parse(
    gpa: std.mem.Allocator,
    io: std.Io,
    source: [:0]const u8,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) Error![]const []u8 {
    return parseFor(gpa, io, source, project_root, project_root, diag);
}

pub fn parseFor(
    gpa: std.mem.Allocator,
    io: std.Io,
    source: [:0]const u8,
    project_root: []const u8,
    sandbox_root: []const u8,
    diag: ?*?Diagnostic,
) Error![]const []u8 {
    const entries = try parseEntries(gpa, io, source, project_root, diag);
    defer free(gpa, entries);
    return joinOnto(gpa, entries, sandbox_root);
}

pub fn parseEntries(
    gpa: std.mem.Allocator,
    io: std.Io,
    source: [:0]const u8,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) Error![]const []u8 {
    // `trees_owned` is the handover flag. The type check below can be given
    // the two trees, and a `std.zon.parse.Diagnostics` that holds them frees
    // them itself. Only one of the two may free them.
    var trees_owned = true;
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer if (trees_owned) ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
    defer if (trees_owned) zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        diagnostic.note(diag, .{ .chock_zon_not_valid = saidOf(ast, zoir) });
        return error.ChockZonNotValid;
    }

    const node = try findBlockNode(zoir, diag) orelse return &.{};

    var zon_diag: std.zon.parse.Diagnostics = .{};
    const entries = std.zon.parse.fromZoirNodeAlloc(
        []const []const u8,
        gpa,
        ast,
        zoir,
        node,
        &zon_diag,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            diagnostic.note(diag, .{ .deny_block_not_valid = .of(&zon_diag) });
            trees_owned = false;
            zon_diag.deinit(gpa);
            return error.DenyBlockNotValid;
        },
    };
    defer std.zon.parse.free(gpa, entries);

    if (entries.len > max_paths) return error.TooManyDenyPaths;

    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |one| gpa.free(one);
        out.deinit(gpa);
    }

    for (entries) |entry| {
        try check(entry);

        const on_the_host = try std.fs.path.join(gpa, &.{ project_root, entry });
        defer gpa.free(on_the_host);
        if (try isDirectory(io, on_the_host)) return error.DenyPathIsDirectory;

        try out.append(gpa, try gpa.dupe(u8, entry));
    }

    return out.toOwnedSlice(gpa);
}

pub fn free(gpa: std.mem.Allocator, paths: []const []u8) void {
    for (paths) |one| gpa.free(one);
    gpa.free(paths);
}

pub fn check(entry: []const u8) Error!void {
    if (entry.len == 0) return error.DenyPathNotRelative;
    if (std.fs.path.isAbsolute(entry)) return error.DenyPathNotRelative;

    for (entry) |byte| {
        switch (byte) {
            '*', '?', '[' => return error.DenyPathIsAPattern,
            else => {},
        }
    }

    var parts = std.mem.tokenizeScalar(u8, entry, '/');
    var named: usize = 0;
    var last: []const u8 = "";
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, ".")) continue;
        // A `..` anywhere leaves, whatever came before it: `a/../../b` climbs
        // out as surely as `../b` does.
        if (std.mem.eql(u8, part, "..")) return error.DenyPathLeavesProject;
        named += 1;
        last = part;
    }
    // "." and "./" and "" all name the project root, which is a directory.
    if (named == 0) return error.DenyPathIsDirectory;

    // The project's own policy file and only that one. A `chock.zon` in a
    // subdirectory belongs to some nested project and is an ordinary file here.
    if (named == 1 and std.mem.eql(u8, last, file_name)) return error.DenyPathIsChockZon;
}

fn findBlockNode(zoir: std.zig.Zoir, diag: ?*?Diagnostic) Error!?std.zig.Zoir.Node.Index {
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
        // A fault of the file and not of this block. A top level that is a
        // tuple holds no block of any name. Zoir reports no error for this, so
        // the words are this file's own.
        else => {
            diagnostic.note(diag, .{
                .chock_zon_not_valid = .ofText("the file must hold a struct literal"),
            });
            return error.ChockZonNotValid;
        },
    }
}

fn saidOf(ast: std.zig.Ast, zoir: std.zig.Zoir) Diagnostic.Said {
    const zon_diag: std.zon.parse.Diagnostics = .{ .ast = ast, .zoir = zoir };
    return .of(&zon_diag);
}

/// Whether `absolute_path` is a directory on the host today. False for a path
/// that is not there, and false for any other failure: this only improves the
/// message, and `applyDenyMounts` refuses a directory again with the sandbox in
/// front of it.
fn isDirectory(io: std.Io, absolute_path: []const u8) Error!bool {
    const stat = std.Io.Dir.cwd().statFile(io, absolute_path, .{}) catch return false;
    return stat.kind == .directory;
}

const testing = std.testing;

test "a project with no deny_read block denies nothing" {
    const paths = try parse(testing.allocator, testing.io,
        \\.{ .budget = .{ .max_cost = 5.0 } }
    , "/project", null);
    defer free(testing.allocator, paths);
    try testing.expectEqual(@as(usize, 0), paths.len);
}

test "an empty struct literal denies nothing, and is not a fault" {
    const paths = try parse(testing.allocator, testing.io, ".{}", "/project", null);
    defer free(testing.allocator, paths);
    try testing.expectEqual(@as(usize, 0), paths.len);
}

test "each named path comes back joined onto the project root" {
    const paths = try parse(testing.allocator, testing.io,
        \\.{ .deny_read = .{ ".env", "config/secret.txt" } }
    , "/project", null);
    defer free(testing.allocator, paths);

    try testing.expectEqual(@as(usize, 2), paths.len);
    try testing.expectEqualStrings("/project/.env", paths[0]);
    try testing.expectEqualStrings("/project/config/secret.txt", paths[1]);
}

test "the block is read out of a file that also holds every other block" {
    const paths = try parse(testing.allocator, testing.io,
        \\.{
        \\    .budget = .{ .max_cost = 5.0, .currency = "USD" },
        \\    .deny_read = .{ ".env" },
        \\    .subagents = .{ .max_width = 2 },
        \\}
    , "/p", null);
    defer free(testing.allocator, paths);
    try testing.expectEqual(@as(usize, 1), paths.len);
    try testing.expectEqualStrings("/p/.env", paths[0]);
}

test "a chock.zon that is not ZON is refused, and never read as an empty list" {
    try testing.expectError(error.ChockZonNotValid, parse(
        testing.allocator,
        testing.io,
        ".{ .deny_read = ",
        "/p",
        null,
    ));
    try testing.expectError(error.DenyBlockNotValid, parse(
        testing.allocator,
        testing.io,
        ".{ .deny_read = 7 }",
        "/p",
        null,
    ));
}

fn messageFor(source: [:0]const u8, buffer: []u8) ![]const u8 {
    var diag: ?Diagnostic = null;
    if (parse(testing.allocator, testing.io, source, "/p", &diag)) |paths| {
        free(testing.allocator, paths);
        return error.NoFault;
    } else |_| {}
    const fault = diag orelse return error.NoDiagnostic;
    return std.fmt.bufPrint(buffer, "{f}", .{&fault});
}

test "a fault in any block of chock.zon names the file and the line, and no block" {
    var buffer: [512]u8 = undefined;

    try testing.expectEqualStrings(
        "chock.zon is not valid:\n4:9: error: expected field initializer",
        try messageFor(
            \\.{
            \\    .policy = .{
            \\        .agents = .{ .{ .kind = "main" } },
            \\        .{ .action = "net.fetch.org.ziglang", .decision = .allow },
            \\    },
            \\}
        , &buffer),
    );

    try testing.expectEqualStrings(
        "chock.zon is not valid:\n2:36: error: expected field initializer",
        try messageFor(
            \\.{
            \\    .budget = .{ .max_cost = 5.0 },,
            \\}
        , &buffer),
    );

    try testing.expectEqualStrings(
        "chock.zon is not valid:\n3:5: error: expected field initializer",
        try messageFor(
            \\.{
            \\    .budget = .{ .max_cost = 5.0 },
            \\    policy = .{ .rules = .{} },
            \\}
        , &buffer),
    );

    try testing.expectEqualStrings(
        "chock.zon is not valid:\n1:7: error: expected 'EOF', found 'an identifier'",
        try messageFor("hello world\n", &buffer),
    );

    try testing.expectEqualStrings(
        "chock.zon is not valid:\nthe file must hold a struct literal",
        try messageFor(
            \\.{
            \\    .{ .action = "net.fetch.org.ziglang", .decision = .allow },
            \\}
        , &buffer),
    );

    try testing.expectEqualStrings(
        "chock.zon: the deny_read block is not valid:\n2:18: error: expected array",
        try messageFor(
            \\.{
            \\    .deny_read = 7,
            \\}
        , &buffer),
    );

    try testing.expectEqualStrings(
        "chock.zon: the deny_read block is not valid:\n2:29: error: expected string",
        try messageFor(
            \\.{
            \\    .deny_read = .{ ".env", 7 },
            \\}
        , &buffer),
    );
}

test "a misspelled block name is not this reader's fault to report" {
    const paths = try parse(testing.allocator, testing.io,
        \\.{ .polcy = .{ .rules = .{} } }
    , "/p", null);
    defer free(testing.allocator, paths);
    try testing.expectEqual(@as(usize, 0), paths.len);
}

test "a chock.zon above the bound is its own error, and not this block's" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = buffer[0..len];

    var big: std.ArrayList(u8) = .empty;
    defer big.deinit(testing.allocator);
    try big.appendSlice(testing.allocator, ".{ .deny_read = .{ \".env\" } } // ");
    try big.appendNTimes(testing.allocator, 'x', max_file_bytes);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = file_name, .data = big.items });

    var diag: ?Diagnostic = null;
    try testing.expectError(
        error.ChockZonTooLarge,
        loadEntries(testing.allocator, testing.io, root, &diag),
    );

    var line: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "chock.zon is larger than the 65536 bytes this reader accepts",
        try std.fmt.bufPrint(&line, "{f}", .{&diag.?}),
    );
}

test "a caller that wants no diagnostic pays nothing and still gets the error" {
    try testing.expectError(error.ChockZonNotValid, parse(
        testing.allocator,
        testing.io,
        "not zon",
        "/p",
        null,
    ));
}

test "every refused shape of path has its own error" {
    try testing.expectError(error.DenyPathNotRelative, check(""));
    try testing.expectError(error.DenyPathNotRelative, check("/etc/passwd"));
    try testing.expectError(error.DenyPathLeavesProject, check("../outside"));
    try testing.expectError(error.DenyPathLeavesProject, check("a/../../outside"));
    try testing.expectError(error.DenyPathIsAPattern, check("*.env"));
    try testing.expectError(error.DenyPathIsAPattern, check("secret?.txt"));
    try testing.expectError(error.DenyPathIsAPattern, check("secret[12].txt"));
    try testing.expectError(error.DenyPathIsChockZon, check("chock.zon"));
    try testing.expectError(error.DenyPathIsChockZon, check("./chock.zon"));
    try testing.expectError(error.DenyPathIsDirectory, check("."));
    try testing.expectError(error.DenyPathIsDirectory, check("./"));
    try check("nested/chock.zon");

    try check(".env");
    try check("config/secret.txt");
    try check("./config/secret.txt");
    try check("a/b/c/id_rsa");
}

test "a directory in the project is refused by name" {
    // A directory cannot be covered with a file, and covering it with an empty
    // directory would teach the model that the project keeps nothing there.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = buffer[0..len];

    try tmp.dir.createDir(testing.io, "credentials", .default_dir);

    try testing.expectError(error.DenyPathIsDirectory, parse(
        testing.allocator,
        testing.io,
        \\.{ .deny_read = .{ "credentials" } }
    ,
        root,
        null,
    ));
}

test "a path the project does not hold yet is accepted" {
    // A `.env` in `.gitignore` is not in a checkout at all.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = buffer[0..len];

    const paths = try parse(testing.allocator, testing.io,
        \\.{ .deny_read = .{ ".env" } }
    , root, null);
    defer free(testing.allocator, paths);
    try testing.expectEqual(@as(usize, 1), paths.len);
}

test "a list longer than max_paths is refused" {
    const allocator = testing.allocator;

    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(allocator);
    try source.appendSlice(allocator, ".{ .deny_read = .{");
    for (0..max_paths + 1) |index| {
        try source.print(allocator, "\"f{d}\",", .{index});
    }
    try source.appendSlice(allocator, "} }");
    const owned = try source.toOwnedSliceSentinel(allocator, 0);
    defer allocator.free(owned);

    try testing.expectError(error.TooManyDenyPaths, parse(allocator, testing.io, owned, "/p", null));
}

test "a refusal in the middle of a list frees every path already built" {
    // The testing allocator is the check: a refusal on the second entry must
    // free the first.
    try testing.expectError(error.DenyPathNotRelative, parse(
        testing.allocator,
        testing.io,
        \\.{ .deny_read = .{ ".env", "/etc/passwd" } }
    ,
        "/p",
        null,
    ));
}
