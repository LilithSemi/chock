//! Chock's two directories, and the rules that decide whether a file in one
//! of them may be read.

const std = @import("std");

pub const dir_name = "chock";

pub const nix_store_prefix = "/nix/store/";

pub const DirError = std.mem.Allocator.Error || error{
    NoHomeDirectory,
};

pub fn configDir(gpa: std.mem.Allocator, env: *const std.process.Environ.Map) DirError![]u8 {
    return xdgDir(gpa, env, "XDG_CONFIG_HOME", &.{".config"});
}

pub fn dataDir(gpa: std.mem.Allocator, env: *const std.process.Environ.Map) DirError![]u8 {
    return xdgDir(gpa, env, "XDG_DATA_HOME", &.{ ".local", "share" });
}

pub fn stateDir(gpa: std.mem.Allocator, env: *const std.process.Environ.Map) DirError![]u8 {
    return xdgDir(gpa, env, "XDG_STATE_HOME", &.{ ".local", "state" });
}

fn xdgDir(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    variable: []const u8,
    home_relative: []const []const u8,
) DirError![]u8 {
    if (env.get(variable)) |base| {
        if (base.len != 0) return std.fs.path.join(gpa, &.{ base, dir_name });
    }
    const home = env.get("HOME") orelse return error.NoHomeDirectory;
    if (home.len == 0) return error.NoHomeDirectory;

    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(gpa);
    try parts.append(gpa, home);
    try parts.appendSlice(gpa, home_relative);
    try parts.append(gpa, dir_name);
    return std.fs.path.join(gpa, parts.items);
}

pub const Diagnostic = union(enum) {
    stat_failed: StatFailed,
    readable_by_others: ReadableByOthers,
    in_the_nix_store: []const u8,
    links_into_the_nix_store: LinksIntoTheNixStore,

    pub const StatFailed = struct {
        path: []const u8,
        err: anyerror,
    };

    pub const ReadableByOthers = struct {
        path: []const u8,
        mode: u32,
    };

    pub const LinksIntoTheNixStore = struct {
        path: []const u8,
        target: []const u8,
    };

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .stat_failed => |fault| try writer.print(
                "the credential file {s} could not be read: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .readable_by_others => |fault| try writer.print(
                "the credential file {s} has mode {o:0>4}, and a credential must be readable by its owner only. " ++
                    "Run: chmod 600 {s}",
                .{ fault.path, fault.mode, fault.path },
            ),
            .in_the_nix_store => |path| try writer.print(
                "{s} is in the Nix store, which is read only and readable by every user on this machine, " ++
                    "so Chock will not write a credential there",
                .{path},
            ),
            .links_into_the_nix_store => |fault| try writer.print(
                "{s} is a symbolic link into the Nix store ({s}), so home-manager owns it: it is read only, " ++
                    "it is readable by every user on this machine, and it is replaced on the next activation. " ++
                    "Chock will not write a credential there",
                .{ fault.path, fault.target },
            ),
        }
    }
};

fn note(out: ?*?Diagnostic, value: Diagnostic) void {
    const slot = out orelse return;
    if (slot.* != null) return;
    slot.* = value;
}

pub const PrivateError = error{
    CredentialFileIsReadable,
    CredentialFileMissing,
    StatFailed,
};

pub fn requirePrivate(io: std.Io, path: []const u8, diag: ?*?Diagnostic) PrivateError!void {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return error.CredentialFileMissing,
        else => {
            note(diag, .{ .stat_failed = .{ .path = path, .err = err } });
            return error.StatFailed;
        },
    };
    const mode = stat.permissions.toMode() & 0o7777;
    if (mode & 0o077 == 0) return;
    note(diag, .{ .readable_by_others = .{ .path = path, .mode = mode } });
    return error.CredentialFileIsReadable;
}

pub const NixStoreError = error{
    PathIsInTheNixStore,
};

pub fn refuseNixStore(
    io: std.Io,
    path: []const u8,
    link_buffer: []u8,
    diag: ?*?Diagnostic,
) NixStoreError!void {
    std.debug.assert(link_buffer.len >= std.fs.max_path_bytes);

    if (std.mem.startsWith(u8, path, nix_store_prefix)) {
        note(diag, .{ .in_the_nix_store = path });
        return error.PathIsInTheNixStore;
    }

    const len = std.Io.Dir.readLinkAbsolute(io, path, link_buffer) catch return;
    const target = link_buffer[0..len];
    if (!std.mem.startsWith(u8, target, nix_store_prefix)) return;
    note(diag, .{ .links_into_the_nix_store = .{ .path = path, .target = target } });
    return error.PathIsInTheNixStore;
}

const testing = std.testing;

fn tmpPath(buffer: []u8, tmp: std.testing.TmpDir, name: []const u8) ![]const u8 {
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &dir_buffer);
    return std.fmt.bufPrint(buffer, "{s}/{s}", .{ dir_buffer[0..len], name });
}

fn writeWithMode(path: []const u8, mode: std.posix.mode_t, contents: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(testing.io, path, .{
        .truncate = true,
        .permissions = .fromMode(mode),
    });
    defer file.close(testing.io);
    try file.writeStreamingAll(testing.io, contents);
    try file.setPermissions(testing.io, .fromMode(mode));
}

test "a credential file others can read is refused, and the message names the mode" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(&buffer, tmp, "wide");
    try writeWithMode(path, 0o644, "sk-not-a-real-key\n");

    try testing.expectError(error.CredentialFileIsReadable, requirePrivate(testing.io, path, null));

    var narrow_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const narrow = try tmpPath(&narrow_buffer, tmp, "narrow");
    try writeWithMode(narrow, 0o600, "sk-not-a-real-key\n");
    try requirePrivate(testing.io, narrow, null);
}

test "a group readable credential file is refused too, not only a world readable one" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(&buffer, tmp, "group");
    try writeWithMode(path, 0o640, "sk-not-a-real-key\n");
    try testing.expectError(error.CredentialFileIsReadable, requirePrivate(testing.io, path, null));
}

test "a missing credential file is its own answer, and never reads back as a mode that is fine" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(&buffer, tmp, "absent");
    try testing.expectError(error.CredentialFileMissing, requirePrivate(testing.io, path, null));
}

test "a symbolic link into the Nix store is refused for writing, and a plain file is not" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var scratch_link_buffer: [std.fs.max_path_bytes]u8 = undefined;

    var plain_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const plain = try tmpPath(&plain_buffer, tmp, "plain.zon");
    try writeWithMode(plain, 0o600, ".{}\n");
    try refuseNixStore(testing.io, plain, &scratch_link_buffer, null);

    // A link to a path under the store prefix: the target need not exist, since readlink reads the link itself and never the target it points at.
    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const link = try tmpPath(&link_buffer, tmp, "managed.zon");
    try tmp.dir.symLink(
        testing.io,
        nix_store_prefix ++ "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-home-manager-files/.config/chock/config.zon",
        "managed.zon",
        .{},
    );
    try testing.expectError(error.PathIsInTheNixStore, refuseNixStore(testing.io, link, &scratch_link_buffer, null));

    try testing.expectError(
        error.PathIsInTheNixStore,
        refuseNixStore(testing.io, nix_store_prefix ++ "aaaa-chock/config.zon", &scratch_link_buffer, null),
    );

    var absent_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const absent = try tmpPath(&absent_buffer, tmp, "not-yet.zon");
    try refuseNixStore(testing.io, absent, &scratch_link_buffer, null);
}

test "the two directories come from XDG when it is set and from HOME otherwise, and neither is inside the other" {
    const gpa = testing.allocator;

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", "/home/somebody");

    {
        const config = try configDir(gpa, &env);
        defer gpa.free(config);
        const data = try dataDir(gpa, &env);
        defer gpa.free(data);
        try testing.expectEqualStrings("/home/somebody/.config/chock", config);
        try testing.expectEqualStrings("/home/somebody/.local/share/chock", data);
        try testing.expect(!std.mem.startsWith(u8, data, config));
    }

    try env.put("XDG_CONFIG_HOME", "/elsewhere/config");
    try env.put("XDG_DATA_HOME", "/elsewhere/data");
    {
        const config = try configDir(gpa, &env);
        defer gpa.free(config);
        const data = try dataDir(gpa, &env);
        defer gpa.free(data);
        try testing.expectEqualStrings("/elsewhere/config/chock", config);
        try testing.expectEqualStrings("/elsewhere/data/chock", data);
        try testing.expect(!std.mem.startsWith(u8, data, config));
    }
}

test "a machine with no home directory is told so, never given a guessed path" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try testing.expectError(error.NoHomeDirectory, configDir(gpa, &env));
    try testing.expectError(error.NoHomeDirectory, dataDir(gpa, &env));
}

test "the mode a credential file holds reaches the caller, and no longer only a terminal" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(&buffer, tmp, "group");
    try writeWithMode(path, 0o640, "sk-not-a-real-key\n");

    var diag: ?Diagnostic = null;
    try testing.expectError(
        error.CredentialFileIsReadable,
        requirePrivate(testing.io, path, &diag),
    );
    try testing.expectEqual(@as(u32, 0o640), diag.?.readable_by_others.mode);
    try testing.expectEqualStrings(path, diag.?.readable_by_others.path);

    var line_buffer: [1024]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_buffer, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, line, "has mode 0640") != null);
    try testing.expect(std.mem.indexOf(u8, line, "chmod 600") != null);
}

test "a link target is borrowed from the caller's own buffer, so it outlives the call" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const link = try tmpPath(&path_buffer, tmp, "managed.zon");
    const target = nix_store_prefix ++ "zzzz-home-manager-files/.config/chock/config.zon";
    try tmp.dir.symLink(testing.io, target, "managed.zon", .{});

    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var diag: ?Diagnostic = null;
    try testing.expectError(
        error.PathIsInTheNixStore,
        refuseNixStore(testing.io, link, &link_buffer, &diag),
    );
    try testing.expectEqualStrings(target, diag.?.links_into_the_nix_store.target);
    try testing.expectEqualStrings(link, diag.?.links_into_the_nix_store.path);
}

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    note(&diag, .{ .in_the_nix_store = "/nix/store/aaaa-x/config.zon" });
    note(&diag, .{ .readable_by_others = .{ .path = "/other", .mode = 0o644 } });
    try testing.expectEqualStrings("/nix/store/aaaa-x/config.zon", diag.?.in_the_nix_store);

    note(null, .{ .in_the_nix_store = "/nix/store/aaaa-x/config.zon" });
}

test "no two faults of this module read the same" {
    const cases: []const Diagnostic = &.{
        .{ .stat_failed = .{ .path = "/x", .err = error.AccessDenied } },
        .{ .readable_by_others = .{ .path = "/x", .mode = 0o644 } },
        .{ .in_the_nix_store = "/x" },
        .{ .links_into_the_nix_store = .{ .path = "/x", .target = "/nix/store/aaaa-y" } },
    };
    var buffers: [cases.len][512]u8 = undefined;
    var lines: [cases.len][]const u8 = undefined;
    for (cases, 0..) |case, i| {
        lines[i] = try std.fmt.bufPrint(&buffers[i], "{f}", .{case});
        try testing.expect(lines[i].len > 0);
    }
    for (lines, 0..) |line, i| {
        for (lines[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, line, other));
    }
}
