//! Reads Claude Code's own configuration out of a project.
//!
//! The surface is pinned against the shipped binary at nix store path
//! `q2c3ih72p872a6vmsg1b21icl77jskhb-claude-code-2.1.260`, read on
//! 2026-09-24: `CLAUDE.md`, `.claude/settings.json`,
//! `.claude/settings.local.json`, `.mcp.json`, and the four directories a
//! sub agent, a slash command, a plugin, and a skill live in. There is no
//! `.claude/hooks` directory: a hook is configured inside `settings.json`.
//!
//! See `../migrate.zig`'s own top comment for the translation every reader
//! in this build follows: a deny narrows and carries, an allow narrows to
//! ask, and a secret's value is never carried, only its name.

const std = @import("std");
const migrate = @import("../migrate.zig");

const Found = migrate.Found;
const Source = migrate.Source;
const ReadSource = migrate.ReadSource;
const McpServer = migrate.McpServer;
const Hint = migrate.Hint;
const Refusal = migrate.Refusal;
const hashBytes = migrate.hashBytes;
const envName = migrate.envName;

const harness_name = "claude-code";

// CLAUDE.md is a document a person writes; the rest are configuration a tool
// writes, and configuration is small.
const max_instructions_bytes: usize = 1 << 20;
const max_settings_bytes: usize = 64 * 1024;
const max_mcp_bytes: usize = 64 * 1024;

pub fn read(arena: std.mem.Allocator, io: std.Io, project_root: []const u8) anyerror!Found {
    var sources: std.ArrayList(ReadSource) = .empty;
    var instructions: std.ArrayList(Source) = .empty;
    var mcp_servers: std.ArrayList(McpServer) = .empty;
    var policy_hints: std.ArrayList(Hint) = .empty;
    var refused: std.ArrayList(Refusal) = .empty;

    try readInstructions(arena, io, project_root, &sources, &instructions);
    try readSettings(arena, io, project_root, ".claude/settings.json", &sources, &refused);
    try readSettings(arena, io, project_root, ".claude/settings.local.json", &sources, &refused);
    try readMcp(arena, io, project_root, &sources, &mcp_servers, &refused);
    try refuseUncarriedDirectories(arena, io, project_root, &refused);

    return .{
        .sources = try sources.toOwnedSlice(arena),
        .instructions = try instructions.toOwnedSlice(arena),
        .mcp_servers = try mcp_servers.toOwnedSlice(arena),
        .policy_hints = try policy_hints.toOwnedSlice(arena),
        .refused = try refused.toOwnedSlice(arena),
    };
}

/// The bytes of `project_root`/`rel_path`, bounded by `limit`. `null` for a
/// missing or otherwise unreadable file: absence is not an error, and
/// neither is a permission fault this reader cannot fix. Only allocation
/// failure is a real error, so only that is propagated.
fn readBounded(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    rel_path: []const u8,
    limit: usize,
) !?[]const u8 {
    const full = try std.fs.path.join(arena, &.{ project_root, rel_path });
    return std.Io.Dir.cwd().readFileAlloc(io, full, arena, .limited(limit)) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => null,
    };
}

fn exists(arena: std.mem.Allocator, io: std.Io, project_root: []const u8, rel_path: []const u8) !bool {
    const full = try std.fs.path.join(arena, &.{ project_root, rel_path });
    _ = std.Io.Dir.cwd().statFile(io, full, .{}) catch return false;
    return true;
}

fn readInstructions(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    sources: *std.ArrayList(ReadSource),
    instructions: *std.ArrayList(Source),
) !void {
    const rel = "CLAUDE.md";
    const bytes = try readBounded(arena, io, project_root, rel, max_instructions_bytes) orelse return;
    try sources.append(arena, .{ .path = rel, .hash = hashBytes(bytes) });
    try instructions.append(arena, .{ .path = rel, .harness = harness_name });
}

const PermissionsJson = struct {
    allow: []const []const u8 = &.{},
    ask: []const []const u8 = &.{},
    deny: []const []const u8 = &.{},
    additionalDirectories: []const []const u8 = &.{},
    defaultMode: []const u8 = "",
    disableBypassPermissionsMode: bool = false,
};

const SettingsJson = struct {
    permissions: ?PermissionsJson = null,
    // Only presence is asked for: a hook's own shape does not matter to a
    // reader that carries none of it.
    hooks: ?std.json.Value = null,
};

fn readSettings(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    rel: []const u8,
    sources: *std.ArrayList(ReadSource),
    refused: *std.ArrayList(Refusal),
) !void {
    const bytes = try readBounded(arena, io, project_root, rel, max_settings_bytes) orelse return;
    try sources.append(arena, .{ .path = rel, .hash = hashBytes(bytes) });

    const parsed = std.json.parseFromSliceLeaky(SettingsJson, arena, bytes, .{
        .ignore_unknown_fields = true,
    }) catch {
        try refused.append(arena, .{
            .what = rel,
            .reason = "not valid JSON, so nothing in it was carried",
        });
        return;
    };

    if (parsed.hooks != null) {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "hooks in {s}", .{rel}),
            .reason = "a hook runs on the host with full developer privilege, and this build has no way to run one safely",
        });
    }

    const permissions = parsed.permissions orelse return;

    // A rule here is a tool and an argument pattern, as in `Bash(cargo
    // test:*)`. Chock's table matches an action name, so none of these carry:
    // the name would decide nothing, and an interior `*` is refused by the
    // policy reader outright, which would stop the whole file loading.
    for ([_][]const []const u8{ permissions.deny, permissions.allow, permissions.ask }) |list| {
        for (list) |rule| {
            try refused.append(arena, .{
                .what = try std.fmt.allocPrint(arena, "permissions rule {s}", .{rule}),
                .reason = "it names a tool and an argument pattern, and this table decides by action name instead",
            });
        }
    }

    if (permissions.additionalDirectories.len != 0) {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "permissions.additionalDirectories in {s}", .{rel}),
            .reason = "a reach widening that belongs in .workspace.binds, not the policy table, and this build does not write that block yet",
        });
    }

    if (std.mem.eql(u8, permissions.defaultMode, "bypassPermissions")) {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "defaultMode: bypassPermissions in {s}", .{rel}),
            .reason = "it is the off switch, and this build never carries one",
        });
    }

    if (permissions.disableBypassPermissionsMode) {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "disableBypassPermissionsMode in {s}", .{rel}),
            .reason = "it narrows, but Chock has no bypass mode at all, so there is nothing to disable",
        });
    }
}

const McpServerJson = struct {
    command: []const u8 = "",
    args: []const []const u8 = &.{},
    env: std.json.ArrayHashMap([]const u8) = .{},
};

const McpJson = struct {
    mcpServers: std.json.ArrayHashMap(McpServerJson) = .{},
};

fn readMcp(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    sources: *std.ArrayList(ReadSource),
    mcp_servers: *std.ArrayList(McpServer),
    refused: *std.ArrayList(Refusal),
) !void {
    const rel = ".mcp.json";
    const bytes = try readBounded(arena, io, project_root, rel, max_mcp_bytes) orelse return;
    try sources.append(arena, .{ .path = rel, .hash = hashBytes(bytes) });

    const parsed = std.json.parseFromSliceLeaky(McpJson, arena, bytes, .{
        .ignore_unknown_fields = true,
    }) catch {
        try refused.append(arena, .{
            .what = rel,
            .reason = "not valid JSON, so no server in it was carried",
        });
        return;
    };

    var server_it = parsed.mcpServers.map.iterator();
    while (server_it.next()) |server| {
        var names: std.ArrayList([]const u8) = .empty;
        var env_it = server.value_ptr.env.map.iterator();
        while (env_it.next()) |pair| {
            // The value half of this pair is never read past this line: see
            // envName's own doc comment.
            try names.append(arena, envName(pair.key_ptr.*));
        }
        try mcp_servers.append(arena, .{
            .name = server.key_ptr.*,
            .command = server.value_ptr.command,
            .args = server.value_ptr.args,
            .env = try names.toOwnedSlice(arena),
            .source_file = rel,
        });
    }
}

const uncarried_dirs = [_]struct { path: []const u8, reason: []const u8 }{
    .{
        .path = ".claude/agents",
        .reason = "a sub agent runs as its own agent, and this build has no mechanism that runs one",
    },
    .{
        .path = ".claude/commands",
        .reason = "a slash command expands host side, and this build has no mechanism that runs one",
    },
    .{
        .path = ".claude/plugins",
        .reason = "a plugin runs with the host's own privilege, and this build has no mechanism that runs one safely",
    },
    .{
        .path = ".claude/skills",
        .reason = "a skill runs host side instructions, and this build has no mechanism that runs one",
    },
};

fn refuseUncarriedDirectories(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    refused: *std.ArrayList(Refusal),
) !void {
    for (uncarried_dirs) |one| {
        if (!try exists(arena, io, project_root, one.path)) continue;
        try refused.append(arena, .{ .what = one.path, .reason = one.reason });
    }
}

const testing = std.testing;

fn writeProjectFile(io: std.Io, project_root: []const u8, rel_path: []const u8, contents: []const u8) !void {
    const full = try std.fs.path.join(testing.allocator, &.{ project_root, rel_path });
    defer testing.allocator.free(full);
    if (std.fs.path.dirname(full)) |parent| {
        try std.Io.Dir.cwd().createDirPath(io, parent);
    }
    var file = try std.Io.Dir.cwd().createFile(io, full, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
}

fn tmpProjectRoot(arena: std.mem.Allocator, tmp: *testing.TmpDir) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    return arena.dupe(u8, buffer[0..len]);
}

test "a permission rule is refused by name, because it is a tool and a pattern" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    // The shapes Claude Code actually writes. None is an action name here,
    // and `Bash(cargo test:*)` would be refused by the policy reader outright
    // for the `*` in the middle, taking the whole file with it.
    try writeProjectFile(testing.io, project_root, ".claude/settings.json",
        \\{"permissions": {"deny": ["Read(//etc/**)"], "allow": ["Bash(cargo test:*)"], "ask": ["WebFetch(domain:example.com)"]}}
    );

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 0), found.policy_hints.len);
    var seen: usize = 0;
    for (found.refused) |one| {
        if (std.mem.indexOf(u8, one.what, "Bash(cargo test:*)") != null) seen += 1;
        if (std.mem.indexOf(u8, one.what, "Read(//etc/**)") != null) seen += 1;
        if (std.mem.indexOf(u8, one.what, "WebFetch(domain:example.com)") != null) seen += 1;
    }
    try testing.expectEqual(@as(usize, 3), seen);
}

test "an env value never appears anywhere in the returned Found while its name does" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, ".mcp.json",
        \\{"mcpServers": {"openai": {"command": "npx", "args": ["mcp-server-openai"], "env": {"OPENAI_API_KEY": "sk-live-do-not-leak"}}}}
    );

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 1), found.mcp_servers.len);
    const server = found.mcp_servers[0];
    try testing.expectEqualStrings("openai", server.name);
    try testing.expectEqual(@as(usize, 1), server.env.len);
    try testing.expectEqualStrings("OPENAI_API_KEY", server.env[0]);

    const text = try migrate.render(arena, found, "0.1.0-test", "2026-09-24");
    try testing.expect(std.mem.indexOf(u8, text, "OPENAI_API_KEY") != null);
    try testing.expect(std.mem.indexOf(u8, text, "sk-live-do-not-leak") == null);
}

test "a malformed settings.json is refused without losing CLAUDE.md" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, "CLAUDE.md", "# project instructions\n");
    try writeProjectFile(testing.io, project_root, ".claude/settings.json", "{ this is not json");

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 1), found.instructions.len);
    try testing.expectEqualStrings("CLAUDE.md", found.instructions[0].path);

    var saw_refusal = false;
    for (found.refused) |one| {
        if (std.mem.eql(u8, one.what, ".claude/settings.json")) saw_refusal = true;
    }
    try testing.expect(saw_refusal);
}

test "every file read appears in sources with a 64 character hash" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, "CLAUDE.md", "# hi\n");
    try writeProjectFile(testing.io, project_root, ".claude/settings.json", "{}");
    try writeProjectFile(testing.io, project_root, ".claude/settings.local.json", "{}");
    try writeProjectFile(testing.io, project_root, ".mcp.json", "{}");

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 4), found.sources.len);
    const expected_paths = [_][]const u8{
        "CLAUDE.md", ".claude/settings.json", ".claude/settings.local.json", ".mcp.json",
    };
    for (expected_paths) |expected| {
        var found_it = false;
        for (found.sources) |one| {
            if (!std.mem.eql(u8, one.path, expected)) continue;
            found_it = true;
            try testing.expectEqual(@as(usize, 64), one.hash.len);
            for (one.hash) |c| try testing.expect(std.ascii.isHex(c) and !std.ascii.isUpper(c));
        }
        try testing.expect(found_it);
    }
}

test "a project with none of the surface gives an empty Found, not an error" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 0), found.sources.len);
    try testing.expectEqual(@as(usize, 0), found.instructions.len);
    try testing.expectEqual(@as(usize, 0), found.mcp_servers.len);
    try testing.expectEqual(@as(usize, 0), found.policy_hints.len);
    try testing.expectEqual(@as(usize, 0), found.refused.len);
}

test "additionalDirectories, bypassPermissions and disableBypassPermissionsMode are each refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, ".claude/settings.json",
        \\{"permissions": {
        \\  "additionalDirectories": ["/opt/data"],
        \\  "defaultMode": "bypassPermissions",
        \\  "disableBypassPermissionsMode": true
        \\}}
    );

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 3), found.refused.len);
}

test "hooks in settings.json are refused, and the four unsafe directories are each named" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, ".claude/settings.json",
        \\{"hooks": {"PreToolUse": []}}
    );
    try writeProjectFile(testing.io, project_root, ".claude/agents/reviewer.md", "# reviewer\n");
    try writeProjectFile(testing.io, project_root, ".claude/commands/deploy.md", "# deploy\n");
    try writeProjectFile(testing.io, project_root, ".claude/plugins/example/plugin.json", "{}");
    try writeProjectFile(testing.io, project_root, ".claude/skills/reader/SKILL.md", "# reader\n");

    const found = try read(arena, testing.io, project_root);

    // One for the hooks block, one for each of the four directories.
    try testing.expectEqual(@as(usize, 5), found.refused.len);
}
