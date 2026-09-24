//! Reads Zed's own project configuration and returns a neutral `Found`.
//!
//! Pinned against `zed-industries/zed` at commit
//! `2c4bc2d7b2c5b7832ad964f39840d823d961cb0e`, read 2026-09-24.
//!
//! - **Instructions**: an ordered candidate list, checked at the project
//!   root only, with no directory walk. The first one present wins:
//!   `.rules`, `.cursorrules`, `.windsurfrules`, `.clinerules`,
//!   `.github/copilot-instructions.md`, `AGENT.md`, `AGENTS.md`, `CLAUDE.md`,
//!   `GEMINI.md`. `~/.config/zed/AGENTS.md` is user scope, and is never
//!   read here.
//! - **Config**: `.zed/settings.json` at the project root only. Zed's
//!   global settings file is never read here.
//! - **MCP**: Zed calls these context servers, under the top level key
//!   `context_servers`. The entry shape is untagged: a `command` field
//!   means a stdio server, a `url` field with no `command` means an http
//!   one, and this build carries no local command for that, so it is
//!   refused rather than dropped.
//! - **Permissions**: `agent.tool_permissions` sets a stance per tool name,
//!   spelled as a regex pattern over command text. No action this build
//!   defines is a command pattern, so every row here, `default` and each
//!   tool, is a `Refusal` naming the JSON key, never a translated `Hint`.
//!
//! See `../migrate.zig`'s own top comment for the shared translation: a
//! deny narrows and carries, an allow narrows to ask, and a secret's value
//! is never carried, only its name.

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

const harness_name = "zed";

// A `.rules` style file is a document a person writes, so it gets the same
// room as CLAUDE.md. `settings.json` is configuration a tool writes, and
// configuration is small.
const max_instructions_bytes: usize = 1 << 20;
const max_settings_bytes: usize = 64 * 1024;

/// The candidate instruction files, in the order Zed checks them. The first
/// one present at the project root wins; the rest are never opened.
const instruction_candidates = [_][]const u8{
    ".rules",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".github/copilot-instructions.md",
    "AGENT.md",
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
};

pub fn read(arena: std.mem.Allocator, io: std.Io, project_root: []const u8) anyerror!Found {
    var sources: std.ArrayList(ReadSource) = .empty;
    var instructions: std.ArrayList(Source) = .empty;
    var mcp_servers: std.ArrayList(McpServer) = .empty;
    // Every permission fact Zed carries is a command regex, not an action
    // this build defines, so it is always a Refusal: this list stays empty.
    var policy_hints: std.ArrayList(Hint) = .empty;
    var refused: std.ArrayList(Refusal) = .empty;

    try readInstructions(arena, io, project_root, &sources, &instructions);
    try readSettings(arena, io, project_root, &sources, &mcp_servers, &refused);
    try refuseUnreadable(arena, io, project_root, &refused);

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
/// neither is a permission fault this reader cannot fix.
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

fn dirHasEntry(arena: std.mem.Allocator, io: std.Io, project_root: []const u8, rel_path: []const u8) !bool {
    const full = try std.fs.path.join(arena, &.{ project_root, rel_path });
    var dir = std.Io.Dir.openDirAbsolute(io, full, .{ .iterate = true }) catch return false;
    defer dir.close(io);
    var it = dir.iterate();
    return (it.next(io) catch null) != null;
}

/// Checks each candidate in order and stops at the first one present. A
/// candidate after the winner is never opened, which is the property under
/// test: `sources` names only the file that won.
fn readInstructions(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    sources: *std.ArrayList(ReadSource),
    instructions: *std.ArrayList(Source),
) !void {
    for (instruction_candidates) |rel| {
        const bytes = try readBounded(arena, io, project_root, rel, max_instructions_bytes) orelse continue;
        try sources.append(arena, .{ .path = rel, .hash = hashBytes(bytes) });
        try instructions.append(arena, .{ .path = rel, .harness = harness_name });
        return;
    }
}

fn readSettings(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    sources: *std.ArrayList(ReadSource),
    mcp_servers: *std.ArrayList(McpServer),
    refused: *std.ArrayList(Refusal),
) !void {
    const rel = ".zed/settings.json";
    const bytes = try readBounded(arena, io, project_root, rel, max_settings_bytes) orelse return;
    try sources.append(arena, .{ .path = rel, .hash = hashBytes(bytes) });

    const value = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch {
        try refused.append(arena, .{ .what = rel, .reason = "not valid JSON, so nothing in it was carried" });
        return;
    };
    const root = switch (value) {
        .object => |object| object,
        else => {
            try refused.append(arena, .{ .what = rel, .reason = "not a JSON object at the top level, so nothing in it was carried" });
            return;
        },
    };

    try readContextServers(arena, root, rel, mcp_servers, refused);
    try readToolPermissions(arena, root, rel, refused);

    if (root.get("agent_servers")) |_| {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "agent_servers in {s}", .{rel}),
            .reason = "a pointer to an external agent binary; this build has no mechanism that runs one safely",
        });
    }
}

fn jsonString(value: ?std.json.Value) ?[]const u8 {
    return switch (value orelse return null) {
        .string => |s| s,
        else => null,
    };
}

fn jsonStringArray(arena: std.mem.Allocator, value: std.json.Value) ![]const []const u8 {
    if (value != .array) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (value.array.items) |item| {
        if (item == .string) try out.append(arena, item.string);
    }
    return out.toOwnedSlice(arena);
}

/// `context_servers` is an object of name to entry, and the entry shape is
/// untagged: matched by which fields are present, not by a type tag.
fn readContextServers(
    arena: std.mem.Allocator,
    root: std.json.ObjectMap,
    rel: []const u8,
    mcp_servers: *std.ArrayList(McpServer),
    refused: *std.ArrayList(Refusal),
) !void {
    const raw = root.get("context_servers") orelse return;
    const servers = switch (raw) {
        .object => |object| object,
        else => {
            try refused.append(arena, .{ .what = "context_servers", .reason = "not a JSON object, so no server in it was carried" });
            return;
        },
    };

    var it = servers.iterator();
    while (it.next()) |entry| try readContextServer(arena, entry.key_ptr.*, entry.value_ptr.*, rel, mcp_servers, refused);
}

fn readContextServer(
    arena: std.mem.Allocator,
    name: []const u8,
    raw: std.json.Value,
    rel: []const u8,
    mcp_servers: *std.ArrayList(McpServer),
    refused: *std.ArrayList(Refusal),
) !void {
    const object = switch (raw) {
        .object => |o| o,
        else => {
            try refused.append(arena, .{
                .what = try std.fmt.allocPrint(arena, "context server \"{s}\"", .{name}),
                .reason = "not a JSON object, so its shape could not be matched",
            });
            return;
        },
    };

    if (jsonString(object.get("command"))) |command| {
        var names: std.ArrayList([]const u8) = .empty;
        if (object.get("env")) |env| {
            if (env == .object) {
                var env_it = env.object.iterator();
                while (env_it.next()) |pair| try names.append(arena, envName(pair.key_ptr.*));
            }
        }
        const args: []const []const u8 = if (object.get("args")) |raw_args|
            try jsonStringArray(arena, raw_args)
        else
            &.{};
        try mcp_servers.append(arena, .{
            .name = name,
            .command = command,
            .args = args,
            .env = try names.toOwnedSlice(arena),
            .source_file = rel,
        });
        return;
    }

    if (jsonString(object.get("url")) != null) {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "context server \"{s}\"", .{name}),
            .reason = "an http context server has no local command; only a stdio entry with a command is carried",
        });
        return;
    }

    try refused.append(arena, .{
        .what = try std.fmt.allocPrint(arena, "context server \"{s}\"", .{name}),
        .reason = "neither a command nor a url field, so its shape matches neither entry form",
    });
}

/// The whole of `agent.tool_permissions` is a `Refusal`: `default` is a
/// session wide stance, and each entry in `tools` is a regex pattern over
/// command text spelled in Zed's own tool names, not a Chock action.
///
/// **A row for an action this build does not define would read as a
/// carried stance and match nothing.** That is worse than refusing, because
/// the file looks faithful. See this file's own top comment.
fn readToolPermissions(
    arena: std.mem.Allocator,
    root: std.json.ObjectMap,
    rel: []const u8,
    refused: *std.ArrayList(Refusal),
) !void {
    const agent = switch (root.get("agent") orelse return) {
        .object => |o| o,
        else => return,
    };
    const permissions = switch (agent.get("tool_permissions") orelse return) {
        .object => |o| o,
        else => return,
    };

    if (permissions.get("default")) |_| {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "agent.tool_permissions.default in {s}", .{rel}),
            .reason = "a session wide stance covering every tool; no single action here stands for it",
        });
    }

    const tools = switch (permissions.get("tools") orelse return) {
        .object => |o| o,
        else => return,
    };
    var it = tools.iterator();
    while (it.next()) |entry| {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "agent.tool_permissions.tools.\"{s}\" in {s}", .{ entry.key_ptr.*, rel }),
            .reason = "its stance is a regex pattern over command text, spelled in Zed's own tool name; no action here matches a command pattern",
        });
    }
}

fn refuseUnreadable(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    refused: *std.ArrayList(Refusal),
) !void {
    if (try dirHasEntry(arena, io, project_root, ".agents/skills")) {
        try refused.append(arena, .{
            .what = ".agents/skills",
            .reason = "a skill runs host side instructions, and this build has no mechanism that runs one",
        });
    }

    // Zed keeps slash commands in a SQLite prompts-db outside the project,
    // so there is no project file to check the presence of.
    try refused.append(arena, .{
        .what = "slash commands",
        .reason = "Zed stores them in a SQLite prompts-db outside the project, with nothing portable to read",
    });
}

const testing = std.testing;

fn writeProjectFile(io: std.Io, project_root: []const u8, rel_path: []const u8, contents: []const u8) !void {
    const full = try std.fs.path.join(testing.allocator, &.{ project_root, rel_path });
    defer testing.allocator.free(full);
    if (std.fs.path.dirname(full)) |parent| try std.Io.Dir.cwd().createDirPath(io, parent);
    var file = try std.Io.Dir.cwd().createFile(io, full, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
}

fn tmpProjectRoot(arena: std.mem.Allocator, tmp: *testing.TmpDir) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    return arena.dupe(u8, buffer[0..len]);
}

test "the first matching instruction candidate wins, and a later candidate is never read" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, ".rules", "the earlier candidate\n");
    try writeProjectFile(testing.io, project_root, "AGENTS.md", "the later candidate\n");
    try writeProjectFile(testing.io, project_root, "CLAUDE.md", "the latest candidate\n");

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 1), found.instructions.len);
    try testing.expectEqualStrings(".rules", found.instructions[0].path);
    try testing.expectEqualStrings(harness_name, found.instructions[0].harness);

    // Only the winner was opened: a later candidate on disk never reaches
    // `sources`, because `readInstructions` returns as soon as one is read.
    try testing.expectEqual(@as(usize, 1), found.sources.len);
    try testing.expectEqualStrings(".rules", found.sources[0].path);
}

test "agent.tool_permissions is refused rather than given an invented action" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, ".zed/settings.json",
        \\{"agent": {"tool_permissions": {
        \\  "default": "allow",
        \\  "tools": {"terminal": {"default": "confirm"}}
        \\}}}
    );

    const found = try read(arena, testing.io, project_root);

    // The rule that matters most: no Hint is ever built for a regex stance,
    // so nothing here can carry a fabricated action name.
    try testing.expectEqual(@as(usize, 0), found.policy_hints.len);

    var saw_default = false;
    var saw_tool = false;
    for (found.refused) |one| {
        if (std.mem.indexOf(u8, one.what, "tool_permissions.default") != null) saw_default = true;
        if (std.mem.indexOf(u8, one.what, "tools.\"terminal\"") != null) saw_tool = true;
    }
    try testing.expect(saw_default);
    try testing.expect(saw_tool);
}

test "a context server is matched by field shape: command kept, url refused, neither refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, ".zed/settings.json",
        \\{"context_servers": {
        \\  "github": {"command": "npx", "args": ["mcp-github"], "env": {"GITHUB_TOKEN": "ghp_secret"}},
        \\  "remote": {"url": "https://example.com/mcp"},
        \\  "broken": {}
        \\}}
    );

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 1), found.mcp_servers.len);
    try testing.expectEqualStrings("github", found.mcp_servers[0].name);
    try testing.expectEqualStrings("npx", found.mcp_servers[0].command);
    try testing.expectEqual(@as(usize, 1), found.mcp_servers[0].env.len);
    try testing.expectEqualStrings("GITHUB_TOKEN", found.mcp_servers[0].env[0]);

    const text = try migrate.render(arena, found, "0.1.0-test", "2026-09-24");
    try testing.expect(std.mem.indexOf(u8, text, "GITHUB_TOKEN") != null);
    try testing.expect(std.mem.indexOf(u8, text, "ghp_secret") == null);

    var saw_remote = false;
    var saw_broken = false;
    for (found.refused) |one| {
        if (std.mem.indexOf(u8, one.what, "\"remote\"") != null) saw_remote = true;
        if (std.mem.indexOf(u8, one.what, "\"broken\"") != null) saw_broken = true;
    }
    try testing.expect(saw_remote);
    try testing.expect(saw_broken);
}

test "a malformed settings.json is refused without losing the instruction file" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, "AGENTS.md", "# project instructions\n");
    try writeProjectFile(testing.io, project_root, ".zed/settings.json", "{ this is not json");

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 1), found.instructions.len);
    try testing.expectEqualStrings("AGENTS.md", found.instructions[0].path);

    var saw_refusal = false;
    for (found.refused) |one| {
        if (std.mem.eql(u8, one.what, ".zed/settings.json")) saw_refusal = true;
    }
    try testing.expect(saw_refusal);
}

test "an empty project still refuses slash commands, and carries nothing else" {
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

    try testing.expectEqual(@as(usize, 1), found.refused.len);
    try testing.expectEqualStrings("slash commands", found.refused[0].what);
}

test "skills under .agents/skills are refused only when the directory has an entry" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, ".agents/skills/reader/SKILL.md", "# reader\n");

    const found = try read(arena, testing.io, project_root);

    var saw_skills = false;
    for (found.refused) |one| {
        if (std.mem.eql(u8, one.what, ".agents/skills")) saw_skills = true;
    }
    try testing.expect(saw_skills);
}
