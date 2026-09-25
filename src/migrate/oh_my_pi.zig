//! Reads oh-my-pi's own project configuration, rooted at `.omp`, and
//! returns a neutral `Found`.
//!
//! Pinned against `can1357/oh-my-pi` at commit
//! `4a7b586821a4df0afcea657717247f6ec9db8f88`, read 2026-09-24.
//!
//! - **Instructions**: `.omp/AGENTS.md`, `.omp/RULES.md` (always applied),
//!   every `.omp/rules/*.md` and `*.mdc` file, and every
//!   `.omp/instructions/*.md` file. `~/.omp/` is user scope, and is never
//!   read here.
//! - **MCP**: the Claude shape, key `mcpServers`, in `.omp/mcp.json` or
//!   `.omp/.mcp.json`.
//! - **Permissions**: `.omp/config.yml`, under `tools`. `approvalMode` and
//!   the `approval` map are both session or tool wide stances spelled in
//!   oh-my-pi's own tool names, so both are always a `Refusal`, never a
//!   translated `Hint`. `approvalMode`'s schema default is `"yolo"`, which
//!   auto approves everything, so an absent key is refused the same as an
//!   explicit one.
//! - `.omp/agents/*.md`, `.omp/commands/*.md`, `.omp/skills/`, and the
//!   hook scripts under `.omp/hooks/pre/` and `.omp/hooks/post/` are all
//!   refused: each runs host side code this build has no way to run safely.
//!
//! See `../migrate.zig`'s own top comment for the shared translation: a
//! deny narrows and carries, an allow narrows to ask, and a secret's value
//! is never carried, only its name.
//!
//! ## The YAML scanner
//!
//! This build carries no YAML parser and adds none for one project file.
//! `scanConfigYaml` reads two keys only, `tools.approvalMode` and
//! `tools.approval`, with a narrow, indentation based line scanner. What it
//! reads: block style mappings, one `key: value` pair per line, spaces for
//! indentation, an optionally quoted scalar, and a whole line comment whose
//! first non-space character is `#`. What it does not read, and never
//! guesses at: flow style (`{ ... }` or `[ ... ]`), multi-line scalars,
//! anchors and aliases, tabs, or a trailing `# comment` after a value on
//! the same line, which is read as part of the value. A shape it does not
//! read is silently not found, the same as an absent key.

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

const harness_name = "oh-my-pi";

const max_instructions_bytes: usize = 1 << 20;
const max_config_bytes: usize = 64 * 1024;
const max_mcp_bytes: usize = 64 * 1024;

// A runaway directory cannot exhaust the arena: past this many entries, the
// rest are left unscanned.
const max_dir_entries: usize = 256;

pub fn read(arena: std.mem.Allocator, io: std.Io, project_root: []const u8) anyerror!Found {
    var sources: std.ArrayList(ReadSource) = .empty;
    var instructions: std.ArrayList(Source) = .empty;
    var mcp_servers: std.ArrayList(McpServer) = .empty;
    // Every oh-my-pi permission fact is a stance over its own tool names,
    // not an action this build defines, so it is always a Refusal: this
    // list stays empty.
    var policy_hints: std.ArrayList(Hint) = .empty;
    var refused: std.ArrayList(Refusal) = .empty;

    try readInstructionFile(arena, io, project_root, ".omp/AGENTS.md", &sources, &instructions);
    try readInstructionFile(arena, io, project_root, ".omp/RULES.md", &sources, &instructions);
    try readGlobInstructions(arena, io, project_root, "rules", &.{ ".md", ".mdc" }, &sources, &instructions);
    try readGlobInstructions(arena, io, project_root, "instructions", &.{".md"}, &sources, &instructions);

    try readMcp(arena, io, project_root, &sources, &mcp_servers, &refused);
    try readConfigYaml(arena, io, project_root, &sources, &refused);
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
/// missing or otherwise unreadable file: absence is not an error.
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

fn readInstructionFile(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    rel: []const u8,
    sources: *std.ArrayList(ReadSource),
    instructions: *std.ArrayList(Source),
) !void {
    const bytes = try readBounded(arena, io, project_root, rel, max_instructions_bytes) orelse return;
    try sources.append(arena, .{ .path = rel, .hash = hashBytes(bytes) });
    try instructions.append(arena, .{ .path = rel, .harness = harness_name });
}

fn lessThanName(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// The file names directly inside `project_root`/.omp/`sub_dir` whose name
/// ends with one of `extensions`, sorted so two runs on the same directory
/// name the same files in the same order.
fn listMatchingFiles(
    arena: std.mem.Allocator,
    io: std.Io,
    dir_path: []const u8,
    extensions: []const []const u8,
) ![]const []const u8 {
    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true }) catch return &.{};
    defer dir.close(io);

    var names: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    var seen: usize = 0;
    while (seen < max_dir_entries) : (seen += 1) {
        const entry = (it.next(io) catch null) orelse break;
        if (entry.kind != .file) continue;
        var matched = false;
        for (extensions) |ext| {
            if (std.mem.endsWith(u8, entry.name, ext)) {
                matched = true;
                break;
            }
        }
        if (!matched) continue;
        try names.append(arena, try arena.dupe(u8, entry.name));
    }

    std.mem.sort([]const u8, names.items, {}, lessThanName);
    return names.toOwnedSlice(arena);
}

fn readGlobInstructions(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    sub_dir: []const u8,
    extensions: []const []const u8,
    sources: *std.ArrayList(ReadSource),
    instructions: *std.ArrayList(Source),
) !void {
    const dir_path = try std.fs.path.join(arena, &.{ project_root, ".omp", sub_dir });
    const names = try listMatchingFiles(arena, io, dir_path, extensions);
    for (names) |name| {
        const rel = try std.fs.path.join(arena, &.{ ".omp", sub_dir, name });
        try readInstructionFile(arena, io, project_root, rel, sources, instructions);
    }
}

const McpServerJson = struct {
    command: ?[]const u8 = null,
    args: []const []const u8 = &.{},
    env: std.json.ArrayHashMap([]const u8) = .{},
    url: ?[]const u8 = null,
    enabled: bool = true,
};

const McpJson = struct {
    mcpServers: std.json.ArrayHashMap(McpServerJson) = .{},
};

/// Tries `.omp/mcp.json`, and only when that is absent tries
/// `.omp/.mcp.json`: the two candidate names for one file, not two files to
/// merge.
fn readMcp(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    sources: *std.ArrayList(ReadSource),
    mcp_servers: *std.ArrayList(McpServer),
    refused: *std.ArrayList(Refusal),
) !void {
    const candidates = [_][]const u8{ ".omp/mcp.json", ".omp/.mcp.json" };
    for (candidates) |rel| {
        const bytes = try readBounded(arena, io, project_root, rel, max_mcp_bytes) orelse continue;
        try sources.append(arena, .{ .path = rel, .hash = hashBytes(bytes) });
        try scanMcpJson(arena, bytes, rel, mcp_servers, refused);
        return;
    }
}

fn scanMcpJson(
    arena: std.mem.Allocator,
    bytes: []const u8,
    rel: []const u8,
    mcp_servers: *std.ArrayList(McpServer),
    refused: *std.ArrayList(Refusal),
) !void {
    const parsed = std.json.parseFromSliceLeaky(McpJson, arena, bytes, .{
        .ignore_unknown_fields = true,
    }) catch {
        try refused.append(arena, .{ .what = rel, .reason = "not valid JSON, so no server in it was carried" });
        return;
    };

    var it = parsed.mcpServers.map.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const server = entry.value_ptr.*;
        // A disabled server never runs, so there is nothing here to carry.
        if (!server.enabled) continue;

        if (server.command) |command| {
            var names: std.ArrayList([]const u8) = .empty;
            var env_it = server.env.map.iterator();
            while (env_it.next()) |pair| try names.append(arena, envName(pair.key_ptr.*));

            try mcp_servers.append(arena, .{
                .name = name,
                .command = command,
                .args = server.args,
                .env = try names.toOwnedSlice(arena),
                .source_file = rel,
            });
            continue;
        }

        if (server.url != null) {
            try refused.append(arena, .{
                .what = try std.fmt.allocPrint(arena, "mcp server \"{s}\"", .{name}),
                .reason = "an http entry has no local command; only a stdio entry with a command is carried",
            });
            continue;
        }

        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "mcp server \"{s}\"", .{name}),
            .reason = "neither a command nor a url, so its shape matches neither entry form",
        });
    }
}

const ToolStance = struct { name: []const u8, value: []const u8 };

const ConfigScan = struct {
    approval_mode: ?[]const u8 = null,
    tools: []const ToolStance = &.{},
};

fn indentOf(line: []const u8) usize {
    var n: usize = 0;
    while (n < line.len and line[n] == ' ') n += 1;
    return n;
}

fn unquote(raw: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len >= 2) {
        const quote = trimmed[0];
        if ((quote == '"' or quote == '\'') and trimmed[trimmed.len - 1] == quote) {
            return trimmed[1 .. trimmed.len - 1];
        }
    }
    return trimmed;
}

fn scalarAfter(trimmed: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, trimmed, prefix)) return null;
    return unquote(trimmed[prefix.len..]);
}

fn splitPair(trimmed: []const u8) ?ToolStance {
    const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse return null;
    const name = unquote(trimmed[0..colon]);
    if (name.len == 0) return null;
    return .{ .name = name, .value = unquote(trimmed[colon + 1 ..]) };
}

/// Reads `tools.approvalMode` and `tools.approval` out of a `config.yml`
/// document, with the narrow shapes named in this file's own top comment.
fn scanConfigYaml(arena: std.mem.Allocator, bytes: []const u8) !ConfigScan {
    var result = ConfigScan{};
    var tools: std.ArrayList(ToolStance) = .empty;

    var tools_indent: ?usize = null;
    var child_indent: ?usize = null;
    var in_approval = false;
    var approval_indent: ?usize = null;

    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw_line| {
        const raw = std.mem.trimEnd(u8, raw_line, "\r");
        const trimmed = std.mem.trim(u8, raw, " \t");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        const indent = indentOf(raw);

        if (tools_indent == null) {
            if (indent == 0 and std.mem.eql(u8, trimmed, "tools:")) tools_indent = indent;
            continue;
        }
        if (indent <= tools_indent.?) break;

        if (child_indent == null) child_indent = indent;

        if (indent == child_indent.?) {
            in_approval = false;
            if (scalarAfter(trimmed, "approvalMode:")) |value| {
                result.approval_mode = try arena.dupe(u8, value);
            } else if (std.mem.eql(u8, trimmed, "approval:")) {
                in_approval = true;
                approval_indent = null;
            }
            continue;
        }

        if (!in_approval) continue;
        if (approval_indent == null) approval_indent = indent;
        if (indent != approval_indent.?) continue;

        const pair = splitPair(trimmed) orelse continue;
        try tools.append(arena, .{ .name = try arena.dupe(u8, pair.name), .value = try arena.dupe(u8, pair.value) });
    }

    result.tools = try tools.toOwnedSlice(arena);
    return result;
}

/// `yolo` is `approvalMode`'s schema default, so an absent key is refused
/// the same as an explicit `yolo`: see this file's own top comment.
fn readConfigYaml(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    sources: *std.ArrayList(ReadSource),
    refused: *std.ArrayList(Refusal),
) !void {
    const rel = ".omp/config.yml";
    const bytes = try readBounded(arena, io, project_root, rel, max_config_bytes);

    var approval_mode: []const u8 = "yolo";
    var explicit = false;
    var tools: []const ToolStance = &.{};

    if (bytes) |b| {
        try sources.append(arena, .{ .path = rel, .hash = hashBytes(b) });
        const scan = try scanConfigYaml(arena, b);
        if (scan.approval_mode) |mode| {
            approval_mode = mode;
            explicit = true;
        }
        tools = scan.tools;
    }

    const what = if (explicit)
        try std.fmt.allocPrint(arena, "tools.approvalMode = \"{s}\" in {s}", .{ approval_mode, rel })
    else
        try std.fmt.allocPrint(arena, "tools.approvalMode, not set, so its schema default \"yolo\" applies in {s}", .{rel});

    const reason = if (std.mem.eql(u8, approval_mode, "yolo"))
        "yolo approves every tool call with no off switch, and no action here stands for a whole session's stance"
    else
        "a session wide stance covering every tool; no single action here stands for it";

    try refused.append(arena, .{ .what = what, .reason = reason });

    for (tools) |stance| {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "tools.approval.\"{s}\" = \"{s}\" in {s}", .{ stance.name, stance.value, rel }),
            .reason = "spelled in oh-my-pi's own tool names, and no action here means the same call",
        });
    }
}

const uncarried_dirs = [_]struct { path: []const u8, reason: []const u8 }{
    .{
        .path = ".omp/agents",
        .reason = "an agent definition runs as its own agent, and this build has no mechanism that runs one",
    },
    .{
        .path = ".omp/commands",
        .reason = "a command expands host side, and this build has no mechanism that runs one",
    },
    .{
        .path = ".omp/skills",
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
        if (!try dirHasEntry(arena, io, project_root, one.path)) continue;
        try refused.append(arena, .{ .what = one.path, .reason = one.reason });
    }

    const has_hooks = (try dirHasEntry(arena, io, project_root, ".omp/hooks/pre")) or
        (try dirHasEntry(arena, io, project_root, ".omp/hooks/post"));
    if (has_hooks) {
        try refused.append(arena, .{
            .what = ".omp/hooks",
            .reason = "a hook is an executable script run on a session event, and this build has no mechanism that runs one safely",
        });
    }
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

test "an absent approvalMode is refused as its yolo default, and an explicit approval map is refused by name" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    const found = try read(arena, testing.io, project_root);

    // The rule that matters most: no Hint is ever built for a tool stance,
    // so nothing here can carry a fabricated action name.
    try testing.expectEqual(@as(usize, 0), found.policy_hints.len);

    var saw_default_yolo = false;
    for (found.refused) |one| {
        if (std.mem.indexOf(u8, one.what, "approvalMode") != null and std.mem.indexOf(u8, one.reason, "no off switch") != null) {
            saw_default_yolo = true;
        }
    }
    try testing.expect(saw_default_yolo);
}

test "an explicit approval map entry is refused rather than given an invented action" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, ".omp/config.yml",
        \\tools:
        \\  approvalMode: write
        \\  approval:
        \\    shell: allow
        \\    read_file: deny
        \\other:
        \\  ignored: true
    );

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 0), found.policy_hints.len);

    var saw_mode = false;
    var saw_shell = false;
    var saw_read_file = false;
    for (found.refused) |one| {
        if (std.mem.indexOf(u8, one.what, "approvalMode = \"write\"") != null) saw_mode = true;
        if (std.mem.indexOf(u8, one.what, "approval.\"shell\" = \"allow\"") != null) saw_shell = true;
        if (std.mem.indexOf(u8, one.what, "approval.\"read_file\" = \"deny\"") != null) saw_read_file = true;
    }
    try testing.expect(saw_mode);
    try testing.expect(saw_shell);
    try testing.expect(saw_read_file);
}

test "an env value never appears anywhere in the returned Found while its name does" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, ".omp/mcp.json",
        \\{"mcpServers": {"openai": {"command": "npx", "args": ["mcp-server-openai"], "env": {"OPENAI_API_KEY": "sk-live-do-not-leak"}}}}
    );

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 1), found.mcp_servers.len);
    const server = found.mcp_servers[0];
    try testing.expectEqualStrings("openai", server.name);
    try testing.expectEqual(@as(usize, 1), server.env.len);
    try testing.expectEqualStrings("OPENAI_API_KEY", server.env[0]);

    const text = try migrate.render(arena, found, "0.1.0-test", "2026-09-24", &.{});
    try testing.expect(std.mem.indexOf(u8, text, "OPENAI_API_KEY") != null);
    try testing.expect(std.mem.indexOf(u8, text, "sk-live-do-not-leak") == null);
}

test "a malformed mcp.json is refused without losing AGENTS.md" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, ".omp/AGENTS.md", "# project instructions\n");
    try writeProjectFile(testing.io, project_root, ".omp/mcp.json", "{ this is not json");

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 1), found.instructions.len);
    try testing.expectEqualStrings(".omp/AGENTS.md", found.instructions[0].path);

    var saw_refusal = false;
    for (found.refused) |one| {
        if (std.mem.eql(u8, one.what, ".omp/mcp.json")) saw_refusal = true;
    }
    try testing.expect(saw_refusal);
}

test "an mcp server is matched by field shape, and a disabled one carries nothing" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, ".omp/mcp.json",
        \\{"mcpServers": {
        \\  "stdio": {"command": "npx", "enabled": true},
        \\  "remote": {"url": "https://example.com/mcp"},
        \\  "off": {"command": "npx", "enabled": false}
        \\}}
    );

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 1), found.mcp_servers.len);
    try testing.expectEqualStrings("stdio", found.mcp_servers[0].name);

    var saw_remote = false;
    for (found.refused) |one| {
        if (std.mem.indexOf(u8, one.what, "\"remote\"") != null) saw_remote = true;
        try testing.expect(std.mem.indexOf(u8, one.what, "\"off\"") == null);
    }
    try testing.expect(saw_remote);
}

test "rule and instruction files are read from .omp/rules and .omp/instructions, sorted" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, ".omp/rules/b-second.md", "# b\n");
    try writeProjectFile(testing.io, project_root, ".omp/rules/a-first.mdc", "# a\n");
    try writeProjectFile(testing.io, project_root, ".omp/rules/ignored.txt", "not a rule\n");
    try writeProjectFile(testing.io, project_root, ".omp/instructions/only.md", "---\napplyTo: \"**/*.zig\"\n---\nbody\n");

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 3), found.instructions.len);
    try testing.expectEqualStrings(".omp/rules/a-first.mdc", found.instructions[0].path);
    try testing.expectEqualStrings(".omp/rules/b-second.md", found.instructions[1].path);
    try testing.expectEqualStrings(".omp/instructions/only.md", found.instructions[2].path);
}

test "agents, commands, skills and hooks are each refused only when present" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, ".omp/agents/reviewer.md", "# reviewer\n");
    try writeProjectFile(testing.io, project_root, ".omp/commands/deploy.md", "# deploy\n");
    try writeProjectFile(testing.io, project_root, ".omp/skills/reader/SKILL.md", "# reader\n");
    try writeProjectFile(testing.io, project_root, ".omp/hooks/pre/check.sh", "#!/bin/sh\n");

    const found = try read(arena, testing.io, project_root);

    var saw_agents = false;
    var saw_commands = false;
    var saw_skills = false;
    var saw_hooks = false;
    for (found.refused) |one| {
        if (std.mem.eql(u8, one.what, ".omp/agents")) saw_agents = true;
        if (std.mem.eql(u8, one.what, ".omp/commands")) saw_commands = true;
        if (std.mem.eql(u8, one.what, ".omp/skills")) saw_skills = true;
        if (std.mem.eql(u8, one.what, ".omp/hooks")) saw_hooks = true;
    }
    try testing.expect(saw_agents);
    try testing.expect(saw_commands);
    try testing.expect(saw_skills);
    try testing.expect(saw_hooks);
}

test "the yaml scanner reads only block style scalars and stops the tools block at a lower indent" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const scan = try scanConfigYaml(arena,
        \\tools:
        \\  approvalMode: "always-ask"
        \\  approval:
        \\    bash: 'prompt'
        \\    # a whole line comment inside the map is skipped
        \\    git: deny
        \\other_top_level_key: true
    );

    try testing.expectEqualStrings("always-ask", scan.approval_mode.?);
    try testing.expectEqual(@as(usize, 2), scan.tools.len);
    try testing.expectEqualStrings("bash", scan.tools[0].name);
    try testing.expectEqualStrings("prompt", scan.tools[0].value);
    try testing.expectEqualStrings("git", scan.tools[1].name);
    try testing.expectEqualStrings("deny", scan.tools[1].value);
}
