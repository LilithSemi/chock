//! Reads project-scoped configuration for Codex (`openai/codex`) and returns
//! a neutral `Found`. Pinned against commit `cf792c3a257b85259b731cc1c1a2f6a7c550360d`
//! (2026-09-24 on `main`; no release tag reaches that commit, the repo tags
//! per sub-crate instead).
//!
//! What this reads, and where each fact came from in that commit:
//!
//! - `AGENTS.md` and `AGENTS.override.md` at the project root:
//!   `codex-rs/core/src/agents_md.rs` lines 1-18, 41-44.
//! - `.codex/config.toml` at the project root, for `mcp_servers.<name>`
//!   (`codex-rs/config/src/mcp_types.rs` lines 233-315, 377-421) and the
//!   scalar `sandbox_mode` / `approval_policy` keys
//!   (`codex-rs/config/src/config_toml.rs` lines 191-221,
//!   `codex-rs/protocol/src/config_types.rs` lines 99-113,
//!   `codex-rs/protocol/src/protocol.rs` lines 986-1008). This is the
//!   project's own file: `~/.codex/config.toml` is a user's, never read here.
//! - `.codex/rules/` and `.agents/skills/`, refused rather than read:
//!   execpolicy rule files (`codex-rs/core/src/exec_policy.rs` lines 54,
//!   668-679) and skills (`codex-rs/ext/skills/src/host_roots.rs` lines
//!   24-25, 137-154) both run code Chock has no safe way to carry.
//! - `[hooks]` inside `config.toml`, refused: `codex-rs/config/src/hook_config.rs`
//!   lines 20-50 runs an arbitrary command on a session event.
//!
//! Codex's config format is TOML and this build carries no TOML parser.
//! Adding one, or writing a general one, is out of scope, so the scan below
//! is narrow: one key per line, double-quoted strings with no escapes,
//! single-line arrays and inline tables. A line outside that shape is left
//! unread, not guessed at, and a `[mcp_servers.<name>.env]` sub-table is one
//! such shape: only the inline `env = { ... }` form is read.

const std = @import("std");
const migrate = @import("../migrate.zig");

/// Files this scanner will read wholesale, bounded so a runaway file cannot
/// exhaust the arena.
const max_file_bytes: usize = 1 << 20;

pub fn read(arena: std.mem.Allocator, io: std.Io, project_root: []const u8) anyerror!migrate.Found {
    var sources: std.ArrayList(migrate.ReadSource) = .empty;
    var instructions: std.ArrayList(migrate.Source) = .empty;
    var mcp_servers: std.ArrayList(migrate.McpServer) = .empty;
    var policy_hints: std.ArrayList(migrate.Hint) = .empty;
    var refused: std.ArrayList(migrate.Refusal) = .empty;

    try readInstructionFile(arena, io, project_root, "AGENTS.md", &sources, &instructions, &refused);
    try readInstructionFile(arena, io, project_root, "AGENTS.override.md", &sources, &instructions, &refused);
    try readConfigToml(arena, io, project_root, &sources, &mcp_servers, &refused);

    try noteDirectoryIfPresent(
        arena,
        io,
        project_root,
        &.{ ".codex", "rules" },
        "execpolicy rules",
        "codex-rs/core/src/exec_policy.rs runs *.rules files as a command policy DSL; Chock has no execpolicy engine to translate them into",
        &refused,
    );
    try noteDirectoryIfPresent(
        arena,
        io,
        project_root,
        &.{ ".agents", "skills" },
        "skills",
        "a skill is a script Codex can run on its own; Chock has no mechanism that would run one safely",
        &refused,
    );

    return .{
        .sources = try sources.toOwnedSlice(arena),
        .instructions = try instructions.toOwnedSlice(arena),
        .mcp_servers = try mcp_servers.toOwnedSlice(arena),
        .policy_hints = try policy_hints.toOwnedSlice(arena),
        .refused = try refused.toOwnedSlice(arena),
    };
}

/// What one bounded read of a project file came back with.
const Read = union(enum) {
    absent,
    ok: []const u8,
    failed: []const u8,
};

fn readBounded(io: std.Io, path: []const u8, arena: std.mem.Allocator) Read {
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_file_bytes)) catch |err| switch (err) {
        error.FileNotFound => return .absent,
        else => return .{ .failed = @errorName(err) },
    };
    return .{ .ok = bytes };
}

fn readInstructionFile(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    name: []const u8,
    sources: *std.ArrayList(migrate.ReadSource),
    instructions: *std.ArrayList(migrate.Source),
    refused: *std.ArrayList(migrate.Refusal),
) !void {
    const path = try std.fs.path.join(arena, &.{ project_root, name });
    switch (readBounded(io, path, arena)) {
        .absent => {},
        .failed => |reason| try refused.append(arena, .{ .what = name, .reason = reason }),
        .ok => |bytes| {
            try sources.append(arena, .{ .path = name, .hash = migrate.hashBytes(bytes) });
            try instructions.append(arena, .{ .path = name, .harness = "codex" });
        },
    }
}

fn readConfigToml(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    sources: *std.ArrayList(migrate.ReadSource),
    mcp_servers: *std.ArrayList(migrate.McpServer),
    refused: *std.ArrayList(migrate.Refusal),
) !void {
    const relative = ".codex/config.toml";
    const path = try std.fs.path.join(arena, &.{ project_root, ".codex", "config.toml" });
    switch (readBounded(io, path, arena)) {
        .absent => {},
        .failed => |reason| try refused.append(arena, .{ .what = relative, .reason = reason }),
        .ok => |bytes| {
            try sources.append(arena, .{ .path = relative, .hash = migrate.hashBytes(bytes) });
            try scanConfigToml(arena, bytes, relative, mcp_servers, refused);
        },
    }
}

/// A pending `[mcp_servers.<name>]` table, flushed when the next table header
/// is seen or the file ends.
const PendingServer = struct {
    name: []const u8 = "",
    command: ?[]const u8 = null,
    url: ?[]const u8 = null,
    args: []const []const u8 = &.{},
    env: []const []const u8 = &.{},
};

fn flushPendingServer(
    arena: std.mem.Allocator,
    relative: []const u8,
    pending: *PendingServer,
    mcp_servers: *std.ArrayList(migrate.McpServer),
    refused: *std.ArrayList(migrate.Refusal),
) !void {
    if (pending.name.len == 0) return;
    defer pending.* = .{};

    if (pending.command) |command| {
        try mcp_servers.append(arena, .{
            .name = pending.name,
            .command = command,
            .args = pending.args,
            .env = pending.env,
            .source_file = relative,
        });
    } else if (pending.url != null) {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "mcp server \"{s}\"", .{pending.name}),
            .reason = "a streamable_http server has no local command; only a stdio server with a command is carried",
        });
    }
}

fn scanConfigToml(
    arena: std.mem.Allocator,
    bytes: []const u8,
    relative: []const u8,
    mcp_servers: *std.ArrayList(migrate.McpServer),
    refused: *std.ArrayList(migrate.Refusal),
) !void {
    var pending: PendingServer = .{};
    var section: enum { top, mcp_server, other } = .top;
    var hooks_noted = false;
    var approval_table_noted = false;

    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        if (line[0] == '[') {
            try flushPendingServer(arena, relative, &pending, mcp_servers, refused);
            const header = parseTableHeader(line) orelse {
                section = .other;
                continue;
            };
            if (std.mem.startsWith(u8, header, "mcp_servers.")) {
                pending.name = try arena.dupe(u8, unquoteKey(header["mcp_servers.".len..]));
                section = .mcp_server;
            } else if (std.mem.eql(u8, header, "hooks") or std.mem.startsWith(u8, header, "hooks.")) {
                section = .other;
                if (!hooks_noted) {
                    hooks_noted = true;
                    try refused.append(arena, .{
                        .what = "[hooks]",
                        .reason = "a hook runs an arbitrary command on a session event; Chock has nothing that runs one safely",
                    });
                }
            } else if (std.mem.eql(u8, header, "approval_policy") or std.mem.startsWith(u8, header, "approval_policy.")) {
                section = .other;
                if (!approval_table_noted) {
                    approval_table_noted = true;
                    try refused.append(arena, .{
                        .what = "[approval_policy]",
                        .reason = "the granular table form sets five independent switches; only the plain string form is translated",
                    });
                }
            } else {
                section = .other;
            }
            continue;
        }

        const pair = splitKeyValue(line) orelse continue;
        switch (section) {
            .top => try readTopLevelKey(arena, pair, refused),
            .mcp_server => try readServerKey(arena, pair, &pending),
            .other => {},
        }
    }
    try flushPendingServer(arena, relative, &pending, mcp_servers, refused);
}

/// `sandbox_mode` and `approval_policy` are one stance for a whole session.
/// No action here carries either, so both are refused and named.
///
/// **A row for an action this build does not define would read as a carried
/// stance and match nothing.** That is worse than refusing, because the file
/// looks faithful. See this file's own top comment.
fn readTopLevelKey(
    arena: std.mem.Allocator,
    pair: KeyValue,
    refused: *std.ArrayList(migrate.Refusal),
) !void {
    const value = parseQuotedString(pair.value) orelse return;

    if (std.mem.eql(u8, pair.key, "sandbox_mode")) {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "sandbox_mode = \"{s}\"", .{value}),
            .reason = if (std.mem.eql(u8, value, "danger-full-access"))
                "it turns the sandbox off, and this build carries no off switch"
            else
                "it sets one stance for a whole session, and no action here stands for that. " ++
                    "The workspace is a git worktree and the policy table decides each act instead",
        });
        return;
    }

    if (std.mem.eql(u8, pair.key, "approval_policy")) {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "approval_policy = \"{s}\"", .{value}),
            .reason = if (std.mem.eql(u8, value, "never"))
                "it runs every command without asking, and this build carries no off switch"
            else
                "an act nobody names already answers ask here, so there is nothing to carry",
        });
    }
}

fn readServerKey(arena: std.mem.Allocator, pair: KeyValue, pending: *PendingServer) !void {
    if (std.mem.eql(u8, pair.key, "command")) {
        pending.command = parseQuotedString(pair.value);
    } else if (std.mem.eql(u8, pair.key, "url")) {
        pending.url = parseQuotedString(pair.value);
    } else if (std.mem.eql(u8, pair.key, "args")) {
        pending.args = try parseStringArray(arena, pair.value) orelse pending.args;
    } else if (std.mem.eql(u8, pair.key, "env")) {
        pending.env = try parseEnvNames(arena, pair.value) orelse pending.env;
    }
}

fn noteDirectoryIfPresent(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    parts: []const []const u8,
    what: []const u8,
    reason: []const u8,
    refused: *std.ArrayList(migrate.Refusal),
) !void {
    var joined: std.ArrayList([]const u8) = .empty;
    try joined.append(arena, project_root);
    try joined.appendSlice(arena, parts);
    const path = try std.fs.path.join(arena, joined.items);

    var dir = std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true }) catch return;
    defer dir.close(io);
    var it = dir.iterate();
    const has_entry = (it.next(io) catch null) != null;
    if (has_entry) try refused.append(arena, .{ .what = what, .reason = reason });
}

const KeyValue = struct { key: []const u8, value: []const u8 };

fn splitKeyValue(line: []const u8) ?KeyValue {
    const eq = std.mem.indexOfScalar(u8, line, '=') orelse return null;
    return .{
        .key = std.mem.trim(u8, line[0..eq], " \t"),
        .value = std.mem.trim(u8, line[eq + 1 ..], " \t"),
    };
}

fn parseTableHeader(line: []const u8) ?[]const u8 {
    if (line.len < 2 or line[line.len - 1] != ']') return null;
    return std.mem.trim(u8, line[1 .. line.len - 1], " \t");
}

fn unquoteKey(raw: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len >= 2 and trimmed[0] == '"' and trimmed[trimmed.len - 1] == '"') {
        return trimmed[1 .. trimmed.len - 1];
    }
    return trimmed;
}

/// A double-quoted TOML string with no escape processing. A line whose value
/// uses `\"` or a literal `'...'` string does not match, and is left unread.
fn parseQuotedString(value: []const u8) ?[]const u8 {
    if (value.len < 2 or value[0] != '"' or value[value.len - 1] != '"') return null;
    return value[1 .. value.len - 1];
}

fn parseStringArray(arena: std.mem.Allocator, value: []const u8) !?[]const []const u8 {
    if (value.len < 2 or value[0] != '[' or value[value.len - 1] != ']') return null;
    const inner = std.mem.trim(u8, value[1 .. value.len - 1], " \t");
    if (inner.len == 0) return &.{};

    var items: std.ArrayList([]const u8) = .empty;
    var parts = std.mem.splitScalar(u8, inner, ',');
    while (parts.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        if (trimmed.len == 0) continue;
        const one = parseQuotedString(trimmed) orelse return null;
        try items.append(arena, try arena.dupe(u8, one));
    }
    return try items.toOwnedSlice(arena);
}

/// Reads an inline `env = { NAME = "value", ... }` table and keeps only the
/// names: `migrate.envName` is called on each entry's own source text, so the
/// value half never reaches the returned slice.
fn parseEnvNames(arena: std.mem.Allocator, value: []const u8) !?[]const []const u8 {
    if (value.len < 2 or value[0] != '{' or value[value.len - 1] != '}') return null;
    const inner = std.mem.trim(u8, value[1 .. value.len - 1], " \t");
    if (inner.len == 0) return &.{};

    var names: std.ArrayList([]const u8) = .empty;
    var parts = std.mem.splitScalar(u8, inner, ',');
    while (parts.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        if (trimmed.len == 0) continue;
        const name = unquoteKey(migrate.envName(trimmed));
        if (name.len == 0) continue;
        try names.append(arena, try arena.dupe(u8, name));
    }
    return try names.toOwnedSlice(arena);
}

const testing = std.testing;

fn writeProjectFile(project_root: []const u8, relative: []const u8, contents: []const u8) !void {
    const path = try std.fs.path.join(testing.allocator, &.{ project_root, relative });
    defer testing.allocator.free(path);
    if (std.fs.path.dirname(path)) |parent| try std.Io.Dir.cwd().createDirPath(testing.io, parent);
    var file = try std.Io.Dir.createFileAbsolute(testing.io, path, .{});
    defer file.close(testing.io);
    try file.writeStreamingAll(testing.io, contents);
}

test "an empty project comes back with nothing carried and nothing refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);

    const found = try read(arena_state.allocator(), testing.io, buffer[0..len]);
    try testing.expectEqual(@as(usize, 0), found.sources.len);
    try testing.expectEqual(@as(usize, 0), found.instructions.len);
    try testing.expectEqual(@as(usize, 0), found.mcp_servers.len);
    try testing.expectEqual(@as(usize, 0), found.policy_hints.len);
    try testing.expectEqual(@as(usize, 0), found.refused.len);
}

test "AGENTS.md and its local override both become instructions from codex" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const project_root = buffer[0..len];

    try writeProjectFile(project_root, "AGENTS.md", "Build with zig build.\n");
    try writeProjectFile(project_root, "AGENTS.override.md", "Use the local toolchain.\n");

    const found = try read(arena_state.allocator(), testing.io, project_root);
    try testing.expectEqual(@as(usize, 2), found.instructions.len);
    try testing.expectEqualStrings("AGENTS.md", found.instructions[0].path);
    try testing.expectEqualStrings("codex", found.instructions[0].harness);
    try testing.expectEqualStrings("AGENTS.override.md", found.instructions[1].path);

    try testing.expectEqual(@as(usize, 2), found.sources.len);
    try testing.expectEqualStrings(
        &migrate.hashBytes("Build with zig build.\n"),
        &found.sources[0].hash,
    );
}

test "an mcp server's command and args are read, and an env value never appears" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const project_root = buffer[0..len];

    try writeProjectFile(project_root, ".codex/config.toml",
        \\[mcp_servers.docs]
        \\command = "npx"
        \\args = ["-y", "mcp-server-docs"]
        \\env = { OPENAI_API_KEY = "sk-live-do-not-leak", "OTHER_KEY" = "also-secret" }
        \\
    );

    const found = try read(arena_state.allocator(), testing.io, project_root);
    try testing.expectEqual(@as(usize, 1), found.mcp_servers.len);
    const server = found.mcp_servers[0];
    try testing.expectEqualStrings("docs", server.name);
    try testing.expectEqualStrings("npx", server.command);
    try testing.expectEqual(@as(usize, 2), server.args.len);
    try testing.expectEqualStrings("mcp-server-docs", server.args[1]);
    try testing.expectEqualStrings(".codex/config.toml", server.source_file);

    try testing.expectEqual(@as(usize, 2), server.env.len);
    try testing.expectEqualStrings("OPENAI_API_KEY", server.env[0]);
    try testing.expectEqualStrings("OTHER_KEY", server.env[1]);

    for (found.sources) |source| {
        try testing.expect(std.mem.indexOf(u8, source.path, "sk-live-do-not-leak") == null);
    }
    try testing.expect(std.mem.indexOf(u8, server.command, "secret") == null);
}

test "a session wide stance is refused, because no action here stands for one" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const project_root = buffer[0..len];

    try writeProjectFile(project_root, ".codex/config.toml",
        \\sandbox_mode = "workspace-write"
        \\approval_policy = "untrusted"
        \\
    );
    const found = try read(arena_state.allocator(), testing.io, project_root);

    // A row naming an action this build does not define would read as a
    // carried stance and match nothing at all.
    try testing.expectEqual(@as(usize, 0), found.policy_hints.len);
    try testing.expectEqual(@as(usize, 2), found.refused.len);
    try testing.expect(std.mem.indexOf(u8, found.refused[0].what, "workspace-write") != null);
    try testing.expect(std.mem.indexOf(u8, found.refused[1].what, "untrusted") != null);
}

test "the two off switches are refused and named as off switches" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const project_root = buffer[0..len];

    try writeProjectFile(project_root, ".codex/config.toml",
        \\sandbox_mode = "danger-full-access"
        \\approval_policy = "never"
        \\
    );
    const found = try read(arena_state.allocator(), testing.io, project_root);

    try testing.expectEqual(@as(usize, 0), found.policy_hints.len);
    try testing.expectEqual(@as(usize, 2), found.refused.len);
    for (found.refused) |one| {
        try testing.expect(std.mem.indexOf(u8, one.reason, "off switch") != null);
    }
}

test "hooks, the granular approval table, execpolicy rules and skills are all refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const project_root = buffer[0..len];

    try writeProjectFile(project_root, ".codex/config.toml",
        \\[approval_policy]
        \\sandbox_approval = true
        \\
        \\[hooks]
        \\PreToolUse = []
        \\
    );
    try writeProjectFile(project_root, ".codex/rules/deny-rm.rules", "deny rm -rf /\n");
    try writeProjectFile(project_root, ".agents/skills/release/SKILL.md", "# release\n");

    const found = try read(arena_state.allocator(), testing.io, project_root);
    try testing.expectEqual(@as(usize, 4), found.refused.len);

    var saw_hooks = false;
    var saw_approval_table = false;
    var saw_rules = false;
    var saw_skills = false;
    for (found.refused) |one| {
        if (std.mem.eql(u8, one.what, "[hooks]")) saw_hooks = true;
        if (std.mem.eql(u8, one.what, "[approval_policy]")) saw_approval_table = true;
        if (std.mem.eql(u8, one.what, "execpolicy rules")) saw_rules = true;
        if (std.mem.eql(u8, one.what, "skills")) saw_skills = true;
    }
    try testing.expect(saw_hooks);
    try testing.expect(saw_approval_table);
    try testing.expect(saw_rules);
    try testing.expect(saw_skills);
}

test "a streamable_http server with no command is refused, not silently dropped" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const project_root = buffer[0..len];

    try writeProjectFile(project_root, ".codex/config.toml",
        \\[mcp_servers.remote]
        \\url = "https://example.invalid/mcp"
        \\
    );

    const found = try read(arena_state.allocator(), testing.io, project_root);
    try testing.expectEqual(@as(usize, 0), found.mcp_servers.len);
    try testing.expectEqual(@as(usize, 1), found.refused.len);
    try testing.expect(std.mem.indexOf(u8, found.refused[0].what, "remote") != null);
}

test "a malformed config.toml is refused and the rest of the read still works" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const project_root = buffer[0..len];

    // No permission bits are flipped here: this proves a directory standing
    // in for the file's own name is treated as an unreadable file, not a
    // crash, leaving AGENTS.md next to it still readable.
    try std.Io.Dir.cwd().createDirPath(testing.io, project_root);
    const bad_path = try std.fs.path.join(testing.allocator, &.{ project_root, ".codex" });
    defer testing.allocator.free(bad_path);
    try std.Io.Dir.cwd().createDirPath(testing.io, bad_path);
    const config_as_dir = try std.fs.path.join(testing.allocator, &.{ bad_path, "config.toml" });
    defer testing.allocator.free(config_as_dir);
    try std.Io.Dir.createDirAbsolute(testing.io, config_as_dir, .default_dir);

    try writeProjectFile(project_root, "AGENTS.md", "still readable\n");

    const found = try read(arena_state.allocator(), testing.io, project_root);
    try testing.expectEqual(@as(usize, 1), found.instructions.len);
    try testing.expectEqual(@as(usize, 1), found.refused.len);
    try testing.expectEqualStrings(".codex/config.toml", found.refused[0].what);
}
