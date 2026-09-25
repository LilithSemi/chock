//! Reads OpenCode's (`sst/opencode`) own project-scoped configuration.
//!
//! Pinned against `sst/opencode` at commit
//! `6df0d5d951e0bb8c82dd1a7f9315eff4efd7f1ef`, read 2026-09-24: the
//! instruction file walk (`AGENTS.md`, `CLAUDE.md`, `CONTEXT.md`, first
//! match wins), `opencode.json` or `opencode.jsonc` at the project root, and
//! that file's own `mcp`, `permission` and `plugin` keys. This reader is
//! project scoped: a user's own `~/.config/opencode/AGENTS.md` is never
//! read, because it is not the project's to migrate.
//!
//! See `../migrate.zig`'s own top comment for the translation every reader
//! in this build follows: a deny narrows and carries, an allow narrows to
//! ask, and a secret's value is never carried, only its name.
//!
//! Only two of OpenCode's permission keys have a Chock action behind them:
//! `webfetch` maps to `net.fetch.*` and `lsp` maps to `lsp.*`. Every other
//! key, known or not, is a stance on OpenCode's own tool set with no
//! equivalent here, so it is refused rather than given an invented action.
//! `skill` reaches this reader only through that same key: no project local
//! skill directory is pinned for this surface.

const std = @import("std");
const migrate = @import("../migrate.zig");

const Found = migrate.Found;
const Source = migrate.Source;
const ReadSource = migrate.ReadSource;
const McpServer = migrate.McpServer;
const Hint = migrate.Hint;
const Said = migrate.Said;
const Refusal = migrate.Refusal;
const hashBytes = migrate.hashBytes;
const envName = migrate.envName;

const harness_name = "opencode";

// CONTEXT.md and its kin are a document a person writes; opencode.json is
// configuration a tool writes, and configuration is small.
const max_instructions_bytes: usize = 1 << 20;
const max_config_bytes: usize = 64 * 1024;

const instruction_names = [_][]const u8{ "AGENTS.md", "CLAUDE.md", "CONTEXT.md" };
const config_names = [_][]const u8{ "opencode.json", "opencode.jsonc" };

pub fn read(arena: std.mem.Allocator, io: std.Io, project_root: []const u8) anyerror!Found {
    var sources: std.ArrayList(ReadSource) = .empty;
    var instructions: std.ArrayList(Source) = .empty;
    var mcp_servers: std.ArrayList(McpServer) = .empty;
    var policy_hints: std.ArrayList(Hint) = .empty;
    var refused: std.ArrayList(Refusal) = .empty;

    try readInstructions(arena, io, project_root, &sources, &instructions);
    try readConfig(arena, io, project_root, &sources, &mcp_servers, &policy_hints, &refused);
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

/// The first of `AGENTS.md`, `CLAUDE.md`, `CONTEXT.md` at the project root.
/// First match wins; the other two are never even opened, so nothing stacks.
fn readInstructions(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    sources: *std.ArrayList(ReadSource),
    instructions: *std.ArrayList(Source),
) !void {
    for (instruction_names) |rel| {
        const bytes = try readBounded(arena, io, project_root, rel, max_instructions_bytes) orelse continue;
        try sources.append(arena, .{ .path = rel, .hash = hashBytes(bytes) });
        try instructions.append(arena, .{ .path = rel, .harness = harness_name });
        return;
    }
}

/// Strip `//` line comments that fall outside a JSON string, so a JSONC file
/// can be handed to a plain JSON parser. A `//` found while a string is
/// open, as in `"https://example.com"`, is left alone.
fn stripLineComments(arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var in_string = false;
    var escaped = false;
    var i: usize = 0;
    while (i < bytes.len) {
        const c = bytes[i];
        if (in_string) {
            try out.append(arena, c);
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if (c == '"') {
            in_string = true;
            try out.append(arena, c);
            i += 1;
            continue;
        }
        if (c == '/' and i + 1 < bytes.len and bytes[i + 1] == '/') {
            while (i < bytes.len and bytes[i] != '\n') i += 1;
            continue;
        }
        try out.append(arena, c);
        i += 1;
    }
    return out.toOwnedSlice(arena);
}

/// `opencode.json`, or `opencode.jsonc` when there is no plain `.json`. The
/// first one found is the only one read.
fn readConfig(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    sources: *std.ArrayList(ReadSource),
    mcp_servers: *std.ArrayList(McpServer),
    policy_hints: *std.ArrayList(Hint),
    refused: *std.ArrayList(Refusal),
) !void {
    for (config_names) |rel| {
        const bytes = try readBounded(arena, io, project_root, rel, max_config_bytes) orelse continue;
        try sources.append(arena, .{ .path = rel, .hash = hashBytes(bytes) });

        const stripped = try stripLineComments(arena, bytes);
        const value = std.json.parseFromSliceLeaky(std.json.Value, arena, stripped, .{}) catch {
            try refused.append(arena, .{
                .what = rel,
                .reason = "not valid JSON, even with // comments stripped, so nothing in it was carried",
            });
            return;
        };
        const root = switch (value) {
            .object => |o| o,
            else => {
                try refused.append(arena, .{
                    .what = rel,
                    .reason = "not a JSON object at the top level, so nothing in it was carried",
                });
                return;
            },
        };

        if (root.get("mcp")) |mcp_value| try readMcp(arena, rel, mcp_value, mcp_servers, refused);
        if (root.get("permission")) |permission_value| try readPermission(arena, rel, permission_value, policy_hints, refused);
        if (root.get("plugin")) |plugin_value| try refusePlugins(arena, rel, plugin_value, refused);
        return;
    }
}

fn readMcp(
    arena: std.mem.Allocator,
    rel: []const u8,
    value: std.json.Value,
    mcp_servers: *std.ArrayList(McpServer),
    refused: *std.ArrayList(Refusal),
) !void {
    const servers = switch (value) {
        .object => |o| o,
        else => return,
    };

    var it = servers.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const server = switch (entry.value_ptr.*) {
            .object => |o| o,
            else => continue,
        };
        try readOneMcpServer(arena, rel, name, server, mcp_servers, refused);
    }
}

fn readOneMcpServer(
    arena: std.mem.Allocator,
    rel: []const u8,
    name: []const u8,
    server: std.json.ObjectMap,
    mcp_servers: *std.ArrayList(McpServer),
    refused: *std.ArrayList(Refusal),
) !void {
    const kind = switch (server.get("type") orelse std.json.Value{ .string = "" }) {
        .string => |s| s,
        else => "",
    };

    if (std.mem.eql(u8, kind, "remote")) {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "mcp.{s} (remote) in {s}", .{ name, rel }),
            .reason = "a remote MCP server is a URL endpoint, and this build's mcp_servers schema carries only a local command to run",
        });
        return;
    }
    if (!std.mem.eql(u8, kind, "local")) {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "mcp.{s} in {s}", .{ name, rel }),
            .reason = "not declared \"type\": \"local\", so this reader will not guess what it runs",
        });
        return;
    }

    const command_value = server.get("command") orelse {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "mcp.{s} in {s}", .{ name, rel }),
            .reason = "a local server with no command array names nothing to run",
        });
        return;
    };
    const command_array = switch (command_value) {
        .array => |a| a.items,
        else => {
            try refused.append(arena, .{
                .what = try std.fmt.allocPrint(arena, "mcp.{s} in {s}", .{ name, rel }),
                .reason = "command is not an array, and this reader will not guess the program from something else",
            });
            return;
        },
    };
    if (command_array.len == 0) {
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "mcp.{s} in {s}", .{ name, rel }),
            .reason = "the command array is empty, so there is no program at element 0",
        });
        return;
    }

    const program = switch (command_array[0]) {
        .string => |s| s,
        else => {
            try refused.append(arena, .{
                .what = try std.fmt.allocPrint(arena, "mcp.{s} in {s}", .{ name, rel }),
                .reason = "element 0 of command is not a string",
            });
            return;
        },
    };

    var args: std.ArrayList([]const u8) = .empty;
    for (command_array[1..]) |item| switch (item) {
        .string => |s| try args.append(arena, s),
        else => {},
    };

    var env_names: std.ArrayList([]const u8) = .empty;
    if (server.get("environment")) |env_value| switch (env_value) {
        .object => |env_obj| {
            var env_it = env_obj.iterator();
            // The value half of this pair is never read past this line: see
            // envName's own doc comment.
            while (env_it.next()) |pair| try env_names.append(arena, envName(pair.key_ptr.*));
        },
        else => {},
    };

    try mcp_servers.append(arena, .{
        .name = name,
        .command = program,
        .args = try args.toOwnedSlice(arena),
        .env = try env_names.toOwnedSlice(arena),
        .source_file = rel,
    });
}

fn saidFromString(s: []const u8) ?Said {
    if (std.mem.eql(u8, s, "allow")) return .allow;
    if (std.mem.eql(u8, s, "ask")) return .ask;
    if (std.mem.eql(u8, s, "deny")) return .deny;
    return null;
}

fn readPermission(
    arena: std.mem.Allocator,
    rel: []const u8,
    value: std.json.Value,
    policy_hints: *std.ArrayList(Hint),
    refused: *std.ArrayList(Refusal),
) !void {
    switch (value) {
        .string => |s| {
            try refused.append(arena, .{
                .what = try std.fmt.allocPrint(arena, "permission = \"{s}\" in {s}", .{ s, rel }),
                .reason = "a wildcard over another tool's own tool names means nothing here",
            });
        },
        .object => |obj| {
            var it = obj.iterator();
            while (it.next()) |entry| {
                const key = entry.key_ptr.*;
                const raw = switch (entry.value_ptr.*) {
                    .string => |s| s,
                    else => continue,
                };
                const said = saidFromString(raw) orelse continue;

                if (std.mem.eql(u8, key, "webfetch")) {
                    try policy_hints.append(arena, .{ .action = "net.fetch.*", .said = said, .source_file = rel });
                } else if (std.mem.eql(u8, key, "lsp")) {
                    try policy_hints.append(arena, .{ .action = "lsp.*", .said = said, .source_file = rel });
                } else {
                    try refused.append(arena, .{
                        .what = try std.fmt.allocPrint(arena, "permission.{s} = \"{s}\" in {s}", .{ key, raw, rel }),
                        .reason = "Chock decides that act through a different action, and the stance cannot be carried without inventing one",
                    });
                }
            }
        },
        else => {},
    }
}

fn refusePlugins(
    arena: std.mem.Allocator,
    rel: []const u8,
    value: std.json.Value,
    refused: *std.ArrayList(Refusal),
) !void {
    const items = switch (value) {
        .array => |a| a.items,
        else => return,
    };
    if (items.len == 0) return;
    try refused.append(arena, .{
        .what = try std.fmt.allocPrint(arena, "plugin in {s}", .{rel}),
        .reason = "a plugin is a JS/TS module that runs with the host's own privilege, and this build has no mechanism that runs one safely",
    });
}

const uncarried_dirs = [_]struct { path: []const u8, reason: []const u8 }{
    .{
        .path = ".opencode/agent",
        .reason = "an agent runs as its own agent, and this build has no mechanism that runs one",
    },
    .{
        .path = ".opencode/command",
        .reason = "a command expands host side, and this build has no mechanism that runs one",
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

test "webfetch maps to net.fetch.* and lsp maps to lsp.*, each keeping said" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, "opencode.json",
        \\{"permission": {"webfetch": "deny", "lsp": "ask"}}
    );

    const found = try read(arena, testing.io, project_root);

    var saw_fetch = false;
    var saw_lsp = false;
    for (found.policy_hints) |hint| {
        if (std.mem.eql(u8, hint.action, "net.fetch.*")) {
            try testing.expectEqual(migrate.Said.deny, hint.said);
            saw_fetch = true;
        }
        if (std.mem.eql(u8, hint.action, "lsp.*")) {
            try testing.expectEqual(migrate.Said.ask, hint.said);
            saw_lsp = true;
        }
    }
    try testing.expect(saw_fetch);
    try testing.expect(saw_lsp);
}

test "bash is refused rather than given an invented action, and so is a bare wildcard" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, "opencode.json",
        \\{"permission": {"bash": "deny"}}
    );

    const found = try read(arena, testing.io, project_root);

    // No action was invented for bash: nothing carries it as a policy row.
    try testing.expectEqual(@as(usize, 0), found.policy_hints.len);

    var saw_refusal = false;
    for (found.refused) |one| {
        if (std.mem.indexOf(u8, one.what, "bash") != null) saw_refusal = true;
    }
    try testing.expect(saw_refusal);
}

test "a bare string permission sets a wildcard this build refuses, not carries" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, "opencode.json",
        \\{"permission": "ask"}
    );

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 0), found.policy_hints.len);
    try testing.expectEqual(@as(usize, 1), found.refused.len);
}

test "an env value never appears in the returned Found while its name does" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, "opencode.json",
        \\{"mcp": {"weather": {"type": "local", "command": ["npx", "mcp-weather"],
        \\ "environment": {"WEATHER_API_KEY": "sk-live-do-not-leak"}}}}
    );

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 1), found.mcp_servers.len);
    const server = found.mcp_servers[0];
    try testing.expectEqual(@as(usize, 1), server.env.len);
    try testing.expectEqualStrings("WEATHER_API_KEY", server.env[0]);

    const text = try migrate.render(arena, found, "0.1.0-test", "2026-09-24", &.{});
    try testing.expect(std.mem.indexOf(u8, text, "WEATHER_API_KEY") != null);
    try testing.expect(std.mem.indexOf(u8, text, "sk-live-do-not-leak") == null);
}

test "a command array splits into a program at element 0 and args after it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, "opencode.json",
        \\{"mcp": {"fs": {"type": "local", "command": ["node", "server.js", "--stdio"]}}}
    );

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 1), found.mcp_servers.len);
    const server = found.mcp_servers[0];
    try testing.expectEqualStrings("node", server.command);
    try testing.expectEqual(@as(usize, 2), server.args.len);
    try testing.expectEqualStrings("server.js", server.args[0]);
    try testing.expectEqualStrings("--stdio", server.args[1]);
}

test "a remote mcp server is refused, not carried as if it had a command" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, "opencode.json",
        \\{"mcp": {"hosted": {"type": "remote", "url": "https://mcp.example.com"}}}
    );

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 0), found.mcp_servers.len);
    var saw_refusal = false;
    for (found.refused) |one| {
        if (std.mem.indexOf(u8, one.what, "hosted") != null) saw_refusal = true;
    }
    try testing.expect(saw_refusal);
}

test "the instruction walk takes the first of AGENTS.md, CLAUDE.md, CONTEXT.md, no stacking" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, "CLAUDE.md", "# claude\n");
    try writeProjectFile(testing.io, project_root, "CONTEXT.md", "# context\n");

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 1), found.instructions.len);
    try testing.expectEqualStrings("CLAUDE.md", found.instructions[0].path);
}

test "a malformed config is refused without losing the instruction file" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, "AGENTS.md", "# project instructions\n");
    try writeProjectFile(testing.io, project_root, "opencode.json", "{ this is not json");

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 1), found.instructions.len);
    try testing.expectEqualStrings("AGENTS.md", found.instructions[0].path);

    var saw_refusal = false;
    for (found.refused) |one| {
        if (std.mem.eql(u8, one.what, "opencode.json")) saw_refusal = true;
    }
    try testing.expect(saw_refusal);
}

test "a // line comment outside a string is stripped, and one inside a url string is not" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, "opencode.jsonc",
        \\{
        \\  // a comment on its own line
        \\  "mcp": {"docs": {"type": "remote", "url": "https://example.com/mcp"}}
        \\}
    );

    const found = try read(arena, testing.io, project_root);

    try testing.expectEqual(@as(usize, 1), found.sources.len);
    try testing.expectEqualStrings("opencode.jsonc", found.sources[0].path);
    var saw_refusal = false;
    for (found.refused) |one| {
        if (std.mem.indexOf(u8, one.what, "docs") != null) saw_refusal = true;
    }
    try testing.expect(saw_refusal);
}

test ".opencode/agent, .opencode/command and a non-empty plugin array are each refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const project_root = try tmpProjectRoot(arena, &tmp);

    try writeProjectFile(testing.io, project_root, "opencode.json",
        \\{"plugin": ["./my-plugin.ts"]}
    );
    try writeProjectFile(testing.io, project_root, ".opencode/agent/reviewer.md", "# reviewer\n");
    try writeProjectFile(testing.io, project_root, ".opencode/command/deploy.md", "# deploy\n");

    const found = try read(arena, testing.io, project_root);

    // One for the plugin array, one for each of the two directories.
    try testing.expectEqual(@as(usize, 3), found.refused.len);
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
