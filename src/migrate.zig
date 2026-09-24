//! `chock migrate`: read another AI coding harness's configuration and write
//! a `chock.zon` for it. One shot and offline: no session, no model, no
//! network, no sandbox.
//!
//! ```
//! chock migrate [--from <harness>] [--project <dir>] [--print]
//! ```
//!
//! This file builds the command, the `Found` value every future harness
//! reader hands back, the writer that turns one into `chock.zon` text, and
//! the report a person reads on every run. It ships with no reader: `readers`
//! below is empty, and every `--from` is refused until the first one lands.
//!
//! ## The translation, which is the whole point
//!
//! A foreign permission is read against a threat model this build never
//! measured, so nothing it allowed becomes an allow here:
//!
//! - a `deny` carries as `.deny`. A deny only narrows, in any threat model.
//! - an `allow` carries as `.ask`, never `.allow`.
//! - an MCP server becomes an `.mcp_servers` entry, and an `.ask` row beside
//!   it: running a third party program is exactly the kind of act an allow
//!   must not carry silently.
//! - an instruction file becomes a relative path in `.instructions`.
//! - a hook, a plugin, a skill and a slash command are never carried. Each
//!   goes into `Found.refused` with the reason, because Chock has no
//!   mechanism that would run one safely.
//! - a secret's value is never carried. Only an environment variable's own
//!   name is: see `envName`.
//!
//! ## Provenance
//!
//! A generated `chock.zon` is worth nothing to somebody checking it unless
//! they can tell what it came from, and whether that source has since
//! changed. So every reader names every file it read, in `Found.sources`,
//! with the SHA-256 of the bytes it read: see `hashBytes`. `render` writes
//! that list into a header comment before any block, so the file carries its
//! own provenance wherever it travels, and `chock migrate` prints the same
//! list in its report so it is visible even when the header is trimmed.

const std = @import("std");
const chock_core = @import("chock-core");

const Exit = @import("main.zig").Exit;
const version = @import("main.zig").version;
const tty = @import("tty.zig");

const usage_text =
    \\Usage: chock migrate [--from <harness>] [--project <dir>] [--print]
    \\
    \\Reads another AI coding harness's configuration and writes a chock.zon
    \\for it. One shot and offline: no session, no model, no network, no
    \\sandbox.
    \\
    \\Writes chock.zon only when the project has none. With one already
    \\there, nothing is written, and the rows it would have added are printed
    \\instead. --print always writes to standard output and touches no file.
    \\
    \\A foreign deny is carried as .deny. A foreign allow is carried as .ask,
    \\because an allow under another tool's threat model does not become an
    \\allow under this one.
    \\
    \\Options:
    \\  --from <harness>   The harness to read from. Refused when this build
    \\                     reads none of that name.
    \\  --project <dir>    The project. Defaults to the current directory.
    \\  --print            Write to standard output instead of chock.zon.
    \\
++ tty.options_text;

/// One instruction file another harness named, and the harness that named
/// it.
pub const Source = struct {
    path: []const u8,
    harness: []const u8,
};

/// One file a reader read, relative to the project root, and the SHA-256 of
/// the bytes it read, as 64 lower case hex characters. What lets somebody
/// check a generated `chock.zon` against the project that produced it: run
/// `sha256sum` on the same path, and compare.
pub const ReadSource = struct {
    path: []const u8,
    hash: [64]u8,
};

/// The SHA-256 of `bytes`, as 64 lower case hex characters.
///
/// **Every reader calls this on every file it reads**, and puts the result in
/// `Found.sources`. That is what makes provenance a property of `Found`
/// rather than a habit one reader might keep and another forget.
pub fn hashBytes(bytes: []const u8) [64]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// One MCP server another harness ran. `env` holds variable names only: a
/// reader must call `envName` on whatever the source wrote and never keep
/// the value half.
pub const McpServer = struct {
    name: []const u8,
    command: []const u8,
    args: []const []const u8 = &.{},
    env: []const []const u8 = &.{},
    source_file: []const u8 = "",
};

/// What a foreign source said about one action, and where it said it.
pub const Said = enum { allow, deny };

/// The policy row a foreign permission becomes. Never `.allow`: see this
/// file's own top comment.
pub const Decision = enum { deny, ask };

/// One permission line a foreign source carried.
pub const Hint = struct {
    action: []const u8,
    said: Said,
    source_file: []const u8,

    pub fn decision(self: Hint) Decision {
        return switch (self.said) {
            .deny => .deny,
            .allow => .ask,
        };
    }
};

/// Something a foreign source had that carries into no field here.
pub const Refusal = struct {
    what: []const u8,
    reason: []const u8,
};

/// The neutral value every harness reader hands back. Nothing in this file
/// reads a harness's own files; a reader does that and builds one of these.
pub const Found = struct {
    sources: []const ReadSource = &.{}, // every file read, and the sha256 of its bytes
    instructions: []const Source = &.{}, // a path, plus which harness named it
    mcp_servers: []const McpServer = &.{}, // name, command, args, env variable NAMES only
    policy_hints: []const Hint = &.{}, // action, what the source said, source file
    refused: []const Refusal = &.{}, // what was not carried and why
};

/// One harness this build can read a configuration from.
pub const Reader = struct {
    name: []const u8,
    read: *const fn (arena: std.mem.Allocator, io: std.Io, project_root: []const u8) anyerror!Found,
};

/// Every harness this build reads. Empty until the first reader lands: both
/// `--from` and the bare command refuse against this list, and the refusal
/// names every entry in it.
pub const readers = [_]Reader{};

/// The variable name half of a `NAME=value` pair a harness's own file wrote.
/// The value is never returned. A pair with no `=` is already a bare name
/// and comes back unchanged.
pub fn envName(pair: []const u8) []const u8 {
    const split = std.mem.indexOfScalar(u8, pair, '=') orelse return pair;
    return pair[0..split];
}

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = gpa;
    _ = exe_path;

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        else => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    const reader = findReader(options.from) orelse {
        const known = knownHarnesses(arena) catch "none";
        if (options.from.len == 0) {
            tty.print(
                .err,
                "chock migrate: this build reads no harness yet. Known harnesses: {s}.\n",
                .{known},
            );
        } else {
            tty.print(
                .err,
                "chock migrate: \"{s}\" is not a harness this build reads. Known harnesses: {s}.\n",
                .{ options.from, known },
            );
        }
        return Exit.usage.code();
    };

    const project_root = try resolveProject(arena, io, options.project);
    const found = try reader.read(arena, io, project_root);
    return finish(arena, io, project_root, found, options.print);
}

/// Report, then write or print. Split from `main` so a test can drive it
/// with a `Found` it built by hand, with no command line and no harness.
fn finish(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    found: Found,
    print_only: bool,
) !u8 {
    report(found);

    var stamp_buffer: [chock_core.memory.timestamp_bytes]u8 = undefined;
    const stamp = chock_core.memory.now(io, &stamp_buffer);
    const text = try render(arena, found, version, stamp[0..10]);

    if (print_only) {
        tty.out(.plain, "{s}", .{text});
        return Exit.finished.code();
    }

    const path = try std.fs.path.join(arena, &.{ project_root, chock_core.mcp.file_name });
    const wrote = writeChockZon(io, path, text) catch |err| {
        tty.print(.err, "chock migrate: {s} could not be written: {s}\n", .{ path, @errorName(err) });
        return Exit.usage.code();
    };

    if (!wrote) {
        tty.print(
            .warn,
            "chock migrate: {s} already exists, so nothing was written. These are the rows it would have added:\n",
            .{path},
        );
        tty.out(.plain, "{s}", .{text});
        // Never `finished`: a command that wrote nothing must not report
        // success. See `src/main.zig`'s own top comment.
        return Exit.usage.code();
    }

    tty.print(.plain, "chock migrate: wrote {s}\n", .{path});
    return Exit.finished.code();
}

/// Create `path` and write `text` into it, unless it is already there.
///
/// **One call, not a check and then a create.** Two runs of `chock migrate`
/// started together would otherwise both pass a check that ran before
/// either wrote, and the second would overwrite what the first just made.
fn writeChockZon(io: std.Io, path: []const u8, text: []const u8) !bool {
    var file = std.Io.Dir.createFileAbsolute(io, path, .{ .exclusive = true }) catch |err| switch (err) {
        error.PathAlreadyExists => return false,
        else => return err,
    };
    defer file.close(io);
    try file.writeStreamingAll(io, text);
    return true;
}

/// The report every run prints, in three parts: what was carried as is,
/// what was carried narrowed, and what was refused.
fn report(found: Found) void {
    tty.out(.plain, "carried:\n", .{});
    var carried = false;
    for (found.sources) |one| {
        tty.out(.plain, "  source        {s}  sha256:{s}\n", .{ one.path, one.hash });
        carried = true;
    }
    for (found.instructions) |one| {
        tty.out(.plain, "  instructions  {s}  (from {s})\n", .{ one.path, one.harness });
        carried = true;
    }
    for (found.mcp_servers) |server| {
        tty.out(.plain, "  mcp server    {s}\n", .{server.name});
        carried = true;
    }
    for (found.policy_hints) |hint| {
        if (hint.said != .deny) continue;
        tty.out(.plain, "  policy        {s} -> deny  (from {s})\n", .{ hint.action, hint.source_file });
        carried = true;
    }
    if (!carried) tty.out(.plain, "  nothing\n", .{});

    tty.out(.plain, "\nnarrowed, an allow became ask:\n", .{});
    var narrowed = false;
    for (found.policy_hints) |hint| {
        if (hint.said != .allow) continue;
        tty.out(.plain, "  {s}  allow -> ask  (from {s})\n", .{ hint.action, hint.source_file });
        narrowed = true;
    }
    if (!narrowed) tty.out(.plain, "  nothing\n", .{});

    tty.out(.plain, "\nrefused:\n", .{});
    if (found.refused.len == 0) {
        tty.out(.plain, "  nothing\n", .{});
    } else {
        for (found.refused) |one| tty.out(.plain, "  {s}: {s}\n", .{ one.what, one.reason });
    }
}

/// Turn a `Found` into `chock.zon` text, with a provenance header before any
/// block. Every block a foreign source gave nothing for is left out, so a
/// project that named one instruction file gets an `.instructions` block and
/// nothing else.
///
/// `generated_on` is the date the migration ran, as `YYYY-MM-DD`, and
/// nothing else: not a full timestamp, so two runs on one day render the same
/// header. Both it and `version` are given rather than read here, so a test
/// can pin them and this function never touches the clock itself.
pub fn render(
    arena: std.mem.Allocator,
    found: Found,
    tool_version: []const u8,
    generated_on: []const u8,
) std.mem.Allocator.Error![]const u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(arena);

    try renderHeader(arena, &text, found.sources, tool_version, generated_on);

    try text.appendSlice(arena, ".{\n");

    if (found.instructions.len != 0) {
        try text.appendSlice(arena, "    .instructions = .{\n");
        for (found.instructions) |one| {
            try text.print(arena, "        \"{f}\", // from {s}\n", .{ std.zig.fmtString(one.path), one.harness });
        }
        try text.appendSlice(arena, "    },\n");
    }

    if (found.mcp_servers.len != 0) {
        try text.appendSlice(arena, "    .mcp_servers = .{\n");
        for (found.mcp_servers) |server| try renderMcpServer(arena, &text, server);
        try text.appendSlice(arena, "    },\n");
    }

    if (found.policy_hints.len != 0) try renderPolicy(arena, &text, found.policy_hints);

    try text.appendSlice(arena, "}\n");
    return text.toOwnedSlice(arena);
}

/// The comment block that gives a generated `chock.zon` its provenance: the
/// version that wrote it, the date, and every file it was read from with the
/// SHA-256 of the bytes as read. `sha256sum` on the same paths, in the
/// project this file came from, is the whole of what checking it takes.
fn renderHeader(
    arena: std.mem.Allocator,
    text: *std.ArrayList(u8),
    sources: []const ReadSource,
    tool_version: []const u8,
    generated_on: []const u8,
) !void {
    try text.print(arena, "// Generated by chock {s} on {s}.\n", .{ tool_version, generated_on });

    if (sources.len != 0) {
        try text.appendSlice(arena, "// Read from, with the SHA-256 of each file as it was read:\n");
        var width: usize = 0;
        for (sources) |one| width = @max(width, one.path.len);
        for (sources) |one| {
            try text.print(arena, "//   {s}", .{one.path});
            try text.appendNTimes(arena, ' ', width - one.path.len + 2);
            try text.print(arena, "sha256:{s}\n", .{one.hash});
        }
    }

    try text.appendSlice(arena, "//\n// Re-run `chock migrate --print` to see what changed since.\n\n");
}

fn renderMcpServer(arena: std.mem.Allocator, text: *std.ArrayList(u8), server: McpServer) !void {
    try text.print(arena, "        .{{ .name = \"{f}\", .command = .{{ \"{f}\"", .{
        std.zig.fmtString(server.name),
        std.zig.fmtString(server.command),
    });
    for (server.args) |arg| try text.print(arena, ", \"{f}\"", .{std.zig.fmtString(arg)});
    try text.appendSlice(arena, " } }");
    if (server.source_file.len != 0) try text.print(arena, ", // from {s}", .{server.source_file});
    try text.appendSlice(arena, "\n");
    // Names only. The value half of whatever the source wrote never reaches
    // this file: see `envName`.
    for (server.env) |name| try text.print(arena, "        // reads the environment variable {s}\n", .{name});
}

fn renderPolicy(arena: std.mem.Allocator, text: *std.ArrayList(u8), hints: []const Hint) !void {
    try text.appendSlice(arena, "    .policy = .{\n        .rules = .{\n");

    for (hints) |hint| {
        if (hint.decision() != .deny) continue;
        try text.print(arena, "            .{{ .action = \"{f}\", .decision = .deny }}, // from {s}\n", .{
            std.zig.fmtString(hint.action),
            hint.source_file,
        });
    }

    // Every narrowed row is grouped here, each naming the file its allow
    // came from, so a reader sees at a glance what this build would not
    // carry as an allow.
    var wrote_heading = false;
    for (hints) |hint| {
        if (hint.decision() != .ask) continue;
        if (!wrote_heading) {
            try text.appendSlice(arena, "            // narrowed: an allow under another tool becomes an ask here\n");
            wrote_heading = true;
        }
        try text.print(arena, "            .{{ .action = \"{f}\", .decision = .ask }}, // from {s}\n", .{
            std.zig.fmtString(hint.action),
            hint.source_file,
        });
    }

    try text.appendSlice(arena, "        },\n    },\n");
}

fn findReader(name: []const u8) ?Reader {
    for (readers) |one| {
        if (std.mem.eql(u8, one.name, name)) return one;
    }
    return null;
}

fn knownHarnesses(arena: std.mem.Allocator) ![]const u8 {
    if (readers.len == 0) return "none";
    var text: std.ArrayList(u8) = .empty;
    for (readers, 0..) |one, index| {
        if (index != 0) try text.appendSlice(arena, ", ");
        try text.appendSlice(arena, one.name);
    }
    return text.toOwnedSlice(arena);
}

const Options = struct {
    from: []const u8 = "",
    project: ?[]const u8 = null,
    print: bool = false,
};

const ParseError = error{ HelpWanted, BadArguments };

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};
    var index: usize = 0;

    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;
        if (std.mem.eql(u8, argument, "--from")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.from = args[index];
            continue;
        }
        if (std.mem.eql(u8, argument, "--project")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.project = args[index];
            continue;
        }
        if (std.mem.eql(u8, argument, "--print")) {
            options.print = true;
            continue;
        }
        return error.BadArguments;
    }
    return options;
}

/// The project this command is about, as an absolute path. The same two
/// calls `chock run` and `chock memory` make, for the same reason: a path
/// resolved differently here than at `chock run` would write `chock.zon`
/// beside a project the next session never sees.
fn resolveProject(arena: std.mem.Allocator, io: std.Io, given: ?[]const u8) ![]const u8 {
    if (given) |path| {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return arena.dupe(u8, path);
        defer dir.close(io);
        const len = dir.realPath(io, &buffer) catch return arena.dupe(u8, path);
        return arena.dupe(u8, buffer[0..len]);
    }
    return std.process.currentPathAlloc(io, arena);
}

const testing = std.testing;

/// A fixed version and date, so a test of `render` pins a header without
/// reading the real version or the real clock.
const test_version = "0.1.0-test";
const test_date = "2026-09-24";

test "the command line takes a harness, a project and a print flag" {
    try testing.expectEqualStrings("", (try parseOptions(&.{})).from);
    try testing.expect(!(try parseOptions(&.{})).print);

    const named = try parseOptions(&.{ "--from", "claude-code", "--project", "/somewhere", "--print" });
    try testing.expectEqualStrings("claude-code", named.from);
    try testing.expectEqualStrings("/somewhere", named.project.?);
    try testing.expect(named.print);

    try testing.expectError(error.BadArguments, parseOptions(&.{"--from"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--project"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--not-an-option"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}

test "an env value is never rendered while its name is" {
    // What a harness's own file wrote: a name and a value on one line.
    const declared = "OPENAI_API_KEY=sk-live-do-not-leak";
    const name = envName(declared);
    try testing.expectEqualStrings("OPENAI_API_KEY", name);

    const found = Found{
        .mcp_servers = &.{.{
            .name = "openai",
            .command = "npx",
            .args = &.{"mcp-server-openai"},
            .env = &.{name},
            .source_file = ".mcp.json",
        }},
    };
    const text = try render(testing.allocator, found, test_version, test_date);
    defer testing.allocator.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "OPENAI_API_KEY") != null);
    try testing.expect(std.mem.indexOf(u8, text, "sk-live-do-not-leak") == null);

    // A bare name with no `=` is already what a reader wants, unchanged.
    try testing.expectEqualStrings("ANTHROPIC_API_KEY", envName("ANTHROPIC_API_KEY"));
}

test "render puts a foreign deny at .deny and a foreign allow at .ask" {
    const found = Found{
        .policy_hints = &.{
            .{ .action = "git.push", .said = .deny, .source_file = "settings.json" },
            .{ .action = "net.fetch.*", .said = .allow, .source_file = "settings.json" },
        },
    };
    const text = try render(testing.allocator, found, test_version, test_date);
    defer testing.allocator.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "\"git.push\", .decision = .deny") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"net.fetch.*\", .decision = .ask") != null);
    // An allow is never carried as an allow: that would widen under a threat
    // model this build never measured. See this file's own top comment.
    try testing.expect(std.mem.indexOf(u8, text, ".decision = .allow") == null);
}

test "hashBytes gives the sha256 of what it was given, as 64 lower case hex characters" {
    const empty = hashBytes("");
    try testing.expectEqualStrings(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        &empty,
    );

    // Different bytes, a different digest, and still 64 hex characters: the
    // property `render`'s header depends on is that every hash is full length
    // and never a prefix somebody could not check independently.
    const one_byte = hashBytes("x");
    try testing.expect(!std.mem.eql(u8, &empty, &one_byte));
    try testing.expectEqual(@as(usize, 64), one_byte.len);
    for (one_byte) |c| try testing.expect(std.ascii.isHex(c) and !std.ascii.isUpper(c));
}

test "the rendered header names every source and carries a full 64 character hash for each" {
    const found = Found{
        .sources = &.{
            .{ .path = ".claude/settings.json", .hash = hashBytes("{}") },
            .{ .path = "CLAUDE.md", .hash = hashBytes("# hi\n") },
        },
    };
    const text = try render(testing.allocator, found, test_version, test_date);
    defer testing.allocator.free(text);

    // The version and the date come from the caller, and never from a second
    // idea of either kept in this file: see `render`'s own doc comment.
    try testing.expect(std.mem.indexOf(u8, text, "Generated by chock " ++ test_version ++ " on " ++ test_date ++ ".") != null);

    for (found.sources) |one| {
        try testing.expect(std.mem.indexOf(u8, text, one.path) != null);
        const hash_line = try std.fmt.allocPrint(testing.allocator, "sha256:{s}\n", .{one.hash});
        defer testing.allocator.free(hash_line);
        try testing.expect(std.mem.indexOf(u8, text, hash_line) != null);
        try testing.expectEqual(@as(usize, 64), one.hash.len);
    }

    // With no source at all the header still names the version and the date,
    // and asks for nothing that is not there.
    const bare = try render(testing.allocator, Found{}, test_version, test_date);
    defer testing.allocator.free(bare);
    try testing.expect(std.mem.indexOf(u8, bare, "Generated by chock") != null);
    try testing.expect(std.mem.indexOf(u8, bare, "Read from") == null);
}

test "an existing chock.zon is never overwritten" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const project_root = buffer[0..len];

    const path = try std.fs.path.join(arena, &.{ project_root, chock_core.mcp.file_name });
    const kept_before = "// a project's own chock.zon\n.{}\n";
    {
        var handle = try std.Io.Dir.createFileAbsolute(testing.io, path, .{});
        defer handle.close(testing.io);
        try handle.writeStreamingAll(testing.io, kept_before);
    }

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const found = Found{
        .policy_hints = &.{.{ .action = "git.push", .said = .deny, .source_file = "settings.json" }},
    };
    const code = try finish(arena, testing.io, project_root, found, false);

    // Never `finished`: nothing was written. See `src/main.zig`'s own top
    // comment.
    try testing.expect(code != Exit.finished.code());

    const still_there = try std.Io.Dir.cwd().readFileAlloc(testing.io, path, arena, .limited(4096));
    try testing.expectEqualStrings(kept_before, still_there);

    // The row it would have added is printed instead of written.
    try testing.expect(std.mem.indexOf(u8, said.out(), "git.push") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "already exists") != null);
}

test "a project with no chock.zon gets one, once" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const project_root = buffer[0..len];
    const path = try std.fs.path.join(arena, &.{ project_root, chock_core.mcp.file_name });

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const found = Found{
        .instructions = &.{.{ .path = "AGENTS.md", .harness = "claude-code" }},
    };
    try testing.expectEqual(
        Exit.finished.code(),
        try finish(arena, testing.io, project_root, found, false),
    );

    const written = try std.Io.Dir.cwd().readFileAlloc(testing.io, path, arena, .limited(4096));
    try testing.expect(std.mem.indexOf(u8, written, "AGENTS.md") != null);

    // A second run must not overwrite the first: the reader path is fixed
    // above, but this asserts the write step itself is one shot.
    said.clear();
    try testing.expect(
        (try finish(arena, testing.io, project_root, found, false)) != Exit.finished.code(),
    );
    const unchanged = try std.Io.Dir.cwd().readFileAlloc(testing.io, path, arena, .limited(4096));
    try testing.expectEqualStrings(written, unchanged);
}

test "--print never touches chock.zon, even when there is none to protect" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const project_root = buffer[0..len];
    const path = try std.fs.path.join(arena, &.{ project_root, chock_core.mcp.file_name });

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const found = Found{
        .instructions = &.{.{ .path = "AGENTS.md", .harness = "claude-code" }},
    };
    try testing.expectEqual(
        Exit.finished.code(),
        try finish(arena, testing.io, project_root, found, true),
    );
    try testing.expect(std.mem.indexOf(u8, said.out(), "AGENTS.md") != null);
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, path, .{}),
    );
}

test "no reader is built yet, so any --from is refused and names what this build knows" {
    try testing.expect(findReader("claude-code") == null);
    try testing.expectEqualStrings("none", try knownHarnesses(testing.allocator));
}
