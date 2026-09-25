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
//! - an `ask` carries as `.ask`, which is the same row an allow gets but not
//!   the same fact: the report separates the two.
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
//! ## `--sessions` and `--memory`
//!
//! Both are off unless named, and both read the user's home directory
//! directly, which every reader above deliberately does not: a transcript
//! and a notebook are the user's own and live nowhere else, unlike a
//! project's configuration. `--sessions` copies a transcript in as a new
//! session log; `--memory` copies notes in as knowledgebase entries. See
//! `migrate/transcript.zig` and `importMemory` below.
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
const chock_policy = @import("chock-policy");

const Exit = @import("main.zig").Exit;
const version = @import("main.zig").version;
const tty = @import("tty.zig");
const session = @import("session.zig");
const transcript = @import("migrate/transcript.zig");

const usage_text =
    \\Usage: chock migrate [--from <harness>] [--project <dir>] [--print]
    \\                    [--permission <class>] [--sessions] [--memory]
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
    \\--permission <class> carries an allow under that class as .allow. It
    \\takes net.fetch, and it is repeatable. Only a host the source named
    \\itself is carried, never a wider one. Use it when you have read those
    \\grants and accept them, because ask is a refusal for a fetch: only
    \\allow reads a host, so a fetch rule written at ask is the same as no
    \\rule at all.
    \\
    \\--sessions brings a transcript across as a new session log, holding
    \\only session.start and session.imported: the foreign turns never
    \\become message events, and the transcript is copied beside the new
    \\session rather than loaded into context.
    \\
    \\--memory brings another harness's own notes into the knowledgebase, as
    \\data the agent may weigh and never as instructions it must obey.
    \\
    \\Options:
    \\  --from <harness>   The harness to read from. Refused when this build
    \\                     reads none of that name.
    \\  --project <dir>    The project. Defaults to the current directory.
    \\  --print            Write to standard output instead of chock.zon.
    \\  --sessions         Import transcripts as new session logs.
    \\  --memory           Import notes into the knowledgebase, as data.
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

/// What a foreign source said about one action. Kept as the source said it,
/// so the report can tell an act that was narrowed from one that was already
/// this narrow upstream.
pub const Said = enum { allow, ask, deny };

/// The policy row a foreign permission becomes. `.allow` is reachable only
/// through `--permission`, which is a person saying in as many words that they
/// read the source's grants and accept them. Nothing carries one by default.
pub const Decision = enum { deny, ask, allow };

/// A class of permission `--permission` can carry as `.allow`.
///
/// **`net.fetch` is here because `ask` is a refusal for a fetch.** Only
/// `allow` reads a host, so a fetch rule written at `ask` is the same as no
/// rule, and carrying one would be the inert output this file exists to avoid.
/// See `docs/configure/actions.md`.
pub const carryable = [_][]const u8{"net.fetch"};

/// Whether `action` sits under one of the classes named on the command line.
pub fn isCarried(action: []const u8, carry: []const []const u8) bool {
    for (carry) |class| {
        if (std.mem.eql(u8, action, class)) return true;
        if (action.len > class.len and
            std.mem.startsWith(u8, action, class) and
            action[class.len] == '.') return true;
    }
    return false;
}

/// One permission line a foreign source carried.
pub const Hint = struct {
    action: []const u8,
    said: Said,
    source_file: []const u8,

    /// `carry` holds the classes `--permission` named. An allow under one of
    /// them is the only way a row reaches `.allow`.
    pub fn decision(self: Hint, carry: []const []const u8) Decision {
        return switch (self.said) {
            .deny => .deny,
            .ask => .ask,
            .allow => if (isCarried(self.action, carry)) .allow else .ask,
        };
    }

    /// Whether this build wrote something narrower than the source did. An
    /// `ask` upstream lands on `ask` here, so it was carried and not narrowed.
    /// An allow the command line carried is not narrowed either.
    pub fn wasNarrowed(self: Hint, carry: []const []const u8) bool {
        return self.said == .allow and !isCarried(self.action, carry);
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

/// Every action name this build defines, as `docs/configure/actions.md` lists
/// them. A `.*` entry stands for itself and for every name under it.
const known_actions = [_][]const u8{
    "device.*",            "exec.devshell.*",  "exec.nix.store.*", "exec.path.*",
    "exec.unparsed",       "exec.workspace.*", "file.write",       "git.branch.delete",
    "git.commit",          "git.push",         "lsp.*",            "mcp.*",
    "model.select",        "net.connect.*",    "net.fetch",        "net.fetch.*",
    "nix.build",           "nix.build.*",      "nix.net.*",        "nix.net.build.opaque",
    "plugin.*",            "policy.widen",     "sandbox.jit",      "workspace.apply",
    "workspace.integrate",
};

/// Whether `action` is a name this build decides anything by.
///
/// **A row naming an action nothing here defines is worse than no row.** It
/// reads as a carried stance and matches nothing, and a name carrying a `*`
/// anywhere but the end is refused outright by the policy reader, so the whole
/// generated file then fails to load. A reader that finds no equivalent must
/// refuse instead: see `Refusal`.
pub fn isKnownAction(action: []const u8) bool {
    for (known_actions) |known| {
        if (std.mem.eql(u8, action, known)) return true;
        if (std.mem.endsWith(u8, known, ".*")) {
            const prefix = known[0 .. known.len - 1];
            if (std.mem.startsWith(u8, action, prefix) and action.len > prefix.len) return true;
        }
    }
    return false;
}

/// Move every hint naming an action this build does not define into
/// `refused`, so no reader can put an inert or unloadable row in the file.
///
/// A reader should refuse these itself and say something useful about the
/// source's own spelling. This is the net under that, and it runs on every
/// read: a reader added later cannot reintroduce the fault by forgetting.
pub fn vet(arena: std.mem.Allocator, found: Found) std.mem.Allocator.Error!Found {
    var kept: std.ArrayList(Hint) = .empty;
    var refused: std.ArrayList(Refusal) = .empty;
    try refused.appendSlice(arena, found.refused);

    for (found.policy_hints) |hint| {
        if (isKnownAction(hint.action)) {
            try kept.append(arena, hint);
            continue;
        }
        try refused.append(arena, .{
            .what = try std.fmt.allocPrint(arena, "{s} (from {s})", .{ hint.action, hint.source_file }),
            .reason = "no action here goes by that name, so a row for it would decide nothing",
        });
    }

    var out = found;
    out.policy_hints = try kept.toOwnedSlice(arena);
    out.refused = try refused.toOwnedSlice(arena);
    return out;
}

/// One harness this build can read a configuration from.
pub const Reader = struct {
    name: []const u8,
    read: *const fn (arena: std.mem.Allocator, io: std.Io, project_root: []const u8) anyerror!Found,
};

/// Every harness this build reads. Both `--from` and the bare command refuse
/// against this list, and the refusal names every entry in it.
pub const readers = [_]Reader{
    .{ .name = "claude-code", .read = @import("migrate/claude_code.zig").read },
    .{ .name = "codex", .read = @import("migrate/codex.zig").read },
    .{ .name = "opencode", .read = @import("migrate/opencode.zig").read },
    .{ .name = "zed", .read = @import("migrate/zed.zig").read },
    .{ .name = "oh-my-pi", .read = @import("migrate/oh_my_pi.zig").read },
};

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

    const options = parseOptions(arena, args) catch |err| switch (err) {
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
    const found = try vet(arena, try reader.read(arena, io, project_root));

    var env = try environ.createMap(arena);
    defer env.deinit();

    const sessions_result: ?transcript.Result = if (options.sessions)
        try transcript.import(arena, io, &env, options.from, project_root)
    else
        null;
    const memory_result: ?MemoryResult = if (options.memory)
        try importMemory(arena, io, &env, options.from, project_root)
    else
        null;

    return finish(
        arena,
        io,
        project_root,
        found,
        options.print,
        options.permission,
        sessions_result,
        memory_result,
    );
}

/// Report, then write or print. Split from `main` so a test can drive it
/// with a `Found` it built by hand, with no command line and no harness.
fn finish(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    found: Found,
    print_only: bool,
    carry: []const []const u8,
    sessions_result: ?transcript.Result,
    memory_result: ?MemoryResult,
) !u8 {
    report(found, carry, sessions_result, memory_result);

    var stamp_buffer: [chock_core.memory.timestamp_bytes]u8 = undefined;
    const stamp = chock_core.memory.now(io, &stamp_buffer);
    const text = try render(arena, found, version, stamp[0..10], carry);

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
/// what was carried narrowed, and what was refused. `--sessions` and
/// `--memory` each add their own heading, only when the flag was given.
fn report(
    found: Found,
    carry: []const []const u8,
    sessions_result: ?transcript.Result,
    memory_result: ?MemoryResult,
) void {
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
        if (hint.wasNarrowed(carry)) continue;
        tty.out(.plain, "  policy        {s} -> {t}  (from {s})\n", .{
            hint.action,
            hint.decision(carry),
            hint.source_file,
        });
        carried = true;
    }
    if (!carried) tty.out(.plain, "  nothing\n", .{});

    tty.out(.plain, "\nnarrowed, an allow became ask:\n", .{});
    var narrowed = false;
    for (found.policy_hints) |hint| {
        if (!hint.wasNarrowed(carry)) continue;
        tty.out(.plain, "  {s}  allow -> ask  (from {s})\n", .{ hint.action, hint.source_file });
        narrowed = true;
    }
    if (!narrowed) tty.out(.plain, "  nothing\n", .{});

    var granted = false;
    for (found.policy_hints) |hint| {
        if (hint.decision(carry) != .allow) continue;
        if (!granted) {
            tty.out(.plain, "\ncarried as allow, because --permission named the class:\n", .{});
            granted = true;
        }
        tty.out(.plain, "  {s}  allow -> allow  (from {s})\n", .{ hint.action, hint.source_file });
    }

    tty.out(.plain, "\nrefused:\n", .{});
    if (found.refused.len == 0) {
        tty.out(.plain, "  nothing\n", .{});
    } else {
        for (found.refused) |one| tty.out(.plain, "  {s}: {s}\n", .{ one.what, one.reason });
    }

    if (sessions_result) |result| {
        tty.out(.plain, "\nsessions:\n", .{});
        if (result.imported.len == 0 and result.refused.len == 0) tty.out(.plain, "  nothing\n", .{});
        for (result.imported) |one| {
            tty.out(.plain, "  {s}  session {s}  {d} messages  sha256:{s}\n", .{
                one.source_path,
                &one.session_id,
                one.messages,
                &one.content_hash,
            });
            tty.out(.plain, "    copied to {s}\n", .{one.copy_path});
        }
        for (result.refused) |one| tty.out(.plain, "  refused: {s}: {s}\n", .{ one.what, one.reason });
    }

    if (memory_result) |result| {
        tty.out(.plain, "\nmemory:\n", .{});
        tty.out(.plain, "  {d} note(s) carried as data\n", .{result.carried});
        for (result.refused) |one| tty.out(.plain, "  refused: {s}: {s}\n", .{ one.what, one.reason });
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
    carry: []const []const u8,
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

    if (found.policy_hints.len != 0) try renderPolicy(arena, &text, found.policy_hints, carry);

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

fn renderPolicy(
    arena: std.mem.Allocator,
    text: *std.ArrayList(u8),
    hints: []const Hint,
    carry: []const []const u8,
) !void {
    try text.appendSlice(arena, "    .policy = .{\n        .rules = .{\n");

    for (hints) |hint| {
        if (hint.decision(carry) != .deny) continue;
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
        if (hint.decision(carry) != .ask) continue;
        if (!wrote_heading) {
            try text.appendSlice(arena, "            // narrowed: an allow under another tool becomes an ask here\n");
            wrote_heading = true;
        }
        try text.print(arena, "            .{{ .action = \"{f}\", .decision = .ask }}, // from {s}\n", .{
            std.zig.fmtString(hint.action),
            hint.source_file,
        });
    }

    // Last, and grouped with the reason, because this is the one shape that
    // carries another tool's grant unchanged. It is here only because the
    // command line asked for it by class.
    var wrote_carried = false;
    for (hints) |hint| {
        if (hint.decision(carry) != .allow) continue;
        if (!wrote_carried) {
            try text.appendSlice(arena, "            // carried as allow, because --permission named this class\n");
            wrote_carried = true;
        }
        try text.print(arena, "            .{{ .action = \"{f}\", .decision = .allow }}, // from {s}\n", .{
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
    /// Every class `--permission` named. A grant is carried only under one of
    /// these, and the list is empty unless a person wrote it out.
    permission: []const []const u8 = &.{},
    sessions: bool = false,
    memory: bool = false,
};

const ParseError = error{ HelpWanted, BadArguments };

fn parseOptions(arena: std.mem.Allocator, args: []const []const u8) ParseError!Options {
    var options = Options{};
    var carried: std.ArrayList([]const u8) = .empty;
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
        if (std.mem.eql(u8, argument, "--sessions")) {
            options.sessions = true;
            continue;
        }
        if (std.mem.eql(u8, argument, "--memory")) {
            options.memory = true;
            continue;
        }
        if (std.mem.eql(u8, argument, "--permission")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            const class = args[index];
            if (!isCarryable(class)) {
                tty.print(
                    .err,
                    "chock migrate: --permission {s} names no class this build carries. It takes: {s}.\n",
                    .{ class, carryableList() },
                );
                return error.BadArguments;
            }
            carried.append(arena, class) catch return error.BadArguments;
            continue;
        }
        // Naming the option is the whole of the message. A usage page alone
        // leaves a person unable to tell a typo from an option this build
        // does not have.
        tty.print(.err, "chock migrate: there is no option named {s}.\n", .{argument});
        return error.BadArguments;
    }
    options.permission = carried.items;
    return options;
}

fn isCarryable(class: []const u8) bool {
    for (carryable) |known| {
        if (std.mem.eql(u8, class, known)) return true;
    }
    return false;
}

/// The classes this build carries, for a refusal to name. One today, so this
/// is a literal rather than a join that allocates.
fn carryableList() []const u8 {
    comptime var text: []const u8 = "";
    inline for (carryable, 0..) |one, index| {
        text = text ++ (if (index == 0) "" else ", ") ++ one;
    }
    return text;
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

/// What `--memory` did: how many notes were carried, and why any were not.
pub const MemoryResult = struct {
    harness: []const u8,
    carried: usize = 0,
    refused: []const Refusal = &.{},
};

/// At most this many notes are carried in one run. The knowledgebase's own
/// cap is the natural bound: carrying more than a project can ever keep
/// would only be refused note by note further down.
const max_memory_import = chock_core.memory.max_entries;

/// `harness`'s own notes for `project_root`, brought into Chock's
/// knowledgebase as data. Each note becomes its own entry, named after the
/// source file; a name `--memory` finds a second time adds a version rather
/// than a second entry, so a later run of `--memory` updates what it
/// already carried.
fn importMemory(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    harness: []const u8,
    project_root: []const u8,
) !MemoryResult {
    if (!std.mem.eql(u8, harness, transcript.harness_name)) {
        return .{
            .harness = harness,
            .refused = &.{.{
                .what = harness,
                .reason = "its notes location is not pinned yet, so nothing was read",
            }},
        };
    }

    const project_dir = transcript.homeProjectDir(arena, env, project_root) catch |err| return .{
        .harness = harness,
        .refused = &.{.{
            .what = transcript.harness_name,
            .reason = try std.fmt.allocPrint(arena, "its notes directory is unknown: {s}", .{@errorName(err)}),
        }},
    };
    const notes_dir = try std.fs.path.join(arena, &.{ project_dir, "memory" });

    var names: std.ArrayList([]const u8) = .empty;
    {
        var dir = std.Io.Dir.openDirAbsolute(io, notes_dir, .{ .iterate = true }) catch {
            // No such directory is not a fault: most projects have no notes
            // from this harness at all.
            return .{ .harness = harness };
        };
        defer dir.close(io);
        var walker = dir.iterate();
        while (walker.next(io) catch null) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".md")) continue;
            try names.append(arena, try arena.dupe(u8, entry.name));
        }
    }
    std.mem.sort([]const u8, names.items, {}, lessThanBytes);

    const dest_dir = try session.memoryDir(arena, env, project_root);
    try session.createMemoryDir(io, dest_dir);

    var carried: usize = 0;
    var refused: std.ArrayList(Refusal) = .empty;

    for (names.items) |name| {
        if (carried >= max_memory_import) {
            try refused.append(arena, .{
                .what = name,
                .reason = try std.fmt.allocPrint(
                    arena,
                    "at most {d} notes are carried in one run",
                    .{max_memory_import},
                ),
            });
            continue;
        }
        importOneNote(arena, io, harness, notes_dir, dest_dir, name) catch |err| {
            try refused.append(arena, .{
                .what = name,
                .reason = try std.fmt.allocPrint(arena, "could not be carried: {s}", .{@errorName(err)}),
            });
            continue;
        };
        carried += 1;
    }

    return .{ .harness = harness, .carried = carried, .refused = try refused.toOwnedSlice(arena) };
}

fn importOneNote(
    arena: std.mem.Allocator,
    io: std.Io,
    harness: []const u8,
    notes_dir: []const u8,
    dest_dir: []const u8,
    name: []const u8,
) !void {
    const source_path = try std.fs.path.join(arena, &.{ notes_dir, name });
    const body = try std.Io.Dir.cwd().readFileAlloc(io, source_path, arena, .limited(chock_core.memory.max_body_bytes));

    const entry_name = try noteName(arena, name);
    try chock_core.memory.checkName(entry_name);

    const dest_path = try std.fmt.allocPrint(arena, "{s}/{s}" ++ chock_core.memory.extension, .{ dest_dir, entry_name });
    const existing = std.Io.Dir.cwd().readFileAlloc(io, dest_path, arena, .limited(chock_core.memory.max_entry_bytes)) catch |err| switch (err) {
        error.FileNotFound => "",
        else => return err,
    };

    if (existing.len == 0 and chock_core.memory.count(io, dest_dir) >= chock_core.memory.max_entries) {
        return error.KnowledgebaseFull;
    }
    if (chock_core.memory.versionsIn(existing) >= chock_core.memory.max_versions) {
        return error.NoteFull;
    }

    var written_at_buffer: [chock_core.memory.timestamp_bytes]u8 = undefined;
    const text = try chock_core.memory.addVersion(arena, existing, .{
        .name = entry_name,
        .description = try std.fmt.allocPrint(arena, "imported from {s}: {s}", .{ harness, name }),
        .kind = .insight,
        .written_at = chock_core.memory.now(io, &written_at_buffer),
        .body = body,
    });

    var file = try std.Io.Dir.createFileAbsolute(io, dest_path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, text);
}

/// `file_name` with its extension dropped, lower cased, and every character
/// `chock_core.memory.checkName` would refuse turned into `-`. A leading `-`
/// or `_` is trimmed, because a name may not begin with either.
fn noteName(arena: std.mem.Allocator, file_name: []const u8) ![]const u8 {
    const stem = if (std.mem.endsWith(u8, file_name, ".md")) file_name[0 .. file_name.len - 3] else file_name;
    const bound = @min(stem.len, chock_core.memory.max_name_bytes);
    const out = try arena.alloc(u8, bound);
    for (stem[0..bound], 0..) |byte, i| {
        out[i] = switch (byte) {
            'a'...'z', '0'...'9' => byte,
            'A'...'Z' => byte + ('a' - 'A'),
            else => '-',
        };
    }
    var start: usize = 0;
    while (start < out.len and (out[start] == '-' or out[start] == '_')) start += 1;
    return out[start..];
}

fn lessThanBytes(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

const testing = std.testing;

/// A fixed version and date, so a test of `render` pins a header without
/// reading the real version or the real clock.
const test_version = "0.1.0-test";
const test_date = "2026-09-24";

test "the command line takes a harness, a project and a print flag" {
    // The refusals below name the option on standard error, and a passing
    // test must not write there.
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqualStrings("", (try parseOptions(testing.allocator, &.{})).from);
    try testing.expect(!(try parseOptions(testing.allocator, &.{})).print);

    const named = try parseOptions(testing.allocator, &.{ "--from", "claude-code", "--project", "/somewhere", "--print" });
    try testing.expectEqualStrings("claude-code", named.from);
    try testing.expectEqualStrings("/somewhere", named.project.?);
    try testing.expect(named.print);

    try testing.expectError(error.BadArguments, parseOptions(testing.allocator, &.{"--from"}));
    try testing.expectError(error.BadArguments, parseOptions(testing.allocator, &.{"--project"}));
    try testing.expectError(error.BadArguments, parseOptions(testing.allocator, &.{"--not-an-option"}));
    try testing.expectError(error.HelpWanted, parseOptions(testing.allocator, &.{"--help"}));
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
    const text = try render(testing.allocator, found, test_version, test_date, &.{});
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
    const text = try render(testing.allocator, found, test_version, test_date, &.{});
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
    const text = try render(testing.allocator, found, test_version, test_date, &.{});
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
    const bare = try render(testing.allocator, Found{}, test_version, test_date, &.{});
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
    const code = try finish(arena, testing.io, project_root, found, false, &.{}, null, null);

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
        try finish(arena, testing.io, project_root, found, false, &.{}, null, null),
    );

    const written = try std.Io.Dir.cwd().readFileAlloc(testing.io, path, arena, .limited(4096));
    try testing.expect(std.mem.indexOf(u8, written, "AGENTS.md") != null);

    // A second run must not overwrite the first: the reader path is fixed
    // above, but this asserts the write step itself is one shot.
    said.clear();
    try testing.expect(
        (try finish(arena, testing.io, project_root, found, false, &.{}, null, null)) != Exit.finished.code(),
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
        try finish(arena, testing.io, project_root, found, true, &.{}, null, null),
    );
    try testing.expect(std.mem.indexOf(u8, said.out(), "AGENTS.md") != null);
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, path, .{}),
    );
}

test "a harness this build reads is found, and one it does not is refused by name" {
    const gpa = testing.allocator;

    for ([_][]const u8{ "claude-code", "codex", "opencode", "zed", "oh-my-pi" }) |name| {
        try testing.expect(findReader(name) != null);
    }
    try testing.expect(findReader("emacs") == null);

    // The refusal names every harness, so a person who spelled one wrong is
    // told what this build does read.
    const known = try knownHarnesses(gpa);
    defer gpa.free(known);
    for ([_][]const u8{ "claude-code", "codex", "opencode", "zed", "oh-my-pi" }) |name| {
        try testing.expect(std.mem.indexOf(u8, known, name) != null);
    }
}

test {
    _ = @import("migrate/claude_code.zig");
    _ = @import("migrate/codex.zig");
    _ = @import("migrate/transcript.zig");
}

test "a hint naming an action this build does not define never reaches a row" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const found = Found{
        .policy_hints = &.{
            .{ .action = "git.push", .said = .deny, .source_file = "a.json" },
            // Claude Code spells a rule as a tool and an argument pattern. The
            // policy reader refuses an interior `*` outright, so a row carrying
            // one would stop the whole file loading.
            .{ .action = "Bash(cargo test:*)", .said = .allow, .source_file = "a.json" },
            .{ .action = "sandbox.write", .said = .deny, .source_file = "b.toml" },
        },
    };

    const vetted = try vet(arena, found);
    try testing.expectEqual(@as(usize, 1), vetted.policy_hints.len);
    try testing.expectEqualStrings("git.push", vetted.policy_hints[0].action);
    try testing.expectEqual(@as(usize, 2), vetted.refused.len);
    try testing.expect(std.mem.indexOf(u8, vetted.refused[0].what, "Bash(cargo test:*)") != null);
}

test "every action the guard admits is one the policy reader can carry" {
    // A name this build offers but the table refuses would be a file that
    // cannot load, which is the fault the guard exists to stop.
    for (known_actions) |action| {
        try testing.expect(isKnownAction(action));
        try testing.expect(chock_policy.table.patternIsWellFormed(action));
    }
    try testing.expect(isKnownAction("net.fetch.com.example"));
    try testing.expect(!isKnownAction("Bash(cargo test:*)"));
    try testing.expect(!isKnownAction("sandbox.write"));
}

test "a fetch grant is ask until --permission names its class" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const found = Found{ .policy_hints = &.{
        .{ .action = "net.fetch.com.example", .said = .allow, .source_file = "s.json" },
        .{ .action = "git.push", .said = .allow, .source_file = "s.json" },
    } };

    const closed = try render(arena, found, test_version, test_date, &.{});
    try testing.expect(std.mem.indexOf(u8, closed, ".decision = .allow") == null);

    const opened = try render(arena, found, test_version, test_date, &.{"net.fetch"});
    try testing.expect(std.mem.indexOf(u8, opened, "\"net.fetch.com.example\", .decision = .allow") != null);

    // The flag names one class and widens nothing else.
    try testing.expect(std.mem.indexOf(u8, opened, "\"git.push\", .decision = .allow") == null);
}

test "--permission takes a class this build carries and refuses one it does not" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const opened = try parseOptions(arena, &.{ "--permission", "net.fetch" });
    try testing.expectEqual(@as(usize, 1), opened.permission.len);
    try testing.expectEqualStrings("net.fetch", opened.permission[0]);

    try testing.expectEqual(@as(usize, 0), (try parseOptions(arena, &.{})).permission.len);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);
    try testing.expectError(
        error.BadArguments,
        parseOptions(arena, &.{ "--permission", "git.push" }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "net.fetch") != null);
}

test "an option this build does not have is named" {
    const arena = testing.allocator;

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"--nonsense"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--nonsense") != null);
}

test "--sessions and --memory are off unless named" {
    const arena = testing.allocator;

    const bare = try parseOptions(arena, &.{});
    try testing.expect(!bare.sessions);
    try testing.expect(!bare.memory);

    const named = try parseOptions(arena, &.{ "--sessions", "--memory" });
    try testing.expect(named.sessions);
    try testing.expect(named.memory);
}

fn writeHomeFile(io: std.Io, dir: []const u8, rel: []const u8, contents: []const u8) !void {
    const full = try std.fs.path.join(testing.allocator, &.{ dir, rel });
    defer testing.allocator.free(full);
    if (std.fs.path.dirname(full)) |parent| try std.Io.Dir.cwd().createDirPath(io, parent);
    var file = try std.Io.Dir.cwd().createFile(io, full, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
}

test "memory files are carried as data, with a bound on how many by size" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var home = testing.tmpDir(.{});
    defer home.cleanup();
    var home_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const home_len = try home.dir.realPath(testing.io, &home_buffer);
    const home_path = home_buffer[0..home_len];

    var data = testing.tmpDir(.{});
    defer data.cleanup();
    var data_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const data_len = try data.dir.realPath(testing.io, &data_buffer);
    const data_path = data_buffer[0..data_len];

    const project_root = "/home/somebody/work/parser";
    const slug = "-home-somebody-work-parser";
    const notes_dir = try std.fs.path.join(arena, &.{ home_path, ".claude", "projects", slug, "memory" });

    try writeHomeFile(testing.io, notes_dir, "First-Note.md", "# first\nan insight worth keeping\n");
    try writeHomeFile(testing.io, notes_dir, "second-note.md", "# second\nanother one\n");

    var oversized: std.ArrayList(u8) = .empty;
    try oversized.appendNTimes(arena, 'x', chock_core.memory.max_body_bytes + 1);
    try writeHomeFile(testing.io, notes_dir, "too-big.md", oversized.items);

    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();
    try env.put("HOME", home_path);
    try env.put("XDG_DATA_HOME", data_path);

    const result = try importMemory(arena, testing.io, &env, "claude-code", project_root);
    try testing.expectEqual(@as(usize, 2), result.carried);
    try testing.expectEqual(@as(usize, 1), result.refused.len);
    try testing.expectEqualStrings("too-big.md", result.refused[0].what);

    // Each note landed as data in the knowledgebase's own file format, under
    // a name the source file name turned into, never as pasted instructions.
    const dest_dir = try session.memoryDir(arena, &env, project_root);
    const note_text = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        try std.fmt.allocPrint(arena, "{s}/first-note.md", .{dest_dir}),
        arena,
        .limited(4096),
    );
    const entry = try chock_core.memory.parse(note_text);
    try testing.expectEqualStrings("first-note", entry.name);
    try testing.expectEqual(chock_core.memory.Kind.insight, entry.kind);
    try testing.expect(std.mem.indexOf(u8, entry.description, "claude-code") != null);
    try testing.expect(std.mem.indexOf(u8, entry.body, "an insight worth keeping") != null);
}

test "a harness with no pinned notes location is refused by name" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();

    const result = try importMemory(arena, testing.io, &env, "codex", "/somewhere");
    try testing.expectEqual(@as(usize, 0), result.carried);
    try testing.expectEqual(@as(usize, 1), result.refused.len);
    try testing.expect(std.mem.indexOf(u8, result.refused[0].reason, "not pinned") != null);
}
