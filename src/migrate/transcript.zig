//! `chock migrate --sessions`: bring a transcript from another harness
//! across as a new session, never as history Chock claims to have
//! witnessed.
//!
//! One new session log per transcript, holding exactly two events:
//! `session.start`, then `session.imported`. The foreign turns never become
//! `message` events: see `../migrate.zig`'s own `--sessions` documentation
//! for why. The transcript itself is copied beside the new session, mode
//! checked the way a credential is, so an agent can `read_file` it later
//! without the whole thing ever sitting in context.
//!
//! Only Claude Code has a pinned transcript location, read at
//! `~/.claude/projects/<slug>/<uuid>.jsonl` where `<slug>` is the project's
//! absolute path with every `/` turned into `-`. Every other harness is
//! refused: a guessed path is worse than no path.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_proto = @import("chock-proto");
const migrate = @import("../migrate.zig");
const session = @import("../session.zig");

const Refusal = migrate.Refusal;

/// The one harness this build reads a transcript location for.
pub const harness_name = "claude-code";

/// The most of one transcript line this build reads looking for `type` and
/// `timestamp`. A line past this is still hashed and copied whole; only its
/// own metadata is skipped, so one outsized turn cannot pull the whole
/// transcript into memory.
const max_line_scan_bytes: usize = 1 << 20;

/// One transcript that was copied in as a new session.
pub const Imported = struct {
    session_id: [session.id_length]u8,
    /// Where it was read on the machine that ran the import.
    source_path: []const u8,
    /// Where the copy this build made now lives.
    copy_path: []const u8,
    content_hash: [64]u8,
    messages: usize,
};

pub const Result = struct {
    harness: []const u8,
    imported: []const Imported = &.{},
    refused: []const Refusal = &.{},
};

/// Import every transcript `harness` has for `project_root`, each into its
/// own new session. Never touches an existing session.
/// One refusal, on the arena. **Never `&.{ ... }` holding a value read at run
/// time**: that takes the address of a temporary, and the slice dangles the
/// moment the function returns.
pub fn oneRefusal(
    arena: std.mem.Allocator,
    what: []const u8,
    reason: []const u8,
) std.mem.Allocator.Error![]const migrate.Refusal {
    const out = try arena.alloc(migrate.Refusal, 1);
    out[0] = .{ .what = what, .reason = reason };
    return out;
}

pub fn import(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    harness: []const u8,
    project_root: []const u8,
) !Result {
    if (!std.mem.eql(u8, harness, harness_name)) {
        return .{
            .harness = harness,
            .refused = try oneRefusal(arena, harness, "its transcript location is not pinned yet, so nothing was read"),
        };
    }

    const project_dir = homeProjectDir(arena, env, project_root) catch |err| return .{
        .harness = harness,
        .refused = try oneRefusal(arena, harness_name, try std.fmt.allocPrint(
            arena,
            "its transcript directory is unknown: {s}",
            .{@errorName(err)},
        )),
    };

    var names: std.ArrayList([]const u8) = .empty;
    {
        var dir = std.Io.Dir.openDirAbsolute(io, project_dir, .{ .iterate = true }) catch {
            // No such directory is not a fault: most projects have never
            // been opened with Claude Code.
            return .{ .harness = harness };
        };
        defer dir.close(io);
        var walker = dir.iterate();
        while (walker.next(io) catch null) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".jsonl")) continue;
            try names.append(arena, try arena.dupe(u8, entry.name));
        }
    }
    std.mem.sort([]const u8, names.items, {}, lessThanBytes);

    var imported: std.ArrayList(Imported) = .empty;
    var refused: std.ArrayList(Refusal) = .empty;

    for (names.items) |name| {
        const source_path = try std.fs.path.join(arena, &.{ project_dir, name });
        importOne(arena, io, env, project_root, harness, source_path, &imported) catch |err| {
            try refused.append(arena, .{
                .what = source_path,
                .reason = try std.fmt.allocPrint(arena, "could not be imported: {s}", .{@errorName(err)}),
            });
        };
    }

    return .{
        .harness = harness,
        .imported = try imported.toOwnedSlice(arena),
        .refused = try refused.toOwnedSlice(arena),
    };
}

/// Where a harness's own project directory lives under the user's home:
/// `~/.claude/projects/<slug>` for Claude Code. Both `--sessions` and
/// `--memory` read from here, which is the one place this build reads the
/// user's home rather than the project: a transcript and a notebook are the
/// user's own and live nowhere else, unlike a project's configuration.
pub fn homeProjectDir(
    arena: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) (std.mem.Allocator.Error || error{NoHomeDirectory})![]const u8 {
    const home = env.get("HOME") orelse return error.NoHomeDirectory;
    if (home.len == 0) return error.NoHomeDirectory;

    const slug = try arena.dupe(u8, project_root);
    for (slug) |*byte| {
        if (byte.* == '/') byte.* = '-';
    }
    return std.fs.path.join(arena, &.{ home, ".claude", "projects", slug });
}

fn importOne(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    harness: []const u8,
    source_path: []const u8,
    imported: *std.ArrayList(Imported),
) !void {
    const id = session.newId(io);
    const paths = try session.pathsFor(arena, env, project_root, &id);
    try session.create(io, paths);

    const copy_path = try std.fmt.allocPrint(arena, "{s}/{s}.transcript.jsonl", .{ paths.dir, id });
    const scanned = try scanAndCopy(arena, io, source_path, copy_path);

    var mode_fault: ?chock_auth.paths.Diagnostic = null;
    chock_auth.paths.requirePrivate(io, copy_path, &mode_fault) catch |err| {
        std.Io.Dir.deleteFileAbsolute(io, copy_path) catch {};
        return err;
    };

    var log = try chock_proto.log.Log.open(io, paths.log, id[0..]);
    defer log.close(io);
    var locked = try log.lock(io);
    defer locked.unlock(io) catch {};

    const now_ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
    _ = try locked.append(arena, io, .{ .session_start = .{
        .agent_kind = "import",
        .model_alias = "",
        .parent_session = "",
    } }, now_ms);
    _ = try locked.append(arena, io, .{ .session_imported = .{
        .from = harness,
        .source_path = source_path,
        .content_hash = scanned.hash[0..],
        .imported_ms = now_ms,
        .source_started_ms = scanned.source_started_ms,
        .source_ended_ms = scanned.source_ended_ms,
        .messages = scanned.messages,
    } }, now_ms);

    try imported.append(arena, .{
        .session_id = id,
        .source_path = source_path,
        .copy_path = copy_path,
        .content_hash = scanned.hash,
        .messages = scanned.messages,
    });
}

const Scanned = struct {
    hash: [64]u8,
    messages: usize,
    source_started_ms: i64,
    source_ended_ms: i64,
};

/// Copy `source_path` to `dest_path` one chunk at a time, hashing every byte
/// as it goes and reading `type` and `timestamp` out of each line. Never
/// holds more than one line in memory, so a transcript in the hundreds of
/// megabytes never sits in memory whole.
fn scanAndCopy(
    arena: std.mem.Allocator,
    io: std.Io,
    source_path: []const u8,
    dest_path: []const u8,
) !Scanned {
    var source = try std.Io.Dir.openFileAbsolute(io, source_path, .{});
    defer source.close(io);

    var dest = try std.Io.Dir.createFileAbsolute(io, dest_path, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer dest.close(io);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var messages: usize = 0;
    var first_ms: ?i64 = null;
    var last_ms: i64 = 0;

    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(arena);
    var overflowed = false;

    var pos: u64 = 0;
    var read_buffer: [4096]u8 = undefined;
    while (true) {
        const n = try source.readPositionalAll(io, &read_buffer, pos);
        if (n == 0) break;
        pos += n;
        hasher.update(read_buffer[0..n]);
        try dest.writeStreamingAll(io, read_buffer[0..n]);

        var chunk = read_buffer[0..n];
        while (std.mem.indexOfScalar(u8, chunk, '\n')) |cut| {
            if (!overflowed) {
                try line.appendSlice(arena, chunk[0..cut]);
                scanLine(arena, line.items, &messages, &first_ms, &last_ms);
            }
            line.clearRetainingCapacity();
            overflowed = false;
            chunk = chunk[cut + 1 ..];
        }
        if (chunk.len != 0) {
            if (!overflowed) try line.appendSlice(arena, chunk);
            if (line.items.len > max_line_scan_bytes) overflowed = true;
        }
    }
    if (line.items.len != 0 and !overflowed) {
        scanLine(arena, line.items, &messages, &first_ms, &last_ms);
    }

    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    return .{
        .hash = std.fmt.bytesToHex(digest, .lower),
        .messages = messages,
        .source_started_ms = first_ms orelse 0,
        .source_ended_ms = last_ms,
    };
}

const TranscriptLine = struct {
    type: []const u8 = "",
    timestamp: []const u8 = "",
};

/// A line that is not valid JSON, or holds neither field, counts for
/// nothing and stops nothing: most of the lines Claude Code writes are
/// internal bookkeeping this build has no use for.
fn scanLine(
    arena: std.mem.Allocator,
    bytes: []const u8,
    messages: *usize,
    first_ms: *?i64,
    last_ms: *i64,
) void {
    if (bytes.len == 0) return;
    const parsed = std.json.parseFromSliceLeaky(TranscriptLine, arena, bytes, .{
        .ignore_unknown_fields = true,
    }) catch return;

    if (std.mem.eql(u8, parsed.type, "user") or std.mem.eql(u8, parsed.type, "assistant")) {
        messages.* += 1;
    }
    if (parseTimestampMs(parsed.timestamp)) |ms| {
        if (first_ms.* == null) first_ms.* = ms;
        last_ms.* = ms;
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.fff]Z` to milliseconds since the epoch, or null for
/// anything else. This is the one shape `Date.prototype.toISOString` writes,
/// which is what Claude Code's own transcripts carry.
fn parseTimestampMs(text: []const u8) ?i64 {
    if (text.len < 20) return null;
    if (text[4] != '-' or text[7] != '-' or text[10] != 'T' or
        text[13] != ':' or text[16] != ':' or text[text.len - 1] != 'Z') return null;

    const year = std.fmt.parseInt(i64, text[0..4], 10) catch return null;
    const month = std.fmt.parseInt(u8, text[5..7], 10) catch return null;
    const day = std.fmt.parseInt(u8, text[8..10], 10) catch return null;
    const hour = std.fmt.parseInt(i64, text[11..13], 10) catch return null;
    const minute = std.fmt.parseInt(i64, text[14..16], 10) catch return null;
    const second = std.fmt.parseInt(i64, text[17..19], 10) catch return null;
    if (month < 1 or month > 12 or day < 1 or day > 31) return null;

    var millis: i64 = 0;
    const frac = text[19 .. text.len - 1];
    if (frac.len != 0) {
        if (frac[0] != '.') return null;
        var digits: [3]u8 = .{ '0', '0', '0' };
        for (frac[1..], 0..) |c, i| {
            if (!std.ascii.isDigit(c)) return null;
            if (i < 3) digits[i] = c;
        }
        millis = std.fmt.parseInt(i64, &digits, 10) catch return null;
    }

    const days = daysFromCivil(year, month, day);
    const seconds = days * 86400 + hour * 3600 + minute * 60 + second;
    return seconds * 1000 + millis;
}

/// Days since 1970-01-01 for a proleptic Gregorian date. Howard Hinnant's
/// `days_from_civil`, the standard closed form for this.
fn daysFromCivil(year: i64, month: u8, day: u8) i64 {
    const y: i64 = if (month <= 2) year - 1 else year;
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const year_of_era = y - era * 400;
    const month_index = @mod(@as(i64, month) + 9, 12);
    const day_of_year = @divFloor(153 * month_index + 2, 5) + @as(i64, day) - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100) + day_of_year;
    return era * 146097 + day_of_era - 719468;
}

fn lessThanBytes(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

const testing = std.testing;

test "parseTimestampMs matches known epoch values" {
    try testing.expectEqual(@as(?i64, 0), parseTimestampMs("1970-01-01T00:00:00.000Z"));
    try testing.expectEqual(@as(?i64, 1704067200000), parseTimestampMs("2024-01-01T00:00:00.000Z"));
    try testing.expectEqual(@as(?i64, 1704067200500), parseTimestampMs("2024-01-01T00:00:00.5Z"));
    try testing.expectEqual(@as(?i64, null), parseTimestampMs("not a timestamp"));
    try testing.expectEqual(@as(?i64, null), parseTimestampMs("2024-01-01T00:00:00"));
}

fn writeSourceFile(io: std.Io, dir: []const u8, name: []const u8, contents: []const u8) !void {
    try std.Io.Dir.cwd().createDirPath(io, dir);
    const full = try std.fs.path.join(testing.allocator, &.{ dir, name });
    defer testing.allocator.free(full);
    var file = try std.Io.Dir.cwd().createFile(io, full, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
}

test "a transcript import writes session.start then session.imported and no message event" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var home = testing.tmpDir(.{});
    defer home.cleanup();
    var home_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const home_len = try home.dir.realPath(testing.io, &home_buffer);
    const home_path = home_buffer[0..home_len];

    var state = testing.tmpDir(.{});
    defer state.cleanup();
    var state_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const state_len = try state.dir.realPath(testing.io, &state_buffer);
    const state_path = state_buffer[0..state_len];

    const project_root = "/home/somebody/work/parser";
    const slug = "-home-somebody-work-parser";
    const project_dir = try std.fs.path.join(arena, &.{ home_path, ".claude", "projects", slug });

    const transcript_text =
        \\{"type":"user","timestamp":"2026-09-24T10:00:00.000Z","message":"hi"}
        \\{"type":"assistant","timestamp":"2026-09-24T10:00:01.000Z","message":"hello"}
        \\{"type":"system","timestamp":"2026-09-24T10:00:02.000Z"}
        \\
    ;
    try writeSourceFile(testing.io, project_dir, "01H0EXAMPLE.jsonl", transcript_text);

    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();
    try env.put("HOME", home_path);
    try env.put("XDG_STATE_HOME", state_path);

    const result = try import(arena, testing.io, &env, "claude-code", project_root);
    try testing.expectEqual(@as(usize, 1), result.imported.len);
    try testing.expectEqual(@as(usize, 0), result.refused.len);

    const one = result.imported[0];
    try testing.expectEqual(@as(usize, 2), one.messages);
    try testing.expectEqualStrings(&hashOf(transcript_text), &one.content_hash);

    const reread = try session.pathsFor(arena, &env, project_root, &one.session_id);
    var chock_log = try chock_proto.log.Log.open(testing.io, reread.log, one.session_id[0..]);
    defer chock_log.close(testing.io);

    var replay = try chock_log.replayFrom(testing.allocator, testing.io, 0);
    defer replay.deinit();

    const first = (try replay.next(testing.io)).?;
    defer first.deinit();
    try testing.expectEqual(chock_proto.event.Kind.session_start, std.meta.activeTag(first.value.event));

    const second = (try replay.next(testing.io)).?;
    defer second.deinit();
    try testing.expectEqual(chock_proto.event.Kind.session_imported, std.meta.activeTag(second.value.event));
    try testing.expectEqualStrings(&one.content_hash, second.value.event.session_imported.content_hash);
    try testing.expectEqual(@as(usize, 2), second.value.event.session_imported.messages);

    try testing.expect((try replay.next(testing.io)) == null);

    const copy_text = try std.Io.Dir.cwd().readFileAlloc(testing.io, one.copy_path, arena, .limited(1 << 16));
    try testing.expectEqualStrings(transcript_text, copy_text);
}

fn hashOf(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

test "a harness with no pinned transcript location is refused by name" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();

    const result = try import(arena, testing.io, &env, "codex", "/somewhere");
    try testing.expectEqual(@as(usize, 0), result.imported.len);
    try testing.expectEqual(@as(usize, 1), result.refused.len);
    try testing.expect(std.mem.indexOf(u8, result.refused[0].reason, "not pinned") != null);
}
