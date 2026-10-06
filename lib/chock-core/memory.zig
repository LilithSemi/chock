//! The knowledgebase, written out: what an agent worked out in one
//! session and does not have to work out again in the next.

const std = @import("std");
const index = @import("index.zig");

pub const sandbox_dir = "/run/chock/memory";

pub const extension = ".md";

pub const max_name_bytes: usize = 64;

pub const max_body_bytes: usize = 16 * 1024;

pub const max_entries: usize = 128;

pub const max_versions: usize = 16;

pub const max_entry_bytes: usize = max_versions * (max_body_bytes + 4 * 1024);

pub const Kind = enum {
    insight,
    code_fact,
    convention,
    gotcha,
    dead_end,
    environment,

    pub fn parse(text: []const u8) ?Kind {
        return std.meta.stringToEnum(Kind, text);
    }
};

pub const Entry = struct {
    name: []const u8,
    description: []const u8,
    kind: Kind,
    written_at: []const u8,
    session: []const u8 = "",
    version: usize = 1,
    body: []const u8,
};

pub const NameError = error{
    BadName,
};

pub fn checkName(name: []const u8) NameError!void {
    if (name.len == 0 or name.len > max_name_bytes) return error.BadName;
    if (name[0] == '-' or name[0] == '_') return error.BadName;
    for (name) |byte| switch (byte) {
        'a'...'z', '0'...'9', '-', '_' => {},
        else => return error.BadName,
    };
}

pub fn fileName(allocator: std.mem.Allocator, name: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}" ++ extension, .{name});
}

pub fn serialize(allocator: std.mem.Allocator, entry: Entry) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const description = try index.oneLine(allocator, entry.description);
    defer allocator.free(description);

    const added_newline: usize =
        if (entry.body.len != 0 and entry.body[entry.body.len - 1] != '\n') 1 else 0;

    try out.print(allocator, "name: {s}\n", .{entry.name});
    try out.print(allocator, "kind: {t}\n", .{entry.kind});
    try out.print(allocator, "version: {d}\n", .{entry.version});
    try out.print(allocator, "written_at: {s}\n", .{entry.written_at});
    try out.print(allocator, "session: {s}\n", .{entry.session});
    try out.print(allocator, "bytes: {d}\n", .{entry.body.len + added_newline});
    try out.print(allocator, "description: {s}\n", .{description});
    try out.appendSlice(allocator, "\n");
    try out.appendSlice(allocator, entry.body);
    if (added_newline == 1) try out.append(allocator, '\n');
    return out.toOwnedSlice(allocator);
}

pub fn addVersion(
    allocator: std.mem.Allocator,
    existing: []const u8,
    entry: Entry,
) std.mem.Allocator.Error![]u8 {
    var next = entry;
    next.version = versionsIn(existing) + 1;

    const head = try serialize(allocator, next);
    if (existing.len == 0) return head;
    defer allocator.free(head);

    return std.mem.concat(allocator, u8, &.{ head, "\n", existing });
}

pub fn versionsIn(text: []const u8) usize {
    if (text.len == 0) return 0;
    const top = parse(text) catch return 0;
    return top.version;
}

pub const ParseError = error{
    NotAnEntry,
};

pub fn parse(text: []const u8) ParseError!Entry {
    return (try parseRecord(text)).entry;
}

const Record = struct {
    entry: Entry,
    rest: []const u8,
};

fn parseRecord(text: []const u8) ParseError!Record {
    var entry: Entry = .{
        .name = "",
        .description = "",
        .kind = .insight,
        .written_at = "",
        .session = "",
        .body = "",
    };
    var declared_body_bytes: ?usize = null;

    var rest = text;
    while (rest.len != 0) {
        const line_end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..line_end];
        rest = if (line_end == rest.len) rest[rest.len..] else rest[line_end + 1 ..];

        if (std.mem.trim(u8, line, " \t\r").len == 0) break;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..colon], " \t\r");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t\r");

        if (std.mem.eql(u8, key, "name")) {
            entry.name = value;
        } else if (std.mem.eql(u8, key, "description")) {
            entry.description = value;
        } else if (std.mem.eql(u8, key, "kind")) {
            entry.kind = Kind.parse(value) orelse .insight;
        } else if (std.mem.eql(u8, key, "written_at")) {
            entry.written_at = value;
        } else if (std.mem.eql(u8, key, "date")) {
            if (entry.written_at.len == 0) entry.written_at = value;
        } else if (std.mem.eql(u8, key, "session")) {
            entry.session = value;
        } else if (std.mem.eql(u8, key, "version")) {
            entry.version = std.fmt.parseInt(usize, value, 10) catch 1;
        } else if (std.mem.eql(u8, key, "bytes")) {
            declared_body_bytes = std.fmt.parseInt(usize, value, 10) catch null;
        }
    }

    if (entry.name.len == 0) return error.NotAnEntry;

    const declared = declared_body_bytes orelse {
        entry.body = rest;
        return .{ .entry = entry, .rest = "" };
    };
    const take = @min(declared, rest.len);
    entry.body = rest[0..take];
    return .{ .entry = entry, .rest = rest[take..] };
}

pub const Versions = struct {
    rest: []const u8,

    pub fn next(self: *Versions) ?Entry {
        while (self.rest.len != 0 and (self.rest[0] == '\n' or self.rest[0] == '\r')) {
            self.rest = self.rest[1..];
        }
        if (self.rest.len == 0) return null;

        const record = parseRecord(self.rest) catch {
            self.rest = "";
            return null;
        };
        self.rest = record.rest;
        return record.entry;
    }
};

pub fn versions(text: []const u8) Versions {
    return .{ .rest = text };
}

pub fn newestVersion(text: []const u8) []const u8 {
    var walk = versions(text);
    _ = walk.next() orelse return text;
    return text[0 .. text.len - walk.rest.len];
}

pub const timestamp_bytes: usize = 20;

pub fn now(io: std.Io, buffer: *[timestamp_bytes]u8) []const u8 {
    const ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
    const seconds: u64 = if (ms > 0) @intCast(@divFloor(ms, std.time.ms_per_s)) else 0;
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();
    return std.fmt.bufPrint(buffer, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    }) catch unreachable;
}

pub const Listed = struct {
    name: []const u8,
    description: []const u8,
    kind: Kind,
    written_at: []const u8,
    versions: usize = 1,
};

pub fn list(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir_path: []const u8,
) std.mem.Allocator.Error![]const Listed {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return &.{};
    defer dir.close(io);

    var listed: std.ArrayList(Listed) = .empty;
    errdefer listed.deinit(allocator);

    var it = dir.iterate();
    while (it.next(io) catch null) |dir_entry| {
        if (dir_entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, dir_entry.name, extension)) continue;

        const text = dir.readFileAlloc(io, dir_entry.name, allocator, .limited(header_read_bytes)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => (try readFront(allocator, io, dir, dir_entry.name)) orelse continue,
            else => continue,
        };
        const parsed = parse(text) catch continue;
        try listed.append(allocator, .{
            .name = parsed.name,
            .description = parsed.description,
            .kind = parsed.kind,
            .written_at = parsed.written_at,
            .versions = parsed.version,
        });
    }

    std.mem.sort(Listed, listed.items, {}, lessThanName);
    return listed.toOwnedSlice(allocator);
}

const header_read_bytes: usize = 4 * 1024;

fn readFront(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) std.mem.Allocator.Error!?[]u8 {
    var file = dir.openFile(io, sub_path, .{}) catch return null;
    defer file.close(io);

    var text = try allocator.alloc(u8, header_read_bytes);
    errdefer allocator.free(text);

    var filled: usize = 0;
    while (filled < text.len) {
        const n = file.readStreaming(io, &.{text[filled..]}) catch break;
        if (n == 0) break;
        filled += n;
    }
    if (filled != text.len) text = try allocator.realloc(text, filled);
    return text;
}

fn lessThanName(_: void, a: Listed, b: Listed) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

pub fn indexOf(
    allocator: std.mem.Allocator,
    entries: []const Listed,
) std.mem.Allocator.Error![]index.Entry {
    const out = try allocator.alloc(index.Entry, entries.len);
    for (entries, out) |entry, *line| {
        line.* = .{ .name = entry.name, .description = entry.description };
    }
    return out;
}

pub fn count(io: std.Io, dir_path: []const u8) usize {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return 0;
    defer dir.close(io);

    var total: usize = 0;
    var it = dir.iterate();
    while (it.next(io) catch null) |dir_entry| {
        if (dir_entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, dir_entry.name, extension)) continue;
        total += 1;
    }
    return total;
}

pub fn forget(io: std.Io, dir_path: []const u8, name: []const u8) !void {
    try checkName(name);
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);

    var buffer: [max_name_bytes + extension.len]u8 = undefined;
    const file = std.fmt.bufPrint(&buffer, "{s}" ++ extension, .{name}) catch unreachable;
    try dir.deleteFile(io, file);
}

pub fn clear(allocator: std.mem.Allocator, io: std.Io, dir_path: []const u8) std.mem.Allocator.Error!usize {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return 0;
    defer dir.close(io);

    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |name| allocator.free(name);
        names.deinit(allocator);
    }

    var it = dir.iterate();
    while (it.next(io) catch null) |dir_entry| {
        if (dir_entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, dir_entry.name, extension)) continue;
        try names.append(allocator, try allocator.dupe(u8, dir_entry.name));
    }

    var removed: usize = 0;
    for (names.items) |name| {
        dir.deleteFile(io, name) catch continue;
        removed += 1;
    }
    return removed;
}

const testing = std.testing;

test "an entry round trips through the file format, body and all" {
    const allocator = testing.allocator;
    const entry: Entry = .{
        .name = "mount-order",
        .description = "the kernel takes the last matching mount, not the longest prefix",
        .kind = .gotcha,
        .written_at = "2026-08-21T09:15:00Z",
        .session = "01ABC",
        .body = "Binding /run over /run/chock hides everything under it.\n",
    };

    const text = try serialize(allocator, entry);
    defer allocator.free(text);

    const back = try parse(text);
    try testing.expectEqualStrings(entry.name, back.name);
    try testing.expectEqualStrings(entry.description, back.description);
    try testing.expectEqual(Kind.gotcha, back.kind);
    try testing.expectEqualStrings(entry.written_at, back.written_at);
    try testing.expectEqualStrings(entry.session, back.session);
    try testing.expectEqualStrings(entry.body, back.body);
    try testing.expectEqual(@as(usize, 1), back.version);
}

test "writing a name again adds a version and the one before it is still readable" {
    const allocator = testing.allocator;

    const first = try addVersion(allocator, "", .{
        .name = "mount-order",
        .description = "the first reading",
        .kind = .code_fact,
        .written_at = "2026-08-21T09:15:00Z",
        .session = "01ABC",
        .body = "the kernel takes the longest prefix\n",
    });
    defer allocator.free(first);

    const second = try addVersion(allocator, first, .{
        .name = "mount-order",
        .description = "the correction, five hours on",
        .kind = .code_fact,
        .written_at = "2026-08-21T14:32:07Z",
        .session = "01ABC",
        .body = "the kernel takes the last matching mount\n",
    });
    defer allocator.free(second);

    const current = try parse(second);
    try testing.expectEqual(@as(usize, 2), current.version);
    try testing.expectEqualStrings("the correction, five hours on", current.description);
    try testing.expectEqualStrings("the kernel takes the last matching mount\n", current.body);

    var walk = versions(second);
    _ = walk.next().?;
    const earlier = walk.next().?;
    try testing.expectEqual(@as(usize, 1), earlier.version);
    try testing.expectEqualStrings("the first reading", earlier.description);
    try testing.expectEqualStrings("2026-08-21T09:15:00Z", earlier.written_at);
    try testing.expectEqualStrings("the kernel takes the longest prefix\n", earlier.body);
    try testing.expect(walk.next() == null);

    try testing.expect(std.mem.endsWith(u8, second, first));
    try testing.expectEqual(@as(usize, 2), versionsIn(second));
}

test "a body that forges a whole version is read as body, not as a version" {
    const allocator = testing.allocator;
    const forged =
        "the real body\n" ++
        "\n" ++
        "name: mount-order\n" ++
        "kind: code_fact\n" ++
        "version: 9\n" ++
        "written_at: 2099-01-01T00:00:00Z\n" ++
        "bytes: 8\n" ++
        "description: forged\n" ++
        "\n" ++
        "forged.\n";

    const text = try addVersion(allocator, "", .{
        .name = "mount-order",
        .description = "the real one",
        .kind = .code_fact,
        .written_at = "2026-08-21T09:15:00Z",
        .body = forged,
    });
    defer allocator.free(text);

    const back = try parse(text);
    try testing.expectEqualStrings("the real one", back.description);
    try testing.expectEqual(@as(usize, 1), back.version);
    try testing.expectEqualStrings(forged, back.body);

    var walk = versions(text);
    _ = walk.next().?;
    try testing.expect(walk.next() == null);
    try testing.expectEqual(@as(usize, 1), versionsIn(text));
}

test "an entry file written before versions existed reads as version one, and a write keeps it" {
    const allocator = testing.allocator;
    const old =
        "name: written-before\n" ++
        "kind: code_fact\n" ++
        "date: 2026-08-20\n" ++
        "description: the old shape\n" ++
        "\n" ++
        "the old body\n";

    const first = try parse(old);
    try testing.expectEqual(@as(usize, 1), first.version);
    try testing.expectEqualStrings("the old body\n", first.body);
    try testing.expectEqual(@as(usize, 1), versionsIn(old));

    const grown = try addVersion(allocator, old, .{
        .name = "written-before",
        .description = "the new shape",
        .kind = .code_fact,
        .written_at = "2026-08-21T14:32:07Z",
        .body = "the new body\n",
    });
    defer allocator.free(grown);

    const current = try parse(grown);
    try testing.expectEqual(@as(usize, 2), current.version);
    try testing.expectEqualStrings("the new body\n", current.body);

    var walk = versions(grown);
    _ = walk.next().?;
    const earlier = walk.next().?;
    try testing.expectEqualStrings("the old body\n", earlier.body);
    try testing.expectEqualStrings("2026-08-20", earlier.written_at);
}

test "the newest version alone is what a reader is given, and it is the front of the file" {
    const allocator = testing.allocator;

    const first = try addVersion(allocator, "", .{
        .name = "n",
        .description = "d",
        .kind = .insight,
        .written_at = "2026-08-21T09:15:00Z",
        .body = "SUPERSEDED-BODY\n",
    });
    defer allocator.free(first);
    const second = try addVersion(allocator, first, .{
        .name = "n",
        .description = "d",
        .kind = .insight,
        .written_at = "2026-08-21T14:32:07Z",
        .body = "CURRENT-BODY\n",
    });
    defer allocator.free(second);

    const newest = newestVersion(second);
    try testing.expect(std.mem.indexOf(u8, newest, "CURRENT-BODY") != null);
    try testing.expect(std.mem.indexOf(u8, newest, "SUPERSEDED-BODY") == null);
    try testing.expect(std.mem.startsWith(u8, second, newest));

    try testing.expectEqualStrings("just prose\n", newestVersion("just prose\n"));
}

test "a body that looks like a header stays body" {
    const allocator = testing.allocator;
    const text = try serialize(allocator, .{
        .name = "real-name",
        .description = "one line",
        .kind = .insight,
        .written_at = "2026-08-21T09:15:00Z",
        .body = "name: forged-name\ndescription: forged\n",
    });
    defer allocator.free(text);

    const back = try parse(text);
    try testing.expectEqualStrings("real-name", back.name);
    try testing.expectEqualStrings("one line", back.description);
    try testing.expect(std.mem.indexOf(u8, back.body, "forged-name") != null);
}

test "a description with a newline in it becomes one line in the file" {
    const allocator = testing.allocator;
    const text = try serialize(allocator, .{
        .name = "n",
        .description = "first line\nsecond line",
        .kind = .insight,
        .written_at = "2026-08-21T09:15:00Z",
        .body = "body\n",
    });
    defer allocator.free(text);

    const back = try parse(text);
    try testing.expectEqualStrings("first line second line", back.description);
}

test "a name is a plain name, so there is no path to leave the directory through" {
    try checkName("mount-order");
    try checkName("a1_b-c");

    try testing.expectError(error.BadName, checkName(""));
    try testing.expectError(error.BadName, checkName(".."));
    try testing.expectError(error.BadName, checkName("../../etc/passwd"));
    try testing.expectError(error.BadName, checkName("a/b"));
    try testing.expectError(error.BadName, checkName("a.b"));
    try testing.expectError(error.BadName, checkName("-rf"));
    try testing.expectError(error.BadName, checkName("Upper"));
    try testing.expectError(error.BadName, checkName("a" ** (max_name_bytes + 1)));
}

test "an entry a person edited by hand is still readable, and an unknown kind is not fatal" {
    const back = try parse(
        \\name: hand-written
        \\kind: something-a-newer-chock-writes
        \\future-field: ignored
        \\
        \\the body
        \\
    );
    try testing.expectEqualStrings("hand-written", back.name);
    try testing.expectEqual(Kind.insight, back.kind);
    try testing.expectEqualStrings("", back.written_at);
    try testing.expectEqualStrings("the body\n", back.body);
}

test "a file that is not an entry at all is refused rather than read as a blank one" {
    try testing.expectError(error.NotAnEntry, parse("just some prose somebody dropped in\n"));
}

test "the timestamp carries a time of day, and it is the same shape whatever the clock says" {
    var buffer: [timestamp_bytes]u8 = undefined;
    const stamp = now(testing.io, &buffer);
    try testing.expectEqual(timestamp_bytes, stamp.len);
    try testing.expectEqual(@as(u8, '-'), stamp[4]);
    try testing.expectEqual(@as(u8, '-'), stamp[7]);
    try testing.expectEqual(@as(u8, 'T'), stamp[10]);
    try testing.expectEqual(@as(u8, ':'), stamp[13]);
    try testing.expectEqual(@as(u8, ':'), stamp[16]);
    try testing.expectEqual(@as(u8, 'Z'), stamp[19]);
    for (stamp, 0..) |byte, i| {
        if (i == 4 or i == 7 or i == 10 or i == 13 or i == 16 or i == 19) continue;
        try testing.expect(byte >= '0' and byte <= '9');
    }
}

test "two entries written in one session are ordered by their timestamps, which the session identifier cannot do" {
    const allocator = testing.allocator;

    const earlier = try serialize(allocator, .{
        .name = "mount-order",
        .description = "the first reading",
        .kind = .code_fact,
        .written_at = "2026-08-21T09:15:00Z",
        .session = "01ABC",
        .body = "the kernel takes the longest prefix\n",
    });
    defer allocator.free(earlier);
    const later = try serialize(allocator, .{
        .name = "mount-order",
        .description = "the correction, five hours on",
        .kind = .code_fact,
        .written_at = "2026-08-21T14:32:07Z",
        .session = "01ABC",
        .body = "the kernel takes the last matching mount\n",
    });
    defer allocator.free(later);

    const first = try parse(earlier);
    const second = try parse(later);

    try testing.expectEqualStrings(first.session, second.session);
    try testing.expectEqualStrings(first.written_at[0..10], second.written_at[0..10]);
    try testing.expect(std.mem.lessThan(u8, first.written_at, second.written_at));
}

test "an entry written before this field carried a clock still reads, and still sorts" {
    const old = try parse(
        \\name: written-before
        \\kind: code_fact
        \\date: 2026-08-20
        \\
        \\the body
        \\
    );
    try testing.expectEqualStrings("2026-08-20", old.written_at);

    try testing.expect(std.mem.lessThan(u8, old.written_at, "2026-08-20T00:00:01Z"));
    try testing.expect(std.mem.lessThan(u8, old.written_at, "2026-08-21T09:15:00Z"));
}

fn writeEntries(io: std.Io, dir: std.Io.Dir, allocator: std.mem.Allocator, entries: []const Entry) !void {
    for (entries) |entry| {
        const name = try fileName(allocator, entry.name);
        defer allocator.free(name);

        const existing = dir.readFileAlloc(io, name, allocator, .limited(max_entry_bytes)) catch "";
        defer if (existing.len != 0) allocator.free(existing);

        const text = try addVersion(allocator, existing, entry);
        defer allocator.free(text);

        var file = try dir.createFile(io, name, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, text);
    }
}

test "listing a knowledgebase reads the headers, sorts by name, and never reads a body" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const big_body = try arena.alloc(u8, max_body_bytes);
    @memset(big_body, 'x');
    try writeEntries(testing.io, tmp.dir, arena, &.{
        .{ .name = "zeta", .description = "the last one", .kind = .convention, .written_at = "2026-01-02T00:00:00Z", .body = "b\n" },
        .{ .name = "alpha", .description = "the first one", .kind = .dead_end, .written_at = "2026-01-01T00:00:00Z", .body = big_body },
    });
    try writeEntries(testing.io, tmp.dir, arena, &.{});
    {
        var stray = try tmp.dir.createFile(testing.io, "notes.txt", .{});
        defer stray.close(testing.io);
        try stray.writeStreamingAll(testing.io, "not an entry\n");
    }

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const dir_path = buffer[0..len];

    const entries = try list(arena, testing.io, dir_path);
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqualStrings("alpha", entries[0].name);
    try testing.expectEqualStrings("zeta", entries[1].name);
    try testing.expectEqual(Kind.dead_end, entries[0].kind);
    try testing.expectEqualStrings("2026-01-01T00:00:00Z", entries[0].written_at);

    const lines = try indexOf(arena, entries);
    try testing.expectEqual(@as(usize, 2), lines.len);
    for (lines) |line| try testing.expect(std.mem.indexOf(u8, line.description, "xxxx") == null);

    try testing.expectEqual(@as(usize, 2), count(testing.io, dir_path));
}

test "listing says how many versions a name holds, and still never reads a body" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const big_body = try arena.alloc(u8, max_body_bytes);
    @memset(big_body, 'x');

    try writeEntries(testing.io, tmp.dir, arena, &.{
        .{ .name = "once", .description = "written one time", .kind = .insight, .written_at = "2026-01-01T00:00:00Z", .body = "b\n" },
        .{ .name = "twice", .description = "the first reading", .kind = .code_fact, .written_at = "2026-01-01T00:00:00Z", .body = big_body },
        .{ .name = "twice", .description = "the correction", .kind = .code_fact, .written_at = "2026-01-02T00:00:00Z", .body = big_body },
    });

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const dir_path = buffer[0..len];

    const entries = try list(arena, testing.io, dir_path);
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqualStrings("once", entries[0].name);
    try testing.expectEqual(@as(usize, 1), entries[0].versions);
    try testing.expectEqualStrings("twice", entries[1].name);
    try testing.expectEqual(@as(usize, 2), entries[1].versions);
    try testing.expectEqualStrings("the correction", entries[1].description);

    try testing.expectEqual(@as(usize, 2), count(testing.io, dir_path));
}

test "a knowledgebase that was never written is empty, not an error" {
    const allocator = testing.allocator;
    const entries = try list(allocator, testing.io, "/there/is/no/such/directory/anywhere");
    defer allocator.free(entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
    try testing.expectEqual(@as(usize, 0), count(testing.io, "/there/is/no/such/directory/anywhere"));
}

test "clearing removes every entry and leaves a stranger's file alone" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeEntries(testing.io, tmp.dir, arena, &.{
        .{ .name = "one", .description = "d", .kind = .insight, .written_at = "2026-01-01T00:00:00Z", .body = "b\n" },
        .{ .name = "two", .description = "d", .kind = .insight, .written_at = "2026-01-01T00:00:00Z", .body = "b\n" },
    });
    {
        var stray = try tmp.dir.createFile(testing.io, "README", .{});
        defer stray.close(testing.io);
        try stray.writeStreamingAll(testing.io, "not Chock's\n");
    }

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const dir_path = buffer[0..len];

    try testing.expectEqual(@as(usize, 2), try clear(arena, testing.io, dir_path));
    try testing.expectEqual(@as(usize, 0), count(testing.io, dir_path));
    _ = try tmp.dir.statFile(testing.io, "README", .{});
}

test "forgetting one entry removes that one and no other" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeEntries(testing.io, tmp.dir, arena, &.{
        .{ .name = "keep", .description = "d", .kind = .insight, .written_at = "2026-01-01T00:00:00Z", .body = "b\n" },
        .{ .name = "drop", .description = "d", .kind = .insight, .written_at = "2026-01-01T00:00:00Z", .body = "b\n" },
    });

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const dir_path = buffer[0..len];

    try forget(testing.io, dir_path, "drop");
    const entries = try list(arena, testing.io, dir_path);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqualStrings("keep", entries[0].name);

    try testing.expectError(error.BadName, forget(testing.io, dir_path, "../keep"));
}
