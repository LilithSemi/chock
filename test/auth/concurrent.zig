//! Two terminals, one credential store. Real processes, never several calls in
//! one test binary, because `flock` locks an open file description and two
//! `Store.put` calls here would say nothing about two `chock login` commands.

const std = @import("std");
const chock_auth = @import("chock-auth");

// The test runner panics on unknown argv, so build.zig embeds the helper path.
const helper_path = @import("login_helper_path").login_helper_path;

/// The helper's exit statuses, kept in step with `test/auth/login_helper.zig`.
const stored = 0;
const busy = 1;
const name_taken = 5;

/// The first `stored_ms`. Each helper adds its index, so an entry names a login.
const first_stored_ms: i64 = 1_700_000_000_000;

const lead_ms: i64 = 200;

const Outcome = struct {
    failures: usize = 0,
    busy: usize = 0,
    unsound: usize = 0,
    stored: usize = 0,
    refused: usize = 0,
};

/// `replace` is a login that was given `--name`. `refuse` is one given none.
const IfPresent = enum {
    replace,
    refuse,

    fn argument(self: IfPresent) []const u8 {
        return @tagName(self);
    }
};

const ParsedIndex = struct {
    version: u32 = 0,
    instances: []const Instance = &.{},

    const Instance = struct {
        name: []const u8,
        kind: []const u8,
        base_url: []const u8 = "",
        stored_ms: i64,
    };
};

/// `distinct` gives every login its own name, the shape that shows a lost update.
fn raceOnce(
    allocator: std.mem.Allocator,
    io: std.Io,
    count: usize,
    distinct: bool,
    if_present: IfPresent,
) !Outcome {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(io, &buffer);
    const data_dir = try std.fs.path.join(allocator, &.{ buffer[0..length], "share", "chock" });
    defer allocator.free(data_dir);

    const names = try allocator.alloc([]u8, count);
    const tokens = try allocator.alloc([]u8, count);
    defer {
        for (names) |name| allocator.free(name);
        for (tokens) |token| allocator.free(token);
        allocator.free(names);
        allocator.free(tokens);
    }
    for (names, tokens, 0..) |*name, *token, i| {
        name.* = if (distinct)
            try std.fmt.allocPrint(allocator, "instance-{d}", .{i})
        else
            try allocator.dupe(u8, "work");
        // Of different lengths, because one length hides the worst mixture.
        var padding: [40]u8 = undefined;
        const width = 4 + i * 5;
        @memset(padding[0..width], 'x');
        token.* = try std.fmt.allocPrint(allocator, "sk-{d}-{s}", .{ i, padding[0..width] });
    }

    const children = try allocator.alloc(std.process.Child, count);
    defer allocator.free(children);

    const start_ms = std.Io.Timestamp.now(io, .real).toMilliseconds() + lead_ms;
    // All are started before any is waited for, and all wait for one instant.
    for (children, names, tokens, 0..) |*child, name, token, i| {
        var ms_text: [24]u8 = undefined;
        var start_text: [24]u8 = undefined;
        child.* = try std.process.spawn(io, .{
            .argv = &.{
                helper_path,
                data_dir,
                name,
                token,
                try std.fmt.bufPrint(&ms_text, "{d}", .{first_stored_ms + @as(i64, @intCast(i))}),
                try std.fmt.bufPrint(&start_text, "{d}", .{start_ms}),
                if_present.argument(),
            },
            .stdin = .ignore,
            // `zig build` reads a binary that wrote to standard error as failed.
            .stdout = .ignore,
            .stderr = .ignore,
        });
    }

    var outcome = Outcome{};
    for (children) |*child| {
        const status: u8 = switch (try child.wait(io)) {
            .exited => |code| code,
            else => 255,
        };
        switch (status) {
            stored => outcome.stored += 1,
            busy => outcome.busy += 1,
            name_taken => outcome.refused += 1,
            else => outcome.failures += 1,
        }
    }

    outcome.unsound = try soundness(allocator, io, data_dir, names, tokens, distinct);
    return outcome;
}

fn soundness(
    allocator: std.mem.Allocator,
    io: std.Io,
    data_dir: []const u8,
    names: []const []u8,
    tokens: []const []u8,
    distinct: bool,
) !usize {
    var wrong: usize = 0;
    const driver = chock_auth.store.Driver{ .data_dir = data_dir };

    const parsed = parseIndex(allocator, io, data_dir) catch return names.len;
    defer std.zon.parse.free(allocator, parsed);

    if (parsed.version != 1) wrong += 1;
    if (parsed.instances.len != (if (distinct) names.len else 1)) wrong += 1;

    var seen = try allocator.alloc(bool, names.len);
    defer allocator.free(seen);
    @memset(seen, false);

    for (parsed.instances) |instance| {
        if (!std.mem.eql(u8, instance.kind, "aiand")) wrong += 1;
        const which = whichLogin(instance.stored_ms, names.len) orelse {
            wrong += 1;
            continue;
        };
        if (!std.mem.eql(u8, instance.name, names[which])) wrong += 1;
        if (seen[which]) wrong += 1;
        seen[which] = true;
    }

    if (distinct) {
        for (names, tokens) |name, token| {
            var found = (store(&driver).get(allocator, io, name, null) catch {
                wrong += 1;
                continue;
            }) orelse {
                wrong += 1;
                continue;
            };
            defer found.deinit();
            if (!std.mem.eql(u8, found.token, token)) wrong += 1;
        }
        return wrong;
    }

    var found = (store(&driver).get(allocator, io, names[0], null) catch return wrong + 1) orelse
        return wrong + 1;
    defer found.deinit();
    const which = whichLogin(found.stored_ms, names.len) orelse return wrong + 1;
    if (!std.mem.eql(u8, found.token, tokens[which])) return wrong + 1;
    return wrong;
}

/// A store over a driver the caller owns. `Driver.secrets` keeps a pointer to
/// the driver, so a driver made inside this function would be dead on return.
fn store(driver: *const chock_auth.store.Driver) chock_auth.store.Store {
    return .{ .data_dir = driver.data_dir, .secrets = driver.secrets() };
}

fn whichLogin(stored_ms: i64, count: usize) ?usize {
    if (stored_ms < first_stored_ms) return null;
    const offset = stored_ms - first_stored_ms;
    if (offset >= @as(i64, @intCast(count))) return null;
    return @intCast(offset);
}

fn parseIndex(allocator: std.mem.Allocator, io: std.Io, data_dir: []const u8) !ParsedIndex {
    const path = try std.fs.path.join(allocator, &.{ data_dir, chock_auth.store.index_file_name });
    defer allocator.free(path);

    const source = try std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        allocator,
        .limited(chock_auth.store.max_index_bytes),
        .of(u8),
        0,
    );
    defer allocator.free(source);

    // No `ignore_unknown_fields`. Trailing bytes are what a mixture leaves.
    return std.zon.parse.fromSliceAlloc(ParsedIndex, allocator, source, null, .{});
}

const Totals = struct {
    sessions: usize = 0,
    failures: usize = 0,
    busy: usize = 0,
    unsound: usize = 0,
    stored: usize = 0,
    refused: usize = 0,
};

fn measure(
    allocator: std.mem.Allocator,
    io: std.Io,
    count: usize,
    distinct: bool,
    if_present: IfPresent,
    iterations: usize,
) !Totals {
    var totals = Totals{ .sessions = count * iterations };
    for (0..iterations) |_| {
        const outcome = try raceOnce(allocator, io, count, distinct, if_present);
        totals.failures += outcome.failures;
        totals.busy += outcome.busy;
        totals.unsound += outcome.unsound;
        totals.stored += outcome.stored;
        totals.refused += outcome.refused;
    }
    return totals;
}

test "four logins for one provider at once leave one whole entry, not a mixture" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(
        Totals{ .sessions = 100, .stored = 100 },
        try measure(allocator, std.testing.io, 4, false, .replace, 25),
    );
}

test "eight logins for one provider at once still leave one whole entry" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(
        Totals{ .sessions = 80, .stored = 80 },
        try measure(allocator, std.testing.io, 8, false, .replace, 10),
    );
}

test "four logins for four providers at once each keep their own credential" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(
        Totals{ .sessions = 100, .stored = 100 },
        try measure(allocator, std.testing.io, 4, true, .replace, 25),
    );
}

test "eight logins for eight providers at once each keep their own credential" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(
        Totals{ .sessions = 80, .stored = 80 },
        try measure(allocator, std.testing.io, 8, true, .replace, 10),
    );
}

test "four logins with no name of their own at once store one and refuse three" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(
        Totals{ .sessions = 100, .stored = 25, .refused = 75 },
        try measure(allocator, std.testing.io, 4, false, .refuse, 25),
    );
}

test "eight logins with no name of their own at once store one and refuse seven" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(
        Totals{ .sessions = 80, .stored = 10, .refused = 70 },
        try measure(allocator, std.testing.io, 8, false, .refuse, 10),
    );
}
