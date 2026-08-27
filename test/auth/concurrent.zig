//! Two terminals, one credential store.
//!
//! **The ordinary case, and it used to corrupt the store.** A person who runs
//! `chock login` twice, or once while a script does, has two processes reading
//! the whole index, changing it, and writing it back. Before
//! `lib/chock-auth/lock.zig` there was no exclusion at all, and the temporary
//! file every write goes through was a constant `<path>.new`: two logins opened
//! that one inode with `truncate`, each wrote from offset zero, and the first
//! rename published whatever was in it while the other writer carried on
//! writing into the file that was now the store.
//!
//! Measured on 2026-08-25, Linux 6.18.42, aarch64, with the helper this file
//! starts. "Bad stores" counts the runs whose store was not what was put in.
//!
//! | shape | neither, as filed | lock only missing | both, as shipped |
//! |---|---|---|---|
//! | one name, four way, 25 runs | **67 of 100 sessions failed**, 5 bad stores | 0 failed, 0 bad | 0 failed, 0 bad |
//! | one name, eight way, 10 runs | **68 of 80 sessions failed**, 1 bad store | 0 failed, 0 bad | 0 failed, 0 bad |
//! | a name each, four way, 25 runs | **68 of 100 sessions failed**, 25 bad stores | **0 failed, 25 bad stores** | 0 failed, 0 bad |
//! | a name each, eight way, 10 runs | **65 of 80 sessions failed**, 10 bad stores | **0 failed, 10 bad stores** | 0 failed, 0 bad |
//!
//! **Read the middle column.** With the temporary name made unique and no lock,
//! every session exits zero and every store has still lost a credential. A
//! check that counted exit statuses would have called that fixed.
//!
//! ## The two faults that were left, and are not left now
//!
//! Both leave the store well formed, so neither is the corruption above. They
//! are still two logins ending in a store that says something no single login
//! said. Measured on 2026-08-25, on the same machine.
//!
//! | shape | before | after |
//! |---|---|---|
//! | one name, four way, 25 runs, `--name` given | 0 failed, **1 run in 25 bad** | 0 failed, 0 bad |
//! | one name, four way, 25 runs, no `--name` | **99 of 100 said stored**, 1 refused | 25 stored, 75 refused |
//! | one name, eight way, 10 runs, no `--name` | **79 of 80 said stored**, 1 refused | 10 stored, 70 refused |
//!
//! **Residual 1 is the two `no --name` rows.** A second unnamed instance
//! must never silently replace the first. The look that enforced
//! that was outside every lock, so nearly every session passed it, nearly every
//! session said the credential was kept, and one credential per run was in the
//! store: 74 people in 100 were told a key had been stored that had not been.
//! The look is still there, because it is what keeps a person from being asked
//! for a credential that cannot be kept, and `Store.put` now makes it again
//! with the index locked.
//!
//! **Residual 2 is the first row.** The credential and the index had a lock
//! each, so a run could end with the entry of one login beside the credential
//! of another. Both files parse and neither is truncated. `Store.put` now holds
//! the index's lock over the driver as well, so one login writes both or
//! neither.
//!
//! **A count of exit statuses would have missed the fault.** What breaks here
//! is a file that still parses and holds the wrong thing, so every run below
//! reads the index back as a file, checks it holds one whole entry for each
//! name that was stored, and then reads each credential out through the driver.
//! A run in which nothing exited non zero and one credential quietly went
//! missing counts as a failure here. See `Outcome`.
//!
//! **Real processes and not several calls in one test binary.** `flock` locks
//! an open file description, so two `Store.put` calls inside this binary would
//! contend correctly and say nothing about two `chock login` commands.

const std = @import("std");
const chock_auth = @import("chock-auth");

// Zig 0.16's default test runner panics on an argv it does not recognize, so
// the helper's path is a build time constant. Every probe in this project is
// wired this way.
const helper_path = @import("login_helper_path").login_helper_path;

/// The helper's exit statuses. Kept in step with `test/auth/login_helper.zig`
/// by name.
const stored = 0;
const busy = 1;
const name_taken = 5;

/// The first `stored_ms` a helper is given. Each one gets this plus its own
/// index, so an entry says which login wrote it and a mixture of two entries
/// shows as a time that belongs to the other one.
const first_stored_ms: i64 = 1_700_000_000_000;

/// How long the helpers are given to all reach their starting instant. What is
/// under measurement is microseconds long, so processes started one after the
/// other would never overlap and the race would go unentered.
const lead_ms: i64 = 200;

/// What one race left behind.
///
/// **`unsound` is the one that matters.** A session that exits zero after
/// publishing a mixture is exactly the fault, so it is counted apart from a
/// session that said no.
const Outcome = struct {
    /// Sessions that ended in a way that is not an answer.
    failures: usize = 0,
    /// Sessions that gave up on the lock. See `lib/chock-auth/lock.zig`.
    busy: usize = 0,
    /// Ways in which the store that came out is not what was put in.
    unsound: usize = 0,
    /// Sessions that said the credential was kept.
    stored: usize = 0,
    /// Sessions that were told the name was already there. Only a `.refuse`
    /// race produces these.
    refused: usize = 0,
};

/// What a login does when the name it is storing is already in the index.
///
/// **These are the two shapes `chock login` has**, and only one of them is
/// about a lost credential. See `test/auth/login_helper.zig`.
const IfPresent = enum {
    /// A login that was given `--name`. It replaces, and it is right to.
    replace,
    /// A login that was given none. It must refuse rather than silently
    /// replace the first.
    refuse,

    fn argument(self: IfPresent) []const u8 {
        return @tagName(self);
    }
};

/// What the index holds, read as a file and not as an answer from the store.
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

/// Run `count` logins at once on one empty store and say what came of it.
///
/// `distinct` gives every login a name of its own, which is the shape that
/// shows a lost update: a correct store then holds every one of them. With one
/// name they all replace each other, and only the corruption shows.
///
/// `if_present` chooses which of the two logins each one is. `.refuse` is a
/// login with no `--name`, and only that shape can lose a credential a person
/// was told had been kept.
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
    // Two levels the store has to make itself, which is a machine that has
    // never run `chock login`. Making that directory is part of the race.
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
        // **Deliberately of different lengths.** Values of one length hide the
        // worst mixture, where a short writer's bytes sit under a long writer's
        // tail and the file still parses.
        var padding: [40]u8 = undefined;
        const width = 4 + i * 5;
        @memset(padding[0..width], 'x');
        token.* = try std.fmt.allocPrint(allocator, "sk-{d}-{s}", .{ i, padding[0..width] });
    }

    const children = try allocator.alloc(std.process.Child, count);
    defer allocator.free(children);

    const start_ms = std.Io.Timestamp.now(io, .real).toMilliseconds() + lead_ms;
    // Every one is started before any one is waited for, and every one waits
    // for the same instant. A test that waited on the first before starting the
    // second would be a sequential run, which proves nothing about this fault.
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
            // A test binary that writes to standard error fails this build
            // whatever it exited with. See `test/proto/lock.zig`.
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

/// Everything that has to be true of the store afterwards, counted.
///
/// **This is the half a count of exit statuses cannot do.** The index is parsed
/// as a file, its shape is checked entry by entry, and then every credential is
/// read out through the driver, which parses the credential file in its turn.
fn soundness(
    allocator: std.mem.Allocator,
    io: std.Io,
    data_dir: []const u8,
    names: []const []u8,
    tokens: []const []u8,
    distinct: bool,
) !usize {
    var wrong: usize = 0;
    // **Owned here, and this frame is why.** `store` builds an interface that
    // keeps a pointer to this driver, so the driver has to outlive every store
    // made from it.
    const driver = chock_auth.store.Driver{ .data_dir = data_dir };

    const parsed = parseIndex(allocator, io, data_dir) catch return names.len;
    defer std.zon.parse.free(allocator, parsed);

    if (parsed.version != 1) wrong += 1;
    // One name means every login replaced the last, so exactly one entry. A
    // name each means every one of them has to be there.
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
        // **Every field of an entry has to come from one login.** A mixture
        // that still parses shows here as a name that does not go with the time
        // beside it.
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
            // A mixture can still parse, so the value has to match to the byte.
            if (!std.mem.eql(u8, found.token, token)) wrong += 1;
        }
        return wrong;
    }

    var found = (store(&driver).get(allocator, io, names[0], null) catch return wrong + 1) orelse
        return wrong + 1;
    defer found.deinit();
    // **The index and the credential have to name one login, not two.**
    // Residual 2: the two files have locks of their own, so a store
    // whose entry came from one run and whose credential came from another is
    // whole, parses, and is still wrong. `stored_ms` is what says which login
    // wrote the entry, and the token says which one wrote the value.
    const which = whichLogin(found.stored_ms, names.len) orelse return wrong + 1;
    if (!std.mem.eql(u8, found.token, tokens[which])) return wrong + 1;
    return wrong;
}

/// A store over a driver the CALLER owns.
///
/// **The driver cannot be a local here.** `Driver.secrets` builds an interface
/// holding a pointer to the driver, so a driver made inside this function would
/// be dead the moment the store is returned. That was the shape before, and a
/// comment above it said the pointer never outlives the call it is made for,
/// which was exactly wrong. Debug builds survived it because the dead frame
/// still held plausible bytes. `--release=safe` did not: `std.fs.path.join`
/// read a garbage `data_dir` and the test crashed.
fn store(driver: *const chock_auth.store.Driver) chock_auth.store.Store {
    return .{ .data_dir = driver.data_dir, .secrets = driver.secrets() };
}

/// Which login wrote an entry, from the time in it, or null when no login was
/// given that time.
fn whichLogin(stored_ms: i64, count: usize) ?usize {
    if (stored_ms < first_stored_ms) return null;
    const offset = stored_ms - first_stored_ms;
    if (offset >= @as(i64, @intCast(count))) return null;
    return @intCast(offset);
}

/// The index, parsed, or an error when it is not well formed. Callers free the
/// result with `std.zon.parse.free`.
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

    // No `ignore_unknown_fields`, unlike the store's own reader: trailing bytes
    // and a field that is not a field are exactly what a mixture leaves.
    return std.zon.parse.fromSliceAlloc(ParsedIndex, allocator, source, null, .{});
}

/// Every run of one shape, added up.
///
/// **One value, checked in one `expectEqual`, because a failure has to say the
/// numbers.** The interesting failures are counted rather than thrown, so a
/// shape that goes wrong here prints how many sessions did what beside how
/// many should have.
const Totals = struct {
    sessions: usize = 0,
    failures: usize = 0,
    busy: usize = 0,
    unsound: usize = 0,
    stored: usize = 0,
    refused: usize = 0,
};

/// Run one shape `iterations` times and add up what came of it.
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
    // Mutation check: take the lock out of `Store.put` and this fails, 67
    // sessions in 100 measured. The constant `.new` alone is caught by
    // `chock-auth/store.zig`'s own "the temporary file a write goes through is
    // this process's own", because a lock that still works serialises the
    // writers that would have shared the name.
    //
    // Everything under a lock here is one small read and one rename, so a login
    // should never run out of the five second bound at this size. A busy answer
    // means the bound is wrong, not that the store is.
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
    // **This is the half that shows a lost update.** With one name a login that
    // dropped another's entry still looks correct, because there is only ever
    // one entry to hold. With a name each, a store that lost one is a person
    // who logged in and has no credential.
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
    // **A second unnamed instance never silently replaces the first.** The
    // look that enforced it was outside every lock, so all four passed it, all
    // four said the credential was kept, and one credential was in the store:
    // three people were told a key had been stored that had not.
    //
    // Measured before the check moved under the lock: 100 of 100 sessions said
    // stored, 0 refused, and 75 of those answers were wrong.
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
