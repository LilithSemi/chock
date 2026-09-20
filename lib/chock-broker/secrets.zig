//! The credentials. A tool definition names one with the handle
//! `{{secret:name}}`, and `resolve` puts the value in only when the sandbox
//! launcher builds the child's environment, so no value reaches the context.

const std = @import("std");
const chock_proto = @import("chock-proto");
const diagnostic = @import("diagnostic.zig");
const Diagnostic = diagnostic.Diagnostic;

const event = chock_proto.event;

/// One fixed string, never stars: a length is a fact about the credential.
pub const redacted_marker = "[redacted]";

pub const handle_open = "{{secret:";
pub const handle_close = "}}";

/// Nothing in `src/` fills this today, so every function here runs over an
/// empty set. A live session redacts at `chock_core.Loop.appendAndApply`.
pub const Store = struct {
    entries: []const Entry = &.{},

    pub const Entry = struct {
        name: []const u8,
        value: []const u8,
    };

    pub fn get(self: Store, name: []const u8) ?[]const u8 {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.value;
        }
        return null;
    }

    pub fn longestValue(self: Store) usize {
        var longest: usize = 0;
        for (self.entries) |entry| longest = @max(longest, entry.value.len);
        return longest;
    }
};

pub const ResolveError = std.mem.Allocator.Error || error{
    UnknownSecret,
    UnterminatedHandle,
};

/// Call it when the child's environment is built, and nowhere else.
pub fn resolve(
    store: Store,
    gpa: std.mem.Allocator,
    text: []const u8,
    diag: ?*?Diagnostic,
) ResolveError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    var index: usize = 0;
    while (std.mem.indexOfPos(u8, text, index, handle_open)) |open| {
        try out.appendSlice(gpa, text[index..open]);
        const name_start = open + handle_open.len;
        const close = std.mem.indexOfPos(u8, text, name_start, handle_close) orelse {
            _ = diagnostic.note(diag, .secret_handle_unterminated);
            return error.UnterminatedHandle;
        };
        const name = text[name_start..close];
        const value = store.get(name) orelse {
            _ = diagnostic.note(diag, .{ .secret_not_named = name });
            return error.UnknownSecret;
        };
        try out.appendSlice(gpa, value);
        index = close + handle_close.len;
    }
    try out.appendSlice(gpa, text[index..]);
    return out.toOwnedSlice(gpa);
}

pub fn resolveEnv(
    store: Store,
    gpa: std.mem.Allocator,
    entries: []const []const u8,
    diag: ?*?Diagnostic,
) ResolveError![][]u8 {
    const out = try gpa.alloc([]u8, entries.len);
    var built: usize = 0;
    errdefer {
        for (out[0..built]) |entry| gpa.free(entry);
        gpa.free(out);
    }
    for (entries, out) |entry, *slot| {
        slot.* = try resolve(store, gpa, entry, diag);
        built += 1;
    }
    return out;
}

pub fn freeEnv(gpa: std.mem.Allocator, env: [][]u8) void {
    for (env) |entry| gpa.free(entry);
    gpa.free(env);
}

/// A value can end one piece and start the next, so a scan of each piece on its
/// own finds nothing.
pub const Redactor = struct {
    /// Empty values are left out: an empty needle matches everywhere.
    values: []const []const u8,
    /// One less than the longest value, the longest run that can still grow
    /// into one when the next piece arrives.
    hold_bytes: usize,
    pending: std.ArrayList(u8) = .empty,
    out: std.ArrayList(u8) = .empty,

    pub fn init(gpa: std.mem.Allocator, store: Store) std.mem.Allocator.Error!Redactor {
        const values = try gpa.alloc([]const u8, store.entries.len);
        defer gpa.free(values);
        for (store.entries, values) |entry, *slot| slot.* = entry.value;
        return initValues(gpa, values);
    }

    /// The same, for a credential that has no name.
    pub fn initValues(
        gpa: std.mem.Allocator,
        values: []const []const u8,
    ) std.mem.Allocator.Error!Redactor {
        var kept: std.ArrayList([]const u8) = .empty;
        errdefer kept.deinit(gpa);
        var longest: usize = 0;
        for (values) |value| {
            if (value.len == 0) continue;
            try kept.append(gpa, value);
            longest = @max(longest, value.len);
        }
        return .{
            .values = try kept.toOwnedSlice(gpa),
            .hold_bytes = if (longest == 0) 0 else longest - 1,
        };
    }

    pub fn deinit(self: *Redactor, gpa: std.mem.Allocator) void {
        gpa.free(self.values);
        self.pending.deinit(gpa);
        self.out.deinit(gpa);
        self.* = undefined;
    }

    pub fn push(self: *Redactor, gpa: std.mem.Allocator, piece: []const u8) std.mem.Allocator.Error!void {
        try self.pending.appendSlice(gpa, piece);
        try self.sweep(gpa, false);
    }

    pub fn finish(self: *Redactor, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        try self.sweep(gpa, true);
        return self.out.toOwnedSlice(gpa);
    }

    fn sweep(self: *Redactor, gpa: std.mem.Allocator, release_all: bool) std.mem.Allocator.Error!void {
        var start: usize = 0;
        while (self.firstValue(start)) |hit| {
            try self.out.appendSlice(gpa, self.pending.items[start..hit.index]);
            try self.out.appendSlice(gpa, redacted_marker);
            start = hit.index + hit.len;
        }

        const rest = self.pending.items[start..];
        const hold = if (release_all) 0 else @min(rest.len, self.hold_bytes);
        try self.out.appendSlice(gpa, rest[0 .. rest.len - hold]);

        const kept_from = self.pending.items.len - hold;
        std.mem.copyForwards(u8, self.pending.items[0..hold], self.pending.items[kept_from..]);
        self.pending.shrinkRetainingCapacity(hold);
    }

    const Hit = struct { index: usize, len: usize };

    /// On a tie the longer value wins, so a prefix leaves no rest behind.
    fn firstValue(self: *const Redactor, from: usize) ?Hit {
        var best: ?Hit = null;
        for (self.values) |value| {
            const at = std.mem.indexOfPos(u8, self.pending.items, from, value) orelse continue;
            const better = if (best) |current|
                at < current.index or (at == current.index and value.len > current.len)
            else
                true;
            if (better) best = .{ .index = at, .len = value.len };
        }
        return best;
    }
};

pub fn redact(store: Store, gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]u8 {
    var redactor = try Redactor.init(gpa, store);
    defer redactor.deinit(gpa);
    try redactor.push(gpa, text);
    return redactor.finish(gpa);
}

pub const AppendError = std.mem.Allocator.Error || chock_proto.storage.StorageError;

/// Redact first: `chockd` serves the log to every attached client, and the log
/// is append only, so no later pass can take a value back.
pub fn appendToolResult(
    store: Store,
    gpa: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    result: event.ToolResult,
    time_ms: i64,
) AppendError!u64 {
    const clean = try redact(store, gpa, result.output);
    defer gpa.free(clean);

    return locked.append(gpa, io, .{ .tool_result = .{
        .call_id = result.call_id,
        .output = clean,
        .is_error = result.is_error,
        .truncated = result.truncated,
    } }, time_ms);
}

// A `Store` that held a path would give a mount builder something to mount.
comptime {
    const forbidden = [_][]const u8{ "path", "file", "dir", "mount", "source", "target" };
    for (@typeInfo(Store).@"struct".fields ++ @typeInfo(Store.Entry).@"struct".fields) |field| {
        for (forbidden) |bad| {
            if (std.mem.indexOf(u8, field.name, bad) != null) {
                @compileError("the credential store holds values and never a path: " ++ field.name);
            }
        }
    }
}

const testing = std.testing;

const the_secret = "sk-live-9f2c4a7b1d3e";
const other_secret = "ghp_zzzz1111yyyy2222";

fn testStore() Store {
    return .{ .entries = &.{
        .{ .name = "aiand", .value = the_secret },
        .{ .name = "github", .value = other_secret },
    } };
}

fn logBytes(backing: *const chock_proto.storage.Memory) []const u8 {
    return backing.bytes.items;
}

test "a handle is replaced in the child's environment and never in the context" {
    const gpa = testing.allocator;

    const definition = "run the command with AIAND_TOKEN={{secret:aiand}} set";

    try testing.expect(std.mem.indexOf(u8, definition, the_secret) == null);
    try testing.expect(std.mem.indexOf(u8, definition, "{{secret:aiand}}") != null);

    const child_env = try resolveEnv(testStore(), gpa, &.{
        "PATH=/usr/bin",
        "AIAND_TOKEN={{secret:aiand}}",
        "GITHUB_TOKEN={{secret:github}}",
    }, null);
    defer freeEnv(gpa, child_env);

    try testing.expectEqualStrings("PATH=/usr/bin", child_env[0]);
    try testing.expectEqualStrings("AIAND_TOKEN=" ++ the_secret, child_env[1]);
    try testing.expectEqualStrings("GITHUB_TOKEN=" ++ other_secret, child_env[2]);

    const both = try resolve(testStore(), gpa, "a{{secret:aiand}}b{{secret:github}}c", null);
    defer gpa.free(both);
    try testing.expectEqualStrings("a" ++ the_secret ++ "b" ++ other_secret ++ "c", both);

    try testing.expectError(
        error.UnknownSecret,
        resolve(testStore(), gpa, "TOKEN={{secret:nothing-by-that-name}}", null),
    );
    try testing.expectError(
        error.UnterminatedHandle,
        resolve(testStore(), gpa, "TOKEN={{secret:aiand", null),
    );
}

test "a secret value never appears in the log after a tool call prints its environment" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01SECRET");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const env_output =
        "PATH=/usr/bin\n" ++
        "AIAND_TOKEN=" ++ the_secret ++ "\n" ++
        "GITHUB_TOKEN=" ++ other_secret ++ "\n" ++
        "HOME=/home/ross\n";

    _ = try appendToolResult(testStore(), gpa, io, &locked, .{
        .call_id = "call1",
        .output = env_output,
        .is_error = false,
        .truncated = false,
    }, 1_700_000_000_000);

    try testing.expect(std.mem.indexOf(u8, logBytes(&backing), the_secret) == null);
    try testing.expect(std.mem.indexOf(u8, logBytes(&backing), other_secret) == null);

    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    const parsed = (try replay.next(io)).?;
    defer parsed.deinit();
    const stored = parsed.value.event.tool_result.output;
    try testing.expectEqualStrings(
        "PATH=/usr/bin\nAIAND_TOKEN=" ++ redacted_marker ++
            "\nGITHUB_TOKEN=" ++ redacted_marker ++ "\nHOME=/home/ross\n",
        stored,
    );
}

test "a secret split across two reads of a tool result is still redacted" {
    const gpa = testing.allocator;

    for (1..the_secret.len) |cut| {
        var redactor = try Redactor.init(gpa, testStore());
        defer redactor.deinit(gpa);

        try redactor.push(gpa, "before " ++ the_secret[0..0]);
        try redactor.push(gpa, the_secret[0..cut]);
        try redactor.push(gpa, the_secret[cut..]);
        try redactor.push(gpa, " after");

        const result = try redactor.finish(gpa);
        defer gpa.free(result);
        try testing.expectEqualStrings("before " ++ redacted_marker ++ " after", result);
    }

    {
        var redactor = try Redactor.init(gpa, testStore());
        defer redactor.deinit(gpa);
        const whole = "x" ++ the_secret ++ "y";
        for (whole) |byte| try redactor.push(gpa, &.{byte});
        const result = try redactor.finish(gpa);
        defer gpa.free(result);
        try testing.expectEqualStrings("x" ++ redacted_marker ++ "y", result);
    }

    {
        var redactor = try Redactor.init(gpa, testStore());
        defer redactor.deinit(gpa);
        try redactor.push(gpa, "the tail is " ++ the_secret[0 .. the_secret.len - 1]);
        const result = try redactor.finish(gpa);
        defer gpa.free(result);
        try testing.expectEqualStrings("the tail is " ++ the_secret[0 .. the_secret.len - 1], result);
    }

    {
        var redactor = try Redactor.init(gpa, testStore());
        defer redactor.deinit(gpa);
        try redactor.push(gpa, "a" ++ other_secret ++ "b" ++ the_secret[0..4]);
        try redactor.push(gpa, the_secret[4..] ++ "c");
        const result = try redactor.finish(gpa);
        defer gpa.free(result);
        try testing.expectEqualStrings(
            "a" ++ redacted_marker ++ "b" ++ redacted_marker ++ "c",
            result,
        );
    }
}

test "redaction happens before the append, not after" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01SECRET");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var redactor = try Redactor.init(gpa, testStore());
    defer redactor.deinit(gpa);
    try redactor.push(gpa, "token is " ++ the_secret[0..7]);
    const bytes_in_the_log_so_far = logBytes(&backing).len;
    try redactor.push(gpa, the_secret[7..] ++ "\n");
    const streamed = try redactor.finish(gpa);
    defer gpa.free(streamed);

    try testing.expectEqual(bytes_in_the_log_so_far, logBytes(&backing).len);
    try testing.expect(std.mem.indexOf(u8, streamed, the_secret) == null);

    _ = try appendToolResult(testStore(), gpa, io, &locked, .{
        .call_id = "call1",
        .output = streamed,
        .is_error = false,
        .truncated = false,
    }, 1_700_000_000_000);

    try testing.expect(std.mem.indexOf(u8, logBytes(&backing), the_secret) == null);
    try testing.expectEqualStrings(
        "token is " ++ redacted_marker ++ "\n",
        streamed,
    );

    _ = try appendToolResult(testStore(), gpa, io, &locked, .{
        .call_id = "call2",
        .output = "raw " ++ the_secret,
        .is_error = true,
        .truncated = false,
    }, 1_700_000_000_001);
    try testing.expect(std.mem.indexOf(u8, logBytes(&backing), the_secret) == null);

    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    var seen: usize = 0;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .tool_result) continue;
        seen += 1;
        if (seen == 2) {
            try testing.expect(parsed.value.event.tool_result.is_error);
            try testing.expectEqualStrings("raw " ++ redacted_marker, parsed.value.event.tool_result.output);
        }
    }
    try testing.expectEqual(@as(usize, 2), seen);
}

test "a store with no credentials changes nothing, and an empty value matches nothing" {
    const gpa = testing.allocator;

    const empty = try redact(.{}, gpa, "nothing to hide here");
    defer gpa.free(empty);
    try testing.expectEqualStrings("nothing to hide here", empty);

    const with_empty = Store{ .entries = &.{
        .{ .name = "unset", .value = "" },
        .{ .name = "aiand", .value = the_secret },
    } };
    const result = try redact(with_empty, gpa, "a " ++ the_secret ++ " b");
    defer gpa.free(result);
    try testing.expectEqualStrings("a " ++ redacted_marker ++ " b", result);
}

test "a value that is a prefix of another leaves none of the longer one behind" {
    const gpa = testing.allocator;

    const nested = Store{ .entries = &.{
        .{ .name = "short", .value = "sk-live" },
        .{ .name = "long", .value = the_secret },
    } };

    const result = try redact(nested, gpa, "key=" ++ the_secret ++ ";");
    defer gpa.free(result);
    try testing.expectEqualStrings("key=" ++ redacted_marker ++ ";", result);
    try testing.expect(std.mem.indexOf(u8, result, "9f2c4a7b1d3e") == null);
}
