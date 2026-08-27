//! The credentials, and the two things Chock does with them.
//!
//! ## The model never sees a value
//!
//! A tool definition names a credential with the handle `{{secret:name}}`. The
//! handle is what the model reads, what the log records, and what a client
//! shows. `resolve` replaces it with the value only when the sandbox launcher
//! builds the environment for the child, and that happens after the model
//! output is parsed. So there is no turn of the loop on which a value could
//! reach the context.
//!
//! ## Redaction happens before the append, never after
//!
//! Every tool result is scanned before it enters the context, and a match on a
//! known value becomes `[redacted]`.
//!
//! **The order is the whole point.** `chockd` serves the session log to every
//! attached client, so a value that reaches the log has already been given
//! away, and a redaction that runs afterwards cannot take it back. The log is
//! append only and hash chained, so there is no afterwards to run in: a record
//! cannot be edited without breaking the chain of every record after it.
//! `appendToolResult` is the only way into the log from here and it redacts
//! first. A test reads the log's own bytes and proves the value is in none of
//! them.
//!
//! Without this, one call to `env` puts every credential into the context.
//!
//! **What a live session uses instead, today.** `chock-core` imports no
//! `chock-broker`, so the agent loop cannot call `appendToolResult`. It redacts
//! at its own seam, `chock_core.Loop.appendAndApply`, out of
//! `chock_core.redact.Policy`, and that covers every record it writes and not
//! a tool result alone. **Nothing fills `Store` in `src/` at all**, so the
//! functions here run over an empty set in every session that exists. They are
//! kept for the day a `{{secret:name}}` handle gets a producer, and this
//! paragraph is here so that nobody counts them as cover that is already
//! there.
//!
//! ## A streamed result can cut a value in half
//!
//! This is the case a scan of each piece on its own gets wrong. A tool that
//! streams gives its result in pieces, and a value can end one piece and
//! start the next, so neither piece holds it and both look clean.
//!
//! `Redactor` answers it by holding bytes back. After each piece it releases
//! everything except the last `longest value - 1` bytes, which are the only
//! bytes that can still become the start of a value. The next piece joins
//! them and the whole value is there to be found. `finish` releases what is
//! left, so nothing is lost.
//!
//! ## The store is never mounted into the sandbox
//!
//! Not read only. Not at all. A path an agent cannot see is stronger than a
//! path an agent may only read, which is the `commondir` lesson a second time:
//! own the path, do not protect the file.
//!
//! `Store` holds values and never a path, which is what makes the rule
//! structural instead of a habit. Reading whatever `chock login` wrote is
//! the broker process's own work at startup, and it hands the values here.
//! There is no path in this file for a mount builder to find, and the
//! comptime block at the end fails the build if one appears.
//!
//! The other two rules are kept elsewhere and named here so a reader can find
//! them: the loop holds no credential field, which `lib/chock-core/Loop.zig`
//! fails its own build over, and a credential never enters the log, which is
//! this file's own `appendToolResult` here and `chock_core.Loop.appendAndApply`
//! in the loop.

const std = @import("std");
const chock_proto = @import("chock-proto");
const diagnostic = @import("diagnostic.zig");
const Diagnostic = diagnostic.Diagnostic;

const event = chock_proto.event;

/// What a redacted value is replaced with. One fixed string, not the value's
/// length in stars: a length is itself a fact about the credential.
pub const redacted_marker = "[redacted]";

/// The two halves of a handle, spelled `{{secret:name}}`.
pub const handle_open = "{{secret:";
pub const handle_close = "}}";

/// The credentials this broker holds. Values only. See this file's own top
/// comment on why there is no path here.
pub const Store = struct {
    entries: []const Entry = &.{},

    pub const Entry = struct {
        /// The name a handle uses, for example "aiand" in
        /// `{{secret:aiand}}`.
        name: []const u8,
        value: []const u8,
    };

    /// The value of one name, or null when this store has no such name.
    pub fn get(self: Store, name: []const u8) ?[]const u8 {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.value;
        }
        return null;
    }

    /// The length of the longest value. Zero for an empty store. This is
    /// what decides how many bytes `Redactor` holds back.
    pub fn longestValue(self: Store) usize {
        var longest: usize = 0;
        for (self.entries) |entry| longest = @max(longest, entry.value.len);
        return longest;
    }
};

/// What replacing the handles in a piece of text can fail with.
pub const ResolveError = std.mem.Allocator.Error || error{
    /// A handle names something this store does not hold. Refused rather
    /// than left in place: a handle that reaches a child process unreplaced
    /// is a configuration mistake that would otherwise show up much later as
    /// a rejected request the user cannot explain.
    UnknownSecret,
    /// A `{{secret:` with no closing `}}`.
    UnterminatedHandle,
};

/// Replace every `{{secret:name}}` in `text` with its value. Owned by the
/// caller.
///
/// Call this when the environment for the child process is built, and
/// nowhere else. See this file's own top comment.
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

/// Replace the handles in every entry of a child's environment. Each entry
/// is a whole `KEY=VALUE` string, the shape `Sandbox.Config.env` takes.
/// Release the result with `freeEnv`.
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

/// Redacts a result that arrives in pieces.
///
/// `push` each piece, then `finish`. See this file's own top comment for why
/// a scan of each piece on its own is wrong, and for what the held back
/// bytes are.
pub const Redactor = struct {
    /// The values to look for, in the order the store gave them. Empty
    /// values are left out: an empty needle matches at every position and
    /// would turn the whole result into markers.
    values: []const []const u8,
    /// How many bytes never leave `pending` until `finish`. One less than
    /// the longest value: a run of that length is the longest one that can
    /// still turn into a value when the next piece arrives.
    hold_bytes: usize,
    /// Bytes read but not yet released.
    pending: std.ArrayList(u8) = .empty,
    /// Bytes released, redacted.
    out: std.ArrayList(u8) = .empty,

    /// The caller frees the result with `deinit`. `store` must outlive it.
    pub fn init(gpa: std.mem.Allocator, store: Store) std.mem.Allocator.Error!Redactor {
        const values = try gpa.alloc([]const u8, store.entries.len);
        defer gpa.free(values);
        for (store.entries, values) |entry, *slot| slot.* = entry.value;
        return initValues(gpa, values);
    }

    /// The same, over values with no names at all.
    ///
    /// **This is what lets a credential be redacted without being nameable.**
    /// A name is what a `{{secret:name}}` handle spells, and
    /// `chock-broker/askpass.zig` holds a kind of credential that must have
    /// none: see `Grants.redactor` and that file's own top comment. A
    /// redactor reads values and never a name, so it does not need one, and
    /// `init` above is this function with the names dropped first.
    ///
    /// The caller frees the result with `deinit`. `values` must outlive it.
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

    /// Take one piece of the result.
    pub fn push(self: *Redactor, gpa: std.mem.Allocator, piece: []const u8) std.mem.Allocator.Error!void {
        try self.pending.appendSlice(gpa, piece);
        try self.sweep(gpa, false);
    }

    /// No more pieces. Gives back the whole redacted result, owned by the
    /// caller. The redactor is empty afterwards and can be used again.
    pub fn finish(self: *Redactor, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        try self.sweep(gpa, true);
        return self.out.toOwnedSlice(gpa);
    }

    /// Replace every value in `pending`, release what can no longer become
    /// one, and keep the rest.
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

    /// The first value in `pending` at or after `from`. On a tie the longer
    /// one wins, so a value that is a prefix of another never leaves the
    /// rest of the longer one behind.
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

/// Redact a whole result that is already in memory. Owned by the caller.
pub fn redact(store: Store, gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]u8 {
    var redactor = try Redactor.init(gpa, store);
    defer redactor.deinit(gpa);
    try redactor.push(gpa, text);
    return redactor.finish(gpa);
}

/// What appending a tool result can fail with.
pub const AppendError = std.mem.Allocator.Error || chock_proto.storage.StorageError;

/// Redact one tool result and then append it. **This is the only way a tool
/// result enters the log from here, and it redacts first.**
///
/// A caller that already streamed the result through a `Redactor` still
/// comes through this function, and the second scan finds nothing, because
/// the value is already gone. That costs one pass and it buys an
/// unconditional rule: every path into the log is redacted, and there is no
/// second path to remember.
///
/// `locked` is `anytype` for the same reason `Broker.request` takes it that
/// way: `chock_proto.storage.Locked` is not `pub`.
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

// The store is never mounted, enforced by the build rather than by a reviewer.
// A `Store` that held a path would give a mount builder something to mount, and
// the rule is that the store is never mounted at all. See this file's own top
// comment.
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

/// Every byte the log holds. `Memory` keeps the same wire shape a real file
/// does, so this is what `chockd` would serve to another client.
fn logBytes(backing: *const chock_proto.storage.Memory) []const u8 {
    return backing.bytes.items;
}

test "a handle is replaced in the child's environment and never in the context" {
    // Both halves. The environment the child gets holds the value. The text
    // the model read, which is also the text that reaches the log, holds the
    // handle and not the value.
    const gpa = testing.allocator;

    const definition = "run the command with AIAND_TOKEN={{secret:aiand}} set";

    // The context side. Nothing here replaces anything, so the value is
    // absent and the handle is present.
    try testing.expect(std.mem.indexOf(u8, definition, the_secret) == null);
    try testing.expect(std.mem.indexOf(u8, definition, "{{secret:aiand}}") != null);

    // The child side, built by the launcher after the model output is
    // parsed.
    const child_env = try resolveEnv(testStore(), gpa, &.{
        "PATH=/usr/bin",
        "AIAND_TOKEN={{secret:aiand}}",
        "GITHUB_TOKEN={{secret:github}}",
    }, null);
    defer freeEnv(gpa, child_env);

    try testing.expectEqualStrings("PATH=/usr/bin", child_env[0]);
    try testing.expectEqualStrings("AIAND_TOKEN=" ++ the_secret, child_env[1]);
    try testing.expectEqualStrings("GITHUB_TOKEN=" ++ other_secret, child_env[2]);

    // Two handles in one string, and text on both sides of each.
    const both = try resolve(testStore(), gpa, "a{{secret:aiand}}b{{secret:github}}c", null);
    defer gpa.free(both);
    try testing.expectEqualStrings("a" ++ the_secret ++ "b" ++ other_secret ++ "c", both);

    // A handle for a credential this store does not hold is refused rather
    // than passed through, so the mistake is reported here and not much
    // later as a request the user cannot explain.
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
    // `env` is the call that does it: it prints every variable, so every
    // credential the child was given comes back in the result.
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

    // Neither value is anywhere in the log, in any line, in any field.
    try testing.expect(std.mem.indexOf(u8, logBytes(&backing), the_secret) == null);
    try testing.expect(std.mem.indexOf(u8, logBytes(&backing), other_secret) == null);

    // And the result is still a usable result: the rest of the environment
    // is there, and each value became one marker.
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
    // The hard case, and the one a scan of each piece on its own fails. A
    // streamed result arrives in pieces, and a value can end one piece and
    // start the next, so neither piece holds it.
    const gpa = testing.allocator;

    // Every cut of the value, one at a time, including the two that leave a
    // single byte on one side.
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

    // One byte at a time, which is the worst a stream can do.
    {
        var redactor = try Redactor.init(gpa, testStore());
        defer redactor.deinit(gpa);
        const whole = "x" ++ the_secret ++ "y";
        for (whole) |byte| try redactor.push(gpa, &.{byte});
        const result = try redactor.finish(gpa);
        defer gpa.free(result);
        try testing.expectEqualStrings("x" ++ redacted_marker ++ "y", result);
    }

    // Nothing is lost when a piece ends in bytes that could have become a
    // value and then did not. This is what the held back bytes cost, and
    // `finish` is what pays it back.
    {
        var redactor = try Redactor.init(gpa, testStore());
        defer redactor.deinit(gpa);
        try redactor.push(gpa, "the tail is " ++ the_secret[0 .. the_secret.len - 1]);
        const result = try redactor.finish(gpa);
        defer gpa.free(result);
        try testing.expectEqualStrings("the tail is " ++ the_secret[0 .. the_secret.len - 1], result);
    }

    // Two values, one whole and one split, in the same stream.
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
    // The log is append only and `chockd` serves it to other clients, so a
    // value that reaches it has already been given away and a redaction that
    // runs later cannot take it back.
    //
    // Two facts pin the order. First: the log's own bytes never hold the
    // value, and an implementation that appended and then redacted would
    // have to rewrite a line the log cannot rewrite. Second: a result that
    // was streamed through a `Redactor` still goes in through the same one
    // function, so there is no second way in that could forget.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01SECRET");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    // A streamed result, cut through the middle of the value.
    var redactor = try Redactor.init(gpa, testStore());
    defer redactor.deinit(gpa);
    try redactor.push(gpa, "token is " ++ the_secret[0..7]);
    const bytes_in_the_log_so_far = logBytes(&backing).len;
    try redactor.push(gpa, the_secret[7..] ++ "\n");
    const streamed = try redactor.finish(gpa);
    defer gpa.free(streamed);

    // Nothing was written while the pieces were arriving. A redactor that
    // wrote as it read would have put the first piece in the log, and that
    // first piece is where the value starts.
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

    // The same value, appended without ever being streamed, is redacted too.
    // Both routes end at the one function, which is what makes the rule hold
    // with no second path to remember.
    _ = try appendToolResult(testStore(), gpa, io, &locked, .{
        .call_id = "call2",
        .output = "raw " ++ the_secret,
        .is_error = true,
        .truncated = false,
    }, 1_700_000_000_001);
    try testing.expect(std.mem.indexOf(u8, logBytes(&backing), the_secret) == null);

    // Two results are in the log, so neither append was skipped, and the
    // second kept its own `is_error`.
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
    // An empty needle matches at every position, so a store entry with an
    // empty value would turn a whole result into markers. It is left out of
    // the search instead.
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
    // On a tie the longer value wins. Without that, redacting the shorter
    // one first would leave the rest of the longer one in the log, which is
    // most of a credential.
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
