//! The session log: one file, one line per event, JSON Lines on disk. The byte
//! offset `append` returns is that event's identifier. An envelope's `id` field is
//! always zero on disk, so a reader takes the identifier from the seek offset.

const std = @import("std");
const chain = @import("chain.zig");
const event = @import("event.zig");
const chock_io = @import("chock-io");
const short_write_probe = @import("short_write_probe.zig");

const format_version: u32 = 1;

pub const max_header_bytes: usize = 64;

pub const LogError = error{
    FileNotFound,
    AccessDenied,
    IsDir,
    OpenFailed,
    WriteFailed,
    ShortWrite,
    SyncFailed,
    OffsetOutOfRange,
    OffsetNotLineStart,
    Busy,
    NotLocked,
    BadHeader,
    Unexpected,
} || event.EncodeError;

pub const Log = struct {
    file: std.Io.File,
    session: []const u8,
    /// What `open` found, never an instruction: another `Log` on the same path can
    /// move the fragment or remove it, so `append` finds it again itself.
    tail_was_torn: bool = false,
    torn_tail_at: u64 = 0,
    lock_generation: u64 = 0,

    /// Opened through `std.posix.openatZ` because no option in `std.Io.Dir` asks for
    /// `O_APPEND`, and `append` needs it to land every write at the true end of file.
    pub fn open(io: std.Io, path: [:0]const u8, session: []const u8) LogError!Log {
        const flags: std.posix.O = .{ .ACCMODE = .RDWR, .CREAT = true, .APPEND = true };
        const fd = std.posix.openatZ(std.posix.AT.FDCWD, path, flags, 0o644) catch |err| switch (err) {
            error.FileNotFound => return error.FileNotFound,
            error.AccessDenied => return error.AccessDenied,
            error.IsDir => return error.IsDir,
            else => return error.OpenFailed,
        };

        var log: Log = .{
            .file = .{ .handle = fd, .flags = .{ .nonblocking = false } },
            .session = session,
        };
        log.ensureHeader(io) catch |err| {
            log.file.close(io);
            return err;
        };
        log.checkTornTail(io) catch |err| {
            log.file.close(io);
            return err;
        };
        return log;
    }

    /// Safe to call more than once, and the handle check is what makes it safe:
    /// `std.Io` panics on a close of an invalid handle where `close(2)` gave `EBADF`.
    pub fn close(self: *Log, io: std.Io) void {
        if (self.file.handle == -1) return;
        self.file.close(io);
        self.file.handle = -1;
    }

    /// `tryLock` is `flock(2)`, which locks the open file description and not the
    /// path: two `open` calls contend correctly, but a `dup` of one shares the lock.
    pub fn lock(self: *Log, io: std.Io) LogError!Locked {
        std.debug.assert(self.file.handle != -1);
        const acquired = self.file.tryLock(io, .exclusive) catch return error.Unexpected;
        if (!acquired) return error.Busy;
        self.lock_generation +%= 1;
        return .{ .log = self, .generation = self.lock_generation };
    }

    fn ensureHeader(self: *Log, io: std.Io) LogError!void {
        var buffer: [max_header_bytes]u8 = undefined;
        const filled = self.file.readPositionalAll(io, &buffer, 0) catch return error.Unexpected;

        if (filled == 0) return self.writeHeader(io);

        const newline = std.mem.indexOfScalar(u8, buffer[0..filled], '\n') orelse return error.BadHeader;
        const header_line = buffer[0..newline];

        const prefix = "{\"chock_log\":";
        const suffix = "}";
        if (!std.mem.startsWith(u8, header_line, prefix) or !std.mem.endsWith(u8, header_line, suffix))
            return error.BadHeader;

        const number_text = header_line[prefix.len .. header_line.len - suffix.len];
        const version = parseVersionNumber(number_text) orelse return error.BadHeader;
        if (version != format_version) return error.BadHeader;
    }

    fn writeHeader(self: *Log, io: std.Io) LogError!void {
        const line = std.fmt.comptimePrint("{{\"chock_log\":{d}}}\n", .{format_version});
        try self.writeExact(io, line);
    }

    /// Never writes: a read only caller must see the same tear a writer does.
    fn checkTornTail(self: *Log, io: std.Io) LogError!void {
        const size = try self.tailIsTorn(io) orelse return;
        self.tail_was_torn = true;
        self.torn_tail_at = try self.findTornFragmentStart(io, size);
    }

    fn tailIsTorn(self: *Log, io: std.Io) LogError!?u64 {
        const size = self.file.length(io) catch return error.Unexpected;
        if (size == 0) return null;

        var last_byte: [1]u8 = undefined;
        const n = self.file.readPositionalAll(io, &last_byte, size - 1) catch return error.Unexpected;
        if (n != 1) return error.Unexpected;
        if (last_byte[0] == '\n') return null;
        return size;
    }

    /// Never answers the header: a caller about to cut must not cut that away.
    fn findTornFragmentStart(self: *Log, io: std.Io, size: u64) LogError!u64 {
        const header_end = try self.headerEnd(io);
        return @max(header_end, try self.findLineStart(io, size));
    }

    fn findLineStart(self: *const Log, io: std.Io, end: u64) LogError!u64 {
        var read_buffer: [4096]u8 = undefined;
        var pos = end;
        while (pos > 0) {
            const chunk_len: usize = @intCast(@min(read_buffer.len, pos));
            const chunk_start = pos - chunk_len;
            const n = self.file.readPositionalAll(io, read_buffer[0..chunk_len], chunk_start) catch return error.Unexpected;
            if (std.mem.lastIndexOfScalar(u8, read_buffer[0..n], '\n')) |i| {
                return chunk_start + i + 1;
            }
            pos = chunk_start;
        }
        return 0;
    }

    fn digestOfRange(self: *const Log, io: std.Io, start: u64, end: u64) LogError!chain.Digest {
        std.debug.assert(start <= end);
        var hasher: chain.Hasher = .{};
        var pos = start;
        var read_buffer: [4096]u8 = undefined;
        while (pos < end) {
            const want: usize = @intCast(@min(read_buffer.len, end - pos));
            const n = self.file.readPositionalAll(io, read_buffer[0..want], pos) catch return error.Unexpected;
            // A short read means the file was cut underneath us. Never hash part.
            if (n == 0) return error.Unexpected;
            hasher.update(read_buffer[0..n]);
            pos += n;
        }
        return hasher.finish();
    }

    pub fn headerDigest(self: *const Log, io: std.Io) LogError!chain.Digest {
        const header_end = try self.headerEnd(io);
        return self.digestOfRange(io, 0, header_end - 1);
    }

    /// A copied log must carry these bytes: a header composed again verifies only
    /// while the two spellings agree.
    pub fn headerLine(self: *const Log, io: std.Io, buffer: *[max_header_bytes]u8) LogError![]const u8 {
        const filled = self.file.readPositionalAll(io, buffer, 0) catch return error.Unexpected;
        const newline = std.mem.indexOfScalar(u8, buffer[0..filled], '\n') orelse return error.BadHeader;
        return buffer[0..newline];
    }

    /// Read on every call, never remembered: another `Log` on this path can append.
    fn lastLineDigest(self: *const Log, io: std.Io) LogError!chain.Digest {
        const size = self.file.length(io) catch return error.Unexpected;
        std.debug.assert(size > 0);
        const end = size - 1;
        return self.digestOfRange(io, try self.findLineStart(io, end), end);
    }

    /// One write per call. A short result is reported, never completed with a second.
    fn writeExact(self: *Log, io: std.Io, line: []const u8) LogError!void {
        const written = self.file.writeStreaming(io, &.{}, &.{line}, 1) catch return error.WriteFailed;
        if (written != line.len) return error.ShortWrite;
    }

    /// Inclusive of `offset`, so it is wrong for a client's `Last-Event-ID`, which
    /// names an event the client already has. Use `resumeAfter` for that.
    pub fn replayFrom(self: *const Log, allocator: std.mem.Allocator, io: std.Io, offset: u64) LogError!Replay {
        const header_end = try self.headerEnd(io);
        if (offset == 0) return .{ .file = self.file, .allocator = allocator, .pos = header_end };

        const size = self.file.length(io) catch return error.Unexpected;
        if (offset < header_end or offset >= size) return error.OffsetOutOfRange;

        var prev_byte: [1]u8 = undefined;
        const n = self.file.readPositionalAll(io, &prev_byte, offset - 1) catch return error.Unexpected;
        if (n != 1) return error.Unexpected;
        if (prev_byte[0] != '\n') return error.OffsetNotLineStart;

        return .{ .file = self.file, .allocator = allocator, .pos = offset };
    }

    pub fn resumeAfter(
        self: *const Log,
        allocator: std.mem.Allocator,
        io: std.Io,
        last_event_id: u64,
    ) (LogError || event.DecodeError)!Replay {
        var replay = try self.replayFrom(allocator, io, last_event_id);
        if (last_event_id == 0) return replay;
        errdefer replay.deinit();

        const named_event = try replay.next(io);
        if (named_event) |parsed| parsed.deinit();
        return replay;
    }

    fn headerEnd(self: *const Log, io: std.Io) LogError!u64 {
        var buffer: [max_header_bytes]u8 = undefined;
        const filled = self.file.readPositionalAll(io, &buffer, 0) catch return error.Unexpected;
        const newline = std.mem.indexOfScalar(u8, buffer[0..filled], '\n') orelse return error.BadHeader;
        return newline + 1;
    }
};

/// The file boundary stops naming `Locked`, not building one: Zig still builds a
/// value of a type it cannot name, through `@TypeOf`. `generation` is what refuses it.
const Locked = struct {
    log: *Log,
    generation: u64,
    held: bool = true,

    pub fn unlock(self: *Locked, io: std.Io) LogError!void {
        std.debug.assert(self.log.file.handle != -1);
        self.log.file.unlock(io);
        self.held = false;
    }

    pub fn append(self: *Locked, allocator: std.mem.Allocator, io: std.Io, ev: event.Event, time_ms: i64) LogError!u64 {
        const log = self.log;

        std.debug.assert(log.file.handle != -1);
        // Real `if`s, not asserts: a stripped check gives an offset to a stranger.
        if (self.generation != log.lock_generation) return error.NotLocked;
        if (!self.held) return error.NotLocked;

        // Ask the file every time, both whether a tear exists and where it starts.
        // Cutting to the offset `open` cached destroys committed events.
        if (try log.tailIsTorn(io)) |size| {
            const cut_at = try log.findTornFragmentStart(io, size);
            log.file.setLength(io, cut_at) catch return error.Unexpected;
        }
        log.tail_was_torn = false;

        const prev = try log.lastLineDigest(io);

        const envelope = event.Envelope{
            .id = 0,
            .session = log.session,
            .time_ms = time_ms,
            .event = ev,
            .prev = &prev,
        };
        const text = try event.toJson(allocator, envelope);
        defer allocator.free(text);

        // The line and its newline reach the kernel as one write. A crash between
        // two writes leaves a line a replay cannot tell from a partial write.
        const line = try std.fmt.allocPrint(allocator, "{s}\n", .{text});
        defer allocator.free(line);

        // Correct only because the lock makes this log the one writer.
        const offset = log.file.length(io) catch return error.Unexpected;

        try log.writeExact(io, line);

        // `sync` on every append, slow and deliberate: an approval record must live.
        log.file.sync(io) catch return error.SyncFailed;

        return offset;
    }
};

pub const Replay = struct {
    file: std.Io.File,
    allocator: std.mem.Allocator,
    pos: u64,
    buffer: std.ArrayList(u8) = .empty,
    /// Reflects the last call to `next` alone: read it right after each `next` that
    /// gave null, because an owner can append past the tear between two calls.
    truncated: bool = false,
    truncated_at: u64 = 0,

    pub fn deinit(self: *Replay) void {
        self.buffer.deinit(self.allocator);
    }

    /// The writer's own bytes, for a verifier. Meaningless after a second `next`.
    pub fn line(self: *const Replay) []const u8 {
        return self.buffer.items;
    }

    /// A tear is never an error, but a complete line that is not valid JSON is one.
    /// A tear does not end the replay: `pos` stays put for the next call.
    pub fn next(self: *Replay, io: std.Io) (LogError || event.DecodeError)!?std.json.Parsed(event.Envelope) {
        self.buffer.clearRetainingCapacity();
        const line_start = self.pos;
        var read_buffer: [4096]u8 = undefined;
        var saw_any_bytes = false;

        while (true) {
            const n = self.file.readPositionalAll(io, &read_buffer, self.pos) catch return error.Unexpected;

            if (n == 0) {
                if (!saw_any_bytes) {
                    self.truncated = false;
                    return null;
                }
                self.truncated = true;
                self.truncated_at = line_start;
                // Back to the line start, so a later call notices a real line there.
                self.pos = line_start;
                return null;
            }

            saw_any_bytes = true;
            if (std.mem.indexOfScalar(u8, read_buffer[0..n], '\n')) |newline_index| {
                try self.buffer.appendSlice(self.allocator, read_buffer[0..newline_index]);
                self.pos += newline_index + 1;
                self.truncated = false;

                var parsed = try event.fromJson(self.allocator, self.buffer.items);
                parsed.value.id = line_start;
                return parsed;
            }

            try self.buffer.appendSlice(self.allocator, read_buffer[0..n]);
            self.pos += n;
        }
    }
};

/// `std.fmt.parseInt` alone accepts `+1` and `01` as 1, and JSON accepts neither,
/// so a corrupt header would pass as version 1 without this check.
fn parseVersionNumber(text: []const u8) ?u32 {
    if (text.len == 0) return null;
    for (text) |c| {
        if (c < '0' or c > '9') return null;
    }
    if (text.len > 1 and text[0] == '0') return null;
    return std.fmt.parseInt(u32, text, 10) catch null;
}

pub const AbsoluteDirPathError = error{RealPathFailed};

/// `pub` only because `test/proto/lock.zig` is a separate test binary.
pub fn absoluteDirPath(io: std.Io, buffer: []u8, dir: std.Io.Dir) AbsoluteDirPathError![:0]u8 {
    const len = dir.realPath(io, buffer) catch return error.RealPathFailed;
    buffer[len] = 0;
    return buffer[0..len :0];
}

const TestLog = struct {
    tmp: std.testing.TmpDir,
    log: Log,
    path_buffer: [std.fs.max_path_bytes]u8 = undefined,
    path_len: usize,

    fn init(name: []const u8) !TestLog {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const dir_path = try absoluteDirPath(std.testing.io, &dir_path_buffer, tmp.dir);

        var self: TestLog = .{ .tmp = tmp, .log = undefined, .path_len = 0 };
        const written = try std.fmt.bufPrintZ(&self.path_buffer, "{s}/{s}", .{ dir_path, name });
        self.path_len = written.len;

        self.log = try Log.open(std.testing.io, self.path(), "01TESTSESSION");
        // The handle is discarded: it points at `self.log`, returned by value.
        _ = try self.log.lock(std.testing.io);
        return self;
    }

    fn deinit(self: *TestLog) void {
        self.log.close(std.testing.io);
        self.tmp.cleanup();
    }

    fn path(self: *const TestLog) [:0]const u8 {
        return self.path_buffer[0..self.path_len :0];
    }

    fn append(self: *TestLog, allocator: std.mem.Allocator, ev: event.Event, time_ms: i64) !u64 {
        var locked = try self.log.lock(std.testing.io);
        return locked.append(allocator, std.testing.io, ev, time_ms);
    }

    fn reopen(self: *TestLog) !void {
        self.log.close(std.testing.io);
        self.log = try Log.open(std.testing.io, self.path(), "01TESTSESSION");
        _ = try self.log.lock(std.testing.io);
    }

    fn readAll(self: *TestLog, allocator: std.mem.Allocator) ![]u8 {
        const size = self.log.file.length(std.testing.io) catch return error.Unexpected;
        const bytes = try allocator.alloc(u8, size);
        errdefer allocator.free(bytes);
        const n = self.log.file.readPositionalAll(std.testing.io, bytes, 0) catch return error.Unexpected;
        return bytes[0..n];
    }

    fn truncateTo(self: *TestLog, len: u64) !void {
        self.log.file.setLength(std.testing.io, len) catch return error.Unexpected;
    }
};

const TornLogOffsets = struct {
    before_offset: u64,
    fragment_offset: u64,
};

fn seedTornLog(io: std.Io, path: [:0]const u8) !TornLogOffsets {
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true });
    defer file.close(io);

    const header = std.fmt.comptimePrint("{{\"chock_log\":{d}}}\n", .{format_version});
    try file.writeStreamingAll(io, header);
    const before_offset: u64 = header.len;

    const allocator = std.testing.allocator;
    const before_text = try event.toJson(allocator, .{
        .id = 0,
        .session = "01TESTSESSION",
        .time_ms = 1,
        .event = .{ .message = .{ .role = .user, .content = &.{.{ .text = "before" }} } },
    });
    defer allocator.free(before_text);
    const before_line = try std.fmt.allocPrint(allocator, "{s}\n", .{before_text});
    defer allocator.free(before_line);
    try file.writeStreamingAll(io, before_line);
    const fragment_offset = before_offset + before_line.len;

    const fragment = "{\"id\":0,\"session\":\"01TE";
    try file.writeStreamingAll(io, fragment);

    return .{ .before_offset = before_offset, .fragment_offset = fragment_offset };
}

test "append returns the offset of the line it wrote, and the next append follows it" {
    const allocator = std.testing.allocator;
    var tmp = try TestLog.init("append-offsets");
    defer tmp.deinit();

    const first = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "a" }} } }, 1);
    const second = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "b" }} } }, 2);

    try std.testing.expect(second > first);
    const bytes = try tmp.readAll(allocator);
    defer allocator.free(bytes);
    try std.testing.expectEqual(second, std.mem.indexOfScalarPos(u8, bytes, first, '\n').? + 1);
}

test "every append ends with exactly one newline" {
    const allocator = std.testing.allocator;
    var tmp = try TestLog.init("append-newline");
    defer tmp.deinit();

    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "a\nb" }} } }, 1);
    const bytes = try tmp.readAll(allocator);
    defer allocator.free(bytes);

    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, bytes, "\n"));
}

test "a new log starts with a header that names the format version" {
    const allocator = std.testing.allocator;
    var tmp = try TestLog.init("append-header");
    defer tmp.deinit();

    const bytes = try tmp.readAll(allocator);
    defer allocator.free(bytes);
    try std.testing.expect(std.mem.startsWith(u8, bytes, "{\"chock_log\":"));
}

test "append refuses a file whose header names a version this build does not know" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/future-header", .{dir_path});

    {
        var log = try Log.open(io, path, "01TESTSESSION");
        defer log.close(io);
    }
    {
        var file = try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, "{\"chock_log\":999}\n");
    }

    try std.testing.expectError(error.BadHeader, Log.open(io, path, "01TESTSESSION"));
}

test "regression: a header naming a version with a leading zero or a leading plus is not accepted as version 1" {
    const io = std.testing.io;
    const bad_headers = [_][]const u8{
        "{\"chock_log\":01}\n",
        "{\"chock_log\":+1}\n",
    };

    for (bad_headers, 0..) |bad_header, i| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();

        var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/bad-version-{d}", .{ dir_path, i });

        var file = try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true });
        try file.writeStreamingAll(io, bad_header);
        file.close(io);

        try std.testing.expectError(error.BadHeader, Log.open(io, path, "01TESTSESSION"));
    }
}

test "closing a log twice does not touch whatever descriptor the kernel hands out next" {
    var tmp = try TestLog.init("double-close");
    defer tmp.deinit();

    tmp.log.close(std.testing.io);
    try std.testing.expectEqual(@as(std.posix.fd_t, -1), tmp.log.file.handle);
}

/// Each payload can move a byte offset in a way plain ASCII never would.
const offset_contract_payloads = [_][]const u8{
    "héllo wörld",
    "🎉 party",
    "she said \"hi\"",
    "a\\b",
    "line one\nline two",
};

fn expectEventLineAt(allocator: std.mem.Allocator, bytes: []const u8, offset: u64, expected_text: []const u8) !void {
    try std.testing.expectEqual(@as(u8, '\n'), bytes[offset - 1]);
    try std.testing.expectEqual(@as(u8, '{'), bytes[offset]);

    const line_end = std.mem.indexOfScalarPos(u8, bytes, offset, '\n').?;
    const parsed = try event.fromJson(allocator, bytes[offset..line_end]);
    defer parsed.deinit();
    try std.testing.expectEqualStrings(expected_text, parsed.value.event.message.content[0].text);
}

test "append's offset is the exact byte where its line starts, for payloads that can shift a byte boundary" {
    const allocator = std.testing.allocator;
    var tmp = try TestLog.init("append-offset-contract");
    defer tmp.deinit();

    var offsets: [offset_contract_payloads.len]u64 = undefined;
    for (offset_contract_payloads, 0..) |text, i| {
        offsets[i] = try tmp.append(
            allocator,
            .{ .message = .{ .role = .user, .content = &.{.{ .text = text }} } },
            @intCast(i + 1),
        );
    }

    const bytes = try tmp.readAll(allocator);
    defer allocator.free(bytes);
    for (offset_contract_payloads, 0..) |text, i| {
        try expectEventLineAt(allocator, bytes, offsets[i], text);
    }
}

test "an append's offset still locates its line after the log is closed and reopened" {
    const allocator = std.testing.allocator;
    var tmp = try TestLog.init("append-offset-reopen");
    defer tmp.deinit();

    var offsets: [offset_contract_payloads.len]u64 = undefined;
    for (offset_contract_payloads, 0..) |text, i| {
        offsets[i] = try tmp.append(
            allocator,
            .{ .message = .{ .role = .user, .content = &.{.{ .text = text }} } },
            @intCast(i + 1),
        );
    }

    try tmp.reopen();

    const bytes = try tmp.readAll(allocator);
    defer allocator.free(bytes);
    for (offset_contract_payloads, 0..) |text, i| {
        try expectEventLineAt(allocator, bytes, offsets[i], text);
    }
}

test "a write that lands short at the kernel is reported as ShortWrite, never retried or silently accepted" {
    // A write above PIPE_BUF loses its atomicity, so a nonblocking pipe gives a
    // short write on demand. The mechanism is portable, this reproduction is not.
    const chock_io_driver = chock_io.default();
    const raw_pipe = try chock_io_driver.pipeCloseOnExec();
    defer std.Io.File.close(.{ .handle = raw_pipe.read_fd, .flags = .{ .nonblocking = false } }, std.testing.io);
    defer std.Io.File.close(.{ .handle = raw_pipe.write_fd, .flags = .{ .nonblocking = false } }, std.testing.io);
    try short_write_probe.setNonblocking(raw_pipe.write_fd);

    const over_capacity = try short_write_probe.overCapacity(raw_pipe.write_fd);

    const allocator = std.testing.allocator;
    const line = try allocator.alloc(u8, over_capacity);
    defer allocator.free(line);
    @memset(line, 'a');

    var log: Log = .{
        .file = .{ .handle = raw_pipe.write_fd, .flags = .{ .nonblocking = true } },
        .session = "01TESTSESSION",
    };
    try std.testing.expectError(error.ShortWrite, log.writeExact(std.testing.io, line));
}

test "regression: a torn tail from an interrupted append does not swallow every event after it" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/torn-tail", .{dir_path});

    {
        var seed_file = try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true });
        defer seed_file.close(io);
        try seed_file.writeStreamingAll(io, "{\"chock_log\":1}\n{\"id\":0,\"session\":\"01TE");
    }

    const allocator = std.testing.allocator;
    var log = try Log.open(io, path, "01TESTSESSION");
    defer log.close(io);

    try std.testing.expect(log.tail_was_torn);

    var locked = try log.lock(io);
    const offset = try locked.append(
        allocator,
        io,
        .{ .message = .{ .role = .user, .content = &.{.{ .text = "after the tear" }} } },
        1,
    );

    const size = log.file.length(io) catch return error.Unexpected;
    const read_buffer = try allocator.alloc(u8, size);
    defer allocator.free(read_buffer);
    const n = log.file.readPositionalAll(io, read_buffer, 0) catch return error.Unexpected;
    const bytes = read_buffer[0..n];

    try expectEventLineAt(allocator, bytes, offset, "after the tear");
}

test "regression: open then replay on a torn log reports the tear instead of a decode error" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/torn-open-then-replay", .{dir_path});

    const allocator = std.testing.allocator;
    _ = try seedTornLog(io, path);

    var log = try Log.open(io, path, "01TESTSESSION");
    defer log.close(io);
    try std.testing.expect(log.tail_was_torn);

    var replay = try log.replayFrom(allocator, io, 0);
    defer replay.deinit();

    const first = (try replay.next(io)).?;
    defer first.deinit();
    try std.testing.expectEqualStrings("before", first.value.event.message.content[0].text);

    try std.testing.expect((try replay.next(io)) == null);
    try std.testing.expect(replay.truncated);
}

test "an append after a torn open removes the fragment and lands a valid line at the right offset" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/torn-append-truncates", .{dir_path});

    const allocator = std.testing.allocator;
    const seed = try seedTornLog(io, path);

    var log = try Log.open(io, path, "01TESTSESSION");
    defer log.close(io);
    try std.testing.expectEqual(seed.fragment_offset, log.torn_tail_at);

    var locked = try log.lock(io);
    const offset = try locked.append(
        allocator,
        io,
        .{ .message = .{ .role = .user, .content = &.{.{ .text = "after the tear" }} } },
        2,
    );

    try std.testing.expectEqual(seed.fragment_offset, offset);
    try std.testing.expect(!log.tail_was_torn);

    const size = log.file.length(io) catch return error.Unexpected;
    const read_buffer = try allocator.alloc(u8, size);
    defer allocator.free(read_buffer);
    const n = log.file.readPositionalAll(io, read_buffer, 0) catch return error.Unexpected;
    const bytes = read_buffer[0..n];

    try expectEventLineAt(allocator, bytes, offset, "after the tear");
    const line_end = std.mem.indexOfScalarPos(u8, bytes, offset, '\n').? + 1;
    try std.testing.expectEqual(bytes.len, line_end);
}

test "a replay after that append reads every event with no tear reported" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/torn-append-then-replay", .{dir_path});

    const allocator = std.testing.allocator;
    _ = try seedTornLog(io, path);

    var log = try Log.open(io, path, "01TESTSESSION");
    defer log.close(io);
    var locked = try log.lock(io);
    _ = try locked.append(
        allocator,
        io,
        .{ .message = .{ .role = .user, .content = &.{.{ .text = "after the tear" }} } },
        2,
    );

    var replay = try log.replayFrom(allocator, io, 0);
    defer replay.deinit();

    const expected_texts = [_][]const u8{ "before", "after the tear" };
    var i: usize = 0;
    while (try replay.next(io)) |envelope| {
        defer envelope.deinit();
        try std.testing.expectEqualStrings(expected_texts[i], envelope.value.event.message.content[0].text);
        i += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), i);
    try std.testing.expect(!replay.truncated);
}

test "regression: a stale torn tail flag on a second handle does not destroy what the first handle wrote" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/handover-stale-tear", .{dir_path});

    const allocator = std.testing.allocator;
    _ = try seedTornLog(io, path);

    var owner_a = try Log.open(io, path, "01TESTSESSION");
    defer owner_a.close(io);
    try std.testing.expect(owner_a.tail_was_torn);
    var owner_b = try Log.open(io, path, "01TESTSESSION");
    defer owner_b.close(io);
    try std.testing.expect(owner_b.tail_was_torn);

    var locked_a = try owner_a.lock(io);
    const a_texts = [_][]const u8{ "a-one", "a-two", "a-three" };
    for (a_texts, 0..) |text, i| {
        _ = try locked_a.append(
            allocator,
            io,
            .{ .message = .{ .role = .user, .content = &.{.{ .text = text }} } },
            @intCast(i + 1),
        );
    }
    try locked_a.unlock(io);

    var locked_b = try owner_b.lock(io);
    _ = try locked_b.append(
        allocator,
        io,
        .{ .message = .{ .role = .user, .content = &.{.{ .text = "b-one" }} } },
        4,
    );

    var replay = try owner_b.replayFrom(allocator, io, 0);
    defer replay.deinit();
    const expected_texts = [_][]const u8{ "before", "a-one", "a-two", "a-three", "b-one" };
    var i: usize = 0;
    while (try replay.next(io)) |envelope| {
        defer envelope.deinit();
        try std.testing.expectEqualStrings(expected_texts[i], envelope.value.event.message.content[0].text);
        i += 1;
    }
    try std.testing.expectEqual(expected_texts.len, i);
    try std.testing.expect(!replay.truncated);
}

test "regression: cutting a fresh tear at the offset an earlier open cached destroys the events written since" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/handover-fresh-tear", .{dir_path});

    const allocator = std.testing.allocator;

    var owner_b = try Log.open(io, path, "01TESTSESSION");
    defer owner_b.close(io);
    try std.testing.expect(!owner_b.tail_was_torn);

    var owner_a = try Log.open(io, path, "01TESTSESSION");
    var locked_a = try owner_a.lock(io);
    var a_texts: [10][]const u8 = undefined;
    var text_buffers: [10][8]u8 = undefined;
    for (0..10) |i| {
        a_texts[i] = try std.fmt.bufPrint(&text_buffers[i], "a-{d}", .{i});
        _ = try locked_a.append(
            allocator,
            io,
            .{ .message = .{ .role = .user, .content = &.{.{ .text = a_texts[i] }} } },
            @intCast(i + 1),
        );
    }
    const fragment_written = owner_a.file.writeStreaming(io, &.{}, &.{"{\"id\":0,\"session\":\"01TE"}, 1) catch return error.Unexpected;
    try std.testing.expectEqual(@as(usize, "{\"id\":0,\"session\":\"01TE".len), fragment_written);
    owner_a.close(io);

    var locked_b = try owner_b.lock(io);
    _ = try locked_b.append(
        allocator,
        io,
        .{ .message = .{ .role = .user, .content = &.{.{ .text = "b-one" }} } },
        11,
    );

    var replay = try owner_b.replayFrom(allocator, io, 0);
    defer replay.deinit();
    var expected_texts: [11][]const u8 = undefined;
    @memcpy(expected_texts[0..10], &a_texts);
    expected_texts[10] = "b-one";
    var i: usize = 0;
    while (try replay.next(io)) |envelope| {
        defer envelope.deinit();
        try std.testing.expectEqualStrings(expected_texts[i], envelope.value.event.message.content[0].text);
        i += 1;
    }
    try std.testing.expectEqual(@as(usize, 11), i);
    try std.testing.expect(!replay.truncated);
}

test "regression: a tear that appears after this handle's own open is still found and cut" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/tear-after-open", .{dir_path});

    const allocator = std.testing.allocator;
    var log = try Log.open(io, path, "01TESTSESSION");
    defer log.close(io);
    try std.testing.expect(!log.tail_was_torn);

    var locked = try log.lock(io);
    _ = try locked.append(
        allocator,
        io,
        .{ .message = .{ .role = .user, .content = &.{.{ .text = "before" }} } },
        1,
    );
    try std.testing.expect(!log.tail_was_torn);
    const fragment = "{\"id\":0,\"session\":\"01TE";
    const fragment_written = log.file.writeStreaming(io, &.{}, &.{fragment}, 1) catch return error.Unexpected;
    try std.testing.expectEqual(@as(usize, fragment.len), fragment_written);

    const offset = try locked.append(
        allocator,
        io,
        .{ .message = .{ .role = .user, .content = &.{.{ .text = "after" }} } },
        2,
    );

    var replay = try log.replayFrom(allocator, io, 0);
    defer replay.deinit();
    const first = (try replay.next(io)).?;
    defer first.deinit();
    try std.testing.expectEqualStrings("before", first.value.event.message.content[0].text);
    const second = (try replay.next(io)).?;
    defer second.deinit();
    try std.testing.expectEqual(offset, second.value.id);
    try std.testing.expectEqualStrings("after", second.value.event.message.content[0].text);
    try std.testing.expect((try replay.next(io)) == null);
    try std.testing.expect(!replay.truncated);
}

test "regression: a replay resumes once an owner appends past a tear it already reported" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/replay-resumes-after-tear", .{dir_path});

    const allocator = std.testing.allocator;
    _ = try seedTornLog(io, path);

    var reader = try Log.open(io, path, "01TESTSESSION");
    defer reader.close(io);

    var replay = try reader.replayFrom(allocator, io, 0);
    defer replay.deinit();

    const first = (try replay.next(io)).?;
    defer first.deinit();
    try std.testing.expectEqualStrings("before", first.value.event.message.content[0].text);

    try std.testing.expect((try replay.next(io)) == null);
    try std.testing.expect(replay.truncated);

    var writer = try Log.open(io, path, "01TESTSESSION");
    defer writer.close(io);
    var locked = try writer.lock(io);
    _ = try locked.append(
        allocator,
        io,
        .{ .message = .{ .role = .user, .content = &.{.{ .text = "after restart" }} } },
        2,
    );

    const resumed = (try replay.next(io)).?;
    defer resumed.deinit();
    try std.testing.expectEqualStrings("after restart", resumed.value.event.message.content[0].text);
    try std.testing.expect(!replay.truncated);
}

test "replay gives back every event that append wrote, in order" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("replay-order");
    defer tmp.deinit();

    const first = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);
    const second = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "two" }} } }, 2);
    const third = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "three" }} } }, 3);

    var replay = try tmp.log.replayFrom(allocator, io, 0);
    defer replay.deinit();

    const expected_offsets = [_]u64{ first, second, third };
    const expected_texts = [_][]const u8{ "one", "two", "three" };
    var i: usize = 0;
    while (try replay.next(io)) |envelope| {
        defer envelope.deinit();
        try std.testing.expectEqual(expected_offsets[i], envelope.value.id);
        try std.testing.expectEqualStrings(expected_texts[i], envelope.value.event.message.content[0].text);
        i += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), i);
    try std.testing.expect(!replay.truncated);
}

test "replay from an offset starts at that event and not before it" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("replay-from-offset");
    defer tmp.deinit();

    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);
    const second = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "two" }} } }, 2);
    const third = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "three" }} } }, 3);

    var replay = try tmp.log.replayFrom(allocator, io, second);
    defer replay.deinit();

    const first_seen = (try replay.next(io)).?;
    defer first_seen.deinit();
    try std.testing.expectEqual(second, first_seen.value.id);
    try std.testing.expectEqualStrings("two", first_seen.value.event.message.content[0].text);

    const second_seen = (try replay.next(io)).?;
    defer second_seen.deinit();
    try std.testing.expectEqual(third, second_seen.value.id);
    try std.testing.expectEqualStrings("three", second_seen.value.event.message.content[0].text);

    try std.testing.expect((try replay.next(io)) == null);
    try std.testing.expect(!replay.truncated);
}

test "regression: resumeAfter does not redeliver the event a client's Last-Event-ID names" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("resume-after-skips-named-event");
    defer tmp.deinit();

    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);
    const second = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "two" }} } }, 2);
    const third = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "three" }} } }, 3);

    var replay = try tmp.log.resumeAfter(allocator, io, second);
    defer replay.deinit();

    const only_seen = (try replay.next(io)).?;
    defer only_seen.deinit();
    try std.testing.expectEqual(third, only_seen.value.id);
    try std.testing.expectEqualStrings("three", only_seen.value.event.message.content[0].text);

    try std.testing.expect((try replay.next(io)) == null);
    try std.testing.expect(!replay.truncated);
}

test "resumeAfter the log's own last event returns nothing, not that event again" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("resume-after-last-event");
    defer tmp.deinit();

    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);
    const last = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "two" }} } }, 2);

    var replay = try tmp.log.resumeAfter(allocator, io, last);
    defer replay.deinit();

    try std.testing.expect((try replay.next(io)) == null);
    try std.testing.expect(!replay.truncated);
}

test "resumeAfter with an id of 0 replays from the start, since there is nothing yet to skip" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("resume-after-zero");
    defer tmp.deinit();

    const first = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);
    const second = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "two" }} } }, 2);

    var replay = try tmp.log.resumeAfter(allocator, io, 0);
    defer replay.deinit();

    const first_seen = (try replay.next(io)).?;
    defer first_seen.deinit();
    try std.testing.expectEqual(first, first_seen.value.id);

    const second_seen = (try replay.next(io)).?;
    defer second_seen.deinit();
    try std.testing.expectEqual(second, second_seen.value.id);

    try std.testing.expect((try replay.next(io)) == null);
}

test "replay stops at a truncated last line and says that it did" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("replay-truncated");
    defer tmp.deinit();

    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "whole" }} } }, 1);
    const second = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "cut" }} } }, 2);
    try tmp.truncateTo(second + 5);

    var replay = try tmp.log.replayFrom(allocator, io, 0);
    defer replay.deinit();

    var count: usize = 0;
    while (try replay.next(io)) |envelope| {
        defer envelope.deinit();
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expect(replay.truncated);
    try std.testing.expectEqual(second, replay.truncated_at);
}

test "replay refuses an offset past the end of the file instead of returning an empty stream" {
    // A caught up caller and one with a wrong offset both see nothing from a naive
    // replay. Only this error tells them apart.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("replay-offset-out-of-range");
    defer tmp.deinit();

    const offset = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);

    try std.testing.expectError(error.OffsetOutOfRange, tmp.log.replayFrom(allocator, io, offset + 1000));
}

test "replay refuses an offset that does not land on the start of a line" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("replay-offset-mid-line");
    defer tmp.deinit();

    const offset = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);

    try std.testing.expectError(error.OffsetNotLineStart, tmp.log.replayFrom(allocator, io, offset + 1));
}

// The test that a second process cannot take a held lock lives in test/proto/lock.zig:
// two `Log` values here cannot prove it, because two `open` calls already contend.

test "the lock is free again once the holder closes the log" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/lock-release-on-close", .{dir_path});

    var first = try Log.open(io, path, "01TESTSESSION");
    _ = try first.lock(io);

    var second = try Log.open(io, path, "01TESTSESSION");
    try std.testing.expectError(error.Busy, second.lock(io));

    first.close(io);
    _ = try second.lock(io);
    second.close(io);
}

test "taking the lock does not change the contents of the log" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("lock-is-not-a-write");
    defer tmp.deinit();

    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "before" }} } }, 1);
    const before = try tmp.readAll(allocator);
    defer allocator.free(before);

    var locked = try tmp.log.lock(io);
    try locked.unlock(io);
    locked = try tmp.log.lock(io);

    const after = try tmp.readAll(allocator);
    defer allocator.free(after);
    try std.testing.expectEqualStrings(before, after);
}

test "a released lock cannot be used to append" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("append-after-unlock");
    defer tmp.deinit();

    var locked = try tmp.log.lock(io);
    try locked.unlock(io);

    try std.testing.expectError(
        error.NotLocked,
        locked.append(allocator, io, .{ .message = .{ .role = .user, .content = &.{.{ .text = "too late" }} } }, 1),
    );
}

test "regression: a handle whose generation does not match the log's own is refused, not merely one whose held flag is false" {
    // `held` defaults to true on a struct literal, so it cannot catch a handle
    // built outside `lock`. The `generation` comparison is what does.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("forged-generation");
    defer tmp.deinit();

    var forged: Locked = .{ .log = &tmp.log, .generation = 0 };
    try std.testing.expectError(
        error.NotLocked,
        forged.append(allocator, io, .{ .message = .{ .role = .user, .content = &.{.{ .text = "forged" }} } }, 1),
    );
}

fn linesOf(allocator: std.mem.Allocator, bytes: []const u8) ![][]const u8 {
    var found: std.ArrayList([]const u8) = .empty;
    errdefer found.deinit(allocator);
    var walker = std.mem.splitScalar(u8, bytes, '\n');
    while (walker.next()) |one| {
        if (one.len == 0) continue;
        try found.append(allocator, one);
    }
    return found.toOwnedSlice(allocator);
}

fn prevOf(allocator: std.mem.Allocator, line: []const u8) ![]u8 {
    const parsed = try event.fromJson(allocator, line);
    defer parsed.deinit();
    return allocator.dupe(u8, parsed.value.prev);
}

test "the first event carries the header line's hash and each one after carries the line before it" {
    const allocator = std.testing.allocator;
    var tmp = try TestLog.init("chain-written");
    defer tmp.deinit();

    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);
    _ = try tmp.append(allocator, .{ .message = .{ .role = .assistant, .content = &.{.{ .text = "two" }} } }, 2);
    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "three" }} } }, 3);

    const bytes = try tmp.readAll(allocator);
    defer allocator.free(bytes);
    const lines = try linesOf(allocator, bytes);
    defer allocator.free(lines);
    try std.testing.expectEqual(@as(usize, 4), lines.len);

    for (lines[1..], 0..) |line, i| {
        const prev = try prevOf(allocator, line);
        defer allocator.free(prev);
        try std.testing.expectEqualStrings(&chain.of(lines[i]), prev);
    }

    const first = try prevOf(allocator, lines[1]);
    defer allocator.free(first);
    const second = try prevOf(allocator, lines[2]);
    defer allocator.free(second);
    try std.testing.expect(!std.mem.eql(u8, first, second));
}

test "an append after a torn tail chains onto the last whole line, never onto the fragment" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp_dir.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/chain-after-tear", .{dir_path});
    const seeded = try seedTornLog(io, path);

    var log = try Log.open(io, path, "01TESTSESSION");
    defer log.close(io);
    try std.testing.expect(log.tail_was_torn);
    var locked = try log.lock(io);
    const written = try locked.append(
        allocator,
        io,
        .{ .message = .{ .role = .assistant, .content = &.{.{ .text = "after the crash" }} } },
        2,
    );
    try std.testing.expectEqual(seeded.fragment_offset, written);

    const size = try log.file.length(io);
    const bytes = try allocator.alloc(u8, size);
    defer allocator.free(bytes);
    _ = try log.file.readPositionalAll(io, bytes, 0);
    const lines = try linesOf(allocator, bytes);
    defer allocator.free(lines);
    try std.testing.expectEqual(@as(usize, 3), lines.len);

    const prev = try prevOf(allocator, lines[2]);
    defer allocator.free(prev);
    try std.testing.expectEqualStrings(&chain.of(lines[1]), prev);
    try std.testing.expect(!std.mem.eql(u8, prev, &chain.of("{\"id\":0,\"session\":\"01TE")));
}

test "a second handle chains onto what the first one wrote, not onto what it last saw itself" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("chain-handover");
    defer tmp.deinit();

    var second = try Log.open(io, tmp.path(), "01TESTSESSION");
    defer second.close(io);

    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);
    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "two" }} } }, 2);

    var giving_up = try tmp.log.lock(io);
    try giving_up.unlock(io);

    var locked = try second.lock(io);
    _ = try locked.append(allocator, io, .{ .message = .{ .role = .assistant, .content = &.{.{ .text = "three" }} } }, 3);

    const bytes = try tmp.readAll(allocator);
    defer allocator.free(bytes);
    const lines = try linesOf(allocator, bytes);
    defer allocator.free(lines);
    try std.testing.expectEqual(@as(usize, 4), lines.len);

    const prev = try prevOf(allocator, lines[3]);
    defer allocator.free(prev);
    try std.testing.expectEqualStrings(&chain.of(lines[2]), prev);
    try std.testing.expect(!std.mem.eql(u8, prev, &chain.of(lines[0])));
}

test "the digest of a header and of a last line are read off the file, not built from a guess" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("chain-digests");
    defer tmp.deinit();

    const header = try tmp.log.headerDigest(io);
    try std.testing.expectEqualStrings(&chain.of("{\"chock_log\":1}"), &header);
    try std.testing.expectEqualStrings(&header, &try tmp.log.lastLineDigest(io));

    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);
    const bytes = try tmp.readAll(allocator);
    defer allocator.free(bytes);
    const lines = try linesOf(allocator, bytes);
    defer allocator.free(lines);

    try std.testing.expectEqualStrings(&header, &try tmp.log.headerDigest(io));
    try std.testing.expectEqualStrings(&chain.of(lines[1]), &try tmp.log.lastLineDigest(io));
}

test "a line longer than the read buffer hashes the same as the whole line at once" {
    const allocator = std.testing.allocator;
    var tmp = try TestLog.init("chain-long-line");
    defer tmp.deinit();

    const long = try allocator.alloc(u8, 20_000);
    defer allocator.free(long);
    // Not one repeated byte: a chunk read twice, or out of order, hashes the same
    // over a run of identical bytes and this test would pass a broken reader.
    for (long, 0..) |*byte, i| byte.* = @intCast('a' + (i % 26));

    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = long }} } }, 1);
    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "short" }} } }, 2);

    const bytes = try tmp.readAll(allocator);
    defer allocator.free(bytes);
    const lines = try linesOf(allocator, bytes);
    defer allocator.free(lines);
    try std.testing.expect(lines[1].len > 20_000);

    const prev = try prevOf(allocator, lines[2]);
    defer allocator.free(prev);
    try std.testing.expectEqualStrings(&chain.of(lines[1]), prev);
}
