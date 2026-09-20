//! The storage interface, over JSON Lines or memory. `append` needs the
//! exclusive lock, so `Storage`'s vtable has no `append` entry: `Storage.lock`
//! is the only way to get a `Locked`, and `Locked` is the only place it lives.

const std = @import("std");
const chain = @import("chain.zig");
const event = @import("event.zig");
const log = @import("log.zig");

pub const StorageError = log.LogError;

pub const max_header_bytes = log.max_header_bytes;

pub const ReplayError = StorageError || event.DecodeError;

pub const Replay = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        next: *const fn (ptr: *anyopaque, io: std.Io) ReplayError!?std.json.Parsed(event.Envelope),
        deinit: *const fn (ptr: *anyopaque) void,
        truncated: *const fn (ptr: *anyopaque) bool,
        line: *const fn (ptr: *anyopaque) []const u8,
        at: *const fn (ptr: *anyopaque) u64,
    };

    pub fn next(self: *Replay, io: std.Io) ReplayError!?std.json.Parsed(event.Envelope) {
        return self.vtable.next(self.ptr, io);
    }

    pub fn deinit(self: *Replay) void {
        self.vtable.deinit(self.ptr);
    }

    /// A torn tail and a clean end of log both give null from `next`. Only this
    /// tells them apart, and only for the most recent call.
    pub fn truncated(self: *Replay) bool {
        return self.vtable.truncated(self.ptr);
    }

    /// A verifier hashes these bytes rather than encoding the parsed envelope
    /// again. A fresh encoding makes a sound log read as tampered with.
    pub fn line(self: *Replay) []const u8 {
        return self.vtable.line(self.ptr);
    }

    /// Read this before a `next`, to name the line that call is about to read.
    /// A failed `next` has already moved past the line it choked on.
    pub fn at(self: *Replay) u64 {
        return self.vtable.at(self.ptr);
    }
};

/// This type is not `pub`, but Zig still lets a caller reach the same unnamed
/// type through reflection and build one. `generation` refuses such a handle at
/// run time: it must still match the backend's own lock counter.
const Locked = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    generation: u64,

    pub const VTable = struct {
        append: *const fn (ptr: *anyopaque, generation: u64, allocator: std.mem.Allocator, io: std.Io, ev: event.Event, time_ms: i64) StorageError!u64,
        unlock: *const fn (ptr: *anyopaque, generation: u64, io: std.Io) StorageError!void,
    };

    pub fn append(self: *Locked, allocator: std.mem.Allocator, io: std.Io, ev: event.Event, time_ms: i64) StorageError!u64 {
        return self.vtable.append(self.ptr, self.generation, allocator, io, ev, time_ms);
    }

    pub fn unlock(self: *Locked, io: std.Io) StorageError!void {
        return self.vtable.unlock(self.ptr, self.generation, io);
    }
};

pub const Storage = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        replay: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, io: std.Io, offset: u64) StorageError!Replay,
        lock: *const fn (ptr: *anyopaque, io: std.Io) StorageError!Locked,
        close: *const fn (ptr: *anyopaque, io: std.Io) void,
        headerDigest: *const fn (ptr: *anyopaque, io: std.Io) StorageError!chain.Digest,
        headerLine: *const fn (
            ptr: *anyopaque,
            io: std.Io,
            buffer: *[max_header_bytes]u8,
        ) StorageError![]const u8,
    };

    pub fn replay(self: Storage, allocator: std.mem.Allocator, io: std.Io, offset: u64) StorageError!Replay {
        return self.vtable.replay(self.ptr, allocator, io, offset);
    }

    pub fn lock(self: Storage, io: std.Io) StorageError!Locked {
        return self.vtable.lock(self.ptr, io);
    }

    /// Safe to call more than once on either backend.
    pub fn close(self: Storage, io: std.Io) void {
        self.vtable.close(self.ptr, io);
    }

    pub fn verifier(self: Storage, io: std.Io) StorageError!chain.Verifier {
        return .init(try self.headerDigest(io));
    }

    pub fn headerDigest(self: Storage, io: std.Io) StorageError!chain.Digest {
        return self.vtable.headerDigest(self.ptr, io);
    }

    /// A copy of a log must hold the very header bytes the original holds, or a
    /// verifier at the far end compares its own spelling against the writer's.
    pub fn headerLine(
        self: Storage,
        io: std.Io,
        buffer: *[max_header_bytes]u8,
    ) StorageError![]const u8 {
        return self.vtable.headerLine(self.ptr, io, buffer);
    }
};

/// A torn tail, a line that will not decode, and a log with no chain at all are
/// answers, not errors. Only a fault that stopped the reading is an error.
pub fn verify(store: Storage, allocator: std.mem.Allocator, io: std.Io) StorageError!chain.Report {
    var reader = try store.verifier(io);
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();

    while (true) {
        const line_start = replay.at();
        const parsed = replay.next(io) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Unexpected => return error.Unexpected,
            else => return reader.finish(.undecodable, line_start),
        } orelse {
            const ending: chain.Ending = if (replay.truncated()) .torn else .complete;
            return reader.finish(ending, line_start);
        };
        defer parsed.deinit();
        reader.take(parsed.value.id, replay.line(), parsed.value.prev);
    }
}

pub const JsonLines = struct {
    log: log.Log,
    held: bool = false,
    lock_generation: u64 = 0,

    pub fn storage(self: *JsonLines) Storage {
        return .{ .ptr = self, .vtable = &json_lines_vtable };
    }

    fn closeFn(ptr: *anyopaque, io: std.Io) void {
        const self: *JsonLines = @ptrCast(@alignCast(ptr));
        self.log.close(io);
    }

    fn replayFn(ptr: *anyopaque, allocator: std.mem.Allocator, io: std.Io, offset: u64) StorageError!Replay {
        const self: *JsonLines = @ptrCast(@alignCast(ptr));
        // A stable address distinct from `self`: more than one replay can run
        // at once against the same log.
        const inner = try allocator.create(log.Replay);
        errdefer allocator.destroy(inner);
        inner.* = try self.log.replayFrom(allocator, io, offset);
        return .{ .ptr = inner, .vtable = &json_lines_replay_vtable };
    }

    fn replayNextFn(ptr: *anyopaque, io: std.Io) ReplayError!?std.json.Parsed(event.Envelope) {
        const self: *log.Replay = @ptrCast(@alignCast(ptr));
        return self.next(io);
    }

    fn replayDeinitFn(ptr: *anyopaque) void {
        const self: *log.Replay = @ptrCast(@alignCast(ptr));
        const allocator = self.allocator;
        self.deinit();
        allocator.destroy(self);
    }

    fn replayTruncatedFn(ptr: *anyopaque) bool {
        const self: *log.Replay = @ptrCast(@alignCast(ptr));
        return self.truncated;
    }

    fn replayLineFn(ptr: *anyopaque) []const u8 {
        const self: *log.Replay = @ptrCast(@alignCast(ptr));
        return self.line();
    }

    fn replayAtFn(ptr: *anyopaque) u64 {
        const self: *log.Replay = @ptrCast(@alignCast(ptr));
        return self.pos;
    }

    fn headerDigestFn(ptr: *anyopaque, io: std.Io) StorageError!chain.Digest {
        const self: *JsonLines = @ptrCast(@alignCast(ptr));
        return self.log.headerDigest(io);
    }

    fn headerLineFn(
        ptr: *anyopaque,
        io: std.Io,
        buffer: *[max_header_bytes]u8,
    ) StorageError![]const u8 {
        const self: *JsonLines = @ptrCast(@alignCast(ptr));
        return self.log.headerLine(io, buffer);
    }

    fn lockFn(ptr: *anyopaque, io: std.Io) StorageError!Locked {
        const self: *JsonLines = @ptrCast(@alignCast(ptr));
        // The kernel lock is re-entrant on one open file description, so it
        // cannot tell a genuine second owner from this backend locking twice.
        if (self.held) return error.Busy;
        _ = try self.log.lock(io);
        self.held = true;
        self.lock_generation +%= 1;
        return .{ .ptr = self, .vtable = &json_lines_locked_vtable, .generation = self.lock_generation };
    }

    fn appendFn(
        ptr: *anyopaque,
        generation: u64,
        allocator: std.mem.Allocator,
        io: std.Io,
        ev: event.Event,
        time_ms: i64,
    ) StorageError!u64 {
        const self: *JsonLines = @ptrCast(@alignCast(ptr));
        if (!self.held or generation != self.lock_generation) return error.NotLocked;
        var locked = try self.log.lock(io);
        return locked.append(allocator, io, ev, time_ms);
    }

    fn unlockFn(ptr: *anyopaque, generation: u64, io: std.Io) StorageError!void {
        const self: *JsonLines = @ptrCast(@alignCast(ptr));
        if (!self.held or generation != self.lock_generation) return error.NotLocked;
        var locked = try self.log.lock(io);
        try locked.unlock(io);
        self.held = false;
    }
};

const json_lines_vtable = Storage.VTable{
    .replay = JsonLines.replayFn,
    .lock = JsonLines.lockFn,
    .close = JsonLines.closeFn,
    .headerDigest = JsonLines.headerDigestFn,
    .headerLine = JsonLines.headerLineFn,
};

const json_lines_locked_vtable = Locked.VTable{
    .append = JsonLines.appendFn,
    .unlock = JsonLines.unlockFn,
};

const json_lines_replay_vtable = Replay.VTable{
    .next = JsonLines.replayNextFn,
    .deinit = JsonLines.replayDeinitFn,
    .truncated = JsonLines.replayTruncatedFn,
    .line = JsonLines.replayLineFn,
    .at = JsonLines.replayAtFn,
};

/// Keeps every event in memory. It mirrors `log.Log`'s wire shape, but not its
/// durability or its crash recovery: no sync, and no torn tail to find.
pub const Memory = struct {
    allocator: std.mem.Allocator,
    session: []const u8,
    bytes: std.ArrayList(u8) = .empty,
    held: bool = false,
    lock_generation: u64 = 0,
    /// `std.ArrayList.deinit` leaves the list undefined and not empty, so a
    /// second `deinit` without this guard frees the same allocation twice.
    deinited: bool = false,

    const header = "{\"chock_log\":1}\n";

    pub fn init(allocator: std.mem.Allocator, session: []const u8) std.mem.Allocator.Error!Memory {
        var self: Memory = .{ .allocator = allocator, .session = session };
        try self.bytes.appendSlice(allocator, header);
        return self;
    }

    pub fn deinit(self: *Memory) void {
        if (self.deinited) return;
        self.deinited = true;
        self.bytes.deinit(self.allocator);
    }

    pub fn storage(self: *Memory) Storage {
        return .{ .ptr = self, .vtable = &memory_vtable };
    }

    fn closeFn(ptr: *anyopaque, io: std.Io) void {
        _ = io;
        const self: *Memory = @ptrCast(@alignCast(ptr));
        self.deinit();
    }

    fn lockFn(ptr: *anyopaque, io: std.Io) StorageError!Locked {
        _ = io;
        const self: *Memory = @ptrCast(@alignCast(ptr));
        if (self.held) return error.Busy;
        self.held = true;
        self.lock_generation +%= 1;
        return .{ .ptr = self, .vtable = &memory_locked_vtable, .generation = self.lock_generation };
    }

    fn appendFn(
        ptr: *anyopaque,
        generation: u64,
        allocator: std.mem.Allocator,
        io: std.Io,
        ev: event.Event,
        time_ms: i64,
    ) StorageError!u64 {
        _ = io;
        const self: *Memory = @ptrCast(@alignCast(ptr));
        if (!self.held or generation != self.lock_generation) return error.NotLocked;

        const prev = self.lastLineDigest();

        const envelope = event.Envelope{
            .id = 0,
            .session = self.session,
            .time_ms = time_ms,
            .event = ev,
            .prev = &prev,
        };
        const text = try event.toJson(allocator, envelope);
        defer allocator.free(text);

        const offset: u64 = self.bytes.items.len;
        try self.bytes.appendSlice(self.allocator, text);
        try self.bytes.append(self.allocator, '\n');
        return offset;
    }

    fn unlockFn(ptr: *anyopaque, generation: u64, io: std.Io) StorageError!void {
        _ = io;
        const self: *Memory = @ptrCast(@alignCast(ptr));
        if (!self.held or generation != self.lock_generation) return error.NotLocked;
        self.held = false;
    }

    fn lastLineDigest(self: *const Memory) chain.Digest {
        const bytes = self.bytes.items;
        std.debug.assert(bytes.len > 0 and bytes[bytes.len - 1] == '\n');
        const end = bytes.len - 1;
        const start = if (std.mem.lastIndexOfScalar(u8, bytes[0..end], '\n')) |i| i + 1 else 0;
        return chain.of(bytes[start..end]);
    }

    fn headerDigestFn(ptr: *anyopaque, io: std.Io) StorageError!chain.Digest {
        _ = io;
        _ = ptr;
        return chain.of(header[0 .. header.len - 1]);
    }

    fn headerLineFn(
        ptr: *anyopaque,
        io: std.Io,
        buffer: *[max_header_bytes]u8,
    ) StorageError![]const u8 {
        _ = io;
        _ = ptr;
        // Copied and not borrowed from the literal, so a caller cannot rely on
        // the answer outliving its buffer.
        const line = header[0 .. header.len - 1];
        @memcpy(buffer[0..line.len], line);
        return buffer[0..line.len];
    }

    fn replayFn(ptr: *anyopaque, allocator: std.mem.Allocator, io: std.Io, offset: u64) StorageError!Replay {
        _ = io;
        const self: *Memory = @ptrCast(@alignCast(ptr));
        const header_end: u64 = header.len;
        if (offset != 0) {
            if (offset < header_end or offset >= self.bytes.items.len) return error.OffsetOutOfRange;
            if (self.bytes.items[offset - 1] != '\n') return error.OffsetNotLineStart;
        }
        const start: u64 = if (offset == 0) header_end else offset;

        const inner = try allocator.create(MemoryReplay);
        errdefer allocator.destroy(inner);
        inner.* = .{ .memory = self, .allocator = allocator, .pos = start };
        return .{ .ptr = inner, .vtable = &memory_replay_vtable };
    }
};

const memory_vtable = Storage.VTable{
    .replay = Memory.replayFn,
    .lock = Memory.lockFn,
    .close = Memory.closeFn,
    .headerDigest = Memory.headerDigestFn,
    .headerLine = Memory.headerLineFn,
};

const memory_locked_vtable = Locked.VTable{
    .append = Memory.appendFn,
    .unlock = Memory.unlockFn,
};

const MemoryReplay = struct {
    memory: *Memory,
    allocator: std.mem.Allocator,
    pos: u64,
    /// A slice into the backend's buffer. Nothing may append while a caller
    /// reads a replay of it.
    last_line: []const u8 = "",

    fn nextFn(ptr: *anyopaque, io: std.Io) ReplayError!?std.json.Parsed(event.Envelope) {
        _ = io;
        const self: *MemoryReplay = @ptrCast(@alignCast(ptr));
        self.last_line = "";
        const bytes = self.memory.bytes.items;
        if (self.pos >= bytes.len) return null;

        const line_start = self.pos;
        const newline = std.mem.indexOfScalarPos(u8, bytes, @intCast(self.pos), '\n') orelse return null;
        const line = bytes[@intCast(line_start)..newline];
        self.pos = newline + 1;

        var parsed = try event.fromJson(self.allocator, line);
        parsed.value.id = line_start;
        self.last_line = line;
        return parsed;
    }

    fn lineFn(ptr: *anyopaque) []const u8 {
        const self: *MemoryReplay = @ptrCast(@alignCast(ptr));
        return self.last_line;
    }

    fn atFn(ptr: *anyopaque) u64 {
        const self: *MemoryReplay = @ptrCast(@alignCast(ptr));
        return self.pos;
    }

    fn deinitFn(ptr: *anyopaque) void {
        const self: *MemoryReplay = @ptrCast(@alignCast(ptr));
        self.allocator.destroy(self);
    }

    /// Always false. An in memory buffer has no crash to leave a tear behind.
    fn truncatedFn(ptr: *anyopaque) bool {
        _ = ptr;
        return false;
    }
};

const memory_replay_vtable = Replay.VTable{
    .next = MemoryReplay.nextFn,
    .truncated = MemoryReplay.truncatedFn,
    .deinit = MemoryReplay.deinitFn,
    .line = MemoryReplay.lineFn,
    .at = MemoryReplay.atFn,
};

test "the json lines storage satisfies the storage interface" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try log.absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/session.jsonl", .{dir_path});

    var backing = JsonLines{ .log = try log.Log.open(io, path, "01STORAGE") };
    const store: Storage = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    const offset = try locked.append(allocator, io, .{ .message = .{ .role = .user, .content = &.{.{ .text = "hi" }} } }, 1);
    try locked.unlock(io);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    const envelope = (try replay.next(io)).?;
    defer envelope.deinit();

    try std.testing.expectEqual(offset, envelope.value.id);
    try std.testing.expectEqualStrings("hi", envelope.value.event.message.content[0].text);
    try std.testing.expect((try replay.next(io)) == null);
    try std.testing.expect(!replay.truncated());
}

test "a fake storage satisfies the same interface, so a caller needs no file" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var backing = try Memory.init(allocator, "01STORAGE");
    const store: Storage = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    const offset = try locked.append(
        allocator,
        io,
        .{ .message = .{ .role = .assistant, .content = &.{.{ .text = "in memory" }} } },
        5,
    );
    try locked.unlock(io);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    const envelope = (try replay.next(io)).?;
    defer envelope.deinit();

    try std.testing.expectEqual(offset, envelope.value.id);
    try std.testing.expectEqualStrings("in memory", envelope.value.event.message.content[0].text);
    try std.testing.expect((try replay.next(io)) == null);
    try std.testing.expect(!replay.truncated());
}

test "a second lock is refused while the first is held, the same way on the fake storage and the real one" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var mem_backing = try Memory.init(allocator, "01STORAGE");
    const mem_store: Storage = mem_backing.storage();
    defer mem_store.close(io);
    try expectSecondLockIsRefused(mem_store, io);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try log.absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/double-lock", .{dir_path});
    var json_backing = JsonLines{ .log = try log.Log.open(io, path, "01STORAGE") };
    const json_store: Storage = json_backing.storage();
    defer json_store.close(io);
    try expectSecondLockIsRefused(json_store, io);
}

fn expectSecondLockIsRefused(store: Storage, io: std.Io) !void {
    var locked = try store.lock(io);
    try std.testing.expectError(error.Busy, store.lock(io));
    try locked.unlock(io);

    var locked_again = try store.lock(io);
    try locked_again.unlock(io);
}

test "regression: a caller using only the Storage interface can tell a torn tail from a clean end of log" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try log.absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/storage-torn-tail", .{dir_path});

    {
        var file = try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, "{\"chock_log\":1}\n{\"id\":0,\"session\":\"01ST");
    }

    var backing = JsonLines{ .log = try log.Log.open(io, path, "01STORAGE") };
    const store: Storage = backing.storage();
    defer store.close(io);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    try std.testing.expect((try replay.next(io)) == null);
    try std.testing.expect(replay.truncated());
}

test "regression: a Locked handle whose generation does not match the backend's own is refused, on both backends" {
    // Zig lets a caller build a value of a type it cannot name, so a forged
    // handle can reach `append` with no lock ever taken.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var mem_backing = try Memory.init(allocator, "01STORAGE");
    const mem_store: Storage = mem_backing.storage();
    defer mem_store.close(io);
    var mem_locked = try mem_store.lock(io);
    defer mem_locked.unlock(io) catch {};
    var mem_forged: Locked = .{ .ptr = &mem_backing, .vtable = &memory_locked_vtable, .generation = 0 };
    try std.testing.expectError(
        error.NotLocked,
        mem_forged.append(allocator, io, .{ .message = .{ .role = .user, .content = &.{.{ .text = "forged" }} } }, 1),
    );

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try log.absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/forged-generation", .{dir_path});
    var json_backing = JsonLines{ .log = try log.Log.open(io, path, "01STORAGE") };
    const json_store: Storage = json_backing.storage();
    defer json_store.close(io);
    var json_locked = try json_store.lock(io);
    defer json_locked.unlock(io) catch {};
    var json_forged: Locked = .{ .ptr = &json_backing, .vtable = &json_lines_locked_vtable, .generation = 0 };
    try std.testing.expectError(
        error.NotLocked,
        json_forged.append(allocator, io, .{ .message = .{ .role = .user, .content = &.{.{ .text = "forged" }} } }, 1),
    );
}

test "regression: closing storage twice is harmless on both backends, not only the file backed one" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var mem_backing = try Memory.init(allocator, "01STORAGE");
    const mem_store: Storage = mem_backing.storage();
    mem_store.close(io);
    mem_store.close(io);
    try std.testing.expect(mem_backing.deinited);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try log.absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/double-close", .{dir_path});
    var json_backing = JsonLines{ .log = try log.Log.open(io, path, "01STORAGE") };
    const json_store: Storage = json_backing.storage();
    json_store.close(io);
    json_store.close(io);
    try std.testing.expectEqual(@as(std.posix.fd_t, -1), json_backing.log.file.handle);
}

fn scratchPath(
    tmp: *std.testing.TmpDir,
    dir_buffer: []u8,
    path_buffer: []u8,
    name: []const u8,
) ![:0]u8 {
    const dir_path = try log.absoluteDirPath(std.testing.io, dir_buffer, tmp.dir);
    return std.fmt.bufPrintZ(path_buffer, "{s}/{s}", .{ dir_path, name });
}

fn writeWholeFile(io: std.Io, path: [:0]const u8, bytes: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

fn readWholeFile(allocator: std.mem.Allocator, io: std.Io, path: [:0]const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(4 * 1024 * 1024));
}

fn seedChainedLog(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: [:0]const u8,
    count: usize,
) ![]u64 {
    var backing = JsonLines{ .log = try log.Log.open(io, path, "01CHAINSESSION") };
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const offsets = try allocator.alloc(u64, count);
    errdefer allocator.free(offsets);
    for (offsets, 0..) |*offset, i| {
        var text_buffer: [32]u8 = undefined;
        const text = try std.fmt.bufPrint(&text_buffer, "event number {d}", .{i});
        offset.* = try locked.append(
            allocator,
            io,
            .{ .message = .{ .role = .user, .content = &.{.{ .text = text }} } },
            @intCast(i),
        );
    }
    return offsets;
}

fn verifyFile(allocator: std.mem.Allocator, io: std.Io, path: [:0]const u8) !chain.Report {
    var backing = JsonLines{ .log = try log.Log.open(io, path, "01CHAINSESSION") };
    const store = backing.storage();
    defer store.close(io);
    return verify(store, allocator, io);
}

test "a real log written through the real writer verifies, on both backends" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&tmp, &dir_buffer, &path_buffer, "chain-intact");

    const offsets = try seedChainedLog(allocator, io, path, 5);
    defer allocator.free(offsets);

    const report = try verifyFile(allocator, io, path);
    try std.testing.expectEqual(chain.Verdict.intact, report.verdict);
    try std.testing.expectEqual(@as(u64, 5), report.events);
    try std.testing.expectEqual(@as(u64, 5), report.chained);
    try std.testing.expect(!report.edited());

    var memory = try Memory.init(allocator, "01CHAINSESSION");
    const mem_store = memory.storage();
    defer mem_store.close(io);
    var mem_locked = try mem_store.lock(io);
    for (0..5) |i| {
        _ = try mem_locked.append(
            allocator,
            io,
            .{ .message = .{ .role = .user, .content = &.{.{ .text = "in memory" }} } },
            @intCast(i),
        );
    }
    try mem_locked.unlock(io);

    const mem_report = try verify(mem_store, allocator, io);
    try std.testing.expectEqual(chain.Verdict.intact, mem_report.verdict);
    try std.testing.expectEqual(@as(u64, 5), mem_report.chained);
}

test "an event changed in the middle of a log is found, and the report names where" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&tmp, &dir_buffer, &path_buffer, "chain-edited");

    const offsets = try seedChainedLog(allocator, io, path, 5);
    defer allocator.free(offsets);
    try std.testing.expectEqual(chain.Verdict.intact, (try verifyFile(allocator, io, path)).verdict);

    const before = try readWholeFile(allocator, io, path);
    defer allocator.free(before);
    const edited = try allocator.dupe(u8, before);
    defer allocator.free(edited);
    const target = std.mem.indexOf(u8, edited, "event number 2").?;
    edited[target + "event number ".len] = '9';
    try writeWholeFile(io, path, edited);
    try std.testing.expectEqual(before.len, edited.len);

    const report = try verifyFile(allocator, io, path);
    try std.testing.expectEqual(chain.Verdict.broken, report.verdict);
    try std.testing.expect(report.edited());
    try std.testing.expectEqual(offsets[3], report.at);
    try std.testing.expectEqual(offsets[2], report.after);
    try std.testing.expectEqual(@as(u64, 5), report.events);
}

test "an event changed in the middle is found on the fake backend too" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var memory = try Memory.init(allocator, "01CHAINSESSION");
    const store = memory.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    var offsets: [4]u64 = undefined;
    for (&offsets, 0..) |*offset, i| {
        var text_buffer: [32]u8 = undefined;
        const text = try std.fmt.bufPrint(&text_buffer, "event number {d}", .{i});
        offset.* = try locked.append(
            allocator,
            io,
            .{ .message = .{ .role = .user, .content = &.{.{ .text = text }} } },
            @intCast(i),
        );
    }
    try locked.unlock(io);
    try std.testing.expectEqual(chain.Verdict.intact, (try verify(store, allocator, io)).verdict);

    const target = std.mem.indexOf(u8, memory.bytes.items, "event number 1").?;
    memory.bytes.items[target + "event number ".len] = '8';

    const report = try verify(store, allocator, io);
    try std.testing.expectEqual(chain.Verdict.broken, report.verdict);
    try std.testing.expectEqual(offsets[2], report.at);
    try std.testing.expectEqual(offsets[1], report.after);
}

test "a torn final line is reported as truncation and never as tampering" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&tmp, &dir_buffer, &path_buffer, "chain-torn");

    const offsets = try seedChainedLog(allocator, io, path, 3);
    defer allocator.free(offsets);

    const whole = try readWholeFile(allocator, io, path);
    defer allocator.free(whole);
    const fragment_at = whole.len;
    const torn = try std.fmt.allocPrint(allocator, "{s}{{\"id\":0,\"session\":\"01CH", .{whole});
    defer allocator.free(torn);
    try writeWholeFile(io, path, torn);

    const report = try verifyFile(allocator, io, path);
    try std.testing.expectEqual(chain.Verdict.torn, report.verdict);
    try std.testing.expect(!report.edited());
    try std.testing.expectEqual(@as(u64, fragment_at), report.at);
    try std.testing.expectEqual(@as(u64, 3), report.events);
    try std.testing.expectEqual(@as(u64, 3), report.chained);
}

test "a log edited in the middle and torn at the end is reported as edited, not as torn" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&tmp, &dir_buffer, &path_buffer, "chain-both");

    const offsets = try seedChainedLog(allocator, io, path, 4);
    defer allocator.free(offsets);

    const whole = try readWholeFile(allocator, io, path);
    defer allocator.free(whole);
    const both = try std.fmt.allocPrint(allocator, "{s}{{\"id\":0,\"sessi", .{whole});
    defer allocator.free(both);
    const target = std.mem.indexOf(u8, both, "event number 1").?;
    both[target + "event number ".len] = '7';
    try writeWholeFile(io, path, both);

    const report = try verifyFile(allocator, io, path);
    try std.testing.expectEqual(chain.Verdict.broken, report.verdict);
    try std.testing.expectEqual(offsets[2], report.at);
}

test "a log with no chain at all is read rather than refused" {
    // `unchained` is not a pass: nothing can say whether such a log was edited.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&tmp, &dir_buffer, &path_buffer, "chain-legacy");

    try writeWholeFile(io, path, "{\"chock_log\":1}\n" ++
        "{\"id\":0,\"session\":\"01CHAINSESSION\",\"time_ms\":1," ++
        "\"event\":{\"session.start\":{\"agent_kind\":\"coder\",\"model_alias\":\"main\"," ++
        "\"parent_session\":\"\"}},\"version\":1}\n" ++
        "{\"id\":0,\"session\":\"01CHAINSESSION\",\"time_ms\":2," ++
        "\"event\":{\"session.end\":{\"reason\":\"finished\",\"detail\":\"\"}},\"version\":1}\n");

    const report = try verifyFile(allocator, io, path);
    try std.testing.expectEqual(chain.Verdict.unchained, report.verdict);
    try std.testing.expectEqual(@as(u64, 2), report.events);
    try std.testing.expectEqual(@as(u64, 0), report.chained);
    try std.testing.expect(!report.edited());

    var backing = JsonLines{ .log = try log.Log.open(io, path, "01CHAINSESSION") };
    const store = backing.storage();
    defer store.close(io);
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    const first = (try replay.next(io)).?;
    defer first.deinit();
    try std.testing.expectEqualStrings("coder", first.value.event.session_start.agent_kind);
}

test "an old log a new build carried on verifies over the part that is chained" {
    // The first chained event's `prev` is the hash of the unchained line in
    // front of it, because `append` reads the file and does not remember.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&tmp, &dir_buffer, &path_buffer, "chain-upgraded");

    try writeWholeFile(io, path, "{\"chock_log\":1}\n" ++
        "{\"id\":0,\"session\":\"01CHAINSESSION\",\"time_ms\":1," ++
        "\"event\":{\"session.start\":{\"agent_kind\":\"coder\",\"model_alias\":\"main\"," ++
        "\"parent_session\":\"\"}},\"version\":1}\n");

    {
        var backing = JsonLines{ .log = try log.Log.open(io, path, "01CHAINSESSION") };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        _ = try locked.append(allocator, io, .{ .message = .{
            .role = .assistant,
            .content = &.{.{ .text = "carried on" }},
        } }, 2);
        _ = try locked.append(allocator, io, .{ .message = .{
            .role = .user,
            .content = &.{.{ .text = "and again" }},
        } }, 3);
        try locked.unlock(io);
    }

    const report = try verifyFile(allocator, io, path);
    try std.testing.expectEqual(chain.Verdict.partly_chained, report.verdict);
    try std.testing.expectEqual(@as(u64, 3), report.events);
    try std.testing.expectEqual(@as(u64, 2), report.chained);

    const whole = try readWholeFile(allocator, io, path);
    defer allocator.free(whole);
    const edited = try allocator.dupe(u8, whole);
    defer allocator.free(edited);
    const target = std.mem.indexOf(u8, edited, "carried on").?;
    edited[target] = 'b';
    try writeWholeFile(io, path, edited);
    try std.testing.expectEqual(chain.Verdict.broken, (try verifyFile(allocator, io, path)).verdict);
}

test "a compacted session still verifies, and the log still holds every event the fold covered" {
    // A chain cannot survive an event taken out of the middle of the file. A
    // compaction that rewrote the file would fail the second half of this test.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&tmp, &dir_buffer, &path_buffer, "chain-compacted");

    var folded: [4]u64 = undefined;
    var after_compaction: u64 = 0;
    {
        var backing = JsonLines{ .log = try log.Log.open(io, path, "01CHAINSESSION") };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);

        for (&folded, 0..) |*offset, i| {
            var text_buffer: [32]u8 = undefined;
            const text = try std.fmt.bufPrint(&text_buffer, "turn {d}", .{i});
            offset.* = try locked.append(
                allocator,
                io,
                .{ .message = .{ .role = .user, .content = &.{.{ .text = text }} } },
                @intCast(i),
            );
        }

        const kept = [_]event.EventRange{.{ .from_id = folded[2], .through_id = folded[3] }};
        _ = try locked.append(allocator, io, .{ .compaction = .{
            .summary = "four turns of looking at one parser",
            .from_id = folded[0],
            .through_id = folded[3],
            .kept_ranges = &kept,
            .model_alias = "main",
        } }, 5);

        after_compaction = try locked.append(allocator, io, .{ .message = .{
            .role = .assistant,
            .content = &.{.{ .text = "carrying on with a shorter context" }},
        } }, 6);
        try locked.unlock(io);
    }

    const report = try verifyFile(allocator, io, path);
    try std.testing.expectEqual(chain.Verdict.intact, report.verdict);
    try std.testing.expectEqual(@as(u64, 6), report.events);
    try std.testing.expectEqual(@as(u64, 6), report.chained);

    var backing = JsonLines{ .log = try log.Log.open(io, path, "01CHAINSESSION") };
    const store = backing.storage();
    defer store.close(io);
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();

    var seen: std.ArrayList(u64) = .empty;
    defer seen.deinit(allocator);
    var span: ?event.Compaction = null;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try seen.append(allocator, parsed.value.id);
        if (parsed.value.event == .compaction) span = parsed.value.event.compaction;
    }

    try std.testing.expectEqual(folded[0], span.?.from_id);
    try std.testing.expectEqual(folded[3], span.?.through_id);
    for (folded) |id| {
        try std.testing.expect(std.mem.indexOfScalar(u64, seen.items, id) != null);
    }
    try std.testing.expect(std.mem.indexOfScalar(u64, seen.items, after_compaction) != null);
}

test "the chain is over the bytes on disk, never over a fresh encoding of what was parsed" {
    // A verifier that encoded each parsed envelope again would call a sound log
    // tampered with. No test over Chock's own writer can see that.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&tmp, &dir_buffer, &path_buffer, "chain-foreign-shape");

    const header = "{\"chock_log\":1}";
    // Written out in full, so a change of hash function has to change this line.
    const header_digest = "ec2d45163a1d5e394b485bcf3394804d1cd4f071ce3aab0dd323f7dd3072b116";
    try std.testing.expectEqualStrings(header_digest, &chain.of(header));

    const first = "{ \"session\" : \"01CHAINSESSION\", \"time_ms\" : 1, \"id\" : 0, " ++
        "\"event\" : { \"session.start\" : { \"agent_kind\" : \"coder\", " ++
        "\"model_alias\" : \"main\", \"parent_session\" : \"\" } }, " ++
        "\"prev\" : \"" ++ header_digest ++ "\" }";
    const second = try std.fmt.allocPrint(
        allocator,
        "{{ \"session\" : \"01CHAINSESSION\" , \"time_ms\" : 2 , \"id\" : 0 , " ++
            "\"event\" : {{ \"session.end\" : {{ \"reason\" : \"finished\" , \"detail\" : \"\" }} }} , " ++
            "\"prev\" : \"{s}\" }}",
        .{&chain.of(first)},
    );
    defer allocator.free(second);

    const whole = try std.fmt.allocPrint(allocator, "{s}\n{s}\n{s}\n", .{ header, first, second });
    defer allocator.free(whole);
    try writeWholeFile(io, path, whole);

    const report = try verifyFile(allocator, io, path);
    try std.testing.expectEqual(chain.Verdict.intact, report.verdict);
    try std.testing.expectEqual(@as(u64, 2), report.chained);
}

test "a complete line that will not decode is its own answer, and never a tear" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&tmp, &dir_buffer, &path_buffer, "chain-undecodable");

    const offsets = try seedChainedLog(allocator, io, path, 3);
    defer allocator.free(offsets);

    const whole = try readWholeFile(allocator, io, path);
    defer allocator.free(whole);
    const broken = try std.fmt.allocPrint(allocator, "{s}not json at all\n", .{whole});
    defer allocator.free(broken);
    const bad_line_at = whole.len;
    try writeWholeFile(io, path, broken);

    const report = try verifyFile(allocator, io, path);
    try std.testing.expectEqual(chain.Verdict.undecodable, report.verdict);
    try std.testing.expect(!report.edited());
    try std.testing.expectEqual(@as(u64, bad_line_at), report.at);
    try std.testing.expectEqual(@as(u64, 3), report.events);
}

test "a log nothing can open is never reported as verified" {
    // A `Report` nobody could fill in carries `unreadable`, so a caller that
    // forgot to check the error does not get a pass.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&tmp, &dir_buffer, &path_buffer, "chain-bad-header");

    try writeWholeFile(io, path, "this is not a chock session log\n");
    try std.testing.expectError(error.BadHeader, verifyFile(allocator, io, path));
    try std.testing.expectEqual(chain.Verdict.unreadable, (chain.Report{}).verdict);
}
