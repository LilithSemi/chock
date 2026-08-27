//! The storage interface. Storage has three operations, append, replay, and
//! lock, and JSON Lines is the only implementation in version 1. PostgreSQL
//! comes later, and the agent loop must not change when it does.
//!
//! A vtable, in the style `std.mem.Allocator` uses, not a generic type parameter.
//! The daemon holds one storage whose kind it learns from configuration when it
//! runs, not when it compiles, so a comptime parameter cannot name it.
//!
//! `append` needs the exclusive lock, the same rule `lib/chock-proto/log.zig`
//! enforces with its own `Locked` type. This file carries that rule across the
//! vtable boundary the same way: `Storage`'s own vtable has no `append` entry,
//! only `replay` and `lock`. `Storage.lock` is the only function that returns a
//! `Locked`, and `Locked` is the only place `append` and `unlock` live. A caller
//! holding only a `Storage` therefore has no path to `append` at all.
//!
//! This file's own `Locked`, like `log.Locked`, is not `pub`. A `struct{ ptr:
//! *anyopaque, vtable: *const VTable }` is plain data, and Zig has no per field
//! access control, only per file, so a public field here would be exactly as
//! forgeable as a public field on `log.Locked` was before that hole was closed.
//! Keeping the type itself out of every other file's reach stops the ordinary
//! mistake of writing `storage.Locked{ .ptr = ..., .vtable = ... }` by hand, but
//! it does not stop a caller reaching the same unnamed type through reflection
//! and building one that way. See `Locked`'s own doc comment for that route and
//! `generation` for what actually refuses the result at run time.
//!
//! Every vtable function that can touch a file takes `io: std.Io`, threaded down
//! from the caller the same way `log.zig` takes it. `Memory`, which touches no
//! file at all, still accepts and ignores it, so both backends satisfy the same
//! `VTable` shape.

const std = @import("std");
const chain = @import("chain.zig");
const event = @import("event.zig");
const log = @import("log.zig");

/// Every error a storage backend can return. Reused from `log.LogError` rather
/// than repeated, since the JSON Lines backend forwards `log.Log`'s errors
/// unchanged. A future PostgreSQL backend translates its own failures into
/// this same closed set rather than adding to it: that is what keeps the
/// promise in this file's top comment, that the agent loop does not have to
/// change when the storage does.
pub const StorageError = log.LogError;

/// The most bytes a header line can take. Read from `log.zig`, so a caller with
/// a buffer on its stack sizes it from the one place that decides.
pub const max_header_bytes = log.max_header_bytes;

/// `StorageError`, plus the ways a stored line can fail to parse back into an
/// event. Only `Replay.next` can hit the second half.
pub const ReplayError = StorageError || event.DecodeError;

/// A replay in progress. Behind a vtable so a caller reading through this type
/// never learns whether the line it just read came from a file or from memory.
pub const Replay = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        next: *const fn (ptr: *anyopaque, io: std.Io) ReplayError!?std.json.Parsed(event.Envelope),
        deinit: *const fn (ptr: *anyopaque) void,
        /// True after the most recent call to `next` found the log ending mid
        /// line: a write that reached the backend but never got its closing
        /// newline, the mark of a crash. Mirrors `log.Replay.truncated`. See
        /// that field's own doc comment for why this reflects only the last
        /// call, not every call before it.
        truncated: *const fn (ptr: *anyopaque) bool,
        /// The stored bytes of the line the last `next` gave back an envelope
        /// for. Mirrors `log.Replay.line`, and carries the same rule: only
        /// meaningful right after a `next` that returned something.
        line: *const fn (ptr: *anyopaque) []const u8,
        /// The byte offset the next `next` will read from. Mirrors
        /// `log.Replay.pos`, which a caller outside this package cannot reach
        /// through the interface, and which is the only way to name the line a
        /// replay stopped on.
        at: *const fn (ptr: *anyopaque) u64,
    };

    /// Give back the next envelope, or null once the storage is exhausted. The
    /// caller owns the returned value and must call its own `.deinit()`.
    pub fn next(self: *Replay, io: std.Io) ReplayError!?std.json.Parsed(event.Envelope) {
        return self.vtable.next(self.ptr, io);
    }

    /// Release whatever this replay holds. Call once, when the caller is done
    /// reading.
    pub fn deinit(self: *Replay) void {
        self.vtable.deinit(self.ptr);
    }

    /// True when the most recent null from `next` was a torn tail, a crash mid
    /// write, rather than a clean end of log. Without this, a caller using only
    /// the `Storage` interface, which is every caller once the daemon exists,
    /// cannot tell the two apart: both give null from `next` and nothing else.
    pub fn truncated(self: *Replay) bool {
        return self.vtable.truncated(self.ptr);
    }

    /// The bytes of the line the last `next` gave back an envelope for, with
    /// no closing newline. A verifier hashes these rather than encoding the
    /// parsed envelope again: see `log.Replay.line` for why the difference
    /// decides whether a well formed log reads as tampered with.
    pub fn line(self: *Replay) []const u8 {
        return self.vtable.line(self.ptr);
    }

    /// The byte offset the next `next` will read from.
    ///
    /// **Read it before a `next`, to name the line that call is about to
    /// read.** A `next` that could not parse a line has already stepped past
    /// it, and a `next` that found a torn fragment puts the position back at
    /// that fragment's start. Only the value taken beforehand names the same
    /// line in both cases.
    pub fn at(self: *Replay) u64 {
        return self.vtable.at(self.ptr);
    }
};

/// Proof that the caller holds the storage's exclusive lock. Only `Storage.lock`
/// produces one, and this type is not `pub`, so no file outside this one can
/// name it to write the struct literal that would forge one directly. That
/// stops the ordinary mistake, the same way it does for `log.Locked`, but not a
/// caller willing to reach the same unnamed type through reflection and build
/// one anyway: see `log.Locked`'s own doc comment for that route in detail,
/// since the fix here is the identical shape applied to this vtable based
/// handle instead of a struct with named fields.
///
/// `generation` is what actually refuses a handle built that way. Every backend
/// keeps its own counter, incremented each time its `lockFn` succeeds, and
/// stamps that value onto the `Locked` it returns. `appendFn` and `unlockFn`
/// take the caller's stamped value back as a parameter and refuse to run unless
/// it still matches the backend's own counter. A handle that never went through
/// a real `Storage.lock` call carries whatever its author guessed or left at
/// the type's default, not the backend's actual current value.
const Locked = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    /// The value the backend's own lock counter held when `lockFn` produced
    /// this handle. See this struct's own doc comment.
    generation: u64,

    pub const VTable = struct {
        append: *const fn (ptr: *anyopaque, generation: u64, allocator: std.mem.Allocator, io: std.Io, ev: event.Event, time_ms: i64) StorageError!u64,
        unlock: *const fn (ptr: *anyopaque, generation: u64, io: std.Io) StorageError!void,
    };

    /// Append one event and return its identifier. The caller gives `time_ms`.
    /// This never reads the clock, so a caller stays in control of it in a test.
    pub fn append(self: *Locked, allocator: std.mem.Allocator, io: std.Io, ev: event.Event, time_ms: i64) StorageError!u64 {
        return self.vtable.append(self.ptr, self.generation, allocator, io, ev, time_ms);
    }

    /// Release the lock this handle represents.
    pub fn unlock(self: *Locked, io: std.Io) StorageError!void {
        return self.vtable.unlock(self.ptr, self.generation, io);
    }
};

/// The storage interface. Holds no operation named `append`. See this file's
/// top comment for why that lives on `Locked` instead.
pub const Storage = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        replay: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, io: std.Io, offset: u64) StorageError!Replay,
        lock: *const fn (ptr: *anyopaque, io: std.Io) StorageError!Locked,
        /// Release whatever this storage holds. Mirrors `log.Log.close`.
        close: *const fn (ptr: *anyopaque, io: std.Io) void,
        /// The hash of this storage's own header line, which every chain is
        /// anchored to. Mirrors `log.Log.headerDigest`.
        headerDigest: *const fn (ptr: *anyopaque, io: std.Io) StorageError!chain.Digest,
        /// The header line itself, without its closing newline, written into
        /// the caller's buffer. Mirrors `log.Log.headerLine`.
        ///
        /// **On the interface and not only on the file backend**, because the
        /// caller that needs it is `lib/chock-proto/ship.zig`, and a shipper
        /// that reached past this interface to the concrete backend would be
        /// tested against whichever one the test happened to hold. See
        /// `verify`, which is a free function for the same reason.
        headerLine: *const fn (
            ptr: *anyopaque,
            io: std.Io,
            buffer: *[max_header_bytes]u8,
        ) StorageError![]const u8,
    };

    /// Start a replay at `offset`, or from the start when `offset` is 0. Mirrors
    /// `log.Log.replayFrom`. See that function's doc comment for what `offset`
    /// means and how an out of range one is refused.
    pub fn replay(self: Storage, allocator: std.mem.Allocator, io: std.Io, offset: u64) StorageError!Replay {
        return self.vtable.replay(self.ptr, allocator, io, offset);
    }

    /// Take the exclusive lock. Mirrors `log.Log.lock`: the process holding the
    /// returned `Locked` is the owner of this session.
    pub fn lock(self: Storage, io: std.Io) StorageError!Locked {
        return self.vtable.lock(self.ptr, io);
    }

    /// Release whatever this storage holds: the file descriptor for JSON Lines,
    /// the in memory buffer for the fake. Safe to call more than once on either
    /// backend: a second call is a harmless no-op, the same as `log.Log.close`.
    /// Call once, when the caller is done with the storage. Without this, a
    /// caller had to reach past the interface to the concrete backend to clean
    /// up, for example `backing.log.close(io)`, which only works when the caller
    /// already knows which backend it holds, the exact thing this interface
    /// exists to let a caller not know.
    pub fn close(self: Storage, io: std.Io) void {
        self.vtable.close(self.ptr, io);
    }

    /// A verifier anchored to this storage's header line, ready to be fed the
    /// events of a replay in file order.
    ///
    /// **Its own call, and not folded into `verify`**, because a caller that
    /// is already replaying the whole log for something else, which is what
    /// `chock sessions` does, verifies the chain in that same pass rather than
    /// reading every log twice.
    pub fn verifier(self: Storage, io: std.Io) StorageError!chain.Verifier {
        return .init(try self.headerDigest(io));
    }

    /// The digest of this storage's own header line, which the chain is
    /// anchored to.
    ///
    /// **On the interface, because a seal signs it.** `lib/chock-pcsc/seal.zig`
    /// covers the header digest as well as the head, so a header swapped for
    /// another is caught by the seal and not only by the first event's `prev`.
    /// A caller that reached past this interface for it would be tested against
    /// whichever backend the test happened to hold.
    pub fn headerDigest(self: Storage, io: std.Io) StorageError!chain.Digest {
        return self.vtable.headerDigest(self.ptr, io);
    }

    /// This storage's header line, exactly as it is stored, without the newline
    /// that closes it. The answer points into `buffer`.
    ///
    /// **The bytes and not only the digest.** A copy of a log has to hold the
    /// very header line the original holds, or a verifier at the far end
    /// compares its own spelling of a header against the writer's. See
    /// `lib/chock-proto/ship.zig`.
    pub fn headerLine(
        self: Storage,
        io: std.Io,
        buffer: *[max_header_bytes]u8,
    ) StorageError![]const u8 {
        return self.vtable.headerLine(self.ptr, io, buffer);
    }
};

/// Read a whole log and say whether its chain holds. See
/// `lib/chock-proto/chain.zig` for what each verdict means and for what a
/// chain does not defeat.
///
/// **A torn tail, a line that will not decode, and a log with no chain at all
/// are answers, not errors.** Each is a fact a reader acts on differently, and
/// a function that returned an error for any of them would collapse them back
/// into one. Only a fault that stopped the reading itself, running out of
/// memory or a file that would not read, comes back as an error.
///
/// A free function over `Storage` rather than a method, so it is written once
/// and both backends are verified by exactly the same code. A fake that
/// verified more permissively than the real thing would be a protocol tested
/// against a stand-in, which is the mistake this project has already paid for
/// once.
pub fn verify(store: Storage, allocator: std.mem.Allocator, io: std.Io) StorageError!chain.Report {
    var reader = try store.verifier(io);
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();

    while (true) {
        // Read before the call, never after. A `next` that fails to parse has
        // already stepped over the line it choked on, and a `next` that finds a
        // tear puts its position back at the fragment's start. Only the value
        // from before the call names the same line in both cases.
        const line_start = replay.at();
        const parsed = replay.next(io) catch |err| switch (err) {
            // The reading itself failed. Nothing was learned about the chain,
            // so nothing is claimed about it.
            error.OutOfMemory => return error.OutOfMemory,
            error.Unexpected => return error.Unexpected,
            // Everything left is a line that would not parse. That is a fact
            // about the log and it belongs in the report.
            else => return reader.finish(.undecodable, line_start),
        } orelse {
            const ending: chain.Ending = if (replay.truncated()) .torn else .complete;
            return reader.finish(ending, line_start);
        };
        defer parsed.deinit();
        reader.take(parsed.value.id, replay.line(), parsed.value.prev);
    }
}

/// The JSON Lines implementation of `Storage`, over `log.Log`. The caller opens
/// the log and hands it to this type. Release it either directly,
/// `backing.log.close(io)`, or through the interface, `store.close(io)`. Both
/// end up at the same `File.close`.
pub const JsonLines = struct {
    log: log.Log,
    /// Whether this backend currently considers itself locked. `Storage.lock`'s
    /// vtable function sets this. `Locked`'s own vtable functions read and clear
    /// it. This is a plain bool, not a stored `log.Locked`, because `log.Locked`
    /// is not `pub`: this file cannot name it as a field type any more than an
    /// outside caller can forge one, and both restrictions come from the same
    /// fix. `appendFn` and `unlockFn` ask `self.log` for a fresh `log.Locked`
    /// each time instead, which costs nothing extra: the underlying lock is
    /// re-entrant on one open file description, so re-taking a lock this
    /// process already holds always succeeds at once. See `Memory.held` for the
    /// same shape on the fake backend, which this now matches.
    held: bool = false,
    /// Counts every successful `lockFn` call. `lockFn` stamps this value onto
    /// the `Locked` it returns. `appendFn` and `unlockFn` refuse to run unless
    /// the caller's stamped value still matches this counter, which is what
    /// tells a genuine handle apart from one built without ever calling
    /// `Storage.lock`. See `storage.Locked`'s own doc comment.
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
        // The wrapper needs a stable address distinct from `self`, since more
        // than one replay can run at once against the same log. Freed again in
        // `replayDeinitFn`, using the same allocator stored on the value itself.
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
        // Refuse a second lock at this interface even though the kernel's own
        // lock would allow it: the lock is re-entrant on one open file
        // description, so it cannot by itself tell a genuine second owner
        // apart from this same backend locking twice. `Memory.lockFn` already
        // refuses a second lock this way. Without this check the two backends
        // would disagree on a sequence a test can run against either one, the
        // exact drift this fix closes.
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
        // No lock held, a handle used again after its own unlock, or a handle
        // whose generation does not match this backend's own counter: all three
        // are the caller's bug. log.Locked already refuses the "used after
        // unlock" case on its own once it has a real handle, but a forged
        // handle, or the plain "never locked" case, needs a check here since
        // there is no real `log.Locked` to ask yet. See `storage.Locked`'s own
        // doc comment for the forged case this generation check exists for.
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

/// A storage that keeps every event in memory instead of a file. Exists so a
/// test of the agent loop needs no file on disk. See the second test in this
/// file.
///
/// It mirrors `log.Log`'s wire shape: the same header line, one JSON line per
/// event, and the byte offset of a line as that event's own id. `MemoryReplay`
/// therefore walks it the same offset based way `log.Replay` walks a real
/// file. It does not mirror `log.Log`'s durability or its crash recovery.
/// There is no sync, because there is nothing here to make durable past
/// this process exiting. There is no torn tail to find either, because every
/// write to `bytes` finishes or the process is gone and the buffer with it,
/// so `MemoryReplay.truncatedFn` always answers false. `held` here is a plain
/// bool, not a kernel lock, because nothing outside this one process can
/// ever see `bytes` to contend with it. None of this backend's own vtable
/// functions touch a file, so each still accepts `io: std.Io`, to satisfy the
/// shared `VTable` shape, and ignores it.
pub const Memory = struct {
    allocator: std.mem.Allocator,
    session: []const u8,
    bytes: std.ArrayList(u8) = .empty,
    held: bool = false,
    /// Counts every successful `lockFn` call, the same token `JsonLines` keeps.
    /// See `storage.Locked`'s own doc comment.
    lock_generation: u64 = 0,
    /// True once `deinit` has freed `bytes`. Checked by `deinit` itself, not
    /// asserted, so a second call is a harmless no-op instead of the double
    /// free a reviewer reproduced: `std.ArrayList.deinit` leaves the list in an
    /// undefined state, not an empty one, so calling it twice without this
    /// guard frees the same allocation twice. A fake backend that crashes on a
    /// call the real, file backed one tolerates defeats the reason the fake
    /// exists, see `log.Log.close`, which is already safe to call more than
    /// once for exactly this reason.
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
        // Mirrors log.Log.lock's non-blocking behaviour: a second locker is told
        // at once, not left waiting for a lock nothing will ever release for it.
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

        // **The fake chains too.** A stand-in more permissive than the real
        // thing is a protocol tested against nothing, which is a mistake this
        // project has already paid for once. A test of the agent loop written
        // over this backend must produce a log that verifies exactly like a
        // file backed one.
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

    /// The digest of the last whole line in the buffer, which is what the next
    /// event's `prev` must carry. Mirrors `log.Log.lastLineDigest`, over a
    /// slice instead of a file: a buffer that holds only the header answers
    /// the header's own digest, which is what anchors a chain.
    fn lastLineDigest(self: *const Memory) chain.Digest {
        const bytes = self.bytes.items;
        // `init` writes the header, so the buffer always ends with a newline
        // by the time anything can append.
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
        // Copied into the caller's buffer rather than borrowed from this file's
        // own literal, so both backends answer the same shape and a caller
        // cannot come to rely on the answer outliving its buffer.
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
    /// The bytes of the line the last `nextFn` gave back an envelope for. A
    /// slice into the backend's own buffer, which nothing appends to while a
    /// caller is reading a replay of it, so it stays valid until the next
    /// call. Mirrors `log.Replay.line`.
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

    /// Always false. A growing in memory buffer has no crash to leave a tear
    /// behind: every write to `bytes` either finishes or the process is gone
    /// and the buffer with it, so `nextFn` never finds a line with no closing
    /// newline the way a real file left mid write can.
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
    // The interface exists so PostgreSQL can replace the file later without the
    // agent loop changing. Once `store` is built, nothing below touches
    // `log.Log` or `log.Locked` by name, only `Storage`, `Locked`, and `Replay`.
    // Cleanup goes through `store.close(io)`, not `backing.log.close(io)`: a
    // caller that only ever holds a `Storage` must be able to release it
    // without reaching past the interface to the concrete backend underneath.
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
    // If a test of the agent loop needs a file on disk, the interface is not
    // doing its job. This drives the same sequence as the test above, through
    // the same Storage type, over a backend that never opens a file. Cleanup
    // goes through `store.close(io)` here too, so both backends prove the same
    // interface really is enough on its own.
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
    // Before this fix, JsonLines let a second lock through: the underlying lock
    // is re-entrant on one open file description, so locking a descriptor this
    // process already holds just reaffirms the same lock instead of failing.
    // Memory already refused a second lock. A test written against the fake
    // could pass and then fail against the real backend, which defeats the
    // reason the fake exists. Running the identical sequence against both here
    // means a future regression that reopens this gap fails right here, not
    // later against whichever backend a caller happened to test with.
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

/// Drive the same lock, lock again, unlock, lock again sequence against
/// `store`, whichever backend it wraps. A second lock while the first is
/// still held must fail with `error.Busy`. Releasing the first must let a
/// fresh lock through again.
fn expectSecondLockIsRefused(store: Storage, io: std.Io) !void {
    var locked = try store.lock(io);
    try std.testing.expectError(error.Busy, store.lock(io));
    try locked.unlock(io);

    var locked_again = try store.lock(io);
    try locked_again.unlock(io);
}

test "regression: a caller using only the Storage interface can tell a torn tail from a clean end of log" {
    // Before this fix, nothing in the vtable could say a replay stopped
    // because of a crash rather than because the caller is caught up: both
    // gave null from `next` and nothing else. This seeds a file with a good
    // header and a fragment with no closing newline directly, bypassing
    // `Log.open`, the same shape `log.zig`'s own torn tail tests use, then
    // proves the fact reaches a caller that never names `log.Log` or
    // `log.Replay`, only `Storage` and `Replay`.
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
    // A clean end of log and a torn tail both give null here. Only
    // `replay.truncated()` tells them apart, and it must be true.
    try std.testing.expect((try replay.next(io)) == null);
    try std.testing.expect(replay.truncated());
}

test "regression: a Locked handle whose generation does not match the backend's own is refused, on both backends" {
    // Pins the third route a reviewer found: `storage.Locked` cannot be named
    // outside this file, but Zig still lets a caller build a value of a type it
    // cannot name, the same way as `log.Locked`, see that type's own doc
    // comment for the reflection route in detail. A reviewer forged one this
    // way in a scratch program and reached `append` with no lock ever taken,
    // because the only check at the time, `held`, read true off the real
    // owner's own state on the very same backend struct: `Storage.ptr` and
    // `JsonLines.log` are real fields a caller holding only a `Storage` can
    // still reach directly. `generation` closes it: a forged handle carries
    // whatever its author guessed or left at 0, and a real `lock` on this
    // backend has already moved its own counter past that. This builds the
    // struct directly rather than through reflection, since this test lives
    // inside the file that can still name `Locked`, but it exercises the exact
    // comparison the reflection route depends on. Delete that comparison, or
    // mark `Locked` `pub` again without it, and this is the test that fails.
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
    // The reviewer found a segfault here: Memory.deinit freed its buffer twice,
    // once through each close call, because `std.ArrayList.deinit` leaves the
    // list undefined rather than empty, so a second call on the same value
    // frees whatever garbage sits in that undefined state. JsonLines already
    // tolerated a second close, since `log.Log.close` does. A fake backend that
    // crashes on a call the real backend tolerates defeats the reason the fake
    // exists.
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

/// A path under a fresh temporary directory. The caller keeps `tmp` alive for
/// as long as it uses the path.
fn scratchPath(
    tmp: *std.testing.TmpDir,
    dir_buffer: []u8,
    path_buffer: []u8,
    name: []const u8,
) ![:0]u8 {
    const dir_path = try log.absoluteDirPath(std.testing.io, dir_buffer, tmp.dir);
    return std.fmt.bufPrintZ(path_buffer, "{s}/{s}", .{ dir_path, name });
}

/// Write `bytes` to `path`, whatever was there before. Bypasses `Log`
/// entirely, so a test can put a shape on disk that no writer would ever
/// make: a chain that disagrees, an event with no chain at all, a fragment
/// with no closing newline.
fn writeWholeFile(io: std.Io, path: [:0]const u8, bytes: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

fn readWholeFile(allocator: std.mem.Allocator, io: std.Io, path: [:0]const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(4 * 1024 * 1024));
}

/// Append `count` message events through a real `JsonLines` store, and give
/// back the offset each one landed at. The events are what a session really
/// writes, through the real writer, so what is on disk afterwards is a real
/// log and not a shape a test invented.
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

/// Verify the log at `path` through a fresh handle, the way a reader that was
/// not the writer sees it.
fn verifyFile(allocator: std.mem.Allocator, io: std.Io, path: [:0]const u8) !chain.Report {
    var backing = JsonLines{ .log = try log.Log.open(io, path, "01CHAINSESSION") };
    const store = backing.storage();
    defer store.close(io);
    return verify(store, allocator, io);
}

test "a real log written through the real writer verifies, on both backends" {
    // The baseline every other test here is measured against. Without it, a
    // `verify` that answered `broken` for everything would pass all of them.
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

    // And the fake writes a chain too, so a test of the agent loop over it
    // produces a log that verifies exactly the same way. A fake that skipped
    // this would be a stand-in more permissive than the real thing.
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
    // **The fact this whole change exists for.** A log written honestly, then
    // one byte of one event changed in place afterwards, the way somebody with
    // an editor and a reason would do it. The changed line still carries the
    // hash it always did, so it passes on its own. The event after it is what
    // gives the change away: it names bytes that are no longer there.
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

    // Change "event number 2" to "event number 9", in place. The same length,
    // so every offset after it is untouched and the file still reads as a
    // well formed log line by line. Nothing but the chain can see this.
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
    // The event whose recorded hash disagreed, and the event before it. The
    // change sits between those two, and it is event 2 that was changed.
    try std.testing.expectEqual(offsets[3], report.at);
    try std.testing.expectEqual(offsets[2], report.after);
    // It still read the whole file rather than stopping at the fault, so a
    // reader learns how much of the log there was as well as where it broke.
    try std.testing.expectEqual(@as(u64, 5), report.events);
}

test "an event changed in the middle is found on the fake backend too" {
    // The same attack against `Memory`, whose buffer a test can edit exactly
    // the way an editor edits a file. Run against both backends because a
    // stand-in that missed this would let a loop test pass over a log the real
    // storage would have refused.
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
    // The two answers that must never be one. Somebody edited this log and the
    // power went out mid write are different facts, and a reader does
    // different things about them: one is a fault to recover from and the
    // other is a person to find.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&tmp, &dir_buffer, &path_buffer, "chain-torn");

    const offsets = try seedChainedLog(allocator, io, path, 3);
    defer allocator.free(offsets);

    // A write that reached the kernel and never got its closing newline. The
    // fragment is a real event's opening bytes, which is what makes this the
    // hard case: a reader that parsed before it looked would see a broken
    // line rather than an unfinished one.
    const whole = try readWholeFile(allocator, io, path);
    defer allocator.free(whole);
    const fragment_at = whole.len;
    const torn = try std.fmt.allocPrint(allocator, "{s}{{\"id\":0,\"session\":\"01CH", .{whole});
    defer allocator.free(torn);
    try writeWholeFile(io, path, torn);

    const report = try verifyFile(allocator, io, path);
    try std.testing.expectEqual(chain.Verdict.torn, report.verdict);
    // **Not an edit**, which is the whole point of the two verdicts.
    try std.testing.expect(!report.edited());
    try std.testing.expectEqual(@as(u64, fragment_at), report.at);
    // And everything before the tear was still read and still checked, so a
    // tear does not cost a reader the chain over the rest of the log.
    try std.testing.expectEqual(@as(u64, 3), report.events);
    try std.testing.expectEqual(@as(u64, 3), report.chained);
}

test "a log edited in the middle and torn at the end is reported as edited, not as torn" {
    // Both faults at once, which a crash during an edit really does produce.
    // The tear at the end explains nothing about a hash that disagreed
    // earlier, so naming the smaller fault would bury the larger one.
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
    // Every log written before this change carries no `prev` on any line, and
    // there is no way to give one to a log that already exists. Those sessions
    // must stay readable forever, which means the answer is a verdict and
    // never an error.
    //
    // It is also not a pass: nothing here can say whether such a log was
    // edited, and `unchained` is what stops a reader believing otherwise.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&tmp, &dir_buffer, &path_buffer, "chain-legacy");

    // Exactly the bytes a build from before the chain wrote: no `prev` member
    // anywhere, not even an empty one.
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

    // And the events themselves still read, which is what "read rather than
    // refused" has to mean: a verdict nobody can act on is no better than an
    // error.
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
    // The real shape of an upgrade: a session started before this change and
    // resumed after it. The first chained event's `prev` is the hash of the
    // unchained line in front of it, which only works because `append` reads
    // the file rather than remembering what it wrote.
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

    // And the chained part is genuinely checked and not merely counted: an
    // edit inside it is still found.
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
    // **The one place a naive hash chain breaks, worked out rather than
    // discovered later.** A chain cannot survive an event being taken out of
    // the middle of the file. Compaction is the one thing in Chock that sounds
    // like it does that, and it does not: `lib/chock-core/compaction.zig` says
    // in its own first lines that a compaction summarises the context the
    // model sees and deletes nothing from the log. It is one more appended
    // event.
    //
    // So this test proves two things at once. The chain over a compacted
    // session is intact, and every event id inside `[from_id, through_id]` is
    // still readable out of the log, including the ones `kept_ranges` did not
    // keep in the context. A later compaction that rewrote the file would fail
    // the second half here, and the failure is the message: the chain is what
    // such a rewrite breaks.
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

        // The fold covers all four and keeps only the last two verbatim in the
        // context. The two it did not keep are the ones that must still be in
        // the log for this test to mean anything.
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
    // Four turns, the compaction itself, and the turn after it.
    try std.testing.expectEqual(@as(u64, 6), report.events);
    try std.testing.expectEqual(@as(u64, 6), report.chained);

    // Every event of the folded span is still there to be read and still there
    // to be hashed, the two that `kept_ranges` named and the two it did not.
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
    // A log whose lines are valid JSON in a shape this build would never
    // write: the members in another order, and whitespace inside the object.
    // The chain over those lines is correct, because it was built from the
    // bytes themselves.
    //
    // A verifier that encoded each parsed envelope again would compare its own
    // JSON with the writer's, find every byte in a different place, and call a
    // sound log tampered with. That is the failure this pins, and no test
    // written over Chock's own writer could ever see it, because both sides
    // would then agree by accident.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&tmp, &dir_buffer, &path_buffer, "chain-foreign-shape");

    const header = "{\"chock_log\":1}";
    // The digest written out in full, and not read from `chain.of` here, so
    // this test names the number it expects rather than agreeing with whatever
    // the code computes. A change of hash function has to change this line.
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
    // A tear can only ever be the last line of a file. A line that is
    // complete, newline and all, and still will not parse can be any of them,
    // so the two cannot share a verdict: one is a write that never finished
    // and the other is a file somebody changed badly.
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
    // The events before it were read and checked, so the report is still worth
    // something.
    try std.testing.expectEqual(@as(u64, 3), report.events);
}

test "a log nothing can open is never reported as verified" {
    // An absent answer is never a permissive answer, which is the same rule a
    // policy keeps. A `Report` nobody could fill in carries `unreadable`, and a
    // caller that forgot to check the error still does not get a pass by
    // default.
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
