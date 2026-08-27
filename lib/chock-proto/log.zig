//! The session log: one file, one line per event, JSON Lines on disk. The log is the
//! truth for a session. Every other part of Chock reads state by folding it. The byte
//! offset `append` returns for a line is that event's identifier for the rest of Chock,
//! which is what lets a reconnect and a seek be the same operation. An envelope's `id`
//! field is always zero on disk, so a reader must take the real identifier from the
//! seek offset, not from that field. See `lib/chock-proto/event.zig` for the envelope
//! this file serializes.
//!
//! `Replay` is the read side. It walks the log forward from a given offset, one line
//! at a time, and stamps each envelope's `id` with the offset its line started at
//! before handing it back. Nothing downstream ever sees the zero `append` wrote. A
//! reconnect and the daemon side of `/daemonize` both use this: give `replayFrom` the
//! last offset a caller already has, and it resumes exactly there. A tear at the end
//! of the file, the mark of a write that never reached its closing newline, ends the
//! replay without an error and without breaking `open`'s own check for the same thing.
//! See `Replay.truncated`. A complete line that is not valid JSON is a different fact,
//! corruption rather than a tear, and that one does surface as an error.
//!
//! Every event carries `prev`, the hash of the whole line written before it, so a
//! log is evidence against an edit and not only against a crash. `append` reads the
//! last line off the file itself and hashes it, rather than remembering what it wrote,
//! because a second `Log` on the same path can have appended in between. The first
//! event of a log carries the header line's own hash. `Replay.line` is what lets a
//! reader hash the same bytes the writer did. See `lib/chock-proto/chain.zig` for the
//! reader, the verdicts, and an honest account of what a chain does not defeat.
//!
//! Every disk access in this file goes through `std.Io`, threaded in as an explicit
//! parameter the same way the rest of Chock does, so this file runs unmodified on
//! Darwin as well as Linux. See `open` for the one call that still reaches past
//! `std.Io` to `std.posix`, and why.

const std = @import("std");
const chain = @import("chain.zig");
const event = @import("event.zig");
const chock_io = @import("chock-io");
const short_write_probe = @import("short_write_probe.zig");

/// The log file format. Named in the header line every log starts with, so a future
/// format change has something to detect instead of something to guess at.
const format_version: u32 = 1;

/// The most bytes a header line can take, its closing newline included. The
/// header names a version number and nothing else, so this is generous by an
/// order of magnitude, and it is what makes a header something a caller can read
/// into a buffer on its stack. `ensureHeader` and `headerEnd` read the same
/// number.
pub const max_header_bytes: usize = 64;

pub const LogError = error{
    /// A component of the log path does not exist, for example a missing parent
    /// directory. Creating the file is not creating the directory that holds it.
    FileNotFound,
    /// The path exists but this process may not open it for reading and writing.
    AccessDenied,
    /// The path names a directory, not a file the log format can be written to.
    IsDir,
    /// Opening the log path failed for a reason this file has no specific recovery
    /// for.
    OpenFailed,
    /// A write did not reach the kernel at all.
    WriteFailed,
    /// The kernel accepted fewer bytes than the line held. A partial line corrupts the
    /// offset of every line after it, so this is reported, never retried.
    ShortWrite,
    /// `File.sync` returned an error. The line may be on disk or may not be. The
    /// caller cannot treat the last `append` as durable.
    SyncFailed,
    /// `replayFrom` was given an offset that is not within the events currently on
    /// disk: at or past the end of the file, or before the first event. The offset
    /// usually comes from a client's `Last-Event-ID`, so this is untrusted input.
    /// Answer the client with an error instead of the empty stream a caller who is
    /// genuinely caught up would also see.
    OffsetOutOfRange,
    /// `replayFrom` was given an offset that does not land on the first byte of a
    /// line. A well formed offset always came from `append`'s own return value, so
    /// this can only mean the caller sent something else.
    OffsetNotLineStart,
    /// `lock` found another process already holding the exclusive lock on this log.
    /// This is the one member of this set that is an ownership fact, not a fault: it
    /// means a different process currently owns the session. A caller shows the user
    /// a different message for this than for `Unexpected`.
    Busy,
    /// `Locked.append` was called on a handle that is not proof of a currently
    /// held lock: either `unlock` already ran on it, or its `generation` does not
    /// match the log's own counter, which is what a handle built without ever
    /// calling `Log.lock` carries. Marking `Locked` unnamed outside this file
    /// stops the ordinary mistake of constructing one directly, but Zig still
    /// lets a caller build a value of a type it cannot name, see `Locked`'s own
    /// doc comment, so this run time check is the actual backstop for both
    /// cases, not the type system. A real bug in the caller's own call sequence
    /// in the `unlock`-already-ran case. A forged or superseded handle in the
    /// `generation` mismatch case. Either way the fix is to stop using the
    /// handle, never to retry.
    NotLocked,
    /// The file already has content, but its first line is not a header this build
    /// recognizes: missing, malformed, or naming a version this build has never heard
    /// of. A guess about an unknown format is worse than an error. This also covers a
    /// header line itself cut short by a crash during file creation. Only a fragment
    /// past an intact header is recovered as a torn tail. See `Log.tail_was_torn`.
    BadHeader,
    /// A call into `std.Io` failed with something this file has no specific recovery
    /// for.
    Unexpected,
} || event.EncodeError;

/// An open session log. One `Log` is one file. A session belongs to whichever process
/// holds this log's exclusive lock, see `lock`, and that is the whole mechanism behind
/// `/daemonize`: the owner calls `unlock` on the handle `lock` gave it, the new owner
/// calls `lock` again, and there is no other handover protocol.
pub const Log = struct {
    file: std.Io.File,
    /// The session every envelope this log writes belongs to. `open` borrows this
    /// string. The caller keeps it alive for as long as the log stays open.
    session: []const u8,
    /// Set by `open` when the file's last line had no trailing newline: an earlier
    /// append reached the kernel only partly before a crash or a power loss. `open`
    /// does not touch the file for this. It only records the fact and where the
    /// fragment starts, in `torn_tail_at`. A caller that cares whether an event was
    /// lost should check this flag and warn, since only a full sequential read can
    /// tell how much, if anything, went missing.
    tail_was_torn: bool = false,
    /// The byte offset where the torn fragment started at the moment `open` ran.
    /// Meaningless unless `tail_was_torn` is true. This is a fact about the past,
    /// reported for a caller that wants to know, never an instruction: `append`
    /// finds the fragment's current start itself, fresh, on every call, because a
    /// second `Log` on the same path can move where the fragment sits, or remove
    /// it, between this handle's `open` and its own next `append`. See `append`.
    torn_tail_at: u64 = 0,
    /// Counts every successful `lock` call on this `Log`. Not an ownership count,
    /// a token: each `Locked` `lock` hands out carries the value this counter held
    /// at that moment, and `Locked.append` refuses to run unless the handle's
    /// stored value still matches this one. See `Locked` for why a runtime check
    /// is what closes this hole, not the type system, and see `error.NotLocked`.
    lock_generation: u64 = 0,

    /// Open or create the log at `path` and give it envelopes for `session`. A new file
    /// gets a header line first. An existing file must already carry one this build
    /// recognizes, or this returns `error.BadHeader`. Never fails just because the last
    /// line on disk is a fragment from an interrupted write, and never writes to the
    /// file to deal with one either, so a read only caller gets the same answer a
    /// writer does. See `tail_was_torn`.
    ///
    /// Opened through `std.posix.openatZ`, not `std.Io.Dir`, because this file needs
    /// `O_APPEND` and no option in `std.Io.Dir.OpenFileOptions` or
    /// `CreateFileOptions` exposes it: `std.Io`'s cross platform surface has no place
    /// to ask for append mode at all. `append` below depends on `O_APPEND`: it is
    /// what makes a plain write always land at the true end of file, portably, no
    /// matter what a caller's own last known offset says. `std.posix` still reaches
    /// the real `open(2)` on every POSIX target Chock cares about, Linux directly and
    /// Darwin through libc, so this is the one place in the file that steps down from
    /// `std.Io` to `std.posix` rather than a raw Linux syscall, and it is a single call.
    /// Once the descriptor exists, it is wrapped in a `std.Io.File` and every other
    /// operation in this file goes through `std.Io` again.
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

    /// Close the log. Does not fail: a close error here has nothing durable left to
    /// report, the same as `std.Io.File.close` itself, which returns nothing to fail
    /// with. Safe to call more than once: the handle is invalidated after the first
    /// close, and this checks for that invalid value itself before closing again,
    /// so a repeat call neither closes whatever unrelated descriptor the kernel
    /// hands out next nor calls `File.close` a second time on the same one.
    ///
    /// That guard is load bearing in a way the old raw `linux.close` never needed:
    /// the kernel's own `close(2)` answers a second close with plain `EBADF`, which
    /// `linux.close`'s caller was free to discard, but `std.Io`'s own backend
    /// treats closing an already invalid handle as a bug in the caller and panics
    /// on it in a Debug or ReleaseSafe build. Checking here, before ever reaching
    /// `File.close` a second time, is what keeps this function's own "safe to call
    /// more than once" promise true under `std.Io` the same way it was under the
    /// raw syscall.
    ///
    /// The kernel releases the lock this file description held the moment its last
    /// descriptor closes, with no separate call needed, so a process that exits
    /// without ever calling this, for example one that is killed, still gives the lock
    /// back. A `Locked` handle taken before this runs is not touched here. A caller
    /// that still holds one and tries to use it after close passes an invalidated
    /// handle into `append` or `unlock`. In a Debug or ReleaseSafe build, that
    /// function's own assert catches the mistake right away. In ReleaseFast the
    /// assert compiles out, so nothing catches it before the next call, but `std.Io`
    /// still rejects the stale handle at the kernel level, which surfaces to the
    /// caller as `error.Unexpected` rather than undefined behaviour.
    pub fn close(self: *Log, io: std.Io) void {
        if (self.file.handle == -1) return;
        self.file.close(io);
        self.file.handle = -1;
    }

    /// Take the exclusive lock that decides which process owns this session.
    /// The process holding this lock is the owner, and `/daemonize` moves
    /// ownership by one side calling `unlock` on its handle and the other
    /// calling `lock`, with no separate transfer protocol.
    ///
    /// Returns a `Locked` handle instead of only flipping a flag on `self`. `append`
    /// is a method on `Locked`, not on `Log`, so an ordinary caller reaches it only
    /// through a value this function handed out. `Locked` is not `pub`, so no file
    /// outside this one can write out its own struct literal by naming the type
    /// directly, which stops the ordinary mistake of building one by hand. It does
    /// not stop a caller willing to reach the same type through `@TypeOf(self.lock(
    /// ))` or a reflection built from that, which Zig does still allow to build a
    /// value of a type it cannot name. `generation` is what refuses that value:
    /// see `Locked`'s own doc comment for why the real defense here is a runtime
    /// check, not the type system, and see `error.NotLocked`.
    ///
    /// Uses `File.tryLock`, so this returns `error.Busy` at once, as soon as
    /// `tryLock` answers `false`, when another process already holds the log rather
    /// than blocking. A caller left waiting forever for a session somebody else owns
    /// is a worse failure than a caller told no right away. The first looks like a
    /// hang with no explanation. The second can show the user a clear message,
    /// because `Busy` is its own error and never confused with `Unexpected`.
    ///
    /// `File.tryLock`/`unlock` lock this open file description, `self.file`, not the
    /// path and not this process: on every POSIX target this file runs on, `std.Io`'s
    /// own implementation is `flock(2)` underneath, the exact call this file used to
    /// make directly. A second `Log` opened on the same path, through a second `open`
    /// call in this process or another, contends for this lock correctly, because
    /// each `open` makes its own file description. Only a duplicated descriptor, for
    /// example one made with `dup`, would share this lock instead of contending for
    /// it, and Chock never duplicates a log's descriptor that way.
    pub fn lock(self: *Log, io: std.Io) LogError!Locked {
        std.debug.assert(self.file.handle != -1);
        const acquired = self.file.tryLock(io, .exclusive) catch return error.Unexpected;
        if (!acquired) return error.Busy;
        self.lock_generation +%= 1;
        return .{ .log = self, .generation = self.lock_generation };
    }

    /// Read the first line of a file that already has content, and check it against
    /// the header this build writes. Write a fresh header when the file is new.
    fn ensureHeader(self: *Log, io: std.Io) LogError!void {
        var buffer: [max_header_bytes]u8 = undefined;
        const filled = self.file.readPositionalAll(io, &buffer, 0) catch return error.Unexpected;

        // A zero length file is not a corrupt one: it is what `open`'s own `CREAT`
        // hands back for a path that did not exist yet, and nothing has raced ahead
        // of us to write a header. Giving it a fresh header is the only sane reading,
        // so this is not treated as a missing header on an otherwise real log.
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

    /// Check whether the file ends with a newline, and record where the fragment
    /// starts if it does not. A missing trailing newline means the last write to
    /// this file stopped after some bytes reached disk but before the newline that
    /// closes the line, so the last line on disk is a fragment, not a full event.
    /// This never writes to the file: a read only caller must see the same tear a
    /// writer does, and a caller that does write only removes the fragment on its
    /// first `append`, once it is actually about to write over it.
    fn checkTornTail(self: *Log, io: std.Io) LogError!void {
        const size = try self.tailIsTorn(io) orelse return;
        self.tail_was_torn = true;
        self.torn_tail_at = try self.findTornFragmentStart(io, size);
    }

    /// Read the file's current size, and say whether its last byte is missing the
    /// newline that closes a line. Returns the size when it is missing, so a
    /// caller that already needs the size for something else, such as finding
    /// where the fragment starts, does not pay for a second length query. Returns
    /// null when the file is empty or the last byte is a newline: nothing is torn.
    ///
    /// `checkTornTail` calls this once, at `open`. `append` calls it again, right
    /// before it would cut anything: see the comment at that call site for why a
    /// fact this function found once is not proof of what the file holds later.
    fn tailIsTorn(self: *Log, io: std.Io) LogError!?u64 {
        const size = self.file.length(io) catch return error.Unexpected;
        if (size == 0) return null;

        var last_byte: [1]u8 = undefined;
        const n = self.file.readPositionalAll(io, &last_byte, size - 1) catch return error.Unexpected;
        if (n != 1) return error.Unexpected;
        if (last_byte[0] == '\n') return null;
        return size;
    }

    /// Find the offset where the file's last, unterminated line begins. The
    /// fragment starts right after the newline that closes the line before it,
    /// or right after the header if the whole file past the header is one
    /// fragment with no complete line in it. The header itself is never
    /// answered: `open` has already proved an intact header is there, and a
    /// caller about to cut must not be told to cut that away.
    fn findTornFragmentStart(self: *Log, io: std.Io, size: u64) LogError!u64 {
        const header_end = try self.headerEnd(io);
        return @max(header_end, try self.findLineStart(io, size));
    }

    /// The offset where the line that ends at `end` begins. `end` is the
    /// position of that line's own closing newline, or the size of the file
    /// when the last line never got one. Searches backward for the newline
    /// that closes the line before it: this line starts one byte after it.
    ///
    /// Answers 0 when no earlier newline is there at all, which is the header's
    /// own line and the only line of a log that starts at zero.
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

    /// The digest of the bytes in `[start, end)`, read in chunks so a line of
    /// any length costs one buffer rather than its own size in memory. A tool
    /// result is the line that makes this matter.
    fn digestOfRange(self: *const Log, io: std.Io, start: u64, end: u64) LogError!chain.Digest {
        std.debug.assert(start <= end);
        var hasher: chain.Hasher = .{};
        var pos = start;
        var read_buffer: [4096]u8 = undefined;
        while (pos < end) {
            const want: usize = @intCast(@min(read_buffer.len, end - pos));
            const n = self.file.readPositionalAll(io, read_buffer[0..want], pos) catch return error.Unexpected;
            // The range was measured off this same file a moment ago and this
            // handle holds the lock, so a short read here means the file was
            // cut underneath us: never something to hash a partial answer for.
            if (n == 0) return error.Unexpected;
            hasher.update(read_buffer[0..n]);
            pos += n;
        }
        return hasher.finish();
    }

    /// The digest of this log's header line, without its closing newline. The
    /// first event of a log carries this as its `prev`, so the chain is
    /// anchored to the header rather than starting in the air. See
    /// `lib/chock-proto/chain.zig`.
    pub fn headerDigest(self: *const Log, io: std.Io) LogError!chain.Digest {
        const header_end = try self.headerEnd(io);
        return self.digestOfRange(io, 0, header_end - 1);
    }

    /// The header line itself, as it sits on disk, without its closing newline,
    /// written into `buffer`.
    ///
    /// **The bytes and not only their digest**, because a caller that copies a
    /// log somewhere else has to write the very line this file holds. A copy
    /// with a header this build composed again would verify only while the two
    /// spellings happened to agree, which is the fault `chain.zig`'s reordered
    /// key test names. `lib/chock-proto/ship.zig` is the caller.
    ///
    /// `chain.of` over the answer always equals `headerDigest`, and
    /// `lib/chock-proto/ship.zig` has the test that says so.
    pub fn headerLine(self: *const Log, io: std.Io, buffer: *[max_header_bytes]u8) LogError![]const u8 {
        const filled = self.file.readPositionalAll(io, buffer, 0) catch return error.Unexpected;
        const newline = std.mem.indexOfScalar(u8, buffer[0..filled], '\n') orelse return error.BadHeader;
        return buffer[0..newline];
    }

    /// The digest of the last whole line in the file, which is what the next
    /// event's `prev` must carry.
    ///
    /// **Read from the file on every call, never remembered.** A second `Log`
    /// on the same path can have appended since this handle opened, which is
    /// the shape a `/daemonize` handover takes, so an answer cached at `open`
    /// would chain a new event onto a line that is no longer the last one.
    /// `append` re-reads the torn tail for the same reason: see its own
    /// comment.
    ///
    /// A file holding only its header answers the header's own digest, because
    /// `findLineStart` walks back to 0 when there is no earlier newline.
    fn lastLineDigest(self: *const Log, io: std.Io) LogError!chain.Digest {
        const size = self.file.length(io) catch return error.Unexpected;
        // `ensureHeader` wrote or proved a header before anything could reach
        // this, so the file always holds at least one closing newline here.
        std.debug.assert(size > 0);
        const end = size - 1;
        return self.digestOfRange(io, try self.findLineStart(io, end), end);
    }

    /// Write `line` in one call to `std.Io` and confirm every byte of it landed.
    /// `File.writeStreaming` issues exactly one write to the kernel per call, the
    /// same guarantee the old direct `linux.write` gave: a short result is reported
    /// back to the caller here, never silently completed with a second write. See
    /// `append`'s own comment on why a line and its newline must reach the kernel as
    /// one write, never two.
    fn writeExact(self: *Log, io: std.Io, line: []const u8) LogError!void {
        const written = self.file.writeStreaming(io, &.{}, &.{line}, 1) catch return error.WriteFailed;
        if (written != line.len) return error.ShortWrite;
    }

    /// Start a replay inclusive of `offset`, the byte position of some line already
    /// in the file, or 0 for a full replay from the start. This is the offset based
    /// entry point: give it a byte position you already computed, and the event at
    /// that exact position is the first one back.
    ///
    /// A nonzero `offset` queries the file's current size for the range check below.
    /// That is a read only query, and it does not disturb `append`: `append` never
    /// relies on any shared file position, since the log is opened with `O_APPEND`,
    /// so the kernel repositions to the true end of file before every write, no
    /// matter what any query beforehand saw.
    ///
    /// This is for internal use, a caller that already has a byte offset and wants
    /// to seek to it. It is the wrong function for a client's `Last-Event-ID`. That
    /// value names the last event the client already has, so resuming there with
    /// this function would hand the client that same event a second time. Use
    /// `resumeAfter` for that case. See its own doc comment for the difference.
    ///
    /// `Envelope.id` documents 0 as meaning "not yet written", so no real event can
    /// ever sit at offset 0. That offset is always the header line instead. A full
    /// replay therefore starts just past the header, not on top of it, since the
    /// header is not itself an envelope and would only fail to parse as one.
    ///
    /// A nonzero `offset` is checked before it is trusted: it must fall within the
    /// events already on disk, and it must sit on the first byte of a line, never
    /// `error.OffsetOutOfRange` or `error.OffsetNotLineStart` silently swallowed
    /// into an empty replay. An offset past the end of the file looks exactly like
    /// a caller who is fully caught up unless this is checked. An offset that
    /// reaches this function by way of `resumeAfter` started as untrusted client
    /// input, a `Last-Event-ID` this process does not control.
    pub fn replayFrom(self: *const Log, allocator: std.mem.Allocator, io: std.Io, offset: u64) LogError!Replay {
        const header_end = try self.headerEnd(io);
        if (offset == 0) return .{ .file = self.file, .allocator = allocator, .pos = header_end };

        const size = self.file.length(io) catch return error.Unexpected;
        if (offset < header_end or offset >= size) return error.OffsetOutOfRange;

        // `offset` claims to be the start of a line. The byte right before it must
        // then be the newline that closes the line before it, the header's own
        // newline included, or this offset never came from `append`.
        var prev_byte: [1]u8 = undefined;
        const n = self.file.readPositionalAll(io, &prev_byte, offset - 1) catch return error.Unexpected;
        if (n != 1) return error.Unexpected;
        if (prev_byte[0] != '\n') return error.OffsetNotLineStart;

        return .{ .file = self.file, .allocator = allocator, .pos = offset };
    }

    /// Start a replay positioned right after the event named by `last_event_id`.
    /// This is the client facing entry point: `last_event_id` is a client's own
    /// `Last-Event-ID`, and that value means "I already have this one, send
    /// what comes after", never "send this one again". `replayFrom` starts
    /// inclusive of the offset it is given instead, so calling it directly on a
    /// `Last-Event-ID` redelivers the event the client already has. Use
    /// `replayFrom` only for an internal offset a caller computed itself, never
    /// for a value that arrived as a client's own header.
    ///
    /// `last_event_id` of 0 means the client has nothing yet, the same case
    /// `replayFrom` treats as a full replay from the start, so this returns that
    /// same full replay rather than trying to skip an event that does not exist.
    ///
    /// This costs one extra parsed and discarded event over `replayFrom`, since
    /// finding "right after" a byte offset means reading the line at that offset
    /// first. That line's own errors, `OffsetOutOfRange`, `OffsetNotLineStart`,
    /// and a JSON decode failure, all still surface here exactly as they would
    /// from `replayFrom` itself.
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

    /// The offset right after the header line's newline, where the first event, if
    /// any, begins. `open` already proved a well formed header is present, so this
    /// only needs to find where it ends.
    fn headerEnd(self: *const Log, io: std.Io) LogError!u64 {
        var buffer: [max_header_bytes]u8 = undefined;
        const filled = self.file.readPositionalAll(io, &buffer, 0) catch return error.Unexpected;
        const newline = std.mem.indexOfScalar(u8, buffer[0..filled], '\n') orelse return error.BadHeader;
        return newline + 1;
    }
};

/// The proof that this process holds the exclusive lock on a `Log`. This type is
/// not `pub`, so no file outside this one can write out `log.Locked{ ... }` by
/// naming the type directly. That stops the ordinary mistake: a caller cannot
/// build one by hand without first getting past `Log.lock`.
///
/// It does not stop every route. An earlier version of this file made `Locked`
/// `pub` with public fields and claimed the type system closed this off
/// entirely. It did not hold: any file could write `log.Locked{ .log = &some_log
/// }` and call `append` on it without ever calling `lock`, because Zig has no per
/// field access control, only per file. Marking a field `pub` or leaving it bare
/// makes no difference, so that version was fixed by making the type itself
/// unnamed outside this file. A second version, this one, then shipped the same
/// overstated claim about the fix: Zig still lets a caller build a value of a
/// type it cannot name, by reaching it through `@TypeOf` on a value this file
/// already returned, or through a comptime reflection built from that, and
/// either one still compiles a struct literal for `Locked` outside this file.
/// The file boundary stops naming the type. It does not stop constructing it.
///
/// `generation` is what actually closes this at run time. `Log.lock` stamps
/// every `Locked` it hands out with the value its own `lock_generation` counter
/// held at that moment, see `Log.lock_generation`, and `append` below refuses to
/// run unless the handle's stamp still matches the log's own counter. A forged
/// handle that never went through a real `lock` call carries whatever value its
/// author guessed or left at its type's default, and a real `lock` call already
/// having run on this `Log` means the counter has moved past that. This is a
/// plain `if`, never `std.debug.assert`, because an assert is stripped in
/// `ReleaseFast` and a check that only exists in some build modes is the reason
/// this hole survived two earlier passes at closing it. See `error.NotLocked`
/// and `storage.Locked` for the same fix applied to the vtable based handle the
/// `Storage` interface hands out.
///
/// `unlock` spends this handle a second way: it sets `held` false, and Zig has
/// no way to forbid using a value again after one of its own methods consumes
/// it. `held` catches a caller that keeps a `Locked` around past its own
/// `unlock` call and calls `append` on it again, the same run time check as
/// `generation`, checked for the same reason.
const Locked = struct {
    /// The log this handle holds the lock on. Never null: a `Locked` only exists
    /// because `Log.lock` already succeeded on this pointer.
    log: *Log,
    /// The value `log.lock_generation` held at the moment the `lock` call that
    /// produced this handle ran. `append` refuses to run unless this still
    /// matches `log.lock_generation`, which is what tells a genuine handle apart
    /// from one built without ever calling `lock`. See this struct's own doc
    /// comment and `Log.lock_generation`.
    generation: u64,
    /// False once `unlock` has run. Checked by `append`, not asserted, because a
    /// caller reusing a spent handle must be refused in every build mode, the same
    /// guarantee this whole type exists to give for the "never locked at all" case.
    held: bool = true,

    /// Release the lock this handle represents. This is the other half of a
    /// `/daemonize` handover: the process giving up the session calls this, and the
    /// new owner then calls `Log.lock` and replays the file from the start. Safe to
    /// call more than once. `File.unlock` on a file description with no lock held is
    /// a harmless no-op at the kernel level, and a second call here just leaves
    /// `held` false, which it already was.
    ///
    /// `File.unlock` returns `void`, not an error union: unlike the old direct
    /// `flock(LOCK_UN)` call, `std.Io` gives this call no way to fail, so this
    /// function keeps returning `LogError!void` only so every existing caller's
    /// `try locked.unlock(...)` keeps compiling. It never actually produces an
    /// error.
    pub fn unlock(self: *Locked, io: std.Io) LogError!void {
        std.debug.assert(self.log.file.handle != -1);
        self.log.file.unlock(io);
        self.held = false;
    }

    /// Append one event and return the byte offset of the line it wrote. That offset is
    /// the event's identifier for the rest of Chock: a client that reconnects sends the
    /// last one it saw, and the server seeks to it. The envelope this writes always
    /// carries `id = 0` on disk, so a reader must set `id` from the seek offset before
    /// it passes the envelope on.
    ///
    /// The caller gives `time_ms`. This function never reads the clock, so every test
    /// that calls it is deterministic.
    ///
    /// Only reachable through a `Locked` value, and an ordinary caller gets one of
    /// those only from a successful `Log.lock`. A caller willing to construct a
    /// `Locked` by reflection instead, see `Locked`'s own doc comment, does not go
    /// through `lock` and so cannot supply a `generation` that matches the log's
    /// own counter, which this checks below and refuses with `error.NotLocked`
    /// when it disagrees. That check, not the type system, is what makes the
    /// offset this returns trustworthy: this process really is the sole writer
    /// while a genuine `Locked` for the current generation exists.
    pub fn append(self: *Locked, allocator: std.mem.Allocator, io: std.Io, ev: event.Event, time_ms: i64) LogError!u64 {
        const log = self.log;

        // Calling append after close is our own bug, not a runtime fault: close
        // invalidates the handle precisely so a use after close is caught here
        // instead of silently touching whatever descriptor the kernel reused.
        std.debug.assert(log.file.handle != -1);
        // A handle whose `generation` does not match the log's current
        // `lock_generation` never came from a real `lock` call on this log, or is
        // one that did but has since been superseded by another. Either way this
        // process holding onto it is not proof of anything. A real `if`, checked
        // in every build mode: see `Locked`'s own doc comment for why an assert
        // here would not have caught the forgery a reviewer demonstrated.
        if (self.generation != log.lock_generation) return error.NotLocked;
        // A handle whose unlock already ran must not be able to append again, and this
        // must hold in every build mode: silently handing back an offset here is the
        // exact bug this file exists to close, so this is a real branch, not an
        // assert that a fast build would strip.
        if (!self.held) return error.NotLocked;

        // `tail_was_torn` and `torn_tail_at` are facts this particular `Log` cached
        // at `open`. Neither is evidence about the file now: a second `Log` on the
        // same path, the shape a /daemonize handover takes, can have appended
        // through its own handle since this handle's `open` ran, clearing the old
        // tear, writing new events, and even leaving a fresh tear of its own at a
        // different offset. Gating this check on the cached flag would miss a tear
        // that appeared after this handle's own `open` found none. Cutting to the
        // cached offset would miss the real fragment's current start and destroy
        // committed events sitting between the old offset and the new one instead.
        // So every append asks the file itself, both whether a tear exists and
        // where it starts, and never trusts what `open` recorded for either fact.
        if (try log.tailIsTorn(io)) |size| {
            // A fragment is a line whose closing newline never arrived. `sync` only
            // ever runs after the write it follows, so a line missing that newline
            // was never made durable. Nothing this cuts away was ever committed.
            // Cutting it now, right before this append's own write, means a fresh
            // line starts where the fragment did instead of gluing onto its tail.
            const cut_at = try log.findTornFragmentStart(io, size);
            log.file.setLength(io, cut_at) catch return error.Unexpected;
        }
        log.tail_was_torn = false;

        // The hash of whatever line really is last, read now, after any
        // fragment above was cut away and before this line goes on the end.
        // **Read, not remembered**: see `lastLineDigest`. A fragment that was
        // cut is never hashed, and it never was an event: the log calls `sync`
        // only after a whole line reached the kernel, so nothing inside a
        // fragment was ever durable.
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

        // The line and its trailing newline must reach the kernel in one write call, so
        // they are built into one buffer first. Two separate writes could interleave
        // with a crash between them and leave a line with no newline, which a replay
        // could not tell apart from a genuine partial write.
        const line = try std.fmt.allocPrint(allocator, "{s}\n", .{text});
        defer allocator.free(line);

        // The file is opened with O_APPEND, so the write itself always lands at the
        // true end of file no matter what this offset says. Querying it here only
        // gives the right answer because this log has one writer, and holding this
        // `Locked` handle is what makes that true rather than merely assumed: the lock
        // it represents is what keeps every other process from growing the file
        // between this query and the write below.
        const offset = log.file.length(io) catch return error.Unexpected;

        try log.writeExact(io, line);

        // A session log that records an approval must survive a power loss, because
        // the whole approval model rests on the record. This is deliberately not
        // batched or skipped: `sync` runs on every append, even though it is slow. A
        // later milestone may relax it for an event that does not change a decision,
        // but only once a measurement shows what that costs, not before.
        log.file.sync(io) catch return error.SyncFailed;

        return offset;
    }
};

/// Walks a log forward, one line at a time, from the offset `Log.replayFrom` was
/// given. Holds a scratch buffer that `next` reuses line to line. Call `deinit`
/// once done to free it.
pub const Replay = struct {
    file: std.Io.File,
    allocator: std.mem.Allocator,
    /// The byte offset of the next line to read.
    pos: u64,
    /// Scratch space for the line `next` is currently assembling. Cleared, not
    /// freed, between calls so repeated reads do not reallocate every time.
    buffer: std.ArrayList(u8) = .empty,
    /// True after the most recent call to `next` found the file ending mid line:
    /// bytes were read but no closing newline ever showed up before EOF. This is
    /// the same write-was-interrupted case `Log.open` detects as `tail_was_torn`.
    /// This reflects only the last call, not every call before it: an owner can
    /// append past the tear between two calls to `next`, the way a daemon does
    /// right after it restarts, and the tear that call reports would then be
    /// stale. The next call to `next` reads the file again and clears this if the
    /// tear is gone, so a caller must read `truncated` right after each `next`
    /// that returns null, not remember an old value from an earlier call.
    truncated: bool = false,
    /// The offset where the truncated line began. Meaningless unless `truncated`.
    truncated_at: u64 = 0,

    pub fn deinit(self: *Replay) void {
        self.buffer.deinit(self.allocator);
    }

    /// The bytes of the line the last `next` returned an envelope for, without
    /// its closing newline, exactly as they sit on disk.
    ///
    /// **Only meaningful right after a `next` that gave back an envelope.**
    /// `next` clears this buffer before it reads, so a call after a null, or
    /// after a second `next`, reads other bytes or none.
    ///
    /// This exists so a verifier hashes the bytes the writer hashed. Encoding
    /// the parsed envelope again would compare this reader's JSON against the
    /// writer's, and one difference in key order, in the form of a number, or
    /// in the escape of a character would then read as tampering. See
    /// `lib/chock-proto/chain.zig`.
    pub fn line(self: *const Replay) []const u8 {
        return self.buffer.items;
    }

    /// Give back the next envelope, or null once the log is exhausted. The `id` on
    /// the envelope this returns is the offset its line started at, never the zero
    /// `append` wrote to disk. That offset is the identifier the rest of Chock uses.
    ///
    /// Null means one of two different things, told apart by `truncated`: the file
    /// ended exactly on a newline, a complete replay, or it ended partway through a
    /// line, a tear reported through `truncated` and `truncated_at`. A tear is never
    /// an error, because a crash mid write must not make the session unreadable. A
    /// complete line that fails to parse as JSON is a third, distinct fact,
    /// corruption rather than a tear, and that one is returned as an error.
    ///
    /// A tear found on one call is not the end of this `Replay`: `pos` still sits
    /// at the start of the torn line, unmoved, so a later call reads that same spot
    /// again. If an owner has since appended past the tear, this call reads a real,
    /// complete line there instead and returns it, with `truncated` cleared. A
    /// caller that wants to notice the log growing again, for example a live tail
    /// across a daemon restart, keeps calling `next` instead of stopping the first
    /// time it sees `truncated`.
    pub fn next(self: *Replay, io: std.Io) (LogError || event.DecodeError)!?std.json.Parsed(event.Envelope) {
        self.buffer.clearRetainingCapacity();
        const line_start = self.pos;
        var read_buffer: [4096]u8 = undefined;
        var saw_any_bytes = false;

        while (true) {
            const n = self.file.readPositionalAll(io, &read_buffer, self.pos) catch return error.Unexpected;

            if (n == 0) {
                // EOF exactly where the last line ended is a complete replay. EOF
                // after some bytes with no newline in them is a tear: a write
                // reached the kernel but the closing newline never followed.
                if (!saw_any_bytes) {
                    self.truncated = false;
                    return null;
                }
                self.truncated = true;
                self.truncated_at = line_start;
                // The loop below already moved `pos` past the fragment bytes it
                // read while still hoping to find a newline. Put it back at the
                // line's start: a later call must re-read the fragment's own
                // bytes from the beginning, not from wherever this call gave up,
                // so it notices a real line there once an owner appends past
                // the tear and cuts the fragment away.
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

/// Parse the digits of a JSON number, the way `ensureHeader` needs it: unsigned,
/// base 10, no leading `+`, and no leading zero on a value with more than one digit.
/// `std.fmt.parseInt` alone accepts `+1` and `01` as 1, and JSON does not, so a
/// corrupt header naming either would silently pass as version 1 without this check.
fn parseVersionNumber(text: []const u8) ?u32 {
    if (text.len == 0) return null;
    for (text) |c| {
        if (c < '0' or c > '9') return null;
    }
    if (text.len > 1 and text[0] == '0') return null;
    return std.fmt.parseInt(u32, text, 10) catch null;
}

/// The one way `absoluteDirPath` can fail: `std.Io.Dir.realPath` on `dir` returned
/// an error, which only happens for a handle this process does not actually have
/// open.
pub const AbsoluteDirPathError = error{RealPathFailed};

/// Read the absolute path of an already open directory, through `std.Io.Dir.realPath`.
/// `std.testing.tmpDir` hands back a directory reached only through a relative path,
/// but a test needs an absolute one to build a path it can pass to `Log.open` that
/// does not depend on the test binary's own working directory.
///
/// This used to read `/proc/self/fd/<dir_fd>` by hand, which only exists on Linux.
/// `std.Io.Dir.realPath` covers the same need portably: on Linux it still reads
/// `/proc/self/fd`, and on Darwin it uses `fcntl(F_GETPATH)`, so this function needs
/// no platform branch of its own.
///
/// Nothing outside a test block calls this: it stays `pub` only because
/// `test/proto/lock.zig` is a separate test binary that reaches this package
/// through `chock-proto`'s own public surface rather than by being compiled into
/// this file. `state.zig`, `storage.zig`, and `test/proto/lock.zig` all reuse this
/// same function instead of each keeping their own copy. Two more copies, of the
/// same name, live in `lib/chock-sandbox/Sandbox.zig` and `test/sandbox/escape.zig`.
/// Neither can become a caller of this one: `chock-sandbox`, and its own tests,
/// stay free of any dependency on `chock-proto`.
pub fn absoluteDirPath(io: std.Io, buffer: []u8, dir: std.Io.Dir) AbsoluteDirPathError![:0]u8 {
    const len = dir.realPath(io, buffer) catch return error.RealPathFailed;
    buffer[len] = 0;
    return buffer[0..len :0];
}

/// A `Log` over a fresh file under a per-test temporary directory, closed and removed
/// on `deinit`. `std.testing.tmpDir` gives every call its own randomly named
/// subdirectory under `.zig-cache/tmp`, so two test runs at once never fight over one
/// name even though every test in this file passes a plain, repeated `name`.
const TestLog = struct {
    tmp: std.testing.TmpDir,
    log: Log,
    /// Owns the path text `log` was opened with, so `reopen` can open it again. A
    /// slice into a local buffer from `init` would dangle once `init` returned, so
    /// this buffer lives on the `TestLog` value itself instead.
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
        // Every test in this file that appends through a TestLog stands in for the
        // one process that owns the session, so it takes the lock right away, the
        // same as a real caller must before its first append. The handle this returns
        // is discarded on purpose: it points at `self.log`, and `self` is a local
        // variable that `init` is about to return by value, so keeping the handle past
        // this line would leave it pointing at a copy that no longer exists. `append`
        // below takes a fresh handle every time instead, which is always safe once the
        // kernel already holds this file description's lock.
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

    /// Append one event through a freshly taken handle. Re-locking here is harmless:
    /// the kernel already holds this file description's exclusive lock from `init` or
    /// `reopen`, and taking the same lock again on the same description just reaffirms
    /// it. This is what lets every test below call `tmp.append(...)` without keeping a
    /// `Locked` value alive across the return of `init`, which would otherwise point at
    /// a `Log` that has since moved.
    fn append(self: *TestLog, allocator: std.mem.Allocator, ev: event.Event, time_ms: i64) !u64 {
        var locked = try self.log.lock(std.testing.io);
        return locked.append(allocator, std.testing.io, ev, time_ms);
    }

    /// Close and reopen the same file, standing in for a `chockd` restart. Confirms
    /// that closing and reopening a log does not disturb offsets already handed out.
    /// Closing released the old lock, so this takes it again, the same as a real
    /// restart must before it appends anything more.
    fn reopen(self: *TestLog) !void {
        self.log.close(std.testing.io);
        self.log = try Log.open(std.testing.io, self.path(), "01TESTSESSION");
        _ = try self.log.lock(std.testing.io);
    }

    /// Read the whole file from its start, regardless of wherever the log's own file
    /// position happens to sit from opening it or appending to it. A positional read
    /// needs no seek first: it names its own offset.
    fn readAll(self: *TestLog, allocator: std.mem.Allocator) ![]u8 {
        const size = self.log.file.length(std.testing.io) catch return error.Unexpected;
        const bytes = try allocator.alloc(u8, size);
        errdefer allocator.free(bytes);
        const n = self.log.file.readPositionalAll(std.testing.io, bytes, 0) catch return error.Unexpected;
        return bytes[0..n];
    }

    /// Cut the file to `len` bytes, standing in for a crash that stopped a write
    /// partway through a line: the bytes up to `len` stay, everything past them is
    /// gone, and no trailing newline is added back.
    fn truncateTo(self: *TestLog, len: u64) !void {
        self.log.file.setLength(std.testing.io, len) catch return error.Unexpected;
    }
};

/// Where the pieces of a file `seedTornLog` writes begin.
const TornLogOffsets = struct {
    /// The offset of the one complete event line before the fragment.
    before_offset: u64,
    /// The offset where the torn fragment itself begins.
    fragment_offset: u64,
};

/// Write a fresh file at `path` directly, bypassing `Log.open`, with a good header,
/// one complete event line, and then a fragment with no closing newline: the shape
/// an append that reached the kernel but never got to write its trailing newline
/// leaves behind. Every test for the torn-tail fix in `open` and `append` starts
/// from this same file, since that fix must be provable from the raw bytes on
/// disk, not from a state only `Log` itself can produce.
///
/// This writes through `std.Io.Dir.createFileAbsolute` and `File.writeStreamingAll`,
/// which loop internally until every byte lands or a write fails outright. That
/// looping is exactly what `Log.writeExact` itself must never do, see that
/// function's own comment, but this helper is deliberately not `Log.writeExact`: it
/// is scaffolding that builds a file shape for a test, not the code under test, so
/// there is no torn-write invariant here to protect.
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

    // The fragment's own bytes do not need to be valid JSON, complete or
    // otherwise: a tear is reported by its missing newline alone, and the bytes
    // past it are never parsed.
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

    // The first event starts after the header line, and the second starts exactly one
    // line after the first. An offset is the identifier, so this is the whole contract.
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

    // The payload holds a newline. The line must not: std.json escapes it inside the
    // JSON string, so the only two raw newlines here are the header's and this line's.
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

    // Write a header claiming a format version far ahead of what this build knows,
    // standing in for a log a future Chock wrote in a format this build cannot read.
    {
        var log = try Log.open(io, path, "01TESTSESSION");
        defer log.close(io);
    }
    // Overwrite the header this build just wrote with one naming an unknown version.
    {
        var file = try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, "{\"chock_log\":999}\n");
    }

    try std.testing.expectError(error.BadHeader, Log.open(io, path, "01TESTSESSION"));
}

test "regression: a header naming a version with a leading zero or a leading plus is not accepted as version 1" {
    // std.fmt.parseInt alone reads "01" and "+1" as the integer 1, but JSON's own
    // number grammar allows neither a leading zero on a multi digit number nor a
    // leading plus sign. A corrupt header should not silently pass as a well formed
    // version 1 header just because Zig's integer parser is more permissive than
    // JSON is.
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

    // The fix invalidates the handle on the first close. Assert that directly
    // instead of trying to force a real descriptor collision, which would be flaky
    // by nature. deinit's own close, right after this one, is the second close that
    // must stay harmless.
    tmp.log.close(std.testing.io);
    try std.testing.expectEqual(@as(std.posix.fd_t, -1), tmp.log.file.handle);
}

/// Payloads chosen because each can move a byte offset in a way a plain ASCII
/// payload never would: a multi-byte UTF-8 character, an astral code point, a quote
/// and a backslash that JSON must escape, and a raw newline that JSON must turn into
/// the two characters `\` and `n` inside the string.
const offset_contract_payloads = [_][]const u8{
    "héllo wörld",
    "🎉 party",
    "she said \"hi\"",
    "a\\b",
    "line one\nline two",
};

/// Confirm one fact about one line in `bytes`, starting at `offset`: the byte before
/// it is the newline that ends the previous line, the byte at it opens the JSON
/// object, and the line itself parses back to `expected_text`. This is the whole
/// offset contract `append` promises, checked the way a real reconnect would use it:
/// seek to the offset, read from there, and trust what comes out.
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

    // A reconnect can arrive long after the process that wrote these events is
    // gone. Closing and reopening stands in for that restart.
    try tmp.reopen();

    const bytes = try tmp.readAll(allocator);
    defer allocator.free(bytes);
    for (offset_contract_payloads, 0..) |text, i| {
        try expectEventLineAt(allocator, bytes, offsets[i], text);
    }
}

test "a write that lands short at the kernel is reported as ShortWrite, never retried or silently accepted" {
    // A nonblocking pipe reproduces a short write on demand: writes of more than
    // PIPE_BUF (4096 bytes on Linux) lose their atomicity guarantee, so a write
    // bigger than both PIPE_BUF and the pipe's own capacity makes the kernel accept
    // only as many bytes as fit and return that count, the same shape a full disk
    // or an interrupted write leaves behind. This calls writeExact directly rather
    // than through append, because append also queries the file's length and syncs
    // it, and neither one makes sense on a pipe.
    //
    // The pipe itself comes from chock_io.default(), not a raw `linux.pipe2` call
    // in this file: see lib/chock-io.zig's own top comment. Close-on-exec is not
    // what this test needs, but it is harmless here, and using the same module
    // every other pipe in this codebase goes through beats a second, private
    // creation path that could drift from it. Nonblocking mode, and reading the
    // pipe's own current capacity, are the two things chock_io does not offer, on
    // purpose: neither is a primitive production Chock needs, only this one test
    // does, so both live in ./short_write_probe.zig instead of growing chock-io
    // a third and fourth function. See that file's own top comment. The
    // mechanism this test proves, a short write reported rather than silently
    // completed with a second write, is itself platform independent, and is
    // exercised on every target through writeExact's own use in append. The way
    // this test reproduces one is not portable, so it sits behind a driver:
    // Linux reads the pipe size from the kernel, and Darwin, which has no call
    // for it, names a bound instead.
    const chock_io_driver = chock_io.default();
    const raw_pipe = try chock_io_driver.pipeCloseOnExec();
    defer std.Io.File.close(.{ .handle = raw_pipe.read_fd, .flags = .{ .nonblocking = false } }, std.testing.io);
    defer std.Io.File.close(.{ .handle = raw_pipe.write_fd, .flags = .{ .nonblocking = false } }, std.testing.io);
    try short_write_probe.setNonblocking(raw_pipe.write_fd);

    // A count above this pipe's own buffer, so one write cannot be taken in
    // full. Linux reads the exact size and adds a page. Darwin has no call for
    // the size and answers with a bound far above the largest pipe macOS
    // makes. Either way a count that was somehow too small would fail this
    // test on the missing error below, never pass it: see `overCapacity`.
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
    // Reproduces the bug a reviewer found: seed a file with a good header and half
    // of an event line, the shape a write that reached the kernel but never got its
    // closing newline leaves behind, then open it and append a real event. Before
    // the fix, the new event's bytes landed glued onto the fragment with no
    // newline between them, so a sequential reader hit one unparseable merged line
    // and never reached anything appended after it.
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

    // open must not refuse a torn log, since a crash must not make a whole session
    // unreadable, but it must say the tail was torn so the caller can decide what to
    // tell the user about the event that may have been lost.
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
    // Pins the actual bug: the only path a real caller takes is open, then
    // replay, with nothing in between. Before the fix, open sealed the torn
    // fragment with a newline of its own, so by the time replay ran, the
    // fragment looked like one complete line that was not valid JSON. Replay
    // threw a decode error and `truncated` stayed false, exactly the shape a
    // daemon restart, a /daemonize handover, or a reconnecting client would
    // hit on any session log that crashed mid write.
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

    // No decode error: the second call finds the fragment, reports it as a
    // tear, and returns null rather than throwing.
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

    // The new line starts exactly where the fragment used to start: the
    // fragment is gone, not merely followed by a second, glued-on line.
    try std.testing.expectEqual(seed.fragment_offset, offset);
    try std.testing.expect(!log.tail_was_torn);

    const size = log.file.length(io) catch return error.Unexpected;
    const read_buffer = try allocator.alloc(u8, size);
    defer allocator.free(read_buffer);
    const n = log.file.readPositionalAll(io, read_buffer, 0) catch return error.Unexpected;
    const bytes = read_buffer[0..n];

    try expectEventLineAt(allocator, bytes, offset, "after the tear");
    // Nothing follows the new line: no fragment byte survived the cut.
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
    // The fragment is gone, so there is nothing left to report as torn.
    try std.testing.expect(!replay.truncated);
}

test "regression: a stale torn tail flag on a second handle does not destroy what the first handle wrote" {
    // Reproduces the /daemonize handover a reviewer found broken: two `Log`
    // handles open on the same crashed file both cache `tail_was_torn` at
    // `open`. Before the fix, whichever handle appended second trusted its own
    // stale flag and truncated the file back to the fragment's old start,
    // destroying every event the first handle had already written and had
    // unlocked for the second to take over. A /daemonize must lose no event.
    // This is that sequence, run directly against two `Log` values instead of
    // two processes, since flock already treats two `open` calls on one path as
    // two real contenders.
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/handover-stale-tear", .{dir_path});

    const allocator = std.testing.allocator;
    _ = try seedTornLog(io, path);

    // Owner A and owner B both open the crashed file before either one
    // appends, the same order a real handover reaches when a client attaches
    // to a daemon that already has its own handle open. Both cache the same
    // torn tail fact.
    var owner_a = try Log.open(io, path, "01TESTSESSION");
    defer owner_a.close(io);
    try std.testing.expect(owner_a.tail_was_torn);
    var owner_b = try Log.open(io, path, "01TESTSESSION");
    defer owner_b.close(io);
    try std.testing.expect(owner_b.tail_was_torn);

    // Owner A holds the session first: it locks, appends several events, the
    // first of which clears the fragment and A's own copy of the flag, then
    // hands the session off by unlocking.
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

    // Owner B takes over, the way `/daemonize` moves ownership, and appends.
    // B's own `tail_was_torn` is still true here: it never touched it. Before
    // the fix this alone was enough to truncate the file back to the
    // fragment's original offset, taking every one of A's events with it.
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
    // Reproduces the second bug a reviewer found in the same fix that produced the
    // test above: append re-checked whether a tear exists now, correctly, but still
    // cut the file back to the offset its own `open` had cached, which is stale.
    // Handle B opens the file while it is clean. Owner A, on its own handle, then
    // appends ten events and crashes mid an eleventh write, leaving a real tear
    // well past where B's file was when B opened it. B's cached offset points at
    // the start of the file, not at A's fresh fragment, so cutting there destroyed
    // every one of A's ten events instead of just the fragment. The fix finds the
    // fragment's start fresh, from the file as it is now, every time.
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/handover-fresh-tear", .{dir_path});

    const allocator = std.testing.allocator;

    // B opens first, on a file with nothing on it yet but the header. Its own
    // `tail_was_torn` is false: there is no tear to find at this moment.
    var owner_b = try Log.open(io, path, "01TESTSESSION");
    defer owner_b.close(io);
    try std.testing.expect(!owner_b.tail_was_torn);

    // A opens second and becomes the owner: it locks, appends ten events, each one
    // synced by `append` itself, then "crashes" partway through an eleventh write,
    // the shape a real interrupted write leaves on disk.
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
    // Closing stands in for the crash itself: a killed process leaves exactly this
    // shape on disk, and closing here releases A's lock the same way the kernel
    // would on process exit, which is what lets B take over next.
    owner_a.close(io);

    // B, still holding the handle it opened before any of this happened, takes
    // over and appends. Its own cached fields are unchanged from its own `open`,
    // stale by construction, and must not be trusted for where to cut.
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
    // All ten of A's committed events survive, plus B's own: nothing collapsed
    // eleven committed writes down to two the way the stale offset did.
    try std.testing.expectEqual(@as(usize, 11), i);
    try std.testing.expect(!replay.truncated);
}

test "regression: a tear that appears after this handle's own open is still found and cut" {
    // The route the earlier fix missed: this handle's `tail_was_torn` was false at
    // `open`, because the file had no tear yet. A tear then appears, from this same
    // handle's own next write being interrupted between the kernel accepting the
    // bytes and the newline that would have closed the line. Before this fix,
    // `append` used the cached flag to decide whether to even look, so a tear that
    // showed up after `open` was never found, and the fragment's bytes stayed on
    // disk, glued onto whatever `append` wrote next.
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
    // `log.tail_was_torn` is still false here: nothing re-evaluates it between
    // calls. A fragment now lands directly on the file, standing in for a write
    // this same process started and never finished before a crash.
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
    // Reproduces the second bug a reviewer found: a `Replay` that hits a torn
    // tail used to latch `truncated` forever, returning null from every later
    // call even after an owner appended past the tear. Stands in for a daemon
    // restarting after a crash while a client's live tail is already reading:
    // the client's first read of the tear must not be its last.
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

    // The tear, reported once. On a clean log this is what a fully caught up
    // reader would also see, so `truncated` is the only thing that says a
    // crash happened here.
    try std.testing.expect((try replay.next(io)) == null);
    try std.testing.expect(replay.truncated);

    // The daemon restarts, on its own `Log` handle, and appends the next
    // turn. This clears the tear on disk the same way any append does.
    var writer = try Log.open(io, path, "01TESTSESSION");
    defer writer.close(io);
    var locked = try writer.lock(io);
    _ = try locked.append(
        allocator,
        io,
        .{ .message = .{ .role = .user, .content = &.{.{ .text = "after restart" }} } },
        2,
    );

    // The same `Replay`, called again: it must not still be latched. It reads
    // the same spot again, finds a real line there now, and hands it back
    // with `truncated` cleared.
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
        // The identifier a reader sees is the seek offset, never the zero append
        // wrote to disk: that offset is what a reconnect sends back as Last-Event-ID.
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

    // `replayFrom` is the offset based entry point: it starts inclusive of the
    // exact byte it is given, an internal caller's own concern, not a
    // client's Last-Event-ID. See `resumeAfter` below for that case.
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
    // Pins the bug a reviewer found: folding a resume on top of a full replay
    // produced 3 context entries for a 2 event log, because the resume handed
    // back the client's own last event a second time. `resumeAfter` must skip
    // the named event and start with whatever comes after it.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("resume-after-skips-named-event");
    defer tmp.deinit();

    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);
    const second = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "two" }} } }, 2);
    const third = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "three" }} } }, 3);

    // A client whose Last-Event-ID is `second` already has "one" and "two". A
    // resume must start at "three", not repeat "two".
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
    // A client that is fully caught up, whose Last-Event-ID names the very
    // last event on disk, must see an empty resume, the same as a client that
    // reconnects to a log nothing has been appended to since.
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
    // 0 is the id a client with no prior event sends, the same value
    // `replayFrom` already treats as a full replay. There is no earlier event
    // to skip past in that case, so resumeAfter must not try.
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
    // Cut the last line in half, the way a crash during a write leaves it.
    try tmp.truncateTo(second + 5);

    var replay = try tmp.log.replayFrom(allocator, io, 0);
    defer replay.deinit();

    var count: usize = 0;
    while (try replay.next(io)) |envelope| {
        defer envelope.deinit();
        count += 1;
    }
    // The whole event survives. The half written one does not, and the caller is told.
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expect(replay.truncated);
    try std.testing.expectEqual(second, replay.truncated_at);
}

test "replay refuses an offset past the end of the file instead of returning an empty stream" {
    // A caught up caller and a caller with a wrong offset both see nothing
    // from a naive replay, and only this error tells them apart. The offset
    // usually arrives as a client's Last-Event-ID, so it cannot be trusted
    // just because it is a plausible looking number.
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

    // One byte into a real line is still within the file, but it is not
    // where any event begins, so this must be told apart from a good offset.
    try std.testing.expectError(error.OffsetNotLineStart, tmp.log.replayFrom(allocator, io, offset + 1));
}

// A third test, "a second process cannot take the lock while the first holds it",
// lives in test/proto/lock.zig instead of here. flock locks an open file description,
// not a path and not a process: two Log values in this same test binary, each from its
// own open call, would already be two separate descriptions and would already contend
// for real. That would not tell apart a genuine second process from a second open in
// the same process, and the property /daemonize depends on is specifically that a
// second process cannot take a session another process owns. Proving that needs an
// actual second process, so that test spawns one, the same way test/sandbox/escape.zig
// spawns test/sandbox/probe.zig. See build.zig for how its path reaches the test.

test "the lock is free again once the holder closes the log" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try absoluteDirPath(io, &dir_path_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/lock-release-on-close", .{dir_path});

    // Two independent open calls on the same path each get their own open file
    // description, so the lock treats them as two real contenders, the same shape a
    // second process opening this path would be. This is the handover /daemonize
    // needs: the current owner holds the lock, and nobody else can take it while
    // that description stays open.
    var first = try Log.open(io, path, "01TESTSESSION");
    _ = try first.lock(io);

    var second = try Log.open(io, path, "01TESTSESSION");
    try std.testing.expectError(error.Busy, second.lock(io));

    // Closing the first releases its lock at the kernel level: this is the client
    // side of a /daemonize handover. The second can now take the lock the first
    // used to hold.
    first.close(io);
    _ = try second.lock(io);
    second.close(io);
}

test "taking the lock does not change the contents of the log" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("lock-is-not-a-write");
    defer tmp.deinit();

    // TestLog.init already took the lock as part of opening. Write one real event so
    // there is content worth pinning, then read the file back before touching the
    // lock again.
    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "before" }} } }, 1);
    const before = try tmp.readAll(allocator);
    defer allocator.free(before);

    // Release and retake the lock through a fresh handle each time. Neither lock
    // call writes a byte to the file. Only append and the header write in
    // ensureHeader ever do that.
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

    // The handle is spent: unlock already ran, so holding it is no longer proof that
    // this process owns the session. append must refuse it rather than hand back an
    // offset another process might now also be handing out.
    try std.testing.expectError(
        error.NotLocked,
        locked.append(allocator, io, .{ .message = .{ .role = .user, .content = &.{.{ .text = "too late" }} } }, 1),
    );
}

test "regression: a handle whose generation does not match the log's own is refused, not merely one whose held flag is false" {
    // Pins the fix for the third route a reviewer found: `Locked` cannot be
    // named outside this file, but Zig still lets a caller build a value of a
    // type it cannot name, through @TypeOf on a value this file already
    // returned, or a comptime reflection built from that. A reviewer did this
    // in a scratch program outside the repository and reached `append` with no
    // lock of their own ever taken, because the only check left at the time was
    // `held`, and `held` defaults to `true` on a freshly built struct literal
    // whether or not `lock` ever ran. `generation` is the check that catches
    // that: a handle built this way is left at its type's default, 0, and a
    // real `lock` call on this log has already moved `lock_generation` past
    // that by the time any test could reach this point. This test builds the
    // struct directly instead of through reflection, since this test lives
    // inside the one file that can still name `Locked`, but it exercises the
    // exact runtime comparison the reflection route depends on: delete that
    // comparison, or mark `Locked` `pub` again without it, and this is the
    // test that fails.
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

/// The lines of a log's raw bytes, without the newlines that close them. The
/// header is the first, and every event follows it in file order.
fn linesOf(allocator: std.mem.Allocator, bytes: []const u8) ![][]const u8 {
    var found: std.ArrayList([]const u8) = .empty;
    errdefer found.deinit(allocator);
    var walker = std.mem.splitScalar(u8, bytes, '\n');
    while (walker.next()) |one| {
        // The last piece of a file that ends in a newline is empty and is not
        // a line. No real line of this format is empty: every one of them is
        // at least an opening and a closing brace.
        if (one.len == 0) continue;
        try found.append(allocator, one);
    }
    return found.toOwnedSlice(allocator);
}

/// The `prev` field of one event line.
fn prevOf(allocator: std.mem.Allocator, line: []const u8) ![]u8 {
    const parsed = try event.fromJson(allocator, line);
    defer parsed.deinit();
    return allocator.dupe(u8, parsed.value.prev);
}

test "the first event carries the header line's hash and each one after carries the line before it" {
    // The whole write side of the chain, read back out of the bytes on disk
    // rather than out of anything `Log` remembers. The first event names the
    // header, so the chain is anchored rather than starting in the air, and a
    // header somebody swapped is found at the first event.
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

    // And no two of them are the same digest, which is what would happen if
    // `append` hashed something fixed, the session identifier for instance,
    // instead of the line in front of it.
    const first = try prevOf(allocator, lines[1]);
    defer allocator.free(first);
    const second = try prevOf(allocator, lines[2]);
    defer allocator.free(second);
    try std.testing.expect(!std.mem.eql(u8, first, second));
}

test "an append after a torn tail chains onto the last whole line, never onto the fragment" {
    // The one place a crash and the chain meet. `append` cuts a fragment away
    // before it writes, and the line it writes must then name the last whole
    // line, which is the event before the fragment. Hashing the file as it
    // stood before the cut would chain onto bytes that are about to stop
    // existing, and every later reading would call that an edit.
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
    // The fragment was cut, so the new line starts exactly where it did.
    try std.testing.expectEqual(seeded.fragment_offset, written);

    const size = try log.file.length(io);
    const bytes = try allocator.alloc(u8, size);
    defer allocator.free(bytes);
    _ = try log.file.readPositionalAll(io, bytes, 0);
    const lines = try linesOf(allocator, bytes);
    defer allocator.free(lines);
    // Header, the one event that survived, and the new one. The fragment is
    // gone rather than glued to anything.
    try std.testing.expectEqual(@as(usize, 3), lines.len);

    const prev = try prevOf(allocator, lines[2]);
    defer allocator.free(prev);
    try std.testing.expectEqualStrings(&chain.of(lines[1]), prev);
    // And explicitly not the fragment's own bytes, which is the answer a
    // version that hashed the file before the cut would have written.
    try std.testing.expect(!std.mem.eql(u8, prev, &chain.of("{\"id\":0,\"session\":\"01TE")));
}

test "a second handle chains onto what the first one wrote, not onto what it last saw itself" {
    // A `/daemonize` handover is two `Log` values over one path, and the new
    // owner opened its handle before the old owner finished writing. A chain
    // built from anything a handle remembered at `open` would name a line that
    // is no longer last, so `append` reads the file every time. This is the
    // same reason `append` re-reads the torn tail rather than trusting the
    // flag `open` cached.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("chain-handover");
    defer tmp.deinit();

    // The second handle opens now, while the log holds only its header, and
    // appends nothing yet.
    var second = try Log.open(io, tmp.path(), "01TESTSESSION");
    defer second.close(io);

    // The first handle writes two events after that.
    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);
    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "two" }} } }, 2);

    // The old owner lets go, which is the whole of a handover: one side calls
    // `unlock` and the other calls `lock`, with no protocol in between.
    var giving_up = try tmp.log.lock(io);
    try giving_up.unlock(io);

    // Now the second handle owns the session and writes.
    var locked = try second.lock(io);
    _ = try locked.append(allocator, io, .{ .message = .{ .role = .assistant, .content = &.{.{ .text = "three" }} } }, 3);

    const bytes = try tmp.readAll(allocator);
    defer allocator.free(bytes);
    const lines = try linesOf(allocator, bytes);
    defer allocator.free(lines);
    try std.testing.expectEqual(@as(usize, 4), lines.len);

    const prev = try prevOf(allocator, lines[3]);
    defer allocator.free(prev);
    // The line the other handle wrote, and not the header, which is all this
    // handle had ever seen for itself.
    try std.testing.expectEqualStrings(&chain.of(lines[2]), prev);
    try std.testing.expect(!std.mem.eql(u8, prev, &chain.of(lines[0])));
}

test "the digest of a header and of a last line are read off the file, not built from a guess" {
    // `headerDigest` is what anchors every verification, and `lastLineDigest`
    // is what every append hashes. A log holding only its header must answer
    // the same digest for both, which is what makes the first event's `prev`
    // the header's own hash and needs no special case anywhere.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = try TestLog.init("chain-digests");
    defer tmp.deinit();

    const header = try tmp.log.headerDigest(io);
    try std.testing.expectEqualStrings(&chain.of("{\"chock_log\":1}"), &header);
    try std.testing.expectEqualStrings(&header, &try tmp.log.lastLineDigest(io));

    // Once an event is there, the last line moves and the header does not.
    _ = try tmp.append(allocator, .{ .message = .{ .role = .user, .content = &.{.{ .text = "one" }} } }, 1);
    const bytes = try tmp.readAll(allocator);
    defer allocator.free(bytes);
    const lines = try linesOf(allocator, bytes);
    defer allocator.free(lines);

    try std.testing.expectEqualStrings(&header, &try tmp.log.headerDigest(io));
    try std.testing.expectEqualStrings(&chain.of(lines[1]), &try tmp.log.lastLineDigest(io));
}

test "a line longer than the read buffer hashes the same as the whole line at once" {
    // `digestOfRange` reads a line in 4096 byte chunks, and a tool result is
    // the line that makes that matter. A chunked hash that dropped or repeated
    // a chunk would still return a digest, and every log with a large event in
    // it would then read as edited at the event after it.
    const allocator = std.testing.allocator;
    var tmp = try TestLog.init("chain-long-line");
    defer tmp.deinit();

    const long = try allocator.alloc(u8, 20_000);
    defer allocator.free(long);
    // Not one repeated byte: a chunk read twice, or in the wrong order, would
    // hash the same over a run of identical bytes and this test would pass a
    // reader that is genuinely broken.
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
