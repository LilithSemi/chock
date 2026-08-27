//! Where a seal lives: a file beside the log, named after it.
//!
//! `seal.zig` builds the signature and `seal.Record` is the JSON it travels
//! in. This file is the answer to the question that record left open, which is
//! where the bytes go.
//!
//! ## A seal cannot be the last line it seals
//!
//! The obvious home is a new event kind, appended like every other event. It
//! does not work, and the reason is not a matter of taste.
//!
//! **A seal names the digest of the last line of the log.** An appended seal
//! becomes the last line, so the digest it names would have to be its own, and
//! that value is not known until the line is written. The only way out is for
//! the seal to name the line in front of it and then sit past the head it
//! signed. The log now ends with a line no signature covers, which is the exact
//! gap `chain.zig` cannot close and the exact gap a seal exists to close. A
//! second seal over the first would inherit the same problem.
//!
//! Three more facts point the same way:
//!
//! * **A log is sealed again when it grows.** A session that ended, was
//!   resumed, and ended again wants one seal about the file as it now stands. A
//!   sidecar is replaced. An event kind would leave both in the file and make a
//!   reader decide which of two signatures is the real one.
//! * **Appending needs the log's exclusive lock**, which is how `log.zig`
//!   decides who owns a session. Sealing happens after a session has ended and
//!   the lock is gone, so an appending sealer would have to take ownership of a
//!   session that is over.
//! * **A seal is not something the agent did.** The log is the record of a
//!   session. A seal is a statement about that file, made by whoever holds the
//!   key, and it can be made by a person and a key that were not there at the
//!   time.
//!
//! ## What a sidecar costs, and why the cost is paid openly
//!
//! **Anybody can delete this file.** Nothing here stops that, and no design
//! could: a seal that could not be removed would have to live somewhere the
//! writer cannot reach, which is a second party and not a file layout.
//!
//! So a missing seal is reported as `seal.Verdict.absent` and **never as a
//! pass**. `chock sessions verify` prints the seal state on every row for that
//! reason: a reader who sees nothing must not be able to read the silence as a
//! signature. Deleting the sidecar takes a log from "sealed" to "not sealed",
//! which is visible, and never to "sealed and holding".
//!
//! ## The name
//!
//! The log's own path with `suffix` on the end, so a directory listing puts the
//! two next to each other and neither name has to be built from parts. This
//! file knows nothing about where a session log lives or what it is called:
//! `src/sessions.zig` owns that layout and hands the path in.

const std = @import("std");
const seal = @import("seal.zig");

/// What is put on the end of a log's own path to name its seal. **On the end
/// of the whole path**, extension and all, so a reader who has the log's name
/// has the seal's name with no parsing.
pub const suffix = ".seal";

/// The largest seal file this reads. A record holds at most four certificates
/// of `seal.max_certificate_len` bytes in base64, plus fields of fixed width,
/// so this is well over the largest record `write` can produce and it still
/// bounds a file somebody else wrote.
pub const max_bytes: usize = 64 * 1024;

pub const PathError = error{
    /// The log's path plus `suffix` does not fit in the buffer given.
    NameTooLong,
};

/// The seal path for a log at `log_path`, written into `buffer`.
pub fn pathFor(buffer: []u8, log_path: []const u8) PathError![]u8 {
    if (log_path.len + suffix.len > buffer.len) return error.NameTooLong;
    @memcpy(buffer[0..log_path.len], log_path);
    @memcpy(buffer[log_path.len..][0..suffix.len], suffix);
    return buffer[0 .. log_path.len + suffix.len];
}

/// What reading the file beside a log found.
///
/// **`absent` and `malformed` are two different facts.** No file at all is the
/// ordinary state of every log written before there were seals, and every log
/// nobody has sealed. A file that is there and will not read is a seal somebody
/// wrote and something has since happened to, which is worth a different
/// sentence. Neither is a pass.
pub const Found = union(enum) {
    /// There is no file. See this file's own top comment on why that is
    /// reported and never assumed away.
    absent,
    /// The file is there and could not be turned into a seal: an I/O fault, a
    /// file over `max_bytes`, text that is not JSON, or a field of the wrong
    /// width. **Nothing was checked**, so this is never a pass.
    malformed,
    /// The record parsed. The signature has not been looked at yet: that is
    /// `seal.read`, and it needs the log's own digests, which this file does
    /// not have.
    seal: seal.Seal,
};

/// Read the seal beside a log.
///
/// `arena` must be an arena: the answer's strings point into what this parsed
/// and nothing here frees them. `certs` holds the decoded attestation and must
/// outlive the answer.
pub fn read(
    arena: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    certs: *seal.ReadBuffer,
) Found {
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_bytes)) catch |err| switch (err) {
        // The one case that is not a fault. Anything else, a directory that
        // cannot be listed included, is a file this could not read rather than
        // a log nobody sealed.
        error.FileNotFound, error.NotDir => return .absent,
        else => return .malformed,
    };

    const record = std.json.parseFromSliceLeaky(seal.Record, arena, text, .{
        // A field this build does not know is a record from a later format.
        // Refused rather than passed over: `seal.Record.chock_seal` is checked
        // against `seal.format_version` by `seal.read`, and a reader that
        // quietly dropped a field could verify a record it did not understand.
        .ignore_unknown_fields = false,
    }) catch return .malformed;

    return .{ .seal = seal.fromRecord(record, certs) catch return .malformed };
}

pub const WriteError = error{
    /// The file could not be created or written.
    WriteFailed,
} || std.mem.Allocator.Error;

/// Write `record` beside a log, replacing whatever was there.
///
/// **A torn write is safe here and needs no rename dance.** Half a record is
/// not JSON, so `read` answers `malformed`, and `malformed` is not a pass. The
/// worst a crash mid write can do is take a seal away, which is a state a
/// reader is already told about on every row.
///
/// **No mode is set.** A seal holds a public key and a signature and no secret,
/// so a file only its owner can read would stop the one reader it is for.
pub fn write(
    arena: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    record: seal.Record,
) WriteError!void {
    const text = std.json.Stringify.valueAlloc(arena, record, .{}) catch return error.OutOfMemory;

    var file = std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true }) catch
        return error.WriteFailed;
    defer file.close(io);
    file.writeStreamingAll(io, text) catch return error.WriteFailed;
    // A closing newline, so the file is a line a shell tool can read and a
    // person can `cat` without their prompt landing on the record.
    file.writeStreamingAll(io, "\n") catch return error.WriteFailed;
}

const testing = std.testing;
const software = @import("software.zig");

const test_session = "01JZZZZZZZZZZZZZZZZZZZZZZZ";
const test_header = [_]u8{'a'} ** seal.digest_hex_len;
const test_head = [_]u8{'b'} ** seal.digest_hex_len;

fn testExpectation() seal.Expectation {
    return .{ .session = test_session, .header = &test_header, .head = &test_head, .events = 7 };
}

fn testRequest(level: seal.Level) seal.Request {
    return .{
        .session = test_session,
        .header = test_header,
        .head = test_head,
        .events = 7,
        .level = level,
    };
}

/// A path inside a fresh temporary directory. The seal path is built by
/// `pathFor` from a log path, exactly as a caller builds it.
fn scratchPath(buffer: []u8, tmp: *testing.TmpDir) ![]u8 {
    var real: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &real);
    var log_path: [std.fs.max_path_bytes]u8 = undefined;
    const log = try std.fmt.bufPrint(&log_path, "{s}/{s}.jsonl", .{ real[0..len], test_session });
    return pathFor(buffer, log);
}

test "a seal written beside a log reads back and still verifies" {
    // The round trip through a real file. `seal.zig` already proves a record
    // survives a round trip through memory; this proves the file is the same
    // carriage, so a reader who has the two paths and a public key is done.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&path_buffer, &tmp);

    var key = try software.Key.fromSeed([_]u8{0x31} ** 32);
    var held = seal.Held{};
    const signed = try seal.sign(testRequest(.software), key.signer(), &held);

    var buffer = seal.Buffer{};
    try write(arena, testing.io, path, try seal.toRecord(signed, &buffer));

    var certs = seal.ReadBuffer{};
    const found = read(arena, testing.io, path, &certs);
    try testing.expect(found == .seal);
    const reading = seal.read(found.seal, testExpectation(), .{ .now_sec = 0 });
    try testing.expectEqual(seal.Verdict.signed_software, reading.verdict);
    try testing.expectEqual(@as(?seal.Level, .software), reading.claimed);
}

test "a seal file that is not there is absent, and absent is never a seal" {
    // The state every log written before seals existed is in, and the state a
    // log whose sidecar somebody deleted is in. The answer names it rather than
    // guessing, and it is not a `seal`.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&path_buffer, &tmp);

    var certs = seal.ReadBuffer{};
    try testing.expect(read(arena, testing.io, path, &certs) == .absent);

    // And the mutation check: the same call over a file that is there answers
    // something else, so `absent` is not what this returns for everything.
    var key = try software.Key.fromSeed([_]u8{0x32} ** 32);
    var buffer = seal.Buffer{};
    var held = seal.Held{};
    try write(arena, testing.io, path, try seal.toRecord(
        try seal.sign(testRequest(.software), key.signer(), &held),
        &buffer,
    ));
    try testing.expect(read(arena, testing.io, path, &certs) == .seal);
}

test "a seal file somebody edited is malformed, and malformed is never absent" {
    // Half a write, a text editor, or a truncation. Each is a seal that was
    // written and cannot be read, which is a different fact from no seal at
    // all, and neither of the two is a pass.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&path_buffer, &tmp);

    var key = try software.Key.fromSeed([_]u8{0x33} ** 32);
    var buffer = seal.Buffer{};
    const record = held: {
        var held = seal.Held{};
        break :held try seal.toRecord(try seal.sign(testRequest(.software), key.signer(), &held), &buffer);
    };
    try write(arena, testing.io, path, record);

    const whole = try std.Io.Dir.cwd().readFileAlloc(testing.io, path, arena, .limited(max_bytes));
    var certs = seal.ReadBuffer{};

    // Cut in half, which is what a crash mid write leaves.
    {
        var file = try std.Io.Dir.cwd().createFile(testing.io, path, .{ .truncate = true });
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, whole[0 .. whole.len / 2]);
    }
    try testing.expect(read(arena, testing.io, path, &certs) == .malformed);

    // A key one character short. That is not a field of any width at all, so
    // `seal.fromRecord` refuses it rather than padding it, and this is where
    // that refusal reaches a reader. **A key two characters short is a
    // different fault**: it reads back as bytes and `seal.read` calls it
    // malformed, because its width belongs to no scheme.
    {
        var short = record;
        short.key = record.key[0 .. record.key.len - 1];
        try write(arena, testing.io, path, short);
    }
    try testing.expect(read(arena, testing.io, path, &certs) == .malformed);
}

test "a seal path is the log's own path with the suffix on the end" {
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "/state/chock/parser/01JQ.jsonl.seal",
        try pathFor(&buffer, "/state/chock/parser/01JQ.jsonl"),
    );

    // A buffer that cannot hold the answer is refused, never filled part way.
    var small: [8]u8 = undefined;
    try testing.expectError(error.NameTooLong, pathFor(&small, "/state/chock/parser/01JQ.jsonl"));
}

test "a record from a later format is refused rather than read in part" {
    // A field this build does not know means a record this build does not
    // understand. Passing over it would let a reader check a signature over
    // fields it never saw and report a pass.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&path_buffer, &tmp);

    var key = try software.Key.fromSeed([_]u8{0x34} ** 32);
    var buffer = seal.Buffer{};
    const record = held: {
        var held = seal.Held{};
        break :held try seal.toRecord(try seal.sign(testRequest(.software), key.signer(), &held), &buffer);
    };
    const text = try std.json.Stringify.valueAlloc(arena, record, .{});

    // The same record with one field nobody here knows, spliced in after the
    // opening brace.
    const later = try std.fmt.allocPrint(arena, "{{\"witness\":\"x\",{s}", .{text[1..]});
    {
        var file = try std.Io.Dir.cwd().createFile(testing.io, path, .{ .truncate = true });
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, later);
    }

    var certs = seal.ReadBuffer{};
    try testing.expect(read(arena, testing.io, path, &certs) == .malformed);
}

test {
    testing.refAllDecls(@This());
}
