//! Where a seal lives: a file beside the log, named after it.

const std = @import("std");
const seal = @import("seal.zig");

pub const suffix = ".seal";

pub const max_bytes: usize = 64 * 1024;

pub const PathError = error{
    NameTooLong,
};

pub fn pathFor(buffer: []u8, log_path: []const u8) PathError![]u8 {
    if (log_path.len + suffix.len > buffer.len) return error.NameTooLong;
    @memcpy(buffer[0..log_path.len], log_path);
    @memcpy(buffer[log_path.len..][0..suffix.len], suffix);
    return buffer[0 .. log_path.len + suffix.len];
}

pub const Found = union(enum) {
    absent,
    malformed,
    seal: seal.Seal,
};

pub fn read(
    arena: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    certs: *seal.ReadBuffer,
) Found {
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_bytes)) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return .absent,
        else => return .malformed,
    };

    const record = std.json.parseFromSliceLeaky(seal.Record, arena, text, .{
        // A field this build does not know means a record from a later format. It is refused rather than skipped, because a reader that silently dropped a field could verify a record it did not fully understand.
        .ignore_unknown_fields = false,
    }) catch return .malformed;

    return .{ .seal = seal.fromRecord(record, certs) catch return .malformed };
}

pub const WriteError = error{
    WriteFailed,
} || std.mem.Allocator.Error;

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

fn scratchPath(buffer: []u8, tmp: *testing.TmpDir) ![]u8 {
    var real: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &real);
    var log_path: [std.fs.max_path_bytes]u8 = undefined;
    const log = try std.fmt.bufPrint(&log_path, "{s}/{s}.jsonl", .{ real[0..len], test_session });
    return pathFor(buffer, log);
}

test "a seal written beside a log reads back and still verifies" {
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
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try scratchPath(&path_buffer, &tmp);

    var certs = seal.ReadBuffer{};
    try testing.expect(read(arena, testing.io, path, &certs) == .absent);

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

    {
        var file = try std.Io.Dir.cwd().createFile(testing.io, path, .{ .truncate = true });
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, whole[0 .. whole.len / 2]);
    }
    try testing.expect(read(arena, testing.io, path, &certs) == .malformed);

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

    var small: [8]u8 = undefined;
    try testing.expectError(error.NameTooLong, pathFor(&small, "/state/chock/parser/01JQ.jsonl"));
}

test "a record from a later format is refused rather than read in part" {
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
