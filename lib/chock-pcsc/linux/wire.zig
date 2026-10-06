//! The bytes `pcscd` reads and writes on its own unix socket, and nothing else.

const std = @import("std");
const builtin = @import("builtin");

pub const endian = builtin.cpu.arch.endian();

pub const protocol_version: Version = .{ .major = 4, .minor = 5 };

pub const Version = struct {
    major: i32,
    minor: i32,

    pub fn accepts(self: Version, other: Version) bool {
        return self.major == other.major and self.minor == other.minor;
    }

    pub fn format(self: Version, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{d}:{d}", .{ self.major, self.minor });
    }
};

pub const Command = enum(u32) {
    establish_context = 0x01,
    release_context = 0x02,
    connect = 0x04,
    disconnect = 0x06,
    transmit = 0x09,
    version = 0x11,
    get_readers_state = 0x12,
};

pub const Return = enum(u32) {
    success = 0x00000000,
    insufficient_buffer = 0x80100008,
    unknown_reader = 0x80100009,
    sharing_violation = 0x8010000B,
    no_smartcard = 0x8010000C,
    not_ready = 0x80100010,
    reader_unavailable = 0x80100017,
    no_service = 0x8010001D,
    service_stopped = 0x8010001E,
    no_readers_available = 0x8010002E,
    unresponsive_card = 0x80100066,
    removed_card = 0x80100069,
    security_violation = 0x8010006A,
    _,
};

pub const scope_system: u32 = 0x0002;

pub const share_shared: u32 = 0x0002;

pub const protocol_t0: u32 = 0x0001;
pub const protocol_t1: u32 = 0x0002;
pub const protocol_any: u32 = protocol_t0 | protocol_t1;

pub const disposition_leave: u32 = 0x0000;

pub const io_request_len: u32 = @sizeOf(usize) * 2;

pub const header_len = 8;

pub fn encodeHeader(command: Command, size: u32) [header_len]u8 {
    var out: [header_len]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], size, endian);
    std.mem.writeInt(u32, out[4..8], @intFromEnum(command), endian);
    return out;
}

pub const version_len = 12;

pub fn encodeVersion(offered: Version) [version_len]u8 {
    var out: [version_len]u8 = undefined;
    std.mem.writeInt(i32, out[0..4], offered.major, endian);
    std.mem.writeInt(i32, out[4..8], offered.minor, endian);
    // The client writes SCARD_S_SUCCESS here and the daemon overwrites it with the real answer.
    std.mem.writeInt(u32, out[8..12], 0, endian);
    return out;
}

pub const VersionReply = struct {
    daemon: Version,
    rv: Return,
};

pub fn decodeVersion(body: *const [version_len]u8) VersionReply {
    return .{
        .daemon = .{
            .major = std.mem.readInt(i32, body[0..4], endian),
            .minor = std.mem.readInt(i32, body[4..8], endian),
        },
        .rv = @enumFromInt(std.mem.readInt(u32, body[8..12], endian)),
    };
}

pub const establish_len = 12;

pub fn encodeEstablish(scope: u32) [establish_len]u8 {
    var out: [establish_len]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], scope, endian);
    std.mem.writeInt(u32, out[4..8], 0, endian);
    std.mem.writeInt(u32, out[8..12], 0, endian);
    return out;
}

pub const EstablishReply = struct {
    context: u32,
    rv: Return,
};

pub fn decodeEstablish(body: *const [establish_len]u8) EstablishReply {
    return .{
        .context = std.mem.readInt(u32, body[4..8], endian),
        .rv = @enumFromInt(std.mem.readInt(u32, body[8..12], endian)),
    };
}

pub const release_len = 8;

pub fn encodeRelease(context: u32) [release_len]u8 {
    var out: [release_len]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], context, endian);
    std.mem.writeInt(u32, out[4..8], 0, endian);
    return out;
}

pub fn decodeRelease(body: *const [release_len]u8) struct { context: u32, rv: Return } {
    return .{
        .context = std.mem.readInt(u32, body[0..4], endian),
        .rv = @enumFromInt(std.mem.readInt(u32, body[4..8], endian)),
    };
}

pub const max_reader_name = 128;

pub const reader_state_len = 184;

pub const max_readers = 16;

pub const readers_state_len = max_readers * reader_state_len;

pub fn readerName(slot: *const [reader_state_len]u8) []const u8 {
    const field = slot[0..max_reader_name];
    const end = std.mem.indexOfScalar(u8, field, 0) orelse max_reader_name;
    return field[0..end];
}

pub fn writeReaderList(states: *const [readers_state_len]u8, out: []u8) error{BufferTooSmall}!usize {
    var written: usize = 0;
    var slot: usize = 0;
    while (slot < max_readers) : (slot += 1) {
        const name = readerName(states[slot * reader_state_len ..][0..reader_state_len]);
        if (name.len == 0) continue;
        if (written + name.len + 1 > out.len) return error.BufferTooSmall;
        @memcpy(out[written..][0..name.len], name);
        out[written + name.len] = 0;
        written += name.len + 1;
    }
    return written;
}

pub const connect_len = 4 + max_reader_name + 4 + 4 + 4 + 4 + 4;

pub const NameTooLong = error{NameTooLong};

pub fn encodeConnect(context: u32, reader: []const u8) NameTooLong![connect_len]u8 {
    if (reader.len >= max_reader_name) return error.NameTooLong;
    var out: [connect_len]u8 = @splat(0);
    std.mem.writeInt(u32, out[0..4], context, endian);
    @memcpy(out[4..][0..reader.len], reader);
    std.mem.writeInt(u32, out[132..136], share_shared, endian);
    std.mem.writeInt(u32, out[136..140], protocol_any, endian);
    return out;
}

pub const ConnectReply = struct {
    card: i32,
    active_protocol: u32,
    rv: Return,
};

pub fn decodeConnect(body: *const [connect_len]u8) ConnectReply {
    return .{
        .card = std.mem.readInt(i32, body[140..144], endian),
        .active_protocol = std.mem.readInt(u32, body[144..148], endian),
        .rv = @enumFromInt(std.mem.readInt(u32, body[148..152], endian)),
    };
}

pub const disconnect_len = 12;

pub fn encodeDisconnect(card: i32) [disconnect_len]u8 {
    var out: [disconnect_len]u8 = undefined;
    std.mem.writeInt(i32, out[0..4], card, endian);
    std.mem.writeInt(u32, out[4..8], disposition_leave, endian);
    std.mem.writeInt(u32, out[8..12], 0, endian);
    return out;
}

pub fn decodeDisconnect(body: *const [disconnect_len]u8) Return {
    return @enumFromInt(std.mem.readInt(u32, body[8..12], endian));
}

pub const transmit_len = 32;

pub fn encodeTransmit(card: i32, send_protocol: u32, send_len: u32, receive_len: u32) [transmit_len]u8 {
    var out: [transmit_len]u8 = undefined;
    std.mem.writeInt(i32, out[0..4], card, endian);
    std.mem.writeInt(u32, out[4..8], send_protocol, endian);
    std.mem.writeInt(u32, out[8..12], io_request_len, endian);
    std.mem.writeInt(u32, out[12..16], send_len, endian);
    std.mem.writeInt(u32, out[16..20], protocol_any, endian);
    std.mem.writeInt(u32, out[20..24], io_request_len, endian);
    std.mem.writeInt(u32, out[24..28], receive_len, endian);
    std.mem.writeInt(u32, out[28..32], 0, endian);
    return out;
}

pub const TransmitReply = struct {
    received: u32,
    rv: Return,
};

pub fn decodeTransmit(body: *const [transmit_len]u8) TransmitReply {
    return .{
        .received = std.mem.readInt(u32, body[24..28], endian),
        .rv = @enumFromInt(std.mem.readInt(u32, body[28..32], endian)),
    };
}

const testing = std.testing;

const wire_capture = [_]u8{
    0x0c, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

test "the handshake this build sends is the one a real libpcsclite sent" {
    if (endian != .little) return error.SkipZigTest;

    const header = encodeHeader(.version, version_len);
    const body = encodeVersion(protocol_version);
    try testing.expectEqualSlices(u8, wire_capture[0..8], &header);
    try testing.expectEqualSlices(u8, wire_capture[8..20], &body);
}

test "a version answer is read back out of the bytes it was written into" {
    const written = encodeVersion(.{ .major = 4, .minor = 0 });
    const read = decodeVersion(&written);
    try testing.expectEqual(@as(i32, 4), read.daemon.major);
    try testing.expectEqual(@as(i32, 0), read.daemon.minor);
    try testing.expectEqual(Return.success, read.rv);
}

test "the version this build speaks is accepted and every neighbour of it is not" {
    try testing.expect(protocol_version.accepts(.{ .major = 4, .minor = 5 }));
    try testing.expect(!protocol_version.accepts(.{ .major = 4, .minor = 4 }));
    try testing.expect(!protocol_version.accepts(.{ .major = 4, .minor = 6 }));
    try testing.expect(!protocol_version.accepts(.{ .major = 5, .minor = 5 }));
}

test "a version prints as the two numbers pcscd's own log prints" {
    var buffer: [16]u8 = undefined;
    const said = try std.fmt.bufPrint(&buffer, "{f}", .{protocol_version});
    try testing.expectEqualStrings("4:5", said);
}

test "the reader list is built from the named slots and skips the empty ones" {
    var states: [readers_state_len]u8 = @splat(0);
    @memcpy(states[0..9], "Reader 00");
    @memcpy(states[2 * reader_state_len ..][0..9], "Reader 02");

    var out: [64]u8 = undefined;
    const written = try writeReaderList(&states, &out);
    try testing.expectEqualSlices(u8, "Reader 00\x00Reader 02\x00", out[0..written]);
}

test "a machine with no reader writes no bytes rather than one empty name" {
    const states: [readers_state_len]u8 = @splat(0);
    var out: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try writeReaderList(&states, &out));
}

test "a reader name stops at its zero byte and not at the end of the field" {
    var slot: [reader_state_len]u8 = @splat(0xaa);
    @memcpy(slot[0..9], "Reader 00");
    slot[9] = 0;
    try testing.expectEqualStrings("Reader 00", readerName(&slot));
}

test "a reader list too long for the caller's buffer is refused, never cut short" {
    var states: [readers_state_len]u8 = @splat(0);
    @memcpy(states[0..9], "Reader 00");
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, writeReaderList(&states, &tiny));
}

test "a reader name that fills the field is refused before it is sent" {
    const long: [max_reader_name]u8 = @splat('r');
    try testing.expectError(error.NameTooLong, encodeConnect(1, &long));
    const longest: [max_reader_name - 1]u8 = @splat('r');
    const body = try encodeConnect(1, &longest);
    try testing.expectEqual(@as(u8, 0), body[4 + max_reader_name - 1]);
}

test "a connect states the reader, the share mode and both protocols" {
    const body = try encodeConnect(0x12345678, "Reader 00");
    try testing.expectEqual(@as(u32, 0x12345678), std.mem.readInt(u32, body[0..4], endian));
    try testing.expectEqualStrings("Reader 00", std.mem.sliceTo(body[4..132], 0));
    try testing.expectEqual(share_shared, std.mem.readInt(u32, body[132..136], endian));
    try testing.expectEqual(protocol_any, std.mem.readInt(u32, body[136..140], endian));
}

test "a connect answer is read from the offsets the request left empty" {
    var body: [connect_len]u8 = @splat(0);
    std.mem.writeInt(i32, body[140..144], 7, endian);
    std.mem.writeInt(u32, body[144..148], protocol_t1, endian);
    std.mem.writeInt(u32, body[148..152], @intFromEnum(Return.no_smartcard), endian);
    const reply = decodeConnect(&body);
    try testing.expectEqual(@as(i32, 7), reply.card);
    try testing.expectEqual(protocol_t1, reply.active_protocol);
    try testing.expectEqual(Return.no_smartcard, reply.rv);
}

test "a disconnect leaves the card alone rather than resetting it" {
    const body = encodeDisconnect(7);
    try testing.expectEqual(disposition_leave, std.mem.readInt(u32, body[4..8], endian));
    try testing.expectEqual(Return.success, decodeDisconnect(&body));
}

test "a transmit states both buffer lengths and the protocol the card settled on" {
    const body = encodeTransmit(7, protocol_t1, 5, 258);
    try testing.expectEqual(@as(i32, 7), std.mem.readInt(i32, body[0..4], endian));
    try testing.expectEqual(protocol_t1, std.mem.readInt(u32, body[4..8], endian));
    try testing.expectEqual(io_request_len, std.mem.readInt(u32, body[8..12], endian));
    try testing.expectEqual(@as(u32, 5), std.mem.readInt(u32, body[12..16], endian));
    try testing.expectEqual(@as(u32, 258), std.mem.readInt(u32, body[24..28], endian));

    const reply = decodeTransmit(&body);
    try testing.expectEqual(@as(u32, 258), reply.received);
    try testing.expectEqual(Return.success, reply.rv);
}

test "a code the daemon passed through from a driver stays a number" {
    const unnamed: Return = @enumFromInt(0x8010004d);
    try testing.expectEqual(@as(u32, 0x8010004d), @intFromEnum(unnamed));
    try testing.expect(unnamed != .success);
}

test "the sizes this driver frames its messages with" {
    try testing.expectEqual(@as(usize, 8), header_len);
    try testing.expectEqual(@as(usize, 12), version_len);
    try testing.expectEqual(@as(usize, 12), establish_len);
    try testing.expectEqual(@as(usize, 8), release_len);
    try testing.expectEqual(@as(usize, 152), connect_len);
    try testing.expectEqual(@as(usize, 12), disconnect_len);
    try testing.expectEqual(@as(usize, 32), transmit_len);
    try testing.expectEqual(@as(usize, 184), reader_state_len);
    try testing.expectEqual(@as(usize, 2944), readers_state_len);
}

test {
    testing.refAllDecls(@This());
}
