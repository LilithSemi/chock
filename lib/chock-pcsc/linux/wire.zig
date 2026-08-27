//! The bytes `pcscd` reads and writes on its own unix socket, and nothing else.
//!
//! **No socket, no state and no platform call is here.** This file turns a
//! request into bytes and bytes into an answer, so every rule the daemon holds
//! a client to can be pinned by a test that needs no daemon at all. The socket
//! work is `driver.zig`.
//!
//! ## Where these layouts come from
//!
//! `pcsc-lite` states this protocol in its own source and nowhere else: there
//! is no document, no header a distribution ships, and no version of it that is
//! promised to hold. The layouts below are read from `src/winscard_msg.h`,
//! `src/winscard_clnt.c` and `src/winscard_svc.c` of **pcsc-lite 2.4.1**, which
//! is the release running on the machine this was written against, and the
//! header framing is confirmed byte for byte against a real `libpcsclite`
//! client: see `wire_capture` below.
//!
//! **A different daemon is refused rather than guessed at.** The handshake
//! carries a version, `Version.accepts` decides, and a daemon that answers
//! anything else gets a refusal that names both numbers. See `driver.zig`'s own
//! `Failure.version_mismatch`.
//!
//! ## The daemon writes its own memory, so the order is this host's
//!
//! Every message is a C `struct` sent with one `write`. There is no packing, no
//! network byte order and no conversion on either end: a field is whatever the
//! machine's own layout says it is. So this file states the offsets that layout
//! gives on the platforms Chock builds for, and reads and writes with
//! `endian` rather than with a fixed order. **A client on a machine of a
//! different width or order than the daemon cannot speak this protocol at all**,
//! which is true of `libpcsclite` too, and is not a limit this file adds.
//!
//! ## Padding is part of the layout
//!
//! `READER_STATE` ends with a 33 byte array followed by two 4 byte fields, so
//! the C rules put three bytes of padding in the middle of it. `reader_state_len`
//! is the size those rules give, and `readers_state_len` multiplies it by the
//! number of slots the daemon always sends. **A wrong size here does not read a
//! wrong reader name: it desynchronises every later message on the connection**,
//! because the daemon frames nothing. `test/pcsc/pcscd.zig` pins the size
//! against the real daemon for that reason.

const std = @import("std");
const builtin = @import("builtin");

/// The order every field is read and written in. See this file's own top
/// comment: the daemon writes its own memory, so this is the host's order and
/// never a wire order chosen by anybody.
pub const endian = builtin.cpu.arch.endian();

/// What this build offers in the handshake, and the only version it speaks.
///
/// `PROTOCOL_VERSION_MAJOR` and `PROTOCOL_VERSION_MINOR` of pcsc-lite 2.4.1.
pub const protocol_version: Version = .{ .major = 4, .minor = 5 };

/// One end's protocol version.
pub const Version = struct {
    major: i32,
    minor: i32,

    /// Whether a client that offers `self` can speak to a daemon that answers
    /// `other`.
    ///
    /// **Exact, and deliberately narrower than `libpcsclite`.** The real client
    /// keeps a backward window: when the daemon refuses, it offers the daemon's
    /// own minor number and tries again. Chock does not, because the answer to
    /// a daemon this build does not know is a refusal a person can read, not a
    /// second handshake at a version nothing here was ever run against. A
    /// silent downgrade is the failure this whole module is built to avoid:
    /// see `lib/chock-pcsc.zig` on why a fallback is recorded.
    pub fn accepts(self: Version, other: Version) bool {
        return self.major == other.major and self.minor == other.minor;
    }

    /// `4:5`, the form pcsc-lite's own logs use, so a person reading a refusal
    /// and a person reading `pcscd`'s log see the same two numbers.
    pub fn format(self: Version, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{d}:{d}", .{ self.major, self.minor });
    }
};

/// The commands this driver sends. `enum pcsc_msg_commands`, of which these
/// seven are the whole of what a signature needs.
///
/// **Not the whole enum.** The daemon has sixteen more, for transactions,
/// attributes and reader events, and a name here that nothing sends would be a
/// claim this file makes and no test can check.
pub const Command = enum(u32) {
    establish_context = 0x01,
    release_context = 0x02,
    connect = 0x04,
    disconnect = 0x06,
    transmit = 0x09,
    version = 0x11,
    get_readers_state = 0x12,
};

/// What the daemon put in an `rv` field.
///
/// **Non exhaustive on purpose.** The daemon has about seventy of these and
/// passes through whatever a reader driver gave it. A code nobody named here
/// must stay readable as a number in a diagnostic rather than become a
/// different code that happens to have a name.
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

/// `SCARD_SCOPE_SYSTEM`. The only scope `pcscd` implements: it ignores the
/// field, and the real client sends whatever its caller gave.
pub const scope_system: u32 = 0x0002;

/// `SCARD_SHARE_SHARED`. Chock reads a certificate and signs one digest, so it
/// has no reason to lock a reader another program is using.
pub const share_shared: u32 = 0x0002;

/// `SCARD_PROTOCOL_T0` and `SCARD_PROTOCOL_T1`, and the two together, which is
/// `SCARD_PROTOCOL_ANY`: let the reader settle it.
pub const protocol_t0: u32 = 0x0001;
pub const protocol_t1: u32 = 0x0002;
pub const protocol_any: u32 = protocol_t0 | protocol_t1;

/// `SCARD_LEAVE_CARD`. A disconnect that reset the card would throw away a PIN
/// another program on the same reader had already verified.
pub const disposition_leave: u32 = 0x0000;

/// `sizeof(SCARD_IO_REQUEST)`, which is two `unsigned long` fields.
///
/// **Not four bytes each.** `pcsc-lite` types this one structure with C's own
/// `unsigned long` and not with its `DWORD`, so it is eight bytes wide on a
/// 32 bit build and sixteen on a 64 bit one. The daemon copies the number
/// through to the reader driver and does not check it.
pub const io_request_len: u32 = @sizeOf(usize) * 2;

/// `struct rxHeader`: the size of what follows, then the command.
///
/// **Every message from a client carries one. No answer from the daemon does.**
/// The daemon replies with a bare body whose length the client is expected to
/// already know, which is why every wrong length below desynchronises a
/// connection rather than failing it.
pub const header_len = 8;

pub fn encodeHeader(command: Command, size: u32) [header_len]u8 {
    var out: [header_len]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], size, endian);
    std.mem.writeInt(u32, out[4..8], @intFromEnum(command), endian);
    return out;
}

/// `struct version_struct`: major, minor, rv.
pub const version_len = 12;

pub fn encodeVersion(offered: Version) [version_len]u8 {
    var out: [version_len]u8 = undefined;
    std.mem.writeInt(i32, out[0..4], offered.major, endian);
    std.mem.writeInt(i32, out[4..8], offered.minor, endian);
    // The client sends `SCARD_S_SUCCESS` here and the daemon overwrites it.
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

/// `struct establish_struct`: dwScope, hContext, rv.
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

/// `struct release_struct`: hContext, rv.
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

/// `MAX_READERNAME`, the fixed width of the name field in every message that
/// carries one.
pub const max_reader_name = 128;

/// `sizeof(READER_STATE)`, worked out from the C layout:
///
/// | Offset | Field | Bytes |
/// | --- | --- | --- |
/// | 0 | `readerName[128]` | 128 |
/// | 128 | `eventCounter` | 4 |
/// | 132 | `readerState` | 4 |
/// | 136 | `readerSharing` | 4 |
/// | 140 | `cardAtr[33]` | 33 |
/// | 173 | padding | 3 |
/// | 176 | `cardAtrLength` | 4 |
/// | 180 | `cardProtocol` | 4 |
///
/// The three padding bytes are the part a reader of the header misses, and the
/// part a wrong answer here is silent about. See this file's own top comment.
pub const reader_state_len = 184;

/// `PCSCLITE_MAX_READERS_CONTEXTS`. The daemon answers this many slots every
/// time, whatever is attached: a slot whose name is empty is a slot with no
/// reader in it, and there is no count anywhere in the answer.
pub const max_readers = 16;

/// How many bytes one `CMD_GET_READERS_STATE` answers with.
pub const readers_state_len = max_readers * reader_state_len;

/// The name in one slot, or an empty slice for a slot with no reader.
///
/// **Read up to the first zero byte and never the whole field.** The daemon
/// sends 128 bytes whatever the name is, and the bytes past the terminator are
/// whatever was in that slot before.
pub fn readerName(slot: *const [reader_state_len]u8) []const u8 {
    const field = slot[0..max_reader_name];
    const end = std.mem.indexOfScalar(u8, field, 0) orelse max_reader_name;
    return field[0..end];
}

/// Turn one `CMD_GET_READERS_STATE` answer into the zero separated multi string
/// `Pcsc.listReaders` promises, and answer how many bytes were written.
///
/// **A machine with no reader writes nothing and that is not an error.** PC/SC
/// itself answers `SCARD_E_NO_READERS_AVAILABLE` for the same state, which
/// makes a caller tell an empty list from a failure by reading an error code.
/// Here it is a length, so `ReaderList` walks nothing and a caller that forgot
/// to check gets an empty loop instead of a reader that is not there.
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

/// `struct connect_struct`: hContext, szReader[128], dwShareMode,
/// dwPreferredProtocols, hCard, dwActiveProtocol, rv.
pub const connect_len = 4 + max_reader_name + 4 + 4 + 4 + 4 + 4;

pub const NameTooLong = error{NameTooLong};

/// **The name must fit with a zero byte to spare.** The daemon overwrites the
/// last byte of the field with a terminator before it reads the name, so a name
/// of exactly 128 bytes reaches it one character short and would connect to a
/// reader nobody asked for.
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

/// `struct disconnect_struct`: hCard, dwDisposition, rv.
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

/// `struct transmit_struct`: hCard, ioSendPciProtocol, ioSendPciLength,
/// cbSendLength, ioRecvPciProtocol, ioRecvPciLength, pcbRecvLength, rv.
pub const transmit_len = 32;

/// The header and body of a transmit. **The command bytes follow this with no
/// header of their own**, which is the one place in the protocol where a
/// message is two writes and not one.
pub fn encodeTransmit(card: i32, send_protocol: u32, send_len: u32, receive_len: u32) [transmit_len]u8 {
    var out: [transmit_len]u8 = undefined;
    std.mem.writeInt(i32, out[0..4], card, endian);
    std.mem.writeInt(u32, out[4..8], send_protocol, endian);
    std.mem.writeInt(u32, out[8..12], io_request_len, endian);
    std.mem.writeInt(u32, out[12..16], send_len, endian);
    // What the real client sends when its caller asked for no receive PCI.
    std.mem.writeInt(u32, out[16..20], protocol_any, endian);
    std.mem.writeInt(u32, out[20..24], io_request_len, endian);
    std.mem.writeInt(u32, out[24..28], receive_len, endian);
    std.mem.writeInt(u32, out[28..32], 0, endian);
    return out;
}

pub const TransmitReply = struct {
    /// How many bytes of answer follow. **Only when `rv` is `success`**: the
    /// daemon sends the buffer after the body on that one condition, so a
    /// caller that read this number on a failure would wait for bytes nobody
    /// is going to send.
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

/// The first twenty bytes a real `libpcsclite` 2.4.1 client put on this
/// machine's socket, captured with `strace` and copied here byte for byte.
///
/// **This is the whole reason the framing above is not a reading of a header.**
/// Eight bytes of `rxHeader` saying twelve bytes of `CMD_VERSION` follow, then
/// the twelve bytes themselves offering 4:5. A test that only agreed with the C
/// declaration would agree with a misreading of it just as happily.
const wire_capture = [_]u8{
    // sendto(3, "\f\0\0\0\21\0\0\0", 8, MSG_NOSIGNAL, ...)
    0x0c, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
    // sendto(3, "\4\0\0\0\5\0\0\0\0\0\0\0", 12, MSG_NOSIGNAL, ...)
    0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

test "the handshake this build sends is the one a real libpcsclite sent" {
    // Byte for byte against a capture, so a wrong field order, a wrong command
    // number and a wrong version all fail here rather than at a daemon.
    if (endian != .little) return error.SkipZigTest;

    const header = encodeHeader(.version, version_len);
    const body = encodeVersion(protocol_version);
    try testing.expectEqualSlices(u8, wire_capture[0..8], &header);
    try testing.expectEqualSlices(u8, wire_capture[8..20], &body);
}

test "a version answer is read back out of the bytes it was written into" {
    // The round trip, and the field the daemon overwrites. `rv` is the only
    // one of the three the client does not choose.
    const written = encodeVersion(.{ .major = 4, .minor = 0 });
    const read = decodeVersion(&written);
    try testing.expectEqual(@as(i32, 4), read.daemon.major);
    try testing.expectEqual(@as(i32, 0), read.daemon.minor);
    try testing.expectEqual(Return.success, read.rv);
}

test "the version this build speaks is accepted and every neighbour of it is not" {
    // The narrow rule, stated as four cases. A build that accepted a minor
    // number it had never spoken to would take the silent downgrade this
    // module exists to refuse.
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
    // The shape of the daemon's answer: a fixed number of slots, no count, and
    // an empty name for a slot with no reader. A build that read a count would
    // find none.
    var states: [readers_state_len]u8 = @splat(0);
    @memcpy(states[0..9], "Reader 00");
    // A gap. Slot 1 stays empty and slot 2 is named, which is what a reader
    // unplugged from the middle of the list leaves behind.
    @memcpy(states[2 * reader_state_len ..][0..9], "Reader 02");

    var out: [64]u8 = undefined;
    const written = try writeReaderList(&states, &out);
    try testing.expectEqualSlices(u8, "Reader 00\x00Reader 02\x00", out[0..written]);
}

test "a machine with no reader writes no bytes rather than one empty name" {
    // The state of the box this was written on. A zero here reads as an empty
    // list through `ReaderList`, and a single zero byte would read as a reader
    // whose name is nothing.
    const states: [readers_state_len]u8 = @splat(0);
    var out: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try writeReaderList(&states, &out));
}

test "a reader name stops at its zero byte and not at the end of the field" {
    // The field is 128 bytes whatever the name is. Reading all of it would give
    // a name with 119 trailing zeros in it, which connects to nothing.
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
    // The four fields the daemon reads. A build that left the protocol mask at
    // zero would be told the card supports nothing.
    const body = try encodeConnect(0x12345678, "Reader 00");
    try testing.expectEqual(@as(u32, 0x12345678), std.mem.readInt(u32, body[0..4], endian));
    try testing.expectEqualStrings("Reader 00", std.mem.sliceTo(body[4..132], 0));
    try testing.expectEqual(share_shared, std.mem.readInt(u32, body[132..136], endian));
    try testing.expectEqual(protocol_any, std.mem.readInt(u32, body[136..140], endian));
}

test "a connect answer is read from the offsets the request left empty" {
    // The three fields the daemon fills in. Reading `rv` from the wrong offset
    // would read the active protocol and call every failure a success.
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
    // The enum is open, so a code nobody named here reads back as itself and a
    // diagnostic can print it. Turning it into a named neighbour would tell a
    // person the wrong thing about their reader.
    const unnamed: Return = @enumFromInt(0x8010004d);
    try testing.expectEqual(@as(u32, 0x8010004d), @intFromEnum(unnamed));
    try testing.expect(unnamed != .success);
}

test "the sizes this driver frames its messages with" {
    // Every one of these is a length the daemon compares against and closes the
    // connection over: see `READ_BODY` in `winscard_svc.c`. They are stated
    // here so a change to a layout above fails a test rather than a daemon.
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
