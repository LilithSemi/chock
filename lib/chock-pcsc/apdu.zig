//! ISO 7816-4 application protocol data units: the frame every smart card
//! command and every smart card answer takes.
//!
//! This file holds no card knowledge and no PC/SC knowledge. It builds the
//! bytes of a command and it reads the bytes of an answer. `piv.zig` says what
//! those bytes mean, and `../chock-pcsc.zig` moves them to a card.
//!
//! ## Short form only, and why that is enough
//!
//! ISO 7816-4 has two command forms. The short form gives one byte to the
//! length of the sent data and one byte to the length of the expected answer.
//! The extended form gives three bytes to each. **This file writes the short
//! form only, and refuses data it cannot fit.**
//!
//! Every command Chock sends to a PIV card fits: the largest is a
//! `GENERAL AUTHENTICATE` that carries a 32 byte digest inside two nested TLV
//! headers, which is under 50 bytes. Answers are larger than 256 bytes, because
//! a certificate is, and the card cuts those into pieces itself with `61 XX`
//! and `GET RESPONSE`. See `Status.moreData` and `get_response_ins`.
//!
//! An extended form written here and never sent would be untested code on the
//! path that signs. A refusal that names the limit is the honest answer, and
//! `error.DataTooLong` is that refusal.

const std = @import("std");

/// The `INS` byte of `GET RESPONSE`, ISO 7816-4 section 11.3.1. A card that
/// answers `61 XX` is holding `XX` more bytes for the caller to ask for.
pub const get_response_ins: u8 = 0xc0;

/// The largest data field a short form command can carry. One byte of length
/// means 255 bytes at most, and a zero `Lc` is written as no `Lc` at all.
pub const max_command_data = 255;

/// The largest answer one exchange can return, without the two status bytes. A
/// short form `Le` of zero asks for 256, which is the whole range one byte of
/// length can name.
pub const max_response_data = 256;

/// The two status bytes a card ends every answer with.
///
/// **Kept as two bytes, never folded into a boolean.** `6a 82` (the object is
/// not there) and `69 82` (the PIN was never given) are different facts that a
/// caller acts on differently, and a card is free to answer with a status this
/// build has never seen.
pub const Status = struct {
    sw1: u8,
    sw2: u8,

    /// The two bytes as one number, `SW1` high. This is the form the ISO and
    /// NIST tables print, so it is the form a reader can look up.
    pub fn value(self: Status) u16 {
        return (@as(u16, self.sw1) << 8) | self.sw2;
    }

    /// `90 00`, and nothing else. A card that answers `61 XX` has more to give
    /// and has not finished, so that is not success here.
    pub fn ok(self: Status) bool {
        return self.value() == 0x9000;
    }

    /// How many more bytes the card holds, when it answers `61 XX`. Null when
    /// the answer is anything else.
    ///
    /// A card may answer `61 00`, which means 256 more bytes and not zero more,
    /// because the byte counts the same way a short form `Le` does. A caller
    /// that read this as zero would stop one exchange early and lose the tail
    /// of a certificate.
    pub fn moreData(self: Status) ?u16 {
        if (self.sw1 != 0x61) return null;
        return if (self.sw2 == 0) max_response_data else self.sw2;
    }

    /// How many bytes the card wants asked for, when it answers `6c XX`. The
    /// caller sends the same command again with this `Le`.
    pub fn wrongLength(self: Status) ?u16 {
        if (self.sw1 != 0x6c) return null;
        return if (self.sw2 == 0) max_response_data else self.sw2;
    }

    /// How many tries at the PIN are left, when the card answers `63 CX`. Null
    /// for any other status, which includes success.
    ///
    /// Zero tries left is a real answer and not an absent one: the card has
    /// blocked the PIN. `63 c0` is what that looks like on the wire, and some
    /// cards send `69 83` instead. See `blocked`.
    pub fn pinRetriesLeft(self: Status) ?u4 {
        if (self.sw1 != 0x63) return null;
        if (self.sw2 & 0xf0 != 0xc0) return null;
        return @truncate(self.sw2 & 0x0f);
    }

    /// The PIN is blocked and no further try will be taken.
    pub fn blocked(self: Status) bool {
        return self.value() == 0x6983 or self.pinRetriesLeft() == 0;
    }

    /// The card refused because the PIN was never given, or the key needs a
    /// touch that did not come. ISO 7816-4 calls this "security status not
    /// satisfied".
    pub fn securityNotSatisfied(self: Status) bool {
        return self.value() == 0x6982;
    }

    /// There is nothing in the object or the file that was named.
    pub fn notFound(self: Status) bool {
        return self.value() == 0x6a82;
    }
};

/// Why a command could not be turned into bytes.
pub const EncodeError = error{
    /// The data field is longer than the short form can name. See this file's
    /// own top comment on why the extended form is not written here.
    DataTooLong,
    /// More than 256 bytes were asked for in one exchange. A caller that wants
    /// more asks again after `61 XX`.
    ExpectedTooLong,
    /// The buffer the caller gave is smaller than the command needs.
    BufferTooSmall,
};

/// One command, before it becomes bytes.
pub const Command = struct {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: []const u8 = &.{},
    /// How many bytes of answer to ask for. Null writes no `Le` field at all,
    /// which is the right form for a command that returns only a status.
    /// 256 is written as the byte zero, which is what the short form means by
    /// it.
    expect: ?u16 = null,

    /// The largest number of bytes `encode` can write: the four header bytes,
    /// one length byte, the whole data field, and one expected length byte.
    pub const max_encoded_len = 4 + 1 + max_command_data + 1;

    /// Write this command into `out` and answer the part of `out` that was
    /// used.
    pub fn encode(self: Command, out: []u8) EncodeError![]u8 {
        if (self.data.len > max_command_data) return error.DataTooLong;
        if (self.expect) |e| {
            if (e > max_response_data or e == 0) return error.ExpectedTooLong;
        }

        var len: usize = 4;
        if (self.data.len != 0) len += 1 + self.data.len;
        if (self.expect != null) len += 1;
        if (out.len < len) return error.BufferTooSmall;

        out[0] = self.cla;
        out[1] = self.ins;
        out[2] = self.p1;
        out[3] = self.p2;
        var pos: usize = 4;
        if (self.data.len != 0) {
            out[pos] = @intCast(self.data.len);
            pos += 1;
            @memcpy(out[pos..][0..self.data.len], self.data);
            pos += self.data.len;
        }
        if (self.expect) |e| {
            // 256 is the byte zero. The short form has no other way to name
            // the whole range one byte of length can hold.
            out[pos] = if (e == max_response_data) 0 else @intCast(e);
            pos += 1;
        }
        return out[0..pos];
    }
};

/// One answer, after it stops being bytes. `data` points into the buffer the
/// caller gave the transport, so it lives exactly as long as that buffer.
pub const Response = struct {
    data: []const u8,
    status: Status,
};

/// Why an answer could not be read.
pub const DecodeError = error{
    /// Fewer than two bytes came back. Every answer ends with a status word,
    /// so an answer shorter than that is a broken exchange and never an empty
    /// one.
    TooShort,
};

/// Split a card's answer into its data and its status word.
pub fn decode(bytes: []const u8) DecodeError!Response {
    if (bytes.len < 2) return error.TooShort;
    return .{
        .data = bytes[0 .. bytes.len - 2],
        .status = .{ .sw1 = bytes[bytes.len - 2], .sw2 = bytes[bytes.len - 1] },
    };
}

/// The `GET RESPONSE` command for a card that answered `61 XX`. `count` is what
/// `Status.moreData` gave.
pub fn getResponse(cla: u8, count: u16) Command {
    return .{ .cla = cla, .ins = get_response_ins, .p1 = 0, .p2 = 0, .expect = count };
}

const testing = std.testing;

test "a command with no data and no expected answer is four bytes and nothing else" {
    // The shortest legal form. A stray zero length byte here would make the
    // card read the next command's first byte as this command's data.
    var buffer: [Command.max_encoded_len]u8 = undefined;
    const bytes = try (Command{ .cla = 0x00, .ins = 0x20, .p1 = 0x00, .p2 = 0x80 }).encode(&buffer);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x20, 0x00, 0x80 }, bytes);
}

test "a data field is written with its own length in front of it" {
    var buffer: [Command.max_encoded_len]u8 = undefined;
    const bytes = try (Command{
        .cla = 0x00,
        .ins = 0xa4,
        .p1 = 0x04,
        .p2 = 0x00,
        .data = &.{ 0xa0, 0x00, 0x00 },
        .expect = 256,
    }).encode(&buffer);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xa4, 0x04, 0x00, 0x03, 0xa0, 0x00, 0x00, 0x00 }, bytes);
}

test "an expected length of 256 is written as the byte zero, and 255 as itself" {
    // The one place the short form is not a plain number. A build that wrote
    // 256 as 0xff would read one byte short of every certificate.
    var buffer: [Command.max_encoded_len]u8 = undefined;
    const whole = try (Command{ .cla = 0, .ins = 0xc0, .p1 = 0, .p2 = 0, .expect = 256 }).encode(&buffer);
    try testing.expectEqual(@as(u8, 0x00), whole[4]);

    const almost = try (Command{ .cla = 0, .ins = 0xc0, .p1 = 0, .p2 = 0, .expect = 255 }).encode(&buffer);
    try testing.expectEqual(@as(u8, 0xff), almost[4]);
}

test "data longer than the short form can name is refused, never cut short" {
    // The honest refusal this file's top comment argues for. A cut down command
    // would be a different command, and the card would sign the wrong thing.
    var buffer: [512]u8 = undefined;
    const too_much = [_]u8{0} ** (max_command_data + 1);
    try testing.expectError(
        error.DataTooLong,
        (Command{ .cla = 0, .ins = 0, .p1 = 0, .p2 = 0, .data = &too_much }).encode(&buffer),
    );
}

test "an expected length above 256, or of zero, is refused" {
    var buffer: [Command.max_encoded_len]u8 = undefined;
    try testing.expectError(
        error.ExpectedTooLong,
        (Command{ .cla = 0, .ins = 0, .p1 = 0, .p2 = 0, .expect = 257 }).encode(&buffer),
    );
    // Zero is refused rather than written, because the byte zero already means
    // 256 on the wire. A caller that wants no answer leaves `expect` null.
    try testing.expectError(
        error.ExpectedTooLong,
        (Command{ .cla = 0, .ins = 0, .p1 = 0, .p2 = 0, .expect = 0 }).encode(&buffer),
    );
}

test "a buffer one byte short is refused rather than written past" {
    var buffer: [8]u8 = undefined;
    try testing.expectError(
        error.BufferTooSmall,
        (Command{ .cla = 0, .ins = 0, .p1 = 0, .p2 = 0, .data = &.{ 1, 2, 3 }, .expect = 1 }).encode(buffer[0..8]),
    );
}

test "an answer splits into its data and the two status bytes that end it" {
    const response = try decode(&.{ 0xde, 0xad, 0x90, 0x00 });
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad }, response.data);
    try testing.expect(response.status.ok());
    try testing.expectEqual(@as(u16, 0x9000), response.status.value());

    // A bare status word is a whole answer with no data in it.
    const bare = try decode(&.{ 0x69, 0x82 });
    try testing.expectEqual(@as(usize, 0), bare.data.len);
    try testing.expect(bare.status.securityNotSatisfied());
}

test "an answer shorter than a status word is a broken exchange" {
    try testing.expectError(error.TooShort, decode(&.{0x90}));
    try testing.expectError(error.TooShort, decode(&.{}));
}

test "61 00 means 256 more bytes, never no more bytes" {
    // The off by one that loses the tail of a certificate. `61 00` is the
    // status a card sends when exactly 256 bytes are still waiting.
    const all = Status{ .sw1 = 0x61, .sw2 = 0x00 };
    try testing.expectEqual(@as(?u16, 256), all.moreData());

    const some = Status{ .sw1 = 0x61, .sw2 = 0x2f };
    try testing.expectEqual(@as(?u16, 0x2f), some.moreData());

    // And a card that has finished says so with a different byte entirely.
    try testing.expectEqual(@as(?u16, null), (Status{ .sw1 = 0x90, .sw2 = 0x00 }).moreData());
}

test "61 XX is not success, so a reader cannot stop on it" {
    // A build that took any non error status for success would keep the first
    // 256 bytes of a certificate and throw the rest away.
    const more = Status{ .sw1 = 0x61, .sw2 = 0x10 };
    try testing.expect(!more.ok());
}

test "6c XX names the length to ask for again" {
    const retry = Status{ .sw1 = 0x6c, .sw2 = 0x08 };
    try testing.expectEqual(@as(?u16, 8), retry.wrongLength());
    try testing.expectEqual(@as(?u16, null), retry.moreData());
}

test "63 CX counts the PIN tries left, and zero of them is blocked" {
    const two_left = Status{ .sw1 = 0x63, .sw2 = 0xc2 };
    try testing.expectEqual(@as(?u4, 2), two_left.pinRetriesLeft());
    try testing.expect(!two_left.blocked());

    const none_left = Status{ .sw1 = 0x63, .sw2 = 0xc0 };
    try testing.expectEqual(@as(?u4, 0), none_left.pinRetriesLeft());
    try testing.expect(none_left.blocked());

    // 69 83 is the other spelling of blocked, which some cards use instead.
    try testing.expect((Status{ .sw1 = 0x69, .sw2 = 0x83 }).blocked());

    // A `63` that is not a `63 CX` carries no count. Reading a count out of it
    // would report a number the card never sent.
    try testing.expectEqual(@as(?u4, null), (Status{ .sw1 = 0x63, .sw2 = 0x00 }).pinRetriesLeft());
    // Success carries no count either.
    try testing.expectEqual(@as(?u4, null), (Status{ .sw1 = 0x90, .sw2 = 0x00 }).pinRetriesLeft());
}

test "a status this build does not know keeps both of its bytes" {
    // A card is an external device. An unknown answer is reported as itself
    // rather than folded into a pass or a fail.
    const strange = Status{ .sw1 = 0x6f, .sw2 = 0x1a };
    try testing.expect(!strange.ok());
    try testing.expectEqual(@as(u16, 0x6f1a), strange.value());
    try testing.expectEqual(@as(?u16, null), strange.moreData());
    try testing.expectEqual(@as(?u4, null), strange.pinRetriesLeft());
    try testing.expect(!strange.blocked());
}

test "a GET RESPONSE keeps the class byte of the command it follows" {
    // A card that got a command with a secure messaging class byte answers a
    // GET RESPONSE with the same class. Sending 0x00 there would break the
    // session on such a card.
    const command = getResponse(0x0c, 0x20);
    try testing.expectEqual(@as(u8, 0x0c), command.cla);
    try testing.expectEqual(get_response_ins, command.ins);
    try testing.expectEqual(@as(?u16, 0x20), command.expect);
}

test {
    testing.refAllDecls(@This());
}
