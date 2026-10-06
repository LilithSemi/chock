//! ISO 7816-4 application protocol data units: the frame every smart card

const std = @import("std");

pub const get_response_ins: u8 = 0xc0;

pub const max_command_data = 255;

pub const max_response_data = 256;

pub const Status = struct {
    sw1: u8,
    sw2: u8,

    pub fn value(self: Status) u16 {
        return (@as(u16, self.sw1) << 8) | self.sw2;
    }

    pub fn ok(self: Status) bool {
        return self.value() == 0x9000;
    }

    pub fn moreData(self: Status) ?u16 {
        if (self.sw1 != 0x61) return null;
        return if (self.sw2 == 0) max_response_data else self.sw2;
    }

    pub fn wrongLength(self: Status) ?u16 {
        if (self.sw1 != 0x6c) return null;
        return if (self.sw2 == 0) max_response_data else self.sw2;
    }

    pub fn pinRetriesLeft(self: Status) ?u4 {
        if (self.sw1 != 0x63) return null;
        if (self.sw2 & 0xf0 != 0xc0) return null;
        return @truncate(self.sw2 & 0x0f);
    }

    pub fn blocked(self: Status) bool {
        return self.value() == 0x6983 or self.pinRetriesLeft() == 0;
    }

    pub fn securityNotSatisfied(self: Status) bool {
        return self.value() == 0x6982;
    }

    pub fn notFound(self: Status) bool {
        return self.value() == 0x6a82;
    }
};

pub const EncodeError = error{
    DataTooLong,
    ExpectedTooLong,
    BufferTooSmall,
};

pub const Command = struct {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: []const u8 = &.{},
    expect: ?u16 = null,

    pub const max_encoded_len = 4 + 1 + max_command_data + 1;

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
            // 256 is written as the byte zero: the short form has no other way to name the whole range one byte of length can hold.
            out[pos] = if (e == max_response_data) 0 else @intCast(e);
            pos += 1;
        }
        return out[0..pos];
    }
};

pub const Response = struct {
    data: []const u8,
    status: Status,
};

pub const DecodeError = error{
    TooShort,
};

pub fn decode(bytes: []const u8) DecodeError!Response {
    if (bytes.len < 2) return error.TooShort;
    return .{
        .data = bytes[0 .. bytes.len - 2],
        .status = .{ .sw1 = bytes[bytes.len - 2], .sw2 = bytes[bytes.len - 1] },
    };
}

pub fn getResponse(cla: u8, count: u16) Command {
    return .{ .cla = cla, .ins = get_response_ins, .p1 = 0, .p2 = 0, .expect = count };
}

const testing = std.testing;

test "a command with no data and no expected answer is four bytes and nothing else" {
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
    var buffer: [Command.max_encoded_len]u8 = undefined;
    const whole = try (Command{ .cla = 0, .ins = 0xc0, .p1 = 0, .p2 = 0, .expect = 256 }).encode(&buffer);
    try testing.expectEqual(@as(u8, 0x00), whole[4]);

    const almost = try (Command{ .cla = 0, .ins = 0xc0, .p1 = 0, .p2 = 0, .expect = 255 }).encode(&buffer);
    try testing.expectEqual(@as(u8, 0xff), almost[4]);
}

test "data longer than the short form can name is refused, never cut short" {
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

    const bare = try decode(&.{ 0x69, 0x82 });
    try testing.expectEqual(@as(usize, 0), bare.data.len);
    try testing.expect(bare.status.securityNotSatisfied());
}

test "an answer shorter than a status word is a broken exchange" {
    try testing.expectError(error.TooShort, decode(&.{0x90}));
    try testing.expectError(error.TooShort, decode(&.{}));
}

test "61 00 means 256 more bytes, never no more bytes" {
    const all = Status{ .sw1 = 0x61, .sw2 = 0x00 };
    try testing.expectEqual(@as(?u16, 256), all.moreData());

    const some = Status{ .sw1 = 0x61, .sw2 = 0x2f };
    try testing.expectEqual(@as(?u16, 0x2f), some.moreData());

    try testing.expectEqual(@as(?u16, null), (Status{ .sw1 = 0x90, .sw2 = 0x00 }).moreData());
}

test "61 XX is not success, so a reader cannot stop on it" {
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

    try testing.expect((Status{ .sw1 = 0x69, .sw2 = 0x83 }).blocked());

    try testing.expectEqual(@as(?u4, null), (Status{ .sw1 = 0x63, .sw2 = 0x00 }).pinRetriesLeft());
    try testing.expectEqual(@as(?u4, null), (Status{ .sw1 = 0x90, .sw2 = 0x00 }).pinRetriesLeft());
}

test "a status this build does not know keeps both of its bytes" {
    const strange = Status{ .sw1 = 0x6f, .sw2 = 0x1a };
    try testing.expect(!strange.ok());
    try testing.expectEqual(@as(u16, 0x6f1a), strange.value());
    try testing.expectEqual(@as(?u16, null), strange.moreData());
    try testing.expectEqual(@as(?u4, null), strange.pinRetriesLeft());
    try testing.expect(!strange.blocked());
}

test "a GET RESPONSE keeps the class byte of the command it follows" {
    const command = getResponse(0x0c, 0x20);
    try testing.expectEqual(@as(u8, 0x0c), command.cla);
    try testing.expectEqual(get_response_ins, command.ins);
    try testing.expectEqual(@as(?u16, 0x20), command.expect);
}

test {
    testing.refAllDecls(@This());
}
