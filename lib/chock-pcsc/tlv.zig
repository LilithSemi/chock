//! BER-TLV, the tag, length and value form a PIV card wraps every data object

const std = @import("std");

pub const Tag = u32;

pub const max_length_bytes = 3;

pub const max_tag_bytes = 3;

pub const Error = error{
    Truncated,
    LengthUnsupported,
    TagUnsupported,
};

pub const Element = struct {
    tag: Tag,
    value: []const u8,
    encoded_len: usize,
};

pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    pub fn next(self: *Reader) Error!?Element {
        if (self.pos >= self.bytes.len) return null;
        const element = try read(self.bytes[self.pos..]);
        self.pos += element.encoded_len;
        return element;
    }

    pub fn find(self: *Reader, tag: Tag) Error!?[]const u8 {
        while (try self.next()) |element| {
            if (element.tag == tag) return element.value;
        }
        return null;
    }
};

pub fn read(bytes: []const u8) Error!Element {
    if (bytes.len == 0) return error.Truncated;

    // ISO 7816-4 5.2.2.1: when the low five bits of the first byte are all set, the tag continues into the bytes after it, each one continuing while its own top bit is set.
    var pos: usize = 1;
    var tag: Tag = bytes[0];
    if (bytes[0] & 0x1f == 0x1f) {
        while (true) {
            if (pos >= bytes.len) return error.Truncated;
            if (pos >= max_tag_bytes) return error.TagUnsupported;
            const byte = bytes[pos];
            tag = (tag << 8) | byte;
            pos += 1;
            if (byte & 0x80 == 0) break;
        }
    }

    if (pos >= bytes.len) return error.Truncated;
    const first_length = bytes[pos];
    pos += 1;
    var length: usize = 0;
    if (first_length & 0x80 == 0) {
        length = first_length;
    } else {
        const count = first_length & 0x7f;
        if (count == 0 or count > 2) return error.LengthUnsupported;
        if (pos + count > bytes.len) return error.Truncated;
        for (bytes[pos..][0..count]) |byte| length = (length << 8) | byte;
        pos += count;
    }

    if (pos + length > bytes.len) return error.Truncated;
    return .{
        .tag = tag,
        .value = bytes[pos..][0..length],
        .encoded_len = pos + length,
    };
}

const testing = std.testing;

test "a one byte tag with a short length reads its value" {
    const element = try read(&.{ 0x70, 0x03, 0xaa, 0xbb, 0xcc });
    try testing.expectEqual(@as(Tag, 0x70), element.tag);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, element.value);
    try testing.expectEqual(@as(usize, 5), element.encoded_len);
}

test "a three byte tag keeps its bytes in wire order" {
    const element = try read(&.{ 0x5f, 0xc1, 0x05, 0x01, 0x42 });
    try testing.expectEqual(@as(Tag, 0x5fc105), element.tag);
    try testing.expectEqualSlices(u8, &.{0x42}, element.value);

    const other = try read(&.{ 0x5f, 0xc1, 0x0a, 0x01, 0x42 });
    try testing.expectEqual(@as(Tag, 0x5fc10a), other.tag);
    try testing.expect(element.tag != other.tag);
}

test "a two byte length reads a value longer than 255 bytes" {
    var bytes: [4 + 300]u8 = undefined;
    bytes[0] = 0x70;
    bytes[1] = 0x82;
    bytes[2] = 0x01;
    bytes[3] = 0x2c;
    @memset(bytes[4..], 0x5a);
    const element = try read(&bytes);
    try testing.expectEqual(@as(usize, 300), element.value.len);
    try testing.expectEqual(@as(usize, 304), element.encoded_len);
}

test "a one byte long length is read, and 0x81 0x00 is a real empty value" {
    const element = try read(&.{ 0x70, 0x81, 0x02, 0x01, 0x02 });
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, element.value);

    const empty = try read(&.{ 0x70, 0x81, 0x00 });
    try testing.expectEqual(@as(usize, 0), empty.value.len);
    try testing.expectEqual(@as(usize, 3), empty.encoded_len);
}

test "a length that runs past the end of the buffer is refused" {
    try testing.expectError(error.Truncated, read(&.{ 0x70, 0x10, 0x01 }));
    try testing.expectError(error.Truncated, read(&.{ 0x70, 0x82, 0xff }));
    try testing.expectError(error.Truncated, read(&.{0x70}));
    try testing.expectError(error.Truncated, read(&.{}));
    try testing.expectError(error.Truncated, read(&.{ 0x5f, 0xc1 }));
}

test "the indefinite length form and an over long length are refused" {
    try testing.expectError(error.LengthUnsupported, read(&.{ 0x70, 0x80, 0x01 }));
    try testing.expectError(error.LengthUnsupported, read(&.{ 0x70, 0x83, 0x01, 0x00, 0x00 }));
}

test "a tag longer than three bytes is refused rather than cut down" {
    try testing.expectError(error.TagUnsupported, read(&.{ 0x5f, 0xc1, 0x81, 0x05, 0x00 }));
}

test "a reader walks a sequence and stops at its end" {
    var reader = Reader.init(&.{ 0x71, 0x01, 0x00, 0xfe, 0x00, 0x70, 0x02, 0xab, 0xcd });
    const first = (try reader.next()).?;
    try testing.expectEqual(@as(Tag, 0x71), first.tag);
    const second = (try reader.next()).?;
    try testing.expectEqual(@as(Tag, 0xfe), second.tag);
    try testing.expectEqual(@as(usize, 0), second.value.len);
    const third = (try reader.next()).?;
    try testing.expectEqual(@as(Tag, 0x70), third.tag);
    try testing.expectEqualSlices(u8, &.{ 0xab, 0xcd }, third.value);
    try testing.expectEqual(@as(?Element, null), try reader.next());
}

test "find answers the value of a tag at this level, and nothing for one nested inside" {
    const object = [_]u8{ 0x53, 0x05, 0x70, 0x02, 0xab, 0xcd, 0x00 };
    var top = Reader.init(&object);
    try testing.expectEqual(@as(?[]const u8, null), try top.find(0x70));

    var again = Reader.init(&object);
    const inner_bytes = (try again.find(0x53)).?;
    var inner = Reader.init(inner_bytes);
    try testing.expectEqualSlices(u8, &.{ 0xab, 0xcd }, (try inner.find(0x70)).?);
}

test {
    testing.refAllDecls(@This());
}
