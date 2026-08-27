//! BER-TLV, the tag, length and value form a PIV card wraps every data object
//! in. See NIST SP 800-73-4 part 1 appendix A, which gives the tags, and
//! ISO 7816-4 section 5.2.2, which gives the encoding.
//!
//! ## Why this is not `std.crypto.Certificate.der`
//!
//! The standard library has a DER reader, and this file does not use it.
//! DER is one shape of BER with the loose parts removed. PIV objects use the
//! loose parts: a three byte tag such as `5F C1 05`, and a length written in
//! one, two or three bytes. `std.crypto.Certificate.der.Element` reads what an
//! X.509 certificate needs and answers a `Slice` into a `Certificate`, which is
//! a type this layer has no reason to build. The certificate **inside** a PIV
//! object is still read by the standard library: see `attestation.zig`.

const std = @import("std");

/// A tag, packed into one number with its bytes in the order they sit on the
/// wire. `5F C1 05` becomes `0x5fc105`. Three bytes is the longest tag PIV
/// uses, so a `u32` holds every one of them and the packing loses nothing.
pub const Tag = u32;

/// The longest length field this reader accepts: `82` and two bytes, which
/// names up to 65535. PIV has no object larger than that, and refusing the
/// longer forms keeps a hostile length from naming a range no buffer can hold.
pub const max_length_bytes = 3;

/// The longest tag this reader accepts, in bytes. Three is what `Tag` can hold
/// without losing a byte, and three is the longest tag PIV uses.
pub const max_tag_bytes = 3;

pub const Error = error{
    /// The bytes ended in the middle of a tag, a length, or a value.
    Truncated,
    /// A length field longer than `max_length_bytes`, or the indefinite form,
    /// which a card must not use for a PIV object.
    LengthUnsupported,
    /// A tag longer than three bytes.
    TagUnsupported,
};

/// One tag, length and value, and how many bytes all three took together.
pub const Element = struct {
    tag: Tag,
    value: []const u8,
    /// The whole element, tag and length included. A caller walking a sequence
    /// steps by this and not by `value.len`.
    encoded_len: usize,
};

/// Walks a sequence of elements. Holds a position and nothing else, so it
/// allocates nothing and can be copied freely.
pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    /// The next element, or null when the bytes are used up.
    pub fn next(self: *Reader) Error!?Element {
        if (self.pos >= self.bytes.len) return null;
        const element = try read(self.bytes[self.pos..]);
        self.pos += element.encoded_len;
        return element;
    }

    /// The value of the first element with this tag, at this level only. Null
    /// when there is none. **This does not descend into a value**: a caller
    /// that wants a nested element makes a second `Reader` over the value it
    /// got back, which keeps the depth of a search visible at the call site
    /// rather than hidden in a walk of unknown depth.
    pub fn find(self: *Reader, tag: Tag) Error!?[]const u8 {
        while (try self.next()) |element| {
            if (element.tag == tag) return element.value;
        }
        return null;
    }
};

/// Read one element from the front of `bytes`.
pub fn read(bytes: []const u8) Error!Element {
    if (bytes.len == 0) return error.Truncated;

    // ISO 7816-4 section 5.2.2.1: when the low five bits of the first byte are
    // all set, the tag carries on into the bytes that follow, and each of those
    // keeps going while its top bit is set.
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
        // Zero is the indefinite form, which needs an end of contents marker
        // and has no place in a PIV object. Anything above two bytes names a
        // range larger than a card can hold.
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
    // 5F C1 05 is the PIV authentication certificate object, SP 800-73-4 part 1
    // table 6. A reader that dropped the continuation bytes would find the same
    // tag for every certificate object on the card.
    const element = try read(&.{ 0x5f, 0xc1, 0x05, 0x01, 0x42 });
    try testing.expectEqual(@as(Tag, 0x5fc105), element.tag);
    try testing.expectEqualSlices(u8, &.{0x42}, element.value);

    // And a different slot really is a different tag, which is the whole
    // reason the continuation bytes are kept.
    const other = try read(&.{ 0x5f, 0xc1, 0x0a, 0x01, 0x42 });
    try testing.expectEqual(@as(Tag, 0x5fc10a), other.tag);
    try testing.expect(element.tag != other.tag);
}

test "a two byte length reads a value longer than 255 bytes" {
    // A certificate is longer than one byte of length can name, so getting this
    // wrong makes every real card unreadable.
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
    // The whole reason this reader exists rather than a set of slice
    // arithmetic at each call site. A card, or somebody between the caller and
    // the card, can name any length at all.
    try testing.expectError(error.Truncated, read(&.{ 0x70, 0x10, 0x01 }));
    try testing.expectError(error.Truncated, read(&.{ 0x70, 0x82, 0xff }));
    try testing.expectError(error.Truncated, read(&.{0x70}));
    try testing.expectError(error.Truncated, read(&.{}));
    // A tag that says it carries on, and then does not.
    try testing.expectError(error.Truncated, read(&.{ 0x5f, 0xc1 }));
}

test "the indefinite length form and an over long length are refused" {
    // 0x80 is the indefinite form, which needs an end of contents marker this
    // reader does not look for. Accepting it would make the value run to the
    // end of the buffer, which is a different object.
    try testing.expectError(error.LengthUnsupported, read(&.{ 0x70, 0x80, 0x01 }));
    // Three bytes of length names more than any card holds.
    try testing.expectError(error.LengthUnsupported, read(&.{ 0x70, 0x83, 0x01, 0x00, 0x00 }));
}

test "a tag longer than three bytes is refused rather than cut down" {
    // Packing a longer tag into a u32 would drop its first byte, and two
    // different tags would then read as one.
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
    // The depth rule this reader keeps on purpose. Tag 0x70 below sits inside
    // the value of 0x53, so a search at the top level must not find it: a
    // caller that wants it opens a second reader over 0x53's value.
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
