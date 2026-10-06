//! Attestation: what makes "the key is on a card" provable instead of claimed.

const std = @import("std");
const tlv = @import("tlv.zig");
const Certificate = std.crypto.Certificate;

pub const public_key_len = 65;

pub const max_chain_len = 4;

pub const Verdict = enum {
    absent,
    no_root,
    malformed,
    key_mismatch,
    expired,
    untrusted,
    bound,
};

pub fn read(
    certs: []const []const u8,
    key: []const u8,
    root: ?[]const u8,
    now_sec: i64,
) Verdict {
    if (certs.len == 0) return .absent;
    if (certs.len > max_chain_len) return .malformed;
    const root_der = root orelse return .no_root;

    const leaf = parse(certs[0]) catch return .malformed;
    switch (leaf.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| if (curve != .X9_62_prime256v1) return .key_mismatch,
        else => return .key_mismatch,
    }
    if (key.len != public_key_len) return .key_mismatch;
    if (!std.mem.eql(u8, leaf.pubKey(), key)) return .key_mismatch;

    const trusted = parse(root_der) catch return .malformed;

    var subject = leaf;
    for (certs[1..]) |issuer_der| {
        const issuer = parse(issuer_der) catch return .malformed;
        if (link(subject, issuer, now_sec)) |verdict| return verdict;
        subject = issuer;
    }
    if (link(subject, trusted, now_sec)) |verdict| return verdict;
    return .bound;
}

pub const KeyError = error{
    CertificateUnreadable,
    KeyUnsupported,
};

pub fn publicKeyOf(der: []const u8) KeyError![public_key_len]u8 {
    const parsed = parse(der) catch return error.CertificateUnreadable;
    switch (parsed.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| if (curve != .X9_62_prime256v1) return error.KeyUnsupported,
        else => return error.KeyUnsupported,
    }
    const bytes = parsed.pubKey();
    if (bytes.len != public_key_len or bytes[0] != 0x04) return error.KeyUnsupported;
    return bytes[0..public_key_len].*;
}

fn parse(der: []const u8) !Certificate.Parsed {
    if (!safeToParse(der)) return error.CertificateUnsafeToParse;
    const certificate = Certificate{ .buffer = der, .index = 0 };
    return certificate.parse();
}

const max_depth = 24;

const max_children = 12;

const sequence_tag: tlv.Tag = 0x30;
const bitstring_tag: tlv.Tag = 0x03;
const context_zero_tag: tlv.Tag = 0xa0;

pub fn safeToParse(der: []const u8) bool {
    const top = tlv.read(der) catch return false;
    if (top.tag != sequence_tag) return false;
    if (top.encoded_len != der.len) return false;
    if (!tiles(top.value, max_depth)) return false;

    var outer: [max_children]tlv.Element = undefined;
    const outer_count = childrenOf(top.value, &outer) orelse return false;
    // A certificate parses to exactly three elements: the body, the signature algorithm, and the signature. The standard library reads at the start of the third one.
    if (outer_count != 3) return false;
    if (outer[0].tag != sequence_tag) return false;
    if (outer[1].tag != sequence_tag) return false;
    if (!hasChild(outer[1].value)) return false;
    if (outer[2].tag != bitstring_tag or outer[2].value.len == 0) return false;

    var body: [max_children]tlv.Element = undefined;
    const body_count = childrenOf(outer[0].value, &body) orelse return false;
    const base: usize = if (body_count != 0 and body[0].tag == context_zero_tag) 1 else 0;
    if (body_count < base + 6) return false;

    const validity = body[base + 3];
    var window: [max_children]tlv.Element = undefined;
    const window_count = childrenOf(validity.value, &window) orelse return false;
    if (window_count < 2) return false;

    const public_key_info = body[base + 5];
    var spki: [max_children]tlv.Element = undefined;
    const spki_count = childrenOf(public_key_info.value, &spki) orelse return false;
    if (spki_count < 2) return false;
    if (spki[0].tag != sequence_tag or !hasChild(spki[0].value)) return false;
    if (spki[1].tag != bitstring_tag or spki[1].value.len == 0) return false;

    return true;
}

fn tiles(bytes: []const u8, depth: usize) bool {
    var pos: usize = 0;
    while (pos < bytes.len) {
        const element = tlv.read(bytes[pos..]) catch return false;
        if (isConstructed(element.tag) and element.value.len != 0) {
            if (depth == 0) return false;
            if (!tiles(element.value, depth - 1)) return false;
        }
        pos += element.encoded_len;
    }
    return true;
}

fn childrenOf(bytes: []const u8, out: *[max_children]tlv.Element) ?usize {
    var reader = tlv.Reader.init(bytes);
    var count: usize = 0;
    while (reader.next() catch return null) |element| {
        if (count == max_children) return null;
        out[count] = element;
        count += 1;
    }
    return count;
}

fn hasChild(bytes: []const u8) bool {
    var reader = tlv.Reader.init(bytes);
    const first = reader.next() catch return false;
    return first != null;
}

fn isConstructed(tag: tlv.Tag) bool {
    var first = tag;
    while (first > 0xff) first >>= 8;
    return first & 0x20 != 0;
}

fn link(subject: Certificate.Parsed, issuer: Certificate.Parsed, now_sec: i64) ?Verdict {
    subject.verify(issuer, now_sec) catch |err| return switch (err) {
        error.CertificateNotYetValid, error.CertificateExpired => .expired,
        else => .untrusted,
    };
    return null;
}

const testing = std.testing;

test "no certificates is absent, and absent is never a weaker yes" {
    const key = [_]u8{0x04} ++ [_]u8{0x11} ** 64;
    try testing.expectEqual(Verdict.absent, read(&.{}, &key, null, 0));
    try testing.expectEqual(Verdict.absent, read(&.{}, &key, "root der", 0));
}

test "a reader with no root proves nothing, and never trusts everything" {
    const key = [_]u8{0x04} ++ [_]u8{0x11} ** 64;
    try testing.expectEqual(Verdict.no_root, read(&.{"not really a certificate"}, &key, null, 0));
}

test "a chain longer than the bound is refused before anything is parsed" {
    const key = [_]u8{0x04} ++ [_]u8{0x11} ** 64;
    const too_many = [_][]const u8{"x"} ** (max_chain_len + 1);
    try testing.expectEqual(Verdict.malformed, read(&too_many, &key, "root", 0));
}

test "bytes that are not a certificate are malformed, never untrusted" {
    const key = [_]u8{0x04} ++ [_]u8{0x11} ** 64;
    try testing.expectEqual(
        Verdict.malformed,
        read(&.{"this is not DER at all"}, &key, "nor is this", 0),
    );
}

test "only bound says the key lives in hardware" {
    const answers = [_]Verdict{ .absent, .no_root, .malformed, .key_mismatch, .expired, .untrusted };
    for (answers) |answer| try testing.expect(answer != .bound);
}

test {
    testing.refAllDecls(@This());
}
