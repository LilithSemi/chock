//! The seal: a signature over the head of a session log's hash chain.

const std = @import("std");
const attestation = @import("attestation.zig");
const tlv = @import("tlv.zig");

pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const rsa = std.crypto.Certificate.rsa;

pub const digest_hex_len = 64;

pub const public_key_len = Ecdsa.PublicKey.uncompressed_sec1_encoded_length;

pub const signature_len = Ecdsa.Signature.encoded_length;

pub const rsa_modulus_tag: tlv.Tag = 0x81;
pub const rsa_exponent_tag: tlv.Tag = 0x82;

pub const rsa2048_modulus_len = 256;

pub const max_public_key_len = 320;

pub const max_signature_len = rsa2048_modulus_len;

pub const Scheme = enum {
    ecdsa_p256,
    rsa2048,

    pub fn text(self: Scheme) []const u8 {
        return switch (self) {
            .ecdsa_p256 => "ECDSA P-256",
            .rsa2048 => "RSA2048",
        };
    }
};

pub const RsaParts = struct {
    modulus: []const u8,
    exponent: []const u8,
};

pub fn rsaParts(key: []const u8) ?RsaParts {
    var reader = tlv.Reader.init(key);
    const first = (reader.next() catch return null) orelse return null;
    if (first.tag != rsa_modulus_tag) return null;
    const second = (reader.next() catch return null) orelse return null;
    if (second.tag != rsa_exponent_tag) return null;
    if ((reader.next() catch return null) != null) return null;
    if (first.value.len == 0 or second.value.len == 0) return null;
    return .{ .modulus = first.value, .exponent = second.value };
}

pub fn schemeOf(key: []const u8) ?Scheme {
    if (key.len == public_key_len and key[0] == 0x04) return .ecdsa_p256;
    const parts = rsaParts(key) orelse return null;
    if (parts.modulus.len != rsa2048_modulus_len) return null;
    return .rsa2048;
}

pub const max_session_len = 128;

pub const max_attestation_certs = 4;

pub const max_certificate_len = 3072;

pub const domain = "chock-seal-v1\x00";

pub const format_version: u32 = 1;

pub const Level = enum(u8) {
    card_attested = 1,
    card = 2,
    software = 3,

    pub fn atLeast(self: Level, other: Level) bool {
        return @intFromEnum(self) <= @intFromEnum(other);
    }
};

pub const Seal = struct {
    version: u32 = format_version,
    session: []const u8,
    header: [digest_hex_len]u8,
    head: [digest_hex_len]u8,
    events: u64,
    level: Level,
    key: []const u8,
    signature: []const u8,
    attestation: []const []const u8 = &.{},
};

pub const max_canonical_len = domain.len + 4 + 1 +
    (8 + max_session_len) +
    (8 + digest_hex_len) +
    (8 + digest_hex_len) +
    8 +
    (8 + max_public_key_len);

pub const CanonicalError = error{
    SessionUnusable,
    DigestUnusable,
    KeyUnusable,
};

pub fn canonical(seal: Seal, out: *[max_canonical_len]u8) CanonicalError![]const u8 {
    if (seal.session.len == 0 or seal.session.len > max_session_len) return error.SessionUnusable;
    if (!isDigest(&seal.header) or !isDigest(&seal.head)) return error.DigestUnusable;
    if (seal.key.len == 0 or seal.key.len > max_public_key_len) return error.KeyUnusable;

    var pos: usize = 0;
    @memcpy(out[pos..][0..domain.len], domain);
    pos += domain.len;
    std.mem.writeInt(u32, out[pos..][0..4], seal.version, .big);
    pos += 4;
    out[pos] = @intFromEnum(seal.level);
    pos += 1;
    pos += writeField(out[pos..], seal.session);
    pos += writeField(out[pos..], &seal.header);
    pos += writeField(out[pos..], &seal.head);
    std.mem.writeInt(u64, out[pos..][0..8], seal.events, .big);
    pos += 8;
    pos += writeField(out[pos..], seal.key);
    return out[0..pos];
}

fn writeField(out: []u8, value: []const u8) usize {
    std.mem.writeInt(u64, out[0..8], value.len, .big);
    @memcpy(out[8..][0..value.len], value);
    return 8 + value.len;
}

pub fn isDigest(text: []const u8) bool {
    if (text.len != digest_hex_len) return false;
    for (text) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return false;
    }
    return true;
}

pub fn digestOf(seal: Seal) CanonicalError![Sha256.digest_length]u8 {
    var buffer: [max_canonical_len]u8 = undefined;
    const bytes = try canonical(seal, &buffer);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    return digest;
}

pub const SignError = error{
    Unusable,
} || CanonicalError || error{
    AttestationMissing,
    AttestationTooLong,
};

pub const Held = struct {
    key: [max_public_key_len]u8 = undefined,
    signature: [max_signature_len]u8 = undefined,
};

pub const Signer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        publicKey: *const fn (
            ptr: *anyopaque,
            out: *[max_public_key_len]u8,
        ) SignError![]const u8,
        signDigest: *const fn (
            ptr: *anyopaque,
            digest: [Sha256.digest_length]u8,
            out: *[max_signature_len]u8,
        ) SignError![]const u8,
        reason: ?*const fn (ptr: *anyopaque) ?[]const u8 = null,
    };

    pub fn reason(self: Signer) ?[]const u8 {
        const ask = self.vtable.reason orelse return null;
        return ask(self.ptr);
    }
};

pub const Request = struct {
    session: []const u8,
    header: [digest_hex_len]u8,
    head: [digest_hex_len]u8,
    events: u64,
    level: Level,
    attestation: []const []const u8 = &.{},
};

pub fn sign(request: Request, signer: Signer, held: *Held) SignError!Seal {
    if (request.level == .card_attested and request.attestation.len == 0)
        return error.AttestationMissing;
    if (request.attestation.len > max_attestation_certs) return error.AttestationTooLong;

    var seal = Seal{
        .session = request.session,
        .header = request.header,
        .head = request.head,
        .events = request.events,
        .level = request.level,
        .key = try signer.vtable.publicKey(signer.ptr, &held.key),
        .signature = &.{},
        .attestation = request.attestation,
    };
    seal.signature = try signer.vtable.signDigest(
        signer.ptr,
        try digestOf(seal),
        &held.signature,
    );
    return seal;
}

pub const Verdict = enum {
    absent,
    malformed,
    signature_bad,
    head_mismatch,
    signed_software,
    signed_card,
    signed_card_attested,
    claim_unsupported,
};

pub const Field = enum { session, header, head, events };

pub const Reading = struct {
    verdict: Verdict = .absent,
    claimed: ?Level = null,
    attestation: attestation.Verdict = .absent,
    mismatched: ?Field = null,
    scheme: ?Scheme = null,

    pub fn signed(self: Reading) bool {
        return switch (self.verdict) {
            .signed_software, .signed_card, .signed_card_attested => true,
            .absent, .malformed, .signature_bad, .head_mismatch, .claim_unsupported => false,
        };
    }

    pub fn hardwareProved(self: Reading) bool {
        return self.verdict == .signed_card_attested;
    }

    pub fn sentence(self: Reading) []const u8 {
        return switch (self.verdict) {
            .absent =>
            \\This log carries no seal, so nothing has signed it and nothing here can defeat a rewrite of the whole file.
            ,
            .malformed =>
            \\This log has a seal that could not be read at all, so nothing was checked. Read it as unsealed.
            ,
            .signature_bad =>
            \\This log's seal does not check out against the key it carries: somebody changed the seal, or that key never signed it.
            ,
            .head_mismatch =>
            \\This log's seal checks out and it is about a different log. A chain repaired by hand looks exactly like this.
            ,
            .signed_software =>
            \\This log is sealed with a software key, the weakest of the three levels: it proves one key signed and nothing about where that key lives.
            ,
            .signed_card =>
            \\This log is sealed with a key the record says lives on a card, and shows no attestation, so nothing here can check that claim.
            ,
            .signed_card_attested =>
            \\This log is sealed with a card key, and an attestation chaining to the trusted root says the key was made on that card and never left it.
            ,
            .claim_unsupported =>
            \\This log's seal claims a card made it and shows nothing that supports the claim. Read it as unsealed.
            ,
        };
    }
};

pub const defeats_a_rewrite =
    "A seal over the chain head is what a rewrite of the whole log cannot forge without the key. " ++
    "What that is worth is what the key is worth, which is the level on each row.";

pub const Expectation = struct {
    session: []const u8,
    header: []const u8,
    head: []const u8,
    events: u64,
};

pub const Trust = struct {
    root: ?[]const u8 = null,
    now_sec: i64,
};

pub fn read(seal: Seal, expect: Expectation, trust: Trust) Reading {
    if (seal.version != format_version) return .{ .verdict = .malformed };
    var buffer: [max_canonical_len]u8 = undefined;
    const bytes = canonical(seal, &buffer) catch return .{ .verdict = .malformed };

    const scheme = schemeOf(seal.key) orelse return .{ .verdict = .malformed };
    switch (scheme) {
        .ecdsa_p256 => {
            if (seal.signature.len != signature_len) return .{ .verdict = .malformed };
            const public_key = Ecdsa.PublicKey.fromSec1(seal.key) catch
                return .{ .verdict = .malformed };
            var digest: [Sha256.digest_length]u8 = undefined;
            Sha256.hash(bytes, &digest, .{});
            const signature = Ecdsa.Signature.fromBytes(seal.signature[0..signature_len].*);
            signature.verifyPrehashed(digest, public_key) catch
                return .{ .verdict = .signature_bad };
        },
        .rsa2048 => {
            if (seal.signature.len != rsa2048_modulus_len) return .{ .verdict = .malformed };
            const parts = rsaParts(seal.key) orelse return .{ .verdict = .malformed };
            const public_key = rsa.PublicKey.fromBytes(parts.exponent, parts.modulus) catch
                return .{ .verdict = .malformed };
            // This checks the padded block the card signed, not the digest: the block holds the hash of the whole message, which is the same hash digestOf computes here.
            rsa.PKCS1v1_5Signature.verify(
                rsa2048_modulus_len,
                seal.signature[0..rsa2048_modulus_len].*,
                bytes,
                public_key,
                Sha256,
            ) catch return .{ .verdict = .signature_bad };
        },
    }

    // Only past this point is the record's own claim worth reading, because every field up to here could be whatever the last person to touch the file put there.
    if (!std.mem.eql(u8, seal.session, expect.session))
        return .{ .verdict = .head_mismatch, .claimed = seal.level, .mismatched = .session };
    if (!std.mem.eql(u8, &seal.header, expect.header))
        return .{ .verdict = .head_mismatch, .claimed = seal.level, .mismatched = .header };
    if (!std.mem.eql(u8, &seal.head, expect.head))
        return .{ .verdict = .head_mismatch, .claimed = seal.level, .mismatched = .head };
    if (seal.events != expect.events)
        return .{ .verdict = .head_mismatch, .claimed = seal.level, .mismatched = .events };

    const found = attestation.read(seal.attestation, seal.key, trust.root, trust.now_sec);
    return switch (seal.level) {
        .software => .{ .verdict = .signed_software, .claimed = .software, .attestation = found, .scheme = scheme },
        .card => .{ .verdict = .signed_card, .claimed = .card, .attestation = found, .scheme = scheme },
        .card_attested => .{
            .verdict = if (found == .bound) .signed_card_attested else .claim_unsupported,
            .claimed = .card_attested,
            .attestation = found,
            .scheme = scheme,
        },
    };
}

pub const Record = struct {
    chock_seal: u32,
    session: []const u8,
    header: []const u8,
    head: []const u8,
    events: u64,
    level: Level,
    key: []const u8,
    signature: []const u8,
    attestation: []const []const u8 = &.{},
};

const base64 = std.base64.standard;

pub const RecordError = error{
    Malformed,
} || CanonicalError;

pub const Buffer = struct {
    header: [digest_hex_len]u8 = undefined,
    head: [digest_hex_len]u8 = undefined,
    key: [max_public_key_len * 2]u8 = undefined,
    signature: [max_signature_len * 2]u8 = undefined,
    certs: [max_attestation_certs][base64.Encoder.calcSize(max_certificate_len)]u8 = undefined,
    cert_slices: [max_attestation_certs][]const u8 = undefined,
};

fn hexInto(out: []u8, bytes: []const u8) []const u8 {
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        out[i * 2] = alphabet[byte >> 4];
        out[i * 2 + 1] = alphabet[byte & 0x0f];
    }
    return out[0 .. bytes.len * 2];
}

pub fn toRecord(seal: Seal, buffer: *Buffer) RecordError!Record {
    if (seal.attestation.len > max_attestation_certs) return error.Malformed;
    if (seal.key.len == 0 or seal.key.len > max_public_key_len) return error.KeyUnusable;
    if (seal.signature.len == 0 or seal.signature.len > max_signature_len)
        return error.Malformed;
    buffer.header = seal.header;
    buffer.head = seal.head;
    const key = hexInto(&buffer.key, seal.key);
    const signature = hexInto(&buffer.signature, seal.signature);
    for (seal.attestation, 0..) |der, i| {
        if (der.len > max_certificate_len) return error.Malformed;
        buffer.cert_slices[i] = base64.Encoder.encode(&buffer.certs[i], der);
    }
    return .{
        .chock_seal = seal.version,
        .session = seal.session,
        .header = &buffer.header,
        .head = &buffer.head,
        .events = seal.events,
        .level = seal.level,
        .key = key,
        .signature = signature,
        .attestation = buffer.cert_slices[0..seal.attestation.len],
    };
}

pub const ReadBuffer = struct {
    key: [max_public_key_len]u8 = undefined,
    signature: [max_signature_len]u8 = undefined,
    bytes: [max_attestation_certs][max_certificate_len]u8 = undefined,
    slices: [max_attestation_certs][]const u8 = undefined,
};

pub fn fromRecord(record: Record, held: *ReadBuffer) RecordError!Seal {
    if (record.header.len != digest_hex_len or record.head.len != digest_hex_len)
        return error.DigestUnusable;
    if (record.key.len == 0 or record.key.len % 2 != 0) return error.KeyUnusable;
    if (record.key.len > max_public_key_len * 2) return error.KeyUnusable;
    if (record.signature.len == 0 or record.signature.len % 2 != 0) return error.Malformed;
    if (record.signature.len > max_signature_len * 2) return error.Malformed;
    if (record.attestation.len > max_attestation_certs) return error.Malformed;
    if (record.session.len == 0 or record.session.len > max_session_len)
        return error.SessionUnusable;

    var seal = Seal{
        .session = record.session,
        .header = record.header[0..digest_hex_len].*,
        .head = record.head[0..digest_hex_len].*,
        .events = record.events,
        .level = record.level,
        .key = &.{},
        .signature = &.{},
        .version = record.chock_seal,
    };
    seal.key = std.fmt.hexToBytes(
        held.key[0 .. record.key.len / 2],
        record.key,
    ) catch return error.Malformed;
    seal.signature = std.fmt.hexToBytes(
        held.signature[0 .. record.signature.len / 2],
        record.signature,
    ) catch return error.Malformed;

    for (record.attestation, 0..) |text, i| {
        const size = base64.Decoder.calcSizeForSlice(text) catch return error.Malformed;
        if (size > max_certificate_len) return error.Malformed;
        base64.Decoder.decode(held.bytes[i][0..size], text) catch return error.Malformed;
        held.slices[i] = held.bytes[i][0..size];
    }
    seal.attestation = held.slices[0..record.attestation.len];
    return seal;
}

const testing = std.testing;
const software = @import("software.zig");

const test_header = [_]u8{'a'} ** digest_hex_len;
const test_head = [_]u8{'b'} ** digest_hex_len;

fn testSigner(key: *software.Key) Signer {
    return .{ .ptr = key, .vtable = &test_signer_vtable };
}

fn testPublicKey(ptr: *anyopaque, out: *[max_public_key_len]u8) SignError![]const u8 {
    const key: *software.Key = @ptrCast(@alignCast(ptr));
    out[0..public_key_len].* = key.publicKey();
    return out[0..public_key_len];
}

fn testSignDigest(
    ptr: *anyopaque,
    digest: [Sha256.digest_length]u8,
    out: *[max_signature_len]u8,
) SignError![]const u8 {
    const key: *software.Key = @ptrCast(@alignCast(ptr));
    out[0..signature_len].* = key.signDigest(digest) catch return error.Unusable;
    return out[0..signature_len];
}

const test_key = [_]u8{4} ++ [_]u8{7} ** 64;

const test_signer_vtable = Signer.VTable{
    .publicKey = testPublicKey,
    .signDigest = testSignDigest,
};

fn testExpectation() Expectation {
    return .{ .session = "01J0SESSION", .header = &test_header, .head = &test_head, .events = 42 };
}

fn testRequest(level: Level) Request {
    return .{
        .session = "01J0SESSION",
        .header = test_header,
        .head = test_head,
        .events = 42,
        .level = level,
    };
}

test "a signature over a chain head verifies with only the public key in the record" {
    var key = try software.Key.fromSeed([_]u8{0x01} ** 32);
    var held_1 = Held{};
    const seal = try sign(testRequest(.software), testSigner(&key), &held_1);

    const reading = read(seal, testExpectation(), .{ .now_sec = 0 });
    try testing.expectEqual(Verdict.signed_software, reading.verdict);
    try testing.expect(reading.signed());
    try testing.expectEqual(@as(?Level, .software), reading.claimed);
    try testing.expect(!reading.hardwareProved());
}

test "one changed byte anywhere in the signed fields breaks the signature" {
    var key = try software.Key.fromSeed([_]u8{0x02} ** 32);
    var held_2 = Held{};
    const seal = try sign(testRequest(.software), testSigner(&key), &held_2);
    const expect = testExpectation();

    var head_changed = seal;
    head_changed.head[0] = 'c';
    try testing.expectEqual(Verdict.signature_bad, read(head_changed, expect, .{ .now_sec = 0 }).verdict);

    var header_changed = seal;
    header_changed.header[63] = 'c';
    try testing.expectEqual(Verdict.signature_bad, read(header_changed, expect, .{ .now_sec = 0 }).verdict);

    var events_changed = seal;
    events_changed.events = 43;
    try testing.expectEqual(Verdict.signature_bad, read(events_changed, expect, .{ .now_sec = 0 }).verdict);

    var session_changed = seal;
    session_changed.session = "01J0OTHER00";
    try testing.expectEqual(Verdict.signature_bad, read(session_changed, expect, .{ .now_sec = 0 }).verdict);

    var version_changed = seal;
    version_changed.version = 2;
    try testing.expectEqual(Verdict.malformed, read(version_changed, expect, .{ .now_sec = 0 }).verdict);

    var signature_changed = seal;
    var flipped: [signature_len]u8 = seal.signature[0..signature_len].*;
    flipped[0] ^= 0x01;
    signature_changed.signature = &flipped;
    try testing.expectEqual(Verdict.signature_bad, read(signature_changed, expect, .{ .now_sec = 0 }).verdict);
}

test "the recorded level cannot be raised by editing the record" {
    var key = try software.Key.fromSeed([_]u8{0x03} ** 32);
    var held_3 = Held{};
    const seal = try sign(testRequest(.software), testSigner(&key), &held_3);
    const expect = testExpectation();
    try testing.expectEqual(Verdict.signed_software, read(seal, expect, .{ .now_sec = 0 }).verdict);

    var raised = seal;
    raised.level = .card;
    try testing.expectEqual(Verdict.signature_bad, read(raised, expect, .{ .now_sec = 0 }).verdict);

    var raised_further = seal;
    raised_further.level = .card_attested;
    try testing.expectEqual(Verdict.signature_bad, read(raised_further, expect, .{ .now_sec = 0 }).verdict);

    var held_4 = Held{};
    var lowered = try sign(testRequest(.card), testSigner(&key), &held_4);
    lowered.level = .software;
    try testing.expectEqual(Verdict.signature_bad, read(lowered, expect, .{ .now_sec = 0 }).verdict);
}

test "an attacker who re-signs with their own key cannot claim a card made it" {
    var attacker = try software.Key.fromSeed([_]u8{0x04} ** 32);
    var held_5 = Held{};
    var forged = try sign(testRequest(.card), testSigner(&attacker), &held_5);
    forged.level = .card_attested;
    const forged_signature = try attacker.signDigest(try digestOf(forged));
    forged.signature = &forged_signature;

    const reading = read(forged, testExpectation(), .{ .now_sec = 0 });
    try testing.expectEqual(Verdict.claim_unsupported, reading.verdict);
    try testing.expect(!reading.signed());
    try testing.expect(!reading.hardwareProved());
    try testing.expectEqual(attestation.Verdict.absent, reading.attestation);
    try testing.expectEqual(@as(?Level, .card_attested), reading.claimed);
}

test "a seal signed by one key does not verify under another key's seal" {
    var mine = try software.Key.fromSeed([_]u8{0x05} ** 32);
    var theirs = try software.Key.fromSeed([_]u8{0x06} ** 32);
    var held_6 = Held{};
    const seal = try sign(testRequest(.software), testSigner(&mine), &held_6);

    var swapped = seal;
    const other_key = theirs.publicKey();
    swapped.key = &other_key;
    try testing.expectEqual(
        Verdict.signature_bad,
        read(swapped, testExpectation(), .{ .now_sec = 0 }).verdict,
    );
}

test "a seal about another log is named as such, and the field that disagreed is named" {
    var key = try software.Key.fromSeed([_]u8{0x07} ** 32);
    var held_7 = Held{};
    const seal = try sign(testRequest(.software), testSigner(&key), &held_7);

    var repaired = testExpectation();
    const other_head = [_]u8{'c'} ** digest_hex_len;
    repaired.head = &other_head;
    const reading = read(seal, repaired, .{ .now_sec = 0 });
    try testing.expectEqual(Verdict.head_mismatch, reading.verdict);
    try testing.expectEqual(@as(?Field, .head), reading.mismatched);
    try testing.expect(!reading.signed());

    var moved = testExpectation();
    moved.session = "01J0ELSEWHERE";
    try testing.expectEqual(@as(?Field, .session), read(seal, moved, .{ .now_sec = 0 }).mismatched);

    var grown = testExpectation();
    grown.events = 43;
    try testing.expectEqual(@as(?Field, .events), read(seal, grown, .{ .now_sec = 0 }).mismatched);

    var reheaded = testExpectation();
    const other_header = [_]u8{'d'} ** digest_hex_len;
    reheaded.header = &other_header;
    try testing.expectEqual(@as(?Field, .header), read(seal, reheaded, .{ .now_sec = 0 }).mismatched);
}

test "the default reading is absent, and absent is never a pass" {
    const nothing = Reading{};
    try testing.expectEqual(Verdict.absent, nothing.verdict);
    try testing.expect(!nothing.signed());
    try testing.expect(!nothing.hardwareProved());
    try testing.expectEqual(@as(?Level, null), nothing.claimed);
}

test "every verdict has its own sentence, and no sentence for an absent seal reads as a pass" {
    var seen: [@typeInfo(Verdict).@"enum".fields.len][]const u8 = undefined;
    inline for (@typeInfo(Verdict).@"enum".fields, 0..) |field, i| {
        const text = (Reading{ .verdict = @enumFromInt(field.value) }).sentence();
        try testing.expect(text.len != 0);
        for (seen[0..i]) |earlier| try testing.expect(!std.mem.eql(u8, earlier, text));
        seen[i] = text;
    }

    const absent_text = (Reading{ .verdict = .absent }).sentence();
    try testing.expect(std.mem.indexOf(u8, absent_text, "no seal") != null);
    try testing.expect(std.mem.indexOf(u8, absent_text, "is sealed") == null);

    try testing.expect(std.mem.indexOf(
        u8,
        (Reading{ .verdict = .signed_software }).sentence(),
        "software key",
    ) != null);
    try testing.expect(std.mem.indexOf(
        u8,
        (Reading{ .verdict = .signed_card_attested }).sentence(),
        "never left it",
    ) != null);
}

test "signing refuses to record an attestation level with no attestation" {
    var key = try software.Key.fromSeed([_]u8{0x08} ** 32);
    var held_8 = Held{};
    try testing.expectError(
        error.AttestationMissing,
        sign(testRequest(.card_attested), testSigner(&key), &held_8),
    );
}

test "the canonical form separates fields by length, so no field can eat another" {
    const one = Seal{
        .session = "ab",
        .header = test_header,
        .head = test_head,
        .events = 1,
        .level = .software,
        .key = &test_key,
        .signature = &test_key,
    };
    var two = one;
    two.session = "a";
    var buffer_one: [max_canonical_len]u8 = undefined;
    var buffer_two: [max_canonical_len]u8 = undefined;
    const bytes_one = try canonical(one, &buffer_one);
    const bytes_two = try canonical(two, &buffer_two);
    try testing.expect(!std.mem.eql(u8, bytes_one, bytes_two));

    try testing.expect(std.mem.startsWith(u8, bytes_one, domain));
}

test "a session that is empty or too long is refused rather than cut down" {
    var seal = Seal{
        .session = "",
        .header = test_header,
        .head = test_head,
        .events = 0,
        .level = .software,
        .key = &test_key,
        .signature = &test_key,
    };
    var buffer: [max_canonical_len]u8 = undefined;
    try testing.expectError(error.SessionUnusable, canonical(seal, &buffer));

    const long = [_]u8{'x'} ** (max_session_len + 1);
    seal.session = &long;
    try testing.expectError(error.SessionUnusable, canonical(seal, &buffer));
}

test "a digest of the wrong width or the wrong alphabet is refused" {
    try testing.expect(isDigest(&test_header));
    try testing.expect(!isDigest("ABCDEF" ++ [_]u8{'a'} ** 58));
    try testing.expect(!isDigest("abc"));
    try testing.expect(!isDigest(&[_]u8{'a'} ** 65));
    try testing.expect(!isDigest(""));

    const seal = Seal{
        .session = "s",
        .header = [_]u8{'Z'} ** digest_hex_len,
        .head = test_head,
        .events = 0,
        .level = .software,
        .key = &test_key,
        .signature = &test_key,
    };
    var buffer: [max_canonical_len]u8 = undefined;
    try testing.expectError(error.DigestUnusable, canonical(seal, &buffer));
}

test "a key that is not a point on the curve is malformed, never a bad signature" {
    var key = try software.Key.fromSeed([_]u8{0x09} ** 32);
    var held_9 = Held{};
    var seal = try sign(testRequest(.software), testSigner(&key), &held_9);
    const junk_key = [_]u8{0xff} ** public_key_len;
    seal.key = &junk_key;
    try testing.expectEqual(
        Verdict.malformed,
        read(seal, testExpectation(), .{ .now_sec = 0 }).verdict,
    );
}

test "a level compares by strength, and card_attested is the strongest" {
    try testing.expect(Level.card_attested.atLeast(.card));
    try testing.expect(Level.card_attested.atLeast(.software));
    try testing.expect(Level.card.atLeast(.software));
    try testing.expect(!Level.software.atLeast(.card));
    try testing.expect(Level.card.atLeast(.card));
    try testing.expectEqual(@as(u8, 1), @intFromEnum(Level.card_attested));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(Level.card));
    try testing.expectEqual(@as(u8, 3), @intFromEnum(Level.software));
}

test "a seal survives the trip through its record with every field intact" {
    var key = try software.Key.fromSeed([_]u8{0x0a} ** 32);
    var held_10 = Held{};
    const seal = try sign(testRequest(.card), testSigner(&key), &held_10);

    var buffer = Buffer{};
    const record = try toRecord(seal, &buffer);
    const text = try std.json.Stringify.valueAlloc(testing.allocator, record, .{});
    defer testing.allocator.free(text);

    const parsed = try std.json.parseFromSlice(Record, testing.allocator, text, .{});
    defer parsed.deinit();
    var certs = ReadBuffer{};
    const restored = try fromRecord(parsed.value, &certs);

    try testing.expectEqual(Verdict.signed_card, read(restored, testExpectation(), .{ .now_sec = 0 }).verdict);
    try testing.expectEqualSlices(u8, &seal.head, &restored.head);
    try testing.expectEqualSlices(u8, seal.key, restored.key);
    try testing.expectEqualSlices(u8, seal.signature, restored.signature);
    try testing.expectEqual(seal.events, restored.events);
    try testing.expectEqual(seal.level, restored.level);
}

test "a record with a field of the wrong width is refused rather than padded" {
    var key = try software.Key.fromSeed([_]u8{0x0b} ** 32);
    var held_11 = Held{};
    const seal = try sign(testRequest(.software), testSigner(&key), &held_11);
    var buffer = Buffer{};
    const record = try toRecord(seal, &buffer);

    var short_key = record;
    short_key.key = record.key[0 .. record.key.len - 2];
    var certs = ReadBuffer{};
    const with_short_key = try fromRecord(short_key, &certs);
    try testing.expectEqual(@as(?Scheme, null), schemeOf(with_short_key.key));
    try testing.expectEqual(
        Verdict.malformed,
        read(with_short_key, testExpectation(), .{ .now_sec = 0 }).verdict,
    );

    var half_byte = record;
    half_byte.key = record.key[0 .. record.key.len - 1];
    try testing.expectError(error.KeyUnusable, fromRecord(half_byte, &certs));

    var short_head = record;
    short_head.head = record.head[0..63];
    try testing.expectError(error.DigestUnusable, fromRecord(short_head, &certs));

    var short_signature = record;
    short_signature.signature = record.signature[0..126];
    var second = ReadBuffer{};
    try testing.expectEqual(
        Verdict.malformed,
        read(try fromRecord(short_signature, &second), testExpectation(), .{ .now_sec = 0 }).verdict,
    );

    var no_session = record;
    no_session.session = "";
    try testing.expectError(error.SessionUnusable, fromRecord(no_session, &certs));

    var not_hex = record;
    const junk = [_]u8{'z'} ** (public_key_len * 2);
    not_hex.key = &junk;
    try testing.expectError(error.Malformed, fromRecord(not_hex, &certs));
}

test {
    testing.refAllDecls(@This());
}

test "an elliptic curve key and an RSA key cannot be read as one another" {
    const ec = [_]u8{0x04} ++ [_]u8{0x11} ** 64;
    try testing.expectEqual(@as(?Scheme, .ecdsa_p256), schemeOf(&ec));

    const rsa_key = [_]u8{ 0x81, 0x82, 0x01, 0x00 } ++ [_]u8{0xab} ** 256 ++
        [_]u8{ 0x82, 0x03, 0x01, 0x00, 0x01 };
    try testing.expectEqual(@as(?Scheme, .rsa2048), schemeOf(&rsa_key));
    const parts = rsaParts(&rsa_key).?;
    try testing.expectEqual(@as(usize, 256), parts.modulus.len);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x01 }, parts.exponent);

    const uncompressed_but_short = [_]u8{0x04} ++ [_]u8{0x11} ** 63;
    try testing.expectEqual(@as(?Scheme, null), schemeOf(&uncompressed_but_short));
    const compressed = [_]u8{0x02} ++ [_]u8{0x11} ** 64;
    try testing.expectEqual(@as(?Scheme, null), schemeOf(&compressed));
    try testing.expectEqual(@as(?Scheme, null), schemeOf(""));
    const small = [_]u8{ 0x81, 0x81, 0x80 } ++ [_]u8{0xab} ** 128 ++
        [_]u8{ 0x82, 0x03, 0x01, 0x00, 0x01 };
    try testing.expectEqual(@as(?Scheme, null), schemeOf(&small));
    const swapped = [_]u8{ 0x82, 0x03, 0x01, 0x00, 0x01 } ++
        [_]u8{ 0x81, 0x82, 0x01, 0x00 } ++ [_]u8{0xab} ** 256;
    try testing.expectEqual(@as(?Scheme, null), schemeOf(&swapped));
    const trailing = rsa_key ++ [_]u8{ 0x83, 0x01, 0x00 };
    try testing.expectEqual(@as(?Scheme, null), schemeOf(&trailing));
}

test "a seal written before the key field could vary is still read and still verifies" {
    const written =
        \\{"chock_seal":1,"session":"01M0TJXD6Y20QJGX55R31DYD47",
        \\"header":"ec2d45163a1d5e394b485bcf3394804d1cd4f071ce3aab0dd323f7dd3072b116",
        \\"head":"e7e0b73ba71b06dedf3a0c28d4bb07e82477bc6cc9309d5605f3777689b5d151",
        \\"events":6,"level":"software",
        \\"key":"041d754b809ae5f3d8c8ecc1289152d7a3d852ef7673feab4432455f868e7c0cdb
        \\acf381a94d41009c1433faa44fc7c54540f1a200e0a06037952112904b2ff36c",
        \\"signature":"4aa9254dd9592f3fd7903720c8fe0dfef32e1c94272b01dd1c51d35da0a68882
        \\2317c0dae18991932b13b62e32965514baf27de06944b6c88747c2e096813bae",
        \\"attestation":[]}
    ;
    var text: [written.len]u8 = undefined;
    var at: usize = 0;
    for (written) |byte| {
        if (byte == '\n') continue;
        text[at] = byte;
        at += 1;
    }

    const parsed = try std.json.parseFromSlice(Record, testing.allocator, text[0..at], .{});
    defer parsed.deinit();
    var held = ReadBuffer{};
    const restored = try fromRecord(parsed.value, &held);

    try testing.expectEqual(@as(?Scheme, .ecdsa_p256), schemeOf(restored.key));
    try testing.expectEqual(@as(usize, public_key_len), restored.key.len);
    try testing.expectEqual(@as(usize, signature_len), restored.signature.len);

    const reading = read(restored, .{
        .session = "01M0TJXD6Y20QJGX55R31DYD47",
        .header = "ec2d45163a1d5e394b485bcf3394804d1cd4f071ce3aab0dd323f7dd3072b116",
        .head = "e7e0b73ba71b06dedf3a0c28d4bb07e82477bc6cc9309d5605f3777689b5d151",
        .events = 6,
    }, .{ .now_sec = 0 });
    try testing.expectEqual(Verdict.signed_software, reading.verdict);
    try testing.expect(reading.signed());
}
