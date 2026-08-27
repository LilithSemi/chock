//! Attestation: what makes "the key is on a card" provable instead of claimed.
//!
//! A PIV key that was generated on the card can be attested. The card builds a
//! certificate for that key, signs it with a key the vendor put in the card at
//! manufacture, and that key's own certificate chains to the vendor's
//! certificate authority. The leaf states two things a reader cannot get any
//! other way: the key was created in hardware, and it never left it.
//!
//! Without one, `seal.Level.card` is a claim and nothing more. The signature
//! proves that whoever holds the key signed. It says nothing about where the key
//! lives, and a person who copied a software key can make the same signature.
//! That is the whole distance between level 1 and level 2.
//!
//! ## The root is passed in, never built in
//!
//! A vendor root certificate is not written into this source. Two reasons.
//! First, a root pinned in a binary cannot be changed when the vendor rotates
//! it, and a reader stuck on an old root reads every new card as untrusted.
//! Second, the reader is the one who decides what to trust: an auditor checking
//! somebody else's log supplies the root they are willing to accept, and
//! `null` means they accept none. **`null` never means "trust anything"**: a
//! seal that claims an attestation reads as unsupported when there is nothing
//! to check it against.
//!
//! ## The moment is passed in too
//!
//! A certificate has a validity window, so reading one needs a time. It comes
//! from the caller rather than from a clock here, which keeps every test in this
//! module free of a wall clock assertion and lets an auditor ask "was this
//! chain good on the day the log was written".
//!
//! ## `std.crypto.Certificate.parse` does not check its bounds, so this does
//!
//! **Measured, not assumed.** `std.crypto.Certificate.der.Element.parse` reads
//! `bytes[i]` and `bytes[i + 1]` with no length check at all, so a certificate
//! that ends in the middle of an element makes the whole process abort with an
//! index out of bounds panic. That was found by feeding it 22 bytes that are
//! not DER. It is not a theoretical hazard here: **a seal is a record somebody
//! else wrote**, and an auditor reading a log they were given must get a verdict
//! and never a crash.
//!
//! So `safeToParse` runs first, over the same bytes, using this module's own
//! bounds checked reader. It proves three things:
//!
//! 1. **Every element tiles its parent exactly.** No element runs past the end
//!    of the one that holds it, and no gap is left between siblings. That makes
//!    every position the standard library computes from an element's end either
//!    the start of another element or the end of an ancestor.
//! 2. **The certificate has the shape the standard library walks.** Three
//!    elements at the top, at least six inside the certificate body, two inside
//!    the validity window, two inside the public key. Without this, the standard
//!    library reads at the end of the buffer, which is the one position rule 1
//!    cannot make safe.
//! 3. **Both bit strings hold at least one byte.** `parseBitString` reads the
//!    first byte of its element without checking that there is one.
//!
//! A certificate that fails any of the three is `malformed`. Every real
//! certificate passes: see `test/pcsc/attestation.zig`, which sweeps every
//! truncation and a systematic set of single byte changes of a real certificate
//! through `read` and proves not one of them ends the process.

const std = @import("std");
const tlv = @import("tlv.zig");
const Certificate = std.crypto.Certificate;

/// The uncompressed SEC-1 public key length, 65 bytes for P-256. The form both
/// a certificate and a seal hold.
pub const public_key_len = 65;

/// The longest chain this reads: a leaf, an intermediate, and room for one more.
/// A bound on work driven by a record somebody else wrote.
pub const max_chain_len = 4;

/// What reading an attestation found.
///
/// **Only `bound` says the key lives in hardware.** Everything else is a reason
/// it could not be shown, and a caller must not treat any of them as a weaker
/// yes.
pub const Verdict = enum {
    /// The record carried no certificates at all.
    absent,
    /// The reader supplied no root, so there is nothing to check a chain
    /// against. Never "trust anything".
    no_root,
    /// A certificate would not parse, or the chain is longer than
    /// `max_chain_len`.
    malformed,
    /// The chain parses and the leaf is about a different public key from the
    /// one that signed the seal. **This is an attestation borrowed from
    /// somewhere else**: a real chain, for a real card, that has nothing to do
    /// with the key in this record.
    key_mismatch,
    /// A certificate in the chain was outside its validity window at the moment
    /// the reader gave. Its own answer, because an expired chain is a different
    /// fact from a forged one.
    expired,
    /// The chain does not reach the root: a link whose issuer does not match, or
    /// a signature that does not check out.
    untrusted,
    /// The key that signed the seal is the key in the leaf certificate, and that
    /// certificate chains to the root the reader trusts.
    bound,
};

/// Read an attestation chain. `certs` is DER, leaf first. `key` is the
/// uncompressed SEC-1 public key the seal carries. `root` is the DER of the
/// certificate authority the reader trusts, or null.
/// `key` is the public key the seal carries. **A key of any other shape than an
/// uncompressed P-256 point answers `key_mismatch`**: every attestation this
/// reads holds such a point, so a seal whose key is an RSA one is not the key
/// in the leaf certificate, whatever else it is.
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
    // The binding. Everything else in this function is about whether the chain
    // is real; this is about whether it is about the right key.
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
    /// The bytes are not a certificate this reader will parse. See
    /// `safeToParse`.
    CertificateUnreadable,
    /// The certificate holds a key that is not an uncompressed P-256 point, so
    /// it is not a key this project signs with.
    KeyUnsupported,
};

/// The public key a certificate holds, in the uncompressed SEC-1 form.
///
/// This is how the card path learns its own public key: the key never leaves
/// the card, so the certificate in the slot is the only place to read it from.
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

/// How deep the structure walk goes. A certificate is about six levels deep, so
/// this is room to spare and still a bound on work a record somebody else wrote
/// can ask for.
const max_depth = 24;

/// How many children of one element this counts. A certificate body holds ten
/// at most, so anything larger is not a certificate.
const max_children = 12;

const sequence_tag: tlv.Tag = 0x30;
const bitstring_tag: tlv.Tag = 0x03;
const context_zero_tag: tlv.Tag = 0xa0;

/// Whether `std.crypto.Certificate.parse` can read these bytes without leaving
/// the buffer. See this file's own top comment for the three things this proves
/// and why the standard library needs it proved for it.
pub fn safeToParse(der: []const u8) bool {
    const top = tlv.read(der) catch return false;
    if (top.tag != sequence_tag) return false;
    if (top.encoded_len != der.len) return false;
    if (!tiles(top.value, max_depth)) return false;

    var outer: [max_children]tlv.Element = undefined;
    const outer_count = childrenOf(top.value, &outer) orelse return false;
    // Exactly three: the certificate body, the signature algorithm, and the
    // signature. The standard library reads at the start of the third one, and
    // with only two that position is the end of the buffer.
    if (outer_count != 3) return false;
    if (outer[0].tag != sequence_tag) return false;
    if (outer[1].tag != sequence_tag) return false;
    if (!hasChild(outer[1].value)) return false;
    if (outer[2].tag != bitstring_tag or outer[2].value.len == 0) return false;

    var body: [max_children]tlv.Element = undefined;
    const body_count = childrenOf(outer[0].value, &body) orelse return false;
    // A version element is optional. With one, the six fields the standard
    // library walks start one place later.
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

/// Whether `bytes` is filled exactly by whole elements, with every constructed
/// element's contents filled the same way.
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

/// The elements directly inside `bytes`, or null when there are more than
/// `max_children` of them or the bytes do not tile.
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

/// The constructed bit, ISO 8825 clause 8.1.2.5, which lives in the first byte
/// of the tag whatever the tag's length.
fn isConstructed(tag: tlv.Tag) bool {
    var first = tag;
    while (first > 0xff) first >>= 8;
    return first & 0x20 != 0;
}

/// Check one link of the chain. Null when it holds, a verdict when it does not.
fn link(subject: Certificate.Parsed, issuer: Certificate.Parsed, now_sec: i64) ?Verdict {
    subject.verify(issuer, now_sec) catch |err| return switch (err) {
        error.CertificateNotYetValid, error.CertificateExpired => .expired,
        else => .untrusted,
    };
    return null;
}

const testing = std.testing;

test "no certificates is absent, and absent is never a weaker yes" {
    // The shape a level 2 seal takes. `absent` has to stay separate from every
    // failure, because a card without attestation is an honest level 2 and a
    // forged chain is not.
    const key = [_]u8{0x04} ++ [_]u8{0x11} ** 64;
    try testing.expectEqual(Verdict.absent, read(&.{}, &key, null, 0));
    try testing.expectEqual(Verdict.absent, read(&.{}, &key, "root der", 0));
}

test "a reader with no root proves nothing, and never trusts everything" {
    // The failure mode this guards: a null root read as "no checking needed".
    // A chain the reader cannot check is a chain the reader has not checked.
    const key = [_]u8{0x04} ++ [_]u8{0x11} ** 64;
    try testing.expectEqual(Verdict.no_root, read(&.{"not really a certificate"}, &key, null, 0));
}

test "a chain longer than the bound is refused before anything is parsed" {
    const key = [_]u8{0x04} ++ [_]u8{0x11} ** 64;
    const too_many = [_][]const u8{"x"} ** (max_chain_len + 1);
    try testing.expectEqual(Verdict.malformed, read(&too_many, &key, "root", 0));
}

test "bytes that are not a certificate are malformed, never untrusted" {
    // Two different faults. A reader told "untrusted" goes looking for a forged
    // chain; a reader told "malformed" goes looking for a truncated file.
    const key = [_]u8{0x04} ++ [_]u8{0x11} ** 64;
    try testing.expectEqual(
        Verdict.malformed,
        read(&.{"this is not DER at all"}, &key, "nor is this", 0),
    );
}

test "only bound says the key lives in hardware" {
    // A guard on the enum itself. A caller that treated any answer other than a
    // failure as a yes would read `no_root` as hardware backed.
    const answers = [_]Verdict{ .absent, .no_root, .malformed, .key_mismatch, .expired, .untrusted };
    for (answers) |answer| try testing.expect(answer != .bound);
}

test {
    testing.refAllDecls(@This());
}
