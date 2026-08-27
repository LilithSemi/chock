//! The seal: a signature over the head of a session log's hash chain.
//!
//! `lib/chock-proto/chain.zig` is honest about its own limit. A hash chain
//! catches an edit in the middle by somebody who does not hash the file again.
//! It catches nothing else. Rewriting a whole log and recomputing every `prev`
//! field takes four lines of shell, and the chain then reports that it holds.
//!
//! **A signature over the chain head makes that rewrite useless without the
//! key.** The head is the hash of the last line of the file, so a seal also
//! covers the one event a chain cannot: the last one, which nothing after it
//! carries the hash of. For a session that has ended, that gap is permanent
//! without a seal.
//!
//! ## What the signature covers
//!
//! `canonical` builds the exact bytes that get hashed and signed:
//!
//! * the session identifier, so a seal cannot be moved to another session,
//! * the digest of the log's header line, which is what the chain is anchored
//!   to,
//! * the digest of the last line, which is the head,
//! * how many events the log holds, so events cannot be added past the head
//!   without the count disagreeing,
//! * **the level**, so a recorded fallback cannot be raised afterwards,
//! * the public key, so a seal cannot be re-pointed at another key.
//!
//! Every field is written with its own length in front of it, after a fixed
//! prefix that names the format. **Nothing is escaped and nothing is
//! delimited**, because a length in front is the only encoding where two
//! different field sets cannot produce the same bytes. A form that joined
//! fields with a separator would let a session identifier holding that
//! separator forge a different seal.
//!
//! ## Never a re-serialization
//!
//! `canonical` is built from the parsed values and never from the JSON the
//! record was carried in, for the same reason `chain.zig` hashes the bytes on
//! disk and never a fresh encoding of the parsed event: two encoders that
//! disagree about key order or number form would read as tampering. Here the
//! direction is the other way round. The JSON is carriage only, and a verifier
//! rebuilds the signed bytes itself, so a record reformatted by a text editor
//! still verifies while a record with one changed value does not.
//!
//! ## The three levels
//!
//! `Level` has three values and Chock takes the best it can get:
//!
//! 1. `card_attested`: a key made on a card, with an attestation certificate
//!    that chains to the vendor's own certificate authority and states the key
//!    was made in hardware and never left it.
//! 2. `card`: a key on a card with no attestation. The card was used. Nothing
//!    here can prove that, which is exactly why level 1 exists.
//! 3. `software`: a key in this process. See `software.zig`.
//!
//! **A fallback that is not recorded is a silent downgrade.** Anybody who can
//! unplug the card or stop the daemon would otherwise get the weaker signature
//! while the log still said "signed". So the level sits inside the signed bytes,
//! and `read` reports the level it found rather than answering pass or fail.
//! `Verdict` has eight values and none of them is "valid".
//!
//! ## Verification needs no card, no daemon and no platform branch
//!
//! `read` is `std.crypto` and, for an attestation, a chain of certificates. It
//! takes no branch on `builtin.os.tag` and calls nothing in this module's
//! transport. **That is the half an auditor uses and it must never need
//! hardware.**
//!
//! ## Two key shapes, and how a reader tells them apart
//!
//! A seal carries the public key, so the key's own bytes say which scheme
//! signed it:
//!
//! * 65 bytes starting with `04` is an uncompressed SEC-1 point on P-256.
//! * A `81` element holding the modulus followed by a `82` element holding the
//!   exponent is an RSA key. That is the shape a PIV card gives for one, so
//!   nothing has to re-encode what the card said.
//!
//! The two cannot be read as one another: the first byte differs and so does
//! the length. **The scheme is therefore signed** without a field of its own,
//! because the key is inside the canonical bytes. A separate algorithm field
//! outside them could be edited for free, and a separate field inside them
//! would change the canonical bytes of every seal written before it existed.
//!
//! **An older seal still verifies, byte for byte.** The key was already written
//! with its length in front of it, so widening the field changed no encoding.
//! `test/pcsc/verify.zig` holds a seal recorded before this change and reads it
//! back.

const std = @import("std");
const attestation = @import("attestation.zig");
const tlv = @import("tlv.zig");

/// The elliptic curve scheme, named once so the card path and the software path
/// cannot drift onto different curves.
pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const rsa = std.crypto.Certificate.rsa;

/// A chain digest as it is written: lowercase hexadecimal, 64 characters. The
/// same width `lib/chock-proto/chain.zig` writes into an envelope's `prev`.
pub const digest_hex_len = 64;

/// The uncompressed SEC-1 public key, 65 bytes. The form a certificate holds,
/// so an attestation can be matched against a seal's key byte for byte.
pub const public_key_len = Ecdsa.PublicKey.uncompressed_sec1_encoded_length;

/// The signature as `r` then `s`, 32 bytes each. **Not DER.** DER has more than
/// one way to write the same signature, so a record that stored it would have a
/// field whose bytes could change without its meaning changing.
pub const signature_len = Ecdsa.Signature.encoded_length;

/// The RSA modulus element of a public key, and the exponent element beside it.
/// The tags a PIV card uses for the same two values.
pub const rsa_modulus_tag: tlv.Tag = 0x81;
pub const rsa_exponent_tag: tlv.Tag = 0x82;

/// An RSA2048 modulus, and the signature a key of that size makes. Both are the
/// size of the modulus, which is what RSA gives.
pub const rsa2048_modulus_len = 256;

/// The longest public key a seal carries. An RSA2048 key in the shape above is
/// 265 bytes; this is that with room to spare and still a bound, because the
/// canonical buffer is sized once at compile time.
pub const max_public_key_len = 320;

/// The longest signature a seal carries. An RSA signature is as long as the
/// modulus.
pub const max_signature_len = rsa2048_modulus_len;

/// Which scheme a seal's key belongs to. Read from the key's own bytes: see this
/// file's own top comment.
pub const Scheme = enum {
    ecdsa_p256,
    rsa2048,

    /// What `chock sessions verify` calls this, so a person can tell an
    /// elliptic curve software key from an RSA card key by reading a row.
    pub fn text(self: Scheme) []const u8 {
        return switch (self) {
            .ecdsa_p256 => "ECDSA P-256",
            .rsa2048 => "RSA2048",
        };
    }
};

/// The modulus and the exponent of an RSA public key, borrowed from the key.
pub const RsaParts = struct {
    modulus: []const u8,
    exponent: []const u8,
};

/// Cut an RSA public key into its two numbers, or null when the bytes are not
/// one. **The order is fixed**: the modulus first. A form that accepted either
/// order would give one key two encodings, and a seal is signed over the bytes.
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

/// Which scheme these key bytes are, or null when they are neither.
///
/// **This is the whole of the algorithm agility in the format.** A key that
/// answers null here is `malformed` and never a bad signature: nothing signed
/// it, so calling it tampering would point a reader at something that did not
/// happen.
pub fn schemeOf(key: []const u8) ?Scheme {
    if (key.len == public_key_len and key[0] == 0x04) return .ecdsa_p256;
    const parts = rsaParts(key) orelse return null;
    if (parts.modulus.len != rsa2048_modulus_len) return null;
    return .rsa2048;
}

/// The longest session identifier a seal carries. A bound, because the session
/// identifier reaches this from outside and the canonical buffer is sized once
/// at compile time.
pub const max_session_len = 128;

/// The longest certificate chain an attestation may carry: a leaf, an
/// intermediate, and room for one more. A bound on work driven by a record
/// somebody else wrote.
pub const max_attestation_certs = 4;

/// The largest certificate this reads, in bytes. A PIV data object is at most
/// 3072 bytes, so nothing larger can have come off a card.
pub const max_certificate_len = 3072;

/// The prefix every canonical form starts with. It names the format, so a
/// signature over a version 1 seal can never be read as a signature over some
/// later shape with the same fields in a different order.
pub const domain = "chock-seal-v1\x00";

/// The wire version of this record.
pub const format_version: u32 = 1;

/// Which of the three levels produced this signature. See this file's own top
/// comment.
///
/// **The number is part of the wire format.** Lower is stronger, so a reader
/// can compare two levels, and the values never change.
pub const Level = enum(u8) {
    card_attested = 1,
    card = 2,
    software = 3,

    /// Whether `self` is at least as strong as `other`.
    pub fn atLeast(self: Level, other: Level) bool {
        return @intFromEnum(self) <= @intFromEnum(other);
    }
};

/// One seal, with every field in the form it is signed over. The JSON record is
/// a separate shape: see `Record`.
pub const Seal = struct {
    version: u32 = format_version,
    session: []const u8,
    /// The digest of the log's header line, lowercase hexadecimal.
    header: [digest_hex_len]u8,
    /// The digest of the last line of the log, lowercase hexadecimal. This is
    /// the head of the chain.
    head: [digest_hex_len]u8,
    /// How many event lines the log held when this was signed.
    events: u64,
    level: Level,
    /// The public key, in whichever of the two shapes `schemeOf` names.
    key: []const u8,
    /// The signature, in the form the scheme gives: `r` then `s` for an
    /// elliptic curve key, and the modulus width for an RSA one.
    signature: []const u8,
    /// The attestation certificates, DER, leaf first. **Not covered by the
    /// signature**: the leaf certificate commits to the key by holding it, so
    /// it needs no help from the signature to be bound. Stripping it does not
    /// go unnoticed, because the level that is signed still says
    /// `card_attested` and `read` then answers `claim_unsupported`.
    attestation: []const []const u8 = &.{},
};

/// How many bytes `canonical` can write at most. Every field is a fixed width
/// except the session identifier, which `max_session_len` bounds.
pub const max_canonical_len = domain.len + 4 + 1 +
    (8 + max_session_len) +
    (8 + digest_hex_len) +
    (8 + digest_hex_len) +
    8 +
    (8 + max_public_key_len);

pub const CanonicalError = error{
    /// The session identifier is longer than `max_session_len`, or empty.
    SessionUnusable,
    /// A digest is not 64 lowercase hexadecimal characters.
    DigestUnusable,
    /// The public key is longer than `max_public_key_len`, or empty.
    KeyUnusable,
};

/// Build the exact bytes the signature is over. See this file's own top comment
/// for the encoding and why it has no separators.
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

/// Whether a digest is written the one way this format accepts: 64 characters,
/// lowercase hexadecimal. Upper case would hash differently and read as a
/// different digest, so it is refused rather than folded.
pub fn isDigest(text: []const u8) bool {
    if (text.len != digest_hex_len) return false;
    for (text) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return false;
    }
    return true;
}

/// The digest that gets signed: SHA-256 over the canonical bytes. A PIV card
/// signs a digest and never a message, so this is the value that crosses to the
/// card. The software path signs the same digest.
pub fn digestOf(seal: Seal) CanonicalError![Sha256.digest_length]u8 {
    var buffer: [max_canonical_len]u8 = undefined;
    const bytes = try canonical(seal, &buffer);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    return digest;
}

pub const SignError = error{
    /// The signer could not use its key. A card that was removed, a PIN that
    /// was never given, a transport that is not there.
    Unusable,
} || CanonicalError || error{
    /// The level says `card_attested` and no attestation came with it. Refused
    /// at the point of signing as well as at the point of reading, because a
    /// seal that claims what it cannot show is a bug in the signer and not an
    /// attack.
    AttestationMissing,
    /// More certificates than `max_attestation_certs`.
    AttestationTooLong,
};

/// Where the key and the signature of one seal live. **The caller owns it and
/// it must outlive the seal**, because a seal borrows both.
///
/// A buffer and not two returned arrays, because the two schemes give values of
/// different widths and a fixed array would have to be the larger of them
/// everywhere.
pub const Held = struct {
    key: [max_public_key_len]u8 = undefined,
    signature: [max_signature_len]u8 = undefined,
};

/// Whatever holds the private key. A card behind `piv.zig`, or a
/// `software.Key`. Two calls, both over raw bytes, so nothing above knows which
/// it has, and each writes into the caller's buffer and answers the part it
/// used.
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
        /// Why the last call refused, in one sentence, or null when this signer
        /// has refused nothing.
        ///
        /// **A channel and not a vocabulary.** The words belong to whoever
        /// implements it, so nothing here has to name a card, a reader or a PIN.
        /// Null by default, because a signer with one way to fail says nothing
        /// the error name does not.
        reason: ?*const fn (ptr: *anyopaque) ?[]const u8 = null,
    };

    /// Why this signer last refused, or null when it has no more to say than
    /// `SignError` does.
    ///
    /// **The one thing `SignError` cannot carry.** `Unusable` covers a card that
    /// was removed, a person who declined, a line too long to read, a terminal
    /// that would not hide the typing and a PIN the card would not take, and a
    /// caller that printed the error name gave a person none of that. A slot
    /// whose PIN policy is `always` asks before every signature, so this is read
    /// far more often than the answer any single open gave.
    pub fn reason(self: Signer) ?[]const u8 {
        const ask = self.vtable.reason orelse return null;
        return ask(self.ptr);
    }
};

/// What a caller asks to have sealed.
pub const Request = struct {
    session: []const u8,
    header: [digest_hex_len]u8,
    head: [digest_hex_len]u8,
    events: u64,
    /// **The level the caller really used**, not the level it wanted. See this
    /// file's own top comment.
    level: Level,
    attestation: []const []const u8 = &.{},
};

/// Sign a request and answer the seal. The seal borrows `request.session`,
/// `request.attestation` and `held`, so all three must outlive it.
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

/// What one reading of a seal found.
///
/// **None of these is called "valid".** A seal is not a pass or a fail: it says
/// which of the three levels produced it, and a reader decides what that is
/// worth. See this file's own top comment.
pub const Verdict = enum {
    /// There is no seal at all. **Never read as a pass**: an absent answer is
    /// never a permissive answer, the same rule `chain.Verdict.unreadable`
    /// keeps.
    absent,
    /// The record could not be turned into a seal: a digest of the wrong shape,
    /// a key that is not a point on the curve, a session identifier that is too
    /// long.
    malformed,
    /// The signature does not check out against the key the record carries.
    /// **Somebody changed the record**, or the key in it is not the key that
    /// signed. Changing the recorded level is one way to land here, because the
    /// level is inside the signed bytes.
    signature_bad,
    /// The signature checks out, and the seal is about a different log from the
    /// one in front of the reader. `Reading.mismatched` names the field that
    /// disagreed. **A log whose chain was repaired by hand lands here**: the
    /// repair changed the bytes of a line, so the head is a different digest
    /// from the one that was signed.
    head_mismatch,
    /// The signature checks out and the record says a software key made it. The
    /// weakest of the three levels: this proves the same key signed, and
    /// nothing about where the key lives.
    signed_software,
    /// The signature checks out and the record says a card made it, with no
    /// attestation. **Nothing here can check that claim**, which is why
    /// `signed_card_attested` is a separate answer.
    signed_card,
    /// The signature checks out, the record says a card made it, and an
    /// attestation certificate chaining to the trusted root says the key was
    /// made on that card and never left it.
    signed_card_attested,
    /// The signature checks out and the record claims a level its evidence does
    /// not support: `card_attested` with no attestation, with one that does not
    /// chain to the root, or with one that is about a different key.
    /// `Reading.attestation` says which. **Somebody who removed the card and
    /// signed with a software key lands here if they also raise the level.**
    claim_unsupported,
};

/// Which field of a seal disagreed with the log in front of the reader.
pub const Field = enum { session, header, head, events };

/// What one reading found, whole.
pub const Reading = struct {
    verdict: Verdict = .absent,
    /// The level the record recorded, once the signature has checked out. Null
    /// before that, because an unsigned record's claim is worth nothing.
    claimed: ?Level = null,
    /// What reading the attestation found. `.absent` when the record carried
    /// none.
    attestation: attestation.Verdict = .absent,
    /// For `head_mismatch` only: which field disagreed.
    mismatched: ?Field = null,
    /// Which scheme signed, once the signature has checked out. Null before
    /// that, for the reason `claimed` is: an unchecked record says nothing.
    ///
    /// **Derived from the key, which is inside the signed bytes**, so it is
    /// worth exactly as much as the signature and not one word more.
    scheme: ?Scheme = null,

    /// Whether a signature over this exact log checked out, at any level.
    pub fn signed(self: Reading) bool {
        return switch (self.verdict) {
            .signed_software, .signed_card, .signed_card_attested => true,
            .absent, .malformed, .signature_bad, .head_mismatch, .claim_unsupported => false,
        };
    }

    /// Whether the key is proved to live in hardware. Only an attestation that
    /// chains to the trusted root gives this. **A `signed_card` reading answers
    /// false**, because a claim is not a proof.
    pub fn hardwareProved(self: Reading) bool {
        return self.verdict == .signed_card_attested;
    }

    /// The one sentence a reader needs about what this reading is worth.
    ///
    /// **Here, beside the mechanism**, for the reason `chain.not_a_signature`
    /// sits beside the hash chain: a command prints the same words this module's
    /// own top comment argues for, and the two cannot drift apart.
    ///
    /// **No sentence here reads as a pass for `absent`.** A log nobody sealed is
    /// the ordinary state, and the sentence for it says what is missing rather
    /// than saying nothing.
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

/// The one sentence a reader needs when every log in front of them carries a
/// seal that checks out.
///
/// **The counterpart of `chain.not_a_signature`**, which is the honest sentence
/// for a log with no seal: whoever can rewrite the whole file can hash every
/// line again and write a chain that agrees with it. A seal is the thing that
/// sentence disclaims, so a sealed log has earned different words. Held here,
/// beside the mechanism, for the reason `Reading.sentence` is.
pub const defeats_a_rewrite =
    "A seal over the chain head is what a rewrite of the whole log cannot forge without the key. " ++
    "What that is worth is what the key is worth, which is the level on each row.";

/// What the reader knows about the log it is holding.
pub const Expectation = struct {
    session: []const u8,
    /// The digest of the log's header line, read from the log itself.
    header: []const u8,
    /// The digest of the last line of the log, read from the log itself.
    head: []const u8,
    events: u64,
};

/// What the reader is willing to trust.
pub const Trust = struct {
    /// The DER of the vendor certificate authority an attestation must chain
    /// to. **Null means no attestation can be proved**, so a seal that claims
    /// one reads as `claim_unsupported` rather than being taken on trust.
    root: ?[]const u8 = null,
    /// The moment the certificate validity windows are measured against, in
    /// seconds since the epoch. Passed in rather than read here, so a test pins
    /// it and no assertion in this module depends on a wall clock.
    now_sec: i64,
};

/// Read a seal against the log in front of you. Needs no card, no daemon and no
/// platform branch.
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
            // The canonical bytes and not the digest: this checks the padded
            // block the card signed, and the block holds the hash of the whole
            // message. Hashing it here is the same SHA-256 `digestOf` does.
            rsa.PKCS1v1_5Signature.verify(
                rsa2048_modulus_len,
                seal.signature[0..rsa2048_modulus_len].*,
                bytes,
                public_key,
                Sha256,
            ) catch return .{ .verdict = .signature_bad };
        },
    }

    // Only past this point is the record's own claim worth reading: before it,
    // every field is whatever the last person to touch the file wanted.
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

/// The JSON shape a seal is carried in. **Carriage only**: the signature is
/// never over this text. See this file's own top comment.
///
/// Digests, the key and the signature are lowercase hexadecimal, which is what
/// the rest of this project writes and what a reader can check with a tool they
/// already have. Certificates are base64, because a certificate is around 800
/// bytes and hexadecimal would double the longest line in the record.
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
    /// A field is not the width or the alphabet this format uses.
    Malformed,
} || CanonicalError;

/// The record for a seal. The strings point into `buffer`, which the caller
/// owns and which must outlive the record.
pub const Buffer = struct {
    header: [digest_hex_len]u8 = undefined,
    head: [digest_hex_len]u8 = undefined,
    key: [max_public_key_len * 2]u8 = undefined,
    signature: [max_signature_len * 2]u8 = undefined,
    certs: [max_attestation_certs][base64.Encoder.calcSize(max_certificate_len)]u8 = undefined,
    cert_slices: [max_attestation_certs][]const u8 = undefined,
};

/// Lowercase hexadecimal of `bytes` at the front of `out`, and the part used.
///
/// **Not `std.fmt.bytesToHex`**, which needs the width at compile time. The two
/// schemes give keys and signatures of different widths, and a fixed width here
/// would put the wider one's padding into the record.
fn hexInto(out: []u8, bytes: []const u8) []const u8 {
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        out[i * 2] = alphabet[byte >> 4];
        out[i * 2 + 1] = alphabet[byte & 0x0f];
    }
    return out[0 .. bytes.len * 2];
}

/// Turn a seal into the record that gets written.
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

/// The bytes a seal read out of a record points into: the key, the signature and
/// every decoded certificate.
pub const ReadBuffer = struct {
    key: [max_public_key_len]u8 = undefined,
    signature: [max_signature_len]u8 = undefined,
    bytes: [max_attestation_certs][max_certificate_len]u8 = undefined,
    slices: [max_attestation_certs][]const u8 = undefined,
};

/// Turn a record back into a seal. The seal borrows `record.session` and points
/// into `held`, so both must outlive it.
///
/// **A field of the wrong width is refused rather than padded.** A key that is
/// 64 bytes instead of 65 is not a key with a byte missing; it is a different
/// record. The widths a scheme allows are checked in `read`, by `schemeOf`, so
/// this refuses only what no scheme could hold.
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

/// A key literal for a test that only needs bytes of the right shape. The `04`
/// makes `schemeOf` read it as an elliptic curve point.
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
    // The whole point. No card, no daemon, no credential store, no platform
    // branch: the seal and the log's own digests are everything the reader has.
    var key = try software.Key.fromSeed([_]u8{0x01} ** 32);
    var held_1 = Held{};
    const seal = try sign(testRequest(.software), testSigner(&key), &held_1);

    const reading = read(seal, testExpectation(), .{ .now_sec = 0 });
    try testing.expectEqual(Verdict.signed_software, reading.verdict);
    try testing.expect(reading.signed());
    try testing.expectEqual(@as(?Level, .software), reading.claimed);
    // And the key really was the one that checked it, not a constant answer:
    // the same seal against another key's signature fails below.
    try testing.expect(!reading.hardwareProved());
}

test "one changed byte anywhere in the signed fields breaks the signature" {
    // The mutation check for the canonical form. Every field named in this
    // file's own top comment is tried, because a field left out of `canonical`
    // would be a field an editor could change for free.
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
    // The attack this is built against: somebody unplugs the card, Chock falls
    // back to a software key and records it, and the attacker then edits the
    // level to say a card made it. The level sits inside the signed bytes, so
    // the edit shows up as a broken signature and not as a stronger seal.
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

    // Lowering it is caught the same way. A record is not free to be edited in
    // either direction.
    var held_4 = Held{};
    var lowered = try sign(testRequest(.card), testSigner(&key), &held_4);
    lowered.level = .software;
    try testing.expectEqual(Verdict.signature_bad, read(lowered, expect, .{ .now_sec = 0 }).verdict);
}

test "an attacker who re-signs with their own key cannot claim a card made it" {
    // The second half of the same attack. Editing the level breaks the
    // signature, so the attacker signs a whole new seal with a key they hold and
    // writes `card_attested` in it. The signature checks out, because it is
    // their key, and the claim still fails: there is no attestation behind it.
    var attacker = try software.Key.fromSeed([_]u8{0x04} ** 32);
    var held_5 = Held{};
    var forged = try sign(testRequest(.card), testSigner(&attacker), &held_5);
    // `sign` refuses to write `card_attested` with no attestation, so the
    // attacker writes it directly and signs the result themselves, which is the
    // strongest version of this attack.
    forged.level = .card_attested;
    const forged_signature = try attacker.signDigest(try digestOf(forged));
    forged.signature = &forged_signature;

    const reading = read(forged, testExpectation(), .{ .now_sec = 0 });
    try testing.expectEqual(Verdict.claim_unsupported, reading.verdict);
    try testing.expect(!reading.signed());
    try testing.expect(!reading.hardwareProved());
    try testing.expectEqual(attestation.Verdict.absent, reading.attestation);
    // The record still says what it claimed, so a message can name it.
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
    // What a log whose chain was repaired by hand looks like. The repair
    // rehashed every line, so the head is a different digest from the one that
    // was signed, and the signature is over the old head and still checks out.
    // Reporting that as a broken signature would send a reader looking for the
    // wrong thing.
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

    // A seal lifted from another session is caught the same way.
    var moved = testExpectation();
    moved.session = "01J0ELSEWHERE";
    try testing.expectEqual(@as(?Field, .session), read(seal, moved, .{ .now_sec = 0 }).mismatched);

    // And an event appended past the head with the head left alone.
    var grown = testExpectation();
    grown.events = 43;
    try testing.expectEqual(@as(?Field, .events), read(seal, grown, .{ .now_sec = 0 }).mismatched);

    var reheaded = testExpectation();
    const other_header = [_]u8{'d'} ** digest_hex_len;
    reheaded.header = &other_header;
    try testing.expectEqual(@as(?Field, .header), read(seal, reheaded, .{ .now_sec = 0 }).mismatched);
}

test "the default reading is absent, and absent is never a pass" {
    // The same rule `chain.Report` keeps for a log nothing could open.
    const nothing = Reading{};
    try testing.expectEqual(Verdict.absent, nothing.verdict);
    try testing.expect(!nothing.signed());
    try testing.expect(!nothing.hardwareProved());
    try testing.expectEqual(@as(?Level, null), nothing.claimed);
}

test "every verdict has its own sentence, and no sentence for an absent seal reads as a pass" {
    // The rule the command depends on. A reading that printed nothing for
    // `absent`, or printed the same words as a signed one, would let a reader
    // take silence for a signature.
    var seen: [@typeInfo(Verdict).@"enum".fields.len][]const u8 = undefined;
    inline for (@typeInfo(Verdict).@"enum".fields, 0..) |field, i| {
        const text = (Reading{ .verdict = @enumFromInt(field.value) }).sentence();
        try testing.expect(text.len != 0);
        for (seen[0..i]) |earlier| try testing.expect(!std.mem.eql(u8, earlier, text));
        seen[i] = text;
    }

    // And the words themselves: the absent sentence names what is missing, and
    // says nothing a reader could take for a signature.
    const absent_text = (Reading{ .verdict = .absent }).sentence();
    try testing.expect(std.mem.indexOf(u8, absent_text, "no seal") != null);
    try testing.expect(std.mem.indexOf(u8, absent_text, "is sealed") == null);

    // A seal that checks out says which of the three levels made it, by name.
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
    // Caught in the signer as well as in the reader. A seal that claims what it
    // cannot show is a bug in Chock, and it should fail where it is written
    // rather than months later in front of an auditor.
    var key = try software.Key.fromSeed([_]u8{0x08} ** 32);
    var held_8 = Held{};
    try testing.expectError(
        error.AttestationMissing,
        sign(testRequest(.card_attested), testSigner(&key), &held_8),
    );
}

test "the canonical form separates fields by length, so no field can eat another" {
    // The forgery a separator based encoding allows. Two different seals whose
    // fields concatenate to the same text must not hash the same. With a length
    // in front of each field they cannot.
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
    // A form that joined the session to the next field with no length would
    // give these two the same bytes for a header starting with "b".
    var buffer_one: [max_canonical_len]u8 = undefined;
    var buffer_two: [max_canonical_len]u8 = undefined;
    const bytes_one = try canonical(one, &buffer_one);
    const bytes_two = try canonical(two, &buffer_two);
    try testing.expect(!std.mem.eql(u8, bytes_one, bytes_two));

    // And the prefix is there, so a signature over this shape can never be read
    // as a signature over a later one.
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
    // Two different faults. A record whose key is nonsense was never a
    // signature at all, and calling it a bad signature would point a reader at
    // tampering that did not happen.
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
    // The numbers are wire format and must not move.
    try testing.expectEqual(@as(u8, 1), @intFromEnum(Level.card_attested));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(Level.card));
    try testing.expectEqual(@as(u8, 3), @intFromEnum(Level.software));
}

test "a seal survives the trip through its record with every field intact" {
    // The record is carriage only, so the proof it works is that a seal read
    // back out of one still verifies. A field lost or reordered in the JSON
    // would break the signature here rather than in front of an auditor.
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

    // **The width of a key belongs to its scheme, so `read` is where it is
    // refused.** A key one byte short is not an elliptic curve point and not an
    // RSA key either, so `schemeOf` answers neither and the reading is
    // `malformed`. Refusing it in `fromRecord` by a fixed width would have made
    // an RSA key unreadable, which is the whole reason this moved.
    var short_key = record;
    short_key.key = record.key[0 .. record.key.len - 2];
    var certs = ReadBuffer{};
    const with_short_key = try fromRecord(short_key, &certs);
    try testing.expectEqual(@as(?Scheme, null), schemeOf(with_short_key.key));
    try testing.expectEqual(
        Verdict.malformed,
        read(with_short_key, testExpectation(), .{ .now_sec = 0 }).verdict,
    );

    // An odd number of hexadecimal characters is not a field of any width, so
    // it is refused where it is read.
    var half_byte = record;
    half_byte.key = record.key[0 .. record.key.len - 1];
    try testing.expectError(error.KeyUnusable, fromRecord(half_byte, &certs));

    var short_head = record;
    short_head.head = record.head[0..63];
    try testing.expectError(error.DigestUnusable, fromRecord(short_head, &certs));

    // The same for a signature: the scheme decides how wide one is.
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

    // A key of the right width that is not hexadecimal at all.
    var not_hex = record;
    const junk = [_]u8{'z'} ** (public_key_len * 2);
    not_hex.key = &junk;
    try testing.expectError(error.Malformed, fromRecord(not_hex, &certs));
}

test {
    testing.refAllDecls(@This());
}

test "an elliptic curve key and an RSA key cannot be read as one another" {
    // The whole of the algorithm agility in this format. The key's own bytes
    // say which scheme signed, so no field outside the signature decides it.
    const ec = [_]u8{0x04} ++ [_]u8{0x11} ** 64;
    try testing.expectEqual(@as(?Scheme, .ecdsa_p256), schemeOf(&ec));

    const rsa_key = [_]u8{ 0x81, 0x82, 0x01, 0x00 } ++ [_]u8{0xab} ** 256 ++
        [_]u8{ 0x82, 0x03, 0x01, 0x00, 0x01 };
    try testing.expectEqual(@as(?Scheme, .rsa2048), schemeOf(&rsa_key));
    const parts = rsaParts(&rsa_key).?;
    try testing.expectEqual(@as(usize, 256), parts.modulus.len);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x01 }, parts.exponent);

    // Neither shape is reachable from the other, and everything else is
    // `malformed` rather than a bad signature: nothing signed it.
    const uncompressed_but_short = [_]u8{0x04} ++ [_]u8{0x11} ** 63;
    try testing.expectEqual(@as(?Scheme, null), schemeOf(&uncompressed_but_short));
    const compressed = [_]u8{0x02} ++ [_]u8{0x11} ** 64;
    try testing.expectEqual(@as(?Scheme, null), schemeOf(&compressed));
    try testing.expectEqual(@as(?Scheme, null), schemeOf(""));
    // An RSA key whose modulus is not 2048 bits.
    const small = [_]u8{ 0x81, 0x81, 0x80 } ++ [_]u8{0xab} ** 128 ++
        [_]u8{ 0x82, 0x03, 0x01, 0x00, 0x01 };
    try testing.expectEqual(@as(?Scheme, null), schemeOf(&small));
    // The two elements the other way round. **One key, one encoding**: a form
    // that took either order would give the same key two sets of signed bytes.
    const swapped = [_]u8{ 0x82, 0x03, 0x01, 0x00, 0x01 } ++
        [_]u8{ 0x81, 0x82, 0x01, 0x00 } ++ [_]u8{0xab} ** 256;
    try testing.expectEqual(@as(?Scheme, null), schemeOf(&swapped));
    // And a third element after the two, which is a key with something extra
    // stuck on the end of it.
    const trailing = rsa_key ++ [_]u8{ 0x83, 0x01, 0x00 };
    try testing.expectEqual(@as(?Scheme, null), schemeOf(&trailing));
}

test "a seal written before the key field could vary is still read and still verifies" {
    // **The one thing a format change here may not do.** A log is append only
    // and hash chained, so a seal that stopped verifying could not be made
    // again: the head it names belongs to a session that has ended.
    //
    // The record below is a real one, copied out of
    // `~/.local/state/chock/sessions` on the machine this was written for. It
    // was written by the build before the key and the signature became variable
    // width, and it is read here by the build that came after. **The widening
    // changed no encoding**, because the key was already written with its length
    // in front of it, and this is what says so.
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
    // The line breaks above are for reading. JSON has no place for them inside
    // a string, so they come out before the parser sees it.
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

    // Still an elliptic curve key, still 65 bytes, still the same scheme.
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
