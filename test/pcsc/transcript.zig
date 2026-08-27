//! A whole PIV exchange, played back with no card, no reader and no daemon.
//!
//! ## What this is, and what it is not
//!
//! **This transcript was not captured from a physical card.** No card and no
//! reader was available where this was written. Every command in it is built
//! from NIST SP 800-73-4, named table by table in `lib/chock-pcsc/piv.zig`, and
//! every answer is built into the container shape that document specifies.
//!
//! What that still catches, and it is most of the value: the transcript is
//! written out here, and `chock_pcsc.Recorded` refuses any command it does not
//! hold. So the bytes `piv.zig` sends are pinned against a written down
//! expectation rather than against whatever the code happens to produce. A
//! change to one byte of a command fails this file.
//!
//! What it cannot catch: a place where SP 800-73-4 and a real card disagree, or
//! a vendor quirk. That needs a card, and it is named as an open item rather
//! than glossed over.
//!
//! **One piece of it is genuinely from another implementation.** The signature
//! the card answers with was made by `openssl`, not by Chock, so decoding it and
//! checking it against the certificate proves the decoding is right rather than
//! proving two halves of one program agree. See `fixtures.zig`.

const std = @import("std");
const chock_pcsc = @import("chock-pcsc");
const fixtures = @import("fixtures.zig");

const piv = chock_pcsc.piv;
const testing = std.testing;

fn beU16(comptime n: usize) [2]u8 {
    return .{ @intCast(n >> 8), @intCast(n & 0xff) };
}

/// The certificate container a card answers `GET DATA` with, SP 800-73-4 part 1
/// table 39: `53 { 70 (the certificate), 71 (one CertInfo byte), FE (a check
/// byte) }`.
const container_contents =
    [_]u8{ 0x70, 0x82 } ++ beU16(fixtures.leaf_der.len) ++ fixtures.leaf_der ++
    [_]u8{ 0x71, 0x01, 0x00 } ++
    [_]u8{ 0xfe, 0x00 };
const container = [_]u8{ 0x53, 0x82 } ++ beU16(container_contents.len) ++ container_contents;

comptime {
    // A card sends at most 256 bytes an exchange, so this container takes
    // exactly three of them. A fixture change that moved that boundary would
    // silently stop testing the `GET RESPONSE` loop, so it fails the build
    // instead.
    if (container.len != 515) @compileError("the recorded container is no longer three exchanges long");
}

/// The command that asks for the digital signature slot's certificate.
const get_certificate = [_]u8{ 0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x0a, 0x00 };
/// `GET RESPONSE` for 256 more bytes. The length byte zero means 256, never
/// none.
const get_response_256 = [_]u8{ 0x00, 0xc0, 0x00, 0x00, 0x00 };
/// `GET RESPONSE` for the last three bytes.
const get_response_3 = [_]u8{ 0x00, 0xc0, 0x00, 0x00, 0x03 };

/// The `GENERAL AUTHENTICATE` that asks slot `9C` to sign the digest, with the
/// nested template of SP 800-73-4 part 2 table 7.
const general_authenticate =
    [_]u8{ 0x00, 0x87, 0x11, 0x9c, 0x26, 0x7c, 0x24, 0x82, 0x00, 0x81, 0x20 } ++
    fixtures.transcript_digest ++
    [_]u8{0x00};

const signature_answer =
    [_]u8{ 0x7c, @intCast(fixtures.transcript_signature_der.len + 2), 0x82, @intCast(fixtures.transcript_signature_der.len) } ++
    fixtures.transcript_signature_der ++
    [_]u8{ 0x90, 0x00 };

const select_command =
    [_]u8{ 0x00, 0xa4, 0x04, 0x00, 0x0b } ++ piv.aid ++ [_]u8{0x00};
const select_answer = [_]u8{ 0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x90, 0x00 };
const verify_command = [_]u8{ 0x00, 0x20, 0x00, 0x80, 0x08, '1', '2', '3', '4', '5', '6', 0xff, 0xff };

/// Selecting the PIV application, which every other command needs first.
/// Shared with `verify.zig`, which drives a whole card path over it.
pub const select_exchange = chock_pcsc.Exchange{
    .send = &select_command,
    .receive = &select_answer,
};

/// Reading the certificate out of the digital signature slot, which takes three
/// exchanges because the container is 515 bytes and a card answers at most 256
/// bytes at a time. Shared with `verify.zig`, which drives the same card
/// through a whole seal.
pub const certificate_exchanges = [_]chock_pcsc.Exchange{
    .{ .send = &get_certificate, .receive = container[0..256] ++ [_]u8{ 0x61, 0x00 } },
    .{ .send = &get_response_256, .receive = container[256..512] ++ [_]u8{ 0x61, 0x03 } },
    .{ .send = &get_response_3, .receive = container[512..] ++ [_]u8{ 0x90, 0x00 } },
};

/// The whole session, in the order a card sees it: select the application, give
/// the PIN, read the certificate, sign.
const session = [_]chock_pcsc.Exchange{
    .{ .send = &select_command, .receive = &select_answer },
    .{ .send = &verify_command, .receive = &.{ 0x90, 0x00 } },
} ++ certificate_exchanges ++ [_]chock_pcsc.Exchange{
    .{ .send = &general_authenticate, .receive = &signature_answer },
};

test "a whole PIV session round trips, and every recorded exchange is reached" {
    // The end to end pass over the APDU layer: select, PIN, a certificate that
    // takes three exchanges to read, and a signature.
    var recorded = chock_pcsc.Recorded{ .exchanges = &session };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);
    defer card.disconnect();

    var out: [piv.max_object_len]u8 = undefined;
    try piv.select(card, &out);
    try testing.expectEqual(piv.PinOutcome.accepted, try piv.verifyPin(card, "123456", &out));

    // The certificate comes back whole, all 502 bytes of it, joined from three
    // exchanges. A loop that stopped at the first `61 XX` would give back 256.
    const certificate = try piv.readCertificate(card, .digital_signature, &out);
    try testing.expectEqualSlices(u8, &fixtures.leaf_der, certificate);

    var signing_out: [piv.max_object_len]u8 = undefined;
    var signature_bytes: [chock_pcsc.seal.max_signature_len]u8 = undefined;
    const signature = try piv.signDigest(
        card,
        .digital_signature,
        .ecc_p256,
        fixtures.transcript_digest,
        &signing_out,
        &signature_bytes,
    );

    // The signature the card gave, decoded from DER into the fixed width form,
    // checks out against the public key in the certificate the card gave. Two
    // separate answers from the transcript agreeing with each other is what
    // makes this more than a decoding exercise.
    const key = try chock_pcsc.attestation.publicKeyOf(certificate);
    const public_key = try chock_pcsc.seal.Ecdsa.PublicKey.fromSec1(&key);
    try chock_pcsc.seal.Ecdsa.Signature.fromBytes(signature[0..chock_pcsc.seal.signature_len].*)
        .verifyPrehashed(fixtures.transcript_digest, public_key);

    // Every recorded step was played. Without this a flow that stopped after
    // the certificate would still pass every assertion above it.
    try testing.expect(recorded.drained());
}

test "a command with one byte changed is refused by the recorded transport" {
    // The property that keeps this transcript from being a stand-in more
    // permissive than a real card. If `piv.zig` ever sends a different byte,
    // the test above fails rather than passing quietly, and this proves the
    // transport really does compare.
    var wrong_slot = session;
    var altered = general_authenticate;
    altered[3] = 0x9a;
    wrong_slot[5] = .{ .send = &altered, .receive = &signature_answer };

    var recorded = chock_pcsc.Recorded{ .exchanges = &wrong_slot };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);

    var out: [piv.max_object_len]u8 = undefined;
    var signature_bytes: [chock_pcsc.seal.max_signature_len]u8 = undefined;
    try piv.select(card, &out);
    _ = try piv.verifyPin(card, "123456", &out);
    _ = try piv.readCertificate(card, .digital_signature, &out);
    try testing.expectError(error.Unexpected, piv.signDigest(
        card,
        .digital_signature,
        .ecc_p256,
        fixtures.transcript_digest,
        &out,
        &signature_bytes,
    ));
}

test "a card that answers a signature that is not DER is refused, not accepted" {
    // The card is untrusted input. A malformed answer must come back as a named
    // fault and never as a signature made of whatever bytes arrived.
    var broken = session;
    const junk = [_]u8{ 0x7c, 0x04, 0x82, 0x02, 0xff, 0xff, 0x90, 0x00 };
    broken[5] = .{ .send = &general_authenticate, .receive = &junk };

    var recorded = chock_pcsc.Recorded{ .exchanges = &broken };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);

    var out: [piv.max_object_len]u8 = undefined;
    var signature_bytes: [chock_pcsc.seal.max_signature_len]u8 = undefined;
    try piv.select(card, &out);
    _ = try piv.verifyPin(card, "123456", &out);
    _ = try piv.readCertificate(card, .digital_signature, &out);
    try testing.expectError(error.SignatureMalformed, piv.signDigest(
        card,
        .digital_signature,
        .ecc_p256,
        fixtures.transcript_digest,
        &out,
        &signature_bytes,
    ));
}

test {
    testing.refAllDecls(@This());
}
