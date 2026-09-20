//! A whole PIV exchange, played back with no card, no reader and no daemon.
//! Every command is built from NIST SP 800-73-4, not captured from a card, so it
//! cannot catch a place where that document and a real card disagree.

const std = @import("std");
const chock_pcsc = @import("chock-pcsc");
const fixtures = @import("fixtures.zig");

const piv = chock_pcsc.piv;
const testing = std.testing;

fn beU16(comptime n: usize) [2]u8 {
    return .{ @intCast(n >> 8), @intCast(n & 0xff) };
}

/// SP 800-73-4 part 1 table 39: `53 { 70 certificate, 71 CertInfo, FE check }`.
const container_contents =
    [_]u8{ 0x70, 0x82 } ++ beU16(fixtures.leaf_der.len) ++ fixtures.leaf_der ++
    [_]u8{ 0x71, 0x01, 0x00 } ++
    [_]u8{ 0xfe, 0x00 };
const container = [_]u8{ 0x53, 0x82 } ++ beU16(container_contents.len) ++ container_contents;

comptime {
    // A card sends at most 256 bytes an exchange. A fixture change that moved this
    // boundary would stop testing the `GET RESPONSE` loop without saying so.
    if (container.len != 515) @compileError("the recorded container is no longer three exchanges long");
}

const get_certificate = [_]u8{ 0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x0a, 0x00 };
/// `GET RESPONSE` for 256 more bytes. The length byte zero means 256, never none.
const get_response_256 = [_]u8{ 0x00, 0xc0, 0x00, 0x00, 0x00 };
const get_response_3 = [_]u8{ 0x00, 0xc0, 0x00, 0x00, 0x03 };

/// SP 800-73-4 part 2 table 7 nests the template this way.
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

/// Shared with `verify.zig`, which drives a whole card path over it.
pub const select_exchange = chock_pcsc.Exchange{
    .send = &select_command,
    .receive = &select_answer,
};

/// Three exchanges, because a card answers at most 256 bytes. Shared with
/// `verify.zig`.
pub const certificate_exchanges = [_]chock_pcsc.Exchange{
    .{ .send = &get_certificate, .receive = container[0..256] ++ [_]u8{ 0x61, 0x00 } },
    .{ .send = &get_response_256, .receive = container[256..512] ++ [_]u8{ 0x61, 0x03 } },
    .{ .send = &get_response_3, .receive = container[512..] ++ [_]u8{ 0x90, 0x00 } },
};

const session = [_]chock_pcsc.Exchange{
    .{ .send = &select_command, .receive = &select_answer },
    .{ .send = &verify_command, .receive = &.{ 0x90, 0x00 } },
} ++ certificate_exchanges ++ [_]chock_pcsc.Exchange{
    .{ .send = &general_authenticate, .receive = &signature_answer },
};

test "a whole PIV session round trips, and every recorded exchange is reached" {
    var recorded = chock_pcsc.Recorded{ .exchanges = &session };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);
    defer card.disconnect();

    var out: [piv.max_object_len]u8 = undefined;
    try piv.select(card, &out);
    try testing.expectEqual(piv.PinOutcome.accepted, try piv.verifyPin(card, "123456", &out));

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

    const key = try chock_pcsc.attestation.publicKeyOf(certificate);
    const public_key = try chock_pcsc.seal.Ecdsa.PublicKey.fromSec1(&key);
    try chock_pcsc.seal.Ecdsa.Signature.fromBytes(signature[0..chock_pcsc.seal.signature_len].*)
        .verifyPrehashed(fixtures.transcript_digest, public_key);

    try testing.expect(recorded.drained());
}

test "a command with one byte changed is refused by the recorded transport" {
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
