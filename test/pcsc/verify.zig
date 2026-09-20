//! A seal over a real hash chain, read back with nothing but a public key. A log
//! rewritten by hand, with every `prev` written again, is a log the chain reports
//! as holding, and the seal is what catches it. No card, reader or daemon.

const std = @import("std");
const chock_pcsc = @import("chock-pcsc");
const chock_proto = @import("chock-proto");
const fixtures = @import("fixtures.zig");

const chain = chock_proto.chain;
const seal = chock_pcsc.seal;
const piv = chock_pcsc.piv;
const software = chock_pcsc.software;
const testing = std.testing;

test {
    _ = @import("attestation.zig");
    _ = @import("transcript.zig");
}

const session_id = "01JZZZZZZZZZZZZZZZZZZZZZZZ";
const header_line = "{\"chock_log\":1}";

/// Each line carries the digest of the line before it, inside the line, so an
/// edit changes every line after it and the head with them.
const Log = struct {
    const max_line = 192;

    text: [3][max_line]u8 = undefined,
    lengths: [3]usize = undefined,
    prevs: [3]chain.Digest = undefined,
    /// Held here, because an expectation points at it.
    header: chain.Digest = undefined,

    fn build(says: [3][]const u8) !Log {
        var log = Log{};
        log.header = chain.of(header_line);
        var previous = log.header;
        for (says, 0..) |say, i| {
            log.prevs[i] = previous;
            const written = try std.fmt.bufPrint(
                &log.text[i],
                "{{\"id\":{d},\"prev\":\"{s}\",\"say\":\"{s}\"}}",
                .{ 16 + i * 16, previous, say },
            );
            log.lengths[i] = written.len;
            previous = chain.of(written);
        }
        return log;
    }

    fn line(self: *const Log, index: usize) []const u8 {
        return self.text[index][0..self.lengths[index]];
    }

    fn verdict(self: *const Log) chain.Verdict {
        var verifier = chain.Verifier.init(self.header);
        for (0..3) |i| verifier.take(@intCast(16 + i * 16), self.line(i), &self.prevs[i]);
        return verifier.finish(.complete, 0).verdict;
    }

    /// The one thing no event in the log carries.
    fn head(self: *const Log) chain.Digest {
        return chain.of(self.line(2));
    }
};

fn expectationFor(log: *const Log, head: *const chain.Digest) seal.Expectation {
    return .{
        .session = session_id,
        .header = &log.header,
        .head = head,
        .events = 3,
    };
}

fn requestFor(log: *const Log, head: chain.Digest, level: seal.Level) seal.Request {
    return .{
        .session = session_id,
        .header = log.header,
        .head = head,
        .events = 3,
        .level = level,
    };
}

fn softwareSigner(key: *software.Key) seal.Signer {
    return .{ .ptr = key, .vtable = &software_vtable };
}

fn softwarePublicKey(ptr: *anyopaque, out: *[seal.max_public_key_len]u8) seal.SignError![]const u8 {
    const key: *software.Key = @ptrCast(@alignCast(ptr));
    out[0..seal.public_key_len].* = key.publicKey();
    return out[0..seal.public_key_len];
}

fn softwareSignDigest(
    ptr: *anyopaque,
    digest: [32]u8,
    out: *[seal.max_signature_len]u8,
) seal.SignError![]const u8 {
    const key: *software.Key = @ptrCast(@alignCast(ptr));
    out[0..seal.signature_len].* = key.signDigest(digest) catch return error.Unusable;
    return out[0..seal.signature_len];
}

const software_vtable = seal.Signer.VTable{
    .publicKey = softwarePublicKey,
    .signDigest = softwareSignDigest,
};

test "a signature over a chain head verifies with only a public key" {
    const log = try Log.build(.{
        "first", "second", "third",
    });
    try testing.expectEqual(chain.Verdict.intact, log.verdict());

    var key = try software.Key.fromSeed([_]u8{0x21} ** 32);
    const head = log.head();
    var vheld_1 = seal.Held{};
    const sealed = try seal.sign(requestFor(&log, head, .software), softwareSigner(&key), &vheld_1);

    const reading = seal.read(sealed, expectationFor(&log, &head), .{ .now_sec = fixtures.inside_window });
    try testing.expectEqual(seal.Verdict.signed_software, reading.verdict);
    try testing.expect(reading.signed());
}

test "a log whose chain was repaired by hand passes the chain and fails the seal" {
    const original = try Log.build(.{
        "first", "paid 10", "third",
    });
    try testing.expectEqual(chain.Verdict.intact, original.verdict());

    var key = try software.Key.fromSeed([_]u8{0x22} ** 32);
    const head = original.head();
    var vheld_2 = seal.Held{};
    const sealed = try seal.sign(requestFor(&original, head, .software), softwareSigner(&key), &vheld_2);
    try testing.expectEqual(
        seal.Verdict.signed_software,
        seal.read(sealed, expectationFor(&original, &head), .{ .now_sec = 0 }).verdict,
    );

    const repaired = try Log.build(.{
        "first", "paid 90", "third",
    });
    try testing.expectEqual(chain.Verdict.intact, repaired.verdict());

    const repaired_head = repaired.head();
    const reading = seal.read(sealed, expectationFor(&repaired, &repaired_head), .{ .now_sec = 0 });
    try testing.expectEqual(seal.Verdict.head_mismatch, reading.verdict);
    try testing.expectEqual(@as(?seal.Field, .head), reading.mismatched);
    try testing.expect(!reading.signed());
}

test "cutting the last event off a log changes the head, which no chain notices" {
    const whole = try Log.build(.{
        "first", "second", "the thing somebody wants gone",
    });
    var key = try software.Key.fromSeed([_]u8{0x23} ** 32);
    const head = whole.head();
    var vheld_3 = seal.Held{};
    const sealed = try seal.sign(requestFor(&whole, head, .software), softwareSigner(&key), &vheld_3);

    var verifier = chain.Verifier.init(whole.header);
    verifier.take(16, whole.line(0), &whole.prevs[0]);
    verifier.take(32, whole.line(1), &whole.prevs[1]);
    try testing.expectEqual(chain.Verdict.intact, verifier.finish(.complete, 0).verdict);

    // Nothing carries the hash of the last line, so removing it leaves a chain
    // that still holds.
    const shorter_head = chain.of(whole.line(1));
    const reading = seal.read(sealed, .{
        .session = session_id,
        .header = &whole.header,
        .head = &shorter_head,
        .events = 2,
    }, .{ .now_sec = 0 });
    try testing.expectEqual(seal.Verdict.head_mismatch, reading.verdict);
    try testing.expect(!reading.signed());
}

test "a digest of this project's chain is the width a seal carries" {
    // Two modules write the same digest width in two places.
    try testing.expectEqual(chain.digest_len, seal.digest_hex_len);
    try testing.expect(seal.isDigest(&chain.of("anything at all")));
}

/// The signature answer is built here, because the digest a seal signs is not
/// known until the seal's fields are settled.
const CardTape = struct {
    body: [64]u8 = undefined,
    request: [128]u8 = undefined,
    answer: [128]u8 = undefined,
    exchanges: [transcript.certificate_exchanges.len + 1]chock_pcsc.Exchange = undefined,

    fn build(self: *CardTape, digest: [32]u8) ![]const chock_pcsc.Exchange {
        const key = try software.Key.fromSecret(fixtures.leaf_secret);
        const raw = try key.signDigest(digest);
        var der_buffer: [seal.Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        const der = seal.Ecdsa.Signature.fromBytes(raw).toDer(&der_buffer);

        const command = try piv.generalAuthenticateCommand(
            .digital_signature,
            .ecc_p256,
            &digest,
            &self.body,
        );
        const request_bytes = try command.encode(&self.request);

        self.answer[0] = 0x7c;
        self.answer[1] = @intCast(der.len + 2);
        self.answer[2] = 0x82;
        self.answer[3] = @intCast(der.len);
        @memcpy(self.answer[4..][0..der.len], der);
        self.answer[4 + der.len] = 0x90;
        self.answer[5 + der.len] = 0x00;

        @memcpy(
            self.exchanges[0..transcript.certificate_exchanges.len],
            &transcript.certificate_exchanges,
        );
        self.exchanges[transcript.certificate_exchanges.len] = .{
            .send = request_bytes,
            .receive = self.answer[0 .. 6 + der.len],
        };
        return &self.exchanges;
    }
};

const transcript = @import("transcript.zig");

test "a card key with an attestation reads as level 1, with only the root to trust" {
    const log = try Log.build(.{
        "first", "second", "third",
    });
    const head = log.head();
    const attestation_chain = [_][]const u8{ &fixtures.leaf_der, &fixtures.intermediate_der };

    var certificate_only = chock_pcsc.Recorded{ .exchanges = &transcript.certificate_exchanges };
    const first_transport = certificate_only.pcsc();
    try first_transport.establish();
    const first_card = try first_transport.connect(certificate_only.reader_name);
    var scratch: [piv.max_object_len]u8 = undefined;
    var probe = try piv.CardSigner.init(first_card, .digital_signature, &scratch);

    var request = requestFor(&log, head, .card_attested);
    request.attestation = &attestation_chain;
    const digest = try seal.digestOf(.{
        .session = request.session,
        .header = request.header,
        .head = request.head,
        .events = request.events,
        .level = request.level,
        .key = probe.key(),
        .signature = probe.key(),
    });

    var tape = CardTape{};
    var recorded = chock_pcsc.Recorded{ .exchanges = try tape.build(digest) };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);
    var signing_scratch: [piv.max_object_len]u8 = undefined;
    var signer = try piv.CardSigner.init(card, .digital_signature, &signing_scratch);
    var vheld_8 = seal.Held{};
    const sealed = try seal.sign(request, signer.signer(), &vheld_8);
    try testing.expect(recorded.drained());

    const reading = seal.read(sealed, expectationFor(&log, &head), .{
        .root = &fixtures.root_der,
        .now_sec = fixtures.inside_window,
    });
    try testing.expectEqual(seal.Verdict.signed_card_attested, reading.verdict);
    try testing.expect(reading.hardwareProved());
    try testing.expectEqual(chock_pcsc.attestation.Verdict.bound, reading.attestation);
}

test "the same seal with the attestation stripped falls to claim_unsupported" {
    const log = try Log.build(.{
        "first", "second", "third",
    });
    const head = log.head();
    const attestation_chain = [_][]const u8{ &fixtures.leaf_der, &fixtures.intermediate_der };

    var key = try software.Key.fromSecret(fixtures.leaf_secret);
    var request = requestFor(&log, head, .card_attested);
    request.attestation = &attestation_chain;
    var vheld_4 = seal.Held{};
    const sealed = try seal.sign(request, softwareSigner(&key), &vheld_4);

    var stripped = sealed;
    stripped.attestation = &.{};
    const reading = seal.read(stripped, expectationFor(&log, &head), .{
        .root = &fixtures.root_der,
        .now_sec = fixtures.inside_window,
    });
    try testing.expectEqual(seal.Verdict.claim_unsupported, reading.verdict);
    try testing.expect(!reading.hardwareProved());
    try testing.expectEqual(chock_pcsc.attestation.Verdict.absent, reading.attestation);
}

test "an auditor with no root cannot prove hardware, and does not pretend to" {
    const log = try Log.build(.{
        "first", "second", "third",
    });
    const head = log.head();
    const attestation_chain = [_][]const u8{ &fixtures.leaf_der, &fixtures.intermediate_der };

    var key = try software.Key.fromSecret(fixtures.leaf_secret);
    var request = requestFor(&log, head, .card_attested);
    request.attestation = &attestation_chain;
    var vheld_5 = seal.Held{};
    const sealed = try seal.sign(request, softwareSigner(&key), &vheld_5);

    const reading = seal.read(sealed, expectationFor(&log, &head), .{ .now_sec = fixtures.inside_window });
    try testing.expectEqual(seal.Verdict.claim_unsupported, reading.verdict);
    try testing.expectEqual(chock_pcsc.attestation.Verdict.no_root, reading.attestation);
}

test "the level a fallback recorded cannot be raised by the person who caused it" {
    const log = try Log.build(.{
        "first", "second", "third",
    });
    const head = log.head();
    var key = try software.Key.fromSeed([_]u8{0x24} ** 32);
    var vheld_6 = seal.Held{};
    const sealed = try seal.sign(requestFor(&log, head, .software), softwareSigner(&key), &vheld_6);
    const expect = expectationFor(&log, &head);
    const trust = seal.Trust{ .root = &fixtures.root_der, .now_sec = fixtures.inside_window };

    try testing.expectEqual(seal.Verdict.signed_software, seal.read(sealed, expect, trust).verdict);

    var raised = sealed;
    raised.level = .card_attested;
    try testing.expectEqual(seal.Verdict.signature_bad, seal.read(raised, expect, trust).verdict);

    const attestation_chain = [_][]const u8{ &fixtures.leaf_der, &fixtures.intermediate_der };
    raised.attestation = &attestation_chain;
    try testing.expectEqual(seal.Verdict.signature_bad, seal.read(raised, expect, trust).verdict);

    var forged = raised;
    const forged_bytes = try key.signDigest(try seal.digestOf(forged));
    forged.signature = &forged_bytes;
    const reading = seal.read(forged, expect, trust);
    try testing.expectEqual(seal.Verdict.claim_unsupported, reading.verdict);
    try testing.expectEqual(chock_pcsc.attestation.Verdict.key_mismatch, reading.attestation);
    try testing.expect(!reading.hardwareProved());
}

const attempt = chock_pcsc.attempt;

const SignatureExchange = struct {
    body: [64]u8 = undefined,
    request: [128]u8 = undefined,
    answer: [128]u8 = undefined,

    fn make(self: *SignatureExchange, digest: [32]u8) !chock_pcsc.Exchange {
        const key = try software.Key.fromSecret(fixtures.leaf_secret);
        const raw = try key.signDigest(digest);
        var der_buffer: [seal.Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        const der = seal.Ecdsa.Signature.fromBytes(raw).toDer(&der_buffer);

        const command = try piv.generalAuthenticateCommand(
            attempt.seal_slot,
            .ecc_p256,
            &digest,
            &self.body,
        );
        const request_bytes = try command.encode(&self.request);

        self.answer[0] = 0x7c;
        self.answer[1] = @intCast(der.len + 2);
        self.answer[2] = 0x82;
        self.answer[3] = @intCast(der.len);
        @memcpy(self.answer[4..][0..der.len], der);
        self.answer[4 + der.len] = 0x90;
        self.answer[5 + der.len] = 0x00;
        return .{ .send = request_bytes, .receive = self.answer[0 .. 6 + der.len] };
    }
};

/// `Recorded` refuses a command it has no recording of, so a change to the order
/// or to one byte fails here.
const PathTape = struct {
    probe: SignatureExchange = .{},
    real: SignatureExchange = .{},
    exchanges: [transcript.certificate_exchanges.len + 4]chock_pcsc.Exchange = undefined,

    const metadata_command = [_]u8{ 0x00, 0xf7, 0x00, 0x9c, 0x00 };
    /// A card with no `GET METADATA`, so this tape drives the certificate path.
    const metadata_exchange = chock_pcsc.Exchange{
        .send = &metadata_command,
        .receive = &.{ 0x6d, 0x00 },
    };

    /// A constant of `attempt.zig`, so it is known before the seal is.
    fn probeDigest() [32]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(attempt.probe_domain, &digest, .{});
        return digest;
    }

    fn build(self: *PathTape, seal_digest: ?[32]u8) ![]const chock_pcsc.Exchange {
        self.exchanges[0] = transcript.select_exchange;
        self.exchanges[1] = metadata_exchange;
        @memcpy(
            self.exchanges[2..][0..transcript.certificate_exchanges.len],
            &transcript.certificate_exchanges,
        );
        const after_certificate = 2 + transcript.certificate_exchanges.len;
        self.exchanges[after_certificate] = try self.probe.make(probeDigest());
        const digest = seal_digest orelse return self.exchanges[0 .. after_certificate + 1];
        self.exchanges[after_certificate + 1] = try self.real.make(digest);
        return self.exchanges[0 .. after_certificate + 2];
    }
};

test "the card path a command takes gives a level 2 seal, and names the reader it used" {
    const log = try Log.build(.{
        "first", "second", "third",
    });
    const head = log.head();

    var first_tape = PathTape{};
    var first_recorded = chock_pcsc.Recorded{ .exchanges = try first_tape.build(null) };
    var first_scratch: [piv.max_object_len]u8 = undefined;
    var first = attempt.Attempt.init(first_recorded.pcsc(), &first_scratch);
    defer first.deinit();
    try testing.expectEqual(attempt.Outcome.ready, first.open());
    try testing.expect(first_recorded.drained());
    try testing.expectEqualStrings(first_recorded.reader_name, first.reader());
    try testing.expectEqual(@as(?seal.Level, .card), first.level());

    const request = requestFor(&log, head, .card);
    const digest = try seal.digestOf(.{
        .session = request.session,
        .header = request.header,
        .head = request.head,
        .events = request.events,
        .level = request.level,
        .key = first.card_signer.?.key(),
        .signature = first.card_signer.?.key(),
    });

    var tape = PathTape{};
    var recorded = chock_pcsc.Recorded{ .exchanges = try tape.build(digest) };
    var scratch: [piv.max_object_len]u8 = undefined;
    var second = attempt.Attempt.init(recorded.pcsc(), &scratch);
    defer second.deinit();
    try testing.expectEqual(attempt.Outcome.ready, second.open());

    var vheld_7 = seal.Held{};
    const sealed = try seal.sign(request, second.signer().?, &vheld_7);
    try testing.expect(recorded.drained());

    const reading = seal.read(sealed, expectationFor(&log, &head), .{ .now_sec = 0 });
    try testing.expectEqual(seal.Verdict.signed_card, reading.verdict);
    try testing.expect(reading.signed());
    try testing.expect(!reading.hardwareProved());
    try testing.expectEqual(chock_pcsc.attestation.Verdict.absent, reading.attestation);
    try testing.expectEqual(@as(usize, 0), sealed.attestation.len);
}

test "a card that will not sign without a PIN is a fallback and never a seal" {
    var tape = PathTape{};
    const whole = try tape.build(null);
    var refused: [transcript.certificate_exchanges.len + 3]chock_pcsc.Exchange = undefined;
    @memcpy(&refused, whole);
    // `69 82`, security status not satisfied: what a slot with a PIN policy
    // answers a signature it was given no PIN for.
    refused[whole.len - 1] = .{
        .send = whole[whole.len - 1].send,
        .receive = &.{ 0x69, 0x82 },
    };

    var recorded = chock_pcsc.Recorded{ .exchanges = &refused };
    var scratch: [piv.max_object_len]u8 = undefined;
    var one = attempt.Attempt.init(recorded.pcsc(), &scratch);
    defer one.deinit();

    try testing.expectEqual(attempt.Outcome.pin_required, one.open());
    try testing.expect(recorded.drained());
    try testing.expectEqual(@as(?seal.Signer, null), one.signer());
    try testing.expectEqual(@as(?seal.Level, null), one.level());
}

test {
    testing.refAllDecls(@This());
}

const apdu = chock_pcsc.apdu;
const Modulus = std.crypto.ff.Modulus(2048);

/// The public key as a PIV card writes one, which is also what a seal carries.
const rsa_card_key = [_]u8{ 0x81, 0x82, 0x01, 0x00 } ++ fixtures.rsa_modulus ++
    [_]u8{ 0x82, 0x03 } ++ fixtures.rsa_exponent;

fn rsaSign(block: [seal.rsa2048_modulus_len]u8) ![seal.rsa2048_modulus_len]u8 {
    const modulus = try Modulus.fromBytes(&fixtures.rsa_modulus, .big);
    const value = try Modulus.Fe.fromBytes(modulus, &block, .big);
    const signed = try modulus.powWithEncodedExponent(
        value,
        &fixtures.rsa_private_exponent,
        .big,
    );
    var out: [seal.rsa2048_modulus_len]u8 = undefined;
    try signed.toBytes(&out, .big);
    return out;
}

/// Cut the way a real card cuts it, because neither an RSA public key nor an RSA
/// signature fits in one exchange: 256 bytes and `61 XX`, then a `GET RESPONSE`.
const LongAnswer = struct {
    first: [apdu.max_response_data + 2]u8 = undefined,
    rest: [apdu.max_response_data + 2]u8 = undefined,
    again: [8]u8 = undefined,

    fn into(
        self: *LongAnswer,
        command: []const u8,
        data: []const u8,
        out: []chock_pcsc.Exchange,
    ) ![]const chock_pcsc.Exchange {
        const head = @min(data.len, apdu.max_response_data);
        const left = data.len - head;
        @memcpy(self.first[0..head], data[0..head]);
        if (left == 0) {
            self.first[head] = 0x90;
            self.first[head + 1] = 0x00;
            out[0] = .{ .send = command, .receive = self.first[0 .. head + 2] };
            return out[0..1];
        }
        self.first[head] = 0x61;
        self.first[head + 1] = @intCast(left);
        @memcpy(self.rest[0..left], data[head..]);
        self.rest[left] = 0x90;
        self.rest[left + 1] = 0x00;
        const bytes = try apdu.getResponse(0, @intCast(left)).encode(&self.again);
        out[0] = .{ .send = command, .receive = self.first[0 .. head + 2] };
        out[1] = .{ .send = bytes, .receive = self.rest[0 .. left + 2] };
        return out[0..2];
    }
};

const RsaSignExchange = struct {
    body: [piv.max_authenticate_body]u8 = undefined,
    head_request: [apdu.Command.max_encoded_len]u8 = undefined,
    tail_request: [apdu.Command.max_encoded_len]u8 = undefined,
    answer_bytes: [8 + seal.rsa2048_modulus_len]u8 = undefined,
    answer: LongAnswer = .{},

    fn into(
        self: *RsaSignExchange,
        digest: [32]u8,
        out: []chock_pcsc.Exchange,
    ) ![]const chock_pcsc.Exchange {
        var block: [seal.rsa2048_modulus_len]u8 = undefined;
        try piv.pkcs1Sha256Into(&block, digest);
        const signature = try rsaSign(block);

        const whole = try piv.generalAuthenticateCommand(
            attempt.seal_slot,
            .rsa2048,
            &block,
            &self.body,
        );
        // The same split `chock_pcsc.Card.exchangeLong` makes, written out here.
        const head = try (apdu.Command{
            .cla = whole.cla | chock_pcsc.Card.chaining_bit,
            .ins = whole.ins,
            .p1 = whole.p1,
            .p2 = whole.p2,
            .data = whole.data[0..apdu.max_command_data],
        }).encode(&self.head_request);
        const tail = try (apdu.Command{
            .cla = whole.cla,
            .ins = whole.ins,
            .p1 = whole.p1,
            .p2 = whole.p2,
            .data = whole.data[apdu.max_command_data..],
            .expect = whole.expect,
        }).encode(&self.tail_request);

        self.answer_bytes[0] = 0x7c;
        self.answer_bytes[1] = 0x82;
        self.answer_bytes[2] = 0x01;
        self.answer_bytes[3] = 0x04;
        self.answer_bytes[4] = 0x82;
        self.answer_bytes[5] = 0x82;
        self.answer_bytes[6] = 0x01;
        self.answer_bytes[7] = 0x00;
        @memcpy(self.answer_bytes[8..], &signature);

        out[0] = .{ .send = head, .receive = &.{ 0x90, 0x00 } };
        const answered = try self.answer.into(tail, &self.answer_bytes, out[1..]);
        return out[0 .. 1 + answered.len];
    }
};

/// A test value: every test below drives `Recorded`, so no card is sent it.
const recorded_pin = "654321";

/// This slot's PIN policy is `always`, so the card path unlocks it and hands
/// that unlock to the first seal signature.
const RsaTape = struct {
    metadata_bytes: [14 + rsa_card_key.len]u8 = undefined,
    metadata_request: [8]u8 = undefined,
    metadata_answer: LongAnswer = .{},
    verify_request: [apdu.Command.max_encoded_len]u8 = undefined,
    retries_request: [8]u8 = undefined,
    first: RsaSignExchange = .{},
    later: RsaSignExchange = .{},
    exchanges: [16]chock_pcsc.Exchange = undefined,
    count: usize = 0,
    /// Named here so a test can record a card whose PIN is not digits.
    pin: []const u8 = recorded_pin,
    /// Two at most: the card path's prompt, and the one every seal after it gives.
    signatures: usize = 1,
    /// `90 00` is accepted, and `63 CX` is wrong with X tries left.
    verify_answer: []const u8 = &.{ 0x90, 0x00 },
    /// The first `VERIFY` goes through `attempt.Attempt.givePin` and every one
    /// after it through `piv.CardSigner.authorise`.
    second_verify_answer: ?[]const u8 = null,

    fn push(self: *RsaTape, made: []const chock_pcsc.Exchange) void {
        self.count += made.len;
    }

    fn build(self: *RsaTape, seal_digest: ?[32]u8) ![]const chock_pcsc.Exchange {
        self.exchanges[0] = transcript.select_exchange;
        self.count = 1;

        const metadata_command = try piv.metadataCommand(attempt.seal_slot)
            .encode(&self.metadata_request);

        // `01` the algorithm, `02` the PIN and touch policies, `03` where the key
        // came from, `04` the public key. Yubico's `GET METADATA` tags.
        self.metadata_bytes = [_]u8{ 0x01, 0x01, 0x07 } ++
            [_]u8{ 0x02, 0x02, 0x03, 0x01 } ++
            [_]u8{ 0x03, 0x01, 0x01 } ++
            [_]u8{ 0x04, 0x82 } ++
            [_]u8{ @intCast(rsa_card_key.len >> 8), @intCast(rsa_card_key.len & 0xff) } ++
            rsa_card_key;

        self.push(try self.metadata_answer.into(
            metadata_command,
            &self.metadata_bytes,
            self.exchanges[self.count..],
        ));

        self.count += try self.pinExchanges(self.exchanges[self.count..], self.verify_answer);

        const digest = seal_digest orelse return self.exchanges[0..self.count];
        self.push(try self.first.into(digest, self.exchanges[self.count..]));
        if (self.signatures < 2) return self.exchanges[0..self.count];

        self.count += try self.pinExchanges(
            self.exchanges[self.count..],
            self.second_verify_answer orelse self.verify_answer,
        );
        self.push(try self.later.into(digest, self.exchanges[self.count..]));
        return self.exchanges[0..self.count];
    }

    /// The counter first, so a person knows how many tries are left before typing.
    fn pinExchanges(self: *RsaTape, out: []chock_pcsc.Exchange, answered: []const u8) !usize {
        const retries = try piv.pinRetriesCommand().encode(&self.retries_request);
        out[0] = .{ .send = retries, .receive = &.{ 0x63, 0xc3 } };
        var padded: [piv.pin_field_len]u8 = undefined;
        try piv.padPin(self.pin, &padded);
        const verify = try piv.verifyPinCommand(&padded).encode(&self.verify_request);
        out[1] = .{ .send = verify, .receive = answered };
        return 2;
    }
};

/// The count is the retry guard: a build that asked twice for one signature
/// fails on it.
const FixedPin = struct {
    asked: usize = 0,
    shown: [8]chock_pcsc.pin.Tries = undefined,
    answer: chock_pcsc.pin.Answer = .{ .pin = recorded_pin },
    /// A slot with the `always` policy asks once per signature.
    then: ?chock_pcsc.pin.Answer = null,

    fn asker(self: *FixedPin) chock_pcsc.pin.Asker {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_pcsc.pin.Asker.VTable{ .ask = askFn };

    fn askFn(
        ptr: *anyopaque,
        question: chock_pcsc.pin.Question,
        out: *chock_pcsc.pin.Buffer,
    ) chock_pcsc.pin.Answer {
        const self: *FixedPin = @ptrCast(@alignCast(ptr));
        if (self.asked < self.shown.len) self.shown[self.asked] = question.tries;
        const answer = if (self.asked == 0) self.answer else self.then orelse self.answer;
        self.asked += 1;
        return switch (answer) {
            .pin => |value| pin: {
                @memcpy(out[0..value.len], value);
                break :pin .{ .pin = out[0..value.len] };
            },
            else => answer,
        };
    }
};

test "an RSA2048 key with no certificate gives a level 2 seal a verifier reads back" {
    const log = try Log.build(.{
        "first", "second", "third",
    });
    const head = log.head();

    var first_pin = FixedPin{};
    var first_tape = RsaTape{};
    var first_recorded = chock_pcsc.Recorded{ .exchanges = try first_tape.build(null) };
    var first_scratch: [piv.max_object_len]u8 = undefined;
    var first = attempt.Attempt.init(first_recorded.pcsc(), &first_scratch);
    defer first.deinit();
    first.asker = first_pin.asker();
    try testing.expectEqual(attempt.Outcome.ready, first.open());
    try testing.expect(first_recorded.drained());
    try testing.expectEqual(@as(?seal.Level, .card), first.level());
    try testing.expectEqualSlices(u8, &rsa_card_key, first.card_signer.?.key());
    try testing.expectEqual(@as(?seal.Scheme, .rsa2048), seal.schemeOf(first.card_signer.?.key()));
    try testing.expectEqual(@as(usize, 1), first_pin.asked);
    try testing.expectEqual(@as(?u4, 3), first_pin.shown[0].count());

    const request = requestFor(&log, head, .card);
    const digest = try seal.digestOf(.{
        .session = request.session,
        .header = request.header,
        .head = request.head,
        .events = request.events,
        .level = request.level,
        .key = &rsa_card_key,
        .signature = &rsa_card_key,
    });

    var second_pin = FixedPin{};
    var tape = RsaTape{};
    var recorded = chock_pcsc.Recorded{ .exchanges = try tape.build(digest) };
    var scratch: [piv.max_object_len]u8 = undefined;
    var second = attempt.Attempt.init(recorded.pcsc(), &scratch);
    defer second.deinit();
    second.asker = second_pin.asker();
    try testing.expectEqual(attempt.Outcome.ready, second.open());

    var held = seal.Held{};
    const sealed = try seal.sign(request, second.signer().?, &held);
    try testing.expect(recorded.drained());
    try testing.expectEqual(@as(usize, seal.rsa2048_modulus_len), sealed.signature.len);

    try testing.expectEqual(@as(usize, 1), second_pin.asked);

    const reading = seal.read(sealed, expectationFor(&log, &head), .{ .now_sec = 0 });
    try testing.expectEqual(seal.Verdict.signed_card, reading.verdict);
    try testing.expect(reading.signed());
    try testing.expect(!reading.hardwareProved());

    var broken = sealed;
    var flipped: [seal.rsa2048_modulus_len]u8 = sealed.signature[0..seal.rsa2048_modulus_len].*;
    flipped[0] ^= 0x01;
    broken.signature = &flipped;
    try testing.expectEqual(
        seal.Verdict.signature_bad,
        seal.read(broken, expectationFor(&log, &head), .{ .now_sec = 0 }).verdict,
    );
}

test "a person who refuses the PIN gets a fallback, and the card is asked nothing" {
    // The refusal is final for the run: the recording holds no second `VERIFY`.
    var refusing = FixedPin{ .answer = .declined };
    var tape = RsaTape{};
    const whole = try tape.build(null);
    const upto = whole.len - 1;

    var recorded = chock_pcsc.Recorded{ .exchanges = whole[0..upto] };
    var scratch: [piv.max_object_len]u8 = undefined;
    var one = attempt.Attempt.init(recorded.pcsc(), &scratch);
    defer one.deinit();
    one.asker = refusing.asker();

    try testing.expectEqual(attempt.Outcome.pin_declined, one.open());
    try testing.expect(recorded.drained());
    try testing.expectEqual(@as(usize, 1), refusing.asked);
    try testing.expectEqual(@as(?seal.Signer, null), one.signer());
    try testing.expectEqual(@as(?seal.Level, null), one.level());
}

test "an answer too long to read is its own outcome, and the card is asked nothing" {
    var overlong = FixedPin{ .answer = .too_long };
    var tape = RsaTape{};
    const whole = try tape.build(null);
    const upto = whole.len - 1;

    var recorded = chock_pcsc.Recorded{ .exchanges = whole[0..upto] };
    var scratch: [piv.max_object_len]u8 = undefined;
    var one = attempt.Attempt.init(recorded.pcsc(), &scratch);
    defer one.deinit();
    one.asker = overlong.asker();

    try testing.expectEqual(attempt.Outcome.pin_too_long, one.open());
    try testing.expect(recorded.drained());
    try testing.expectEqual(@as(usize, 1), overlong.asked);
    try testing.expectEqual(@as(?seal.Signer, null), one.signer());
    try testing.expectEqual(@as(?seal.Level, null), one.level());

    try testing.expect(!std.mem.eql(
        u8,
        attempt.Outcome.pin_too_long.sentence(),
        attempt.Outcome.pin_declined.sentence(),
    ));
}

test "a card whose PIN is letters gives the same level 2 seal as one whose PIN is digits" {
    // SP 800-73-4 says a PIV PIN is digits. `ykman piv access change-pin` does
    // not agree, and the card is the authority on its own PIN.
    var typed = FixedPin{ .answer = .{ .pin = "yubico" } };
    var tape = RsaTape{ .pin = "yubico" };
    var recorded = chock_pcsc.Recorded{ .exchanges = try tape.build(null) };
    var scratch: [piv.max_object_len]u8 = undefined;
    var one = attempt.Attempt.init(recorded.pcsc(), &scratch);
    defer one.deinit();
    one.asker = typed.asker();

    try testing.expectEqual(attempt.Outcome.ready, one.open());
    try testing.expect(recorded.drained());
    try testing.expectEqual(@as(?seal.Level, .card), one.level());
    try testing.expectEqual(@as(usize, 1), typed.asked);
}

/// Worked out from the request, so a tape and the seal made from it cannot ask
/// for two different things.
fn sealDigestFor(request: seal.Request) ![32]u8 {
    return seal.digestOf(.{
        .session = request.session,
        .header = request.header,
        .head = request.head,
        .events = request.events,
        .level = request.level,
        .key = &rsa_card_key,
        .signature = &.{},
    });
}

test "a prompt after the first says why it failed, and each answer keeps its own words" {
    // Two seals, because the second prompt is the one `piv.CardSigner.authorise`
    // puts up.
    const cases = [_]struct { answer: chock_pcsc.pin.Answer, want: attempt.Outcome }{
        .{ .answer = .nobody, .want = .pin_nobody },
        .{ .answer = .declined, .want = .pin_declined },
        .{ .answer = .too_long, .want = .pin_too_long },
        .{ .answer = .unreadable, .want = .pin_unreadable },
    };

    var seen: [cases.len][]const u8 = undefined;
    for (cases, 0..) |one, index| {
        const log = try Log.build(.{ "first", "second", "third" });
        const request = requestFor(&log, log.head(), .card);

        var typed = FixedPin{ .then = one.answer };
        var tape = RsaTape{ .signatures = 2 };
        const whole = try tape.build(try sealDigestFor(request));
        var recorded = chock_pcsc.Recorded{ .exchanges = whole[0 .. whole.len - 4] };
        var scratch: [piv.max_object_len]u8 = undefined;
        var open = attempt.Attempt.init(recorded.pcsc(), &scratch);
        defer open.deinit();
        open.asker = typed.asker();

        try testing.expectEqual(attempt.Outcome.ready, open.open());
        try testing.expectEqual(@as(?attempt.Outcome, null), open.stopped());
        try testing.expectEqual(@as(usize, 1), typed.asked);

        var held = seal.Held{};
        const signer = open.signer().?;
        _ = try seal.sign(request, signer, &held);
        try testing.expectEqual(@as(usize, 1), typed.asked);
        try testing.expectEqual(@as(?attempt.Outcome, null), open.stopped());

        try testing.expectError(error.Unusable, seal.sign(request, signer, &held));
        try testing.expect(recorded.drained());
        try testing.expectEqual(@as(usize, 2), typed.asked);

        try testing.expectEqual(@as(?attempt.Outcome, one.want), open.stopped());
        try testing.expect(signer.reason() != null);
        const why = signer.reason().?;
        try testing.expectEqualStrings(one.want.sentence(), why);
        for (seen[0..index]) |earlier| try testing.expect(!std.mem.eql(u8, earlier, why));
        seen[index] = why;

        try testing.expectError(error.Unusable, seal.sign(request, signer, &held));
        try testing.expectEqual(@as(usize, 2), typed.asked);
        try testing.expect(recorded.drained());
        try testing.expectEqual(@as(?attempt.Outcome, one.want), open.stopped());
    }
}

test "a wrong PIN on a later prompt spends one try, and the run never asks again" {
    // Three wrong PINs block the card. The recording holds two `VERIFY` commands
    // and refuses anything else, so a third ask fails here and not on a card.
    const log = try Log.build(.{ "first", "second", "third" });
    const request = requestFor(&log, log.head(), .card);

    var typed = FixedPin{};
    var tape = RsaTape{ .signatures = 2, .second_verify_answer = &.{ 0x63, 0xc2 } };
    const whole = try tape.build(try sealDigestFor(request));
    var recorded = chock_pcsc.Recorded{ .exchanges = whole[0 .. whole.len - 3] };
    var scratch: [piv.max_object_len]u8 = undefined;
    var open = attempt.Attempt.init(recorded.pcsc(), &scratch);
    defer open.deinit();
    open.asker = typed.asker();

    try testing.expectEqual(attempt.Outcome.ready, open.open());

    var held = seal.Held{};
    const signer = open.signer().?;
    _ = try seal.sign(request, signer, &held);
    try testing.expectEqual(@as(usize, 1), typed.asked);

    try testing.expectError(error.Unusable, seal.sign(request, signer, &held));
    try testing.expect(recorded.drained());
    try testing.expectEqual(@as(usize, 2), typed.asked);
    try testing.expectEqual(@as(?attempt.Outcome, .pin_wrong), open.stopped());
    try testing.expect(std.mem.indexOf(u8, signer.reason().?, "one try is gone") != null);

    for (0..3) |_| try testing.expectError(error.Unusable, seal.sign(request, signer, &held));
    try testing.expectEqual(@as(usize, 2), typed.asked);
    try testing.expect(recorded.drained());
    try testing.expectEqual(@as(?attempt.Outcome, .pin_wrong), open.stopped());
}

test "nobody at a keyboard is a refusal, and the card is never asked for a PIN" {
    var nobody = FixedPin{ .answer = .nobody };
    var tape = RsaTape{};
    const whole = try tape.build(null);
    const upto = whole.len - 1;

    var recorded = chock_pcsc.Recorded{ .exchanges = whole[0..upto] };
    var scratch: [piv.max_object_len]u8 = undefined;
    var one = attempt.Attempt.init(recorded.pcsc(), &scratch);
    defer one.deinit();
    one.asker = nobody.asker();

    try testing.expectEqual(attempt.Outcome.pin_nobody, one.open());
    try testing.expect(recorded.drained());
    var bare_tape = RsaTape{};
    const bare_whole = try bare_tape.build(null);
    var bare_recorded = chock_pcsc.Recorded{ .exchanges = bare_whole[0 .. bare_whole.len - 2] };
    var bare_scratch: [piv.max_object_len]u8 = undefined;
    var bare = attempt.Attempt.init(bare_recorded.pcsc(), &bare_scratch);
    defer bare.deinit();
    try testing.expectEqual(attempt.Outcome.pin_required, bare.open());
    try testing.expect(bare_recorded.drained());
}
