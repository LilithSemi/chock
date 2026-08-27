//! A seal over a real hash chain, read back with nothing but a public key.
//!
//! This is the file that joins the two halves. `lib/chock-proto/chain.zig`
//! builds the chain a session log carries, and this signs the head of one and
//! then tries every way of getting past it that the chain alone cannot stop.
//!
//! **The one that matters**: a log rewritten by hand, with every `prev` field
//! computed again, which the chain reports as holding. That was done in four
//! lines of shell against the real thing. Here it is done in Zig, the chain
//! agrees that it holds, and the seal says the log is not the one that was
//! signed.
//!
//! Nothing here uses a card, a reader or a daemon.

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

/// A log of three events, built the way `lib/chock-proto/log.zig` builds one.
///
/// **Each line carries the digest of the line before it, inside the line.**
/// That is what makes a repair a real repair: changing one event changes its
/// bytes, so every `prev` after it has to be written again, so every line after
/// it changes too, and the head with them. A model that kept the digests beside
/// the lines instead of inside them would let an edit leave the head alone,
/// and the test below would then prove nothing.
const Log = struct {
    const max_line = 192;

    text: [3][max_line]u8 = undefined,
    lengths: [3]usize = undefined,
    prevs: [3]chain.Digest = undefined,
    /// The digest of the header line, held here rather than recomputed at each
    /// call site: an expectation points at it, and a pointer to a value that
    /// has already gone is a pointer to anything.
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

    /// The digest of the last line, which is the head of the chain and the one
    /// thing no event in the log carries.
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
    // No card, no daemon, no credential store, no platform branch. The reader
    // has the log's own digests and the record, and nothing else.
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
    // The whole reason this module exists. `chain.zig` says it in its own first
    // lines: anybody who can rewrite the file can hash every line again and
    // write a chain that agrees with the new text. That is done below, the
    // chain reports that it holds, and the seal is what catches it.
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

    // The rewrite. One line changed, and every digest after it computed again,
    // which is the four lines of shell that defeated the chain on its own.
    const repaired = try Log.build(.{
        "first", "paid 90", "third",
    });
    // The chain is happy. This is the fact the seal exists to answer.
    try testing.expectEqual(chain.Verdict.intact, repaired.verdict());

    const repaired_head = repaired.head();
    const reading = seal.read(sealed, expectationFor(&repaired, &repaired_head), .{ .now_sec = 0 });
    try testing.expectEqual(seal.Verdict.head_mismatch, reading.verdict);
    try testing.expectEqual(@as(?seal.Field, .head), reading.mismatched);
    try testing.expect(!reading.signed());
}

test "cutting the last event off a log changes the head, which no chain notices" {
    // The gap a chain cannot close on its own: nothing carries the hash of the
    // last line, so removing it leaves a chain that still holds. For a session
    // that has ended, that is permanent.
    const whole = try Log.build(.{
        "first", "second", "the thing somebody wants gone",
    });
    var key = try software.Key.fromSeed([_]u8{0x23} ** 32);
    const head = whole.head();
    var vheld_3 = seal.Held{};
    const sealed = try seal.sign(requestFor(&whole, head, .software), softwareSigner(&key), &vheld_3);

    // The last line is gone. A chain reader over the two that are left finds
    // nothing wrong at all.
    var verifier = chain.Verifier.init(whole.header);
    verifier.take(16, whole.line(0), &whole.prevs[0]);
    verifier.take(32, whole.line(1), &whole.prevs[1]);
    try testing.expectEqual(chain.Verdict.intact, verifier.finish(.complete, 0).verdict);

    // The seal names a head that is no longer the last line, and a count of
    // events that no longer matches.
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
    // The two modules agree on the shape of a digest by writing the same number
    // in two places. A change to one of them would make every seal malformed,
    // so it is pinned here rather than found later.
    try testing.expectEqual(chain.digest_len, seal.digest_hex_len);
    try testing.expect(seal.isDigest(&chain.of("anything at all")));
}

/// Build the recorded exchanges for a card that holds `fixtures.leaf_der` in
/// its digital signature slot and will sign `digest` with the matching key.
///
/// The certificate answers come out of the same container shape
/// `transcript.zig` builds. The signature answer has to be built here, because
/// the digest a seal signs is not known until the seal's own fields are settled.
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

    // The card's public key comes off the certificate in the slot, which is the
    // only place it can come from: the private key never leaves the card.
    var certificate_only = chock_pcsc.Recorded{ .exchanges = &transcript.certificate_exchanges };
    const first_transport = certificate_only.pcsc();
    try first_transport.establish();
    const first_card = try first_transport.connect(certificate_only.reader_name);
    var scratch: [piv.max_object_len]u8 = undefined;
    var probe = try piv.CardSigner.init(first_card, .digital_signature, &scratch);

    // With the key known, the digest the card will be asked for is settled, so
    // the answer it gives can be recorded.
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

    // And now the half an auditor uses: the record, the log's own digests, and
    // the vendor root. No card anywhere in this call.
    const reading = seal.read(sealed, expectationFor(&log, &head), .{
        .root = &fixtures.root_der,
        .now_sec = fixtures.inside_window,
    });
    try testing.expectEqual(seal.Verdict.signed_card_attested, reading.verdict);
    try testing.expect(reading.hardwareProved());
    try testing.expectEqual(chock_pcsc.attestation.Verdict.bound, reading.attestation);
}

test "the same seal with the attestation stripped falls to claim_unsupported" {
    // Somebody who deletes the certificates from the record does not get a
    // level 2 seal out of a level 1 one. The level is signed, so the record
    // still claims an attestation it can no longer show.
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
    // The whole point of recording the level. Somebody stops the daemon, Chock
    // signs at level 3 and says so, and the person who stopped the daemon then
    // tries to make the record say a card did it.
    const log = try Log.build(.{
        "first", "second", "third",
    });
    const head = log.head();
    var key = try software.Key.fromSeed([_]u8{0x24} ** 32);
    var vheld_6 = seal.Held{};
    const sealed = try seal.sign(requestFor(&log, head, .software), softwareSigner(&key), &vheld_6);
    const expect = expectationFor(&log, &head);
    const trust = seal.Trust{ .root = &fixtures.root_der, .now_sec = fixtures.inside_window };

    // As written, it says software, and a reader can act on that.
    try testing.expectEqual(seal.Verdict.signed_software, seal.read(sealed, expect, trust).verdict);

    // Edited: the signature is over the level, so this breaks.
    var raised = sealed;
    raised.level = .card_attested;
    try testing.expectEqual(seal.Verdict.signature_bad, seal.read(raised, expect, trust).verdict);

    // Edited and given a real attestation chain that has nothing to do with
    // this key. Still broken, because the level is still inside the signature.
    const attestation_chain = [_][]const u8{ &fixtures.leaf_der, &fixtures.intermediate_der };
    raised.attestation = &attestation_chain;
    try testing.expectEqual(seal.Verdict.signature_bad, seal.read(raised, expect, trust).verdict);

    // Signed again with the attacker's own key so the signature checks out, and
    // still carrying somebody else's real attestation. The leaf is about a
    // different key, so the claim is unsupported.
    var forged = raised;
    const forged_bytes = try key.signDigest(try seal.digestOf(forged));
    forged.signature = &forged_bytes;
    const reading = seal.read(forged, expect, trust);
    try testing.expectEqual(seal.Verdict.claim_unsupported, reading.verdict);
    try testing.expectEqual(chock_pcsc.attestation.Verdict.key_mismatch, reading.attestation);
    try testing.expect(!reading.hardwareProved());
}

const attempt = chock_pcsc.attempt;

/// One `GENERAL AUTHENTICATE` and the answer a card gives it, built for a
/// digest that is not known until the seal's own fields are settled.
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

/// Every exchange the card path takes, in the order a card sees them: select
/// the application, read the certificate, sign the probe digest, and then sign
/// the seal.
///
/// **Built to `Recorded`, which refuses a command it has no recording of.** A
/// change to the order or to one byte of a command fails here rather than
/// passing.
const PathTape = struct {
    probe: SignatureExchange = .{},
    real: SignatureExchange = .{},
    exchanges: [transcript.certificate_exchanges.len + 4]chock_pcsc.Exchange = undefined,

    /// `GET METADATA` for the seal slot, and the answer a card without that
    /// command gives. **This tape is a card that has no metadata command**, so
    /// it drives the certificate path, which is the one this card can take.
    const metadata_command = [_]u8{ 0x00, 0xf7, 0x00, 0x9c, 0x00 };
    const metadata_exchange = chock_pcsc.Exchange{
        .send = &metadata_command,
        .receive = &.{ 0x6d, 0x00 },
    };

    /// The digest `attempt.open` asks the card for before it says a card key is
    /// in hand. A constant of `attempt.zig`, so it is known before the seal is.
    fn probeDigest() [32]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(attempt.probe_domain, &digest, .{});
        return digest;
    }

    /// The exchanges up to and including the probe. `seal_digest` adds the
    /// seal's own signature after it.
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
    // The wiring itself, and not only the pieces under it. `chock sessions
    // seal` reaches a card through `attempt.open`, so this drives that call and
    // signs a real log with what it hands back.
    const log = try Log.build(.{
        "first", "second", "third",
    });
    const head = log.head();

    // Pass one learns the key, because the digest a seal signs is not settled
    // until the key that signs it is known.
    var first_tape = PathTape{};
    var first_recorded = chock_pcsc.Recorded{ .exchanges = try first_tape.build(null) };
    var first_scratch: [piv.max_object_len]u8 = undefined;
    var first = attempt.Attempt.init(first_recorded.pcsc(), &first_scratch);
    defer first.deinit();
    try testing.expectEqual(attempt.Outcome.ready, first.open());
    try testing.expect(first_recorded.drained());
    // The reader the card was found in is carried back, so a message can name
    // it instead of saying "a card".
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

    // And the half an auditor uses. The record says a card signed, and it says
    // nothing about hardware, because no attestation came with it.
    const reading = seal.read(sealed, expectationFor(&log, &head), .{ .now_sec = 0 });
    try testing.expectEqual(seal.Verdict.signed_card, reading.verdict);
    try testing.expect(reading.signed());
    try testing.expect(!reading.hardwareProved());
    try testing.expectEqual(chock_pcsc.attestation.Verdict.absent, reading.attestation);
    try testing.expectEqual(@as(usize, 0), sealed.attestation.len);
}

test "a card that will not sign without a PIN is a fallback and never a seal" {
    // The probe is what turns a slot the card will not use into a fallback. A
    // path that skipped it would get this refusal in the middle of sealing,
    // after it had already told the caller a card was in hand.
    var tape = PathTape{};
    const whole = try tape.build(null);
    var refused: [transcript.certificate_exchanges.len + 3]chock_pcsc.Exchange = undefined;
    @memcpy(&refused, whole);
    // `69 82`: security status not satisfied, which is what a slot with a PIN
    // policy answers a signature it was given no PIN for.
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

/// The public key as a PIV card writes one: the modulus element, then the
/// exponent element. This is also exactly what a seal carries.
const rsa_card_key = [_]u8{ 0x81, 0x82, 0x01, 0x00 } ++ fixtures.rsa_modulus ++
    [_]u8{ 0x82, 0x03 } ++ fixtures.rsa_exponent;

/// The private key operation a card does, done here so a recording can hold the
/// answer a real card would give.
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

/// One card answer that does not fit in a single short form exchange, cut the
/// way a real card cuts it: 256 bytes and `61 XX`, then a `GET RESPONSE` for
/// what is left.
///
/// **Not a convenience.** Neither an RSA public key nor an RSA signature fits
/// in one exchange, so a recording that handed either back whole would be a
/// card no reader has.
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

/// One `GENERAL AUTHENTICATE` over an RSA key: the two chained pieces the
/// command takes, and the long answer that comes back.
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
        // The same split `chock_pcsc.Card.exchangeLong` makes, written out here
        // so a change to it fails against this recording.
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

        // `7C { 82 (the signature) }`, which is what the card wraps it in.
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

/// The PIN this recorded card takes. **A test value and nothing else**: no card
/// on this machine is ever sent it, because every test below drives `Recorded`.
const recorded_pin = "654321";

/// The whole card, recorded: select, metadata, the PIN the card path gives it,
/// and then a signature for every seal asked for with a PIN before all but the
/// first.
///
/// **This slot's PIN policy is `always`, so it is never probed.** The card path
/// unlocks it and hands that unlock to the first seal signature, which is why
/// the tape below holds one `VERIFY` and one signature for a run that seals one
/// log. See `attempt.zig`'s own top comment.
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
    /// The PIN this recorded card expects in the `VERIFY` field. Named here so
    /// a test can record a card whose PIN is not digits.
    pin: []const u8 = recorded_pin,
    /// How many seal signatures this run makes. **Two at most**, because two is
    /// what separates the prompt the card path gives from the prompt every seal
    /// after the first gives, and one more would prove nothing the second does
    /// not.
    signatures: usize = 1,
    /// What the card answers the `VERIFY` with. `90 00` is accepted, and
    /// `63 CX` is wrong with X tries left.
    verify_answer: []const u8 = &.{ 0x90, 0x00 },
    /// What the card answers the **second** `VERIFY` with, and null to answer it
    /// the same way as the first.
    ///
    /// **Named here because the two prompts are different code.** The first goes
    /// through `attempt.Attempt.givePin` and every one after it through
    /// `piv.CardSigner.authorise`, so a card that takes the first PIN and then
    /// refuses the next one is the shape that only the second path sees.
    second_verify_answer: ?[]const u8 = null,

    fn push(self: *RsaTape, made: []const chock_pcsc.Exchange) void {
        self.count += made.len;
    }

    /// Build the tape. `seal_digest` is null for a run that stops at the PIN and
    /// signs nothing.
    fn build(self: *RsaTape, seal_digest: ?[32]u8) ![]const chock_pcsc.Exchange {
        self.exchanges[0] = transcript.select_exchange;
        self.count = 1;

        const metadata_command = try piv.metadataCommand(attempt.seal_slot)
            .encode(&self.metadata_request);

        // `01` the algorithm, `02` the PIN policy and the touch policy, `03`
        // where the key came from, and `04` the public key. The tags Yubico's
        // own `GET METADATA` answers with, and the values the owner's card
        // gives: RSA2048, a PIN before every use, no touch, generated on the
        // card.
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

        // The unlock the card path does. **No signature follows it here**: the
        // first seal is what uses it.
        self.count += try self.pinExchanges(self.exchanges[self.count..], self.verify_answer);

        const digest = seal_digest orelse return self.exchanges[0..self.count];
        self.push(try self.first.into(digest, self.exchanges[self.count..]));
        if (self.signatures < 2) return self.exchanges[0..self.count];

        // The second seal, which the card makes ask again because it cleared
        // its own status when it used the key.
        self.count += try self.pinExchanges(
            self.exchanges[self.count..],
            self.second_verify_answer orelse self.verify_answer,
        );
        self.push(try self.later.into(digest, self.exchanges[self.count..]));
        return self.exchanges[0..self.count];
    }

    /// The counter read and the `VERIFY` that follows it. **The counter first**,
    /// because a person has to be told how many tries are left before they type.
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

/// An asker that answers with a fixed PIN, and counts how many times it was
/// asked. **The count is the retry guard**: a build that asked twice for one
/// signature would fail on the count and not only on the recording.
const FixedPin = struct {
    asked: usize = 0,
    shown: [8]chock_pcsc.pin.Tries = undefined,
    answer: chock_pcsc.pin.Answer = .{ .pin = recorded_pin },
    /// What to answer from the **second** ask onwards, and null to answer every
    /// ask the same way.
    ///
    /// **The prompt a person meets most.** A slot whose PIN policy is `always`
    /// asks once per signature, so sealing one log asks once and sealing twenty
    /// asks twenty times. Only the first of those goes through
    /// `attempt.Attempt.givePin`.
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
    // The card the owner has. Three things this proves together and none of
    // them alone: the public key comes out of `GET METADATA` and not out of a
    // certificate, the signature request reaches the card in two chained
    // pieces, and the padded block the card signed is the one RFC 8017 says.
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
    // The key is the card's own, in the shape a seal carries.
    try testing.expectEqualSlices(u8, &rsa_card_key, first.card_signer.?.key());
    try testing.expectEqual(@as(?seal.Scheme, .rsa2048), seal.schemeOf(first.card_signer.?.key()));
    // The count was read off the card and handed to whoever draws the prompt,
    // before anybody typed.
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

    // **A slot with the `always` policy is asked once for each signature**, and
    // never twice for one. One signature was made here, the seal, and it used
    // the unlock the card path already did. This slot is not probed: see
    // `attempt.zig`'s own top comment.
    try testing.expectEqual(@as(usize, 1), second_pin.asked);

    // And the half an auditor uses. No card, no daemon, and an RSA key.
    const reading = seal.read(sealed, expectationFor(&log, &head), .{ .now_sec = 0 });
    try testing.expectEqual(seal.Verdict.signed_card, reading.verdict);
    try testing.expect(reading.signed());
    try testing.expect(!reading.hardwareProved());

    // One changed byte of the signature is caught, so the check above is a real
    // check and not a branch that answers yes.
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
    // The refusal is final for the run. **No loop anywhere**: the asker below
    // answers once and the recording holds no second `VERIFY`, so a build that
    // tried again would fail here rather than spending a try on somebody's
    // card.
    var refusing = FixedPin{ .answer = .declined };
    var tape = RsaTape{};
    const whole = try tape.build(null);
    // Everything up to and including the counter read. The `VERIFY` is cut off,
    // because it should never happen.
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
    // **What a person is told has to follow what they did.** This person typed
    // something, and it was longer than the prompt reads, so telling them none
    // was given is false. The card is never contacted either way, so this is
    // about honesty and not about the counter.
    //
    // The recording below holds no `VERIFY`, and it refuses any command it does
    // not hold, so a build that sent the long line to the card would fail here
    // rather than spend a try on somebody's key.
    //
    // Mutation check: answer `.pin_declined` for a `.too_long` answer in
    // `Attempt.givePin` and this fails on the outcome.
    var overlong = FixedPin{ .answer = .too_long };
    var tape = RsaTape{};
    const whole = try tape.build(null);
    // Everything up to and including the counter read, which spends nothing.
    const upto = whole.len - 1;

    var recorded = chock_pcsc.Recorded{ .exchanges = whole[0..upto] };
    var scratch: [piv.max_object_len]u8 = undefined;
    var one = attempt.Attempt.init(recorded.pcsc(), &scratch);
    defer one.deinit();
    one.asker = overlong.asker();

    try testing.expectEqual(attempt.Outcome.pin_too_long, one.open());
    try testing.expect(recorded.drained());
    // Asked once. **No loop**: the refusal is final for the run.
    try testing.expectEqual(@as(usize, 1), overlong.asked);
    try testing.expectEqual(@as(?seal.Signer, null), one.signer());
    try testing.expectEqual(@as(?seal.Level, null), one.level());

    // And the words a person reads are not the words a decline gets.
    try testing.expect(!std.mem.eql(
        u8,
        attempt.Outcome.pin_too_long.sentence(),
        attempt.Outcome.pin_declined.sentence(),
    ));
}

test "a card whose PIN is letters gives the same level 2 seal as one whose PIN is digits" {
    // What the old rule cost. This whole path was unreachable for a person
    // whose YubiKey PIN is not numeric, and what they were told instead was
    // that their own PIN was malformed. SP 800-73-4 says a PIV PIN is digits;
    // `ykman piv access change-pin` does not agree, and the card is the
    // authority on its own PIN.
    var typed = FixedPin{ .answer = .{ .pin = "yubico" } };
    var tape = RsaTape{ .pin = "yubico" };
    var recorded = chock_pcsc.Recorded{ .exchanges = try tape.build(null) };
    var scratch: [piv.max_object_len]u8 = undefined;
    var one = attempt.Attempt.init(recorded.pcsc(), &scratch);
    defer one.deinit();
    one.asker = typed.asker();

    // The recording refuses any command it does not hold, so this passing means
    // the letters really went out in the `VERIFY` field, padded with `FF`.
    try testing.expectEqual(attempt.Outcome.ready, one.open());
    try testing.expect(recorded.drained());
    try testing.expectEqual(@as(?seal.Level, .card), one.level());
    try testing.expectEqual(@as(usize, 1), typed.asked);
}

/// The digest a recorded card is asked to sign for the seal itself, as against
/// the probe. **Worked out from the request**, so a tape and the seal made from
/// it cannot ask the card to sign two different things.
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
    // **The fault this closes.** A slot whose PIN policy is `always` asks once
    // per signature, so sealing two logs asks twice. The first ask goes through
    // `Attempt.givePin`, which keeps the four answers apart and gives each one a
    // sentence. Every ask after it goes through `piv.CardSigner.authorise`,
    // which folded all four into one error with no sentence, so a person who
    // mistyped on the second prompt got a failed seal and nothing at all to
    // read. Sealing twenty logs asks twenty times, and only the first of those
    // was explained.
    //
    // Two seals are made below for that reason: the first uses the unlock the
    // card path did, and the second is the one that puts the question up again.
    //
    // The recording holds no second `VERIFY` and refuses any command it does
    // not hold, so a build that sent one of these four answers to the card
    // would fail here rather than spend a try on somebody's key.
    //
    // Mutation check: answer `.pin_declined` for a `.too_long` answer in
    // `Outcome.forAnswer` and the third case fails on the outcome.
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
        // Everything up to and including the second counter read, which spends
        // nothing. The `VERIFY` after it and the signature after that are cut
        // off, because neither should happen.
        var recorded = chock_pcsc.Recorded{ .exchanges = whole[0 .. whole.len - 4] };
        var scratch: [piv.max_object_len]u8 = undefined;
        var open = attempt.Attempt.init(recorded.pcsc(), &scratch);
        defer open.deinit();
        open.asker = typed.asker();

        // The card opened on the first prompt, and nothing was signed by it.
        try testing.expectEqual(attempt.Outcome.ready, open.open());
        try testing.expectEqual(@as(?attempt.Outcome, null), open.stopped());
        try testing.expectEqual(@as(usize, 1), typed.asked);

        var held = seal.Held{};
        const signer = open.signer().?;
        // The first seal, which asks nobody: it uses the unlock the card path
        // did. A build that asked here would take `one.answer` and fail below
        // on the count and on the outcome.
        _ = try seal.sign(request, signer, &held);
        try testing.expectEqual(@as(usize, 1), typed.asked);
        try testing.expectEqual(@as(?attempt.Outcome, null), open.stopped());

        // The second seal, which the card makes ask again.
        try testing.expectError(error.Unusable, seal.sign(request, signer, &held));
        try testing.expect(recorded.drained());
        // Asked twice for two seals. **Never a third time**, whatever the
        // answer was.
        try testing.expectEqual(@as(usize, 2), typed.asked);

        // The fact, and the sentence a person reads for it.
        try testing.expectEqual(@as(?attempt.Outcome, one.want), open.stopped());
        try testing.expect(signer.reason() != null);
        const why = signer.reason().?;
        try testing.expectEqualStrings(one.want.sentence(), why);
        // And it is not the sentence any of the other three would have given.
        // A reason that came back the same for all four would be the fault
        // this test is about, wearing a sentence.
        for (seen[0..index]) |earlier| try testing.expect(!std.mem.eql(u8, earlier, why));
        seen[index] = why;

        // **The refusal is final for the run and not for one signature.** The
        // next log of the same run asks nobody and touches no card.
        try testing.expectError(error.Unusable, seal.sign(request, signer, &held));
        try testing.expectEqual(@as(usize, 2), typed.asked);
        try testing.expect(recorded.drained());
        try testing.expectEqual(@as(?attempt.Outcome, one.want), open.stopped());
    }
}

test "a wrong PIN on a later prompt spends one try, and the run never asks again" {
    // **The way this could destroy somebody's key.** A card that wants the PIN
    // before every signature is asked again by every log of a run, so a person
    // who mistypes while sealing the second of twenty logs would be asked a
    // third time and a fourth, would very likely type the same PIN, and three
    // wrong ones block the card and send them to the PUK.
    //
    // The recording holds exactly two `VERIFY` commands, the second answered
    // `63 C2`, and refuses anything it does not hold. A build that asked a
    // third time fails here rather than on somebody's card.
    //
    // Mutation check: drop the `stopped` test at the top of
    // `piv.CardSigner.authorise` and this fails on the recording, because the
    // run puts the question up again.
    const log = try Log.build(.{ "first", "second", "third" });
    const request = requestFor(&log, log.head(), .card);

    var typed = FixedPin{};
    var tape = RsaTape{ .signatures = 2, .second_verify_answer = &.{ 0x63, 0xc2 } };
    const whole = try tape.build(try sealDigestFor(request));
    // The second signature is cut off, because the card never gets that far.
    var recorded = chock_pcsc.Recorded{ .exchanges = whole[0 .. whole.len - 3] };
    var scratch: [piv.max_object_len]u8 = undefined;
    var open = attempt.Attempt.init(recorded.pcsc(), &scratch);
    defer open.deinit();
    open.asker = typed.asker();

    try testing.expectEqual(attempt.Outcome.ready, open.open());

    var held = seal.Held{};
    const signer = open.signer().?;
    // The first log of the run, which uses the unlock the card path did and
    // asks nobody.
    _ = try seal.sign(request, signer, &held);
    try testing.expectEqual(@as(usize, 1), typed.asked);

    // The second, where the card asks again and the answer is wrong.
    try testing.expectError(error.Unusable, seal.sign(request, signer, &held));
    try testing.expect(recorded.drained());
    try testing.expectEqual(@as(usize, 2), typed.asked);
    try testing.expectEqual(@as(?attempt.Outcome, .pin_wrong), open.stopped());
    // The words a person reads say a try is gone and that nothing tries again,
    // which is what they act on.
    try testing.expect(std.mem.indexOf(u8, signer.reason().?, "one try is gone") != null);

    // Three more logs of the same run. **Not one more prompt, and not one more
    // `VERIFY`.**
    for (0..3) |_| try testing.expectError(error.Unusable, seal.sign(request, signer, &held));
    try testing.expectEqual(@as(usize, 2), typed.asked);
    try testing.expect(recorded.drained());
    // And the reason kept is the first one, which is the one a person caused.
    try testing.expectEqual(@as(?attempt.Outcome, .pin_wrong), open.stopped());
}

test "nobody at a keyboard is a refusal, and the card is never asked for a PIN" {
    var nobody = FixedPin{ .answer = .nobody };
    var tape = RsaTape{};
    const whole = try tape.build(null);
    // The counter is still read, because it costs no try and the question says
    // the number. The `VERIFY` after it is cut off: nobody answered.
    const upto = whole.len - 1;

    var recorded = chock_pcsc.Recorded{ .exchanges = whole[0..upto] };
    var scratch: [piv.max_object_len]u8 = undefined;
    var one = attempt.Attempt.init(recorded.pcsc(), &scratch);
    defer one.deinit();
    one.asker = nobody.asker();

    try testing.expectEqual(attempt.Outcome.pin_nobody, one.open());
    try testing.expect(recorded.drained());
    // And with no asker at all, which is what a build with nothing wired gives.
    var bare_tape = RsaTape{};
    const bare_whole = try bare_tape.build(null);
    // **Not even the counter is read.** With nobody to ask there is no question
    // to put a number in, so the card is left alone entirely.
    var bare_recorded = chock_pcsc.Recorded{ .exchanges = bare_whole[0 .. bare_whole.len - 2] };
    var bare_scratch: [piv.max_object_len]u8 = undefined;
    var bare = attempt.Attempt.init(bare_recorded.pcsc(), &bare_scratch);
    defer bare.deinit();
    try testing.expectEqual(attempt.Outcome.pin_required, bare.open());
    try testing.expect(bare_recorded.drained());
}
