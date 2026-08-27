//! The attestation reader against a real certificate chain, and a sweep that
//! proves a hostile record cannot end the process.
//!
//! Everything here runs with no card, no reader and no daemon. That is the rule
//! `lib/chock-pcsc.zig` states and this file is where it is checked: an auditor
//! reading somebody else's log has `std.crypto` and a root certificate, and
//! nothing else.

const std = @import("std");
const chock_pcsc = @import("chock-pcsc");
const fixtures = @import("fixtures.zig");

const attestation = chock_pcsc.attestation;
const software = chock_pcsc.software;
const testing = std.testing;

fn leafKey() ![attestation.public_key_len]u8 {
    const key = try software.Key.fromSecret(fixtures.leaf_secret);
    return key.publicKey();
}

test "a real chain binds the key that signed the seal to the root the reader trusts" {
    // The whole of level 1. The leaf holds this key, the intermediate signed the
    // leaf, and the root signed the intermediate, so the reader can say the key
    // lives where the vendor says it does.
    const key = try leafKey();
    const chain = [_][]const u8{ &fixtures.leaf_der, &fixtures.intermediate_der };
    try testing.expectEqual(
        attestation.Verdict.bound,
        attestation.read(&chain, &key, &fixtures.root_der, fixtures.inside_window),
    );
}

test "a leaf borrowed from another card is refused, however real it is" {
    // The attack a chain check alone does not stop: take a genuine attestation
    // off a card you own and staple it to a seal signed by a software key. The
    // chain verifies. The key in the leaf is not the key that signed, and that
    // is what catches it.
    const key = try leafKey();
    const borrowed = [_][]const u8{ &fixtures.other_key_leaf_der, &fixtures.intermediate_der };
    try testing.expectEqual(
        attestation.Verdict.key_mismatch,
        attestation.read(&borrowed, &key, &fixtures.root_der, fixtures.inside_window),
    );

    // And that leaf really is a valid certificate, so the refusal above is about
    // the key and not about the certificate being broken: read against its own
    // key it binds.
    const parsed = try std.crypto.Certificate.parse(.{ .buffer = &fixtures.other_key_leaf_der, .index = 0 });
    var other_key: [attestation.public_key_len]u8 = undefined;
    @memcpy(&other_key, parsed.pubKey());
    try testing.expectEqual(
        attestation.Verdict.bound,
        attestation.read(&borrowed, &other_key, &fixtures.root_der, fixtures.inside_window),
    );
}

test "a chain that reaches a different root is untrusted, even with the same name" {
    // The rogue root carries the same subject name as the real one, so a check
    // that compared names and not signatures would accept this.
    const key = try leafKey();
    const rogue = [_][]const u8{&fixtures.rogue_leaf_der};
    try testing.expectEqual(
        attestation.Verdict.untrusted,
        attestation.read(&rogue, &key, &fixtures.root_der, fixtures.inside_window),
    );

    // Against the root that really did sign it, the same chain binds. That is
    // what makes the answer above about the signature rather than about the
    // certificate being unreadable.
    try testing.expectEqual(
        attestation.Verdict.bound,
        attestation.read(&rogue, &key, &fixtures.rogue_root_der, fixtures.inside_window),
    );
}

test "a chain with a link missing does not reach the root" {
    // The leaf alone. Its issuer is the intermediate, not the root, so nothing
    // joins them.
    const key = try leafKey();
    const short = [_][]const u8{&fixtures.leaf_der};
    try testing.expectEqual(
        attestation.Verdict.untrusted,
        attestation.read(&short, &key, &fixtures.root_der, fixtures.inside_window),
    );
}

test "a window that has closed, and one that has not opened, are both expired" {
    // Its own answer, because an expired chain is a card that is still real and
    // a forged chain is not. A reader acts on the two differently.
    const key = try leafKey();
    const closed = [_][]const u8{ &fixtures.expired_leaf_der, &fixtures.intermediate_der };
    try testing.expectEqual(
        attestation.Verdict.expired,
        attestation.read(&closed, &key, &fixtures.root_der, fixtures.inside_window),
    );

    const good = [_][]const u8{ &fixtures.leaf_der, &fixtures.intermediate_der };
    try testing.expectEqual(
        attestation.Verdict.expired,
        attestation.read(&good, &key, &fixtures.root_der, fixtures.before_window),
    );
}

test "one changed byte anywhere in the leaf stops it binding" {
    // The mutation check for the chain. Without it, every test above would pass
    // against a reader that answered `bound` for anything that parsed.
    const key = try leafKey();
    var leaf = fixtures.leaf_der;
    const intermediate = fixtures.intermediate_der;

    var index: usize = 0;
    while (index < leaf.len) : (index += 1) {
        const original = leaf[index];
        leaf[index] = original ^ 0xff;
        const chain = [_][]const u8{ &leaf, &intermediate };
        const verdict = attestation.read(&chain, &key, &fixtures.root_der, fixtures.inside_window);
        leaf[index] = original;
        try testing.expect(verdict != .bound);
    }
}

test "a changed root name or root key stops the chain, and its own signature is not read" {
    // **A trust anchor is trusted by fiat, so its own signature is never
    // checked.** Only two things about a root take part in a chain: the name a
    // certificate names as its issuer, and the key that signed it. Changing a
    // byte of either breaks the chain. Changing a byte of the root's own
    // signature changes nothing, because nobody verifies a root against itself,
    // and a test that expected otherwise would be pinning a fact that is not
    // true.
    const key = try leafKey();
    const chain = [_][]const u8{ &fixtures.leaf_der, &fixtures.intermediate_der };
    var root = fixtures.root_der;
    const parsed = try std.crypto.Certificate.parse(.{ .buffer = &fixtures.root_der, .index = 0 });

    for ([_]std.crypto.Certificate.der.Element.Slice{ parsed.subject_slice, parsed.pub_key_slice }) |part| {
        var index: usize = part.start;
        while (index < part.end) : (index += 1) {
            const original = root[index];
            root[index] = original ^ 0xff;
            const verdict = attestation.read(&chain, &key, &root, fixtures.inside_window);
            root[index] = original;
            try testing.expect(verdict != .bound);
        }
    }

    // The other half of the same claim, stated rather than assumed: a byte in
    // the root's own signature leaves the chain binding.
    const signature_start = parsed.signature_slice.start;
    const before = root[signature_start];
    root[signature_start] = before ^ 0xff;
    try testing.expectEqual(
        attestation.Verdict.bound,
        attestation.read(&chain, &key, &root, fixtures.inside_window),
    );
    root[signature_start] = before;
}

test "no truncation of a certificate ends the process, and none of them binds" {
    // `std.crypto.Certificate` reads DER with no bounds check of its own, so a
    // certificate that stops in the middle of an element aborts the program
    // rather than returning an error. A seal is a record somebody else wrote, so
    // this had to be closed: see `attestation.safeToParse`.
    //
    // The test is the sweep. Every prefix of a real certificate goes through the
    // reader in both places a certificate can sit, and the proof that the guard
    // works is that this test finishes at all.
    const key = try leafKey();

    // Every prefix short of the whole thing. The whole thing is left out on
    // purpose: that one does bind, and it is the test above.
    var length: usize = 0;
    while (length < fixtures.leaf_der.len) : (length += 1) {
        const cut = fixtures.leaf_der[0..length];
        const chain = [_][]const u8{ cut, &fixtures.intermediate_der };
        try testing.expect(
            attestation.read(&chain, &key, &fixtures.root_der, fixtures.inside_window) != .bound,
        );
    }

    var root_length: usize = 0;
    while (root_length < fixtures.root_der.len) : (root_length += 1) {
        const chain = [_][]const u8{ &fixtures.leaf_der, &fixtures.intermediate_der };
        try testing.expect(
            attestation.read(&chain, &key, fixtures.root_der[0..root_length], fixtures.inside_window) != .bound,
        );
    }
}

test "no single byte change to a certificate ends the process" {
    // The other half of the sweep. A truncation only ever cuts the last element
    // short; a changed byte can put a length field anywhere, which is the case
    // that reaches furthest past the end.
    const key = try leafKey();
    var leaf = fixtures.leaf_der;

    const replacements = [_]u8{ 0x00, 0x01, 0x30, 0x7f, 0x80, 0x82, 0xa0, 0xff };
    var index: usize = 0;
    while (index < leaf.len) : (index += 1) {
        const original = leaf[index];
        for (replacements) |replacement| {
            if (replacement == original) continue;
            leaf[index] = replacement;
            const chain = [_][]const u8{ &leaf, &fixtures.intermediate_der };
            try testing.expect(
                attestation.read(&chain, &key, &fixtures.root_der, fixtures.inside_window) != .bound,
            );
        }
        leaf[index] = original;
    }
}

test "the guard lets every real certificate through" {
    // The other side of the guard. A check strict enough to refuse a real
    // certificate would make every attestation unreadable, which is a quieter
    // failure than a crash and a worse one.
    const real = [_][]const u8{
        &fixtures.root_der,
        &fixtures.intermediate_der,
        &fixtures.leaf_der,
        &fixtures.other_key_leaf_der,
        &fixtures.expired_leaf_der,
        &fixtures.rogue_root_der,
        &fixtures.rogue_leaf_der,
    };
    for (real) |der| try testing.expect(attestation.safeToParse(der));
}

test {
    testing.refAllDecls(@This());
}
