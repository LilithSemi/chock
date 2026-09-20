//! The attestation reader against a real certificate chain, and a sweep that
//! proves a hostile record cannot end the process. Everything here runs with no
//! card, no reader and no daemon.

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
    const key = try leafKey();
    const chain = [_][]const u8{ &fixtures.leaf_der, &fixtures.intermediate_der };
    try testing.expectEqual(
        attestation.Verdict.bound,
        attestation.read(&chain, &key, &fixtures.root_der, fixtures.inside_window),
    );
}

test "a leaf borrowed from another card is refused, however real it is" {
    const key = try leafKey();
    const borrowed = [_][]const u8{ &fixtures.other_key_leaf_der, &fixtures.intermediate_der };
    try testing.expectEqual(
        attestation.Verdict.key_mismatch,
        attestation.read(&borrowed, &key, &fixtures.root_der, fixtures.inside_window),
    );

    const parsed = try std.crypto.Certificate.parse(.{ .buffer = &fixtures.other_key_leaf_der, .index = 0 });
    var other_key: [attestation.public_key_len]u8 = undefined;
    @memcpy(&other_key, parsed.pubKey());
    try testing.expectEqual(
        attestation.Verdict.bound,
        attestation.read(&borrowed, &other_key, &fixtures.root_der, fixtures.inside_window),
    );
}

test "a chain that reaches a different root is untrusted, even with the same name" {
    // The rogue root carries the same subject name as the real one.
    const key = try leafKey();
    const rogue = [_][]const u8{&fixtures.rogue_leaf_der};
    try testing.expectEqual(
        attestation.Verdict.untrusted,
        attestation.read(&rogue, &key, &fixtures.root_der, fixtures.inside_window),
    );

    try testing.expectEqual(
        attestation.Verdict.bound,
        attestation.read(&rogue, &key, &fixtures.rogue_root_der, fixtures.inside_window),
    );
}

test "a chain with a link missing does not reach the root" {
    const key = try leafKey();
    const short = [_][]const u8{&fixtures.leaf_der};
    try testing.expectEqual(
        attestation.Verdict.untrusted,
        attestation.read(&short, &key, &fixtures.root_der, fixtures.inside_window),
    );
}

test "a window that has closed, and one that has not opened, are both expired" {
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
    // A trust anchor is trusted by fiat, so nobody reads its own signature. Only
    // its subject name and its key take part in a chain.
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
    // certificate that stops inside an element aborts the program instead of
    // returning an error. `attestation.safeToParse` is the guard.
    const key = try leafKey();

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
    // A changed byte can put a length field anywhere, which reaches further past
    // the end than a truncation can.
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
