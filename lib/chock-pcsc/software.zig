//! The level 3 key: a P-256 key pair held in this process, for a machine with
//! no card, no reader or no daemon.
//!
//! ## What this key cannot do
//!
//! Nothing here stops a person who can read the secret from signing whatever
//! they like. The secret is 32 bytes in this process's memory and, between runs,
//! wherever the caller put it. It proves that the same key signed two logs. It
//! proves nothing about where that key lives, and `seal.read` never reports a
//! software seal as hardware backed.
//!
//! ## Where the secret is kept is not this file's business
//!
//! `toSecret` and `fromSecret` are the whole of the storage interface here.
//! `lib/chock-auth/store.zig` already holds a credential store with a platform
//! driver under it, a file at mode `0600` on Linux and the Keychain on macOS,
//! and that is where the secret belongs. This module does not import
//! `chock-auth`, because a verifier must never need a credential store to check
//! a signature.

const std = @import("std");
const seal = @import("seal.zig");

/// The signature scheme. The same one `piv.zig` uses for a card key, named in
/// one place so the two paths cannot drift onto different curves.
pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// How many bytes the secret takes when it is stored.
pub const secret_len = Ecdsa.SecretKey.encoded_length;

/// A key pair this process holds.
pub const Key = struct {
    pair: Ecdsa.KeyPair,

    /// A fresh key from the system's random source. `io` is passed in rather
    /// than reached for, which is what lets a test use a seeded source.
    pub fn generate(io: std.Io) Key {
        return .{ .pair = Ecdsa.KeyPair.generate(io) };
    }

    /// A key from a seed, for a test that needs the same key twice. **Not for a
    /// real key**: the seed decides the secret, so a seed a person could guess
    /// is a secret a person could guess.
    pub fn fromSeed(seed: [Ecdsa.KeyPair.seed_length]u8) !Key {
        return .{ .pair = try Ecdsa.KeyPair.generateDeterministic(seed) };
    }

    /// A key from a stored secret.
    pub fn fromSecret(secret: [secret_len]u8) !Key {
        return .{ .pair = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(secret)) };
    }

    /// The secret, for a caller that is about to put it in the credential
    /// store. Nothing else has a reason to call this.
    pub fn toSecret(self: Key) [secret_len]u8 {
        return self.pair.secret_key.toBytes();
    }

    /// The public key in the uncompressed SEC-1 form, which is the form a seal
    /// carries and the form a certificate holds.
    pub fn publicKey(self: Key) [Ecdsa.PublicKey.uncompressed_sec1_encoded_length]u8 {
        return self.pair.public_key.toUncompressedSec1();
    }

    /// Sign a SHA-256 digest, and answer the fixed width `r` then `s` form.
    ///
    /// **Deterministic, with no added noise.** RFC 6979 style signing means the
    /// same key over the same digest always gives the same bytes, so a test can
    /// pin a signature and a reader can tell a re-signing from a new signature.
    /// The card path is deterministic on the card for the same reason.
    pub fn signDigest(self: Key, digest: [std.crypto.hash.sha2.Sha256.digest_length]u8) ![Ecdsa.Signature.encoded_length]u8 {
        const signature = try self.pair.signPrehashed(digest, null);
        return signature.toBytes();
    }

    /// This key behind `seal.Signer`, so `seal.sign` cannot tell it from a
    /// card. **The same shape `piv.CardSigner.signer` has**, which is the whole
    /// point: the level a seal records is decided by the caller that chose a
    /// signer, and never by anything below this line.
    ///
    /// The key must outlive the signer.
    pub fn signer(self: *Key) seal.Signer {
        return .{ .ptr = self, .vtable = &signer_vtable };
    }

    const signer_vtable = seal.Signer.VTable{
        .publicKey = signerPublicKey,
        .signDigest = signerSignDigest,
    };

    fn signerPublicKey(
        ptr: *anyopaque,
        out: *[seal.max_public_key_len]u8,
    ) seal.SignError![]const u8 {
        const self: *Key = @ptrCast(@alignCast(ptr));
        out[0..seal.public_key_len].* = self.publicKey();
        return out[0..seal.public_key_len];
    }

    fn signerSignDigest(
        ptr: *anyopaque,
        digest: [std.crypto.hash.sha2.Sha256.digest_length]u8,
        out: *[seal.max_signature_len]u8,
    ) seal.SignError![]const u8 {
        const self: *Key = @ptrCast(@alignCast(ptr));
        // The only fault this can carry is a key that will not sign, which is
        // what `Unusable` names. There is no card to be removed here.
        out[0..seal.signature_len].* = self.signDigest(digest) catch return error.Unusable;
        return out[0..seal.signature_len];
    }
};

const testing = std.testing;

test "a key made from a secret is the same key, public part and all" {
    // The property the credential store depends on. A secret that did not round
    // trip would give a new public key on every run, and every earlier seal
    // would stop verifying.
    const original = try Key.fromSeed([_]u8{0x11} ** 32);
    const secret = original.toSecret();
    const restored = try Key.fromSecret(secret);
    try testing.expectEqualSlices(u8, &original.publicKey(), &restored.publicKey());
    try testing.expectEqualSlices(u8, &secret, &restored.toSecret());
}

test "two different seeds give two different keys" {
    // Guards against a derivation that ignored its input, which would give every
    // machine the same signing key.
    const one = try Key.fromSeed([_]u8{0x11} ** 32);
    const two = try Key.fromSeed([_]u8{0x22} ** 32);
    try testing.expect(!std.mem.eql(u8, &one.publicKey(), &two.publicKey()));
}

test "a public key is the 65 byte uncompressed SEC-1 form and starts with 04" {
    // A certificate holds this exact form, so an attestation can be matched
    // against a seal's key byte for byte. A compressed key would never match.
    const key = try Key.fromSeed([_]u8{0x33} ** 32);
    const public = key.publicKey();
    try testing.expectEqual(@as(usize, 65), public.len);
    try testing.expectEqual(@as(u8, 0x04), public[0]);
}

test "a signature verifies against the public key, and not against another key" {
    const key = try Key.fromSeed([_]u8{0x44} ** 32);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("the head of a chain", &digest, .{});

    const raw = try key.signDigest(digest);
    const signature = Ecdsa.Signature.fromBytes(raw);
    try signature.verifyPrehashed(digest, key.pair.public_key);

    // Another key's public part must not verify it, which is the whole reason
    // a seal carries a key.
    const other = try Key.fromSeed([_]u8{0x55} ** 32);
    try testing.expectError(
        error.SignatureVerificationFailed,
        signature.verifyPrehashed(digest, other.pair.public_key),
    );
}

test "one changed bit of the digest breaks the signature" {
    // The mutation check. Without it this test would pass against an
    // implementation that verified nothing at all.
    const key = try Key.fromSeed([_]u8{0x66} ** 32);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("the head of a chain", &digest, .{});
    const signature = Ecdsa.Signature.fromBytes(try key.signDigest(digest));

    var changed = digest;
    changed[31] ^= 0x01;
    try testing.expectError(
        error.SignatureVerificationFailed,
        signature.verifyPrehashed(changed, key.pair.public_key),
    );
}

test "signing is deterministic, so the same digest gives the same bytes twice" {
    const key = try Key.fromSeed([_]u8{0x77} ** 32);
    const digest = [_]u8{0xab} ** 32;
    try testing.expectEqualSlices(u8, &try key.signDigest(digest), &try key.signDigest(digest));
    // And a different digest gives different bytes, so the answer is not a
    // constant.
    try testing.expect(!std.mem.eql(u8, &try key.signDigest(digest), &try key.signDigest([_]u8{0xac} ** 32)));
}

test {
    testing.refAllDecls(@This());
}
