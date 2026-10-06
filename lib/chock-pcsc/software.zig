//! The level 3 key: a P-256 key pair held in this process, for a machine with
//! no smart card attached.

const std = @import("std");
const seal = @import("seal.zig");

pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const secret_len = Ecdsa.SecretKey.encoded_length;

pub const Key = struct {
    pair: Ecdsa.KeyPair,

    pub fn generate(io: std.Io) Key {
        return .{ .pair = Ecdsa.KeyPair.generate(io) };
    }

    pub fn fromSeed(seed: [Ecdsa.KeyPair.seed_length]u8) !Key {
        return .{ .pair = try Ecdsa.KeyPair.generateDeterministic(seed) };
    }

    pub fn fromSecret(secret: [secret_len]u8) !Key {
        return .{ .pair = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(secret)) };
    }

    pub fn toSecret(self: Key) [secret_len]u8 {
        return self.pair.secret_key.toBytes();
    }

    pub fn publicKey(self: Key) [Ecdsa.PublicKey.uncompressed_sec1_encoded_length]u8 {
        return self.pair.public_key.toUncompressedSec1();
    }

    pub fn signDigest(self: Key, digest: [std.crypto.hash.sha2.Sha256.digest_length]u8) ![Ecdsa.Signature.encoded_length]u8 {
        const signature = try self.pair.signPrehashed(digest, null);
        return signature.toBytes();
    }

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
        out[0..seal.signature_len].* = self.signDigest(digest) catch return error.Unusable;
        return out[0..seal.signature_len];
    }
};

const testing = std.testing;

test "a key made from a secret is the same key, public part and all" {
    const original = try Key.fromSeed([_]u8{0x11} ** 32);
    const secret = original.toSecret();
    const restored = try Key.fromSecret(secret);
    try testing.expectEqualSlices(u8, &original.publicKey(), &restored.publicKey());
    try testing.expectEqualSlices(u8, &secret, &restored.toSecret());
}

test "two different seeds give two different keys" {
    const one = try Key.fromSeed([_]u8{0x11} ** 32);
    const two = try Key.fromSeed([_]u8{0x22} ** 32);
    try testing.expect(!std.mem.eql(u8, &one.publicKey(), &two.publicKey()));
}

test "a public key is the 65 byte uncompressed SEC-1 form and starts with 04" {
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

    const other = try Key.fromSeed([_]u8{0x55} ** 32);
    try testing.expectError(
        error.SignatureVerificationFailed,
        signature.verifyPrehashed(digest, other.pair.public_key),
    );
}

test "one changed bit of the digest breaks the signature" {
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
    try testing.expect(!std.mem.eql(u8, &try key.signDigest(digest), &try key.signDigest([_]u8{0xac} ** 32)));
}

test {
    testing.refAllDecls(@This());
}
