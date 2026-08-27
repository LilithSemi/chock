//! Fixtures for the tests in this directory: a certificate chain, a private key
//! that matches the leaf of it, and the pieces of a PIV exchange.
//!
//! ## Where these came from, exactly
//!
//! **These certificates were not captured from a card.** No card, no reader and
//! no daemon was available where this was written, and saying otherwise would be
//! the one thing this project's own notes name as the way a test goes vacuous.
//!
//! They were made with `openssl` on a workstation, once, and the bytes were
//! written into this file. `openssl` is not in the build: nothing here runs it,
//! and `zig build` stays the only tool a build needs. What that buys is real
//! X.509: the chain below is signed with real ECDSA over P-256, and
//! `std.crypto.Certificate`, which is the real parser and the real verifier, is
//! what reads it. A chain this project's own code both made and checked would
//! prove nothing; a chain the standard library verifies is a real chain.
//!
//! **What it does not buy**: the extensions under Yubico's own object
//! identifier arc are the right shape and hold made up values, and the leaf
//! subject is written to look like a real one. Nothing here proves Chock can
//! read a certificate a Yubikey actually emits. That needs a Yubikey, and it is
//! named as an open item rather than glossed over.
//!
//! ## The chain
//!
//! `leaf_der` is signed by `intermediate_der`, which is signed by `root_der`.
//! `leaf_der` holds the public key of `leaf_secret`, so a seal signed with that
//! key is bound to this chain and a seal signed with any other key is not.
//!
//! The rest are the cases a reader has to keep apart:
//!
//! * `other_key_leaf_der`: a real leaf, correctly signed by the same
//!   intermediate, for a different key. This is an attestation borrowed from
//!   another card.
//! * `expired_leaf_der`: the same key and the same issuer, with a validity
//!   window that closed in 2020.
//! * `rogue_root_der` and `rogue_leaf_der`: a whole second chain, made by
//!   somebody else, with the same subject name as the real root.
//!
//! ## Times
//!
//! Every test in this directory passes a fixed moment rather than reading a
//! clock, so no assertion here depends on the day it runs.

const std = @import("std");

/// A moment inside every validity window below except the expired one.
/// 2030-01-01T00:00:00Z.
pub const inside_window: i64 = 1893456000;

/// A moment before the chain was made. 2020-01-01T00:00:00Z, which is also
/// inside `expired_leaf_der`'s own window.
pub const before_window: i64 = 1577836800;

/// The private key the leaf certificate is about, as the raw 32 byte scalar.
pub const leaf_secret = hex("52bfb777ed365c094caa8d4b02bf839b55964aa447b368f480b85a5f0d621a86");

/// Turn a hexadecimal literal into bytes at compile time. The certificates
/// below are written this way because a hexadecimal string is what every other
/// tool prints them as, so a reader can check one against `openssl` output.
fn hex(comptime text: []const u8) [text.len / 2]u8 {
    // A certificate is around 500 bytes, and the standard library's own decoder
    // takes one branch a byte, which is past the compiler's default budget.
    @setEvalBranchQuota(text.len * 8);
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

pub const root_der = hex("308201983082013da003020102021414f4653466ac1112e9df5a67d4" ++
    "d742e101494b04300a06082a8648ce3d0403023021311f301d060355" ++
    "04030c1643686f636b20546573742050495620526f6f74204341301e" ++
    "170d3236303832343139353432345a170d3436303831393139353432" ++
    "345a3021311f301d06035504030c1643686f636b2054657374205049" ++
    "5620526f6f742043413059301306072a8648ce3d020106082a8648ce" ++
    "3d03010703420004eb7f5d061be20ebff705b688a341eb95c33d36fa" ++
    "4ec8f8cbbf88b774e9618ff9f4f8ef5b0b6777fdd9d2b8398df21c90" ++
    "afc35533192d5c0d75024a2477a22d1aa3533051301d0603551d0e04" ++
    "16041400d745afad42b9155bdabd1059059d79af03b3f4301f060355" ++
    "1d2304183016801400d745afad42b9155bdabd1059059d79af03b3f4" ++
    "300f0603551d130101ff040530030101ff300a06082a8648ce3d0403" ++
    "020349003046022100ed7ad78cfc89240b3c1fca44588d535a6806cf" ++
    "283f579aeab4aacc6d8728da430221008905f700f155725e746ab3d8" ++
    "d2168b84a19b3db0e496b8779dbd002dc41f15cf");

pub const intermediate_der = hex("308201a230820147a0030201020214500b7e362ef5e04676ec04328e" ++
    "f0a1e442c88e4f300a06082a8648ce3d0403023021311f301d060355" ++
    "04030c1643686f636b20546573742050495620526f6f74204341301e" ++
    "170d3236303832343139353432345a170d3436303831393139353432" ++
    "345a302b3129302706035504030c2043686f636b2054657374205049" ++
    "56204174746573746174696f6e2030303030303059301306072a8648" ++
    "ce3d020106082a8648ce3d03010703420004ec1969d369f76d2ffaa2" ++
    "11422a910894442f9788070c8277bda56ffcd221fe578169a15c4f14" ++
    "81e074e03e80631184479a5bb55999f8fc2ce415616d0536f3f1a353" ++
    "3051300f0603551d130101ff040530030101ff301d0603551d0e0416" ++
    "0414a68a38deafc6e5b499bea60ffc8dd7d91cd1673e301f0603551d" ++
    "2304183016801400d745afad42b9155bdabd1059059d79af03b3f430" ++
    "0a06082a8648ce3d0403020349003046022100e9fdc9889d7ed828ce" ++
    "d807b5ca745b1d75d266500d566d8403c461ad239192a602210080d2" ++
    "8f8610fb7648cd266964f2f5d65cb0e86257d4f6d4eb3ec5621002ca" ++
    "6c35");

pub const leaf_der = hex("308201f230820199a003020102021435875234ae05628670c5f4a75e" ++
    "e47d94c907054e300a06082a8648ce3d040302302b31293027060355" ++
    "04030c2043686f636b20546573742050495620417474657374617469" ++
    "6f6e203030303030301e170d3236303832343139353434315a170d33" ++
    "36303832313139353434315a30253123302106035504030c1a597562" ++
    "694b657920504956204174746573746174696f6e2039633059301306" ++
    "072a8648ce3d020106082a8648ce3d03010703420004c05a8dc8bc0a" ++
    "3e09b5485209629dc5642150bd54cd5b22b87f033f8fd65ff70eadb7" ++
    "f154bd7e04a2a65625146ac241be077e6e3b17b1cb94e0eafd41af9a" ++
    "b8e5a381a030819d300c0603551d130101ff04023000300e0603551d" ++
    "0f0101ff0404030207803013060a2b0601040182c40a030304050403" ++
    "0504033014060a2b0601040182c40a03070406020400bc614e301206" ++
    "0a2b0601040182c40a0308040403020101301d0603551d0e04160414" ++
    "3817a2675e6da7164ae14c0dc199473fee6fc347301f0603551d2304" ++
    "1830168014a68a38deafc6e5b499bea60ffc8dd7d91cd1673e300a06" ++
    "082a8648ce3d04030203470030440220185279b5cfb96681ba4c58bc" ++
    "aca220addf13dd76e6e4b72c5a2b5cffd522556202204db2738cd1ce" ++
    "6197bcf077cc0e18cb4f915ad58398b6178674bb32bd84dc9bab");

pub const other_key_leaf_der = hex("308201f430820199a0030201020214423bac897e48941b9ce950994e" ++
    "63841d9d61cca2300a06082a8648ce3d040302302b31293027060355" ++
    "04030c2043686f636b20546573742050495620417474657374617469" ++
    "6f6e203030303030301e170d3236303832343139353434315a170d33" ++
    "36303832313139353434315a30253123302106035504030c1a597562" ++
    "694b657920504956204174746573746174696f6e2039633059301306" ++
    "072a8648ce3d020106082a8648ce3d030107034200045bf584465eeb" ++
    "206999e59e02142d64f5257ce95bba9d4b1f25e746f719f7793c4c9f" ++
    "fd8d8c3f97db2b449f2d3fcc4af94edf477e7e134c79602301d455e9" ++
    "8aa9a381a030819d300c0603551d130101ff04023000300e0603551d" ++
    "0f0101ff0404030207803013060a2b0601040182c40a030304050403" ++
    "0504033014060a2b0601040182c40a03070406020400bc614e301206" ++
    "0a2b0601040182c40a0308040403020101301d0603551d0e04160414" ++
    "8e9f0b803aac0e61e12a06625941adec708c8424301f0603551d2304" ++
    "1830168014a68a38deafc6e5b499bea60ffc8dd7d91cd1673e300a06" ++
    "082a8648ce3d04030203490030460221008536de6f4cd4d84fc53c6b" ++
    "da960ba8b92a0e418aa875573814e91d337d8c80d702210088542be3" ++
    "0bafbc6f8d0d17d26f7dcdb93e6a407a843ee967ed16f23efdb34382");

pub const expired_leaf_der = hex("308201f330820199a003020102021475bf54d69f8a1410ca839f8713" ++
    "9e6b11597a26ba300a06082a8648ce3d040302302b31293027060355" ++
    "04030c2043686f636b20546573742050495620417474657374617469" ++
    "6f6e203030303030301e170d3230303130313030303030305a170d32" ++
    "30303130323030303030305a30253123302106035504030c1a597562" ++
    "694b657920504956204174746573746174696f6e2039633059301306" ++
    "072a8648ce3d020106082a8648ce3d03010703420004c05a8dc8bc0a" ++
    "3e09b5485209629dc5642150bd54cd5b22b87f033f8fd65ff70eadb7" ++
    "f154bd7e04a2a65625146ac241be077e6e3b17b1cb94e0eafd41af9a" ++
    "b8e5a381a030819d300c0603551d130101ff04023000300e0603551d" ++
    "0f0101ff0404030207803013060a2b0601040182c40a030304050403" ++
    "0504033014060a2b0601040182c40a03070406020400bc614e301206" ++
    "0a2b0601040182c40a0308040403020101301d0603551d0e04160414" ++
    "3817a2675e6da7164ae14c0dc199473fee6fc347301f0603551d2304" ++
    "1830168014a68a38deafc6e5b499bea60ffc8dd7d91cd1673e300a06" ++
    "082a8648ce3d0403020348003045022100f54772fd112b442a011ccc" ++
    "36876e75d689121de0ee4cbdd7963003a77e723403022015793c8d16" ++
    "135842a2b39f81000e879b266446805fda5c4956bd77bce7b1ee5f");

pub const rogue_root_der = hex("308201973082013da003020102021451a08ae1cd7d26ab2ce52e8dc5" ++
    "49b268fa0eb678300a06082a8648ce3d0403023021311f301d060355" ++
    "04030c1643686f636b20546573742050495620526f6f74204341301e" ++
    "170d3236303832343139353434315a170d3436303831393139353434" ++
    "315a3021311f301d06035504030c1643686f636b2054657374205049" ++
    "5620526f6f742043413059301306072a8648ce3d020106082a8648ce" ++
    "3d03010703420004242d7fa9b570edaa94682b02556166631eaf9661" ++
    "566429025a75b7b33c619136dd001d2641b36a27f201623f54fe627b" ++
    "7f9b95a1b9b5714dc6e8e4b289f29415a3533051301d0603551d0e04" ++
    "1604145efef04208c0f17cac72755da340de9241045df4301f060355" ++
    "1d230418301680145efef04208c0f17cac72755da340de9241045df4" ++
    "300f0603551d130101ff040530030101ff300a06082a8648ce3d0403" ++
    "02034800304502206a3085e4917c55f6b509ca97466e91ddc6bea3a8" ++
    "deee0a93ff49239e46011ab8022100db0cb08f502530e76ba7f328e3" ++
    "d9fc20516a59c0df864b66cbf04db75019e5c9");

pub const rogue_leaf_der = hex("308201e93082018fa003020102021421bee52f5091611d8d76c7560c" ++
    "f2dac29ebbde0d300a06082a8648ce3d0403023021311f301d060355" ++
    "04030c1643686f636b20546573742050495620526f6f74204341301e" ++
    "170d3236303832343139353434315a170d3336303832313139353434" ++
    "315a30253123302106035504030c1a597562694b6579205049562041" ++
    "74746573746174696f6e2039633059301306072a8648ce3d02010608" ++
    "2a8648ce3d03010703420004c05a8dc8bc0a3e09b5485209629dc564" ++
    "2150bd54cd5b22b87f033f8fd65ff70eadb7f154bd7e04a2a6562514" ++
    "6ac241be077e6e3b17b1cb94e0eafd41af9ab8e5a381a030819d300c" ++
    "0603551d130101ff04023000300e0603551d0f0101ff040403020780" ++
    "3013060a2b0601040182c40a0303040504030504033014060a2b0601" ++
    "040182c40a03070406020400bc614e3012060a2b0601040182c40a03" ++
    "08040403020101301d0603551d0e041604143817a2675e6da7164ae1" ++
    "4c0dc199473fee6fc347301f0603551d230418301680145efef04208" ++
    "c0f17cac72755da340de9241045df4300a06082a8648ce3d04030203" ++
    "4800304502201be14a53e628009b280b138218b1d1f94d2dcdfbf788" ++
    "8d869e43b3c3b95680430221008c1be356b14db69e616dc49747d12a" ++
    "51084bf8c35e1be77acc04d6fbc5efece6");

/// The digest the recorded `GENERAL AUTHENTICATE` asks the card to sign:
/// SHA-256 of "chock pcsc transcript".
pub const transcript_digest = hex("a14f4bfd6bdd8c2fd8d1fea079911c68d252a639847324bdf4fdd10e261e88d9");

/// The signature a card answers that request with, DER encoded, made by the
/// same private key `leaf_der` holds the public part of.
///
/// **Made by `openssl` and not by this project's own code.** A signature Chock
/// produced and then checked with Chock would prove only that two halves of one
/// program agree. This one was produced by a different implementation entirely,
/// so decoding it and checking it against `leaf_der` proves the decoding is
/// right.
pub const transcript_signature_der = hex("304402200facb9e0c03ad59db784de07e1958adc456d174105c1d317" ++
    "ed114755d8e153ff022012ec5c10e2ef0fde57e166ec9b8b37177d41" ++
    "c4c127a93e7676d4c909c955973c");

/// A real RSA2048 key, made once with `ssh-keygen -t rsa -b 2048 -m PEM` on
/// the machine this was written for, and read out of the PKCS#1 DER it wrote.
///
/// **The private half is here on purpose and it guards nothing.** A card never
/// gives its private key up, so a test that wanted to record what a card would
/// answer had to hold a key it could sign with. This one signs the seals in
/// this directory and nothing else.
///
/// **What it buys**: the RSA half of `seal.read` is checked against a signature
/// made by raw modular exponentiation with this exponent, so the padding, the
/// key encoding and the verification all have to agree with a key this project
/// did not make.
pub const rsa_modulus = hex("9509dfd16e1418d7f321af6642275d2ad7544e7ceeb561a9c612c058" ++
    "fcffa394780f67dd2df0c54c5696bd1e3cc58484ad45da750035b14c" ++
    "e36abcdd6f99a5fea31bce1a45ab2fa76f0179241714f891493d1fc2" ++
    "8f7ad48c64388c80f1f1f31349e1e2f52920420a5971a1ff5729a9d6" ++
    "e3242d1ce80338cdef378e38b17f57e1c493dc3d439d526cc455027c" ++
    "0e123b6e6ac113706b71076a98f975b910097d152f611160483846f3" ++
    "042214e0ea8b4e593eb793bb350bcafc19e882a1f4ed136485e268d0" ++
    "9627daf918ab201dc61fd0afbf2c4d02b6ba1932fdc8d819f466067f" ++
    "124b01cd7b69bd875e143ec44ab403fd028ac58029215cffec1d59e1" ++
    "2583668f");

/// The public exponent, 65537. The one every RSA key a PIV card generates has.
pub const rsa_exponent = hex("010001");

/// The private exponent of `rsa_modulus`. See the comment on it.
pub const rsa_private_exponent = hex("06d1efdb0e957ed98af7b4a6124ae8d98807049c74f3f9e721f843b3" ++
    "0ec8c7fc884df42bcbe963aded9c72450af4e2ee8b5b51f6deae9651" ++
    "756ab1ffd4168ce10d27bd93b8327038d23c98058dc4d8e71519e5f5" ++
    "2a49ada64b03c7723320264670b01489b17b176a8fd3425d83e8952c" ++
    "0f32dd99a0085db616c74d0bcd1b8db2e64262630255eef87310bb3f" ++
    "b58de745cbfd378e95420224e4b52d876253c49d88b8b1d7b37f435a" ++
    "6963057a22c909bf1e29124b4f88603cd1d6aeae115a2646b56e1b1a" ++
    "dd329aa5e9fff6049e5a774160341159949c3c8a1d5bfc3071fef8b4" ++
    "78a904f371d4a39e8a6be463d1ab991c05aaaaa564e039db871de8c0" ++
    "c6041c19");
