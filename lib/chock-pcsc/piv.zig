//! PIV, the card application Chock signs with. NIST SP 800-73-4 gives the
//! application identifier, the data object tags, and the four commands used
//! here. `apdu.zig` builds the frame, `tlv.zig` reads the objects, and this file
//! says what the bytes mean.
//!
//! ## The commands, and what each one is for
//!
//! 1. `select`, ISO 7816-4 `SELECT` by name with the PIV application
//!    identifier. Nothing else works until this is done.
//! 2. `verifyPin`, ISO 7816-4 `VERIFY`. A signing key on a PIV card needs the
//!    PIN before it will use the private key. The card counts the wrong tries
//!    itself and blocks after the last one, so this reports the count back
//!    rather than trying again. `pinRetries` reads that count **without
//!    spending one**, which is what makes a prompt honest.
//! 3. `readCertificate`, `GET DATA` on a certificate object.
//! 4. `signDigest`, `GENERAL AUTHENTICATE`. The card signs a value computed off
//!    the card. For an elliptic curve key that value is the digest and the
//!    answer is DER; for an RSA key it is the whole padded block and the answer
//!    is the raw signature. See `pkcs1Sha256Into`.
//!
//! And two that are not in SP 800-73-4 at all, both Yubico's own: `attest`,
//! `INS F9`, and `readMetadata`, `INS F7`.
//!
//! ## A key and a certificate are separate objects
//!
//! **This is the distinction that cost this project a wrong conclusion.** A PIV
//! slot holds a private key and a certificate, written by two separate
//! commands, and a key generated with no certificate beside it is an ordinary
//! state. A build that read only the certificate reported the owner's own card
//! as holding no key in any slot; it held an RSA2048 key in slot 9C the whole
//! time.
//!
//! `readMetadata` is the command that answers the question that was really
//! being asked, and it carries the public key as well, so a slot with no
//! certificate can still be signed with. `readCertificate` stays for a card
//! that has no `GET METADATA`, and that path says what it measured rather than
//! what it guessed.
//!
//! ## Every command here is built in full and compared byte for byte
//!
//! The tests below hold the exact bytes each command becomes. That is what
//! makes them worth writing: a test that only checked a command "was built"
//! would pin nothing, and a card is not available to catch a wrong byte later.
//! Each constant is traceable to a table in SP 800-73-4, named in the comment
//! beside it.
//!
//! ## The card is untrusted input
//!
//! A card can answer with anything. Every length here is checked, every status
//! word is read rather than assumed, and no answer is asserted about. See
//! IronStyle's backbone rule.

const std = @import("std");
const apdu = @import("apdu.zig");
const tlv = @import("tlv.zig");
const iface = @import("../chock-pcsc.zig");
const seal = @import("seal.zig");
const attestation = @import("attestation.zig");
const pin_prompt = @import("pin.zig");
/// **Imported for one enumeration and nothing else**: `attempt.Outcome`, which
/// already holds one member and one sentence per way a card path can stop.
/// `CardSigner` needs those words for the prompts it puts up itself, and a
/// second set of them here would be a second thing to keep true.
const attempt = @import("attempt.zig");

/// The PIV card application identifier. SP 800-73-4 part 1 section 2.2: the
/// NIST registered application provider identifier `A0 00 00 03 08` followed by
/// the PIV application portion `00 00 10 00 01 00`.
pub const aid = [_]u8{ 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00 };

/// The interindustry class byte. No secure messaging, no chaining, no logical
/// channel.
pub const cla: u8 = 0x00;

/// The largest data object a PIV card holds, SP 800-73-4 part 1 section 3.3.
/// A caller sizes its buffer by this.
pub const max_object_len = 3072;

/// Which key on the card. The number is the key reference SP 800-73-4 part 1
/// table 4 gives it, which is also the byte `GENERAL AUTHENTICATE` puts in `P2`.
pub const Slot = enum(u8) {
    piv_authentication = 0x9a,
    card_management = 0x9b,
    digital_signature = 0x9c,
    key_management = 0x9d,
    card_authentication = 0x9e,
    /// Yubico's attestation key. Not in SP 800-73-4. Its certificate is what
    /// every attestation this module reads chains to. See `attest`.
    attestation = 0xf9,

    /// The data object tag that holds this slot's X.509 certificate.
    /// SP 800-73-4 part 1 table 3, and for `attestation` the tag Yubico
    /// documents for its own object.
    ///
    /// Null for `card_management`: the card management key has no certificate
    /// object of its own, so there is nothing to read.
    pub fn certificateTag(self: Slot) ?tlv.Tag {
        return switch (self) {
            .piv_authentication => 0x5fc105,
            .card_management => null,
            .digital_signature => 0x5fc10a,
            .key_management => 0x5fc10b,
            .card_authentication => 0x5fc101,
            .attestation => 0x5fff01,
        };
    }

    /// What the card does about the PIN for this slot when its metadata says
    /// `default`.
    ///
    /// **`digital_signature` is `always`.** SP 800-73-4 part 1 section 3.2.1
    /// gives that slot a PIN check before every use, and a stock YubiKey follows
    /// it. A caller that assumed `once` here would sign the first log and be
    /// refused on the second, in the middle of a run.
    pub fn defaultPinPolicy(self: Slot) PinPolicy {
        return switch (self) {
            .digital_signature => .always,
            .card_authentication => .never,
            else => .once,
        };
    }
};

/// Which algorithm a key uses, SP 800-78-4 table 6-2. The two Chock can sign
/// with are here, and the two it cannot are named as well, so a card holding one
/// of those is refused by name rather than signed with the wrong algorithm
/// identifier in `P1`.
pub const Algorithm = enum(u8) {
    rsa1024 = 0x06,
    rsa2048 = 0x07,
    ecc_p256 = 0x11,
    ecc_p384 = 0x14,
    _,

    /// Whether this build can sign with a key of this algorithm.
    pub fn usable(self: Algorithm) bool {
        return switch (self) {
            .ecc_p256, .rsa2048 => true,
            else => false,
        };
    }

    /// How many bytes a signature from a key of this algorithm takes, or null
    /// when this build has no scheme for it.
    pub fn signatureLen(self: Algorithm) ?usize {
        return switch (self) {
            .ecc_p256 => seal.signature_len,
            .rsa2048 => seal.rsa2048_modulus_len,
            else => null,
        };
    }

    /// The name a message calls this, for a card holding a key nothing here can
    /// use.
    pub fn text(self: Algorithm) []const u8 {
        return switch (self) {
            .rsa1024 => "RSA1024",
            .rsa2048 => "RSA2048",
            .ecc_p256 => "ECC P-256",
            .ecc_p384 => "ECC P-384",
            _ => "an algorithm this build has no name for",
        };
    }
};

/// When the card wants the PIN before it uses a key. Yubico's `GET METADATA`
/// reports it in the first byte of tag `02`.
pub const PinPolicy = enum(u8) {
    /// The card did not say, so the slot's own default holds. See
    /// `Slot.defaultPinPolicy`.
    default = 0x00,
    never = 0x01,
    /// Once for the connection. One `VERIFY` covers every signature after it.
    once = 0x02,
    /// Before every single signature. **This is what a stock signature slot
    /// does**, so it is the ordinary case and not the strange one.
    always = 0x03,
    _,
};

/// Whether the card wants a touch as well. Read and reported, never worked
/// around: a touch is a person at the machine and there is nothing software can
/// do about it except say that is what the card is waiting for.
pub const TouchPolicy = enum(u8) {
    default = 0x00,
    never = 0x01,
    always = 0x02,
    cached = 0x03,
    _,
};

/// How the certificate in a container is stored, SP 800-73-4 part 1 table 39.
/// The low three bits of the `CertInfo` byte.
pub const CertInfo = enum(u3) {
    uncompressed = 0b000,
    gzipped = 0b001,
    _,
};

pub const Error = error{
    /// Fewer bytes than the six a card PIN is at least. Checked here rather than
    /// sent, because a card counts a try it cannot read against the same counter
    /// as a wrong one.
    ///
    /// **Its own error and not one shared with the other two**, because a person
    /// who typed too little, a person who typed too much and a person whose PIN
    /// holds the pad byte each have a different thing to do next. One error for
    /// all three made the message name every cause and settle none of them.
    PinTooShort,
    /// More bytes than the eight the `VERIFY` field holds.
    ///
    /// **A count of bytes and never of characters.** A character outside plain
    /// ASCII takes more than one byte, so a PIN of eight characters can be nine
    /// bytes or more and lands here. See `padPin`.
    PinTooLongForField,
    /// The PIN holds the byte `FF`, which is the pad. See `padPin` for why that
    /// makes it a PIN no card can be asked about.
    PinHoldsPad,
    /// The card refused the command with a status this layer does not treat as
    /// a fact of its own. Read `status` on the answer for the two bytes.
    CardRefused,
    /// The card said the object is not there. A slot with no certificate in it
    /// looks like this.
    ObjectAbsent,
    /// The card wants the PIN, or a touch that did not come.
    NotAuthenticated,
    /// The answer was not shaped the way SP 800-73-4 says it must be.
    Malformed,
    /// The certificate is stored compressed. This module does not decompress,
    /// and says so rather than handing back the compressed bytes as if they
    /// were a certificate.
    CertificateCompressed,
    /// The signature the card returned is not a DER encoded ECDSA signature
    /// over the curve that was asked for.
    SignatureMalformed,
    /// The slot holds a key of an algorithm this build cannot sign with.
    /// **Not an empty slot and not a broken card**: the key is really there.
    KeyUnsupported,
};

/// Everything `select`, `verifyPin`, `readCertificate` and `signDigest` can
/// fail with.
pub const CardError = Error || iface.Card.ExchangeError;

/// The `SELECT` command for the PIV application. ISO 7816-4 section 11.1.1 with
/// `P1` of `04`, which selects by name.
pub fn selectCommand() apdu.Command {
    return .{
        .cla = cla,
        .ins = 0xa4,
        .p1 = 0x04,
        .p2 = 0x00,
        .data = &aid,
        .expect = apdu.max_response_data,
    };
}

/// Select the PIV application. Nothing else on the card answers until this has
/// been done.
pub fn select(card: iface.Card, out: []u8) CardError!void {
    const answer = try card.exchange(selectCommand(), out);
    if (answer.status.notFound()) return error.ObjectAbsent;
    if (!answer.status.ok()) return error.CardRefused;
}

/// A PIN is eight bytes on the wire, padded with `FF`. SP 800-73-4 part 2
/// section 3.2.1.
pub const pin_field_len = 8;
pub const min_pin_len = 6;
/// What the unused part of the field is filled with, SP 800-73-4 part 2 section
/// 3.2.1. **Also the one byte a PIN may not hold**: see `padPin`.
pub const pad_byte = 0xff;

/// Pad a PIN into the eight byte field `VERIFY` takes.
///
/// **The card is the authority on its own PIN, and this rule matches the
/// hardware rather than the document.** SP 800-73-4 says a PIV PIN is digits,
/// and a YubiKey does not hold its owner to that: `ykman piv access change-pin`
/// takes letters. A rule taken from the document locks a person whose PIN is
/// not numeric out of their own card and tells them their PIN is malformed,
/// which is a false statement about somebody's hardware. So the bytes go to the
/// card and the card decides.
///
/// Three things are still refused here, **each with an error of its own**, and
/// none of them can cost a try:
///
/// 1. **Fewer than six bytes**, which is `error.PinTooShort`. No card PIN is
///    that short, so sending it would spend one of three tries to learn what the
///    length already says. An empty answer is here, and `attempt.zig` reads it
///    as a person declining before it ever reaches this.
/// 2. **More than eight bytes**, which is `error.PinTooLongForField`. The field
///    holds eight and no more.
/// 3. **The byte `FF`**, which is `error.PinHoldsPad`. It is the pad, so the
///    card cannot tell it from the end of a shorter PIN: `1234567` and
///    `1234567 FF` are the same eight bytes on the wire. Sending it would ask
///    the card about a PIN that is not the one typed, and spend a try on the
///    wrong question.
///
/// **Three errors and not one, because the three have three remedies.** A single
/// error made the message name every cause, so a person read a sentence that
/// listed what might have happened and could act on none of it.
///
/// **The two lengths count bytes and not characters.** A character outside plain
/// ASCII takes more than one byte, so a PIN of eight characters can be nine
/// bytes and is refused here. The message that carries `PinTooLongForField` says
/// so, because a person who counted eight characters otherwise reads a refusal
/// that looks wrong to them.
///
/// Everything else is sent, including letters, punctuation and bytes above
/// ASCII, because a card can hold any of them.
pub fn padPin(pin: []const u8, out: *[pin_field_len]u8) Error!void {
    if (pin.len < min_pin_len) return error.PinTooShort;
    if (pin.len > pin_field_len) return error.PinTooLongForField;
    for (pin) |c| {
        if (c == pad_byte) return error.PinHoldsPad;
    }
    @memset(out, pad_byte);
    @memcpy(out[0..pin.len], pin);
}

/// The `VERIFY` command for the PIV application PIN. `P2` of `80` is the key
/// reference of the application PIN, SP 800-73-4 part 1 table 4.
pub fn verifyPinCommand(padded: *const [pin_field_len]u8) apdu.Command {
    return .{ .cla = cla, .ins = 0x20, .p1 = 0x00, .p2 = 0x80, .data = padded };
}

/// The `VERIFY` command with no data at all, which asks the card how many tries
/// are left without spending one. SP 800-73-4 part 2 section 3.2.1.
pub fn pinRetriesCommand() apdu.Command {
    return .{ .cla = cla, .ins = 0x20, .p1 = 0x00, .p2 = 0x80 };
}

/// What the card said about its own counter, read without spending a try.
///
/// **Here and not in `pin.zig`**, because it is a fact the card states and
/// `pin.zig` only carries it to a person.
pub const Tries = union(enum) {
    /// This many tries before the card blocks.
    left: u4,
    /// No try is left. The card needs the PUK.
    blocked,
    /// The PIN is already verified on this connection, so the card answered the
    /// empty `VERIFY` with success and named no count.
    verified,
    /// The card answered something with no count in it. **Never read as
    /// plenty**: it means the count is not known.
    unknown,

    /// The count, or null when the card named none.
    pub fn count(self: Tries) ?u4 {
        return switch (self) {
            .left => |n| n,
            .blocked => 0,
            .verified, .unknown => null,
        };
    }
};

/// What the card said about a PIN.
pub const PinOutcome = union(enum) {
    accepted,
    /// The PIN was wrong, and this many tries are left before the card blocks.
    wrong: u4,
    /// No further try will be taken. The card needs a PUK to come back.
    blocked,
};

/// Give the card the PIN. **A wrong PIN is an outcome and not an error**,
/// because the count of tries left is a fact the caller has to show a user
/// before it spends another one.
pub fn verifyPin(card: iface.Card, pin: []const u8, out: []u8) CardError!PinOutcome {
    var padded: [pin_field_len]u8 = undefined;
    try padPin(pin, &padded);
    // The padded PIN leaves this frame here rather than at the end of the
    // function, so it does not sit in the stack after the call returns.
    defer std.crypto.secureZero(u8, &padded);

    const answer = try card.exchange(verifyPinCommand(&padded), out);
    if (answer.status.ok()) return .accepted;
    if (answer.status.blocked()) return .blocked;
    if (answer.status.pinRetriesLeft()) |left| return .{ .wrong = left };
    return error.CardRefused;
}

/// Ask the card how many tries are left, **without spending one**.
///
/// This is the number a person is shown before they type. It has to be read
/// from the card rather than counted here, because a try spent by any other
/// program on this machine counts against the same counter.
pub fn pinRetries(card: iface.Card, out: []u8) CardError!Tries {
    const answer = try card.exchange(pinRetriesCommand(), out);
    // Blocked first. A card with no tries left answers `63 C0`, which is also a
    // count, and a caller that read the count would offer a prompt for a card
    // that has nothing left to spend.
    if (answer.status.blocked()) return .blocked;
    if (answer.status.pinRetriesLeft()) |left| return .{ .left = left };
    if (answer.status.ok()) return .verified;
    return .unknown;
}

/// Yubico's `GET METADATA`, `INS F7`. Not in SP 800-73-4. It answers what is in
/// a slot without reading a certificate: the algorithm, the PIN and touch
/// policies, where the key came from, and **the public key itself**.
pub fn metadataCommand(slot: Slot) apdu.Command {
    return .{
        .cla = cla,
        .ins = 0xf7,
        .p1 = 0x00,
        .p2 = @intFromEnum(slot),
        .expect = apdu.max_response_data,
    };
}

/// What a slot holds, as `GET METADATA` reports it.
///
/// **This is how a key with no certificate is found.** A PIV slot holds a key
/// and a certificate as two separate objects, written by two separate commands,
/// and a key can be generated without a certificate ever being put beside it. A
/// build that read only the certificate reports such a slot as empty, which is a
/// false statement about somebody's hardware and one this project has already
/// made once.
pub const Metadata = struct {
    algorithm: Algorithm,
    pin_policy: PinPolicy = .default,
    touch_policy: TouchPolicy = .default,
    /// The public key, in the shape a seal carries: an uncompressed SEC-1 point
    /// for an elliptic curve key, and the modulus element beside the exponent
    /// element for an RSA one. Borrowed from the buffer `readMetadata` was
    /// given.
    key: []const u8,

    /// The PIN policy that really holds, with the slot's own default filled in.
    pub fn pinPolicy(self: Metadata, slot: Slot) PinPolicy {
        if (self.pin_policy == .default) return slot.defaultPinPolicy();
        return self.pin_policy;
    }
};

/// The tags inside a metadata answer.
const metadata_algorithm_tag: tlv.Tag = 0x01;
const metadata_policy_tag: tlv.Tag = 0x02;
const metadata_public_tag: tlv.Tag = 0x04;
/// The element an elliptic curve public key sits in, inside the public key
/// element. The same tag `GENERATE ASYMMETRIC KEY PAIR` answers with.
const ec_point_tag: tlv.Tag = 0x86;

pub const MetadataError = error{
    /// The card does not have this command. Every YubiKey before firmware 5.3
    /// is here, and so is every card that is not a YubiKey. **Not "the slot is
    /// empty"**: nothing was learned about the slot at all.
    MetadataUnsupported,
};

/// Read what is in a slot. `out` holds the answer and the key points into it.
///
/// `error.ObjectAbsent` means the card says the slot holds no key, which is the
/// one place this module may say that.
pub fn readMetadata(
    card: iface.Card,
    slot: Slot,
    out: []u8,
) (CardError || MetadataError)!Metadata {
    const answer = try card.exchange(metadataCommand(slot), out);
    if (answer.status.notFound()) return error.ObjectAbsent;
    // `6D 00` is "instruction not supported" and `6A 81` is "function not
    // supported". A card without this command answers one of the two, and
    // neither says anything about the slot.
    const status = answer.status.value();
    if (status == 0x6d00 or status == 0x6a81) return error.MetadataUnsupported;
    if (!answer.status.ok()) return error.CardRefused;
    return parseMetadata(answer.data);
}

/// Read a metadata answer. Split out from `readMetadata` so a test can drive it
/// with bytes and no card.
pub fn parseMetadata(bytes: []const u8) Error!Metadata {
    var reader = tlv.Reader.init(bytes);
    var algorithm: ?Algorithm = null;
    var pin_policy: PinPolicy = .default;
    var touch_policy: TouchPolicy = .default;
    var public: ?[]const u8 = null;

    while (reader.next() catch return error.Malformed) |element| {
        switch (element.tag) {
            metadata_algorithm_tag => {
                if (element.value.len != 1) return error.Malformed;
                algorithm = @enumFromInt(element.value[0]);
            },
            metadata_policy_tag => {
                if (element.value.len < 2) return error.Malformed;
                pin_policy = @enumFromInt(element.value[0]);
                touch_policy = @enumFromInt(element.value[1]);
            },
            metadata_public_tag => public = element.value,
            else => {},
        }
    }

    const found = algorithm orelse return error.Malformed;
    const bytes_of_key = public orelse return error.Malformed;
    return .{
        .algorithm = found,
        .pin_policy = pin_policy,
        .touch_policy = touch_policy,
        .key = try sealKeyOf(found, bytes_of_key),
    };
}

/// The seal's form of a public key, out of the element the card gave.
///
/// **The RSA bytes are kept exactly as the card wrote them.** They already are
/// the modulus element followed by the exponent element, which is the shape
/// `seal.schemeOf` reads, so nothing is re-encoded and the key a verifier checks
/// against is byte for byte the key the card named.
pub fn sealKeyOf(algorithm: Algorithm, public: []const u8) Error![]const u8 {
    switch (algorithm) {
        .ecc_p256 => {
            var reader = tlv.Reader.init(public);
            const point = (reader.find(ec_point_tag) catch return error.Malformed) orelse
                return error.Malformed;
            if (point.len != seal.public_key_len or point[0] != 0x04) return error.Malformed;
            return point;
        },
        .rsa2048 => {
            const parts = seal.rsaParts(public) orelse return error.Malformed;
            if (parts.modulus.len != seal.rsa2048_modulus_len) return error.Malformed;
            return public;
        },
        else => return error.KeyUnsupported,
    }
}

/// The `GET DATA` command for one data object. SP 800-73-4 part 2 section 3.1.2:
/// `P1 P2` of `3F FF`, and the object named in a `5C` tagged list.
pub fn getDataCommand(tag: tlv.Tag, buffer: *[5]u8) Error!apdu.Command {
    const tag_bytes = try encodeTag(tag, buffer[2..]);
    buffer[0] = 0x5c;
    buffer[1] = @intCast(tag_bytes.len);
    return .{
        .cla = cla,
        .ins = 0xcb,
        .p1 = 0x3f,
        .p2 = 0xff,
        .data = buffer[0 .. 2 + tag_bytes.len],
        .expect = apdu.max_response_data,
    };
}

/// Write a packed tag back out as the bytes it came from. A leading zero byte
/// is never written, so `0x5fc105` becomes three bytes and `0x70` becomes one.
fn encodeTag(tag: tlv.Tag, out: *[3]u8) Error!Ru8Slice {
    if (tag > 0xffffff) return error.Malformed;
    if (tag <= 0xff) {
        out[0] = @intCast(tag);
        return out[0..1];
    }
    if (tag <= 0xffff) {
        out[0] = @intCast(tag >> 8);
        out[1] = @intCast(tag & 0xff);
        return out[0..2];
    }
    out[0] = @intCast(tag >> 16);
    out[1] = @intCast((tag >> 8) & 0xff);
    out[2] = @intCast(tag & 0xff);
    return out[0..3];
}

const Ru8Slice = []const u8;

/// Pull the certificate out of a certificate container. SP 800-73-4 part 1
/// table 39: `53` holds `70` with the certificate and `71` with one `CertInfo`
/// byte.
pub fn parseCertificateObject(object: []const u8) Error![]const u8 {
    var outer = tlv.Reader.init(object);
    const container = (outer.find(0x53) catch return error.Malformed) orelse return error.Malformed;

    var inner = tlv.Reader.init(container);
    const certificate = (inner.find(0x70) catch return error.Malformed) orelse return error.Malformed;
    if (certificate.len == 0) return error.Malformed;

    // `71` is optional in practice, and a container without it is read as
    // uncompressed, which is what every card in the field writes. A container
    // that says gzipped is refused rather than handed back as if it were DER.
    var again = tlv.Reader.init(container);
    if ((again.find(0x71) catch return error.Malformed)) |info| {
        if (info.len != 1) return error.Malformed;
        const stored: CertInfo = @enumFromInt(@as(u3, @truncate(info[0])));
        if (stored != .uncompressed) return error.CertificateCompressed;
    }
    return certificate;
}

/// Read a slot's X.509 certificate, DER encoded, into `out`.
pub fn readCertificate(card: iface.Card, slot: Slot, out: []u8) CardError![]const u8 {
    const tag = slot.certificateTag() orelse return error.ObjectAbsent;
    var data: [5]u8 = undefined;
    const answer = try card.exchange(try getDataCommand(tag, &data), out);
    if (answer.status.notFound()) return error.ObjectAbsent;
    if (answer.status.securityNotSatisfied()) return error.NotAuthenticated;
    if (!answer.status.ok()) return error.CardRefused;
    return parseCertificateObject(answer.data);
}

/// The dynamic authentication template tag, SP 800-73-4 part 2 table 7.
const dynamic_authentication_tag: u8 = 0x7c;
/// The response element inside it, sent empty to ask the card to fill it in.
const response_tag: u8 = 0x82;
/// The challenge element, which carries the digest to sign.
const challenge_tag: u8 = 0x81;

/// The largest value this builds a `GENERAL AUTHENTICATE` request for. An
/// RSA2048 block is the whole width of the modulus.
pub const max_challenge_len = seal.rsa2048_modulus_len;

/// How many bytes the request body of a `GENERAL AUTHENTICATE` takes for a
/// challenge of `challenge_len`: the outer tag and its length field, the empty
/// response element, and the challenge tag, length field and value.
pub fn authenticateBodyLen(challenge_len: usize) usize {
    return 1 + lengthFieldLen(innerLen(challenge_len)) + innerLen(challenge_len);
}

/// What sits inside the `7C` template: the empty response element, then the
/// challenge element whole.
fn innerLen(challenge_len: usize) usize {
    return 2 + 1 + lengthFieldLen(challenge_len) + challenge_len;
}

/// How many bytes a BER length field takes for `value`. One below 128, and two
/// or three above it, because the long form spends a byte saying how many
/// follow. ISO 7816-4 section 5.2.2.2.
fn lengthFieldLen(value: usize) usize {
    if (value < 0x80) return 1;
    if (value <= 0xff) return 2;
    return 3;
}

/// Write a BER length field and answer how many bytes it took.
fn writeLength(out: []u8, value: usize) usize {
    if (value < 0x80) {
        out[0] = @intCast(value);
        return 1;
    }
    if (value <= 0xff) {
        out[0] = 0x81;
        out[1] = @intCast(value);
        return 2;
    }
    out[0] = 0x82;
    out[1] = @intCast(value >> 8);
    out[2] = @intCast(value & 0xff);
    return 3;
}

/// The `GENERAL AUTHENTICATE` command that asks a slot to sign. SP 800-73-4
/// part 2 section 3.2.4: `P1` is the algorithm, `P2` is the key reference, and
/// the body is `7C { 82 (empty), 81 (the challenge) }`.
///
/// **The challenge is not always the digest.** For an elliptic curve key the
/// card signs the digest as it is given. For an RSA key the card does the raw
/// private key operation and nothing else, so the challenge has to be the whole
/// padded block, built here. See `pkcs1Sha256Into`.
///
/// **The hashing is off the card either way.** A PIV card never hashes a
/// message, which is why the seal's canonical bytes are hashed in `seal.zig`.
pub fn generalAuthenticateCommand(
    slot: Slot,
    algorithm: Algorithm,
    challenge: []const u8,
    buffer: []u8,
) Error!apdu.Command {
    if (challenge.len == 0 or challenge.len > max_challenge_len) return error.Malformed;
    const body_len = authenticateBodyLen(challenge.len);
    if (buffer.len < body_len) return error.Malformed;

    var pos: usize = 0;
    buffer[pos] = dynamic_authentication_tag;
    pos += 1;
    pos += writeLength(buffer[pos..], innerLen(challenge.len));
    buffer[pos] = response_tag;
    buffer[pos + 1] = 0x00;
    pos += 2;
    buffer[pos] = challenge_tag;
    pos += 1;
    pos += writeLength(buffer[pos..], challenge.len);
    @memcpy(buffer[pos..][0..challenge.len], challenge);
    pos += challenge.len;

    return .{
        .cla = cla,
        .ins = 0x87,
        .p1 = @intFromEnum(algorithm),
        .p2 = @intFromEnum(slot),
        .data = buffer[0..pos],
        .expect = apdu.max_response_data,
    };
}

/// The DER of a SHA-256 `DigestInfo` with the hash left off, RFC 8017
/// section 9.2 note 1. A constant of the standard, so it is written out rather
/// than built by an encoder that could disagree with the one a verifier uses.
pub const sha256_digest_info_prefix = [_]u8{
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
};

/// Build the EMSA-PKCS1-v1_5 block for a SHA-256 digest, RFC 8017 section 9.2:
/// `00 01 FF..FF 00 || DigestInfo`, the whole width of the modulus.
///
/// **The padding is not optional and it is not negotiable.** The card does a raw
/// RSA operation over whatever it is given, so a block built wrong gives a
/// signature that verifies against nothing and fails months later, in front of
/// somebody checking a log.
///
/// **At least eight `FF` bytes.** RFC 8017 requires it, and a 2048 bit modulus
/// over a SHA-256 digest leaves 202 of them, so this can only fail for a modulus
/// far smaller than anything here accepts.
pub fn pkcs1Sha256Into(
    out: []u8,
    digest: [std.crypto.hash.sha2.Sha256.digest_length]u8,
) Error!void {
    const tail = sha256_digest_info_prefix.len + digest.len;
    if (out.len < tail + 11) return error.Malformed;

    out[0] = 0x00;
    out[1] = 0x01;
    const pad_end = out.len - tail - 1;
    @memset(out[2..pad_end], 0xff);
    out[pad_end] = 0x00;
    @memcpy(out[pad_end + 1 ..][0..sha256_digest_info_prefix.len], &sha256_digest_info_prefix);
    @memcpy(out[out.len - digest.len ..], &digest);
}

/// Pull the DER signature out of a `GENERAL AUTHENTICATE` answer:
/// `7C { 82 (the signature) }`.
pub fn parseAuthenticateResponse(answer: []const u8) Error![]const u8 {
    var outer = tlv.Reader.init(answer);
    const template = (outer.find(dynamic_authentication_tag) catch return error.Malformed) orelse
        return error.Malformed;
    var inner = tlv.Reader.init(template);
    const signature = (inner.find(response_tag) catch return error.Malformed) orelse
        return error.Malformed;
    if (signature.len == 0) return error.Malformed;
    return signature;
}

/// The curve Chock signs on. Named here so the card path and the software path
/// cannot drift onto different curves.
pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const Sha256 = std.crypto.hash.sha2.Sha256;

/// The longest body a signature request takes, which is the RSA2048 one.
pub const max_authenticate_body = authenticateBodyLen(max_challenge_len);

/// Ask a slot to sign a SHA-256 digest. The signature is written into
/// `signature` and the part used is answered.
///
/// **The two schemes differ on both sides of the card.** An elliptic curve key
/// is given the digest and answers DER, which is decoded here and never carried
/// further: DER has more than one way to write the same signature, so a seal
/// that stored it would have a field whose bytes could change without its
/// meaning changing. An RSA key is given a padded block and answers the raw
/// signature, which already has exactly one form.
pub fn signDigest(
    card: iface.Card,
    slot: Slot,
    algorithm: Algorithm,
    digest: [Sha256.digest_length]u8,
    scratch: []u8,
    signature: *[seal.max_signature_len]u8,
) CardError![]const u8 {
    var body: [max_authenticate_body]u8 = undefined;
    var block: [seal.rsa2048_modulus_len]u8 = undefined;

    const challenge: []const u8 = switch (algorithm) {
        .ecc_p256 => &digest,
        .rsa2048 => challenge: {
            try pkcs1Sha256Into(&block, digest);
            break :challenge &block;
        },
        else => return error.KeyUnsupported,
    };

    const command = try generalAuthenticateCommand(slot, algorithm, challenge, &body);
    // `exchangeLong` and not `exchange`: an RSA2048 request is 266 bytes of
    // body, which no short form command can carry.
    const answer = try card.exchangeLong(command, scratch);
    if (answer.status.securityNotSatisfied()) return error.NotAuthenticated;
    if (!answer.status.ok()) return error.CardRefused;

    const value = try parseAuthenticateResponse(answer.data);
    switch (algorithm) {
        .ecc_p256 => {
            const decoded = Ecdsa.Signature.fromDer(value) catch return error.SignatureMalformed;
            signature[0..seal.signature_len].* = decoded.toBytes();
            return signature[0..seal.signature_len];
        },
        .rsa2048 => {
            if (value.len != seal.rsa2048_modulus_len) return error.SignatureMalformed;
            @memcpy(signature[0..seal.rsa2048_modulus_len], value);
            return signature[0..seal.rsa2048_modulus_len];
        },
        else => unreachable,
    }
}

/// Yubico's attestation command, `INS F9`. Not in SP 800-73-4. The card builds
/// a certificate for the key in `slot`, signs it with the key in slot `F9`, and
/// answers the DER of that certificate directly, with no `53` container around
/// it.
///
/// **This is what makes hardware backed provable rather than claimed.** The
/// certificate states the key was made on the card, and the chain it sits in
/// ends at a vendor certificate authority. See `attestation.zig`.
pub fn attestCommand(slot: Slot) apdu.Command {
    return .{
        .cla = cla,
        .ins = 0xf9,
        .p1 = @intFromEnum(slot),
        .p2 = 0x00,
        .expect = apdu.max_response_data,
    };
}

/// Ask the card for an attestation of `slot`. The answer is a DER certificate
/// in `out`.
///
/// A card that has no such command answers with a status that is not success,
/// and this reports `error.CardRefused` rather than a certificate. A card
/// without attestation is level 2, not a failure: see `seal.Level`.
pub fn attest(card: iface.Card, slot: Slot, out: []u8) CardError![]const u8 {
    const answer = try card.exchange(attestCommand(slot), out);
    if (!answer.status.ok()) return error.CardRefused;
    if (answer.data.len == 0) return error.Malformed;
    return answer.data;
}

/// A `seal.Signer` backed by one slot on one card. This is the only place the
/// transport and the seal format meet.
///
/// **The public key is read from the slot's certificate, once, at `init`.** A
/// private key on a card never leaves it, so the certificate is the only place
/// the matching public key can be read from, and a seal has to carry it: an
/// auditor with no card must be able to check the signature.
pub const CardSigner = struct {
    card: iface.Card,
    slot: Slot,
    /// Where card answers are put. The caller owns it and it must outlive this.
    scratch: []u8,
    algorithm: Algorithm,
    /// The public key. **Copied out of `scratch` and never borrowed from it**:
    /// every later card answer is written into `scratch`, so a key that pointed
    /// there would be whatever the last command brought back by the time a seal
    /// asked for it.
    key_bytes: [seal.max_public_key_len]u8 = undefined,
    key_len: usize = 0,
    /// What the card said it wants before it uses this key, and `default` when
    /// it did not say.
    ///
    /// **A guess is not filled in here.** Only `always` makes this ask before a
    /// signature; every other value waits for the card to refuse and asks then.
    /// A slot guessed as `always` would put a prompt in front of a person for a
    /// key that needed none, and a slot guessed as `once` would be refused in
    /// the middle of a run. The card is the one that knows.
    pin_policy: PinPolicy,
    /// Whether the card holds a `VERIFY` that no signature has used yet.
    ///
    /// **A boolean, and never the PIN.** Nothing here keeps what a person
    /// typed: the card keeps the fact that it was told, and this records only
    /// that the fact is still good for one signature. See the comptime block at
    /// the end of `attempt.zig`.
    ///
    /// **Why it exists.** A slot whose policy is `always` refuses a signature
    /// that no `VERIFY` came directly before, so `attempt.Attempt` unlocks the
    /// card when it opens it. Without this the first signature of the run asks
    /// again, and one seal costs a person two prompts. Three wrong PINs block
    /// the card, so a prompt nobody needs is a risk nobody chose.
    ///
    /// Only `attempt.Attempt` sets it, directly after the card accepted the
    /// PIN, and the first signature after that clears it. Every signature after
    /// that one asks again, because the card cleared its own status when it
    /// used the key.
    verify_unused: bool = false,
    /// Who to ask when the card wants the PIN before a signature. Null asks
    /// nobody, which makes a slot with the `always` policy answer
    /// `error.Unusable` and the caller fall back and record it.
    ///
    /// **A pair of pointers and never a PIN.** See the comptime block at the end
    /// of `attempt.zig`.
    asker: ?pin_prompt.Asker = null,
    /// The reader this card is in, for the question a person is shown. Empty
    /// until a caller that knows it says so.
    reader: []const u8 = "",
    /// Why this signer refused, and null while it has refused nothing.
    ///
    /// **The reason `seal.SignError` has no room for.** Every way a signature
    /// ends other than a signature is `error.Unusable`, so a caller that printed
    /// the error name told a person nothing at all. A slot whose PIN policy is
    /// `always` meets this often: sealing twenty logs asks twenty times, and
    /// only the first ask goes through `attempt.Attempt.givePin`.
    ///
    /// **It is also what makes a refusal final.** A wrong PIN on the second log
    /// would otherwise be asked for again on the third and on the fourth, and
    /// three wrong PINs block the card. Once this holds a reason, no later
    /// signature asks anybody anything.
    stopped: ?attempt.Outcome = null,
    /// How many bytes the refused PIN had, and null when no length was measured.
    /// It goes to `attempt.Outcome.sentenceWith` beside `stopped`.
    ///
    /// **A count and never the value.** It is kept for the outcomes
    /// `attempt.Outcome.countsBytes` names and for no other, and it is kept
    /// beside the first reason, for the reason that one is: it is the one a
    /// person caused.
    stopped_bytes: ?usize = null,
    /// Where `reasonFn` writes a sentence that carries a measured number.
    ///
    /// **A rendered sentence and never a PIN.** `authorise` writes the count of
    /// bytes here and nothing else ever writes to it, so no part of what was
    /// typed can arrive in it.
    reason_bytes: [attempt.max_sentence_len]u8 = undefined,

    pub const InitError = CardError || MetadataError || attestation.KeyError;

    /// Open a signer over `slot` from what `GET METADATA` says is in it. The
    /// card must already have had `select` called on it.
    ///
    /// **This needs no certificate.** A PIV slot holds a key and a certificate
    /// as separate objects, and a key generated without one is the ordinary
    /// state of a card nobody has issued a certificate for.
    pub fn fromMetadata(
        card: iface.Card,
        slot: Slot,
        scratch: []u8,
        metadata: Metadata,
    ) Error!CardSigner {
        if (metadata.key.len == 0 or metadata.key.len > seal.max_public_key_len)
            return error.KeyUnsupported;
        var made = CardSigner{
            .card = card,
            .slot = slot,
            .scratch = scratch,
            .algorithm = metadata.algorithm,
            .pin_policy = metadata.pin_policy,
        };
        @memcpy(made.key_bytes[0..metadata.key.len], metadata.key);
        made.key_len = metadata.key.len;
        return made;
    }

    /// Open a signer over `slot` from the certificate in it. The path for a card
    /// with no `GET METADATA`, where the certificate is the only place a public
    /// key can be read from.
    pub fn init(card: iface.Card, slot: Slot, scratch: []u8) InitError!CardSigner {
        const certificate = try readCertificate(card, slot, scratch);
        var made = CardSigner{
            .card = card,
            .slot = slot,
            .scratch = scratch,
            .algorithm = .ecc_p256,
            .pin_policy = .default,
        };
        made.key_bytes[0..seal.public_key_len].* = try attestation.publicKeyOf(certificate);
        made.key_len = seal.public_key_len;
        return made;
    }

    /// The public key this signs with.
    pub fn key(self: *const CardSigner) []const u8 {
        return self.key_bytes[0..self.key_len];
    }

    /// The signer. **`self` must not move afterwards**, because the seal's key
    /// is read back out of it on every signature.
    pub fn signer(self: *CardSigner) seal.Signer {
        return .{ .ptr = self, .vtable = &signer_vtable };
    }

    /// Give the card the PIN, once, for one signature.
    ///
    /// **There is no loop here and there must never be one.** A card blocks
    /// after three wrong PINs, so a retry nobody asked for is a way to destroy
    /// somebody's key. Every answer other than `accepted` ends this signature,
    /// and ends every signature after it in the same run: see `stopped`.
    ///
    /// **The prompt a person meets most.** A slot whose PIN policy is `always`
    /// asks before every signature, so a run that seals twenty logs comes here
    /// nineteen times and reaches `attempt.Attempt.givePin` once: the first
    /// signature uses the unlock the card path already did. Both keep the
    /// answers apart the same way, because both call `Outcome.forAnswer`.
    fn authorise(self: *CardSigner) seal.SignError!void {
        // **A refusal is final for the whole run and not for one signature.**
        // See `stopped`: this is the line that keeps a person who mistyped from
        // being asked again by the next log, and again by the one after it.
        if (self.stopped != null) return error.Unusable;

        const asker = self.asker orelse return self.refuse(.pin_required);

        // The count first, before anybody types. It spends no try.
        const tries = pinRetries(self.card, self.scratch) catch Tries.unknown;
        if (tries == .blocked) return self.refuse(.pin_blocked);

        var buffer: pin_prompt.Buffer = undefined;
        defer pin_prompt.wipe(&buffer);

        const answer = asker.ask(.{
            .reader = self.reader,
            .slot = self.slot,
            .tries = tries,
        }, &buffer);
        // **Every answer but a PIN ends this signature, and each one keeps its
        // own name.** The same mapping `attempt.Attempt.givePin` makes for the
        // first prompt of a run, called rather than copied, because this is the
        // one a person meets on every prompt after that.
        if (attempt.Outcome.forAnswer(answer)) |refused| return self.refuse(refused);
        // Null from `forAnswer` is a PIN with bytes in it, and nothing else.
        const value = answer.pin;

        const given = verifyPin(self.card, value, self.scratch) catch |err| {
            const refused = attempt.Outcome.forVerify(err);
            // The count travels with the first reason, so the sentence says the
            // number that was typed. A number beside a refusal no length caused
            // would read as the cause, which is why `countsBytes` decides.
            if (self.stopped == null and refused.countsBytes()) self.stopped_bytes = value.len;
            return self.refuse(refused);
        };
        switch (given) {
            .accepted => {},
            .wrong => return self.refuse(.pin_wrong),
            .blocked => return self.refuse(.pin_blocked),
        }
    }

    /// Keep why this signature ended, and answer the one error the seal format
    /// has. **The first reason is the one kept**, because it is the one a person
    /// caused. Every refusal after it is this signer holding the line.
    fn refuse(self: *CardSigner, reason: attempt.Outcome) seal.SignError {
        if (self.stopped == null) self.stopped = reason;
        return error.Unusable;
    }

    /// Why the last signature was refused, for `seal.Signer`. Null while nothing
    /// has been refused.
    fn reasonFn(ptr: *anyopaque) ?[]const u8 {
        const self: *CardSigner = @ptrCast(@alignCast(ptr));
        const stopped = self.stopped orelse return null;
        // The number the count measured goes in the sentence for the two
        // outcomes it is about. Everything else answers a constant, and the
        // buffer is left alone.
        return stopped.sentenceWith(self.stopped_bytes, &self.reason_bytes);
    }

    fn publicKeyFn(
        ptr: *anyopaque,
        out: *[seal.max_public_key_len]u8,
    ) seal.SignError![]const u8 {
        const self: *CardSigner = @ptrCast(@alignCast(ptr));
        if (self.key_len == 0 or self.key_len > out.len) return self.refuse(.key_unreadable);
        @memcpy(out[0..self.key_len], self.key_bytes[0..self.key_len]);
        return out[0..self.key_len];
    }

    fn signDigestFn(
        ptr: *anyopaque,
        digest: [Sha256.digest_length]u8,
        out: *[seal.max_signature_len]u8,
    ) seal.SignError![]const u8 {
        const self: *CardSigner = @ptrCast(@alignCast(ptr));
        // **Before the signature, and only for the policy that says so.** A slot
        // with `once` was unlocked when the card path opened, and a prompt here
        // would be one a person did not need to answer.
        if (self.pin_policy == .always) {
            // **A slot with `always` was unlocked when the card path opened as
            // well, and that unlock is good for one signature.** See
            // `verify_unused`. It is cleared before the card is asked, so a
            // signature the card refuses cannot let the next one skip the
            // question too.
            if (self.verify_unused) {
                self.verify_unused = false;
            } else {
                try self.authorise();
            }
        }

        return self.sign(digest, out) catch |err| switch (err) {
            // The card asked. **Once, and never in a loop**: whatever refuses a
            // signature the card has just taken the PIN for is not something a
            // second try at the counter will fix, and the counter is what blocks
            // the card.
            error.NotAuthenticated => {
                if (self.pin_policy == .always) return self.refuse(.pin_not_enough);
                try self.authorise();
                return self.sign(digest, out) catch self.refuse(.pin_not_enough);
            },
            // Every other way a card can refuse becomes one error, and each one
            // still leaves a reason behind it. The caller's answer to all of
            // them is the same: fall back a level and record it.
            error.NoCard, error.Removed => self.refuse(.no_card),
            error.KeyUnsupported => self.refuse(.key_unsupported),
            else => self.refuse(.card_refused),
        };
    }

    /// One `GENERAL AUTHENTICATE`, with the card's own refusal kept whole so the
    /// caller above can tell a PIN from everything else.
    fn sign(
        self: *CardSigner,
        digest: [Sha256.digest_length]u8,
        out: *[seal.max_signature_len]u8,
    ) CardError![]const u8 {
        return signDigest(self.card, self.slot, self.algorithm, digest, self.scratch, out);
    }

    const signer_vtable = seal.Signer.VTable{
        .publicKey = publicKeyFn,
        .signDigest = signDigestFn,
        .reason = reasonFn,
    };
};

const testing = std.testing;

test "the PIV application identifier is the eleven bytes SP 800-73-4 gives" {
    // Every other command in this file is useless if the select is wrong, and
    // there is no card here to find that out later.
    try testing.expectEqualSlices(
        u8,
        &.{ 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00 },
        &aid,
    );
}

test "the SELECT command is the exact bytes a card expects" {
    var buffer: [apdu.Command.max_encoded_len]u8 = undefined;
    const bytes = try selectCommand().encode(&buffer);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0xa4, 0x04, 0x00, 0x0b,
        0xa0, 0x00, 0x00, 0x03, 0x08,
        0x00, 0x00, 0x10, 0x00, 0x01,
        0x00, 0x00,
    }, bytes);
}

test "a PIN is padded to eight bytes with FF, and only the length and the pad byte are refused" {
    var padded: [pin_field_len]u8 = undefined;
    try padPin("123456", &padded);
    try testing.expectEqualSlices(u8, &.{ '1', '2', '3', '4', '5', '6', 0xff, 0xff }, &padded);

    // Eight bytes fill the field with no padding left.
    try padPin("12345678", &padded);
    try testing.expectEqualSlices(u8, "12345678", &padded);

    // The fault this replaced: a rule taken from SP 800-73-4 rather than from
    // the hardware. A YubiKey takes letters, so a person whose PIN is `yubico`
    // could never reach their own card and was told their PIN was malformed.
    try padPin("yubico", &padded);
    try testing.expectEqualSlices(u8, &.{ 'y', 'u', 'b', 'i', 'c', 'o', 0xff, 0xff }, &padded);
    try padPin("pa55 w0r", &padded);
    try testing.expectEqualSlices(u8, "pa55 w0r", &padded);
    // A byte above ASCII is one keypress in a Latin-1 locale and half a
    // character in a UTF-8 one. Both reach the card.
    try padPin(&.{ 0xc3, 0xa9, '1', '2', '3', '4' }, &padded);
    try testing.expectEqualSlices(u8, &.{ 0xc3, 0xa9, '1', '2', '3', '4', 0xff, 0xff }, &padded);

    try testing.expectError(error.PinTooShort, padPin("12345", &padded));
    try testing.expectError(error.PinTooLongForField, padPin("123456789", &padded));
    try testing.expectError(error.PinTooShort, padPin("", &padded));
    // The pad byte cannot be sent as part of a PIN, because the field gives the
    // card no way to tell it from the end of a shorter one.
    try testing.expectError(error.PinHoldsPad, padPin(&.{ '1', '2', '3', '4', '5', 0xff }, &padded));
}

test "each of the three rules that refuse a PIN answers with an error of its own" {
    // **The fault this closes.** All three answered `error.PinMalformed`, which
    // reached a person as one sentence that named every cause and settled none.
    // Somebody who ran the command twice learned nothing either time, because
    // the words could not say which rule had fired.
    //
    // The boundaries are here as well, on both sides of each rule, because the
    // gap that made the fault was a bound in the wrong place: `pin_too_long`
    // fired at the 64 byte buffer and not at the eight byte field, so every
    // length from nine to 64 fell into the shared error.
    //
    // Mutation check: put any two of the three rules back on one error and the
    // case for the rule that lost its name fails on the error.
    var padded: [pin_field_len]u8 = undefined;

    // Five bytes is one short of the least a card takes, and six is the least.
    try testing.expectError(error.PinTooShort, padPin("12345", &padded));
    try padPin("123456", &padded);

    // Eight bytes fill the field, and nine is one over it. Nine used to be
    // indistinguishable from five.
    try padPin("12345678", &padded);
    try testing.expectError(error.PinTooLongForField, padPin("123456789", &padded));

    // The two widths at the far end. 64 is what the prompt's buffer holds, so a
    // line of that length reaches this rather than being refused at the
    // terminal, and 65 never reaches this at all. Both are the field's answer
    // and not the buffer's.
    const sixty_four = [_]u8{'7'} ** 64;
    try testing.expectError(error.PinTooLongForField, padPin(&sixty_four, &padded));
    const sixty_five = [_]u8{'7'} ** 65;
    try testing.expectError(error.PinTooLongForField, padPin(&sixty_five, &padded));

    // The pad byte, in a value whose length is right, so nothing but the byte
    // itself can be what refused it.
    try testing.expectError(
        error.PinHoldsPad,
        padPin(&.{ '1', '2', '3', '4', '5', 0xff }, &padded),
    );

    // **Eight characters and nine bytes.** `é` is two bytes in UTF-8, so this
    // is the PIN a person counts as eight and the field measures as nine. It is
    // the length rule that refuses it, and the message that carries the error
    // has to say that bytes are not characters.
    const eight_characters = "é1234567";
    try testing.expectEqual(@as(usize, 9), eight_characters.len);
    try testing.expectError(error.PinTooLongForField, padPin(eight_characters, &padded));
}

test "the VERIFY command carries the padded PIN and the application PIN reference" {
    var padded: [pin_field_len]u8 = undefined;
    try padPin("123456", &padded);
    var buffer: [apdu.Command.max_encoded_len]u8 = undefined;
    const bytes = try verifyPinCommand(&padded).encode(&buffer);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x20, 0x00, 0x80, 0x08,
        '1',  '2',  '3',  '4',  '5',
        '6',  0xff, 0xff,
    }, bytes);

    // The query form has no data at all, which is what makes it cost no try.
    const query = try pinRetriesCommand().encode(&buffer);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x20, 0x00, 0x80 }, query);
}

test "each slot names its own certificate object, and no two share a tag" {
    // A build that gave two slots the same tag would read the authentication
    // certificate and seal it as if it were the signature key's.
    try testing.expectEqual(@as(?tlv.Tag, 0x5fc105), Slot.piv_authentication.certificateTag());
    try testing.expectEqual(@as(?tlv.Tag, 0x5fc10a), Slot.digital_signature.certificateTag());
    try testing.expectEqual(@as(?tlv.Tag, 0x5fc10b), Slot.key_management.certificateTag());
    try testing.expectEqual(@as(?tlv.Tag, 0x5fc101), Slot.card_authentication.certificateTag());
    try testing.expectEqual(@as(?tlv.Tag, 0x5fff01), Slot.attestation.certificateTag());
    // The card management key holds no certificate, and null says so rather
    // than naming an object that is not there.
    try testing.expectEqual(@as(?tlv.Tag, null), Slot.card_management.certificateTag());

    const slots = [_]Slot{
        .piv_authentication,  .digital_signature, .key_management,
        .card_authentication, .attestation,
    };
    for (slots, 0..) |a, i| {
        for (slots[i + 1 ..]) |b| {
            try testing.expect(a.certificateTag().? != b.certificateTag().?);
        }
    }
}

test "the GET DATA command names the object in a 5C list, three tag bytes and all" {
    var data: [5]u8 = undefined;
    var buffer: [apdu.Command.max_encoded_len]u8 = undefined;
    const command = try getDataCommand(Slot.digital_signature.certificateTag().?, &data);
    const bytes = try command.encode(&buffer);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0xcb, 0x3f, 0xff, 0x05,
        0x5c, 0x03, 0x5f, 0xc1, 0x0a,
        0x00,
    }, bytes);
}

test "a one byte tag is named with one byte, not padded out to three" {
    // A `5C 03 00 00 70` would name a different object from `5C 01 70`, and the
    // card would answer that it has no such thing.
    var data: [5]u8 = undefined;
    const command = try getDataCommand(0x70, &data);
    try testing.expectEqualSlices(u8, &.{ 0x5c, 0x01, 0x70 }, command.data);

    var two: [5]u8 = undefined;
    const wide = try getDataCommand(0x7f61, &two);
    try testing.expectEqualSlices(u8, &.{ 0x5c, 0x02, 0x7f, 0x61 }, wide.data);
}

test "a certificate is pulled out of its container, and a compressed one is refused" {
    // SP 800-73-4 part 1 table 39. The container is two levels deep, so a
    // reader that searched one level would find nothing.
    const container = [_]u8{
        0x53, 0x0a,
        0x70, 0x03,
        0x30, 0x82,
        0x01, 0x71,
        0x01, 0x00,
        0xfe, 0x00,
    };
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x82, 0x01 }, try parseCertificateObject(&container));

    const compressed = [_]u8{
        0x53, 0x08,
        0x70, 0x03,
        0x1f, 0x8b,
        0x08, 0x71,
        0x01, 0x01,
    };
    try testing.expectError(error.CertificateCompressed, parseCertificateObject(&compressed));
}

test "a container with no 53, no 70, or an empty certificate is malformed" {
    try testing.expectError(error.Malformed, parseCertificateObject(&.{ 0x70, 0x01, 0x00 }));
    try testing.expectError(error.Malformed, parseCertificateObject(&.{ 0x53, 0x03, 0x71, 0x01, 0x00 }));
    try testing.expectError(error.Malformed, parseCertificateObject(&.{ 0x53, 0x02, 0x70, 0x00 }));
    try testing.expectError(error.Malformed, parseCertificateObject(&.{}));
    // A length that runs past the end comes back as a fault, not a crash.
    try testing.expectError(error.Malformed, parseCertificateObject(&.{ 0x53, 0x40, 0x70 }));
}

test "the GENERAL AUTHENTICATE body is the nested template SP 800-73-4 table 7 gives" {
    // The empty `82` is the card's instruction to fill in the response. Leaving
    // it out, or putting it after the challenge, makes the card refuse.
    const digest = [_]u8{0xab} ** 32;
    var body: [64]u8 = undefined;
    const command = try generalAuthenticateCommand(.digital_signature, .ecc_p256, &digest, &body);

    try testing.expectEqual(@as(u8, 0x87), command.ins);
    try testing.expectEqual(@as(u8, 0x11), command.p1);
    try testing.expectEqual(@as(u8, 0x9c), command.p2);

    var expected: [38]u8 = undefined;
    expected[0] = 0x7c;
    expected[1] = 36;
    expected[2] = 0x82;
    expected[3] = 0x00;
    expected[4] = 0x81;
    expected[5] = 32;
    @memset(expected[6..], 0xab);
    try testing.expectEqualSlices(u8, &expected, command.data);
}

test "a challenge that is empty or larger than any key takes is refused" {
    var body: [64]u8 = undefined;
    try testing.expectError(
        error.Malformed,
        generalAuthenticateCommand(.digital_signature, .ecc_p256, &.{}, &body),
    );
    const huge = [_]u8{0} ** (max_challenge_len + 1);
    try testing.expectError(
        error.Malformed,
        generalAuthenticateCommand(.digital_signature, .ecc_p256, &huge, &body),
    );
    // And a body buffer one byte short is refused rather than written past.
    var tight: [37]u8 = undefined;
    const digest = [_]u8{0} ** 32;
    try testing.expectError(
        error.Malformed,
        generalAuthenticateCommand(.digital_signature, .ecc_p256, &digest, &tight),
    );
}

test "the signature is pulled out of the answer template, two levels down" {
    const answer = [_]u8{ 0x7c, 0x05, 0x82, 0x03, 0x30, 0x06, 0x02 };
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x06, 0x02 }, try parseAuthenticateResponse(&answer));

    try testing.expectError(error.Malformed, parseAuthenticateResponse(&.{ 0x82, 0x01, 0x00 }));
    try testing.expectError(error.Malformed, parseAuthenticateResponse(&.{ 0x7c, 0x02, 0x82, 0x00 }));
    try testing.expectError(error.Malformed, parseAuthenticateResponse(&.{}));
}

test "the attest command names the slot in P1 and carries no data" {
    var buffer: [apdu.Command.max_encoded_len]u8 = undefined;
    const bytes = try attestCommand(.digital_signature).encode(&buffer);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xf9, 0x9c, 0x00, 0x00 }, bytes);
}

test "select reports a card that has no PIV application, and one that has" {
    var absent = iface.Recorded{ .exchanges = &.{
        .{
            .send = &.{
                0x00, 0xa4, 0x04, 0x00, 0x0b,
                0xa0, 0x00, 0x00, 0x03, 0x08,
                0x00, 0x00, 0x10, 0x00, 0x01,
                0x00, 0x00,
            },
            .receive = &.{ 0x6a, 0x82 },
        },
    } };
    const no_piv = absent.pcsc();
    try no_piv.establish();
    const blank_card = try no_piv.connect(absent.reader_name);
    var out: [max_object_len]u8 = undefined;
    try testing.expectError(error.ObjectAbsent, select(blank_card, &out));

    var present = iface.Recorded{
        .exchanges = &.{
            .{
                .send = &.{
                    0x00, 0xa4, 0x04, 0x00, 0x0b,
                    0xa0, 0x00, 0x00, 0x03, 0x08,
                    0x00, 0x00, 0x10, 0x00, 0x01,
                    0x00, 0x00,
                },
                // The application property template a real PIV card answers with.
                .receive = &.{ 0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x90, 0x00 },
            },
        },
    };
    const piv_present = present.pcsc();
    try piv_present.establish();
    const good_card = try piv_present.connect(present.reader_name);
    try select(good_card, &out);
    try testing.expect(present.drained());
}

test "a wrong PIN comes back as a count of tries left, never as an error" {
    var padded: [pin_field_len]u8 = undefined;
    try padPin("111111", &padded);
    var recorded = iface.Recorded{ .exchanges = &.{
        .{
            .send = &.{ 0x00, 0x20, 0x00, 0x80, 0x08, '1', '1', '1', '1', '1', '1', 0xff, 0xff },
            .receive = &.{ 0x63, 0xc2 },
        },
    } };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);

    var out: [16]u8 = undefined;
    const outcome = try verifyPin(card, "111111", &out);
    try testing.expectEqual(PinOutcome{ .wrong = 2 }, outcome);
}

test "a blocked PIN is its own outcome, and no further try is offered" {
    var recorded = iface.Recorded{ .exchanges = &.{
        .{
            .send = &.{ 0x00, 0x20, 0x00, 0x80, 0x08, '1', '1', '1', '1', '1', '1', 0xff, 0xff },
            .receive = &.{ 0x69, 0x83 },
        },
    } };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);
    var out: [16]u8 = undefined;
    try testing.expectEqual(PinOutcome.blocked, try verifyPin(card, "111111", &out));
}

test "a slot the card has locked reports NotAuthenticated and never a certificate" {
    var recorded = iface.Recorded{ .exchanges = &.{
        .{
            .send = &.{ 0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x0a, 0x00 },
            .receive = &.{ 0x69, 0x82 },
        },
    } };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);
    var out: [max_object_len]u8 = undefined;
    try testing.expectError(error.NotAuthenticated, readCertificate(card, .digital_signature, &out));
}

test "a slot with no certificate in it reports ObjectAbsent" {
    var recorded = iface.Recorded{ .exchanges = &.{
        .{
            .send = &.{ 0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x0a, 0x00 },
            .receive = &.{ 0x6a, 0x82 },
        },
    } };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);
    var out: [max_object_len]u8 = undefined;
    try testing.expectError(error.ObjectAbsent, readCertificate(card, .digital_signature, &out));
}

test {
    testing.refAllDecls(@This());
}

test "the PKCS#1 block is the one RFC 8017 section 9.2 gives, to the byte" {
    // **The padding is the whole of the RSA signature.** The card does a raw
    // private key operation over whatever it is given, so a block built wrong
    // is a signature that verifies against nothing, and it fails months later
    // in front of somebody checking a log rather than here.
    //
    // The cross check that this agrees with a reader nobody here wrote is in
    // `test/pcsc/verify.zig`: a signature made over this block is verified by
    // `std.crypto.Certificate.rsa`, which builds the same block itself.
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash("chock", &digest, .{});

    var block: [seal.rsa2048_modulus_len]u8 = undefined;
    try pkcs1Sha256Into(&block, digest);

    try testing.expectEqual(@as(u8, 0x00), block[0]);
    try testing.expectEqual(@as(u8, 0x01), block[1]);
    // 256 bytes, less the two above, less the zero separator, less the 19 byte
    // DigestInfo prefix and the 32 byte hash: 202 bytes of FF.
    const pad_end = seal.rsa2048_modulus_len - 1 - sha256_digest_info_prefix.len - digest.len;
    try testing.expectEqual(@as(usize, 204), pad_end);
    for (block[2..pad_end]) |byte| try testing.expectEqual(@as(u8, 0xff), byte);
    try testing.expectEqual(@as(u8, 0x00), block[pad_end]);
    try testing.expectEqualSlices(
        u8,
        &sha256_digest_info_prefix,
        block[pad_end + 1 ..][0..sha256_digest_info_prefix.len],
    );
    try testing.expectEqualSlices(u8, &digest, block[seal.rsa2048_modulus_len - digest.len ..]);

    // RFC 8017 wants at least eight FF bytes, so a modulus too small for the
    // block is refused rather than written short.
    var tiny: [40]u8 = undefined;
    try testing.expectError(error.Malformed, pkcs1Sha256Into(&tiny, digest));
}

test "an RSA signature request is one command with a two byte length, and it is chained" {
    // The body of an RSA2048 request is 266 bytes, which no short form command
    // can carry. **That is why `Card.exchangeLong` exists**, and why the lengths
    // here are the long BER form.
    var body: [max_authenticate_body]u8 = undefined;
    const block = [_]u8{0xab} ** seal.rsa2048_modulus_len;
    const command = try generalAuthenticateCommand(.digital_signature, .rsa2048, &block, &body);

    try testing.expectEqual(@as(u8, 0x87), command.ins);
    try testing.expectEqual(@as(u8, 0x07), command.p1);
    try testing.expectEqual(@as(u8, 0x9c), command.p2);
    try testing.expectEqual(@as(usize, 266), command.data.len);
    // `7C 82 01 06`, then `82 00`, then `81 82 01 00` and the block.
    try testing.expectEqualSlices(u8, &.{ 0x7c, 0x82, 0x01, 0x06 }, command.data[0..4]);
    try testing.expectEqualSlices(u8, &.{ 0x82, 0x00 }, command.data[4..6]);
    try testing.expectEqualSlices(u8, &.{ 0x81, 0x82, 0x01, 0x00 }, command.data[6..10]);
    try testing.expectEqualSlices(u8, &block, command.data[10..]);
    // And it does not fit, which is the fact the chaining is for.
    try testing.expect(command.data.len > apdu.max_command_data);

    // The elliptic curve request is unchanged and still fits in one command,
    // so the change above cost the older path nothing.
    var short_body: [max_authenticate_body]u8 = undefined;
    const digest = [_]u8{0xcd} ** 32;
    const short = try generalAuthenticateCommand(
        .digital_signature,
        .ecc_p256,
        &digest,
        &short_body,
    );
    try testing.expectEqual(@as(usize, 38), short.data.len);
    try testing.expectEqualSlices(u8, &.{ 0x7c, 0x24, 0x82, 0x00, 0x81, 0x20 }, short.data[0..6]);
    try testing.expect(short.data.len <= apdu.max_command_data);
}

test "metadata says the algorithm, the policies and the public key of a slot" {
    // The command that separates a slot with no certificate from a slot with no
    // key. Reading only the certificate reported the owner's card as empty for
    // two tasks while it held an RSA2048 key the whole time.
    const rsa_key = [_]u8{ 0x81, 0x82, 0x01, 0x00 } ++ [_]u8{0x5a} ** 256 ++
        [_]u8{ 0x82, 0x03, 0x01, 0x00, 0x01 };
    const answer = [_]u8{ 0x01, 0x01, 0x07 } ++
        [_]u8{ 0x02, 0x02, 0x03, 0x01 } ++
        [_]u8{ 0x03, 0x01, 0x01 } ++
        [_]u8{ 0x04, 0x82, 0x01, 0x09 } ++ rsa_key;

    const found = try parseMetadata(&answer);
    try testing.expectEqual(Algorithm.rsa2048, found.algorithm);
    try testing.expectEqual(PinPolicy.always, found.pin_policy);
    try testing.expectEqual(TouchPolicy.never, found.touch_policy);
    try testing.expectEqualSlices(u8, &rsa_key, found.key);
    try testing.expect(found.algorithm.usable());

    // An elliptic curve key comes back as the bare point, which is the shape a
    // seal carries and the shape a certificate would have given.
    const point = [_]u8{0x04} ++ [_]u8{0x33} ** 64;
    const ec_answer = [_]u8{ 0x01, 0x01, 0x11 } ++
        [_]u8{ 0x02, 0x02, 0x02, 0x01 } ++
        [_]u8{ 0x04, 0x43, 0x86, 0x41 } ++ point;
    const ec = try parseMetadata(&ec_answer);
    try testing.expectEqual(Algorithm.ecc_p256, ec.algorithm);
    try testing.expectEqual(PinPolicy.once, ec.pin_policy);
    try testing.expectEqualSlices(u8, &point, ec.key);

    // A key of an algorithm this build cannot sign with is named, not silently
    // taken for one it can.
    const p384 = [_]u8{ 0x01, 0x01, 0x14 } ++ [_]u8{ 0x04, 0x02, 0x86, 0x00 };
    const other = parseMetadata(&p384);
    try testing.expectError(error.KeyUnsupported, other);

    // A card can answer anything, so a truncated element is a named fault.
    try testing.expectError(error.Malformed, parseMetadata(&.{ 0x01, 0x05, 0x07 }));
    try testing.expectError(error.Malformed, parseMetadata(&.{ 0x01, 0x01, 0x07 }));
}

test "the count of tries left is read without spending one, and zero is blocked" {
    // The command that makes the prompt honest. A `VERIFY` with no data field
    // asks the card how many tries are left and is not counted as an attempt.
    var buffer: [8]u8 = undefined;
    const query = try pinRetriesCommand().encode(&buffer);
    // Four bytes and nothing else: a length field here would make the card read
    // it as an attempt with an empty PIN.
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x20, 0x00, 0x80 }, query);

    var three = iface.Recorded{ .exchanges = &.{
        .{ .send = query, .receive = &.{ 0x63, 0xc3 } },
    } };
    const transport = three.pcsc();
    try transport.establish();
    var out: [64]u8 = undefined;
    const card = try transport.connect(three.reader_name);
    try testing.expectEqual(@as(?u4, 3), (try pinRetries(card, &out)).count());

    // **Zero left is `blocked` and not a count**, because a caller that read the
    // number would offer a prompt to a card with nothing left to spend.
    var none = iface.Recorded{ .exchanges = &.{
        .{ .send = query, .receive = &.{ 0x63, 0xc0 } },
    } };
    const second = none.pcsc();
    try second.establish();
    const blocked_card = try second.connect(none.reader_name);
    try testing.expectEqual(Tries.blocked, try pinRetries(blocked_card, &out));

    // And a card that names no count says so rather than saying plenty.
    var quiet = iface.Recorded{ .exchanges = &.{
        .{ .send = query, .receive = &.{ 0x6a, 0x86 } },
    } };
    const third = quiet.pcsc();
    try third.establish();
    const quiet_card = try third.connect(quiet.reader_name);
    try testing.expectEqual(Tries.unknown, try pinRetries(quiet_card, &out));
}
