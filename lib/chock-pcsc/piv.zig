//! PIV, the card application Chock signs with. NIST SP 800-73-4 gives the
//! application id, the slots and the algorithms.

const std = @import("std");
const apdu = @import("apdu.zig");
const tlv = @import("tlv.zig");
const iface = @import("../chock-pcsc.zig");
const seal = @import("seal.zig");
const attestation = @import("attestation.zig");
const pin_prompt = @import("pin.zig");
const attempt = @import("attempt.zig");

pub const aid = [_]u8{ 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00 };

pub const cla: u8 = 0x00;

pub const max_object_len = 3072;

pub const Slot = enum(u8) {
    piv_authentication = 0x9a,
    card_management = 0x9b,
    digital_signature = 0x9c,
    key_management = 0x9d,
    card_authentication = 0x9e,
    attestation = 0xf9,

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

    pub fn defaultPinPolicy(self: Slot) PinPolicy {
        return switch (self) {
            .digital_signature => .always,
            .card_authentication => .never,
            else => .once,
        };
    }
};

pub const Algorithm = enum(u8) {
    rsa1024 = 0x06,
    rsa2048 = 0x07,
    ecc_p256 = 0x11,
    ecc_p384 = 0x14,
    _,

    pub fn usable(self: Algorithm) bool {
        return switch (self) {
            .ecc_p256, .rsa2048 => true,
            else => false,
        };
    }

    pub fn signatureLen(self: Algorithm) ?usize {
        return switch (self) {
            .ecc_p256 => seal.signature_len,
            .rsa2048 => seal.rsa2048_modulus_len,
            else => null,
        };
    }

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

pub const PinPolicy = enum(u8) {
    default = 0x00,
    never = 0x01,
    once = 0x02,
    always = 0x03,
    _,
};

pub const TouchPolicy = enum(u8) {
    default = 0x00,
    never = 0x01,
    always = 0x02,
    cached = 0x03,
    _,
};

pub const CertInfo = enum(u3) {
    uncompressed = 0b000,
    gzipped = 0b001,
    _,
};

pub const Error = error{
    PinTooShort,
    PinTooLongForField,
    PinHoldsPad,
    CardRefused,
    ObjectAbsent,
    NotAuthenticated,
    Malformed,
    CertificateCompressed,
    SignatureMalformed,
    KeyUnsupported,
};

pub const CardError = Error || iface.Card.ExchangeError;

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

pub fn select(card: iface.Card, out: []u8) CardError!void {
    const answer = try card.exchange(selectCommand(), out);
    if (answer.status.notFound()) return error.ObjectAbsent;
    if (!answer.status.ok()) return error.CardRefused;
}

pub const pin_field_len = 8;
pub const min_pin_len = 6;
pub const pad_byte = 0xff;

pub fn padPin(pin: []const u8, out: *[pin_field_len]u8) Error!void {
    if (pin.len < min_pin_len) return error.PinTooShort;
    if (pin.len > pin_field_len) return error.PinTooLongForField;
    for (pin) |c| {
        if (c == pad_byte) return error.PinHoldsPad;
    }
    @memset(out, pad_byte);
    @memcpy(out[0..pin.len], pin);
}

pub fn verifyPinCommand(padded: *const [pin_field_len]u8) apdu.Command {
    return .{ .cla = cla, .ins = 0x20, .p1 = 0x00, .p2 = 0x80, .data = padded };
}

pub fn pinRetriesCommand() apdu.Command {
    return .{ .cla = cla, .ins = 0x20, .p1 = 0x00, .p2 = 0x80 };
}

pub const Tries = union(enum) {
    left: u4,
    blocked,
    verified,
    unknown,

    pub fn count(self: Tries) ?u4 {
        return switch (self) {
            .left => |n| n,
            .blocked => 0,
            .verified, .unknown => null,
        };
    }
};

pub const PinOutcome = union(enum) {
    accepted,
    wrong: u4,
    blocked,
};

pub fn verifyPin(card: iface.Card, pin: []const u8, out: []u8) CardError!PinOutcome {
    var padded: [pin_field_len]u8 = undefined;
    try padPin(pin, &padded);
    // The padded PIN leaves this frame right after the call, rather than at the end of the function, so it never sits on the stack after it returns.
    defer std.crypto.secureZero(u8, &padded);

    const answer = try card.exchange(verifyPinCommand(&padded), out);
    if (answer.status.ok()) return .accepted;
    if (answer.status.blocked()) return .blocked;
    if (answer.status.pinRetriesLeft()) |left| return .{ .wrong = left };
    return error.CardRefused;
}

pub fn pinRetries(card: iface.Card, out: []u8) CardError!Tries {
    const answer = try card.exchange(pinRetriesCommand(), out);
    // The blocked status is checked first: a card with no tries left answers 63 C0, which also looks like a count, and reading it as one would offer a prompt for a card that has nothing left to give.
    if (answer.status.blocked()) return .blocked;
    if (answer.status.pinRetriesLeft()) |left| return .{ .left = left };
    if (answer.status.ok()) return .verified;
    return .unknown;
}

pub fn metadataCommand(slot: Slot) apdu.Command {
    return .{
        .cla = cla,
        .ins = 0xf7,
        .p1 = 0x00,
        .p2 = @intFromEnum(slot),
        .expect = apdu.max_response_data,
    };
}

pub const Metadata = struct {
    algorithm: Algorithm,
    pin_policy: PinPolicy = .default,
    touch_policy: TouchPolicy = .default,
    key: []const u8,

    pub fn pinPolicy(self: Metadata, slot: Slot) PinPolicy {
        if (self.pin_policy == .default) return slot.defaultPinPolicy();
        return self.pin_policy;
    }
};

const metadata_algorithm_tag: tlv.Tag = 0x01;
const metadata_policy_tag: tlv.Tag = 0x02;
const metadata_public_tag: tlv.Tag = 0x04;
const ec_point_tag: tlv.Tag = 0x86;

pub const MetadataError = error{
    MetadataUnsupported,
};

pub fn readMetadata(
    card: iface.Card,
    slot: Slot,
    out: []u8,
) (CardError || MetadataError)!Metadata {
    const answer = try card.exchange(metadataCommand(slot), out);
    if (answer.status.notFound()) return error.ObjectAbsent;
    const status = answer.status.value();
    if (status == 0x6d00 or status == 0x6a81) return error.MetadataUnsupported;
    if (!answer.status.ok()) return error.CardRefused;
    return parseMetadata(answer.data);
}

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

pub fn parseCertificateObject(object: []const u8) Error![]const u8 {
    var outer = tlv.Reader.init(object);
    const container = (outer.find(0x53) catch return error.Malformed) orelse return error.Malformed;

    var inner = tlv.Reader.init(container);
    const certificate = (inner.find(0x70) catch return error.Malformed) orelse return error.Malformed;
    if (certificate.len == 0) return error.Malformed;

    var again = tlv.Reader.init(container);
    if ((again.find(0x71) catch return error.Malformed)) |info| {
        if (info.len != 1) return error.Malformed;
        const stored: CertInfo = @enumFromInt(@as(u3, @truncate(info[0])));
        if (stored != .uncompressed) return error.CertificateCompressed;
    }
    return certificate;
}

pub fn readCertificate(card: iface.Card, slot: Slot, out: []u8) CardError![]const u8 {
    const tag = slot.certificateTag() orelse return error.ObjectAbsent;
    var data: [5]u8 = undefined;
    const answer = try card.exchange(try getDataCommand(tag, &data), out);
    if (answer.status.notFound()) return error.ObjectAbsent;
    if (answer.status.securityNotSatisfied()) return error.NotAuthenticated;
    if (!answer.status.ok()) return error.CardRefused;
    return parseCertificateObject(answer.data);
}

const dynamic_authentication_tag: u8 = 0x7c;
const response_tag: u8 = 0x82;
const challenge_tag: u8 = 0x81;

pub const max_challenge_len = seal.rsa2048_modulus_len;

pub fn authenticateBodyLen(challenge_len: usize) usize {
    return 1 + lengthFieldLen(innerLen(challenge_len)) + innerLen(challenge_len);
}

fn innerLen(challenge_len: usize) usize {
    return 2 + 1 + lengthFieldLen(challenge_len) + challenge_len;
}

fn lengthFieldLen(value: usize) usize {
    if (value < 0x80) return 1;
    if (value <= 0xff) return 2;
    return 3;
}

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

pub const sha256_digest_info_prefix = [_]u8{
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
};

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

pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const max_authenticate_body = authenticateBodyLen(max_challenge_len);

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

pub fn attestCommand(slot: Slot) apdu.Command {
    return .{
        .cla = cla,
        .ins = 0xf9,
        .p1 = @intFromEnum(slot),
        .p2 = 0x00,
        .expect = apdu.max_response_data,
    };
}

pub fn attest(card: iface.Card, slot: Slot, out: []u8) CardError![]const u8 {
    const answer = try card.exchange(attestCommand(slot), out);
    if (!answer.status.ok()) return error.CardRefused;
    if (answer.data.len == 0) return error.Malformed;
    return answer.data;
}

pub const CardSigner = struct {
    card: iface.Card,
    slot: Slot,
    scratch: []u8,
    algorithm: Algorithm,
    key_bytes: [seal.max_public_key_len]u8 = undefined,
    key_len: usize = 0,
    pin_policy: PinPolicy,
    verify_unused: bool = false,
    asker: ?pin_prompt.Asker = null,
    reader: []const u8 = "",
    stopped: ?attempt.Outcome = null,
    stopped_bytes: ?usize = null,
    reason_bytes: [attempt.max_sentence_len]u8 = undefined,

    pub const InitError = CardError || MetadataError || attestation.KeyError;

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

    pub fn key(self: *const CardSigner) []const u8 {
        return self.key_bytes[0..self.key_len];
    }

    pub fn signer(self: *CardSigner) seal.Signer {
        return .{ .ptr = self, .vtable = &signer_vtable };
    }

    fn authorise(self: *CardSigner) seal.SignError!void {
        // A refusal ends the whole run, so a person who mistyped is not asked again by the next log or the one after it.
        if (self.stopped != null) return error.Unusable;

        const asker = self.asker orelse return self.refuse(.pin_required);

        const tries = pinRetries(self.card, self.scratch) catch Tries.unknown;
        if (tries == .blocked) return self.refuse(.pin_blocked);

        var buffer: pin_prompt.Buffer = undefined;
        defer pin_prompt.wipe(&buffer);

        const answer = asker.ask(.{
            .reader = self.reader,
            .slot = self.slot,
            .tries = tries,
        }, &buffer);
        if (attempt.Outcome.forAnswer(answer)) |refused| return self.refuse(refused);
        const value = answer.pin;

        const given = verifyPin(self.card, value, self.scratch) catch |err| {
            const refused = attempt.Outcome.forVerify(err);
            if (self.stopped == null and refused.countsBytes()) self.stopped_bytes = value.len;
            return self.refuse(refused);
        };
        switch (given) {
            .accepted => {},
            .wrong => return self.refuse(.pin_wrong),
            .blocked => return self.refuse(.pin_blocked),
        }
    }

    fn refuse(self: *CardSigner, reason: attempt.Outcome) seal.SignError {
        if (self.stopped == null) self.stopped = reason;
        return error.Unusable;
    }

    fn reasonFn(ptr: *anyopaque) ?[]const u8 {
        const self: *CardSigner = @ptrCast(@alignCast(ptr));
        const stopped = self.stopped orelse return null;
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
        if (self.pin_policy == .always) {
            if (self.verify_unused) {
                self.verify_unused = false;
            } else {
                try self.authorise();
            }
        }

        return self.sign(digest, out) catch |err| switch (err) {
            error.NotAuthenticated => {
                if (self.pin_policy == .always) return self.refuse(.pin_not_enough);
                try self.authorise();
                return self.sign(digest, out) catch self.refuse(.pin_not_enough);
            },
            error.NoCard, error.Removed => self.refuse(.no_card),
            error.KeyUnsupported => self.refuse(.key_unsupported),
            else => self.refuse(.card_refused),
        };
    }

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

    try padPin("12345678", &padded);
    try testing.expectEqualSlices(u8, "12345678", &padded);

    try padPin("yubico", &padded);
    try testing.expectEqualSlices(u8, &.{ 'y', 'u', 'b', 'i', 'c', 'o', 0xff, 0xff }, &padded);
    try padPin("pa55 w0r", &padded);
    try testing.expectEqualSlices(u8, "pa55 w0r", &padded);
    try padPin(&.{ 0xc3, 0xa9, '1', '2', '3', '4' }, &padded);
    try testing.expectEqualSlices(u8, &.{ 0xc3, 0xa9, '1', '2', '3', '4', 0xff, 0xff }, &padded);

    try testing.expectError(error.PinTooShort, padPin("12345", &padded));
    try testing.expectError(error.PinTooLongForField, padPin("123456789", &padded));
    try testing.expectError(error.PinTooShort, padPin("", &padded));
    try testing.expectError(error.PinHoldsPad, padPin(&.{ '1', '2', '3', '4', '5', 0xff }, &padded));
}

test "each of the three rules that refuse a PIN answers with an error of its own" {
    var padded: [pin_field_len]u8 = undefined;

    try testing.expectError(error.PinTooShort, padPin("12345", &padded));
    try padPin("123456", &padded);

    try padPin("12345678", &padded);
    try testing.expectError(error.PinTooLongForField, padPin("123456789", &padded));

    const sixty_four = [_]u8{'7'} ** 64;
    try testing.expectError(error.PinTooLongForField, padPin(&sixty_four, &padded));
    const sixty_five = [_]u8{'7'} ** 65;
    try testing.expectError(error.PinTooLongForField, padPin(&sixty_five, &padded));

    try testing.expectError(
        error.PinHoldsPad,
        padPin(&.{ '1', '2', '3', '4', '5', 0xff }, &padded),
    );

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

    const query = try pinRetriesCommand().encode(&buffer);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x20, 0x00, 0x80 }, query);
}

test "each slot names its own certificate object, and no two share a tag" {
    try testing.expectEqual(@as(?tlv.Tag, 0x5fc105), Slot.piv_authentication.certificateTag());
    try testing.expectEqual(@as(?tlv.Tag, 0x5fc10a), Slot.digital_signature.certificateTag());
    try testing.expectEqual(@as(?tlv.Tag, 0x5fc10b), Slot.key_management.certificateTag());
    try testing.expectEqual(@as(?tlv.Tag, 0x5fc101), Slot.card_authentication.certificateTag());
    try testing.expectEqual(@as(?tlv.Tag, 0x5fff01), Slot.attestation.certificateTag());
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
    var data: [5]u8 = undefined;
    const command = try getDataCommand(0x70, &data);
    try testing.expectEqualSlices(u8, &.{ 0x5c, 0x01, 0x70 }, command.data);

    var two: [5]u8 = undefined;
    const wide = try getDataCommand(0x7f61, &two);
    try testing.expectEqualSlices(u8, &.{ 0x5c, 0x02, 0x7f, 0x61 }, wide.data);
}

test "a certificate is pulled out of its container, and a compressed one is refused" {
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
    try testing.expectError(error.Malformed, parseCertificateObject(&.{ 0x53, 0x40, 0x70 }));
}

test "the GENERAL AUTHENTICATE body is the nested template SP 800-73-4 table 7 gives" {
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
    // The padding is the whole of the RSA signature: a block built wrong still verifies against nothing, but only months later against a real log. test/pcsc/verify.zig cross checks this block against std.crypto.Certificate.rsa, which builds the same block independently.
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash("chock", &digest, .{});

    var block: [seal.rsa2048_modulus_len]u8 = undefined;
    try pkcs1Sha256Into(&block, digest);

    try testing.expectEqual(@as(u8, 0x00), block[0]);
    try testing.expectEqual(@as(u8, 0x01), block[1]);
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

    var tiny: [40]u8 = undefined;
    try testing.expectError(error.Malformed, pkcs1Sha256Into(&tiny, digest));
}

test "an RSA signature request is one command with a two byte length, and it is chained" {
    var body: [max_authenticate_body]u8 = undefined;
    const block = [_]u8{0xab} ** seal.rsa2048_modulus_len;
    const command = try generalAuthenticateCommand(.digital_signature, .rsa2048, &block, &body);

    try testing.expectEqual(@as(u8, 0x87), command.ins);
    try testing.expectEqual(@as(u8, 0x07), command.p1);
    try testing.expectEqual(@as(u8, 0x9c), command.p2);
    try testing.expectEqual(@as(usize, 266), command.data.len);
    try testing.expectEqualSlices(u8, &.{ 0x7c, 0x82, 0x01, 0x06 }, command.data[0..4]);
    try testing.expectEqualSlices(u8, &.{ 0x82, 0x00 }, command.data[4..6]);
    try testing.expectEqualSlices(u8, &.{ 0x81, 0x82, 0x01, 0x00 }, command.data[6..10]);
    try testing.expectEqualSlices(u8, &block, command.data[10..]);
    try testing.expect(command.data.len > apdu.max_command_data);

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

    const point = [_]u8{0x04} ++ [_]u8{0x33} ** 64;
    const ec_answer = [_]u8{ 0x01, 0x01, 0x11 } ++
        [_]u8{ 0x02, 0x02, 0x02, 0x01 } ++
        [_]u8{ 0x04, 0x43, 0x86, 0x41 } ++ point;
    const ec = try parseMetadata(&ec_answer);
    try testing.expectEqual(Algorithm.ecc_p256, ec.algorithm);
    try testing.expectEqual(PinPolicy.once, ec.pin_policy);
    try testing.expectEqualSlices(u8, &point, ec.key);

    const p384 = [_]u8{ 0x01, 0x01, 0x14 } ++ [_]u8{ 0x04, 0x02, 0x86, 0x00 };
    const other = parseMetadata(&p384);
    try testing.expectError(error.KeyUnsupported, other);

    try testing.expectError(error.Malformed, parseMetadata(&.{ 0x01, 0x05, 0x07 }));
    try testing.expectError(error.Malformed, parseMetadata(&.{ 0x01, 0x01, 0x07 }));
}

test "the count of tries left is read without spending one, and zero is blocked" {
    var buffer: [8]u8 = undefined;
    const query = try pinRetriesCommand().encode(&buffer);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x20, 0x00, 0x80 }, query);

    var three = iface.Recorded{ .exchanges = &.{
        .{ .send = query, .receive = &.{ 0x63, 0xc3 } },
    } };
    const transport = three.pcsc();
    try transport.establish();
    var out: [64]u8 = undefined;
    const card = try transport.connect(three.reader_name);
    try testing.expectEqual(@as(?u4, 3), (try pinRetries(card, &out)).count());

    var none = iface.Recorded{ .exchanges = &.{
        .{ .send = query, .receive = &.{ 0x63, 0xc0 } },
    } };
    const second = none.pcsc();
    try second.establish();
    const blocked_card = try second.connect(none.reader_name);
    try testing.expectEqual(Tries.blocked, try pinRetries(blocked_card, &out));

    var quiet = iface.Recorded{ .exchanges = &.{
        .{ .send = query, .receive = &.{ 0x6a, 0x86 } },
    } };
    const third = quiet.pcsc();
    try third.establish();
    const quiet_card = try third.connect(quiet.reader_name);
    try testing.expectEqual(Tries.unknown, try pinRetries(quiet_card, &out));
}
