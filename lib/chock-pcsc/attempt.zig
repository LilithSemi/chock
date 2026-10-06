//! Reach for a card key and answer what was found.

const std = @import("std");
const iface = @import("../chock-pcsc.zig");
const piv = @import("piv.zig");
const pin = @import("pin.zig");
const seal = @import("seal.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const seal_slot: piv.Slot = .digital_signature;

pub const probe_domain = "chock-seal-probe-v1\x00";

pub const max_reader_name = 128;

pub const reader_list_bytes = 4096;

pub const max_sentence_len = 512;

const counted_too_short =
    "{d} bytes were typed and a PIV PIN is six to eight bytes, " ++
    "so the card was never asked and no try was spent";

const uncounted_too_short =
    "fewer bytes were typed than the six a PIV PIN is at least, " ++
    "so the card was never asked and no try was spent";

const counted_too_long_for_card =
    "{d} bytes were typed and a PIV PIN is six to eight bytes, " ++
    "so the card was never asked and no try was spent. " ++
    "Bytes are not characters: a character outside plain ASCII takes more than one byte, " ++
    "so a PIN of eight characters can be longer than eight bytes. " ++
    "A card can also hold more than one PIN, and only the PIV one signs here, " ++
    "so an answer this long is one of the others";

const uncounted_too_long_for_card =
    "more bytes were typed than the eight a PIV PIN is at most, " ++
    "so the card was never asked and no try was spent. " ++
    "Bytes are not characters: a character outside plain ASCII takes more than one byte, " ++
    "so a PIN of eight characters can be longer than eight bytes. " ++
    "A card can also hold more than one PIN, and only the PIV one signs here, " ++
    "so an answer this long is one of the others";

pub const Outcome = enum {
    ready,
    not_tried,
    no_transport,
    no_daemon,
    not_authorized,
    protocol_mismatch,
    no_reader,
    no_card,
    no_piv,
    no_key,
    no_certificate,
    key_unreadable,
    key_unsupported,
    pin_required,
    pin_nobody,
    pin_declined,
    pin_too_long,
    pin_unreadable,
    pin_too_short,
    pin_too_long_for_card,
    pin_holds_pad,
    pin_wrong,
    pin_blocked,
    pin_not_enough,
    card_refused,

    pub fn sentence(self: Outcome) []const u8 {
        return switch (self) {
            .ready => "a card in a reader on this machine signed",
            .not_tried => "nothing on this run asked for a card",
            .no_transport =>
            \\this build has no PC/SC transport for this platform, so no daemon was asked and no card was looked for
            ,
            .no_daemon => "no PC/SC daemon answered on this machine, so no reader could be asked",
            .not_authorized =>
            \\a PC/SC daemon answered and refused this client, so it named no reader
            ,
            .protocol_mismatch =>
            \\a PC/SC daemon answered and speaks a protocol this build does not, so it named no reader
            ,
            .no_reader => "a PC/SC daemon answered and no reader is attached",
            .no_card => "a reader is attached and holds no card",
            .no_piv => "a card is in the reader and it has no PIV application",
            .no_key => "a PIV card is in the reader and it says its signature slot holds no key",
            .no_certificate =>
            \\a PIV card is in the reader, its signature slot holds no certificate, and the card has no command that says whether a key is in there
            ,
            .key_unreadable =>
            \\the certificate in the card's signature slot holds no key this can read
            ,
            .key_unsupported =>
            \\a PIV card's signature slot holds a key of an algorithm this build cannot sign with
            ,
            .pin_required =>
            \\a PIV card holds the key and wants a PIN before it signs, and this run had nobody to ask
            ,
            .pin_nobody =>
            \\a PIV card holds the key and wants a PIN, and nobody is at a keyboard on this run to give one
            ,
            .pin_declined => "a PIV card wanted a PIN before it would sign and none was given",
            .pin_too_long => std.fmt.comptimePrint(
                "more than {d} bytes were typed and a card PIN is eight at most, " ++
                    "so the card was never asked and no try was spent",
                .{pin.max_pin_bytes},
            ),
            .pin_unreadable =>
            \\the answer could not be read off the terminal, so the card was never asked and no try was spent
            ,
            .pin_too_short => uncounted_too_short,
            .pin_too_long_for_card => uncounted_too_long_for_card,
            .pin_holds_pad =>
            \\what was typed holds the byte FF, which is the pad that fills the rest of the eight byte field, so a card reads 1234567 and 1234567 FF as one PIN and would be asked about a PIN that is not the one typed, and the card was never asked and no try was spent
            ,
            .pin_wrong =>
            \\the PIN given was wrong, so one try is gone; nothing here tries again, because the card blocks after the last one
            ,
            .pin_blocked =>
            \\this card's PIN is blocked and only the PUK unblocks it; no try was spent finding that out
            ,
            .pin_not_enough =>
            \\the card took the PIN and refused to sign anyway, so the PIN is not what stopped it and nothing here asked again
            ,
            .card_refused => "a PIV card refused the signature and gave no reason to act on",
        };
    }

    pub fn countsBytes(self: Outcome) bool {
        return switch (self) {
            .pin_too_short, .pin_too_long_for_card => true,
            .ready,
            .not_tried,
            .no_transport,
            .no_daemon,
            .not_authorized,
            .protocol_mismatch,
            .no_reader,
            .no_card,
            .no_piv,
            .no_key,
            .no_certificate,
            .key_unreadable,
            .key_unsupported,
            .pin_required,
            .pin_nobody,
            .pin_declined,
            .pin_too_long,
            .pin_unreadable,
            .pin_holds_pad,
            .pin_wrong,
            .pin_blocked,
            .pin_not_enough,
            .card_refused,
            => false,
        };
    }

    pub fn sentenceWith(self: Outcome, typed_bytes: ?usize, out: []u8) []const u8 {
        if (!self.countsBytes()) return self.sentence();
        const bytes = typed_bytes orelse return self.sentence();
        // A buffer too small for the counted sentence falls back to the plain one. The comptime block below makes that unreachable for a caller that gives max_sentence_len bytes.
        return switch (self) {
            .pin_too_short => std.fmt.bufPrint(out, counted_too_short, .{bytes}) catch
                self.sentence(),
            .pin_too_long_for_card => std.fmt.bufPrint(out, counted_too_long_for_card, .{bytes}) catch
                self.sentence(),
            else => self.sentence(),
        };
    }

    pub fn forAnswer(answer: pin.Answer) ?Outcome {
        return switch (answer) {
            // No bytes means the person pressed Enter to decline signing with the software key, and must not read as a malformed PIN.
            .pin => |typed| if (typed.len == 0) .pin_declined else null,
            .nobody => .pin_nobody,
            .declined => .pin_declined,
            .too_long => .pin_too_long,
            .unreadable => .pin_unreadable,
        };
    }

    pub fn forVerify(err: piv.CardError) Outcome {
        return switch (err) {
            error.PinTooShort => .pin_too_short,
            error.PinTooLongForField => .pin_too_long_for_card,
            error.PinHoldsPad => .pin_holds_pad,
            error.NoCard, error.Removed => .no_card,
            else => .card_refused,
        };
    }

    pub fn fromPin(self: Outcome) bool {
        return switch (self) {
            .pin_required,
            .pin_nobody,
            .pin_declined,
            .pin_too_long,
            .pin_unreadable,
            .pin_too_short,
            .pin_too_long_for_card,
            .pin_holds_pad,
            .pin_wrong,
            .pin_blocked,
            .pin_not_enough,
            => true,
            .ready,
            .not_tried,
            .no_transport,
            .no_daemon,
            .not_authorized,
            .protocol_mismatch,
            .no_reader,
            .no_card,
            .no_piv,
            .no_key,
            .no_certificate,
            .key_unreadable,
            .key_unsupported,
            .card_refused,
            => false,
        };
    }

    pub fn pinAttemptFailed(self: Outcome) bool {
        return switch (self) {
            .pin_too_long,
            .pin_unreadable,
            .pin_too_short,
            .pin_too_long_for_card,
            .pin_holds_pad,
            .pin_wrong,
            .pin_not_enough,
            => true,
            .ready,
            .not_tried,
            .no_transport,
            .no_daemon,
            .not_authorized,
            .protocol_mismatch,
            .no_reader,
            .no_card,
            .no_piv,
            .no_key,
            .no_certificate,
            .key_unreadable,
            .key_unsupported,
            .pin_required,
            .pin_nobody,
            .pin_declined,
            .pin_blocked,
            .card_refused,
            => false,
        };
    }

    pub fn fromTransport(self: Outcome) bool {
        return switch (self) {
            .no_transport, .no_daemon, .not_authorized, .protocol_mismatch => true,
            .ready,
            .not_tried,
            .no_reader,
            .no_card,
            .no_piv,
            .no_key,
            .no_certificate,
            .key_unreadable,
            .key_unsupported,
            .pin_required,
            .pin_nobody,
            .pin_declined,
            .pin_too_long,
            .pin_unreadable,
            .pin_too_short,
            .pin_too_long_for_card,
            .pin_holds_pad,
            .pin_wrong,
            .pin_blocked,
            .pin_not_enough,
            .card_refused,
            => false,
        };
    }
};

pub const Attempt = struct {
    transport: iface.Pcsc,
    scratch: []u8,
    outcome: Outcome = .not_tried,
    card: ?iface.Card = null,
    card_signer: ?piv.CardSigner = null,
    reader_bytes: [max_reader_name]u8 = undefined,
    reader_len: usize = 0,
    asker: ?pin.Asker = null,
    tries: ?piv.Tries = null,
    metadata: ?piv.Metadata = null,
    pin_given: bool = false,
    pin_bytes: ?usize = null,

    pub fn init(transport: iface.Pcsc, scratch: []u8) Attempt {
        return .{ .transport = transport, .scratch = scratch };
    }

    pub fn open(self: *Attempt) Outcome {
        self.transport.establish() catch |err| return self.finish(switch (err) {
            error.Unavailable => .no_transport,
            error.NotAuthorized => .not_authorized,
            error.ProtocolMismatch => .protocol_mismatch,
            else => .no_daemon,
        });

        var names: [reader_list_bytes]u8 = undefined;
        const written = self.transport.listReaders(&names) catch
            return self.finish(.no_daemon);

        var list = iface.ReaderList.init(names[0..written]);
        var found: Outcome = .no_reader;
        while (list.next()) |name| {
            const one = self.tryReader(name);
            if (one == .ready) return self.finish(.ready);
            if (found == .no_reader or found == .no_card) found = one;
        }
        return self.finish(found);
    }

    pub fn signer(self: *Attempt) ?seal.Signer {
        if (self.outcome != .ready) return null;
        if (self.card_signer) |*held| return held.signer();
        return null;
    }

    pub fn level(self: *const Attempt) ?seal.Level {
        return if (self.outcome == .ready) .card else null;
    }

    pub fn reader(self: *const Attempt) []const u8 {
        return self.reader_bytes[0..self.reader_len];
    }

    pub fn stopped(self: *const Attempt) ?Outcome {
        const held = self.card_signer orelse return null;
        return held.stopped;
    }

    pub fn deinit(self: *Attempt) void {
        if (self.card) |held| held.disconnect();
        self.card = null;
        self.card_signer = null;
        self.outcome = .not_tried;
        self.reader_len = 0;
    }

    fn finish(self: *Attempt, outcome: Outcome) Outcome {
        self.outcome = outcome;
        if (outcome != .ready) {
            self.reader_len = 0;
        }
        return outcome;
    }

    fn tryReader(self: *Attempt, name: []const u8) Outcome {
        const card = self.transport.connect(name) catch |err| return switch (err) {
            error.NoCard => .no_card,
            error.Removed => .no_card,
            error.NoReader => .no_reader,
            else => .card_refused,
        };
        self.card = card;

        piv.select(card, self.scratch) catch |err| return self.closing(switch (err) {
            error.ObjectAbsent => .no_piv,
            error.NoCard, error.Removed => .no_card,
            else => .card_refused,
        });

        if (name.len <= self.reader_bytes.len) {
            @memcpy(self.reader_bytes[0..name.len], name);
            self.reader_len = name.len;
        }

        if (self.openSigner(card)) |refused| return self.closing(refused);

        // A slot with the always policy is not probed: the probe would spend a prompt and a try that the signature right after would need again.
        if (self.card_signer.?.pin_policy == .always) {
            if (self.givePin(card)) |refused| return self.closing(refused);
            self.card_signer.?.verify_unused = true;
            return .ready;
        }

        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(probe_domain, &digest, .{});
        var signature: [seal.max_signature_len]u8 = undefined;
        _ = piv.signDigest(
            card,
            seal_slot,
            self.card_signer.?.algorithm,
            digest,
            self.scratch,
            &signature,
        ) catch |err| {
            const after: Outcome = switch (err) {
                // A slot already given the PIN is never asked again: whatever is refusing the signature here will not be fixed by spending another try.
                error.NotAuthenticated => pin: {
                    if (self.pin_given) break :pin .pin_not_enough;
                    if (self.givePin(card)) |refused| break :pin refused;
                    break :pin self.signAfterPin(card, digest, &signature);
                },
                error.KeyUnsupported => .key_unsupported,
                error.NoCard, error.Removed => .no_card,
                else => .card_refused,
            };
            if (after != .ready) return self.closing(after);
            return .ready;
        };

        return .ready;
    }

    fn openSigner(self: *Attempt, card: iface.Card) ?Outcome {
        const metadata = piv.readMetadata(card, seal_slot, self.scratch) catch |err| switch (err) {
            error.ObjectAbsent => return .no_key,
            error.MetadataUnsupported => return self.openFromCertificate(card),
            error.NotAuthenticated => return .pin_required,
            error.NoCard, error.Removed => return .no_card,
            else => return .card_refused,
        };
        self.metadata = metadata;

        if (!metadata.algorithm.usable()) return .key_unsupported;
        var made = piv.CardSigner.fromMetadata(card, seal_slot, self.scratch, metadata) catch
            return .key_unsupported;
        made.asker = self.asker;
        self.card_signer = made;
        self.card_signer.?.reader = self.reader();
        return null;
    }

    fn openFromCertificate(self: *Attempt, card: iface.Card) ?Outcome {
        var made = piv.CardSigner.init(card, seal_slot, self.scratch) catch |err| switch (err) {
            error.ObjectAbsent => return .no_certificate,
            error.NotAuthenticated => return .pin_required,
            error.CertificateUnreadable, error.KeyUnsupported => return .key_unreadable,
            error.CertificateCompressed, error.Malformed => return .key_unreadable,
            error.NoCard, error.Removed => return .no_card,
            else => return .card_refused,
        };
        made.asker = self.asker;
        self.card_signer = made;
        self.card_signer.?.reader = self.reader();
        return null;
    }

    fn givePin(self: *Attempt, card: iface.Card) ?Outcome {
        const asker = self.asker orelse return .pin_required;

        const tries = piv.pinRetries(card, self.scratch) catch piv.Tries.unknown;
        self.tries = tries;
        if (tries == .blocked) return .pin_blocked;

        var buffer: pin.Buffer = undefined;
        defer pin.wipe(&buffer);

        const answer = asker.ask(.{
            .reader = self.reader(),
            .slot = seal_slot,
            .tries = tries,
        }, &buffer);
        if (Outcome.forAnswer(answer)) |refused| return refused;
        const value = answer.pin;

        const given = piv.verifyPin(card, value, self.scratch) catch |err| {
            const refused = Outcome.forVerify(err);
            // pin_bytes is set only for refusals a length caused: a count beside pin_holds_pad would read as the cause, and the pad byte is refused at any length.
            if (refused.countsBytes()) self.pin_bytes = value.len;
            return refused;
        };
        switch (given) {
            .accepted => {
                self.pin_given = true;
                return null;
            },
            .wrong => |left| {
                self.tries = .{ .left = left };
                return .pin_wrong;
            },
            .blocked => {
                self.tries = .blocked;
                return .pin_blocked;
            },
        }
    }

    fn signAfterPin(
        self: *Attempt,
        card: iface.Card,
        digest: [Sha256.digest_length]u8,
        signature: *[seal.max_signature_len]u8,
    ) Outcome {
        _ = piv.signDigest(
            card,
            seal_slot,
            self.card_signer.?.algorithm,
            digest,
            self.scratch,
            signature,
        ) catch |err| return switch (err) {
            error.NotAuthenticated => .pin_required,
            error.KeyUnsupported => .key_unsupported,
            error.NoCard, error.Removed => .no_card,
            else => .card_refused,
        };
        return .ready;
    }

    fn closing(self: *Attempt, outcome: Outcome) Outcome {
        self.close();
        return outcome;
    }

    fn close(self: *Attempt) void {
        if (self.card) |held| held.disconnect();
        self.card = null;
        self.card_signer = null;
    }
};

// A PIN lives in one stack frame only: givePin and CardSigner.authorise read it into a buffer of their own and wipe it before the call ends, never a struct field. This block fails the build if a field could hold one, the same guard chock-broker/askpass.zig keeps over its own endpoint.
comptime {
    for (std.enums.values(Outcome)) |one| {
        if (one.sentence().len > max_sentence_len) {
            @compileError("this outcome's sentence is longer than max_sentence_len: " ++ @tagName(one));
        }
    }
    const widest = std.math.maxInt(usize);
    for ([_][]const u8{
        std.fmt.comptimePrint(counted_too_short, .{widest}),
        std.fmt.comptimePrint(counted_too_long_for_card, .{widest}),
    }) |filled| {
        if (filled.len > max_sentence_len) {
            @compileError("a counted sentence is longer than max_sentence_len");
        }
    }
}

comptime {
    for ([_]type{ Attempt, piv.CardSigner }) |held| {
        for (@typeInfo(held).@"struct".fields) |field| {
            if (field.type == pin.Buffer or field.type == pin.Answer) {
                @compileError("nothing that outlives one call may hold a PIN: " ++ field.name);
            }
        }
    }
}

const testing = std.testing;

const select_command = [_]u8{ 0x00, 0xa4, 0x04, 0x00, 0x0b } ++ piv.aid ++ [_]u8{0x00};
const select_answer = [_]u8{ 0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x90, 0x00 };
const get_certificate = [_]u8{ 0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x0a, 0x00 };
const get_metadata = [_]u8{ 0x00, 0xf7, 0x00, 0x9c, 0x00 };
const no_metadata = [_]u8{ 0x6d, 0x00 };

test "a daemon that is not there is not a card that is not there" {
    var scratch: [piv.max_object_len]u8 = undefined;
    var refusing = Refusing{ .err = error.NoService };
    var attempt = Attempt.init(refusing.pcsc(), &scratch);
    try testing.expectEqual(Outcome.no_daemon, attempt.open());

    refusing.err = error.NotAuthorized;
    var second = Attempt.init(refusing.pcsc(), &scratch);
    try testing.expectEqual(Outcome.not_authorized, second.open());

    refusing.err = error.ProtocolMismatch;
    var third = Attempt.init(refusing.pcsc(), &scratch);
    try testing.expectEqual(Outcome.protocol_mismatch, third.open());

    refusing.err = error.Unavailable;
    var fourth = Attempt.init(refusing.pcsc(), &scratch);
    try testing.expectEqual(Outcome.no_transport, fourth.open());
}

test "a daemon with no reader is its own answer, and no signer comes of it" {
    var empty = iface.Recorded{ .exchanges = &.{}, .reader_name = "" };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(empty.pcsc(), &scratch);
    defer attempt.deinit();

    try testing.expectEqual(Outcome.no_reader, attempt.open());
    try testing.expectEqual(@as(?seal.Signer, null), attempt.signer());
    try testing.expectEqual(@as(?seal.Level, null), attempt.level());
    try testing.expectEqualStrings("", attempt.reader());
}

test "a card with no PIV application is not a card with an empty slot" {
    var no_piv = iface.Recorded{ .exchanges = &.{
        .{ .send = &select_command, .receive = &.{ 0x6a, 0x82 } },
    } };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(no_piv.pcsc(), &scratch);
    defer attempt.deinit();

    try testing.expectEqual(Outcome.no_piv, attempt.open());
    try testing.expect(no_piv.drained());
    try testing.expectEqual(@as(?seal.Signer, null), attempt.signer());
}

test "a PIV card whose signature slot is empty answers no_key and signs nothing" {
    var no_key = iface.Recorded{ .exchanges = &.{
        .{ .send = &select_command, .receive = &select_answer },
        .{ .send = &get_metadata, .receive = &.{ 0x6a, 0x82 } },
    } };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(no_key.pcsc(), &scratch);
    defer attempt.deinit();

    try testing.expectEqual(Outcome.no_key, attempt.open());
    try testing.expect(no_key.drained());
    try testing.expectEqual(@as(?seal.Signer, null), attempt.signer());
    try testing.expectEqual(@as(?seal.Level, null), attempt.level());
}

test "a card that cannot say whether a key is there never claims the slot is empty" {
    var quiet = iface.Recorded{ .exchanges = &.{
        .{ .send = &select_command, .receive = &select_answer },
        .{ .send = &get_metadata, .receive = &no_metadata },
        .{ .send = &get_certificate, .receive = &.{ 0x6a, 0x82 } },
    } };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(quiet.pcsc(), &scratch);
    defer attempt.deinit();

    try testing.expectEqual(Outcome.no_certificate, attempt.open());
    try testing.expect(quiet.drained());
    const text = Outcome.no_certificate.sentence();
    try testing.expect(std.mem.indexOf(u8, text, "no certificate") != null);
    try testing.expect(std.mem.indexOf(u8, text, "holds no key") == null);
}

test "a slot that refuses to be read without a PIN is named as a PIN, not as an empty slot" {
    var locked = iface.Recorded{ .exchanges = &.{
        .{ .send = &select_command, .receive = &select_answer },
        .{ .send = &get_metadata, .receive = &no_metadata },
        .{ .send = &get_certificate, .receive = &.{ 0x69, 0x82 } },
    } };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(locked.pcsc(), &scratch);
    defer attempt.deinit();

    try testing.expectEqual(Outcome.pin_required, attempt.open());
    try testing.expect(locked.drained());
}

test "an outcome that is not ready yields no signer, even with a card signer in hand" {
    var recorded = iface.Recorded{ .exchanges = &.{} };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(recorded.pcsc(), &scratch);
    attempt.card_signer = .{
        .card = .{ .pcsc = recorded.pcsc(), .handle = .{ .value = 1, .protocol = .t1 } },
        .slot = seal_slot,
        .scratch = &scratch,
        .algorithm = .ecc_p256,
        .pin_policy = .never,
        .key_bytes = ([_]u8{0x04} ++ [_]u8{0x11} ** 64) ++ [_]u8{0} ** (seal.max_public_key_len - 65),
        .key_len = 65,
    };

    inline for (@typeInfo(Outcome).@"enum".fields) |field| {
        const outcome: Outcome = @enumFromInt(field.value);
        if (outcome != .ready) {
            attempt.outcome = outcome;
            try testing.expectEqual(@as(?seal.Signer, null), attempt.signer());
            try testing.expectEqual(@as(?seal.Level, null), attempt.level());
        }
    }

    attempt.outcome = .ready;
    try testing.expect(attempt.signer() != null);
    try testing.expectEqual(@as(?seal.Level, .card), attempt.level());
}

test "every outcome has its own sentence, and none of them says what this build links" {
    var seen: [@typeInfo(Outcome).@"enum".fields.len][]const u8 = undefined;
    inline for (@typeInfo(Outcome).@"enum".fields, 0..) |field, i| {
        const text = (@as(Outcome, @enumFromInt(field.value))).sentence();
        try testing.expect(text.len != 0);
        for (seen[0..i]) |earlier| try testing.expect(!std.mem.eql(u8, earlier, text));
        seen[i] = text;
        try testing.expect(std.mem.indexOf(u8, text, "links") == null);
    }
}

test "only a transport outcome carries a driver's own failure" {
    try testing.expect(Outcome.no_daemon.fromTransport());
    try testing.expect(Outcome.not_authorized.fromTransport());
    try testing.expect(Outcome.protocol_mismatch.fromTransport());
    try testing.expect(Outcome.no_transport.fromTransport());
    try testing.expect(!Outcome.no_key.fromTransport());
    try testing.expect(!Outcome.no_card.fromTransport());
    try testing.expect(!Outcome.ready.fromTransport());
}

const Refusing = struct {
    err: iface.Error,

    fn pcsc(self: *Refusing) iface.Pcsc {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn establishFn(ptr: *anyopaque) iface.Error!void {
        const self: *Refusing = @ptrCast(@alignCast(ptr));
        return self.err;
    }

    fn listReadersFn(ptr: *anyopaque, out: []u8) iface.Error!usize {
        const self: *Refusing = @ptrCast(@alignCast(ptr));
        _ = out;
        return self.err;
    }

    fn connectFn(ptr: *anyopaque, name: []const u8) iface.Error!iface.Handle {
        const self: *Refusing = @ptrCast(@alignCast(ptr));
        _ = name;
        return self.err;
    }

    fn transmitFn(
        ptr: *anyopaque,
        handle: iface.Handle,
        send: []const u8,
        receive: []u8,
    ) iface.Error!usize {
        const self: *Refusing = @ptrCast(@alignCast(ptr));
        _ = handle;
        _ = send;
        _ = receive;
        return self.err;
    }

    fn disconnectFn(ptr: *anyopaque, handle: iface.Handle) void {
        _ = ptr;
        _ = handle;
    }

    const vtable = iface.Pcsc.VTable{
        .establish = establishFn,
        .listReaders = listReadersFn,
        .connect = connectFn,
        .transmit = transmitFn,
        .disconnect = disconnectFn,
    };
};

test {
    testing.refAllDecls(@This());
}

const CountingPin = struct {
    asked: usize = 0,
    tries: piv.Tries = .unknown,
    value: []const u8 = "123456",
    instead: ?pin.Answer = null,

    fn asker(self: *CountingPin) pin.Asker {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = pin.Asker.VTable{ .ask = askFn };

    fn askFn(ptr: *anyopaque, question: pin.Question, out: *pin.Buffer) pin.Answer {
        const self: *CountingPin = @ptrCast(@alignCast(ptr));
        self.asked += 1;
        self.tries = question.tries;
        if (self.instead) |answer| return answer;
        @memcpy(out[0..self.value.len], self.value);
        return .{ .pin = out[0..self.value.len] };
    }
};

const ec_point = [_]u8{0x04} ++ [_]u8{0x33} ** 64;
const ec_metadata = [_]u8{ 0x01, 0x01, 0x11 } ++
    [_]u8{ 0x02, 0x02, 0x03, 0x01 } ++
    [_]u8{ 0x04, 0x43, 0x86, 0x41 } ++ ec_point ++ [_]u8{ 0x90, 0x00 };
const ec_metadata_once = [_]u8{ 0x01, 0x01, 0x11 } ++
    [_]u8{ 0x02, 0x02, 0x02, 0x01 } ++
    [_]u8{ 0x04, 0x43, 0x86, 0x41 } ++ ec_point ++ [_]u8{ 0x90, 0x00 };
const ec_metadata_never = [_]u8{ 0x01, 0x01, 0x11 } ++
    [_]u8{ 0x02, 0x02, 0x01, 0x01 } ++
    [_]u8{ 0x04, 0x43, 0x86, 0x41 } ++ ec_point ++ [_]u8{ 0x90, 0x00 };
const pin_retries_command = [_]u8{ 0x00, 0x20, 0x00, 0x80 };
const verify_command = [_]u8{ 0x00, 0x20, 0x00, 0x80, 0x08, '1', '2', '3', '4', '5', '6', 0xff, 0xff };
const verify_letters_command = [_]u8{ 0x00, 0x20, 0x00, 0x80, 0x08, 'y', 'u', 'b', 'i', 'c', 'o', 0xff, 0xff };

const probe_digest = built: {
    @setEvalBranchQuota(4000);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(probe_domain, &digest, .{});
    break :built digest;
};

const sign_command = built: {
    @setEvalBranchQuota(4000);
    var body: [piv.max_authenticate_body]u8 = undefined;
    const command = piv.generalAuthenticateCommand(
        seal_slot,
        .ecc_p256,
        &probe_digest,
        &body,
    ) catch unreachable;
    var encoded: [64]u8 = undefined;
    const bytes = command.encode(&encoded) catch unreachable;
    break :built encoded[0..bytes.len].*;
};

const ec_signature_der = [_]u8{ 0x30, 0x44, 0x02, 0x20 } ++ [_]u8{0x33} ** 32 ++
    [_]u8{ 0x02, 0x20 } ++ [_]u8{0x33} ** 32;
const ec_signature_answer = [_]u8{ 0x7c, 0x48, 0x82, 0x46 } ++ ec_signature_der ++
    [_]u8{ 0x90, 0x00 };

fn signOnce(made: seal.Signer) seal.SignError!usize {
    var out: [seal.max_signature_len]u8 = undefined;
    const bytes = try made.vtable.signDigest(made.ptr, probe_digest, &out);
    return bytes.len;
}

test "a card that refuses after taking the PIN is not asked for a second one" {
    var counting = CountingPin{};
    var stubborn = iface.Recorded{
        .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata },
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
            .{ .send = &verify_command, .receive = &.{ 0x90, 0x00 } },
            .{ .send = &sign_command, .receive = &.{ 0x69, 0x82 } },
        },
    };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(stubborn.pcsc(), &scratch);
    defer attempt.deinit();
    attempt.asker = counting.asker();

    try testing.expectEqual(Outcome.ready, attempt.open());
    try testing.expectEqual(@as(usize, 1), counting.asked);

    const made = attempt.signer().?;
    try testing.expectError(error.Unusable, signOnce(made));
    try testing.expect(stubborn.drained());
    try testing.expectEqual(@as(usize, 1), counting.asked);
    try testing.expectEqual(@as(?Outcome, .pin_not_enough), attempt.stopped());
    try testing.expectEqualStrings(Outcome.pin_not_enough.sentence(), made.reason().?);
}

test "a slot that wants the PIN every time asks once for one seal" {
    var counting = CountingPin{};
    var card = iface.Recorded{
        .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata },
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
            .{ .send = &verify_command, .receive = &.{ 0x90, 0x00 } },
            .{ .send = &sign_command, .receive = &ec_signature_answer },
        },
    };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(card.pcsc(), &scratch);
    defer attempt.deinit();
    attempt.asker = counting.asker();

    try testing.expectEqual(Outcome.ready, attempt.open());
    try testing.expectEqual(@as(usize, 1), counting.asked);
    try testing.expectEqual(@as(?u4, 3), counting.tries.count());

    const made = signOnce(attempt.signer().?);
    try testing.expectEqual(@as(usize, 1), counting.asked);
    try testing.expectEqual(@as(usize, seal.signature_len), try made);
    try testing.expect(card.drained());
    try testing.expectEqual(@as(?Outcome, null), attempt.stopped());
}

test "a slot that wants the PIN every time asks again for every seal after the first" {
    var counting = CountingPin{};
    var card = iface.Recorded{
        .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata },
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
            .{ .send = &verify_command, .receive = &.{ 0x90, 0x00 } },
            .{ .send = &sign_command, .receive = &ec_signature_answer },
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
            .{ .send = &verify_command, .receive = &.{ 0x90, 0x00 } },
            .{ .send = &sign_command, .receive = &ec_signature_answer },
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
            .{ .send = &verify_command, .receive = &.{ 0x90, 0x00 } },
            .{ .send = &sign_command, .receive = &ec_signature_answer },
        },
    };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(card.pcsc(), &scratch);
    defer attempt.deinit();
    attempt.asker = counting.asker();

    try testing.expectEqual(Outcome.ready, attempt.open());
    const made = attempt.signer().?;
    var refused: usize = 0;
    for (0..3) |_| _ = signOnce(made) catch {
        refused += 1;
    };
    try testing.expectEqual(@as(usize, 3), counting.asked);
    try testing.expectEqual(@as(usize, 0), refused);
    try testing.expect(card.drained());
}

test "a slot that wants the PIN once is probed, and asks when the card says so" {
    var counting = CountingPin{};
    var card = iface.Recorded{
        .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata_once },
            .{ .send = &sign_command, .receive = &.{ 0x69, 0x82 } },
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
            .{ .send = &verify_command, .receive = &.{ 0x90, 0x00 } },
            .{ .send = &sign_command, .receive = &ec_signature_answer },
            .{ .send = &sign_command, .receive = &ec_signature_answer },
        },
    };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(card.pcsc(), &scratch);
    defer attempt.deinit();
    attempt.asker = counting.asker();

    try testing.expectEqual(Outcome.ready, attempt.open());
    try testing.expectEqual(@as(usize, 1), counting.asked);

    try testing.expectEqual(@as(usize, seal.signature_len), try signOnce(attempt.signer().?));
    try testing.expect(card.drained());
    try testing.expectEqual(@as(usize, 1), counting.asked);
}

test "a slot that wants no PIN asks nobody, and the probe is what proves it" {
    var counting = CountingPin{};
    var card = iface.Recorded{
        .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata_never },
            .{ .send = &sign_command, .receive = &ec_signature_answer },
            .{ .send = &sign_command, .receive = &ec_signature_answer },
        },
    };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(card.pcsc(), &scratch);
    defer attempt.deinit();
    attempt.asker = counting.asker();

    try testing.expectEqual(Outcome.ready, attempt.open());
    try testing.expectEqual(@as(usize, seal.signature_len), try signOnce(attempt.signer().?));
    try testing.expect(card.drained());
    try testing.expectEqual(@as(usize, 0), counting.asked);
}

test "a wrong PIN ends the run, and the count left is carried back to say so" {
    var counting = CountingPin{};
    var wrong = iface.Recorded{ .exchanges = &.{
        .{ .send = &select_command, .receive = &select_answer },
        .{ .send = &get_metadata, .receive = &ec_metadata },
        .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
        .{ .send = &verify_command, .receive = &.{ 0x63, 0xc2 } },
    } };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(wrong.pcsc(), &scratch);
    defer attempt.deinit();
    attempt.asker = counting.asker();

    try testing.expectEqual(Outcome.pin_wrong, attempt.open());
    try testing.expect(wrong.drained());
    try testing.expectEqual(@as(usize, 1), counting.asked);
    try testing.expectEqual(@as(?u4, 2), attempt.tries.?.count());
    try testing.expectEqual(@as(?u4, 3), counting.tries.count());
}

test "a blocked card is never given a PIN, and no try is spent finding out" {
    var counting = CountingPin{};
    var blocked = iface.Recorded{ .exchanges = &.{
        .{ .send = &select_command, .receive = &select_answer },
        .{ .send = &get_metadata, .receive = &ec_metadata },
        .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc0 } },
    } };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(blocked.pcsc(), &scratch);
    defer attempt.deinit();
    attempt.asker = counting.asker();

    try testing.expectEqual(Outcome.pin_blocked, attempt.open());
    try testing.expect(blocked.drained());
    try testing.expectEqual(@as(usize, 0), counting.asked);
}

test "a PIN no field can carry never reaches the card, and each rule keeps its own outcome" {
    const cases = [_]struct { value: []const u8, want: Outcome, bytes: ?usize }{
        .{ .value = "12345", .want = .pin_too_short, .bytes = 5 },
        .{ .value = "123456789", .want = .pin_too_long_for_card, .bytes = 9 },
        .{ .value = "fido2-pin-for-the-same-key", .want = .pin_too_long_for_card, .bytes = 26 },
        .{ .value = "é1234567", .want = .pin_too_long_for_card, .bytes = 9 },
        .{ .value = &.{ '1', '2', '3', '4', '5', 0xff }, .want = .pin_holds_pad, .bytes = null },
    };
    for (cases) |one| {
        var counting = CountingPin{ .value = one.value };
        var never_asked = iface.Recorded{ .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata },
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
        } };
        var scratch: [piv.max_object_len]u8 = undefined;
        var attempt = Attempt.init(never_asked.pcsc(), &scratch);
        defer attempt.deinit();
        attempt.asker = counting.asker();

        try testing.expectEqual(one.want, attempt.open());
        try testing.expect(never_asked.drained());
        try testing.expectEqual(@as(usize, 1), counting.asked);
        try testing.expectEqual(one.bytes, attempt.pin_bytes);
    }
}

test "a PIN that is not digits reaches the card, and the card is the one that decides" {
    var counting = CountingPin{ .value = "yubico" };
    var card = iface.Recorded{
        .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata },
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
            .{ .send = &verify_letters_command, .receive = &.{ 0x63, 0xc2 } },
        },
    };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(card.pcsc(), &scratch);
    defer attempt.deinit();
    attempt.asker = counting.asker();

    try testing.expectEqual(Outcome.pin_wrong, attempt.open());
    try testing.expect(card.drained());
    try testing.expectEqual(@as(usize, 1), counting.asked);
    try testing.expectEqual(@as(?u4, 2), attempt.tries.?.count());
}

test "an answer of no bytes is a person declining and never a malformed PIN" {
    var counting = CountingPin{ .value = "" };
    var never_asked = iface.Recorded{ .exchanges = &.{
        .{ .send = &select_command, .receive = &select_answer },
        .{ .send = &get_metadata, .receive = &ec_metadata },
        .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
    } };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(never_asked.pcsc(), &scratch);
    defer attempt.deinit();
    attempt.asker = counting.asker();

    try testing.expectEqual(Outcome.pin_declined, attempt.open());
    try testing.expect(never_asked.drained());
}

test "an answer that could not be read keeps its own outcome and is never a decline" {
    const cases = [_]struct { answer: pin.Answer, want: Outcome }{
        .{ .answer = .declined, .want = .pin_declined },
        .{ .answer = .too_long, .want = .pin_too_long },
        .{ .answer = .unreadable, .want = .pin_unreadable },
        .{ .answer = .nobody, .want = .pin_nobody },
    };
    for (cases) |one| {
        var counting = CountingPin{ .instead = one.answer };
        var never_asked = iface.Recorded{ .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata },
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
        } };
        var scratch: [piv.max_object_len]u8 = undefined;
        var attempt = Attempt.init(never_asked.pcsc(), &scratch);
        defer attempt.deinit();
        attempt.asker = counting.asker();

        try testing.expectEqual(one.want, attempt.open());
        try testing.expect(never_asked.drained());
        try testing.expectEqual(@as(usize, 1), counting.asked);
        try testing.expectEqual(@as(?seal.Signer, null), attempt.signer());
    }

    try testing.expect(std.mem.indexOf(u8, Outcome.pin_declined.sentence(), "none was given") != null);
    try testing.expect(std.mem.indexOf(u8, Outcome.pin_too_long.sentence(), "were typed") != null);
    try testing.expect(std.mem.indexOf(u8, Outcome.pin_too_long.sentence(), "none was given") == null);
    try testing.expect(std.mem.indexOf(u8, Outcome.pin_unreadable.sentence(), "could not be read") != null);
    try testing.expect(std.mem.indexOf(u8, Outcome.pin_unreadable.sentence(), "none was given") == null);
    for ([_]Outcome{ .pin_too_long, .pin_unreadable }) |one| {
        try testing.expect(std.mem.indexOf(u8, one.sentence(), "no try was spent") != null);
    }

    for (cases) |one| try testing.expectEqual(one.want, Outcome.forAnswer(one.answer).?);
    try testing.expectEqual(@as(?Outcome, null), Outcome.forAnswer(.{ .pin = "123456" }));
    try testing.expectEqual(@as(?Outcome, .pin_declined), Outcome.forAnswer(.{ .pin = "" }));
}

test "each PIN the card was never asked about reads as its own complaint" {
    const line_too_long = Outcome.pin_too_long.sentence();
    const too_short = Outcome.pin_too_short.sentence();
    const too_long_for_card = Outcome.pin_too_long_for_card.sentence();
    const holds_pad = Outcome.pin_holds_pad.sentence();

    try testing.expect(std.mem.indexOf(u8, holds_pad, "byte FF") != null);
    for ([_][]const u8{ line_too_long, too_short, too_long_for_card }) |one| {
        try testing.expect(std.mem.indexOf(u8, one, "FF") == null);
    }

    try testing.expect(std.mem.indexOf(u8, too_long_for_card, "Bytes are not characters") != null);
    try testing.expect(std.mem.indexOf(u8, too_long_for_card, "more than one PIN") != null);
    try testing.expect(std.mem.indexOf(u8, too_short, "Bytes are not characters") == null);

    const all = [_][]const u8{ line_too_long, too_short, too_long_for_card, holds_pad };
    for (all, 0..) |one, index| {
        for (all[index + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, one, other));
            try testing.expect(std.mem.indexOf(u8, one, other) == null);
            try testing.expect(std.mem.indexOf(u8, other, one) == null);
        }
        try testing.expect(std.mem.indexOf(u8, one, "no try was spent") != null);
    }
}

test "the two refusals a length caused say the number that was typed" {
    var room: [max_sentence_len]u8 = undefined;

    const twelve = Outcome.pin_too_long_for_card.sentenceWith(12, &room);
    try testing.expect(std.mem.startsWith(u8, twelve, "12 bytes were typed"));
    try testing.expect(std.mem.indexOf(u8, twelve, "six to eight bytes") != null);

    const five = Outcome.pin_too_short.sentenceWith(5, &room);
    try testing.expect(std.mem.startsWith(u8, five, "5 bytes were typed"));

    const no_count = Outcome.pin_too_long_for_card.sentenceWith(null, &room);
    try testing.expectEqualStrings(Outcome.pin_too_long_for_card.sentence(), no_count);

    try testing.expect(!Outcome.pin_holds_pad.countsBytes());
    try testing.expectEqualStrings(
        Outcome.pin_holds_pad.sentence(),
        Outcome.pin_holds_pad.sentenceWith(6, &room),
    );
    for (std.enums.values(Outcome)) |one| {
        if (one.countsBytes()) continue;
        try testing.expectEqualStrings(one.sentence(), one.sentenceWith(9, &room));
    }
}
