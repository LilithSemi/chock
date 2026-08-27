//! Reach for a card key, and say exactly what was found.
//!
//! Everything else in this module is one step of the card path: a transport, an
//! APDU, a PIV command, a signer over one slot. This is the step that joins
//! them and answers the one question a caller has before it signs anything:
//! **is there a card key here, and if not, what stopped it.**
//!
//! ## Why the answer is a value and not an error
//!
//! A caller that only learns "no card" writes one sentence for eleven different
//! machines. A daemon nobody is running, a daemon that refused this client, a
//! reader with an empty slot and a card with no key in the slot are four
//! different facts, and a person acts differently on each. So this answers an
//! `Outcome`, one member per fact, and the sentence for each sits beside it.
//!
//! **A fallback nobody can read is the same fault as a fallback nobody
//! records.** `seal.Level` keeps a downgrade out of the record; `Outcome` keeps
//! it out of the message. A person who reads "software" on a machine with a
//! reader plugged in has to be told which of the eleven happened.
//!
//! ## The probe signature
//!
//! `open` asks the card to sign one fixed digest before it answers `ready`.
//!
//! A PIV signature slot can hold a key and still refuse to use it: the slot's
//! PIN policy decides. Without the probe that refusal would arrive in the middle
//! of sealing, one log at a time, after the caller had already committed to the
//! card. With it, a card that will not sign is a fallback like any other and the
//! message says why.
//!
//! **A slot whose PIN policy is `always` is not probed.** That slot refuses a
//! signature that no `VERIFY` came directly before, so a probe there needs a
//! prompt of its own and then uses the unlock up. The seal signature that comes
//! moments later then asks a second time, and one seal cost a person two
//! prompts on a card that blocks after three wrong PINs. The early answer is
//! worth nothing there, because the real signature is the next thing that
//! happens and a card that refuses it seals nothing. So `open` unlocks that
//! slot, hands the unlock to the first signature through
//! `piv.CardSigner.verify_unused`, and lets the real signature be the proof.
//!
//! ## The PIN, and the counter that can destroy a key
//!
//! A stock signature slot wants the PIN before every use, so a card seal without
//! one is unreachable. `Attempt.asker` is who to ask, and `lib/chock-pcsc/pin.zig`
//! states the whole rule. The three parts that matter here:
//!
//! * **The count of tries left is read before anybody is asked**, and reading it
//!   spends none, so the question can say the number.
//! * **Nothing retries.** `givePin` has no loop and `pin_given` stops a second
//!   ask after the card takes a PIN and refuses anyway. Three wrong PINs block
//!   the card and then it needs the PUK.
//! * **Every refusal is final for the run** and becomes a fallback that says
//!   which refusal it was: nobody at a keyboard, a person who declined, a PIN of
//!   the wrong shape, a wrong PIN, or a blocked card are five different facts.
//!
//! ## What it never claims
//!
//! `open` answers a level 2 key and never a level 1 one. An attestation makes a
//! seal level 1 only for a reader that holds the vendor certificate authority to
//! chain it to, and this project ships none: `seal.read` with no root answers
//! `claim_unsupported` for a seal that claims one, which reads worse than the
//! honest level 2. See `attestation.zig`.

const std = @import("std");
const iface = @import("../chock-pcsc.zig");
const piv = @import("piv.zig");
const pin = @import("pin.zig");
const seal = @import("seal.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

/// The slot a seal is signed in.
///
/// **`9C`, the PIV digital signature key.** SP 800-73-4 part 1 table 4 gives
/// that slot to signatures over data, which is what a seal is, and `9A` to
/// authentication. A fixed slot rather than a search over all of them: a card
/// with a key in two slots would otherwise sign with whichever one this looked
/// at first, and the seal would name a key the owner did not choose.
pub const seal_slot: piv.Slot = .digital_signature;

/// The bytes the probe signature is over. A constant of this file, so a card is
/// never asked to sign anything that reached this program from outside.
pub const probe_domain = "chock-seal-probe-v1\x00";

/// The longest reader name this keeps. `pcsc-lite` bounds its own name field at
/// 128 bytes, so a name longer than this is not a name any daemon gave.
pub const max_reader_name = 128;

/// How many bytes the reader list is read into. Each name takes at most
/// `max_reader_name` bytes and a zero, so this holds far more readers than a
/// machine has USB ports.
pub const reader_list_bytes = 4096;

/// How much room `Outcome.sentenceWith` needs. **Checked at build time** by the
/// comptime block below, over every sentence and over the widest number a count
/// of bytes can print, so a sentence that grew past this fails the build instead
/// of quietly falling back to the form with no number in it.
pub const max_sentence_len = 512;

/// The sentence for a PIN shorter than the field a card takes, with the count
/// that was measured. **The count is bytes**, which is what the field measures.
const counted_too_short =
    "{d} bytes were typed and a PIV PIN is six to eight bytes, " ++
    "so the card was never asked and no try was spent";

/// The same fact for a caller that measured no count.
const uncounted_too_short =
    "fewer bytes were typed than the six a PIV PIN is at least, " ++
    "so the card was never asked and no try was spent";

/// The sentence for a PIN longer than the field a card takes, with the count
/// that was measured.
///
/// Three facts, and a person needs all three:
///
/// 1. **The number they typed.** Somebody who typed twelve bytes learns at once
///    that what they typed is not a PIV PIN at all.
/// 2. **Bytes are not characters.** A character outside plain ASCII takes more
///    than one byte, so a PIN of eight characters can be nine bytes and is
///    refused. That person counted eight, and without this the refusal looks
///    wrong to them.
/// 3. **A card holds more than one PIN.** A long answer is usually a real PIN
///    that belongs to another application on the same key rather than a typing
///    mistake, so the person is confident and still wrong. Only the PIV PIN
///    reaches the slot that signs. The other applications are not named, because
///    nothing here reads which ones a card carries.
const counted_too_long_for_card =
    "{d} bytes were typed and a PIV PIN is six to eight bytes, " ++
    "so the card was never asked and no try was spent. " ++
    "Bytes are not characters: a character outside plain ASCII takes more than one byte, " ++
    "so a PIN of eight characters can be longer than eight bytes. " ++
    "A card can also hold more than one PIN, and only the PIV one signs here, " ++
    "so an answer this long is one of the others";

/// The same fact for a caller that measured no count.
const uncounted_too_long_for_card =
    "more bytes were typed than the eight a PIV PIN is at most, " ++
    "so the card was never asked and no try was spent. " ++
    "Bytes are not characters: a character outside plain ASCII takes more than one byte, " ++
    "so a PIN of eight characters can be longer than eight bytes. " ++
    "A card can also hold more than one PIN, and only the PIV one signs here, " ++
    "so an answer this long is one of the others";

/// What reaching for a card key found. Exactly one of these is true of a run,
/// and only `ready` means a card key is in hand.
pub const Outcome = enum {
    /// A card key is in hand. It signed the probe digest, or, on a slot whose
    /// PIN policy is `always`, it took the PIN and holds an unlock the first
    /// seal signature uses. See this file's own top comment on the probe.
    ready,
    /// Nothing asked. The value an `Attempt` carries before `open`.
    not_tried,
    /// This build has no PC/SC transport for this platform. **Never read as
    /// "there is no card"**: nothing was asked. See `chock-pcsc.zig`.
    no_transport,
    /// No daemon answered.
    no_daemon,
    /// A daemon answered and refused this client.
    not_authorized,
    /// A daemon answered and speaks a protocol this build does not.
    protocol_mismatch,
    /// A daemon answered and named no reader.
    no_reader,
    /// A reader is attached and holds no card.
    no_card,
    /// A card answered and has no PIV application.
    no_piv,
    /// **The card says the slot holds no key.** Measured with `GET METADATA`,
    /// which is the one command that answers that question.
    no_key,
    /// The card has no `GET METADATA` and its slot holds no certificate, so
    /// **whether it holds a key was not measured**.
    ///
    /// Its own outcome because reading it as `no_key` is a false statement about
    /// somebody's hardware, and this project has already made that one: a slot
    /// holding an RSA key with no certificate beside it was reported as empty,
    /// and the wrong conclusion stood for two tasks.
    no_certificate,
    /// The slot holds a certificate whose public key this cannot read.
    key_unreadable,
    /// The slot holds a key of an algorithm this build cannot sign with.
    /// **The key is really there**, which is what separates this from `no_key`.
    key_unsupported,
    /// The card holds the key and wants a PIN, and this run had nobody to ask
    /// for one.
    pin_required,
    /// A PIN was needed and nobody is at a keyboard. A subagent, a session a
    /// daemon started, and a piped command are all here.
    pin_nobody,
    /// A person was asked for the PIN and gave none.
    pin_declined,
    /// A person typed more than a prompt can read, so the whole line was
    /// refused and **the card was never asked**.
    ///
    /// Its own outcome, because reading it as `pin_declined` tells somebody who
    /// typed a long line that they gave nothing, which is a false statement
    /// about what they did.
    pin_too_long,
    /// The answer could not be read off the terminal at all, so there is
    /// nothing to say about what anybody typed.
    ///
    /// Its own outcome for the same reason `pin_too_long` is: a terminal that
    /// would not turn its echo off, or a line that could not be read, is not a
    /// person refusing.
    pin_unreadable,
    /// Fewer bytes were typed than the six a card PIN is at least, so **the card
    /// was never asked and no try was spent**. See `piv.padPin`.
    pin_too_short,
    /// More bytes were typed than the eight a card PIN is at most, so **the card
    /// was never asked and no try was spent**. See `piv.padPin`.
    ///
    /// **Not the same fact as `pin_too_long`, and the sentences must keep saying
    /// so.** A `pin_too_long` line was refused at the terminal, at the 64 byte
    /// buffer the prompt reads into, and not one byte of it was read. This one
    /// was read and then measured against the eight byte field the card takes.
    /// Every length from nine to 64 bytes is this one.
    pin_too_long_for_card,
    /// What was typed holds the byte `FF`, which is the pad, so **the card was
    /// never asked and no try was spent**.
    ///
    /// **Its own outcome and never one of the two lengths.** A six byte PIN
    /// holding `FF` lands here, and telling that person their PIN was the wrong
    /// length is a false statement about what they typed. See `piv.padPin` for
    /// why the byte cannot be sent.
    pin_holds_pad,
    /// The PIN given was wrong. One try is gone. `Attempt.tries` says how many
    /// are left. **Nothing here tries again**: see `Attempt.givePin`.
    pin_wrong,
    /// The card's PIN is blocked and needs the PUK. No try was spent finding
    /// out, because the counter is read without spending one.
    pin_blocked,
    /// The card took the PIN and then refused to sign anyway. Something other
    /// than the PIN is stopping it, so **nothing here asks a second time**: a
    /// second ask would spend a try on a fault the PIN is not.
    pin_not_enough,
    /// The card refused a command for a reason a caller cannot act on.
    card_refused,

    /// Why the run signed the way it did, in one sentence.
    ///
    /// **Here, beside the mechanism**, for the reason `seal.Reading.sentence`
    /// is: a command prints the sentence for the outcome it measured, so the
    /// words and the fact they are about cannot drift apart. A command that
    /// held its own fixed sentence would go on printing it after the fact
    /// changed, which is what happened to the line this replaced.
    ///
    /// **No sentence says what this build can do.** Each says what this run
    /// did, and every one of them names the step that stopped.
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
            // The width comes from the buffer that refused the line, so the
            // number a person reads is the number the prompt used.
            .pin_too_long => std.fmt.comptimePrint(
                "more than {d} bytes were typed and a card PIN is eight at most, " ++
                    "so the card was never asked and no try was spent",
                .{pin.max_pin_bytes},
            ),
            .pin_unreadable =>
            \\the answer could not be read off the terminal, so the card was never asked and no try was spent
            ,
            // **One rule per sentence.** These three shared an outcome and a
            // sentence that named every cause, so a person read a list of what
            // might have happened and could act on none of it. `sentenceWith`
            // puts the number that was measured into the two lengths.
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

    /// Whether a count of bytes is part of what this outcome says.
    ///
    /// **A caller records the number for these and for no other.** A number
    /// printed beside a refusal that no length caused reads as the cause, and
    /// `pin_holds_pad` is refused whatever its length is.
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

    /// The sentence, with the number of bytes that were measured written into
    /// it. `out` must hold `max_sentence_len` bytes.
    ///
    /// **A second function, because `sentence` has no buffer to write into.**
    /// Every other outcome states a fact that is the same on every machine, and
    /// these two state a fact about one thing one person typed. A count of null
    /// is a caller that measured none, and it gets the same fact with no number.
    ///
    /// The result borrows `out` for the two counted outcomes and is a constant
    /// of this file for every other one, so a caller keeps `out` alive for as
    /// long as it reads the answer.
    pub fn sentenceWith(self: Outcome, typed_bytes: ?usize, out: []u8) []const u8 {
        if (!self.countsBytes()) return self.sentence();
        const bytes = typed_bytes orelse return self.sentence();
        // A buffer too small leaves the fact standing without the number, which
        // is the part a person needs least. The comptime block below makes that
        // unreachable for a caller that gave `max_sentence_len` bytes.
        //
        // `countsBytes` named the two arms below and nothing else, so nothing
        // else reaches the last one.
        return switch (self) {
            .pin_too_short => std.fmt.bufPrint(out, counted_too_short, .{bytes}) catch
                self.sentence(),
            .pin_too_long_for_card => std.fmt.bufPrint(out, counted_too_long_for_card, .{bytes}) catch
                self.sentence(),
            else => self.sentence(),
        };
    }

    /// The outcome for one answer to the PIN question, and null for the one
    /// answer that goes on to the card.
    ///
    /// **One mapping, because two callers make it.** `Attempt.givePin` asks for
    /// the first signature of a run, and `piv.CardSigner.authorise` asks for
    /// every signature after it. A slot whose PIN policy is `always` reaches the
    /// second far more often than the first: sealing twenty logs asks twenty
    /// times, and only the first ask goes through `givePin`. A mapping written
    /// out twice drifts, and this one drifted already, into four answers that
    /// all became a single error with no sentence.
    pub fn forAnswer(answer: pin.Answer) ?Outcome {
        return switch (answer) {
            // **No bytes is a person declining, and never a malformed PIN.** The
            // prompt offers Enter as the way to sign with the software key, so a
            // person who presses it did what they were told. An asker that reads
            // the empty line itself answers `.declined` and never gets here, and
            // this holds for the one that does not.
            .pin => |typed| if (typed.len == 0) .pin_declined else null,
            .nobody => .pin_nobody,
            .declined => .pin_declined,
            .too_long => .pin_too_long,
            .unreadable => .pin_unreadable,
        };
    }

    /// The outcome for a card that would not take the PIN it was given.
    ///
    /// **The three shape refusals say no try was spent, and that is why they
    /// are here.** The card was never sent anything, and saying so is the
    /// difference between a person retyping and a person hunting for a PUK.
    ///
    /// **One outcome per rule.** `piv.padPin` answers three errors and this
    /// keeps them three, because a person who typed too little, a person who
    /// typed too much and a person whose PIN holds the pad byte each do a
    /// different thing next.
    pub fn forVerify(err: piv.CardError) Outcome {
        return switch (err) {
            error.PinTooShort => .pin_too_short,
            error.PinTooLongForField => .pin_too_long_for_card,
            error.PinHoldsPad => .pin_holds_pad,
            error.NoCard, error.Removed => .no_card,
            else => .card_refused,
        };
    }

    /// Whether a PIN is what stopped this. A caller prints the count of tries
    /// left beside these and beside nothing else, because those are the outcomes
    /// a counter is about.
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

    /// Whether somebody tried to use the card and the card key did not sign.
    ///
    /// **This is the question a run's exit code is answered with**, and it is
    /// not the same question as "did a card sign". A fallback is the whole
    /// design and most fallbacks are honest, so most of them end a run that
    /// worked. Three groups, and only the last is a failure:
    ///
    /// 1. **Nothing was tried.** No reader, no card, no PIV application, no key,
    ///    nobody at a keyboard. Nobody asked the card for anything and nothing
    ///    was refused, so a software seal is the answer and the run worked.
    /// 2. **Somebody chose the software key.** The prompt offers Enter for
    ///    exactly that, so `pin_declined` is a person doing what they were told.
    ///    A chosen fallback is never a failure.
    /// 3. **Somebody answered the PIN question and no card seal came of it.**
    ///    They asked for a card seal, they gave something, and it did not
    ///    happen. A run that wrote a weaker artefact and reported success here
    ///    is a silent downgrade that a person scripting a release would never
    ///    see, which is the one thing `seal.Level` exists to stop.
    ///
    /// **`pin_blocked` is not here, and that is a decision.** The counter is
    /// read before anybody types and a blocked card ends the path before the
    /// prompt is drawn, so nobody answered anything. It is the same shape as an
    /// empty slot: the card cannot do it and the run says so. A caller that
    /// wants a card seal or nothing has to refuse every fallback and not only
    /// this group.
    pub fn pinAttemptFailed(self: Outcome) bool {
        return switch (self) {
            // Something was typed and the prompt would not take it.
            .pin_too_long,
            .pin_unreadable,
            // Something was typed and this refused it before the card saw it.
            .pin_too_short,
            .pin_too_long_for_card,
            .pin_holds_pad,
            // Something was typed and the card refused it. One try is gone.
            .pin_wrong,
            // The card took the PIN and would not sign anyway.
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

    /// Whether the transport itself is what stopped this. A caller prints the
    /// driver's own failure beside these and for no other, because those are
    /// the outcomes a driver has a sentence about.
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

/// One reach for a card key over one transport.
///
/// **The caller owns it and it must not move** once `open` has answered
/// `ready`: the signer points into this. `deinit` closes whatever was opened
/// and is safe on an attempt that opened nothing.
pub const Attempt = struct {
    transport: iface.Pcsc,
    /// Where card answers are put. It must outlive the attempt, because the
    /// signer keeps it.
    scratch: []u8,
    outcome: Outcome = .not_tried,
    card: ?iface.Card = null,
    card_signer: ?piv.CardSigner = null,
    reader_bytes: [max_reader_name]u8 = undefined,
    reader_len: usize = 0,
    /// Who to ask when the card wants a PIN. Null asks nobody, and the outcome
    /// then says the PIN is why. **A pair of pointers and never a PIN**: see the
    /// comptime block at the end of this file.
    asker: ?pin.Asker = null,
    /// What the card said about its counter, when it was asked. Null when no
    /// counter was read. Read without spending a try.
    tries: ?piv.Tries = null,
    /// What the slot holds, when the card would say. Null for a card with no
    /// `GET METADATA`.
    metadata: ?piv.Metadata = null,
    /// Whether a PIN was already given to this card on this run. **The guard
    /// that stops a second ask**, which would spend a second try. A boolean, and
    /// never the value.
    pin_given: bool = false,
    /// How many bytes the PIN that was refused had, and null when no length was
    /// measured. It goes to `Outcome.sentenceWith`, so a person reads the number
    /// they typed rather than a rule they have to measure themselves against.
    ///
    /// **A count and never the value**, and it is set only for the outcomes
    /// `Outcome.countsBytes` names, so no number is printed beside a refusal
    /// that a length did not cause.
    pin_bytes: ?usize = null,

    pub fn init(transport: iface.Pcsc, scratch: []u8) Attempt {
        return .{ .transport = transport, .scratch = scratch };
    }

    /// Try every reader the daemon names, and stop at the first card that
    /// signs.
    ///
    /// **A reader with a card beats a reader with none.** A machine with two
    /// readers, one empty, must not report an empty slot when the other one
    /// held the key, and must not report "no card" when a card was there and
    /// its slot was empty. So the more particular answer is kept.
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

    /// The signer, or null when no card key is in hand. **Null on every outcome
    /// but `ready`**, so a caller cannot sign with a half opened card.
    pub fn signer(self: *Attempt) ?seal.Signer {
        if (self.outcome != .ready) return null;
        if (self.card_signer) |*held| return held.signer();
        return null;
    }

    /// The level a seal signed by this carries. Null when nothing is in hand.
    ///
    /// **Never `card_attested`.** See this file's own top comment: a claim of
    /// hardware with no root to check it against reads worse than the level
    /// that is true.
    pub fn level(self: *const Attempt) ?seal.Level {
        return if (self.outcome == .ready) .card else null;
    }

    /// The reader the card was found in. Empty when no card was reached, so a
    /// message never names a reader that gave nothing.
    pub fn reader(self: *const Attempt) []const u8 {
        return self.reader_bytes[0..self.reader_len];
    }

    /// Why the card refused a signature **after** `open` answered `ready`, and
    /// null while it has refused none.
    ///
    /// **The half of the answer `open` cannot give.** A slot whose PIN policy is
    /// `always` asks again before every signature, so a run that opened a card
    /// can still be stopped by the second prompt, the third, or the twentieth.
    /// `seal.SignError` has one member for all of those, and this is where the
    /// fact behind it is kept.
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
            // Nothing usable came of this reader, so the name is dropped rather
            // than left for a message to print beside a failure it is not
            // about.
            self.reader_len = 0;
        }
        return outcome;
    }

    /// One reader, from the connect to the probe signature. Leaves the card
    /// connected only when it answers `ready`.
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

        // The name is kept before the signer is opened, so the question a person
        // is asked can say which reader the card is in. `finish` drops it again
        // for every outcome but `ready`.
        if (name.len <= self.reader_bytes.len) {
            @memcpy(self.reader_bytes[0..name.len], name);
            self.reader_len = name.len;
        }

        if (self.openSigner(card)) |refused| return self.closing(refused);

        // **A slot that wants the PIN every time is unlocked and never probed.**
        // A slot with the `always` policy refuses a signature that no `VERIFY`
        // came directly before, so the probe below needs an unlock of its own
        // and then uses it up. The seal signature that follows moments later
        // asked for a second one, and one seal cost a person two prompts. Every
        // prompt is another chance to mistype and three wrong PINs block the
        // card, so the probe is not worth a prompt here.
        //
        // **Nothing is lost by leaving it out.** The probe buys an early answer,
        // and on this slot the real signature is the next thing that happens: a
        // card that refuses it seals nothing and the command faults. The unlock
        // stays because it is what the card asks for, and `verify_unused` hands
        // it to that first signature.
        if (self.card_signer.?.pin_policy == .always) {
            if (self.givePin(card)) |refused| return self.closing(refused);
            self.card_signer.?.verify_unused = true;
            return .ready;
        }

        // The probe. See this file's own top comment for why a card that holds
        // the key is asked to use it before anything is sealed.
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
                // A slot with the `once` policy asks here and not before,
                // because this is where the card first says it wants one.
                //
                // **And a slot that was already given the PIN is not asked
                // again.** Whatever is stopping this card, a second try at the
                // counter is not going to find it.
                //
                // No path reaches this line with the PIN already given, because
                // the one slot that is unlocked before the probe returns above
                // and never probes. The guard stays because the cost of it
                // being wrong is a spent try on somebody's key.
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

    /// Open a signer over the seal slot, or answer why there is none.
    ///
    /// **`GET METADATA` first, and the certificate only as a fallback.** A PIV
    /// slot holds a key and a certificate as two separate objects, so a build
    /// that read only the certificate reports a slot holding a key with no
    /// certificate as empty. That is a false statement about somebody's
    /// hardware, and this project made it once: see `Outcome.no_certificate`.
    fn openSigner(self: *Attempt, card: iface.Card) ?Outcome {
        const metadata = piv.readMetadata(card, seal_slot, self.scratch) catch |err| switch (err) {
            // The card says the slot is empty. The one place this module may
            // say so.
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

    /// The old path, for a card with no `GET METADATA`: read the public key out
    /// of the certificate in the slot.
    fn openFromCertificate(self: *Attempt, card: iface.Card) ?Outcome {
        var made = piv.CardSigner.init(card, seal_slot, self.scratch) catch |err| switch (err) {
            // **Never `no_key`.** All this measured is that no certificate is
            // in the slot, and this card has no command that would say more.
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

    /// Ask a person for the PIN, once, and give it to the card, once. Null when
    /// the card accepted it, and the outcome that ends the card path otherwise.
    ///
    /// **There is no loop in this function and there must never be one.** A PIV
    /// card blocks after three wrong PINs and then needs the PUK. A retry
    /// nobody asked for turns one mistyped digit into a spent try, and a build
    /// that retried by itself would spend all three in a second. Every answer
    /// but `accepted` is final for this run.
    ///
    /// **The count is read before anybody is asked**, and reading it spends no
    /// try, so the question can say how many are left.
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
        // **Every answer keeps its own name.** An answer that could not be read
        // is not a person refusing, and folding one into the other tells
        // somebody they gave nothing when they gave something. The card is
        // untouched on all four, so this costs no try either way.
        if (Outcome.forAnswer(answer)) |refused| return refused;
        // Null from `forAnswer` is a PIN with bytes in it, and nothing else.
        const value = answer.pin;

        const given = piv.verifyPin(card, value, self.scratch) catch |err| {
            const refused = Outcome.forVerify(err);
            // The count, so the sentence can say the number that was typed. Only
            // for the refusals a length caused: a number beside `pin_holds_pad`
            // would read as the cause, and the pad byte is refused at any
            // length.
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

    /// The probe signature again, after a PIN was accepted. **Once**: a card
    /// that refuses a signature the PIN it just took should have authorised has
    /// a reason of its own, and asking a person for the PIN again would spend a
    /// try on a fault the PIN is not.
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

// **A PIN lives in one stack frame and nowhere else.** `givePin` reads one into
// a buffer of its own and wipes it before that frame ends, and
// `piv.CardSigner.authorise` does the same. Neither an `Attempt` nor a
// `CardSigner` outlives one call, so a field of either that could hold a PIN
// would be a value kept for the length of a command instead. This fails the
// build if one appears, the same guard `chock-broker/askpass.zig` keeps over its
// own endpoint.
// Every sentence fits the buffer callers give `Outcome.sentenceWith`, measured
// at build time and never at run time. A sentence that outgrew the buffer would
// otherwise silently lose the number a person needs, on the one machine where
// the number is the whole answer.
comptime {
    for (std.enums.values(Outcome)) |one| {
        if (one.sentence().len > max_sentence_len) {
            @compileError("this outcome's sentence is longer than max_sentence_len: " ++ @tagName(one));
        }
    }
    // The counted forms, filled with the widest number a byte count can print.
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

/// The `SELECT` a card sees, and the answer one with a PIV application gives.
const select_command = [_]u8{ 0x00, 0xa4, 0x04, 0x00, 0x0b } ++ piv.aid ++ [_]u8{0x00};
const select_answer = [_]u8{ 0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x90, 0x00 };
/// `GET DATA` for the signature slot's certificate object, `5F C1 0A`.
const get_certificate = [_]u8{ 0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x0a, 0x00 };
/// `GET METADATA` for the signature slot. The first thing the card path asks
/// about a slot now, because it is the only command that says whether a key is
/// in there.
const get_metadata = [_]u8{ 0x00, 0xf7, 0x00, 0x9c, 0x00 };
/// What a card without that command answers: "instruction not supported".
const no_metadata = [_]u8{ 0x6d, 0x00 };

test "a daemon that is not there is not a card that is not there" {
    // The four the caller must not read as one another. A transport that
    // answered one error for all of them would make every machine print the
    // same sentence.
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
    // The two a person acts on differently: one card is the wrong card, the
    // other is the right card with nothing provisioned in it.
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
    // The one card state that may be called an empty slot: the card itself said
    // so, through the command that answers that question.
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
    // The fault this outcome exists for. `GET DATA` for the certificate object
    // answered `6a 82`, which is what a real YubiKey answered on 2026-08-22, and
    // the conclusion drawn from it was "the card holds no key in any slot". The
    // card held an RSA2048 key in this very slot the whole time: a certificate
    // and a key are separate objects, and only one of them was asked about.
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
    // And the words say what was measured and not what was guessed.
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
    // The guard that keeps a half opened card out of a seal. **The signer is
    // really there** for every case below, so a build that answered it whenever
    // it held one would pass every outcome here rather than none of them. That
    // is the state a card reached after its certificate and refused to sign.
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

    // And the same signer is handed back for `ready`, so the guard above is
    // about the outcome and not about the signer being absent.
    attempt.outcome = .ready;
    try testing.expect(attempt.signer() != null);
    try testing.expectEqual(@as(?seal.Level, .card), attempt.level());
}

test "every outcome has its own sentence, and none of them says what this build links" {
    // The fault this file was written for. The message a command prints has to
    // be about the run, so no sentence here may state a property of the build
    // that a later build makes false.
    var seen: [@typeInfo(Outcome).@"enum".fields.len][]const u8 = undefined;
    inline for (@typeInfo(Outcome).@"enum".fields, 0..) |field, i| {
        const text = (@as(Outcome, @enumFromInt(field.value))).sentence();
        try testing.expect(text.len != 0);
        for (seen[0..i]) |earlier| try testing.expect(!std.mem.eql(u8, earlier, text));
        seen[i] = text;
        // "links no PC/SC library" was true when it was written and false a
        // task later. The transport a platform has is stated by
        // `Outcome.no_transport` alone, and even that says what happened on
        // this run rather than what was compiled in.
        try testing.expect(std.mem.indexOf(u8, text, "links") == null);
    }
}

test "only a transport outcome carries a driver's own failure" {
    // A caller prints the driver's sentence beside these and beside nothing
    // else. A card with an empty slot has no driver failure to print, and
    // printing the last one would name a fault that is not this one.
    try testing.expect(Outcome.no_daemon.fromTransport());
    try testing.expect(Outcome.not_authorized.fromTransport());
    try testing.expect(Outcome.protocol_mismatch.fromTransport());
    try testing.expect(Outcome.no_transport.fromTransport());
    try testing.expect(!Outcome.no_key.fromTransport());
    try testing.expect(!Outcome.no_card.fromTransport());
    try testing.expect(!Outcome.ready.fromTransport());
}

/// A transport that answers one error to everything. `Recorded` cannot do this:
/// it is built to be a card that works, and these are the machines where
/// nothing gets as far as a card.
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

/// An asker that answers with a fixed PIN and counts how many times it was
/// asked. **The count is the retry guard**: a build that asked twice would fail
/// on the count and not only on the recording.
const CountingPin = struct {
    asked: usize = 0,
    tries: piv.Tries = .unknown,
    value: []const u8 = "123456",
    /// What to answer instead of a PIN, for the tests about the answers that
    /// never reach a card.
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

/// A card with an elliptic curve key in the seal slot and a PIN before every
/// use. Short enough to write out, and the same flow an RSA card takes.
const ec_point = [_]u8{0x04} ++ [_]u8{0x33} ** 64;
const ec_metadata = [_]u8{ 0x01, 0x01, 0x11 } ++
    [_]u8{ 0x02, 0x02, 0x03, 0x01 } ++
    [_]u8{ 0x04, 0x43, 0x86, 0x41 } ++ ec_point ++ [_]u8{ 0x90, 0x00 };
/// The same card with a PIN policy of `once`, and the same card again with a
/// policy of `never`.
///
/// **One byte apart from the card above**, so a count of prompts that differs
/// between the three differs because of the policy and for no other reason.
const ec_metadata_once = [_]u8{ 0x01, 0x01, 0x11 } ++
    [_]u8{ 0x02, 0x02, 0x02, 0x01 } ++
    [_]u8{ 0x04, 0x43, 0x86, 0x41 } ++ ec_point ++ [_]u8{ 0x90, 0x00 };
const ec_metadata_never = [_]u8{ 0x01, 0x01, 0x11 } ++
    [_]u8{ 0x02, 0x02, 0x01, 0x01 } ++
    [_]u8{ 0x04, 0x43, 0x86, 0x41 } ++ ec_point ++ [_]u8{ 0x90, 0x00 };
/// `VERIFY` with no data, which asks the counter and spends nothing.
const pin_retries_command = [_]u8{ 0x00, 0x20, 0x00, 0x80 };
/// `VERIFY` with "123456" padded with `FF`.
const verify_command = [_]u8{ 0x00, 0x20, 0x00, 0x80, 0x08, '1', '2', '3', '4', '5', '6', 0xff, 0xff };
/// `VERIFY` with "yubico" padded with `FF`. **A PIN SP 800-73-4 says cannot
/// exist**, and one a YubiKey takes.
const verify_letters_command = [_]u8{ 0x00, 0x20, 0x00, 0x80, 0x08, 'y', 'u', 'b', 'i', 'c', 'o', 0xff, 0xff };

/// The digest the probe is over. A test that asks a signer for a signature uses
/// this one as well, so one recorded `GENERAL AUTHENTICATE` covers both and a
/// test never has to say which of the two a command is.
const probe_digest = built: {
    @setEvalBranchQuota(4000);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(probe_domain, &digest, .{});
    break :built digest;
};

/// A signature request over the seal slot with an elliptic curve key. Built
/// rather than written out, because the digest is a hash of a constant and a
/// number typed here would be a number nothing checks.
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

/// What an elliptic curve card answers a signature with: `7C { 82 (the DER) }`.
/// The DER holds two 32 byte integers, each of them small enough that no leading
/// zero is needed, so the bytes below are the whole of a well formed answer.
const ec_signature_der = [_]u8{ 0x30, 0x44, 0x02, 0x20 } ++ [_]u8{0x33} ** 32 ++
    [_]u8{ 0x02, 0x20 } ++ [_]u8{0x33} ** 32;
const ec_signature_answer = [_]u8{ 0x7c, 0x48, 0x82, 0x46 } ++ ec_signature_der ++
    [_]u8{ 0x90, 0x00 };

/// Ask a signer for one signature over `probe_digest`, and answer how many bytes
/// came back. **The bytes are dropped on purpose**: these tests count prompts
/// and card commands, and the signature itself is checked against a real key in
/// `test/pcsc/verify.zig`.
fn signOnce(made: seal.Signer) seal.SignError!usize {
    var out: [seal.max_signature_len]u8 = undefined;
    const bytes = try made.vtable.signDigest(made.ptr, probe_digest, &out);
    return bytes.len;
}

test "a card that refuses after taking the PIN is not asked for a second one" {
    // **The guard that keeps a spent try from becoming three.** Whatever refuses
    // a signature the card has just taken the PIN for is not something another
    // try at the counter will fix, so this asks once and stops.
    //
    // The recording holds one counter read and one `VERIFY` and refuses any
    // command it does not hold, so a build that asked again fails here rather
    // than on somebody's card.
    //
    // Mutation check: drop the `stopped` test at the top of
    // `piv.CardSigner.authorise`, or ask again where `signDigestFn` answers
    // `pin_not_enough`, and this fails on the count.
    var counting = CountingPin{};
    var stubborn = iface.Recorded{
        .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata },
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
            .{ .send = &verify_command, .receive = &.{ 0x90, 0x00 } },
            // The card took the PIN and refuses the signature anyway.
            .{ .send = &sign_command, .receive = &.{ 0x69, 0x82 } },
        },
    };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(stubborn.pcsc(), &scratch);
    defer attempt.deinit();
    attempt.asker = counting.asker();

    // The card opened on the PIN alone. Nothing has been signed yet, which is
    // the whole point of not probing a slot with this policy.
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
    // **The fault this closes.** One seal used to cost two prompts on this
    // slot: one to unlock the card for a probe signature, and one for the seal
    // itself, because the probe used the first unlock up. Every prompt is
    // another chance to mistype and three wrong PINs block the card, so the
    // early answer a probe gives is not worth one here: the real signature is
    // the next thing that happens.
    //
    // The recording holds exactly one counter read and one `VERIFY`, and it
    // refuses any command it does not hold. A build that probed would fail on
    // the second `VERIFY` it has no recording of, and on the count below.
    //
    // Mutation check: probe this slot as well, by dropping the early `return
    // .ready` in `tryReader`, and the count reads 2.
    var counting = CountingPin{};
    var card = iface.Recorded{
        .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata },
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
            .{ .send = &verify_command, .receive = &.{ 0x90, 0x00 } },
            // The seal signature, and the only one this card is asked for.
            .{ .send = &sign_command, .receive = &ec_signature_answer },
        },
    };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(card.pcsc(), &scratch);
    defer attempt.deinit();
    attempt.asker = counting.asker();

    try testing.expectEqual(Outcome.ready, attempt.open());
    // **Asked before a byte was signed, and asked once.** The count the card
    // reported reached the question, so a person is told how many tries are
    // left before they type.
    try testing.expectEqual(@as(usize, 1), counting.asked);
    try testing.expectEqual(@as(?u4, 3), counting.tries.count());

    // **The count is read before the signature is.** A build that asked a
    // second time fails on this line and names the fault, rather than failing
    // further down on a recording that ran out of commands.
    const made = signOnce(attempt.signer().?);
    try testing.expectEqual(@as(usize, 1), counting.asked);
    try testing.expectEqual(@as(usize, seal.signature_len), try made);
    try testing.expect(card.drained());
    try testing.expectEqual(@as(?Outcome, null), attempt.stopped());
}

test "a slot that wants the PIN every time asks again for every seal after the first" {
    // **The card's rule and not this program's.** A slot with this policy clears
    // its own status every time it uses the key, so each seal after the first
    // needs a `VERIFY` of its own. Three seals here, three prompts: one per
    // signature, and never two for one.
    //
    // Mutation check: leave `verify_unused` set in `signDigestFn` instead of
    // clearing it and the recording fails, because the second seal signs with
    // no `VERIFY` in front of it.
    var counting = CountingPin{};
    var card = iface.Recorded{
        .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata },
            // The card path unlocks the card, and the first seal uses it.
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
            .{ .send = &verify_command, .receive = &.{ 0x90, 0x00 } },
            .{ .send = &sign_command, .receive = &ec_signature_answer },
            // The second seal, and the third.
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
    // **The count first, and the signatures after it.** A build that stopped
    // asking would fail on the recording, which names a missing command and not
    // the prompt nobody got, so the count is read before anything else.
    var refused: usize = 0;
    for (0..3) |_| _ = signOnce(made) catch {
        refused += 1;
    };
    try testing.expectEqual(@as(usize, 3), counting.asked);
    try testing.expectEqual(@as(usize, 0), refused);
    try testing.expect(card.drained());
}

test "a slot that wants the PIN once is probed, and asks when the card says so" {
    // **The probe stays where it costs nothing.** This slot signs the probe
    // without a PIN or says once that it wants one, so the early answer a probe
    // gives is free. The prompt lands where the card first asks for it, and
    // every seal after that is signed with no prompt at all.
    //
    // Mutation check: skip the probe for this policy as well and the recording
    // fails on the first signature it has no recording of.
    var counting = CountingPin{};
    var card = iface.Recorded{
        .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata_once },
            // The probe, refused: this is where the card says it wants a PIN.
            .{ .send = &sign_command, .receive = &.{ 0x69, 0x82 } },
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
            .{ .send = &verify_command, .receive = &.{ 0x90, 0x00 } },
            // The probe again, and now the card signs it.
            .{ .send = &sign_command, .receive = &ec_signature_answer },
            // The seal, with no prompt in front of it.
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
    // Still one. The unlock this card took holds for the rest of the run.
    try testing.expectEqual(@as(usize, 1), counting.asked);
}

test "a slot that wants no PIN asks nobody, and the probe is what proves it" {
    // The recording holds no counter read and no `VERIFY`, and it refuses any
    // command it does not hold, so a build that put a prompt in front of a
    // person for a key that needs none fails here.
    var counting = CountingPin{};
    var card = iface.Recorded{
        .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata_never },
            // The probe, which this card signs straight away.
            .{ .send = &sign_command, .receive = &ec_signature_answer },
            // And the seal.
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
    // **One try and no more.** The recording below holds exactly one `VERIFY`,
    // so a build that tried again fails here rather than on somebody's card.
    // Two tries left is what the card reported, and that number reaches the
    // caller so a message can say it.
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
    // And the person was told three were left before they typed, which is the
    // number the card gave and not one this counted itself.
    try testing.expectEqual(@as(?u4, 3), counting.tries.count());
}

test "a blocked card is never given a PIN, and no try is spent finding out" {
    // The counter is read first, so a card with nothing left to spend is named
    // before anybody is asked to type into it.
    //
    // Mutation check: move the `blocked` test in `givePin` below the ask and
    // this fails, because the asker is called and the recording has no `VERIFY`.
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
    // The difference between a person retyping and a person hunting for a PUK.
    //
    // **Three rules and three outcomes.** All three answered one outcome once,
    // and the sentence for it had to name every cause, so a person who ran the
    // command twice was told what might have happened and never which of the
    // three did. Every case below is a different thing a person does and a
    // different thing they do next.
    //
    // **No case here spends a try, and that must stay true.** The recording
    // holds no `VERIFY` and refuses any command it does not hold, so a build
    // that sent one of these to a card would fail here rather than on somebody's
    // key. The owner's card read 3/3 tries after two runs that landed in the
    // second case, which is this property measured on real hardware.
    //
    // Mutation check: put any two of the three rules back on one error in
    // `piv.padPin` and the case for the rule that lost its name fails on the
    // outcome.
    const cases = [_]struct { value: []const u8, want: Outcome, bytes: ?usize }{
        // Five bytes, one short of the least a PIV field takes.
        .{ .value = "12345", .want = .pin_too_short, .bytes = 5 },
        // Nine bytes, one over the most it takes. Everything from nine to 64
        // used to land on the shared outcome, which is most of the fault.
        .{ .value = "123456789", .want = .pin_too_long_for_card, .bytes = 9 },
        // A real PIN of another application on the same key is the ordinary way
        // this happens, and it is far longer than nine.
        .{ .value = "fido2-pin-for-the-same-key", .want = .pin_too_long_for_card, .bytes = 26 },
        // **Eight characters and nine bytes**, because `é` is two bytes in
        // UTF-8. The person counted eight.
        .{ .value = "é1234567", .want = .pin_too_long_for_card, .bytes = 9 },
        // The pad byte, at a length the field accepts, so nothing but the byte
        // can be what refused it. **No count is kept**: a number here would read
        // as the cause and the length is not the cause.
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
        // Every recorded exchange was played and there is no `VERIFY` among
        // them.
        try testing.expect(never_asked.drained());
        // Asked once. **No loop**, so a refusal costs nothing whatever it was.
        try testing.expectEqual(@as(usize, 1), counting.asked);
        // The count the message says, measured where the refusal happened.
        try testing.expectEqual(one.bytes, attempt.pin_bytes);
    }
}

test "a PIN that is not digits reaches the card, and the card is the one that decides" {
    // The fault this replaced: a rule taken from SP 800-73-4, which says a PIV
    // PIN is six to eight digits, rather than from the hardware, which does not
    // hold anybody to that. A YubiKey PIN set with `ykman piv access
    // change-pin` can be letters, so a person whose PIN is `yubico` could never
    // reach their own card and was told their own PIN was malformed.
    //
    // **The trade this makes, stated where it happens.** The card is asked, so
    // a wrong answer of the right length now spends one of three tries, where
    // before it spent none. The card is the only thing that knows its own PIN,
    // and a build that refuses for it locks people out.
    var counting = CountingPin{ .value = "yubico" };
    var card = iface.Recorded{
        .exchanges = &.{
            .{ .send = &select_command, .receive = &select_answer },
            .{ .send = &get_metadata, .receive = &ec_metadata },
            .{ .send = &pin_retries_command, .receive = &.{ 0x63, 0xc3 } },
            // The letters went out in the `VERIFY` field, padded, and this card
            // says they are the wrong ones with two tries left.
            .{ .send = &verify_letters_command, .receive = &.{ 0x63, 0xc2 } },
        },
    };
    var scratch: [piv.max_object_len]u8 = undefined;
    var attempt = Attempt.init(card.pcsc(), &scratch);
    defer attempt.deinit();
    attempt.asker = counting.asker();

    try testing.expectEqual(Outcome.pin_wrong, attempt.open());
    try testing.expect(card.drained());
    // Once. **No loop**, whatever the card answered.
    try testing.expectEqual(@as(usize, 1), counting.asked);
    try testing.expectEqual(@as(?u4, 2), attempt.tries.?.count());
}

test "an answer of no bytes is a person declining and never a malformed PIN" {
    // The prompt offers Enter as the way to sign with the software key, so a
    // person who presses it did what they were told. Telling them they typed
    // something wrong is this program blaming them for its own offer.
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
    // And the card was left alone, so the fallback costs nothing.
    try testing.expect(never_asked.drained());
}

test "an answer that could not be read keeps its own outcome and is never a decline" {
    // **The pair of faults this closes, one at each end of the range.** An
    // empty answer must not read as a malformed PIN, and a long or unreadable
    // one must not read as a person who gave nothing. Each of the three below
    // is a different thing that happened, so each gets a different sentence.
    //
    // Mutation check: fold any two of these prongs together in `givePin` and
    // the case for the folded one fails on the outcome.
    const cases = [_]struct { answer: pin.Answer, want: Outcome }{
        .{ .answer = .declined, .want = .pin_declined },
        .{ .answer = .too_long, .want = .pin_too_long },
        .{ .answer = .unreadable, .want = .pin_unreadable },
        .{ .answer = .nobody, .want = .pin_nobody },
    };
    for (cases) |one| {
        var counting = CountingPin{ .instead = one.answer };
        // The counter read is here, because it spends nothing and the question
        // says the number. There is no `VERIFY` after it, so a build that sent
        // one would fail here rather than on somebody's card.
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
        // Asked once, and the run ended there.
        try testing.expectEqual(@as(usize, 1), counting.asked);
        try testing.expectEqual(@as(?seal.Signer, null), attempt.signer());
    }

    // And what a person reads is different for each, which is the whole point
    // of separating them. The words follow what happened: one says nothing was
    // given, one says too much was typed, and one says nothing could be read.
    try testing.expect(std.mem.indexOf(u8, Outcome.pin_declined.sentence(), "none was given") != null);
    try testing.expect(std.mem.indexOf(u8, Outcome.pin_too_long.sentence(), "were typed") != null);
    try testing.expect(std.mem.indexOf(u8, Outcome.pin_too_long.sentence(), "none was given") == null);
    try testing.expect(std.mem.indexOf(u8, Outcome.pin_unreadable.sentence(), "could not be read") != null);
    try testing.expect(std.mem.indexOf(u8, Outcome.pin_unreadable.sentence(), "none was given") == null);
    // Neither of the two new ones reaches a card, so both say so.
    for ([_]Outcome{ .pin_too_long, .pin_unreadable }) |one| {
        try testing.expect(std.mem.indexOf(u8, one.sentence(), "no try was spent") != null);
    }

    // And the mapping the card path shares reads the same way round. **Both
    // prompts of a run go through it**, so a table that drifted here would
    // drift for `piv.CardSigner.authorise` at the same moment: see
    // `Outcome.forAnswer`.
    for (cases) |one| try testing.expectEqual(one.want, Outcome.forAnswer(one.answer).?);
    // The one answer that goes on to the card, and the one that does not
    // although it wears the same tag.
    try testing.expectEqual(@as(?Outcome, null), Outcome.forAnswer(.{ .pin = "123456" }));
    try testing.expectEqual(@as(?Outcome, .pin_declined), Outcome.forAnswer(.{ .pin = "" }));
}

test "each PIN the card was never asked about reads as its own complaint" {
    // **The fault this closes.** Three rules shared one sentence, and that
    // sentence had to name every cause: "either not the six to eight bytes a
    // card PIN is or holds the pad byte FF". A person read a list of what might
    // have happened. The owner ran the command twice and learned nothing either
    // time, because the words could not say which rule had fired.
    //
    // Four sentences here, and every one of them says a different thing:
    //
    // 1. `pin_too_long` was refused at the terminal, at the 64 byte buffer the
    //    prompt reads into, and not one byte of it was read.
    // 2. `pin_too_short` was read and measured against the six byte least.
    // 3. `pin_too_long_for_card` was read and measured against the eight byte
    //    field. Every length from nine to 64 is this one.
    // 4. `pin_holds_pad` was the right length and holds the byte the card
    //    cannot tell from the end of a shorter PIN.
    //
    // Mutation check: give any two of the four the same sentence and the
    // "no two of these read alike" loop fails on the pair.
    const line_too_long = Outcome.pin_too_long.sentence();
    const too_short = Outcome.pin_too_short.sentence();
    const too_long_for_card = Outcome.pin_too_long_for_card.sentence();
    const holds_pad = Outcome.pin_holds_pad.sentence();

    // The pad byte is named where it can happen, and nowhere else. A person
    // whose six byte PIN holds `FF` must never be told about a length.
    try testing.expect(std.mem.indexOf(u8, holds_pad, "byte FF") != null);
    for ([_][]const u8{ line_too_long, too_short, too_long_for_card }) |one| {
        try testing.expect(std.mem.indexOf(u8, one, "FF") == null);
    }

    // **Bytes are not characters, and only the card's own field says so.** A
    // person who typed eight characters and one of them outside plain ASCII is
    // refused for nine bytes, and the refusal looks wrong to them without this.
    try testing.expect(std.mem.indexOf(u8, too_long_for_card, "Bytes are not characters") != null);
    // And a long answer is usually a real PIN of another application on the
    // same key rather than a typing mistake, so the sentence says that a card
    // holds more than one PIN. **No application is named**, because nothing
    // here reads which ones a card carries.
    try testing.expect(std.mem.indexOf(u8, too_long_for_card, "more than one PIN") != null);
    // A PIN too short cannot come from that trap, because a character is never
    // fewer than one byte, so the sentence does not raise it.
    try testing.expect(std.mem.indexOf(u8, too_short, "Bytes are not characters") == null);

    // No two of these read alike, which is what "one way to say four things"
    // would look like.
    const all = [_][]const u8{ line_too_long, too_short, too_long_for_card, holds_pad };
    for (all, 0..) |one, index| {
        for (all[index + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, one, other));
            try testing.expect(std.mem.indexOf(u8, one, other) == null);
            try testing.expect(std.mem.indexOf(u8, other, one) == null);
        }
        // And every one of them still says the card was left alone, which is
        // the part a person acts on before anything else.
        try testing.expect(std.mem.indexOf(u8, one, "no try was spent") != null);
    }
}

test "the two refusals a length caused say the number that was typed" {
    // **The number is what a person acts on.** Somebody who typed twelve bytes
    // and reads "twelve" knows at once that what they typed is not a PIV PIN at
    // all, and on a YubiKey that is usually a real PIN of another application on
    // the same key. A rule with no number leaves them to measure their own
    // typing against it.
    //
    // Mutation check: answer `sentence()` from `sentenceWith` for either counted
    // outcome and that case fails on the number.
    var room: [max_sentence_len]u8 = undefined;

    const twelve = Outcome.pin_too_long_for_card.sentenceWith(12, &room);
    try testing.expect(std.mem.startsWith(u8, twelve, "12 bytes were typed"));
    try testing.expect(std.mem.indexOf(u8, twelve, "six to eight bytes") != null);

    const five = Outcome.pin_too_short.sentenceWith(5, &room);
    try testing.expect(std.mem.startsWith(u8, five, "5 bytes were typed"));

    // **A count of null is a caller that measured none**, and it gets the same
    // fact with no number rather than a wrong one.
    const no_count = Outcome.pin_too_long_for_card.sentenceWith(null, &room);
    try testing.expectEqualStrings(Outcome.pin_too_long_for_card.sentence(), no_count);

    // **A number is printed only where a length is the cause.** The pad byte is
    // refused at any length, so a number beside it would read as the cause.
    try testing.expect(!Outcome.pin_holds_pad.countsBytes());
    try testing.expectEqualStrings(
        Outcome.pin_holds_pad.sentence(),
        Outcome.pin_holds_pad.sentenceWith(6, &room),
    );
    // The same for every outcome no PIN shape caused, so a count that leaked in
    // from somewhere cannot change what any of them says.
    for (std.enums.values(Outcome)) |one| {
        if (one.countsBytes()) continue;
        try testing.expectEqualStrings(one.sentence(), one.sentenceWith(9, &room));
    }
}
