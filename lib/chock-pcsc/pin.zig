//! Asking a person for a card PIN, and the rules that stop the asking from
//! destroying their key.
//!
//! ## The counter is the dangerous part
//!
//! A PIV card counts wrong PINs and blocks after the last one. A blocked card
//! needs the PUK to come back, and a card whose PUK is also spent is scrap. So
//! three rules hold everywhere a PIN is asked for, and each one is a line of
//! code somewhere below or in `attempt.zig`:
//!
//! 1. **Never ask twice in one run.** There is no loop over `Asker.ask` in this
//!    module and there must never be one. A retry that a person did not start
//!    turns one wrong keystroke into a spent try, and three of those brick the
//!    key.
//! 2. **Say how many tries are left before anybody types.** The card reports the
//!    count, and asking for it costs nothing: a `VERIFY` with no data field is
//!    answered with the count and never counted as an attempt. `Question.tries`
//!    carries it to whoever draws the prompt.
//! 3. **A refusal is final for the run.** Nobody at the keyboard, an empty
//!    answer, a PIN of the wrong shape: each one ends the card path and the
//!    caller falls back and records the fallback.
//!
//! ## Nobody to ask is a refusal
//!
//! A subagent, a session `chock daemon` started, and a piped command all have
//! nobody at a keyboard. **An implementation of `Asker` reads that before it
//! writes a byte** and answers `nobody` at once, the way `chock-core/ask.zig`
//! does. A prompt drawn where nothing can answer it is a hang, and a hang in a
//! seal is worse than a software seal, because a software seal is recorded and
//! honest.
//!
//! ## Where the value goes, and every place it does not
//!
//! It goes from the keyboard into one `Buffer` in the frame that asked, from
//! there into one `VERIFY` command, and nowhere else. `lib/chock-broker/askpass.zig`
//! keeps the same discipline for a git password and states it at length.
//!
//! - **Not into the session log.** Sealing writes nothing into a log at all.
//! - **Not into an environment variable, and not onto a command line.** `ps`
//!   shows every argument to every other user of the machine, and a shell keeps
//!   them in a history file.
//! - **Not into a structure that outlives the call.** The comptime block at the
//!   end of `attempt.zig` fails the build if a long lived value grows a field
//!   that could hold one, which is the shape that mistake would take.
//! - **Not on the screen.** The terminal's echo is off while it is typed, and it
//!   is put back afterwards whatever happens. See `src/tty.zig`.
//!
//! Every buffer that held one is overwritten by `wipe` before its frame ends.

const std = @import("std");
const piv = @import("piv.zig");

/// The longest answer this reads.
///
/// **Longer than a PIN can be, on purpose.** A PIV PIN is six to eight bytes
/// and `piv.padPin` refuses anything else. A buffer of exactly eight would turn
/// a person's nine keystroke typing mistake into a wrong PIN of the first eight,
/// which the card would count as a spent try. With room to spare the mistake is
/// refused here and the card is never asked.
pub const max_pin_bytes = 64;

/// The one buffer a PIN is ever read into.
///
/// **A named type and not a bare array**, so a comptime block can prove that no
/// structure outliving one call holds one. See `attempt.zig`.
pub const Buffer = [max_pin_bytes]u8;

/// What the card said about its own counter, read without spending a try. Held
/// in `piv.zig`, because it is a fact the card states and this file only carries
/// it to a person.
pub const Tries = piv.Tries;

/// What a person is being asked, and everything they need to decide.
///
/// **It holds no answer and it never will.** The comptime block below fails the
/// build if a field appears that one could sit in.
pub const Question = struct {
    /// The reader the card is in, so a person with two cards knows which one is
    /// being asked about.
    reader: []const u8,
    /// The slot the key is in.
    slot: piv.Slot,
    /// What the card said about its counter. Shown before anybody types.
    tries: Tries,
};

/// What came back. Exactly one of these is true of one ask.
pub const Answer = union(enum) {
    /// The bytes typed, borrowed from the `Buffer` the asker was given.
    pin: []const u8,
    /// Nobody is at a keyboard. Read before a byte is written: see this file's
    /// own top comment. A terminal that goes away while the question is up says
    /// the same thing later, because the fact is the same one.
    nobody,
    /// Somebody was asked and gave nothing.
    declined,
    /// The terminal would not give an answer that could be kept off the screen.
    /// **Its own answer and not `declined`**, because a person who typed a PIN
    /// into a terminal that was still echoing needs to be told so.
    unreadable,
    /// More was typed than `Buffer` holds, so the whole line was refused and
    /// none of it was read.
    ///
    /// **Its own answer and not `declined`**, for the reason an empty answer is
    /// a decline and never a malformed PIN: the message has to follow what the
    /// person did. Telling somebody who typed a long line that they gave
    /// nothing is a false statement about them, the same fault the other way
    /// round.
    too_long,
};

/// Whoever can put the question to a person. One call, and it may be called more
/// than once in a run only because a slot with the `always` policy needs the PIN
/// before every signature. **It is never called twice for one signature.**
pub const Asker = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Ask, writing the answer into `out` and answering the part used.
        ask: *const fn (ptr: *anyopaque, question: Question, out: *Buffer) Answer,
    };

    pub fn ask(self: Asker, question: Question, out: *Buffer) Answer {
        return self.vtable.ask(self.ptr, question, out);
    }
};

/// Overwrite bytes that held a PIN. A buffer that is dropped and not overwritten
/// stays in this process's memory until something else happens to use it.
pub fn wipe(buffer: *Buffer) void {
    std.crypto.secureZero(u8, buffer);
}

// The question a person is shown holds no answer, and there is no shape for one
// to arrive in. This fails the build if a field appears that could carry one,
// the same guard `chock-broker/askpass.zig` keeps over its own log record.
comptime {
    const forbidden = [_][]const u8{ "pin", "secret", "password", "answer", "value", "code" };
    for (@typeInfo(Question).@"struct".fields) |field| {
        for (forbidden) |bad| {
            if (std.mem.indexOf(u8, field.name, bad) != null) {
                @compileError("a PIN question must not hold the answer: " ++ field.name);
            }
        }
    }
}

const testing = std.testing;

test "a count of zero tries left is the same fact as blocked" {
    // A caller that read the count and not the tag would offer a prompt to a
    // card that has nothing left to spend.
    try testing.expectEqual(@as(?u4, 0), (Tries{ .blocked = {} }).count());
    try testing.expectEqual(@as(?u4, 3), (Tries{ .left = 3 }).count());
    // And a card that named no count says so, rather than saying plenty.
    try testing.expectEqual(@as(?u4, null), (Tries{ .unknown = {} }).count());
    try testing.expectEqual(@as(?u4, null), (Tries{ .verified = {} }).count());
}

test "the buffer is longer than any PIN a card accepts" {
    // The mistake this width exists to stop: a person types nine digits, the
    // buffer holds eight, and the card counts a wrong PIN against a counter that
    // blocks after three.
    try testing.expect(max_pin_bytes > piv.pin_field_len);
    var buffer: Buffer = [_]u8{'7'} ** max_pin_bytes;
    wipe(&buffer);
    for (buffer) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test {
    testing.refAllDecls(@This());
}
