//! The hash chain over a session log. Every event carries the hash of the line
//! written before it, so a change to one event in the middle of a log is found
//! rather than only unlikely.
//!
//! The log is already this project's record. Every command folds it, a session
//! replays from it, and `chock sessions` reads it. The chain is what makes that
//! record evidence against a person who edits it, and not only against a crash.
//!
//! ## A hash chain is not a signature
//!
//! **Anybody who can rewrite the whole file can hash every line again and write
//! a chain that agrees with the new text.** This module does not stop that and
//! cannot. What it defeats is an edit in the middle: a line changed in place
//! leaves the line after it carrying the hash of bytes that are no longer
//! there, and that is what `verdict.broken` names. An edit in the middle is the
//! realistic case, because it is the cheap one.
//!
//! A reader who takes `intact` for proof that nothing was ever changed is
//! reading more than this gives. Evidence a rewrite cannot forge needs a second
//! party: a key this process cannot read, or a copy of the digest kept where
//! the writer cannot reach it. Chock has neither today. `not_a_signature` is
//! that same sentence in one line, so a command can print it and the two cannot
//! drift apart.
//!
//! ## What is hashed
//!
//! The exact bytes of a line as they sit on disk, without the newline that
//! closes it. **Never a fresh serialization of the parsed event.** A verifier
//! that encoded the envelope again would compare its own JSON with the
//! writer's, and a difference in key order, in the form of a number, or in the
//! escape of one character would then read as tampering. The bytes on disk are
//! the only thing both sides can agree on.
//!
//! The first event's `prev` is the hash of the log's header line, so the chain
//! is anchored to the header instead of starting in the air. A header swapped
//! for another is found at the first event.
//!
//! ## An empty `prev` is a log, not a fault
//!
//! Every log written before this field existed carries no chain at all, and
//! those logs stay readable. An event with an empty `prev` is counted, passed
//! over, and still hashed for the event that follows it, so a log an old build
//! started and a new build continued verifies over the part that is chained.
//! `Report` says how many of the events it read carried a chain. See
//! `Verdict.unchained` and `Verdict.partly_chained`.
//!
//! ## Compaction folds the context, never the log
//!
//! A naive hash chain breaks the moment something removes an event from the
//! middle of the file, and compaction is the one thing in Chock that sounds
//! like it does that. It does not. `lib/chock-core/compaction.zig` says it in
//! its own first lines: **a compaction summarises the context the model sees
//! and deletes nothing from the log.** It is one more appended event,
//! `compaction`, carrying `from_id`, `through_id` and `kept_ranges`, and a
//! replay of the same log builds the same shorter context again.
//!
//! So the chain runs over every line the file holds, in file order, and a
//! compacted session verifies exactly like any other. The events named in
//! `from_id .. through_id` are all still there to be hashed, including the ones
//! `kept_ranges` did not keep in the context.
//!
//! That is a fact about the current design and not a law of nature, which is
//! why `storage.zig` holds a test that appends a compaction over a real span
//! and then reads every event of that span back out of the log. A later
//! compaction that rewrote the file would fail that test, and the failure is
//! the message: the chain is what such a rewrite breaks.
//!
//! ## A torn line is not a broken chain
//!
//! A write that reached the kernel without its closing newline is a crash or a
//! power loss, and `log.Replay` already reports it as `truncated`. It is a
//! different fact from a hash that does not match, so it is a different verdict
//! here. Nothing was ever committed inside a fragment: the log calls `sync`
//! only after a whole line reached the kernel, so a fragment is work that was
//! never durable rather than work somebody took away.

const std = @import("std");

/// The hash. SHA-256, because it is the digest a reader can check with a tool
/// they already have and because `lib/chock-policy/table.zig` and
/// `lib/chock-nix/DevShell.zig` already use it, so this project holds one
/// answer to "which hash" and not three.
const Hash = std.crypto.hash.sha2.Sha256;

/// How many characters a digest takes on the wire. Lowercase hexadecimal, two
/// characters a byte.
pub const digest_len = Hash.digest_length * 2;

/// One digest, as it is written into an envelope's `prev` field: lowercase
/// hexadecimal, no prefix, fixed width.
pub const Digest = [digest_len]u8;

/// The one sentence a reader needs about what this defeats and what it does
/// not. Held here, beside the mechanism, so a command prints the same words
/// this module's own top comment argues for.
pub const not_a_signature =
    "A hash chain is not a signature: whoever can rewrite the whole file can write a " ++
    "chain that agrees with it. What it finds is an edit in the middle.";

/// The digest of `bytes`. Give it one line, without the newline that closes
/// it.
pub fn of(bytes: []const u8) Digest {
    var digest: [Hash.digest_length]u8 = undefined;
    Hash.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// A digest built from more than one piece, for a caller reading a line off a
/// disk in chunks. `of` is the whole line in one call, for a caller that
/// already holds it.
pub const Hasher = struct {
    inner: Hash = Hash.init(.{}),

    pub fn update(self: *Hasher, bytes: []const u8) void {
        self.inner.update(bytes);
    }

    pub fn finish(self: *Hasher) Digest {
        var digest: [Hash.digest_length]u8 = undefined;
        self.inner.final(&digest);
        return std.fmt.bytesToHex(digest, .lower);
    }
};

/// What reading a whole log's chain found.
pub const Verdict = enum {
    /// Every event that was read carried the hash of the one before it, and
    /// every one of them agreed. An empty log is `intact`: it has nothing that
    /// can disagree.
    intact,
    /// The log holds events and not one of them carries a chain. This is what
    /// every log written before the chain existed looks like, and it is read
    /// rather than refused. **It is not a pass.** Nothing here can say whether
    /// such a log was edited.
    unchained,
    /// Some events carry a chain, some do not, and every chain that is there
    /// agrees. An old build appending after a new one looks like this. So does
    /// somebody stripping the field off a run of events, which is why this is
    /// its own answer and not `intact`: read `Report.chained` against
    /// `Report.events` and decide.
    partly_chained,
    /// An event names a previous hash that the line before it does not have.
    /// **Somebody changed this log after it was written.** `Report.at` names
    /// the event that disagreed and `Report.after` names the one before it, so
    /// the change is between those two.
    broken,
    /// The last line of the log has no closing newline: a write that reached
    /// the kernel and never finished. **A crash or a power loss, and not an
    /// edit.** `Report.at` is where the fragment starts.
    torn,
    /// A line that is complete, newline and all, would not parse as an event.
    /// A different fault from a tear, because a tear can only ever be the last
    /// line and this can be any of them. `Report.at` names where it starts.
    undecodable,
    /// The log could not be opened or read at all, so nothing was verified.
    /// **Never read as a pass**: an absent answer is never a permissive answer.
    unreadable,
};

/// What one reading of a log's chain found, whole.
pub const Report = struct {
    verdict: Verdict = .unreadable,
    /// The byte offset the verdict is about, when it is about one: the event
    /// whose `prev` disagreed, the start of the torn fragment, or the start of
    /// the line that would not decode. Zero otherwise.
    at: u64 = 0,
    /// For `broken` only: the event before `at`, whose bytes are what hashed
    /// differently. The change sits between this event and `at`. Zero when the
    /// event before `at` is the header line, which is offset zero anyway.
    after: u64 = 0,
    /// How many events the reading got through.
    events: u64 = 0,
    /// How many of those carried a chain at all.
    chained: u64 = 0,

    /// Whether this reading found a change somebody made. Only `broken` is
    /// that. A tear, a line that will not decode, and a log nothing could open
    /// are all faults, and not one of them is proof of an edit.
    pub fn edited(self: Report) bool {
        return self.verdict == .broken;
    }
};

/// How the reading of a log ended, which the caller knows and this file cannot
/// see.
pub const Ending = enum {
    /// The file ended exactly where its last line ended.
    complete,
    /// The last line has no closing newline. See `Verdict.torn`.
    torn,
    /// A complete line would not parse. See `Verdict.undecodable`.
    undecodable,
};

/// Reads a log's chain, one line at a time, and holds no memory of the lines
/// themselves. Seed it with the digest of the header line, feed it every event
/// line in file order, then ask `finish`.
///
/// **It keeps reading after it finds a break.** Only the first disagreement is
/// named, because that is where the change is, and carrying on past it is what
/// lets `events` count the whole file rather than stopping at the fault. A
/// single event changed in place breaks the chain once and then agrees again,
/// since every following event is hashed against the line that really is
/// before it.
pub const Verifier = struct {
    /// The digest the next event's `prev` must carry.
    expected: Digest,
    /// The identifier of the line `expected` was taken from. The header line's
    /// own offset is zero, which is what this starts at.
    previous_id: u64 = 0,
    events: u64 = 0,
    chained: u64 = 0,
    found_break: bool = false,
    broken_at: u64 = 0,
    broken_after: u64 = 0,

    /// A verifier anchored to a log's header line.
    pub fn init(header: Digest) Verifier {
        return .{ .expected = header };
    }

    /// Take one complete event line. `id` is the byte offset the line starts
    /// at, which is the event's identifier. `line` is the bytes of that line
    /// with no closing newline, exactly as they sit on disk. `prev` is the
    /// `prev` field read out of that same line, empty for an event written
    /// before the chain existed.
    pub fn take(self: *Verifier, id: u64, line: []const u8, prev: []const u8) void {
        self.events += 1;
        if (prev.len != 0) {
            self.chained += 1;
            if (!self.found_break and !std.mem.eql(u8, prev, &self.expected)) {
                self.found_break = true;
                self.broken_at = id;
                self.broken_after = self.previous_id;
            }
        }
        // Hashed whether or not it carried a chain of its own, so an event with
        // no `prev` does not hide the event after it: that one is still
        // measured against the real bytes in front of it.
        self.expected = of(line);
        self.previous_id = id;
    }

    /// The whole reading. `at` is only read for a `torn` or `undecodable`
    /// ending, and names where that line starts.
    ///
    /// **A break beats every other answer.** A log edited in the middle and
    /// then torn at the end is reported as edited: the tear at the end explains
    /// nothing about a hash that disagreed a thousand events earlier, and
    /// naming the smaller fault would bury the larger one.
    pub fn finish(self: Verifier, ending: Ending, at: u64) Report {
        if (self.found_break) return .{
            .verdict = .broken,
            .at = self.broken_at,
            .after = self.broken_after,
            .events = self.events,
            .chained = self.chained,
        };

        const verdict: Verdict = switch (ending) {
            .torn => .torn,
            .undecodable => .undecodable,
            .complete => if (self.chained == self.events)
                .intact
            else if (self.chained == 0)
                .unchained
            else
                .partly_chained,
        };
        return .{
            .verdict = verdict,
            .at = if (ending == .complete) 0 else at,
            .events = self.events,
            .chained = self.chained,
        };
    }
};

const testing = std.testing;

test "a digest is fixed width lowercase hexadecimal, and one byte changes it" {
    // The width is what an envelope's `prev` field is compared against, and a
    // digest of another shape would make every comparison below meaningless.
    const one = of("{\"id\":0}");
    try testing.expectEqual(@as(usize, 64), one.len);
    for (one) |c| try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));

    const other = of("{\"id\":1}");
    try testing.expect(!std.mem.eql(u8, &one, &other));

    // The same bytes always give the same answer, whether they arrive whole or
    // in pieces. The file backed reader hashes a line in chunks, so these two
    // paths must not be able to disagree.
    var pieces: Hasher = .{};
    pieces.update("{\"id\"");
    pieces.update(":0}");
    try testing.expectEqualStrings(&one, &pieces.finish());
}

test "an unbroken chain over three events reads as intact" {
    const header = of("{\"chock_log\":1}");
    var v = Verifier.init(header);

    const first = "{\"id\":0,\"a\":1}";
    v.take(16, first, &header);
    const second = "{\"id\":0,\"a\":2}";
    v.take(31, second, &of(first));
    v.take(46, "{\"id\":0,\"a\":3}", &of(second));

    const report = v.finish(.complete, 0);
    try testing.expectEqual(Verdict.intact, report.verdict);
    try testing.expectEqual(@as(u64, 3), report.events);
    try testing.expectEqual(@as(u64, 3), report.chained);
    try testing.expect(!report.edited());
}

test "an event whose recorded hash disagrees is named, and only the first one is" {
    // The realistic attack: one event changed in place. The changed line still
    // carries whatever `prev` it always had, so it passes. The event after it
    // is the one that names bytes that are no longer there.
    const header = of("{\"chock_log\":1}");
    var v = Verifier.init(header);

    const first = "{\"id\":0,\"a\":1}";
    v.take(16, first, &header);

    // Event 31 was written after a line reading `...\"a\":2}`. Somebody has
    // since changed that line to `...\"a\":9}`, so the hash event 46 carries no
    // longer matches what sits in front of it.
    const edited = "{\"id\":0,\"a\":9}";
    v.take(31, edited, &of(first));
    v.take(46, "{\"id\":0,\"a\":3}", &of("{\"id\":0,\"a\":2}"));
    // A fourth event, hashed against the third for real, agrees again. Without
    // `found_break` this would overwrite the answer and the log would read as
    // whole.
    v.take(61, "{\"id\":0,\"a\":4}", &of("{\"id\":0,\"a\":3}"));

    const report = v.finish(.complete, 0);
    try testing.expectEqual(Verdict.broken, report.verdict);
    try testing.expect(report.edited());
    // The event that disagreed, and the one before it. The change is between
    // them, and it is event 31 that was changed.
    try testing.expectEqual(@as(u64, 46), report.at);
    try testing.expectEqual(@as(u64, 31), report.after);
    // And it still counted the whole file rather than stopping at the fault.
    try testing.expectEqual(@as(u64, 4), report.events);
}

test "a break at the very first event points back at the header" {
    // The anchor. A header swapped for another is found here and nowhere else,
    // because no event before the first one can carry its hash.
    const header = of("{\"chock_log\":1}");
    var v = Verifier.init(header);
    v.take(16, "{\"id\":0,\"a\":1}", &of("{\"chock_log\":2}"));

    const report = v.finish(.complete, 0);
    try testing.expectEqual(Verdict.broken, report.verdict);
    try testing.expectEqual(@as(u64, 16), report.at);
    try testing.expectEqual(@as(u64, 0), report.after);
}

test "a log with no chain at all is read, and never called intact" {
    // Every log written before the chain existed looks like this, and refusing
    // it would make those sessions unreadable forever. It is also not a pass:
    // nothing can say whether such a log was edited.
    var v = Verifier.init(of("{\"chock_log\":1}"));
    v.take(16, "{\"id\":0,\"a\":1}", "");
    v.take(31, "{\"id\":0,\"a\":2}", "");

    const report = v.finish(.complete, 0);
    try testing.expectEqual(Verdict.unchained, report.verdict);
    try testing.expectEqual(@as(u64, 2), report.events);
    try testing.expectEqual(@as(u64, 0), report.chained);
    try testing.expect(!report.edited());
}

test "an old log a new build carried on is partly chained, and the chained part is checked" {
    // Two events from before the chain, then two after. The first chained
    // event's `prev` is the hash of the unchained line in front of it, which is
    // exactly what a writer computes off the file rather than off its own
    // memory of what it wrote.
    const header = of("{\"chock_log\":1}");
    var v = Verifier.init(header);

    const old_first = "{\"id\":0,\"a\":1}";
    const old_second = "{\"id\":0,\"a\":2}";
    v.take(16, old_first, "");
    v.take(31, old_second, "");
    const new_first = "{\"id\":0,\"a\":3}";
    v.take(46, new_first, &of(old_second));
    v.take(61, "{\"id\":0,\"a\":4}", &of(new_first));

    const report = v.finish(.complete, 0);
    try testing.expectEqual(Verdict.partly_chained, report.verdict);
    try testing.expectEqual(@as(u64, 4), report.events);
    try testing.expectEqual(@as(u64, 2), report.chained);

    // And the chained half is genuinely checked, not merely counted: the same
    // sequence with a wrong hash on the first new event is broken.
    var wrong = Verifier.init(header);
    wrong.take(16, old_first, "");
    wrong.take(31, old_second, "");
    wrong.take(46, new_first, &of("something else entirely"));
    try testing.expectEqual(Verdict.broken, wrong.finish(.complete, 0).verdict);
}

test "a torn last line is truncation and never tampering" {
    // The two answers this whole module has to keep apart. Somebody edited this
    // and the power went out are not the same fact, and a reader acts on them
    // differently.
    const header = of("{\"chock_log\":1}");
    var v = Verifier.init(header);
    v.take(16, "{\"id\":0,\"a\":1}", &header);

    const report = v.finish(.torn, 31);
    try testing.expectEqual(Verdict.torn, report.verdict);
    try testing.expect(!report.edited());
    try testing.expectEqual(@as(u64, 31), report.at);
    // The events before the tear were still read and still checked.
    try testing.expectEqual(@as(u64, 1), report.events);
    try testing.expectEqual(@as(u64, 1), report.chained);
}

test "a log edited in the middle and torn at the end is reported as edited" {
    // The precedence rule, and the one case where two faults are present at
    // once. A tear at the end explains nothing about a hash that disagreed
    // earlier, so naming the tear would bury the edit.
    const header = of("{\"chock_log\":1}");
    var v = Verifier.init(header);
    v.take(16, "{\"id\":0,\"a\":1}", &header);
    v.take(31, "{\"id\":0,\"a\":2}", &of("not what is there"));

    const report = v.finish(.torn, 46);
    try testing.expectEqual(Verdict.broken, report.verdict);
    try testing.expectEqual(@as(u64, 31), report.at);
}

test "a line that will not decode is its own answer, and not a tear" {
    // A tear can only ever be the last line of a file. A line that is complete
    // and will not parse can be any of them, so the two cannot share a verdict.
    const header = of("{\"chock_log\":1}");
    var v = Verifier.init(header);
    v.take(16, "{\"id\":0,\"a\":1}", &header);

    const report = v.finish(.undecodable, 31);
    try testing.expectEqual(Verdict.undecodable, report.verdict);
    try testing.expectEqual(@as(u64, 31), report.at);
    try testing.expect(!report.edited());
}

test "an empty log is intact, because it holds nothing that can disagree" {
    var v = Verifier.init(of("{\"chock_log\":1}"));
    const report = v.finish(.complete, 0);
    try testing.expectEqual(Verdict.intact, report.verdict);
    try testing.expectEqual(@as(u64, 0), report.events);
}

test "a report that could not be built at all is unreadable, never a pass" {
    // The default. An absent answer is never a permissive answer, the rule a
    // policy keeps and this keeps for a log.
    const nothing = Report{};
    try testing.expectEqual(Verdict.unreadable, nothing.verdict);
    try testing.expect(!nothing.edited());
}
