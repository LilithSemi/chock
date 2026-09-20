//! The hash chain over a session log. It finds an event that somebody changed
//! in the middle of a log. It does not stop a person who rewrites the whole
//! file and hashes every line again.

const std = @import("std");

const Hash = std.crypto.hash.sha2.Sha256;

pub const digest_len = Hash.digest_length * 2;

pub const Digest = [digest_len]u8;

pub const not_a_signature =
    "A hash chain is not a signature: whoever can rewrite the whole file can write a " ++
    "chain that agrees with it. What it finds is an edit in the middle.";

/// Hash the exact bytes of the line on disk, never a new serialization of the
/// parsed event: a difference in key order would then read as tampering.
pub fn of(bytes: []const u8) Digest {
    var digest: [Hash.digest_length]u8 = undefined;
    Hash.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

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

pub const Verdict = enum {
    intact,
    /// Not a pass: nothing here can say whether such a log was edited.
    unchained,
    partly_chained,
    broken,
    torn,
    undecodable,
    /// An absent answer is never a permissive answer.
    unreadable,
};

pub const Report = struct {
    verdict: Verdict = .unreadable,
    at: u64 = 0,
    after: u64 = 0,
    events: u64 = 0,
    chained: u64 = 0,

    pub fn edited(self: Report) bool {
        return self.verdict == .broken;
    }
};

pub const Ending = enum {
    complete,
    torn,
    undecodable,
};

/// It keeps reading after a break, and names only the first disagreement.
pub const Verifier = struct {
    expected: Digest,
    previous_id: u64 = 0,
    events: u64 = 0,
    chained: u64 = 0,
    found_break: bool = false,
    broken_at: u64 = 0,
    broken_after: u64 = 0,

    pub fn init(header: Digest) Verifier {
        return .{ .expected = header };
    }

    /// `prev` is empty for an event written before the chain existed.
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
        // Hash it even with no chain, so an unchained event cannot hide the next.
        self.expected = of(line);
        self.previous_id = id;
    }

    /// A break beats every other ending.
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
    const one = of("{\"id\":0}");
    try testing.expectEqual(@as(usize, 64), one.len);
    for (one) |c| try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));

    const other = of("{\"id\":1}");
    try testing.expect(!std.mem.eql(u8, &one, &other));

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
    const header = of("{\"chock_log\":1}");
    var v = Verifier.init(header);

    const first = "{\"id\":0,\"a\":1}";
    v.take(16, first, &header);

    const edited = "{\"id\":0,\"a\":9}";
    v.take(31, edited, &of(first));
    v.take(46, "{\"id\":0,\"a\":3}", &of("{\"id\":0,\"a\":2}"));
    v.take(61, "{\"id\":0,\"a\":4}", &of("{\"id\":0,\"a\":3}"));

    const report = v.finish(.complete, 0);
    try testing.expectEqual(Verdict.broken, report.verdict);
    try testing.expect(report.edited());
    try testing.expectEqual(@as(u64, 46), report.at);
    try testing.expectEqual(@as(u64, 31), report.after);
    try testing.expectEqual(@as(u64, 4), report.events);
}

test "a break at the very first event points back at the header" {
    const header = of("{\"chock_log\":1}");
    var v = Verifier.init(header);
    v.take(16, "{\"id\":0,\"a\":1}", &of("{\"chock_log\":2}"));

    const report = v.finish(.complete, 0);
    try testing.expectEqual(Verdict.broken, report.verdict);
    try testing.expectEqual(@as(u64, 16), report.at);
    try testing.expectEqual(@as(u64, 0), report.after);
}

test "a log with no chain at all is read, and never called intact" {
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

    var wrong = Verifier.init(header);
    wrong.take(16, old_first, "");
    wrong.take(31, old_second, "");
    wrong.take(46, new_first, &of("something else entirely"));
    try testing.expectEqual(Verdict.broken, wrong.finish(.complete, 0).verdict);
}

test "a torn last line is truncation and never tampering" {
    const header = of("{\"chock_log\":1}");
    var v = Verifier.init(header);
    v.take(16, "{\"id\":0,\"a\":1}", &header);

    const report = v.finish(.torn, 31);
    try testing.expectEqual(Verdict.torn, report.verdict);
    try testing.expect(!report.edited());
    try testing.expectEqual(@as(u64, 31), report.at);
    try testing.expectEqual(@as(u64, 1), report.events);
    try testing.expectEqual(@as(u64, 1), report.chained);
}

test "a log edited in the middle and torn at the end is reported as edited" {
    const header = of("{\"chock_log\":1}");
    var v = Verifier.init(header);
    v.take(16, "{\"id\":0,\"a\":1}", &header);
    v.take(31, "{\"id\":0,\"a\":2}", &of("not what is there"));

    const report = v.finish(.torn, 46);
    try testing.expectEqual(Verdict.broken, report.verdict);
    try testing.expectEqual(@as(u64, 31), report.at);
}

test "a line that will not decode is its own answer, and not a tear" {
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
    const nothing = Report{};
    try testing.expectEqual(Verdict.unreadable, nothing.verdict);
    try testing.expect(!nothing.edited());
}
