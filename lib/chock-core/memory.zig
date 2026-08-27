//! The knowledgebase, written out: what an agent worked out in one session
//! and does not have to work out again in the next.
//!
//! **Do not confuse this with `instructions.zig` next door.** Two different
//! things wear the name "memory file", and conflating them is the fault to
//! avoid:
//!
//! | | Written by | Trust | Lives |
//! |---|---|---|---|
//! | project instructions | a person | what the user chose | in the project |
//! | a knowledgebase entry | **the agent** | **data, never instruction** | outside the project |
//!
//! ## The hazard, which is real
//!
//! A writable memory directory is two things at once: a place to keep notes,
//! and a channel out of the sandbox that does not pass through
//! `workspace.apply`. It is also a persistence mechanism, because a note
//! written this session is read next session.
//!
//! **An agent that writes its own instructions has written its own prompt for
//! next time**, which is the same fault as an agent editing `chock.zon`
//! reached by a slower route. And a memory written by a compromised session
//! is a persistent injection into every future session which survives the
//! sandbox by construction, because outliving the sandbox is what memory is
//! for.
//!
//! Three rules hold it, and none is expensive:
//!
//! 1. **A note is data, never an instruction.** It arrives in the next
//!    session under a heading that says the agent wrote it, and the prompt
//!    says a model weighing its own past note against the user's request
//!    prefers the user. See `prompt.zig`.
//! 2. **Bound it.** `max_body_bytes` per entry and `max_entries` per project.
//!    A memory directory is not a place to move a repository through one file
//!    at a time. `validName` is the other half: a name is a plain name, so
//!    there is no path to leave the directory through.
//! 3. **Show it.** `chock memory` reads and clears it. Memory a user cannot
//!    inspect is memory a user cannot trust, and clearing it is one command.
//!
//! ## The prompt carries the index, never the bodies
//!
//! Two hundred entries cost two hundred short lines and nothing more until
//! the agent calls `read_memory`. Loading every body would defeat the whole
//! purpose on the models this is meant to help most. `index.zig` is the
//! mechanism, shared with the guidance shelf and the subtree instruction
//! files, and `prompt.zig` holds the test that pins the size against the
//! entry count. **That is the property the whole design rests on, and it is
//! the one a later change would break in silence.**
//!
//! ## Staleness is a normal state, not an error
//!
//! A fact about the code that was true in March is a lie in August, and an
//! agent that trusts it confidently is worse than one that knew nothing. So
//! every entry carries the time it was written, the prompt tells an agent to
//! check that a file or a function an entry names still exists, and an entry
//! naming something that is gone is still readable rather than fatal.
//!
//! **Write a fact, not a status.** "The kernel takes the last matching mount"
//! stays true. "The build is broken" was false within minutes when a memory
//! written during this project's own work said it, and a later reader who
//! trusted it would have gone looking for a fault that was not there. A
//! knowledgebase of statuses is a stale dashboard. What the session was doing
//! belongs in the session log, which already holds it.
//!
//! **Supersede over duplicate.** An entry is fetched by name, and writing a
//! name that already exists supersedes that entry. So correcting an entry is
//! the ordinary path and not a special one, and a knowledgebase cannot fill
//! with six versions of the same fact with no way to tell which is current.
//!
//! ## Superseding adds a version. It never removes one
//!
//! **The write used to replace the file, so an agent could erase what it, or
//! an earlier session, had written.** A memory an agent can quietly empty is
//! not a record of anything. This is the same fault as an agent editing its
//! own prompt, reached by a slower route: the note the user would have read
//! is gone, and nothing says it was ever there.
//!
//! So an entry file holds every version that was written under that name,
//! and a write adds one. **The shape is the session log's.** `state.zig`
//! folds an append only log into the state of a session, and the state is
//! what a reader sees while the log keeps every event. Here the fold is
//! trivial: the current entry is the newest version, and `parse` gives it.
//! `versions` walks the rest.
//!
//! That is not a conflict with the supersede rule above. It is the same rule
//! kept the way the log keeps it: **superseding is what the fold does, not
//! what the file does.**
//!
//! **The newest version is first in the file, not last.** A log appends, and
//! reading one forward is how `state.zig` reaches the current state. This
//! file cannot afford that read: `list` builds the prompt index from the
//! header of every entry in the project and must never read a body, and
//! `read_memory` gives the model one version and must not spend the context
//! on the ones it superseded. Both want the newest header at a fixed place,
//! and the front of the file is the only such place. Nothing else changes:
//! no version is dropped, the order is total, and `cat` shows the current
//! fact first and its history under it, which is the order a person reads in
//! as well.
//!
//! ## The bounds, and what they now count
//!
//! Past `max_versions` a write is refused and says so. **Dropping the oldest
//! version instead would give back exactly what this section took away**,
//! since an agent that wanted a fact gone could write the name until the
//! fact fell off the end. A refusal costs an agent one turn and a new name.
//!
//! ## The file format
//!
//! One version is a header of `key: value` lines, a blank line, and the body.
//! A file is one or more of those, newest first, each with a blank line
//! between. Plain text on purpose: a user reads these with `cat` and greps
//! them, and a format that needed a parser to read would be one more reason
//! not to look.

const std = @import("std");
const index = @import("index.zig");

/// Where the memory directory is mounted inside the sandbox, for the one
/// tool call that reads it and the one that writes it. **No other tool call
/// carries this mount at all**, so the memory directory is not merely read
/// only to the rest of the sandbox: it is not there. See
/// `lib/chock-core/tools.zig`'s own `readMemory` and `writeMemory`.
///
/// Under `chock-sandbox`'s own runtime prefix, where every path of Chock's
/// own inside a sandbox lives. Spelled here rather than imported, because
/// this file holds no other sandbox concept and importing one for a string
/// would tie the knowledgebase to the sandbox it happens to run behind.
pub const sandbox_dir = "/run/chock/memory";

/// The file extension every entry carries. Markdown, because the body is
/// prose a person reads.
pub const extension = ".md";

/// The longest an entry's name may be. The name is the file name and the
/// index line, so it is short on purpose.
pub const max_name_bytes: usize = 64;

/// The longest **one version's** body may be. One fact does not need more,
/// and a memory directory is not a place to move a repository through one
/// file at a time. A file holding several versions is bounded by
/// `max_entry_bytes` instead.
pub const max_body_bytes: usize = 16 * 1024;

/// How many **names** one project may keep. Not versions: a name that already
/// exists takes another version and never another entry, so correcting a fact
/// never meets this cap. Past this, a write is refused and says so, so the
/// agent prunes rather than growing an index nobody reads.
pub const max_entries: usize = 128;

/// How many versions one name may keep. Past this a write is refused, and
/// this file's own top comment says why the oldest version is not dropped
/// instead.
///
/// Sixteen, because that is deep enough that no honest correcting run reaches
/// it, and shallow enough that the whole history of one name is something a
/// person reads in one sitting.
pub const max_versions: usize = 16;

/// The most one entry file may hold, over every version in it: the bound a
/// reader of a whole file gives its read. `max_versions` bodies at
/// `max_body_bytes`, and a generous allowance over each for the header.
pub const max_entry_bytes: usize = max_versions * (max_body_bytes + 4 * 1024);

/// What kind of thing one entry holds. **Not decoration**: the kind is what
/// tells a reader how fast the entry goes stale. A convention outlives a
/// fact about the code, and a dead end outlives both.
pub const Kind = enum {
    /// Something that was worked out, that the code does not say.
    insight,
    /// A fact about this code: a behaviour, an ordering that matters.
    code_fact,
    /// A project convention that is real and written nowhere.
    convention,
    /// A surprising behaviour that costs time to rediscover.
    gotcha,
    /// **The most undervalued entry of all.** "We tried X, it does not work,
    /// because Y" saves the next agent the whole detour, and nobody ever
    /// thinks to write it down.
    dead_end,
    /// Where the test server is, what the build actually needs.
    environment,

    pub fn parse(text: []const u8) ?Kind {
        return std.meta.stringToEnum(Kind, text);
    }
};

/// One fact. **One fact**: an entry holding five things cannot be superseded
/// when one of them changes.
pub const Entry = struct {
    /// Short and stable. This is how the entry is fetched, and writing it
    /// again supersedes this entry rather than making a second one.
    name: []const u8,
    /// One line, which is what the index in the prompt carries.
    description: []const u8,
    kind: Kind,
    /// When it was written, as `YYYY-MM-DDThh:mm:ssZ`. See `now`.
    ///
    /// **A time, and not only a day, because two entries written in one
    /// session need an order.** A session here runs for hours, so an entry
    /// and its own correction five hours later carry the same day and the
    /// same session identifier. A reader holding both wants to know which
    /// came first, and only the clock answers that.
    ///
    /// **This orders the versions of one name, so it is load bearing and no
    /// longer only informational.** A file holds every version that was
    /// written under its name, and this is what says which of two is the
    /// correction. See this file's top comment.
    written_at: []const u8,
    /// Which session wrote it. Empty when the writer had no session.
    session: []const u8 = "",
    /// Which version of this name, counting from one. `addVersion` sets it,
    /// so nothing else has to work it out. An entry written before this field
    /// existed reads as version 1, which is what it is.
    ///
    /// **The newest version's number is how many versions the file holds**,
    /// which is what lets `list` report the history from a read of the front
    /// of the file alone.
    version: usize = 1,
    body: []const u8,
};

pub const NameError = error{
    /// The name is empty, too long, or holds a character that is not a plain
    /// name character. **A name is a file name**, so this is what stands
    /// between the model and a path of its own choosing.
    BadName,
};

/// Whether `name` is one Chock will turn into a file name.
///
/// Lower case letters, digits, `-` and `_`, and nothing else. No dot, so
/// there is no `.` and no `..`; no slash, so there is no directory; no
/// leading `-`, so no program reads it as an option.
///
/// **This is a whitelist and not a check for the dangerous shapes.** A
/// blacklist of `..` and `/` is a list somebody has to keep complete, and
/// the set of characters a plain name needs is small enough to write down.
pub fn checkName(name: []const u8) NameError!void {
    if (name.len == 0 or name.len > max_name_bytes) return error.BadName;
    if (name[0] == '-' or name[0] == '_') return error.BadName;
    for (name) |byte| switch (byte) {
        'a'...'z', '0'...'9', '-', '_' => {},
        else => return error.BadName,
    };
}

/// `name` plus the extension. Caller owns the result.
pub fn fileName(allocator: std.mem.Allocator, name: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}" ++ extension, .{name});
}

/// One version of an entry: the header, a blank line, and the body. Caller
/// owns the result.
///
/// **This is one version and not a whole file.** `addVersion` is what builds
/// a file, by putting this on top of the versions that are already there.
///
/// **Chock writes this, never the model.** The model gives fields and this
/// puts them in the format, so a body holding something that looks like a
/// header line cannot become one: `parse` stops at the first blank line and
/// everything after it is body, whatever it looks like. `bytes` carries that
/// property across a version boundary as well: a reader takes exactly that
/// many bytes of body, so a body holding a whole forged version is read as
/// what it is, text.
pub fn serialize(allocator: std.mem.Allocator, entry: Entry) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    // The description is put through `oneLine` here rather than trusted,
    // because a description carrying a newline would make the header
    // ambiguous and would cost more than one line of prompt.
    const description = try index.oneLine(allocator, entry.description);
    defer allocator.free(description);

    // A body always ends in a newline in the file, so the version that
    // follows it starts on a line of its own. That added byte is part of the
    // body, so `bytes` counts it.
    const added_newline: usize =
        if (entry.body.len != 0 and entry.body[entry.body.len - 1] != '\n') 1 else 0;

    try out.print(allocator, "name: {s}\n", .{entry.name});
    try out.print(allocator, "kind: {t}\n", .{entry.kind});
    try out.print(allocator, "version: {d}\n", .{entry.version});
    try out.print(allocator, "written_at: {s}\n", .{entry.written_at});
    try out.print(allocator, "session: {s}\n", .{entry.session});
    try out.print(allocator, "bytes: {d}\n", .{entry.body.len + added_newline});
    try out.print(allocator, "description: {s}\n", .{description});
    try out.appendSlice(allocator, "\n");
    try out.appendSlice(allocator, entry.body);
    if (added_newline == 1) try out.append(allocator, '\n');
    return out.toOwnedSlice(allocator);
}

/// The whole file for a name that already holds `existing`, once `entry` is
/// written under that name. Caller owns the result.
///
/// **This is what makes a write add rather than replace.** `existing` is
/// carried through byte for byte, so no version an earlier write put there
/// can be lost by this one. `entry.version` is set here from the version
/// already on top, so a caller never has to count.
///
/// `existing` may be empty, which is a name nothing has been written under
/// yet, and it may be a file a person edited by hand, which reads as one
/// version. See `parse`.
pub fn addVersion(
    allocator: std.mem.Allocator,
    existing: []const u8,
    entry: Entry,
) std.mem.Allocator.Error![]u8 {
    var next = entry;
    next.version = versionsIn(existing) + 1;

    const head = try serialize(allocator, next);
    if (existing.len == 0) return head;
    defer allocator.free(head);

    // A blank line between two versions. The reader does not need it, since
    // `bytes` already says where the body ends, but a person reading the file
    // does.
    return std.mem.concat(allocator, u8, &.{ head, "\n", existing });
}

/// How many versions an entry file holds. Zero for a name nothing was written
/// under, and one for a file a person wrote by hand with no `version` header.
///
/// **The newest version is first**, so this is a read of the front of the
/// file and never a walk of the whole of it. See this file's top comment.
pub fn versionsIn(text: []const u8) usize {
    if (text.len == 0) return 0;
    const top = parse(text) catch return 0;
    return top.version;
}

pub const ParseError = error{
    /// The file has no header, or the header has no `name`. A file somebody
    /// dropped in the directory by hand, most likely.
    NotAnEntry,
};

/// Read one entry back. Every field is a slice of `text` and nothing is
/// allocated, so the caller keeps `text` alive for as long as the result.
///
/// **A field this build does not know is skipped, not refused.** A newer
/// Chock may write one, and an entry that is otherwise readable must stay
/// readable: this is the same rule the session log already keeps for an
/// event kind it does not know.
///
/// **An unknown kind reads as `insight`, and a missing time reads as
/// empty.** Staleness is a normal state, and so is an entry a person edited
/// by hand. Neither is a reason to make a knowledgebase unreadable.
///
/// **A `date` header still reads, into `written_at`.** Entries written before
/// this field carried a clock hold `date: YYYY-MM-DD`, which is the same
/// format one day shorter, so it sorts against a full timestamp exactly as it
/// should: every entry of that day comes before every entry timed later in
/// it. Refusing those entries, or dropping the day they do carry, would throw
/// away a knowledgebase to gain nothing.
///
/// **This reads the newest version, which is the one at the front.** Every
/// older version is under it, and `versions` walks them. A file with no
/// `version` header is one version, which is what a file written before this
/// field existed is.
pub fn parse(text: []const u8) ParseError!Entry {
    return (try parseRecord(text)).entry;
}

/// One version, and the bytes of `text` that come after it.
const Record = struct {
    entry: Entry,
    rest: []const u8,
};

fn parseRecord(text: []const u8) ParseError!Record {
    var entry: Entry = .{
        .name = "",
        .description = "",
        .kind = .insight,
        .written_at = "",
        .session = "",
        .body = "",
    };
    // Null for a file written before the header carried it. Such a file holds
    // one version, so the whole of the rest of it is that version's body.
    var declared_body_bytes: ?usize = null;

    var rest = text;
    while (rest.len != 0) {
        const line_end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..line_end];
        rest = if (line_end == rest.len) rest[rest.len..] else rest[line_end + 1 ..];

        // The blank line ends the header. Everything after it is body,
        // whatever it looks like.
        if (std.mem.trim(u8, line, " \t\r").len == 0) break;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..colon], " \t\r");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t\r");

        if (std.mem.eql(u8, key, "name")) {
            entry.name = value;
        } else if (std.mem.eql(u8, key, "description")) {
            entry.description = value;
        } else if (std.mem.eql(u8, key, "kind")) {
            entry.kind = Kind.parse(value) orelse .insight;
        } else if (std.mem.eql(u8, key, "written_at")) {
            entry.written_at = value;
        } else if (std.mem.eql(u8, key, "date")) {
            // The older spelling. A `written_at` line wins, whichever order
            // the two appear in, so an entry that somehow holds both reads as
            // the more exact of the two.
            if (entry.written_at.len == 0) entry.written_at = value;
        } else if (std.mem.eql(u8, key, "session")) {
            entry.session = value;
        } else if (std.mem.eql(u8, key, "version")) {
            entry.version = std.fmt.parseInt(usize, value, 10) catch 1;
        } else if (std.mem.eql(u8, key, "bytes")) {
            declared_body_bytes = std.fmt.parseInt(usize, value, 10) catch null;
        }
    }

    if (entry.name.len == 0) return error.NotAnEntry;

    const declared = declared_body_bytes orelse {
        entry.body = rest;
        return .{ .entry = entry, .rest = "" };
    };
    // Never past the end of what is there. A file cut short by a read limit
    // is still a readable version, and the truncation costs the tail of the
    // body rather than the whole entry.
    const take = @min(declared, rest.len);
    entry.body = rest[0..take];
    return .{ .entry = entry, .rest = rest[take..] };
}

/// A walk over every version in one entry file, newest first. Each `Entry`
/// is a slice of the text given to `versions`, so the caller keeps that text
/// alive for as long as the results.
pub const Versions = struct {
    rest: []const u8,

    /// The next version, or null at the end of the file. **A version this
    /// cannot read ends the walk rather than failing it**, the same rule
    /// `parse` keeps for a file a person edited by hand: the versions already
    /// given back are still good ones.
    pub fn next(self: *Versions) ?Entry {
        // The blank line `addVersion` puts between two versions, and any
        // other blank a person left there.
        while (self.rest.len != 0 and (self.rest[0] == '\n' or self.rest[0] == '\r')) {
            self.rest = self.rest[1..];
        }
        if (self.rest.len == 0) return null;

        const record = parseRecord(self.rest) catch {
            self.rest = "";
            return null;
        };
        self.rest = record.rest;
        return record.entry;
    }
};

/// Every version in `text`, newest first. See `Versions`.
pub fn versions(text: []const u8) Versions {
    return .{ .rest = text };
}

/// `text` cut down to the newest version alone, with every older version
/// left off. **What `read_memory` gives the model**: an agent asked for the
/// fact, not for the history of the fact, and the versions it superseded
/// would cost context to say nothing current.
pub fn newestVersion(text: []const u8) []const u8 {
    var walk = versions(text);
    _ = walk.next() orelse return text;
    return text[0 .. text.len - walk.rest.len];
}

/// How many bytes `now` writes: `YYYY-MM-DDThh:mm:ssZ`.
pub const timestamp_bytes: usize = 20;

/// Now, as `YYYY-MM-DDThh:mm:ssZ`, in UTC. Written into every entry so a
/// reader can weigh how far it may have drifted, and so two entries have an
/// order.
///
/// **One form, everywhere, and it sorts as text.** ISO 8601 with the fields
/// largest first means `std.mem.lessThan` over two of these gives the same
/// answer a clock does, so nothing has to parse a timestamp back to compare
/// two entries.
///
/// **UTC and not the local zone.** Two machines reading one knowledgebase
/// must agree on what an entry's timestamp means, and a local zone would make
/// the sort above wrong for a knowledgebase two machines wrote into.
pub fn now(io: std.Io, buffer: *[timestamp_bytes]u8) []const u8 {
    const ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
    const seconds: u64 = if (ms > 0) @intCast(@divFloor(ms, std.time.ms_per_s)) else 0;
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();
    return std.fmt.bufPrint(buffer, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    }) catch unreachable;
}

// The index in the prompt is built before a session starts, by the process
// that already holds the project and the configuration. That process is not
// inside the sandbox and does not need to be: it is reading Chock's own
// directory, the same way it reads `chock.zon`. The sandbox matters for the
// tool calls, which go the other way, and they live in `tools.zig`.

/// One entry's index line plus what a lister needs. `index.Entry` alone
/// cannot carry the time it was written, and that is what makes a stale entry
/// weighable.
pub const Listed = struct {
    name: []const u8,
    description: []const u8,
    kind: Kind,
    written_at: []const u8,
    /// How many versions this name holds, the newest one counted. One for a
    /// name written once. **Free to read**, because the newest version is at
    /// the front of the file and carries the number: see `Entry.version`.
    versions: usize = 1,
};

/// Every entry in `dir`, sorted by name, header only. **The bodies are not
/// read**, because the index is what goes in the prompt and a body that was
/// read to build an index is a body that costs memory for nothing.
///
/// A directory that is not there is an empty knowledgebase, not an error: a
/// project whose first session has not written anything yet is the ordinary
/// case.
///
/// Everything in the result is owned by `allocator`. An arena frees it all
/// at once.
pub fn list(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir_path: []const u8,
) std.mem.Allocator.Error![]const Listed {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return &.{};
    defer dir.close(io);

    var listed: std.ArrayList(Listed) = .empty;
    errdefer listed.deinit(allocator);

    var it = dir.iterate();
    while (it.next(io) catch null) |dir_entry| {
        if (dir_entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, dir_entry.name, extension)) continue;

        const text = dir.readFileAlloc(io, dir_entry.name, allocator, .limited(header_read_bytes)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // A file too long for this read still has its whole header in
            // the first `header_read_bytes`, so read that much and carry on.
            error.StreamTooLong => (try readFront(allocator, io, dir, dir_entry.name)) orelse continue,
            else => continue,
        };
        const parsed = parse(text) catch continue;
        try listed.append(allocator, .{
            .name = parsed.name,
            .description = parsed.description,
            .kind = parsed.kind,
            .written_at = parsed.written_at,
            .versions = parsed.version,
        });
    }

    std.mem.sort(Listed, listed.items, {}, lessThanName);
    return listed.toOwnedSlice(allocator);
}

/// How much of an entry file `list` reads. The header is seven short lines,
/// so this is far more than one needs and still far less than a body, let
/// alone a file of every version of one.
const header_read_bytes: usize = 4 * 1024;

fn readFront(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) std.mem.Allocator.Error!?[]u8 {
    var file = dir.openFile(io, sub_path, .{}) catch return null;
    defer file.close(io);

    var text = try allocator.alloc(u8, header_read_bytes);
    errdefer allocator.free(text);

    var filled: usize = 0;
    while (filled < text.len) {
        const n = file.readStreaming(io, &.{text[filled..]}) catch break;
        if (n == 0) break;
        filled += n;
    }
    // Shrunk with `realloc`, never handed back as a subslice: see
    // `lib/chock-core/instructions.zig`'s own `readFront` for why.
    if (filled != text.len) text = try allocator.realloc(text, filled);
    return text;
}

fn lessThanName(_: void, a: Listed, b: Listed) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

/// The index the prompt carries: one line per entry, name and description
/// and nothing else. Caller owns the slice.
pub fn indexOf(
    allocator: std.mem.Allocator,
    entries: []const Listed,
) std.mem.Allocator.Error![]index.Entry {
    const out = try allocator.alloc(index.Entry, entries.len);
    for (entries, out) |entry, *line| {
        line.* = .{ .name = entry.name, .description = entry.description };
    }
    return out;
}

/// How many entries `dir_path` holds. `write_memory` asks before it writes a
/// new name, so `max_entries` is enforced and not merely documented.
pub fn count(io: std.Io, dir_path: []const u8) usize {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return 0;
    defer dir.close(io);

    var total: usize = 0;
    var it = dir.iterate();
    while (it.next(io) catch null) |dir_entry| {
        if (dir_entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, dir_entry.name, extension)) continue;
        total += 1;
    }
    return total;
}

/// Remove one entry. **A wrong entry must be removable in one step**, by the
/// user and by an agent that finds it false.
pub fn forget(io: std.Io, dir_path: []const u8, name: []const u8) !void {
    try checkName(name);
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);

    var buffer: [max_name_bytes + extension.len]u8 = undefined;
    const file = std.fmt.bufPrint(&buffer, "{s}" ++ extension, .{name}) catch unreachable;
    try dir.deleteFile(io, file);
}

/// Remove every entry, and answer how many went. **Clearing memory is one
/// obvious step**, because memory a user cannot clear is memory a user
/// cannot trust.
///
/// Only files with the entry extension go: a directory Chock shares with
/// nothing today may share with something tomorrow, and a clear that removed
/// a stranger's file would be a surprise nobody asked for.
pub fn clear(allocator: std.mem.Allocator, io: std.Io, dir_path: []const u8) std.mem.Allocator.Error!usize {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return 0;
    defer dir.close(io);

    // The names first, then the deletes: deleting while iterating a
    // directory is undefined on more than one filesystem.
    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |name| allocator.free(name);
        names.deinit(allocator);
    }

    var it = dir.iterate();
    while (it.next(io) catch null) |dir_entry| {
        if (dir_entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, dir_entry.name, extension)) continue;
        try names.append(allocator, try allocator.dupe(u8, dir_entry.name));
    }

    var removed: usize = 0;
    for (names.items) |name| {
        dir.deleteFile(io, name) catch continue;
        removed += 1;
    }
    return removed;
}

const testing = std.testing;

test "an entry round trips through the file format, body and all" {
    const allocator = testing.allocator;
    const entry: Entry = .{
        .name = "mount-order",
        .description = "the kernel takes the last matching mount, not the longest prefix",
        .kind = .gotcha,
        .written_at = "2026-08-21T09:15:00Z",
        .session = "01ABC",
        .body = "Binding /run over /run/chock hides everything under it.\n",
    };

    const text = try serialize(allocator, entry);
    defer allocator.free(text);

    const back = try parse(text);
    try testing.expectEqualStrings(entry.name, back.name);
    try testing.expectEqualStrings(entry.description, back.description);
    try testing.expectEqual(Kind.gotcha, back.kind);
    try testing.expectEqualStrings(entry.written_at, back.written_at);
    try testing.expectEqualStrings(entry.session, back.session);
    try testing.expectEqualStrings(entry.body, back.body);
    try testing.expectEqual(@as(usize, 1), back.version);
}

test "writing a name again adds a version and the one before it is still readable" {
    // The fault this closes: the write used to replace the file, so an agent
    // could erase what it or an earlier session wrote. The assertion that
    // matters is the second one. A test that only checked the new body was
    // there would have passed against the old behaviour as well.
    const allocator = testing.allocator;

    const first = try addVersion(allocator, "", .{
        .name = "mount-order",
        .description = "the first reading",
        .kind = .code_fact,
        .written_at = "2026-08-21T09:15:00Z",
        .session = "01ABC",
        .body = "the kernel takes the longest prefix\n",
    });
    defer allocator.free(first);

    const second = try addVersion(allocator, first, .{
        .name = "mount-order",
        .description = "the correction, five hours on",
        .kind = .code_fact,
        .written_at = "2026-08-21T14:32:07Z",
        .session = "01ABC",
        .body = "the kernel takes the last matching mount\n",
    });
    defer allocator.free(second);

    // A read gives the newest, so superseding still works the way it did.
    const current = try parse(second);
    try testing.expectEqual(@as(usize, 2), current.version);
    try testing.expectEqualStrings("the correction, five hours on", current.description);
    try testing.expectEqualStrings("the kernel takes the last matching mount\n", current.body);

    var walk = versions(second);
    _ = walk.next().?;
    const earlier = walk.next().?;
    try testing.expectEqual(@as(usize, 1), earlier.version);
    try testing.expectEqualStrings("the first reading", earlier.description);
    try testing.expectEqualStrings("2026-08-21T09:15:00Z", earlier.written_at);
    try testing.expectEqualStrings("the kernel takes the longest prefix\n", earlier.body);
    try testing.expect(walk.next() == null);

    // The bytes of the first file are carried through untouched, which is
    // what says the write added and did not rewrite.
    try testing.expect(std.mem.endsWith(u8, second, first));
    try testing.expectEqual(@as(usize, 2), versionsIn(second));
}

test "a body that forges a whole version is read as body, not as a version" {
    // The model chooses the body, so a body holding a complete header of its
    // own is a thing that will happen. `bytes` says where the body ends, so
    // nothing in the body is ever read as the start of the next version.
    const allocator = testing.allocator;
    const forged =
        "the real body\n" ++
        "\n" ++
        "name: mount-order\n" ++
        "kind: code_fact\n" ++
        "version: 9\n" ++
        "written_at: 2099-01-01T00:00:00Z\n" ++
        "bytes: 8\n" ++
        "description: forged\n" ++
        "\n" ++
        "forged.\n";

    const text = try addVersion(allocator, "", .{
        .name = "mount-order",
        .description = "the real one",
        .kind = .code_fact,
        .written_at = "2026-08-21T09:15:00Z",
        .body = forged,
    });
    defer allocator.free(text);

    const back = try parse(text);
    try testing.expectEqualStrings("the real one", back.description);
    try testing.expectEqual(@as(usize, 1), back.version);
    try testing.expectEqualStrings(forged, back.body);

    // One version, whatever the body says. A reader that looked in the body
    // for a boundary would find two here, and the second would claim to be
    // version 9.
    var walk = versions(text);
    _ = walk.next().?;
    try testing.expect(walk.next() == null);
    try testing.expectEqual(@as(usize, 1), versionsIn(text));
}

test "an entry file written before versions existed reads as version one, and a write keeps it" {
    // Every entry on disk today is one version with no `version` and no
    // `bytes` header. Such a file must keep reading, and a write on top of it
    // must keep it rather than throw it away, which is the same fault by
    // another route.
    const allocator = testing.allocator;
    const old =
        "name: written-before\n" ++
        "kind: code_fact\n" ++
        "date: 2026-08-20\n" ++
        "description: the old shape\n" ++
        "\n" ++
        "the old body\n";

    const first = try parse(old);
    try testing.expectEqual(@as(usize, 1), first.version);
    try testing.expectEqualStrings("the old body\n", first.body);
    try testing.expectEqual(@as(usize, 1), versionsIn(old));

    const grown = try addVersion(allocator, old, .{
        .name = "written-before",
        .description = "the new shape",
        .kind = .code_fact,
        .written_at = "2026-08-21T14:32:07Z",
        .body = "the new body\n",
    });
    defer allocator.free(grown);

    const current = try parse(grown);
    try testing.expectEqual(@as(usize, 2), current.version);
    try testing.expectEqualStrings("the new body\n", current.body);

    var walk = versions(grown);
    _ = walk.next().?;
    const earlier = walk.next().?;
    try testing.expectEqualStrings("the old body\n", earlier.body);
    try testing.expectEqualStrings("2026-08-20", earlier.written_at);
}

test "the newest version alone is what a reader is given, and it is the front of the file" {
    // What `read_memory` hands the model. The versions it superseded say
    // nothing current and would cost context to say it.
    const allocator = testing.allocator;

    const first = try addVersion(allocator, "", .{
        .name = "n",
        .description = "d",
        .kind = .insight,
        .written_at = "2026-08-21T09:15:00Z",
        .body = "SUPERSEDED-BODY\n",
    });
    defer allocator.free(first);
    const second = try addVersion(allocator, first, .{
        .name = "n",
        .description = "d",
        .kind = .insight,
        .written_at = "2026-08-21T14:32:07Z",
        .body = "CURRENT-BODY\n",
    });
    defer allocator.free(second);

    const newest = newestVersion(second);
    try testing.expect(std.mem.indexOf(u8, newest, "CURRENT-BODY") != null);
    try testing.expect(std.mem.indexOf(u8, newest, "SUPERSEDED-BODY") == null);
    // At the front, so a read that was cut short by a size limit loses the
    // history and never the current fact.
    try testing.expect(std.mem.startsWith(u8, second, newest));

    // And a file that is not an entry at all is handed back whole, rather
    // than cut down to nothing.
    try testing.expectEqualStrings("just prose\n", newestVersion("just prose\n"));
}

test "a body that looks like a header stays body" {
    // The model chooses the body, so a body holding `name: something-else`
    // is a thing that will happen. The blank line ends the header and
    // nothing after it is read as one, which is what keeps a body from
    // rewriting the entry it is in.
    const allocator = testing.allocator;
    const text = try serialize(allocator, .{
        .name = "real-name",
        .description = "one line",
        .kind = .insight,
        .written_at = "2026-08-21T09:15:00Z",
        .body = "name: forged-name\ndescription: forged\n",
    });
    defer allocator.free(text);

    const back = try parse(text);
    try testing.expectEqualStrings("real-name", back.name);
    try testing.expectEqualStrings("one line", back.description);
    try testing.expect(std.mem.indexOf(u8, back.body, "forged-name") != null);
}

test "a description with a newline in it becomes one line in the file" {
    const allocator = testing.allocator;
    const text = try serialize(allocator, .{
        .name = "n",
        .description = "first line\nsecond line",
        .kind = .insight,
        .written_at = "2026-08-21T09:15:00Z",
        .body = "body\n",
    });
    defer allocator.free(text);

    const back = try parse(text);
    try testing.expectEqualStrings("first line second line", back.description);
}

test "a name is a plain name, so there is no path to leave the directory through" {
    // This is what stands between the model and a file of its own choosing.
    try checkName("mount-order");
    try checkName("a1_b-c");

    try testing.expectError(error.BadName, checkName(""));
    try testing.expectError(error.BadName, checkName(".."));
    try testing.expectError(error.BadName, checkName("../../etc/passwd"));
    try testing.expectError(error.BadName, checkName("a/b"));
    try testing.expectError(error.BadName, checkName("a.b"));
    try testing.expectError(error.BadName, checkName("-rf"));
    try testing.expectError(error.BadName, checkName("Upper"));
    try testing.expectError(error.BadName, checkName("a" ** (max_name_bytes + 1)));
}

test "an entry a person edited by hand is still readable, and an unknown kind is not fatal" {
    // Staleness and hand editing are normal states. A knowledgebase that
    // refused to read an entry over a field it did not know would be one
    // more reason to stop trusting it.
    const back = try parse(
        \\name: hand-written
        \\kind: something-a-newer-chock-writes
        \\future-field: ignored
        \\
        \\the body
        \\
    );
    try testing.expectEqualStrings("hand-written", back.name);
    try testing.expectEqual(Kind.insight, back.kind);
    try testing.expectEqualStrings("", back.written_at);
    try testing.expectEqualStrings("the body\n", back.body);
}

test "a file that is not an entry at all is refused rather than read as a blank one" {
    try testing.expectError(error.NotAnEntry, parse("just some prose somebody dropped in\n"));
}

test "the timestamp carries a time of day, and it is the same shape whatever the clock says" {
    // Not a wall clock assertion: this pins the shape, never the value. A
    // test that asserted on today's date would fail on the day the date
    // changed, which is every day.
    var buffer: [timestamp_bytes]u8 = undefined;
    const stamp = now(testing.io, &buffer);
    try testing.expectEqual(timestamp_bytes, stamp.len);
    // `YYYY-MM-DDThh:mm:ssZ`. The separators are what say this is a time and
    // not only a day, which is the whole point of the field.
    try testing.expectEqual(@as(u8, '-'), stamp[4]);
    try testing.expectEqual(@as(u8, '-'), stamp[7]);
    try testing.expectEqual(@as(u8, 'T'), stamp[10]);
    try testing.expectEqual(@as(u8, ':'), stamp[13]);
    try testing.expectEqual(@as(u8, ':'), stamp[16]);
    try testing.expectEqual(@as(u8, 'Z'), stamp[19]);
    for (stamp, 0..) |byte, i| {
        if (i == 4 or i == 7 or i == 10 or i == 13 or i == 16 or i == 19) continue;
        try testing.expect(byte >= '0' and byte <= '9');
    }
}

test "two entries written in one session are ordered by their timestamps, which the session identifier cannot do" {
    // The fact the field exists for. A session here runs for hours, so an
    // entry and its own correction later the same session carry the identical
    // session identifier and the identical day. Only the clock says which one
    // a reader should believe.
    const allocator = testing.allocator;

    const earlier = try serialize(allocator, .{
        .name = "mount-order",
        .description = "the first reading",
        .kind = .code_fact,
        .written_at = "2026-08-21T09:15:00Z",
        .session = "01ABC",
        .body = "the kernel takes the longest prefix\n",
    });
    defer allocator.free(earlier);
    const later = try serialize(allocator, .{
        .name = "mount-order",
        .description = "the correction, five hours on",
        .kind = .code_fact,
        .written_at = "2026-08-21T14:32:07Z",
        .session = "01ABC",
        .body = "the kernel takes the last matching mount\n",
    });
    defer allocator.free(later);

    const first = try parse(earlier);
    const second = try parse(later);

    // Same session, same day: neither field separates the two.
    try testing.expectEqualStrings(first.session, second.session);
    try testing.expectEqualStrings(first.written_at[0..10], second.written_at[0..10]);
    // The timestamp does, as plain text, with nothing parsed back: see `now`.
    try testing.expect(std.mem.lessThan(u8, first.written_at, second.written_at));
}

test "an entry written before this field carried a clock still reads, and still sorts" {
    // A `date: YYYY-MM-DD` header is what every entry on disk holds today.
    // Refusing those, or dropping the day they do carry, would throw a
    // knowledgebase away to gain nothing.
    const old = try parse(
        \\name: written-before
        \\kind: code_fact
        \\date: 2026-08-20
        \\
        \\the body
        \\
    );
    try testing.expectEqualStrings("2026-08-20", old.written_at);

    // And it sorts against a full timestamp the way it should: a day with no
    // time comes before every entry timed later in that day, and before every
    // entry of the day after.
    try testing.expect(std.mem.lessThan(u8, old.written_at, "2026-08-20T00:00:01Z"));
    try testing.expect(std.mem.lessThan(u8, old.written_at, "2026-08-21T09:15:00Z"));
}

/// A knowledgebase directory in a fresh temporary directory, with the
/// entries a test names already in it. An entry whose name is already there
/// takes another version of it, the same way `write_memory` does.
fn writeEntries(io: std.Io, dir: std.Io.Dir, allocator: std.mem.Allocator, entries: []const Entry) !void {
    for (entries) |entry| {
        const name = try fileName(allocator, entry.name);
        defer allocator.free(name);

        const existing = dir.readFileAlloc(io, name, allocator, .limited(max_entry_bytes)) catch "";
        defer if (existing.len != 0) allocator.free(existing);

        const text = try addVersion(allocator, existing, entry);
        defer allocator.free(text);

        var file = try dir.createFile(io, name, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, text);
    }
}

test "listing a knowledgebase reads the headers, sorts by name, and never reads a body" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const big_body = try arena.alloc(u8, max_body_bytes);
    @memset(big_body, 'x');
    try writeEntries(testing.io, tmp.dir, arena, &.{
        .{ .name = "zeta", .description = "the last one", .kind = .convention, .written_at = "2026-01-02T00:00:00Z", .body = "b\n" },
        .{ .name = "alpha", .description = "the first one", .kind = .dead_end, .written_at = "2026-01-01T00:00:00Z", .body = big_body },
    });
    // A file that is not an entry, and a file with the wrong extension.
    try writeEntries(testing.io, tmp.dir, arena, &.{});
    {
        var stray = try tmp.dir.createFile(testing.io, "notes.txt", .{});
        defer stray.close(testing.io);
        try stray.writeStreamingAll(testing.io, "not an entry\n");
    }

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const dir_path = buffer[0..len];

    const entries = try list(arena, testing.io, dir_path);
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqualStrings("alpha", entries[0].name);
    try testing.expectEqualStrings("zeta", entries[1].name);
    try testing.expectEqual(Kind.dead_end, entries[0].kind);
    try testing.expectEqualStrings("2026-01-01T00:00:00Z", entries[0].written_at);

    // The index is names and descriptions, and there is nowhere in it for a
    // body to be.
    const lines = try indexOf(arena, entries);
    try testing.expectEqual(@as(usize, 2), lines.len);
    for (lines) |line| try testing.expect(std.mem.indexOf(u8, line.description, "xxxx") == null);

    try testing.expectEqual(@as(usize, 2), count(testing.io, dir_path));
}

test "listing says how many versions a name holds, and still never reads a body" {
    // `chock memory` shows this, so a user can see that an entry has a
    // history before asking for it. The number comes off the newest version's
    // own header at the front of the file, so the read stays the size of a
    // header however deep the history is.
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Two bodies far larger than `header_read_bytes`, so a listing that
    // walked the versions rather than reading the front would have to read
    // past what it asks the filesystem for.
    const big_body = try arena.alloc(u8, max_body_bytes);
    @memset(big_body, 'x');

    try writeEntries(testing.io, tmp.dir, arena, &.{
        .{ .name = "once", .description = "written one time", .kind = .insight, .written_at = "2026-01-01T00:00:00Z", .body = "b\n" },
        .{ .name = "twice", .description = "the first reading", .kind = .code_fact, .written_at = "2026-01-01T00:00:00Z", .body = big_body },
        .{ .name = "twice", .description = "the correction", .kind = .code_fact, .written_at = "2026-01-02T00:00:00Z", .body = big_body },
    });

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const dir_path = buffer[0..len];

    const entries = try list(arena, testing.io, dir_path);
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqualStrings("once", entries[0].name);
    try testing.expectEqual(@as(usize, 1), entries[0].versions);
    try testing.expectEqualStrings("twice", entries[1].name);
    try testing.expectEqual(@as(usize, 2), entries[1].versions);
    // The newest version is what the listing describes, not the first.
    try testing.expectEqualStrings("the correction", entries[1].description);

    // Two names, and a second version is not a second entry: this is what
    // `max_entries` counts.
    try testing.expectEqual(@as(usize, 2), count(testing.io, dir_path));
}

test "a knowledgebase that was never written is empty, not an error" {
    const allocator = testing.allocator;
    const entries = try list(allocator, testing.io, "/there/is/no/such/directory/anywhere");
    defer allocator.free(entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
    try testing.expectEqual(@as(usize, 0), count(testing.io, "/there/is/no/such/directory/anywhere"));
}

test "clearing removes every entry and leaves a stranger's file alone" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeEntries(testing.io, tmp.dir, arena, &.{
        .{ .name = "one", .description = "d", .kind = .insight, .written_at = "2026-01-01T00:00:00Z", .body = "b\n" },
        .{ .name = "two", .description = "d", .kind = .insight, .written_at = "2026-01-01T00:00:00Z", .body = "b\n" },
    });
    {
        var stray = try tmp.dir.createFile(testing.io, "README", .{});
        defer stray.close(testing.io);
        try stray.writeStreamingAll(testing.io, "not Chock's\n");
    }

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const dir_path = buffer[0..len];

    try testing.expectEqual(@as(usize, 2), try clear(arena, testing.io, dir_path));
    try testing.expectEqual(@as(usize, 0), count(testing.io, dir_path));
    _ = try tmp.dir.statFile(testing.io, "README", .{});
}

test "forgetting one entry removes that one and no other" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeEntries(testing.io, tmp.dir, arena, &.{
        .{ .name = "keep", .description = "d", .kind = .insight, .written_at = "2026-01-01T00:00:00Z", .body = "b\n" },
        .{ .name = "drop", .description = "d", .kind = .insight, .written_at = "2026-01-01T00:00:00Z", .body = "b\n" },
    });

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const dir_path = buffer[0..len];

    try forget(testing.io, dir_path, "drop");
    const entries = try list(arena, testing.io, dir_path);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqualStrings("keep", entries[0].name);

    // And a name that could name a path is refused before anything is
    // opened, the same rule `checkName` keeps for a write.
    try testing.expectError(error.BadName, forget(testing.io, dir_path, "../keep"));
}
