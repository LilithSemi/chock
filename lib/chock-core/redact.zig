//! Secrets, kept out of a model request.
//!
//! ## Read this first, because the name of this file oversells it
//!
//! **Redaction is protection against accident, never against a hostile
//! agent.** An agent that can read a file can base64 it, split it across
//! three tool results, or spell it out one character at a time, and every one
//! of those reaches the provider whole. Nothing here looks for any of that,
//! and nothing here could: the moment the bytes are inside the process, the
//! agent has already won any contest about what happens to them.
//!
//! The fault this does answer is real and is not rare. **An agent that reads
//! a file with a credential in it puts that credential in the session log and
//! in the next provider request.** It did not mean to. Nobody asked it to. A
//! `.env` is the file that used to be named here, and a project can now say
//! the agent may not read that one at all: see layer 1 below. What is left for
//! this file is every credential nobody named. `chock-auth` is careful with the
//! credentials Chock itself holds, and none of that care applies to a
//! credential that arrives through the workspace, which is every credential a
//! project keeps in a file.
//!
//! ## Three layers, and only the first one holds
//!
//! 1. **Prevention, which is the only one that holds.** A tool call reads
//!    through the mount tree `chock_workspace.Workspace.sandboxConfig`
//!    builds, so bytes that are not in that tree never enter the process and
//!    there is nothing to miss. **This file is not that layer and cannot
//!    stand in for it.**
//!
//!    **That layer is built, and it is a `deny_read` block in `chock.zon`.**
//!    See `chock_workspace.deny`, which reads the block off the host project
//!    before the sandbox exists, and `chock_sandbox.namespace.Mount.Deny`,
//!    which covers each named file with a bind of one file over one file,
//!    applied after the workspace mounts so it wins. The workspace still binds
//!    the whole working tree in one mount, and Landlock still cannot subtract
//!    a file from it, because Landlock rights accumulate on a nested path and
//!    are never narrowed by a wider rule; the mount is the whole boundary.
//!
//!    **What it does not cover, and what this file is therefore still for.**
//!    A denied path names one file inside the project. A directory is refused
//!    by name, and so is an absolute path, so `~/.aws` is not something a
//!    project can write there. A credential that arrives some other way, in a
//!    file nobody thought to name or in the output of a program, is not
//!    covered by any mount, and layers 2 and 3 below are what it gets.
//! 2. **Exact redaction, which is this file's `Secret` list.** Chock knows
//!    its own provider credentials, so it can match them wherever they
//!    appear, which catches the realistic case of a credential echoing back
//!    inside an error message a program printed. A project adds its own. No
//!    guessing, and every appearance is found.
//! 3. **Heuristics, which are best effort and are labelled so.** `AKIA`,
//!    `ghp_`, `github_pat_`, a PEM private key block, and a JWT. These catch
//!    the common accident. **They will always have false negatives and false
//!    positives on real code**, because the shape of a secret and the shape
//!    of a test fixture are the same shape. `Policy.heuristics` is off by
//!    default for that reason.
//!
//! ## Two seams, and the log is the one that cannot be undone
//!
//! **The session log is redacted, and so is the provider request.** They are
//! different questions and each one has its own answer:
//!
//! * The log is append only and hash chained. Each record carries the hash of
//!   the bytes of the record before it, so **a secret written there cannot be
//!   taken out again without breaking the chain**. There is no cleanup after
//!   the fact, only prevention. `chockd` also serves the log to every attached
//!   client, so a value that reached it was already given away. `event`
//!   below is what stops that, and `Loop.appendAndApply` is the one place in
//!   the loop that writes a record.
//! * A provider request leaves the machine. Most of it is built out of the
//!   log, so the log seam already covers it, but the system prompt is not: it
//!   is handed to the loop directly and never appended. `request` below is
//!   what covers that, and `Loop.sendOnce` is its one caller.
//!
//! **A redacted record is what gets hashed.** The replacement happens before
//! the append, so the chain runs over the bytes the file really holds and a
//! log written this way verifies as `intact`. A test in `lib/chock-core/Loop.zig`
//! reads a real log back and proves it.
//!
//! **The record still says what happened.** A marker stands where the value
//! was, so a reader learns that a secret was there, which line it was on, and
//! which layer caught it. What is lost is the value alone.
//!
//! ## The agent is told, and this is not a courtesy
//!
//! A silent replacement makes a model retry: it reads the file again, gets
//! the same nothing, and spends turns on a value it will never see. A marker
//! costs one turn, because the model reads it and stops asking. See
//! `Source.marker`, and note that the three markers differ, so a model can
//! tell "this is a credential Chock holds" from "this looked like a secret to
//! a pattern".
//!
//! **No marker ever carries the value, and neither does any message this file
//! or any test of it writes.** A redactor that proves itself by printing what
//! it caught is not a redactor.
//!
//! ## What is deliberately left alone
//!
//! * **A reasoning block.** `chock_proto.event.Reasoning` carries a signature
//!   the provider checks against the text it signed, so an edited reasoning
//!   block is a refused request. A reasoning block also holds the model's own
//!   words about a context that was already redacted on the way in.
//! * **The tool definitions.** Chock writes those, so a secret in one is a
//!   bug in Chock and not a leak from a workspace.
//! * **A role, a model alias, a call id, or a tool name.** None of them ever
//!   holds bytes a workspace supplied.

const std = @import("std");
const chock_proto = @import("chock-proto");
const chock_provider = @import("chock-provider");

const log_event = chock_proto.event;
const message = chock_provider.message;

pub const Error = std.mem.Allocator.Error;

/// The one sentence a reader needs about what this defeats and what it does
/// not. Held here, beside the mechanism, for the same reason
/// `chock_proto.chain.not_a_signature` is held beside the hash chain: a
/// command that shows this to a person must show the words this module's own
/// top comment argues for, and not a paraphrase that got friendlier over
/// time.
pub const not_a_boundary =
    "Redaction is protection against accident, never against an agent that means to leak: " ++
    "anything an agent can read it can encode first. What this catches is a secret that " ++
    "reached a tool result by mistake.";

/// Why one run of bytes was replaced. **The three answers reach the model as
/// three different markers**, so an agent can tell a credential Chock holds
/// from a guess a pattern made.
pub const Source = enum {
    /// A credential Chock itself holds, out of the credential store. Exact,
    /// so every appearance is found.
    credential,
    /// A value the project declared secret. Exact, the same as above.
    declared,
    /// A run of bytes with the shape of a secret. Best effort: see this
    /// file's own top comment on false negatives and false positives.
    pattern,

    /// What the model reads in place of the bytes. **Never the value, never
    /// its length, and never a hash of it**: a marker that carried any of
    /// those would put the secret back in the request in a different
    /// alphabet, which is the whole thing this file exists to stop.
    pub fn marker(self: Source) []const u8 {
        return switch (self) {
            .credential => "[chock: redacted, a credential this session holds]",
            .declared => "[chock: redacted, a value this project declared secret]",
            .pattern => "[chock: redacted, this has the shape of a secret]",
        };
    }
};

/// One value that must not reach a provider.
pub const Secret = struct {
    value: []const u8,
    source: Source = .declared,
};

/// The shortest exact secret this file will match on.
///
/// **A short secret matches ordinary text far more often than it matches the
/// secret.** A four character value appears inside words, inside hashes, and
/// inside base64, so a policy that carried one would replace half a tool
/// result with markers and would teach an agent to distrust every marker it
/// sees. A credential shorter than this is not a credential, so the honest
/// answer is to skip it rather than to carpet the request.
///
/// **A skipped secret is not redacted at all.** `Policy.tooShort` counts
/// them, so a caller building a policy out of a project's own declarations
/// can say so to the person who wrote them, rather than leaving them to
/// believe a value is protected when it is not.
pub const min_secret_bytes: usize = 8;

/// What this session treats as secret.
///
/// **The default is inert.** No exact secrets and no heuristics, so a project
/// that declared nothing gets a request byte for byte identical to the one it
/// would have got before this file existed. `request` returns its argument
/// unchanged in that case, and a test in `lib/chock-core/Loop.zig` pins it.
pub const Policy = struct {
    /// Every value matched exactly, wherever it appears. Ordinarily the
    /// provider credentials this session holds, plus whatever the project
    /// declared. **Borrowed, not owned**: the caller keeps them alive for the
    /// whole session, the same way `Loop.Deps.system_prompt` is kept alive.
    secrets: []const Secret = &.{},
    /// Whether the best effort patterns run. Off by default: see this file's
    /// own top comment.
    heuristics: bool = false,

    /// Whether this policy would change any request at all. `request` reads
    /// this first, so an inert policy costs one comparison per turn and not a
    /// scan of the context.
    pub fn isEmpty(self: Policy) bool {
        if (self.heuristics) return false;
        for (self.secrets) |secret| {
            if (secret.value.len >= min_secret_bytes) return false;
        }
        return true;
    }

    /// How many declared secrets are too short to be matched on. See
    /// `min_secret_bytes`: a caller shows this number to whoever wrote the
    /// declarations, because a value counted here is not protected.
    pub fn tooShort(self: Policy) usize {
        var count: usize = 0;
        for (self.secrets) |secret| {
            if (secret.value.len < min_secret_bytes) count += 1;
        }
        return count;
    }
};

/// The bytes to send in place of `source`, or null when `source` holds
/// nothing this policy matches. **Null is the common answer**, and it is what
/// keeps an untouched request from being copied. The caller owns a returned
/// slice.
///
/// A match is replaced by `Source.marker`, so the run of bytes is gone and
/// the fact that it was there is not. Two secrets that both match at one
/// position take the longer one, so a policy holding a token and the same
/// token with its prefix never replaces half of one and leaves the rest.
pub fn text(gpa: std.mem.Allocator, policy: Policy, source: []const u8) Error![]const u8 {
    return (try find(gpa, policy, source)) orelse source;
}

/// The same as `text`, and it says whether anything was found. Null means
/// `source` is already clean, which is what a caller checks when it wants to
/// avoid an allocation, or when a test wants to pin that nothing happened.
pub fn find(gpa: std.mem.Allocator, policy: Policy, source: []const u8) Error!?[]u8 {
    if (policy.isEmpty()) return null;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    var copied: usize = 0;
    var at: usize = 0;
    var found = false;
    while (at < source.len) {
        const hit = matchAt(policy, source, at) orelse {
            at += 1;
            continue;
        };
        found = true;
        try out.appendSlice(gpa, source[copied..at]);
        try out.appendSlice(gpa, hit.source.marker());
        at += hit.len;
        copied = at;
    }
    if (!found) {
        out.deinit(gpa);
        return null;
    }
    try out.appendSlice(gpa, source[copied..]);
    const owned = try out.toOwnedSlice(gpa);
    return owned;
}

/// One request, with every run of bytes a workspace could have supplied
/// replaced. **Called from exactly one place**, `Loop.sendOnce`, which is the
/// only place in this library that hands a request to a provider client. A
/// second caller of `chock_provider.Client.sendAndAssemble` anywhere in
/// `chock-core` would be a way past this function, which is why there is not
/// one.
///
/// `arena` is expected to be the turn's arena, the same convention
/// `chock_core.context.build` takes: the returned request borrows every slice
/// it did not have to rewrite, so it is valid for exactly as long as both the
/// argument and the arena are.
///
/// An inert policy returns `req` itself, unchanged and uncopied.
pub fn request(arena: std.mem.Allocator, policy: Policy, req: message.Request) Error!message.Request {
    if (policy.isEmpty()) return req;

    var messages = try arena.alloc(message.Message, req.messages.len);
    for (req.messages, 0..) |one, index| {
        messages[index] = one;
        messages[index].content = try parts(arena, policy, one.content);
    }

    return .{
        .model = req.model,
        .system = try text(arena, policy, req.system),
        .messages = messages,
        // Chock's own words, so nothing a workspace supplied is in them.
        .tools = req.tools,
    };
}

fn parts(
    arena: std.mem.Allocator,
    policy: Policy,
    content: []const message.ContentPart,
) Error![]const message.ContentPart {
    var out = try arena.alloc(message.ContentPart, content.len);
    for (content, 0..) |part, index| {
        out[index] = switch (part) {
            .text => |said| .{ .text = try text(arena, policy, said) },
            // Signed by the provider against the text it signed, and an
            // edited block is a refused request.
            .reasoning => part,
            .tool_use => |use| blk: {
                var copy = use;
                // JSON text, and every marker is free of a quote and of a
                // backslash, so a replacement inside a JSON string leaves
                // the string parsable.
                copy.arguments = try text(arena, policy, use.arguments);
                break :blk .{ .tool_use = copy };
            },
            .tool_result => |result| blk: {
                var copy = result;
                copy.output = try text(arena, policy, result.output);
                break :blk .{ .tool_result = copy };
            },
            // A part shape this build does not know, kept verbatim through a
            // replay of an older or newer log. Its strings came from the same
            // wire every other part came from, so they get the same
            // treatment.
            .unknown => |part_unknown| .{ .unknown = .{
                .name = part_unknown.name,
                .raw = try value(arena, policy, part_unknown.raw),
            } },
        };
    }
    return out;
}

fn value(arena: std.mem.Allocator, policy: Policy, source: std.json.Value) Error!std.json.Value {
    switch (source) {
        .string => |said| return .{ .string = try text(arena, policy, said) },
        .array => |items| {
            var out = std.json.Array.init(arena);
            try out.ensureTotalCapacity(items.items.len);
            for (items.items) |one| out.appendAssumeCapacity(try value(arena, policy, one));
            return .{ .array = out };
        },
        .object => |fields| {
            var out: std.json.ObjectMap = .empty;
            try out.ensureTotalCapacity(arena, fields.count());
            var each = fields.iterator();
            while (each.next()) |field| {
                out.putAssumeCapacity(field.key_ptr.*, try value(arena, policy, field.value_ptr.*));
            }
            return .{ .object = out };
        },
        // A number, a bool, or a null. None of them can hold a secret, and
        // `number_string` is digits by the time a parser produced it.
        else => return source,
    }
}

/// One log record, with every run of bytes a workspace could have supplied
/// replaced. **Called from exactly one place**, `Loop.appendAndApply`, which
/// is the only place in this library that writes a record. A second caller of
/// `chock_proto.storage.Locked.append` anywhere in `chock-core` would be a way
/// past this function, which is why there is not one.
///
/// **This is the seam that cannot be moved later.** The log is append only and
/// hash chained, so a secret that reaches it stays there. See this file's own
/// top comment.
///
/// `arena` needs to stay alive only until the record is written and folded,
/// because `Locked.append` serializes what it is given and
/// `chock_proto.state.Session.apply` copies what it keeps. `Loop` gives this
/// an arena of its own for one call and releases it straight after.
///
/// An inert policy returns `ev` itself, unchanged and uncopied.
pub fn event(arena: std.mem.Allocator, policy: Policy, ev: log_event.Event) Error!log_event.Event {
    if (policy.isEmpty()) return ev;
    return anything(arena, policy, log_event.Event, ev);
}

/// One value of any shape an event is built out of, rewritten.
///
/// **Reflection, and not a list of the fields that matter.** A list is a thing
/// a reader keeps up to date, and the field that gets forgotten is the field
/// nobody thought could hold a credential. This walks whatever the type says
/// is there, so an event kind added next month is covered on the day it is
/// added, and so is a field a future writer sent that this build kept in
/// `chock_proto.event.Extra` without understanding it.
///
/// **A shape this cannot walk fails the build.** The `@compileError` below is
/// the whole guarantee: there is no silent pass through for a type nobody
/// taught this about.
fn anything(
    arena: std.mem.Allocator,
    policy: Policy,
    comptime T: type,
    given: T,
) Error!T {
    if (T == []const u8) return try text(arena, policy, given);
    if (T == std.json.Value) return try value(arena, policy, given);
    // Signed by the provider against the text it signed, so an edited block is
    // a refused request on the next turn. The log holds what the provider will
    // be given back, so the two have to agree. A model can only write a secret
    // into a reasoning block that it read in a context this same function
    // already cleaned.
    if (T == log_event.Reasoning) return given;

    switch (@typeInfo(T)) {
        // None of these can hold bytes a workspace supplied. A number stays a
        // number, and an enum member is a name this build wrote itself.
        .bool, .int, .float, .void, .@"enum" => return given,
        .optional => {
            const inner = given orelse return null;
            return try anything(arena, policy, @TypeOf(inner), inner);
        },
        .pointer => |info| {
            if (info.size != .slice) {
                @compileError("chock_core.redact walks a slice and not " ++ @typeName(T));
            }
            const out = try arena.alloc(info.child, given.len);
            for (given, out) |one, *slot| slot.* = try anything(arena, policy, info.child, one);
            return out;
        },
        .@"struct" => |info| {
            var out = given;
            inline for (info.fields) |field| {
                @field(out, field.name) = try anything(
                    arena,
                    policy,
                    field.type,
                    @field(given, field.name),
                );
            }
            return out;
        },
        .@"union" => |info| {
            if (info.tag_type == null) {
                @compileError("chock_core.redact cannot walk the untagged union " ++ @typeName(T));
            }
            switch (given) {
                inline else => |payload, tag| return @unionInit(
                    T,
                    @tagName(tag),
                    try anything(arena, policy, @TypeOf(payload), payload),
                ),
            }
        },
        else => @compileError("chock_core.redact does not know how to walk " ++ @typeName(T)),
    }
}

/// One run of bytes to replace, starting where the scan is.
const Hit = struct {
    len: usize,
    source: Source,
};

fn matchAt(policy: Policy, source: []const u8, at: usize) ?Hit {
    const rest = source[at..];

    // The exact list first, and the longest of it, so a policy holding both a
    // token and a longer value that starts with it replaces the whole of the
    // longer one.
    var best: ?Hit = null;
    for (policy.secrets) |secret| {
        if (secret.value.len < min_secret_bytes) continue;
        if (!std.mem.startsWith(u8, rest, secret.value)) continue;
        if (best) |found| {
            if (secret.value.len <= found.len) continue;
        }
        best = .{ .len = secret.value.len, .source = secret.source };
    }
    if (best) |found| return found;

    if (!policy.heuristics) return null;
    // A pattern only fires at the start of a run, so `AKIA` inside a longer
    // word is not a key. An exact secret has no such rule, because an exact
    // secret is the value itself wherever it sits.
    if (at != 0 and isTokenByte(source[at - 1])) return null;
    const len = matchPattern(rest) orelse return null;
    return .{ .len = len, .source = .pattern };
}

/// How long the best effort match at the start of `rest` is, or null.
///
/// **Five shapes, and the list is short on purpose.** Every entry costs a
/// false positive somewhere, and a redactor that eats ordinary code teaches
/// an agent to work around it.
fn matchPattern(rest: []const u8) ?usize {
    if (matchPem(rest)) |len| return len;
    if (matchPrefixRun(rest, "AKIA", 16, isUpperAlnum)) |len| return len;
    if (matchPrefixRun(rest, "ghp_", 36, isAlnum)) |len| return len;
    if (matchPrefixRun(rest, "github_pat_", 22, isTokenByte)) |len| return len;
    if (matchJwt(rest)) |len| return len;
    return null;
}

/// A PEM private key block, from its opening line through its closing one.
///
/// **The whole block, and not the header.** A header on its own is public
/// knowledge and the bytes under it are the key, so a rule that replaced the
/// header would leave the secret and remove the label. A block with no
/// closing line runs to the end of the text, which is what a truncated tool
/// result looks like.
fn matchPem(rest: []const u8) ?usize {
    const begin = "-----BEGIN ";
    if (!std.mem.startsWith(u8, rest, begin)) return null;
    const first_line_end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
    if (std.mem.indexOf(u8, rest[0..first_line_end], "PRIVATE KEY-----") == null) return null;

    const end_at = std.mem.indexOf(u8, rest, "-----END ") orelse return rest.len;
    const after = rest[end_at..];
    const end_line = std.mem.indexOfScalar(u8, after, '\n') orelse after.len;
    return end_at + end_line;
}

/// A fixed prefix and a run of at least `least` bytes after it. The whole run
/// is replaced, not only the first `least` of it, so a longer key than this
/// file expected is still removed whole.
fn matchPrefixRun(
    rest: []const u8,
    prefix: []const u8,
    least: usize,
    comptime allowed: fn (u8) bool,
) ?usize {
    if (!std.mem.startsWith(u8, rest, prefix)) return null;
    var end = prefix.len;
    while (end < rest.len and allowed(rest[end])) end += 1;
    if (end - prefix.len < least) return null;
    return end;
}

/// A JSON Web Token: three base64url runs joined by dots, the first of which
/// starts `eyJ`, which is how a base64url encoder writes `{"`.
///
/// Each run has a floor, because two dots in a line of ordinary text are not
/// a token and a rule with no floor would find one in every sentence that
/// began with those three letters.
fn matchJwt(rest: []const u8) ?usize {
    const least_segment: usize = 8;
    if (!std.mem.startsWith(u8, rest, "eyJ")) return null;

    var at: usize = 0;
    var segment: usize = 0;
    while (segment < 3) : (segment += 1) {
        const start = at;
        while (at < rest.len and isBase64UrlByte(rest[at])) at += 1;
        if (at - start < least_segment) return null;
        if (segment == 2) break;
        if (at >= rest.len or rest[at] != '.') return null;
        at += 1;
    }
    return at;
}

fn isAlnum(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte);
}

fn isUpperAlnum(byte: u8) bool {
    return std.ascii.isDigit(byte) or (byte >= 'A' and byte <= 'Z');
}

fn isTokenByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_';
}

fn isBase64UrlByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-';
}

// **No test below writes a secret into a failure message.** Every check is a
// boolean over a haystack, never an equality of two strings, because
// `expectEqualStrings` prints both sides and one of those sides is the thing
// this file exists to keep out of print. The values used are invented here and
// are not anybody's credential.

const testing = std.testing;

/// An invented value with no meaning anywhere, long enough to be matched on.
const fake_credential = "sk-test-000000000000000000000000";

/// The shapes the pattern list looks for, as fixtures.
///
/// **Named, and never written inline on an assertion.** A failing
/// `testing.expect` prints the source line it was written on, so a literal on
/// that line is a literal in the build log. Every one of these is a
/// documentation example or an invented run of characters, and none of them
/// opens anything, but the habit is the point: a value under test belongs
/// behind a name.
const shapes = struct {
    const aws = "AKIAIOSFODNN7EXAMPLE";
    const aws_in_a_word = "const" ++ aws;
    const aws_too_short = "AKIASHORT";
    const github = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    const github_too_short = "ghp_short";
    const github_pat = "github_pat_11ABCDEFG0" ++ "a" ** 22;
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." ++
        "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const jwt_too_short = "eyJhbGci.a.b";
    const key_body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ";
    const key_body_unfinished = "b3BlbnNzaC1rZXktdjEAAAAA";
};

test "a policy that declares nothing changes nothing" {
    // The property that lets this ship: a project that never heard of
    // redaction gets what it always got. `request` reads `isEmpty` first and
    // hands its argument straight back, so there is not even a copy.
    //
    // Mutation check: give `Policy` a default of `.heuristics = true` and
    // this fails, because the pattern list then fires on the token below.
    const policy = Policy{};
    try testing.expect(policy.isEmpty());
    try testing.expectEqual(
        @as(?[]u8, null),
        try find(testing.allocator, policy, shapes.github),
    );
}

test "a known credential is replaced everywhere it appears" {
    // The whole point of the exact layer: not the first appearance, every
    // one. A credential that echoes back inside an error message often
    // appears twice, once in the command line the program repeated and once
    // in the message itself.
    const gpa = testing.allocator;
    const policy = Policy{ .secrets = &.{.{ .value = fake_credential, .source = .credential }} };

    const source = "curl -H auth: " ++ fake_credential ++ "\nrefused for " ++ fake_credential ++ ", retry\n";
    const cleaned = (try find(gpa, policy, source)).?;
    defer gpa.free(cleaned);

    try testing.expect(std.mem.indexOf(u8, cleaned, fake_credential) == null);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, cleaned, Source.credential.marker()));
    // Everything that was not the secret survived, so a model still reads the
    // error it has to act on.
    try testing.expect(std.mem.indexOf(u8, cleaned, "refused for ") != null);
    try testing.expect(std.mem.indexOf(u8, cleaned, ", retry\n") != null);
}

test "the marker names which layer caught it, and never the value" {
    // Three markers, because "a credential Chock holds" and "a pattern
    // guessed" are different facts and a model that cannot tell them apart
    // cannot decide what to do next.
    const seen = [_]Source{ .credential, .declared, .pattern };
    for (seen) |source| {
        const marker = source.marker();
        try testing.expect(std.mem.startsWith(u8, marker, "[chock: "));
        try testing.expect(std.mem.endsWith(u8, marker, "]"));
        // A marker goes inside a JSON string, both in a tool call's arguments
        // and on the wire. A quote or a backslash in one would break the
        // string it lands in.
        try testing.expect(std.mem.indexOfScalar(u8, marker, '"') == null);
        try testing.expect(std.mem.indexOfScalar(u8, marker, '\\') == null);
        try testing.expect(std.mem.indexOf(u8, marker, fake_credential) == null);
        for (seen) |other| {
            if (other == source) continue;
            try testing.expect(!std.mem.eql(u8, marker, other.marker()));
        }
    }
}

test "a secret shorter than the floor is skipped rather than carpeting the text" {
    // A three character secret would match inside ordinary words, which is
    // worse than not matching at all. The count is what a caller shows to
    // whoever wrote the declaration, so nobody believes a value is protected
    // when it is not.
    const gpa = testing.allocator;
    const policy = Policy{ .secrets = &.{.{ .value = "abc" }} };
    try testing.expectEqual(@as(usize, 1), policy.tooShort());
    try testing.expect(policy.isEmpty());
    try testing.expectEqual(@as(?[]u8, null), try find(gpa, policy, "abcdef abc abc"));
}

test "the longer of two overlapping secrets wins" {
    // A policy holding both a token and a longer value that starts with it
    // must not replace the first half and leave the rest of the secret in the
    // request.
    //
    // **Both orders, and that is what makes this bite.** A version with no
    // comparison at all keeps whichever secret is last in the list, so a test
    // that only listed the short one first would pass against it.
    //
    // Mutation check: drop the length comparison in `matchAt` and the second
    // order below leaves the tail of the longer value in the text.
    const gpa = testing.allocator;
    const short = "aaaaaaaabbbb";
    const long = short ++ "ccccdddd";
    const orders = [_][2]Secret{
        .{ .{ .value = short }, .{ .value = long } },
        .{ .{ .value = long }, .{ .value = short } },
    };

    for (orders) |listed| {
        const policy = Policy{ .secrets = &listed };
        const cleaned = (try find(gpa, policy, "x " ++ long ++ " y")).?;
        defer gpa.free(cleaned);
        try testing.expect(std.mem.indexOf(u8, cleaned, "cccc") == null);
        try testing.expect(std.mem.indexOf(u8, cleaned, "dddd") == null);
        try testing.expect(std.mem.indexOf(u8, cleaned, "x ") != null);
        try testing.expect(std.mem.indexOf(u8, cleaned, " y") != null);
    }
}

test "the heuristics catch the five shapes they name" {
    const gpa = testing.allocator;
    const policy = Policy{ .heuristics = true };

    const cases = [_][]const u8{ shapes.aws, shapes.github, shapes.github_pat, shapes.jwt };
    for (cases) |one| {
        const source = try std.fmt.allocPrint(gpa, "before {s} after", .{one});
        defer gpa.free(source);
        const cleaned = (try find(gpa, policy, source)).?;
        defer gpa.free(cleaned);
        try testing.expect(std.mem.indexOf(u8, cleaned, one) == null);
        try testing.expect(std.mem.indexOf(u8, cleaned, Source.pattern.marker()) != null);
        try testing.expect(std.mem.indexOf(u8, cleaned, "before ") != null);
        try testing.expect(std.mem.indexOf(u8, cleaned, " after") != null);
    }
}

test "a private key block is replaced whole, header to footer" {
    // The bytes under the header are the key. A rule that took the header
    // alone would remove the label and leave the secret, which is the worst
    // of the three answers.
    //
    // Mutation check: return `begin.len` from `matchPem` and the body below
    // survives.
    const gpa = testing.allocator;
    const policy = Policy{ .heuristics = true };
    const body = shapes.key_body;
    const block =
        "-----BEGIN RSA PRIVATE KEY-----\n" ++
        body ++ "\n" ++
        "-----END RSA PRIVATE KEY-----";

    const cleaned = (try find(gpa, policy, "note\n" ++ block ++ "\ntail")).?;
    defer gpa.free(cleaned);
    try testing.expect(std.mem.indexOf(u8, cleaned, body) == null);
    try testing.expect(std.mem.indexOf(u8, cleaned, "BEGIN RSA PRIVATE KEY") == null);
    try testing.expect(std.mem.indexOf(u8, cleaned, "END RSA PRIVATE KEY") == null);
    try testing.expect(std.mem.indexOf(u8, cleaned, "note\n") != null);
    try testing.expect(std.mem.indexOf(u8, cleaned, "\ntail") != null);
}

test "a key block with no closing line is replaced to the end" {
    // What a truncated tool result looks like. Stopping at a footer that is
    // not there would leave the whole body in the request.
    const gpa = testing.allocator;
    const policy = Policy{ .heuristics = true };
    const started = "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++ shapes.key_body_unfinished ++ "\n";
    const cleaned = (try find(gpa, policy, started)).?;
    defer gpa.free(cleaned);
    try testing.expect(std.mem.indexOf(u8, cleaned, shapes.key_body_unfinished) == null);
    try testing.expectEqualStrings(Source.pattern.marker(), cleaned);
}

test "a pattern does not fire in the middle of a word" {
    // `AKIA` inside a longer identifier is an identifier. Without the
    // boundary check this replaces a piece of ordinary code and the model
    // reads a marker where a symbol name was.
    //
    // Mutation check: delete the `isTokenByte` guard in `matchAt` and this
    // fails.
    const gpa = testing.allocator;
    const policy = Policy{ .heuristics = true };
    try testing.expectEqual(
        @as(?[]u8, null),
        try find(gpa, policy, shapes.aws_in_a_word),
    );
}

test "a shape that is too short for its pattern is left alone" {
    // The floors are what keep the pattern list from eating ordinary text.
    // Mutation check: drop the `least` comparison in `matchPrefixRun` and
    // both of these are replaced.
    const gpa = testing.allocator;
    const policy = Policy{ .heuristics = true };
    try testing.expectEqual(@as(?[]u8, null), try find(gpa, policy, shapes.aws_too_short));
    try testing.expectEqual(@as(?[]u8, null), try find(gpa, policy, shapes.github_too_short));
    try testing.expectEqual(@as(?[]u8, null), try find(gpa, policy, shapes.jwt_too_short));
}

test "a request has every part a workspace could have filled redacted" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const policy = Policy{ .secrets = &.{.{ .value = fake_credential, .source = .credential }} };

    var raw: std.json.ObjectMap = .empty;
    try raw.put(arena, "note", .{ .string = "token " ++ fake_credential });

    const content = [_]message.ContentPart{
        .{ .text = "I read " ++ fake_credential },
        .{ .reasoning = .{ .text = "thinking about it", .signature = "sig-" ++ fake_credential } },
        .{ .tool_use = .{
            .call_id = "c1",
            .tool = "run_command",
            .arguments = "{\"argv\":[\"echo\",\"" ++ fake_credential ++ "\"]}",
        } },
        .{ .tool_result = .{ .call_id = "c1", .output = fake_credential, .is_error = false } },
        .{ .unknown = .{ .name = "citation", .raw = .{ .object = raw } } },
    };
    const messages = [_]message.Message{.{ .role = .assistant, .content = &content }};

    const cleaned = try request(arena, policy, .{
        .model = "m",
        .system = "the project says " ++ fake_credential,
        .messages = &messages,
    });

    try testing.expect(std.mem.indexOf(u8, cleaned.system, fake_credential) == null);
    const out = cleaned.messages[0].content;
    try testing.expect(std.mem.indexOf(u8, out[0].text, fake_credential) == null);
    try testing.expect(std.mem.indexOf(u8, out[2].tool_use.arguments, fake_credential) == null);
    try testing.expect(std.mem.indexOf(u8, out[3].tool_result.output, fake_credential) == null);
    try testing.expect(std.mem.indexOf(u8, out[4].unknown.raw.object.get("note").?.string, fake_credential) == null);

    // **The reasoning block is untouched on purpose.** Its signature is over
    // the text the provider signed, so an edit here is a refused request.
    try testing.expect(std.mem.indexOf(u8, out[1].reasoning.signature, fake_credential) != null);

    // A tool call's arguments are JSON, and a marker has to leave them
    // parsable.
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, out[2].tool_use.arguments, .{});
    defer parsed.deinit();
    try testing.expect(parsed.value == .object);
}

test "every string a record holds is walked, and a field nobody named is too" {
    // **The property the reflection buys.** A list of the fields that matter is
    // a list somebody keeps up to date, and the field that gets forgotten is the
    // field nobody believed could hold a credential. Two of the four below are
    // fields this build has no name for at all: `Extra` holds what a future
    // writer sent, and `Event.unknown` holds a kind this build never heard of.
    //
    // Mutation check: return `ev` from `event` and every search below fails.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const policy = Policy{ .secrets = &.{.{ .value = fake_credential, .source = .credential }} };

    var future: std.json.ObjectMap = .empty;
    try future.put(arena, "answer", .{ .string = "from " ++ fake_credential });

    const cleaned = try event(arena, policy, .{ .tool_result = .{
        .call_id = "c1",
        .output = "printed " ++ fake_credential,
        .is_error = false,
        .truncated = false,
        .extra = .{ .members = &.{
            .{ .name = "note", .value = .{ .string = "also " ++ fake_credential } },
            .{ .name = "nested", .value = .{ .object = future } },
        } },
    } });

    const result = cleaned.tool_result;
    try testing.expect(std.mem.indexOf(u8, result.output, fake_credential) == null);
    try testing.expect(std.mem.indexOf(u8, result.extra.members[0].value.string, fake_credential) == null);
    try testing.expect(
        std.mem.indexOf(u8, result.extra.members[1].value.object.get("answer").?.string, fake_credential) == null,
    );
    // The words around the value stay, so the record still says what happened.
    try testing.expect(std.mem.indexOf(u8, result.output, "printed ") != null);
    try testing.expectEqualStrings("c1", result.call_id);
    try testing.expect(!result.is_error);

    // A kind this build has no field for at all.
    var payload: std.json.ObjectMap = .empty;
    try payload.put(arena, "said", .{ .string = fake_credential });
    const opaque_one = try event(arena, policy, .{ .unknown = .{
        .kind = "provider.thing",
        .payload = .{ .object = payload },
    } });
    try testing.expect(
        std.mem.indexOf(u8, opaque_one.unknown.payload.object.get("said").?.string, fake_credential) == null,
    );
}

test "a reasoning block in a record is left alone, because the provider signed it" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const policy = Policy{ .secrets = &.{.{ .value = fake_credential, .source = .credential }} };

    const content = [_]log_event.ContentPart{
        .{ .text = "I read " ++ fake_credential },
        .{ .reasoning = .{ .text = "about " ++ fake_credential, .signature = "sig" } },
    };
    const cleaned = try event(arena, policy, .{ .message = .{
        .role = .assistant,
        .content = &content,
    } });

    const out = cleaned.message.content;
    try testing.expect(std.mem.indexOf(u8, out[0].text, fake_credential) == null);
    try testing.expect(std.mem.indexOf(u8, out[1].reasoning.text, fake_credential) != null);
}

test "an inert policy hands the record straight back, with nothing copied" {
    // The property that lets this sit on every append: a session that declared
    // nothing pays one comparison and not a walk of the record.
    //
    // Mutation check: drop the `isEmpty` check in `event` and the pointers
    // below differ, because the walk allocates a copy of every slice.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // **A slice of parts, and not a string.** A clean string comes back
    // unchanged whether it was walked or not, because `text` gives its argument
    // straight back when it finds nothing. A slice of parts is copied by the
    // walk and only by the walk, so this is the pointer that answers the
    // question.
    const said = "AKIAIOSFODNN7EXAMPLE";
    const content = [_]log_event.ContentPart{.{ .text = said }};
    const given = log_event.Event{ .message = .{ .role = .assistant, .content = &content } };

    const cleaned = try event(arena, Policy{}, given);
    try testing.expectEqual(@as([*]const log_event.ContentPart, &content), cleaned.message.content.ptr);
    try testing.expectEqual(said.ptr, cleaned.message.content[0].text.ptr);
}

test "the sentence about what this is not is held here and says so" {
    // The same rule `chock_proto.chain.not_a_signature` carries: a command
    // that shows this to a person shows the words the mechanism argues for.
    // A reword that quietly drops "never" is the failure this catches.
    try testing.expect(std.mem.indexOf(u8, not_a_boundary, "never") != null);
    try testing.expect(std.mem.indexOf(u8, not_a_boundary, "accident") != null);
}
