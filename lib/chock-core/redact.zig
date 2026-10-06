//! Secrets, kept out of a model request. Redaction protects against an
//! accident; it stops nothing a hostile agent deliberately works around.

const std = @import("std");
const chock_proto = @import("chock-proto");
const chock_provider = @import("chock-provider");

const log_event = chock_proto.event;
const message = chock_provider.message;

pub const Error = std.mem.Allocator.Error;

pub const not_a_boundary =
    "Redaction is protection against accident, never against an agent that means to leak: " ++
    "anything an agent can read it can encode first. What this catches is a secret that " ++
    "reached a tool result by mistake.";

pub const Source = enum {
    credential,
    declared,
    pattern,

    pub fn marker(self: Source) []const u8 {
        return switch (self) {
            .credential => "[chock: redacted, a credential this session holds]",
            .declared => "[chock: redacted, a value this project declared secret]",
            .pattern => "[chock: redacted, this has the shape of a secret]",
        };
    }
};

pub const Secret = struct {
    value: []const u8,
    source: Source = .declared,
};

pub const min_secret_bytes: usize = 8;

pub const Policy = struct {
    secrets: []const Secret = &.{},
    heuristics: bool = false,

    pub fn isEmpty(self: Policy) bool {
        if (self.heuristics) return false;
        for (self.secrets) |secret| {
            if (secret.value.len >= min_secret_bytes) return false;
        }
        return true;
    }

    pub fn tooShort(self: Policy) usize {
        var count: usize = 0;
        for (self.secrets) |secret| {
            if (secret.value.len == 0) continue;
            if (secret.value.len < min_secret_bytes) count += 1;
        }
        return count;
    }
};

pub fn text(gpa: std.mem.Allocator, policy: Policy, source: []const u8) Error![]const u8 {
    return (try find(gpa, policy, source)) orelse source;
}

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
            .reasoning => part,
            .tool_use => |use| blk: {
                var copy = use;
                copy.arguments = try text(arena, policy, use.arguments);
                break :blk .{ .tool_use = copy };
            },
            .tool_result => |result| blk: {
                var copy = result;
                copy.output = try text(arena, policy, result.output);
                break :blk .{ .tool_result = copy };
            },
            .image => part,
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
        else => return source,
    }
}

pub fn event(arena: std.mem.Allocator, policy: Policy, ev: log_event.Event) Error!log_event.Event {
    if (policy.isEmpty()) return ev;
    return anything(arena, policy, log_event.Event, ev);
}

fn anything(
    arena: std.mem.Allocator,
    policy: Policy,
    comptime T: type,
    given: T,
) Error!T {
    if (T == []const u8) return try text(arena, policy, given);
    if (T == std.json.Value) return try value(arena, policy, given);
    if (T == log_event.Reasoning) return given;

    switch (@typeInfo(T)) {
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

const Hit = struct {
    len: usize,
    source: Source,
};

fn matchAt(policy: Policy, source: []const u8, at: usize) ?Hit {
    const rest = source[at..];

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
    if (at != 0 and isTokenByte(source[at - 1])) return null;
    const len = matchPattern(rest) orelse return null;
    return .{ .len = len, .source = .pattern };
}

fn matchPattern(rest: []const u8) ?usize {
    if (matchPem(rest)) |len| return len;
    if (matchPrefixRun(rest, "AKIA", 16, isUpperAlnum)) |len| return len;
    if (matchPrefixRun(rest, "ghp_", 36, isAlnum)) |len| return len;
    if (matchPrefixRun(rest, "github_pat_", 22, isTokenByte)) |len| return len;
    if (matchJwt(rest)) |len| return len;
    return null;
}

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

const testing = std.testing;

const fake_credential = "sk-test-000000000000000000000000";

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
    const policy = Policy{};
    try testing.expect(policy.isEmpty());
    try testing.expectEqual(
        @as(?[]u8, null),
        try find(testing.allocator, policy, shapes.github),
    );
}

test "a known credential is replaced everywhere it appears" {
    const gpa = testing.allocator;
    const policy = Policy{ .secrets = &.{.{ .value = fake_credential, .source = .credential }} };

    const source = "curl -H auth: " ++ fake_credential ++ "\nrefused for " ++ fake_credential ++ ", retry\n";
    const cleaned = (try find(gpa, policy, source)).?;
    defer gpa.free(cleaned);

    try testing.expect(std.mem.indexOf(u8, cleaned, fake_credential) == null);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, cleaned, Source.credential.marker()));
    try testing.expect(std.mem.indexOf(u8, cleaned, "refused for ") != null);
    try testing.expect(std.mem.indexOf(u8, cleaned, ", retry\n") != null);
}

test "the marker names which layer caught it, and never the value" {
    const seen = [_]Source{ .credential, .declared, .pattern };
    for (seen) |source| {
        const marker = source.marker();
        try testing.expect(std.mem.startsWith(u8, marker, "[chock: "));
        try testing.expect(std.mem.endsWith(u8, marker, "]"));
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
    const gpa = testing.allocator;
    const policy = Policy{ .secrets = &.{.{ .value = "abc" }} };
    try testing.expectEqual(@as(usize, 1), policy.tooShort());
    try testing.expect(policy.isEmpty());
    try testing.expectEqual(@as(?[]u8, null), try find(gpa, policy, "abcdef abc abc"));
}

test "an empty slot is inert, counts as nothing, and takes a value later" {
    const gpa = testing.allocator;

    var slots = [_]Secret{
        .{ .value = "sk-a-real-looking-token-here", .source = .credential },
        .{ .value = "", .source = .credential },
    };
    var policy = Policy{ .secrets = &slots };

    try testing.expect(!policy.isEmpty());
    try testing.expectEqual(@as(usize, 0), policy.tooShort());

    const before = try text(gpa, policy, "plain words and nothing else");
    try testing.expectEqualStrings("plain words and nothing else", before);

    slots[1].value = "hunter2-correct-horse";
    policy = .{ .secrets = &slots };
    const after = try find(gpa, policy, "remote says hunter2-correct-horse is wrong");
    defer if (after) |one| gpa.free(one);
    try testing.expect(after != null);
    try testing.expect(std.mem.indexOf(u8, after.?, "hunter2-correct-horse") == null);

    slots[1].value = "";
    policy = .{ .secrets = &slots };
    try testing.expectEqual(@as(usize, 0), policy.tooShort());
    const again = try text(gpa, policy, "remote says hunter2-correct-horse is wrong");
    try testing.expectEqualStrings("remote says hunter2-correct-horse is wrong", again);
}

test "the longer of two overlapping secrets wins" {
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
    const gpa = testing.allocator;
    const policy = Policy{ .heuristics = true };
    const started = "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++ shapes.key_body_unfinished ++ "\n";
    const cleaned = (try find(gpa, policy, started)).?;
    defer gpa.free(cleaned);
    try testing.expect(std.mem.indexOf(u8, cleaned, shapes.key_body_unfinished) == null);
    try testing.expectEqualStrings(Source.pattern.marker(), cleaned);
}

test "a pattern does not fire in the middle of a word" {
    const gpa = testing.allocator;
    const policy = Policy{ .heuristics = true };
    try testing.expectEqual(
        @as(?[]u8, null),
        try find(gpa, policy, shapes.aws_in_a_word),
    );
}

test "a shape that is too short for its pattern is left alone" {
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

    try testing.expect(std.mem.indexOf(u8, out[1].reasoning.signature, fake_credential) != null);

    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, out[2].tool_use.arguments, .{});
    defer parsed.deinit();
    try testing.expect(parsed.value == .object);
}

test "every string a record holds is walked, and a field nobody named is too" {
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
    try testing.expect(std.mem.indexOf(u8, result.output, "printed ") != null);
    try testing.expectEqualStrings("c1", result.call_id);
    try testing.expect(!result.is_error);

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
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const said = "AKIAIOSFODNN7EXAMPLE";
    const content = [_]log_event.ContentPart{.{ .text = said }};
    const given = log_event.Event{ .message = .{ .role = .assistant, .content = &content } };

    const cleaned = try event(arena, Policy{}, given);
    try testing.expectEqual(@as([*]const log_event.ContentPart, &content), cleaned.message.content.ptr);
    try testing.expectEqual(said.ptr, cleaned.message.content[0].text.ptr);
}

test "the sentence about what this is not is held here and says so" {
    try testing.expect(std.mem.indexOf(u8, not_a_boundary, "never") != null);
    try testing.expect(std.mem.indexOf(u8, not_a_boundary, "accident") != null);
}
