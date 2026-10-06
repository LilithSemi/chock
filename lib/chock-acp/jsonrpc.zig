//! The JSON-RPC 2.0 envelope ACP speaks, and the framing that carries it.
//! A message is one line, so it and its newline go out in one write, or a
//! second write could let another message land between them. An id is held as the exact bytes it arrived as, and echoed back.

const std = @import("std");

pub const version = "2.0";

pub const max_message_bytes: usize = 4 * 1024 * 1024;

/// From `ErrorCode`: the first five are JSON-RPC's, the rest ACP's.
pub const Code = enum(i32) {
    parse_error = -32700,
    invalid_request = -32600,
    method_not_found = -32601,
    invalid_params = -32602,
    internal_error = -32603,
    request_cancelled = -32800,
    authentication_required = -32000,
    resource_not_found = -32002,

    pub fn text(self: Code) []const u8 {
        return switch (self) {
            .parse_error => "invalid JSON was received",
            .invalid_request => "the JSON sent is not a valid Request object",
            .method_not_found => "the method does not exist or is not available",
            .invalid_params => "invalid method parameters",
            .internal_error => "internal error",
            .request_cancelled => "the method was aborted",
            .authentication_required => "authentication is required before this",
            .resource_not_found => "the resource was not found",
        };
    }
};

/// Held as arrived, never parsed, so it echoes back exactly.
pub const Id = struct {
    /// The JSON token, so `7` stays `7` and `"a"` stays `"a"`.
    raw: []const u8,

    pub fn isNull(self: Id) bool {
        return std.mem.eql(u8, self.raw, "null");
    }

    pub const null_id = Id{ .raw = "null" };
};

/// A notification has no id; nothing else differs.
pub const Incoming = struct {
    id: ?Id,
    method: []const u8,
    /// Raw JSON; empty when there were none.
    params: []const u8,

    pub fn isNotification(self: Incoming) bool {
        return self.id == null;
    }
};

pub const Reply = struct {
    id: Id,
    /// Raw JSON; empty when the reply carried an error.
    result: []const u8,
    /// `error.message` if refused, null otherwise.
    refusal: ?[]const u8 = null,

    pub fn failed(self: Reply) bool {
        return self.refusal != null;
    }
};

/// Either direction, for a peer that both asks and answers.
pub const Any = union(enum) {
    request: Incoming,
    reply: Reply,
};

pub const ParseError = error{
    OutOfMemory,
    NotAnObject,
    WrongVersion,
    NoMethod,
    BadId,
};

/// Only a method, or its absence, tells a request from a reply.
pub fn parseAny(arena: std.mem.Allocator, line: []const u8) ParseError!Any {
    const parsed = std.json.parseFromSlice(std.json.Value, arena, line, .{}) catch
        return error.NotAnObject;

    const object = switch (parsed.value) {
        .object => |one| one,
        else => return error.NotAnObject,
    };

    const said = object.get("jsonrpc") orelse return error.WrongVersion;
    switch (said) {
        .string => |text| if (!std.mem.eql(u8, text, version)) return error.WrongVersion,
        else => return error.WrongVersion,
    }

    if (object.get("method") != null) return .{ .request = try parse(arena, line) };

    const id = try readId(arena, object.get("id") orelse return error.BadId) orelse
        return error.BadId;

    if (object.get("error")) |held| {
        const message = switch (held) {
            .object => |one| switch (one.get("message") orelse std.json.Value{ .null = {} }) {
                .string => |text| text,
                else => "the peer refused and said nothing",
            },
            else => "the peer refused and said nothing",
        };
        return .{ .reply = .{ .id = id, .result = "", .refusal = message } };
    }

    const result = if (object.get("result")) |held| switch (held) {
        .null => "",
        else => try std.json.Stringify.valueAlloc(arena, held, .{}),
    } else "";
    return .{ .reply = .{ .id = id, .result = result } };
}

/// `jsonrpc` is checked; another version could mean anything.
pub fn parse(arena: std.mem.Allocator, line: []const u8) ParseError!Incoming {
    const parsed = std.json.parseFromSlice(std.json.Value, arena, line, .{}) catch
        return error.NotAnObject;

    const object = switch (parsed.value) {
        .object => |one| one,
        else => return error.NotAnObject,
    };

    const said = object.get("jsonrpc") orelse return error.WrongVersion;
    switch (said) {
        .string => |text| if (!std.mem.eql(u8, text, version)) return error.WrongVersion,
        else => return error.WrongVersion,
    }

    const method = switch (object.get("method") orelse return error.NoMethod) {
        .string => |text| text,
        else => return error.NoMethod,
    };

    var id: ?Id = null;
    if (object.get("id")) |held| id = try readId(arena, held);

    const params = if (object.get("params")) |held| switch (held) {
        .null => "",
        else => try std.json.Stringify.valueAlloc(arena, held, .{}),
    } else "";

    return .{ .id = id, .method = method, .params = params };
}

/// Null for a `null` id, a request nothing can answer.
fn readId(arena: std.mem.Allocator, held: std.json.Value) ParseError!?Id {
    return switch (held) {
        .integer => |number| .{ .raw = try std.fmt.allocPrint(arena, "{d}", .{number}) },
        // `std.json.fmt` already writes the quotes: this is already a string token.
        .string => |text| .{ .raw = try std.fmt.allocPrint(arena, "{f}", .{std.json.fmt(text, .{})}) },
        .null => null,
        // A float or an object is not an id at all.
        else => error.BadId,
    };
}

pub const WriteError = error{
    OutOfMemory,
    EmbeddedNewline,
    WriteFailed,
};

/// A raw newline here is the caller's fault; JSON would have escaped one in a string.
pub fn writeFrame(
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    body: []const u8,
) WriteError!void {
    if (std.mem.indexOfScalar(u8, body, '\n') != null) return error.EmbeddedNewline;

    const framed = try std.fmt.allocPrint(arena, "{s}\n", .{body});
    writer.writeAll(framed) catch return error.WriteFailed;
    writer.flush() catch return error.WriteFailed;
}

/// `result` is raw JSON; this only wraps it in the envelope.
pub fn resultBody(
    arena: std.mem.Allocator,
    id: Id,
    result: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        arena,
        "{{\"jsonrpc\":\"{s}\",\"id\":{s},\"result\":{s}}}",
        .{ version, id.raw, if (result.len == 0) "null" else result },
    );
}

/// The message is the peer's to read: it says what happened, never the code.
pub fn errorBody(
    arena: std.mem.Allocator,
    id: Id,
    code: Code,
    said: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        arena,
        "{{\"jsonrpc\":\"{s}\",\"id\":{s},\"error\":{{\"code\":{d},\"message\":{f}}}}}",
        .{ version, id.raw, @intFromEnum(code), std.json.fmt(said, .{}) },
    );
}

/// The id is this side's to choose; the peer echoes it back.
pub fn requestBody(
    arena: std.mem.Allocator,
    id: Id,
    method: []const u8,
    params: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        arena,
        "{{\"jsonrpc\":\"{s}\",\"id\":{s},\"method\":{f},\"params\":{s}}}",
        .{ version, id.raw, std.json.fmt(method, .{}), if (params.len == 0) "null" else params },
    );
}

pub fn notificationBody(
    arena: std.mem.Allocator,
    method: []const u8,
    params: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        arena,
        "{{\"jsonrpc\":\"{s}\",\"method\":{f},\"params\":{s}}}",
        .{ version, std.json.fmt(method, .{}), if (params.len == 0) "null" else params },
    );
}

const testing = std.testing;

fn arenaFor(state: *std.heap.ArenaAllocator) std.mem.Allocator {
    return state.allocator();
}

test "a request carries its method, its params and its id" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = arenaFor(&state);

    const one = try parse(arena,
        \\{"jsonrpc":"2.0","id":7,"method":"session/prompt","params":{"sessionId":"s1"}}
    );
    try testing.expectEqualStrings("session/prompt", one.method);
    try testing.expectEqualStrings("7", one.id.?.raw);
    try testing.expect(!one.isNotification());
    try testing.expect(std.mem.indexOf(u8, one.params, "\"sessionId\":\"s1\"") != null);
}

test "a message with no id is a notification, which is the only difference" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = arenaFor(&state);

    const one = try parse(arena,
        \\{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"s1"}}
    );
    try testing.expect(one.isNotification());
    try testing.expectEqual(@as(?Id, null), one.id);

    // A null id reads as a notification, never as a literal `null`.
    const nulled = try parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"x\"}");
    try testing.expect(nulled.isNotification());
}

test "a string id is echoed as a string and a number as a number" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = arenaFor(&state);

    const named = try parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":\"a-1\",\"method\":\"x\"}");
    try testing.expectEqualStrings("\"a-1\"", named.id.?.raw);

    const reply = try resultBody(arena, named.id.?, "{\"ok\":true}");
    try testing.expect(std.mem.indexOf(u8, reply, "\"id\":\"a-1\"") != null);

    const numbered = try parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"x\"}");
    const numbered_reply = try resultBody(arena, numbered.id.?, "");
    try testing.expect(std.mem.indexOf(u8, numbered_reply, "\"id\":12") != null);
    try testing.expect(std.mem.indexOf(u8, numbered_reply, "\"result\":null") != null);
}

test "another version is refused rather than read as this one" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = arenaFor(&state);

    try testing.expectError(error.WrongVersion, parse(arena, "{\"jsonrpc\":\"1.0\",\"method\":\"x\"}"));
    try testing.expectError(error.WrongVersion, parse(arena, "{\"method\":\"x\"}"));
    try testing.expectError(error.NoMethod, parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":1}"));
    try testing.expectError(error.NotAnObject, parse(arena, "[1,2]"));
    try testing.expectError(error.NotAnObject, parse(arena, "not json at all"));
}

test "a frame is one write, and a body holding a newline is refused" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = arenaFor(&state);

    var buffer: [256]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&buffer);

    try writeFrame(arena, &sink, "{\"a\":1}");
    try testing.expectEqualStrings("{\"a\":1}\n", sink.buffered());

    try testing.expectError(
        error.EmbeddedNewline,
        writeFrame(arena, &sink, "{\"a\":\"one\ntwo\"}"),
    );
}

test "a newline inside a string is escaped, so a real message still frames" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = arenaFor(&state);

    const body = try notificationBody(
        arena,
        "session/update",
        try std.json.Stringify.valueAlloc(arena, .{ .text = "one\ntwo" }, .{}),
    );
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, body, '\n'));
    try testing.expect(std.mem.indexOf(u8, body, "one\\ntwo") != null);

    var buffer: [256]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&buffer);
    try writeFrame(arena, &sink, body);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sink.buffered(), "\n"));
}

test "an error reply names the code and says what happened" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = arenaFor(&state);

    const body = try errorBody(arena, .{ .raw = "3" }, .method_not_found, Code.method_not_found.text());
    try testing.expect(std.mem.indexOf(u8, body, "\"code\":-32601") != null);
    try testing.expect(std.mem.indexOf(u8, body, "does not exist") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"id\":3") != null);

    // Every code has a message, so no refusal goes out with an empty one.
    inline for (@typeInfo(Code).@"enum".fields) |field| {
        const code: Code = @enumFromInt(field.value);
        try testing.expect(code.text().len != 0);
    }
}

test "a quote in a message cannot end the JSON string it is in" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = arenaFor(&state);

    const body = try errorBody(arena, .null_id, .invalid_params, "the tool \"gh\" is unknown");
    var reparsed = try std.json.parseFromSlice(std.json.Value, arena, body, .{});
    const said = reparsed.value.object.get("error").?.object.get("message").?.string;
    try testing.expectEqualStrings("the tool \"gh\" is unknown", said);
}

test "a reply is told from a request by its method, and by nothing else" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = arenaFor(&state);

    const asked = try parseAny(arena,
        \\{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{}}
    );
    try testing.expect(asked == .request);
    try testing.expectEqualStrings("session/prompt", asked.request.method);

    const answered = try parseAny(arena,
        \\{"jsonrpc":"2.0","id":1,"result":{"outcome":{"outcome":"selected","optionId":"allow"}}}
    );
    try testing.expect(answered == .reply);
    try testing.expectEqualStrings("1", answered.reply.id.raw);
    try testing.expect(!answered.reply.failed());
    try testing.expect(std.mem.indexOf(u8, answered.reply.result, "selected") != null);
}

test "a refusal carries what the peer said, and an empty result is not a refusal" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = arenaFor(&state);

    const refused = try parseAny(arena,
        \\{"jsonrpc":"2.0","id":"a","error":{"code":-32601,"message":"no such method"}}
    );
    try testing.expect(refused.reply.failed());
    try testing.expectEqualStrings("no such method", refused.reply.refusal.?);
    try testing.expectEqualStrings("\"a\"", refused.reply.id.raw);

    const empty = try parseAny(arena, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":null}");
    try testing.expect(!empty.reply.failed());
    try testing.expectEqualStrings("", empty.reply.result);

    try testing.expectError(error.BadId, parseAny(arena, "{\"jsonrpc\":\"2.0\",\"result\":1}"));
}
