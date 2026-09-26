//! The JSON-RPC 2.0 envelope ACP speaks, and the framing that carries it.
//!
//! ## The framing is the newline, and one write is what keeps it
//!
//! ACP's stdio transport says a message is one line: delimited by `\n`, and it
//! **must not** hold an embedded newline. So a message and its newline go out in
//! one `writeAll`. Two writes would let a message reach the wire with no newline
//! behind it, which joins it to the next one and breaks every message after.
//! `lib/chock-core/mcp_driver.zig` learned that against a real server and says
//! so; this is the same rule on the other side of the wire.
//!
//! ## Nothing but a message may reach standard output
//!
//! The transport says the agent must not write anything to `stdout` that is not
//! a valid ACP message. Chock's own `tty.print` already goes to standard error,
//! which the transport permits for logging, so the rule costs nothing as long as
//! no caller reaches for standard output.
//!
//! ## An id is echoed and never read
//!
//! JSON-RPC lets an id be a number or a string, and a response carries back the
//! id it answers. This holds the id as the bytes it arrived as, so a client that
//! sends a string gets that string back. A peer that renumbered ids would fail
//! against a client that matches on them.

const std = @import("std");

pub const version = "2.0";

/// The largest message this reader accepts before it gives up on the line.
///
/// A peer that writes more than this with no newline is one this cannot frame,
/// and reading on would grow without a bound somebody chose.
pub const max_message_bytes: usize = 4 * 1024 * 1024;

/// Predefined codes, from the ACP schema's own `ErrorCode`. The first five are
/// JSON-RPC 2.0's; the rest are ACP's, inside the reserved range.
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

/// A request's identity, as the bytes it arrived as. See this file's own note on
/// why it is not read.
pub const Id = struct {
    /// The JSON token, so `7` stays `7` and `"a"` stays `"a"`.
    raw: []const u8,

    pub fn isNull(self: Id) bool {
        return std.mem.eql(u8, self.raw, "null");
    }

    pub const null_id = Id{ .raw = "null" };
};

/// What arrived on the wire. A notification is a request with no id, which is
/// the only thing that separates the two in JSON-RPC.
pub const Incoming = struct {
    id: ?Id,
    method: []const u8,
    /// The `params` member as raw JSON, for the caller that knows the method to
    /// parse into its own type. Empty when there were none.
    params: []const u8,

    pub fn isNotification(self: Incoming) bool {
        return self.id == null;
    }
};

/// A reply to something this side asked. It carries an id and no method, which
/// is what separates it from a request.
pub const Reply = struct {
    id: Id,
    /// The `result` member as raw JSON. Empty when the reply carried an error.
    result: []const u8,
    /// The `error.message` when the peer refused, and null when it did not.
    refusal: ?[]const u8 = null,

    pub fn failed(self: Reply) bool {
        return self.refusal != null;
    }
};

/// Either direction of traffic. A peer that both answers and asks reads every
/// line through this, because a reply and a request arrive on the same wire.
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

/// Read one message, whichever direction it is going.
///
/// A request has a method; a reply has an id and none. Nothing else tells them
/// apart, so a caller that only ever parsed requests would refuse every answer
/// to its own questions.
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

/// Read one message. `line` is one frame with its newline already removed.
///
/// The `jsonrpc` member is checked rather than ignored: a peer speaking another
/// version would have every field mean something else, and answering it as
/// though it were 2.0 would be worse than refusing it.
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

/// An id as the token it arrived as. Null for a `null` id, which is a request
/// nothing can answer.
fn readId(arena: std.mem.Allocator, held: std.json.Value) ParseError!?Id {
    return switch (held) {
        .integer => |number| .{ .raw = try std.fmt.allocPrint(arena, "{d}", .{number}) },
        // `std.json.fmt` writes the quotes itself, so the id is already a JSON
        // string token here.
        .string => |text| .{ .raw = try std.fmt.allocPrint(arena, "{f}", .{std.json.fmt(text, .{})}) },
        .null => null,
        // A float or an object is not an id at all.
        else => error.BadId,
    };
}

pub const WriteError = error{
    OutOfMemory,
    /// The message holds a newline, which the framing cannot carry. Raised
    /// rather than written, because writing it would break every message after.
    EmbeddedNewline,
    WriteFailed,
};

/// One message and its newline, in one `writeAll`. See this file's own note.
///
/// `body` is the whole JSON object without its newline. It is checked for a
/// newline first: JSON escapes one inside a string as `\n`, so a raw newline in
/// a serialized message is a caller's fault and not a peer's.
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

/// A reply carrying a result. `result` is raw JSON, so the caller serializes its
/// own payload and this only puts the envelope around it.
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

/// A reply carrying an error. The message is the peer's to read, so it says what
/// happened and never what the code was.
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

/// A request this side asks the peer. The id is this side's to choose, and the
/// peer echoes it back.
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

/// A notification: a method and its params, with no id, so nothing answers it.
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

    // A null id is nothing anything can answer, so it is read as a
    // notification rather than as an id spelled `null`.
    const nulled = try parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"x\"}");
    try testing.expect(nulled.isNotification());
}

test "a string id is echoed as a string and a number as a number" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = arenaFor(&state);

    const named = try parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":\"a-1\",\"method\":\"x\"}");
    try testing.expectEqualStrings("\"a-1\"", named.id.?.raw);

    // The reply puts the id back as it arrived, so a client matching on the
    // exact token finds its own request.
    const reply = try resultBody(arena, named.id.?, "{\"ok\":true}");
    try testing.expect(std.mem.indexOf(u8, reply, "\"id\":\"a-1\"") != null);

    const numbered = try parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"x\"}");
    const numbered_reply = try resultBody(arena, numbered.id.?, "");
    try testing.expect(std.mem.indexOf(u8, numbered_reply, "\"id\":12") != null);
    // No result is `null` and never an absent member: a response object must
    // hold one of result or error.
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

    // The framing cannot carry it, so it is refused where it can still be
    // fixed rather than written where it breaks every message after.
    try testing.expectError(
        error.EmbeddedNewline,
        writeFrame(arena, &sink, "{\"a\":\"one\ntwo\"}"),
    );
}

test "a newline inside a string is escaped, so a real message still frames" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = arenaFor(&state);

    // This is the ordinary case: an agent's message chunk holds newlines, and
    // JSON escapes them, so the frame stays one line.
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
    // Escaped, so the object still parses. Built by hand here, so this is the
    // test that the hand built one is still JSON.
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

    // A null result is a reply that succeeded and returned nothing, which is
    // what every notification style method answers with.
    const empty = try parseAny(arena, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":null}");
    try testing.expect(!empty.reply.failed());
    try testing.expectEqualStrings("", empty.reply.result);

    // A reply with no id is nothing this side can match to a question it asked.
    try testing.expectError(error.BadId, parseAny(arena, "{\"jsonrpc\":\"2.0\",\"result\":1}"));
}
