//! The Model Context Protocol's own messages, as bytes to send and as answers
//! to read. There is one transport over pipes and another over HTTP, and they
//! share this file, so neither can read one reply a way the other does not.

const std = @import("std");

const mcp = @import("mcp.zig");

pub const protocol_version = "2025-06-18";

pub const client_name = "chock";

const empty_object = struct {}{};

pub fn initializeBody(arena: std.mem.Allocator, id: i64) std.mem.Allocator.Error![]u8 {
    return std.json.Stringify.valueAlloc(arena, .{
        .jsonrpc = "2.0",
        .id = id,
        .method = "initialize",
        // Params must be an object: `.{}` is a tuple and writes as `[]`.
        .params = .{
            .protocolVersion = protocol_version,
            .capabilities = empty_object,
            .clientInfo = .{ .name = client_name, .version = "1" },
        },
    }, .{});
}

pub fn initializedBody(arena: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
    return std.json.Stringify.valueAlloc(arena, .{
        .jsonrpc = "2.0",
        .method = "notifications/initialized",
        .params = empty_object,
    }, .{});
}

pub fn listBody(arena: std.mem.Allocator, id: i64) std.mem.Allocator.Error![]u8 {
    return std.json.Stringify.valueAlloc(arena, .{
        .jsonrpc = "2.0",
        .id = id,
        .method = "tools/list",
        .params = empty_object,
    }, .{});
}

/// `arguments` is whatever the model wrote. Anything that is not an object
/// becomes an empty one, because a tool call carries named arguments.
pub fn callBody(
    arena: std.mem.Allocator,
    id: i64,
    name: []const u8,
    arguments: []const u8,
) std.mem.Allocator.Error![]u8 {
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, arguments, .{}) catch
        std.json.Value.null;
    const args: std.json.Value = if (parsed == .object)
        parsed
    else
        std.json.parseFromSliceLeaky(std.json.Value, arena, "{}", .{}) catch
            return error.OutOfMemory;

    return std.json.Stringify.valueAlloc(arena, .{
        .jsonrpc = "2.0",
        .id = id,
        .method = "tools/call",
        .params = .{ .name = name, .arguments = args },
    }, .{});
}

/// The message itself when it answers `id`, and null for anything else. A
/// server may send its own requests and notifications first.
pub fn replyFor(message: std.json.Value, id: i64) ?std.json.Value {
    if (message != .object) return null;
    const object = message.object;
    if (object.get("method") != null) return null;

    const answered = object.get("id") orelse return null;
    if (answered != .integer or answered.integer != id) return null;
    if (object.get("result") == null and object.get("error") == null) return null;
    return message;
}

pub fn isListChanged(message: std.json.Value) bool {
    if (message != .object) return false;
    const method = message.object.get("method") orelse return false;
    if (method != .string) return false;
    return std.mem.eql(u8, method.string, "notifications/tools/list_changed");
}

/// Whether the server asked something of this client. Chock answers none of
/// them, and counting one is how a session shows it was asked.
pub fn isServerRequest(message: std.json.Value) bool {
    if (message != .object) return false;
    if (message.object.get("method") == null) return false;
    return message.object.get("id") != null;
}

/// The version the server answered the handshake with, or an empty string.
pub fn negotiatedIn(reply: std.json.Value) []const u8 {
    const result = objectField(reply, "result") orelse return "";
    const named = result.get("protocolVersion") orelse return "";
    if (named != .string) return "";
    return named.string;
}

pub fn declaredFrom(
    arena: std.mem.Allocator,
    reply: std.json.Value,
) std.mem.Allocator.Error![]const mcp.Declared {
    const result = objectField(reply, "result") orelse return &.{};
    const declared = result.get("tools") orelse return &.{};
    if (declared != .array) return &.{};

    var out: std.ArrayList(mcp.Declared) = .empty;
    for (declared.array.items) |item| {
        if (item != .object) continue;
        const name = item.object.get("name") orelse continue;
        if (name != .string) continue;
        const description = blk: {
            const raw = item.object.get("description") orelse break :blk "";
            if (raw != .string) break :blk "";
            break :blk raw.string;
        };
        const schema = item.object.get("inputSchema") orelse std.json.Value.null;
        try out.append(arena, .{
            .name = name.string,
            .description = description,
            .schema = schema,
        });
    }
    return out.toOwnedSlice(arena);
}

pub fn outcomeFrom(
    arena: std.mem.Allocator,
    reply: std.json.Value,
) std.mem.Allocator.Error!mcp.Outcome {
    if (objectField(reply, "error")) |failure| {
        const message = failure.get("message") orelse std.json.Value.null;
        const text = if (message == .string) message.string else "the server refused the call";
        return .{ .text = text, .is_error = true };
    }

    const result = objectField(reply, "result") orelse
        return .{ .text = "the server answered nothing", .is_error = true };

    var text: std.ArrayList(u8) = .empty;
    if (result.get("content")) |content| {
        if (content == .array) {
            for (content.array.items) |part| {
                if (part != .object) continue;
                const kind = part.object.get("type") orelse std.json.Value.null;
                const kind_name = if (kind == .string) kind.string else "";
                const body = part.object.get("text") orelse std.json.Value.null;
                if (body == .string and std.mem.eql(u8, kind_name, "text")) {
                    if (text.items.len != 0) try text.append(arena, '\n');
                    try text.appendSlice(arena, body.string);
                    continue;
                }
                if (text.items.len != 0) try text.append(arena, '\n');
                const named = try std.fmt.allocPrint(
                    arena,
                    "[chock: the server sent a {s} part, which this build does not carry]",
                    .{if (kind_name.len != 0) kind_name else "content"},
                );
                try text.appendSlice(arena, named);
            }
        }
    }

    const failed = blk: {
        const raw = result.get("isError") orelse break :blk false;
        if (raw != .bool) break :blk false;
        break :blk raw.bool;
    };
    return .{ .text = try text.toOwnedSlice(arena), .is_error = failed };
}

pub fn objectField(message: std.json.Value, name: []const u8) ?std.json.ObjectMap {
    if (message != .object) return null;
    const field = message.object.get(name) orelse return null;
    if (field != .object) return null;
    return field.object;
}

const testing = std.testing;

/// Answers a reference server gave over HTTP, kept as they arrived.
const real_list_reply =
    \\{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"Give back the text it was given.","inputSchema":{"properties":{"text":{"title":"Text","type":"string"}},"required":["text"],"title":"echoArguments","type":"object"},"outputSchema":{"properties":{"result":{"title":"Result","type":"string"}},"required":["result"],"title":"echoOutput","type":"object"}}]}}
;

const real_tool_fault =
    \\{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Error executing tool echo: 1 validation error"}],"isError":true}}
;

const real_method_error =
    \\{"jsonrpc":"2.0","id":4,"error":{"code":-32602,"message":"Invalid request parameters","data":""}}
;

fn parse(arena: std.mem.Allocator, text: []const u8) !std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
}

test "a real tools/list answer gives the tool, its words and its schema" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const declared = try declaredFrom(arena, try parse(arena, real_list_reply));
    try testing.expectEqual(@as(usize, 1), declared.len);
    try testing.expectEqualStrings("echo", declared[0].name);
    try testing.expectEqualStrings("Give back the text it was given.", declared[0].description);
    try testing.expect(declared[0].schema == .object);
    try testing.expect(declared[0].schema.object.get("properties") != null);
}

test "a tool that failed is an answer with its words, and never a dead server" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outcome = try outcomeFrom(arena, try parse(arena, real_tool_fault));
    try testing.expect(outcome.is_error);
    try testing.expectEqualStrings("Error executing tool echo: 1 validation error", outcome.text);
}

test "a method the server does not know is a JSON-RPC error, and its message is the answer" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outcome = try outcomeFrom(arena, try parse(arena, real_method_error));
    try testing.expect(outcome.is_error);
    try testing.expectEqualStrings("Invalid request parameters", outcome.text);
}

test "a part this build does not carry is named, and the text parts stay" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const reply = try parse(arena,
        \\{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"first"},{"type":"image","data":"AA"},{"type":"text","text":"last"}]}}
    );
    const outcome = try outcomeFrom(arena, reply);
    try testing.expect(!outcome.is_error);
    try testing.expectEqualStrings(
        "first\n[chock: the server sent a image part, which this build does not carry]\nlast",
        outcome.text,
    );
}

test "a result with nothing in it still answers, rather than reading as a fault" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outcome = try outcomeFrom(arena, try parse(arena,
        \\{"jsonrpc":"2.0","id":1,"result":{}}
    ));
    try testing.expect(!outcome.is_error);
    try testing.expectEqualStrings("", outcome.text);

    const nothing = try outcomeFrom(arena, try parse(arena,
        \\{"jsonrpc":"2.0","id":1}
    ));
    try testing.expect(nothing.is_error);
    try testing.expectEqualStrings("the server answered nothing", nothing.text);
}

test "a reply is the one with this id, and a server's own message is not a reply" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const answer = try parse(arena, real_list_reply);
    try testing.expect(replyFor(answer, 2) != null);
    try testing.expect(replyFor(answer, 3) == null);

    const asked = try parse(arena,
        \\{"jsonrpc":"2.0","id":2,"method":"sampling/createMessage","params":{}}
    );
    try testing.expect(replyFor(asked, 2) == null);
    try testing.expect(isServerRequest(asked));

    const told = try parse(arena,
        \\{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}
    );
    try testing.expect(replyFor(told, 2) == null);
    try testing.expect(isListChanged(told));
    try testing.expect(!isServerRequest(told));

    const half = try parse(arena,
        \\{"jsonrpc":"2.0","id":2}
    );
    try testing.expect(replyFor(half, 2) == null);
}

test "the handshake's own answer carries the version the server settled on" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const reply = try parse(arena,
        \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{}}}
    );
    try testing.expectEqualStrings("2025-03-26", negotiatedIn(reply));

    const silent = try parse(arena,
        \\{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}
    );
    try testing.expectEqualStrings("", negotiatedIn(silent));
}

test "a body names its method, and arguments that are not an object become one" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const opening = try initializeBody(arena, 1);
    try testing.expect(std.mem.indexOf(u8, opening, "\"method\":\"initialize\"") != null);
    try testing.expect(std.mem.indexOf(u8, opening, "\"capabilities\":{}") != null);

    const listing = try listBody(arena, 2);
    try testing.expect(std.mem.indexOf(u8, listing, "\"method\":\"tools/list\"") != null);
    try testing.expect(std.mem.indexOf(u8, listing, "\"params\":{}") != null);

    const calling = try callBody(arena, 3, "echo", "{\"text\":\"hei\"}");
    try testing.expect(std.mem.indexOf(u8, calling, "\"name\":\"echo\"") != null);
    try testing.expect(std.mem.indexOf(u8, calling, "\"text\":\"hei\"") != null);

    const bare = try callBody(arena, 4, "echo", "not json at all");
    try testing.expect(std.mem.indexOf(u8, bare, "\"arguments\":{}") != null);

    const told = try initializedBody(arena);
    try testing.expect(std.mem.indexOf(u8, told, "\"id\"") == null);
}
