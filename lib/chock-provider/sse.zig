//! Server sent events, and the tool call fragments a streaming response splits

const std = @import("std");
const message = @import("message.zig");

pub const Event = union(enum) {
    data: Data,
    done,

    pub fn deinit(self: Event, allocator: std.mem.Allocator) void {
        switch (self) {
            .data => |data| data.deinit(allocator),
            .done => {},
        }
    }
};

pub const Data = struct {
    name: []const u8,
    body: []const u8,

    pub fn deinit(self: Data, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.body);
    }
};

pub const Parser = struct {
    allocator: std.mem.Allocator,
    line_buf: std.ArrayList(u8) = .empty,
    pending: std.ArrayList(u8) = .empty,
    pending_name: std.ArrayList(u8) = .empty,
    have_pending: bool = false,
    skip_to_blank: bool = false,
    events: std.ArrayList(Event) = .empty,
    events_read: usize = 0,
    compactions: usize = 0,

    pub const max_line_bytes: usize = 4 * 1024 * 1024;
    pub const max_pending_bytes: usize = 2 * max_line_bytes;
    pub const max_queued_events: usize = 200_000;

    pub const Error = std.mem.Allocator.Error || error{
        LineTooLong,
        EventTooLarge,
        TooManyQueuedEvents,
    };

    pub fn init(allocator: std.mem.Allocator) Parser {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Parser) void {
        for (self.events.items[self.events_read..]) |event| event.deinit(self.allocator);
        self.events.deinit(self.allocator);
        self.pending.deinit(self.allocator);
        self.pending_name.deinit(self.allocator);
        self.line_buf.deinit(self.allocator);
    }

    pub const FinishStatus = enum {
        complete,
        truncated,
    };

    pub fn finish(self: *const Parser) FinishStatus {
        if (self.line_buf.items.len != 0 or self.have_pending) return .truncated;
        return .complete;
    }

    fn findLineBreak(buf: []const u8, start: usize) ?struct { end: usize, next: usize } {
        var i = start;
        while (i < buf.len) : (i += 1) {
            switch (buf[i]) {
                '\n' => return .{ .end = i, .next = i + 1 },
                '\r' => {
                    if (i + 1 >= buf.len) return null;
                    const break_end: usize = if (buf[i + 1] == '\n') i + 2 else i + 1;
                    return .{ .end = i, .next = break_end };
                },
                else => {},
            }
        }
        return null;
    }

    pub fn feed(self: *Parser, bytes: []const u8) Error!void {
        // A chunk this large with no line break would stay buffered forever. Clear pending data too, so later input does not glue onto this rejected line.
        if (findLineBreak(bytes, 0) == null and self.line_buf.items.len + bytes.len > max_line_bytes) {
            self.line_buf.clearAndFree(self.allocator);
            self.dropPendingEvent();
            return error.LineTooLong;
        }
        try self.line_buf.appendSlice(self.allocator, bytes);

        // Bytes are consumed whether processLine accepts them or not, so the buffer still compacts past this line after an error, or feed() would reprocess the same bytes next call.
        var start: usize = 0;
        var line_error: ?Error = null;
        while (findLineBreak(self.line_buf.items, start)) |brk| {
            // A complete line past the cap is rejected here too, terminated or not.
            if (brk.end - start > max_line_bytes) {
                start = brk.next;
                line_error = error.LineTooLong;
                break;
            }
            const line = self.line_buf.items[start..brk.end];
            start = brk.next;
            self.processLine(line) catch |err| {
                line_error = err;
                break;
            };
        }

        // Compacts once per call, not once per line, so draining many small lines costs O(bytes), not O(lines squared).
        const remaining = self.line_buf.items.len - start;
        std.mem.copyForwards(u8, self.line_buf.items[0..remaining], self.line_buf.items[start..]);
        self.line_buf.shrinkRetainingCapacity(remaining);
        self.compactions += 1;

        if (line_error) |err| {
            // An event in progress is dropped here, so a clean event fed afterward does not glue onto its leftovers.
            if (err == error.LineTooLong) self.dropPendingEvent();
            return err;
        }

        if (self.line_buf.items.len > max_line_bytes) {
            self.line_buf.clearAndFree(self.allocator);
            self.dropPendingEvent();
            return error.LineTooLong;
        }
    }

    fn processLine(self: *Parser, line: []const u8) Error!void {
        if (self.skip_to_blank) {
            // Everything up to the discarded event's own blank line is swallowed here, not treated as a new event.
            if (line.len == 0) self.skip_to_blank = false;
            return;
        }
        if (line.len == 0) {
            if (!self.have_pending) {
                // A blank line with nothing pending dispatches no event but still resets the event name, per the SSE spec.
                self.pending_name.clearRetainingCapacity();
                return;
            }
            try self.finishEvent();
            return;
        }

        const colon = std.mem.indexOfScalar(u8, line, ':');
        const field = if (colon) |c| line[0..c] else line;
        // id: and retry: are not read here. An SSE comment line such as ": keep-alive" has an empty field name too, so it falls through the same check.
        const is_data = std.mem.eql(u8, field, "data");
        const is_name = std.mem.eql(u8, field, "event");
        if (!is_data and !is_name) return;

        var value: []const u8 = "";
        if (colon) |c| {
            value = line[c + 1 ..];
            if (value.len != 0 and value[0] == ' ') value = value[1..];
        }

        if (is_name) {
            self.pending_name.clearRetainingCapacity();
            try self.pending_name.appendSlice(self.allocator, value);
            return;
        }

        // A second data: line in the same event joins onto the first with a newline, per the SSE spec.
        if (self.have_pending) try self.pending.append(self.allocator, '\n');
        try self.pending.appendSlice(self.allocator, value);
        self.have_pending = true;

        if (self.pending.items.len > max_pending_bytes) {
            self.dropPendingEvent();
            self.skip_to_blank = true;
            return error.EventTooLarge;
        }
    }

    fn dropPendingEvent(self: *Parser) void {
        self.pending.clearAndFree(self.allocator);
        self.pending_name.clearAndFree(self.allocator);
        self.have_pending = false;
    }

    fn finishEvent(self: *Parser) Error!void {
        defer {
            self.pending.clearRetainingCapacity();
            self.pending_name.clearRetainingCapacity();
            self.have_pending = false;
        }
        if (std.mem.eql(u8, self.pending.items, "[DONE]")) {
            try self.events.append(self.allocator, .done);
        } else {
            const body = try self.allocator.dupe(u8, self.pending.items);
            errdefer self.allocator.free(body);
            const name = try self.allocator.dupe(u8, self.pending_name.items);
            errdefer self.allocator.free(name);
            try self.events.append(self.allocator, .{ .data = .{ .name = name, .body = body } });
        }
        // Nothing else bounds how many parsed events queue if the caller never drains. This only tells the caller to drain before feeding more.
        if (self.events.items.len - self.events_read > max_queued_events) return error.TooManyQueuedEvents;
    }

    pub fn next(self: *Parser) ?Event {
        if (self.events_read == self.events.items.len) {
            self.events_read = 0;
            self.events.clearRetainingCapacity();
            return null;
        }
        const event = self.events.items[self.events_read];
        self.events_read += 1;
        return event;
    }
};

pub const ToolCallFragment = message.ToolCallFragment;

pub const ToolCall = struct {
    index: usize,
    id: []const u8,
    name: []const u8,
    arguments: []const u8,
    complete: bool,
};

pub const ToolCallAssembler = struct {
    allocator: std.mem.Allocator,
    entries: std.AutoArrayHashMapUnmanaged(usize, Entry) = .empty,
    lookup_steps: usize = 0,

    const Entry = struct {
        id: std.ArrayList(u8) = .empty,
        name: std.ArrayList(u8) = .empty,
        arguments: std.ArrayList(u8) = .empty,
        has_id: bool = false,
        has_name: bool = false,
    };

    pub const max_arguments_bytes: usize = 16 * 1024 * 1024;

    pub const Error = std.mem.Allocator.Error || error{
        ArgumentsTooLarge,
    };

    pub fn init(allocator: std.mem.Allocator) ToolCallAssembler {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ToolCallAssembler) void {
        for (self.entries.values()) |*entry| {
            entry.id.deinit(self.allocator);
            entry.name.deinit(self.allocator);
            entry.arguments.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
    }

    fn entryFor(self: *ToolCallAssembler, index: usize) std.mem.Allocator.Error!*Entry {
        self.lookup_steps += 1;
        const result = try self.entries.getOrPut(self.allocator, index);
        if (!result.found_existing) result.value_ptr.* = .{};
        return result.value_ptr;
    }

    pub fn feed(self: *ToolCallAssembler, fragment: ToolCallFragment) Error!void {
        const entry = try self.entryFor(fragment.index);
        if (fragment.id) |id| {
            entry.id.clearRetainingCapacity();
            try entry.id.appendSlice(self.allocator, id);
            entry.has_id = true;
        }
        if (fragment.name) |name| {
            entry.name.clearRetainingCapacity();
            try entry.name.appendSlice(self.allocator, name);
            entry.has_name = true;
        }
        if (fragment.arguments) |arguments| {
            if (entry.arguments.items.len + arguments.len > max_arguments_bytes) return error.ArgumentsTooLarge;
            try entry.arguments.appendSlice(self.allocator, arguments);
        }
    }

    pub fn finished(self: *ToolCallAssembler) std.mem.Allocator.Error![]const ToolCall {
        var out: std.ArrayList(ToolCall) = .empty;
        errdefer {
            for (out.items) |call| {
                self.allocator.free(call.id);
                self.allocator.free(call.name);
                self.allocator.free(call.arguments);
            }
            out.deinit(self.allocator);
        }
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const entry = kv.value_ptr.*;
            const id = try self.allocator.dupe(u8, entry.id.items);
            errdefer self.allocator.free(id);
            const name = try self.allocator.dupe(u8, entry.name.items);
            errdefer self.allocator.free(name);
            const arguments = try self.allocator.dupe(u8, entry.arguments.items);
            try out.append(self.allocator, .{
                .index = kv.key_ptr.*,
                .id = id,
                .name = name,
                .arguments = arguments,
                .complete = entry.has_id and entry.has_name,
            });
        }
        return out.toOwnedSlice(self.allocator);
    }
};

pub fn freeFinished(allocator: std.mem.Allocator, calls: []const ToolCall) void {
    for (calls) |call| {
        allocator.free(call.id);
        allocator.free(call.name);
        allocator.free(call.arguments);
    }
    allocator.free(calls);
}

const ApplyDeltaError = error{
    BodyNotObject,
    MissingChoices,
    ChoicesNotArray,
    NoChoices,
    ChoiceNotObject,
    MissingDelta,
    DeltaNotObject,
    ToolCallsNotArray,
    ToolCallNotObject,
    ToolCallMissingIndex,
    ToolCallIndexNotInteger,
    ToolCallIndexNegative,
    ToolCallFunctionNotObject,
} || ToolCallAssembler.Error || std.json.ParseError(std.json.Scanner);

const ParsedDelta = struct {
    content: ?[]const u8 = null,
    reasoning_content: ?[]const u8 = null,
    fragments: std.ArrayList(ToolCallFragment) = .empty,

    fn deinit(self: *ParsedDelta, allocator: std.mem.Allocator) void {
        self.fragments.deinit(allocator);
    }
};

fn parseDelta(allocator: std.mem.Allocator, delta: std.json.ObjectMap) ApplyDeltaError!ParsedDelta {
    var out = ParsedDelta{};
    errdefer out.deinit(allocator);

    if (delta.get("content")) |content_value| {
        if (content_value == .string) out.content = content_value.string;
    }
    if (delta.get("reasoning_content")) |reasoning_value| {
        if (reasoning_value == .string) out.reasoning_content = reasoning_value.string;
    }

    if (delta.get("tool_calls")) |tool_calls_value| {
        if (tool_calls_value != .array) return error.ToolCallsNotArray;
        for (tool_calls_value.array.items) |call_value| {
            if (call_value != .object) return error.ToolCallNotObject;
            const call = call_value.object;

            const index_value = call.get("index") orelse return error.ToolCallMissingIndex;
            if (index_value != .integer) return error.ToolCallIndexNotInteger;
            if (index_value.integer < 0) return error.ToolCallIndexNegative;
            var fragment = ToolCallFragment{ .index = @intCast(index_value.integer) };

            if (call.get("id")) |id_value| {
                if (id_value == .string) fragment.id = id_value.string;
            }
            if (call.get("function")) |function_value| {
                if (function_value != .object) return error.ToolCallFunctionNotObject;
                const function = function_value.object;
                if (function.get("name")) |name_value| {
                    if (name_value == .string) fragment.name = name_value.string;
                }
                if (function.get("arguments")) |arguments_value| {
                    if (arguments_value == .string) fragment.arguments = arguments_value.string;
                }
            }
            try out.fragments.append(allocator, fragment);
        }
    }
    return out;
}

fn applyDeltaJson(
    allocator: std.mem.Allocator,
    assembler: *ToolCallAssembler,
    text_out: *std.ArrayList(u8),
    reasoning_out: *std.ArrayList(u8),
    json_text: []const u8,
) ApplyDeltaError!void {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.BodyNotObject;
    const choices_value = parsed.value.object.get("choices") orelse return error.MissingChoices;
    if (choices_value != .array) return error.ChoicesNotArray;
    if (choices_value.array.items.len == 0) return error.NoChoices;

    const choice_value = choices_value.array.items[0];
    if (choice_value != .object) return error.ChoiceNotObject;
    const delta_value = choice_value.object.get("delta") orelse return error.MissingDelta;
    if (delta_value != .object) return error.DeltaNotObject;

    // Nothing is written to text_out, reasoning_out, or assembler until parseDelta validates the whole delta, so an error here leaves nothing partially applied.
    var delta = try parseDelta(allocator, delta_value.object);
    defer delta.deinit(allocator);

    if (delta.content) |content| try text_out.appendSlice(allocator, content);
    if (delta.reasoning_content) |reasoning| try reasoning_out.appendSlice(allocator, reasoning);
    for (delta.fragments.items) |fragment| try assembler.feed(fragment);
}

test "a data line split across two reads produces one event" {
    const allocator = std.testing.allocator;
    const raw = @embedFile("testdata/unicode_content_event.sse");

    var parser = Parser.init(allocator);
    defer parser.deinit();

    for (raw) |byte| try parser.feed(&[_]u8{byte});

    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expect(event == .data);
    try std.testing.expectEqualStrings(raw[6 .. raw.len - 2], event.data.body);
    try std.testing.expect(parser.next() == null);
}

test "the done marker ends the stream" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    try parser.feed("data: [DONE]\n\n");

    const first = parser.next() orelse return error.TestExpectedEvent;
    defer first.deinit(allocator);
    try std.testing.expect(first == .data);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}", first.data.body);

    const second = parser.next() orelse return error.TestExpectedEvent;
    try std.testing.expect(second == .done);

    try std.testing.expect(parser.next() == null);
}

test "an event's name reaches the caller, because two payload shapes share one stream" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    try parser.feed("data: [DONE]\n\n");
    try parser.feed("event: metrics\ndata: {\"cost\":0.000018}\n\n");
    try parser.feed("data: {\"choices\":[]}\n\n");

    const chunk = parser.next() orelse return error.TestExpectedEvent;
    defer chunk.deinit(allocator);
    try std.testing.expectEqualStrings("", chunk.data.name);

    const done = parser.next() orelse return error.TestExpectedEvent;
    try std.testing.expect(done == .done);

    const metrics = parser.next() orelse return error.TestExpectedEvent;
    defer metrics.deinit(allocator);
    try std.testing.expectEqualStrings("metrics", metrics.data.name);
    try std.testing.expectEqualStrings("{\"cost\":0.000018}", metrics.data.body);

    const after = parser.next() orelse return error.TestExpectedEvent;
    defer after.deinit(allocator);
    try std.testing.expectEqualStrings("", after.data.name);

    try std.testing.expect(parser.next() == null);
}

test "a named event with no data of its own dispatches nothing and names nothing after it" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("event: ping\n\n");
    try std.testing.expect(parser.next() == null);

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expectEqualStrings("", event.data.name);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}", event.data.body);
}

test "a tool call whose arguments arrive in five fragments assembles into one call" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    try assembler.feed(.{ .index = 0, .id = "call_1", .name = "read_file", .arguments = "{" });
    try assembler.feed(.{ .index = 0, .arguments = "\"path\":" });
    try assembler.feed(.{ .index = 0, .arguments = "\"" });
    try assembler.feed(.{ .index = 0, .arguments = "README.md" });
    try assembler.feed(.{ .index = 0, .arguments = "\"}" });

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);

    try std.testing.expectEqual(@as(usize, 1), calls.len);
    try std.testing.expectEqualStrings("call_1", calls[0].id);
    try std.testing.expectEqualStrings("read_file", calls[0].name);
    try std.testing.expectEqualStrings("{\"path\":\"README.md\"}", calls[0].arguments);
    try std.testing.expect(calls[0].complete);
}

test "two tool calls in one response stay separate" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    try assembler.feed(.{ .index = 0, .id = "call_a", .name = "read_file", .arguments = "{\"path\":\"a" });
    try assembler.feed(.{ .index = 1, .id = "call_b", .name = "read_file", .arguments = "{\"path\":\"b" });
    try assembler.feed(.{ .index = 0, .arguments = ".zig\"}" });
    try assembler.feed(.{ .index = 1, .arguments = ".zig\"}" });

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);

    try std.testing.expectEqual(@as(usize, 2), calls.len);
    try std.testing.expectEqualStrings("call_a", calls[0].id);
    try std.testing.expectEqualStrings("{\"path\":\"a.zig\"}", calls[0].arguments);
    try std.testing.expectEqualStrings("call_b", calls[1].id);
    try std.testing.expectEqualStrings("{\"path\":\"b.zig\"}", calls[1].arguments);
}

test "a comment line is ignored and does not end the event in progress" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: first half\n: keep-alive\ndata: second half\n\n");

    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expect(event == .data);
    try std.testing.expectEqualStrings("first half\nsecond half", event.data.body);
    try std.testing.expect(parser.next() == null);
}

test "a stray blank line before any data manufactures no event" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("\ndata: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n");

    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expect(event == .data);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}", event.data.body);
    try std.testing.expect(parser.next() == null);
}

test "a trailing carriage return on a data line is stripped" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\r\n\r\n");

    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expect(event == .data);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}", event.data.body);
}

test "a bare carriage return with no following newline still ends a line" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\r\r: pad\n");

    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expect(event == .data);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}", event.data.body);
    try std.testing.expect(parser.next() == null);
    try std.testing.expectEqual(Parser.FinishStatus.complete, parser.finish());
}

test "two data lines in one event join with a newline between them" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: first half\ndata: second half\n\n");

    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expectEqualStrings("first half\nsecond half", event.data.body);
}

test "a later id or name fragment overwrites the one an index already held" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    try assembler.feed(.{ .index = 0, .id = "first-id", .name = "first-name" });
    try assembler.feed(.{ .index = 0, .id = "second-id", .name = "second-name" });

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);

    try std.testing.expectEqual(@as(usize, 1), calls.len);
    try std.testing.expectEqualStrings("second-id", calls[0].id);
    try std.testing.expectEqualStrings("second-name", calls[0].name);
}

test "text and a tool call in the same stream both come out whole" {
    const allocator = std.testing.allocator;
    const raw = @embedFile("testdata/text_and_tool_call.sse");

    var parser = Parser.init(allocator);
    defer parser.deinit();
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    var reasoning: std.ArrayList(u8) = .empty;
    defer reasoning.deinit(allocator);

    var saw_done = false;
    var offset: usize = 0;
    var chunk_size: usize = 1;
    while (offset < raw.len) {
        const end = @min(offset + chunk_size, raw.len);
        try parser.feed(raw[offset..end]);
        offset = end;
        chunk_size = if (chunk_size >= 7) 1 else chunk_size + 1;

        while (parser.next()) |event| {
            defer event.deinit(allocator);
            switch (event) {
                .data => |data| try applyDeltaJson(allocator, &assembler, &text, &reasoning, data.body),
                .done => saw_done = true,
            }
        }
    }

    try std.testing.expect(saw_done);
    try std.testing.expectEqual(Parser.FinishStatus.complete, parser.finish());
    try std.testing.expectEqualStrings("I will read the file /home/ross/chock/README.md.", text.items);
    try std.testing.expectEqual(@as(usize, 0), reasoning.items.len);

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);
    try std.testing.expectEqual(@as(usize, 1), calls.len);
    try std.testing.expectEqualStrings("ur9rVD4YQsXUINcxCvlse6lpXVjR1Wfi", calls[0].id);
    try std.testing.expectEqualStrings("read_file", calls[0].name);
    try std.testing.expectEqualStrings("{\"path\":\"/home/ross/chock/README.md\"}", calls[0].arguments);
    try std.testing.expect(calls[0].complete);
}

test "a real captured reasoning stream keeps reasoning_content apart from content" {
    const allocator = std.testing.allocator;
    const raw = @embedFile("testdata/reasoning_content_stream.sse");

    var parser = Parser.init(allocator);
    defer parser.deinit();
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    var reasoning: std.ArrayList(u8) = .empty;
    defer reasoning.deinit(allocator);

    try parser.feed(raw);
    var saw_done = false;
    while (parser.next()) |event| {
        defer event.deinit(allocator);
        switch (event) {
            .data => |data| try applyDeltaJson(allocator, &assembler, &text, &reasoning, data.body),
            .done => saw_done = true,
        }
    }

    try std.testing.expect(saw_done);
    try std.testing.expectEqualStrings(
        \\Here is the step-by-step breakdown:
        \\
        \\1.  The farmer initially has 17 sheep.
        \\2.  The phrase "all but 9 die" is a mathematical way of saying that every single sheep died, except for the 9 that survived.
        \\3.  Therefore, the number of sheep remaining is the number that did not die.
        \\
        \\There are 9 sheep left.
    , text.items);
    try std.testing.expectEqual(@as(usize, 2500), reasoning.items.len);
    try std.testing.expect(std.mem.startsWith(u8, reasoning.items, "1.  **Analyze the Request:**"));
    try std.testing.expect(std.mem.endsWith(u8, reasoning.items, "The logic holds up."));
}

test "an orphan tool call fragment reports incomplete instead of an empty id and name" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    try assembler.feed(.{ .index = 0, .arguments = "{\"path\":\"orphaned.zig\"}" });

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);

    try std.testing.expectEqual(@as(usize, 1), calls.len);
    try std.testing.expect(!calls[0].complete);
    try std.testing.expectEqualStrings("", calls[0].id);
    try std.testing.expectEqualStrings("", calls[0].name);
}

test "a stream cut off mid line reports truncated, not complete" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"cut off partway");
    try std.testing.expectEqual(Parser.FinishStatus.truncated, parser.finish());
    try std.testing.expect(parser.next() == null);
}

test "a stream cut off after a data line but before its blank line reports truncated" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"whole line, no terminator\"}}]}\n");
    try std.testing.expectEqual(Parser.FinishStatus.truncated, parser.finish());
    try std.testing.expect(parser.next() == null);
}

test "a stream that ends right after a whole event's blank line reports complete" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    try std.testing.expectEqual(Parser.FinishStatus.complete, parser.finish());

    const event = parser.next() orelse return error.TestExpectedEvent;
    event.deinit(allocator);
}

test "a later feed does not invalidate strings finished already returned" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    try assembler.feed(.{ .index = 0, .id = "call_1", .name = "read_file", .arguments = "{\"path\":\"a" });

    const first_calls = try assembler.finished();
    defer freeFinished(allocator, first_calls);
    try std.testing.expectEqualStrings("{\"path\":\"a", first_calls[0].arguments);

    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try assembler.feed(.{ .index = 0, .arguments = "0123456789" });
    }

    try std.testing.expectEqualStrings("{\"path\":\"a", first_calls[0].arguments);
}

fn manySmallEvents(allocator: std.mem.Allocator, event_count: usize) std.mem.Allocator.Error!std.ArrayList(u8) {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    const one_event = "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n";
    var i: usize = 0;
    while (i < event_count) : (i += 1) try body.appendSlice(allocator, one_event);
    return body;
}

test "feeding many small events compacts the buffer once per call, not once per line" {
    const allocator = std.testing.allocator;

    const small_count = 4_000;
    const large_count = 2 * small_count;

    var small = Parser.init(allocator);
    defer small.deinit();
    var small_body = try manySmallEvents(allocator, small_count);
    defer small_body.deinit(allocator);
    try small.feed(small_body.items);

    var large = Parser.init(allocator);
    defer large.deinit();
    var large_body = try manySmallEvents(allocator, large_count);
    defer large_body.deinit(allocator);
    try large.feed(large_body.items);

    try std.testing.expectEqual(@as(usize, 1), small.compactions);
    try std.testing.expectEqual(@as(usize, 1), large.compactions);

    var drained: usize = 0;
    while (small.next()) |event| {
        defer event.deinit(allocator);
        drained += 1;
    }
    try std.testing.expectEqual(@as(usize, small_count), drained);
}

test "handing out one queued event moves none of the ones behind it" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    const event_count = 4_096;
    var body = try manySmallEvents(allocator, event_count);
    defer body.deinit(allocator);
    try parser.feed(body.items);
    try std.testing.expectEqual(@as(usize, event_count), parser.events.items.len);

    var drained: usize = 0;
    while (parser.next()) |event| {
        defer event.deinit(allocator);
        drained += 1;
        try std.testing.expectEqual(@as(usize, event_count), parser.events.items.len);
        try std.testing.expectEqual(drained, parser.events_read);
    }

    try std.testing.expectEqual(@as(usize, event_count), drained);
    try std.testing.expectEqual(@as(usize, 0), parser.events.items.len);
    try std.testing.expectEqual(@as(usize, 0), parser.events_read);
}

test "a line longer than the cap is rejected, and the parser recovers after" {
    const attack_size = 8 * 1024 * 1024;
    comptime std.debug.assert(attack_size > Parser.max_line_bytes);
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    const oversized = try allocator.alloc(u8, attack_size);
    defer allocator.free(oversized);
    @memset(oversized, 'x');

    try std.testing.expectError(error.LineTooLong, parser.feed(oversized));

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}", event.data.body);
}

test "a line that crosses the cap over several feed calls, none containing a newline, still recovers" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    const chunk = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(chunk);
    @memset(chunk, 'x');

    var fed: usize = 0;
    var hit_cap = false;
    while (fed < 64 * 1024 * 1024) : (fed += chunk.len) {
        parser.feed(chunk) catch |err| {
            try std.testing.expectEqual(error.LineTooLong, err);
            hit_cap = true;
            break;
        };
    }
    try std.testing.expect(hit_cap);

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}", event.data.body);
}

test "an event whose data lines never get a blank line is rejected once pending is capped" {
    const attack_total = 16 * 1024 * 1024;
    comptime std.debug.assert(attack_total > Parser.max_pending_bytes);
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    const chunk = try allocator.alloc(u8, 64 * 1024);
    defer allocator.free(chunk);
    @memset(chunk, 'x');

    var total: usize = 0;
    var hit_cap = false;
    while (total < attack_total) : (total += chunk.len) {
        parser.feed("data: ") catch unreachable;
        parser.feed(chunk) catch unreachable;
        parser.feed("\n") catch |err| {
            try std.testing.expectEqual(error.EventTooLarge, err);
            hit_cap = true;
            break;
        };
    }
    try std.testing.expect(hit_cap);

    try parser.feed("\n");

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}", event.data.body);
}

fn expectApplyDeltaError(err: ApplyDeltaError, json_text: []const u8) !void {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    var reasoning: std.ArrayList(u8) = .empty;
    defer reasoning.deinit(allocator);

    try std.testing.expectError(err, applyDeltaJson(allocator, &assembler, &text, &reasoning, json_text));
}

test "Finding 1, attack 1: an empty object returns MissingChoices instead of aborting" {
    try expectApplyDeltaError(error.MissingChoices, "{}");
}

test "Finding 1, attack 2: an empty choices array returns NoChoices instead of aborting" {
    try expectApplyDeltaError(error.NoChoices, "{\"choices\":[]}");
}

test "Finding 1, attack 3: choices as an object returns ChoicesNotArray instead of aborting" {
    try expectApplyDeltaError(error.ChoicesNotArray, "{\"choices\":{}}");
}

test "Finding 1, attack 4: a choice with no delta returns MissingDelta instead of aborting" {
    try expectApplyDeltaError(error.MissingDelta, "{\"choices\":[{}]}");
}

test "Finding 1, attack 5: a tool call with no index returns ToolCallMissingIndex instead of aborting" {
    try expectApplyDeltaError(
        error.ToolCallMissingIndex,
        "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"name\":\"x\"}}]}}]}",
    );
}

test "Finding 1, attack 6: a negative index returns ToolCallIndexNegative instead of aborting" {
    try expectApplyDeltaError(
        error.ToolCallIndexNegative,
        "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":-1,\"function\":{\"name\":\"x\"}}]}}]}",
    );
}

test "Finding 1, attack 7: an index too large for an i64 returns ToolCallIndexNotInteger instead of aborting" {
    try expectApplyDeltaError(
        error.ToolCallIndexNotInteger,
        "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":99999999999999999999999999999,\"function\":{\"name\":\"x\"}}]}}]}",
    );
}

test "Finding 1, attack 8: an empty delta is a defined no-op, not an error and not a crash" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    var reasoning: std.ArrayList(u8) = .empty;
    defer reasoning.deinit(allocator);

    try applyDeltaJson(allocator, &assembler, &text, &reasoning, "{\"choices\":[{\"delta\":{}}]}");

    try std.testing.expectEqual(@as(usize, 0), text.items.len);
    try std.testing.expectEqual(@as(usize, 0), reasoning.items.len);
    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);
    try std.testing.expectEqual(@as(usize, 0), calls.len);
}

test "Finding 1, attack 9: arguments of the wrong JSON type are skipped, not an error and not a crash" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    var reasoning: std.ArrayList(u8) = .empty;
    defer reasoning.deinit(allocator);

    try applyDeltaJson(
        allocator,
        &assembler,
        &text,
        &reasoning,
        "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":123}}]}}]}",
    );

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);
    try std.testing.expectEqual(@as(usize, 1), calls.len);
    try std.testing.expectEqual(@as(usize, 0), calls[0].arguments.len);
    try std.testing.expect(!calls[0].complete);
}

test "a single complete line longer than the cap is rejected even though its terminator already arrived" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.appendSlice(allocator, "data: ");
    try body.appendNTimes(allocator, 'x', Parser.max_line_bytes + 1);
    try body.appendSlice(allocator, "\n\n");

    try std.testing.expectError(error.LineTooLong, parser.feed(body.items));

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}", event.data.body);
}

test "the event queue is bounded, and TooManyQueuedEvents does not lose events already queued" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    var body = try manySmallEvents(allocator, Parser.max_queued_events + 1);
    defer body.deinit(allocator);

    try std.testing.expectError(error.TooManyQueuedEvents, parser.feed(body.items));

    var drained: usize = 0;
    while (parser.next()) |event| {
        defer event.deinit(allocator);
        drained += 1;
    }
    try std.testing.expectEqual(Parser.max_queued_events + 1, drained);
}

test "the caps free the oversized buffer's capacity, not just its length" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    const oversized = try allocator.alloc(u8, Parser.max_line_bytes + 1);
    defer allocator.free(oversized);
    @memset(oversized, 'x');
    try std.testing.expectError(error.LineTooLong, parser.feed(oversized));
    try std.testing.expectEqual(@as(usize, 0), parser.line_buf.capacity);

    const chunk = try allocator.alloc(u8, 64 * 1024);
    defer allocator.free(chunk);
    @memset(chunk, 'x');
    var total: usize = 0;
    var hit_cap = false;
    while (total < Parser.max_pending_bytes + chunk.len) : (total += chunk.len) {
        parser.feed("data: ") catch unreachable;
        parser.feed(chunk) catch unreachable;
        parser.feed("\n") catch |err| {
            try std.testing.expectEqual(error.EventTooLarge, err);
            hit_cap = true;
            break;
        };
    }
    try std.testing.expect(hit_cap);
    try std.testing.expectEqual(@as(usize, 0), parser.pending.capacity);
}

test "a tool call's accumulated arguments are capped" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    const chunk = try allocator.alloc(u8, 64 * 1024);
    defer allocator.free(chunk);
    @memset(chunk, 'x');

    var total: usize = 0;
    var hit_cap = false;
    while (total < ToolCallAssembler.max_arguments_bytes + chunk.len) : (total += chunk.len) {
        assembler.feed(.{ .index = 0, .arguments = chunk }) catch |err| {
            try std.testing.expectEqual(error.ArgumentsTooLarge, err);
            hit_cap = true;
            break;
        };
    }
    try std.testing.expect(hit_cap);
}

fn lookupStepsToFeedDistinctIndices(allocator: std.mem.Allocator, count: usize) !usize {
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    var i: usize = 0;
    while (i < count) : (i += 1) {
        try assembler.feed(.{ .index = i, .id = "id", .name = "name", .arguments = "{}" });
    }

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);
    try std.testing.expectEqual(count, calls.len);
    return assembler.lookup_steps;
}

test "feeding n distinct tool call indices costs work proportional to n, not to n squared" {
    const allocator = std.testing.allocator;

    const small_count: usize = 4_000;
    const large_count: usize = 2 * small_count;

    const small_steps = try lookupStepsToFeedDistinctIndices(allocator, small_count);
    const large_steps = try lookupStepsToFeedDistinctIndices(allocator, large_count);

    try std.testing.expect(small_steps >= small_count);
    try std.testing.expect(large_steps >= large_count);

    try std.testing.expect(large_steps <= 3 * small_steps);
}

test "Finding 3: a rejected body applies nothing, not even the parts that came before the bad field" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    var reasoning: std.ArrayList(u8) = .empty;
    defer reasoning.deinit(allocator);

    const body =
        \\{"choices":[{"delta":{"content":"LEAKED","tool_calls":[
        \\{"index":0,"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"x\"}"}},
        \\{"function":{"name":"no_index"}}
        \\]}}]}
    ;

    try std.testing.expectError(
        error.ToolCallMissingIndex,
        applyDeltaJson(allocator, &assembler, &text, &reasoning, body),
    );

    try std.testing.expectEqual(@as(usize, 0), text.items.len);
    try std.testing.expectEqual(@as(usize, 0), reasoning.items.len);
    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);
    try std.testing.expectEqual(@as(usize, 0), calls.len);
}

fn expectOnlyCleanEventFollows(allocator: std.mem.Allocator, parser: *Parser) !void {
    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"clean\"}}]}\n\n");
    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expect(event == .data);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"clean\"}}]}", event.data.body);
    try std.testing.expect(parser.next() == null);
}

test "every error path leaves the parser clean: a known good event after each comes out exactly right" {
    const allocator = std.testing.allocator;

    {
        var parser = Parser.init(allocator);
        defer parser.deinit();
        const oversized = try allocator.alloc(u8, Parser.max_line_bytes + 1);
        defer allocator.free(oversized);
        @memset(oversized, 'x');
        try std.testing.expectError(error.LineTooLong, parser.feed(oversized));
        try expectOnlyCleanEventFollows(allocator, &parser);
    }

    {
        var parser = Parser.init(allocator);
        defer parser.deinit();
        try parser.feed("data: leftover from a half-built event\n");
        var attack: std.ArrayList(u8) = .empty;
        defer attack.deinit(allocator);
        try attack.appendSlice(allocator, "data: x\n");
        try attack.appendNTimes(allocator, 'x', Parser.max_line_bytes + 100);
        try std.testing.expectError(error.LineTooLong, parser.feed(attack.items));
        try expectOnlyCleanEventFollows(allocator, &parser);
    }

    {
        var parser = Parser.init(allocator);
        defer parser.deinit();
        try parser.feed("data: leftover from a half-built event\n");
        var attack: std.ArrayList(u8) = .empty;
        defer attack.deinit(allocator);
        try attack.appendSlice(allocator, "data: ");
        try attack.appendNTimes(allocator, 'x', Parser.max_line_bytes + 1);
        try attack.appendSlice(allocator, "\n\n");
        try std.testing.expectError(error.LineTooLong, parser.feed(attack.items));
        try expectOnlyCleanEventFollows(allocator, &parser);
    }

    {
        var parser = Parser.init(allocator);
        defer parser.deinit();
        const chunk = try allocator.alloc(u8, 64 * 1024);
        defer allocator.free(chunk);
        @memset(chunk, 'x');
        var total: usize = 0;
        var hit_cap = false;
        while (total < Parser.max_pending_bytes + chunk.len) : (total += chunk.len) {
            parser.feed("data: ") catch unreachable;
            parser.feed(chunk) catch unreachable;
            parser.feed("\n") catch |err| {
                try std.testing.expectEqual(error.EventTooLarge, err);
                hit_cap = true;
                break;
            };
        }
        try std.testing.expect(hit_cap);
        try parser.feed("\n");
        try expectOnlyCleanEventFollows(allocator, &parser);
    }

    {
        var parser = Parser.init(allocator);
        defer parser.deinit();
        var body = try manySmallEvents(allocator, Parser.max_queued_events + 1);
        defer body.deinit(allocator);
        try std.testing.expectError(error.TooManyQueuedEvents, parser.feed(body.items));

        var drained: usize = 0;
        while (parser.next()) |event| {
            defer event.deinit(allocator);
            drained += 1;
        }
        try std.testing.expectEqual(Parser.max_queued_events + 1, drained);

        try expectOnlyCleanEventFollows(allocator, &parser);
    }
}
