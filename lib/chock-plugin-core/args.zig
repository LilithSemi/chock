//! One tool call's arguments, as bytes, in the order the tool declared its
//! fields. No names travel on the wire, only values in schema order.

const std = @import("std");

const schema = @import("schema.zig");

const Property = schema.Property;
const Shape = schema.Shape;

pub const EncodeError = error{
    TypeMismatch,
    MissingField,
    /// Above what a `u32` holds.
    TooLarge,
    OutOfMemory,
};

pub const DecodeError = error{
    Truncated,
    /// A byte that isn't 0 or 1.
    Malformed,
    /// No default for a left-out field.
    MissingField,
    /// More than the reader can hold.
    TooLarge,
    OutOfMemory,
};

/// Caller owns the bytes.
pub fn encodeAlloc(
    gpa: std.mem.Allocator,
    properties: []const Property,
    value: std.json.Value,
) EncodeError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try encodeObject(gpa, &out, properties, value);
    return out.toOwnedSlice(gpa);
}

fn encodeObject(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    properties: []const Property,
    value: std.json.Value,
) EncodeError!void {
    if (value != .object) return error.TypeMismatch;
    for (properties) |property| {
        // A JSON null means left out, not the wrong type.
        const held = value.object.get(property.name);
        const set = held != null and held.? != .null;
        if (!set) {
            if (property.required) return error.MissingField;
            try out.append(gpa, 0);
            continue;
        }
        try out.append(gpa, 1);
        try encodeValue(gpa, out, property.shape, held.?);
    }
}

fn encodeValue(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    shape: Shape,
    value: std.json.Value,
) EncodeError!void {
    switch (shape.kind) {
        .string => {
            if (value != .string) return error.TypeMismatch;
            try putString(gpa, out, value.string);
        },
        .boolean => {
            if (value != .bool) return error.TypeMismatch;
            try out.append(gpa, @intFromBool(value.bool));
        },
        .integer => {
            if (value != .integer) return error.TypeMismatch;
            try putInt(gpa, out, i64, value.integer);
        },
        .number => {
            const held: f64 = switch (value) {
                .integer => |n| @floatFromInt(n),
                .float => |f| f,
                else => return error.TypeMismatch,
            };
            try putInt(gpa, out, u64, @bitCast(held));
        },
        .array => {
            if (value != .array) return error.TypeMismatch;
            if (value.array.items.len > std.math.maxInt(u32)) return error.TooLarge;
            try putInt(gpa, out, u32, @intCast(value.array.items.len));
            // No item shape means no entry this side can describe.
            const item = shape.items orelse return;
            for (value.array.items) |one| try encodeValue(gpa, out, item.*, one);
        },
        .object => try encodeObject(gpa, out, shape.properties, value),
    }
}

fn putString(gpa: std.mem.Allocator, out: *std.ArrayList(u8), text: []const u8) EncodeError!void {
    if (text.len > std.math.maxInt(u32)) return error.TooLarge;
    try putInt(gpa, out, u32, @intCast(text.len));
    try out.appendSlice(gpa, text);
}

fn putInt(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    comptime T: type,
    value: T,
) EncodeError!void {
    var raw: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
    std.mem.writeInt(T, &raw, value, .little);
    try out.appendSlice(gpa, &raw);
}

/// `gpa` is for lists only; `bytes` must outlive a borrowed string.
pub fn decode(
    comptime Args: type,
    bytes: []const u8,
    gpa: std.mem.Allocator,
) DecodeError!Args {
    var cursor: Cursor = .{ .bytes = bytes, .at = 0 };
    const out = try decodeObject(Args, &cursor, gpa);
    // Leftover bytes mean mismatched field lists.
    if (cursor.at != cursor.bytes.len) return error.Malformed;
    return out;
}

fn decodeObject(comptime Args: type, cursor: *Cursor, gpa: std.mem.Allocator) DecodeError!Args {
    var out: Args = undefined;
    inline for (@typeInfo(Args).@"struct".fields) |field| {
        if (try cursor.present()) {
            @field(out, field.name) = try decodeValue(field.type, cursor, gpa);
        } else if (field.defaultValue()) |fallback| {
            @field(out, field.name) = fallback;
        } else if (@typeInfo(field.type) == .optional) {
            @field(out, field.name) = null;
        } else {
            return error.MissingField;
        }
    }
    return out;
}

fn decodeValue(comptime T: type, cursor: *Cursor, gpa: std.mem.Allocator) DecodeError!T {
    // Absent never reaches here; decodeObject uses the default.
    const info = @typeInfo(T);
    if (info == .optional) return try decodeValue(info.optional.child, cursor, gpa);

    return switch (T) {
        []const u8 => try cursor.string(),
        bool => try cursor.present(),
        i64 => @bitCast(try cursor.int(u64)),
        f64 => @bitCast(try cursor.int(u64)),
        else => blk: {
            // One field per property, same walk as the top level.
            if (@typeInfo(T) == .@"struct") break :blk try decodeObject(T, cursor, gpa);

            const Item = @typeInfo(T).pointer.child;
            const count = try cursor.int(u32);
            const list = try gpa.alloc(Item, count);
            for (list) |*slot| slot.* = try decodeValue(Item, cursor, gpa);
            break :blk list;
        },
    };
}

/// Checks what's left first, so truncation refuses rather than overreads.
const Cursor = struct {
    bytes: []const u8,
    at: usize,

    fn take(self: *Cursor, want: usize) DecodeError![]const u8 {
        if (self.bytes.len - self.at < want) return error.Truncated;
        const out = self.bytes[self.at..][0..want];
        self.at += want;
        return out;
    }

    /// Exactly 0 or 1.
    fn present(self: *Cursor) DecodeError!bool {
        const raw = try self.take(1);
        return switch (raw[0]) {
            0 => false,
            1 => true,
            else => error.Malformed,
        };
    }

    fn int(self: *Cursor, comptime T: type) DecodeError!T {
        const width = @divExact(@typeInfo(T).int.bits, 8);
        const raw = try self.take(width);
        return std.mem.readInt(T, raw[0..width], .little);
    }

    /// Borrowed, never copied.
    fn string(self: *Cursor) DecodeError![]const u8 {
        const length = try self.int(u32);
        return self.take(length);
    }
};

const testing = std.testing;

const Greet = struct {
    who: []const u8,
    loudly: ?bool = null,
    times: ?i64 = null,

    pub const docs = .{
        .who = "Who to greet.",
        .loudly = "True to shout it.",
        .times = "How many times.",
    };
};

fn roundTrip(comptime Args: type, arena: std.mem.Allocator, text: []const u8) !Args {
    const properties = comptime schema.propertiesOf(Args, "the tool \"test\"");
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
    const bytes = try encodeAlloc(arena, properties, value);
    return decode(Args, bytes, arena);
}

test "a string and an optional flag reach the tool as values" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const properties = comptime schema.propertiesOf(Greet, "the tool \"greet\"");
    const value = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        "{\"who\":\"Ross\",\"loudly\":true}",
        .{},
    );
    const bytes = try encodeAlloc(arena.allocator(), properties, value);
    const args = try decode(Greet, bytes, arena.allocator());

    try testing.expectEqualStrings("Ross", args.who);
    try testing.expectEqual(@as(?bool, true), args.loudly);
    try testing.expectEqual(@as(?i64, null), args.times);
}

test "a field the model left out keeps the struct's own default" {
    const Flagged = struct {
        loudly: ?bool = true,
        pub const docs = .{ .loudly = "True to shout it." };
    };
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const properties = comptime schema.propertiesOf(Flagged, "the tool \"flag\"");
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), "{}", .{});
    const bytes = try encodeAlloc(arena.allocator(), properties, value);
    const args = try decode(Flagged, bytes, arena.allocator());
    try testing.expectEqual(@as(?bool, true), args.loudly);
}

test "a required field the model left out is refused before anything is written" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const properties = comptime schema.propertiesOf(Greet, "the tool \"greet\"");
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), "{}", .{});
    try testing.expectError(
        error.MissingField,
        encodeAlloc(arena.allocator(), properties, value),
    );
}

test "a value of the wrong type is refused rather than written as something else" {
    // The host checks the schema; this is the second line of defense.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const properties = comptime schema.propertiesOf(Greet, "the tool \"greet\"");
    const value = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        "{\"who\":7}",
        .{},
    );
    try testing.expectError(
        error.TypeMismatch,
        encodeAlloc(arena.allocator(), properties, value),
    );
}

test "a list of strings and a list of records both survive the trip" {
    const Step = struct {
        title: []const u8,
        done: ?bool = null,
        pub const docs = .{ .title = "What it is.", .done = "Whether it is." };
    };
    const Plan = struct {
        argv: []const []const u8,
        steps: []const Step,
        pub const docs = .{ .argv = "The words.", .steps = "The list." };
    };

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const properties = comptime schema.propertiesOf(Plan, "the tool \"plan\"");
    const value = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        "{\"argv\":[\"zig\",\"build\"],\"steps\":[{\"title\":\"one\",\"done\":true},{\"title\":\"two\"}]}",
        .{},
    );
    const bytes = try encodeAlloc(arena.allocator(), properties, value);
    const args = try decode(Plan, bytes, arena.allocator());

    try testing.expectEqual(@as(usize, 2), args.argv.len);
    try testing.expectEqualStrings("zig", args.argv[0]);
    try testing.expectEqualStrings("build", args.argv[1]);
    try testing.expectEqual(@as(usize, 2), args.steps.len);
    try testing.expectEqualStrings("one", args.steps[0].title);
    try testing.expectEqual(@as(?bool, true), args.steps[0].done);
    try testing.expectEqualStrings("two", args.steps[1].title);
    try testing.expectEqual(@as(?bool, null), args.steps[1].done);
}

test "a whole number reaches a number field, and a float reaches it too" {
    const Measured = struct {
        ratio: f64,
        pub const docs = .{ .ratio = "How much." };
    };
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const whole = try roundTrip(Measured, arena.allocator(), "{\"ratio\":2}");
    try testing.expectEqual(@as(f64, 2.0), whole.ratio);
    const fractional = try roundTrip(Measured, arena.allocator(), "{\"ratio\":0.5}");
    try testing.expectEqual(@as(f64, 0.5), fractional.ratio);
}

test "a whole number field refuses a fraction" {
    const Counted = struct {
        times: i64,
        pub const docs = .{ .times = "How many." };
    };
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    try testing.expectError(
        error.TypeMismatch,
        roundTrip(Counted, arena.allocator(), "{\"times\":1.5}"),
    );
    const two = try roundTrip(Counted, arena.allocator(), "{\"times\":-2}");
    try testing.expectEqual(@as(i64, -2), two.times);
}

test "a record that stops in the middle of a field is refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const properties = comptime schema.propertiesOf(Greet, "the tool \"greet\"");
    const value = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        "{\"who\":\"Ross\"}",
        .{},
    );
    const bytes = try encodeAlloc(arena.allocator(), properties, value);
    for (0..bytes.len) |cut| {
        try testing.expectError(error.Truncated, decode(Greet, bytes[0..cut], arena.allocator()));
    }
}

test "a present byte that is neither zero nor one is refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const properties = comptime schema.propertiesOf(Greet, "the tool \"greet\"");
    const value = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        "{\"who\":\"Ross\"}",
        .{},
    );
    const bytes = try encodeAlloc(arena.allocator(), properties, value);
    bytes[0] = 2;
    try testing.expectError(error.Malformed, decode(Greet, bytes, arena.allocator()));
}

test "bytes left over after the last field are refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const properties = comptime schema.propertiesOf(Greet, "the tool \"greet\"");
    const value = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        "{\"who\":\"Ross\"}",
        .{},
    );
    const bytes = try encodeAlloc(arena.allocator(), properties, value);
    const longer = try arena.allocator().alloc(u8, bytes.len + 1);
    @memcpy(longer[0..bytes.len], bytes);
    longer[bytes.len] = 0;
    try testing.expectError(error.Malformed, decode(Greet, longer, arena.allocator()));
}

test "a tool that takes nothing has a record of no bytes at all" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const Nothing = struct {};
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), "{}", .{});
    const bytes = try encodeAlloc(arena.allocator(), &.{}, value);
    try testing.expectEqual(@as(usize, 0), bytes.len);
    _ = try decode(Nothing, bytes, arena.allocator());
}
