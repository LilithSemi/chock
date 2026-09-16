//! One tool call's arguments, as bytes, in the order the tool declared its
//! fields.
//!
//! The host writes this and the guest reads it. It is the third format in this
//! library and the only one that carries a value rather than a description:
//! `wire.zig` says what a tool takes, and this says what one call passes.
//!
//! ## Why the guest is not handed the model's JSON
//!
//! A guest that read JSON would carry a JSON reader, and a plugin is
//! interpreted by the engine in `lib/chock-core/plugin_engine.zig`. **Measured
//! on this machine, 2026-09-15**: the same plugin, built `ReleaseSmall` for
//! `wasm32-freestanding`, takes
//!
//! ```text
//! with std.json in the guest      45,454 bytes    159 seconds to instantiate
//! with this reader in the guest    1,455 bytes      0.2 seconds
//! ```
//!
//! The host's own module reader takes 0.03 seconds on both, so the cost is the
//! engine and not the file. A plugin nobody can load in under two and a half
//! minutes is a plugin nobody can use, so the parse stays on the host, where a
//! parser is already there and costs nothing.
//!
//! The host also checks the arguments against the schema it advertised before
//! it writes anything, so what arrives here already matches what the tool said
//! it takes. This reader still refuses everything it cannot read, because the
//! two sides are separate programs and one of them may be older.
//!
//! ## The layout
//!
//! One field per declared property, in the order the tool declared them. No
//! names travel: both sides walk the same list in the same order, the host from
//! the schema it read and the guest from the struct the schema was made of.
//!
//! ```text
//! field   := u8 present , value?        value only when present is 1
//! value   := by the property's kind
//!   string  : u32 length , bytes
//!   boolean : u8, 0 or 1
//!   integer : i64 little endian
//!   number  : f64 little endian, as its bits
//!   array   : u32 count , value*        each by the item shape
//!   object  : field*                    one per property of that object
//! ```
//!
//! A present byte of zero says the model left the field out. The guest then
//! uses the field's own default, and a field with no default and no optional
//! is a refusal: the host would not have sent that, so it is a disagreement
//! between the two sides and not something to guess about.

const std = @import("std");

const schema = @import("schema.zig");

const Property = schema.Property;
const Shape = schema.Shape;

/// What can go wrong writing a record. Every one of them means the value did
/// not match the schema it was written against.
pub const EncodeError = error{
    /// A value is not of the type the schema declares for it.
    TypeMismatch,
    /// A required field is not in the value at all.
    MissingField,
    /// A string or a count is above what a `u32` holds.
    TooLarge,
    OutOfMemory,
};

/// What can go wrong reading one. Every one of them means the bytes and the
/// struct disagree.
pub const DecodeError = error{
    /// The bytes ran out in the middle of a field.
    Truncated,
    /// A present byte that is neither zero nor one.
    Malformed,
    /// A field the host left out, that the struct has no default for.
    MissingField,
    /// A count above what the reader has room for.
    TooLarge,
    OutOfMemory,
};

/// Write the arguments for one call. `properties` is the tool's own schema, and
/// `value` is what the model wrote, already parsed.
///
/// The caller owns the bytes and frees them with `gpa.free`.
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
        // **A JSON null is a field left out and not a field of the wrong
        // type.** Providers write one for an argument the model chose not to
        // set, and the guest's own default is the right answer for it.
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
            // An array with no item shape carries no entry this side can
            // describe, so the count is all that is written. `schema.shapeOf`
            // never builds one, and a blob that states one is refused before
            // it reaches here.
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

/// Read the arguments for one call into `Args`, the tool's own argument type.
///
/// `gpa` is only ever asked for the storage a list needs: a string is the bytes
/// themselves and is never copied, so a fixed buffer of a few hundred bytes
/// serves a tool that takes no list at all. `bytes` must outlive the value.
pub fn decode(
    comptime Args: type,
    bytes: []const u8,
    gpa: std.mem.Allocator,
) DecodeError!Args {
    var cursor: Cursor = .{ .bytes = bytes, .at = 0 };
    const out = try decodeObject(Args, &cursor, gpa);
    // **Bytes left over are a disagreement and not a detail.** Two sides that
    // walked different field lists would each read something, and the one that
    // stopped early is the one that noticed.
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
    // An optional field that is present holds its own type's value. The
    // absent case never reaches here: `decodeObject` answers it from the
    // default.
    const info = @typeInfo(T);
    if (info == .optional) return try decodeValue(info.optional.child, cursor, gpa);

    return switch (T) {
        []const u8 => try cursor.string(),
        bool => try cursor.present(),
        i64 => @bitCast(try cursor.int(u64)),
        f64 => @bitCast(try cursor.int(u64)),
        else => blk: {
            // A record: one field per property, the same walk as the top
            // level. This is what an array of records holds.
            if (@typeInfo(T) == .@"struct") break :blk try decodeObject(T, cursor, gpa);

            const Item = @typeInfo(T).pointer.child;
            const count = try cursor.int(u32);
            const list = try gpa.alloc(Item, count);
            for (list) |*slot| slot.* = try decodeValue(Item, cursor, gpa);
            break :blk list;
        },
    };
}

/// A cursor over one record. Every read checks what is left first, so bytes
/// that stop in the middle of a field are a refusal and never a read past the
/// end of the buffer the host wrote.
const Cursor = struct {
    bytes: []const u8,
    at: usize,

    fn take(self: *Cursor, want: usize) DecodeError![]const u8 {
        if (self.bytes.len - self.at < want) return error.Truncated;
        const out = self.bytes[self.at..][0..want];
        self.at += want;
        return out;
    }

    /// One byte that is exactly zero or exactly one. Anything else is a record
    /// this reader will not guess about.
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

    /// Borrowed from the record and never copied, which is what keeps a tool
    /// that takes strings free of an allocator.
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

/// One round trip: parse the text a model would write, encode it against the
/// tool's own schema, and read it back into the tool's own type.
fn roundTrip(comptime Args: type, arena: std.mem.Allocator, text: []const u8) !Args {
    const properties = comptime schema.propertiesOf(Args, "the tool \"test\"");
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
    const bytes = try encodeAlloc(arena, properties, value);
    return decode(Args, bytes, arena);
}

test "a string and an optional flag reach the tool as values" {
    // The whole point of the format: the body reads `args.who` and never a
    // string it has to pick apart itself.
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
    // Left out, so the struct's own default answers, and the default is null.
    try testing.expectEqual(@as(?i64, null), args.times);
}

test "a field the model left out keeps the struct's own default" {
    // A default that is not null is the case a reader that wrote null for
    // every absent field would get wrong.
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
    // The guest never sees this call. The host is where a missing field is
    // caught, because the host is the side that knows what was advertised.
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
    // The host checks against the schema before this runs, so this is the
    // second line and not the first. It is here because the two sides are
    // separate programs: a host that skipped the check must not be able to
    // hand a guest a number where it asked for a string.
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
    // The two nested shapes the mapping can build. A reader that walked the
    // fields in a different order from the writer would read the count of one
    // list as the length of a string in the other.
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
    // A model writes `2` as often as it writes `2.0`, and a reader that took
    // only one of them would refuse half the calls that are right.
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
    // An integer field is a whole number, and rounding one on the way in would
    // be this host deciding what the model meant.
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
    // The bytes cross a process boundary into an engine that checks nothing,
    // so the reader has to be the thing that stops.
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
    // The byte decides whether a length follows. A reader that took any
    // non zero value as present would read the next field as a length.
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
    // Two sides walking different field lists is the fault this catches, and
    // it is the fault a plugin built against another Chock would have.
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
    // The ordinary plugin. It must cost nothing on the wire and nothing to
    // read, or every such tool would pay for a feature it does not use.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const Nothing = struct {};
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), "{}", .{});
    const bytes = try encodeAlloc(arena.allocator(), &.{}, value);
    try testing.expectEqual(@as(usize, 0), bytes.len);
    _ = try decode(Nothing, bytes, arena.allocator());
}
