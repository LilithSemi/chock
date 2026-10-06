//! Schema: what a tool's arguments look like, as data.

const std = @import("std");

pub const Kind = enum(u8) {
    string = 1,
    boolean = 2,
    integer = 3,
    number = 4,
    array = 5,
    object = 6,

    pub fn jsonName(self: Kind) []const u8 {
        return switch (self) {
            .string => "string",
            .boolean => "boolean",
            .integer => "integer",
            .number => "number",
            .array => "array",
            .object => "object",
        };
    }

    /// Null, not a trap, for an unknown byte.
    pub fn fromWord(word: u8) ?Kind {
        return std.enums.fromInt(Kind, word);
    }

    /// Null for a JSON type word this project does not write.
    pub fn fromJsonName(word: []const u8) ?Kind {
        inline for (@typeInfo(Kind).@"enum".fields) |field| {
            const kind: Kind = @enumFromInt(field.value);
            if (std.mem.eql(u8, kind.jsonName(), word)) return kind;
        }
        return null;
    }
};

pub const Shape = struct {
    kind: Kind,
    /// Null except for an array.
    items: ?*const Shape = null,
    /// Empty except for an object.
    properties: []const Property = &.{},

    pub fn eql(a: Shape, b: Shape) bool {
        if (a.kind != b.kind) return false;
        if (a.items == null or b.items == null) {
            if (a.items != null or b.items != null) return false;
        } else if (!a.items.?.eql(b.items.?.*)) return false;
        return propertiesEql(a.properties, b.properties);
    }
};

pub const Property = struct {
    name: []const u8,
    description: []const u8,
    required: bool,
    shape: Shape,

    pub fn eql(a: Property, b: Property) bool {
        if (!std.mem.eql(u8, a.name, b.name)) return false;
        if (!std.mem.eql(u8, a.description, b.description)) return false;
        if (a.required != b.required) return false;
        return a.shape.eql(b.shape);
    }
};

/// Order matters.
pub fn propertiesEql(a: []const Property, b: []const Property) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!x.eql(y)) return false;
    }
    return true;
}

/// One address for every string array's `Shape.items`.
const string_shape: Shape = .{ .kind = .string };

/// Reads fields from `Args` and sentences from its `docs` declaration.
pub fn propertiesOf(comptime Args: type, comptime whose: []const u8) []const Property {
    comptime {
        const info = @typeInfo(Args);
        if (info != .@"struct") {
            @compileError(whose ++ " declares an argument type of " ++ @typeName(Args) ++
                ", and a tool's arguments must be a struct, because the model writes them " ++
                "as a JSON object");
        }
        if (info.@"struct".fields.len == 0) return &.{};

        if (!@hasDecl(Args, "docs")) {
            @compileError(whose ++ " has the argument type " ++ @typeName(Args) ++
                ", which has fields and no `docs` declaration. Add " ++ @typeName(Args) ++
                ".docs with one sentence per field, because a field the model cannot read " ++
                "a sentence about is a field it has to guess at");
        }

        var acc: [info.@"struct".fields.len]Property = undefined;
        for (info.@"struct".fields, &acc) |field, *out| {
            if (!@hasField(@TypeOf(Args.docs), field.name)) {
                @compileError(whose ++ " has the field \"" ++ field.name ++ "\" and " ++
                    @typeName(Args) ++ ".docs holds no sentence for it");
            }
            out.* = .{
                .name = field.name,
                .description = @field(Args.docs, field.name),
                // From the Zig type only; no second place to disagree.
                .required = @typeInfo(field.type) != .optional,
                .shape = shapeOf(field.type, whose, field.name),
            };
        }
        const frozen = acc;
        return &frozen;
    }
}

/// Every non-mapping branch is a compile error naming the tool, field, and type.
fn shapeOf(comptime T: type, comptime whose: []const u8, comptime field_name: []const u8) Shape {
    return switch (T) {
        []const u8, ?[]const u8 => .{ .kind = .string },
        ?bool => .{ .kind = .boolean },
        i64, ?i64 => .{ .kind = .integer },
        f64, ?f64 => .{ .kind = .number },
        []const []const u8, ?[]const []const u8 => .{ .kind = .array, .items = &string_shape },
        // A flag is always optional, or every call must state the ordinary case.
        bool => @compileError(whose ++ " declares the field \"" ++ field_name ++
            "\" as a required bool. A flag must be optional, written `?bool = false`, " ++
            "because a required flag makes every call carry a word to say the ordinary thing"),
        else => blk: {
            const child = switch (@typeInfo(T)) {
                .optional => |opt| opt.child,
                else => T,
            };
            const info = @typeInfo(child);
            // A list of records; the item struct carries its own docs.
            if (info == .pointer and info.pointer.size == .slice and
                @typeInfo(info.pointer.child) == .@"struct")
            {
                const item: Shape = .{
                    .kind = .object,
                    .properties = propertiesOf(info.pointer.child, whose),
                };
                const frozen = item;
                break :blk .{ .kind = .array, .items = &frozen };
            }
            @compileError(whose ++ " declares the field \"" ++ field_name ++ "\" of type " ++
                @typeName(T) ++ ", which this Chock has no JSON type for. The types it has " ++
                "are []const u8, i64, f64, []const []const u8, a slice of structs, and an " ++
                "optional of any of those, plus ?bool");
        },
    };
}

/// The caller owns the returned value.
pub fn jsonValue(
    properties: []const Property,
    allocator: std.mem.Allocator,
) std.mem.Allocator.Error!std.json.Value {
    var map: std.json.ObjectMap = .empty;
    var required = std.json.Array.init(allocator);

    for (properties) |property| {
        var one = try shapeValue(property.shape, allocator);
        try one.object.put(allocator, "description", .{ .string = property.description });
        try map.put(allocator, property.name, one);
        if (property.required) try required.append(.{ .string = property.name });
    }

    var root: std.json.ObjectMap = .empty;
    try root.put(allocator, "type", .{ .string = Kind.object.jsonName() });
    try root.put(allocator, "properties", .{ .object = map });
    try root.put(allocator, "required", .{ .array = required });
    return .{ .object = root };
}

/// Always an object, so a description can be added.
fn shapeValue(shape: Shape, allocator: std.mem.Allocator) std.mem.Allocator.Error!std.json.Value {
    switch (shape.kind) {
        .object => return jsonValue(shape.properties, allocator),
        .array => {
            var map: std.json.ObjectMap = .empty;
            try map.put(allocator, "type", .{ .string = Kind.array.jsonName() });
            // No items is a valid answer, not an assertion.
            if (shape.items) |item| try map.put(allocator, "items", try shapeValue(item.*, allocator));
            return .{ .object = map };
        },
        else => {
            var map: std.json.ObjectMap = .empty;
            try map.put(allocator, "type", .{ .string = shape.kind.jsonName() });
            return .{ .object = map };
        },
    }
}

const testing = std.testing;

const Greet = struct {
    who: []const u8,
    loudly: ?bool = null,

    pub const docs = .{
        .who = "Who to greet.",
        .loudly = "True to shout it.",
    };
};

test "an optional field is optional in the schema and a plain one is required" {
    const properties = comptime propertiesOf(Greet, "the tool \"greet\"");
    try testing.expectEqual(@as(usize, 2), properties.len);
    try testing.expectEqualStrings("who", properties[0].name);
    try testing.expect(properties[0].required);
    try testing.expectEqual(Kind.string, properties[0].shape.kind);
    try testing.expectEqualStrings("loudly", properties[1].name);
    try testing.expect(!properties[1].required);
    try testing.expectEqual(Kind.boolean, properties[1].shape.kind);
}

test "a struct with no field describes a tool that takes nothing" {
    const properties = comptime propertiesOf(struct {}, "the tool \"hello\"");
    try testing.expectEqual(@as(usize, 0), properties.len);
}

test "a list of records nests one object inside one array" {
    const Step = struct {
        title: []const u8,
        pub const docs = .{ .title = "What the step does." };
    };
    const Plan = struct {
        steps: []const Step,
        pub const docs = .{ .steps = "The whole list." };
    };

    const properties = comptime propertiesOf(Plan, "the tool \"plan\"");
    try testing.expectEqual(Kind.array, properties[0].shape.kind);
    const item = properties[0].shape.items.?;
    try testing.expectEqual(Kind.object, item.kind);
    try testing.expectEqual(@as(usize, 1), item.properties.len);
    try testing.expectEqualStrings("title", item.properties[0].name);
}

test "the rendered schema names the type, the description and the required set" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const value = try jsonValue(comptime propertiesOf(Greet, "the tool \"greet\""), arena.allocator());
    try testing.expectEqualStrings("object", value.object.get("type").?.string);

    const properties = value.object.get("properties").?.object;
    try testing.expectEqualStrings("string", properties.get("who").?.object.get("type").?.string);
    try testing.expectEqualStrings("Who to greet.", properties.get("who").?.object.get("description").?.string);
    try testing.expectEqualStrings("boolean", properties.get("loudly").?.object.get("type").?.string);

    const required = value.object.get("required").?.array;
    try testing.expectEqual(@as(usize, 1), required.items.len);
    try testing.expectEqualStrings("who", required.items[0].string);
}

test "an array of strings states what one entry holds" {
    const Many = struct {
        argv: []const []const u8,
        pub const docs = .{ .argv = "The words." };
    };
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const value = try jsonValue(comptime propertiesOf(Many, "the tool \"run\""), arena.allocator());
    const argv = value.object.get("properties").?.object.get("argv").?.object;
    try testing.expectEqualStrings("array", argv.get("type").?.string);
    try testing.expectEqualStrings("string", argv.get("items").?.object.get("type").?.string);
}

test "a kind byte outside the set is refused rather than read as a kind" {
    try testing.expectEqual(Kind.string, Kind.fromWord(1).?);
    try testing.expectEqual(@as(?Kind, null), Kind.fromWord(0));
    try testing.expectEqual(@as(?Kind, null), Kind.fromWord(7));
    try testing.expectEqual(@as(?Kind, null), Kind.fromWord(255));
}

test "eql sees a description that changed and a requirement that changed" {
    const one: Property = .{ .name = "who", .description = "a", .required = true, .shape = .{ .kind = .string } };
    try testing.expect(one.eql(one));
    try testing.expect(!one.eql(.{ .name = "who", .description = "b", .required = true, .shape = .{ .kind = .string } }));
    try testing.expect(!one.eql(.{ .name = "who", .description = "a", .required = false, .shape = .{ .kind = .string } }));
    try testing.expect(!one.eql(.{ .name = "who", .description = "a", .required = true, .shape = .{ .kind = .integer } }));
}

test "eql separates an array with an item shape from one without" {
    const bare: Shape = .{ .kind = .array };
    const full: Shape = .{ .kind = .array, .items = &string_shape };
    try testing.expect(!bare.eql(full));
    try testing.expect(full.eql(.{ .kind = .array, .items = &string_shape }));
}

test "every JSON type word reads back as the kind that wrote it" {
    inline for (@typeInfo(Kind).@"enum".fields) |field| {
        const kind: Kind = @enumFromInt(field.value);
        try testing.expectEqual(kind, Kind.fromJsonName(kind.jsonName()).?);
    }
    try testing.expectEqual(@as(?Kind, null), Kind.fromJsonName("null"));
    try testing.expectEqual(@as(?Kind, null), Kind.fromJsonName(""));
}
