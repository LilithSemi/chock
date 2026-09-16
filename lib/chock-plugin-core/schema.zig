//! What a tool's arguments look like, as data, and the one mapping from a Zig
//! type onto it.
//!
//! A tool tells the model what it takes. A built-in tool does that from its own
//! argument struct, and a plugin tool has to say the same thing across a file
//! boundary, so the shape has to exist as plain data as well as as a Zig type.
//! This file holds both ends:
//!
//! * `Property` and `Shape` are the data. They hold no `type` and no pointer
//!   into a guest, so `lib/chock-plugin-core/wire.zig` carries them to a host
//!   that has read a file and nothing else.
//! * `propertiesOf` is the mapping, at compile time, from an argument struct
//!   onto that data. **It is the only mapping in this project.**
//!   `lib/chock-core/tools.zig` builds a built-in tool's schema through it and
//!   `lib/chock-plugin-sdk/metadata.zig` builds a plugin tool's schema through
//!   it, so the model reads one spelling of one idea.
//! * `jsonValue` renders the data as the JSON schema a provider reads. A host
//!   calls it for a built-in tool and for a plugin tool alike.
//!
//! ## The mapping is total
//!
//! A Zig type this file has no JSON type for is a `@compileError` that names
//! the tool, the field, and the type. It is never dropped. A dropped field
//! would leave the model reading a schema that does not match what the tool
//! really parses, which is a wrong answer the build could have refused.
//!
//! ## A field description is one string and not a locale set
//!
//! Everything else a plugin says about itself carries a locale, and a field
//! description does not. The reason is the sharing above: a built-in tool's
//! `docs` declaration is one sentence per field, and one mapping that reads two
//! different description shapes would be two mappings. A tool description is
//! still localised, because that one is not read from Zig code.

const std = @import("std");

/// The JSON types a tool argument may have.
///
/// Numbered from one, so a zeroed byte is not a valid kind and a blob of zeros
/// fails here as well as on the magic.
pub const Kind = enum(u8) {
    string = 1,
    /// **Only ever an optional field.** See `shapeOf`.
    boolean = 2,
    integer = 3,
    number = 4,
    array = 5,
    object = 6,

    /// The word this kind is written with in a JSON schema.
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

    /// The kind one byte names, or null when the byte is not one of these.
    /// Null is what turns a hostile blob into a message instead of a trap.
    pub fn fromWord(word: u8) ?Kind {
        return std.enums.fromInt(Kind, word);
    }

    /// The kind one JSON schema type word names, or null for a word this
    /// project does not write. **The inverse of `jsonName` and read from the
    /// same list**, so a host that checks arguments against a rendered schema
    /// and a guest that wrote that schema cannot mean different things by one
    /// word.
    pub fn fromJsonName(word: []const u8) ?Kind {
        inline for (@typeInfo(Kind).@"enum".fields) |field| {
            const kind: Kind = @enumFromInt(field.value);
            if (std.mem.eql(u8, kind.jsonName(), word)) return kind;
        }
        return null;
    }
};

/// What one value looks like. `items` is set for an array and null otherwise,
/// and `properties` is filled for an object and empty otherwise.
pub const Shape = struct {
    kind: Kind,
    /// What one entry of an array holds. Null for every other kind.
    items: ?*const Shape = null,
    /// The fields of an object. Empty for every other kind.
    properties: []const Property = &.{},

    pub fn eql(a: Shape, b: Shape) bool {
        if (a.kind != b.kind) return false;
        if (a.items == null or b.items == null) {
            if (a.items != null or b.items != null) return false;
        } else if (!a.items.?.eql(b.items.?.*)) return false;
        return propertiesEql(a.properties, b.properties);
    }
};

/// One field of an object: what the model calls it, what it means, whether it
/// may be left out, and what it holds.
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

/// Whether two property lists say the same thing, in the same order.
pub fn propertiesEql(a: []const Property, b: []const Property) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!x.eql(y)) return false;
    }
    return true;
}

/// The shape of a string, which every array of strings points at. A file scope
/// constant so there is one address to point `Shape.items` at.
const string_shape: Shape = .{ .kind = .string };

/// The properties of `Args`, read from the struct's own fields and from its
/// `docs` declaration, which holds one sentence per field.
///
/// `whose` names the thing being described, and it is there for one job: it
/// goes into every compile error this file raises, so an author reading the
/// failure is told which tool has the field that cannot be described. A caller
/// passes something like `the tool "greet"`.
///
/// An argument struct with no field answers an empty list, which is how a tool
/// that takes nothing is described. Such a struct needs no `docs`.
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
                // **Read from the Zig type, and from nothing else.** An
                // optional field is one the model may leave out, so there is no
                // second place the two can stop agreeing.
                .required = @typeInfo(field.type) != .optional,
                .shape = shapeOf(field.type, whose, field.name),
            };
        }
        const frozen = acc;
        return &frozen;
    }
}

/// The shape of one field. Every branch that is not a mapping is a compile
/// error naming the tool, the field, and the type.
fn shapeOf(comptime T: type, comptime whose: []const u8, comptime field_name: []const u8) Shape {
    return switch (T) {
        []const u8, ?[]const u8 => .{ .kind = .string },
        ?bool => .{ .kind = .boolean },
        i64, ?i64 => .{ .kind = .integer },
        f64, ?f64 => .{ .kind = .number },
        []const []const u8, ?[]const []const u8 => .{ .kind = .array, .items = &string_shape },
        // **A flag is only ever optional.** A required flag is a field every
        // call has to carry to say the ordinary thing, and the ordinary thing
        // is what a default is for.
        bool => @compileError(whose ++ " declares the field \"" ++ field_name ++
            "\" as a required bool. A flag must be optional, written `?bool = false`, " ++
            "because a required flag makes every call carry a word to say the ordinary thing"),
        else => blk: {
            const child = switch (@typeInfo(T)) {
                .optional => |opt| opt.child,
                else => T,
            };
            const info = @typeInfo(child);
            // A list of records, which `update_plan` needs: a task list is many
            // steps, and one tool call per step would cost a round trip each.
            // The item struct carries its own `docs`, so the nested shape is
            // built by the same rule as the outer one and there is still
            // exactly one description of each field.
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

/// The JSON schema for an object with these properties, which is what a
/// provider reads and what the model writes its arguments against.
///
/// The caller owns the returned value and everything under it. An arena is the
/// simplest way to release the whole tree at once.
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

/// The JSON schema for one value. Always an object, so a caller may put a
/// description into it.
fn shapeValue(shape: Shape, allocator: std.mem.Allocator) std.mem.Allocator.Error!std.json.Value {
    switch (shape.kind) {
        .object => return jsonValue(shape.properties, allocator),
        .array => {
            var map: std.json.ObjectMap = .empty;
            try map.put(allocator, "type", .{ .string = Kind.array.jsonName() });
            // An array with no item shape cannot be built by `shapeOf`, and a
            // blob that states one is refused by the reader. Writing no
            // `items` is still the right answer rather than an assertion: a
            // schema without it is a schema the provider accepts.
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
    // The two are read from the Zig type alone, so there is nothing to keep in
    // step by hand and no way for the model to be told the wrong thing.
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
    // The shape `plugins/hello.zig` has. It must need no `docs` at all, or
    // every tool that takes nothing would carry a declaration to say so.
    const properties = comptime propertiesOf(struct {}, "the tool \"hello\"");
    try testing.expectEqual(@as(usize, 0), properties.len);
}

test "a list of records nests one object inside one array" {
    // The one nested shape a tool argument has. The item struct is read by the
    // same rule as the outer one, so a field of it that has no sentence fails
    // the build in the same place.
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
    // What the provider reads. A missing `required` array or a tuple written
    // where an object belongs is the fault that ends a session on a 400.
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
    // A provider that is given an array with no `items` has to guess, and a
    // model given the same thing writes a list of objects into a list of
    // strings.
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
    // Every byte of a blob is a number somebody else wrote, so the reader has
    // to be able to say "that is not a kind" instead of indexing with it.
    try testing.expectEqual(Kind.string, Kind.fromWord(1).?);
    try testing.expectEqual(@as(?Kind, null), Kind.fromWord(0));
    try testing.expectEqual(@as(?Kind, null), Kind.fromWord(7));
    try testing.expectEqual(@as(?Kind, null), Kind.fromWord(255));
}

test "eql sees a description that changed and a requirement that changed" {
    // The round trip through the wire format is asserted with this, so a
    // comparison that skipped a field would make the round trip prove nothing.
    const one: Property = .{ .name = "who", .description = "a", .required = true, .shape = .{ .kind = .string } };
    try testing.expect(one.eql(one));
    try testing.expect(!one.eql(.{ .name = "who", .description = "b", .required = true, .shape = .{ .kind = .string } }));
    try testing.expect(!one.eql(.{ .name = "who", .description = "a", .required = false, .shape = .{ .kind = .string } }));
    try testing.expect(!one.eql(.{ .name = "who", .description = "a", .required = true, .shape = .{ .kind = .integer } }));
}

test "eql separates an array with an item shape from one without" {
    // The two serialise to different bytes, so they must not compare equal.
    const bare: Shape = .{ .kind = .array };
    const full: Shape = .{ .kind = .array, .items = &string_shape };
    try testing.expect(!bare.eql(full));
    try testing.expect(full.eql(.{ .kind = .array, .items = &string_shape }));
}

test "every JSON type word reads back as the kind that wrote it" {
    // A host checks the model's arguments against a rendered schema, and the
    // word in that schema is the only thing it has to go on. A word that read
    // back as nothing would make the check pass over a field of the wrong type.
    inline for (@typeInfo(Kind).@"enum".fields) |field| {
        const kind: Kind = @enumFromInt(field.value);
        try testing.expectEqual(kind, Kind.fromJsonName(kind.jsonName()).?);
    }
    try testing.expectEqual(@as(?Kind, null), Kind.fromJsonName("null"));
    try testing.expectEqual(@as(?Kind, null), Kind.fromJsonName(""));
}
