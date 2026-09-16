//! The metadata format, as pure functions over bytes, in both directions.
//!
//! Nothing here parses wasm, starts an engine, or touches a guest's linear
//! memory. `serialize` turns a `Metadata` into bytes, `parse` turns bytes back
//! into a `Metadata`, and a host that has the bytes learns what a plugin is
//! without running one instruction of it.
//!
//! ## Why bytes and not the struct
//!
//! A guest could export the memory image of its `Metadata` instead. That
//! couples the host to the guest's wasm32 layout: field order, alignment, and
//! a four byte pointer chased into the data segment for every string. It
//! breaks on any added field, and it breaks worst on the compatibility field,
//! because a host cannot read the field that decides the layout if reading it
//! already needs that layout. A length prefixed blob has the same no execution
//! property with none of the coupling.
//!
//! ## The prefix never moves
//!
//! The first twelve bytes are the same in every ABI, forever:
//!
//! ```text
//! offset 0   u32 little endian   the magic word, `Magic.word`
//! offset 4   u32 little endian   the ABI version of the body
//! offset 8   u32 little endian   the length of the whole blob, prefix included
//! ```
//!
//! Everything after byte twelve belongs to one ABI and may change with it.
//! Holding several ABIs later is then a matter of adding a body reader, not of
//! touching the code that decides which reader to call.
//!
//! **The magic is checked before any length prefixed read.** A blob that is
//! not ours must never hand this reader a length to trust.
//!
//! ## Two failures, two messages
//!
//! A host meets two different problems and must not confuse them.
//!
//! - The guest exports no `chock_plugin_magic` symbol at all, or its blob does
//!   not start with `Magic.word`. That file is not a Chock plugin. The symbol
//!   name is the magic, so its absence is the whole answer.
//! - The symbol is there and the ABI version is a number this build does not
//!   know. That is a Chock plugin built for another Chock. The answer names
//!   both numbers and asks the author to rebuild, which is the answer that is
//!   actually useful, because this is the failure that happens constantly.
//!
//! `abiVersion` answers `null` rather than trapping for the second case, and
//! `Refusal` carries both numbers into the message.
//!
//! ## Bounds
//!
//! A blob comes from a file somebody else wrote, so every count and every
//! length in it is untrusted. This reader refuses anything above the bounds
//! below with a named error, and the message says which bound it passed.

const std = @import("std");
const metadata = @import("metadata.zig");
const schema = @import("schema.zig");

const Property = schema.Property;
const Shape = schema.Shape;
const Metadata = metadata.Metadata;
const LocaleField = metadata.LocaleField;
const ToolDescriptor = metadata.ToolDescriptor;
const VersionConstraint = metadata.VersionConstraint;

/// The largest metadata blob this reader accepts. A plugin describes itself in
/// a few kilobytes. A larger blob is a mistake or an attack.
pub const max_blob_bytes: u32 = 1 << 20;

/// The largest single string: a name, an author, a locale tag, a description,
/// or a capability name.
pub const max_string_bytes: u32 = 8 << 10;

/// The largest number of translations of one piece of text.
pub const max_locales: u32 = 64;

/// The largest number of tools one plugin may offer.
pub const max_tools: u32 = 256;

/// The largest number of capabilities one tool may declare.
pub const max_capabilities: u32 = 64;

/// The largest number of fields one argument object may hold.
///
/// **Every one of them is read by the model on every turn of the session.** A
/// tool that took more separate values than this is a tool nobody can call
/// correctly, and a blob that states more is a blob that wants the host to
/// allocate on its say so.
pub const max_properties: u32 = 32;

/// How deeply one argument schema may nest.
///
/// A property's own shape is depth one, the item shape of an array is depth
/// two, and a field of that item is depth three. The deepest shape the mapping
/// in `schema.zig` can build is a list of records, which reaches depth three,
/// so this leaves room and still stops a blob that asks this reader to recurse
/// until the stack runs out. **The check is on the way in, before any memory
/// is spent**, which is the only place it does any good.
pub const max_schema_depth: u32 = 8;

/// The magic word, and the symbol whose name carries the same claim.
///
/// `word` is a constant of the format and never changes with the ABI.
/// Changing it per ABI would collapse "this is not a Chock plugin" into "this
/// plugin is older than this Chock", and the second failure is the one with a
/// useful answer.
pub const Magic = struct {
    /// In file order the bytes are `'C'`, `'H'`, `'K'`, `0x9E`. The high bit
    /// of the last byte is set on purpose: a blob that went through a channel
    /// that strips the eighth bit stops matching. The value is far from zero
    /// and far from all ones, so neither a zeroed page nor an erased flash
    /// page reads as a plugin.
    pub const word: u32 = 0x9E4B_4843;

    /// The guest symbol whose presence says "this module is a Chock plugin"
    /// and whose `u32` value is the ABI version it was built for. The name is
    /// the magic. The number is the version. A host that finds no such symbol
    /// is holding something that is not a plugin at all.
    pub const symbol = "chock_plugin_magic";

    pub fn matches(read_word: u32) bool {
        return read_word == word;
    }
};

/// The ABI versions this build of Chock knows how to read.
///
/// Exhaustive on purpose. `abiVersion` uses `std.enums.fromInt`, which answers
/// null for a number that is not a member, and null is what turns an unknown
/// ABI into a message instead of a trap. A non exhaustive enum would accept
/// every `u32` and throw that answer away.
///
/// Numbering starts at one. Zero is never a valid ABI version, so a zeroed
/// region of memory fails on the ABI field as well as on the magic.
pub const AbiVersion = enum(u32) {
    /// The first ABI. Its tool records carry a name, a description and a
    /// capability set, and nothing about what the tool takes.
    v1 = 1,
    /// v1 with an argument schema on every tool record. See
    /// `lib/chock-plugin-core/schema.zig`.
    v2 = 2,

    /// The ABI this build writes and the one it prefers to read.
    pub const current: AbiVersion = .v2;

    /// Whether a tool record in this ABI carries an argument schema. A v1
    /// plugin still loads, and every tool of it takes nothing, which is what
    /// that plugin already meant.
    pub fn carriesSchema(self: AbiVersion) bool {
        return self != .v1;
    }
};

/// The ABI version `word` names, or null when this build does not know that
/// number. Null is an answer a caller can put in a message. It is not a fault
/// in this code, so it is not an assertion.
pub fn abiVersion(word: u32) ?AbiVersion {
    return std.enums.fromInt(AbiVersion, word);
}

/// The fixed prefix of every blob, in every ABI.
pub const Prefix = struct {
    /// The raw number, kept as written rather than as an `AbiVersion`, so a
    /// caller can name it in a message even when this build does not know it.
    abi_version: u32,
    /// The length of the whole blob, this prefix included.
    total_len: u32,

    pub const len: u32 = 12;
    pub const magic_offset: u32 = 0;
    pub const abi_version_offset: u32 = 4;
    pub const total_len_offset: u32 = 8;

    comptime {
        // The prefix is a promise to every future ABI. If a field is added it
        // goes after byte twelve, never inside these three.
        if (total_len_offset + 4 != len) @compileError("the fixed prefix changed width");
    }

    /// Read the prefix, and nothing else. `bytes` needs to hold only `len`
    /// bytes, so a host reads the head of a section and learns from it how
    /// much more to fetch. Whether the rest is really there is `parse`'s
    /// question, not this one.
    ///
    /// The magic is checked first, so a blob that is not ours never gets to
    /// state a length.
    pub fn read(bytes: []const u8, refusal: ?*?Refusal) PrefixError!Prefix {
        if (bytes.len < len) {
            return note(refusal, .{ .truncated = .{
                .what = "the fixed prefix",
                .have = bytes.len,
                .need = len,
            } }, error.Truncated);
        }

        const word = std.mem.readInt(u32, bytes[magic_offset..][0..4], .little);
        if (!Magic.matches(word)) {
            return note(refusal, .{ .not_a_plugin = .{
                .found = word,
                .expected = Magic.word,
            } }, error.NotAPlugin);
        }

        const declared_abi = std.mem.readInt(u32, bytes[abi_version_offset..][0..4], .little);
        const total = std.mem.readInt(u32, bytes[total_len_offset..][0..4], .little);

        if (total < len or total > max_blob_bytes) {
            return note(refusal, .{ .too_large = .{
                .what = "the declared blob length",
                .found = total,
                .bound = max_blob_bytes,
            } }, error.TooLarge);
        }
        return .{ .abi_version = declared_abi, .total_len = total };
    }

    /// The ABI this prefix names, or null when this build does not know it.
    pub fn known(self: Prefix) ?AbiVersion {
        return abiVersion(self.abi_version);
    }
};

/// What can go wrong before a single body byte is read.
pub const PrefixError = error{
    /// The bytes do not start with `Magic.word`. This is not a Chock plugin.
    NotAPlugin,
    /// The magic is right and the ABI number is one this build does not know.
    /// Name both numbers and ask the author to rebuild.
    UnknownAbiVersion,
    /// Fewer bytes are present than the format or the prefix itself says are
    /// needed.
    Truncated,
    /// A count or a length above a bound this file keeps.
    TooLarge,
};

/// What can go wrong reading a whole blob.
pub const ParseError = PrefixError || error{
    OutOfMemory,
    /// The prefix is well formed and the body behind it is not.
    MalformedBody,
};

/// What can go wrong writing one.
pub const SerializeError = error{
    /// The destination is smaller than `serializedLen` said it needs to be.
    BufferTooSmall,
    /// The record would not survive `parse`, because some part of it is above
    /// a bound this file keeps.
    TooLarge,
};

/// The detail behind a refusal, for the message a user reads. No part of this
/// allocates, so there is nothing to release.
pub const Refusal = union(enum) {
    not_a_plugin: NotAPlugin,
    unknown_abi_version: UnknownAbiVersion,
    truncated: Truncated,
    too_large: TooLarge,
    malformed_body: MalformedBody,

    pub const NotAPlugin = struct {
        found: u32,
        expected: u32,
    };

    /// Both numbers, always. A message that names only one of them sends an
    /// author to look for the wrong problem.
    pub const UnknownAbiVersion = struct {
        /// The ABI the plugin was built for.
        found: u32,
        /// The ABI this build of Chock writes and reads.
        speaks: u32,
    };

    pub const Truncated = struct {
        what: []const u8,
        have: usize,
        need: usize,
    };

    pub const TooLarge = struct {
        what: []const u8,
        found: u64,
        bound: u64,
    };

    pub const MalformedBody = struct {
        what: []const u8,
        at: usize,
    };

    pub fn format(self: Refusal, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .not_a_plugin => |d| try writer.print(
                "not a Chock plugin: the metadata starts with 0x{X:0>8}, and every Chock plugin starts with 0x{X:0>8}",
                .{ d.found, d.expected },
            ),
            .unknown_abi_version => |d| try writer.print(
                "built for plugin ABI {d}, this Chock speaks plugin ABI {d}: rebuild the plugin",
                .{ d.found, d.speaks },
            ),
            .truncated => |d| try writer.print(
                "the metadata is cut short at {s}: {d} bytes are present where {d} are necessary",
                .{ d.what, d.have, d.need },
            ),
            .too_large => |d| try writer.print(
                "{s} is {d}, above the bound of {d} this reader keeps",
                .{ d.what, d.found, d.bound },
            ),
            .malformed_body => |d| try writer.print(
                "the metadata body is malformed at byte {d}: {s}",
                .{ d.at, d.what },
            ),
        }
    }
};

fn note(slot: ?*?Refusal, refusal: Refusal, err: anytype) @TypeOf(err) {
    if (slot) |s| s.* = refusal;
    return err;
}

/// The number of bytes `serialize` writes for `record`, prefix included.
///
/// Every addition saturates. A record big enough to wrap a `usize` gives back
/// a length above `max_blob_bytes`, which `serializeInto` refuses, so the
/// arithmetic here can never produce a small number for a large record.
pub fn serializedLen(record: Metadata) usize {
    var total: usize = Prefix.len;
    total +|= stringLen(record.name);
    total +|= versionLen(record.version);
    total +|= constraintLen(record.chock_version);
    total +|= stringLen(record.author);
    total +|= localesLen(record.description);
    total +|= 4;
    for (record.tools) |tool| {
        total +|= stringLen(tool.name);
        total +|= localesLen(tool.description);
        total +|= 4;
        for (tool.capabilities) |capability| total +|= stringLen(capability);
        total +|= propertiesLen(tool.parameters);
    }
    return total;
}

fn propertiesLen(properties: []const Property) usize {
    var total: usize = 4;
    for (properties) |property| {
        total +|= stringLen(property.name);
        total +|= stringLen(property.description);
        total +|= 1;
        total +|= shapeLen(property.shape);
    }
    return total;
}

fn shapeLen(shape: Shape) usize {
    var total: usize = 1;
    switch (shape.kind) {
        .array => total +|= 1 +| if (shape.items) |item| shapeLen(item.*) else 0,
        .object => total +|= propertiesLen(shape.properties),
        else => {},
    }
    return total;
}

fn stringLen(text: []const u8) usize {
    return 4 +| text.len;
}

fn optionalStringLen(text: ?[]const u8) usize {
    return 1 +| if (text) |t| stringLen(t) else 0;
}

fn versionLen(version: std.SemanticVersion) usize {
    return 24 +| optionalStringLen(version.pre) +| optionalStringLen(version.build);
}

fn constraintLen(constraint: VersionConstraint) usize {
    var total = versionLen(constraint.min);
    total +|= 1 +| if (constraint.rec) |v| versionLen(v) else 0;
    total +|= 1 +| if (constraint.max) |v| versionLen(v) else 0;
    return total;
}

fn localesLen(fields: []const LocaleField) usize {
    var total: usize = 4;
    for (fields) |field| total +|= stringLen(field.locale) +| stringLen(field.value);
    return total;
}

/// Write `record` into `out` in the current ABI, and answer how many bytes it
/// took. Refuses any record `parse` would refuse, so a guest can never emit a
/// blob that this same file will not read back.
pub fn serializeInto(record: Metadata, out: []u8) SerializeError!usize {
    const total = serializedLen(record);
    if (total > max_blob_bytes) return error.TooLarge;
    if (out.len < total) return error.BufferTooSmall;
    try checkBounds(record);

    var at: usize = 0;
    putU32(out, &at, Magic.word);
    putU32(out, &at, @intFromEnum(AbiVersion.current));
    putU32(out, &at, @intCast(total));

    putString(out, &at, record.name);
    putVersion(out, &at, record.version);
    putConstraint(out, &at, record.chock_version);
    putString(out, &at, record.author);
    putLocales(out, &at, record.description);

    putU32(out, &at, @intCast(record.tools.len));
    for (record.tools) |tool| {
        putString(out, &at, tool.name);
        putLocales(out, &at, tool.description);
        putU32(out, &at, @intCast(tool.capabilities.len));
        for (tool.capabilities) |capability| putString(out, &at, capability);
        putProperties(out, &at, tool.parameters);
    }

    std.debug.assert(at == total);
    return at;
}

/// Write `record` into memory the caller owns. For a host or a test. The guest
/// uses `serializeComptime`, which needs no allocator at all.
pub fn serializeAlloc(gpa: std.mem.Allocator, record: Metadata) (SerializeError || error{OutOfMemory})![]u8 {
    const total = serializedLen(record);
    if (total > max_blob_bytes) return error.TooLarge;
    const out = try gpa.alloc(u8, total);
    errdefer gpa.free(out);
    const written = try serializeInto(record, out);
    std.debug.assert(written == out.len);
    return out;
}

/// The guest's own path: the blob as a fixed array, built while the plugin
/// compiles. There is no allocator in a wasm guest and there does not need to
/// be one, because the metadata is known in full at compile time.
///
/// A record above a bound fails the build with the name of the bound, rather
/// than shipping a plugin whose metadata no host will read.
pub fn serializeComptime(comptime record: Metadata) [serializedLen(record)]u8 {
    comptime {
        var out: [serializedLen(record)]u8 = undefined;
        const written = serializeInto(record, &out) catch |err| @compileError(
            "this plugin's metadata cannot be serialized: " ++ @errorName(err),
        );
        std.debug.assert(written == out.len);
        return out;
    }
}

fn checkBounds(record: Metadata) SerializeError!void {
    try checkString(record.name);
    try checkVersion(record.version);
    try checkVersion(record.chock_version.min);
    if (record.chock_version.rec) |v| try checkVersion(v);
    if (record.chock_version.max) |v| try checkVersion(v);
    try checkString(record.author);
    try checkLocales(record.description);
    if (record.tools.len > max_tools) return error.TooLarge;
    for (record.tools) |tool| {
        try checkString(tool.name);
        try checkLocales(tool.description);
        if (tool.capabilities.len > max_capabilities) return error.TooLarge;
        for (tool.capabilities) |capability| try checkString(capability);
        try checkProperties(tool.parameters, 0);
    }
}

/// **A writer refuses everything the reader refuses.** A guest that could
/// serialise a schema this same file will not read back would ship a plugin no
/// host loads, and the author would learn it from a user rather than from the
/// build.
///
/// The depth is checked by `checkShape` and not here. Every road into this
/// function has already passed through that one at the same depth, so a check
/// here would never fire.
fn checkProperties(properties: []const Property, depth: u32) SerializeError!void {
    if (properties.len > max_properties) return error.TooLarge;
    for (properties) |property| {
        try checkString(property.name);
        try checkString(property.description);
        try checkShape(property.shape, depth + 1);
    }
}

fn checkShape(shape: Shape, depth: u32) SerializeError!void {
    if (depth > max_schema_depth) return error.TooLarge;
    switch (shape.kind) {
        .array => if (shape.items) |item| try checkShape(item.*, depth + 1),
        .object => try checkProperties(shape.properties, depth),
        else => {},
    }
}

fn checkString(text: []const u8) SerializeError!void {
    if (text.len > max_string_bytes) return error.TooLarge;
}

fn checkVersion(version: std.SemanticVersion) SerializeError!void {
    if (version.pre) |t| try checkString(t);
    if (version.build) |t| try checkString(t);
}

fn checkLocales(fields: []const LocaleField) SerializeError!void {
    if (fields.len > max_locales) return error.TooLarge;
    for (fields) |field| {
        try checkString(field.locale);
        try checkString(field.value);
    }
}

fn putU32(out: []u8, at: *usize, value: u32) void {
    std.mem.writeInt(u32, out[at.*..][0..4], value, .little);
    at.* += 4;
}

fn putU64(out: []u8, at: *usize, value: u64) void {
    std.mem.writeInt(u64, out[at.*..][0..8], value, .little);
    at.* += 8;
}

fn putString(out: []u8, at: *usize, text: []const u8) void {
    putU32(out, at, @intCast(text.len));
    @memcpy(out[at.*..][0..text.len], text);
    at.* += text.len;
}

fn putOptionalString(out: []u8, at: *usize, text: ?[]const u8) void {
    if (text) |t| {
        out[at.*] = 1;
        at.* += 1;
        putString(out, at, t);
    } else {
        out[at.*] = 0;
        at.* += 1;
    }
}

fn putVersion(out: []u8, at: *usize, version: std.SemanticVersion) void {
    putU64(out, at, version.major);
    putU64(out, at, version.minor);
    putU64(out, at, version.patch);
    putOptionalString(out, at, version.pre);
    putOptionalString(out, at, version.build);
}

fn putOptionalVersion(out: []u8, at: *usize, version: ?std.SemanticVersion) void {
    if (version) |v| {
        out[at.*] = 1;
        at.* += 1;
        putVersion(out, at, v);
    } else {
        out[at.*] = 0;
        at.* += 1;
    }
}

fn putConstraint(out: []u8, at: *usize, constraint: VersionConstraint) void {
    putVersion(out, at, constraint.min);
    putOptionalVersion(out, at, constraint.rec);
    putOptionalVersion(out, at, constraint.max);
}

fn putProperties(out: []u8, at: *usize, properties: []const Property) void {
    putU32(out, at, @intCast(properties.len));
    for (properties) |property| {
        putString(out, at, property.name);
        putString(out, at, property.description);
        out[at.*] = @intFromBool(property.required);
        at.* += 1;
        putShape(out, at, property.shape);
    }
}

/// One shape: the kind byte, then whatever that kind carries. An array writes a
/// presence byte before its item shape, because an array with no item shape and
/// an array of strings are different declarations.
fn putShape(out: []u8, at: *usize, shape: Shape) void {
    out[at.*] = @intFromEnum(shape.kind);
    at.* += 1;
    switch (shape.kind) {
        .array => {
            if (shape.items) |item| {
                out[at.*] = 1;
                at.* += 1;
                putShape(out, at, item.*);
            } else {
                out[at.*] = 0;
                at.* += 1;
            }
        },
        .object => putProperties(out, at, shape.properties),
        else => {},
    }
}

fn putLocales(out: []u8, at: *usize, fields: []const LocaleField) void {
    putU32(out, at, @intCast(fields.len));
    for (fields) |field| {
        putString(out, at, field.locale);
        putString(out, at, field.value);
    }
}

/// A parsed record and the memory behind it. Every string in `record` is a
/// copy, so the caller may release the blob as soon as this returns.
pub const Parsed = struct {
    arena: std.heap.ArenaAllocator,
    /// The ABI the blob declared, which this build knows because `parse`
    /// refused it otherwise.
    abi_version: AbiVersion,
    record: Metadata,

    /// Release everything the record holds. `record` is not valid after this.
    pub fn deinit(self: Parsed) void {
        self.arena.deinit();
    }
};

/// Read a whole blob. `refusal` is optional: a caller that passes null pays
/// nothing and learns only the error, and a caller that passes a slot gets the
/// detail for the message.
///
/// The order of the checks is part of the format. The magic comes first, then
/// the ABI version, and only then does this reader trust a length.
pub fn parse(gpa: std.mem.Allocator, bytes: []const u8, refusal: ?*?Refusal) ParseError!Parsed {
    const prefix = try Prefix.read(bytes, refusal);
    const known = prefix.known() orelse return note(refusal, .{ .unknown_abi_version = .{
        .found = prefix.abi_version,
        .speaks = @intFromEnum(AbiVersion.current),
    } }, error.UnknownAbiVersion);

    if (bytes.len < prefix.total_len) {
        return note(refusal, .{ .truncated = .{
            .what = "the blob body",
            .have = bytes.len,
            .need = prefix.total_len,
        } }, error.Truncated);
    }

    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();

    var reader: Reader = .{
        .bytes = bytes[0..prefix.total_len],
        .at = Prefix.len,
        .refusal = refusal,
    };
    const record = try readBody(arena.allocator(), &reader, known);

    if (reader.at != reader.bytes.len) {
        return note(refusal, .{ .malformed_body = .{
            .what = "the declared length leaves bytes over",
            .at = reader.at,
        } }, error.MalformedBody);
    }

    return .{ .arena = arena, .abi_version = known, .record = record };
}

fn readBody(arena: std.mem.Allocator, reader: *Reader, abi: AbiVersion) ParseError!Metadata {
    const name = try reader.string("the plugin name");
    const version = try reader.version("the plugin version");
    const chock_version = try reader.constraint();
    const author = try reader.string("the author");
    const description = try reader.locales(arena, "the plugin description");

    const tool_count = try reader.count("the tool count", max_tools);
    const tools = try arena.alloc(ToolDescriptor, tool_count);
    for (tools) |*tool| {
        const tool_name = try reader.string("a tool name");
        const tool_description = try reader.locales(arena, "a tool description");
        const capability_count = try reader.count("a capability count", max_capabilities);
        const capabilities = try arena.alloc([]const u8, capability_count);
        for (capabilities) |*capability| {
            capability.* = try arena.dupe(u8, try reader.string("a capability name"));
        }
        // **A v1 plugin still loads, and its tools take nothing.** That is
        // what a v1 plugin already meant: the ABI it was built for had no way
        // to say a tool takes an argument, so an empty schema is the truth
        // about it and not a guess.
        const parameters = if (abi.carriesSchema())
            try reader.properties(arena, 0)
        else
            &.{};

        tool.* = .{
            .name = try arena.dupe(u8, tool_name),
            .description = tool_description,
            .capabilities = capabilities,
            .parameters = parameters,
        };
    }

    return .{
        .name = try arena.dupe(u8, name),
        .version = try dupeVersion(arena, version),
        .chock_version = .{
            .min = try dupeVersion(arena, chock_version.min),
            .rec = if (chock_version.rec) |v| try dupeVersion(arena, v) else null,
            .max = if (chock_version.max) |v| try dupeVersion(arena, v) else null,
        },
        .author = try arena.dupe(u8, author),
        .description = description,
        .tools = tools,
    };
}

fn dupeVersion(arena: std.mem.Allocator, version: std.SemanticVersion) error{OutOfMemory}!std.SemanticVersion {
    return .{
        .major = version.major,
        .minor = version.minor,
        .patch = version.patch,
        .pre = if (version.pre) |t| try arena.dupe(u8, t) else null,
        .build = if (version.build) |t| try arena.dupe(u8, t) else null,
    };
}

/// A cursor over the body. Every read states what it was reading, so a
/// refusal can say which field ran out of bytes rather than only where.
const Reader = struct {
    bytes: []const u8,
    at: usize,
    refusal: ?*?Refusal,

    fn take(self: *Reader, want: usize, what: []const u8) ParseError![]const u8 {
        const left = self.bytes.len - self.at;
        if (left < want) {
            return note(self.refusal, .{ .truncated = .{
                .what = what,
                .have = left,
                .need = want,
            } }, error.Truncated);
        }
        const out = self.bytes[self.at..][0..want];
        self.at += want;
        return out;
    }

    fn u32Field(self: *Reader, what: []const u8) ParseError!u32 {
        const raw = try self.take(4, what);
        return std.mem.readInt(u32, raw[0..4], .little);
    }

    fn u64Field(self: *Reader, what: []const u8) ParseError!u64 {
        const raw = try self.take(8, what);
        return std.mem.readInt(u64, raw[0..8], .little);
    }

    fn count(self: *Reader, what: []const u8, bound: u32) ParseError!u32 {
        const value = try self.u32Field(what);
        if (value > bound) {
            return note(self.refusal, .{ .too_large = .{
                .what = what,
                .found = value,
                .bound = bound,
            } }, error.TooLarge);
        }
        return value;
    }

    /// Borrowed from the blob, never copied. `readBody` copies what it keeps.
    fn string(self: *Reader, what: []const u8) ParseError![]const u8 {
        const length = try self.count(what, max_string_bytes);
        return self.take(length, what);
    }

    fn optionalString(self: *Reader, what: []const u8) ParseError!?[]const u8 {
        return switch (try self.tag(what)) {
            false => null,
            true => try self.string(what),
        };
    }

    /// A presence byte is exactly zero or exactly one. Any other value is a
    /// blob this reader will not guess about.
    fn tag(self: *Reader, what: []const u8) ParseError!bool {
        const raw = try self.take(1, what);
        return switch (raw[0]) {
            0 => false,
            1 => true,
            else => note(self.refusal, .{ .malformed_body = .{
                .what = what,
                .at = self.at - 1,
            } }, error.MalformedBody),
        };
    }

    fn number(self: *Reader, what: []const u8) ParseError!usize {
        const value = try self.u64Field(what);
        if (value > std.math.maxInt(usize)) {
            return note(self.refusal, .{ .too_large = .{
                .what = what,
                .found = value,
                .bound = std.math.maxInt(usize),
            } }, error.TooLarge);
        }
        return @intCast(value);
    }

    fn version(self: *Reader, what: []const u8) ParseError!std.SemanticVersion {
        return .{
            .major = try self.number(what),
            .minor = try self.number(what),
            .patch = try self.number(what),
            .pre = try self.optionalString(what),
            .build = try self.optionalString(what),
        };
    }

    fn optionalVersion(self: *Reader, what: []const u8) ParseError!?std.SemanticVersion {
        return switch (try self.tag(what)) {
            false => null,
            true => try self.version(what),
        };
    }

    fn constraint(self: *Reader) ParseError!VersionConstraint {
        return .{
            .min = try self.version("the lowest Chock version"),
            .rec = try self.optionalVersion("the recommended Chock version"),
            .max = try self.optionalVersion("the highest Chock version"),
        };
    }

    /// One argument object's fields. `depth` is how far this reader has already
    /// nested, and `shape` is what checks it: every road into this function has
    /// passed through that one at the same depth, so a check here would never
    /// fire.
    fn properties(self: *Reader, arena: std.mem.Allocator, depth: u32) ParseError![]const Property {
        const total = try self.count("an argument field count", max_properties);
        const fields = try arena.alloc(Property, total);
        for (fields) |*field| {
            const name = try self.string("an argument field name");
            const description = try self.string("an argument field description");
            field.* = .{
                .name = try arena.dupe(u8, name),
                .description = try arena.dupe(u8, description),
                .required = try self.tag("an argument field requirement"),
                .shape = try self.shape(arena, depth + 1),
            };
        }
        return fields;
    }

    /// One value's shape. The kind byte is checked against the set before it
    /// decides anything, so a byte nobody wrote is a refusal and never a jump.
    fn shape(self: *Reader, arena: std.mem.Allocator, depth: u32) ParseError!Shape {
        if (depth > max_schema_depth) {
            return note(self.refusal, .{ .too_large = .{
                .what = "the argument schema nesting",
                .found = depth,
                .bound = max_schema_depth,
            } }, error.TooLarge);
        }

        const raw = try self.take(1, "an argument field type");
        const kind = schema.Kind.fromWord(raw[0]) orelse return note(self.refusal, .{ .malformed_body = .{
            .what = "an argument field type this Chock does not have",
            .at = self.at - 1,
        } }, error.MalformedBody);

        switch (kind) {
            .array => {
                if (!try self.tag("an array item shape")) return .{ .kind = .array };
                const item = try arena.create(Shape);
                item.* = try self.shape(arena, depth + 1);
                return .{ .kind = .array, .items = item };
            },
            .object => return .{ .kind = .object, .properties = try self.properties(arena, depth) },
            else => return .{ .kind = kind },
        }
    }

    fn locales(self: *Reader, arena: std.mem.Allocator, what: []const u8) ParseError![]const LocaleField {
        const total = try self.count(what, max_locales);
        const fields = try arena.alloc(LocaleField, total);
        for (fields) |*field| {
            const locale = try self.string("a locale tag");
            const value = try self.string(what);
            field.* = .{
                .locale = try arena.dupe(u8, locale),
                .value = try arena.dupe(u8, value),
            };
        }
        return fields;
    }
};

const testing = std.testing;

/// A record that uses every part of the format at once: an optional that is
/// present, an optional that is absent, several locales, several tools, and a
/// tool with no capabilities beside one with two.
const sample: Metadata = .{
    .name = "sample",
    .version = .{ .major = 1, .minor = 2, .patch = 3, .pre = "rc.1", .build = "abcdef" },
    .chock_version = .{
        .min = .{ .major = 0, .minor = 1, .patch = 0 },
        .rec = .{ .major = 0, .minor = 2, .patch = 0 },
        .max = null,
    },
    .author = "Somebody <somebody@example.com>",
    .description = &.{
        .{ .locale = "en", .value = "A sample" },
        .{ .locale = "ja", .value = "見本" },
    },
    .tools = &.{
        .{
            .name = "quiet",
            .description = &.{.{ .locale = "en", .value = "Changes nothing" }},
        },
        .{
            .name = "loud",
            .description = &.{.{ .locale = "en", .value = "Changes something" }},
            .capabilities = &.{ "fs.read", "git.commit" },
        },
    },
};

test "a record survives serialize and parse unchanged" {
    const bytes = try serializeAlloc(testing.allocator, sample);
    defer testing.allocator.free(bytes);

    var parsed = try parse(testing.allocator, bytes, null);
    defer parsed.deinit();

    try testing.expect(sample.eql(parsed.record));
    try testing.expectEqual(AbiVersion.current, parsed.abi_version);

    // Named by hand as well, because `sample.eql` is one function and a test
    // that rests on it alone says nothing the moment that function is wrong.
    // A serialiser that wrote a locale where its value belongs, or dropped a
    // capability, passes `eql` if `eql` is broken and fails here either way.
    try testing.expectEqualStrings("sample", parsed.record.name);
    try testing.expectEqualStrings("rc.1", parsed.record.version.pre.?);
    try testing.expectEqualStrings("abcdef", parsed.record.version.build.?);
    try testing.expectEqual(@as(usize, 2), parsed.record.description.len);
    try testing.expectEqualStrings("ja", parsed.record.description[1].locale);
    try testing.expectEqualStrings("見本", parsed.record.description[1].value);
    try testing.expectEqual(@as(usize, 2), parsed.record.tools.len);
    try testing.expectEqualStrings("quiet", parsed.record.tools[0].name);
    try testing.expectEqual(@as(usize, 0), parsed.record.tools[0].capabilities.len);
    try testing.expectEqualStrings("git.commit", parsed.record.tools[1].capabilities[1]);
    try testing.expectEqual(@as(?std.SemanticVersion, null), parsed.record.chock_version.max);
    try testing.expectEqual(@as(usize, 2), parsed.record.chock_version.rec.?.minor);
}

test "the parsed record owns its bytes, so the blob may go" {
    const bytes = try serializeAlloc(testing.allocator, sample);
    var parsed = try parse(testing.allocator, bytes, null);
    defer parsed.deinit();
    // Overwrite the blob before reading the record. A parser that handed back
    // slices into the blob would answer with this filler.
    @memset(bytes, 0xAA);
    testing.allocator.free(bytes);
    try testing.expectEqualStrings("sample", parsed.record.name);
    try testing.expectEqualStrings("loud", parsed.record.tools[1].name);
}

test "an all zero buffer is not a plugin" {
    // The reason `Magic.word` is not zero. A zeroed page, an erased flash
    // page, or a file of the right length full of nothing must be refused at
    // the first field, before any length in it is trusted.
    var zeros: [64]u8 = @splat(0);
    var refusal: ?Refusal = null;
    try testing.expectError(error.NotAPlugin, parse(testing.allocator, &zeros, &refusal));
    try testing.expect(refusal.? == .not_a_plugin);
    try testing.expectEqual(@as(u32, 0), refusal.?.not_a_plugin.found);
}

test "an unknown ABI version is refused with both numbers in the message" {
    // The failure that happens constantly: a plugin built for another Chock.
    // The answer must name the plugin's ABI and this build's ABI, or the
    // author has nothing to act on.
    const bytes = try serializeAlloc(testing.allocator, sample);
    defer testing.allocator.free(bytes);
    std.mem.writeInt(u32, bytes[Prefix.abi_version_offset..][0..4], 7, .little);

    var refusal: ?Refusal = null;
    try testing.expectError(error.UnknownAbiVersion, parse(testing.allocator, bytes, &refusal));

    var text: std.Io.Writer.Allocating = .init(testing.allocator);
    defer text.deinit();
    try refusal.?.format(&text.writer);

    const want = try std.fmt.allocPrint(
        testing.allocator,
        "built for plugin ABI 7, this Chock speaks plugin ABI {d}: rebuild the plugin",
        .{@intFromEnum(AbiVersion.current)},
    );
    defer testing.allocator.free(want);
    try testing.expectEqualStrings(want, text.written());
}

test "a wrong magic is a different refusal from a wrong ABI version" {
    // Two failures, two messages. Collapsing them sends an author to check
    // whether the file is corrupt when the file is merely old.
    const bytes = try serializeAlloc(testing.allocator, sample);
    defer testing.allocator.free(bytes);
    std.mem.writeInt(u32, bytes[Prefix.magic_offset..][0..4], 0xDEAD_BEEF, .little);

    var refusal: ?Refusal = null;
    try testing.expectError(error.NotAPlugin, parse(testing.allocator, bytes, &refusal));

    var text: std.Io.Writer.Allocating = .init(testing.allocator);
    defer text.deinit();
    try refusal.?.format(&text.writer);
    try testing.expectEqualStrings(
        "not a Chock plugin: the metadata starts with 0xDEADBEEF, and every Chock plugin starts with 0x9E4B4843",
        text.written(),
    );
}

test "the magic is checked before the declared length is trusted" {
    // A blob that is not ours must never hand this reader a length. The
    // length field here says four gigabytes minus one, which is far above
    // `max_blob_bytes`, so a reader that read the length first would answer
    // TooLarge and tell the user the wrong thing about the wrong file.
    var blob: [Prefix.len]u8 = @splat(0);
    std.mem.writeInt(u32, blob[Prefix.magic_offset..][0..4], Magic.word ^ 1, .little);
    std.mem.writeInt(u32, blob[Prefix.total_len_offset..][0..4], std.math.maxInt(u32), .little);
    try testing.expectError(error.NotAPlugin, Prefix.read(&blob, null));
}

test "a blob shorter than the fixed prefix is refused before any field is read" {
    // Eleven bytes carry a magic and an ABI version but not a length. A
    // reader that checked the prefix field by field would read past the end.
    var blob: [Prefix.len - 1]u8 = @splat(0);
    std.mem.writeInt(u32, blob[Prefix.magic_offset..][0..4], Magic.word, .little);
    var refusal: ?Refusal = null;
    try testing.expectError(error.Truncated, Prefix.read(&blob, &refusal));
    try testing.expectEqual(@as(usize, Prefix.len), refusal.?.truncated.need);
    try testing.expectEqual(@as(usize, Prefix.len - 1), refusal.?.truncated.have);
}

test "a blob cut short of its own declared length is refused" {
    // The prefix is intact and says how long the blob is. Fewer bytes than
    // that is a truncated file, not a malformed body, and the reader must not
    // start reading the body to find that out.
    const bytes = try serializeAlloc(testing.allocator, sample);
    defer testing.allocator.free(bytes);

    var refusal: ?Refusal = null;
    try testing.expectError(
        error.Truncated,
        parse(testing.allocator, bytes[0 .. bytes.len - 1], &refusal),
    );
    try testing.expectEqual(bytes.len, refusal.?.truncated.need);
    try testing.expectEqual(bytes.len - 1, refusal.?.truncated.have);
}

test "a body cut short inside a string is refused rather than read past" {
    // Shorten the declared total length so the prefix and the buffer agree,
    // but the body runs out in the middle of a field. This is the case a
    // reader that trusted its own lengths would walk off the end of.
    const bytes = try serializeAlloc(testing.allocator, sample);
    defer testing.allocator.free(bytes);

    const cut = bytes[0 .. Prefix.len + 6];
    std.mem.writeInt(u32, cut[Prefix.total_len_offset..][0..4], @intCast(cut.len), .little);

    var refusal: ?Refusal = null;
    try testing.expectError(error.Truncated, parse(testing.allocator, cut, &refusal));
    try testing.expectEqualStrings("the plugin name", refusal.?.truncated.what);
}

test "a declared string length above the bound is refused before the bytes are taken" {
    // The first field of the body is the plugin name. Claim a name of one
    // gigabyte inside a blob of a few hundred bytes.
    const bytes = try serializeAlloc(testing.allocator, sample);
    defer testing.allocator.free(bytes);
    std.mem.writeInt(u32, bytes[Prefix.len..][0..4], 1 << 30, .little);

    var refusal: ?Refusal = null;
    try testing.expectError(error.TooLarge, parse(testing.allocator, bytes, &refusal));
    try testing.expectEqual(@as(u64, max_string_bytes), refusal.?.too_large.bound);
    try testing.expectEqual(@as(u64, 1 << 30), refusal.?.too_large.found);
}

test "a declared tool count above the bound is refused before the tools are allocated" {
    // A count is an allocation request from a file somebody else wrote. Four
    // billion tools must cost nothing to refuse.
    const bytes = try serializeAlloc(testing.allocator, sample);
    defer testing.allocator.free(bytes);

    // Walk the body to the tool count rather than writing an offset by hand,
    // so this test keeps working when a field ahead of it changes width.
    var reader: Reader = .{ .bytes = bytes, .at = Prefix.len, .refusal = null };
    _ = try reader.string("name");
    _ = try reader.version("version");
    _ = try reader.constraint();
    _ = try reader.string("author");
    var scratch: std.heap.ArenaAllocator = .init(testing.allocator);
    defer scratch.deinit();
    _ = try reader.locales(scratch.allocator(), "description");
    const tool_count_at = reader.at;

    std.mem.writeInt(u32, bytes[tool_count_at..][0..4], std.math.maxInt(u32), .little);
    var refusal: ?Refusal = null;
    try testing.expectError(error.TooLarge, parse(testing.allocator, bytes, &refusal));
    try testing.expectEqual(@as(u64, max_tools), refusal.?.too_large.bound);
}

test "a presence byte that is neither zero nor one is refused" {
    // The optional pre release tag of the plugin version. A reader that took
    // any non zero byte as present would accept a blob it cannot round trip.
    const bytes = try serializeAlloc(testing.allocator, sample);
    defer testing.allocator.free(bytes);

    // The name field, then major, minor and patch, then the pre release tag.
    const pre_tag_at = Prefix.len + 4 + sample.name.len + 24;
    try testing.expectEqual(@as(u8, 1), bytes[pre_tag_at]);
    bytes[pre_tag_at] = 2;

    var refusal: ?Refusal = null;
    try testing.expectError(error.MalformedBody, parse(testing.allocator, bytes, &refusal));
    try testing.expectEqual(pre_tag_at, refusal.?.malformed_body.at);
}

test "a blob whose declared length leaves bytes over is refused" {
    // The body must account for every byte the prefix claimed. Extra bytes
    // inside the declared length are a blob this reader does not understand,
    // and reading it anyway would let a later ABI's fields pass unnoticed.
    const bytes = try serializeAlloc(testing.allocator, sample);
    defer testing.allocator.free(bytes);

    const padded = try testing.allocator.alloc(u8, bytes.len + 3);
    defer testing.allocator.free(padded);
    @memcpy(padded[0..bytes.len], bytes);
    @memset(padded[bytes.len..], 0);
    std.mem.writeInt(u32, padded[Prefix.total_len_offset..][0..4], @intCast(padded.len), .little);

    try testing.expectError(error.MalformedBody, parse(testing.allocator, padded, null));
}

test "bytes after the declared length are ignored" {
    // The other side of the rule above. A blob read out of a larger buffer,
    // such as a wasm section with padding after it, still parses.
    const bytes = try serializeAlloc(testing.allocator, sample);
    defer testing.allocator.free(bytes);

    const padded = try testing.allocator.alloc(u8, bytes.len + 8);
    defer testing.allocator.free(padded);
    @memcpy(padded[0..bytes.len], bytes);
    @memset(padded[bytes.len..], 0xFF);

    var parsed = try parse(testing.allocator, padded, null);
    defer parsed.deinit();
    try testing.expect(sample.eql(parsed.record));
}

test "the prefix is at the offsets the format promises" {
    // The prefix is a promise to every ABI that comes later. Read the three
    // fields out of a real blob by hand, at the documented offsets and
    // widths, rather than through the reader that wrote them.
    const bytes = try serializeAlloc(testing.allocator, sample);
    defer testing.allocator.free(bytes);

    try testing.expectEqual(@as(u32, 0x9E4B_4843), std.mem.readInt(u32, bytes[0..4], .little));
    try testing.expectEqual(
        @as(u32, @intFromEnum(AbiVersion.current)),
        std.mem.readInt(u32, bytes[4..8], .little),
    );
    try testing.expectEqual(@as(u32, @intCast(bytes.len)), std.mem.readInt(u32, bytes[8..12], .little));
    try testing.expectEqualSlices(u8, &.{ 'C', 'H', 'K', 0x9E }, bytes[0..4]);
}

test "abiVersion answers null for a number this build does not know" {
    // The whole reason the version is separate from the magic: an unknown ABI
    // is a message, never a trap. `@enumFromInt` on this input would be
    // undefined behaviour.
    try testing.expectEqual(AbiVersion.v1, abiVersion(1).?);
    try testing.expectEqual(@as(?AbiVersion, null), abiVersion(0));
    try testing.expectEqual(@as(?AbiVersion, null), abiVersion(7));
    try testing.expectEqual(@as(?AbiVersion, null), abiVersion(std.math.maxInt(u32)));
}

test "serializedLen agrees with what serializeInto writes" {
    // The guest sizes its exported array with `serializedLen` and fills it
    // with `serializeInto`. A disagreement between the two is a buffer
    // overrun in every plugin ever built.
    var buffer: [4096]u8 = undefined;
    const written = try serializeInto(sample, &buffer);
    try testing.expectEqual(serializedLen(sample), written);
}

test "serializeInto refuses a buffer one byte short" {
    var buffer: [4096]u8 = undefined;
    const need = serializedLen(sample);
    try testing.expectError(error.BufferTooSmall, serializeInto(sample, buffer[0 .. need - 1]));
}

test "serialize refuses a record parse would refuse" {
    // The guest and the host share one set of bounds. A plugin must fail to
    // build rather than ship metadata no host will read.
    const long = "x" ** (max_string_bytes + 1);
    const oversized: Metadata = .{
        .name = long,
        .version = .{ .major = 0, .minor = 0, .patch = 1 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "a",
    };
    var buffer: [max_string_bytes * 2]u8 = undefined;
    try testing.expectError(error.TooLarge, serializeInto(oversized, &buffer));
}

test "serializeComptime builds the same bytes at compile time" {
    // The guest never allocates, so its blob is built while it compiles. It
    // must be the very same blob the host side path produces.
    const compiled = comptime serializeComptime(sample);
    const allocated = try serializeAlloc(testing.allocator, sample);
    defer testing.allocator.free(allocated);
    try testing.expectEqualSlices(u8, allocated, &compiled);
}

test "an empty record still carries a readable prefix" {
    // The smallest thing a plugin can say about itself. A plugin with no
    // tools and no description must still round trip, because the host reads
    // the metadata of every module before it decides anything.
    const bare: Metadata = .{
        .name = "",
        .version = .{ .major = 0, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 0, .patch = 0 } },
        .author = "",
    };
    const bytes = try serializeAlloc(testing.allocator, bare);
    defer testing.allocator.free(bytes);

    var parsed = try parse(testing.allocator, bytes, null);
    defer parsed.deinit();
    try testing.expect(bare.eql(parsed.record));
    try testing.expectEqual(@as(usize, 0), parsed.record.tools.len);
}

/// A schema that uses every part of the format: a required string, an optional
/// flag, a list of strings, and a list of records.
const schema_sample: []const Property = &.{
    .{ .name = "who", .description = "Who to greet.", .required = true, .shape = .{ .kind = .string } },
    .{ .name = "loudly", .description = "True to shout.", .required = false, .shape = .{ .kind = .boolean } },
    .{ .name = "times", .description = "How many.", .required = false, .shape = .{ .kind = .integer } },
    .{ .name = "ratio", .description = "How much.", .required = false, .shape = .{ .kind = .number } },
    .{
        .name = "argv",
        .description = "The words.",
        .required = false,
        .shape = .{ .kind = .array, .items = &.{ .kind = .string } },
    },
    .{
        .name = "steps",
        .description = "The list.",
        .required = true,
        .shape = .{ .kind = .array, .items = &.{ .kind = .object, .properties = &.{
            .{ .name = "title", .description = "What it is.", .required = true, .shape = .{ .kind = .string } },
        } } },
    },
};

test "an argument schema survives the round trip field for field" {
    // The schema is what the model writes its arguments against. A field that
    // was dropped, reordered, or read back with the wrong requirement would
    // leave the model told something the plugin does not mean.
    var record = sample;
    var tools: [1]ToolDescriptor = .{.{ .name = "greet", .parameters = schema_sample }};
    record.tools = &tools;

    const bytes = try serializeAlloc(testing.allocator, record);
    defer testing.allocator.free(bytes);

    var parsed = try parse(testing.allocator, bytes, null);
    defer parsed.deinit();
    try testing.expect(record.eql(parsed.record));

    const read = parsed.record.tools[0].parameters;
    try testing.expectEqual(@as(usize, 6), read.len);
    try testing.expectEqualStrings("who", read[0].name);
    try testing.expect(read[0].required);
    try testing.expect(!read[1].required);
    try testing.expectEqual(schema.Kind.array, read[4].shape.kind);
    try testing.expectEqual(schema.Kind.string, read[4].shape.items.?.kind);
    try testing.expectEqual(schema.Kind.object, read[5].shape.items.?.kind);
    try testing.expectEqualStrings("title", read[5].shape.items.?.properties[0].name);
}

test "a schema with more fields than the bound is refused, and the bound is named" {
    // The count comes out of a file somebody else wrote, and every field of it
    // is read by the model on every turn. A reader that allocated on the
    // count's say so would allocate whatever the file asked for.
    var many: [max_properties + 1]Property = @splat(.{
        .name = "f",
        .description = "A field.",
        .required = false,
        .shape = .{ .kind = .string },
    });
    var tools: [1]ToolDescriptor = .{.{ .name = "greet", .parameters = &many }};
    var record = sample;
    record.tools = &tools;

    // The writer refuses what the reader refuses, so a guest cannot ship a
    // blob this same file will not read back.
    try testing.expectError(error.TooLarge, serializeAlloc(testing.allocator, record));

    // And the reader refuses it, measured by writing the count by hand into a
    // blob that is otherwise well formed.
    var small: [1]ToolDescriptor = .{.{ .name = "greet", .parameters = &.{} }};
    record.tools = &small;
    const bytes = try serializeAlloc(testing.allocator, record);
    defer testing.allocator.free(bytes);

    const at = std.mem.lastIndexOf(u8, bytes, &.{ 0, 0, 0, 0 }).?;
    std.mem.writeInt(u32, bytes[at..][0..4], max_properties + 1, .little);

    var refusal: ?Refusal = null;
    try testing.expectError(error.TooLarge, parse(testing.allocator, bytes, &refusal));
    try testing.expectEqual(@as(u64, max_properties), refusal.?.too_large.bound);
    try testing.expectEqualStrings("an argument field count", refusal.?.too_large.what);
}

test "a schema that nests past the bound is refused before it is followed" {
    // A blob that asked this reader to recurse a thousand levels would run the
    // stack out before anything noticed. The check is on the way in.
    // Each slot points at the one before it, so the nesting is real and the
    // walk is finite. A slot that pointed at itself would be a test that hangs
    // rather than one that measures the bound.
    var holder: [max_schema_depth + 2]Shape = undefined;
    holder[0] = .{ .kind = .string };
    for (holder[1..], 0..) |*slot, before| {
        slot.* = .{ .kind = .array, .items = &holder[before] };
    }

    var tools: [1]ToolDescriptor = .{.{ .name = "greet", .parameters = &.{.{
        .name = "deep",
        .description = "A field.",
        .required = false,
        .shape = holder[holder.len - 1],
    }} }};
    var record = sample;
    record.tools = &tools;
    try testing.expectError(error.TooLarge, serializeAlloc(testing.allocator, record));
}

test "a blob that nests deeper than the bound is refused before it is followed" {
    // **The reader's own guard, against bytes rather than against a record.**
    // The writer refuses what the reader refuses, so a blob this deep cannot be
    // built by serialising one: it is spliced together here, which is exactly
    // how a hostile one would arrive.
    //
    // Mutation check: take the depth check out of `Reader.shape` and this runs
    // the stack out instead of answering.
    var tools: [1]ToolDescriptor = .{.{ .name = "greet", .parameters = &.{.{
        .name = "argv",
        .description = "The words.",
        .required = true,
        .shape = .{ .kind = .array, .items = &.{ .kind = .string } },
    }} }};
    var record = sample;
    record.tools = &tools;

    const bytes = try serializeAlloc(testing.allocator, record);
    defer testing.allocator.free(bytes);

    // The shape is the last three bytes: an array, a present item, a string.
    const shape_at = bytes.len - 3;
    try testing.expectEqual(@intFromEnum(schema.Kind.array), bytes[shape_at]);
    try testing.expectEqual(@as(u8, 1), bytes[shape_at + 1]);
    try testing.expectEqual(@intFromEnum(schema.Kind.string), bytes[shape_at + 2]);

    // One more array level is two bytes: the kind, then the present byte of
    // the item that follows.
    const levels = max_schema_depth + 4;
    const deeper = try testing.allocator.alloc(u8, bytes.len + levels * 2);
    defer testing.allocator.free(deeper);
    @memcpy(deeper[0..shape_at], bytes[0..shape_at]);
    for (0..levels) |level| {
        deeper[shape_at + level * 2] = @intFromEnum(schema.Kind.array);
        deeper[shape_at + level * 2 + 1] = 1;
    }
    @memcpy(deeper[shape_at + levels * 2 ..], bytes[shape_at..]);
    std.mem.writeInt(u32, deeper[Prefix.total_len_offset..][0..4], @intCast(deeper.len), .little);

    var refusal: ?Refusal = null;
    try testing.expectError(error.TooLarge, parse(testing.allocator, deeper, &refusal));
    try testing.expectEqual(@as(u64, max_schema_depth), refusal.?.too_large.bound);
    try testing.expectEqualStrings("the argument schema nesting", refusal.?.too_large.what);
}

test "a field type byte this Chock does not have is refused rather than read" {
    // The byte decides what is read next. A reader that indexed with it would
    // take a number nobody wrote as a shape.
    var tools: [1]ToolDescriptor = .{.{ .name = "greet", .parameters = &.{.{
        .name = "who",
        .description = "Who to greet.",
        .required = true,
        .shape = .{ .kind = .string },
    }} }};
    var record = sample;
    record.tools = &tools;

    const bytes = try serializeAlloc(testing.allocator, record);
    defer testing.allocator.free(bytes);

    // The kind byte is the last one of the blob: name, description, the
    // requirement byte, then the shape.
    try testing.expectEqual(@intFromEnum(schema.Kind.string), bytes[bytes.len - 1]);
    bytes[bytes.len - 1] = 200;

    var refusal: ?Refusal = null;
    try testing.expectError(error.MalformedBody, parse(testing.allocator, bytes, &refusal));
    try testing.expectEqualStrings(
        "an argument field type this Chock does not have",
        refusal.?.malformed_body.what,
    );
}

test "a plugin built for the first ABI still loads, and its tools take nothing" {
    // The reason the ABI number went up rather than the body changing under
    // it. A v1 plugin said nothing about what its tools take, because its ABI
    // had no way to, so an empty schema is the truth about it.
    var tools: [1]ToolDescriptor = .{.{ .name = "greet", .parameters = &.{} }};
    var record = sample;
    record.tools = &tools;

    const bytes = try serializeAlloc(testing.allocator, record);
    defer testing.allocator.free(bytes);

    // A v2 blob whose tools carry an empty schema is a v1 blob with four zero
    // bytes on the end of each tool record. Take them off and call it v1.
    const shortened = try testing.allocator.alloc(u8, bytes.len - 4);
    defer testing.allocator.free(shortened);
    @memcpy(shortened, bytes[0 .. bytes.len - 4]);
    std.mem.writeInt(u32, shortened[Prefix.abi_version_offset..][0..4], 1, .little);
    std.mem.writeInt(u32, shortened[Prefix.total_len_offset..][0..4], @intCast(shortened.len), .little);

    var parsed = try parse(testing.allocator, shortened, null);
    defer parsed.deinit();
    try testing.expectEqual(AbiVersion.v1, parsed.abi_version);
    try testing.expectEqual(@as(usize, 1), parsed.record.tools.len);
    try testing.expectEqual(@as(usize, 0), parsed.record.tools[0].parameters.len);
}
