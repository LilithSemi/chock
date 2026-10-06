//! What a plugin host and a plugin guest both need.

pub const metadata = @import("chock-plugin-core/metadata.zig");
pub const schema = @import("chock-plugin-core/schema.zig");
pub const wire = @import("chock-plugin-core/wire.zig");
pub const args = @import("chock-plugin-core/args.zig");
pub const call = @import("chock-plugin-core/call.zig");

pub const VersionConstraint = metadata.VersionConstraint;
pub const LocaleField = metadata.LocaleField;
pub const ToolDescriptor = metadata.ToolDescriptor;
pub const Property = schema.Property;
pub const Shape = schema.Shape;
pub const Kind = schema.Kind;
pub const Metadata = metadata.Metadata;

pub const Magic = wire.Magic;
pub const AbiVersion = wire.AbiVersion;
pub const Prefix = wire.Prefix;
pub const Refusal = wire.Refusal;
pub const ParseError = wire.ParseError;
pub const PrefixError = wire.PrefixError;
pub const SerializeError = wire.SerializeError;
pub const max_properties = wire.max_properties;
pub const max_schema_depth = wire.max_schema_depth;
pub const Parsed = wire.Parsed;

pub const abiVersion = wire.abiVersion;
pub const serializedLen = wire.serializedLen;
pub const serializeInto = wire.serializeInto;
pub const serializeAlloc = wire.serializeAlloc;
pub const serializeComptime = wire.serializeComptime;
pub const parse = wire.parse;

pub const init_symbol = "chock_plugin_init";

pub const call_symbol = call.call_symbol;

test {
    @import("std").testing.refAllDecls(@This());
}
