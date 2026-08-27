//! What a plugin host and a plugin guest both need, and nothing else.
//!
//! This library holds the types a plugin describes itself with, the magic, and
//! the serialisation format as pure functions over bytes in both directions.
//! It parses no wasm, starts no engine, and wires nothing to the agent loop.
//! The host side reader and the guest side code generator are separate jobs
//! and separate libraries.
//!
//! It imports no other chock library, and it compiles for
//! `wasm32-freestanding`, because `chock-plugin-sdk` builds it into every
//! plugin. Anything that needs a file, a socket, or a process belongs
//! somewhere else.
//!
//! ## The two symbols, and the two failures they separate
//!
//! A guest exports `chock_plugin_magic`, whose `u32` value is the ABI version
//! it was built for, and `chock_plugin_metadata`, which is the serialised
//! record. **The symbol name is the magic.** A module with no such symbol is
//! not a Chock plugin at all. A module that has it with a number this build
//! does not know is a Chock plugin for another Chock, which is a different
//! problem with a different answer: name both numbers and ask for a rebuild.
//!
//! `chock_plugin_init` is the third symbol, and it is the only one that ever
//! runs. Reading the metadata never calls it, so a host inspects a plugin and
//! then refuses it, rather than running it to find out whether to run it.
//!
//! See `lib/chock-plugin-core/wire.zig` for the format and for why the fixed
//! prefix never moves.

pub const metadata = @import("chock-plugin-core/metadata.zig");
pub const wire = @import("chock-plugin-core/wire.zig");
/// The call ABI: the one exported function that runs a tool, and where the
/// answer is in the guest's own memory. See its own top comment for why every
/// field of an answer is bounds checked by the host.
pub const call = @import("chock-plugin-core/call.zig");

pub const VersionConstraint = metadata.VersionConstraint;
pub const LocaleField = metadata.LocaleField;
pub const ToolDescriptor = metadata.ToolDescriptor;
pub const Metadata = metadata.Metadata;

pub const Magic = wire.Magic;
pub const AbiVersion = wire.AbiVersion;
pub const Prefix = wire.Prefix;
pub const Refusal = wire.Refusal;
pub const ParseError = wire.ParseError;
pub const PrefixError = wire.PrefixError;
pub const SerializeError = wire.SerializeError;
pub const Parsed = wire.Parsed;

pub const abiVersion = wire.abiVersion;
pub const serializedLen = wire.serializedLen;
pub const serializeInto = wire.serializeInto;
pub const serializeAlloc = wire.serializeAlloc;
pub const serializeComptime = wire.serializeComptime;
pub const parse = wire.parse;

/// The guest symbol a host calls after it has read the metadata and decided to
/// load the plugin. It binds the tool table and answers how many entries it
/// bound.
pub const init_symbol = "chock_plugin_init";

/// The guest symbol a host calls to run one tool. See `call`.
pub const call_symbol = call.call_symbol;

test {
    @import("std").testing.refAllDecls(@This());
}
