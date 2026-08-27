//! The root source file of a plugin binary.
//!
//! A plugin author's file declares `chock_plugin_metadata` and calls nothing.
//! Zig analyses a declaration only when something reaches it, so a binary
//! whose root is the author's file reaches nothing and emits no symbols at
//! all. This file is the root instead. It names the author's declaration, and
//! it names `chock-plugin-sdk`'s export block, so both are analysed and the
//! three guest symbols land in the module.
//!
//! Re-exporting the declaration here is what makes `@import("root")` name it
//! from anywhere in the compilation, which is where
//! `lib/chock-plugin-sdk/exports.zig` reads it.
//!
//! `build.zig` builds a plugin from this file with the author's file supplied
//! as the module `chock-plugin`.

const chock_plugin_sdk = @import("chock-plugin-sdk");

/// The author's own declaration, under the name the SDK looks for. This is
/// what makes `@import("root").chock_plugin_metadata` name it from anywhere in
/// the compilation.
pub const chock_plugin_metadata: chock_plugin_sdk.Metadata =
    @import("chock-plugin").chock_plugin_metadata;

comptime {
    // Reaching the SDK's export block is the other half of the job. Without
    // this line the plugin compiles and exports nothing at all.
    _ = chock_plugin_sdk.exports;
}
