//! The root source file of a plugin binary. A plugin author's file reaches
//! nothing on its own, so this file re-exports it and the SDK's export block.

const chock_plugin_sdk = @import("chock-plugin-sdk");

pub const chock_plugin_metadata: chock_plugin_sdk.Metadata =
    @import("chock-plugin").chock_plugin_metadata;

comptime {
    // Without this line the plugin compiles and exports nothing at all.
    _ = chock_plugin_sdk.exports;
}
