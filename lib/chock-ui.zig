//! The widget tree Chock draws, and the state behind it.
//!
//! One tree for three backends: phantom's terminal, its window, and its web
//! backend over wasm. Nothing here reaches a syscall, so it compiles for
//! wasm32-freestanding. The wiring that feeds it lives in `src/ui.zig` for a
//! native run and in the web app root for a browser.

pub const layout = @import("chock-ui/layout.zig");
pub const model = @import("chock-ui/model.zig");
pub const ui = @import("chock-ui/Ui.zig");
pub const Ui = ui.Ui;
pub const host = @import("chock-ui/host.zig");
pub const Host = host.Host;
pub const source = @import("chock-ui/source.zig");
pub const Source = source.Source;

pub const text = @import("chock-ui/text.zig");

test {
    _ = layout;
    _ = model;
    _ = host;
    _ = source;
    _ = text;
}
