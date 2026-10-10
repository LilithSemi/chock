//! The browser's root widget. The same tree the terminal and the window draw:
//! `app.zig` wires `chock-ui`'s interface to the daemon, and this file only
//! names it.

const phantom = @import("phantom");
const web_source = @import("source.zig");
const web_host = @import("host.zig");
const app = @import("app.zig");

pub fn root(ctx: *phantom.BuildContext) phantom.Widget {
    const page = app.App{};
    return ctx.new(page).widget();
}

test {
    // Names each file so its tests are collected. An import nothing references
    // is never analysed, and its tests silently do not exist.
    _ = web_source;
    _ = web_host;
    _ = app;
}
