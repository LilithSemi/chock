//! Reads a container image and gives back an environment and a set of
//! directories to mount. The sandbox is unchanged by it.

const std = @import("std");

const diagnostic = @import("chock-container/diagnostic.zig");

pub const Diagnostic = diagnostic.Diagnostic;

pub const Sink = diagnostic.Sink;

pub const sinkOf = diagnostic.sinkOf;

pub const config = @import("chock-container/config.zig");
pub const Image = @import("chock-container/Image.zig");
pub const proc = @import("chock-container/proc.zig");
pub const reference = @import("chock-container/reference.zig");
pub const Runtime = @import("chock-container/Runtime.zig");

test {
    std.testing.refAllDecls(@This());
    _ = config;
    _ = Image;
    _ = proc;
    _ = reference;
    _ = Runtime;
}
