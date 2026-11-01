//! Chock's configuration adapter around the package-owned OCI runtime.

const std = @import("std");
const oci = @import("oci");

pub const Diagnostic = oci.Diagnostic;
pub const Sink = oci.Sink;
pub const sinkOf = oci.sinkOf;

pub const config = @import("chock-container/config.zig");
pub const Image = oci.Image;
pub const proc = oci.proc;
pub const reference = oci.reference;
pub const Runtime = oci.Runtime;

test {
    std.testing.refAllDecls(@This());
    _ = config;
    _ = oci;
}
