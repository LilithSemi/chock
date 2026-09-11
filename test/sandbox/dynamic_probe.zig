//! A dynamically linked program, for the one thing `test/sandbox/probe.zig`
//! cannot be.
//!
//! **The probe is statically linked, so it never runs a dynamic loader.** That
//! is a blind spot and not a clean result: the loader's opens come first, and
//! there are dozens of them, so a path record that names every open outside
//! the workspace is full of toolchain paths before the program has run a line
//! of its own. A record split on what the sandbox's own configuration granted
//! counts those and keeps the names for the paths nobody granted. This program
//! is what makes that difference measurable through a real `Sandbox.spawn`.
//!
//! It links libc, which is what makes it dynamic. The interpreter and every
//! library it then opens are under the toolchain tree, and that tree is a
//! mount the sandbox configuration declares, so a correct split names none of
//! them.
//!
//! It then opens one path the configuration grants nothing for. That open is
//! the only name the record should hold. **The open does not have to succeed**:
//! the kernel tells the reader about the call before it runs it, so a path that
//! is not there is recorded exactly as one that is.

const std = @import("std");
const linux = std.os.linux;

/// The one path nothing in the sandbox configuration grants. The same spelling
/// as `probe.zig`'s own `named_ungranted`, because the caller looks for it by
/// name in the record.
const named_ungranted = "/etc/chock-probe-secret";

pub fn main() void {
    const rc = linux.openat(linux.AT.FDCWD, named_ungranted, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(rc) == .SUCCESS) _ = linux.close(@intCast(rc));
}
