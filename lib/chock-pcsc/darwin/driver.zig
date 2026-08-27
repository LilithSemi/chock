//! The Darwin transport for `chock-pcsc`. See `../../chock-pcsc.zig`'s own top
//! comment for the decision this file carries out.
//!
//! **Every call here answers `error.Unavailable`, and that is deliberate.**
//!
//! macOS ships `PCSC.framework` with the system, so nothing has to be
//! installed. It is still a framework that has to be linked, and linking it
//! means `-framework PCSC` in `build.zig`, which is the same C dependency this
//! repository does not take anywhere else. Darwin may reach `std.c`, the libc
//! binding Zig already links on this target,
//! and `chock-io/darwin/driver.zig` uses exactly that. **`PCSC.framework` is
//! not libc.** It is a separate framework with its own linker flag, so the
//! bend that lets `chock-io` call `pipe` does not reach this far.
//!
//! There is a second reason, and it is the one that would still hold if the
//! rule changed: there is no Darwin machine with a reader to check an
//! implementation against. A transport written and never run is a transport
//! that has not been shown to work.
//!
//! **`error.Unavailable` is never `error.NoCard`.** Nothing was asked here, so
//! nothing can be concluded about a reader or a card.
//!
//! What replaces this file, when it is replaced: one more implementation of
//! `Pcsc.VTable`, five functions, with no change anywhere above it.

const std = @import("std");
const iface = @import("../../chock-pcsc.zig");

/// The same shape `../linux/driver.zig` has, so `chock-pcsc.zig` states one
/// type and no platform branch reaches a caller. It holds nothing, because
/// there is nothing on this platform to hold.
pub const Driver = struct {
    /// Taken and ignored. A driver on this platform opens nothing.
    io: std.Io,

    pub fn init(io: std.Io) Driver {
        return .{ .io = io };
    }

    pub fn pcsc(self: *Driver) iface.Pcsc {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Nothing was opened, so there is nothing to close. Here so a caller
    /// writes the same two lines on either platform.
    pub fn deinit(self: *Driver) void {
        _ = self;
    }
};

fn establishFn(ptr: *anyopaque) iface.Error!void {
    _ = ptr;
    return error.Unavailable;
}

fn listReadersFn(ptr: *anyopaque, out: []u8) iface.Error!usize {
    _ = ptr;
    _ = out;
    return error.Unavailable;
}

fn connectFn(ptr: *anyopaque, reader: []const u8) iface.Error!iface.Handle {
    _ = ptr;
    _ = reader;
    return error.Unavailable;
}

fn transmitFn(ptr: *anyopaque, handle: iface.Handle, send: []const u8, receive: []u8) iface.Error!usize {
    _ = ptr;
    _ = handle;
    _ = send;
    _ = receive;
    return error.Unavailable;
}

fn disconnectFn(ptr: *anyopaque, handle: iface.Handle) void {
    _ = ptr;
    _ = handle;
}

const vtable = iface.Pcsc.VTable{
    .establish = establishFn,
    .listReaders = listReadersFn,
    .connect = connectFn,
    .transmit = transmitFn,
    .disconnect = disconnectFn,
};
