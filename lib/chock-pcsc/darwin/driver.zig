//! The Darwin transport for `chock-pcsc`. See `../../chock-pcsc.zig`'s own top

const std = @import("std");
const iface = @import("../../chock-pcsc.zig");

pub const Driver = struct {
    io: std.Io,

    pub fn init(io: std.Io) Driver {
        return .{ .io = io };
    }

    pub fn pcsc(self: *Driver) iface.Pcsc {
        return .{ .ptr = self, .vtable = &vtable };
    }

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
