//! The channel a device passthrough uses to cross the sandbox boundary: a
//! fixed size message carrying two paths, over a SOCK_SEQPACKET pair.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

/// Must differ from `routerlink.fd_number`, since the two channels can be open at once.
pub const fd_number: i32 = 4;

pub const request_magic: u32 = 0x31564443;

pub const reply_magic: u32 = 0x31524443;

pub const max_path_bytes: usize = 108;

/// Fixed size, so `serveOne` can refuse a wrong length message outright instead of parsing it.
pub const Place = extern struct {
    magic: u32 = request_magic,
    kind: u8 = 0,
    /// Always zero. Without it, compiler padding here would send this process's own memory across the boundary.
    _pad: [3]u8 = @splat(0),
    source_len: u32 = 0,
    /// Never resolved here: this file only bounds its length. Whether it escapes the tree is `driver.zig`'s own question.
    source: [max_path_bytes]u8 = @splat(0),
    target_len: u32 = 0,
    target: [max_path_bytes]u8 = @splat(0),
};

/// No source rides with this: removing a node needs no authority beyond naming which one.
pub const Drop = extern struct {
    magic: u32 = reply_magic,
    path_len: u32 = 0,
    path: [max_path_bytes]u8 = @splat(0),
};

pub const DeviceSeam = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Result = enum {
        done,
        failed,
    };

    pub const VTable = struct {
        place: *const fn (ptr: *anyopaque, kind: u8, source: []const u8, target: []const u8) Result,
        drop: *const fn (ptr: *anyopaque, path: []const u8) Result,
    };

    pub fn place(self: DeviceSeam, kind: u8, source: []const u8, target: []const u8) Result {
        return self.vtable.place(self.ptr, kind, source, target);
    }

    pub fn drop(self: DeviceSeam, path: []const u8) Result {
        return self.vtable.drop(self.ptr, path);
    }
};

pub const Outcome = enum {
    placed,
    /// Carried outward, not absorbed, so a caller can count or log the failure instead of it vanishing silently.
    place_failed,
    dropped,
    drop_failed,
    peer_gone,
    nothing,
};

/// Checks only the shape: a `Place` or `Drop` with our magic and lengths that fit. Whether a path resolves to anything is the seam's own question.
pub fn serveOne(fd: i32, seam: DeviceSeam) Outcome {
    // SOCK_SEQPACKET keeps message boundaries, so a shorter Drop lands whole in a buffer sized for the larger Place.
    var buffer: [@sizeOf(Place)]u8 align(@alignOf(Place)) = undefined;
    var iov = [1]std.posix.iovec{.{ .base = &buffer, .len = buffer.len }};
    var message = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const rc = linux.recvmsg(fd, &message, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .AGAIN, .INTR => return .nothing,
        else => return .peer_gone,
    }
    // Zero is the end of the stream: the far end closed.
    if (rc == 0) return .peer_gone;

    const truncated = (message.flags & linux.MSG.TRUNC) != 0;

    if (rc == @sizeOf(Place) and !truncated) {
        const place: *const Place = @ptrCast(@alignCast(&buffer));
        if (place.magic == request_magic and
            std.mem.allEqual(u8, &place._pad, 0) and
            place.source_len > 0 and place.source_len <= max_path_bytes and
            place.target_len > 0 and place.target_len <= max_path_bytes)
        {
            return switch (seam.place(
                place.kind,
                place.source[0..place.source_len],
                place.target[0..place.target_len],
            )) {
                .done => .placed,
                .failed => .place_failed,
            };
        }
    } else if (rc == @sizeOf(Drop) and !truncated) {
        const drop: *const Drop = @ptrCast(@alignCast(buffer[0..@sizeOf(Drop)]));
        if (drop.magic == reply_magic and drop.path_len > 0 and drop.path_len <= max_path_bytes) {
            return switch (seam.drop(drop.path[0..drop.path_len])) {
                .done => .dropped,
                .failed => .drop_failed,
            };
        }
    }

    return .nothing;
}

pub const SendError = error{
    PathUnusable,
    PeerGone,
};

pub fn sendPlace(fd: i32, kind: u8, source: []const u8, target: []const u8) SendError!void {
    if (source.len == 0 or source.len > max_path_bytes) return error.PathUnusable;
    if (target.len == 0 or target.len > max_path_bytes) return error.PathUnusable;

    var place = Place{ .kind = kind, .source_len = @intCast(source.len), .target_len = @intCast(target.len) };
    @memcpy(place.source[0..source.len], source);
    @memcpy(place.target[0..target.len], target);

    // MSG_NOSIGNAL: a gone peer answers EPIPE here instead of raising SIGPIPE at this whole process.
    const rc = linux.sendto(fd, @ptrCast(&place), @sizeOf(Place), linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(rc) != .SUCCESS or rc != @sizeOf(Place)) return error.PeerGone;
}

pub fn sendDrop(fd: i32, path: []const u8) SendError!void {
    if (path.len == 0 or path.len > max_path_bytes) return error.PathUnusable;

    var drop = Drop{ .path_len = @intCast(path.len) };
    @memcpy(drop.path[0..path.len], path);

    const sent = linux.sendto(fd, @ptrCast(&drop), @sizeOf(Drop), linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(sent) != .SUCCESS or sent != @sizeOf(Drop)) return error.PeerGone;
}

/// Both ends are close-on-exec. The driver clears the child's end last, right before the helper runs, so a sandbox that fails to come up never hands out a channel.
pub fn makePair() error{SocketFailed}![2]i32 {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &fds);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    return fds;
}

const testing = std.testing;

fn linuxOnly() !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
}

const StubSeam = struct {
    places: usize = 0,
    drops: usize = 0,
    place_kind: u8 = 0,
    place_source: [max_path_bytes]u8 = @splat(0),
    place_source_len: usize = 0,
    place_target: [max_path_bytes]u8 = @splat(0),
    place_target_len: usize = 0,
    drop_path: [max_path_bytes]u8 = @splat(0),
    drop_path_len: usize = 0,
    place_result: DeviceSeam.Result = .done,
    drop_result: DeviceSeam.Result = .done,

    fn seam(self: *StubSeam) DeviceSeam {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = DeviceSeam.VTable{ .place = placeFn, .drop = dropFn };

    fn placeFn(ptr: *anyopaque, kind: u8, source: []const u8, target: []const u8) DeviceSeam.Result {
        const self: *StubSeam = @ptrCast(@alignCast(ptr));
        self.places += 1;
        self.place_kind = kind;
        @memcpy(self.place_source[0..source.len], source);
        self.place_source_len = source.len;
        @memcpy(self.place_target[0..target.len], target);
        self.place_target_len = target.len;
        return self.place_result;
    }

    fn dropFn(ptr: *anyopaque, path: []const u8) DeviceSeam.Result {
        const self: *StubSeam = @ptrCast(@alignCast(ptr));
        self.drops += 1;
        @memcpy(self.drop_path[0..path.len], path);
        self.drop_path_len = path.len;
        return self.drop_result;
    }

    fn sawPlaceSource(self: *const StubSeam) []const u8 {
        return self.place_source[0..self.place_source_len];
    }

    fn sawPlaceTarget(self: *const StubSeam) []const u8 {
        return self.place_target[0..self.place_target_len];
    }

    fn sawDropPath(self: *const StubSeam) []const u8 {
        return self.drop_path[0..self.drop_path_len];
    }
};

test "both wire structures are a fixed size with no padding a compiler chose" {
    try testing.expectEqual(
        @as(usize, 4 + 1 + 3 + 4 + max_path_bytes + 4 + max_path_bytes),
        @sizeOf(Place),
    );
    try testing.expectEqual(@as(usize, 4 + 4 + max_path_bytes), @sizeOf(Drop));
    try testing.expect(@sizeOf(Place) != @sizeOf(Drop));
    try testing.expect(request_magic != reply_magic);
}

test "a placement carries a source and a target, and nothing else" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try sendPlace(pair[0], 7, "bus/usb/001/005", "/dev/chock-widget0");

    var stub = StubSeam{};
    try testing.expectEqual(Outcome.placed, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 1), stub.places);
    try testing.expectEqual(@as(usize, 0), stub.drops);
    try testing.expectEqual(@as(u8, 7), stub.place_kind);
    try testing.expectEqualStrings("bus/usb/001/005", stub.sawPlaceSource());
    try testing.expectEqualStrings("/dev/chock-widget0", stub.sawPlaceTarget());
}

test "a removal carries a target and nothing else" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try sendDrop(pair[0], "/dev/chock-widget0");

    var stub = StubSeam{};
    try testing.expectEqual(Outcome.dropped, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 0), stub.places);
    try testing.expectEqual(@as(usize, 1), stub.drops);
    try testing.expectEqualStrings("/dev/chock-widget0", stub.sawDropPath());
}

test "a message of the wrong length is refused outright" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const short = [_]u8{0} ** 8;
    const rc = linux.sendto(pair[0], &short, short.len, linux.MSG.NOSIGNAL, null, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));

    var stub = StubSeam{};
    try testing.expectEqual(Outcome.nothing, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 0), stub.places);
    try testing.expectEqual(@as(usize, 0), stub.drops);

    var oversize: [@sizeOf(Place) + 64]u8 = @splat(0);
    var place = Place{ .source_len = 3, .target_len = 3 };
    @memcpy(place.source[0..3], "abc");
    @memcpy(place.target[0..3], "abc");
    @memcpy(oversize[0..@sizeOf(Place)], std.mem.asBytes(&place));
    const long_rc = linux.sendto(pair[0], &oversize, oversize.len, linux.MSG.NOSIGNAL, null, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(long_rc));
    try testing.expectEqual(Outcome.nothing, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 0), stub.places);
}

test "a seam that cannot place or drop is carried outward, not swallowed" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try sendPlace(pair[0], 1, "bus/usb/001/005", "/dev/chock-widget0");

    var stub = StubSeam{ .place_result = .failed };
    try testing.expectEqual(Outcome.place_failed, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 1), stub.places);

    try sendDrop(pair[0], "/dev/chock-widget0");
    stub.drop_result = .failed;
    try testing.expectEqual(Outcome.drop_failed, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 1), stub.drops);
}

test "a magic that is not ours, a reserved byte, or a path of no length is refused" {
    try linuxOnly();
    const cases = [_]struct { name: []const u8, place: Place }{
        .{ .name = "a magic that is not ours", .place = blk: {
            var one = Place{ .magic = 0xdeadbeef, .source_len = 3, .target_len = 3 };
            @memcpy(one.source[0..3], "abc");
            @memcpy(one.target[0..3], "abc");
            break :blk one;
        } },
        .{ .name = "a reserved byte that is not zero", .place = blk: {
            var one = Place{ .source_len = 3, .target_len = 3, ._pad = .{ 1, 0, 0 } };
            @memcpy(one.source[0..3], "abc");
            @memcpy(one.target[0..3], "abc");
            break :blk one;
        } },
        .{ .name = "a source of no length", .place = Place{ .source_len = 0, .target_len = 3 } },
        .{ .name = "a source longer than the buffer", .place = Place{ .source_len = max_path_bytes + 1, .target_len = 3 } },
        .{ .name = "a target of no length", .place = Place{ .source_len = 3, .target_len = 0 } },
        .{ .name = "a target longer than the buffer", .place = Place{ .source_len = 3, .target_len = max_path_bytes + 1 } },
    };

    var got_through: std.ArrayList(u8) = .empty;
    defer got_through.deinit(testing.allocator);

    for (cases) |case| {
        const pair = try makePair();
        defer _ = linux.close(pair[0]);
        defer _ = linux.close(pair[1]);

        const rc = linux.sendto(pair[0], @ptrCast(&case.place), @sizeOf(Place), linux.MSG.NOSIGNAL, null, 0);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));

        var stub = StubSeam{};
        const outcome = serveOne(pair[1], stub.seam());
        if (outcome != .nothing) {
            try got_through.print(testing.allocator, "{s} answered {t}\n", .{ case.name, outcome });
        }
        if (stub.places + stub.drops != 0) {
            try got_through.print(testing.allocator, "{s} reached the seam\n", .{case.name});
        }
    }

    try testing.expectEqualStrings("", got_through.items);
}

test "the far side is gone once its peer has closed" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[1]);
    _ = linux.close(pair[0]);

    var stub = StubSeam{};
    try testing.expectEqual(Outcome.peer_gone, serveOne(pair[1], stub.seam()));
}

test "sendPlace and sendDrop refuse a path they could not put in a message" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try testing.expectError(error.PathUnusable, sendPlace(pair[0], 0, "", "/dev/chock-widget0"));
    try testing.expectError(error.PathUnusable, sendPlace(pair[0], 0, "a" ** (max_path_bytes + 1), "/dev/chock-widget0"));
    try testing.expectError(error.PathUnusable, sendPlace(pair[0], 0, "bus/usb/001/005", ""));
    try testing.expectError(error.PathUnusable, sendPlace(pair[0], 0, "bus/usb/001/005", "a" ** (max_path_bytes + 1)));
    try testing.expectError(error.PathUnusable, sendDrop(pair[0], ""));
    try testing.expectError(error.PathUnusable, sendDrop(pair[0], "a" ** (max_path_bytes + 1)));
}

test "a channel that has gone answers PeerGone rather than waiting" {
    try linuxOnly();
    const pair = try makePair();
    _ = linux.close(pair[1]);
    defer _ = linux.close(pair[0]);

    try testing.expectError(error.PeerGone, sendPlace(pair[0], 0, "bus/usb/001/005", "/dev/chock-widget0"));
    try testing.expectError(error.PeerGone, sendDrop(pair[0], "/dev/chock-widget0"));
}
