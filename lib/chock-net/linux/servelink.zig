//! The one channel that carries an inbound connection into the sandbox. The
//! host accepts a connection on a port the project published, writes the port
//! down this channel with the accepted descriptor attached, and the helper on
//! the other end dials the server the agent runs and relays between the two.
//!
//! The router cannot do this work: `roles.router_calls` refuses it `socket` and
//! `connect`, so that it can reach nothing it was not handed. The helper here
//! may dial, and only inside the sandbox's own namespace, where the one thing
//! listening is the agent's own server.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

const netbroker = @import("netbroker.zig");
const router = @import("router.zig");

pub const request_magic: u32 = 0x31565243;

pub const max_requests: usize = 4096;

/// A port and nothing else. The address is never named: the helper dials
/// loopback inside the sandbox, which is the only place it can reach.
pub const Request = extern struct {
    magic: u32 = request_magic,
    port: u16,
    reserved: u16 = 0,
};

pub const Taken = struct {
    port: u16,
    handle: posix.fd_t,
};

pub const SendError = error{ChannelGone};

/// Hands one accepted connection to the helper. The caller keeps its own copy
/// of `handle` and closes it: a descriptor sent this way is duplicated.
pub fn send(channel_fd: posix.fd_t, port: u16, handle: posix.fd_t) SendError!void {
    std.debug.assert(port != 0);
    var request = Request{ .port = port };
    var iov = [1]posix.iovec_const{.{ .base = @ptrCast(&request), .len = @sizeOf(Request) }};

    var control: [netbroker.control_bytes]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const header: *linux.cmsghdr = @ptrCast(&control);
    header.* = .{
        .len = netbroker.cmsg_len,
        .level = linux.SOL.SOCKET,
        .type = 0x01, // SCM_RIGHTS
    };
    @memcpy(control[netbroker.cmsg_data_offset..][0..@sizeOf(i32)], std.mem.asBytes(&handle));

    const message = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = netbroker.control_bytes,
        .flags = 0,
    };

    const rc = linux.sendmsg(channel_fd, &message, linux.MSG.NOSIGNAL);
    if (linux.errno(rc) != .SUCCESS or rc != @sizeOf(Request)) return error.ChannelGone;
}

pub const Outcome = union(enum) {
    took: Taken,
    nothing,
    peer_gone,
};

/// One message, or why there is none. A message the reader cannot use closes
/// the descriptor that came with it rather than leaking it into the helper.
pub fn receive(channel_fd: posix.fd_t) Outcome {
    var request: Request = undefined;
    var iov = [1]posix.iovec{.{ .base = @ptrCast(&request), .len = @sizeOf(Request) }};
    var control: [netbroker.control_bytes]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    var message = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = netbroker.control_bytes,
        .flags = 0,
    };

    const rc = linux.recvmsg(channel_fd, &message, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .AGAIN, .INTR => return .nothing,
        else => return .peer_gone,
    }
    if (rc == 0) return .peer_gone;

    const handle = netbroker.firstReceivedFd(&message, &control);
    if (rc != @sizeOf(Request) or request.magic != request_magic or request.port == 0) {
        if (handle) |one| _ = linux.close(one);
        return .nothing;
    }
    const taken = handle orelse return .nothing;
    return .{ .took = .{ .port = request.port, .handle = taken } };
}

pub const Counts = struct {
    taken: u64 = 0,
    dialled: u64 = 0,
    waited: u64 = 0,
    without_server: u64 = 0,
    without_link: u64 = 0,
};

/// A server the agent just started is still binding when the first connection
/// arrives, which is the everyday case: the agent says where the page is and a
/// person opens it at once. A connection waits this long for the port to answer
/// before it is closed, which a browser reads as a connection that went away.
pub const dial_budget_ms: i64 = 5000;

/// A connection waiting for the server to come up. It is already accepted on
/// the host, so the person's browser is holding it open.
const Waiting = struct {
    port: u16,
    handle: posix.fd_t = -1,
    until_ms: i64 = 0,
};

/// The helper's side. Owns the relay and nothing else: every connection it
/// carries arrives as a descriptor, and the only one it opens itself is to a
/// port inside this namespace.
pub const Server = struct {
    channel_fd: posix.fd_t,
    waiting: [router.max_links]?Waiting = @splat(null),
    relay: router.Router = .{
        .relay_fd = -1,
        .resolver_fd = -1,
        .policy = undefined,
        .host = undefined,
        .allow_timeout_ms = 0,
        .answer_ttl_s = 0,
        .names = .{},
        .links = @splat(.{}),
        .counts = .{},
    },
    counts: Counts = .{},
    peer_gone: bool = false,
    /// The time `step` was last called with, so `take` dates what it parks
    /// without reading a clock of its own.
    now_ms: i64 = 0,

    /// Takes everything the host has handed over, then moves the bytes already
    /// in flight. The channel is read first, so a connection waits no longer
    /// than one step before it is dialled.
    pub fn step(self: *Server, now_ms: i64, timeout_ms: i32) router.Error!void {
        self.now_ms = now_ms;
        self.take();
        self.retry(now_ms);
        try self.relay.step(now_ms, timeout_ms, null);
    }

    /// Anything still waiting for its server. A port that answers now is
    /// relayed, and one past its budget is closed, which the browser reads as
    /// a connection that went away.
    fn retry(self: *Server, now_ms: i64) void {
        for (&self.waiting) |*slot| {
            const held = slot.* orelse continue;
            if (dial(held.port)) |inside| {
                slot.* = null;
                self.link(inside, held.handle);
                continue;
            }
            if (now_ms < held.until_ms) continue;
            slot.* = null;
            self.counts.without_server += 1;
            _ = linux.close(held.handle);
        }
    }

    /// True when something is still waiting, so a caller can keep stepping
    /// rather than leave a connection unanswered.
    pub fn stillWaiting(self: *const Server) bool {
        for (self.waiting) |slot| {
            if (slot != null) return true;
        }
        return false;
    }

    fn take(self: *Server) void {
        for (0..router.max_links) |_| {
            switch (receive(self.channel_fd)) {
                .nothing => return,
                .peer_gone => {
                    self.peer_gone = true;
                    return;
                },
                .took => |one| {
                    self.counts.taken += 1;
                    self.carry(one, self.now_ms);
                },
            }
        }
    }

    fn carry(self: *Server, one: Taken, now_ms: i64) void {
        if (dial(one.port)) |inside| {
            self.link(inside, one.handle);
            return;
        }
        if (self.park(one, now_ms)) return;
        self.counts.without_server += 1;
        _ = linux.close(one.handle);
    }

    fn link(self: *Server, inside: posix.fd_t, outside: posix.fd_t) void {
        if (!self.relay.adopt(inside, outside)) {
            self.counts.without_link += 1;
            _ = linux.close(inside);
            _ = linux.close(outside);
            return;
        }
        self.counts.dialled += 1;
    }

    fn park(self: *Server, one: Taken, now_ms: i64) bool {
        for (&self.waiting) |*slot| {
            if (slot.* != null) continue;
            slot.* = .{
                .port = one.port,
                .handle = one.handle,
                .until_ms = now_ms + dial_budget_ms,
            };
            self.counts.waited += 1;
            return true;
        }
        return false;
    }
};

/// Loopback inside this namespace, and a blocking connect: nothing is between
/// the two ends, so it answers at once or not at all.
fn dial(port: u16) ?posix.fd_t {
    const made = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(made) != .SUCCESS) return null;
    const fd: posix.fd_t = @intCast(made);

    var address = linux.sockaddr.in{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
        .zero = @splat(0),
    };
    const connected = linux.connect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in));
    if (linux.errno(connected) != .SUCCESS) {
        _ = linux.close(fd);
        return null;
    }
    return fd;
}

const testing = std.testing;

fn listenOnLoopback() !struct { fd: posix.fd_t, port: u16 } {
    const made = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(made) != .SUCCESS) return error.SocketFailed;
    const fd: posix.fd_t = @intCast(made);

    var address = linux.sockaddr.in{
        .family = linux.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
        .zero = @splat(0),
    };
    if (linux.errno(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        _ = linux.close(fd);
        return error.BindFailed;
    }
    if (linux.errno(linux.listen(fd, 8)) != .SUCCESS) {
        _ = linux.close(fd);
        return error.ListenFailed;
    }

    var named: linux.sockaddr.in = undefined;
    var length: posix.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.errno(linux.getsockname(fd, @ptrCast(&named), &length)) != .SUCCESS) {
        _ = linux.close(fd);
        return error.NameFailed;
    }
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, named.port) };
}

/// A listener on one named port, which is what a server inside the sandbox
/// does and what `listenOnLoopback` cannot do: that one takes whatever the
/// kernel hands out.
fn listenOnPort(port: u16) !posix.fd_t {
    const made = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(made) != .SUCCESS) return error.SocketFailed;
    const fd: posix.fd_t = @intCast(made);
    errdefer _ = linux.close(fd);

    var one: u32 = 1;
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&one), @sizeOf(u32));

    var address = linux.sockaddr.in{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
        .zero = @splat(0),
    };
    if (linux.errno(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        return error.BindFailed;
    }
    if (linux.errno(linux.listen(fd, 8)) != .SUCCESS) return error.ListenFailed;
    return fd;
}

fn channelPair() ![2]i32 {
    var pair: [2]i32 = undefined;
    const made = linux.socketpair(
        linux.AF.UNIX,
        linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC,
        0,
        &pair,
    );
    if (linux.errno(made) != .SUCCESS) return error.SocketFailed;
    return pair;
}

fn readWithin(server: *Server, fd: posix.fd_t, into: []u8) !usize {
    for (0..100) |_| {
        const rc = linux.read(fd, into.ptr, into.len);
        if (linux.errno(rc) == .SUCCESS and rc != 0) return rc;
        try server.step(0, 10);
    }
    return error.NothingRelayed;
}

test "a connection the host accepted reaches a server inside, and the answer goes back" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const inside = try listenOnLoopback();
    defer _ = linux.close(inside.fd);

    const channel = try channelPair();
    defer _ = linux.close(channel[0]);
    defer _ = linux.close(channel[1]);

    // The host's end of a connection it accepted. A socketpair stands for it:
    // what matters here is that it is a descriptor the helper never opened.
    const outside = try channelPair();
    defer _ = linux.close(outside[0]);

    var server = Server{ .channel_fd = channel[1] };
    try send(channel[0], inside.port, outside[1]);
    _ = linux.close(outside[1]);

    try server.step(0, 10);
    try testing.expectEqual(@as(u64, 1), server.counts.taken);
    try testing.expectEqual(@as(u64, 1), server.counts.dialled);
    try testing.expectEqual(@as(u64, 0), server.counts.without_server);

    const served = linux.accept4(inside.fd, null, null, linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(served));
    const served_fd: posix.fd_t = @intCast(served);
    defer _ = linux.close(served_fd);

    var heard: [64]u8 = undefined;
    const asked = "GET /index.html HTTP/1.1\r\n\r\n";
    try testing.expectEqual(asked.len, linux.write(outside[0], asked.ptr, asked.len));
    try testing.expectEqual(asked.len, try readWithin(&server, served_fd, &heard));
    try testing.expectEqualStrings(asked, heard[0..asked.len]);

    const answered = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi";
    try testing.expectEqual(answered.len, linux.write(served_fd, answered.ptr, answered.len));
    try testing.expectEqual(answered.len, try readWithin(&server, outside[0], &heard));
    try testing.expectEqualStrings(answered, heard[0..answered.len]);
}

test "a port nothing listens on yet is waited for, and then closed" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // Bound, read, then closed: the port is one nothing can be listening on.
    const closed = try listenOnLoopback();
    _ = linux.close(closed.fd);

    const channel = try channelPair();
    defer _ = linux.close(channel[0]);
    defer _ = linux.close(channel[1]);
    const outside = try channelPair();
    defer _ = linux.close(outside[0]);

    var server = Server{ .channel_fd = channel[1] };
    try send(channel[0], closed.port, outside[1]);
    _ = linux.close(outside[1]);

    // A server that is still binding is the everyday case, so the connection
    // is held rather than refused.
    try server.step(0, 10);
    try testing.expectEqual(@as(u64, 1), server.counts.taken);
    try testing.expectEqual(@as(u64, 1), server.counts.waited);
    try testing.expectEqual(@as(u64, 0), server.counts.dialled);
    try testing.expectEqual(@as(u64, 0), server.counts.without_server);
    try testing.expect(server.stillWaiting());

    // Past the budget it is closed, and the helper is still running.
    try server.step(dial_budget_ms, 10);
    try testing.expectEqual(@as(u64, 1), server.counts.without_server);
    try testing.expect(!server.stillWaiting());
    try testing.expect(!server.peer_gone);

    // The host sees the connection end rather than hanging on a server that is
    // not there.
    var heard: [8]u8 = undefined;
    for (0..50) |_| {
        const rc = linux.read(outside[0], &heard, heard.len);
        if (linux.errno(rc) == .SUCCESS and rc == 0) return;
        try server.step(dial_budget_ms, 10);
    }
    return error.ConnectionHeldOpen;
}

test "a connection that arrives before the server does is relayed once it answers" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // The port is free when the connection is handed over, and a server binds
    // it afterwards. This is the order a session really has: the agent starts
    // the server, says where it is, and a person opens the page at once.
    const chosen = try listenOnLoopback();
    const port = chosen.port;
    _ = linux.close(chosen.fd);

    const channel = try channelPair();
    defer _ = linux.close(channel[0]);
    defer _ = linux.close(channel[1]);
    const outside = try channelPair();
    defer _ = linux.close(outside[0]);

    var server = Server{ .channel_fd = channel[1] };
    try send(channel[0], port, outside[1]);
    _ = linux.close(outside[1]);

    try server.step(0, 10);
    try testing.expect(server.stillWaiting());

    const inside = try listenOnPort(port);
    defer _ = linux.close(inside);

    try server.step(1, 10);
    try testing.expect(!server.stillWaiting());
    try testing.expectEqual(@as(u64, 1), server.counts.dialled);

    const served = linux.accept4(inside, null, null, linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(served));
    const served_fd: posix.fd_t = @intCast(served);
    defer _ = linux.close(served_fd);

    var heard: [64]u8 = undefined;
    const answered = "it was waiting";
    try testing.expectEqual(answered.len, linux.write(served_fd, answered.ptr, answered.len));
    try testing.expectEqual(answered.len, try readWithin(&server, outside[0], &heard));
    try testing.expectEqualStrings(answered, heard[0..answered.len]);
}

test "a message this reader cannot use is dropped with its descriptor, and the channel goes on" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const channel = try channelPair();
    defer _ = linux.close(channel[0]);
    defer _ = linux.close(channel[1]);

    var wrong = Request{ .magic = 0, .port = 80 };
    var iov = [1]posix.iovec_const{.{ .base = @ptrCast(&wrong), .len = @sizeOf(Request) }};
    const message = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    try testing.expectEqual(
        @sizeOf(Request),
        linux.sendmsg(channel[0], &message, linux.MSG.NOSIGNAL),
    );

    var server = Server{ .channel_fd = channel[1] };
    try server.step(0, 10);
    try testing.expectEqual(@as(u64, 0), server.counts.taken);
    try testing.expect(!server.peer_gone);

    // A port of zero names nothing, so it is not a request either.
    const outside = try channelPair();
    defer _ = linux.close(outside[0]);
    defer _ = linux.close(outside[1]);
    var zero = Request{ .port = 0 };
    var zero_iov = [1]posix.iovec_const{.{ .base = @ptrCast(&zero), .len = @sizeOf(Request) }};
    const zero_message = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &zero_iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    _ = linux.sendmsg(channel[0], &zero_message, linux.MSG.NOSIGNAL);
    try server.step(0, 10);
    try testing.expectEqual(@as(u64, 0), server.counts.taken);
}

test "a host that has gone is noticed, and the helper stops asking" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const channel = try channelPair();
    defer _ = linux.close(channel[1]);
    _ = linux.close(channel[0]);

    var server = Server{ .channel_fd = channel[1] };
    try server.step(0, 10);
    try testing.expect(server.peer_gone);
}
