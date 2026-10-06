//! The exchange a filtered network namespace process uses to reach a host: one request out,
//! one connected descriptor back.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const iface = @import("../Sandbox.zig");
const NetBroker = iface.NetBroker;

pub const max_host_bytes: usize = 255;

pub const max_requests: usize = 256;

pub const request_magic: u32 = 0x314E4843;

pub const reply_magic: u32 = 0x31524843;

pub const Request = extern struct {
    magic: u32 = request_magic,
    port: u16,
    host_len: u8,
    reserved: u8 = 0,
    host: [max_host_bytes]u8,
};

pub const Reply = extern struct {
    magic: u32 = reply_magic,
    status: Status,
    reserved: [3]u8 = @splat(0),

    pub const Status = enum(u8) {
        granted = 0,
        refused = 1,
        _,
    };
};

pub const fd_number: i32 = 3;

pub const Answer = union(enum) {
    granted: i32,
    refused,
};

pub const AskError = error{
    HostNameUnusable,
    BrokerGone,
    BrokerProtocol,
};

pub fn ask(fd: i32, host: []const u8, port: u16) AskError!Answer {
    if (host.len == 0 or host.len > max_host_bytes) return error.HostNameUnusable;

    var request = Request{ .port = port, .host_len = @intCast(host.len), .host = @splat(0) };
    @memcpy(request.host[0..host.len], host);

    const sent = linux.sendto(
        fd,
        @ptrCast(&request),
        @sizeOf(Request),
        linux.MSG.NOSIGNAL,
        null,
        0,
    );
    if (linux.errno(sent) != .SUCCESS or sent != @sizeOf(Request)) return error.BrokerGone;

    var reply: Reply = undefined;
    var iov = [1]std.posix.iovec{.{ .base = @ptrCast(&reply), .len = @sizeOf(Reply) }};
    var control: [control_bytes]u8 align(@alignOf(linux.cmsghdr)) = undefined;
    var message = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };

    const rc = linux.recvmsg(fd, &message, linux.MSG.CMSG_CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return error.BrokerGone;
    if (rc == 0) return error.BrokerGone;
    if (rc != @sizeOf(Reply)) return error.BrokerProtocol;
    if (reply.magic != reply_magic) return error.BrokerProtocol;

    const received = firstReceivedFd(&message, &control);

    switch (reply.status) {
        .granted => {
            const handle = received orelse return error.BrokerProtocol;
            return .{ .granted = handle };
        },
        .refused => {
            if (received) |handle| _ = linux.close(handle);
            return .refused;
        },
        _ => {
            if (received) |handle| _ = linux.close(handle);
            return error.BrokerProtocol;
        },
    }
}

pub const Outcome = enum {
    served,
    peer_gone,
    nothing,
};

pub fn serveOne(fd: i32, broker: NetBroker) Outcome {
    var request: Request = undefined;
    var iov = [1]std.posix.iovec{.{ .base = @ptrCast(&request), .len = @sizeOf(Request) }};
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
    if (rc == 0) return .peer_gone;
    if (rc != @sizeOf(Request)) return refuse(fd);
    if ((message.flags & linux.MSG.TRUNC) != 0) return refuse(fd);
    if (request.magic != request_magic) return refuse(fd);
    if (request.port == 0) return refuse(fd);
    if (request.host_len == 0 or request.host_len > max_host_bytes) return refuse(fd);

    const host = request.host[0..request.host_len];
    if (!hostBytesAreUsable(host)) return refuse(fd);

    switch (broker.connect(host, request.port)) {
        .refused => return refuse(fd),
        .granted => |handle| {
            defer _ = linux.close(handle);
            return grant(fd, handle);
        },
    }
}

pub fn hostBytesAreUsable(host: []const u8) bool {
    if (host.len == 0 or host.len > max_host_bytes) return false;
    if (host[0] == '.' or host[host.len - 1] == '.') return false;

    var label: usize = 0;
    for (host) |byte| {
        if (byte == '.') {
            if (label == 0) return false;
            label = 0;
            continue;
        }
        const ok = (byte >= 'a' and byte <= 'z') or
            (byte >= 'A' and byte <= 'Z') or
            (byte >= '0' and byte <= '9') or
            byte == '-';
        if (!ok) return false;
        label += 1;
        if (label > 63) return false;
    }
    return label != 0;
}

fn refuse(fd: i32) Outcome {
    var reply = Reply{ .status = .refused };
    var iov = [1]std.posix.iovec_const{.{ .base = @ptrCast(&reply), .len = @sizeOf(Reply) }};
    var message = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    const rc = linux.sendmsg(fd, &message, linux.MSG.NOSIGNAL);
    if (linux.errno(rc) != .SUCCESS) return .peer_gone;
    return .served;
}

fn grant(fd: i32, handle: i32) Outcome {
    var reply = Reply{ .status = .granted };
    var iov = [1]std.posix.iovec_const{.{ .base = @ptrCast(&reply), .len = @sizeOf(Reply) }};

    var control: [control_bytes]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const header: *linux.cmsghdr = @ptrCast(@alignCast(&control));
    header.* = .{
        .len = cmsg_len,
        .level = linux.SOL.SOCKET,
        .type = linux.SCM.RIGHTS,
    };
    @memcpy(control[cmsg_data_offset..][0..@sizeOf(i32)], std.mem.asBytes(&handle));

    var message = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    const rc = linux.sendmsg(fd, &message, linux.MSG.NOSIGNAL);
    if (linux.errno(rc) != .SUCCESS) return .peer_gone;
    return .served;
}

pub fn cmsgAlign(len: usize) usize {
    const width: usize = @sizeOf(usize);
    return (len + width - 1) & ~(width - 1);
}

pub const cmsg_data_offset: usize = cmsgAlign(@sizeOf(linux.cmsghdr));

pub const cmsg_len: usize = cmsg_data_offset + @sizeOf(i32);

pub const control_bytes: usize = cmsg_data_offset + cmsgAlign(@sizeOf(i32));

pub fn firstReceivedFd(message: *const linux.msghdr, control: []align(@alignOf(linux.cmsghdr)) const u8) ?i32 {
    if (message.controllen < cmsg_len) return null;
    if ((message.flags & linux.MSG.CTRUNC) != 0) return null;

    const header: *const linux.cmsghdr = @ptrCast(@alignCast(control.ptr));
    if (header.level != linux.SOL.SOCKET or header.type != linux.SCM.RIGHTS) return null;
    if (header.len < cmsg_len or header.len > message.controllen) return null;

    const payload = header.len - cmsg_data_offset;
    const count = payload / @sizeOf(i32);
    if (count == 0) return null;

    var first: i32 = undefined;
    @memcpy(std.mem.asBytes(&first), control[cmsg_data_offset..][0..@sizeOf(i32)]);
    var index: usize = 1;
    while (index < count) : (index += 1) {
        var extra: i32 = undefined;
        @memcpy(std.mem.asBytes(&extra), control[cmsg_data_offset + index * @sizeOf(i32) ..][0..@sizeOf(i32)]);
        _ = linux.close(extra);
    }
    return first;
}

pub fn makePair() error{SocketFailed}![2]i32 {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(
        linux.AF.UNIX,
        linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC,
        0,
        &fds,
    );
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    return fds;
}

const testing = std.testing;

const StubBroker = struct {
    host: []const u8,
    port: u16,
    give: i32,
    seen_host: [max_host_bytes]u8 = @splat(0),
    seen_host_len: usize = 0,
    seen_port: u16 = 0,
    asks: usize = 0,

    fn broker(self: *StubBroker) NetBroker {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = NetBroker.VTable{ .connect = connectFn };

    fn connectFn(ptr: *anyopaque, host: []const u8, port: u16) NetBroker.Grant {
        const self: *StubBroker = @ptrCast(@alignCast(ptr));
        self.asks += 1;
        @memcpy(self.seen_host[0..host.len], host);
        self.seen_host_len = host.len;
        self.seen_port = port;
        if (!std.mem.eql(u8, host, self.host) or port != self.port) return .refused;
        const rc = linux.dup(self.give);
        if (linux.errno(rc) != .SUCCESS) return .refused;
        return .{ .granted = @intCast(rc) };
    }

    fn sawHost(self: *const StubBroker) []const u8 {
        return self.seen_host[0..self.seen_host_len];
    }
};

const ReadReply = struct {
    reply: Reply,
    handle: ?i32,
    bytes: usize,
};

fn readReply(fd: i32) !ReadReply {
    var reply: Reply = undefined;
    var iov = [1]std.posix.iovec{.{ .base = @ptrCast(&reply), .len = @sizeOf(Reply) }};
    var control: [control_bytes]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    var message = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    const rc = linux.recvmsg(fd, &message, linux.MSG.CMSG_CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return error.NothingArrived;
    return .{ .reply = reply, .handle = firstReceivedFd(&message, &control), .bytes = rc };
}

fn sendRequest(fd: i32, host: []const u8, port: u16) !void {
    var request = Request{ .port = port, .host_len = @intCast(host.len), .host = @splat(0) };
    @memcpy(request.host[0..host.len], host);
    const written = linux.write(fd, @ptrCast(&request), @sizeOf(Request));
    try testing.expectEqual(@as(usize, @sizeOf(Request)), written);
}

fn upstreamPair() ![2]i32 {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds);
    if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    return fds;
}

test "a granted descriptor really carries the connection, and the reply names no address" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const upstream = try upstreamPair();
    defer _ = linux.close(upstream[0]);
    defer _ = linux.close(upstream[1]);

    var stub = StubBroker{ .host = "api.example.com", .port = 443, .give = upstream[1] };

    try sendRequest(pair[1], "api.example.com", 443);
    try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.broker()));

    try testing.expectEqualStrings("api.example.com", stub.sawHost());
    try testing.expectEqual(@as(u16, 443), stub.seen_port);

    var got = try readReply(pair[1]);
    try testing.expectEqual(@as(usize, @sizeOf(Reply)), got.bytes);
    try testing.expectEqual(Reply.Status.granted, got.reply.status);
    const handle = got.handle orelse return error.NoDescriptorArrived;
    defer _ = linux.close(handle);

    const token = "the-far-end-connected-this";
    _ = linux.write(upstream[0], token, token.len);
    var buffer: [64]u8 = undefined;
    const read = linux.read(handle, &buffer, buffer.len);
    try testing.expectEqualStrings(token, buffer[0..read]);

    try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, &got.reply.reserved);
}

test "a refusal carries no descriptor and no reason at all" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const upstream = try upstreamPair();
    defer _ = linux.close(upstream[0]);
    defer _ = linux.close(upstream[1]);

    var stub = StubBroker{ .host = "api.example.com", .port = 443, .give = upstream[1] };

    try sendRequest(pair[1], "evil.example.net", 443);
    try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.broker()));

    var refused_by_policy = try readReply(pair[1]);
    try testing.expectEqual(Reply.Status.refused, refused_by_policy.reply.status);
    try testing.expect(refused_by_policy.handle == null);

    var not_a_name = Request{ .port = 443, .host_len = 16, .host = fill("a..b.example.com") };
    _ = linux.write(pair[1], @ptrCast(&not_a_name), @sizeOf(Request));
    try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.broker()));
    var refused_by_shape = try readReply(pair[1]);
    try testing.expect(refused_by_shape.handle == null);
    try testing.expectEqualSlices(
        u8,
        std.mem.asBytes(&refused_by_policy.reply),
        std.mem.asBytes(&refused_by_shape.reply),
    );
    try testing.expectEqual(@as(usize, 1), stub.asks);
}

test "a request that is not a request is refused, and the far end never asks about it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const upstream = try upstreamPair();
    defer _ = linux.close(upstream[0]);
    defer _ = linux.close(upstream[1]);
    var stub = StubBroker{ .host = "api.example.com", .port = 443, .give = upstream[1] };

    const bad = [_]Request{
        .{ .magic = 0, .port = 443, .host_len = 15, .host = fill("api.example.com") },
        .{ .port = 0, .host_len = 15, .host = fill("api.example.com") },
        .{ .port = 443, .host_len = 0, .host = @splat(0) },
        .{ .port = 443, .host_len = 15, .host = fill("api example.com") },
        .{ .port = 443, .host_len = 15, .host = fill("api/example.com") },
        .{ .port = 443, .host_len = 15, .host = fill("api*example.com") },
        .{ .port = 443, .host_len = 15, .host = fill("api\x00example.com") },
        .{ .port = 443, .host_len = 16, .host = fill("api..example.com") },
        .{ .port = 443, .host_len = 16, .host = fill(".api.example.com") },
        .{ .port = 443, .host_len = 16, .host = fill("api.example.com.") },
    };

    for (bad) |request| {
        var one = request;
        const written = linux.write(pair[1], @ptrCast(&one), @sizeOf(Request));
        try testing.expectEqual(@as(usize, @sizeOf(Request)), written);
        try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.broker()));

        const got = try readReply(pair[1]);
        try testing.expectEqual(Reply.Status.refused, got.reply.status);
        try testing.expect(got.handle == null);
    }
    try testing.expectEqual(@as(usize, 0), stub.asks);

    try sendRequest(pair[1], "api.example.com", 443);
    try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.broker()));
    try testing.expectEqual(@as(usize, 1), stub.asks);
    const good = try readReply(pair[1]);
    try testing.expectEqual(Reply.Status.granted, good.reply.status);
    if (good.handle) |handle| _ = linux.close(handle);
}

test "a message that is not one whole request is refused, whatever its length" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const upstream = try upstreamPair();
    defer _ = linux.close(upstream[0]);
    defer _ = linux.close(upstream[1]);
    var stub = StubBroker{ .host = "api.example.com", .port = 443, .give = upstream[1] };

    var request = Request{ .port = 443, .host_len = 15, .host = fill("api.example.com") };
    const bytes = std.mem.asBytes(&request);
    for ([_]usize{ 1, 7, @sizeOf(Request) - 1 }) |length| {
        _ = linux.write(pair[1], bytes.ptr, length);
        try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.broker()));
        const got = try readReply(pair[1]);
        try testing.expectEqual(Reply.Status.refused, got.reply.status);
    }

    var oversize: [@sizeOf(Request) + 64]u8 = @splat(0);
    @memcpy(oversize[0..@sizeOf(Request)], bytes);
    _ = linux.write(pair[1], &oversize, oversize.len);
    try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.broker()));
    const long = try readReply(pair[1]);
    try testing.expectEqual(Reply.Status.refused, long.reply.status);

    try testing.expectEqual(@as(usize, 0), stub.asks);
}

test "a descriptor a sandboxed process sends across is never received" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const upstream = try upstreamPair();
    defer _ = linux.close(upstream[0]);
    defer _ = linux.close(upstream[1]);
    var stub = StubBroker{ .host = "api.example.com", .port = 443, .give = upstream[1] };

    const before = openDescriptorCount();

    var request = Request{ .port = 443, .host_len = 15, .host = fill("api.example.com") };
    var iov = [1]std.posix.iovec_const{.{ .base = @ptrCast(&request), .len = @sizeOf(Request) }};
    var control: [control_bytes]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const header: *linux.cmsghdr = @ptrCast(@alignCast(&control));
    header.* = .{ .len = cmsg_len, .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS };
    @memcpy(control[cmsg_data_offset..][0..@sizeOf(i32)], std.mem.asBytes(&upstream[0]));
    var message = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.sendmsg(pair[1], &message, 0)));

    try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.broker()));
    try testing.expectEqual(@as(usize, 1), stub.asks);
    const got = try readReply(pair[1]);
    try testing.expectEqual(Reply.Status.granted, got.reply.status);
    if (got.handle) |handle| _ = linux.close(handle);

    try testing.expectEqual(before, openDescriptorCount());
}

fn openDescriptorCount() usize {
    const rc = linux.open("/proc/self/fd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return 0;
    const dir: i32 = @intCast(rc);
    defer _ = linux.close(dir);

    var count: usize = 0;
    var buffer: [4096]u8 = undefined;
    while (true) {
        const nread = linux.getdents64(dir, &buffer, buffer.len);
        if (linux.errno(nread) != .SUCCESS or nread == 0) break;
        var offset: usize = 0;
        while (offset < nread) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            count += 1;
            offset += entry.reclen;
        }
    }
    return count;
}

fn fill(comptime text: []const u8) [max_host_bytes]u8 {
    var out: [max_host_bytes]u8 = @splat(0);
    @memcpy(out[0..text.len], text);
    return out;
}

test "a name that is a name is accepted, and every shape rule is a rule that refuses something" {
    try testing.expect(hostBytesAreUsable("api.anthropic.com"));
    try testing.expect(hostBytesAreUsable("localhost"));
    try testing.expect(hostBytesAreUsable("a-b.example-1.co.uk"));
    try testing.expect(hostBytesAreUsable("1.2.3.4"));
    try testing.expect(hostBytesAreUsable("a" ** 63 ++ ".com"));

    try testing.expect(!hostBytesAreUsable(""));
    try testing.expect(!hostBytesAreUsable("."));
    try testing.expect(!hostBytesAreUsable(".com"));
    try testing.expect(!hostBytesAreUsable("com."));
    try testing.expect(!hostBytesAreUsable("a..com"));
    try testing.expect(!hostBytesAreUsable("a" ** 64 ++ ".com"));
    try testing.expect(!hostBytesAreUsable("a" ** 256));
    try testing.expect(!hostBytesAreUsable("a_b.com"));
    try testing.expect(!hostBytesAreUsable("a b.com"));
    try testing.expect(!hostBytesAreUsable("a\x00b.com"));
    try testing.expect(!hostBytesAreUsable("a*b.com"));
    try testing.expect(!hostBytesAreUsable("http://a.com"));
}

test "the wire structures have the size and the layout the kernel is given" {
    try testing.expectEqual(@as(usize, 264), @sizeOf(Request));
    try testing.expectEqual(@as(usize, 8), @sizeOf(Reply));
    try testing.expectEqual(@as(usize, 16), cmsg_data_offset);
    try testing.expectEqual(@as(usize, 20), cmsg_len);
    try testing.expectEqual(@as(usize, 24), control_bytes);
}

test "a far end that has gone answers BrokerGone rather than waiting" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const pair = try makePair();
    _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try testing.expectError(error.BrokerGone, ask(pair[1], "api.example.com", 443));
}

test "ask refuses a name it could not put in a request" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try testing.expectError(error.HostNameUnusable, ask(pair[1], "", 443));
    try testing.expectError(error.HostNameUnusable, ask(pair[1], "a" ** 256, 443));
}
