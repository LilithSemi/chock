//! The one channel between the network router and the process outside the sandbox: resolve a
//! name, or open a connection to an address the router already allowed.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const iface = @import("../Sandbox.zig");
const NetRouter = iface.NetRouter;
const NetBroker = iface.NetBroker;

const router = @import("router.zig");
const nftables = @import("nftables.zig");
const netbroker = @import("netbroker.zig");

pub const max_host_bytes: usize = netbroker.max_host_bytes;

comptime {
    if (router.name_capacity != max_host_bytes) @compileError(
        "routerlink: a name the resolver can parse must fit in one request. See max_host_bytes.",
    );
}

pub const fd_number: i32 = 3;

pub const max_requests: usize = 4096;

pub const request_magic: u32 = 0x31515243;

pub const reply_magic: u32 = 0x31525243;

pub const Kind = enum(u8) {
    resolve = 0,
    open = 1,
    _,
};

pub const Family = enum(u8) {
    ipv4 = 0,
    ipv6 = 1,
    _,

    pub fn ofAddress(address: NetRouter.Address) Family {
        return switch (address) {
            .ipv4 => .ipv4,
            .ipv6 => .ipv6,
        };
    }

    pub fn seam(self: Family) ?NetRouter.Family {
        return switch (self) {
            .ipv4 => .ipv4,
            .ipv6 => .ipv6,
            _ => null,
        };
    }
};

pub const Request = extern struct {
    magic: u32 = request_magic,
    kind: Kind,
    family: Family,
    host_len: u8,
    reserved: u8 = 0,
    port: u16,
    reserved2: u16 = 0,
    address: [16]u8 = @splat(0),
    host: [max_host_bytes]u8 = @splat(0),
};

pub const Reply = extern struct {
    magic: u32 = reply_magic,
    status: Status,
    family: Family = .ipv4,
    reserved: [2]u8 = @splat(0),
    address: [16]u8 = @splat(0),

    pub const Status = enum(u8) {
        granted = 0,
        refused = 1,
        unresolved = 2,
        _,
    };
};

pub const Client = struct {
    fd: i32,
    session: nftables.Session,
    held: ?Held = null,

    const Held = struct {
        name: [max_host_bytes]u8,
        name_len: usize,
        kind: router.RecordKind,
        reply: Reply,

        fn isAbout(self: *const Held, name: []const u8, kind: router.RecordKind) bool {
            return self.kind == kind and std.mem.eql(u8, self.name[0..self.name_len], name);
        }
    };

    pub fn policy(self: *Client) router.Policy {
        return .{ .ptr = self, .vtable = &policy_vtable };
    }

    pub fn host(self: *Client) router.Host {
        return .{ .ptr = self, .vtable = &host_vtable };
    }

    const policy_vtable = router.Policy.VTable{ .name = nameFn, .connect = connectFn };
    const host_vtable = router.Host.VTable{
        .resolve = resolveFn,
        .allow = allowFn,
        .open = openFn,
    };

    fn nameFn(ptr: *anyopaque, name: []const u8, kind: router.RecordKind) router.Policy.Verdict {
        const self: *Client = @ptrCast(@alignCast(ptr));
        self.held = null;
        if (name.len == 0 or name.len > max_host_bytes) return .refuse;

        var request = Request{
            .kind = .resolve,
            .family = switch (kind.family()) {
                .ipv4 => .ipv4,
                .ipv6 => .ipv6,
            },
            .host_len = @intCast(name.len),
            .port = 0,
        };
        @memcpy(request.host[0..name.len], name);

        const reply = exchange(self.fd, &request, null) orelse return .refuse;
        var held = Held{
            .name = @splat(0),
            .name_len = name.len,
            .kind = kind,
            .reply = reply,
        };
        @memcpy(held.name[0..name.len], name);
        self.held = held;

        return switch (reply.status) {
            .granted, .unresolved => .permit,
            .refused, _ => .refuse,
        };
    }

    fn connectFn(
        ptr: *anyopaque,
        name: ?[]const u8,
        dest: router.Destination,
    ) router.Policy.Verdict {
        _ = ptr;
        _ = dest;
        return if (name == null) .refuse else .permit;
    }

    fn resolveFn(
        ptr: *anyopaque,
        name: []const u8,
        kind: router.RecordKind,
    ) router.Host.ResolveError!nftables.Address {
        const self: *Client = @ptrCast(@alignCast(ptr));
        const held = self.held orelse return error.NotResolved;
        if (!held.isAbout(name, kind)) return error.NotResolved;
        self.held = null;
        if (held.reply.status != .granted) return error.NotResolved;
        return addressOf(held.reply.family, held.reply.address, kind) orelse error.NotResolved;
    }

    fn allowFn(
        ptr: *anyopaque,
        address: nftables.Address,
        timeout_ms: u64,
    ) router.Host.AllowError!void {
        const self: *Client = @ptrCast(@alignCast(ptr));
        self.session.allow(address, timeout_ms, null) catch return error.NotAllowed;
    }

    fn openFn(ptr: *anyopaque, dest: router.Destination) router.Host.OpenError!i32 {
        const self: *Client = @ptrCast(@alignCast(ptr));
        var request = Request{
            .kind = .open,
            .family = Family.ofAddress(dest.address),
            .host_len = 0,
            .port = dest.port,
        };
        switch (dest.address) {
            .ipv4 => |bytes| @memcpy(request.address[0..4], &bytes),
            .ipv6 => |bytes| @memcpy(request.address[0..16], &bytes),
        }

        var received: ?i32 = null;
        const reply = exchange(self.fd, &request, &received) orelse {
            if (received) |handle| _ = linux.close(handle);
            return error.NotConnected;
        };
        if (reply.status != .granted) {
            if (received) |handle| _ = linux.close(handle);
            return error.NotConnected;
        }
        return received orelse error.NotConnected;
    }
};

fn exchange(fd: i32, request: *const Request, carried: ?*?i32) ?Reply {
    if (carried) |slot| slot.* = null;
    if (fd < 0) return null;

    const sent = linux.sendto(fd, @ptrCast(request), @sizeOf(Request), linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(sent) != .SUCCESS or sent != @sizeOf(Request)) return null;

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
    if (linux.errno(rc) != .SUCCESS) return null;
    if (rc == 0) return null;

    const received = netbroker.firstReceivedFd(&message, &control);
    if (carried) |slot| slot.* = received else if (received) |handle| _ = linux.close(handle);

    if (rc != @sizeOf(Reply)) return null;
    if (reply.magic != reply_magic) return null;
    return reply;
}

fn addressOf(family: Family, bytes: [16]u8, kind: router.RecordKind) ?nftables.Address {
    const wanted = kind.family();
    return switch (family) {
        .ipv4 => if (wanted == .ipv4) nftables.Address{ .ipv4 = bytes[0..4].* } else null,
        .ipv6 => if (wanted == .ipv6) nftables.Address{ .ipv6 = bytes } else null,
        _ => null,
    };
}

pub const Outcome = enum { served, peer_gone, nothing };

pub fn serveOne(fd: i32, seam: NetRouter) Outcome {
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
    if (request.reserved != 0 or request.reserved2 != 0) return refuse(fd);

    const want = request.family.seam() orelse return refuse(fd);

    switch (request.kind) {
        .resolve => {
            if (request.port != 0) return refuse(fd);
            if (request.host_len == 0 or request.host_len > max_host_bytes) return refuse(fd);
            const host = request.host[0..request.host_len];
            if (!netbroker.hostBytesAreUsable(host)) return refuse(fd);
            return switch (seam.resolve(host, want)) {
                .granted => |address| answerAddress(fd, address),
                .refused => refuse(fd),
                .unresolved => answer(fd, .{ .status = .unresolved }),
            };
        },
        .open => {
            if (request.port == 0) return refuse(fd);
            if (request.host_len != 0) return refuse(fd);
            const address: NetRouter.Address = switch (want) {
                .ipv4 => .{ .ipv4 = request.address[0..4].* },
                .ipv6 => .{ .ipv6 = request.address },
            };
            if (want == .ipv4 and !std.mem.allEqual(u8, request.address[4..], 0)) return refuse(fd);
            return switch (seam.open(address, request.port)) {
                .refused => refuse(fd),
                .granted => |handle| {
                    defer _ = linux.close(handle);
                    return grant(fd, handle);
                },
            };
        },
        _ => return refuse(fd),
    }
}

fn refuse(fd: i32) Outcome {
    return answer(fd, .{ .status = .refused });
}

fn answerAddress(fd: i32, address: NetRouter.Address) Outcome {
    var reply = Reply{ .status = .granted, .family = Family.ofAddress(address) };
    switch (address) {
        .ipv4 => |bytes| @memcpy(reply.address[0..4], &bytes),
        .ipv6 => |bytes| @memcpy(reply.address[0..16], &bytes),
    }
    return answer(fd, reply);
}

fn answer(fd: i32, reply: Reply) Outcome {
    var held = reply;
    var iov = [1]std.posix.iovec_const{.{ .base = @ptrCast(&held), .len = @sizeOf(Reply) }};
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
    header.* = .{ .len = cmsg_len, .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS };
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

const cmsg_data_offset: usize = netbroker.cmsg_data_offset;
const cmsg_len: usize = netbroker.cmsg_len;
const control_bytes: usize = netbroker.control_bytes;

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
    address: ?NetRouter.Address = null,
    unresolved: bool = false,
    give: ?i32 = null,

    resolves: usize = 0,
    opens: usize = 0,
    seen_host: [max_host_bytes]u8 = @splat(0),
    seen_host_len: usize = 0,
    seen_family: ?NetRouter.Family = null,
    seen_address: ?NetRouter.Address = null,
    seen_port: u16 = 0,

    fn seam(self: *StubSeam) NetRouter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = NetRouter.VTable{ .resolve = resolveFn, .open = openFn };

    fn resolveFn(ptr: *anyopaque, host: []const u8, want: NetRouter.Family) NetRouter.Resolution {
        const self: *StubSeam = @ptrCast(@alignCast(ptr));
        self.resolves += 1;
        self.seen_host_len = host.len;
        @memcpy(self.seen_host[0..host.len], host);
        self.seen_family = want;
        if (self.unresolved) return .unresolved;
        const address = self.address orelse return .refused;
        return .{ .granted = address };
    }

    fn openFn(ptr: *anyopaque, address: NetRouter.Address, port: u16) NetBroker.Grant {
        const self: *StubSeam = @ptrCast(@alignCast(ptr));
        self.opens += 1;
        self.seen_address = address;
        self.seen_port = port;
        const handle = self.give orelse return .refused;
        const rc = linux.dup(handle);
        if (linux.errno(rc) != .SUCCESS) return .refused;
        return .{ .granted = @intCast(rc) };
    }

    fn sawHost(self: *const StubSeam) []const u8 {
        return self.seen_host[0..self.seen_host_len];
    }
};

fn queueReply(fd: i32, reply: Reply) !void {
    var held = reply;
    const rc = linux.sendto(fd, @ptrCast(&held), @sizeOf(Reply), linux.MSG.NOSIGNAL, null, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
}

fn takeReply(fd: i32) !Reply {
    var reply: Reply = undefined;
    const rc = linux.recvfrom(fd, @ptrCast(&reply), @sizeOf(Reply), 0, null, null);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expectEqual(@sizeOf(Reply), rc);
    return reply;
}

fn sendRequest(fd: i32, request: Request) !void {
    var held = request;
    const rc = linux.sendto(fd, @ptrCast(&held), @sizeOf(Request), linux.MSG.NOSIGNAL, null, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
}

fn resolveRequest(name: []const u8, family: Family) Request {
    var request = Request{ .kind = .resolve, .family = family, .host_len = @intCast(name.len), .port = 0 };
    @memcpy(request.host[0..name.len], name);
    return request;
}

test "both wire structures are a fixed size with no padding a compiler chose" {
    try testing.expectEqual(@as(usize, 4 + 1 + 1 + 1 + 1 + 2 + 2 + 16 + max_host_bytes + 1), @sizeOf(Request));
    try testing.expectEqual(@as(usize, 4 + 1 + 1 + 2 + 16), @sizeOf(Reply));

    try testing.expect(request_magic != reply_magic);
}

test "a name the far side refuses is refused, and no address is ever asked for" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try queueReply(pair[0], .{ .status = .refused });

    var client = Client{ .fd = pair[1], .session = .{ .fd = -1 } };
    try testing.expectEqual(router.Policy.Verdict.refuse, client.policy().askName("evil.test", .a));

    try testing.expectError(error.NotResolved, client.host().resolve("evil.test", .a));
}

test "a permitted name is one question on the wire and two answers read from it" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    var reply = Reply{ .status = .granted, .family = .ipv4 };
    @memcpy(reply.address[0..4], &[_]u8{ 93, 184, 216, 34 });
    try queueReply(pair[0], reply);

    var client = Client{ .fd = pair[1], .session = .{ .fd = -1 } };
    try testing.expectEqual(router.Policy.Verdict.permit, client.policy().askName("api.anthropic.com", .a));
    const address = try client.host().resolve("api.anthropic.com", .a);
    try testing.expectEqualSlices(u8, &.{ 93, 184, 216, 34 }, &address.ipv4);

    try testing.expectError(error.NotResolved, client.host().resolve("api.anthropic.com", .a));
}

test "a resolve for a question nobody asked never reaches the wire" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    var reply = Reply{ .status = .granted, .family = .ipv4 };
    @memcpy(reply.address[0..4], &[_]u8{ 93, 184, 216, 34 });
    try queueReply(pair[0], reply);

    var client = Client{ .fd = pair[1], .session = .{ .fd = -1 } };
    try testing.expectEqual(router.Policy.Verdict.permit, client.policy().askName("api.anthropic.com", .a));

    try testing.expectError(error.NotResolved, client.host().resolve("other.anthropic.com", .a));
    try testing.expectError(error.NotResolved, client.host().resolve("api.anthropic.com", .aaaa));
}

test "an answer of the wrong width is refused rather than cut down to size" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    var reply = Reply{ .status = .granted, .family = .ipv6 };
    reply.address = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try queueReply(pair[0], reply);

    var client = Client{ .fd = pair[1], .session = .{ .fd = -1 } };
    try testing.expectEqual(router.Policy.Verdict.permit, client.policy().askName("api.anthropic.com", .a));
    try testing.expectError(error.NotResolved, client.host().resolve("api.anthropic.com", .a));
}

test "a permitted name with no address of that width is a permission and not a refusal" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try queueReply(pair[0], .{ .status = .unresolved });

    var client = Client{ .fd = pair[1], .session = .{ .fd = -1 } };
    try testing.expectEqual(router.Policy.Verdict.permit, client.policy().askName("api.anthropic.com", .a));
    try testing.expectError(error.NotResolved, client.host().resolve("api.anthropic.com", .a));
}

test "a channel that has gone refuses rather than waiting" {
    try linuxOnly();
    const pair = try makePair();
    _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    var client = Client{ .fd = pair[1], .session = .{ .fd = -1 } };
    try testing.expectEqual(router.Policy.Verdict.refuse, client.policy().askName("api.anthropic.com", .a));
    try testing.expectError(
        error.NotConnected,
        client.host().open(.{ .address = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 443 }),
    );
}

test "a destination the name table does not know is refused by the router's own policy" {
    try linuxOnly();
    var client = Client{ .fd = -1, .session = .{ .fd = -1 } };
    const dest = router.Destination{ .address = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 443 };
    try testing.expectEqual(router.Policy.Verdict.refuse, client.policy().askConnect(null, dest));
    try testing.expectEqual(router.Policy.Verdict.permit, client.policy().askConnect("api.anthropic.com", dest));
}

test "an address that will not go in the kernel's allow set is an error and not a silence" {
    try linuxOnly();
    var client = Client{ .fd = -1, .session = .{ .fd = -1 } };
    try testing.expectError(
        error.NotAllowed,
        client.host().allow(.{ .ipv4 = .{ 93, 184, 216, 34 } }, 30_000),
    );
}

test "the far side reads a name, answers about it, and hands the address back" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    var stub = StubSeam{ .address = .{ .ipv4 = .{ 93, 184, 216, 34 } } };
    try sendRequest(pair[1], resolveRequest("api.anthropic.com", .ipv4));
    try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.seam()));

    try testing.expectEqual(@as(usize, 1), stub.resolves);
    try testing.expectEqualStrings("api.anthropic.com", stub.sawHost());
    try testing.expectEqual(NetRouter.Family.ipv4, stub.seen_family.?);

    const reply = try takeReply(pair[1]);
    try testing.expectEqual(Reply.Status.granted, reply.status);
    try testing.expectEqual(Family.ipv4, reply.family);
    try testing.expectEqualSlices(u8, &.{ 93, 184, 216, 34 }, reply.address[0..4]);
}

test "the far side refuses a message whose shape is not one request" {
    try linuxOnly();
    const cases = [_]struct { name: []const u8, request: Request }{
        .{ .name = "a magic that is not ours", .request = blk: {
            var one = resolveRequest("api.anthropic.com", .ipv4);
            one.magic = 0xdeadbeef;
            break :blk one;
        } },
        .{ .name = "a kind this file does not have", .request = blk: {
            var one = resolveRequest("api.anthropic.com", .ipv4);
            one.kind = @enumFromInt(9);
            break :blk one;
        } },
        .{ .name = "a width this file does not have", .request = blk: {
            var one = resolveRequest("api.anthropic.com", .ipv4);
            one.family = @enumFromInt(9);
            break :blk one;
        } },
        .{ .name = "a reserved byte that is not zero", .request = blk: {
            var one = resolveRequest("api.anthropic.com", .ipv4);
            one.reserved = 1;
            break :blk one;
        } },
        .{ .name = "a name of no length", .request = blk: {
            var one = resolveRequest("api.anthropic.com", .ipv4);
            one.host_len = 0;
            break :blk one;
        } },
        .{ .name = "a name that is not a name", .request = resolveRequest("api anthropic com", .ipv4) },
        .{ .name = "a resolve that carries a port", .request = blk: {
            var one = resolveRequest("api.anthropic.com", .ipv4);
            one.port = 443;
            break :blk one;
        } },
        .{ .name = "an open with no port", .request = .{ .kind = .open, .family = .ipv4, .host_len = 0, .port = 0 } },
        .{ .name = "an open that also carries a name", .request = blk: {
            var one = resolveRequest("api.anthropic.com", .ipv4);
            one.kind = .open;
            one.port = 443;
            break :blk one;
        } },
        .{ .name = "a four byte address with bytes in its tail", .request = blk: {
            var one = Request{ .kind = .open, .family = .ipv4, .host_len = 0, .port = 443 };
            one.address[7] = 1;
            break :blk one;
        } },
    };

    var got_through: std.ArrayList(u8) = .empty;
    defer got_through.deinit(testing.allocator);

    for (cases) |case| {
        const pair = try makePair();
        defer _ = linux.close(pair[0]);
        defer _ = linux.close(pair[1]);

        var stub = StubSeam{ .address = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .give = 1 };
        try sendRequest(pair[1], case.request);
        try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.seam()));

        const reply = try takeReply(pair[1]);
        if (reply.status != .refused) {
            try got_through.print(testing.allocator, "{s} was not refused\n", .{case.name});
        }
        if (stub.resolves + stub.opens != 0) {
            try got_through.print(testing.allocator, "{s} reached the seam\n", .{case.name});
        }
    }

    try testing.expectEqualStrings("", got_through.items);
}

test "a message that is not the size of a request is refused before it is read" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    var stub = StubSeam{ .address = .{ .ipv4 = .{ 93, 184, 216, 34 } } };
    const short = [_]u8{0} ** 8;
    const rc = linux.sendto(pair[1], &short, short.len, linux.MSG.NOSIGNAL, null, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.seam()));

    const reply = try takeReply(pair[1]);
    try testing.expectEqual(Reply.Status.refused, reply.status);
    try testing.expectEqual(@as(usize, 0), stub.resolves);
}

test "the far side is gone once its peer has closed" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    _ = linux.close(pair[1]);

    var stub = StubSeam{};
    try testing.expectEqual(Outcome.peer_gone, serveOne(pair[0], stub.seam()));
}

test "an open carries the address and the port, and a descriptor comes back" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const give_rc = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(give_rc));
    const give: i32 = @intCast(give_rc);
    defer _ = linux.close(give);

    var stub = StubSeam{ .give = give };
    try sendRequest(pair[1], .{
        .kind = .open,
        .family = .ipv4,
        .host_len = 0,
        .port = 443,
        .address = [_]u8{ 93, 184, 216, 34 } ++ [_]u8{0} ** 12,
    });
    try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.seam()));

    try testing.expectEqual(@as(usize, 1), stub.opens);
    try testing.expectEqualSlices(u8, &.{ 93, 184, 216, 34 }, &stub.seen_address.?.ipv4);
    try testing.expectEqual(@as(u16, 443), stub.seen_port);

    var client = Client{ .fd = pair[1], .session = .{ .fd = -1 } };
    const carried = try client.host().open(.{
        .address = .{ .ipv4 = .{ 93, 184, 216, 34 } },
        .port = 443,
    });
    defer _ = linux.close(carried);
    try testing.expect(carried != give);
}

test "a refusal carries no descriptor and no address" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    var stub = StubSeam{};
    try sendRequest(pair[1], .{
        .kind = .open,
        .family = .ipv4,
        .host_len = 0,
        .port = 443,
        .address = [_]u8{ 93, 184, 216, 34 } ++ [_]u8{0} ** 12,
    });
    try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.seam()));
    try testing.expectEqual(@as(usize, 1), stub.opens);

    var client = Client{ .fd = pair[1], .session = .{ .fd = -1 } };
    try testing.expectError(
        error.NotConnected,
        client.host().open(.{ .address = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 443 }),
    );
}
