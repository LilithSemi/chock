//! The network inside the sandbox namespace: loopback, one dummy device with
//! no route out, one address on it, and a default route through it.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const namespace = @import("namespace.zig");

pub const device_name = "chock0";

pub const link_kind = "dummy";

pub const address4: [4]u8 = .{ 10, 99, 0, 1 };
pub const prefix4: u8 = 24;

pub const address6: [16]u8 = .{ 0xfd, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
pub const prefix6: u8 = 64;

pub const Step = enum {
    open_socket,
    bind_socket,
    send,
    receive,
    loopback_up,
    dummy_create,
    device_index,
    address4_add,
    address6_add,
    device_up,
    route4_add,
    route6_add,
    link_read,
    address_read,
    route_read,
};

pub const Diagnostic = struct {
    step: Step,
    errno: i32,

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const name = std.enums.fromInt(linux.E, self.errno);
        if (name) |e| {
            try writer.print("{t} at the {t} step", .{ e, self.step });
        } else {
            try writer.print("errno {d} at the {t} step", .{ self.errno, self.step });
        }
    }
};

pub const Error = error{
    KernelModuleMissing,
    NotPermitted,
    Refused,
    ExchangeFailed,
};

fn note(diag: ?*?Diagnostic, step: Step, errno: i32) void {
    if (diag) |slot| slot.* = .{ .step = step, .errno = errno };
}

fn classify(step: Step, errno: i32) Error {
    if (errno == @intFromEnum(linux.E.PERM) or errno == @intFromEnum(linux.E.ACCES)) return error.NotPermitted;
    if (errno == @intFromEnum(linux.E.OPNOTSUPP)) {
        return switch (step) {
            .dummy_create => error.KernelModuleMissing,
            else => error.Refused,
        };
    }
    if (errno == @intFromEnum(linux.E.PROTONOSUPPORT) and step == .open_socket) return error.KernelModuleMissing;
    return error.Refused;
}

pub const Session = struct {
    fd: i32,
    sequence: u32 = 1,

    pub fn open(diag: ?*?Diagnostic) Error!Session {
        const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.ROUTE);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => |e| {
                note(diag, .open_socket, @intFromEnum(e));
                return classify(.open_socket, @intFromEnum(e));
            },
        }
        const fd: i32 = @intCast(rc);
        const me: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        switch (linux.errno(linux.bind(fd, @ptrCast(&me), @sizeOf(linux.sockaddr.nl)))) {
            .SUCCESS => {},
            else => |e| {
                _ = linux.close(fd);
                note(diag, .bind_socket, @intFromEnum(e));
                return classify(.bind_socket, @intFromEnum(e));
            },
        }
        return .{ .fd = fd };
    }

    pub fn close(self: Session) void {
        _ = linux.close(self.fd);
    }

    pub fn configure(self: *Session, diag: ?*?Diagnostic) Error!u32 {
        var buffer: [max_request]u8 = undefined;

        try self.exchange(buffer[0..buildLinkUp(&buffer, loopback_name, self.sequence)], .loopback_up, diag);
        try self.exchange(buffer[0..buildDummyLink(&buffer, self.sequence)], .dummy_create, diag);

        const index = try self.linkIndex(device_name, diag);

        try self.exchange(buffer[0..buildAddress(&buffer, .{
            .family = af_inet,
            .prefix = prefix4,
            .flags = 0,
            .index = index,
            .bytes = &address4,
        }, self.sequence)], .address4_add, diag);
        try self.exchange(buffer[0..buildAddress(&buffer, .{
            .family = af_inet6,
            .prefix = prefix6,
            .flags = ifa_f_nodad,
            .index = index,
            .bytes = &address6,
        }, self.sequence)], .address6_add, diag);

        try self.exchange(buffer[0..buildLinkUp(&buffer, device_name, self.sequence)], .device_up, diag);

        try self.exchange(buffer[0..buildDefaultRoute(&buffer, af_inet, index, self.sequence)], .route4_add, diag);
        try self.exchange(buffer[0..buildDefaultRoute(&buffer, af_inet6, index, self.sequence)], .route6_add, diag);

        return index;
    }

    fn linkIndex(self: *Session, name: []const u8, diag: ?*?Diagnostic) Error!u32 {
        var buffer: [max_request]u8 = undefined;
        const length = buildLinkQuery(&buffer, name, self.sequence);
        const facts = try readLink(self, buffer[0..length], .device_index, diag);
        if (facts.index == 0) {
            note(diag, .device_index, @intFromEnum(linux.E.NODEV));
            return error.Refused;
        }
        return facts.index;
    }

    fn exchange(self: *Session, bytes: []const u8, step: Step, diag: ?*?Diagnostic) Error!void {
        const sent = self.sequence;
        try self.send(bytes, step, diag);

        var reply: [reply_capacity]u8 = undefined;
        const filled = try self.receive(&reply, step, diag);
        var messages = Messages{ .bytes = reply[0..filled] };
        while (messages.next()) |message| {
            if (message.sequence != sent) continue;
            if (message.kind != nlmsg_error) continue;
            const code = errorCode(message.body);
            if (code == 0) return;
            note(diag, step, code);
            return classify(step, code);
        }
        note(diag, step, 0);
        return error.ExchangeFailed;
    }

    fn send(self: *Session, bytes: []const u8, step: Step, diag: ?*?Diagnostic) Error!void {
        std.debug.assert(bytes.len >= 16);
        std.debug.assert(std.mem.readInt(u32, bytes[8..12], .little) == self.sequence);

        self.sequence = if (self.sequence == std.math.maxInt(u32)) 1 else self.sequence + 1;

        const rc = linux.sendto(self.fd, bytes.ptr, bytes.len, 0, null, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => |e| {
                note(diag, step, @intFromEnum(e));
                return error.ExchangeFailed;
            },
        }
        if (rc != bytes.len) {
            note(diag, step, 0);
            return error.ExchangeFailed;
        }
    }

    fn receive(self: *Session, into: []u8, step: Step, diag: ?*?Diagnostic) Error!usize {
        const rc = linux.recvfrom(self.fd, into.ptr, into.len, 0, null, null);
        switch (linux.errno(rc)) {
            .SUCCESS => return rc,
            else => |e| {
                note(diag, step, @intFromEnum(e));
                return error.ExchangeFailed;
            },
        }
    }
};

const loopback_name = "lo";

const nlmsg_error: u16 = 2;
const nlmsg_done: u16 = 3;

const rtm_newlink: u16 = 16;
const rtm_getlink: u16 = 18;
const rtm_setlink: u16 = 19;
const rtm_newaddr: u16 = 20;
const rtm_getaddr: u16 = 22;
const rtm_newroute: u16 = 24;
const rtm_getroute: u16 = 26;

const f_request: u16 = 0x001;
const f_ack: u16 = 0x004;
const f_excl: u16 = 0x200;
const f_create: u16 = 0x400;
const f_dump: u16 = 0x300;

const nla_nested: u16 = 0x8000;
const nla_type_mask: u16 = 0x3fff;

const af_unspec: u8 = 0;
const af_inet: u8 = 2;
const af_inet6: u8 = 10;

const ifla_ifname: u16 = 3;
const ifla_stats64: u16 = 23;
const ifla_linkinfo: u16 = 18;
const ifla_info_kind: u16 = 1;

const ifa_address: u16 = 1;
const ifa_local: u16 = 2;

const rta_oif: u16 = 4;
const rta_gateway: u16 = 5;

const iff_up: u32 = 0x1;
const iff_running: u32 = 0x40;
const ifa_f_nodad: u8 = 0x02;

const rt_table_main: u8 = 254;
const rtprot_boot: u8 = 3;
const rt_scope_link: u8 = 253;
const rtn_unicast: u8 = 1;

const max_request = 256;
const reply_capacity = 8192;

const Builder = struct {
    buf: []u8,
    len: usize = 0,

    fn put(b: *Builder, bytes: []const u8) void {
        @memcpy(b.buf[b.len..][0..bytes.len], bytes);
        b.len += bytes.len;
    }

    fn pad(b: *Builder) void {
        while (b.len % 4 != 0) : (b.len += 1) b.buf[b.len] = 0;
    }

    fn attribute(b: *Builder, kind: u16, payload: []const u8) void {
        const at = b.len;
        b.put(&[_]u8{0} ** 4);
        b.put(payload);
        std.mem.writeInt(u16, b.buf[at..][0..2], @intCast(4 + payload.len), .little);
        std.mem.writeInt(u16, b.buf[at + 2 ..][0..2], kind, .little);
        b.pad();
    }

    fn u32Native(b: *Builder, kind: u16, value: u32) void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .little);
        b.attribute(kind, &bytes);
    }

    fn string(b: *Builder, kind: u16, text: []const u8) void {
        const at = b.len;
        b.put(&[_]u8{0} ** 4);
        b.put(text);
        b.put(&[_]u8{0});
        std.mem.writeInt(u16, b.buf[at..][0..2], @intCast(5 + text.len), .little);
        std.mem.writeInt(u16, b.buf[at + 2 ..][0..2], kind, .little);
        b.pad();
    }

    fn openNested(b: *Builder, kind: u16) usize {
        const at = b.len;
        b.put(&[_]u8{0} ** 4);
        std.mem.writeInt(u16, b.buf[at + 2 ..][0..2], kind | nla_nested, .little);
        return at;
    }

    fn closeNested(b: *Builder, at: usize) void {
        std.mem.writeInt(u16, b.buf[at..][0..2], @intCast(b.len - at), .little);
    }

    fn openMessage(b: *Builder, kind: u16, flags: u16, sequence: u32) usize {
        const at = b.len;
        b.put(&[_]u8{0} ** 16);
        std.mem.writeInt(u16, b.buf[at + 4 ..][0..2], kind, .little);
        std.mem.writeInt(u16, b.buf[at + 6 ..][0..2], flags, .little);
        std.mem.writeInt(u32, b.buf[at + 8 ..][0..4], sequence, .little);
        return at;
    }

    fn closeMessage(b: *Builder, at: usize) void {
        std.mem.writeInt(u32, b.buf[at..][0..4], @intCast(b.len - at), .little);
    }

    fn linkHeader(b: *Builder, index: u32, flags: u32, change: u32) void {
        const at = b.len;
        b.put(&[_]u8{0} ** 16);
        b.buf[at] = af_unspec;
        std.mem.writeInt(u32, b.buf[at + 4 ..][0..4], index, .little);
        std.mem.writeInt(u32, b.buf[at + 8 ..][0..4], flags, .little);
        std.mem.writeInt(u32, b.buf[at + 12 ..][0..4], change, .little);
    }

    fn addressHeader(b: *Builder, family: u8, prefix: u8, flags: u8, index: u32) void {
        const at = b.len;
        b.put(&[_]u8{0} ** 8);
        b.buf[at] = family;
        b.buf[at + 1] = prefix;
        b.buf[at + 2] = flags;
        std.mem.writeInt(u32, b.buf[at + 4 ..][0..4], index, .little);
    }

    fn routeHeader(b: *Builder, family: u8, dst_len: u8, scope: u8, kind: u8) void {
        const at = b.len;
        b.put(&[_]u8{0} ** 12);
        b.buf[at] = family;
        b.buf[at + 1] = dst_len;
        b.buf[at + 4] = rt_table_main;
        b.buf[at + 5] = rtprot_boot;
        b.buf[at + 6] = scope;
        b.buf[at + 7] = kind;
    }
};

fn buildLinkUp(buf: []u8, name: []const u8, sequence: u32) usize {
    var b = Builder{ .buf = buf };
    const at = b.openMessage(rtm_setlink, f_request | f_ack, sequence);
    b.linkHeader(0, iff_up, iff_up);
    b.string(ifla_ifname, name);
    b.closeMessage(at);
    return b.len;
}

fn buildDummyLink(buf: []u8, sequence: u32) usize {
    var b = Builder{ .buf = buf };
    const at = b.openMessage(rtm_newlink, f_request | f_ack | f_create | f_excl, sequence);
    b.linkHeader(0, 0, 0);
    b.string(ifla_ifname, device_name);
    const info = b.openNested(ifla_linkinfo);
    b.string(ifla_info_kind, link_kind);
    b.closeNested(info);
    b.closeMessage(at);
    return b.len;
}

fn buildLinkQuery(buf: []u8, name: []const u8, sequence: u32) usize {
    var b = Builder{ .buf = buf };
    const at = b.openMessage(rtm_getlink, f_request, sequence);
    b.linkHeader(0, 0, 0);
    b.string(ifla_ifname, name);
    b.closeMessage(at);
    return b.len;
}

const AddressRequest = struct {
    family: u8,
    prefix: u8,
    flags: u8,
    index: u32,
    bytes: []const u8,
};

fn buildAddress(buf: []u8, request: AddressRequest, sequence: u32) usize {
    var b = Builder{ .buf = buf };
    const at = b.openMessage(rtm_newaddr, f_request | f_ack | f_create | f_excl, sequence);
    b.addressHeader(request.family, request.prefix, request.flags, request.index);
    b.attribute(ifa_local, request.bytes);
    b.attribute(ifa_address, request.bytes);
    b.closeMessage(at);
    return b.len;
}

fn buildDefaultRoute(buf: []u8, family: u8, index: u32, sequence: u32) usize {
    var b = Builder{ .buf = buf };
    const at = b.openMessage(rtm_newroute, f_request | f_ack | f_create | f_excl, sequence);
    b.routeHeader(family, 0, rt_scope_link, rtn_unicast);
    b.u32Native(rta_oif, index);
    b.closeMessage(at);
    return b.len;
}

fn buildAddressDump(buf: []u8, family: u8, sequence: u32) usize {
    var b = Builder{ .buf = buf };
    const at = b.openMessage(rtm_getaddr, f_request | f_dump, sequence);
    b.addressHeader(family, 0, 0, 0);
    b.closeMessage(at);
    return b.len;
}

fn buildRouteDump(buf: []u8, family: u8, sequence: u32) usize {
    var b = Builder{ .buf = buf };
    const at = b.openMessage(rtm_getroute, f_request | f_dump, sequence);
    b.routeHeader(family, 0, 0, 0);
    b.closeMessage(at);
    return b.len;
}

const Message = struct {
    kind: u16,
    sequence: u32,
    body: []const u8,

    fn payload(self: Message, size: usize) []const u8 {
        const aligned = (size + 3) & ~@as(usize, 3);
        if (self.body.len < aligned) return self.body[0..0];
        return self.body[aligned..];
    }
};

const Messages = struct {
    bytes: []const u8,
    at: usize = 0,

    fn next(self: *Messages) ?Message {
        if (self.at + 16 > self.bytes.len) return null;
        const length = std.mem.readInt(u32, self.bytes[self.at..][0..4], .little);
        if (length < 16 or self.at + length > self.bytes.len) return null;
        const message = Message{
            .kind = std.mem.readInt(u16, self.bytes[self.at + 4 ..][0..2], .little),
            .sequence = std.mem.readInt(u32, self.bytes[self.at + 8 ..][0..4], .little),
            .body = self.bytes[self.at + 16 .. self.at + length],
        };
        self.at += (length + 3) & ~@as(usize, 3);
        return message;
    }
};

const Attribute = struct {
    kind: u16,
    payload: []const u8,
};

const Attributes = struct {
    bytes: []const u8,
    at: usize = 0,

    fn next(self: *Attributes) ?Attribute {
        if (self.at + 4 > self.bytes.len) return null;
        const length = std.mem.readInt(u16, self.bytes[self.at..][0..2], .little);
        const kind = std.mem.readInt(u16, self.bytes[self.at + 2 ..][0..2], .little);
        if (length < 4 or self.at + length > self.bytes.len) return null;
        const found = Attribute{
            .kind = kind & nla_type_mask,
            .payload = self.bytes[self.at + 4 .. self.at + length],
        };
        self.at += (length + 3) & ~@as(usize, 3);
        return found;
    }

    fn find(self: Attributes, kind: u16) ?[]const u8 {
        var walk = self;
        while (walk.next()) |attribute| {
            if (attribute.kind == kind) return attribute.payload;
        }
        return null;
    }
};

fn errorCode(body: []const u8) i32 {
    if (body.len < 4) return 0;
    const signed = std.mem.readInt(i32, body[0..4], .little);
    return if (signed < 0) -signed else signed;
}

fn readU32(bytes: []const u8) u32 {
    if (bytes.len < 4) return 0;
    return std.mem.readInt(u32, bytes[0..4], .little);
}

fn readU64(bytes: []const u8) u64 {
    if (bytes.len < 8) return 0;
    return std.mem.readInt(u64, bytes[0..8], .little);
}

const LinkFacts = struct {
    index: u32,
    flags: u32,
    kind: [16]u8,
    tx_packets: u64,
    rx_packets: u64,
};

fn readLink(self: *Session, request: []const u8, step: Step, diag: ?*?Diagnostic) Error!LinkFacts {
    const sent = self.sequence;
    try self.send(request, step, diag);

    var reply: [reply_capacity]u8 = undefined;
    const filled = try self.receive(&reply, step, diag);
    var messages = Messages{ .bytes = reply[0..filled] };
    while (messages.next()) |message| {
        if (message.sequence != sent) continue;
        if (message.kind == nlmsg_error) {
            const code = errorCode(message.body);
            if (code == 0) continue;
            note(diag, step, code);
            return classify(step, code);
        }
        if (message.kind != rtm_newlink) continue;
        if (message.body.len < 16) continue;

        var found = LinkFacts{
            .index = std.mem.readInt(u32, message.body[4..8], .little),
            .flags = std.mem.readInt(u32, message.body[8..12], .little),
            .kind = @splat(0),
            .tx_packets = 0,
            .rx_packets = 0,
        };
        const attributes = Attributes{ .bytes = message.payload(16) };
        if (attributes.find(ifla_linkinfo)) |info| {
            const inside = Attributes{ .bytes = info };
            if (inside.find(ifla_info_kind)) |text| {
                const wanted = @min(text.len, found.kind.len);
                @memcpy(found.kind[0..wanted], text[0..wanted]);
            }
        }
        if (attributes.find(ifla_stats64)) |stats| {
            found.rx_packets = readU64(stats);
            if (stats.len >= 16) found.tx_packets = readU64(stats[8..]);
        }
        return found;
    }
    note(diag, step, 0);
    return error.ExchangeFailed;
}

const AddressFacts = struct {
    prefix: u8,
    bytes: [16]u8,
    length: u8,
};

fn readAddress(self: *Session, family: u8, index: u32, diag: ?*?Diagnostic) Error!?AddressFacts {
    var buffer: [max_request]u8 = undefined;
    const sent = self.sequence;
    const length = buildAddressDump(&buffer, family, sent);
    try self.send(buffer[0..length], .address_read, diag);

    var reply: [reply_capacity]u8 = undefined;
    var datagrams: usize = 0;
    while (datagrams < 64) : (datagrams += 1) {
        const filled = try self.receive(&reply, .address_read, diag);
        var messages = Messages{ .bytes = reply[0..filled] };
        while (messages.next()) |message| {
            if (message.sequence != sent) continue;
            if (message.kind == nlmsg_done) return null;
            if (message.kind == nlmsg_error) {
                const code = errorCode(message.body);
                if (code == 0) continue;
                note(diag, .address_read, code);
                return classify(.address_read, code);
            }
            if (message.body.len < 8) continue;
            if (message.body[0] != family) continue;
            if (std.mem.readInt(u32, message.body[4..8], .little) != index) continue;

            const attributes = Attributes{ .bytes = message.payload(8) };
            const local = attributes.find(ifa_local) orelse
                attributes.find(ifa_address) orelse continue;
            var found = AddressFacts{
                .prefix = message.body[1],
                .bytes = @splat(0),
                .length = @intCast(@min(local.len, 16)),
            };
            @memcpy(found.bytes[0..found.length], local[0..found.length]);
            return found;
        }
    }
    note(diag, .address_read, 0);
    return error.ExchangeFailed;
}

const RouteFacts = struct {
    dst_len: u8,
    table: u8,
    scope: u8,
    kind: u8,
    oif: u32,
    has_gateway: bool,
};

fn readDefaultRoute(self: *Session, family: u8, diag: ?*?Diagnostic) Error!?RouteFacts {
    var buffer: [max_request]u8 = undefined;
    const sent = self.sequence;
    const length = buildRouteDump(&buffer, family, sent);
    try self.send(buffer[0..length], .route_read, diag);

    var reply: [reply_capacity]u8 = undefined;
    var datagrams: usize = 0;
    while (datagrams < 64) : (datagrams += 1) {
        const filled = try self.receive(&reply, .route_read, diag);
        var messages = Messages{ .bytes = reply[0..filled] };
        while (messages.next()) |message| {
            if (message.sequence != sent) continue;
            if (message.kind == nlmsg_done) return null;
            if (message.kind == nlmsg_error) {
                const code = errorCode(message.body);
                if (code == 0) continue;
                note(diag, .route_read, code);
                return classify(.route_read, code);
            }
            if (message.body.len < 12) continue;
            if (message.body[0] != family) continue;
            if (message.body[1] != 0) continue;
            if (message.body[4] != rt_table_main) continue;

            const attributes = Attributes{ .bytes = message.payload(12) };
            return .{
                .dst_len = message.body[1],
                .table = message.body[4],
                .scope = message.body[6],
                .kind = message.body[7],
                .oif = if (attributes.find(rta_oif)) |bytes| readU32(bytes) else 0,
                .has_gateway = attributes.find(rta_gateway) != null,
            };
        }
    }
    note(diag, .route_read, 0);
    return error.ExchangeFailed;
}

const testing = std.testing;

const Measurement = extern struct {
    failed_step: u32,
    failed_errno: i32,

    loopback_index: u32,
    loopback_flags: u32,
    device_index: u32,
    device_flags: u32,
    device_kind: [16]u8,

    address4_found: u32,
    address4_prefix: u32,
    address4_bytes: [16]u8,
    address4_length: u32,
    address6_found: u32,
    address6_prefix: u32,
    address6_bytes: [16]u8,
    address6_length: u32,

    route4_found: u32,
    route4_oif: u32,
    route4_dst_len: u32,
    route4_table: u32,
    route4_kind: u32,
    route4_gateway: u32,
    route6_found: u32,
    route6_oif: u32,
    route6_dst_len: u32,
    route6_table: u32,
    route6_kind: u32,
    route6_gateway: u32,

    before4_errno: i32,
    before6_errno: i32,
    after4_errno: i32,
    after6_errno: i32,
    completed4: u32,
    completed6: u32,
    so_error4: i32,
    so_error6: i32,

    tx_packets: u64,
    rx_packets: u64,

    const no_failure: u32 = 0xffff_ffff;
};

const unreachable4: [4]u8 = .{ 203, 0, 113, 7 };
const unreachable6: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 11 ++ .{1};

const settle_ms: i32 = 300;

const Attempt = struct {
    errno: i32,
    completed: bool,
    so_error: i32,
};

fn attemptConnect(address: *const anyopaque, length: u32, domain: u32) Attempt {
    const rc = linux.socket(domain, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return .{ .errno = @intFromEnum(linux.errno(rc)), .completed = false, .so_error = 0 };
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);

    const started = linux.errno(linux.connect(fd, address, length));
    var attempt = Attempt{ .errno = @intFromEnum(started), .completed = false, .so_error = 0 };
    if (started != .INPROGRESS) return attempt;

    var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
    const ready = linux.poll(&fds, 1, settle_ms);
    if (linux.errno(ready) != .SUCCESS or ready == 0) return attempt;

    var code: i32 = 0;
    var size: linux.socklen_t = @sizeOf(i32);
    if (linux.errno(linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&code), &size)) != .SUCCESS) return attempt;
    attempt.so_error = code;
    attempt.completed = code == 0;
    return attempt;
}

fn measureInChild(record: *Measurement) void {
    record.* = std.mem.zeroes(Measurement);
    record.failed_step = Measurement.no_failure;

    const to4 = linux.sockaddr.in{ .port = std.mem.nativeToBig(u16, 80), .addr = @bitCast(unreachable4) };
    const to6 = linux.sockaddr.in6{ .port = std.mem.nativeToBig(u16, 80), .flowinfo = 0, .addr = unreachable6, .scope_id = 0 };
    record.before4_errno = attemptConnect(&to4, @sizeOf(linux.sockaddr.in), linux.AF.INET).errno;
    record.before6_errno = attemptConnect(&to6, @sizeOf(linux.sockaddr.in6), linux.AF.INET6).errno;

    var diag: ?Diagnostic = null;
    var session = Session.open(&diag) catch {
        recordFailure(record, diag);
        return;
    };
    defer session.close();

    const index = session.configure(&diag) catch {
        recordFailure(record, diag);
        return;
    };
    record.device_index = index;

    const after4 = attemptConnect(&to4, @sizeOf(linux.sockaddr.in), linux.AF.INET);
    record.after4_errno = after4.errno;
    record.completed4 = @intFromBool(after4.completed);
    record.so_error4 = after4.so_error;
    const after6 = attemptConnect(&to6, @sizeOf(linux.sockaddr.in6), linux.AF.INET6);
    record.after6_errno = after6.errno;
    record.completed6 = @intFromBool(after6.completed);
    record.so_error6 = after6.so_error;

    var buffer: [max_request]u8 = undefined;
    var length = buildLinkQuery(&buffer, loopback_name, session.sequence);
    if (readLink(&session, buffer[0..length], .link_read, &diag)) |facts| {
        record.loopback_index = facts.index;
        record.loopback_flags = facts.flags;
    } else |_| {
        recordFailure(record, diag);
        return;
    }

    length = buildLinkQuery(&buffer, device_name, session.sequence);
    if (readLink(&session, buffer[0..length], .link_read, &diag)) |facts| {
        record.device_flags = facts.flags;
        record.device_kind = facts.kind;
        record.tx_packets = facts.tx_packets;
        record.rx_packets = facts.rx_packets;
    } else |_| {
        recordFailure(record, diag);
        return;
    }

    if (readAddress(&session, af_inet, index, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |facts| {
        record.address4_found = 1;
        record.address4_prefix = facts.prefix;
        record.address4_bytes = facts.bytes;
        record.address4_length = facts.length;
    }
    if (readAddress(&session, af_inet6, index, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |facts| {
        record.address6_found = 1;
        record.address6_prefix = facts.prefix;
        record.address6_bytes = facts.bytes;
        record.address6_length = facts.length;
    }

    if (readDefaultRoute(&session, af_inet, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |facts| {
        record.route4_found = 1;
        record.route4_oif = facts.oif;
        record.route4_dst_len = facts.dst_len;
        record.route4_table = facts.table;
        record.route4_kind = facts.kind;
        record.route4_gateway = @intFromBool(facts.has_gateway);
    }
    if (readDefaultRoute(&session, af_inet6, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |facts| {
        record.route6_found = 1;
        record.route6_oif = facts.oif;
        record.route6_dst_len = facts.dst_len;
        record.route6_table = facts.table;
        record.route6_kind = facts.kind;
        record.route6_gateway = @intFromBool(facts.has_gateway);
    }
}

fn recordFailure(record: *Measurement, diag: ?Diagnostic) void {
    if (diag) |d| {
        record.failed_step = @intFromEnum(d.step);
        record.failed_errno = d.errno;
    } else {
        record.failed_step = @intFromEnum(Step.send);
    }
}

fn measure() error{ChildCrashed}!?Measurement {
    if (builtin.os.tag != .linux) return null;
    if (!namespace.probeAvailability().available()) return null;

    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS) return null;

    const child = linux.fork();
    if (linux.errno(child) != .SUCCESS) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return null;
    }

    if (child == 0) {
        _ = linux.close(fds[0]);
        var record: Measurement = undefined;
        if (namespace.enter(.{}, null)) |_| {
            measureInChild(&record);
            const bytes = std.mem.asBytes(&record);
            _ = linux.write(fds[1], bytes.ptr, bytes.len);
        } else |_| {}
        std.process.exit(0);
    }

    _ = linux.close(fds[1]);
    var record: Measurement = undefined;
    const bytes = std.mem.asBytes(&record);
    var filled: usize = 0;
    while (filled < bytes.len) {
        const rc = linux.read(fds[0], bytes.ptr + filled, bytes.len - filled);
        if (linux.errno(rc) != .SUCCESS) break;
        if (rc == 0) break;
        filled += rc;
    }
    _ = linux.close(fds[0]);
    var status: u32 = 0;
    _ = linux.waitpid(@intCast(child), &status, 0);

    if (status != 0) return error.ChildCrashed;
    if (filled != bytes.len) return null;
    return record;
}

fn measuredNothing(record: Measurement) bool {
    if (record.failed_step == Measurement.no_failure) return false;
    const step = std.enums.fromInt(Step, record.failed_step) orelse return false;
    return switch (step) {
        .dummy_create => record.failed_errno == @intFromEnum(linux.E.OPNOTSUPP),
        .open_socket => true,
        .bind_socket,
        .send,
        .receive,
        .loopback_up,
        .device_index,
        .address4_add,
        .address6_add,
        .device_up,
        .route4_add,
        .route6_add,
        .link_read,
        .address_read,
        .route_read,
        => false,
    };
}

test "the created link is a dummy and nothing else" {
    try testing.expectEqualStrings("dummy", link_kind);

    var buffer: [max_request]u8 = undefined;
    const length = buildDummyLink(&buffer, 7);
    var messages = Messages{ .bytes = buffer[0..length] };
    const message = messages.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(rtm_newlink, message.kind);
    try testing.expectEqual(@as(u32, 7), message.sequence);

    const attributes = Attributes{ .bytes = message.payload(16) };
    const name = attributes.find(ifla_ifname) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings(device_name, std.mem.sliceTo(name, 0));

    const info = attributes.find(ifla_linkinfo) orelse return error.TestUnexpectedResult;
    const inside = Attributes{ .bytes = info };
    const kind = inside.find(ifla_info_kind) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("dummy", std.mem.sliceTo(kind, 0));
}

test "the default route has no next hop" {
    inline for (.{ af_inet, af_inet6 }) |family| {
        var buffer: [max_request]u8 = undefined;
        const length = buildDefaultRoute(&buffer, family, 3, 11);
        var messages = Messages{ .bytes = buffer[0..length] };
        const message = messages.next() orelse return error.TestUnexpectedResult;
        try testing.expectEqual(rtm_newroute, message.kind);

        try testing.expectEqual(family, message.body[0]);
        try testing.expectEqual(@as(u8, 0), message.body[1]);
        try testing.expectEqual(rt_table_main, message.body[4]);
        try testing.expectEqual(rtn_unicast, message.body[7]);

        const attributes = Attributes{ .bytes = message.payload(12) };
        const oif = attributes.find(rta_oif) orelse return error.TestUnexpectedResult;
        try testing.expectEqual(@as(u32, 3), readU32(oif));
        try testing.expectEqual(@as(?[]const u8, null), attributes.find(rta_gateway));
    }
}

test "bringing a link up changes that one flag and no other" {
    var buffer: [max_request]u8 = undefined;
    const length = buildLinkUp(&buffer, loopback_name, 2);
    var messages = Messages{ .bytes = buffer[0..length] };
    const message = messages.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(rtm_setlink, message.kind);

    try testing.expectEqual(iff_up, std.mem.readInt(u32, message.body[8..12], .little));
    try testing.expectEqual(iff_up, std.mem.readInt(u32, message.body[12..16], .little));

    const attributes = Attributes{ .bytes = message.payload(16) };
    const name = attributes.find(ifla_ifname) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings(loopback_name, std.mem.sliceTo(name, 0));
}

test "an address carries the same value as its own local and peer" {
    var buffer: [max_request]u8 = undefined;
    const length = buildAddress(&buffer, .{
        .family = af_inet,
        .prefix = prefix4,
        .flags = 0,
        .index = 9,
        .bytes = &address4,
    }, 5);
    var messages = Messages{ .bytes = buffer[0..length] };
    const message = messages.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(rtm_newaddr, message.kind);

    try testing.expectEqual(af_inet, message.body[0]);
    try testing.expectEqual(prefix4, message.body[1]);
    try testing.expectEqual(@as(u32, 9), std.mem.readInt(u32, message.body[4..8], .little));

    const attributes = Attributes{ .bytes = message.payload(8) };
    const local = attributes.find(ifa_local) orelse return error.TestUnexpectedResult;
    const peer = attributes.find(ifa_address) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &address4, local);
    try testing.expectEqualSlices(u8, &address4, peer);
}

fn failedAt(step: Step, errno: i32) Measurement {
    var record = std.mem.zeroes(Measurement);
    record.failed_step = @intFromEnum(step);
    record.failed_errno = errno;
    return record;
}

test "a refusal that is not a missing module fails the test rather than skipping it" {
    try testing.expect(measuredNothing(failedAt(.dummy_create, @intFromEnum(linux.E.OPNOTSUPP))));
    try testing.expect(measuredNothing(failedAt(.open_socket, @intFromEnum(linux.E.PROTONOSUPPORT))));

    try testing.expect(!measuredNothing(failedAt(.route4_add, @intFromEnum(linux.E.OPNOTSUPP))));
    try testing.expect(!measuredNothing(failedAt(.address6_add, @intFromEnum(linux.E.AFNOSUPPORT))));
    try testing.expect(!measuredNothing(failedAt(.device_up, @intFromEnum(linux.E.NODEV))));
    try testing.expect(!measuredNothing(failedAt(.loopback_up, @intFromEnum(linux.E.PERM))));
    try testing.expect(!measuredNothing(failedAt(.dummy_create, @intFromEnum(linux.E.EXIST))));

    var clean = std.mem.zeroes(Measurement);
    clean.failed_step = Measurement.no_failure;
    try testing.expect(!measuredNothing(clean));

    try testing.expectEqual(error.KernelModuleMissing, classify(.dummy_create, @intFromEnum(linux.E.OPNOTSUPP)));
    try testing.expectEqual(error.Refused, classify(.route4_add, @intFromEnum(linux.E.OPNOTSUPP)));
    try testing.expectEqual(error.Refused, classify(.address6_add, @intFromEnum(linux.E.AFNOSUPPORT)));
    try testing.expectEqual(error.NotPermitted, classify(.loopback_up, @intFromEnum(linux.E.PERM)));
    try testing.expectEqual(error.Refused, classify(.dummy_create, @intFromEnum(linux.E.EXIST)));
}

test "setup reads back the interfaces it brought up" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.failed_step);

    try testing.expectEqual(@as(u32, 1), record.loopback_index);
    try testing.expectEqual(iff_up, record.loopback_flags & iff_up);

    try testing.expect(record.device_index > 1);
    try testing.expectEqual(iff_up, record.device_flags & iff_up);
    try testing.expectEqual(iff_running, record.device_flags & iff_running);
    try testing.expectEqualStrings("dummy", std.mem.sliceTo(&record.device_kind, 0));
}

test "setup reads back the addresses it asked for" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.failed_step);

    try testing.expectEqual(@as(u32, 1), record.address4_found);
    try testing.expectEqual(@as(u32, 4), record.address4_length);
    try testing.expectEqualSlices(u8, &address4, record.address4_bytes[0..4]);
    try testing.expectEqual(@as(u32, prefix4), record.address4_prefix);

    try testing.expectEqual(@as(u32, 1), record.address6_found);
    try testing.expectEqual(@as(u32, 16), record.address6_length);
    try testing.expectEqualSlices(u8, &address6, record.address6_bytes[0..16]);
    try testing.expectEqual(@as(u32, prefix6), record.address6_prefix);
}

test "setup reads back a default route that points at the blackhole" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.failed_step);

    inline for (.{
        .{ record.route4_found, record.route4_dst_len, record.route4_table, record.route4_kind, record.route4_oif, record.route4_gateway },
        .{ record.route6_found, record.route6_dst_len, record.route6_table, record.route6_kind, record.route6_oif, record.route6_gateway },
    }) |route| {
        try testing.expectEqual(@as(u32, 1), route[0]);
        try testing.expectEqual(@as(u32, 0), route[1]);
        try testing.expectEqual(@as(u32, rt_table_main), route[2]);
        try testing.expectEqual(@as(u32, rtn_unicast), route[3]);
        try testing.expectEqual(record.device_index, route[4]);
        try testing.expectEqual(@as(u32, 0), route[5]);
    }
}

test "the blackhole takes a connection at the socket layer and never completes one" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.failed_step);

    try testing.expectEqual(@intFromEnum(linux.E.NETUNREACH), record.before4_errno);
    try testing.expectEqual(@intFromEnum(linux.E.ADDRNOTAVAIL), record.before6_errno);

    try testing.expectEqual(@intFromEnum(linux.E.INPROGRESS), record.after4_errno);
    try testing.expectEqual(@intFromEnum(linux.E.INPROGRESS), record.after6_errno);

    try testing.expectEqual(@as(u32, 0), record.completed4);
    try testing.expectEqual(@as(u32, 0), record.completed6);
    try testing.expectEqual(@as(i32, 0), record.so_error4);
    try testing.expectEqual(@as(i32, 0), record.so_error6);

    try testing.expect(record.tx_packets > 0);
    try testing.expectEqual(@as(u64, 0), record.rx_packets);
}
