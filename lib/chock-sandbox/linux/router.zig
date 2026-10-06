//! The userspace half of the network router: the TCP relay every outbound
//! connection is redirected to, and the resolver beside it. Linux only.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

const nftables = @import("nftables.zig");
const netns = @import("netns.zig");

const namespace = @import("namespace.zig");

pub const relay_port: u16 = nftables.relay_port;

pub const resolver_port: u16 = 53;

pub const max_links: usize = 32;

pub const link_buffer_bytes: usize = 4096;

pub const name_capacity: usize = 255;

pub const name_table_capacity: usize = 64;

pub const query_capacity: usize = 1500;

pub const Address = nftables.Address;

pub const Destination = struct {
    address: Address,
    port: u16,

    pub fn equals(self: Destination, other: Destination) bool {
        return self.port == other.port and addressesEqual(self.address, other.address);
    }
};

pub const RecordKind = enum(u16) {
    a = 1,
    aaaa = 28,

    pub fn family(self: RecordKind) std.meta.Tag(Address) {
        return switch (self) {
            .a => .ipv4,
            .aaaa => .ipv6,
        };
    }
};

pub const Policy = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Verdict = enum { permit, refuse };

    pub const VTable = struct {
        name: *const fn (ptr: *anyopaque, name: []const u8, kind: RecordKind) Verdict,
        connect: *const fn (ptr: *anyopaque, name: ?[]const u8, dest: Destination) Verdict,
    };

    pub fn askName(self: Policy, name: []const u8, kind: RecordKind) Verdict {
        return self.vtable.name(self.ptr, name, kind);
    }

    pub fn askConnect(self: Policy, name: ?[]const u8, dest: Destination) Verdict {
        return self.vtable.connect(self.ptr, name, dest);
    }
};

pub const Host = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const ResolveError = error{
        NotResolved,
    };

    pub const AllowError = error{
        NotAllowed,
    };

    pub const OpenError = error{
        NotConnected,
    };

    pub const VTable = struct {
        resolve: *const fn (ptr: *anyopaque, name: []const u8, kind: RecordKind) ResolveError!Address,
        allow: *const fn (ptr: *anyopaque, address: Address, timeout_ms: u64) AllowError!void,
        open: *const fn (ptr: *anyopaque, dest: Destination) OpenError!posix.fd_t,
    };

    pub fn resolve(self: Host, name: []const u8, kind: RecordKind) ResolveError!Address {
        return self.vtable.resolve(self.ptr, name, kind);
    }

    pub fn allow(self: Host, address: Address, timeout_ms: u64) AllowError!void {
        return self.vtable.allow(self.ptr, address, timeout_ms);
    }

    pub fn open(self: Host, dest: Destination) OpenError!posix.fd_t {
        return self.vtable.open(self.ptr, dest);
    }
};

pub const Step = enum {
    relay_socket,
    relay_dual_stack,
    relay_reuse,
    relay_bind,
    relay_listen,
    resolver_socket,
    resolver_bind,
    poll,
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
    PrivilegedPort,
    AddressInUse,
    NotPermitted,
    Refused,
    PollFailed,
};

fn note(diag: ?*?Diagnostic, step: Step, errno: i32) void {
    if (diag) |slot| slot.* = .{ .step = step, .errno = errno };
}

fn classify(step: Step, errno: i32) Error {
    if (errno == @intFromEnum(linux.E.ADDRINUSE)) return error.AddressInUse;
    if (errno == @intFromEnum(linux.E.ACCES)) {
        return switch (step) {
            .resolver_bind => error.PrivilegedPort,
            else => error.NotPermitted,
        };
    }
    if (errno == @intFromEnum(linux.E.PERM)) return error.NotPermitted;
    return error.Refused;
}

const so_original_dst: u32 = 80;
const ip6t_so_original_dst: u32 = 80;

pub const OriginalError = error{
    NoOriginalDestination,
};

pub fn originalDestination(fd: posix.fd_t) OriginalError!Destination {
    var raw: [@sizeOf(linux.sockaddr.in6)]u8 = undefined;

    var length: posix.socklen_t = @sizeOf(linux.sockaddr.in);
    const v4 = linux.getsockopt(fd, linux.SOL.IP, so_original_dst, &raw, &length);
    if (linux.errno(v4) == .SUCCESS) {
        if (decodeOriginal4(raw[0..@min(length, raw.len)])) |dest| return dest;
    }

    length = @sizeOf(linux.sockaddr.in6);
    const v6 = linux.getsockopt(fd, linux.SOL.IPV6, ip6t_so_original_dst, &raw, &length);
    if (linux.errno(v6) == .SUCCESS) {
        if (decodeOriginal6(raw[0..@min(length, raw.len)])) |dest| return dest;
    }

    return error.NoOriginalDestination;
}

fn decodeOriginal4(raw: []const u8) ?Destination {
    if (raw.len < @sizeOf(linux.sockaddr.in)) return null;
    if (std.mem.readInt(u16, raw[0..2], .little) != linux.AF.INET) return null;
    return .{
        .port = std.mem.readInt(u16, raw[2..4], .big),
        .address = .{ .ipv4 = raw[4..8].* },
    };
}

fn decodeOriginal6(raw: []const u8) ?Destination {
    if (raw.len < @sizeOf(linux.sockaddr.in6)) return null;
    if (std.mem.readInt(u16, raw[0..2], .little) != linux.AF.INET6) return null;
    const bytes: [16]u8 = raw[8..24].*;
    const port = std.mem.readInt(u16, raw[2..4], .big);
    if (std.mem.eql(u8, bytes[0..12], &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
        return .{ .port = port, .address = .{ .ipv4 = bytes[12..16].* } };
    }
    return .{ .port = port, .address = .{ .ipv6 = bytes } };
}

fn addressesEqual(left: Address, right: Address) bool {
    return switch (left) {
        .ipv4 => |bytes| switch (right) {
            .ipv4 => |other| std.mem.eql(u8, &bytes, &other),
            .ipv6 => false,
        },
        .ipv6 => |bytes| switch (right) {
            .ipv4 => false,
            .ipv6 => |other| std.mem.eql(u8, &bytes, &other),
        },
    };
}

pub const NameTable = struct {
    entries: [name_table_capacity]Entry = @splat(.{}),

    const Entry = struct {
        address: Address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
        name: [name_capacity]u8 = @splat(0),
        name_len: u8 = 0,
        deadline_ms: i64 = 0,
        live: bool = false,
    };

    pub fn remember(
        self: *NameTable,
        address: Address,
        name: []const u8,
        now_ms: i64,
        lifetime_ms: u64,
    ) void {
        std.debug.assert(name.len <= name_capacity);

        const slot = self.slotFor(address, now_ms);
        slot.address = address;
        slot.name_len = @intCast(name.len);
        @memcpy(slot.name[0..name.len], name);
        slot.deadline_ms = now_ms +| @as(i64, @intCast(@min(lifetime_ms, std.math.maxInt(i64))));
        slot.live = true;
    }

    pub fn lookup(self: *const NameTable, address: Address, now_ms: i64) ?[]const u8 {
        for (&self.entries) |*entry| {
            if (!entry.live) continue;
            if (entry.deadline_ms <= now_ms) continue;
            if (!addressesEqual(entry.address, address)) continue;
            return entry.name[0..entry.name_len];
        }
        return null;
    }

    pub fn live(self: *const NameTable, now_ms: i64) usize {
        var total: usize = 0;
        for (&self.entries) |*entry| {
            if (entry.live and entry.deadline_ms > now_ms) total += 1;
        }
        return total;
    }

    fn slotFor(self: *NameTable, address: Address, now_ms: i64) *Entry {
        var free: ?*Entry = null;
        var soonest: *Entry = &self.entries[0];
        for (&self.entries) |*entry| {
            if (entry.live and entry.deadline_ms > now_ms) {
                if (addressesEqual(entry.address, address)) return entry;
                if (entry.deadline_ms < soonest.deadline_ms or
                    !(soonest.live and soonest.deadline_ms > now_ms))
                {
                    soonest = entry;
                }
            } else if (free == null) {
                free = entry;
            }
        }
        return free orelse soonest;
    }
};

const dns_header_bytes: usize = 12;
const class_internet: u16 = 1;

pub const Rcode = enum(u4) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
    name_error = 3,
    not_implemented = 4,
    refused = 5,
};

pub const Query = struct {
    id: u16,
    opcode: u4,
    recursion_desired: bool,
    qtype: u16,
    qclass: u16,
    name_len: u8,
    name: [name_capacity]u8,
    question_end: usize,

    pub fn text(self: *const Query) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn kind(self: *const Query) ?RecordKind {
        return std.enums.fromInt(RecordKind, self.qtype);
    }
};

pub const ParseError = error{
    NotAQuery,
    NotOneQuestion,
    Malformed,
};

// The only DNS parsing in this file. Everything past the question is copied or dropped, never interpreted.
pub fn parseQuery(bytes: []const u8) ParseError!Query {
    if (bytes.len < dns_header_bytes) return error.Malformed;

    const flags = std.mem.readInt(u16, bytes[2..4], .big);
    if (flags & 0x8000 != 0) return error.NotAQuery;
    if (std.mem.readInt(u16, bytes[4..6], .big) != 1) return error.NotOneQuestion;

    var query: Query = undefined;
    query.id = std.mem.readInt(u16, bytes[0..2], .big);
    query.opcode = @truncate((flags >> 11) & 0xf);
    query.recursion_desired = flags & 0x0100 != 0;

    var at: usize = dns_header_bytes;
    var used: usize = 0;
    while (true) {
        if (at >= bytes.len) return error.Malformed;
        const length = bytes[at];
        if (length & 0xc0 != 0) return error.Malformed;
        at += 1;
        if (length == 0) break;
        if (at + length > bytes.len) return error.Malformed;
        if (used != 0) {
            if (used + 1 > name_capacity) return error.Malformed;
            query.name[used] = '.';
            used += 1;
        }
        if (used + length > name_capacity) return error.Malformed;
        for (bytes[at..][0..length], 0..) |byte, index| {
            query.name[used + index] = std.ascii.toLower(byte);
        }
        used += length;
        at += length;
    }
    if (used == 0) return error.Malformed;

    query.name_len = @intCast(used);
    if (at + 4 > bytes.len) return error.Malformed;
    query.qtype = std.mem.readInt(u16, bytes[at..][0..2], .big);
    query.qclass = std.mem.readInt(u16, bytes[at + 2 ..][0..2], .big);
    query.question_end = at + 4;
    return query;
}

pub const Answer = struct {
    kind: RecordKind,
    address: Address,
};

pub fn buildReply(
    out: []u8,
    source: []const u8,
    query: *const Query,
    rcode: Rcode,
    answer: ?Answer,
    ttl_s: u32,
) ?usize {
    std.debug.assert(query.question_end <= source.len);

    const record: []const u8 = if (answer) |found| switch (found.address) {
        .ipv4 => |*bytes| bytes,
        .ipv6 => |*bytes| bytes,
    } else &.{};
    if (answer) |found| {
        std.debug.assert(found.kind.family() == std.meta.activeTag(found.address));
    }

    const answer_bytes: usize = if (answer == null) 0 else 2 + 2 + 2 + 4 + 2 + record.len;
    const total = query.question_end + answer_bytes;
    if (out.len < total) return null;

    @memcpy(out[0..query.question_end], source[0..query.question_end]);

    var flags: u16 = 0x8000 | @as(u16, @intFromEnum(rcode));
    flags |= @as(u16, query.opcode) << 11;
    if (query.recursion_desired) flags |= 0x0100;
    flags |= 0x0080;
    std.mem.writeInt(u16, out[2..4], flags, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], if (answer == null) 0 else 1, .big);
    std.mem.writeInt(u16, out[8..10], 0, .big);
    std.mem.writeInt(u16, out[10..12], 0, .big);

    if (answer) |found| {
        var at = query.question_end;
        out[at] = 0xc0;
        out[at + 1] = 0x0c;
        at += 2;
        std.mem.writeInt(u16, out[at..][0..2], @intFromEnum(found.kind), .big);
        at += 2;
        std.mem.writeInt(u16, out[at..][0..2], class_internet, .big);
        at += 2;
        std.mem.writeInt(u32, out[at..][0..4], ttl_s, .big);
        at += 4;
        std.mem.writeInt(u16, out[at..][0..2], @intCast(record.len), .big);
        at += 2;
        @memcpy(out[at..][0..record.len], record);
        at += record.len;
        std.debug.assert(at == total);
    }
    return total;
}

pub fn buildFormatError(out: []u8, source: []const u8) ?usize {
    if (source.len < dns_header_bytes or out.len < dns_header_bytes) return null;
    @memset(out[0..dns_header_bytes], 0);
    @memcpy(out[0..2], source[0..2]);
    const flags: u16 = 0x8000 | 0x0080 | @as(u16, @intFromEnum(Rcode.format_error));
    std.mem.writeInt(u16, out[2..4], flags, .big);
    return dns_header_bytes;
}

pub const Counts = struct {
    accepted: u64 = 0,
    without_destination: u64 = 0,
    refused_destinations: u64 = 0,
    without_link: u64 = 0,
    without_upstream: u64 = 0,
    linked: u64 = 0,
    closed: u64 = 0,

    queries: u64 = 0,
    answered: u64 = 0,
    refused_names: u64 = 0,
    refused_types: u64 = 0,
    empty_answers: u64 = 0,
    allow_failures: u64 = 0,
    malformed_queries: u64 = 0,
};

pub const Options = struct {
    policy: Policy,
    host: Host,
    resolver_address: Address = .{ .ipv4 = netns.address4 },
    allow_timeout_ms: u64 = nftables.default_timeout_ms,
    answer_ttl_s: u32 = 10,
};

pub const Router = struct {
    relay_fd: posix.fd_t,
    resolver_fd: posix.fd_t,
    policy: Policy,
    host: Host,
    allow_timeout_ms: u64,
    answer_ttl_s: u32,
    names: NameTable,
    links: [max_links]Link,
    counts: Counts,

    pub fn open(self: *Router, options: Options, diag: ?*?Diagnostic) Error!void {
        std.debug.assert(@as(u64, options.answer_ttl_s) * 1000 < options.allow_timeout_ms);
        std.debug.assert(options.allow_timeout_ms > 0);

        const relay_fd = try openRelay(diag);
        errdefer _ = linux.close(relay_fd);
        const resolver_fd = try openResolver(options.resolver_address, diag);

        self.relay_fd = relay_fd;
        self.resolver_fd = resolver_fd;
        self.policy = options.policy;
        self.host = options.host;
        self.allow_timeout_ms = options.allow_timeout_ms;
        self.answer_ttl_s = options.answer_ttl_s;
        self.names = .{};
        self.counts = .{};
        for (&self.links) |*link| link.live = false;
    }

    pub fn close(self: *Router) void {
        for (&self.links) |*link| {
            if (link.live) self.release(link);
        }
        if (self.relay_fd >= 0) _ = linux.close(self.relay_fd);
        self.relay_fd = -1;
        _ = linux.close(self.resolver_fd);
        self.resolver_fd = -1;
    }

    pub fn pendingBytes(self: *const Router) usize {
        var total: usize = 0;
        for (&self.links) |*link| {
            if (!link.live) continue;
            total += link.out_bound.pending() + link.in_bound.pending();
        }
        return total;
    }

    pub fn stopListening(self: *Router) void {
        if (self.relay_fd < 0) return;
        _ = linux.close(self.relay_fd);
        self.relay_fd = -1;
    }

    pub fn step(self: *Router, now_ms: i64, timeout_ms: i32, diag: ?*?Diagnostic) Error!void {
        var fds: [2 + max_links * 2]posix.pollfd = undefined;
        var owners: [2 + max_links * 2]usize = undefined;
        var sides: [2 + max_links * 2]Side = undefined;

        fds[0] = .{ .fd = self.relay_fd, .events = posix.POLL.IN, .revents = 0 };
        fds[1] = .{ .fd = self.resolver_fd, .events = posix.POLL.IN, .revents = 0 };
        var used: usize = 2;
        for (&self.links, 0..) |*link, index| {
            if (!link.live) continue;
            inline for (.{ Side.inside, Side.outside }) |side| {
                const events = link.events(side);
                if (events != 0) {
                    fds[used] = .{ .fd = link.descriptor(side), .events = events, .revents = 0 };
                    owners[used] = index;
                    sides[used] = side;
                    used += 1;
                }
            }
        }

        _ = posix.poll(fds[0..used], timeout_ms) catch |err| {
            note(diag, .poll, switch (err) {
                error.SystemResources => @intFromEnum(linux.E.NOMEM),
                error.NetworkDown => @intFromEnum(linux.E.NETDOWN),
                else => 0,
            });
            return error.PollFailed;
        };

        if (fds[0].revents & posix.POLL.IN != 0) self.accept(now_ms);
        if (fds[1].revents & posix.POLL.IN != 0) self.serveQuery(now_ms);
        for (fds[2..used], owners[2..used], sides[2..used]) |entry, index, side| {
            self.links[index].service(side, entry.revents);
        }
        for (&self.links) |*link| {
            if (link.live and link.finished()) self.release(link);
        }
    }

    pub fn run(self: *Router, io: std.Io, diag: ?*?Diagnostic) Error!noreturn {
        while (true) {
            const now = std.Io.Timestamp.now(io, .boot).toMilliseconds();
            try self.step(now, -1, diag);
        }
    }

    // Order matters: the policy is asked before anything is dialled, so a refused destination is never reached.
    fn accept(self: *Router, now_ms: i64) void {
        const rc = linux.accept4(self.relay_fd, null, null, linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC);
        if (linux.errno(rc) != .SUCCESS) return;
        const inside: posix.fd_t = @intCast(rc);
        self.counts.accepted += 1;

        const dest = originalDestination(inside) catch {
            self.counts.without_destination += 1;
            _ = linux.close(inside);
            return;
        };

        const name = self.names.lookup(dest.address, now_ms);
        if (self.policy.askConnect(name, dest) == .refuse) {
            self.counts.refused_destinations += 1;
            _ = linux.close(inside);
            return;
        }

        const link = self.freeLink() orelse {
            self.counts.without_link += 1;
            _ = linux.close(inside);
            return;
        };

        const outside = self.host.open(dest) catch {
            self.counts.without_upstream += 1;
            _ = linux.close(inside);
            return;
        };
        makeNonBlocking(outside);

        link.* = .{ .inside = inside, .outside = outside, .live = true };
        self.counts.linked += 1;
    }

    // The address goes into the kernel's allow set before the answer leaves, or the first connection would race it.
    fn serveQuery(self: *Router, now_ms: i64) void {
        var bytes: [query_capacity]u8 = undefined;
        var peer: linux.sockaddr.storage = undefined;
        var peer_len: posix.socklen_t = @sizeOf(linux.sockaddr.storage);
        const rc = linux.recvfrom(self.resolver_fd, &bytes, bytes.len, 0, @ptrCast(&peer), &peer_len);
        if (linux.errno(rc) != .SUCCESS) return;
        const source = bytes[0..rc];
        self.counts.queries += 1;

        var out: [query_capacity]u8 = undefined;
        const query = parseQuery(source) catch {
            self.counts.malformed_queries += 1;
            if (buildFormatError(&out, source)) |length| {
                self.reply(out[0..length], &peer, peer_len);
            }
            return;
        };

        const kind = query.kind();
        if (kind == null or query.qclass != class_internet) {
            self.counts.refused_types += 1;
            self.refuse(&out, source, &query, .refused, &peer, peer_len);
            return;
        }

        if (self.policy.askName(query.text(), kind.?) == .refuse) {
            self.counts.refused_names += 1;
            self.refuse(&out, source, &query, .refused, &peer, peer_len);
            return;
        }

        const address = self.host.resolve(query.text(), kind.?) catch {
            self.counts.empty_answers += 1;
            self.refuse(&out, source, &query, .no_error, &peer, peer_len);
            return;
        };

        self.host.allow(address, self.allow_timeout_ms) catch {
            self.counts.allow_failures += 1;
            self.refuse(&out, source, &query, .server_failure, &peer, peer_len);
            return;
        };
        self.names.remember(address, query.text(), now_ms, self.allow_timeout_ms);

        if (buildReply(&out, source, &query, .no_error, .{
            .kind = kind.?,
            .address = address,
        }, self.answer_ttl_s)) |length| {
            self.counts.answered += 1;
            self.reply(out[0..length], &peer, peer_len);
        }
    }

    fn refuse(
        self: *Router,
        out: []u8,
        source: []const u8,
        query: *const Query,
        rcode: Rcode,
        peer: *const linux.sockaddr.storage,
        peer_len: posix.socklen_t,
    ) void {
        if (buildReply(out, source, query, rcode, null, self.answer_ttl_s)) |length| {
            self.reply(out[0..length], peer, peer_len);
        }
    }

    fn reply(
        self: *Router,
        bytes: []const u8,
        peer: *const linux.sockaddr.storage,
        peer_len: posix.socklen_t,
    ) void {
        _ = linux.sendto(self.resolver_fd, bytes.ptr, bytes.len, linux.MSG.NOSIGNAL, @ptrCast(peer), peer_len);
    }

    fn freeLink(self: *Router) ?*Link {
        for (&self.links) |*link| {
            if (!link.live) return link;
        }
        return null;
    }

    fn release(self: *Router, link: *Link) void {
        _ = linux.close(link.inside);
        _ = linux.close(link.outside);
        link.live = false;
        self.counts.closed += 1;
    }
};

const Side = enum { inside, outside };

const Link = struct {
    inside: posix.fd_t = -1,
    outside: posix.fd_t = -1,
    out_bound: Buffer = .{},
    in_bound: Buffer = .{},
    inside_done: bool = false,
    outside_done: bool = false,
    inside_shut: bool = false,
    outside_shut: bool = false,
    live: bool = false,

    fn descriptor(self: *const Link, side: Side) posix.fd_t {
        return switch (side) {
            .inside => self.inside,
            .outside => self.outside,
        };
    }

    fn intake(self: *Link, side: Side) *Buffer {
        return switch (side) {
            .inside => &self.out_bound,
            .outside => &self.in_bound,
        };
    }

    fn outflow(self: *Link, side: Side) *Buffer {
        return switch (side) {
            .inside => &self.in_bound,
            .outside => &self.out_bound,
        };
    }

    fn done(self: *const Link, side: Side) bool {
        return switch (side) {
            .inside => self.inside_done,
            .outside => self.outside_done,
        };
    }

    fn events(self: *Link, side: Side) i16 {
        var wanted: i16 = 0;
        if (!self.done(side) and self.intake(side).room() > 0) wanted |= posix.POLL.IN;
        if (self.outflow(side).pending() > 0) wanted |= posix.POLL.OUT;
        return wanted;
    }

    fn service(self: *Link, side: Side, revents: i16) void {
        if (revents == 0) return;
        if (revents & (posix.POLL.ERR | posix.POLL.NVAL) != 0) {
            self.inside_done = true;
            self.outside_done = true;
            self.out_bound.clear();
            self.in_bound.clear();
            return;
        }

        if (revents & (posix.POLL.IN | posix.POLL.HUP) != 0) self.readFrom(side);
        if (revents & posix.POLL.OUT != 0) self.writeTo(side);
        self.halfClose();
    }

    fn readFrom(self: *Link, side: Side) void {
        const into = self.intake(side);
        if (into.room() == 0) return;
        const got = posix.read(self.descriptor(side), into.free()) catch |err| switch (err) {
            error.WouldBlock => return,
            else => {
                self.setDone(side);
                return;
            },
        };
        if (got == 0) {
            self.setDone(side);
            return;
        }
        into.end += got;
    }

    fn writeTo(self: *Link, side: Side) void {
        const from = self.outflow(side);
        const pending = from.pending();
        if (pending == 0) return;
        const rc = linux.sendto(
            self.descriptor(side),
            from.bytes[from.start..].ptr,
            pending,
            linux.MSG.NOSIGNAL,
            null,
            0,
        );
        switch (linux.errno(rc)) {
            .SUCCESS => {
                from.start += rc;
                from.compact();
            },
            .AGAIN, .INTR => {},
            else => {
                from.clear();
                self.setDone(switch (side) {
                    .inside => .outside,
                    .outside => .inside,
                });
                self.setDone(side);
            },
        }
    }

    fn halfClose(self: *Link) void {
        if (self.inside_done and self.out_bound.pending() == 0 and !self.outside_shut) {
            _ = linux.shutdown(self.outside, linux.SHUT.WR);
            self.outside_shut = true;
        }
        if (self.outside_done and self.in_bound.pending() == 0 and !self.inside_shut) {
            _ = linux.shutdown(self.inside, linux.SHUT.WR);
            self.inside_shut = true;
        }
    }

    fn finished(self: *const Link) bool {
        return self.inside_done and self.outside_done and
            self.out_bound.pending() == 0 and self.in_bound.pending() == 0;
    }

    fn setDone(self: *Link, side: Side) void {
        switch (side) {
            .inside => self.inside_done = true,
            .outside => self.outside_done = true,
        }
    }
};

const Buffer = struct {
    bytes: [link_buffer_bytes]u8 = @splat(0),
    start: usize = 0,
    end: usize = 0,

    fn pending(self: *const Buffer) usize {
        return self.end - self.start;
    }

    fn room(self: *const Buffer) usize {
        return self.bytes.len - self.end;
    }

    fn free(self: *Buffer) []u8 {
        return self.bytes[self.end..];
    }

    fn clear(self: *Buffer) void {
        self.start = 0;
        self.end = 0;
    }

    fn compact(self: *Buffer) void {
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        }
    }
};

fn openRelay(diag: ?*?Diagnostic) Error!posix.fd_t {
    const rc = linux.socket(
        linux.AF.INET6,
        linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC,
        0,
    );
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |e| {
            note(diag, .relay_socket, @intFromEnum(e));
            return classify(.relay_socket, @intFromEnum(e));
        },
    }
    const fd: posix.fd_t = @intCast(rc);
    errdefer _ = linux.close(fd);

    const off = std.mem.toBytes(@as(c_int, 0));
    posix.setsockopt(fd, linux.SOL.IPV6, linux.IPV6.V6ONLY, &off) catch {
        note(diag, .relay_dual_stack, @intFromEnum(linux.E.INVAL));
        return error.Refused;
    };

    // Avoids waiting out a previous socket's lingering close on restart.
    const on = std.mem.toBytes(@as(c_int, 1));
    posix.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, &on) catch {
        note(diag, .relay_reuse, @intFromEnum(linux.E.INVAL));
        return error.Refused;
    };

    var any: linux.sockaddr.in6 = .{
        .family = linux.AF.INET6,
        .port = std.mem.nativeToBig(u16, relay_port),
        .flowinfo = 0,
        .addr = @splat(0),
        .scope_id = 0,
    };
    switch (linux.errno(linux.bind(fd, @ptrCast(&any), @sizeOf(linux.sockaddr.in6)))) {
        .SUCCESS => {},
        else => |e| {
            note(diag, .relay_bind, @intFromEnum(e));
            return classify(.relay_bind, @intFromEnum(e));
        },
    }
    switch (linux.errno(linux.listen(fd, 64))) {
        .SUCCESS => {},
        else => |e| {
            note(diag, .relay_listen, @intFromEnum(e));
            return classify(.relay_listen, @intFromEnum(e));
        },
    }
    return fd;
}

fn openResolver(address: Address, diag: ?*?Diagnostic) Error!posix.fd_t {
    const family: u32 = switch (address) {
        .ipv4 => linux.AF.INET,
        .ipv6 => linux.AF.INET6,
    };
    const rc = linux.socket(
        family,
        linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC,
        0,
    );
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |e| {
            note(diag, .resolver_socket, @intFromEnum(e));
            return classify(.resolver_socket, @intFromEnum(e));
        },
    }
    const fd: posix.fd_t = @intCast(rc);
    errdefer _ = linux.close(fd);

    const errno = switch (address) {
        .ipv4 => |bytes| blk: {
            var here: linux.sockaddr.in = .{
                .family = linux.AF.INET,
                .port = std.mem.nativeToBig(u16, resolver_port),
                .addr = @bitCast(bytes),
            };
            break :blk linux.errno(linux.bind(fd, @ptrCast(&here), @sizeOf(linux.sockaddr.in)));
        },
        .ipv6 => |bytes| blk: {
            var here: linux.sockaddr.in6 = .{
                .family = linux.AF.INET6,
                .port = std.mem.nativeToBig(u16, resolver_port),
                .flowinfo = 0,
                .addr = bytes,
                .scope_id = 0,
            };
            break :blk linux.errno(linux.bind(fd, @ptrCast(&here), @sizeOf(linux.sockaddr.in6)));
        },
    };
    switch (errno) {
        .SUCCESS => {},
        else => |e| {
            note(diag, .resolver_bind, @intFromEnum(e));
            return classify(.resolver_bind, @intFromEnum(e));
        },
    }
    return fd;
}

fn makeNonBlocking(fd: posix.fd_t) void {
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    if (linux.errno(flags) != .SUCCESS) return;
    var updated: linux.O = @bitCast(@as(u32, @truncate(flags)));
    updated.NONBLOCK = true;
    _ = linux.fcntl(fd, linux.F.SETFL, @as(usize, @as(u32, @bitCast(updated))));
}

const testing = std.testing;

const permitted_name = "registry.npmjs.test";
const refused_name = "metadata.evil.test";
const walled_name = "wall.npmjs.test";

const permitted_ipv4: [4]u8 = .{ 93, 184, 216, 34 };
const refused_ipv4: [4]u8 = .{ 203, 0, 113, 7 };
const walled_ipv4: [4]u8 = .{ 198, 51, 100, 9 };
const never_handed_ipv4: [4]u8 = .{ 10, 20, 30, 40 };

const permitted_port: u16 = 443;
const refused_port: u16 = 8443;

const timed_out: i32 = -1;

const probe_timeout_ms: u64 = 45_000;
const probe_ttl_s: u32 = 10;

const FakePolicy = struct {
    name_calls: u32 = 0,
    connect_calls: u32 = 0,
    last_name_known: bool = false,
    last_name_len: u8 = 0,
    last_name: [name_capacity]u8 = @splat(0),
    last_dest: Destination = .{ .address = .{ .ipv4 = .{ 0, 0, 0, 0 } }, .port = 0 },

    fn policy(self: *FakePolicy) Policy {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Policy.VTable{ .name = nameFn, .connect = connectFn };

    fn nameFn(ptr: *anyopaque, name: []const u8, kind: RecordKind) Policy.Verdict {
        _ = kind;
        const self: *FakePolicy = @ptrCast(@alignCast(ptr));
        self.name_calls += 1;
        if (std.mem.eql(u8, name, permitted_name)) return .permit;
        if (std.mem.eql(u8, name, walled_name)) return .permit;
        return .refuse;
    }

    fn connectFn(ptr: *anyopaque, name: ?[]const u8, dest: Destination) Policy.Verdict {
        const self: *FakePolicy = @ptrCast(@alignCast(ptr));
        self.connect_calls += 1;
        self.last_dest = dest;
        self.last_name_known = name != null;
        self.last_name_len = 0;
        if (name) |text| {
            self.last_name_len = @intCast(text.len);
            @memcpy(self.last_name[0..text.len], text);
        }
        return if (dest.port == permitted_port and
            addressesEqual(dest.address, .{ .ipv4 = permitted_ipv4 })) .permit else .refuse;
    }
};

const FakeHost = struct {
    session: nftables.Session,
    upstream: posix.fd_t,
    handed: bool = false,
    resolve_calls: u32 = 0,
    resolve_calls_for_refused: u32 = 0,
    allow_calls: u32 = 0,
    open_calls: u32 = 0,
    last_open: Destination = .{ .address = .{ .ipv4 = .{ 0, 0, 0, 0 } }, .port = 0 },

    fn host(self: *FakeHost) Host {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Host.VTable{ .resolve = resolveFn, .allow = allowFn, .open = openFn };

    fn resolveFn(ptr: *anyopaque, name: []const u8, kind: RecordKind) Host.ResolveError!Address {
        const self: *FakeHost = @ptrCast(@alignCast(ptr));
        self.resolve_calls += 1;
        if (std.mem.eql(u8, name, refused_name)) {
            self.resolve_calls_for_refused += 1;
            return .{ .ipv4 = refused_ipv4 };
        }
        if (kind != .a) return error.NotResolved;
        if (std.mem.eql(u8, name, permitted_name)) return .{ .ipv4 = permitted_ipv4 };
        if (std.mem.eql(u8, name, walled_name)) return .{ .ipv4 = walled_ipv4 };
        return error.NotResolved;
    }

    fn allowFn(ptr: *anyopaque, address: Address, timeout_ms: u64) Host.AllowError!void {
        const self: *FakeHost = @ptrCast(@alignCast(ptr));
        self.allow_calls += 1;
        if (addressesEqual(address, .{ .ipv4 = walled_ipv4 })) return error.NotAllowed;
        self.session.allow(address, timeout_ms, null) catch return error.NotAllowed;
    }

    fn openFn(ptr: *anyopaque, dest: Destination) Host.OpenError!posix.fd_t {
        const self: *FakeHost = @ptrCast(@alignCast(ptr));
        self.open_calls += 1;
        self.last_open = dest;
        if (self.handed) return error.NotConnected;
        self.handed = true;
        return self.upstream;
    }
};

fn buildQuery(out: []u8, id: u16, name: []const u8, qtype: u16) usize {
    std.mem.writeInt(u16, out[0..2], id, .big);
    std.mem.writeInt(u16, out[2..4], 0x0100, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], 0, .big);
    std.mem.writeInt(u16, out[8..10], 0, .big);
    std.mem.writeInt(u16, out[10..12], 0, .big);
    var at: usize = dns_header_bytes;
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| {
        out[at] = @intCast(label.len);
        at += 1;
        @memcpy(out[at..][0..label.len], label);
        at += label.len;
    }
    out[at] = 0;
    at += 1;
    std.mem.writeInt(u16, out[at..][0..2], qtype, .big);
    at += 2;
    std.mem.writeInt(u16, out[at..][0..2], class_internet, .big);
    at += 2;
    return at;
}

fn replyRcode(bytes: []const u8) u32 {
    return std.mem.readInt(u16, bytes[2..4], .big) & 0xf;
}

fn replyAnswerCount(bytes: []const u8) u32 {
    return std.mem.readInt(u16, bytes[6..8], .big);
}

const Record = struct {
    rtype: u16,
    ttl: u32,
    rdlength: u16,
    rdata: [16]u8,
};

fn readRecord(bytes: []const u8, question_end: usize) ?Record {
    if (bytes.len < question_end + 12) return null;
    var at = question_end + 2;
    const rtype = std.mem.readInt(u16, bytes[at..][0..2], .big);
    at += 4;
    const ttl = std.mem.readInt(u32, bytes[at..][0..4], .big);
    at += 4;
    const rdlength = std.mem.readInt(u16, bytes[at..][0..2], .big);
    at += 2;
    if (rdlength > 16 or bytes.len < at + rdlength) return null;
    var found = Record{ .rtype = rtype, .ttl = ttl, .rdlength = rdlength, .rdata = @splat(0) };
    @memcpy(found.rdata[0..rdlength], bytes[at..][0..rdlength]);
    return found;
}

fn nowMs() i64 {
    return std.Io.Timestamp.now(testing.io, .boot).toMilliseconds();
}

fn socketAddress4(address: [4]u8, port: u16) linux.sockaddr.in {
    return .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(address),
    };
}

fn pump(router: *Router, rounds: usize, now_ms: i64, timeout_ms: i32) void {
    var round: usize = 0;
    while (round < rounds) : (round += 1) {
        router.step(now_ms, timeout_ms, null) catch return;
    }
}

fn ask(
    router: *Router,
    client: posix.fd_t,
    server: *const linux.sockaddr.in,
    query: []const u8,
    out: []u8,
    now_ms: i64,
) usize {
    const sent = linux.sendto(client, query.ptr, query.len, 0, @ptrCast(server), @sizeOf(linux.sockaddr.in));
    if (linux.errno(sent) != .SUCCESS) return 0;
    router.step(now_ms, 1000, null) catch return 0;

    var waiting = [_]posix.pollfd{.{ .fd = client, .events = posix.POLL.IN, .revents = 0 }};
    const ready = posix.poll(&waiting, 1000) catch return 0;
    if (ready == 0) return 0;
    const got = linux.recvfrom(client, out.ptr, out.len, 0, null, null);
    if (linux.errno(got) != .SUCCESS) return 0;
    return got;
}

const Attempt = struct {
    fd: posix.fd_t,
    errno: i32,
    waited_ms: u64,
};

fn attemptConnect(address: [4]u8, port: u16, budget_ms: i32) Attempt {
    const started = nowMs();
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) {
        return .{ .fd = -1, .errno = @intFromEnum(linux.errno(rc)), .waited_ms = 0 };
    }
    const fd: posix.fd_t = @intCast(rc);
    var target = socketAddress4(address, port);
    var code: i32 = 0;
    switch (linux.errno(linux.connect(fd, @ptrCast(&target), @sizeOf(linux.sockaddr.in)))) {
        .SUCCESS => {},
        .INPROGRESS => {
            var waiting = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
            const ready = posix.poll(&waiting, budget_ms) catch 0;
            if (ready == 0) {
                code = timed_out;
            } else {
                var reason: i32 = 0;
                var length: posix.socklen_t = @sizeOf(i32);
                _ = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&reason), &length);
                code = reason;
            }
        },
        else => |e| code = @intFromEnum(e),
    }
    return .{ .fd = fd, .errno = code, .waited_ms = @intCast(nowMs() - started) };
}

fn readWithin(fd: posix.fd_t, into: []u8, budget_ms: i32) usize {
    var waiting = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    const ready = posix.poll(&waiting, budget_ms) catch return 0;
    if (ready == 0) return 0;
    const got = posix.read(fd, into) catch return 0;
    return got;
}

fn writeAll(fd: posix.fd_t, bytes: []const u8) void {
    _ = linux.sendto(fd, bytes.ptr, bytes.len, linux.MSG.NOSIGNAL, null, 0);
}

const Stage = enum(u32) {
    netns_configure,
    nftables_install,
    router_open,
};

const Measurement = extern struct {
    stage: u32,
    failed_step: u32,
    failed_errno: i32,

    permit_rcode: u32,
    permit_ancount: u32,
    permit_rtype: u32,
    permit_rdlength: u32,
    permit_ttl: u32,
    permit_rdata: [16]u8,
    permit_id: u32,
    permit_element_found: u32,
    permit_element_comment: u32,
    permit_element_timeout_ms: u64,

    empty_rcode: u32,
    empty_ancount: u32,

    refuse_rcode: u32,
    refuse_ancount: u32,
    refuse_element_found: u32,
    refuse_resolve_calls: u32,

    type_rcode: u32,
    type_ancount: u32,

    walled_rcode: u32,
    walled_ancount: u32,
    walled_element_found: u32,

    relay_errno: i32,
    relay_accepted: u64,
    relay_linked: u64,
    relay_family: u32,
    relay_port: u32,
    relay_address: [16]u8,
    relay_name_known: u32,
    relay_name_len: u32,
    relay_name: [name_capacity]u8,
    relay_open_calls: u32,
    relay_open_port: u32,
    relay_open_address: [16]u8,
    outward_len: u32,
    outward: [32]u8,
    inward_len: u32,
    inward: [32]u8,

    policy_errno: i32,
    policy_accepted: u64,
    policy_refused: u64,
    policy_open_calls: u32,
    policy_eof: u32,
    policy_asked_port: u32,

    blocked_errno: i32,
    blocked_waited_ms: u64,
    blocked_accepted: u64,

    dead_errno: i32,
    dead_waited_ms: u64,

    const no_failure: u32 = 0xffff_ffff;
};

fn fail(record: *Measurement, stage: Stage, step: u32, errno: i32) void {
    record.stage = @intFromEnum(stage);
    record.failed_step = step;
    record.failed_errno = errno;
}

fn measureInChild(record: *Measurement, pair: [2]posix.fd_t) void {
    record.* = std.mem.zeroes(Measurement);
    record.stage = Measurement.no_failure;
    record.failed_step = Measurement.no_failure;

    var net_diag: ?netns.Diagnostic = null;
    var net_session = netns.Session.open(&net_diag) catch {
        recordNetnsFailure(record, net_diag);
        return;
    };
    defer net_session.close();
    _ = net_session.configure(&net_diag) catch {
        recordNetnsFailure(record, net_diag);
        return;
    };

    var nft_diag: ?nftables.Diagnostic = null;
    const nft = nftables.Session.open(&nft_diag) catch {
        recordNftablesFailure(record, nft_diag);
        return;
    };
    defer nft.close();
    nft.install(&nft_diag) catch {
        recordNftablesFailure(record, nft_diag);
        return;
    };

    var policy = FakePolicy{};
    var host = FakeHost{ .session = nft, .upstream = pair[0] };
    var router: Router = undefined;
    var diag: ?Diagnostic = null;
    router.open(.{
        .policy = policy.policy(),
        .host = host.host(),
        .allow_timeout_ms = probe_timeout_ms,
        .answer_ttl_s = probe_ttl_s,
    }, &diag) catch {
        if (diag) |d| {
            fail(record, .router_open, @intFromEnum(d.step), d.errno);
        } else {
            fail(record, .router_open, Measurement.no_failure, 0);
        }
        return;
    };
    defer router.close();

    const now = nowMs();
    const server = socketAddress4(netns.address4, resolver_port);
    const client = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(client) != .SUCCESS) return;
    const client_fd: posix.fd_t = @intCast(client);
    defer _ = linux.close(client_fd);

    var query: [query_capacity]u8 = undefined;
    var reply: [query_capacity]u8 = undefined;

    var length = buildQuery(&query, 0x1234, permitted_name, @intFromEnum(RecordKind.a));
    var got = ask(&router, client_fd, &server, query[0..length], &reply, now);
    if (got >= dns_header_bytes) {
        record.permit_rcode = replyRcode(reply[0..got]);
        record.permit_ancount = replyAnswerCount(reply[0..got]);
        record.permit_id = std.mem.readInt(u16, reply[0..2], .big);
        if (readRecord(reply[0..got], length)) |found| {
            record.permit_rtype = found.rtype;
            record.permit_ttl = found.ttl;
            record.permit_rdlength = found.rdlength;
            record.permit_rdata = found.rdata;
        }
    }
    if (nft.element(.{ .ipv4 = permitted_ipv4 }, null) catch null) |element| {
        record.permit_element_found = 1;
        record.permit_element_comment = @intFromBool(element.has_comment);
        record.permit_element_timeout_ms = element.timeout_ms;
    }

    length = buildQuery(&query, 0x1235, permitted_name, @intFromEnum(RecordKind.aaaa));
    got = ask(&router, client_fd, &server, query[0..length], &reply, now);
    if (got >= dns_header_bytes) {
        record.empty_rcode = replyRcode(reply[0..got]);
        record.empty_ancount = replyAnswerCount(reply[0..got]);
    }

    const resolves_before = host.resolve_calls;
    length = buildQuery(&query, 0x1236, refused_name, @intFromEnum(RecordKind.a));
    got = ask(&router, client_fd, &server, query[0..length], &reply, now);
    if (got >= dns_header_bytes) {
        record.refuse_rcode = replyRcode(reply[0..got]);
        record.refuse_ancount = replyAnswerCount(reply[0..got]);
    }
    record.refuse_resolve_calls = host.resolve_calls - resolves_before;
    if (nft.element(.{ .ipv4 = refused_ipv4 }, null) catch null) |_| {
        record.refuse_element_found = 1;
    }

    length = buildQuery(&query, 0x1237, permitted_name, 15);
    got = ask(&router, client_fd, &server, query[0..length], &reply, now);
    if (got >= dns_header_bytes) {
        record.type_rcode = replyRcode(reply[0..got]);
        record.type_ancount = replyAnswerCount(reply[0..got]);
    }

    length = buildQuery(&query, 0x1238, walled_name, @intFromEnum(RecordKind.a));
    got = ask(&router, client_fd, &server, query[0..length], &reply, now);
    if (got >= dns_header_bytes) {
        record.walled_rcode = replyRcode(reply[0..got]);
        record.walled_ancount = replyAnswerCount(reply[0..got]);
    }
    if (nft.element(.{ .ipv4 = walled_ipv4 }, null) catch null) |_| {
        record.walled_element_found = 1;
    }

    const inside = attemptConnect(permitted_ipv4, permitted_port, 2000);
    record.relay_errno = inside.errno;
    pump(&router, 3, now, 200);
    record.relay_accepted = router.counts.accepted;
    record.relay_linked = router.counts.linked;
    record.relay_port = policy.last_dest.port;
    switch (policy.last_dest.address) {
        .ipv4 => |bytes| {
            record.relay_family = 4;
            @memcpy(record.relay_address[0..4], &bytes);
        },
        .ipv6 => |bytes| {
            record.relay_family = 6;
            record.relay_address = bytes;
        },
    }
    record.relay_name_known = @intFromBool(policy.last_name_known);
    record.relay_name_len = policy.last_name_len;
    @memcpy(record.relay_name[0..policy.last_name_len], policy.last_name[0..policy.last_name_len]);
    record.relay_open_calls = host.open_calls;
    record.relay_open_port = host.last_open.port;
    if (host.last_open.address == .ipv4) {
        @memcpy(record.relay_open_address[0..4], &host.last_open.address.ipv4);
    }

    if (inside.fd >= 0 and inside.errno == 0) {
        writeAll(inside.fd, "hello upstream");
        pump(&router, 4, now, 200);
        record.outward_len = @intCast(readWithin(pair[1], &record.outward, 500));

        writeAll(pair[1], "hello sandbox");
        pump(&router, 4, now, 200);
        record.inward_len = @intCast(readWithin(inside.fd, &record.inward, 500));
    }

    const opens_before = host.open_calls;
    const refused = attemptConnect(permitted_ipv4, refused_port, 2000);
    record.policy_errno = refused.errno;
    pump(&router, 3, now, 200);
    record.policy_accepted = router.counts.accepted;
    record.policy_refused = router.counts.refused_destinations;
    record.policy_open_calls = host.open_calls - opens_before;
    record.policy_asked_port = policy.last_dest.port;
    if (refused.fd >= 0) {
        var scratch: [8]u8 = undefined;
        record.policy_eof = @intFromBool(readWithin(refused.fd, &scratch, 500) == 0);
        _ = linux.close(refused.fd);
    }

    const accepted_before = router.counts.accepted;
    const blocked = attemptConnect(never_handed_ipv4, permitted_port, 2000);
    record.blocked_errno = blocked.errno;
    record.blocked_waited_ms = blocked.waited_ms;
    pump(&router, 2, now, 100);
    record.blocked_accepted = router.counts.accepted - accepted_before;
    if (blocked.fd >= 0) _ = linux.close(blocked.fd);

    router.stopListening();
    const dead = attemptConnect(permitted_ipv4, permitted_port, 2000);
    record.dead_errno = dead.errno;
    record.dead_waited_ms = dead.waited_ms;
    if (dead.fd >= 0) _ = linux.close(dead.fd);
    if (inside.fd >= 0) _ = linux.close(inside.fd);
}

fn recordNetnsFailure(record: *Measurement, diag: ?netns.Diagnostic) void {
    if (diag) |d| {
        fail(record, .netns_configure, @intFromEnum(d.step), d.errno);
    } else {
        fail(record, .netns_configure, Measurement.no_failure, 0);
    }
}

fn recordNftablesFailure(record: *Measurement, diag: ?nftables.Diagnostic) void {
    if (diag) |d| {
        fail(record, .nftables_install, @intFromEnum(d.step), d.errno);
    } else {
        fail(record, .nftables_install, Measurement.no_failure, 0);
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
        var pair: [2]i32 = undefined;
        const made = linux.socketpair(
            linux.AF.UNIX,
            linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC,
            0,
            &pair,
        );
        if (linux.errno(made) == .SUCCESS) {
            if (namespace.enter(.{}, null)) |_| {
                var record: Measurement = undefined;
                measureInChild(&record, pair);
                const bytes = std.mem.asBytes(&record);
                _ = linux.write(fds[1], bytes.ptr, bytes.len);
            } else |_| {}
        }
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
    if (record.stage == Measurement.no_failure) return false;
    const stage = std.enums.fromInt(Stage, record.stage) orelse return false;
    return switch (stage) {
        .netns_configure => blk: {
            const step = std.enums.fromInt(netns.Step, record.failed_step) orelse break :blk false;
            break :blk switch (step) {
                .dummy_create => record.failed_errno == @intFromEnum(linux.E.OPNOTSUPP),
                .open_socket => true,
                else => false,
            };
        },
        .nftables_install => blk: {
            const step = std.enums.fromInt(nftables.Step, record.failed_step) orelse break :blk false;
            break :blk switch (step) {
                .open_socket, .batch_begin => true,
                else => false,
            };
        },
        .router_open => false,
    };
}

fn relayName(record: *const Measurement) []const u8 {
    return record.relay_name[0..@min(record.relay_name_len, record.relay_name.len)];
}

test "the relay listens where the nat chain sends" {
    try testing.expectEqual(nftables.relay_port, relay_port);

    try testing.expectEqual(@as(u16, 53), resolver_port);
}

test "the pre-nat destination is read out of the sockaddr the kernel fills" {
    var raw4: [@sizeOf(linux.sockaddr.in)]u8 = @splat(0);
    std.mem.writeInt(u16, raw4[0..2], linux.AF.INET, .little);
    std.mem.writeInt(u16, raw4[2..4], 443, .big);
    @memcpy(raw4[4..8], &[_]u8{ 93, 184, 216, 34 });

    const found4 = decodeOriginal4(&raw4) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u16, 443), found4.port);
    try testing.expectEqualSlices(u8, &.{ 93, 184, 216, 34 }, &found4.address.ipv4);

    std.mem.writeInt(u16, raw4[0..2], linux.AF.INET6, .little);
    try testing.expectEqual(@as(?Destination, null), decodeOriginal4(&raw4));

    std.mem.writeInt(u16, raw4[0..2], linux.AF.INET, .little);
    try testing.expectEqual(@as(?Destination, null), decodeOriginal4(raw4[0..7]));

    var raw6: [@sizeOf(linux.sockaddr.in6)]u8 = @splat(0);
    std.mem.writeInt(u16, raw6[0..2], linux.AF.INET6, .little);
    std.mem.writeInt(u16, raw6[2..4], 8443, .big);
    const literal: [16]u8 = .{ 0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    @memcpy(raw6[8..24], &literal);

    const found6 = decodeOriginal6(&raw6) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u16, 8443), found6.port);
    try testing.expectEqualSlices(u8, &literal, &found6.address.ipv6);

    const mapped: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 2, 3 };
    @memcpy(raw6[8..24], &mapped);
    const unwrapped = decodeOriginal6(&raw6) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &.{ 10, 1, 2, 3 }, &unwrapped.address.ipv4);

    std.mem.writeInt(u16, raw6[0..2], linux.AF.INET, .little);
    try testing.expectEqual(@as(?Destination, null), decodeOriginal6(&raw6));
    std.mem.writeInt(u16, raw6[0..2], linux.AF.INET6, .little);
    try testing.expectEqual(@as(?Destination, null), decodeOriginal6(raw6[0..23]));
}

test "a query names one thing and the parser refuses everything else" {
    var bytes: [query_capacity]u8 = undefined;
    const length = buildQuery(&bytes, 0xbeef, "Registry.NPMJS.test", @intFromEnum(RecordKind.a));

    const query = try parseQuery(bytes[0..length]);
    try testing.expectEqual(@as(u16, 0xbeef), query.id);
    try testing.expectEqual(@as(u4, 0), query.opcode);
    try testing.expect(query.recursion_desired);
    try testing.expectEqualStrings("registry.npmjs.test", query.text());
    try testing.expectEqual(RecordKind.a, query.kind().?);
    try testing.expectEqual(class_internet, query.qclass);
    try testing.expectEqual(length, query.question_end);

    const other = buildQuery(&bytes, 1, "example.test", 15);
    const mx = try parseQuery(bytes[0..other]);
    try testing.expectEqual(@as(?RecordKind, null), mx.kind());

    const again = buildQuery(&bytes, 1, "example.test", 1);
    std.mem.writeInt(u16, bytes[2..4], 0x8180, .big);
    try testing.expectError(error.NotAQuery, parseQuery(bytes[0..again]));

    std.mem.writeInt(u16, bytes[2..4], 0x0100, .big);
    std.mem.writeInt(u16, bytes[4..6], 0, .big);
    try testing.expectError(error.NotOneQuestion, parseQuery(bytes[0..again]));
    std.mem.writeInt(u16, bytes[4..6], 2, .big);
    try testing.expectError(error.NotOneQuestion, parseQuery(bytes[0..again]));
    std.mem.writeInt(u16, bytes[4..6], 1, .big);

    var pointer: [256]u8 = @splat('a');
    std.mem.writeInt(u16, pointer[0..2], 1, .big);
    std.mem.writeInt(u16, pointer[2..4], 0x0100, .big);
    std.mem.writeInt(u16, pointer[4..6], 1, .big);
    std.mem.writeInt(u16, pointer[6..8], 0, .big);
    std.mem.writeInt(u16, pointer[8..10], 0, .big);
    std.mem.writeInt(u16, pointer[10..12], 0, .big);
    pointer[dns_header_bytes] = 0xc0;
    pointer[dns_header_bytes + 1] = 0x0c;
    pointer[205] = 0;
    std.mem.writeInt(u16, pointer[206..208], 1, .big);
    std.mem.writeInt(u16, pointer[208..210], class_internet, .big);
    try testing.expectError(error.Malformed, parseQuery(&pointer));

    bytes[dns_header_bytes] = 0xc0;
    bytes[dns_header_bytes + 1] = 0x0c;
    try testing.expectError(error.Malformed, parseQuery(bytes[0 .. dns_header_bytes + 6]));

    const short = buildQuery(&bytes, 1, "example.test", 1);
    try testing.expectError(error.Malformed, parseQuery(bytes[0 .. short - 3]));
    try testing.expectError(error.Malformed, parseQuery(bytes[0..dns_header_bytes]));
    try testing.expectError(error.Malformed, parseQuery(bytes[0..11]));

    var root: [dns_header_bytes + 5]u8 = @splat(0);
    std.mem.writeInt(u16, root[2..4], 0x0100, .big);
    std.mem.writeInt(u16, root[4..6], 1, .big);
    std.mem.writeInt(u16, root[13..15], 1, .big);
    std.mem.writeInt(u16, root[15..17], 1, .big);
    try testing.expectError(error.Malformed, parseQuery(&root));
}

test "a name longer than the table can hold is refused rather than cut short" {
    var bytes: [query_capacity]u8 = undefined;
    var long: [name_capacity + 8]u8 = @splat('a');
    var at: usize = 0;
    while (at + 40 <= long.len) : (at += 40) long[at + 39] = '.';
    const length = buildQuery(&bytes, 1, long[0 .. long.len - 1], 1);
    try testing.expectError(error.Malformed, parseQuery(bytes[0..length]));

    const fits = buildQuery(&bytes, 1, long[0..name_capacity], 1);
    const query = try parseQuery(bytes[0..fits]);
    try testing.expectEqual(@as(u8, name_capacity), query.name_len);
}

test "a reply echoes the question it was asked and carries one answer" {
    var bytes: [query_capacity]u8 = undefined;
    const length = buildQuery(&bytes, 0x4321, "Registry.NPMJS.test", @intFromEnum(RecordKind.a));
    const query = try parseQuery(bytes[0..length]);

    var out: [query_capacity]u8 = undefined;
    const written = buildReply(&out, bytes[0..length], &query, .no_error, .{
        .kind = .a,
        .address = .{ .ipv4 = permitted_ipv4 },
    }, 10) orelse return error.TestUnexpectedResult;

    try testing.expectEqual(@as(u16, 0x4321), std.mem.readInt(u16, out[0..2], .big));
    const flags = std.mem.readInt(u16, out[2..4], .big);
    try testing.expectEqual(@as(u16, 0x8000), flags & 0x8000);
    try testing.expectEqual(@as(u16, 0x0100), flags & 0x0100);
    try testing.expectEqual(@as(u16, 0x0080), flags & 0x0080);
    try testing.expectEqual(@as(u16, 0), flags & 0xf);
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, out[4..6], .big));
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, out[6..8], .big));
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[8..10], .big));
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[10..12], .big));

    try testing.expectEqualSlices(u8, bytes[dns_header_bytes..length], out[dns_header_bytes..length]);

    const found = readRecord(out[0..written], length) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@intFromEnum(RecordKind.a), found.rtype);
    try testing.expectEqual(@as(u32, 10), found.ttl);
    try testing.expectEqual(@as(u16, 4), found.rdlength);
    try testing.expectEqualSlices(u8, &permitted_ipv4, found.rdata[0..4]);
    try testing.expectEqual(@as(u8, 0xc0), out[length]);
    try testing.expectEqual(@as(u8, 0x0c), out[length + 1]);

    const six = buildQuery(&bytes, 1, "example.test", @intFromEnum(RecordKind.aaaa));
    const query6 = try parseQuery(bytes[0..six]);
    const literal: [16]u8 = .{ 0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const written6 = buildReply(&out, bytes[0..six], &query6, .no_error, .{
        .kind = .aaaa,
        .address = .{ .ipv6 = literal },
    }, 30) orelse return error.TestUnexpectedResult;
    const found6 = readRecord(out[0..written6], six) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@intFromEnum(RecordKind.aaaa), found6.rtype);
    try testing.expectEqual(@as(u16, 16), found6.rdlength);
    try testing.expectEqualSlices(u8, &literal, &found6.rdata);

    try testing.expectEqual(@as(?usize, null), buildReply(out[0 .. length + 3], bytes[0..length], &query, .no_error, .{
        .kind = .a,
        .address = .{ .ipv4 = permitted_ipv4 },
    }, 10));
}

test "a refusal carries no answer section and no address at all" {
    var bytes: [query_capacity]u8 = undefined;
    const length = buildQuery(&bytes, 0x0101, refused_name, @intFromEnum(RecordKind.a));
    const query = try parseQuery(bytes[0..length]);

    var out: [query_capacity]u8 = undefined;
    const written = buildReply(&out, bytes[0..length], &query, .refused, null, 10) orelse
        return error.TestUnexpectedResult;

    try testing.expectEqual(length, written);
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[6..8], .big));
    try testing.expectEqual(@as(u16, @intFromEnum(Rcode.refused)), std.mem.readInt(u16, out[2..4], .big) & 0xf);

    try testing.expect(@intFromEnum(Rcode.refused) != @intFromEnum(Rcode.name_error));

    const empty = buildReply(&out, bytes[0..length], &query, .no_error, null, 10) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(length, empty);
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[6..8], .big));
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[2..4], .big) & 0xf);
}

test "a datagram that cannot be parsed still gets an answer" {
    var out: [query_capacity]u8 = undefined;
    const source = [_]u8{ 0xab, 0xcd } ++ [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff };
    const written = buildFormatError(&out, &source) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(dns_header_bytes, written);
    try testing.expectEqual(@as(u16, 0xabcd), std.mem.readInt(u16, out[0..2], .big));
    try testing.expectEqual(@as(u16, 0x8000), std.mem.readInt(u16, out[2..4], .big) & 0x8000);
    try testing.expectEqual(
        @as(u16, @intFromEnum(Rcode.format_error)),
        std.mem.readInt(u16, out[2..4], .big) & 0xf,
    );
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[4..6], .big));
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[6..8], .big));

    try testing.expectEqual(@as(?usize, null), buildFormatError(&out, source[0..11]));
    try testing.expectEqual(@as(?usize, null), buildFormatError(out[0..11], &source));
}

test "the name table is bounded, expires, and keeps the newest name" {
    var table = NameTable{};
    const start: i64 = 1_000_000;
    const life: u64 = 30_000;

    table.remember(.{ .ipv4 = permitted_ipv4 }, permitted_name, start, life);
    try testing.expectEqualStrings(permitted_name, table.lookup(.{ .ipv4 = permitted_ipv4 }, start).?);

    try testing.expectEqualStrings(
        permitted_name,
        table.lookup(.{ .ipv4 = permitted_ipv4 }, start + @as(i64, @intCast(life)) - 1).?,
    );
    try testing.expectEqual(
        @as(?[]const u8, null),
        table.lookup(.{ .ipv4 = permitted_ipv4 }, start + @as(i64, @intCast(life))),
    );

    table.remember(.{ .ipv4 = permitted_ipv4 }, "other.npmjs.test", start, life);
    try testing.expectEqualStrings("other.npmjs.test", table.lookup(.{ .ipv4 = permitted_ipv4 }, start).?);
    try testing.expectEqual(@as(usize, 1), table.live(start));

    try testing.expectEqual(@as(?[]const u8, null), table.lookup(.{ .ipv4 = never_handed_ipv4 }, start));
    try testing.expectEqual(
        @as(?[]const u8, null),
        table.lookup(.{ .ipv6 = @splat(0) }, start),
    );

    var full = NameTable{};
    var index: u32 = 0;
    while (index < name_table_capacity * 4) : (index += 1) {
        var address: [4]u8 = undefined;
        std.mem.writeInt(u32, &address, index + 1, .big);
        full.remember(.{ .ipv4 = address }, "example.test", start, life);
        try testing.expect(full.live(start) <= name_table_capacity);
    }
    try testing.expectEqual(name_table_capacity, full.live(start));

    var newest: [4]u8 = undefined;
    std.mem.writeInt(u32, &newest, name_table_capacity * 4, .big);
    try testing.expect(full.lookup(.{ .ipv4 = newest }, start) != null);

    try testing.expectEqual(@as(usize, 0), full.live(start + @as(i64, @intCast(life))));
}

test "a refusal names the call the kernel would not take" {
    try testing.expectEqual(error.PrivilegedPort, classify(.resolver_bind, @intFromEnum(linux.E.ACCES)));
    try testing.expectEqual(error.NotPermitted, classify(.relay_bind, @intFromEnum(linux.E.ACCES)));
    try testing.expectEqual(error.NotPermitted, classify(.relay_socket, @intFromEnum(linux.E.PERM)));
    try testing.expectEqual(error.AddressInUse, classify(.relay_bind, @intFromEnum(linux.E.ADDRINUSE)));
    try testing.expectEqual(error.AddressInUse, classify(.resolver_bind, @intFromEnum(linux.E.ADDRINUSE)));
    try testing.expectEqual(error.Refused, classify(.relay_listen, @intFromEnum(linux.E.INVAL)));
    try testing.expectEqual(error.Refused, classify(.resolver_socket, @intFromEnum(linux.E.AFNOSUPPORT)));
}

test "a refusal that is not a missing module fails the test rather than skipping it" {
    try testing.expect(measuredNothing(failedAt(
        .netns_configure,
        @intFromEnum(netns.Step.dummy_create),
        @intFromEnum(linux.E.OPNOTSUPP),
    )));
    try testing.expect(measuredNothing(failedAt(
        .nftables_install,
        @intFromEnum(nftables.Step.batch_begin),
        @intFromEnum(linux.E.OPNOTSUPP),
    )));

    try testing.expect(!measuredNothing(failedAt(
        .netns_configure,
        @intFromEnum(netns.Step.route4_add),
        @intFromEnum(linux.E.OPNOTSUPP),
    )));
    try testing.expect(!measuredNothing(failedAt(
        .nftables_install,
        @intFromEnum(nftables.Step.relay_rule),
        @intFromEnum(linux.E.NOENT),
    )));
    try testing.expect(!measuredNothing(failedAt(
        .router_open,
        @intFromEnum(Step.resolver_bind),
        @intFromEnum(linux.E.ACCES),
    )));
    try testing.expect(!measuredNothing(failedAt(
        .router_open,
        @intFromEnum(Step.relay_bind),
        @intFromEnum(linux.E.ADDRINUSE),
    )));

    var clean = std.mem.zeroes(Measurement);
    clean.stage = Measurement.no_failure;
    try testing.expect(!measuredNothing(clean));
}

fn failedAt(stage: Stage, step: u32, errno: i32) Measurement {
    var record = std.mem.zeroes(Measurement);
    record.stage = @intFromEnum(stage);
    record.failed_step = step;
    record.failed_errno = errno;
    return record;
}

test "a permitted name resolves and its address lands in the allow set" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    try testing.expectEqual(@as(u32, @intFromEnum(Rcode.no_error)), record.permit_rcode);
    try testing.expectEqual(@as(u32, 1), record.permit_ancount);
    try testing.expectEqual(@as(u32, @intFromEnum(RecordKind.a)), record.permit_rtype);
    try testing.expectEqual(@as(u32, 4), record.permit_rdlength);
    try testing.expectEqualSlices(u8, &permitted_ipv4, record.permit_rdata[0..4]);
    try testing.expectEqual(@as(u32, 0x1234), record.permit_id);

    try testing.expectEqual(@as(u32, 1), record.permit_element_found);
    try testing.expectEqual(probe_timeout_ms, record.permit_element_timeout_ms);
    try testing.expectEqual(@as(u32, 0), record.permit_element_comment);

    try testing.expect(@as(u64, record.permit_ttl) * 1000 < record.permit_element_timeout_ms);

    try testing.expectEqual(@as(u32, @intFromEnum(Rcode.no_error)), record.empty_rcode);
    try testing.expectEqual(@as(u32, 0), record.empty_ancount);
}

test "a name the policy refuses answers REFUSED and never reaches the host" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    try testing.expectEqual(@as(u32, @intFromEnum(Rcode.refused)), record.refuse_rcode);
    try testing.expectEqual(@as(u32, 0), record.refuse_ancount);

    try testing.expectEqual(@as(u32, 0), record.refuse_element_found);

    try testing.expectEqual(@as(u32, 0), record.refuse_resolve_calls);
}

test "a record type this resolver does not answer is refused and not implemented" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    try testing.expectEqual(@as(u32, @intFromEnum(Rcode.refused)), record.type_rcode);
    try testing.expectEqual(@as(u32, 0), record.type_ancount);
}

test "an address the kernel would not take is never answered" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    try testing.expectEqual(@as(u32, @intFromEnum(Rcode.server_failure)), record.walled_rcode);
    try testing.expectEqual(@as(u32, 0), record.walled_ancount);
    try testing.expectEqual(@as(u32, 0), record.walled_element_found);
}

test "a connection to an allowed address reaches the relay with the address it asked for" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    try testing.expectEqual(@as(i32, 0), record.relay_errno);
    try testing.expectEqual(@as(u64, 1), record.relay_accepted);
    try testing.expectEqual(@as(u64, 1), record.relay_linked);

    try testing.expectEqual(@as(u32, 4), record.relay_family);
    try testing.expectEqualSlices(u8, &permitted_ipv4, record.relay_address[0..4]);
    try testing.expectEqual(@as(u32, permitted_port), record.relay_port);
    try testing.expect(record.relay_port != relay_port);
    try testing.expect(!std.mem.eql(u8, record.relay_address[0..4], &.{ 127, 0, 0, 1 }));

    try testing.expectEqual(@as(u32, 1), record.relay_name_known);
    try testing.expectEqualStrings(permitted_name, relayName(&record));

    try testing.expectEqual(@as(u32, 1), record.relay_open_calls);
    try testing.expectEqual(@as(u32, permitted_port), record.relay_open_port);
    try testing.expectEqualSlices(u8, &permitted_ipv4, record.relay_open_address[0..4]);
}

test "the relay carries bytes both ways through a descriptor made outside the namespace" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    try testing.expectEqualStrings("hello upstream", record.outward[0..record.outward_len]);
    try testing.expectEqualStrings("hello sandbox", record.inward[0..record.inward_len]);
}

test "the policy is the only control on a port the kernel has no opinion about" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    try testing.expectEqual(@as(i32, 0), record.policy_errno);
    try testing.expectEqual(@as(u64, 2), record.policy_accepted);
    try testing.expectEqual(@as(u64, 1), record.policy_refused);
    try testing.expectEqual(@as(u32, refused_port), record.policy_asked_port);

    try testing.expectEqual(@as(u32, 0), record.policy_open_calls);

    try testing.expectEqual(@as(u32, 1), record.policy_eof);
}

test "a connection to an address that was never handed out never reaches the relay" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    try testing.expectEqual(@as(u64, 0), record.blocked_accepted);

    try testing.expect(record.blocked_errno != timed_out);
    try testing.expectEqual(@intFromEnum(linux.E.CONNREFUSED), record.blocked_errno);
    try testing.expect(record.blocked_waited_ms < 1000);
}

test "a connection with the relay gone is refused rather than left waiting" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    try testing.expect(record.dead_errno != timed_out);
    try testing.expectEqual(@intFromEnum(linux.E.CONNREFUSED), record.dead_errno);
    try testing.expect(record.dead_waited_ms < 1000);
}

test "a descriptor from the host seam is made ready for a loop that polls" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var pair: [2]posix.fd_t = undefined;
    const made = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &pair);
    if (linux.errno(made) != .SUCCESS) return error.SkipZigTest;
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try testing.expect(!flagsOf(pair[0]).NONBLOCK);
    makeNonBlocking(pair[0]);
    try testing.expect(flagsOf(pair[0]).NONBLOCK);

    var scratch: [4]u8 = undefined;
    try testing.expectError(error.WouldBlock, posix.read(pair[0], &scratch));

    try testing.expectEqual(posix.ACCMODE.RDWR, flagsOf(pair[0]).ACCMODE);
}

fn flagsOf(fd: posix.fd_t) linux.O {
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    return @bitCast(@as(u32, @truncate(flags)));
}
