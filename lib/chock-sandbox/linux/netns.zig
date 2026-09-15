//! The network the sandbox gets inside its own network namespace: loopback, one
//! dummy device, one address on it, and a default route through it.
//!
//! ## What this is for
//!
//! A network namespace with no device at all answers every `connect` with
//! `ENETUNREACH` before the packet reaches any filter. A rule in `chock.zon`
//! then governs nothing, because nothing ever gets far enough to be judged.
//! This file gives the namespace enough of a network that an ordinary
//! `connect` reaches the socket layer, and the ruleset in `nftables.zig`
//! decides what happens next. Nothing else here: no ruleset, no listener, no
//! relay, no resolver.
//!
//! ## THE DUMMY DEVICE IS A BLACKHOLE. THAT IS THE WHOLE DESIGN.
//!
//! `chock0` is a `dummy` link. The kernel accepts a packet for it, counts it,
//! and frees it. **There is no path out of this network namespace through any
//! device.** The routes exist only so the socket layer is reached. The two ways
//! out of the namespace are:
//!
//! 1. the nftables REDIRECT in `nftables.zig`, which sends outbound TCP to a
//!    listener that runs **inside** the namespace, and
//! 2. a descriptor the process inherited from the host, which is how that
//!    listener reaches the real network.
//!
//! Both of those are userspace, and Chock owns both of them.
//!
//! **DO NOT PUT A VETH IN THIS NAMESPACE.** Not to a host bridge, not to a NAT
//! device, not "only for DNS", not "only in the tests". `CAP_NET_RAW` is live
//! inside the sandbox, because the process is root in its own user namespace
//! and the kernel gives it every capability there. A raw socket writes a whole
//! packet. It does not use the `connect` path, so the nat chain never rewrites
//! it, and today that costs nothing because the only device it can write to
//! throws the packet away. **The moment a device in this namespace can deliver
//! a packet to another namespace, a raw socket walks around the nat chain, the
//! filter chain, the listener, the resolver, and the policy, all at once.**
//! There is no rule anywhere in Chock that stops it, because the whole
//! reasoning depends on the kernel having nowhere to put the packet. A veth
//! here is not an improvement to this file. It is the end of the design.
//!
//! `the created link is a dummy and nothing else` and `the default route has no
//! next hop` below are the two tests that hold this shape. They fail on a link
//! kind that is not `dummy` and on a route that names a gateway.
//!
//! ## Both families, and why
//!
//! IPv4 and IPv6 both get an address and a default route. A family with no
//! route is refused by the socket layer with `ENETUNREACH`, which is a
//! different answer from the `reject with icmpx port-unreachable` the guard
//! chain gives, and it arrives without the guard chain ever running. The
//! ruleset already holds an `allowed6` set and an `ip6 daddr` rule, so leaving
//! IPv6 without a route would make half that ruleset unreachable. A host built
//! without IPv6 support refuses the `address6` step with `EAFNOSUPPORT`. That
//! host has not been measured here, so it has no name of its own and arrives as
//! `error.Refused` with the step named.
//!
//! ## Where this runs in the sequence
//!
//! After `namespace.enter` unshares `CLONE_NEWNET`, and before the sandboxed
//! program starts. A netlink socket belongs to the network namespace of the
//! process that opened it, so `Session.open` must happen inside the namespace
//! this is meant to configure. The full order the router needs is: enter the
//! namespace, configure it here, install the ruleset with `nftables.zig`, drop
//! `CAP_NET_ADMIN`, then exec. Dropping the capability first leaves a namespace
//! that cannot be built; dropping it last leaves a ruleset the sandboxed
//! program can flush.
//!
//! **Nothing calls this yet.** It is the second piece of the router. The
//! wiring lands when the pieces exist.
//!
//! ## Linux only, and the netlink byte writer
//!
//! Every call below reaches the kernel through `std.os.linux`, for the reason
//! `nftables.zig` and `netbroker.zig` give: rtnetlink has no `std.Io` and no
//! `std.posix` spelling in this Zig version. The `Builder` here is a near twin
//! of the one in `nftables.zig` and is **deliberately a copy**. The two speak
//! different protocols on different sockets: nfnetlink writes every integer
//! attribute in network byte order and carries a four byte `nfgenmsg`, while
//! rtnetlink writes integer attributes in host byte order and carries a family
//! header of three different sizes. One writer serving both would put the two
//! opposite byte order rules in one place, and a wrong byte order is exactly
//! the mistake neither kernel reports. At this size a copy is cheaper to read
//! and safer to change.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

/// Only the tests below use this, to get a network namespace of their own to
/// configure. Nothing in the module itself enters a namespace.
const namespace = @import("namespace.zig");

/// The blackhole device. See the top comment for what it must stay.
pub const device_name = "chock0";

/// **`dummy`, and nothing else.** A `veth`, a `macvlan`, a `bridge`, or an
/// `ipvlan` all deliver a packet somewhere. This one does not. Read the top
/// comment before changing this word.
pub const link_kind = "dummy";

/// The address on the blackhole device. Nothing answers here. It exists so the
/// socket layer has a source address to pick and a route to resolve.
pub const address4: [4]u8 = .{ 10, 99, 0, 1 };
pub const prefix4: u8 = 24;

/// `fdcc::1`, a unique local address. The same reasoning as `address4`.
pub const address6: [16]u8 = .{ 0xfd, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
pub const prefix6: u8 = 64;

/// Which call the kernel refused. Every error out of this file carries one,
/// because `EOPNOTSUPP` on `dummy_create` is a host with no `dummy` module and
/// `EOPNOTSUPP` anywhere else is a bug here, and the two need different things
/// from a person.
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

/// The call the kernel refused and what it answered. Filled on every error.
pub const Diagnostic = struct {
    step: Step,
    /// The positive errno. Kept as a number because it comes from the kernel
    /// over a socket, and an integer from outside is not an enum until
    /// something checks it.
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
    /// The kernel cannot make this device because the `dummy` module is not
    /// loaded, and a process in a user namespace cannot make the kernel load
    /// one. Tell the person to load `dummy` on the host. **Do not continue
    /// without the device**: every later step needs it, and a namespace with
    /// no route makes the whole ruleset unreachable.
    KernelModuleMissing,
    /// No `CAP_NET_ADMIN` in this network namespace. The caller ran this
    /// outside the namespace, or dropped the capability too early.
    NotPermitted,
    /// The kernel refused for a reason this file does not recognise. Read the
    /// diagnostic; this is a bug here, not a property of the host.
    Refused,
    /// The netlink socket itself would not carry the message, or the kernel
    /// answered a message this file did not send.
    ExchangeFailed,
};

fn note(diag: ?*?Diagnostic, step: Step, errno: i32) void {
    if (diag) |slot| slot.* = .{ .step = step, .errno = errno };
}

/// Turn a refusal into a name a caller can act on.
///
/// * `EPERM` and `EACCES`: no `CAP_NET_ADMIN` in this namespace.
/// * `EOPNOTSUPP` on `dummy_create`: `rtnl_newlink` found no link kind called
///   `dummy` and could not ask the kernel to load one, which is what an
///   unloaded `dummy` module looks like from inside a user namespace.
///   **Only on that one step.** The same errno on any other call is this file
///   sending something the kernel does not accept.
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

/// An open rtnetlink socket to one network namespace.
///
/// **Which namespace is decided when this is opened, not when it is used.** A
/// netlink socket belongs to the network namespace of the process that created
/// it, so a caller opens this after entering the sandbox's namespace and
/// before dropping `CAP_NET_ADMIN`.
pub const Session = struct {
    fd: i32,
    /// The sequence number of the next request. Every reply is checked against
    /// it, so a reply to some other request cannot be read as an answer to
    /// this one.
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

    /// Build the whole network and answer the index of the blackhole device.
    ///
    /// The order is the one the kernel needs. Loopback first, because the
    /// ruleset accepts by output interface and loopback is index 1 in every
    /// new namespace. The device next, then its addresses, then the device
    /// comes up, and only then the default routes: a route through a device
    /// that is down is refused with `ENETDOWN`.
    ///
    /// The index comes back because it is the identity of the blackhole. A
    /// later piece that reads a route or a counter needs it, and this call
    /// already had to ask the kernel for it.
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
            // **No duplicate address detection.** On a device that delivers
            // nothing, nobody can answer, so detection only keeps the address
            // tentative and unusable for about a second on every start.
            .flags = ifa_f_nodad,
            .index = index,
            .bytes = &address6,
        }, self.sequence)], .address6_add, diag);

        try self.exchange(buffer[0..buildLinkUp(&buffer, device_name, self.sequence)], .device_up, diag);

        try self.exchange(buffer[0..buildDefaultRoute(&buffer, af_inet, index, self.sequence)], .route4_add, diag);
        try self.exchange(buffer[0..buildDefaultRoute(&buffer, af_inet6, index, self.sequence)], .route6_add, diag);

        return index;
    }

    /// The index of a link by name, or an error when the kernel holds no such
    /// link. **Not optional**: every caller here asks about a device it has
    /// just made, so an absent one is a fault and not an answer.
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

    /// Send one request and read the acknowledgement. **Every request this
    /// file sends carries `NLM_F_ACK`**, because a kernel that took the change
    /// and a kernel that never saw the message both answer with silence.
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
        // The kernel answers a request that asked for an acknowledgement. An
        // answer that is not one belongs to nothing this file sent.
        note(diag, step, 0);
        return error.ExchangeFailed;
    }

    fn send(self: *Session, bytes: []const u8, step: Step, diag: ?*?Diagnostic) Error!void {
        // The message has to carry the number the reader is about to wait for.
        // A message built from a stale counter is a mistake in this program,
        // and it would make every reply look like an answer to something else.
        std.debug.assert(bytes.len >= 16);
        std.debug.assert(std.mem.readInt(u32, bytes[8..12], .little) == self.sequence);

        // Wraps to 1 rather than to 0, because 0 is the sequence number the
        // kernel uses for a message it sends on its own.
        self.sequence = if (self.sequence == std.math.maxInt(u32)) 1 else self.sequence + 1;

        const rc = linux.sendto(self.fd, bytes.ptr, bytes.len, 0, null, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => |e| {
                note(diag, step, @intFromEnum(e));
                return error.ExchangeFailed;
            },
        }
        // A netlink datagram is written whole or not at all, so a short count
        // is a broken assumption here rather than a partial write to finish.
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

// ---------------------------------------------------------------------------
// The rtnetlink wire, and only as much of it as this one network needs.
// ---------------------------------------------------------------------------

/// The kernel makes loopback first in every new network namespace, so its
/// index is 1 by construction. The name is used anyway, because a lookup by
/// name says what is meant and costs one message.
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
/// `NLM_F_ROOT | NLM_F_MATCH`, which together are `NLM_F_DUMP`.
const f_dump: u16 = 0x300;

const nla_nested: u16 = 0x8000;
/// Strips `NLA_F_NESTED` and `NLA_F_NET_BYTEORDER` from a type read back.
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

/// `IFF_UP`, the only link flag this file ever sets.
const iff_up: u32 = 0x1;
/// `IFF_RUNNING`. The kernel sets it when a link is up and its carrier is on.
const iff_running: u32 = 0x40;
/// `IFA_F_NODAD`. See `configure`.
const ifa_f_nodad: u8 = 0x02;

/// `RT_TABLE_MAIN`.
const rt_table_main: u8 = 254;
/// `RTPROT_BOOT`, which is what a route added by a program rather than by a
/// routing daemon is called.
const rtprot_boot: u8 = 3;
/// `RT_SCOPE_LINK`. A route with no next hop goes no further than the device,
/// which is what `ip route add default dev ...` writes.
const rt_scope_link: u8 = 253;
/// `RTN_UNICAST`.
const rtn_unicast: u8 = 1;

/// Enough for the longest request here, which is a link creation carrying a
/// name and a nested kind.
const max_request = 256;
/// Enough for the longest reply this file reads, which is one datagram of an
/// address or a route dump.
const reply_capacity = 8192;

/// Builds netlink messages into a buffer the caller owns. Every length is
/// written after the part it covers is complete, which is the only way a
/// nested attribute can know its own size.
///
/// **This is a byte writer and not a netlink library.** It knows message
/// headers, attributes and nesting, and nothing at all about what a link or a
/// route means. See the top comment for why it is a copy of the one in
/// `nftables.zig` rather than a shared module.
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

    /// **Host byte order, unlike every integer in `nftables.zig`.** rtnetlink
    /// reads its own integer attributes in the byte order of the machine that
    /// sent them. An address is not an integer here: it is a byte string, and
    /// it goes through `attribute` untouched.
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

    /// The netlink header, without the family header that follows it. The
    /// caller writes that, because rtnetlink has three of them and they are
    /// different sizes.
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

    /// `struct ifinfomsg`: family, a pad byte, the ARP hardware type, the
    /// index, the flags, and the mask of which flags to change.
    fn linkHeader(b: *Builder, index: u32, flags: u32, change: u32) void {
        const at = b.len;
        b.put(&[_]u8{0} ** 16);
        b.buf[at] = af_unspec;
        std.mem.writeInt(u32, b.buf[at + 4 ..][0..4], index, .little);
        std.mem.writeInt(u32, b.buf[at + 8 ..][0..4], flags, .little);
        std.mem.writeInt(u32, b.buf[at + 12 ..][0..4], change, .little);
    }

    /// `struct ifaddrmsg`: family, prefix length, flags, scope, and index.
    fn addressHeader(b: *Builder, family: u8, prefix: u8, flags: u8, index: u32) void {
        const at = b.len;
        b.put(&[_]u8{0} ** 8);
        b.buf[at] = family;
        b.buf[at + 1] = prefix;
        b.buf[at + 2] = flags;
        // Scope stays RT_SCOPE_UNIVERSE. The address is a global one on both
        // families.
        std.mem.writeInt(u32, b.buf[at + 4 ..][0..4], index, .little);
    }

    /// `struct rtmsg`: family, the two prefix lengths, type of service, table,
    /// protocol, scope, route type, and flags.
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

/// `RTM_SETLINK` that turns `IFF_UP` on and touches no other flag. The change
/// mask is `IFF_UP` alone, so nothing else about the link moves.
fn buildLinkUp(buf: []u8, name: []const u8, sequence: u32) usize {
    var b = Builder{ .buf = buf };
    const at = b.openMessage(rtm_setlink, f_request | f_ack, sequence);
    b.linkHeader(0, iff_up, iff_up);
    b.string(ifla_ifname, name);
    b.closeMessage(at);
    return b.len;
}

/// `RTM_NEWLINK` for the blackhole.
///
/// **`NLM_F_EXCL`**, so a device that is already called `chock0` is refused
/// rather than reshaped. A fresh namespace holds no such device, so one that
/// does means this ran twice or ran in the wrong namespace, and silently
/// taking over somebody else's link is the worst of the three outcomes.
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

/// `RTM_NEWADDR`. `IFA_LOCAL` and `IFA_ADDRESS` carry the same value, which is
/// what an address on an ordinary device means. They differ only on a point to
/// point link, where `IFA_ADDRESS` is the far end, and there is no far end
/// here by design.
fn buildAddress(buf: []u8, request: AddressRequest, sequence: u32) usize {
    var b = Builder{ .buf = buf };
    const at = b.openMessage(rtm_newaddr, f_request | f_ack | f_create | f_excl, sequence);
    b.addressHeader(request.family, request.prefix, request.flags, request.index);
    b.attribute(ifa_local, request.bytes);
    b.attribute(ifa_address, request.bytes);
    b.closeMessage(at);
    return b.len;
}

/// `RTM_NEWROUTE` for `default dev chock0`.
///
/// **No `RTA_GATEWAY`.** A gateway is a next hop, and a next hop is a machine
/// that forwards. There is none, there must be none, and `the default route
/// has no next hop` below refuses one. The route exists so that `connect`
/// reaches the socket layer instead of answering `ENETUNREACH`, and for
/// nothing else. See the top comment.
fn buildDefaultRoute(buf: []u8, family: u8, index: u32, sequence: u32) usize {
    var b = Builder{ .buf = buf };
    const at = b.openMessage(rtm_newroute, f_request | f_ack | f_create | f_excl, sequence);
    // A destination prefix length of zero is what makes this the default
    // route: it matches every address no other route claims.
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

// ---------------------------------------------------------------------------
// Reading a reply. Bounded, and it trusts no length the kernel sent.
// ---------------------------------------------------------------------------

const Message = struct {
    kind: u16,
    sequence: u32,
    /// Everything after the netlink header.
    body: []const u8,

    /// Everything after the netlink header and a family header of `size`
    /// bytes, which is where the attributes start.
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

/// The errno an `NLMSG_ERROR` carries, as a positive number. Zero is an
/// acknowledgement and not a fault.
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

// ---------------------------------------------------------------------------
// Reading the network back.
//
// **`readLink` is used by `configure` itself**, because the device index is
// not known until the kernel says what it is. The address and route readers
// below are for the tests: an acknowledgement says the kernel took the
// message, and only a read says what the kernel built out of it. That
// difference is not theory here. See `nftables.zig`'s top comment for the
// measured case where a batch was accepted, acknowledged, and stored something
// else.
// ---------------------------------------------------------------------------

const LinkFacts = struct {
    index: u32,
    flags: u32,
    /// The link kind, `dummy` for the blackhole, empty for loopback, which has
    /// no `IFLA_LINKINFO` at all.
    kind: [16]u8,
    /// `IFLA_STATS64`. `tx_packets` is what the kernel counted into the
    /// blackhole and threw away, and `rx_packets` is what came back, which on
    /// a dummy is always zero.
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
            // `struct rtnl_link_stats64` starts with rx_packets then
            // tx_packets, both 64 bit and both in host byte order.
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

/// The first address of `family` the kernel holds on `index`, or null.
fn readAddress(self: *Session, family: u8, index: u32, diag: ?*?Diagnostic) Error!?AddressFacts {
    var buffer: [max_request]u8 = undefined;
    const sent = self.sequence;
    const length = buildAddressDump(&buffer, family, sent);
    try self.send(buffer[0..length], .address_read, diag);

    var reply: [reply_capacity]u8 = undefined;
    // The bound is on the number of datagrams, so a kernel that never sends
    // an NLMSG_DONE cannot hold this loop open.
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
            // **The two families answer with different attributes.** The IPv4
            // code fills IFA_LOCAL and IFA_ADDRESS, and the IPv6 code fills
            // IFA_ADDRESS alone. Measured on kernel 6.18: a reader that asks
            // only for IFA_LOCAL finds every IPv4 address and no IPv6 address
            // at all, while the add of that address was acknowledged.
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

/// The default route of `family` in the main table, or null when there is
/// none. A default route is one whose destination prefix length is zero.
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

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Everything one child measured, in a shape the kernel carries whole through
/// a pipe. The child measures and the parent asserts, so a failing expectation
/// prints where the test runner can see it.
const Measurement = extern struct {
    /// `no_failure` when every call succeeded, otherwise the step that failed.
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

    /// What `connect` answered before anything was configured, and after.
    before4_errno: i32,
    before6_errno: i32,
    after4_errno: i32,
    after6_errno: i32,
    /// 1 when the connection completed inside the window, which on a blackhole
    /// must never happen.
    completed4: u32,
    completed6: u32,
    /// `SO_ERROR` when the socket became writable, which is how a refusal is
    /// told apart from a success.
    so_error4: i32,
    so_error6: i32,

    /// The blackhole's counters after the two connections were tried.
    tx_packets: u64,
    rx_packets: u64,

    const no_failure: u32 = 0xffff_ffff;
};

/// An address in documentation space that nothing on any network answers.
/// `TEST-NET-3` from RFC 5737.
const unreachable4: [4]u8 = .{ 203, 0, 113, 7 };
/// `2001:db8::1`, the documentation prefix of RFC 3849.
const unreachable6: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 11 ++ .{1};

/// How long the blackhole test waits for a connection that must never
/// complete. A TCP handshake over a working path on the same machine finishes
/// in well under a millisecond, and the first SYN retransmission is a second
/// away, so this window either sees a success or sees nothing.
const settle_ms: i32 = 300;

/// What one `connect` answered.
const Attempt = struct {
    /// The errno `connect` returned. `EINPROGRESS` means the socket layer took
    /// it, so a route exists and the packet is on its way to the device.
    /// `ENETUNREACH` means the socket layer refused before any packet was
    /// made.
    errno: i32,
    /// True when the socket became writable and carried no error, which is a
    /// completed connection.
    completed: bool,
    so_error: i32,
};

/// Try one outbound TCP connection and answer what happened, without blocking
/// for a handshake that must never finish.
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

    // **Before anything is configured.** A namespace with no route answers at
    // the socket layer without ever making a packet, and that is the answer
    // this file exists to change.
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

/// Build the network in a network namespace of its own and report what the
/// kernel then holds.
///
/// **A child, because a network namespace cannot be left.** The test process
/// needs its own namespaces for every later test, and `namespace.enter` spends
/// the one this process has. `nftables.zig` forks for the same reason.
///
/// Answers null when this machine will not give a namespace at all, which the
/// caller must report as a skip. **A machine that cannot build a sandbox
/// measured nothing here, and that is not a pass.**
///
/// **A child that died is not a skip either.** A child that crashes writes a
/// short pipe, which is exactly what a child that could not make the namespace
/// writes, so the two are told apart by the exit status and nothing else.
/// Measured while building this file: an assertion that fired inside the child
/// turned all four namespace tests from failures into skips, and the suite
/// stayed green. `error.ChildCrashed` is what stops that.
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
        // The namespace this process just proved is available. A failure here
        // races nothing: the parent reads a short pipe and, because this
        // process still leaves by `exit(0)`, reports a skip.
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

    // The child leaves by `exit(0)` on both paths it plans to take, so any
    // other status is a crash, a signal, or a panic.
    if (status != 0) return error.ChildCrashed;
    if (filled != bytes.len) return null;
    return record;
}

/// True when the failure is one no message in this file can cause: the kernel
/// has no `dummy` link kind and cannot load one. **Everything else is this
/// file's own fault and must fail the test.**
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
    // **This is the blackhole invariant, on the bytes.** A `dummy` accepts a
    // packet and frees it, so nothing leaves the namespace by any device. Any
    // other kind here, a `veth` above all, delivers the packet to another
    // namespace, and a raw socket then walks around the nat chain, the filter
    // chain, the listener and the policy together. See the top comment.
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
    // The other half of the blackhole invariant. A route with a gateway names
    // a machine that forwards, and there is none inside this namespace. The
    // route carries an output interface and nothing else, so the kernel builds
    // a packet, hands it to the dummy, and the dummy frees it.
    inline for (.{ af_inet, af_inet6 }) |family| {
        var buffer: [max_request]u8 = undefined;
        const length = buildDefaultRoute(&buffer, family, 3, 11);
        var messages = Messages{ .bytes = buffer[0..length] };
        const message = messages.next() orelse return error.TestUnexpectedResult;
        try testing.expectEqual(rtm_newroute, message.kind);

        // Family, a destination prefix length of zero, the main table, and a
        // plain unicast route.
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
    // The change mask says which flags the kernel may touch. A mask wider than
    // IFF_UP would clear every flag the caller did not name, which for
    // loopback means clearing IFF_LOOPBACK itself.
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
    // IFA_ADDRESS is the far end of a point to point link, and IFA_LOCAL is
    // this end. There is no far end on a dummy, so the two are equal. A kernel
    // given only one of them treats the address differently, and this is the
    // pair `ip addr add` sends.
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

/// A run that got nowhere, with the step and the errno it got nowhere on.
/// Everything else is zero, which is what a child that measured nothing sends.
fn failedAt(step: Step, errno: i32) Measurement {
    var record = std.mem.zeroes(Measurement);
    record.failed_step = @intFromEnum(step);
    record.failed_errno = errno;
    return record;
}

test "a refusal that is not a missing module fails the test rather than skipping it" {
    // The skip is for one host only: a kernel with no `dummy` link kind, which
    // no message in this file can cause. rtnetlink itself is built into every
    // kernel that has a network at all, so a socket that will not open is the
    // same kind of answer.
    try testing.expect(measuredNothing(failedAt(.dummy_create, @intFromEnum(linux.E.OPNOTSUPP))));
    try testing.expect(measuredNothing(failedAt(.open_socket, @intFromEnum(linux.E.PROTONOSUPPORT))));

    // **Every other step names a message this file wrote, so a refusal there
    // is a bug here and must be loud.** A step that quietly turns into a skip
    // is how a broken setup passes a green suite.
    try testing.expect(!measuredNothing(failedAt(.route4_add, @intFromEnum(linux.E.OPNOTSUPP))));
    try testing.expect(!measuredNothing(failedAt(.address6_add, @intFromEnum(linux.E.AFNOSUPPORT))));
    try testing.expect(!measuredNothing(failedAt(.device_up, @intFromEnum(linux.E.NODEV))));
    try testing.expect(!measuredNothing(failedAt(.loopback_up, @intFromEnum(linux.E.PERM))));
    // The `dummy` kind is there and the device is already made, so this ran
    // twice or ran in the wrong namespace. That is a caller's bug, not a host.
    try testing.expect(!measuredNothing(failedAt(.dummy_create, @intFromEnum(linux.E.EXIST))));

    // A run that refused nothing measured everything.
    var clean = std.mem.zeroes(Measurement);
    clean.failed_step = Measurement.no_failure;
    try testing.expect(!measuredNothing(clean));

    // A `dummy` that is missing and a route the kernel would not take are two
    // different things, and only the first is the host's.
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

    // Loopback is index 1 in every new network namespace, which is what the
    // `oif "lo" accept` rule in `nftables.zig` depends on.
    try testing.expectEqual(@as(u32, 1), record.loopback_index);
    try testing.expectEqual(iff_up, record.loopback_flags & iff_up);

    // The blackhole is a real device, it is up, and the kernel agrees it is a
    // dummy. **The kind is read from the kernel and not from the request**,
    // because the request is the thing under test.
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

    // The IPv6 address is read back too, because without it an IPv6 `connect`
    // has no source address and the guard chain's `ip6 daddr` rule governs
    // nothing.
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
        // **The device this file made, and no other.** A default route through
        // anything else is a route out of the namespace.
        try testing.expectEqual(record.device_index, route[4]);
        try testing.expectEqual(@as(u32, 0), route[5]);
    }
}

test "the blackhole takes a connection at the socket layer and never completes one" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.failed_step);

    // **Before: the socket layer refuses.** No packet is made, so no filter
    // ever sees it and no rule in `chock.zon` can govern it. **The two
    // families say so differently**, measured on kernel 6.18: IPv4 finds no
    // route and answers ENETUNREACH, and IPv6 gets as far as source address
    // selection, finds the namespace holds no address of its own, and answers
    // EADDRNOTAVAIL.
    try testing.expectEqual(@intFromEnum(linux.E.NETUNREACH), record.before4_errno);
    try testing.expectEqual(@intFromEnum(linux.E.ADDRNOTAVAIL), record.before6_errno);

    // **After: the socket layer takes it.** EINPROGRESS means a route was
    // found, a source address was picked, and a SYN was built and handed to a
    // device. That is the whole purpose of this file.
    try testing.expectEqual(@intFromEnum(linux.E.INPROGRESS), record.after4_errno);
    try testing.expectEqual(@intFromEnum(linux.E.INPROGRESS), record.after6_errno);

    // **And nothing answers.** "Reached the socket layer" and "reached
    // something" differ here: a connection that reached something completes,
    // or is refused with a reset, inside a fraction of a millisecond. This one
    // does neither. The socket is still waiting when the window closes, so
    // `completed` is false and `SO_ERROR` was never read.
    try testing.expectEqual(@as(u32, 0), record.completed4);
    try testing.expectEqual(@as(u32, 0), record.completed6);
    try testing.expectEqual(@as(i32, 0), record.so_error4);
    try testing.expectEqual(@as(i32, 0), record.so_error6);

    // **And the packet really went to the device.** The dummy counted the two
    // SYNs on the way out and gave nothing back, which is the difference
    // between a packet the kernel discarded and a packet that went somewhere.
    // A device that delivered anywhere would have a receive count of its own.
    try testing.expect(record.tx_packets > 0);
    try testing.expectEqual(@as(u64, 0), record.rx_packets);
}
