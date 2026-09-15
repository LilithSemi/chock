//! The userspace half of the network router: the TCP relay every outbound
//! connection is redirected to, and the resolver beside it.
//!
//! ## What this is for
//!
//! `netns.zig` gives the sandbox a network with no exit, and `nftables.zig`
//! tells the kernel what may leave it. Between them they leave two jobs that
//! only a program can do. A redirected connection arrives on a local port and
//! somebody has to work out where it was going and carry its bytes there. And
//! a policy written in names has to meet a kernel that only knows addresses.
//! This file is both of those, in one process, because they are one capability
//! story and one thing to confine.
//!
//!     program connects to 1.2.3.4:443
//!       -> guard chain: is 1.2.3.4 in the allow set?
//!            no  -> rejected, and nothing here ever sees it
//!            yes -> redirected to the relay port
//!       -> the relay accepts, recovers 1.2.3.4:443 with SO_ORIGINAL_DST,
//!          and carries the bytes on a descriptor made outside the namespace
//!
//!     program resolves registry.npmjs.org
//!       -> the resolver answers on UDP 53 inside the namespace
//!       -> the policy judges the NAME, the host resolves it, the address goes
//!          into the kernel allow set, and only then does the answer leave
//!       -> a name the policy refuses answers REFUSED and adds no address
//!
//! ## THE RESOLVER IS NOT A BOUNDARY
//!
//! It is what lets the boundary speak in names. `SO_ORIGINAL_DST` gives an
//! address. Every rule an author writes is a name. The resolver is the one
//! place where a name becomes an address, so it is the one place that can put
//! an address in the kernel's allow set with a policy answer behind it.
//!
//! **An address Chock never handed out is not in the set and dies at the
//! kernel.** That one sentence covers a hardcoded address, a program that
//! carries its own resolver, and DNS over HTTPS, without this file knowing
//! that any of the three exist. Nothing here enumerates a bypass, because the
//! set is empty until a policy answer fills it.
//!
//! ## What a dead relay does, and why it is not a hang
//!
//! The redirect is the kernel's, not this program's. If this process is gone,
//! the kernel still rewrites the destination to the relay port and then finds
//! nothing bound there, so it answers the connection with a reset and the
//! program gets `ECONNREFUSED` at once. **A missing relay is an error and
//! never a wait.** `stopListening` exists so a test can take the listener away
//! and measure exactly that, and `a connection with the relay gone is refused
//! rather than left waiting` below is the measurement.
//!
//! ## UDP is not redirected, and must not be
//!
//! Measured on 2026-09-14: under a REDIRECT, `IP_RECVORIGDSTADDR` gives the
//! address **after** the rewrite, and `SO_ORIGINAL_DST` answers `ENOPROTOOPT`
//! on an unconnected UDP socket. There is no way to learn where a redirected
//! datagram was going. So the resolver is not a redirect target at all: it is
//! simply the address the sandbox is told to use, and the `resolv.conf` inside
//! the sandbox names it. Do not add a UDP redirect and do not try to recover a
//! UDP destination.
//!
//! ## The outbound descriptor is inherited and never made here
//!
//! A socket made inside this network namespace can only reach the blackhole.
//! The relay's outbound descriptor has to be made outside, before the
//! namespace is entered, exactly as `netbroker.zig` already does for a
//! filtered process. That is why `Host.open` is a seam and not a `connect`
//! call in this file.
//!
//! **The relay's own egress never traverses the guard chain**, because it uses
//! a descriptor the kernel associates with another namespace. The kernel
//! cannot constrain the relay. The `SO_ORIGINAL_DST` recovery and the
//! `Policy.connect` question after it are the only control on that path.
//!
//! ## The seams, and what is deliberately not here
//!
//! `Policy` and `Host` are the two seams, the same shape
//! `chock-broker/network.zig` uses for its `Transport`. `Policy` answers about
//! a name and about a destination. `Host` resolves a name, opens the kernel's
//! door, and hands back a descriptor that leaves the namespace. Every test
//! below drives fakes, which is what lets a test pin that a refused name was
//! **never looked up** and that a refused connection was **never dialled**.
//!
//! No policy table, no broker, no capability dropping, and no wiring into a
//! driver. **Nothing calls this yet.** It is the third piece of the router and
//! the wiring lands next.
//!
//! ## Linux only, and why the file is here
//!
//! `SO_ORIGINAL_DST` is a netfilter socket option and the redirect that fills
//! it is nftables, so there is nothing to run on Darwin. `std.posix` in this
//! Zig version has `poll`, `read` and `setsockopt` and no socket calls at all,
//! so everything else reaches the kernel through `std.os.linux`, the same as
//! `netns.zig`, `nftables.zig` and `netbroker.zig` beside it. The file
//! compiles for Darwin and every test in it that opens a socket answers
//! `error.SkipZigTest` there.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

const nftables = @import("nftables.zig");
const netns = @import("netns.zig");

/// Only the tests below use this, to get a network namespace of their own to
/// route inside. Nothing in the module itself enters a namespace.
const namespace = @import("namespace.zig");

/// Where the relay listens. The same number the nat chain redirects to, taken
/// from there so the two can never drift apart.
pub const relay_port: u16 = nftables.relay_port;

/// Where the resolver listens. **Not a redirect target**: it is the address
/// and port the sandbox's own `resolv.conf` names. See the top comment.
pub const resolver_port: u16 = 53;

/// How many connections the relay carries at once. A fixed array, because this
/// process has no allocator and a router that can be made to allocate by a
/// program inside the sandbox is a router with a new way to fail.
pub const max_links: usize = 32;

/// Bytes held in each direction of each link. Two per link, so the whole
/// structure is about a quarter of a megabyte. See `Router` for where to put
/// one.
pub const link_buffer_bytes: usize = 4096;

/// The longest name the resolver will parse or remember. A DNS name is at most
/// 253 characters in the presentation form this uses, so nothing real is lost
/// and a longer one is refused rather than truncated.
pub const name_capacity: usize = 255;

/// How many address to name pairs the table holds. See `NameTable` for the
/// bound and the expiry.
pub const name_table_capacity: usize = 64;

/// The largest datagram the resolver reads. Longer than the 512 bytes plain
/// DNS allows, so an EDNS query arrives whole and is parsed rather than
/// truncated into a format error.
pub const query_capacity: usize = 1500;

/// Which set an address belongs in and what the kernel stores. The same type
/// `nftables.allow` takes, so an address the resolver hands out reaches the
/// allow set without being rewritten on the way.
pub const Address = nftables.Address;

/// An address and a port together: what a program asked for, and what the
/// relay recovers after the kernel has rewritten it.
pub const Destination = struct {
    address: Address,
    port: u16,

    pub fn equals(self: Destination, other: Destination) bool {
        return self.port == other.port and addressesEqual(self.address, other.address);
    }
};

/// The only two record types the resolver answers. Everything else is refused
/// rather than implemented: see `serveQuery`.
pub const RecordKind = enum(u16) {
    a = 1,
    aaaa = 28,

    /// The address family this record type carries. A mismatched pair is a
    /// mistake in this program, and `buildReply` asserts on one.
    pub fn family(self: RecordKind) std.meta.Tag(Address) {
        return switch (self) {
            .a => .ipv4,
            .aaaa => .ipv6,
        };
    }
};

// ---------------------------------------------------------------------------
// The seams.
// ---------------------------------------------------------------------------

/// Who decides. **One of the two seams in this file**, and the reason no test
/// here needs a policy table.
///
/// Two questions and not one, because they are asked at different moments and
/// about different things. `name` is asked before any address exists, which is
/// what makes the answer a decision about the name the program wrote rather
/// than about whatever that name happens to resolve to today. `connect` is
/// asked about a destination the kernel already let through, and it is the
/// only control on the relay's own egress, which no filter can reach.
pub const Policy = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Verdict = enum { permit, refuse };

    pub const VTable = struct {
        /// May this name be resolved at all, for this record type.
        name: *const fn (ptr: *anyopaque, name: []const u8, kind: RecordKind) Verdict,
        /// May the relay carry bytes to this destination. `name` is the name
        /// the resolver last handed this address out for, or null when the
        /// table holds none. **It is a narrowing and not an identity**: see
        /// `NameTable`.
        connect: *const fn (ptr: *anyopaque, name: ?[]const u8, dest: Destination) Verdict,
    };

    pub fn askName(self: Policy, name: []const u8, kind: RecordKind) Verdict {
        return self.vtable.name(self.ptr, name, kind);
    }

    pub fn askConnect(self: Policy, name: ?[]const u8, dest: Destination) Verdict {
        return self.vtable.connect(self.ptr, name, dest);
    }
};

/// The three things the router cannot do from where it stands. **The other
/// seam**, and every one of the three is a capability this file must not hold
/// itself.
///
/// * `resolve` reaches a real resolver, which is on the host side of the
///   sandbox boundary. Nothing inside the namespace can reach one.
/// * `allow` writes the kernel's allow set, which needs `CAP_NET_ADMIN`.
/// * `open` answers with a connected descriptor **made outside this network
///   namespace**. A socket made inside reaches the blackhole and nothing else.
pub const Host = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const ResolveError = error{
        /// No address of that family for that name, whatever the reason was.
        /// **One member and not a resolver's own set**, because none of the
        /// reasons changes what happens here: there is no address, so there is
        /// nothing to put in the allow set and nothing to answer with.
        NotResolved,
    };

    pub const AllowError = error{
        /// The address did not reach the kernel's allow set. The resolver must
        /// not answer after this: an address the guard chain will refuse is an
        /// answer that turns into a refused connection later, and the truth is
        /// available now.
        NotAllowed,
    };

    pub const OpenError = error{
        /// No descriptor. The relay closes the connection it had accepted, so
        /// the program sees the connection end rather than wait.
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

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

/// Which call the kernel refused. Every error out of this file carries one,
/// because `EACCES` on `resolver_bind` is a process without
/// `CAP_NET_BIND_SERVICE` and `EACCES` anywhere else is something different.
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

/// The call the kernel refused and what it answered. Filled on every error.
pub const Diagnostic = struct {
    step: Step,
    /// The positive errno. Kept as a number because it comes from the kernel,
    /// and an integer from outside is not an enum until something checks it.
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
    /// Port 53 is a privileged port and this process may not bind one. In a
    /// user namespace the process is root and holds `CAP_NET_BIND_SERVICE`, so
    /// this means the capability was dropped before the router opened, which
    /// is the ordering mistake `nftables.zig` names for `CAP_NET_ADMIN`.
    PrivilegedPort,
    /// Something is already bound where the router has to listen. A second
    /// router in the same namespace, or a program inside the sandbox that got
    /// there first.
    AddressInUse,
    /// The kernel would not give a socket or a permission this file needs.
    NotPermitted,
    /// The kernel refused for a reason this file does not recognise. Read the
    /// diagnostic. This is a bug here, not a property of the host.
    Refused,
    /// The wait the whole loop is built on would not run. Nothing can be
    /// served after this, so it ends the router rather than a connection.
    PollFailed,
};

fn note(diag: ?*?Diagnostic, step: Step, errno: i32) void {
    if (diag) |slot| slot.* = .{ .step = step, .errno = errno };
}

/// Turn a refusal into a name a caller can act on.
///
/// * `EACCES` on `resolver_bind`: port 53 is privileged and this process may
///   not bind one. **Only on that one step**, because it is the only bind to a
///   port below 1024 this file makes.
/// * `EACCES` and `EPERM` anywhere else: a permission this file needs is gone.
/// * `EADDRINUSE`: something else holds the port.
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

// ---------------------------------------------------------------------------
// What the relay recovers.
// ---------------------------------------------------------------------------

/// `SO_ORIGINAL_DST`, and `IP6T_SO_ORIGINAL_DST` beside it. The same number on
/// both levels, which is a coincidence in the kernel headers and not a rule.
const so_original_dst: u32 = 80;
const ip6t_so_original_dst: u32 = 80;

pub const OriginalError = error{
    /// The kernel holds no pre-nat destination for this connection. Either it
    /// was never redirected, so somebody inside the sandbox connected to the
    /// relay port on purpose, or conntrack has already forgotten it. **The
    /// relay refuses the connection**: it has no destination to carry the
    /// bytes to and no name to ask the policy about.
    NoOriginalDestination,
};

/// Where this connection was going before the kernel rewrote it.
///
/// **The answer is the pre-nat address**, which is what the program asked for,
/// and not the relay's own address the packet now carries. Measured on kernel
/// 6.18 with a dual stack listener: the IPv4 level answers for a connection
/// that arrived as an IPv4 mapped address, and the IPv6 level answers for a
/// native one, so the two are tried in that order.
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

/// `struct sockaddr_in`: the family, then the port in network byte order, then
/// four bytes of address. **The port is big endian and the family is not**,
/// which is the one thing about this structure that is easy to get backwards
/// and impossible to see afterwards.
fn decodeOriginal4(raw: []const u8) ?Destination {
    if (raw.len < @sizeOf(linux.sockaddr.in)) return null;
    if (std.mem.readInt(u16, raw[0..2], .little) != linux.AF.INET) return null;
    return .{
        .port = std.mem.readInt(u16, raw[2..4], .big),
        .address = .{ .ipv4 = raw[4..8].* },
    };
}

/// `struct sockaddr_in6`: the family, the port, four bytes of flow label, then
/// sixteen bytes of address.
///
/// An IPv4 address written as an IPv6 one is unwrapped, because the guard
/// chain sees the real IPv4 packet and holds that address in `allowed4`. A
/// mapped address left wrapped would be asked about in the wrong family and
/// would never match the name the resolver stored.
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

// ---------------------------------------------------------------------------
// The address to name table.
// ---------------------------------------------------------------------------

/// What the resolver handed out, so the relay can turn a destination back into
/// the name the policy is written in.
///
/// **The bound is `name_table_capacity` entries and the array never grows.** A
/// program inside the sandbox drives how many names are resolved, so a table
/// that grew with them would be a way to spend this process's memory from
/// inside. A full table drops the entry that was going to expire first, which
/// is the one a re-resolution is most likely to replace anyway.
///
/// **The expiry is the same lifetime the kernel gives the allow set element.**
/// The caller passes it in, so the two cannot drift: an address the kernel has
/// forgotten is an address this table has forgotten, and a name that is still
/// reachable is a name the relay can still put to the policy. Nothing here
/// keeps a timer. An entry is dead when it is read after its deadline, and the
/// slot is taken by the next name that needs one.
///
/// **This is a heuristic and must be documented as one.** It answers with the
/// name this address was **last** handed out for. Two names can resolve to one
/// address, which on a large content network is the usual case rather than an
/// unusual one, so the answer narrows a destination to a likely name and does
/// not identify it. The policy must treat it that way: a `connect` decision
/// that has to be exact belongs on the address, not on this name.
pub const NameTable = struct {
    entries: [name_table_capacity]Entry = @splat(.{}),

    const Entry = struct {
        address: Address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
        name: [name_capacity]u8 = @splat(0),
        name_len: u8 = 0,
        /// The millisecond after which this entry answers nothing.
        deadline_ms: i64 = 0,
        live: bool = false,
    };

    /// Record that `address` was handed out for `name`, for `lifetime_ms`.
    ///
    /// An address that is already here keeps its slot and gets the new name
    /// and the new deadline, which is what re-resolving a live name does.
    pub fn remember(
        self: *NameTable,
        address: Address,
        name: []const u8,
        now_ms: i64,
        lifetime_ms: u64,
    ) void {
        // The resolver parses into a fixed buffer of exactly this size, so a
        // longer name is a mistake in this program rather than an input.
        std.debug.assert(name.len <= name_capacity);

        const slot = self.slotFor(address, now_ms);
        slot.address = address;
        slot.name_len = @intCast(name.len);
        @memcpy(slot.name[0..name.len], name);
        slot.deadline_ms = now_ms +| @as(i64, @intCast(@min(lifetime_ms, std.math.maxInt(i64))));
        slot.live = true;
    }

    /// The name this address was last handed out for, or null when the table
    /// holds none that is still alive.
    pub fn lookup(self: *const NameTable, address: Address, now_ms: i64) ?[]const u8 {
        for (&self.entries) |*entry| {
            if (!entry.live) continue;
            if (entry.deadline_ms <= now_ms) continue;
            if (!addressesEqual(entry.address, address)) continue;
            return entry.name[0..entry.name_len];
        }
        return null;
    }

    /// How many entries are still alive. For a caller that wants to report the
    /// table's size, and for the tests that pin the bound.
    pub fn live(self: *const NameTable, now_ms: i64) usize {
        var total: usize = 0;
        for (&self.entries) |*entry| {
            if (entry.live and entry.deadline_ms > now_ms) total += 1;
        }
        return total;
    }

    /// The same address, else a slot nothing alive is using, else the entry
    /// that dies first.
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

// ---------------------------------------------------------------------------
// The DNS wire, and only as much of it as a name needs.
// ---------------------------------------------------------------------------

const dns_header_bytes: usize = 12;
/// `IN`, the only class anything here answers.
const class_internet: u16 = 1;

/// The answer codes this file sends. Nothing reads one back, so the set is
/// only what is written.
pub const Rcode = enum(u4) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
    /// **Not used.** A name the policy refuses is refused, not declared
    /// absent: `name_error` is a claim about the world and `refused` is a
    /// claim about this resolver, and only the second one is true.
    name_error = 3,
    not_implemented = 4,
    refused = 5,
};

/// One question, parsed. Everything an answer needs and nothing else.
pub const Query = struct {
    id: u16,
    opcode: u4,
    recursion_desired: bool,
    qtype: u16,
    qclass: u16,
    name_len: u8,
    /// Lower case, dot separated, and with no trailing dot, which is the
    /// spelling a policy rule is written in. **The answer echoes the original
    /// bytes and not this**, so a client that varied the case of its question
    /// gets its own spelling back.
    name: [name_capacity]u8,
    /// How many bytes the header and the question take together. The answer
    /// copies exactly this many.
    question_end: usize,

    pub fn text(self: *const Query) []const u8 {
        return self.name[0..self.name_len];
    }

    /// The record type, when it is one the resolver answers.
    pub fn kind(self: *const Query) ?RecordKind {
        return std.enums.fromInt(RecordKind, self.qtype);
    }
};

pub const ParseError = error{
    /// The QR bit says this is an answer. Nothing sends an answer to a
    /// resolver, so it is dropped rather than replied to.
    NotAQuery,
    /// Not exactly one question. Zero has nothing to answer, and more than one
    /// has no reply shape every client agrees on.
    NotOneQuestion,
    /// The bytes do not hold the name and the type the header promises.
    Malformed,
};

/// Read the one question out of a query. **This is the only DNS parsing here**
/// and there must not be more: everything past the question is copied or
/// dropped, never interpreted.
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
        // **A compression pointer is refused and never followed.** The top two
        // bits mark one. A question in a query does not carry one, and a
        // parser that follows a pointer can be sent around a loop by whoever
        // wrote the packet, which here is the program being sandboxed.
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
    // The root names nothing to resolve and nothing to ask a policy about.
    if (used == 0) return error.Malformed;

    query.name_len = @intCast(used);
    if (at + 4 > bytes.len) return error.Malformed;
    query.qtype = std.mem.readInt(u16, bytes[at..][0..2], .big);
    query.qclass = std.mem.readInt(u16, bytes[at + 2 ..][0..2], .big);
    query.question_end = at + 4;
    return query;
}

/// One address to answer with, of the type that was asked for.
pub const Answer = struct {
    kind: RecordKind,
    address: Address,
};

/// Build the reply to `query`, whose bytes are `source`.
///
/// The header and the question are copied from the query, so the identifier
/// comes back and the name comes back spelled the way it was asked. An
/// `answer` of null makes a refusal, or a reply with nothing in it. Those are
/// the same message with a different code and no answer section.
///
/// Answers null when `out` is too small, which the caller treats as a reply it
/// cannot send.
pub fn buildReply(
    out: []u8,
    source: []const u8,
    query: *const Query,
    rcode: Rcode,
    answer: ?Answer,
    ttl_s: u32,
) ?usize {
    // The parse produced these, so a question that runs past the bytes it was
    // read from is a mistake here rather than a bad packet.
    std.debug.assert(query.question_end <= source.len);

    const record: []const u8 = if (answer) |found| switch (found.address) {
        .ipv4 => |*bytes| bytes,
        .ipv6 => |*bytes| bytes,
    } else &.{};
    if (answer) |found| {
        // An A record carrying sixteen bytes is a packet no client can read,
        // and nothing outside this file chooses the pair.
        std.debug.assert(found.kind.family() == std.meta.activeTag(found.address));
    }

    const answer_bytes: usize = if (answer == null) 0 else 2 + 2 + 2 + 4 + 2 + record.len;
    const total = query.question_end + answer_bytes;
    if (out.len < total) return null;

    @memcpy(out[0..query.question_end], source[0..query.question_end]);

    var flags: u16 = 0x8000 | @as(u16, @intFromEnum(rcode));
    flags |= @as(u16, query.opcode) << 11;
    if (query.recursion_desired) flags |= 0x0100;
    // Recursion is available: this resolver does ask somebody else.
    flags |= 0x0080;
    std.mem.writeInt(u16, out[2..4], flags, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], if (answer == null) 0 else 1, .big);
    std.mem.writeInt(u16, out[8..10], 0, .big);
    std.mem.writeInt(u16, out[10..12], 0, .big);

    if (answer) |found| {
        var at = query.question_end;
        // A pointer to the name at offset 12, which is where the question's
        // name starts in every message this file builds.
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

/// The reply to bytes that could not be parsed: the identifier back, no
/// question, and a format error. **A packet the resolver cannot read still
/// gets an answer**, because the alternative is a program waiting on a
/// resolver that will never speak, and a wait is the worst shape a refusal
/// can have.
///
/// Answers null when there are not even enough bytes to hold an identifier, in
/// which case there is nothing to address a reply to.
pub fn buildFormatError(out: []u8, source: []const u8) ?usize {
    if (source.len < dns_header_bytes or out.len < dns_header_bytes) return null;
    @memset(out[0..dns_header_bytes], 0);
    @memcpy(out[0..2], source[0..2]);
    const flags: u16 = 0x8000 | 0x0080 | @as(u16, @intFromEnum(Rcode.format_error));
    std.mem.writeInt(u16, out[2..4], flags, .big);
    return dns_header_bytes;
}

// ---------------------------------------------------------------------------
// The router.
// ---------------------------------------------------------------------------

/// What the router did, counted. **Recovery is never silent**: every refusal
/// and every dropped connection lands in one of these, so a session can say
/// what happened without this file holding a log writer.
pub const Counts = struct {
    /// Connections the kernel handed the relay.
    accepted: u64 = 0,
    /// Accepted, and the kernel held no pre-nat destination for them.
    without_destination: u64 = 0,
    /// Accepted, and the policy refused the destination.
    refused_destinations: u64 = 0,
    /// Accepted and permitted, and there was no free link.
    without_link: u64 = 0,
    /// Accepted and permitted, and the host gave no descriptor.
    without_upstream: u64 = 0,
    /// Carried: a link was made and the bytes have somewhere to go.
    linked: u64 = 0,
    /// Links that ended, for any reason.
    closed: u64 = 0,

    /// Datagrams the resolver read.
    queries: u64 = 0,
    /// Answered with an address.
    answered: u64 = 0,
    /// Refused because the policy refused the name.
    refused_names: u64 = 0,
    /// Refused because the record type or the class is not answered here.
    refused_types: u64 = 0,
    /// Permitted, and the host had no address of that type. Answered with no
    /// error and no answer.
    empty_answers: u64 = 0,
    /// Permitted and resolved, and the address would not go in the allow set.
    /// Answered with a server failure and no address.
    allow_failures: u64 = 0,
    /// Datagrams that could not be parsed.
    malformed_queries: u64 = 0,
};

pub const Options = struct {
    policy: Policy,
    host: Host,
    /// Which address the resolver binds inside the namespace. The blackhole
    /// device's own address by default, which is the address the sandbox's
    /// `resolv.conf` has to name.
    resolver_address: Address = .{ .ipv4 = netns.address4 },
    /// How long an address the resolver hands out stays in the kernel's allow
    /// set, and how long this file remembers its name.
    allow_timeout_ms: u64 = nftables.default_timeout_ms,
    /// The lifetime the answer carries. **Shorter than `allow_timeout_ms`**,
    /// so a program re-resolves while the door is still open and the fresh
    /// resolution restarts it. `open` asserts the relation.
    answer_ttl_s: u32 = 10,
};

/// One process holding both listeners.
///
/// **Open it in place.** The structure carries every link's buffers, so it is
/// a few hundred kilobytes, and returning one by value would copy all of it.
pub const Router = struct {
    /// The relay's listening socket, or -1 once `stopListening` has taken it
    /// away. A negative descriptor is what `poll` ignores, so the loop needs
    /// no test for it.
    relay_fd: posix.fd_t,
    resolver_fd: posix.fd_t,
    policy: Policy,
    host: Host,
    allow_timeout_ms: u64,
    answer_ttl_s: u32,
    names: NameTable,
    links: [max_links]Link,
    counts: Counts,

    /// Bind both listeners. **Inside the network namespace**, after
    /// `netns.configure` has brought loopback up and while
    /// `CAP_NET_BIND_SERVICE` is still held.
    pub fn open(self: *Router, options: Options, diag: ?*?Diagnostic) Error!void {
        // A lifetime the program cannot re-resolve inside is a door that shuts
        // under a live connection. The numbers are Chock's own, never the
        // sandboxed program's, so a bad pair is a mistake here.
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

    /// How many bytes this router has read and not yet written on.
    ///
    /// **For a caller that has to know when there is nothing left to carry**,
    /// which is the one question a shutdown asks. A program that wrote its
    /// last bytes and exited leaves them here, in the buffer of a live link,
    /// and a router that stopped at that instant would drop them. A caller
    /// steps until this is zero and then leaves.
    ///
    /// **Bytes and not links.** A link stays live for as long as either peer
    /// holds its end, and the peer outside the sandbox has no reason to let go
    /// when the program inside it ends. Waiting for a link to close would
    /// therefore wait for something that may never happen, and waiting for the
    /// bytes waits for the only thing that can still be lost.
    pub fn pendingBytes(self: *const Router) usize {
        var total: usize = 0;
        for (&self.links) |*link| {
            if (!link.live) continue;
            total += link.out_bound.pending() + link.in_bound.pending();
        }
        return total;
    }

    /// Take the relay's listener away and leave everything else running.
    ///
    /// **This is what a dead relay looks like to the kernel**, and the only
    /// reason it is public: the redirect is still installed, so the next
    /// connection is rewritten to a port nothing is bound to and the kernel
    /// resets it. Links already made are untouched.
    pub fn stopListening(self: *Router) void {
        if (self.relay_fd < 0) return;
        _ = linux.close(self.relay_fd);
        self.relay_fd = -1;
    }

    /// Wait once and serve whatever is ready. `timeout_ms` is passed straight
    /// to `poll`, so -1 waits and 0 does not.
    ///
    /// **Only the wait itself can end the router.** Everything else is one
    /// connection or one datagram going wrong, and each of those is counted
    /// and closed rather than returned.
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

    /// Serve until the wait itself fails. There is no other way out: the
    /// router runs for as long as the sandbox does.
    ///
    /// **A monotonic clock, and not the real one.** Every deadline here is a
    /// span and not a date, so a clock the machine's administrator or NTP can
    /// move would expire a name table entry early, or leave one alive late,
    /// for no reason a reader could see. `boot` counts the time the machine
    /// spent suspended, so the table forgets a name no later than the kernel
    /// forgets the address, and forgetting early is the safe direction: the
    /// relay then asks the policy about a destination with no name, which is
    /// the same question a destination nobody resolved gets.
    ///
    /// `step` takes the millisecond instead of reading one, which is what lets
    /// every test below name its own time.
    pub fn run(self: *Router, io: std.Io, diag: ?*?Diagnostic) Error!noreturn {
        while (true) {
            const now = std.Io.Timestamp.now(io, .boot).toMilliseconds();
            try self.step(now, -1, diag);
        }
    }

    /// Take one connection the kernel redirected here.
    ///
    /// The order matters and is the whole control on this path. The
    /// destination is recovered first, because without it there is nothing to
    /// ask about. The policy is asked next, **before** anything is dialled, so
    /// a refused destination is never reached. A link is reserved only after
    /// that, and the descriptor is asked for last.
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

    /// Answer one query.
    ///
    /// **The address goes into the kernel's allow set before the answer
    /// leaves.** The program cannot connect until it has the answer, so there
    /// is no window in which it holds an address the guard chain would refuse.
    /// Doing it the other way round would make every first connection a race.
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
            // **Nothing was resolved and nothing entered the set.** The policy
            // answered before the host was asked, which is what makes the
            // refusal cost nothing and leak nothing.
            self.refuse(&out, source, &query, .refused, &peer, peer_len);
            return;
        }

        const address = self.host.resolve(query.text(), kind.?) catch {
            // The policy permitted the name, so a refusal here would report a
            // decision that was never made. No error and no answer is what a
            // resolver says when it holds nothing of that type.
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
        // One datagram, and no retry. A reply the kernel would not take is a
        // query the program asks again, which costs it one timeout and costs
        // this loop nothing.
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

/// One connection carried in both directions.
///
/// **Backpressure is the buffer.** A direction stops being polled for reading
/// once its buffer is full, so a peer that reads slowly slows the peer that
/// writes fast instead of making this process hold the difference.
const Link = struct {
    /// The connection the sandboxed program made, after the kernel redirected
    /// it here.
    inside: posix.fd_t = -1,
    /// The descriptor the host seam gave back. **Made outside this network
    /// namespace**: see the top comment.
    outside: posix.fd_t = -1,
    /// Bytes read from inside and not yet written outside.
    out_bound: Buffer = .{},
    /// Bytes read from outside and not yet written inside.
    in_bound: Buffer = .{},
    /// The inside peer sent an end of file.
    inside_done: bool = false,
    outside_done: bool = false,
    /// This link has already told the other side that no more bytes come.
    inside_shut: bool = false,
    outside_shut: bool = false,
    live: bool = false,

    fn descriptor(self: *const Link, side: Side) posix.fd_t {
        return switch (side) {
            .inside => self.inside,
            .outside => self.outside,
        };
    }

    /// Where bytes read from `side` go.
    fn intake(self: *Link, side: Side) *Buffer {
        return switch (side) {
            .inside => &self.out_bound,
            .outside => &self.in_bound,
        };
    }

    /// Where bytes written to `side` come from.
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

    /// Move whatever this side is ready for.
    fn service(self: *Link, side: Side, revents: i16) void {
        if (revents == 0) return;
        if (revents & (posix.POLL.ERR | posix.POLL.NVAL) != 0) {
            // Nothing can be read from this link or written to it again, so
            // what is waiting in either direction has nowhere to go.
            self.inside_done = true;
            self.outside_done = true;
            self.out_bound.clear();
            self.in_bound.clear();
            return;
        }

        // A hang up is read like readable data. The last bytes the peer wrote
        // are still in the socket, and reading them is what tells the end of
        // one direction apart from the end of both.
        if (revents & (posix.POLL.IN | posix.POLL.HUP) != 0) self.readFrom(side);
        if (revents & posix.POLL.OUT != 0) self.writeTo(side);
        self.halfClose();
    }

    fn readFrom(self: *Link, side: Side) void {
        const into = self.intake(side);
        if (into.room() == 0) return;
        const got = posix.read(self.descriptor(side), into.free()) catch |err| switch (err) {
            error.WouldBlock => return,
            // Every other reason is this connection ending. The link closes
            // once the bytes already read have been written on.
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
        // **`MSG_NOSIGNAL`, never a plain write.** A peer that closed while
        // bytes were in flight would otherwise kill this process with
        // `SIGPIPE`, and the router carries every other connection in the
        // sandbox.
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
                // Nothing more can reach this side, so the bytes waiting for
                // it are dropped and the direction feeding it is finished.
                from.clear();
                self.setDone(switch (side) {
                    .inside => .outside,
                    .outside => .inside,
                });
                self.setDone(side);
            },
        }
    }

    /// Once one direction has ended and its bytes are gone, tell the other
    /// side. **A half close carried through is what lets a request finish**: a
    /// program that writes, shuts down, and waits for the answer gets nothing
    /// back from a relay that closes both directions together.
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

/// Bytes waiting to be written, in the order they were read.
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

    /// Throw away what is waiting. Only for a direction that has no reader
    /// left, where the bytes have nowhere to go.
    fn clear(self: *Buffer) void {
        self.start = 0;
        self.end = 0;
    }

    /// Give the written bytes back. Only when the buffer has emptied, so a
    /// partial write never moves what is left.
    fn compact(self: *Buffer) void {
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        }
    }
};

// ---------------------------------------------------------------------------
// Opening the two listeners.
// ---------------------------------------------------------------------------

/// The relay listens on every address of both families, because the kernel
/// decides which one a redirected packet arrives on and the relay does not get
/// to choose. `IPV6_V6ONLY` is turned off for the same reason: a redirected
/// IPv4 connection arrives on this socket as a mapped address, and a socket
/// that refused those would take only half the traffic the nat chain sends it.
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

    // A router that restarts inside a live namespace must not wait out a
    // previous socket's lingering close before it can take connections again.
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

/// The resolver listens on one address of one family: the one the sandbox's
/// `resolv.conf` names. **Not on every address**, because a resolver that
/// answered on an address nobody was told to use would answer a program that
/// went looking for one.
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

/// A descriptor from the host seam arrives however its owner made it, and the
/// loop only ever polls before it reads, so a blocking one would stop the
/// whole router on a socket that lied about being ready.
fn makeNonBlocking(fd: posix.fd_t) void {
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    if (linux.errno(flags) != .SUCCESS) return;
    var updated: linux.O = @bitCast(@as(u32, @truncate(flags)));
    updated.NONBLOCK = true;
    _ = linux.fcntl(fd, linux.F.SETFL, @as(usize, @as(u32, @bitCast(updated))));
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// The one name the fake policy permits.
const permitted_name = "registry.npmjs.test";
/// A name it refuses. The fake host holds an address for it anyway, so a test
/// can read the allow set and find that the address never arrived.
const refused_name = "metadata.evil.test";
/// A permitted name whose address the kernel will not take. See scenario J.
const walled_name = "wall.npmjs.test";

const permitted_ipv4: [4]u8 = .{ 93, 184, 216, 34 };
const refused_ipv4: [4]u8 = .{ 203, 0, 113, 7 };
const walled_ipv4: [4]u8 = .{ 198, 51, 100, 9 };
/// An address nothing ever resolved to, so nothing ever put it in the allow
/// set. This is the hardcoded address case.
const never_handed_ipv4: [4]u8 = .{ 10, 20, 30, 40 };

const permitted_port: u16 = 443;
/// The same address on a port the policy refuses. The kernel lets it through,
/// because the allow set holds addresses and not ports, so this is the one
/// case where `Policy.connect` is the whole control.
const refused_port: u16 = 8443;

/// What `attemptConnect` answers when the budget ran out. **Never expected**:
/// a connection that waits is the failure shape this file exists to remove.
const timed_out: i32 = -1;

/// The lifetime the child gives an allow set element. **Deliberately not the
/// set's own default**, which `Options` uses and which is what
/// `nftables.zig`'s set carries. The kernel stores no per element timeout for
/// an element whose timeout is the set default, so a test that used the
/// default would read a zero back and could not tell "the router passed its
/// timeout through" apart from "the router passed nothing and the set default
/// covered for it". Measured while writing this file.
const probe_timeout_ms: u64 = 45_000;
const probe_ttl_s: u32 = 10;

// ---------------------------------------------------------------------------
// The fakes behind the two seams.
// ---------------------------------------------------------------------------

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

/// The host side. **`allow` is the real kernel call**, so the allow set a test
/// reads back was written by `nftables.Session.allow` and not by this file.
/// The other two are fakes, because a real resolver would reach the network
/// and a real descriptor is the thing the wiring supplies.
const FakeHost = struct {
    session: nftables.Session,
    /// A descriptor made **before** the namespace was entered. It stands in
    /// for the connected socket the wiring will inherit. Handed out once.
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
        // **No IPv6 for any of them.** A permitted name with no address of the
        // type asked for is the "no error and no answer" path.
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

// ---------------------------------------------------------------------------
// Small helpers the child uses.
// ---------------------------------------------------------------------------

/// Write a query the way a resolver client would, so the parser is read
/// against bytes this file did not build with its own writer.
fn buildQuery(out: []u8, id: u16, name: []const u8, qtype: u16) usize {
    std.mem.writeInt(u16, out[0..2], id, .big);
    // Recursion desired, which is what every client sets.
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

/// Read the first answer record, which starts right after the question the
/// query carried.
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

/// Run the loop a few times. Twice is the minimum for a byte to cross a link:
/// one pass reads it into the buffer, and the next sees the far side writable.
fn pump(router: *Router, rounds: usize, now_ms: i64, timeout_ms: i32) void {
    var round: usize = 0;
    while (round < rounds) : (round += 1) {
        router.step(now_ms, timeout_ms, null) catch return;
    }
}

/// Send one query, let the router answer it, and read the answer back.
/// **Every wait is bounded**, so a resolver that never speaks fails the test
/// rather than hanging the suite.
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
    /// Zero when the connection completed, a positive errno when the socket
    /// layer refused it, and `timed_out` when the budget ran out.
    errno: i32,
    waited_ms: u64,
};

/// Connect from inside the namespace and answer what the socket layer said.
/// **Never waits longer than `budget_ms`**, because the whole point of the
/// measurement is that a refusal is fast and a hang is the failure.
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

/// Read whatever is already there, waiting no longer than `budget_ms`.
/// Answers zero for nothing and for an end of file alike, so a caller that
/// cares about the difference asks for it separately.
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

// ---------------------------------------------------------------------------
// One child, every measurement.
// ---------------------------------------------------------------------------

/// Which of the three pieces refused, so a failure says whether the host could
/// not build a sandbox or this file has a bug.
const Stage = enum(u32) {
    netns_configure,
    nftables_install,
    router_open,
};

/// Everything one child measured, in a shape the kernel carries whole through
/// a pipe. The child measures and the parent asserts, so a failing expectation
/// prints where the test runner can see it.
const Measurement = extern struct {
    stage: u32,
    failed_step: u32,
    failed_errno: i32,

    // A. The permitted name.
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

    // B. The permitted name, for a type the host holds no address of.
    empty_rcode: u32,
    empty_ancount: u32,

    // C. A name the policy refuses.
    refuse_rcode: u32,
    refuse_ancount: u32,
    refuse_element_found: u32,
    refuse_resolve_calls: u32,

    // D. A record type this resolver does not answer.
    type_rcode: u32,
    type_ancount: u32,

    // J. A permitted name whose address the kernel would not take.
    walled_rcode: u32,
    walled_ancount: u32,
    walled_element_found: u32,

    // E and F. The relay.
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

    // G. The policy refuses a destination the kernel let through.
    policy_errno: i32,
    policy_accepted: u64,
    policy_refused: u64,
    policy_open_calls: u32,
    policy_eof: u32,
    policy_asked_port: u32,

    // H. An address nothing ever handed out.
    blocked_errno: i32,
    blocked_waited_ms: u64,
    blocked_accepted: u64,

    // I. The relay is gone and the redirect is not.
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

    // 1. The network the namespace gets. Without it every connect below is
    //    refused by the socket layer and no filter ever runs.
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

    // 2. The ruleset. The guard chain and the redirect together.
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

    // 3. The router itself.
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

    // A. A permitted name. The address must reach the kernel's allow set and
    //    the answer must carry the same address.
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

    // B. The same name, for a type the host holds no address of.
    length = buildQuery(&query, 0x1235, permitted_name, @intFromEnum(RecordKind.aaaa));
    got = ask(&router, client_fd, &server, query[0..length], &reply, now);
    if (got >= dns_header_bytes) {
        record.empty_rcode = replyRcode(reply[0..got]);
        record.empty_ancount = replyAnswerCount(reply[0..got]);
    }

    // C. A name the policy refuses. **Nothing may be resolved and nothing may
    //    enter the set.**
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

    // D. A record type this resolver does not answer. 15 is MX.
    length = buildQuery(&query, 0x1237, permitted_name, 15);
    got = ask(&router, client_fd, &server, query[0..length], &reply, now);
    if (got >= dns_header_bytes) {
        record.type_rcode = replyRcode(reply[0..got]);
        record.type_ancount = replyAnswerCount(reply[0..got]);
    }

    // J. A permitted name the kernel will not take an address for. The answer
    //    must carry no address, because an address that is not in the set is
    //    one the guard chain refuses.
    length = buildQuery(&query, 0x1238, walled_name, @intFromEnum(RecordKind.a));
    got = ask(&router, client_fd, &server, query[0..length], &reply, now);
    if (got >= dns_header_bytes) {
        record.walled_rcode = replyRcode(reply[0..got]);
        record.walled_ancount = replyAnswerCount(reply[0..got]);
    }
    if (nft.element(.{ .ipv4 = walled_ipv4 }, null) catch null) |_| {
        record.walled_element_found = 1;
    }

    // E. A connection to the address the resolver handed out. The guard chain
    //    accepts it, the nat chain redirects it, and the relay recovers the
    //    address the program asked for and not the one it was rewritten to.
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

    // F. Bytes both ways, through the descriptor made before the namespace
    //    was entered.
    if (inside.fd >= 0 and inside.errno == 0) {
        writeAll(inside.fd, "hello upstream");
        pump(&router, 4, now, 200);
        record.outward_len = @intCast(readWithin(pair[1], &record.outward, 500));

        writeAll(pair[1], "hello sandbox");
        pump(&router, 4, now, 200);
        record.inward_len = @intCast(readWithin(inside.fd, &record.inward, 500));
    }

    // G. The same address on a port the policy refuses. The kernel has no
    //    opinion about a port, so this is the one control on that path.
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

    // H. An address nothing ever resolved to. **It must never reach the
    //    relay**, so the accepted count may not move.
    const accepted_before = router.counts.accepted;
    const blocked = attemptConnect(never_handed_ipv4, permitted_port, 2000);
    record.blocked_errno = blocked.errno;
    record.blocked_waited_ms = blocked.waited_ms;
    pump(&router, 2, now, 100);
    record.blocked_accepted = router.counts.accepted - accepted_before;
    if (blocked.fd >= 0) _ = linux.close(blocked.fd);

    // I. The relay is gone and the redirect is still installed. A program must
    //    get an error and must not wait.
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

/// Build the whole router in a network namespace of its own and report what it
/// then did. **This is the first place all three pieces run together**, so
/// every assertion below is the first evidence the design works at all.
///
/// **A child, because a network namespace cannot be left.** The test process
/// needs its own namespaces for every later test, and `namespace.enter` spends
/// the one this process has. Both sibling files fork for the same reason.
///
/// Answers null when this machine will not give a namespace at all, which the
/// caller must report as a skip. **A machine that cannot build a sandbox
/// measured nothing here, and that is not a pass.**
///
/// **A child that died is not a skip either.** A child that crashes writes a
/// short pipe, which is exactly what a child that could not make the namespace
/// writes, so the two are told apart by the exit status and nothing else.
/// `error.ChildCrashed` is what stops an assertion inside the child from
/// turning every test here green.
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
        // **Made before the namespace is entered, and that is the point.** A
        // socket made after the unshare belongs to the namespace with the
        // blackhole in it. This pair stands in for the connected descriptor
        // the wiring will inherit through the same handover `netbroker.zig`
        // already uses.
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

    // The child leaves by `exit(0)` on both paths it plans to take, so any
    // other status is a crash, a signal, or a panic.
    if (status != 0) return error.ChildCrashed;
    if (filled != bytes.len) return null;
    return record;
}

/// True when the failure is one nothing in this file can cause: a kernel with
/// no `dummy` link kind, or one with no nftables at all. **Everything else is
/// this file's own fault and must fail the test**, because a step that quietly
/// becomes a skip is how a broken router passes a green suite.
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
        // Every listener this file opens is opened in a namespace the two
        // steps above have just built, so a refusal here is a bug here.
        .router_open => false,
    };
}

/// **By pointer, never by value.** Zig may pass a structure this size by
/// reference to a temporary, and a slice into that temporary is dangling the
/// moment the call returns. `nftables.zig` measured that mistake first.
fn relayName(record: *const Measurement) []const u8 {
    return record.relay_name[0..@min(record.relay_name_len, record.relay_name.len)];
}

// ---------------------------------------------------------------------------
// What the bytes say, with no kernel in the way.
// ---------------------------------------------------------------------------

test "the relay listens where the nat chain sends" {
    // Two numbers that must be one. The nat chain redirects to a port that is
    // compiled into a pinned byte sequence in `nftables.zig`, and a relay that
    // bound a different one would take no traffic at all while every test that
    // did not connect through the kernel still passed.
    try testing.expectEqual(nftables.relay_port, relay_port);

    // The resolver is not a redirect target and never becomes one. It is the
    // address the sandbox's own `resolv.conf` names, which has to be the port
    // a resolver client uses without being told.
    try testing.expectEqual(@as(u16, 53), resolver_port);
}

test "the pre-nat destination is read out of the sockaddr the kernel fills" {
    // **This is the layout the whole relay depends on.** The family is in the
    // machine's own byte order and the port is in the network's, and a reader
    // that swapped them would answer a plausible looking address on a port
    // nothing uses.
    var raw4: [@sizeOf(linux.sockaddr.in)]u8 = @splat(0);
    std.mem.writeInt(u16, raw4[0..2], linux.AF.INET, .little);
    std.mem.writeInt(u16, raw4[2..4], 443, .big);
    @memcpy(raw4[4..8], &[_]u8{ 93, 184, 216, 34 });

    const found4 = decodeOriginal4(&raw4) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u16, 443), found4.port);
    try testing.expectEqualSlices(u8, &.{ 93, 184, 216, 34 }, &found4.address.ipv4);

    // A sockaddr for another family is not this one, whatever it holds.
    std.mem.writeInt(u16, raw4[0..2], linux.AF.INET6, .little);
    try testing.expectEqual(@as(?Destination, null), decodeOriginal4(&raw4));

    // Too few bytes is not a short address. It is no address.
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

    // **A mapped address is unwrapped and not carried wrapped.** The guard
    // chain holds the real IPv4 address in `allowed4`, and the name table was
    // written with that address too, so a destination left wrapped would be
    // asked about in a family neither of them uses.
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
    // **Lower case, dotted, and with no trailing dot**, because that is the
    // one spelling a policy rule is written in. A resolver that passed the
    // wire form to a policy would miss every rule an author wrote.
    try testing.expectEqualStrings("registry.npmjs.test", query.text());
    try testing.expectEqual(RecordKind.a, query.kind().?);
    try testing.expectEqual(class_internet, query.qclass);
    try testing.expectEqual(length, query.question_end);

    // A type this file does not answer parses and is refused later, rather
    // than failing to parse. The two are different answers.
    const other = buildQuery(&bytes, 1, "example.test", 15);
    const mx = try parseQuery(bytes[0..other]);
    try testing.expectEqual(@as(?RecordKind, null), mx.kind());

    // An answer is not a query. Nothing sends one to a resolver.
    const again = buildQuery(&bytes, 1, "example.test", 1);
    std.mem.writeInt(u16, bytes[2..4], 0x8180, .big);
    try testing.expectError(error.NotAQuery, parseQuery(bytes[0..again]));

    // Zero questions has nothing to answer and two have no reply every client
    // agrees on.
    std.mem.writeInt(u16, bytes[2..4], 0x0100, .big);
    std.mem.writeInt(u16, bytes[4..6], 0, .big);
    try testing.expectError(error.NotOneQuestion, parseQuery(bytes[0..again]));
    std.mem.writeInt(u16, bytes[4..6], 2, .big);
    try testing.expectError(error.NotOneQuestion, parseQuery(bytes[0..again]));
    std.mem.writeInt(u16, bytes[4..6], 1, .big);

    // **A compression pointer is refused and never followed.** The bytes come
    // from the program being sandboxed, and a parser that followed one can be
    // sent around a loop by whoever wrote them.
    //
    // **The datagram is long enough to hold what the pointer would otherwise
    // be read as.** A pointer's first byte is 0xc0, which a reader with no
    // check takes as a label of 192 characters. In a short datagram that runs
    // off the end and the length check refuses it anyway, so a short one
    // proves nothing about the pointer check. This one has the 192 characters,
    // and the name it would parse into is a name the policy would then be
    // asked about.
    var pointer: [256]u8 = @splat('a');
    std.mem.writeInt(u16, pointer[0..2], 1, .big);
    std.mem.writeInt(u16, pointer[2..4], 0x0100, .big);
    std.mem.writeInt(u16, pointer[4..6], 1, .big);
    std.mem.writeInt(u16, pointer[6..8], 0, .big);
    std.mem.writeInt(u16, pointer[8..10], 0, .big);
    std.mem.writeInt(u16, pointer[10..12], 0, .big);
    pointer[dns_header_bytes] = 0xc0;
    pointer[dns_header_bytes + 1] = 0x0c;
    // Where the label the pointer is mistaken for would end, and the type and
    // class after it. Without the check this parses cleanly.
    pointer[205] = 0;
    std.mem.writeInt(u16, pointer[206..208], 1, .big);
    std.mem.writeInt(u16, pointer[208..210], class_internet, .big);
    try testing.expectError(error.Malformed, parseQuery(&pointer));

    // And the short one is refused too, by whichever check gets there first.
    bytes[dns_header_bytes] = 0xc0;
    bytes[dns_header_bytes + 1] = 0x0c;
    try testing.expectError(error.Malformed, parseQuery(bytes[0 .. dns_header_bytes + 6]));

    // A label that runs past the datagram, and a header with nothing after it.
    const short = buildQuery(&bytes, 1, "example.test", 1);
    try testing.expectError(error.Malformed, parseQuery(bytes[0 .. short - 3]));
    try testing.expectError(error.Malformed, parseQuery(bytes[0..dns_header_bytes]));
    try testing.expectError(error.Malformed, parseQuery(bytes[0..11]));

    // The root names nothing to resolve and nothing to ask a policy about.
    var root: [dns_header_bytes + 5]u8 = @splat(0);
    std.mem.writeInt(u16, root[2..4], 0x0100, .big);
    std.mem.writeInt(u16, root[4..6], 1, .big);
    std.mem.writeInt(u16, root[13..15], 1, .big);
    std.mem.writeInt(u16, root[15..17], 1, .big);
    try testing.expectError(error.Malformed, parseQuery(&root));
}

test "a name longer than the table can hold is refused rather than cut short" {
    // A truncated name is a different name, and a different name is a
    // different policy answer. `remember` asserts on the length for the same
    // reason, so the parser is what has to hold the bound.
    var bytes: [query_capacity]u8 = undefined;
    var long: [name_capacity + 8]u8 = @splat('a');
    var at: usize = 0;
    while (at + 40 <= long.len) : (at += 40) long[at + 39] = '.';
    const length = buildQuery(&bytes, 1, long[0 .. long.len - 1], 1);
    try testing.expectError(error.Malformed, parseQuery(bytes[0..length]));

    // And one that just fits is kept whole.
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
    // An answer, recursion desired kept, recursion available, and no error.
    try testing.expectEqual(@as(u16, 0x8000), flags & 0x8000);
    try testing.expectEqual(@as(u16, 0x0100), flags & 0x0100);
    try testing.expectEqual(@as(u16, 0x0080), flags & 0x0080);
    try testing.expectEqual(@as(u16, 0), flags & 0xf);
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, out[4..6], .big));
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, out[6..8], .big));
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[8..10], .big));
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[10..12], .big));

    // **The question comes back exactly as it was asked**, which keeps the
    // case a client varied on purpose. The parser lower cased its own copy for
    // the policy and this is the other one.
    try testing.expectEqualSlices(u8, bytes[dns_header_bytes..length], out[dns_header_bytes..length]);

    const found = readRecord(out[0..written], length) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@intFromEnum(RecordKind.a), found.rtype);
    try testing.expectEqual(@as(u32, 10), found.ttl);
    try testing.expectEqual(@as(u16, 4), found.rdlength);
    try testing.expectEqualSlices(u8, &permitted_ipv4, found.rdata[0..4]);
    // A pointer back to the name at offset twelve, which is where every
    // message this file builds keeps it.
    try testing.expectEqual(@as(u8, 0xc0), out[length]);
    try testing.expectEqual(@as(u8, 0x0c), out[length + 1]);

    // An AAAA answer carries sixteen bytes and says so.
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

    // A buffer that cannot hold the reply is an answer that does not go out,
    // and never a partial one.
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

    // **The reply ends where the question ends.** Not one byte of address
    // leaves, which is what makes a refusal cost the program nothing to learn
    // from beyond the refusal itself.
    try testing.expectEqual(length, written);
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[6..8], .big));
    try testing.expectEqual(@as(u16, @intFromEnum(Rcode.refused)), std.mem.readInt(u16, out[2..4], .big) & 0xf);

    // **REFUSED and never NXDOMAIN.** A name error claims the name does not
    // exist anywhere, which this resolver does not know and did not check. A
    // refusal is a claim about this resolver, and it is the true one.
    try testing.expect(@intFromEnum(Rcode.refused) != @intFromEnum(Rcode.name_error));

    // No error with no answer is the other shape: the policy permitted the
    // name and the host holds nothing of that type.
    const empty = buildReply(&out, bytes[0..length], &query, .no_error, null, 10) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(length, empty);
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[6..8], .big));
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[2..4], .big) & 0xf);
}

test "a datagram that cannot be parsed still gets an answer" {
    // **A wait is the worst shape a refusal can have.** A program that asked a
    // resolver that never speaks waits out its own timeout and then asks the
    // next name server, and none of that is visible to anybody reading the
    // session.
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

    // Too few bytes to hold an identifier is nothing to address a reply to.
    try testing.expectEqual(@as(?usize, null), buildFormatError(&out, source[0..11]));
    try testing.expectEqual(@as(?usize, null), buildFormatError(out[0..11], &source));
}

test "the name table is bounded, expires, and keeps the newest name" {
    var table = NameTable{};
    const start: i64 = 1_000_000;
    const life: u64 = 30_000;

    table.remember(.{ .ipv4 = permitted_ipv4 }, permitted_name, start, life);
    try testing.expectEqualStrings(permitted_name, table.lookup(.{ .ipv4 = permitted_ipv4 }, start).?);

    // **Expiry is read and never swept.** Nothing here keeps a timer, so the
    // same entry answers before its deadline and answers nothing after it.
    try testing.expectEqualStrings(
        permitted_name,
        table.lookup(.{ .ipv4 = permitted_ipv4 }, start + @as(i64, @intCast(life)) - 1).?,
    );
    try testing.expectEqual(
        @as(?[]const u8, null),
        table.lookup(.{ .ipv4 = permitted_ipv4 }, start + @as(i64, @intCast(life))),
    );

    // **The last name wins, and that is a heuristic.** Two names resolving to
    // one address is the usual case on a large content network, so this
    // narrows a destination to a likely name and does not identify it.
    table.remember(.{ .ipv4 = permitted_ipv4 }, "other.npmjs.test", start, life);
    try testing.expectEqualStrings("other.npmjs.test", table.lookup(.{ .ipv4 = permitted_ipv4 }, start).?);
    // And it took the same slot rather than a second one.
    try testing.expectEqual(@as(usize, 1), table.live(start));

    // An address nobody handed out has no name, which is the answer the relay
    // gives the policy for a hardcoded address that somehow got through.
    try testing.expectEqual(@as(?[]const u8, null), table.lookup(.{ .ipv4 = never_handed_ipv4 }, start));
    // And the two families are not each other.
    try testing.expectEqual(
        @as(?[]const u8, null),
        table.lookup(.{ .ipv6 = @splat(0) }, start),
    );

    // **The bound holds against more names than there are slots.** A program
    // inside the sandbox chooses how many names get resolved, so a table that
    // grew with them would be a way to spend this process's memory from the
    // inside.
    var full = NameTable{};
    var index: u32 = 0;
    while (index < name_table_capacity * 4) : (index += 1) {
        var address: [4]u8 = undefined;
        std.mem.writeInt(u32, &address, index + 1, .big);
        full.remember(.{ .ipv4 = address }, "example.test", start, life);
        try testing.expect(full.live(start) <= name_table_capacity);
    }
    try testing.expectEqual(name_table_capacity, full.live(start));

    // The newest one is still there, so a full table drops something older
    // rather than refusing to record anything more.
    var newest: [4]u8 = undefined;
    std.mem.writeInt(u32, &newest, name_table_capacity * 4, .big);
    try testing.expect(full.lookup(.{ .ipv4 = newest }, start) != null);

    // And once every entry has expired, the table holds nothing at all.
    try testing.expectEqual(@as(usize, 0), full.live(start + @as(i64, @intCast(life))));
}

test "a refusal names the call the kernel would not take" {
    // The privileged port is the one refusal with a name of its own, because
    // it means the capability was dropped before the router opened, which is
    // the same ordering mistake `nftables.zig` names for CAP_NET_ADMIN.
    try testing.expectEqual(error.PrivilegedPort, classify(.resolver_bind, @intFromEnum(linux.E.ACCES)));
    try testing.expectEqual(error.NotPermitted, classify(.relay_bind, @intFromEnum(linux.E.ACCES)));
    try testing.expectEqual(error.NotPermitted, classify(.relay_socket, @intFromEnum(linux.E.PERM)));
    try testing.expectEqual(error.AddressInUse, classify(.relay_bind, @intFromEnum(linux.E.ADDRINUSE)));
    try testing.expectEqual(error.AddressInUse, classify(.resolver_bind, @intFromEnum(linux.E.ADDRINUSE)));
    try testing.expectEqual(error.Refused, classify(.relay_listen, @intFromEnum(linux.E.INVAL)));
    try testing.expectEqual(error.Refused, classify(.resolver_socket, @intFromEnum(linux.E.AFNOSUPPORT)));
}

test "a refusal that is not a missing module fails the test rather than skipping it" {
    // **The skip is for two hosts only**: a kernel with no `dummy` link kind,
    // and one with no nftables at all. Neither is anything this file can
    // cause. Everything else names a call this file made, and a step that
    // quietly turns into a skip is how a broken router passes a green suite.
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
    // **Nothing this file opens is ever a skip.** Both listeners are opened in
    // a namespace the two steps above have just built, so a refusal there is a
    // bug here and has to be loud.
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

    // A run that refused nothing measured everything.
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

// ---------------------------------------------------------------------------
// All three pieces together, against a real kernel.
//
// **This is the first place the namespace, the ruleset and the router run at
// once**, so every assertion below is the first evidence the design works at
// all rather than a claim about one piece in isolation.
// ---------------------------------------------------------------------------

test "a permitted name resolves and its address lands in the allow set" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    // The answer carries the address, the type asked for, and the identifier
    // the question came with.
    try testing.expectEqual(@as(u32, @intFromEnum(Rcode.no_error)), record.permit_rcode);
    try testing.expectEqual(@as(u32, 1), record.permit_ancount);
    try testing.expectEqual(@as(u32, @intFromEnum(RecordKind.a)), record.permit_rtype);
    try testing.expectEqual(@as(u32, 4), record.permit_rdlength);
    try testing.expectEqualSlices(u8, &permitted_ipv4, record.permit_rdata[0..4]);
    try testing.expectEqual(@as(u32, 0x1234), record.permit_id);

    // **And the kernel holds it.** This is the read back, not the answer: the
    // element came out of the allow set the guard chain reads, so a resolver
    // that answered without opening the door would fail here and pass above.
    try testing.expectEqual(@as(u32, 1), record.permit_element_found);
    // **The timeout the router was configured with, read back off the
    // element.** It is not the set's own default on purpose: the kernel stores
    // no per element timeout for one that matches the default, so the default
    // would read back as a zero and prove nothing.
    try testing.expectEqual(probe_timeout_ms, record.permit_element_timeout_ms);
    // A timeout written into the wrong attribute is stored as a comment. See
    // `nftables.zig`, which measured that twice.
    try testing.expectEqual(@as(u32, 0), record.permit_element_comment);

    // **The answer's lifetime is shorter than the door's**, so the program
    // re-resolves while the address is still reachable and the fresh
    // resolution restarts the timeout. The other way round shuts the door
    // under a live connection.
    try testing.expect(@as(u64, record.permit_ttl) * 1000 < record.permit_element_timeout_ms);

    // A permitted name the host holds no address of that type for is answered
    // with no error and no answer, not with a refusal. The policy said yes,
    // and a refusal here would report a decision nobody made.
    try testing.expectEqual(@as(u32, @intFromEnum(Rcode.no_error)), record.empty_rcode);
    try testing.expectEqual(@as(u32, 0), record.empty_ancount);
}

test "a name the policy refuses answers REFUSED and never reaches the host" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    try testing.expectEqual(@as(u32, @intFromEnum(Rcode.refused)), record.refuse_rcode);
    try testing.expectEqual(@as(u32, 0), record.refuse_ancount);

    // **Nothing entered the set.** The fake host holds an address for this
    // name, so an address in `allowed4` here would mean the resolver opened
    // the door for a name the policy had already refused.
    try testing.expectEqual(@as(u32, 0), record.refuse_element_found);

    // **And the host was never asked.** The policy answered before anything
    // was resolved, which is what makes a refusal cost nothing and say
    // nothing about whether the name exists.
    try testing.expectEqual(@as(u32, 0), record.refuse_resolve_calls);
}

test "a record type this resolver does not answer is refused and not implemented" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    // A and AAAA are the only two. Everything else is refused, because a
    // resolver that grew a general record type is a resolver with a parser
    // the sandboxed program can reach.
    try testing.expectEqual(@as(u32, @intFromEnum(Rcode.refused)), record.type_rcode);
    try testing.expectEqual(@as(u32, 0), record.type_ancount);
}

test "an address the kernel would not take is never answered" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    // **This is the ordering, measured.** The address goes into the allow set
    // before the answer leaves, so an allow that fails must take the answer
    // with it. An answer that went out anyway would hand the program an
    // address the guard chain refuses, which is a connection failure much
    // further from the cause.
    try testing.expectEqual(@as(u32, @intFromEnum(Rcode.server_failure)), record.walled_rcode);
    try testing.expectEqual(@as(u32, 0), record.walled_ancount);
    try testing.expectEqual(@as(u32, 0), record.walled_element_found);
}

test "a connection to an allowed address reaches the relay with the address it asked for" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    // The guard chain let it through and the nat chain redirected it, so the
    // socket layer completed a connection to a relay the program never named.
    try testing.expectEqual(@as(i32, 0), record.relay_errno);
    try testing.expectEqual(@as(u64, 1), record.relay_accepted);
    try testing.expectEqual(@as(u64, 1), record.relay_linked);

    // **This is the pre-nat address.** The packet that arrived carried the
    // relay's own address and the relay port, because that is what a REDIRECT
    // rewrites them to. `SO_ORIGINAL_DST` answered with the address and the
    // port the program asked for instead, and those are what the policy was
    // asked about.
    try testing.expectEqual(@as(u32, 4), record.relay_family);
    try testing.expectEqualSlices(u8, &permitted_ipv4, record.relay_address[0..4]);
    try testing.expectEqual(@as(u32, permitted_port), record.relay_port);
    try testing.expect(record.relay_port != relay_port);
    try testing.expect(!std.mem.eql(u8, record.relay_address[0..4], &.{ 127, 0, 0, 1 }));

    // **And the name came back with it.** The resolver handed this address out
    // for this name earlier in the same run, so the table turned the recovered
    // address into the name the policy is written in.
    try testing.expectEqual(@as(u32, 1), record.relay_name_known);
    try testing.expectEqualStrings(permitted_name, relayName(&record));

    // The host seam was asked for the same destination, not for the rewritten
    // one. Nothing between the recovery and the dial may change it.
    try testing.expectEqual(@as(u32, 1), record.relay_open_calls);
    try testing.expectEqual(@as(u32, permitted_port), record.relay_open_port);
    try testing.expectEqualSlices(u8, &permitted_ipv4, record.relay_open_address[0..4]);
}

test "the relay carries bytes both ways through a descriptor made outside the namespace" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    // **The descriptor was made before `namespace.enter`.** A socket made
    // inside this namespace can only reach the blackhole, so the relay's way
    // out has to be inherited, which is the same handover `netbroker.zig`
    // already uses for a filtered process.
    try testing.expectEqualStrings("hello upstream", record.outward[0..record.outward_len]);
    try testing.expectEqualStrings("hello sandbox", record.inward[0..record.inward_len]);
}

test "the policy is the only control on a port the kernel has no opinion about" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    // The allow set holds addresses, so the guard chain let this through on a
    // port nobody permitted and the nat chain redirected it like any other.
    // **The relay is what refuses it**, which is why the recovery and the
    // question after it are the only control on the relay's own egress: the
    // kernel cannot constrain a descriptor from another namespace.
    try testing.expectEqual(@as(i32, 0), record.policy_errno);
    try testing.expectEqual(@as(u64, 2), record.policy_accepted);
    try testing.expectEqual(@as(u64, 1), record.policy_refused);
    try testing.expectEqual(@as(u32, refused_port), record.policy_asked_port);

    // **Nothing was dialled.** The policy was asked before the host was, so a
    // refused destination is never reached even once.
    try testing.expectEqual(@as(u32, 0), record.policy_open_calls);

    // And the program sees the connection end rather than wait on a relay that
    // will never answer it.
    try testing.expectEqual(@as(u32, 1), record.policy_eof);
}

test "a connection to an address that was never handed out never reaches the relay" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    // **This is the whole design in one number.** Nothing resolved this
    // address, so nothing put it in the allow set, so the guard chain rejected
    // it before the nat chain could redirect it. That covers a hardcoded
    // address, a program carrying its own resolver, and DNS over HTTPS, and
    // this file knows about none of the three.
    try testing.expectEqual(@as(u64, 0), record.blocked_accepted);

    // The reject is an ICMP port unreachable, which the socket layer reports
    // as a refusal. **Not a drop and not a timeout**: the program is told at
    // once and does not wait out a full connection attempt.
    try testing.expect(record.blocked_errno != timed_out);
    try testing.expectEqual(@intFromEnum(linux.E.CONNREFUSED), record.blocked_errno);
    try testing.expect(record.blocked_waited_ms < 1000);
}

test "a connection with the relay gone is refused rather than left waiting" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.stage);

    // **The redirect is the kernel's and it outlives the relay.** With the
    // listener gone the destination is still rewritten, the kernel finds
    // nothing bound at the relay port, and it answers with a reset. So a dead
    // relay fails closed and fails fast.
    //
    // A hang is the worst shape this could take, and it is the one shape a
    // green test suite hides: the connection never completes, the program
    // waits out its own timeout, and nothing anywhere says why.
    try testing.expect(record.dead_errno != timed_out);
    try testing.expectEqual(@intFromEnum(linux.E.CONNREFUSED), record.dead_errno);
    try testing.expect(record.dead_waited_ms < 1000);
}

test "a descriptor from the host seam is made ready for a loop that polls" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // **A descriptor the host seam hands back was made by somebody else**, so
    // nothing here decided how it behaves. The loop polls before it reads, and
    // a blocking descriptor that lied about being ready would stop the whole
    // router, every other connection in the sandbox with it.
    var pair: [2]posix.fd_t = undefined;
    const made = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &pair);
    if (linux.errno(made) != .SUCCESS) return error.SkipZigTest;
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    // Read the flag rather than trying to block. A test that really blocked
    // would not come back to say that it had.
    try testing.expect(!flagsOf(pair[0]).NONBLOCK);
    makeNonBlocking(pair[0]);
    try testing.expect(flagsOf(pair[0]).NONBLOCK);

    // And the flag is the one that matters: a read with nothing there answers
    // at once instead of waiting for the peer.
    var scratch: [4]u8 = undefined;
    try testing.expectError(error.WouldBlock, posix.read(pair[0], &scratch));

    // Nothing else about the descriptor changed. A wider write would clear the
    // access mode and leave a socket that can no longer be read.
    try testing.expectEqual(posix.ACCMODE.RDWR, flagsOf(pair[0]).ACCMODE);
}

fn flagsOf(fd: posix.fd_t) linux.O {
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    return @bitCast(@as(u32, @truncate(flags)));
}
