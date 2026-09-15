//! The kernel half of the network router: one fixed nftables ruleset, and one
//! dynamic allow set the resolver writes into.
//!
//! ## What this is for
//!
//! A sandbox with no network at all answers every `connect` with `EPERM`, so a
//! rule written in `chock.zon` never governs a shell command. The router gives
//! the sandbox a real network inside its own namespace instead, lets the kernel
//! do the TCP, and decides what may leave. This file is the part that tells the
//! kernel what may leave. Nothing else here: no resolver, no listener, no relay.
//!
//! ## The ruleset, which is the deliverable
//!
//!     table inet chock {
//!       set allowed4 { type ipv4_addr; flags timeout; timeout 30s }
//!       set allowed6 { type ipv6_addr; flags timeout; timeout 30s }
//!       chain guard {
//!         type filter hook output priority mangle; policy drop;
//!         ct state established,related accept
//!         oif "lo" accept
//!         ip daddr @allowed4 accept
//!         ip6 daddr @allowed6 accept
//!         reject with icmpx port-unreachable
//!       }
//!       chain relay {
//!         type nat hook output priority dstnat;
//!         meta l4proto tcp redirect to :18080
//!       }
//!     }
//!
//! **The priority on `guard` is load bearing and a wrong one fails without a
//! word.** Conntrack runs at -200, so `ct state` is readable at -150.
//! Destination nat runs later at -100, so at -150 the chain still sees the
//! address the program asked for. Measured on 2026-09-14: the same rule at
//! priority 0, which is where `filter OUTPUT` sits, matched zero packets while
//! the connection it was meant to stop reached its listener, because the nat
//! chain had already rewritten the address the rule was reading. A rule that
//! reads correctly and matches nothing is the worst shape a filter can have,
//! so `install reads back the ruleset it wrote` and `the two chains keep the
//! priorities the ordering depends on` below pin both numbers against a real
//! kernel.
//!
//! ## One fixed byte sequence, and one dynamic call
//!
//! `install_batch` is built once, at compile time, into a constant. There is no
//! general expression encoder here and there must not be one: nothing between
//! this file and the kernel checks a type, an attribute number, or a byte
//! order, and every one of those mistakes is accepted silently by a kernel that
//! then behaves differently from what the source says. The only thing that
//! varies at run time is one address and one timeout, which `allow` writes.
//!
//! **Never trust the acknowledgement.** `NFTA_SET_ELEM_TIMEOUT` is 4.
//! Attribute 6 is `NFTA_SET_ELEM_USERDATA`. Measured twice, on 2026-09-14 and
//! again here: a batch that puts the timeout in attribute 6 is accepted and
//! acknowledged, the kernel stores the eight bytes as a comment, the element
//! carries no timeout of its own at all, and it expires on the set default
//! instead. That is why `element` exists and why `allow stores a timeout the
//! kernel gives back as a timeout` reads the element back rather than reading
//! the reply.
//!
//! ## A kernel module cannot be loaded from inside a user namespace
//!
//! `nf_tables`, `nf_nat`, `nft_chain_nat`, `nft_redir`, `nft_reject` and
//! `nf_conntrack` are separate modules on most kernels, and a process in a user
//! namespace cannot make the kernel load one. On a host that has never used
//! nftables the install fails at startup for that reason alone, which no other
//! sandbox layer here has ever depended on. `error.KernelModuleMissing` names
//! that case apart from every other refusal so a caller can tell the person
//! which modules to load, and `Diagnostic.step` says which piece of the ruleset
//! the kernel could not build.
//!
//! ## Linux only, and why the file is here
//!
//! Every call below reaches the kernel through `std.os.linux`, because netlink
//! has no `std.Io` and no `std.posix` spelling: `std.Io.net` speaks addresses
//! and streams, and `std.posix` has no socket calls at all in this Zig version.
//! `netbroker.zig` sits beside it for the same reason. The file compiles for
//! Darwin the same way the others do, and every test that opens a socket
//! answers `error.SkipZigTest` there.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

/// Only the tests below use this, to get a network namespace of their own to
/// install into. Nothing in the module itself enters a namespace.
const namespace = @import("namespace.zig");

/// The table every object below lives in. One table, so tearing the router
/// down is one delete.
pub const table_name = "chock";
/// The set of IPv4 addresses Chock resolved and handed out.
pub const set4_name = "allowed4";
/// The set of IPv6 addresses Chock resolved and handed out.
pub const set6_name = "allowed6";
/// The filter chain. See the top comment for why its priority matters.
pub const guard_chain_name = "guard";
/// The nat chain that sends outbound TCP to the relay.
pub const relay_chain_name = "relay";

/// The port inside the network namespace that every outbound TCP connection is
/// redirected to. The relay listens there; it is not built in this file.
pub const relay_port: u16 = 18080;

/// The timeout an element gets when `allow` does not name one, in
/// milliseconds. **The kernel does the expiry.** A fresh resolution re-adds the
/// current address and the previous one dies on its own, so nothing in Chock
/// keeps a clock or a list of what to remove.
pub const default_timeout_ms: u64 = 30_000;

/// `NF_INET_LOCAL_OUT`. Both chains hook there, because every packet this
/// sandbox can produce is locally generated.
const hook_output: u32 = 3;
/// `NF_IP_PRI_MANGLE`. See the top comment: conntrack at -200 has run, and
/// destination nat at -100 has not.
const guard_priority: i32 = -150;
/// `NF_IP_PRI_NAT_DST`.
const relay_priority: i32 = -100;
/// `NF_DROP`, the verdict for a packet no rule in `guard` accepted.
const guard_policy: u32 = 0;

/// Which of the two sets an address belongs in, and the key bytes to store.
pub const Address = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,

    fn setName(self: Address) []const u8 {
        return switch (self) {
            .ipv4 => set4_name,
            .ipv6 => set6_name,
        };
    }

    fn key(self: *const Address) []const u8 {
        return switch (self.*) {
            .ipv4 => |*bytes| bytes,
            .ipv6 => |*bytes| bytes,
        };
    }
};

/// What the kernel holds for one element of an allow set.
pub const Element = struct {
    /// This element's own timeout, in milliseconds, as the kernel stored it.
    /// **Zero when the kernel holds none**, which is what an element that fell
    /// back to the set default looks like, and what a timeout written into the
    /// wrong attribute leaves behind.
    timeout_ms: u64,
    /// How long the kernel has left before it removes the element, in
    /// milliseconds.
    expiration_ms: u64,
    /// The kernel stored a comment on this element. `allow` never sends one,
    /// so this is true only when a timeout landed in
    /// `NFTA_SET_ELEM_USERDATA`. See the top comment.
    has_comment: bool,
};

/// Which piece of the exchange the kernel refused. Every error out of this
/// file needs one: `KernelModuleMissing` on `batch_begin` is a host with no
/// `nf_tables` at all, and the same name on `relay_rule` is a host with no
/// `nft_redir`, and the two need different things from a person.
pub const Step = enum {
    open_socket,
    bind_socket,
    send,
    receive,
    batch_begin,
    table,
    guard_chain,
    relay_chain,
    set4,
    set6,
    conntrack_rule,
    loopback_rule,
    allowed4_rule,
    allowed6_rule,
    reject_rule,
    relay_rule,
    batch_end,
    element_add,
    element_read,
    chain_read,
    set_read,
    rule_read,

    /// The step a message carries, by its sequence number in `install_batch`.
    /// The kernel names the failing message by that number and nothing else.
    fn ofInstallSequence(seq: u32) Step {
        return switch (seq) {
            0 => .batch_begin,
            1 => .table,
            2 => .guard_chain,
            3 => .relay_chain,
            4 => .set4,
            5 => .set6,
            6 => .conntrack_rule,
            7 => .loopback_rule,
            8 => .allowed4_rule,
            9 => .allowed6_rule,
            10 => .reject_rule,
            11 => .relay_rule,
            else => .batch_end,
        };
    }
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
    /// The kernel cannot build this ruleset because a module it needs is not
    /// loaded, and a process in a user namespace cannot load one. Report the
    /// step and tell the person to load `nf_tables`, `nf_nat`,
    /// `nft_chain_nat`, `nft_redir`, `nft_reject` and `nf_conntrack` on the
    /// host. **Do not continue without the ruleset**: the sandbox would then
    /// have a network and no filter on it.
    KernelModuleMissing,
    /// No `CAP_NET_ADMIN` in this network namespace. The caller entered the
    /// namespace too late, or dropped the capability too early.
    NotPermitted,
    /// The kernel refused for a reason this file does not recognise. Read the
    /// diagnostic; this is a bug here, not a property of the host.
    Refused,
    /// The netlink socket itself would not carry the message.
    ExchangeFailed,
};

fn note(diag: ?*?Diagnostic, step: Step, errno: i32) void {
    if (diag) |slot| slot.* = .{ .step = step, .errno = errno };
}

/// Turn a refusal into the name a caller can act on. The mapping is measured,
/// not guessed, on kernel 6.18:
///
/// * `EOPNOTSUPP` on `batch_begin`: nfnetlink has no nftables subsystem, so
///   `nf_tables` is not loaded and could not be autoloaded.
/// * `ENOENT` on a chain or a rule: the chain type or an expression is a
///   module that is not loaded. Every object the install batch names is
///   created inside that same batch, so `ENOENT` there cannot mean "not
///   found".
/// * `EPERM`: no `CAP_NET_ADMIN`.
fn classify(step: Step, errno: i32) Error {
    if (errno == @intFromEnum(linux.E.PERM) or errno == @intFromEnum(linux.E.ACCES)) return error.NotPermitted;
    if (errno == @intFromEnum(linux.E.OPNOTSUPP) or errno == @intFromEnum(linux.E.PROTONOSUPPORT)) return error.KernelModuleMissing;
    if (errno == @intFromEnum(linux.E.NOENT)) {
        return switch (step) {
            .guard_chain, .relay_chain, .conntrack_rule, .loopback_rule, .allowed4_rule, .allowed6_rule, .reject_rule, .relay_rule => error.KernelModuleMissing,
            else => error.Refused,
        };
    }
    return error.Refused;
}

/// An open netlink socket to the netfilter subsystem of one network namespace.
///
/// **Which namespace is decided when this is opened, not when it is used.** A
/// netlink socket belongs to the network namespace of the process that created
/// it, so a caller opens this after entering the sandbox's namespace and before
/// dropping `CAP_NET_ADMIN`.
pub const Session = struct {
    fd: i32,

    pub fn open(diag: ?*?Diagnostic) Error!Session {
        const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.NETFILTER);
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

    /// Put the whole ruleset in place. Once, at startup, before the sandboxed
    /// program runs and before `CAP_NET_ADMIN` goes away.
    ///
    /// **The filter is advice until the capability is dropped.** A process that
    /// still holds `CAP_NET_ADMIN` in this namespace can flush everything this
    /// call installed. The order is install, drop, then exec, and getting it
    /// backwards leaves a ruleset that tests green and stops nothing.
    pub fn install(self: Session, diag: ?*?Diagnostic) Error!void {
        try self.send(&install_batch, .send, diag);
        try self.acknowledge(Step.ofInstallSequence, diag);
    }

    /// Let this address out for `timeout_ms` milliseconds. Adding an address
    /// that is already there restarts its timeout, which is how a re-resolution
    /// keeps a live name reachable without any expiry logic here.
    pub fn allow(self: Session, address: Address, timeout_ms: u64, diag: ?*?Diagnostic) Error!void {
        // A zero timeout means "never expires" to the kernel, and an element
        // that never expires outlives the policy answer that created it. The
        // value comes from Chock's own policy, never from the sandboxed
        // program, so a zero here is a mistake in this program.
        std.debug.assert(timeout_ms > 0);

        var buffer: [max_element_message]u8 = undefined;
        const length = buildElementBatch(&buffer, address, timeout_ms);
        try self.send(buffer[0..length], .element_add, diag);
        try self.acknowledge(elementAddStep, diag);
    }

    /// What the kernel actually holds for this address, or null when it holds
    /// nothing. **Read this rather than believing an acknowledgement**: see the
    /// top comment for the attribute number that is accepted, acknowledged, and
    /// ignored.
    pub fn element(self: Session, address: Address, diag: ?*?Diagnostic) Error!?Element {
        var buffer: [max_element_message]u8 = undefined;
        const length = buildElementQuery(&buffer, address);
        try self.send(buffer[0..length], .element_read, diag);

        var reply: [reply_capacity]u8 = undefined;
        const filled = try self.receive(&reply, .element_read, diag);
        var messages = Messages{ .bytes = reply[0..filled] };
        while (messages.next()) |message| {
            if (message.kind == nlmsg_error) {
                const code = errorCode(message.body);
                // The kernel answers a key it does not hold with ENOENT, which
                // is an answer and not a fault.
                if (code == @intFromEnum(linux.E.NOENT)) return null;
                if (code == 0) continue;
                note(diag, .element_read, code);
                return classify(.element_read, code);
            }
            if (message.kind != (subsys_nftables << 8) | msg_newsetelem) continue;
            var attributes = Attributes{ .bytes = message.payload() };
            while (attributes.next()) |attribute| {
                if (attribute.kind != nfta_set_elem_list_elements) continue;
                var list = Attributes{ .bytes = attribute.payload };
                while (list.next()) |entry| return readElement(entry.payload);
            }
        }
        return null;
    }

    fn send(self: Session, bytes: []const u8, step: Step, diag: ?*?Diagnostic) Error!void {
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

    fn receive(self: Session, into: []u8, step: Step, diag: ?*?Diagnostic) Error!usize {
        const rc = linux.recvfrom(self.fd, into.ptr, into.len, 0, null, null);
        switch (linux.errno(rc)) {
            .SUCCESS => return rc,
            else => |e| {
                note(diag, step, @intFromEnum(e));
                return error.ExchangeFailed;
            },
        }
    }

    /// Read every reply the kernel queued for a batch and report the first
    /// refusal. **The kernel runs a batch inside `sendto`**, so every reply is
    /// already waiting and a non-blocking read that finds nothing means the
    /// batch is finished, not that it is slow.
    fn acknowledge(self: Session, stepOf: *const fn (u32) Step, diag: ?*?Diagnostic) Error!void {
        var reply: [reply_capacity]u8 = undefined;
        while (true) {
            const rc = linux.recvfrom(self.fd, &reply, reply.len, linux.MSG.DONTWAIT, null, null);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .AGAIN => return,
                else => |e| {
                    note(diag, .receive, @intFromEnum(e));
                    return error.ExchangeFailed;
                },
            }
            var messages = Messages{ .bytes = reply[0..rc] };
            while (messages.next()) |message| {
                if (message.kind != nlmsg_error) continue;
                const code = errorCode(message.body);
                if (code == 0) continue;
                const step = stepOf(message.sequence);
                note(diag, step, code);
                return classify(step, code);
            }
        }
    }
};

fn elementAddStep(sequence: u32) Step {
    return if (sequence == 0) .batch_begin else .element_add;
}

/// Pull the fields this file cares about out of one `NFTA_LIST_ELEM`.
fn readElement(bytes: []const u8) Element {
    var found: Element = .{ .timeout_ms = 0, .expiration_ms = 0, .has_comment = false };
    var attributes = Attributes{ .bytes = bytes };
    while (attributes.next()) |attribute| {
        switch (attribute.kind) {
            nfta_set_elem_timeout => found.timeout_ms = readBe64(attribute.payload),
            nfta_set_elem_expiration => found.expiration_ms = readBe64(attribute.payload),
            nfta_set_elem_userdata => found.has_comment = true,
            else => {},
        }
    }
    return found;
}

// ---------------------------------------------------------------------------
// The nfnetlink wire, and only as much of it as this one ruleset needs.
// ---------------------------------------------------------------------------

const subsys_nftables: u16 = 10;
const nfnl_msg_batch_begin: u16 = 16;
const nfnl_msg_batch_end: u16 = 17;

const msg_newtable: u16 = 0;
const msg_newchain: u16 = 3;
const msg_getchain: u16 = 4;
const msg_newrule: u16 = 6;
const msg_getrule: u16 = 7;
const msg_newset: u16 = 9;
const msg_getset: u16 = 10;
const msg_newsetelem: u16 = 12;
const msg_getsetelem: u16 = 13;

const nlmsg_error: u16 = 2;
const nlmsg_done: u16 = 3;

const f_request: u16 = 0x001;
const f_ack: u16 = 0x004;
const f_create: u16 = 0x400;
const f_append: u16 = 0x800;
/// `NLM_F_ROOT | NLM_F_MATCH`, which together are `NLM_F_DUMP`.
const f_dump: u16 = 0x300;

const nla_nested: u16 = 0x8000;
/// Strips `NLA_F_NESTED` and `NLA_F_NET_BYTEORDER` from a type read back.
const nla_type_mask: u16 = 0x3fff;

const nfta_set_elem_list_table: u16 = 1;
const nfta_set_elem_list_set: u16 = 2;
const nfta_set_elem_list_elements: u16 = 3;
const nfta_list_elem: u16 = 1;

const nfta_set_elem_key: u16 = 1;
/// **4, and not 6.** 6 is `NFTA_SET_ELEM_USERDATA`. See the top comment.
const nfta_set_elem_timeout: u16 = 4;
const nfta_set_elem_expiration: u16 = 5;
const nfta_set_elem_userdata: u16 = 6;
const nfta_data_value: u16 = 1;

/// `NFPROTO_INET`, the family of an `inet` table, which is one table for IPv4
/// and IPv6 together.
const nfproto_inet: u8 = 1;
const nfproto_ipv4: u8 = 2;
const nfproto_ipv6: u8 = 10;
const ipproto_tcp: u8 = 6;

/// Builds netlink messages into a buffer the caller owns. Every length is
/// written after the part it covers is complete, which is the only way a
/// nested attribute can know its own size.
///
/// **This is a byte writer and not an nftables library.** It knows message
/// headers, attributes and nesting, and nothing at all about what an
/// expression means.
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

    /// nftables reads every one of its own integer attributes as network byte
    /// order, whether or not the sender marks it, so these never carry
    /// `NLA_F_NET_BYTEORDER`.
    fn be32(b: *Builder, kind: u16, value: u32) void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .big);
        b.attribute(kind, &bytes);
    }

    fn be64(b: *Builder, kind: u16, value: u64) void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .big);
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

    fn openMessage(b: *Builder, kind: u16, flags: u16, sequence: u32, family: u8, res_id: u16) usize {
        const at = b.len;
        b.put(&[_]u8{0} ** 16);
        std.mem.writeInt(u16, b.buf[at + 4 ..][0..2], kind, .little);
        std.mem.writeInt(u16, b.buf[at + 6 ..][0..2], flags, .little);
        std.mem.writeInt(u32, b.buf[at + 8 ..][0..4], sequence, .little);
        // The nfgenmsg header: family, version, then a big endian id.
        b.put(&[_]u8{ family, 0, 0, 0 });
        std.mem.writeInt(u16, b.buf[b.len - 2 ..][0..2], res_id, .big);
        return at;
    }

    fn closeMessage(b: *Builder, at: usize) void {
        std.mem.writeInt(u32, b.buf[at..][0..4], @intCast(b.len - at), .little);
    }

    fn batchBegin(b: *Builder, sequence: u32) void {
        const at = b.openMessage(nfnl_msg_batch_begin, f_request, sequence, 0, subsys_nftables);
        b.closeMessage(at);
    }

    fn batchEnd(b: *Builder, sequence: u32) void {
        const at = b.openMessage(nfnl_msg_batch_end, f_request, sequence, 0, subsys_nftables);
        b.closeMessage(at);
    }

    fn openChange(b: *Builder, message: u16, flags: u16, sequence: u32) usize {
        return b.openMessage((subsys_nftables << 8) | message, f_request | f_ack | flags, sequence, nfproto_inet, 0);
    }
};

// The expressions, each spelled out once. A parameter here is a place a wrong
// value can hide, so these take only what genuinely differs between the rules
// that use them.

/// `NFTA_EXPR_NAME` plus an open `NFTA_EXPR_DATA`. The caller closes both.
fn openExpression(b: *Builder, name: []const u8) struct { usize, usize } {
    const entry = b.openNested(nfta_list_elem);
    b.string(1, name);
    const data = b.openNested(2);
    return .{ entry, data };
}

fn closeExpression(b: *Builder, marks: struct { usize, usize }) void {
    b.closeNested(marks[1]);
    b.closeNested(marks[0]);
}

/// `meta load <key> => reg 1`.
fn metaLoad(b: *Builder, key: u32) void {
    const marks = openExpression(b, "meta");
    b.be32(2, key); // NFTA_META_KEY
    b.be32(1, 1); // NFTA_META_DREG, NFT_REG_1
    closeExpression(b, marks);
}

/// `cmp <op> reg 1 <value>`. The value is register bytes, in the order the
/// loading expression put them there, so it is not byte swapped here.
fn compare(b: *Builder, op: u32, value: []const u8) void {
    const marks = openExpression(b, "cmp");
    b.be32(1, 1); // NFTA_CMP_SREG
    b.be32(2, op); // NFTA_CMP_OP
    const data = b.openNested(3); // NFTA_CMP_DATA
    b.attribute(nfta_data_value, value);
    b.closeNested(data);
    closeExpression(b, marks);
}

/// `immediate reg 0 accept`, the verdict that ends every accepting rule.
fn immediateAccept(b: *Builder) void {
    const marks = openExpression(b, "immediate");
    b.be32(1, 0); // NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT
    const data = b.openNested(2); // NFTA_IMMEDIATE_DATA
    const verdict = b.openNested(2); // NFTA_DATA_VERDICT
    b.be32(1, 1); // NFTA_VERDICT_CODE, NF_ACCEPT
    b.closeNested(verdict);
    b.closeNested(data);
    closeExpression(b, marks);
}

/// `payload load <length>b @ network header + <offset> => reg 1`.
fn payloadLoad(b: *Builder, offset: u32, length: u32) void {
    const marks = openExpression(b, "payload");
    b.be32(1, 1); // NFTA_PAYLOAD_DREG
    b.be32(2, 1); // NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER
    b.be32(3, offset);
    b.be32(4, length);
    closeExpression(b, marks);
}

/// `lookup reg 1 set <name>`.
fn setLookup(b: *Builder, name: []const u8, id: u32) void {
    const marks = openExpression(b, "lookup");
    b.be32(2, 1); // NFTA_LOOKUP_SREG
    b.string(1, name); // NFTA_LOOKUP_SET
    b.be32(4, id); // NFTA_LOOKUP_SET_ID, which names a set made in this batch
    closeExpression(b, marks);
}

fn openRule(b: *Builder, sequence: u32, chain: []const u8) struct { usize, usize } {
    const at = b.openChange(msg_newrule, f_create | f_append, sequence);
    b.string(1, table_name); // NFTA_RULE_TABLE
    b.string(2, chain); // NFTA_RULE_CHAIN
    const expressions = b.openNested(4); // NFTA_RULE_EXPRESSIONS
    return .{ at, expressions };
}

fn closeRule(b: *Builder, marks: struct { usize, usize }) void {
    b.closeNested(marks[1]);
    b.closeMessage(marks[0]);
}

/// Every set the lookups name is created inside the same batch, so the rules
/// reach them by transaction id rather than by a handle that does not exist
/// yet.
const set4_id: u32 = 1;
const set6_id: u32 = 2;

/// Write the whole ruleset into `buf` and answer how many bytes it took.
/// Evaluated at compile time; see `install_batch`.
fn buildInstall(buf: []u8) usize {
    var b = Builder{ .buf = buf };
    b.batchBegin(0);

    var at = b.openChange(msg_newtable, f_create, 1);
    b.string(1, table_name); // NFTA_TABLE_NAME
    b.be32(2, 0); // NFTA_TABLE_FLAGS
    b.closeMessage(at);

    at = b.openChange(msg_newchain, f_create, 2);
    b.string(1, table_name); // NFTA_CHAIN_TABLE
    b.string(3, guard_chain_name); // NFTA_CHAIN_NAME
    b.be32(5, guard_policy); // NFTA_CHAIN_POLICY
    b.string(7, "filter"); // NFTA_CHAIN_TYPE
    var hook = b.openNested(4); // NFTA_CHAIN_HOOK
    b.be32(1, hook_output);
    b.be32(2, @bitCast(guard_priority));
    b.closeNested(hook);
    b.closeMessage(at);

    at = b.openChange(msg_newchain, f_create, 3);
    b.string(1, table_name);
    b.string(3, relay_chain_name);
    // No policy: a nat chain accepts what no rule matched, and the kernel
    // refuses a nat chain that asks to drop.
    b.string(7, "nat");
    hook = b.openNested(4);
    b.be32(1, hook_output);
    b.be32(2, @bitCast(relay_priority));
    b.closeNested(hook);
    b.closeMessage(at);

    at = b.openChange(msg_newset, f_create, 4);
    b.string(1, table_name); // NFTA_SET_TABLE
    b.string(2, set4_name); // NFTA_SET_NAME
    b.be32(3, 0x10); // NFTA_SET_FLAGS, NFT_SET_TIMEOUT
    b.be32(4, 7); // NFTA_SET_KEY_TYPE, which nft reads back as ipv4_addr
    b.be32(5, 4); // NFTA_SET_KEY_LEN
    b.be32(10, set4_id); // NFTA_SET_ID
    b.be64(11, default_timeout_ms); // NFTA_SET_TIMEOUT
    b.closeMessage(at);

    at = b.openChange(msg_newset, f_create, 5);
    b.string(1, table_name);
    b.string(2, set6_name);
    b.be32(3, 0x10);
    b.be32(4, 8); // ipv6_addr
    b.be32(5, 16);
    b.be32(10, set6_id);
    b.be64(11, default_timeout_ms);
    b.closeMessage(at);

    // ct state established,related accept
    var rule = openRule(&b, 6, guard_chain_name);
    {
        const marks = openExpression(&b, "ct");
        b.be32(2, 0); // NFTA_CT_KEY, NFT_CT_STATE
        b.be32(1, 1); // NFTA_CT_DREG
        closeExpression(&b, marks);
    }
    {
        // The state is a bitmask, so the rule masks it and then asks whether
        // anything is left, which is what "one of these two" compiles to.
        const marks = openExpression(&b, "bitwise");
        b.be32(1, 1); // NFTA_BITWISE_SREG
        b.be32(2, 1); // NFTA_BITWISE_DREG
        b.be32(3, 4); // NFTA_BITWISE_LEN
        const mask = b.openNested(4);
        b.attribute(nfta_data_value, &[_]u8{ 6, 0, 0, 0 }); // ESTABLISHED | RELATED
        b.closeNested(mask);
        const xor = b.openNested(5);
        b.attribute(nfta_data_value, &[_]u8{ 0, 0, 0, 0 });
        b.closeNested(xor);
        closeExpression(&b, marks);
    }
    compare(&b, 1, &[_]u8{ 0, 0, 0, 0 }); // NFT_CMP_NEQ
    immediateAccept(&b);
    closeRule(&b, rule);

    // oif "lo" accept
    rule = openRule(&b, 7, guard_chain_name);
    metaLoad(&b, 5); // NFT_META_OIF
    // The kernel makes loopback first in every network namespace, so index 1
    // is loopback here by construction and not by luck.
    compare(&b, 0, &[_]u8{ 1, 0, 0, 0 });
    immediateAccept(&b);
    closeRule(&b, rule);

    // ip daddr @allowed4 accept
    rule = openRule(&b, 8, guard_chain_name);
    metaLoad(&b, 15); // NFT_META_NFPROTO
    compare(&b, 0, &[_]u8{nfproto_ipv4});
    payloadLoad(&b, 16, 4); // the destination in an IPv4 header
    setLookup(&b, set4_name, set4_id);
    immediateAccept(&b);
    closeRule(&b, rule);

    // ip6 daddr @allowed6 accept
    rule = openRule(&b, 9, guard_chain_name);
    metaLoad(&b, 15);
    compare(&b, 0, &[_]u8{nfproto_ipv6});
    payloadLoad(&b, 24, 16); // the destination in an IPv6 header
    setLookup(&b, set6_name, set6_id);
    immediateAccept(&b);
    closeRule(&b, rule);

    // reject with icmpx port-unreachable
    //
    // A reject and not a drop, because a drop costs the program a full connect
    // timeout on every refusal while this answers at once. An `inet` table can
    // hold this in a filter chain; iptables cannot express it at all.
    rule = openRule(&b, 10, guard_chain_name);
    {
        const marks = openExpression(&b, "reject");
        b.be32(1, 2); // NFTA_REJECT_TYPE, NFT_REJECT_ICMPX_UNREACH
        b.attribute(2, &[_]u8{1}); // NFT_REJECT_ICMPX_PORT_UNREACH
        closeExpression(&b, marks);
    }
    closeRule(&b, rule);

    // meta l4proto tcp redirect to :18080
    rule = openRule(&b, 11, relay_chain_name);
    metaLoad(&b, 16); // NFT_META_L4PROTO
    compare(&b, 0, &[_]u8{ipproto_tcp});
    {
        const marks = openExpression(&b, "immediate");
        b.be32(1, 1); // NFTA_IMMEDIATE_DREG, NFT_REG_1
        const data = b.openNested(2);
        var port: [2]u8 = undefined;
        std.mem.writeInt(u16, &port, relay_port, .big);
        b.attribute(nfta_data_value, &port);
        b.closeNested(data);
        closeExpression(&b, marks);
    }
    {
        const marks = openExpression(&b, "redir");
        b.be32(1, 1); // NFTA_REDIR_REG_PROTO_MIN, the register holding the port
        b.be32(3, 2); // NF_NAT_RANGE_PROTO_SPECIFIED
        closeExpression(&b, marks);
    }
    closeRule(&b, rule);

    b.batchEnd(12);
    return b.len;
}

/// The whole ruleset as one constant. Built at compile time so that nothing at
/// run time can produce a different one, and pinned byte for byte by
/// `the install batch is the pinned byte sequence` below.
const install_batch = build: {
    @setEvalBranchQuota(100_000);
    var buffer: [4096]u8 = @splat(0);
    const length = buildInstall(&buffer);
    const bytes: [length]u8 = buffer[0..length].*;
    break :build bytes;
};

/// Enough for one set element message inside a batch: the longest key is 16
/// bytes and every other part is a short name.
const max_element_message = 256;
/// Enough for the longest reply this file reads, which is a dump of the rules
/// of one chain.
const reply_capacity = 8192;

fn buildElementBatch(buf: []u8, address: Address, timeout_ms: u64) usize {
    var b = Builder{ .buf = buf };
    b.batchBegin(0);
    const at = b.openChange(msg_newsetelem, f_create, 1);
    b.string(nfta_set_elem_list_table, table_name);
    b.string(nfta_set_elem_list_set, address.setName());
    const elements = b.openNested(nfta_set_elem_list_elements);
    const entry = b.openNested(nfta_list_elem);
    const key = b.openNested(nfta_set_elem_key);
    b.attribute(nfta_data_value, address.key());
    b.closeNested(key);
    b.be64(nfta_set_elem_timeout, timeout_ms);
    b.closeNested(entry);
    b.closeNested(elements);
    b.closeMessage(at);
    b.batchEnd(2);
    return b.len;
}

fn buildElementQuery(buf: []u8, address: Address) usize {
    var b = Builder{ .buf = buf };
    const at = b.openMessage((subsys_nftables << 8) | msg_getsetelem, f_request, 0, nfproto_inet, 0);
    b.string(nfta_set_elem_list_table, table_name);
    b.string(nfta_set_elem_list_set, address.setName());
    const elements = b.openNested(nfta_set_elem_list_elements);
    const entry = b.openNested(nfta_list_elem);
    const key = b.openNested(nfta_set_elem_key);
    b.attribute(nfta_data_value, address.key());
    b.closeNested(key);
    b.closeNested(entry);
    b.closeNested(elements);
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

    /// Everything after the netlink header and the nfgenmsg header, which is
    /// where the attributes start.
    fn payload(self: Message) []const u8 {
        if (self.body.len < 4) return self.body[0..0];
        return self.body[4..];
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

fn readBe32(bytes: []const u8) u32 {
    if (bytes.len < 4) return 0;
    return std.mem.readInt(u32, bytes[0..4], .big);
}

fn readBe64(bytes: []const u8) u64 {
    if (bytes.len < 8) return 0;
    return std.mem.readInt(u64, bytes[0..8], .big);
}

// ---------------------------------------------------------------------------
// Reading the installed ruleset back.
//
// **Not public.** Nothing outside this file needs it, and the three things
// this module offers a caller are the install, the allow, and the element.
// What it is for is the tests below: an acknowledgement says the kernel took
// the batch, and only a read says what the kernel built out of it.
// ---------------------------------------------------------------------------

const ChainFacts = struct {
    hook: u32,
    priority: i32,
    policy: u32,
    /// The chain type name, "filter" or "nat", padded with zeros.
    type_name: [8]u8,
};

fn chainFacts(session: Session, name: []const u8, diag: ?*?Diagnostic) Error!?ChainFacts {
    var buffer: [max_element_message]u8 = undefined;
    var b = Builder{ .buf = &buffer };
    const at = b.openMessage((subsys_nftables << 8) | msg_getchain, f_request, 0, nfproto_inet, 0);
    b.string(1, table_name); // NFTA_CHAIN_TABLE
    b.string(3, name); // NFTA_CHAIN_NAME
    b.closeMessage(at);
    try session.send(b.buf[0..b.len], .chain_read, diag);

    var reply: [reply_capacity]u8 = undefined;
    const filled = try session.receive(&reply, .chain_read, diag);
    var messages = Messages{ .bytes = reply[0..filled] };
    while (messages.next()) |message| {
        if (message.kind == nlmsg_error) {
            const code = errorCode(message.body);
            if (code == 0) continue;
            note(diag, .chain_read, code);
            return classify(.chain_read, code);
        }
        const attributes = Attributes{ .bytes = message.payload() };
        var found = ChainFacts{ .hook = 0, .priority = 0, .policy = 0, .type_name = @splat(0) };
        if (attributes.find(4)) |hook| { // NFTA_CHAIN_HOOK
            const inside = Attributes{ .bytes = hook };
            if (inside.find(1)) |number| found.hook = readBe32(number);
            if (inside.find(2)) |priority| found.priority = @bitCast(readBe32(priority));
        }
        if (attributes.find(5)) |policy| found.policy = readBe32(policy);
        if (attributes.find(7)) |text| {
            const wanted = @min(text.len, found.type_name.len);
            @memcpy(found.type_name[0..wanted], text[0..wanted]);
        }
        return found;
    }
    return null;
}

const SetFacts = struct {
    flags: u32,
    key_len: u32,
    timeout_ms: u64,
};

fn setFacts(session: Session, name: []const u8, diag: ?*?Diagnostic) Error!?SetFacts {
    var buffer: [max_element_message]u8 = undefined;
    var b = Builder{ .buf = &buffer };
    const at = b.openMessage((subsys_nftables << 8) | msg_getset, f_request, 0, nfproto_inet, 0);
    b.string(1, table_name); // NFTA_SET_TABLE
    b.string(2, name); // NFTA_SET_NAME
    b.closeMessage(at);
    try session.send(b.buf[0..b.len], .set_read, diag);

    var reply: [reply_capacity]u8 = undefined;
    const filled = try session.receive(&reply, .set_read, diag);
    var messages = Messages{ .bytes = reply[0..filled] };
    while (messages.next()) |message| {
        if (message.kind == nlmsg_error) {
            const code = errorCode(message.body);
            if (code == 0) continue;
            note(diag, .set_read, code);
            return classify(.set_read, code);
        }
        const attributes = Attributes{ .bytes = message.payload() };
        return .{
            .flags = if (attributes.find(3)) |bytes| readBe32(bytes) else 0,
            .key_len = if (attributes.find(5)) |bytes| readBe32(bytes) else 0,
            .timeout_ms = if (attributes.find(11)) |bytes| readBe64(bytes) else 0,
        };
    }
    return null;
}

/// Write the expressions of every rule in one chain, in order, as
/// `name,name;name,name`. This is the shape of the chain rather than its
/// values, which is what says the rules landed in the order they were written
/// and that none of them lost an expression on the way.
fn ruleShape(session: Session, chain: []const u8, into: []u8, diag: ?*?Diagnostic) Error!usize {
    var buffer: [max_element_message]u8 = undefined;
    var b = Builder{ .buf = &buffer };
    const at = b.openMessage((subsys_nftables << 8) | msg_getrule, f_request | f_dump, 0, nfproto_inet, 0);
    b.string(1, table_name); // NFTA_RULE_TABLE
    b.string(2, chain); // NFTA_RULE_CHAIN
    b.closeMessage(at);
    try session.send(b.buf[0..b.len], .rule_read, diag);

    var written: usize = 0;
    var rules: usize = 0;
    var reply: [reply_capacity]u8 = undefined;
    // A dump ends with NLMSG_DONE. The bound is on the number of datagrams, so
    // a kernel that never sends one cannot hold this loop open.
    var datagrams: usize = 0;
    while (datagrams < 64) : (datagrams += 1) {
        const filled = try session.receive(&reply, .rule_read, diag);
        var messages = Messages{ .bytes = reply[0..filled] };
        while (messages.next()) |message| {
            if (message.kind == nlmsg_done) return written;
            if (message.kind == nlmsg_error) {
                const code = errorCode(message.body);
                if (code == 0) continue;
                note(diag, .rule_read, code);
                return classify(.rule_read, code);
            }
            const attributes = Attributes{ .bytes = message.payload() };
            const expressions = attributes.find(4) orelse continue; // NFTA_RULE_EXPRESSIONS
            if (rules > 0) written += append(into[written..], ";");
            rules += 1;
            var list = Attributes{ .bytes = expressions };
            var first = true;
            while (list.next()) |entry| {
                const inside = Attributes{ .bytes = entry.payload };
                const name = inside.find(1) orelse continue; // NFTA_EXPR_NAME
                if (!first) written += append(into[written..], ",");
                first = false;
                written += append(into[written..], std.mem.sliceTo(name, 0));
            }
        }
    }
    note(diag, .rule_read, 0);
    return error.ExchangeFailed;
}

/// Copy what fits and answer how much that was. The caller's buffer is sized
/// for the whole ruleset, so a truncation here makes the test that reads it
/// fail rather than making this call fail.
fn append(into: []u8, text: []const u8) usize {
    const wanted = @min(into.len, text.len);
    @memcpy(into[0..wanted], text[0..wanted]);
    return wanted;
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

    guard_hook: u32,
    guard_priority: i32,
    guard_policy: u32,
    guard_type: [8]u8,

    relay_hook: u32,
    relay_priority: i32,
    relay_policy: u32,
    relay_type: [8]u8,

    set4_flags: u32,
    set4_key_len: u32,
    set4_timeout_ms: u64,
    set6_flags: u32,
    set6_key_len: u32,
    set6_timeout_ms: u64,

    element_found: u32,
    element_has_comment: u32,
    element_timeout_ms: u64,
    element_expiration_ms: u64,

    shape_len: u32,
    shape: [384]u8,

    const no_failure: u32 = 0xffff_ffff;
};

/// The address and the timeout the child asks for. **45 seconds, which is not
/// the set default**, so an element that falls back to the default is a
/// different number and not a coincidence.
const probe_address = Address{ .ipv4 = .{ 10, 1, 2, 3 } };
const probe_timeout_ms: u64 = 45_000;

/// What the two chains must contain, expression by expression, after the
/// install. A missing expression, a reordered rule, or a rule that never
/// landed all read as a different string here.
const expected_shape =
    "ct,bitwise,cmp,immediate" ++
    ";meta,cmp,immediate" ++
    ";meta,cmp,payload,lookup,immediate" ++
    ";meta,cmp,payload,lookup,immediate" ++
    ";reject" ++
    "|meta,cmp,immediate,redir";

fn measureInChild(record: *Measurement) void {
    record.* = std.mem.zeroes(Measurement);
    record.failed_step = Measurement.no_failure;

    var diag: ?Diagnostic = null;
    const session = Session.open(&diag) catch {
        recordFailure(record, diag);
        return;
    };
    defer session.close();

    session.install(&diag) catch {
        recordFailure(record, diag);
        return;
    };
    session.allow(probe_address, probe_timeout_ms, &diag) catch {
        recordFailure(record, diag);
        return;
    };

    if (session.element(probe_address, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |found| {
        record.element_found = 1;
        record.element_has_comment = @intFromBool(found.has_comment);
        record.element_timeout_ms = found.timeout_ms;
        record.element_expiration_ms = found.expiration_ms;
    }

    if (chainFacts(session, guard_chain_name, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |facts| {
        record.guard_hook = facts.hook;
        record.guard_priority = facts.priority;
        record.guard_policy = facts.policy;
        record.guard_type = facts.type_name;
    }
    if (chainFacts(session, relay_chain_name, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |facts| {
        record.relay_hook = facts.hook;
        record.relay_priority = facts.priority;
        record.relay_policy = facts.policy;
        record.relay_type = facts.type_name;
    }

    if (setFacts(session, set4_name, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |facts| {
        record.set4_flags = facts.flags;
        record.set4_key_len = facts.key_len;
        record.set4_timeout_ms = facts.timeout_ms;
    }
    if (setFacts(session, set6_name, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |facts| {
        record.set6_flags = facts.flags;
        record.set6_key_len = facts.key_len;
        record.set6_timeout_ms = facts.timeout_ms;
    }

    var used = ruleShape(session, guard_chain_name, &record.shape, &diag) catch {
        recordFailure(record, diag);
        return;
    };
    used += append(record.shape[used..], "|");
    used += ruleShape(session, relay_chain_name, record.shape[used..], &diag) catch {
        recordFailure(record, diag);
        return;
    };
    record.shape_len = @intCast(used);
}

fn recordFailure(record: *Measurement, diag: ?Diagnostic) void {
    if (diag) |d| {
        record.failed_step = @intFromEnum(d.step);
        record.failed_errno = d.errno;
    } else {
        record.failed_step = @intFromEnum(Step.send);
    }
}

/// Install the ruleset in a network namespace of its own and report what the
/// kernel then holds.
///
/// **A child, because a network namespace cannot be left.** The test process
/// needs its own namespaces for every later test, and `namespace.enter` spends
/// the one this process has. `namespace.probeAvailability` forks for the same
/// reason.
///
/// Answers null when this machine will not give a namespace at all, which the
/// caller must report as a skip. **A machine that cannot build a sandbox
/// measured nothing here, and that is not a pass.**
fn measure() ?Measurement {
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
        // races nothing: the parent reads a short pipe and reports a skip.
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

    if (filled != bytes.len) return null;
    return record;
}

/// True when the failure is one no encoding in this file can cause: the kernel
/// has no nftables at all. **Everything deeper is this file's own fault and
/// must fail the test**, including the `ENOENT` an absent expression module
/// gives, because a wrong expression name gives exactly the same answer.
fn measuredNothing(record: Measurement) bool {
    if (record.failed_step == Measurement.no_failure) return false;
    const step = std.enums.fromInt(Step, record.failed_step) orelse return false;
    return switch (step) {
        .open_socket, .batch_begin => true,
        else => false,
    };
}

/// **By pointer, never by value.** Zig may pass a struct this size by
/// reference to a temporary, and a slice into that temporary is dangling the
/// moment the call returns. Measured here: the test read 384 bytes of stack
/// while the child had written the right string.
fn shapeOf(record: *const Measurement) []const u8 {
    return record.shape[0..@min(record.shape_len, record.shape.len)];
}

test "the install batch is the pinned byte sequence" {
    // **Pinned, because there is no type checker between this file and the
    // kernel.** An attribute number, a byte order, or a nesting depth can all
    // be wrong and still be accepted, so any change to the bytes has to be a
    // change someone chose to make. The read back tests below say what the
    // bytes mean; this one says they did not move by accident.
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&install_batch, &digest, .{});

    try testing.expectEqual(@as(usize, 1688), install_batch.len);
    try testing.expectEqualSlices(
        u8,
        &@as([32]u8, .{
            0x98, 0xca, 0x40, 0x85, 0x32, 0xc5, 0x86, 0x15,
            0xb0, 0x05, 0x9f, 0x0c, 0xcc, 0xdb, 0x44, 0xd9,
            0xa8, 0xd2, 0xff, 0x25, 0x2c, 0x8b, 0xc3, 0x6c,
            0xc7, 0x4d, 0xbc, 0x40, 0x7b, 0xed, 0x14, 0x4c,
        }),
        &digest,
    );
}

test "the batch opens and closes exactly one nfnetlink transaction" {
    // The kernel takes an nftables change only inside a batch, and a batch
    // that is never closed is applied to nothing. Arithmetic on the bytes, so
    // it runs on every host this project builds for.
    var messages = Messages{ .bytes = &install_batch };
    var first: ?u16 = null;
    var last: ?u16 = null;
    var count: usize = 0;
    while (messages.next()) |message| {
        if (first == null) first = message.kind;
        last = message.kind;
        try testing.expectEqual(@as(u32, @intCast(count)), message.sequence);
        count += 1;
    }
    try testing.expectEqual(@as(?u16, nfnl_msg_batch_begin), first);
    try testing.expectEqual(@as(?u16, nfnl_msg_batch_end), last);
    // Begin, table, two chains, two sets, six rules, end.
    try testing.expectEqual(@as(usize, 13), count);
}

test "every change in the batch asks for an acknowledgement" {
    // Without NLM_F_ACK the kernel answers a batch it accepted with silence,
    // and silence is also what a batch that was never delivered looks like.
    // The two begin and end messages carry no change and get no answer.
    var messages = Messages{ .bytes = &install_batch };
    var acknowledged: usize = 0;
    var at: usize = 0;
    while (messages.next()) |message| {
        const flags = std.mem.readInt(u16, install_batch[at + 6 ..][0..2], .little);
        at = messages.at;
        if (message.kind == nfnl_msg_batch_begin or message.kind == nfnl_msg_batch_end) {
            try testing.expectEqual(@as(u16, 0), flags & f_ack);
            continue;
        }
        try testing.expectEqual(f_ack, flags & f_ack);
        acknowledged += 1;
    }
    try testing.expectEqual(@as(usize, 11), acknowledged);
}

test "a set element carries its timeout in attribute 4 and never in 6" {
    // Attribute 6 is NFTA_SET_ELEM_USERDATA. A batch that puts the timeout
    // there is accepted and acknowledged, and the element silently keeps the
    // set default with the timeout stored as a comment. Measured 2026-09-14.
    try testing.expectEqual(@as(u16, 4), nfta_set_elem_timeout);
    try testing.expectEqual(@as(u16, 6), nfta_set_elem_userdata);

    var buffer: [max_element_message]u8 = undefined;
    const length = buildElementBatch(&buffer, probe_address, probe_timeout_ms);
    var messages = Messages{ .bytes = buffer[0..length] };
    _ = messages.next(); // the batch begin
    const change = messages.next() orelse return error.TestUnexpectedResult;
    const attributes = Attributes{ .bytes = change.payload() };
    const elements = attributes.find(nfta_set_elem_list_elements) orelse return error.TestUnexpectedResult;
    var list = Attributes{ .bytes = elements };
    const entry = list.next() orelse return error.TestUnexpectedResult;
    const inside = Attributes{ .bytes = entry.payload };

    const timeout = inside.find(nfta_set_elem_timeout) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(probe_timeout_ms, readBe64(timeout));
    try testing.expectEqual(@as(?[]const u8, null), inside.find(nfta_set_elem_userdata));
}

test "install reads back the ruleset it wrote" {
    const record = measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.failed_step);

    // The two chains, by what the kernel says they are rather than by what
    // the batch asked for.
    try testing.expectEqualStrings("filter", std.mem.sliceTo(&record.guard_type, 0));
    try testing.expectEqualStrings("nat", std.mem.sliceTo(&record.relay_type, 0));
    // NF_DROP is 0 and NF_ACCEPT is 1. A guard that accepts what no rule
    // matched is a guard that stops nothing.
    try testing.expectEqual(@as(u32, 0), record.guard_policy);
    try testing.expectEqual(@as(u32, 1), record.relay_policy);

    // Both sets take timeouts, hold the right key width, and carry the
    // default the kernel expires an element by.
    try testing.expectEqual(@as(u32, 0x10), record.set4_flags);
    try testing.expectEqual(@as(u32, 4), record.set4_key_len);
    try testing.expectEqual(default_timeout_ms, record.set4_timeout_ms);
    try testing.expectEqual(@as(u32, 0x10), record.set6_flags);
    try testing.expectEqual(@as(u32, 16), record.set6_key_len);
    try testing.expectEqual(default_timeout_ms, record.set6_timeout_ms);

    // Every rule, in order, with every expression it was built from.
    try testing.expectEqualStrings(expected_shape, shapeOf(&record));
}

test "the two chains keep the priorities the ordering depends on" {
    const record = measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.failed_step);

    // Both hook the locally generated packet, which is the only kind this
    // sandbox can make.
    try testing.expectEqual(hook_output, record.guard_hook);
    try testing.expectEqual(hook_output, record.relay_hook);

    // **-150, and nothing else.** Conntrack is at -200, so `ct state` is
    // readable. Destination nat is at -100, so the guard still sees the
    // address the program asked for. At 0, which is where `filter OUTPUT`
    // sits, the same rules matched zero packets while the connection they
    // were meant to stop reached its listener.
    try testing.expectEqual(@as(i32, -150), record.guard_priority);
    try testing.expectEqual(@as(i32, -100), record.relay_priority);
    try testing.expect(record.guard_priority < record.relay_priority);
}

test "allow stores a timeout the kernel gives back as a timeout" {
    const record = measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.failed_step);

    try testing.expectEqual(@as(u32, 1), record.element_found);
    // **The number asked for, and not the set default.** The two differ on
    // purpose. A timeout written into the userdata attribute leaves no
    // per-element timeout at all, so this reads zero there while the batch
    // that wrote it was acknowledged.
    try testing.expectEqual(probe_timeout_ms, record.element_timeout_ms);
    try testing.expect(record.element_timeout_ms != default_timeout_ms);
    // Nothing was ever sent as a comment, so anything the kernel holds as one
    // is a timeout that went into the wrong attribute.
    try testing.expectEqual(@as(u32, 0), record.element_has_comment);
    // The kernel is already counting down, so what is left is at most what
    // was asked for, and enough of it is left that the element is live.
    try testing.expect(record.element_expiration_ms <= probe_timeout_ms);
    try testing.expect(record.element_expiration_ms > probe_timeout_ms / 2);
}

test "an address that was never allowed is absent rather than an error" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // The resolver asks about addresses it did not add, so "not there" has to
    // be an answer and not a fault. Proved on the bytes: the query names one
    // key, and the kernel answers ENOENT for a key it does not hold, which
    // `element` turns into null.
    var buffer: [max_element_message]u8 = undefined;
    const length = buildElementQuery(&buffer, .{ .ipv6 = .{0xff} ** 16 });
    var messages = Messages{ .bytes = buffer[0..length] };
    const query = messages.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqual((subsys_nftables << 8) | msg_getsetelem, query.kind);
    const attributes = Attributes{ .bytes = query.payload() };
    const set = attributes.find(nfta_set_elem_list_set) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings(set6_name, std.mem.sliceTo(set, 0));
}

test "an absent kernel module is told apart from a refusal and from a bug" {
    // Measured on kernel 6.18 by asking for objects that are not there:
    // an nftables subsystem nfnetlink does not have answers EOPNOTSUPP at the
    // batch begin, and an expression or a chain type that is not loaded
    // answers ENOENT on the message that names it.
    try testing.expectEqual(error.KernelModuleMissing, classify(.batch_begin, @intFromEnum(linux.E.OPNOTSUPP)));
    try testing.expectEqual(error.KernelModuleMissing, classify(.open_socket, @intFromEnum(linux.E.PROTONOSUPPORT)));
    try testing.expectEqual(error.KernelModuleMissing, classify(.relay_rule, @intFromEnum(linux.E.NOENT)));
    try testing.expectEqual(error.KernelModuleMissing, classify(.relay_chain, @intFromEnum(linux.E.NOENT)));

    // A capability that is gone is a different thing to fix, so it gets a
    // different name.
    try testing.expectEqual(error.NotPermitted, classify(.batch_begin, @intFromEnum(linux.E.PERM)));

    // **ENOENT only means a module where a module is what is missing.** Every
    // object the install batch names is created inside that same batch, so a
    // table or a set that is "not found" is this file getting the bytes wrong
    // and must not read as a property of the host.
    try testing.expectEqual(error.Refused, classify(.table, @intFromEnum(linux.E.NOENT)));
    try testing.expectEqual(error.Refused, classify(.element_add, @intFromEnum(linux.E.NOENT)));
    try testing.expectEqual(error.Refused, classify(.set4, @intFromEnum(linux.E.INVAL)));
}

test "a refusal names the message the kernel would not take" {
    // The kernel says which message failed by its sequence number and nothing
    // else, so this mapping is the only thing that turns a refusal into a
    // sentence a person can act on.
    try testing.expectEqual(Step.batch_begin, Step.ofInstallSequence(0));
    try testing.expectEqual(Step.table, Step.ofInstallSequence(1));
    try testing.expectEqual(Step.guard_chain, Step.ofInstallSequence(2));
    try testing.expectEqual(Step.relay_chain, Step.ofInstallSequence(3));
    try testing.expectEqual(Step.set4, Step.ofInstallSequence(4));
    try testing.expectEqual(Step.set6, Step.ofInstallSequence(5));
    try testing.expectEqual(Step.reject_rule, Step.ofInstallSequence(10));
    try testing.expectEqual(Step.relay_rule, Step.ofInstallSequence(11));
    try testing.expectEqual(Step.batch_end, Step.ofInstallSequence(12));
}

test "an address picks its own set and carries its own key width" {
    const four = Address{ .ipv4 = .{ 192, 0, 2, 1 } };
    const six = Address{ .ipv6 = .{0x20} ++ .{0} ** 15 };
    try testing.expectEqualStrings(set4_name, four.setName());
    try testing.expectEqualStrings(set6_name, six.setName());
    try testing.expectEqual(@as(usize, 4), four.key().len);
    try testing.expectEqual(@as(usize, 16), six.key().len);
}
