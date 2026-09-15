//! The one channel the network router has out of the sandbox, and the two
//! questions it carries.
//!
//! ## What this is for
//!
//! `router.zig` holds the resolver and the relay, and it names three things it
//! cannot do from where it stands: resolve a name, put an address in the
//! kernel's allow set, and open a descriptor that leaves the network
//! namespace. The middle one needs `CAP_NET_ADMIN` and nothing else, so the
//! router does it itself. **The other two are on the far side of the sandbox
//! boundary**, because a socket made inside the namespace reaches the
//! blackhole and a resolver inside it reaches nothing at all.
//!
//! So the router holds one `SOCK_SEQPACKET` pair whose other end is served by
//! the process that called `Sandbox.spawn`, and it asks two things on it:
//!
//!     resolve "registry.npmjs.org", ipv4   ->  granted 104.16.0.1
//!                                          ->  refused
//!                                          ->  unresolved
//!     open 104.16.0.1:443                  ->  granted <descriptor>
//!                                          ->  refused
//!
//! ## Why this is not `netbroker.zig`
//!
//! The netbroker carries a **name** and a port and answers with a descriptor,
//! which is the whole exchange a program written for Chock needs. The router
//! needs the two halves apart: it has to hold an address between the answer to
//! a query and the connection that follows, so the kernel can refuse every
//! address it never handed out. A netbroker reply carries no address on
//! purpose, and giving it one would weaken the exchange it already serves for
//! the sake of a different caller. They are two channels because they answer
//! two different questions, and `netbroker.zig` is left exactly as it is.
//!
//! ## Which side may trust what
//!
//! **The inside is Chock's own code and the outside still checks it.** The
//! router is the one process in the sandbox that nobody else wrote, so nothing
//! hostile speaks this protocol today. `serveOne` bounds every field anyway,
//! for the reason `netbroker.serveOne` does: a check that is only true because
//! of who the caller happens to be is a check that stops being true the moment
//! somebody moves a descriptor.
//!
//! **The name goes out and the address comes back, and the address is the
//! identity from then on.** `open` carries an address and never a name,
//! because the router's own name table answers with the name an address was
//! **last** handed out for and two hosts on one content network share an
//! address. The far side maps the address back to the name **it** resolved,
//! which is exact, and never reads one from inside.
//!
//! ## Linux only, and why the file is here
//!
//! `SCM_RIGHTS` exists on Darwin, but `Sandbox.spawn` refuses there, so there
//! is no router to serve. The file sits under `linux/` with the rest of the
//! mechanism and reaches the kernel through `std.os.linux`. It compiles for
//! Darwin and every test in it that opens a socket answers `error.SkipZigTest`
//! there, the same as `netbroker.zig` and `router.zig` beside it.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const iface = @import("../Sandbox.zig");
const NetRouter = iface.NetRouter;
const NetBroker = iface.NetBroker;

const router = @import("router.zig");
const nftables = @import("nftables.zig");
const netbroker = @import("netbroker.zig");

/// The longest host name one request may carry. The same bound the netbroker
/// and DNS itself have, and the same one `router.name_capacity` parses into.
pub const max_host_bytes: usize = netbroker.max_host_bytes;

comptime {
    // The router parses a query into a buffer of its own and then hands the
    // name here. A name it can hold and this file cannot would be cut short on
    // the way out, and a shortened name is a **different host**, which the far
    // side would then answer about.
    if (router.name_capacity != max_host_bytes) @compileError(
        "routerlink: a name the resolver can parse must fit in one request. See max_host_bytes.",
    );
}

/// The descriptor number the router finds its channel on. **Not
/// `netbroker.fd_number`**, because the two are never both present: see
/// `Config.net_router`. It is the same number for the same reason, which is
/// that zero, one and two are the standard streams.
pub const fd_number: i32 = 3;

/// How many requests one routed call may make before the far end stops
/// listening.
///
/// **A bound and not a target.** One request is one name a program resolved or
/// one connection it made, and every one of them costs the far side a policy
/// read and, when the policy permits, a name lookup or a connect. This is what
/// makes that cost finite.
///
/// **Far above `netbroker.max_requests`, on purpose.** The netbroker serves a
/// program written for Chock, which opens a handful of connections. This
/// serves every program a tool call runs, and installing a package really does
/// resolve dozens of names and open hundreds of connections. A bound a real
/// workload reaches is a bound that reads as a network fault.
pub const max_requests: usize = 4096;

/// The bytes "CRQ1", so a message that is not one of ours is refused rather
/// than read as a request. See `netbroker.request_magic` for why a pair with
/// exactly two ends carries one anyway.
pub const request_magic: u32 = 0x31515243;

/// The bytes "CRR1". See `request_magic`.
pub const reply_magic: u32 = 0x31525243;

/// Which of the two questions a request asks.
pub const Kind = enum(u8) {
    /// `host` and `family` are read. Answered with an address, a refusal, or
    /// "no address of that width".
    resolve = 0,
    /// `address`, `family` and `port` are read. Answered with a descriptor or
    /// a refusal.
    open = 1,
    _,
};

/// Which width an address is. The same two the kernel's allow sets are,
/// spelled as the tag of `NetRouter.Address` so the two cannot drift.
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

    /// The seam's own spelling, or null for a byte that is neither.
    pub fn seam(self: Family) ?NetRouter.Family {
        return switch (self) {
            .ipv4 => .ipv4,
            .ipv6 => .ipv6,
            _ => null,
        };
    }
};

/// What the router asks for. Fixed size, so `serveOne` can refuse a message of
/// the wrong length outright rather than parsing whatever arrived.
pub const Request = extern struct {
    magic: u32 = request_magic,
    kind: Kind,
    /// Which width. The record type for a `resolve`, and the address's own
    /// width for an `open`.
    family: Family,
    /// How many bytes of `host` are the name. Zero for an `open`. Bounded by
    /// `serveOne` before it is used.
    host_len: u8,
    /// Always zero. Present so the structure has no padding the compiler
    /// chooses, which would otherwise send this process's own memory across
    /// the boundary in the gap.
    reserved: u8 = 0,
    /// The port, for an `open`. Zero for a `resolve`, which has no port: a
    /// name is looked up before any connection exists.
    port: u16,
    /// Always zero, for the reason `reserved` is.
    reserved2: u16 = 0,
    /// The address, for an `open`. Four bytes used for `ipv4` and sixteen for
    /// `ipv6`, left aligned, with the rest zero.
    address: [16]u8 = @splat(0),
    host: [max_host_bytes]u8 = @splat(0),
};

/// What comes back.
pub const Reply = extern struct {
    magic: u32 = reply_magic,
    status: Status,
    /// The width of `address`. Only read for a granted `resolve`.
    family: Family = .ipv4,
    /// Always zero, for the reason `Request.reserved` is.
    reserved: [2]u8 = @splat(0),
    address: [16]u8 = @splat(0),

    pub const Status = enum(u8) {
        /// A `resolve` carries an address here. An `open` carries a descriptor
        /// in `SCM_RIGHTS` and no address at all.
        granted = 0,
        /// No, and no reason. See `NetBroker.Grant.refused`.
        refused = 1,
        /// A `resolve` that the policy permitted and that has no address of
        /// the width it asked about. Never answered for an `open`.
        unresolved = 2,
        _,
    };
};

// ---------------------------------------------------------------------------
// The inside half.
// ---------------------------------------------------------------------------

/// The router's own `Policy` and `Host`, over one channel and one nftables
/// session.
///
/// **One question on the wire, and two answers read from it.** `router.zig`
/// asks the policy about a name and then asks the host to resolve that same
/// name, in that order and never the other way round. The far side answers
/// both in one message, because the decision and the lookup are one act there:
/// a name the policy refuses is never looked up. So `askName` sends the
/// request and keeps the reply, and `resolve` reads the reply that was already
/// fetched for exactly that name and record type. A `resolve` for anything
/// else answers `NotResolved` rather than reaching the wire, which is the
/// safe direction and cannot happen from `router.zig` as it stands.
pub const Client = struct {
    /// The channel out. `-1` once it has gone, which turns every answer into a
    /// refusal.
    fd: i32,
    /// The kernel's allow sets, in the sandbox's own network namespace.
    /// **Opened before `CAP_NET_ADMIN` was narrowed to this process**, which
    /// is the one capability the router keeps.
    session: nftables.Session,
    /// The answer to the last `resolve` request, and which question it was
    /// about.
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

    /// May this name be resolved. **The one call that reaches the wire for a
    /// query**, and the reply it reads is what `resolveFn` below answers with.
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
            // **`unresolved` is a permission and not a refusal.** The name was
            // allowed and there is no address of that width, which
            // `router.zig` answers with no error and no answer. Reading it as
            // a refusal would tell a program the name is forbidden, which is a
            // different thing and a wrong one.
            .granted, .unresolved => .permit,
            .refused, _ => .refuse,
        };
    }

    /// May the relay carry bytes to this destination.
    ///
    /// **The name being there is the whole check here, and the exact decision
    /// is the far side's.** A destination the relay sees was let through by
    /// the kernel, which only holds addresses this resolver handed out. The
    /// name table narrows it to the name it was last handed out for, and that
    /// narrowing is a heuristic: see `router.NameTable`. So an address with no
    /// name is refused, which is the fail closed direction and is bounded by
    /// the table's own 64 entries, and an address with one is put to the far
    /// side by `openFn` below, which decides on the **address** and the port.
    fn connectFn(
        ptr: *anyopaque,
        name: ?[]const u8,
        dest: router.Destination,
    ) router.Policy.Verdict {
        _ = ptr;
        _ = dest;
        return if (name == null) .refuse else .permit;
    }

    /// The address for a name the policy has just permitted.
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

    /// Put the address in the kernel's allow set.
    ///
    /// **This one never leaves the sandbox.** It needs `CAP_NET_ADMIN` in this
    /// network namespace and nothing else, and the router holds exactly that
    /// one capability: see `driver.runRouter`. A request on the wire would be
    /// a round trip for a call that is already local.
    fn allowFn(
        ptr: *anyopaque,
        address: nftables.Address,
        timeout_ms: u64,
    ) router.Host.AllowError!void {
        const self: *Client = @ptrCast(@alignCast(ptr));
        self.session.allow(address, timeout_ms, null) catch return error.NotAllowed;
    }

    /// A descriptor to this destination, made outside this network namespace.
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
            // A descriptor with a refusal is a far end this file does not
            // understand. Close it rather than keep it.
            if (received) |handle| _ = linux.close(handle);
            return error.NotConnected;
        }
        return received orelse error.NotConnected;
    }
};

/// Send one request and read one reply. Null when the channel would not carry
/// it or answered something this file cannot read.
///
/// `carried` is filled with the first descriptor the reply brought, when the
/// caller asked for one. **The caller owns it**, including on the paths that
/// answer null, which is why it is written before every return.
fn exchange(fd: i32, request: *const Request, carried: ?*?i32) ?Reply {
    if (carried) |slot| slot.* = null;
    if (fd < 0) return null;

    // **`sendto` with `MSG_NOSIGNAL`, and never a plain `write`.** The far end
    // really can be gone: it closes the pair once the call has ended. The
    // router carries every other connection in the sandbox, so asking a
    // question must never be a way to be killed. The same reasoning
    // `netbroker.ask` gives, and the same measurement behind it.
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

    // `MSG_CMSG_CLOEXEC` so a descriptor that arrives is close-on-exec. The
    // router never runs another program, and the safe default is the one that
    // does not leak a connection into a process nobody meant to give it to.
    const rc = linux.recvmsg(fd, &message, linux.MSG.CMSG_CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return null;
    // Zero is the end of the stream: the far end closed.
    if (rc == 0) return null;

    const received = netbroker.firstReceivedFd(&message, &control);
    if (carried) |slot| slot.* = received else if (received) |handle| _ = linux.close(handle);

    if (rc != @sizeOf(Reply)) return null;
    if (reply.magic != reply_magic) return null;
    return reply;
}

/// The address a granted reply carries, or null when the reply names a width
/// the question did not ask about.
///
/// **A width the question did not ask about is refused and never converted.**
/// An `A` query answered with sixteen bytes is a far side this file does not
/// understand, and answering the query with the first four of them would put a
/// piece of an IPv6 address in the kernel's IPv4 allow set.
fn addressOf(family: Family, bytes: [16]u8, kind: router.RecordKind) ?nftables.Address {
    const wanted = kind.family();
    return switch (family) {
        .ipv4 => if (wanted == .ipv4) nftables.Address{ .ipv4 = bytes[0..4].* } else null,
        .ipv6 => if (wanted == .ipv6) nftables.Address{ .ipv6 = bytes } else null,
        _ => null,
    };
}

// ---------------------------------------------------------------------------
// The outside half.
// ---------------------------------------------------------------------------

/// What one `serveOne` did, for the caller that drives the loop. The same
/// three outcomes `netbroker.Outcome` has, for the same reasons.
pub const Outcome = enum { served, peer_gone, nothing };

/// Read one request, ask `seam`, and answer. **This is the parent side**,
/// called on the end of the pair that stayed outside the sandbox.
///
/// Call it only when the descriptor is readable. It does one `recvmsg` and one
/// `sendmsg` and never waits for anything else.
///
/// ## What is checked here, and what is not
///
/// The shape, and only the shape: exactly one `Request`, our magic, a kind
/// this file knows, a width this file knows, and for a `resolve` a name that
/// holds only bytes a host name can hold. **Which hosts may be reached is
/// `seam`'s question**, and this library must never grow a second answer to
/// it. The same division `netbroker.serveOne` draws.
pub fn serveOne(fd: i32, seam: NetRouter) Outcome {
    var request: Request = undefined;
    var iov = [1]std.posix.iovec{.{ .base = @ptrCast(&request), .len = @sizeOf(Request) }};
    var message = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        // No control buffer at all. **Nothing from inside the sandbox may hand
        // this process a descriptor**, and a receive with no room for control
        // data drops any that arrived rather than opening one here.
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
    // Exactly one `Request`, and neither less nor more. A long one is copied
    // to the buffer's size with the rest dropped, and `MSG_TRUNC` in the
    // answered flags is the only sign of it: see `netbroker.serveOne`.
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
            // The unused tail of a four byte address must be zero. It is
            // padding this file writes, so bytes in it are a message this
            // file did not send.
            if (want == .ipv4 and !std.mem.allEqual(u8, request.address[4..], 0)) return refuse(fd);
            return switch (seam.open(address, request.port)) {
                .refused => refuse(fd),
                .granted => |handle| {
                    // **The driver owns the descriptor from here**, whether
                    // the send worked or not: see `NetBroker.Grant`.
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

/// Send one reply with no descriptor.
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
    // `MSG_NOSIGNAL` so a peer that has already gone answers `EPIPE` here
    // instead of raising `SIGPIPE` at this whole process, which is the
    // harness. See `netbroker.refuse` for the measurement.
    const rc = linux.sendmsg(fd, &message, linux.MSG.NOSIGNAL);
    if (linux.errno(rc) != .SUCCESS) return .peer_gone;
    return .served;
}

/// Say yes, and send `handle` with the reply.
fn grant(fd: i32, handle: i32) Outcome {
    var reply = Reply{ .status = .granted };
    var iov = [1]std.posix.iovec_const{.{ .base = @ptrCast(&reply), .len = @sizeOf(Reply) }};

    var control: [control_bytes]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const header: *linux.cmsghdr = @ptrCast(@alignCast(&control));
    header.* = .{ .len = cmsg_len, .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS };
    // One descriptor, written at the aligned offset the kernel reads it from.
    // `@memcpy` and not a pointer store, because the payload of a control
    // message has the alignment of the buffer and not of an `i32`.
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

/// Make the pair one routed call uses. `[0]` stays outside the sandbox and
/// `[1]` crosses into it.
///
/// Both ends are close-on-exec. **Neither end is ever handed to the sandboxed
/// program**: the inside end belongs to the router, which is a process of
/// Chock's own and never calls `execve`. That is the whole difference from
/// `netbroker.makePair`, whose inside end is placed on descriptor 3 of the
/// caller's program.
pub fn makePair() error{SocketFailed}![2]i32 {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &fds);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    return fds;
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Linux only, the same rule the rest of this library follows: a test that
/// opens a socket makes a Linux system call, and this file compiles for Darwin
/// so that `Sandbox.zig` can name it there.
fn linuxOnly() !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
}

/// A seam that answers from a fixed table and records what it was asked.
const StubSeam = struct {
    /// What `host` resolves to, or null for a name this seam refuses.
    address: ?NetRouter.Address = null,
    /// Answered instead of an address when the name is permitted and there is
    /// nothing of that width.
    unresolved: bool = false,
    /// Whether an open is granted, and with what.
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
        // A duplicate, because `serveOne` closes what it is given.
        const rc = linux.dup(handle);
        if (linux.errno(rc) != .SUCCESS) return .refused;
        return .{ .granted = @intCast(rc) };
    }

    fn sawHost(self: *const StubSeam) []const u8 {
        return self.seen_host[0..self.seen_host_len];
    }
};

/// Put one reply where a `Client` will read it, with no descriptor.
fn queueReply(fd: i32, reply: Reply) !void {
    var held = reply;
    const rc = linux.sendto(fd, @ptrCast(&held), @sizeOf(Reply), linux.MSG.NOSIGNAL, null, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
}

/// Read one raw reply off a pair, for a test that drove `serveOne`.
fn takeReply(fd: i32) !Reply {
    var reply: Reply = undefined;
    const rc = linux.recvfrom(fd, @ptrCast(&reply), @sizeOf(Reply), 0, null, null);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expectEqual(@sizeOf(Reply), rc);
    return reply;
}

/// Send one raw request, for a test that is driving `serveOne` rather than a
/// `Client`.
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
    // **The size is the framing.** `serveOne` refuses a message that is not
    // exactly one `Request`, which is only a check at all while the size is a
    // number both ends agree on. A field added in the middle of either
    // structure without a reserved one beside it would put this process's own
    // memory in the gap and send it across the boundary.
    //
    // The sums are written out rather than taken from `@sizeOf`, so this fails
    // when the shape changes rather than following it.
    try testing.expectEqual(@as(usize, 4 + 1 + 1 + 1 + 1 + 2 + 2 + 16 + max_host_bytes + 1), @sizeOf(Request));
    try testing.expectEqual(@as(usize, 4 + 1 + 1 + 2 + 16), @sizeOf(Reply));

    // And the two magics are different, so a reply read as a request, or the
    // other way round, is refused rather than parsed.
    try testing.expect(request_magic != reply_magic);
}

test "a name the far side refuses is refused, and no address is ever asked for" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    // The answer is put where the client will read it. **Single threaded on
    // purpose**: the client's own send lands in the far end's queue, where
    // nothing reads it, and its read takes what is already waiting.
    try queueReply(pair[0], .{ .status = .refused });

    var client = Client{ .fd = pair[1], .session = .{ .fd = -1 } };
    try testing.expectEqual(router.Policy.Verdict.refuse, client.policy().askName("evil.test", .a));

    // **And the host is not asked afterwards.** The router asks the policy and
    // then asks the host, in that order, so a `resolve` that answered anyway
    // would hand out an address for a name that was refused.
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

    // **Read once and then gone.** A held answer that could be read twice
    // would let a second query for the same name skip the wire and reuse a
    // policy decision that was made about the first.
    //
    // Mutation check: delete `self.held = null;` in `resolveFn` and this line
    // answers with the address instead of an error.
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

    // A different name, and the same name at a different width. **The held
    // answer is about one question**, so neither of these may read it.
    try testing.expectError(error.NotResolved, client.host().resolve("other.anthropic.com", .a));
    try testing.expectError(error.NotResolved, client.host().resolve("api.anthropic.com", .aaaa));
}

test "an answer of the wrong width is refused rather than cut down to size" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    // Sixteen bytes, answered to a question about four. Reading the first four
    // of them would put a piece of an IPv6 address in the kernel's IPv4 allow
    // set, and the program would then be told to connect to it.
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

    // **`permit` and not `refuse`.** The router answers a permitted name with
    // no error and no answer, which is what a resolver says when it holds
    // nothing of that type. A refusal would tell the program the name is
    // forbidden, and a program told that stops asking for the other width.
    //
    // Mutation check: fold `.unresolved` into the refusing arm of `nameFn` and
    // the first line below fails.
    var client = Client{ .fd = pair[1], .session = .{ .fd = -1 } };
    try testing.expectEqual(router.Policy.Verdict.permit, client.policy().askName("api.anthropic.com", .a));
    try testing.expectError(error.NotResolved, client.host().resolve("api.anthropic.com", .a));
}

test "a channel that has gone refuses rather than waiting" {
    try linuxOnly();
    const pair = try makePair();
    _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    // **A refusal and never a wait.** The far end closes when the call has
    // ended, and a router left waiting for an answer would hold every
    // connection in the sandbox until the call's own deadline.
    var client = Client{ .fd = pair[1], .session = .{ .fd = -1 } };
    try testing.expectEqual(router.Policy.Verdict.refuse, client.policy().askName("api.anthropic.com", .a));
    try testing.expectError(
        error.NotConnected,
        client.host().open(.{ .address = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 443 }),
    );
}

test "a destination the name table does not know is refused by the router's own policy" {
    try linuxOnly();
    // The name is the whole check on this path. An address the relay sees was
    // let through by the kernel, which holds only addresses this resolver
    // handed out, and the name table narrows it to the name it was last handed
    // out for. An address with no name is the fail closed direction.
    //
    // Mutation check: answer `.permit` for a null name in `connectFn` and this
    // first line fails.
    var client = Client{ .fd = -1, .session = .{ .fd = -1 } };
    const dest = router.Destination{ .address = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 443 };
    try testing.expectEqual(router.Policy.Verdict.refuse, client.policy().askConnect(null, dest));
    try testing.expectEqual(router.Policy.Verdict.permit, client.policy().askConnect("api.anthropic.com", dest));
}

test "an address that will not go in the kernel's allow set is an error and not a silence" {
    try linuxOnly();
    // The session is closed, which is what a router whose netlink socket has
    // gone looks like. **The resolver must not answer after this**: an address
    // the guard chain will refuse is an answer that becomes a refused
    // connection later, and the truth is available now.
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
    // The bytes come from inside the sandbox. **Every one of these is refused
    // without the seam being asked anything**, which is what makes the shape
    // check a boundary and not a parser.
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

    // Every case that got through, collected and compared against nothing at
    // the end, so a failure names each one rather than only the first.
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
    // Shorter than one request. A long one is the other half and the kernel
    // reports it with `MSG_TRUNC`: see `serveOne`.
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

    // A real descriptor to hand across, and the plainest one there is.
    const give_rc = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(give_rc));
    const give: i32 = @intCast(give_rc);
    defer _ = linux.close(give);

    // **The answer is put in the client's queue by the real far side**, which
    // is what makes this a test of both halves rather than of a reply this
    // test wrote. The request that primes it is sent by hand, and the one the
    // client sends afterwards lands in a queue nothing reads.
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
    // A descriptor of this process's own, and a different number from the one
    // that was sent: the kernel installs a new one on the receiving side.
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
