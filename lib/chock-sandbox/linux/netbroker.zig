//! The exchange a `namespace.Network.filtered` process uses to reach a host:
//! one request out, one connected descriptor back.
//!
//! ## The whole idea in one paragraph
//!
//! A filtered process is in a network namespace with no route out, the same
//! one `none` gets. It cannot open a connection, and the seccomp filter
//! refuses `connect` besides. What it has is **one descriptor**, on a socket
//! pair whose other end is held on the far side of the sandbox boundary. It
//! writes a name and a port on that descriptor. The process on the other end
//! reads them, asks a policy, and, if the policy permits, connects and sends
//! the **connected descriptor** back over `SCM_RIGHTS`. So the connect happens
//! where the policy is, and the sandboxed process never holds an address it
//! chose.
//!
//! ## The child gets a descriptor, never a name
//!
//! Two rules follow from that, and each one is a test:
//!
//! * **A refusal carries no reason.** `Reply` holds a status and nothing else.
//!   A process that learned why it was refused would learn which hosts exist,
//!   which shape of rule refused it, and whether a name resolves, and it would
//!   learn all of that for free by asking. The reason stays on the far side,
//!   for the person reading the session.
//! * **A grant carries no address.** The reply holds a descriptor and no
//!   address at all, so a process cannot ask for one host, be handed another,
//!   and notice, and it also cannot use the answer to map what it is allowed
//!   to reach.
//!
//! ## One message, and no framing to get wrong
//!
//! The pair is `SOCK_SEQPACKET`, so the kernel keeps message boundaries: a
//! read gives one whole `Request` or nothing, and there is no partial line to
//! reassemble and no length prefix to trust. `lib/chock-broker/socket.zig`
//! reassembles lines because its peers are ordinary clients on a stream
//! socket; this pair has exactly two ends and both are ours, so it can use the
//! stronger socket type instead.
//!
//! Both structures are fixed size, which is what lets `serveOne` refuse a
//! message of the wrong length outright rather than parsing whatever arrived.
//!
//! ## Linux only, and why the file is here
//!
//! `SCM_RIGHTS` exists on Darwin too, but `Sandbox.spawn` refuses there, so
//! there is no filtered process to serve. The file sits under `linux/` with
//! the other mechanism modules because every line in it reaches the kernel
//! through `std.os.linux`.
//!
//! It compiles for Darwin, the same as the other four, and every test in it
//! that touches a socket answers `error.SkipZigTest` there rather than making
//! a Linux system call on a kernel that is not Linux. The two that are
//! arithmetic alone, on the shape of a name and on the size of the wire
//! structures, run on both. `cgroup.zig` and `rlimits.zig` already do this and
//! are why the Darwin suite reports skipped tests at all.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const iface = @import("../Sandbox.zig");
const NetBroker = iface.NetBroker;

/// The longest host name one request may carry. The same bound
/// `std.Io.net.HostName.max_len` uses, and the same one DNS itself has.
pub const max_host_bytes: usize = 255;

/// How many requests one sandboxed call may make before the far end stops
/// listening.
///
/// **A bound and not a target.** Nothing stops a sandboxed process asking in a
/// loop, and every ask costs the far end a policy read and, when the policy
/// permits, a name lookup and a connect. This is what makes that cost finite.
/// Past it the far end closes its own end of the pair, so a further `ask` reads
/// the end of the stream and answers `refused`, which is the same answer a
/// policy that permits nothing gives.
///
/// 256 is far above what any real client needs: an MCP server opens a handful
/// of connections, and one that wants hundreds should reuse them.
pub const max_requests: usize = 256;

/// The bytes "CHN1", so a message that is not one of ours is refused rather
/// than read as a request. There is no forgery to defend against on this pair,
/// which has exactly two ends and both are ours, and the witness is here for
/// the reason `SetupFailureRecord`'s own magic is: a read that ever landed on
/// something else must be easy to reject.
pub const request_magic: u32 = 0x314E4843;

/// The bytes "CHR1". See `request_magic`.
pub const reply_magic: u32 = 0x31524843;

/// What a filtered process asks for. Fixed size: see this file's own top
/// comment.
pub const Request = extern struct {
    magic: u32 = request_magic,
    port: u16,
    /// How many bytes of `host` are the name. Bounded by `serveOne` before it
    /// is used, because it arrives from a process that is assumed hostile.
    host_len: u8,
    /// Always zero. Present so the structure has no padding the compiler
    /// chooses, which would otherwise send this process's own memory across
    /// the boundary in the gap.
    reserved: u8 = 0,
    host: [max_host_bytes]u8,
};

/// What comes back. A status and nothing else: see this file's own top
/// comment.
pub const Reply = extern struct {
    magic: u32 = reply_magic,
    status: Status,
    /// Always zero, for the reason `Request.reserved` is.
    reserved: [3]u8 = @splat(0),

    pub const Status = enum(u8) {
        /// One descriptor rides with this reply, in `SCM_RIGHTS`.
        granted = 0,
        /// No descriptor, and no reason.
        refused = 1,
        _,
    };
};

/// The descriptor number a filtered program finds the socket on.
///
/// **A fixed number, and the same shape `Config.stdin_fd` already uses**: the
/// driver puts the descriptor there in the last step before `execve`, so a
/// program does not have to be told which number it landed on and Chock does
/// not have to write one into the environment. Three, because zero, one and
/// two are the standard streams and everything else the sandbox opened is
/// closed or close-on-exec by then.
pub const fd_number: i32 = 3;

/// What one `ask` came back with.
pub const Answer = union(enum) {
    /// A connected descriptor. **The caller owns it and must close it.**
    granted: i32,
    /// No connection. The far end says no more than this.
    refused,
};

pub const AskError = error{
    /// The name is longer than `max_host_bytes`, or empty.
    HostNameUnusable,
    /// The far end has gone, or would not answer. A caller reads this the same
    /// way it reads `refused`: there is no connection. It is a separate member
    /// so a program can say "the sandbox has no broker" rather than "the
    /// policy said no", which are different things to a person.
    BrokerGone,
    /// The far end answered something this file cannot read.
    BrokerProtocol,
};

/// Ask the far end for a connection to `host` on `port`. **This is the child
/// side**, called from inside the sandbox with `fd_number`.
///
/// Blocks until the far end answers. The far end answers from inside the same
/// loop that waits for this call to finish, so a request that is never
/// answered is a request whose whole call has ended, and this read then sees
/// the end of the stream.
///
/// Raw syscalls throughout, and no allocation: this is reached from inside a
/// sandbox by a program that may have neither an allocator nor a `std.Io`.
pub fn ask(fd: i32, host: []const u8, port: u16) AskError!Answer {
    if (host.len == 0 or host.len > max_host_bytes) return error.HostNameUnusable;

    var request = Request{ .port = port, .host_len = @intCast(host.len), .host = @splat(0) };
    @memcpy(request.host[0..host.len], host);

    // **`sendto` with `MSG_NOSIGNAL`, and never a plain `write`.** The far end
    // really can be gone: it closes the pair once `max_requests` is spent, and
    // again once the call has ended. A program inside the sandbox has
    // installed no handler for `SIGPIPE` and has no reason to, because
    // `resetSignalState` puts every signal back to its default before the
    // sandbox comes up, so asking for a connection must never be a way to be
    // killed.
    //
    // **The socket type is what carries that today, and the flag is what
    // keeps it.** Measured on 2026-08-23, on Linux 6.18.42, with `SIGPIPE` at
    // its default: a send on a `SOCK_STREAM` unix socket whose peer is closed
    // killed the process, and the same send on a `SOCK_SEQPACKET` one
    // answered `EPIPE` and raised nothing. This pair is `SOCK_SEQPACKET`, for
    // the framing reason this file's own top comment gives, so the flag
    // changes nothing right now and no test can show it doing anything. It is
    // here because the day somebody changes the socket type is the day the
    // property would be lost with nothing naming it.
    //
    // `null` as the address, because the pair is connected.
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

    // `MSG_CMSG_CLOEXEC` so a descriptor that arrives is close-on-exec. A
    // program that receives a connection and then runs another program is not
    // a shape this project has, and the safe default is the one that does not
    // leak a connection into a process nobody meant to give it to.
    const rc = linux.recvmsg(fd, &message, linux.MSG.CMSG_CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return error.BrokerGone;
    // Zero is the end of the stream: the far end closed. That is the answer a
    // caller gets once `max_requests` has been reached, and after the call it
    // belongs to has ended.
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
            // A descriptor with a refusal is a far end this file does not
            // understand. Close it rather than keep it.
            if (received) |handle| _ = linux.close(handle);
            return .refused;
        },
        _ => {
            if (received) |handle| _ = linux.close(handle);
            return error.BrokerProtocol;
        },
    }
}

/// What one `serveOne` did, for the caller that drives the loop.
pub const Outcome = enum {
    /// A request was read and answered, either way. **This is the one a
    /// caller counts against its own budget**: it is the only outcome a
    /// sandboxed process can make happen on purpose.
    served,
    /// The far end is gone, so the loop is over.
    peer_gone,
    /// Nothing was there after all, or a signal interrupted the read. Not a
    /// fault and not the end: look again. A caller must not count this,
    /// because a signal storm this process did not cause would otherwise
    /// spend a sandboxed call's whole budget.
    nothing,
};

/// Read one request, ask `broker`, and answer. **This is the parent side**,
/// called on the end of the pair that stayed outside the sandbox.
///
/// Call it only when the descriptor is readable. It does one `recvmsg` and one
/// `sendmsg` and never waits for anything else.
///
/// ## What is checked here, and what is not
///
/// The bytes come from a process that is assumed hostile, so this refuses a
/// message that is not exactly one `Request`, a magic that is not ours, a
/// length past the buffer, a port of zero, and a name that holds a byte a host
/// name cannot hold. **That is a shape check and not a policy**: which hosts
/// may be reached is `broker`'s question, and this library must never grow a
/// second answer to it. See `iface.NetBroker`.
///
/// The name check is here as well as in the implementation because this is
/// where the bytes cross the boundary. An implementation that forgot it would
/// otherwise be handed a name with a `\0`, a `/`, or a space in it, and would
/// splice it into whatever it builds a policy key out of.
pub fn serveOne(fd: i32, broker: NetBroker) Outcome {
    var request: Request = undefined;
    var iov = [1]std.posix.iovec{.{ .base = @ptrCast(&request), .len = @sizeOf(Request) }};
    var message = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        // No control buffer at all. **Nothing a sandboxed process sends may
        // hand this process a descriptor**, and a receive with no room for
        // control data drops any that arrived rather than opening one here.
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const rc = linux.recvmsg(fd, &message, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        // Nothing was there after all. Not a fault, and not the end.
        .AGAIN, .INTR => return .nothing,
        else => return .peer_gone,
    }
    if (rc == 0) return .peer_gone;
    // Exactly one `Request`, and neither less nor more. A short message is a
    // short read, which `rc` shows. **A long one is not**: the kernel copies
    // what fits, drops the rest, and reports the size of the buffer, so a
    // message of a thousand bytes would read here as a well formed request
    // with a thousand byte tail nobody saw. `MSG_TRUNC` in the answered flags
    // is the only sign of it.
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
            // **The driver owns the descriptor from here**, whether the send
            // works or not: see `NetBroker.Grant`. A copy left open in this
            // process would hold a connection nobody reads for the rest of the
            // session.
            defer _ = linux.close(handle);
            return grant(fd, handle);
        },
    }
}

/// True when every byte of `host` can be in a host name.
///
/// Letters, digits, hyphen and dot, with no empty label, no leading or
/// trailing dot, and no label past 63 bytes. **This is a shape rule, not a
/// policy**: it says the bytes are a name, and says nothing about which name.
///
/// A `*` is refused here even though a name is read as a value and never as a
/// pattern, because the policy language spells a class with one and a reader
/// should never have to work out whether that matters.
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

/// Say no, with no descriptor and no reason.
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
    // `MSG_NOSIGNAL` so a peer that has already gone answers `EPIPE` here
    // instead of raising `SIGPIPE` at this whole process, which is the
    // harness. The same reason `lib/chock-broker/socket.zig` gives for never
    // setting a disposition of its own: a library must not change the
    // behaviour of the program it is linked into. See `ask` for the
    // measurement that says this pair's own socket type already answers
    // `EPIPE` without a signal, and why the flag is here anyway.
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
    header.* = .{
        .len = cmsg_len,
        .level = linux.SOL.SOCKET,
        .type = linux.SCM.RIGHTS,
    };
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

/// `CMSG_ALIGN` from the kernel's own `linux/socket.h`, which rounds up to the
/// width of a pointer. Written out here because Zig's standard library
/// declares the structures and not the macros around them.
fn cmsgAlign(len: usize) usize {
    const width: usize = @sizeOf(usize);
    return (len + width - 1) & ~(width - 1);
}

/// Where the payload of the one control message starts. `CMSG_DATA`.
const cmsg_data_offset: usize = cmsgAlign(@sizeOf(linux.cmsghdr));

/// `CMSG_LEN` for one descriptor: the header, aligned, plus four bytes.
const cmsg_len: usize = cmsg_data_offset + @sizeOf(i32);

/// `CMSG_SPACE` for one descriptor, which is what a buffer must hold.
const control_bytes: usize = cmsg_data_offset + cmsgAlign(@sizeOf(i32));

/// The first descriptor a received message carries, or null when it carries
/// none.
///
/// **Every descriptor past the first is closed.** A far end that sent two is
/// one this file does not understand, and keeping the extra ones would leak a
/// descriptor per request into a process that has no idea it holds them.
fn firstReceivedFd(message: *const linux.msghdr, control: []align(@alignOf(linux.cmsghdr)) const u8) ?i32 {
    if (message.controllen < cmsg_len) return null;
    // The kernel says it had to drop control data. Whatever is in the buffer
    // is a fragment, so nothing in it may be read as a descriptor.
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

/// Make the pair one filtered call uses. `[0]` stays outside the sandbox and
/// `[1]` crosses into it.
///
/// Both ends are close-on-exec here. The driver clears the flag on the child's
/// end in the last step before `execve`, and nowhere earlier, so a sandbox that
/// failed to come up never hands a program a channel out. See
/// `linux/driver.zig`.
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

/// A broker that grants a descriptor for one host and port, and refuses
/// everything else. It records what it was asked, so a test reads what really
/// crossed rather than trusting that it did.
const StubBroker = struct {
    host: []const u8,
    port: u16,
    /// Handed out on a grant. The test owns the other end.
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
        // A duplicate, because `serveOne` closes what it is given.
        const rc = linux.dup(self.give);
        if (linux.errno(rc) != .SUCCESS) return .refused;
        return .{ .granted = @intCast(rc) };
    }

    fn sawHost(self: *const StubBroker) []const u8 {
        return self.seen_host[0..self.seen_host_len];
    }
};

/// One reply, read off the child's end the way `ask` reads it. A test uses
/// this rather than `ask` when it has to look at the reply itself and not only
/// at what `ask` made of it.
const ReadReply = struct {
    reply: Reply,
    /// The descriptor that rode with it, or null when none did. The test owns
    /// it.
    handle: ?i32,
    /// How many bytes arrived, so a test can pin that a whole reply did.
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

/// Write one request onto the child's end, as a real child would.
fn sendRequest(fd: i32, host: []const u8, port: u16) !void {
    var request = Request{ .port = port, .host_len = @intCast(host.len), .host = @splat(0) };
    @memcpy(request.host[0..host.len], host);
    const written = linux.write(fd, @ptrCast(&request), @sizeOf(Request));
    try testing.expectEqual(@as(usize, @sizeOf(Request)), written);
}

/// A pair of connected descriptors that stands in for a connection to a host.
/// **This is the only stand-in in this file, and it stands in for the network
/// and for nothing else**: as far as every line above is concerned a connected
/// descriptor is a connected descriptor.
fn upstreamPair() ![2]i32 {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds);
    if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    return fds;
}

test "a granted descriptor really carries the connection, and the reply names no address" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // The whole file in one exchange. What is pinned is that the descriptor
    // the far end connected is the descriptor the child ends up holding: the
    // test writes a token into the far end's own peer and the child reads it
    // back out of what arrived, so a `SCM_RIGHTS` send that carried the wrong
    // number, or none, cannot pass.
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    // Stands in for the connection to the host. One end is granted; the test
    // holds the other and speaks into it.
    const upstream = try upstreamPair();
    defer _ = linux.close(upstream[0]);
    defer _ = linux.close(upstream[1]);

    var stub = StubBroker{ .host = "api.example.com", .port = 443, .give = upstream[1] };

    // The request is written first and served second, because both ends are in
    // this one process: a socket pair holds what is written until it is read,
    // so no thread is needed to drive the whole exchange.
    try sendRequest(pair[1], "api.example.com", 443);
    try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.broker()));

    // The name and the port really crossed, unchanged.
    try testing.expectEqualStrings("api.example.com", stub.sawHost());
    try testing.expectEqual(@as(u16, 443), stub.seen_port);

    var got = try readReply(pair[1]);
    try testing.expectEqual(@as(usize, @sizeOf(Reply)), got.bytes);
    try testing.expectEqual(Reply.Status.granted, got.reply.status);
    const handle = got.handle orelse return error.NoDescriptorArrived;
    defer _ = linux.close(handle);

    // **The token is the test.** It proves the descriptor that arrived is the
    // one the far end connected, and not merely some descriptor: a send that
    // carried the wrong number would give a handle that reads nothing.
    const token = "the-far-end-connected-this";
    _ = linux.write(upstream[0], token, token.len);
    var buffer: [64]u8 = undefined;
    const read = linux.read(handle, &buffer, buffer.len);
    try testing.expectEqualStrings(token, buffer[0..read]);

    // And the reply says nothing about where it went. There is no address and
    // no name in it, and no room for one.
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, &got.reply.reserved);
}

test "a refusal carries no descriptor and no reason at all" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // The rule this file's own top comment states. A refusal that carried a
    // reason would tell a sandboxed process whether a name resolves and which
    // shape of rule turned it away, for the cost of asking.
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
    // No descriptor rode with it.
    try testing.expect(refused_by_policy.handle == null);

    // **The refusal for a host the broker turned away is byte for byte the
    // refusal for a name this library turned away itself.** So a sandboxed
    // process cannot tell "no such rule" from "not a name", cannot learn
    // whether a name resolves, and cannot map what it may reach by asking. A
    // reason field of any kind would destroy this, which is why the check is
    // on the bytes and not only on the status.
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
    // And the broker was asked about the first and never about the second, so
    // the two really did take different paths to the same bytes.
    try testing.expectEqual(@as(usize, 1), stub.asks);
}

test "a request that is not a request is refused, and the far end never asks about it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // Two facts, and the second is the one a reader could lose. **The broker
    // is never asked**, so a shape this library should have turned away can
    // never be spliced into a policy key. And every one of these answers
    // `served`, never `peer_gone`: a sandboxed process that writes rubbish must
    // not be able to take the channel away from every later request of the same
    // call.
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const upstream = try upstreamPair();
    defer _ = linux.close(upstream[0]);
    defer _ = linux.close(upstream[1]);
    var stub = StubBroker{ .host = "api.example.com", .port = 443, .give = upstream[1] };

    const bad = [_]Request{
        // Not our magic.
        .{ .magic = 0, .port = 443, .host_len = 15, .host = fill("api.example.com") },
        // Port zero names no service.
        .{ .port = 0, .host_len = 15, .host = fill("api.example.com") },
        // No name at all.
        .{ .port = 443, .host_len = 0, .host = @splat(0) },
        // A name that holds a byte no host name holds. Each of these would
        // otherwise reach whatever the far end builds a policy key out of.
        .{ .port = 443, .host_len = 15, .host = fill("api example.com") },
        .{ .port = 443, .host_len = 15, .host = fill("api/example.com") },
        .{ .port = 443, .host_len = 15, .host = fill("api*example.com") },
        .{ .port = 443, .host_len = 15, .host = fill("api\x00example.com") },
        // An empty label, a leading dot, and a trailing dot.
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
    // Every one of them was turned away here, and not by the broker.
    try testing.expectEqual(@as(usize, 0), stub.asks);

    // And a good request on the same pair is still served, so none of the above
    // left the channel broken.
    try sendRequest(pair[1], "api.example.com", 443);
    try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.broker()));
    try testing.expectEqual(@as(usize, 1), stub.asks);
    const good = try readReply(pair[1]);
    try testing.expectEqual(Reply.Status.granted, good.reply.status);
    if (good.handle) |handle| _ = linux.close(handle);
}

test "a message that is not one whole request is refused, whatever its length" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // `SOCK_SEQPACKET` keeps message boundaries, so a short write is one short
    // message and never a fragment of the next one. A length check that read a
    // short message as a request would read this process's own stack past the
    // bytes that arrived.
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

    // **And a message longer than one request, which is the one a length check
    // alone cannot see.** The kernel copies what fits, drops the rest, and
    // reports the size of the buffer, so this would otherwise read as a well
    // formed request with a tail nobody saw. `MSG_TRUNC` in the answered flags
    // is the only sign of it.
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
    // The pair carries a descriptor in one direction only. A far end that
    // accepted one would let a sandboxed process hand this process a handle on
    // something inside the sandbox, and this process is the one with the whole
    // filesystem and the credentials. `serveOne` passes no control buffer at
    // all, so the kernel drops whatever arrived.
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const upstream = try upstreamPair();
    defer _ = linux.close(upstream[0]);
    defer _ = linux.close(upstream[1]);
    var stub = StubBroker{ .host = "api.example.com", .port = 443, .give = upstream[1] };

    // How many descriptors this process holds before and after. A received one
    // would land on a free number and raise the count.
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

    // The request itself is still a good one, so it is served: what is refused
    // is only the descriptor that rode with it.
    try testing.expectEqual(Outcome.served, serveOne(pair[0], stub.broker()));
    try testing.expectEqual(@as(usize, 1), stub.asks);
    const got = try readReply(pair[1]);
    try testing.expectEqual(Reply.Status.granted, got.reply.status);
    if (got.handle) |handle| _ = linux.close(handle);

    try testing.expectEqual(before, openDescriptorCount());
}

/// How many descriptors this process holds, read out of `/proc/self/fd`. Used
/// by the test above to prove a descriptor that was sent across never landed
/// here.
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

/// A `Request.host` filled from a literal, zero padded. A test helper, so a
/// table of bad requests reads as a table.
fn fill(comptime text: []const u8) [max_host_bytes]u8 {
    var out: [max_host_bytes]u8 = @splat(0);
    @memcpy(out[0..text.len], text);
    return out;
}

test "a name that is a name is accepted, and every shape rule is a rule that refuses something" {
    // `hostBytesAreUsable` is a shape rule, so it has to let a real name
    // through. A rule that refused everything would pass every "hostile name
    // is refused" test above and make the whole channel useless, and nothing
    // else in this file would notice.
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
    // Both sides read these with `@sizeOf`, and `serveOne` refuses a message
    // that is not exactly one `Request`. A field added without a matching
    // change to the other side would otherwise turn every request into a
    // refusal, with nothing naming why.
    try testing.expectEqual(@as(usize, 264), @sizeOf(Request));
    try testing.expectEqual(@as(usize, 8), @sizeOf(Reply));
    // The control buffer is what the kernel writes one descriptor into. A
    // buffer shorter than `CMSG_SPACE` makes the send fail and the receive
    // report truncation, and neither says which number was wrong.
    try testing.expectEqual(@as(usize, 16), cmsg_data_offset);
    try testing.expectEqual(@as(usize, 20), cmsg_len);
    try testing.expectEqual(@as(usize, 24), control_bytes);
}

test "a far end that has gone answers BrokerGone rather than waiting" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // What a sandboxed process sees once `max_requests` has been spent, and
    // what it sees after its own call has ended. A read that waited instead
    // would hang the program inside the sandbox until the call's own deadline.
    const pair = try makePair();
    _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try testing.expectError(error.BrokerGone, ask(pair[1], "api.example.com", 443));
}

test "ask refuses a name it could not put in a request" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // Bounded on the child side too, so a program with a long name gets a
    // plain answer instead of a truncated name being sent to a policy.
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try testing.expectError(error.HostNameUnusable, ask(pair[1], "", 443));
    try testing.expectError(error.HostNameUnusable, ask(pair[1], "a" ** 256, 443));
}
