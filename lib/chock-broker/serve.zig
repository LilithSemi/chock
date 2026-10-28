//! The host end of the inbound path. A project publishes a port, this listens
//! on it, and every connection it accepts goes to the helper that carries it to
//! the server the agent runs. The mechanism inside the sandbox is in
//! `lib/chock-net/linux/servelink.zig`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

const chock_net = @import("chock-net");
const chock_policy = @import("chock-policy");

/// The name a port is answered under lives with the reader that parses it back,
/// in `chock-policy`, so this module names it there rather than spelling it
/// again.
pub const actionInto = chock_policy.table.serveActionInto;

/// A session can publish this many ports. A project that needs more is running
/// more than one service out of one agent.
pub const max_ports: usize = 8;

/// Below this a port needs privilege the host does not give a user process, so
/// a project that names one is told rather than left with a bind that fails.
pub const min_port: u16 = 1024;

/// Loopback and nothing else: a published port is for the person at this
/// machine, and a sandbox is not a way to put a service on a network.
pub const host_address: u32 = 0x7f000001;

pub const Fault = union(enum) {
    port_too_low: u16,
    too_many_ports,
    address_taken: u16,
    not_opened: linux.E,
};

pub const Published = struct {
    port: u16,
    fd: posix.fd_t = -1,
};

/// A Linux mechanism throughout: an epoll fd joins palisade's own poll, and
/// what carries a connection in is a helper in a network namespace.
pub const supported = builtin.os.tag == .linux;

pub const Error = error{ EpollFailed, NoPlatform };

pub const Opened = union(enum) {
    opened,
    /// The port was already published, so nothing changed.
    already,
    refused: Fault,
};

pub const Serve = struct {
    epoll_fd: posix.fd_t = -1,
    ports: [max_ports]Published = @splat(.{ .port = 0 }),
    count: usize = 0,
    accepted: u64 = 0,
    /// A background tool call takes connections on its own thread while the
    /// turn that owns the session can still publish a port.
    lock: std.Io.Mutex = .init,
    io: std.Io = undefined,

    pub fn init(self: *Serve, io: std.Io) Error!void {
        if (!supported) return error.NoPlatform;
        self.io = io;
        const made = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        if (linux.errno(made) != .SUCCESS) return error.EpollFailed;
        self.epoll_fd = @intCast(made);
    }

    /// Runs on the thread that owns the session, after every background call
    /// that could hold a listener has ended, so it takes no lock.
    pub fn deinit(self: *Serve) void {
        for (self.ports[0..self.count]) |one| {
            if (one.fd >= 0) _ = linux.close(one.fd);
        }
        self.count = 0;
        if (self.epoll_fd >= 0) _ = linux.close(self.epoll_fd);
        self.epoll_fd = -1;
    }

    pub fn holds(self: *Serve, port: u16) bool {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        return self.heldUnlocked(port);
    }

    fn heldUnlocked(self: *const Serve, port: u16) bool {
        for (self.ports[0..self.count]) |one| {
            if (one.port == port) return true;
        }
        return false;
    }

    pub fn publish(self: *Serve, port: u16) Opened {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        if (self.heldUnlocked(port)) return .already;
        if (port < min_port) return .{ .refused = .{ .port_too_low = port } };
        if (self.count == max_ports) return .{ .refused = .too_many_ports };

        const made = linux.socket(
            linux.AF.INET,
            linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC,
            0,
        );
        if (linux.errno(made) != .SUCCESS) {
            return .{ .refused = .{ .not_opened = linux.errno(made) } };
        }
        const fd: posix.fd_t = @intCast(made);

        var one: u32 = 1;
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&one), @sizeOf(u32));

        var address = linux.sockaddr.in{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, host_address),
            .zero = @splat(0),
        };
        const bound = linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in));
        if (linux.errno(bound) != .SUCCESS) {
            const why = linux.errno(bound);
            _ = linux.close(fd);
            return .{ .refused = if (why == .ADDRINUSE)
                .{ .address_taken = port }
            else
                .{ .not_opened = why } };
        }
        if (linux.errno(linux.listen(fd, 64)) != .SUCCESS) {
            const why = linux.errno(linux.listen(fd, 64));
            _ = linux.close(fd);
            return .{ .refused = .{ .not_opened = why } };
        }

        var wanted = linux.epoll_event{
            .events = linux.EPOLL.IN,
            .data = .{ .fd = fd },
        };
        if (linux.errno(linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, fd, &wanted)) != .SUCCESS) {
            const why = linux.errno(linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, fd, &wanted));
            _ = linux.close(fd);
            return .{ .refused = .{ .not_opened = why } };
        }

        self.ports[self.count] = .{ .port = port, .fd = fd };
        self.count += 1;
        return .opened;
    }

    /// Closes the listener. What is already relayed stays up: this stops new
    /// connections, it does not reach into one that is running.
    pub fn withdraw(self: *Serve, port: u16) bool {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.ports[0..self.count], 0..) |one, index| {
            if (one.port != port) continue;
            if (one.fd >= 0) {
                _ = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, one.fd, null);
                _ = linux.close(one.fd);
            }
            self.ports[index] = self.ports[self.count - 1];
            self.ports[self.count - 1] = .{ .port = 0 };
            self.count -= 1;
            return true;
        }
        return false;
    }

    pub fn source(self: *Serve) chock_net.links.ServeSource {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_net.links.ServeSource.VTable{ .wakeup = wakeupFn, .next = nextFn };

    fn wakeupFn(ptr: *anyopaque) i32 {
        const self: *Serve = @ptrCast(@alignCast(ptr));
        return self.epoll_fd;
    }

    /// One connection, or null when no published port has one waiting. The
    /// epoll watch is level triggered, so a listener with more than one waiting
    /// is still ready on the next call.
    fn nextFn(ptr: *anyopaque) ?chock_net.links.ServeSource.Inbound {
        const self: *Serve = @ptrCast(@alignCast(ptr));
        return self.take();
    }

    pub fn take(self: *Serve) ?chock_net.links.ServeSource.Inbound {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        if (self.count == 0) return null;

        var ready: [1]linux.epoll_event = undefined;
        const seen = linux.epoll_wait(self.epoll_fd, &ready, ready.len, 0);
        if (linux.errno(seen) != .SUCCESS or seen == 0) return null;

        const listener = ready[0].data.fd;
        const port = self.portOf(listener) orelse return null;

        const taken = linux.accept4(listener, null, null, linux.SOCK.CLOEXEC);
        if (linux.errno(taken) != .SUCCESS) return null;
        self.accepted += 1;
        return .{ .port = port, .handle = @intCast(taken) };
    }

    fn portOf(self: *const Serve, fd: posix.fd_t) ?u16 {
        for (self.ports[0..self.count]) |one| {
            if (one.fd == fd) return one.port;
        }
        return null;
    }
};

pub fn explain(buffer: []u8, fault: Fault) error{NoSpaceLeft}![]const u8 {
    return switch (fault) {
        .port_too_low => |port| std.fmt.bufPrint(
            buffer,
            "port {d} is below {d}, which a program needs privilege this session does not have " ++
                "to listen on, so it was not published. Serve on a higher port.",
            .{ port, min_port },
        ),
        .too_many_ports => std.fmt.bufPrint(
            buffer,
            "this session already publishes {d} ports, which is all it can, so nothing was " ++
                "published.",
            .{max_ports},
        ),
        .address_taken => |port| std.fmt.bufPrint(
            buffer,
            "something on this machine is already listening on 127.0.0.1:{d}, so it was not " ++
                "published. Stop that program, or serve on another port.",
            .{port},
        ),
        .not_opened => |why| std.fmt.bufPrint(
            buffer,
            "the listener could not be opened ({t}), so nothing was published.",
            .{why},
        ),
    };
}

const testing = std.testing;

fn connectToLoopback(port: u16) !posix.fd_t {
    const made = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(made) != .SUCCESS) return error.SocketFailed;
    const fd: posix.fd_t = @intCast(made);
    var address = linux.sockaddr.in{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, host_address),
        .zero = @splat(0),
    };
    if (linux.errno(linux.connect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        _ = linux.close(fd);
        return error.NotConnected;
    }
    return fd;
}

/// A port nothing is on. Taken by binding one and letting it go, which is what
/// every test here needs and what no test may hard code.
fn freePort() !u16 {
    var one = Serve{};
    try one.init(testing.io);
    defer one.deinit();

    const made = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(made) != .SUCCESS) return error.SocketFailed;
    const fd: posix.fd_t = @intCast(made);
    defer _ = linux.close(fd);

    var address = linux.sockaddr.in{
        .family = linux.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, host_address),
        .zero = @splat(0),
    };
    if (linux.errno(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        return error.BindFailed;
    }
    var named: linux.sockaddr.in = undefined;
    var length: posix.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.errno(linux.getsockname(fd, @ptrCast(&named), &length)) != .SUCCESS) {
        return error.NameFailed;
    }
    return std.mem.bigToNative(u16, named.port);
}

test "a published port accepts on loopback, and each connection comes out with its port" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var serve = Serve{};
    try serve.init(testing.io);
    defer serve.deinit();

    const port = try freePort();
    try testing.expectEqual(Opened.opened, serve.publish(port));
    try testing.expect(serve.holds(port));
    try testing.expectEqual(Opened.already, serve.publish(port));

    try testing.expectEqual(@as(?chock_net.links.ServeSource.Inbound, null), serve.take());

    const first = try connectToLoopback(port);
    defer _ = linux.close(first);
    const second = try connectToLoopback(port);
    defer _ = linux.close(second);

    const one = serve.take() orelse return error.NothingAccepted;
    defer _ = linux.close(one.handle);
    try testing.expectEqual(port, one.port);

    // Level triggered: the second waiting connection is still there to take.
    const other = serve.take() orelse return error.SecondConnectionLost;
    defer _ = linux.close(other.handle);
    try testing.expectEqual(port, other.port);
    try testing.expectEqual(@as(u64, 2), serve.accepted);
    try testing.expectEqual(@as(?chock_net.links.ServeSource.Inbound, null), serve.take());
}

test "the seam a sandbox is given is the same listener set" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var serve = Serve{};
    try serve.init(testing.io);
    defer serve.deinit();

    const port = try freePort();
    try testing.expectEqual(Opened.opened, serve.publish(port));

    const seam = serve.source();
    try testing.expectEqual(serve.epoll_fd, seam.vtable.wakeup(seam.ptr));

    const client = try connectToLoopback(port);
    defer _ = linux.close(client);
    const taken = seam.vtable.next(seam.ptr) orelse return error.NothingAccepted;
    defer _ = linux.close(taken.handle);
    try testing.expectEqual(port, taken.port);
}

test "a withdrawn port stops accepting, and a port taken on the host is refused by name" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var serve = Serve{};
    try serve.init(testing.io);
    defer serve.deinit();

    const port = try freePort();
    try testing.expectEqual(Opened.opened, serve.publish(port));
    try testing.expect(serve.withdraw(port));
    try testing.expect(!serve.holds(port));
    try testing.expect(!serve.withdraw(port));
    try testing.expectError(error.NotConnected, connectToLoopback(port));

    // Something else holds it, which is the everyday case of a dev server the
    // person started themselves.
    var other = Serve{};
    try other.init(testing.io);
    defer other.deinit();
    const held = try freePort();
    try testing.expectEqual(Opened.opened, other.publish(held));

    const refused = serve.publish(held);
    try testing.expectEqual(held, refused.refused.address_taken);

    var text: [256]u8 = undefined;
    const said = try explain(&text, refused.refused);
    try testing.expect(std.mem.indexOf(u8, said, "already listening") != null);
}

test "a privileged port and one port too many are refused before anything is opened" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var serve = Serve{};
    try serve.init(testing.io);
    defer serve.deinit();

    const low = serve.publish(80);
    try testing.expectEqual(@as(u16, 80), low.refused.port_too_low);
    try testing.expectEqual(@as(usize, 0), serve.count);

    var ports: [max_ports]u16 = undefined;
    for (&ports) |*slot| {
        slot.* = try freePort();
        try testing.expectEqual(Opened.opened, serve.publish(slot.*));
    }
    const one_more = try freePort();
    try testing.expect(serve.publish(one_more).refused == .too_many_ports);
    try testing.expectEqual(max_ports, serve.count);

    var text: [256]u8 = undefined;
    const said = try explain(&text, .too_many_ports);
    try testing.expect(std.mem.indexOf(u8, said, "8") != null);
}

test "the action name a port is gated by is the one the policy reads back" {
    var buffer: [chock_policy.table.max_serve_action_bytes]u8 = undefined;
    try testing.expectEqualStrings("net.serve.3000", actionInto(&buffer, 3000).?);
    try testing.expectEqual(@as(u16, 8080), chock_policy.table.portNamedBy(actionInto(&buffer, 8080).?).?);
}
