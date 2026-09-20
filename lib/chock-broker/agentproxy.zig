//! An ssh agent proxy: a socket in the sandbox joined to the person's agent.
//! The agent protocol does not say what a signature is for, so no proxy can
//! decide by the bytes. The socket lives only while one approved push runs.

const std = @import("std");
const chock_proto = @import("chock-proto");

const diagnostic = @import("diagnostic.zig");
const socket = @import("socket.zig");

pub const Diagnostic = diagnostic.Diagnostic;

pub const env_socket = "SSH_AUTH_SOCK";

pub const socket_name = "a";

pub const max_links: usize = 4;

pub const buffer_bytes: usize = 8192;

pub const max_passes: usize = 64;

/// `std.posix` has no `close` in Zig 0.16.
fn closeHandle(handle: std.posix.fd_t) void {
    _ = std.posix.system.close(handle);
}

const Link = struct {
    inside: ?std.posix.fd_t = null,
    host: ?std.posix.fd_t = null,

    fn free(self: Link) bool {
        return self.inside == null;
    }

    fn drop(self: *Link) void {
        if (self.inside) |handle| closeHandle(handle);
        if (self.host) |handle| closeHandle(handle);
        self.* = .{};
    }
};

pub const Proxy = struct {
    server: std.Io.net.Server,
    socket_path: []const u8,
    host_socket: []const u8,
    owner_uid: std.posix.uid_t,
    links: [max_links]Link = @splat(.{}),
    accepted: usize = 0,
    refused: usize = 0,
    strangers: usize = 0,
    to_agent: usize = 0,
    to_sandbox: usize = 0,
    diagnostic: ?Diagnostic = null,

    pub const OpenError = socket.Endpoint.OpenError;

    /// The parent directory goes into the sandbox under a Landlock rule that
    /// grants reading alone, so a sandboxed process cannot replace the socket.
    pub fn open(
        io: std.Io,
        path: []const u8,
        host_socket: []const u8,
        diag: ?*?Diagnostic,
    ) OpenError!Proxy {
        const address = try socket.addressFor(path, diag);

        const parent = std.fs.path.dirname(path) orelse return error.SocketUnavailable;
        try socket.ensureDir(io, parent, diag);

        std.Io.Dir.deleteFileAbsolute(io, path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => {
                _ = diagnostic.note(diag, .{ .socket_not_removed = .{ .path = path, .err = err } });
                return error.SocketUnavailable;
            },
        };

        const server = address.listen(io, .{ .kernel_backlog = 2 }) catch |err| {
            _ = diagnostic.note(diag, .{ .socket_not_opened = .{ .path = path, .err = err } });
            return error.SocketUnavailable;
        };

        return .{
            .server = server,
            .socket_path = path,
            .host_socket = host_socket,
            .owner_uid = std.posix.system.getuid(),
        };
    }

    /// The capability to sign lasts until this call, so run it on every path
    /// out of an approved push, including a failing one.
    pub fn close(self: *Proxy, io: std.Io) void {
        for (&self.links) |*link| link.drop();
        self.server.deinit(io);
        std.Io.Dir.deleteFileAbsolute(io, self.socket_path) catch {};
    }

    pub fn busy(self: *const Proxy) bool {
        for (self.links) |link| {
            if (!link.free()) return true;
        }
        return false;
    }

    pub fn step(self: *Proxy, io: std.Io, budget_ms: i32) void {
        var passes: usize = 0;
        while (passes < max_passes) : (passes += 1) {
            if (!self.onePass(io, if (passes == 0) budget_ms else 0)) return;
        }
    }

    fn onePass(self: *Proxy, io: std.Io, timeout_ms: i32) bool {
        var fds: [1 + 2 * max_links]std.posix.pollfd = undefined;
        var owners: [1 + 2 * max_links]usize = undefined;
        var count: usize = 0;

        fds[count] = .{ .fd = self.server.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
        owners[count] = max_links;
        count += 1;

        for (&self.links, 0..) |*link, index| {
            if (link.free()) continue;
            fds[count] = .{ .fd = link.inside.?, .events = std.posix.POLL.IN, .revents = 0 };
            owners[count] = index;
            count += 1;
            fds[count] = .{ .fd = link.host.?, .events = std.posix.POLL.IN, .revents = 0 };
            owners[count] = index;
            count += 1;
        }

        const ready = std.posix.poll(fds[0..count], timeout_ms) catch return false;
        if (ready == 0) return false;

        var moved = false;
        if (fds[0].revents & std.posix.POLL.IN != 0) {
            self.takeOne(io);
            moved = true;
        }

        // Walk backwards, so a dropped slot cannot move the entries still to read.
        var at = count;
        while (at > 1) {
            at -= 1;
            const index = owners[at];
            var link = &self.links[index];
            if (link.free()) continue;
            const revents = fds[at].revents;
            if (revents == 0) continue;
            const from_inside = fds[at].fd == link.inside;
            if (revents & std.posix.POLL.IN != 0) {
                if (self.pump(link, from_inside)) {
                    moved = true;
                    continue;
                }
                link.drop();
                moved = true;
                continue;
            }
            if (revents & (std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL) != 0) {
                link.drop();
                moved = true;
            }
        }
        return moved;
    }

    fn takeOne(self: *Proxy, io: std.Io) void {
        const stream = self.server.accept(io) catch return;
        const inside = stream.socket.handle;
        var joined = false;
        defer if (!joined) closeHandle(inside);

        const uid = socket.peerUid(inside) orelse {
            self.strangers += 1;
            return;
        };
        if (uid != self.owner_uid) {
            self.strangers += 1;
            _ = diagnostic.note(&self.diagnostic, .{ .client_uid_refused = .{
                .uid = uid,
                .owner_uid = self.owner_uid,
            } });
            return;
        }

        const slot = self.freeSlot() orelse {
            self.refused += 1;
            return;
        };

        const address = chock_proto.control.unixAddress(self.host_socket) catch {
            self.refused += 1;
            return;
        };
        const agent = address.connect(io) catch {
            self.refused += 1;
            return;
        };

        slot.* = .{ .inside = inside, .host = agent.socket.handle };
        self.accepted += 1;
        joined = true;
    }

    fn freeSlot(self: *Proxy) ?*Link {
        for (&self.links) |*link| {
            if (link.free()) return link;
        }
        return null;
    }

    fn pump(self: *Proxy, link: *Link, from_inside: bool) bool {
        const source = if (from_inside) link.inside.? else link.host.?;
        const target = if (from_inside) link.host.? else link.inside.?;

        var buffer: [buffer_bytes]u8 = undefined;
        const read = std.posix.read(source, &buffer) catch return false;
        if (read == 0) return false;
        if (!socket.writeAll(target, buffer[0..read])) return false;

        if (from_inside) self.to_agent += read else self.to_sandbox += read;
        return true;
    }
};

comptime {
    for (@typeInfo(Proxy).@"struct".fields) |field| {
        const name = field.name;
        if (std.mem.indexOf(u8, name, "key") != null or
            std.mem.indexOf(u8, name, "secret") != null or
            std.mem.indexOf(u8, name, "signature") != null)
        {
            @compileError("agentproxy.Proxy must hold no key: remove the field " ++ name ++
                ". The proxy moves bytes and the key stays on the host.");
        }
    }
}
