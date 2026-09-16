//! The ssh agent proxy: one socket inside the sandbox, the person's own agent
//! outside it, and bytes moved between them for as long as one approved push
//! runs.
//!
//! ## Why a proxy and not a key
//!
//! An ssh agent never hands out a private key. It signs what it is given and
//! answers with the signature. So a sandbox that can reach an agent has "can
//! sign with this key" and never "has this key", and the key stays on the host
//! where the person put it. Copying a key into a sandbox would give away the
//! key itself, which is the thing that must not happen.
//!
//! ## The sharp edge, said here rather than found later
//!
//! **A proxied agent can sign anything while it is reachable.** This is the
//! known risk of agent forwarding: whoever holds the socket can authenticate
//! to every host that accepts the key, not only the host the push goes to. The
//! agent protocol does not carry what a signature is for, so no proxy can tell
//! a push to your forge from a challenge for somebody else's server by reading
//! the bytes.
//!
//! **So the defence is scope and it is not inspection.** This proxy exists
//! only while an approved push runs, and `close` removes the socket after. The
//! capability lasts as long as the act a person approved, and no longer. It is
//! the same shape `chock-sandbox/linux/netbroker.zig` keeps, where the sandbox
//! gets one connected descriptor rather than a route.
//!
//! **Nothing here parses the agent protocol, on purpose.** A reader that
//! understood the messages would invite a rule written on what it read, and
//! every such rule would be false: the protocol cannot say what a signature is
//! for. Bytes go one way and bytes come back. That is the whole of it, and it
//! is honest about what it can and cannot decide.
//!
//! ## What the sandbox may do to this socket
//!
//! Connect to it, and nothing else. The directory holding it is bound into the
//! sandbox under a Landlock rule that grants reading alone, which is measured:
//! a sandboxed process that tries to create a file beside the socket, or to
//! unlink the socket, is refused with `EACCES`. So the socket cannot be
//! replaced by one the agent wrote.
//!
//! ## Linux and Darwin
//!
//! Everything here is a unix socket and a `poll`, so it compiles and runs on
//! both. `Sandbox.spawn` refuses on Darwin, so no sandboxed program reaches it
//! there yet, and the tests below run on either.

const std = @import("std");
const chock_proto = @import("chock-proto");

const diagnostic = @import("diagnostic.zig");
const socket = @import("socket.zig");

/// Why the proxy could not serve, past what a count says. One type for the
/// whole module: see `chock-broker/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;

/// The variable that names the agent a client should use. **It holds a path
/// and never a key**, which is why a variable may carry it at all.
pub const env_socket = "SSH_AUTH_SOCK";

/// The proxy socket's own name inside the per call credential directory,
/// beside the askpass socket. One character, because a unix socket path is
/// bounded at `socket.max_socket_path` and the session directory has already
/// spent most of it.
pub const socket_name = "a";

/// How many agent connections one approved push may hold at once.
///
/// **A bound and not a target.** `ssh` opens one connection to its agent for
/// an ordinary push. Four leaves room for a push that contacts more than one
/// host, and it keeps the cost of a program that opens sockets in a loop
/// finite.
pub const max_links: usize = 4;

/// How much is moved in one direction in one read. An agent message is a few
/// hundred bytes, and a signature is smaller than this.
pub const buffer_bytes: usize = 8192;

/// How many times `step` looks again after it moved something.
///
/// **This is what lets one whole exchange finish inside one look.** A caller
/// drives this from `chock_core.idle`, which gives it the gap between two
/// slices of a wait, so a proxy that moved one message per look would add a
/// slice of delay to every message of a handshake. Past this bound `step`
/// returns and the next look carries on, so a peer that writes without end
/// cannot hold the caller's thread.
pub const max_passes: usize = 64;

/// Give a descriptor back. `std.posix` has no `close` in Zig 0.16, and this
/// module reaches the kernel the way `chock-broker/socket.zig` does for its own
/// `write`: through `std.posix.system`.
fn closeHandle(handle: std.posix.fd_t) void {
    _ = std.posix.system.close(handle);
}

/// One connection: the program inside the sandbox, and the agent outside it.
const Link = struct {
    /// The sandboxed peer, or null for a slot nothing is using.
    inside: ?std.posix.fd_t = null,
    /// The person's own agent.
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

/// The listening end of one approved push's agent proxy.
///
/// **It holds no key and it cannot hold one.** There is no field here a key
/// could sit in, and the comptime block at the end of this file fails the
/// build if one appears. What this holds is two descriptors per connection and
/// the counts a caller reports.
pub const Proxy = struct {
    server: std.Io.net.Server,
    /// Borrowed from the caller, for `close` to remove.
    socket_path: []const u8,
    /// The person's own agent, as `SSH_AUTH_SOCK` named it on the host.
    /// Borrowed from the caller.
    host_socket: []const u8,
    /// The uid this process runs as. Any other peer is closed at once.
    owner_uid: std.posix.uid_t,
    links: [max_links]Link = @splat(.{}),
    /// How many connections were accepted and joined to the agent.
    accepted: usize = 0,
    /// How many peers were turned away. Counted apart from `accepted`, so a
    /// caller can say a program tried to sign and got nothing, which is not
    /// the same fact as nothing trying.
    refused: usize = 0,
    /// How many peers were closed because they were somebody else.
    strangers: usize = 0,
    /// Bytes moved from the sandbox to the agent.
    to_agent: usize = 0,
    /// Bytes moved from the agent to the sandbox.
    to_sandbox: usize = 0,
    /// Why the first peer was turned away, for the caller to report.
    diagnostic: ?Diagnostic = null,

    pub const OpenError = socket.Endpoint.OpenError;

    /// Make the directory, remove any socket a crash left there, and listen.
    /// `path` is the socket itself, and its parent is made `0o700` by
    /// `socket.ensureDir`, which is the gate.
    ///
    /// `host_socket` is the path the person's own `SSH_AUTH_SOCK` holds. It is
    /// not connected here: a push that never asks the agent anything must not
    /// cost a connection to it, and an agent that has gone away must fail the
    /// one peer that asks rather than the whole push.
    pub fn open(
        io: std.Io,
        path: []const u8,
        host_socket: []const u8,
        diag: ?*?Diagnostic,
    ) OpenError!Proxy {
        const address = try socket.addressFor(path, diag);

        const parent = std.fs.path.dirname(path) orelse return error.SocketUnavailable;
        try socket.ensureDir(io, parent, diag);

        // A file left by a process that is gone would wedge this path for
        // ever, and the directory it sits in is one this user alone can enter,
        // so nothing else could have put it there.
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

    /// Stop listening, drop every connection, and remove the socket file.
    ///
    /// **This is the whole of the security property.** The capability to sign
    /// lasts until this call and not one moment longer, so a caller runs it on
    /// every path out of an approved push, including a failing one.
    pub fn close(self: *Proxy, io: std.Io) void {
        for (&self.links) |*link| link.drop();
        self.server.deinit(io);
        // A directory that has already gone is not a fault worth reporting:
        // the file is scratch, and the next `open` removes a stale one anyway.
        std.Io.Dir.deleteFileAbsolute(io, self.socket_path) catch {};
    }

    /// True while any connection is still joined. For a caller that reports
    /// what one push did.
    pub fn busy(self: *const Proxy) bool {
        for (self.links) |link| {
            if (!link.free()) return true;
        }
        return false;
    }

    /// One look. Takes whatever peers are waiting, moves whatever bytes are
    /// ready in either direction, and drops a connection either end closed.
    ///
    /// **It cannot fail and it says nothing.** A caller drives this from
    /// `chock_core.idle`, whose own contract is that a look behaves the same
    /// whether or not anybody is watching, so there is nothing here to branch
    /// on. What went wrong is in the counts and in `diagnostic`.
    pub fn step(self: *Proxy, io: std.Io, budget_ms: i32) void {
        var passes: usize = 0;
        while (passes < max_passes) : (passes += 1) {
            if (!self.onePass(io, if (passes == 0) budget_ms else 0)) return;
        }
    }

    /// One poll and whatever it found. True when something happened, so `step`
    /// knows to look again.
    fn onePass(self: *Proxy, io: std.Io, timeout_ms: i32) bool {
        // The listener first, then two entries for every joined connection.
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

        // **Backwards, so a dropped slot cannot shift the entries still to
        // read.** Each slot has two entries side by side, and `drop` frees
        // the slot rather than the array, so an index read after a drop is
        // still the index it was.
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
            // The end of the stream, or a broken connection. Either way the
            // exchange is over.
            if (revents & (std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL) != 0) {
                link.drop();
                moved = true;
            }
        }
        return moved;
    }

    /// Accept one waiting peer and join it to the agent. Everything that goes
    /// wrong closes the peer, because a peer that is not joined to an agent
    /// has nothing to say to.
    fn takeOne(self: *Proxy, io: std.Io) void {
        const stream = self.server.accept(io) catch return;
        const inside = stream.socket.handle;
        var joined = false;
        defer if (!joined) closeHandle(inside);

        const uid = socket.peerUid(inside) orelse {
            // The kernel would not say who this is, so it cannot be given the
            // agent.
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
            // The person's agent is not running, or it has gone away. The push
            // then fails at the key, which `ssh` says plainly on its own
            // standard error.
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

    /// Move one read's worth in one direction. False when the connection is
    /// over, which is the end of the stream or any fault at all.
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

// A proxy holds descriptors and counts. **It holds no key and no signature**,
// which is what makes "the key stays on the host" a fact about the type and
// not a promise in a comment. This fails the build if a field appears that
// could hold one.
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
