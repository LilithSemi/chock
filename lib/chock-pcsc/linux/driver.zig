//! The Linux transport for `chock-pcsc`: `pcscd`'s own unix socket, spoken
//! directly, in pure Zig.
//!
//! The daemon's protocol is private to `pcsc-lite`, it is stated in no
//! document, and it opens with a version handshake the daemon refuses on a
//! mismatch. This file speaks it anyway, and the thing that makes that honest
//! rather than reckless is that **there is a real `pcscd` on the machine it was
//! written against**, so the framing is measured and not read. `wire.zig` holds
//! the layouts and a byte for byte capture of a real `libpcsclite` handshake;
//! `test/pcsc/pcscd.zig` drives this file against a running daemon.
//!
//! ## What this proves, and what it does not
//!
//! **Proven against a real daemon:** the framing, the version handshake, the
//! refusal when the versions differ, a context, the reader list, and the close.
//!
//! **Proven against a real card**, on 2026-08-24, with a YubiKey in the reader
//! and `pcscd` 4:5 answering: `connectFn` gave a handle on protocol T=1, and
//! `transmitFn` carried a `SELECT` of the PIV application and a `GET DATA`
//! there and back. The two write framing of a transmit is measured now and no
//! longer only read.
//!
//! **Still not proven:** a transmit long enough to need the `61 XX` loop, and a
//! signature. That card holds no key in a PIV slot, so every certificate object
//! answered `6a 82` in two bytes and nothing longer than that has crossed.
//!
//! ## Four answers and not one
//!
//! A daemon that is not installed, a socket nothing is listening on, a daemon
//! that refuses this client, and a daemon with no reader attached are four
//! different facts, and a person acts differently on each. `Failure` keeps them
//! apart and `chock doctor` prints the one that was measured. The fourth is
//! not hypothetical: on the box this was written for, `pcscd` runs with polkit
//! and **closes the connection with no answer at all** when the client's login
//! session is not active. See `Failure.not_authorized`.

const std = @import("std");
const iface = @import("../../chock-pcsc.zig");

pub const wire = @import("wire.zig");

/// Where `pcscd` listens, as `PCSCLITE_IPC_DIR` is set on every distribution
/// that ships it. The daemon compiles this in and takes no option for it, so a
/// client that looked anywhere else would find nothing.
pub const default_socket_path = "/run/pcscd/pcscd.comm";

/// How long one message may take before this gives up.
///
/// **A bound and not a measurement.** The daemon does real work between a
/// request and its answer, including powering a card, and a client with no
/// bound at all hangs a `chock doctor` row for ever on a daemon that has
/// wedged. Five seconds is far past every control message and is raised
/// through the field, not by editing this.
pub const default_timeout_ms: i32 = 5_000;

/// Why a call did not do what was asked, in enough detail for a person to act.
///
/// **An error code cannot carry two version numbers**, and a refusal that says
/// only "mismatch" costs somebody the hour it takes to find both. So the driver
/// keeps the fact beside the error and `chock doctor` prints it.
///
/// **Every string here is borrowed and nothing is allocated.** A path is the
/// driver's own `socket_path`, and the rest are literals, so a `Failure` lasts
/// exactly as long as the driver it came from.
pub const Failure = union(enum) {
    /// Nothing is at the socket path. The daemon is not installed, or its
    /// socket unit has never been started.
    no_socket: []const u8,
    /// Something is at the path and it is not a socket.
    not_a_socket: []const u8,
    /// The path is a socket and the connection did not open. The daemon is not
    /// listening: a socket file left behind by one that died looks exactly like
    /// this.
    not_listening: []const u8,
    /// The daemon accepted the connection and closed it without answering.
    ///
    /// **This is what its polkit check does when it refuses**, and it says
    /// nothing on the wire about why: `pcscd` closes the socket from inside
    /// `IsClientAuthorized` before it reads one byte. `libpcsclite` reads the
    /// same reset and calls it `SCARD_W_SECURITY_VIOLATION`, which is where the
    /// word in the sentence below comes from.
    ///
    /// **Set from two places, both the same fact.** A client discovers a peer
    /// that closed before reading either on its own read of the handshake
    /// reply (`readHandshake`'s `PeerClosed`) or on its own write of the
    /// handshake offer, if the close won the race first (`sendHandshake`'s
    /// `BrokenPipe`, an `EPIPE`). Which one fires is scheduling, not meaning:
    /// both name the same daemon behaviour, so both set this same variant.
    not_authorized,
    /// The daemon speaks a protocol this build does not.
    version_mismatch: struct { offered: wire.Version, daemon: wire.Version },
    /// The daemon answered a request with a code.
    refused: struct { what: []const u8, rv: wire.Return },
    /// The connection failed while a message was in flight.
    transport: []const u8,

    pub fn format(self: Failure, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .no_socket => |path| try writer.print(
                "there is no pcscd socket at {s}, so no daemon is running here",
                .{path},
            ),
            .not_a_socket => |path| try writer.print(
                "{s} is not a socket, so the path a pcscd client uses is taken by something else",
                .{path},
            ),
            .not_listening => |path| try writer.print(
                "the socket {s} is there and nothing is listening on it, which is what a daemon that died leaves behind",
                .{path},
            ),
            .not_authorized => try writer.writeAll(
                "pcscd accepted the connection and closed it without answering, which is how it " ++
                    "refuses a client its polkit rules do not allow. Its own action is " ++
                    "org.debian.pcsc-lite.access_pcsc, which by default allows an active login " ++
                    "session only",
            ),
            .version_mismatch => |both| try writer.print(
                "this build speaks pcscd protocol {f} and the daemon speaks {f}",
                .{ both.offered, both.daemon },
            ),
            .refused => |it| try writer.print(
                "pcscd refused the {s} with code 0x{x:0>8}",
                .{ it.what, @intFromEnum(it.rv) },
            ),
            .transport => |what| try writer.print(
                "the connection to pcscd failed while the {s} was in flight",
                .{what},
            ),
        }
    }
};

/// One connection to `pcscd`, and the five calls `chock-pcsc` asks a transport
/// for.
///
/// **The caller owns it and it must not move**, because `Pcsc.ptr` points at
/// it. `deinit` releases the context and closes the socket; a driver dropped
/// without it leaks a file descriptor and leaves the daemon holding a context
/// until the socket is reaped.
pub const Driver = struct {
    io: std.Io,
    /// Where to look for the daemon. A field rather than a constant so a test
    /// can drive a daemon of its own: see `test/pcsc/pcscd.zig`.
    socket_path: []const u8 = default_socket_path,
    /// What this build offers in the handshake. A field for the same reason,
    /// and it is the one knob that makes the mismatch path reachable against a
    /// daemon that is not itself mismatched.
    offered: wire.Version = wire.protocol_version,
    timeout_ms: i32 = default_timeout_ms,

    /// The open connection, or null before `establish` and after `deinit`.
    stream: ?std.Io.net.Stream = null,
    /// What the daemon answered in the handshake, or null before one.
    daemon_version: ?wire.Version = null,
    /// The context the daemon gave, meaningful only while `stream` is open.
    context: u32 = 0,
    /// Why the last call failed. **Set on every failure and never cleared by a
    /// success**, so a caller reads it beside the error it just got and not as
    /// a running state.
    failure: ?Failure = null,

    pub fn init(io: std.Io) Driver {
        return .{ .io = io };
    }

    pub fn pcsc(self: *Driver) iface.Pcsc {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Release the context and close the connection. Safe to call twice, and
    /// safe on a driver whose `establish` failed.
    pub fn deinit(self: *Driver) void {
        const stream = self.stream orelse return;
        if (self.context != 0) {
            // Best effort. The daemon drops every context a closed socket held
            // anyway, so a failure here costs nothing and there is nothing a
            // caller could do about it.
            const body = wire.encodeRelease(self.context);
            if (self.writeMessage(.release_context, &body)) {
                var reply: [wire.release_len]u8 = undefined;
                _ = self.recv(&reply) catch {};
            } else |_| {}
            self.context = 0;
        }
        stream.close(self.io);
        self.stream = null;
    }

    /// Open a connection, agree a protocol version, and take a context.
    ///
    /// **Three steps and one call**, because none of them is useful alone and
    /// because the daemon's own authorization refusal lands between the first
    /// and the second. A caller that could see the states in between would have
    /// to know which of them is a working transport.
    pub fn establish(self: *Driver) iface.Error!void {
        if (self.stream != null) return;

        try self.open();
        errdefer {
            self.stream.?.close(self.io);
            self.stream = null;
        }
        try self.handshake();
        try self.takeContext();
    }

    /// Connect, and say which of three things the path is.
    ///
    /// **The connection is made with the system call and not with
    /// `std.Io.net.UnixAddress.connect`, and that is the one place this file
    /// departs from `lib/chock-broker/socket.zig`.** `ConnectError` has no
    /// member for `ECONNREFUSED`, so that library call turns the answer this
    /// function exists to give into `error.Unexpected`, and in a debug build it
    /// prints a stack trace on the way. A socket file that nothing is listening
    /// on is an ordinary state, not a bug: it is what a daemon that died leaves
    /// behind, and a person reading `chock doctor` gets a sentence about it
    /// rather than a stack trace. Everything after this uses the same handle
    /// through `std.Io.net.Stream`, exactly as `socket.zig` does for a
    /// connection the kernel handed it.
    fn open(self: *Driver) iface.Error!void {
        // The path is read first, because a socket that is not there and a file
        // that is not a socket both refuse a connection with the same errno.
        const stat = std.Io.Dir.cwd().statFile(self.io, self.socket_path, .{}) catch {
            self.failure = .{ .no_socket = self.socket_path };
            return error.NoService;
        };
        if (stat.kind != .unix_domain_socket) {
            self.failure = .{ .not_a_socket = self.socket_path };
            return error.NoService;
        }

        var address: std.posix.sockaddr.un = .{ .family = std.posix.AF.UNIX, .path = @splat(0) };
        // One byte short of the field, so the terminator fits. A path that
        // filled it would name a different socket.
        if (self.socket_path.len >= address.path.len) {
            self.failure = .{ .not_a_socket = self.socket_path };
            return error.NoService;
        }
        @memcpy(address.path[0..self.socket_path.len], self.socket_path);

        // **Close on exec.** A tool call this session spawns must not inherit an
        // open connection to the daemon that holds the signing key's reader.
        const opened = std.posix.system.socket(
            std.posix.AF.UNIX,
            std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC,
            0,
        );
        if (std.posix.errno(opened) != .SUCCESS) {
            self.failure = .{ .transport = "connection" };
            return error.NoService;
        }
        const handle: std.posix.fd_t = @intCast(opened);

        while (true) {
            const rc = std.posix.system.connect(
                handle,
                @ptrCast(&address),
                @sizeOf(std.posix.sockaddr.un),
            );
            switch (std.posix.errno(rc)) {
                .SUCCESS => break,
                // Interrupted before the connection was made. Nothing is lost.
                .INTR => continue,
                else => {
                    _ = std.posix.system.close(handle);
                    self.failure = .{ .not_listening = self.socket_path };
                    return error.NoService;
                },
            }
        }

        // The same wrapping `lib/chock-broker/socket.zig` does for a handle the
        // kernel gave it. The address is never read on a unix socket.
        self.stream = .{ .socket = .{ .handle = handle, .address = .{ .ip4 = .loopback(0) } } };
    }

    fn handshake(self: *Driver) iface.Error!void {
        try self.sendHandshake();
        try self.readHandshake();
    }

    /// **The write side of the same race `readHandshake` names below.** This
    /// is the very first write on a freshly opened connection, so a broken
    /// pipe here can only mean one thing: the peer had already closed before
    /// this got the chance to write, which is what `pcscd` does from inside
    /// `IsClientAuthorized`. `EPIPE` on a stream socket is raised only once
    /// the peer's end is gone, so this is not a guess between "closed" and
    /// "some other transport fault": the kernel already told us which one it
    /// is. A build that read this as a plain transport failure would send a
    /// refused client to go start a daemon that is running and already said
    /// no.
    fn sendHandshake(self: *Driver) iface.Error!void {
        const body = wire.encodeVersion(self.offered);
        self.writeMessage(.version, &body) catch |err| switch (err) {
            error.BrokenPipe => {
                self.failure = .not_authorized;
                return error.NotAuthorized;
            },
            error.Failed => {
                self.failure = .{ .transport = "version handshake" };
                return error.NoService;
            },
        };
    }

    /// **Split from the send so a test can put a refusal between the two.**
    /// That is the only order in which a daemon's authorization refusal is
    /// reachable: `pcscd` accepts, checks, and closes, and the client learns
    /// about it on the read it was already waiting on.
    fn readHandshake(self: *Driver) iface.Error!void {
        var reply: [wire.version_len]u8 = undefined;
        self.recv(&reply) catch |err| switch (err) {
            // The one place a closed connection means something specific. The
            // daemon closes here, before it has read anything, when its polkit
            // check refuses the client.
            error.PeerClosed => {
                self.failure = .not_authorized;
                return error.NotAuthorized;
            },
            else => {
                self.failure = .{ .transport = "version handshake" };
                return error.NoService;
            },
        };

        const answer = wire.decodeVersion(&reply);
        self.daemon_version = answer.daemon;

        // **Both the code and the numbers.** The daemon refuses outright only
        // when the client's minor is below its own backward window; a client
        // whose major is wrong and whose minor is not gets `success` and the
        // daemon's own numbers, and a build that read only the code would carry
        // on speaking a protocol nobody agreed to. `test/pcsc/pcscd.zig` drives
        // that case against the real daemon.
        //
        // **The code half is not reachable against pcsc-lite 2.4.1, and it
        // stays.** That daemon sets this field on a version mismatch and on
        // nothing else, and it always answers with its own two numbers, so the
        // numbers alone catch every refusal it can make. A later daemon that
        // refused for another reason would answer numbers this build accepts,
        // and a client that ignored the code would then talk over a refusal.
        if (answer.rv != .success or !self.offered.accepts(answer.daemon)) {
            self.failure = .{ .version_mismatch = .{
                .offered = self.offered,
                .daemon = answer.daemon,
            } };
            return error.ProtocolMismatch;
        }
    }

    fn takeContext(self: *Driver) iface.Error!void {
        const body = wire.encodeEstablish(wire.scope_system);
        try self.sendMessage(.establish_context, &body, "context");

        var reply: [wire.establish_len]u8 = undefined;
        try self.recvMessage(&reply, "context");

        const answer = wire.decodeEstablish(&reply);
        if (answer.rv != .success) {
            self.failure = .{ .refused = .{ .what = "context", .rv = answer.rv } };
            return error.NoService;
        }
        self.context = answer.context;
    }

    fn listReaders(self: *Driver, out: []u8) iface.Error!usize {
        if (self.stream == null) return error.NoService;

        try self.sendMessage(.get_readers_state, &.{}, "reader list");

        // The daemon answers with every slot every time and puts no count in
        // front of them. A wrong size here does not shorten this answer: it
        // moves every later message on the connection.
        var states: [wire.readers_state_len]u8 = undefined;
        try self.recvMessage(&states, "reader list");

        return wire.writeReaderList(&states, out) catch return error.BufferTooSmall;
    }

    fn connect(self: *Driver, reader: []const u8) iface.Error!iface.Handle {
        if (self.stream == null) return error.NoService;

        // A name too long for the daemon's own field is refused here rather
        // than truncated and sent. **`NoReader` and not `Unexpected`**: the
        // daemon has no reader by that name either, because it could not hold
        // one, so the caller's answer is the same one it would have got.
        const body = wire.encodeConnect(self.context, reader) catch return error.NoReader;
        try self.sendMessage(.connect, &body, "connect");

        var reply: [wire.connect_len]u8 = undefined;
        try self.recvMessage(&reply, "connect");

        const answer = wire.decodeConnect(&reply);
        switch (answer.rv) {
            .success => {},
            // The three the caller acts on differently. Everything else is a
            // refusal with its code kept.
            .unknown_reader, .reader_unavailable, .no_readers_available => return error.NoReader,
            .no_smartcard => return error.NoCard,
            .removed_card => return error.Removed,
            else => {
                self.failure = .{ .refused = .{ .what = "connect", .rv = answer.rv } };
                return error.Unexpected;
            },
        }

        return .{
            .value = @bitCast(@as(i64, answer.card)),
            // The reader settles this and the caller does not choose it. T=1 is
            // the answer for anything that is not plainly T=0, because the
            // number goes straight back to the daemon on every transmit.
            .protocol = if (answer.active_protocol == wire.protocol_t0) .t0 else .t1,
        };
    }

    /// **Run against a real card, and by no test here.** See this file's own
    /// top comment for what one YubiKey and one `pcscd` answered. No test in
    /// this file reaches this function with a daemon on the other end, because
    /// a test that needs a card in a reader passes or fails on the machine it
    /// runs on and not on the code.
    fn transmit(
        self: *Driver,
        handle: iface.Handle,
        command_bytes: []const u8,
        receive: []u8,
    ) iface.Error!usize {
        if (self.stream == null) return error.NoService;
        if (command_bytes.len > std.math.maxInt(u32)) return error.Unexpected;

        const card: i32 = @truncate(@as(i64, @bitCast(handle.value)));
        const protocol: u32 = switch (handle.protocol) {
            .t0 => wire.protocol_t0,
            .t1 => wire.protocol_t1,
        };
        const body = wire.encodeTransmit(
            card,
            protocol,
            @intCast(command_bytes.len),
            @intCast(@min(receive.len, std.math.maxInt(u32))),
        );
        try self.sendMessage(.transmit, &body, "transmit");
        // The command bytes follow with no header of their own. This is the one
        // message in the protocol that is two writes.
        //
        // **`BrokenPipe` and `Failed` read the same here.** This write only
        // happens on a connection that already finished a handshake, so a
        // closed peer met here is an ordinary disconnect mid-session, not the
        // authorization race `sendHandshake` distinguishes.
        self.writeAll(command_bytes) catch {
            self.failure = .{ .transport = "transmit" };
            return error.Unexpected;
        };

        var reply: [wire.transmit_len]u8 = undefined;
        try self.recvMessage(&reply, "transmit");

        const answer = wire.decodeTransmit(&reply);
        switch (answer.rv) {
            .success => {},
            .no_smartcard => return error.NoCard,
            .removed_card, .unresponsive_card => return error.Removed,
            .insufficient_buffer => return error.BufferTooSmall,
            else => {
                self.failure = .{ .refused = .{ .what = "transmit", .rv = answer.rv } };
                return error.Unexpected;
            },
        }

        // **Only on success.** The daemon sends the answer buffer after the
        // body on that one condition, so reading it on a failure would wait for
        // bytes nobody is going to send.
        if (answer.received > receive.len) return error.BufferTooSmall;
        try self.recvMessage(receive[0..answer.received], "transmit");
        return answer.received;
    }

    fn disconnect(self: *Driver, handle: iface.Handle) void {
        if (self.stream == null) return;
        const card: i32 = @truncate(@as(i64, @bitCast(handle.value)));
        const body = wire.encodeDisconnect(card);
        // Nothing to report. `Pcsc.VTable.disconnect` answers nothing on every
        // driver, because a close that failed leaves a caller nothing to do.
        if (self.writeMessage(.disconnect, &body)) {
            var reply: [wire.disconnect_len]u8 = undefined;
            self.recv(&reply) catch {};
        } else |_| {}
    }

    /// **`Failed` and `BrokenPipe` are kept apart because `sendHandshake`
    /// reacts to them differently, and nothing else does.** `BrokenPipe` is
    /// `EPIPE`: the peer had already closed the connection when this wrote to
    /// it. On the very first write of a fresh connection, that is not a
    /// generic transport fault, it is the other half of the race
    /// `readHandshake` already names below. Every later write treats the two
    /// the same, because by then a closed peer is an ordinary disconnect and
    /// not the daemon's authorization refusal in disguise.
    const WriteError = error{ Failed, BrokenPipe };

    /// Header and body, in that order, as two writes. That is what
    /// `MessageSendWithHeader` does and the daemon reads them as one message.
    fn writeMessage(self: *Driver, command: wire.Command, body: []const u8) WriteError!void {
        const header = wire.encodeHeader(command, @intCast(body.len));
        try self.writeAll(&header);
        if (body.len != 0) try self.writeAll(body);
    }

    fn sendMessage(
        self: *Driver,
        command: wire.Command,
        body: []const u8,
        what: []const u8,
    ) iface.Error!void {
        self.writeMessage(command, body) catch {
            self.failure = .{ .transport = what };
            return error.NoService;
        };
    }

    /// Write the whole of `bytes`, or say which of two ways it failed.
    ///
    /// **`sendto` with `MSG_NOSIGNAL` and not `write`.** A daemon that closed
    /// the connection would otherwise raise `SIGPIPE` and kill the process
    /// rather than fail one call. This is what `libpcsclite` itself does, and
    /// what `lib/chock-broker/socket.zig` does for the same reason.
    ///
    /// A short write is not a failure: a socket takes what fits and says how
    /// much.
    fn writeAll(self: *Driver, bytes: []const u8) WriteError!void {
        const handle = (self.stream orelse return error.Failed).socket.handle;
        var sent: usize = 0;
        while (sent < bytes.len) {
            const rc = std.posix.system.sendto(
                handle,
                bytes.ptr + sent,
                bytes.len - sent,
                std.posix.MSG.NOSIGNAL,
                null,
                0,
            );
            const written: isize = @bitCast(@as(usize, @bitCast(rc)));
            if (written > 0) {
                sent += @intCast(written);
                continue;
            }
            switch (std.posix.errno(rc)) {
                // Interrupted before anything was written. Nothing is lost.
                .INTR => continue,
                // The peer had already closed. See `WriteError.BrokenPipe`.
                .PIPE => return error.BrokenPipe,
                else => return error.Failed,
            }
        }
    }

    const RecvError = error{
        /// The daemon closed the connection, or reset it, before the whole
        /// answer arrived.
        PeerClosed,
        /// Nothing arrived inside `timeout_ms`.
        TimedOut,
        /// The read itself failed.
        Failed,
    };

    /// Fill `buffer` from the connection, or say which of three things went
    /// wrong. **The daemon frames no answer**, so the length asked for here is
    /// the whole of what a caller knows about where the message ends.
    fn recv(self: *Driver, buffer: []u8) RecvError!void {
        const handle = (self.stream orelse return error.Failed).socket.handle;
        var filled: usize = 0;
        while (filled < buffer.len) {
            var fds = [_]std.posix.pollfd{
                .{ .fd = handle, .events = std.posix.POLL.IN, .revents = 0 },
            };
            const ready = std.posix.poll(&fds, self.timeout_ms) catch return error.Failed;
            if (ready == 0) return error.TimedOut;

            const read = std.posix.read(handle, buffer[filled..]) catch |err| switch (err) {
                // A reset is a close this end learns about the hard way. The
                // daemon's authorization refusal arrives as exactly this.
                error.ConnectionResetByPeer => return error.PeerClosed,
                else => return error.Failed,
            };
            if (read == 0) return error.PeerClosed;
            filled += read;
        }
    }

    fn recvMessage(self: *Driver, buffer: []u8, what: []const u8) iface.Error!void {
        self.recv(buffer) catch {
            self.failure = .{ .transport = what };
            return error.NoService;
        };
    }

    fn establishFn(ptr: *anyopaque) iface.Error!void {
        return from(ptr).establish();
    }

    fn listReadersFn(ptr: *anyopaque, out: []u8) iface.Error!usize {
        return from(ptr).listReaders(out);
    }

    fn connectFn(ptr: *anyopaque, reader: []const u8) iface.Error!iface.Handle {
        return from(ptr).connect(reader);
    }

    fn transmitFn(
        ptr: *anyopaque,
        handle: iface.Handle,
        send_bytes: []const u8,
        receive: []u8,
    ) iface.Error!usize {
        return from(ptr).transmit(handle, send_bytes, receive);
    }

    fn disconnectFn(ptr: *anyopaque, handle: iface.Handle) void {
        from(ptr).disconnect(handle);
    }

    fn from(ptr: *anyopaque) *Driver {
        return @ptrCast(@alignCast(ptr));
    }

    const vtable = iface.Pcsc.VTable{
        .establish = establishFn,
        .listReaders = listReadersFn,
        .connect = connectFn,
        .transmit = transmitFn,
        .disconnect = disconnectFn,
    };
};

// Every test here runs with no daemon at all. The ones that need a real
// `pcscd` are `test/pcsc/pcscd.zig`, which is a target of its own because it
// spawns one.

const testing = std.testing;

test "a path with nothing at it is no daemon, and it says so by name" {
    // The first of the four answers. A build that could not tell this from a
    // daemon that refused would send somebody to look at polkit rules for a
    // machine with no pcscd on it.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &path_buffer);

    var socket_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const missing = try std.fmt.bufPrint(&socket_buffer, "{s}/pcscd.comm", .{path_buffer[0..dir_len]});

    var driver = Driver.init(testing.io);
    driver.socket_path = missing;
    defer driver.deinit();

    try testing.expectError(error.NoService, driver.establish());
    try testing.expect(driver.failure.? == .no_socket);

    var said: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(&said, "{f}", .{driver.failure.?});
    try testing.expect(std.mem.indexOf(u8, text, missing) != null);
    try testing.expect(std.mem.indexOf(u8, text, "no daemon") != null);
}

test "a plain file where the socket belongs is a different answer again" {
    // The second answer. This is what a half installed daemon and a stray file
    // both look like, and neither of them is a daemon that is not listening.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "pcscd.comm", .data = "" });

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &path_buffer);
    var socket_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&socket_buffer, "{s}/pcscd.comm", .{path_buffer[0..dir_len]});

    var driver = Driver.init(testing.io);
    driver.socket_path = path;
    defer driver.deinit();

    try testing.expectError(error.NoService, driver.establish());
    try testing.expect(driver.failure.? == .not_a_socket);
}

test "a socket nobody is listening on is not a socket that is not there" {
    // The third answer, and the one `connect` alone cannot give: a refused
    // connection is not in `UnixAddress.ConnectError`, so the path is read
    // first. This is what a daemon that died leaves behind.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &path_buffer);
    var socket_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&socket_buffer, "{s}/pcscd.comm", .{path_buffer[0..dir_len]});
    if (path.len > std.Io.net.UnixAddress.max_len) return error.SkipZigTest;

    // Listen, then stop, which leaves the file. Making the file by hand would
    // make a regular file, which is the test above and a different fact.
    const address = try std.Io.net.UnixAddress.init(path);
    var server = try address.listen(testing.io, .{});
    server.deinit(testing.io);

    var driver = Driver.init(testing.io);
    driver.socket_path = path;
    defer driver.deinit();

    try testing.expectError(error.NoService, driver.establish());
    try testing.expect(driver.failure.? == .not_listening);
}

test "a peer that closes without answering the handshake is read as not authorized" {
    // The fourth answer, and the state of the machine this was written for.
    // The daemon's polkit refusal says nothing on the wire: it closes. So the
    // stand-in here closes too, which is the whole of what `pcscd` does.
    //
    // **Not the same as a daemon that is not listening.** A caller that read
    // the two the same way would tell somebody to start a daemon that is
    // already running.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &path_buffer);
    var socket_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&socket_buffer, "{s}/pcscd.comm", .{path_buffer[0..dir_len]});
    if (path.len > std.Io.net.UnixAddress.max_len) return error.SkipZigTest;

    const address = try std.Io.net.UnixAddress.init(path);
    var server = try address.listen(testing.io, .{});
    defer server.deinit(testing.io);

    var driver = Driver.init(testing.io);
    driver.socket_path = path;
    driver.timeout_ms = 2_000;
    defer driver.deinit();

    // Connect and send the handshake before anything accepts: the kernel queue
    // holds both, so this needs no second thread.
    try driver.open();
    try driver.sendHandshake();

    // Accept and close with the handshake unread, which is what `pcscd` does
    // from inside its own authorization check. The unread bytes are why the
    // client sees a reset and not a clean end.
    const accepted = try server.accept(testing.io);
    accepted.close(testing.io);

    try testing.expectError(error.NotAuthorized, driver.readHandshake());
    try testing.expect(driver.failure.? == .not_authorized);

    var said: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&said, "{f}", .{driver.failure.?});
    try testing.expect(std.mem.indexOf(u8, text, "access_pcsc") != null);
}

// **The other half of the same race, forced rather than waited for.**
//
// A CI runner hit this side once: `sendHandshake`'s write met a peer that
// had already closed, and it came back as `error.NoService` with
// `Failure.transport`, not `error.NotAuthorized` with `Failure.not_authorized`.
// The test above proves the read side; this one proves the write side by the
// same trick in the other order, closing before the client writes instead of
// after, so which side of the race wins is decided here and not by luck.
//
// **Measured against the code before this test's own fix**: forcing this
// order against the driver as it stood gave exactly the CI failure,
// `error.NoService` and `Failure.transport`. This test pins the corrected
// reading, and a regression back to the old one fails it.
test "a peer that closes before the write is the same not authorized, met from the other side" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &path_buffer);
    var socket_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&socket_buffer, "{s}/pcscd.comm", .{path_buffer[0..dir_len]});
    if (path.len > std.Io.net.UnixAddress.max_len) return error.SkipZigTest;

    const address = try std.Io.net.UnixAddress.init(path);
    var server = try address.listen(testing.io, .{});
    defer server.deinit(testing.io);

    var driver = Driver.init(testing.io);
    driver.socket_path = path;
    driver.timeout_ms = 2_000;
    defer driver.deinit();

    // Connect, then accept and close before a single byte of the handshake is
    // sent. **Both syscalls complete before this returns**, so the write
    // below meets an already-closed peer every time this runs, not on
    // whichever run the scheduler happens to lose.
    try driver.open();
    const accepted = try server.accept(testing.io);
    accepted.close(testing.io);

    try testing.expectError(error.NotAuthorized, driver.sendHandshake());
    try testing.expect(driver.failure.? == .not_authorized);

    // **Still distinguishable from the other two states this file's tests
    // hold apart.** Neither `no_socket` (nothing at the path) nor
    // `not_listening` (a socket nobody accepted) is what happened here: a
    // connection was accepted and then closed, and that stays its own fact.
    try testing.expect(driver.failure.? != .no_socket);
    try testing.expect(driver.failure.? != .not_listening);

    var said: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&said, "{f}", .{driver.failure.?});
    try testing.expect(std.mem.indexOf(u8, text, "access_pcsc") != null);
}

test "a version refusal names this build's version and the daemon's, not just mismatch" {
    const failure = Failure{ .version_mismatch = .{
        .offered = .{ .major = 4, .minor = 5 },
        .daemon = .{ .major = 5, .minor = 0 },
    } };
    var said: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(&said, "{f}", .{failure});
    try testing.expect(std.mem.indexOf(u8, text, "4:5") != null);
    try testing.expect(std.mem.indexOf(u8, text, "5:0") != null);
}

test "a refusal code is printed as itself rather than as a nearby name" {
    const failure = Failure{ .refused = .{ .what = "context", .rv = @enumFromInt(0x8010004d) } };
    var said: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(&said, "{f}", .{failure});
    try testing.expect(std.mem.indexOf(u8, text, "0x8010004d") != null);
}

test "every call before an establish answers NoService rather than reaching a socket" {
    // A driver with no connection has no context either, and a call that got
    // as far as writing would write to a handle that is not there.
    var driver = Driver.init(testing.io);
    defer driver.deinit();

    var names: [64]u8 = undefined;
    try testing.expectError(error.NoService, driver.listReaders(&names));
    try testing.expectError(error.NoService, driver.connect("Reader 00"));
    var answer: [64]u8 = undefined;
    try testing.expectError(error.NoService, driver.transmit(
        .{ .value = 1, .protocol = .t1 },
        &.{0x00},
        &answer,
    ));
    // And a disconnect answers nothing at all, on every driver.
    driver.disconnect(.{ .value = 1, .protocol = .t1 });
}

test {
    testing.refAllDecls(@This());
}
