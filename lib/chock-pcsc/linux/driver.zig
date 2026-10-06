//! The Linux transport for `chock-pcsc`: `pcscd`'s own unix socket, spoken

const std = @import("std");
const iface = @import("../../chock-pcsc.zig");

pub const wire = @import("wire.zig");

pub const default_socket_path = "/run/pcscd/pcscd.comm";

pub const default_timeout_ms: i32 = 5_000;

pub const Failure = union(enum) {
    no_socket: []const u8,
    not_a_socket: []const u8,
    not_listening: []const u8,
    not_authorized,
    version_mismatch: struct { offered: wire.Version, daemon: wire.Version },
    refused: struct { what: []const u8, rv: wire.Return },
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

pub const Driver = struct {
    io: std.Io,
    socket_path: []const u8 = default_socket_path,
    offered: wire.Version = wire.protocol_version,
    timeout_ms: i32 = default_timeout_ms,

    stream: ?std.Io.net.Stream = null,
    daemon_version: ?wire.Version = null,
    context: u32 = 0,
    failure: ?Failure = null,

    pub fn init(io: std.Io) Driver {
        return .{ .io = io };
    }

    pub fn pcsc(self: *Driver) iface.Pcsc {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn deinit(self: *Driver) void {
        const stream = self.stream orelse return;
        if (self.context != 0) {
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

    fn open(self: *Driver) iface.Error!void {
        const stat = std.Io.Dir.cwd().statFile(self.io, self.socket_path, .{}) catch {
            self.failure = .{ .no_socket = self.socket_path };
            return error.NoService;
        };
        if (stat.kind != .unix_domain_socket) {
            self.failure = .{ .not_a_socket = self.socket_path };
            return error.NoService;
        }

        var address: std.posix.sockaddr.un = .{ .family = std.posix.AF.UNIX, .path = @splat(0) };
        if (self.socket_path.len >= address.path.len) {
            self.failure = .{ .not_a_socket = self.socket_path };
            return error.NoService;
        }
        @memcpy(address.path[0..self.socket_path.len], self.socket_path);

        // A tool call this session spawns must not inherit an open connection to the daemon that holds the signing key's reader, so the socket is opened close on exec.
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
                .INTR => continue,
                else => {
                    _ = std.posix.system.close(handle);
                    self.failure = .{ .not_listening = self.socket_path };
                    return error.NoService;
                },
            }
        }

        self.stream = .{ .socket = .{ .handle = handle, .address = .{ .ip4 = .loopback(0) } } };
    }

    fn handshake(self: *Driver) iface.Error!void {
        try self.sendHandshake();
        try self.readHandshake();
    }

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

    fn readHandshake(self: *Driver) iface.Error!void {
        var reply: [wire.version_len]u8 = undefined;
        self.recv(&reply) catch |err| switch (err) {
            // A connection closed here, before anything is read, is the daemon's polkit check refusing the client, not an ordinary disconnect.
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

        // The daemon refuses outright only when the client's minor version is below its own backward window. A client whose major is wrong gets success and the daemon's own numbers instead of a refusal code, so both the numbers and the code are checked.
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

        var states: [wire.readers_state_len]u8 = undefined;
        try self.recvMessage(&states, "reader list");

        return wire.writeReaderList(&states, out) catch return error.BufferTooSmall;
    }

    fn connect(self: *Driver, reader: []const u8) iface.Error!iface.Handle {
        if (self.stream == null) return error.NoService;

        const body = wire.encodeConnect(self.context, reader) catch return error.NoReader;
        try self.sendMessage(.connect, &body, "connect");

        var reply: [wire.connect_len]u8 = undefined;
        try self.recvMessage(&reply, "connect");

        const answer = wire.decodeConnect(&reply);
        switch (answer.rv) {
            .success => {},
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
            .protocol = if (answer.active_protocol == wire.protocol_t0) .t0 else .t1,
        };
    }

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
        // This write happens only after a handshake has already finished, so a closed peer met here is an ordinary disconnect mid-session, not the authorization race sendHandshake distinguishes.
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

        if (answer.received > receive.len) return error.BufferTooSmall;
        try self.recvMessage(receive[0..answer.received], "transmit");
        return answer.received;
    }

    fn disconnect(self: *Driver, handle: iface.Handle) void {
        if (self.stream == null) return;
        const card: i32 = @truncate(@as(i64, @bitCast(handle.value)));
        const body = wire.encodeDisconnect(card);
        if (self.writeMessage(.disconnect, &body)) {
            var reply: [wire.disconnect_len]u8 = undefined;
            self.recv(&reply) catch {};
        } else |_| {}
    }

    const WriteError = error{ Failed, BrokenPipe };

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
                .INTR => continue,
                .PIPE => return error.BrokenPipe,
                else => return error.Failed,
            }
        }
    }

    const RecvError = error{
        PeerClosed,
        TimedOut,
        Failed,
    };

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

const testing = std.testing;

test "a path with nothing at it is no daemon, and it says so by name" {
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
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &path_buffer);
    var socket_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&socket_buffer, "{s}/pcscd.comm", .{path_buffer[0..dir_len]});
    if (path.len > std.Io.net.UnixAddress.max_len) return error.SkipZigTest;

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

    try driver.open();
    try driver.sendHandshake();

    const accepted = try server.accept(testing.io);
    accepted.close(testing.io);

    try testing.expectError(error.NotAuthorized, driver.readHandshake());
    try testing.expect(driver.failure.? == .not_authorized);

    var said: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&said, "{f}", .{driver.failure.?});
    try testing.expect(std.mem.indexOf(u8, text, "access_pcsc") != null);
}

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

    try driver.open();
    const accepted = try server.accept(testing.io);
    accepted.close(testing.io);

    try testing.expectError(error.NotAuthorized, driver.sendHandshake());
    try testing.expect(driver.failure.? == .not_authorized);

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
    driver.disconnect(.{ .value = 1, .protocol = .t1 });
}

test {
    testing.refAllDecls(@This());
}
