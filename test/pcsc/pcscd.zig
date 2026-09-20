//! The Linux transport, driven against a real `pcscd`: a daemon nobody here
//! wrote, reading the bytes this build sends.
//!
//! These tests start their own `pcscd` over `systemd-socket-activate` with
//! `--disable-polkit`, the same binary and the same wire code with one gate
//! turned off that runs before the daemon reads a byte. Only the last test uses
//! the system daemon.
//!
//! A machine has a third answer besides no daemon and a working one: a daemon
//! that accepts the connection and closes it before it answers a byte. A skip on
//! that says the daemon was never reached, which is not a pass.
//!
//! No test needs a card or a reader.

const std = @import("std");
const builtin = @import("builtin");
const chock_pcsc = @import("chock-pcsc");

const wire = chock_pcsc.platform.wire;
const testing = std.testing;

const system_socket = chock_pcsc.platform.default_socket_path;

/// Read off the platform's own structure so it cannot drift. 104 on Darwin and
/// 108 on Linux.
const sun_path_len = @typeInfo(@FieldType(std.posix.sockaddr.un, "path")).array.len;

const Daemon = struct {
    child: std.process.Child,

    const socket_wait_ms = 5_000;

    /// `--disable-polkit` and nothing else is changed. `--auto-exit` makes the
    /// daemon quit with no client, so a killed run leaves nothing behind.
    fn start(io: std.Io, socket: []const u8) !Daemon {
        var child = std.process.spawn(io, .{
            .argv = &.{
                "systemd-socket-activate",
                "-l",
                socket,
                "pcscd",
                "--foreground",
                "--auto-exit",
                "--disable-polkit",
            },
            .stdin = .ignore,
            // `pcscd` logs on standard error whatever the level, and the build
            // fails on a byte a test binary writes there.
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch |err| switch (err) {
            error.FileNotFound => return error.SkipZigTest,
            else => |e| return e,
        };
        errdefer child.kill(io);

        // The socket appears once `systemd-socket-activate` has bound it, which
        // is before `pcscd` starts: the first connection spawns the daemon.
        var waited: i32 = 0;
        while (waited < socket_wait_ms) : (waited += 25) {
            const stat = std.Io.Dir.cwd().statFile(io, socket, .{}) catch {
                std.Io.sleep(io, .fromMilliseconds(25), .awake) catch {};
                continue;
            };
            if (stat.kind == .unix_domain_socket) return .{ .child = child };
            std.Io.sleep(io, .fromMilliseconds(25), .awake) catch {};
        }
        return error.SocketNeverAppeared;
    }

    fn stop(self: *Daemon, io: std.Io) void {
        self.child.kill(io);
    }
};

/// The path is on the heap because `Bench` holds a `Place` by value and a driver
/// that keeps a slice of it.
const Place = struct {
    tmp: testing.TmpDir,
    socket: []u8,

    fn make() !Place {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const dir_len = try tmp.dir.realPath(testing.io, &dir_buffer);
        const socket = try std.fmt.allocPrint(
            testing.allocator,
            "{s}/pcscd.comm",
            .{dir_buffer[0..dir_len]},
        );
        errdefer testing.allocator.free(socket);

        // `std.Io.net.UnixAddress.max_len` is 108 on every platform but Windows,
        // and Darwin's `sun_path` is 104, so a path between the two ends the
        // process inside `connect`. A tree too deep for the bound is a skip.
        if (socket.len >= sun_path_len) return error.SkipZigTest;
        return .{ .tmp = tmp, .socket = socket };
    }

    fn done(self: *Place) void {
        testing.allocator.free(self.socket);
        self.tmp.cleanup();
    }
};

/// The timeout is far past the driver's default because the first connection
/// starts `pcscd`, including its scan of the USB bus.
const Bench = struct {
    place: Place,
    daemon: Daemon,
    driver: chock_pcsc.Driver,

    fn init() !Bench {
        var place = try Place.make();
        errdefer place.done();
        var daemon = try Daemon.start(testing.io, place.socket);
        errdefer daemon.stop(testing.io);

        var driver = chock_pcsc.default(testing.io);
        driver.socket_path = place.socket;
        driver.timeout_ms = 30_000;
        return .{ .place = place, .daemon = daemon, .driver = driver };
    }

    fn deinit(self: *Bench) void {
        self.driver.deinit();
        self.daemon.stop(testing.io);
        self.place.done();
    }
};

/// Whether the daemon closed the connection before it answered anything. One
/// error and one failure together, so a fault anywhere else keeps its own name.
fn refusedBeforeAnswering(err: anyerror, driver: *const chock_pcsc.Driver) bool {
    if (err != error.NotAuthorized) return false;
    const failure = driver.failure orelse return false;
    return failure == .not_authorized;
}

/// Nothing is written on the skip path, because the build fails on a byte a
/// test binary puts on standard error.
fn establishOrSkip(driver: *chock_pcsc.Driver) !void {
    driver.establish() catch |err| {
        if (refusedBeforeAnswering(err, driver)) return error.SkipZigTest;
        return err;
    };
}

fn expectVersionRefusedOrSkip(driver: *chock_pcsc.Driver) !void {
    driver.establish() catch |err| {
        if (refusedBeforeAnswering(err, driver)) return error.SkipZigTest;
        if (err == error.ProtocolMismatch) return;
        return err;
    };
    return error.DaemonAcceptedAVersionItDoesNotSpeak;
}

test "the transport reaches a real pcscd, agrees a version and lists what is attached" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var bench = try Bench.init();
    defer bench.deinit();

    try establishOrSkip(&bench.driver);

    // `pcsc-lite` 2.4.1 answers 4:5.
    try testing.expectEqual(wire.protocol_version, bench.driver.daemon_version.?);
    try testing.expect(bench.driver.context != 0);
    try testing.expectEqual(@as(?chock_pcsc.platform.Failure, null), bench.driver.failure);

    const transport = bench.driver.pcsc();

    var names: [4096]u8 = undefined;
    const written = try transport.listReaders(&names);

    try testing.expect(written <= names.len);
    if (written != 0) try testing.expectEqual(@as(u8, 0), names[written - 1]);
    var list = chock_pcsc.ReaderList.init(names[0..written]);
    var counted: usize = 0;
    while (list.next()) |name| : (counted += 1) {
        try testing.expect(name.len != 0);
        try testing.expect(name.len < wire.max_reader_name);
    }
    try testing.expectEqual(written, counted + sumLengths(names[0..written]));

    // `CMD_GET_READERS_STATE` is answered with 2944 bytes and no length in front
    // of them, so a wrong `reader_state_len` or `max_readers` leaves bytes on the
    // connection and every later message is read from the wrong offset.
    try testing.expectError(error.NoReader, transport.connect("chock test, no such reader"));

    const again = try transport.listReaders(&names);
    try testing.expectEqual(written, again);
}

fn sumLengths(bytes: []const u8) usize {
    var list = chock_pcsc.ReaderList.init(bytes);
    var total: usize = 0;
    while (list.next()) |name| total += name.len;
    return total;
}

test "a version the daemon refuses comes back naming both versions, not just mismatch" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var bench = try Bench.init();
    defer bench.deinit();

    // 4:0 is below the daemon's backward window, so it answers
    // `SCARD_E_SERVICE_STOPPED`.
    bench.driver.offered = .{ .major = 4, .minor = 0 };
    try expectVersionRefusedOrSkip(&bench.driver);
    try testing.expect(bench.driver.failure.? == .version_mismatch);

    var said: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(&said, "{f}", .{bench.driver.failure.?});
    try testing.expect(std.mem.indexOf(u8, text, "4:0") != null);
    try testing.expect(std.mem.indexOf(u8, text, "4:5") != null);
}

test "a daemon that answers success to a version it does not speak is refused anyway" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // `pcscd` refuses outright only when the minor number is below its backward
    // window. A wrong major with an in window minor gets `SCARD_S_SUCCESS` and
    // the daemon's own numbers, so a build that read the code and not the
    // numbers would speak a protocol nobody agreed to.
    var bench = try Bench.init();
    defer bench.deinit();

    bench.driver.offered = .{ .major = 9, .minor = 5 };
    try expectVersionRefusedOrSkip(&bench.driver);
    try testing.expectEqual(wire.protocol_version, bench.driver.daemon_version.?);

    var said: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(&said, "{f}", .{bench.driver.failure.?});
    try testing.expect(std.mem.indexOf(u8, text, "9:5") != null);
    try testing.expect(std.mem.indexOf(u8, text, "4:5") != null);
}

test "a daemon that is not there, one that answers nothing, and one with no reader are three answers" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var bench = try Bench.init();
    defer bench.deinit();

    // Beside a socket this test made, so only the daemon differs.
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const missing = try std.fmt.bufPrint(&buffer, "{s}.gone", .{bench.place.socket});

    var absent = chock_pcsc.default(testing.io);
    absent.socket_path = missing;
    defer absent.deinit();

    try testing.expectError(error.NoService, absent.establish());
    try testing.expect(absent.failure.? == .no_socket);

    bench.driver.establish() catch |err| {
        if (!refusedBeforeAnswering(err, &bench.driver)) return err;
        // The third state and the absent one still must not read the same.
        try testing.expect(bench.driver.failure.? != .no_socket);
        try testing.expect(absent.failure.? != .not_authorized);
        return error.SkipZigTest;
    };

    var names: [4096]u8 = undefined;
    _ = try bench.driver.pcsc().listReaders(&names);

    // A machine with no daemon and a machine with a daemon and no reader must
    // never read the same way.
    try testing.expect(bench.driver.failure == null);
}

test "a seal is read while the transport is refusing, in the same process" {
    // Reading a seal must need no card and no daemon, so the driver is asked
    // and refused first.
    var driver = chock_pcsc.default(testing.io);
    if (builtin.os.tag == .linux) driver.socket_path = "/nonexistent/chock/pcscd.comm";
    defer driver.deinit();
    // Darwin answers `Unavailable` and Linux `NoService`, so neither is pinned.
    try testing.expect(std.meta.isError(driver.pcsc().establish()));

    const seal = chock_pcsc.seal;
    var key = try chock_pcsc.software.Key.fromSeed(@splat(0x21));
    const header: [seal.digest_hex_len]u8 = @splat('a');
    const head: [seal.digest_hex_len]u8 = @splat('b');
    const session = "01TESTSESSIONTESTSESSION00";

    var held = seal.Held{};
    const sealed = try seal.sign(.{
        .session = session,
        .header = header,
        .head = head,
        .events = 3,
        .level = .software,
    }, key.signer(), &held);

    const reading = seal.read(
        sealed,
        .{ .session = session, .header = &header, .head = &head, .events = 3 },
        .{ .now_sec = 1_700_000_000 },
    );
    try testing.expectEqual(seal.Verdict.signed_software, reading.verdict);
    try testing.expect(reading.signed());

    try testing.expectEqual(seal.Level.software, sealed.level);
}

test "the socket a real installation uses is reachable, whatever it then answers" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // Only the system daemon can show that the path a real installation uses is
    // one this driver connects to. What it answers belongs to the machine.
    const stat = std.Io.Dir.cwd().statFile(testing.io, system_socket, .{}) catch
        return error.SkipZigTest;
    if (stat.kind != .unix_domain_socket) return error.SkipZigTest;

    var driver = chock_pcsc.default(testing.io);
    defer driver.deinit();

    driver.establish() catch |err| {
        // `NoService` is not among these: the socket is there and was reached,
        // so reporting "no daemon" would send somebody to start a running one.
        switch (err) {
            error.NotAuthorized, error.ProtocolMismatch => {},
            else => return err,
        }
        try testing.expect(driver.failure != null);
        return;
    };

    try testing.expectEqual(wire.protocol_version, driver.daemon_version.?);
    var names: [4096]u8 = undefined;
    _ = try driver.pcsc().listReaders(&names);
}
