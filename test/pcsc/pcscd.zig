//! The Linux transport, driven against a real `pcscd`.
//!
//! `lib/chock-pcsc/linux/wire.zig` states the layouts and `lib/chock-pcsc/linux/driver.zig`
//! states the four answers a machine can give. Both are checked there with no
//! daemon at all, which proves the code agrees with itself. **This file is the
//! part that cannot be faked**: a daemon nobody here wrote, reading the bytes
//! this build sends and answering with its own.
//!
//! ## Why a daemon of this file's own, and why that is still a real one
//!
//! `pcscd` is running on the machine this was written for and **whether it
//! serves this client belongs to that machine, not to this file**. It is built
//! with polkit, and its action `org.debian.pcsc-lite.access_pcsc` allows an
//! active login session only until an administrator writes a rule. When it
//! refuses, the refusal arrives as a connection the daemon accepts and then
//! closes, so nothing past the first read of the handshake is reachable
//! through it. The box this was written for refused at first and serves the
//! owner now, because a rule was added at
//! `/etc/polkit-1/rules.d/49-pcscd-ross.rules`. **A test that pinned either
//! answer would be a test about that file**, so the last test below accepts
//! both.
//!
//! So these tests start `pcscd` themselves with `--disable-polkit`, over
//! `systemd-socket-activate`, which hands it a listening socket at a path this
//! file chose. **It is the same binary, the same release and the same wire
//! code**, with one authorization gate turned off, and that gate is not part of
//! the protocol: it runs before the daemon reads a byte. This is not a stand-in
//! written by the author of the client, which is the one shape of test this
//! module has to avoid.
//!
//! The system daemon is still used, for the one thing only it can show: that
//! the socket at the path a real installation uses is reachable. See the last
//! test.
//!
//! ## Every skip is a measured condition
//!
//! A machine with no `pcscd`, no `systemd-socket-activate`, or a temporary
//! directory whose path is longer than a unix socket address, cannot run these.
//! Each of those is learned by trying, and none of them is guessed from a
//! platform name.
//!
//! **No test here needs a card or a reader.** The daemon is asked what is
//! attached and whatever it says is fine: what is pinned is that the answer
//! parses and that the connection is still framed correctly afterwards.

const std = @import("std");
const builtin = @import("builtin");
const chock_pcsc = @import("chock-pcsc");

const wire = chock_pcsc.platform.wire;
const testing = std.testing;

/// Where a real installation puts the socket, and the path the driver uses when
/// nobody says otherwise.
const system_socket = chock_pcsc.platform.default_socket_path;

/// The size of this platform's `sun_path`, read off the platform's own
/// structure so it cannot drift. 104 on Darwin and 108 on Linux. See the skip
/// in `Place.make` for why `std.Io.net.UnixAddress.max_len` is the wrong
/// number.
const sun_path_len = @typeInfo(@FieldType(std.posix.sockaddr.un, "path")).array.len;

/// A `pcscd` of this test's own.
const Daemon = struct {
    child: std.process.Child,

    /// How long to wait for the socket file to appear. **A bound and not a
    /// measurement**: `systemd-socket-activate` binds before it waits, so this
    /// is reached in milliseconds or never.
    const socket_wait_ms = 5_000;

    /// Start one, or answer why this machine cannot.
    ///
    /// **`--disable-polkit` and nothing else is changed.** The daemon's own
    /// `-x` makes it quit after a minute with no client, so a run that is
    /// killed between `start` and `stop` leaves nothing behind for long.
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
            // **Nothing of the daemon's reaches this build's output.** `pcscd`
            // logs on standard error whatever the level, and `test/proto/lock.zig`
            // holds the whole build to a silent log.
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch |err| switch (err) {
            // Neither program is on this machine. Measured by trying, which is
            // the only way to learn it.
            error.FileNotFound => return error.SkipZigTest,
            else => |e| return e,
        };
        errdefer child.kill(io);

        // The socket appears as soon as `systemd-socket-activate` has bound it,
        // which is before `pcscd` is started at all: activation is lazy, and
        // the daemon is spawned by the first connection.
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

/// A temporary directory and a socket path inside it, short enough for a unix
/// address.
///
/// **The path is on the heap and not in this struct.** `Bench` holds a `Place`
/// by value and a driver that keeps a slice of the path, so a path stored in a
/// buffer of this struct's own would be pointed at by a slice into whichever
/// copy of it went out of scope first.
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

        // A build tree deep enough to pass the bound cannot host this test, and
        // saying so is better than a refusal that reads as a broken driver.
        //
        // **`std.Io.net.UnixAddress.max_len` is 108 on every platform that is
        // not Windows, and Darwin's `sun_path` is 104**, so this line used to
        // run on a Mac the very cases that end the process inside `connect`:
        // see `lib/chock-proto/control.zig`'s `max_socket_path`. That constant
        // is the one home for the number, and this test target imports
        // `chock-pcsc` alone, which may not import `chock-proto`, so the field
        // itself is read here rather than a second copy of the number being
        // typed out.
        if (socket.len >= sun_path_len) return error.SkipZigTest;
        return .{ .tmp = tmp, .socket = socket };
    }

    fn done(self: *Place) void {
        testing.allocator.free(self.socket);
        self.tmp.cleanup();
    }
};

/// Start a daemon, and give a driver already pointed at it.
///
/// The timeout is raised well past the driver's own default because the first
/// connection is what starts `pcscd`, and starting it includes its scan of the
/// USB bus. **That is a bound on a test that would otherwise hang, not a
/// measurement of how long a daemon takes.**
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

test "the transport reaches a real pcscd, agrees a version and lists what is attached" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var bench = try Bench.init();
    defer bench.deinit();

    try bench.driver.establish();

    // The daemon's own numbers, read off the wire. `pcsc-lite` 2.4.1 is 4:5,
    // and a build that offered anything else would have been refused above.
    try testing.expectEqual(wire.protocol_version, bench.driver.daemon_version.?);
    // A context the daemon made. Zero is what the request carried, so a build
    // that read the field it sent rather than the field it got would see it.
    try testing.expect(bench.driver.context != 0);
    try testing.expectEqual(@as(?chock_pcsc.platform.Failure, null), bench.driver.failure);

    const transport = bench.driver.pcsc();

    var names: [4096]u8 = undefined;
    const written = try transport.listReaders(&names);

    // **Whatever is attached is fine, and the answer must parse.** The machine
    // this was written on has nothing on its USB bus with interface class `0b`,
    // so this is zero here. A box with a reader answers its name, and neither
    // is a failure. What is pinned is the shape: every name is non empty, none
    // of them fills the daemon's own field, and the last one is terminated.
    try testing.expect(written <= names.len);
    if (written != 0) try testing.expectEqual(@as(u8, 0), names[written - 1]);
    var list = chock_pcsc.ReaderList.init(names[0..written]);
    var counted: usize = 0;
    while (list.next()) |name| : (counted += 1) {
        try testing.expect(name.len != 0);
        try testing.expect(name.len < wire.max_reader_name);
    }
    try testing.expectEqual(written, counted + sumLengths(names[0..written]));

    // **The framing proof, and the whole reason this test is worth running.**
    // `CMD_GET_READERS_STATE` is answered with 2944 bytes and no length in
    // front of them, so a wrong `reader_state_len` or a wrong `max_readers`
    // does not shorten the list: it leaves bytes on the connection and every
    // later message is read from the wrong offset. This next message is read
    // from the right one only if the sizes are right, and a reader name that
    // cannot exist has exactly one correct answer.
    try testing.expectError(error.NoReader, transport.connect("chock test, no such reader"));

    // And the connection is still usable after that, which a desynchronised one
    // would not be.
    const again = try transport.listReaders(&names);
    try testing.expectEqual(written, again);
}

/// How many bytes the names in a multi string take, without their terminators.
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

    // 4:0 is below the daemon's own backward window, so it answers
    // `SCARD_E_SERVICE_STOPPED` and its own numbers. This is the refusal path
    // inside `pcscd` and not one this build invented.
    bench.driver.offered = .{ .major = 4, .minor = 0 };
    try testing.expectError(error.ProtocolMismatch, bench.driver.establish());
    try testing.expect(bench.driver.failure.? == .version_mismatch);

    var said: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(&said, "{f}", .{bench.driver.failure.?});
    // Both numbers, because "protocol mismatch" alone costs a person the hour
    // it takes to find them.
    try testing.expect(std.mem.indexOf(u8, text, "4:0") != null);
    try testing.expect(std.mem.indexOf(u8, text, "4:5") != null);
}

test "a daemon that answers success to a version it does not speak is refused anyway" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // **The trap, measured.** `pcscd` refuses a client outright only when its
    // minor number is below the daemon's backward window. A client whose major
    // is wrong and whose minor is not gets `SCARD_S_SUCCESS` back, together
    // with the daemon's own numbers. A build that read the code and not the
    // numbers would carry on speaking a protocol nobody agreed to, and this is
    // the test that catches it: 9:5 is answered with success by the real
    // daemon, and this build still refuses.
    var bench = try Bench.init();
    defer bench.deinit();

    bench.driver.offered = .{ .major = 9, .minor = 5 };
    try testing.expectError(error.ProtocolMismatch, bench.driver.establish());
    try testing.expectEqual(wire.protocol_version, bench.driver.daemon_version.?);

    var said: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(&said, "{f}", .{bench.driver.failure.?});
    try testing.expect(std.mem.indexOf(u8, text, "9:5") != null);
    try testing.expect(std.mem.indexOf(u8, text, "4:5") != null);
}

test "a daemon that is not there and a daemon with no reader are different answers" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var bench = try Bench.init();
    defer bench.deinit();

    // The daemon that is there. It answers a reader list, whatever is in it.
    try bench.driver.establish();
    var names: [4096]u8 = undefined;
    _ = try bench.driver.pcsc().listReaders(&names);

    // A path in the same directory with nothing at it. **Not a guessed path**:
    // it is beside a socket this test made, so the only difference between the
    // two is whether a daemon is listening.
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const missing = try std.fmt.bufPrint(&buffer, "{s}.gone", .{bench.place.socket});

    var absent = chock_pcsc.default(testing.io);
    absent.socket_path = missing;
    defer absent.deinit();

    try testing.expectError(error.NoService, absent.establish());
    try testing.expect(absent.failure.? == .no_socket);

    // The point of the pair: a machine with no daemon and a machine with a
    // daemon and no reader must never read the same way. One is a service to
    // start and the other is a reader to plug in.
    try testing.expect(bench.driver.failure == null);
}

test "a seal is read while the transport is refusing, in the same process" {
    // **The half an auditor uses, proved on a machine whose transport says no.**
    // `seal.read`'s own comment says it needs no card, no daemon and no
    // platform branch. Now that Linux really has a transport, that claim is
    // worth a test that could fail: a driver is made, pointed at a path with no
    // daemon, and asked, all before the seal is read. If reading ever consulted
    // a transport, this is where it would show, and it would show as a machine
    // whose logs cannot be audited because a daemon is down.
    //
    // The same file is checked on Darwin, where the driver is a different one
    // and every call answers `Unavailable`, and both give the same verdict.
    var driver = chock_pcsc.default(testing.io);
    // **Only Linux has a path to point anywhere.** The Darwin driver opens
    // nothing and states no socket, so it has no such field, and naming one
    // here would stop this file compiling on the platform half its point is to
    // cover.
    if (builtin.os.tag == .linux) driver.socket_path = "/nonexistent/chock/pcscd.comm";
    defer driver.deinit();
    // Whatever it answers, it did not succeed. **Not a specific error**: this
    // is Darwin's `Unavailable` and Linux's `NoService`, and pinning either
    // here would pin the platform this test is about not caring about. It goes
    // through `Pcsc` and not through the driver's own method, because that
    // vtable is the only thing both platforms have.
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
        // A moment stated by this test, so no assertion here reads a clock.
        .{ .now_sec = 1_700_000_000 },
    );
    try testing.expectEqual(seal.Verdict.signed_software, reading.verdict);
    try testing.expect(reading.signed());

    // And the level the seal recorded is the one that signed it, so a machine
    // with no card cannot read as one that had one.
    try testing.expectEqual(seal.Level.software, sealed.level);
}

test "the socket a real installation uses is reachable, whatever it then answers" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // The one thing only the system daemon can show: that the path a real
    // installation puts its socket at is one this driver connects to. What it
    // answers afterwards belongs to the machine. On the box this was written
    // for it closes the connection, because its polkit rules refuse a client
    // whose login session is not active, and that is a fourth answer with a
    // sentence of its own rather than a failure.
    const stat = std.Io.Dir.cwd().statFile(testing.io, system_socket, .{}) catch
        return error.SkipZigTest;
    if (stat.kind != .unix_domain_socket) return error.SkipZigTest;

    var driver = chock_pcsc.default(testing.io);
    defer driver.deinit();

    driver.establish() catch |err| {
        // Every answer past a connection that opened. `NoService` is not among
        // them: the socket is there and was reached, so a build that reported
        // "no daemon" here would send somebody to start one that is running.
        switch (err) {
            error.NotAuthorized, error.ProtocolMismatch => {},
            else => return err,
        }
        try testing.expect(driver.failure != null);
        return;
    };

    // A machine whose polkit rules allow this client gets the whole thing.
    try testing.expectEqual(wire.protocol_version, driver.daemon_version.?);
    var names: [4096]u8 = undefined;
    _ = try driver.pcsc().listReaders(&names);
}
