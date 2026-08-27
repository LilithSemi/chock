//! A signature over a session log's hash chain, and the smart card that can
//! hold the key.
//!
//! `lib/chock-proto/chain.zig` says what a hash chain defeats, and says just as
//! plainly what it does not: **whoever can rewrite the whole file can hash every
//! line again and write a chain that agrees with the new text.** That was proved
//! by hand in four lines of shell. A signature over the head of the chain is
//! what makes the same rewrite useless without the key.
//!
//! It also closes a gap the chain cannot close on its own. The last event of a
//! log is unprotected, because nothing after it carries its hash. For a session
//! that has ended, that is permanent. A seal names the head, so cutting the last
//! event off changes the head and the seal no longer describes the file.
//!
//! ## What is here, and what each part needs
//!
//! | Part | Needs a card | Needs a daemon |
//! | --- | --- | --- |
//! | `seal.read`, the verifier | no | no |
//! | `sidecar`, where a seal lives | no | no |
//! | `attestation.read` | no | no |
//! | `software`, the level 3 key | no | no |
//! | `apdu`, `tlv`, `piv` | no | no |
//! | `Pcsc`, the transport | yes | yes |
//!
//! **Verification is pure Zig on every platform and takes no branch on the
//! host.** It is `std.crypto` plus a public key, and for an attestation a chain
//! of certificates. That is the half an auditor uses, and it must never need
//! hardware. No test in this module needs a card, a reader or a daemon.
//!
//! ## The three levels, and why the level is signed
//!
//! `seal.Level` has three values: a card key with an attestation, a card key
//! without one, and a software key. Chock prefers the first it can get and
//! **records which one it used**.
//!
//! A fallback that is not recorded is a silent downgrade. Anybody who can
//! unplug the card or stop the daemon would then get the weaker signature while
//! the log still said "signed". So the level sits inside the bytes the signature
//! covers, and `seal.read` reports the level it found rather than answering pass
//! or fail. See `seal.Verdict`, which has eight values and not two.
//!
//! ## No platform library is linked, and that is a decision
//!
//! PC/SC is one API on three platforms and three different libraries under it:
//! `pcsc-lite` on Linux, `PCSC.framework` on macOS, `WinSCard` on Windows. It is
//! cross platform as an API and not as a protocol, so the two platforms where a
//! daemon is preinstalled are the two where a library still has to be linked.
//!
//! **Chock links none of them.** IronStyle's pure Zig rule holds across this
//! whole repository: no `@cImport`, no `linkSystemLibrary`, no C dependency, and
//! `zig build` is the only tool a build needs. Not one line of `build.zig`
//! breaks that today, and a card reader is not the reason to be the first.
//!
//! So the platforms differ, and the reason is the platform and not the rule:
//!
//! * **Linux has a socket.** `pcscd` listens on one, and a client of it needs
//!   no library and no privilege. The protocol is private to `pcsc-lite` and
//!   version handshaked, which was reason enough to refuse it while there was
//!   no daemon to check an implementation against. There is one now, so
//!   `linux/driver.zig` speaks it, and every layout it uses is measured against
//!   a running `pcscd` rather than read out of a header alone.
//! * **macOS and Windows have a library and no socket.** `PCSC.framework` and
//!   `WinSCard` are called, not spoken to, so there is no wire format to
//!   implement and no pure Zig client to write. Those drivers answer
//!   `error.Unavailable`, which is an honest "this build has no transport",
//!   never "there is no card".
//!
//! ## What a real transport does not prove
//!
//! **The transport being real does not make the PIV layer proven.** `piv.zig`,
//! `attestation.zig` and `seal.zig` are tested against `Recorded`, and the
//! attestation fixtures are certificates this project made with Yubico shaped
//! OIDs holding invented values.
//!
//! **Measured against a real card on 2026-08-24**, through a `pcscd` 4:5 on
//! Linux with a YubiKey in the reader: the connection, the reader name, the
//! `SELECT` of the PIV application, and a `GET DATA` for the signature slot.
//! `Pcsc.transmit` therefore has been run against a card, and `apdu.zig`'s
//! framing came back the shape it says.
//!
//! **Still not proven against hardware**: a signature and an attestation. That
//! card holds no key in any PIV slot. It answered `6a 82` to every certificate
//! object, so `signDigest` and `attest` were never reached. Nothing here has
//! read an attestation a YubiKey emitted.
//!
//! ## The seam every test uses
//!
//! `Recorded` replays an exchange captured from a card. **It refuses any command
//! it does not hold a recording of**, so it can never be more permissive than a
//! real card: a change to what `piv.zig` sends fails the test rather than
//! passing it. See `Recorded.transmit`.
//!
//! ## `pcscd` and not a TPM
//!
//! A client of `pcscd` needs no privilege. `/dev/tpmrm0` is usually owned by
//! root and the `tss` group, so a TPM backed signature would need the user to
//! change group membership before Chock could sign at all. That is why this and
//! not a TPM.

const std = @import("std");
const builtin = @import("builtin");

pub const apdu = @import("chock-pcsc/apdu.zig");
pub const tlv = @import("chock-pcsc/tlv.zig");
pub const piv = @import("chock-pcsc/piv.zig");
pub const seal = @import("chock-pcsc/seal.zig");
pub const attestation = @import("chock-pcsc/attestation.zig");
pub const software = @import("chock-pcsc/software.zig");
pub const sidecar = @import("chock-pcsc/sidecar.zig");
pub const attempt = @import("chock-pcsc/attempt.zig");
pub const pin = @import("chock-pcsc/pin.zig");

/// Why a transport call did not do what was asked.
pub const Error = error{
    /// **This build has no PC/SC transport for this platform.** Never read as
    /// "there is no card" and never read as "there is no reader": nothing was
    /// asked, because there is nothing here to ask. See this file's own top
    /// comment on why no platform library is linked.
    Unavailable,
    /// The daemon is not running, or refused to give a context.
    NoService,
    /// The daemon accepted the connection and refused this client.
    ///
    /// **A daemon that is there and says no**, which is neither `NoService` nor
    /// `NoReader`: nothing is wrong with the machine, and starting a daemon
    /// that is already running fixes nothing. `pcscd` built with polkit answers
    /// this way for a client whose login session is not active. The driver
    /// keeps the sentence a person acts on: see
    /// `chock-pcsc/linux/driver.zig`'s `Failure`.
    NotAuthorized,
    /// The daemon speaks a protocol version this build does not.
    ///
    /// **A plain refusal and never a downgrade.** The version is agreed before
    /// anything else happens, and a client that carried on at whatever version
    /// the daemon named would be speaking a protocol nothing here was run
    /// against. The driver holds both numbers.
    ProtocolMismatch,
    /// The name given does not match a reader that is present.
    NoReader,
    /// The reader is there and holds no card.
    NoCard,
    /// The card left the reader in the middle of an exchange. Different from
    /// `NoCard`, which is a card that was never there: work may have been done
    /// and its answer lost.
    Removed,
    /// The buffer the caller gave is too small for the answer.
    BufferTooSmall,
    /// The transport failed for a reason a caller cannot act on differently
    /// than by giving up.
    Unexpected,
};

/// Which transmission protocol a connection settled on. A caller does not
/// choose between them, and nothing above the transport reads this: it is here
/// because a real driver has to carry it back from `connect` to `transmit`.
pub const Protocol = enum { t0, t1 };

/// A live connection to one card. Opaque above the transport: the number means
/// whatever the driver that made it wants it to mean.
pub const Handle = struct {
    value: u64,
    protocol: Protocol,
};

/// The transport. Five calls, which is the whole of PC/SC that a signature
/// needs.
///
/// This is a vtable and not a comptime parameter, the same shape `chock-io` and
/// `chock-proto/storage.zig` already use. A new platform becomes one more
/// implementation of this table rather than another arm threaded through every
/// call site, and a test can put `Recorded` in the same slot a real reader would
/// take.
pub const Pcsc = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Open a context with whatever manages readers on this platform.
        establish: *const fn (ptr: *anyopaque) Error!void,
        /// Write the names of the readers that are present into `out`, each one
        /// ended by a zero byte, and answer how many bytes were written. This is
        /// the multi string form PC/SC itself uses, so no allocator is needed
        /// here. See `ReaderList`.
        listReaders: *const fn (ptr: *anyopaque, out: []u8) Error!usize,
        /// Open a connection to the card in the named reader.
        connect: *const fn (ptr: *anyopaque, reader: []const u8) Error!Handle,
        /// Send one command and write the answer into `receive`. Answers how
        /// many bytes were written, status word included.
        transmit: *const fn (ptr: *anyopaque, handle: Handle, send: []const u8, receive: []u8) Error!usize,
        /// Close a connection. Nothing to report: a close that failed leaves
        /// the caller nothing to do about it.
        disconnect: *const fn (ptr: *anyopaque, handle: Handle) void,
    };

    pub fn establish(self: Pcsc) Error!void {
        return self.vtable.establish(self.ptr);
    }

    pub fn listReaders(self: Pcsc, out: []u8) Error!usize {
        return self.vtable.listReaders(self.ptr, out);
    }

    pub fn connect(self: Pcsc, reader: []const u8) Error!Card {
        return .{ .pcsc = self, .handle = try self.vtable.connect(self.ptr, reader) };
    }
};

/// Walks the zero separated names `Pcsc.listReaders` writes.
pub const ReaderList = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) ReaderList {
        return .{ .bytes = bytes };
    }

    /// The next name, or null at the end. An empty name ends the list, which is
    /// how PC/SC marks it, so a trailing zero byte does not become a reader
    /// with no name.
    pub fn next(self: *ReaderList) ?[]const u8 {
        if (self.pos >= self.bytes.len) return null;
        const end = std.mem.indexOfScalarPos(u8, self.bytes, self.pos, 0) orelse self.bytes.len;
        const name = self.bytes[self.pos..end];
        if (name.len == 0) {
            self.pos = self.bytes.len;
            return null;
        }
        self.pos = end + 1;
        return name;
    }
};

/// One connected card, and the exchange loop over it.
pub const Card = struct {
    pcsc: Pcsc,
    handle: Handle,

    /// The largest answer one transmit can bring back: 256 bytes of data and
    /// the two status bytes. Every command this project sends uses the short
    /// form, so a card cannot answer with more in one exchange. See
    /// `apdu.zig`'s own top comment.
    const transmit_buffer_len = apdu.max_response_data + 2;

    /// How many `GET RESPONSE` rounds one exchange may take before this gives
    /// up. A card that never stops sending `61 XX` would otherwise loop for
    /// ever. Thirty two rounds is 8192 bytes, well past the largest object a
    /// PIV card holds.
    const max_rounds = 32;

    pub const ExchangeError = Error || apdu.EncodeError || apdu.DecodeError || error{
        /// The answer is longer than the buffer the caller gave.
        AnswerTooLong,
        /// The card kept saying it had more to give past `max_rounds`.
        TooManyRounds,
    };

    /// Send one command, follow every `61 XX` with a `GET RESPONSE`, and answer
    /// the whole thing joined together with the status word that ended it.
    ///
    /// **The status word is returned and never turned into an error.** A `63 C2`
    /// carries a count of PIN tries left, and a `6a 82` says an object is not
    /// there. A caller reads those; this loop only moves bytes.
    pub fn exchange(self: Card, command: apdu.Command, out: []u8) ExchangeError!apdu.Response {
        var request: [apdu.Command.max_encoded_len]u8 = undefined;
        var scratch: [transmit_buffer_len]u8 = undefined;

        const first = try command.encode(&request);
        var written = try self.pcsc.vtable.transmit(self.pcsc.ptr, self.handle, first, &scratch);
        if (written > scratch.len) return error.Unexpected;
        var response = try apdu.decode(scratch[0..written]);

        var filled: usize = 0;
        var rounds: usize = 0;
        while (true) {
            if (filled + response.data.len > out.len) return error.AnswerTooLong;
            @memcpy(out[filled..][0..response.data.len], response.data);
            filled += response.data.len;

            const more = response.status.moreData() orelse break;
            rounds += 1;
            if (rounds > max_rounds) return error.TooManyRounds;

            const again = try apdu.getResponse(command.cla, more).encode(&request);
            written = try self.pcsc.vtable.transmit(self.pcsc.ptr, self.handle, again, &scratch);
            if (written > scratch.len) return error.Unexpected;
            response = try apdu.decode(scratch[0..written]);
        }

        return .{ .data = out[0..filled], .status = response.status };
    }

    /// The bit of the class byte that says "more of this command follows",
    /// ISO 7816-4 section 5.1.1.
    pub const chaining_bit: u8 = 0x10;

    /// Send one command whose data field may be longer than the short form can
    /// name, by command chaining, and answer what the last piece answered.
    ///
    /// **Chaining and not the extended form.** An extended length field is
    /// negotiated: a reader that does not carry it turns a 300 byte command into
    /// a failure with no useful status. Chaining is four bytes of header per
    /// piece and every card that speaks ISO 7816-4 accepts it. An RSA2048
    /// signature request is 266 bytes of body, so this is the only way that
    /// command reaches a card at all.
    ///
    /// **A card that refuses a piece stops the chain.** Carrying on would send
    /// the rest of a command the card has already thrown away, and the last
    /// piece's status would then describe the wrong thing.
    pub fn exchangeLong(self: Card, command: apdu.Command, out: []u8) ExchangeError!apdu.Response {
        if (command.data.len <= apdu.max_command_data) return self.exchange(command, out);

        var sent: usize = 0;
        while (command.data.len - sent > apdu.max_command_data) {
            const piece = apdu.Command{
                .cla = command.cla | chaining_bit,
                .ins = command.ins,
                .p1 = command.p1,
                .p2 = command.p2,
                .data = command.data[sent..][0..apdu.max_command_data],
            };
            const answer = try self.exchange(piece, out);
            if (!answer.status.ok()) return answer;
            sent += apdu.max_command_data;
        }

        return self.exchange(.{
            .cla = command.cla,
            .ins = command.ins,
            .p1 = command.p1,
            .p2 = command.p2,
            .data = command.data[sent..],
            .expect = command.expect,
        }, out);
    }

    pub fn disconnect(self: Card) void {
        self.pcsc.vtable.disconnect(self.pcsc.ptr, self.handle);
    }
};

/// Chosen once, at compile time, from `builtin.os.tag`. Only the branch that
/// matches the real build target is imported, the same rule `chock-io` and
/// `chock-sandbox` follow.
const driver_impl = switch (builtin.os.tag) {
    .linux => @import("chock-pcsc/linux/driver.zig"),
    .macos => @import("chock-pcsc/darwin/driver.zig"),
    else => @compileError("chock-pcsc: no driver for target os " ++ @tagName(builtin.os.tag)),
};

/// The transport for whichever platform this binary was built for.
///
/// **It holds a connection, so the caller holds it and it must not move.**
/// `Pcsc.ptr` points at it. `deinit` closes whatever was opened and is safe on
/// a driver that opened nothing, which is what makes the two lines a caller
/// writes the same on every platform.
///
/// On Linux this speaks `pcscd`'s socket. On Darwin every call answers
/// `error.Unavailable`: see `chock-pcsc/darwin/driver.zig` for that platform's
/// own reason, which is not the same as the one Linux used to give.
pub const Driver = driver_impl.Driver;

/// The platform driver's own module, for the one caller that has to name
/// something inside it.
///
/// **Only the platform that was built for.** A Linux build reaches
/// `platform.wire` and `platform.Failure`; a Darwin build has neither,
/// because a driver that opens nothing states no wire format and has no failure
/// to describe. Anything that reads this is Linux only by construction, which
/// is the same rule `chock-sandbox` and `chock-io` keep for their drivers.
pub const platform = driver_impl;

/// A driver for this platform, over `io`.
pub fn default(io: std.Io) Driver {
    return Driver.init(io);
}

/// One command and the answer a card gave to it, captured together.
pub const Exchange = struct {
    /// The command bytes, exactly as they went to the card.
    send: []const u8,
    /// The answer bytes, status word included, exactly as they came back.
    receive: []const u8,
};

/// Replays a captured exchange with no card, no reader and no daemon. This is
/// the seam every test in this module uses.
///
/// **It refuses a command it has no recording of.** A stand-in that answered
/// anything plausible would be more permissive than a real card, and a change
/// to what `piv.zig` sends would then still pass. Here it fails, and the
/// failure names the command that was not expected. That is the whole point of
/// recording rather than faking.
///
/// It also plays the exchanges in the order they were captured, because the
/// order is part of what was recorded: a PIN given after a signature is a
/// different session from a PIN given before one.
pub const Recorded = struct {
    exchanges: []const Exchange,
    reader_name: []const u8 = "Recorded Reader 00 00",
    /// How many exchanges have been played. A test reads this to prove every
    /// recorded step was reached, so a flow that stopped early cannot pass.
    played: usize = 0,
    established: bool = false,
    connected: bool = false,

    pub fn pcsc(self: *Recorded) Pcsc {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Whether every recorded exchange was played. A test that asserts on an
    /// answer and not on this can pass while skipping the steps that come after
    /// the one it read.
    pub fn drained(self: *const Recorded) bool {
        return self.played == self.exchanges.len;
    }

    fn establishFn(ptr: *anyopaque) Error!void {
        const self: *Recorded = @ptrCast(@alignCast(ptr));
        self.established = true;
    }

    fn listReadersFn(ptr: *anyopaque, out: []u8) Error!usize {
        const self: *Recorded = @ptrCast(@alignCast(ptr));
        if (!self.established) return error.NoService;
        if (out.len < self.reader_name.len + 1) return error.BufferTooSmall;
        @memcpy(out[0..self.reader_name.len], self.reader_name);
        out[self.reader_name.len] = 0;
        return self.reader_name.len + 1;
    }

    fn connectFn(ptr: *anyopaque, reader: []const u8) Error!Handle {
        const self: *Recorded = @ptrCast(@alignCast(ptr));
        if (!self.established) return error.NoService;
        if (!std.mem.eql(u8, reader, self.reader_name)) return error.NoReader;
        self.connected = true;
        return .{ .value = 1, .protocol = .t1 };
    }

    fn transmitFn(ptr: *anyopaque, handle: Handle, send: []const u8, receive: []u8) Error!usize {
        const self: *Recorded = @ptrCast(@alignCast(ptr));
        if (!self.connected or handle.value != 1) return error.NoCard;
        if (self.played >= self.exchanges.len) return error.Unexpected;
        const expected = self.exchanges[self.played];
        // Byte for byte, and never a prefix. A command that agreed on its
        // header and differed in its data would be a different command.
        if (!std.mem.eql(u8, send, expected.send)) return error.Unexpected;
        if (receive.len < expected.receive.len) return error.BufferTooSmall;
        @memcpy(receive[0..expected.receive.len], expected.receive);
        self.played += 1;
        return expected.receive.len;
    }

    fn disconnectFn(ptr: *anyopaque, handle: Handle) void {
        const self: *Recorded = @ptrCast(@alignCast(ptr));
        _ = handle;
        self.connected = false;
    }

    const vtable = Pcsc.VTable{
        .establish = establishFn,
        .listReaders = listReadersFn,
        .connect = connectFn,
        .transmit = transmitFn,
        .disconnect = disconnectFn,
    };
};

const testing = std.testing;

test "a platform with no transport answers Unavailable, which is not no card" {
    // The honest answer a build with no transport gives. A caller that read
    // `Unavailable` as "there is no card" would fall back to a software key on
    // a machine with a card in the reader, and record the fallback as if the
    // card had been tried. The two are different errors so that cannot happen
    // quietly.
    //
    // **Linux has a transport now, so this is not true of it**, and asserting
    // it there would pin the opposite of what that driver does. On Linux the
    // same call reaches a socket: see `chock-pcsc/linux/driver.zig`'s own
    // tests, which pin four different answers for four different machines.
    if (builtin.os.tag == .linux) return error.SkipZigTest;

    var driver = default(std.testing.io);
    defer driver.deinit();
    const transport = driver.pcsc();

    try testing.expectError(error.Unavailable, transport.establish());
    var names: [256]u8 = undefined;
    try testing.expectError(error.Unavailable, transport.listReaders(&names));
    try testing.expectError(error.Unavailable, transport.connect("any reader"));
}

test "the errors a caller must not read as one another" {
    // Five different facts, five different values, and no two of them equal.
    // The whole reason `Error` has this many members is that a caller acts
    // differently on each: `Unavailable` is a build with no transport,
    // `NoService` is a daemon that is not there, `NotAuthorized` is a daemon
    // that said no, `NoReader` is a machine with nothing plugged in, and
    // `NoCard` is a reader with an empty slot.
    const all = [_]Error{
        error.Unavailable,
        error.NoService,
        error.NotAuthorized,
        error.ProtocolMismatch,
        error.NoReader,
        error.NoCard,
    };
    for (all, 0..) |a, i| {
        for (all[i + 1 ..]) |b| try testing.expect(a != b);
    }
}

test "the recorded transport refuses a command it has no recording of" {
    // The property that keeps this stand-in from being more permissive than a
    // real card. A build that changed one byte of an APDU fails here.
    var recorded = Recorded{ .exchanges = &.{
        .{ .send = &.{ 0x00, 0xa4, 0x04, 0x00 }, .receive = &.{ 0x90, 0x00 } },
    } };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);

    var out: [8]u8 = undefined;
    try testing.expectError(error.Unexpected, card.exchange(
        .{ .cla = 0x00, .ins = 0xa4, .p1 = 0x04, .p2 = 0x01 },
        &out,
    ));
    // And the exchange that was recorded really does play, so the refusal
    // above is about the command and not about the transport being broken.
    const answer = try card.exchange(.{ .cla = 0x00, .ins = 0xa4, .p1 = 0x04, .p2 = 0x00 }, &out);
    try testing.expect(answer.status.ok());
    try testing.expect(recorded.drained());
}

test "the recorded transport refuses to transmit before a connect" {
    var recorded = Recorded{ .exchanges = &.{} };
    const transport = recorded.pcsc();
    // A list before an establish is refused too: a context comes first.
    var names: [64]u8 = undefined;
    try testing.expectError(error.NoService, transport.listReaders(&names));
    try testing.expectError(error.NoService, transport.connect(recorded.reader_name));

    try transport.establish();
    try testing.expectError(error.NoReader, transport.connect("Some Other Reader"));
}

test "a reader list is walked by its zero bytes, and the empty name ends it" {
    var recorded = Recorded{ .exchanges = &.{} };
    const transport = recorded.pcsc();
    try transport.establish();

    var names: [64]u8 = undefined;
    const written = try transport.listReaders(&names);
    var list = ReaderList.init(names[0..written]);
    try testing.expectEqualStrings(recorded.reader_name, list.next().?);
    try testing.expectEqual(@as(?[]const u8, null), list.next());

    // The double zero PC/SC ends a real list with must not read as a reader
    // whose name is empty.
    var terminated = ReaderList.init("one\x00two\x00\x00");
    try testing.expectEqualStrings("one", terminated.next().?);
    try testing.expectEqualStrings("two", terminated.next().?);
    try testing.expectEqual(@as(?[]const u8, null), terminated.next());
}

test "a listReaders buffer too small is refused rather than cut short" {
    var recorded = Recorded{ .exchanges = &.{} };
    const transport = recorded.pcsc();
    try transport.establish();
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, transport.listReaders(&tiny));
}

test "an exchange follows 61 XX until the card stops, and joins the pieces in order" {
    // The loop that reads a certificate off a card. A build that kept only the
    // first answer would get the first 256 bytes of a certificate and no more.
    var recorded = Recorded{
        .exchanges = &.{
            // The command, answered with two bytes and "three more waiting".
            .{ .send = &.{ 0x00, 0xcb, 0x3f, 0xff, 0x00 }, .receive = &.{ 0xaa, 0xbb, 0x61, 0x03 } },
            // GET RESPONSE for three, answered with two and "one more waiting".
            .{ .send = &.{ 0x00, 0xc0, 0x00, 0x00, 0x03 }, .receive = &.{ 0xcc, 0xdd, 0x61, 0x01 } },
            // GET RESPONSE for one, answered with one and success.
            .{ .send = &.{ 0x00, 0xc0, 0x00, 0x00, 0x01 }, .receive = &.{ 0xee, 0x90, 0x00 } },
        },
    };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);

    var out: [64]u8 = undefined;
    const answer = try card.exchange(
        .{ .cla = 0x00, .ins = 0xcb, .p1 = 0x3f, .p2 = 0xff, .expect = 256 },
        &out,
    );
    try testing.expect(answer.status.ok());
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee }, answer.data);
    try testing.expect(recorded.drained());
}

test "an exchange that answers a failing status returns it rather than erroring" {
    // A `63 C2` carries a fact the caller needs: two tries at the PIN are left.
    // Turning that into an error would throw the count away.
    var recorded = Recorded{ .exchanges = &.{
        .{ .send = &.{ 0x00, 0x20, 0x00, 0x80 }, .receive = &.{ 0x63, 0xc2 } },
    } };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);

    var out: [8]u8 = undefined;
    const answer = try card.exchange(.{ .cla = 0x00, .ins = 0x20, .p1 = 0x00, .p2 = 0x80 }, &out);
    try testing.expect(!answer.status.ok());
    try testing.expectEqual(@as(?u4, 2), answer.status.pinRetriesLeft());
}

test "an answer longer than the caller's buffer is refused, never written past" {
    var recorded = Recorded{ .exchanges = &.{
        .{ .send = &.{ 0x00, 0xcb, 0x3f, 0xff, 0x00 }, .receive = &.{ 0x01, 0x02, 0x03, 0x90, 0x00 } },
    } };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);

    var small: [2]u8 = undefined;
    try testing.expectError(error.AnswerTooLong, card.exchange(
        .{ .cla = 0x00, .ins = 0xcb, .p1 = 0x3f, .p2 = 0xff, .expect = 256 },
        &small,
    ));
}

test "a card that never stops offering more data is given up on" {
    // A bound on a loop driven by an external device. Without it, a card that
    // always answers `61 01` holds the process for ever.
    const forever = [_]Exchange{
        .{ .send = &.{ 0x00, 0xc0, 0x00, 0x00, 0x01 }, .receive = &.{ 0x00, 0x61, 0x01 } },
    } ** (Card.max_rounds + 2);
    var all: [1 + forever.len]Exchange = undefined;
    all[0] = .{ .send = &.{ 0x00, 0xcb, 0x3f, 0xff, 0x00 }, .receive = &.{ 0x00, 0x61, 0x01 } };
    @memcpy(all[1..], &forever);

    var recorded = Recorded{ .exchanges = &all };
    const transport = recorded.pcsc();
    try transport.establish();
    const card = try transport.connect(recorded.reader_name);

    var out: [256]u8 = undefined;
    try testing.expectError(error.TooManyRounds, card.exchange(
        .{ .cla = 0x00, .ins = 0xcb, .p1 = 0x3f, .p2 = 0xff, .expect = 256 },
        &out,
    ));
}

test {
    testing.refAllDecls(@This());
}
