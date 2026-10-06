//! Signatures over session logs using smart cards or software keys.

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

pub const Error = error{
    Unavailable,
    NoService,
    NotAuthorized,
    ProtocolMismatch,
    NoReader,
    NoCard,
    Removed,
    BufferTooSmall,
    Unexpected,
};

pub const Protocol = enum { t0, t1 };

pub const Handle = struct {
    value: u64,
    protocol: Protocol,
};

pub const Pcsc = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        establish: *const fn (ptr: *anyopaque) Error!void,
        listReaders: *const fn (ptr: *anyopaque, out: []u8) Error!usize,
        connect: *const fn (ptr: *anyopaque, reader: []const u8) Error!Handle,
        transmit: *const fn (ptr: *anyopaque, handle: Handle, send: []const u8, receive: []u8) Error!usize,
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

pub const ReaderList = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) ReaderList {
        return .{ .bytes = bytes };
    }

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

pub const Card = struct {
    pcsc: Pcsc,
    handle: Handle,

    const transmit_buffer_len = apdu.max_response_data + 2;

    const max_rounds = 32;

    pub const ExchangeError = Error || apdu.EncodeError || apdu.DecodeError || error{
        AnswerTooLong,
        TooManyRounds,
    };

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

    pub const chaining_bit: u8 = 0x10;

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

const driver_impl = switch (builtin.os.tag) {
    .linux => @import("chock-pcsc/linux/driver.zig"),
    .macos => @import("chock-pcsc/darwin/driver.zig"),
    else => @compileError("chock-pcsc: no driver for target os " ++ @tagName(builtin.os.tag)),
};

pub const Driver = driver_impl.Driver;

pub const platform = driver_impl;

pub fn default(io: std.Io) Driver {
    return Driver.init(io);
}

pub const Exchange = struct {
    send: []const u8,
    receive: []const u8,
};

pub const Recorded = struct {
    exchanges: []const Exchange,
    reader_name: []const u8 = "Recorded Reader 00 00",
    played: usize = 0,
    established: bool = false,
    connected: bool = false,

    pub fn pcsc(self: *Recorded) Pcsc {
        return .{ .ptr = self, .vtable = &vtable };
    }

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
    const answer = try card.exchange(.{ .cla = 0x00, .ins = 0xa4, .p1 = 0x04, .p2 = 0x00 }, &out);
    try testing.expect(answer.status.ok());
    try testing.expect(recorded.drained());
}

test "the recorded transport refuses to transmit before a connect" {
    var recorded = Recorded{ .exchanges = &.{} };
    const transport = recorded.pcsc();
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
    var recorded = Recorded{
        .exchanges = &.{
            .{ .send = &.{ 0x00, 0xcb, 0x3f, 0xff, 0x00 }, .receive = &.{ 0xaa, 0xbb, 0x61, 0x03 } },
            .{ .send = &.{ 0x00, 0xc0, 0x00, 0x00, 0x03 }, .receive = &.{ 0xcc, 0xdd, 0x61, 0x01 } },
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
