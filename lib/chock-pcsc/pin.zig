//! Asking a person for a card PIN, and the rules that stop the asking from

const std = @import("std");
const piv = @import("piv.zig");

pub const max_pin_bytes = 64;

pub const Buffer = [max_pin_bytes]u8;

pub const Tries = piv.Tries;

pub const Question = struct {
    reader: []const u8,
    slot: piv.Slot,
    tries: Tries,
};

pub const Answer = union(enum) {
    pin: []const u8,
    nobody,
    declined,
    unreadable,
    too_long,
};

pub const Asker = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        ask: *const fn (ptr: *anyopaque, question: Question, out: *Buffer) Answer,
    };

    pub fn ask(self: Asker, question: Question, out: *Buffer) Answer {
        return self.vtable.ask(self.ptr, question, out);
    }
};

pub fn wipe(buffer: *Buffer) void {
    std.crypto.secureZero(u8, buffer);
}

// The question a person is shown holds no answer, and there is no shape for one to arrive in. This fails the build if a field appears that could carry one, the same guard chock-broker/askpass.zig keeps over its own log record.
comptime {
    const forbidden = [_][]const u8{ "pin", "secret", "password", "answer", "value", "code" };
    for (@typeInfo(Question).@"struct".fields) |field| {
        for (forbidden) |bad| {
            if (std.mem.indexOf(u8, field.name, bad) != null) {
                @compileError("a PIN question must not hold the answer: " ++ field.name);
            }
        }
    }
}

const testing = std.testing;

test "a count of zero tries left is the same fact as blocked" {
    try testing.expectEqual(@as(?u4, 0), (Tries{ .blocked = {} }).count());
    try testing.expectEqual(@as(?u4, 3), (Tries{ .left = 3 }).count());
    try testing.expectEqual(@as(?u4, null), (Tries{ .unknown = {} }).count());
    try testing.expectEqual(@as(?u4, null), (Tries{ .verified = {} }).count());
}

test "the buffer is longer than any PIN a card accepts" {
    try testing.expect(max_pin_bytes > piv.pin_field_len);
    var buffer: Buffer = [_]u8{'7'} ** max_pin_bytes;
    wipe(&buffer);
    for (buffer) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test {
    testing.refAllDecls(@This());
}
