//! The call ABI: guest runs one tool, answer at an address.

const std = @import("std");

pub const call_symbol = "chock_plugin_call";

pub const arguments_symbol = "chock_plugin_arguments";

pub const no_answer: usize = 0;

pub const Outcome = enum(u32) {
    success = 0,
    failure = 1,

    pub fn fromWord(word: u32) ?Outcome {
        return std.enums.fromInt(Outcome, word);
    }
};

pub const max_result_bytes: usize = 1 << 20;

pub const Answer = struct {
    outcome: Outcome,
    text_ptr: u32,
    text_len: u32,

    pub const outcome_offset = 0;
    pub const text_ptr_offset = 4;
    pub const text_len_offset = 8;
    pub const len = 12;
};

pub const AnswerError = error{
    AnswerOutOfBounds,
    UnknownOutcome,
    TextOutOfBounds,
};

pub fn readAnswer(memory: []const u8, address: usize) AnswerError!Answer {
    const end = std.math.add(usize, address, Answer.len) catch
        return error.AnswerOutOfBounds;
    if (end > memory.len) return error.AnswerOutOfBounds;

    const record = memory[address..][0..Answer.len];
    const word = std.mem.readInt(u32, record[Answer.outcome_offset..][0..4], .little);
    const outcome = Outcome.fromWord(word) orelse return error.UnknownOutcome;
    const text_ptr = std.mem.readInt(u32, record[Answer.text_ptr_offset..][0..4], .little);
    const text_len = std.mem.readInt(u32, record[Answer.text_len_offset..][0..4], .little);

    if (text_len > max_result_bytes) return error.TextOutOfBounds;
    const text_end = std.math.add(usize, text_ptr, text_len) catch
        return error.TextOutOfBounds;
    if (text_end > memory.len) return error.TextOutOfBounds;

    return .{ .outcome = outcome, .text_ptr = text_ptr, .text_len = text_len };
}

pub fn textOf(memory: []const u8, answer: Answer) []const u8 {
    return memory[answer.text_ptr..][0..answer.text_len];
}

pub fn writeAnswer(record: *[Answer.len]u8, outcome: Outcome, text: []const u8) void {
    std.mem.writeInt(
        u32,
        record[Answer.outcome_offset..][0..4],
        @intFromEnum(outcome),
        .little,
    );
    std.mem.writeInt(
        u32,
        record[Answer.text_ptr_offset..][0..4],
        @truncate(@intFromPtr(text.ptr)),
        .little,
    );
    std.mem.writeInt(
        u32,
        record[Answer.text_len_offset..][0..4],
        @truncate(text.len),
        .little,
    );
}

const testing = std.testing;

fn withAnswer(memory: []u8, at: usize, outcome: u32, text_ptr: u32, text_len: u32) void {
    std.mem.writeInt(u32, memory[at + Answer.outcome_offset ..][0..4], outcome, .little);
    std.mem.writeInt(u32, memory[at + Answer.text_ptr_offset ..][0..4], text_ptr, .little);
    std.mem.writeInt(u32, memory[at + Answer.text_len_offset ..][0..4], text_len, .little);
}

test "an answer a guest wrote reads back with its text" {
    var memory: [128]u8 = @splat(0);
    @memcpy(memory[64..][0..5], "hello");
    withAnswer(&memory, 16, @intFromEnum(Outcome.success), 64, 5);

    const answer = try readAnswer(&memory, 16);
    try testing.expectEqual(Outcome.success, answer.outcome);
    try testing.expectEqualStrings("hello", textOf(&memory, answer));
}

test "a text address past the end of the guest's memory is refused, not read" {
    var memory: [128]u8 = @splat(0);
    withAnswer(&memory, 16, @intFromEnum(Outcome.success), 120, 64);
    try testing.expectError(error.TextOutOfBounds, readAnswer(&memory, 16));

    withAnswer(&memory, 16, @intFromEnum(Outcome.success), 4096, 0);
    try testing.expectError(error.TextOutOfBounds, readAnswer(&memory, 16));
}

test "an address that wraps when the record is added to it is refused" {
    var memory: [128]u8 = @splat(0);
    try testing.expectError(
        error.AnswerOutOfBounds,
        readAnswer(&memory, std.math.maxInt(usize) - 4),
    );
    withAnswer(&memory, 16, @intFromEnum(Outcome.success), std.math.maxInt(u32), 8);
    try testing.expectError(error.TextOutOfBounds, readAnswer(&memory, 16));
}

test "a record that does not fit inside the guest's memory is refused" {
    var memory: [128]u8 = @splat(0);
    try testing.expectError(error.AnswerOutOfBounds, readAnswer(&memory, 120));
    try testing.expectError(error.AnswerOutOfBounds, readAnswer(&memory, 117));
    withAnswer(&memory, 116, @intFromEnum(Outcome.success), 0, 0);
    _ = try readAnswer(&memory, 116);
}

test "an outcome word this ABI does not have is refused rather than read as a failure" {
    var memory: [128]u8 = @splat(0);
    withAnswer(&memory, 16, 7, 0, 0);
    try testing.expectError(error.UnknownOutcome, readAnswer(&memory, 16));
}

test "a text longer than this ABI carries is refused before it is measured against memory" {
    const memory = try testing.allocator.alloc(u8, (max_result_bytes * 2) + 64);
    defer testing.allocator.free(memory);
    @memset(memory, 0);
    withAnswer(memory, 16, @intFromEnum(Outcome.success), 64, max_result_bytes + 1);
    try testing.expectError(error.TextOutOfBounds, readAnswer(memory, 16));
}

test "what a guest writes is what a host reads" {
    var memory: [256]u8 = @splat(0);
    @memcpy(memory[128..][0..5], "hi yo");

    var record: [Answer.len]u8 align(4) = @splat(0);
    writeAnswer(&record, .failure, memory[128..][0..5]);
    std.mem.writeInt(u32, record[Answer.text_ptr_offset..][0..4], 128, .little);
    @memcpy(memory[16..][0..Answer.len], &record);

    const answer = try readAnswer(&memory, 16);
    try testing.expectEqual(Outcome.failure, answer.outcome);
    try testing.expectEqual(@as(u32, 5), answer.text_len);
    try testing.expectEqualStrings("hi yo", textOf(&memory, answer));
}

test "the record is three words and the offsets do not overlap" {
    try testing.expectEqual(@as(usize, 12), Answer.len);
    try testing.expectEqual(@as(usize, 0), Answer.outcome_offset);
    try testing.expectEqual(@as(usize, 4), Answer.text_ptr_offset);
    try testing.expectEqual(@as(usize, 8), Answer.text_len_offset);
}
