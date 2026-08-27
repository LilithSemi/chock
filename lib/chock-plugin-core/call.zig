//! The call ABI: how a host asks a guest to run one tool, and how the answer
//! comes back out of the guest's own memory.
//!
//! `lib/chock-plugin-core/wire.zig` is the discovery format, read with no
//! engine at all. This file is the other half, and it is the only part of a
//! plugin that runs. Both sides read the constants here, so a host and a guest
//! can never disagree about where an answer is.
//!
//! ## One exported function, and an answer at an address
//!
//! ```text
//! chock_plugin_call(index, args_ptr, args_len) -> address
//! ```
//!
//! `index` is the tool's position in the metadata's own tool list, which the
//! host already read and already bounded. **A number and not a name**: a name
//! would mean the host writes a string into the guest's memory before the
//! guest has run, and the host has no allocator in there.
//!
//! The answer is `Answer.len` bytes at the address the call returns: an
//! outcome, then the address and the length of the text. Zero means the guest
//! bound no tool at that index.
//!
//! ## Every field of the answer is a number a hostile guest chose
//!
//! **This is the whole reason `readAnswer` exists.** The engine this project
//! has bounds checks nothing: measured on Vulcan 2026-08-22, `memPtr` is
//! `mem_base + addr + offset` with no check at all. So a guest that answers an
//! address of four billion, or a length longer than its own memory, gets a
//! refusal here rather than a read of whatever sits after the host process's
//! linear memory.
//!
//! `readAnswer` takes the guest's memory as a slice and checks every field
//! against that slice's own length. It is in this library, and not in the
//! host, so the guest side and the host side are read from one file.

const std = @import("std");

/// The guest symbol a host calls to run one tool.
///
/// Separate from `init_symbol`, which binds the table and answers how many
/// tools it bound. A host calls that one first, one time, and this one per
/// call.
pub const call_symbol = "chock_plugin_call";

/// The guest symbol that answers where a host may write the argument text.
///
/// **A function and not a data symbol**, unlike the metadata blob. A buffer of
/// zeros lands in `.bss`, which has no data segment at all, and
/// `lib/chock-core/plugin_module.zig` resolves a data symbol's address through
/// the module's own data segments. So a host could not find this by reading
/// the file, and it does not need to: by the time it wants to write arguments
/// it has already read the metadata and already decided to load the plugin, so
/// calling a function is free.
///
/// It takes the length the host wants to write and answers zero when that does
/// not fit, so **the guest owns the bound on its own buffer** and the host
/// never has to know how big it is.
pub const arguments_symbol = "chock_plugin_arguments";

/// What the address zero means: the guest bound no tool at the index it was
/// asked for. **Zero and not a negative number**, because a wasm32 address is
/// unsigned and address zero is where a linker puts nothing.
pub const no_answer: usize = 0;

/// Whether a tool did the thing it was asked to do. The numbers are the ABI,
/// so they never change inside one `AbiVersion`.
pub const Outcome = enum(u32) {
    success = 0,
    failure = 1,

    /// The outcome one word names, or null when the guest wrote a number this
    /// ABI does not have. **Null and not `failure`**: a guest whose answer
    /// this host cannot read has not failed, it has misbehaved, and the two
    /// read differently to the person looking at the session.
    pub fn fromWord(word: u32) ?Outcome {
        return std.enums.fromInt(Outcome, word);
    }
};

/// The longest answer a guest may give.
///
/// Every byte of it is copied out of the guest and put in front of the model,
/// so this is the same kind of bound `chock_core.mcp.max_result_bytes` keeps
/// and it is above it: what reaches the model is cut separately, by the host,
/// and this one only stops a guest from naming a length that is a denial of
/// service on its own.
pub const max_result_bytes: usize = 1 << 20;

/// The record a guest leaves behind, and where each field is in it.
///
/// Three little endian `u32`s, whatever the host's own word size is. **The
/// widths are the guest's and never the host's**: a plugin is a wasm32 module,
/// so an address in it is four bytes, and a host that read its own `usize`
/// here would read two fields as one on a 64 bit machine.
pub const Answer = struct {
    outcome: Outcome,
    /// Where the text is, in the guest's own memory.
    text_ptr: u32,
    /// How long the text is.
    text_len: u32,

    pub const outcome_offset = 0;
    pub const text_ptr_offset = 4;
    pub const text_len_offset = 8;
    /// How many bytes the record is.
    pub const len = 12;
};

/// Why an answer could not be read out of a guest. Each one names a number the
/// guest wrote, so a person reading the session learns which plugin lied and
/// about what.
pub const AnswerError = error{
    /// The record itself does not fit inside the guest's memory.
    AnswerOutOfBounds,
    /// The outcome word is not one this ABI has.
    UnknownOutcome,
    /// The text runs past the end of the guest's memory, or is longer than
    /// `max_result_bytes`.
    TextOutOfBounds,
};

/// Read the answer at `address` out of `memory`, which is the guest's whole
/// linear memory.
///
/// **Nothing here trusts a number.** `address`, the text address and the text
/// length all come from a module somebody else wrote, and the engine that ran
/// it checked none of them. Every one is measured against `memory.len` with
/// arithmetic that cannot wrap, so the worst a hostile guest gets is a named
/// refusal.
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

/// The text one answer names, inside the guest's memory. Only call this with
/// an `Answer` that `readAnswer` produced from the same `memory`, which is
/// what makes this slice safe.
pub fn textOf(memory: []const u8, answer: Answer) []const u8 {
    return memory[answer.text_ptr..][0..answer.text_len];
}

/// Write one answer into `record`, which is `Answer.len` bytes. The guest side
/// of `readAnswer`, kept here so the two are read together.
///
/// **The address is truncated to four bytes, and on the one target this runs
/// on that loses nothing**: a plugin is a wasm32 module, where a pointer is
/// already four bytes. A host build of the same code truncates a real 64 bit
/// address, which is why nothing on the host side ever reads a record this
/// function produced. See the test at the end of this file.
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

/// A guest memory with one answer in it, built by hand.
fn withAnswer(memory: []u8, at: usize, outcome: u32, text_ptr: u32, text_len: u32) void {
    std.mem.writeInt(u32, memory[at + Answer.outcome_offset ..][0..4], outcome, .little);
    std.mem.writeInt(u32, memory[at + Answer.text_ptr_offset ..][0..4], text_ptr, .little);
    std.mem.writeInt(u32, memory[at + Answer.text_len_offset ..][0..4], text_len, .little);
}

test "an answer a guest wrote reads back with its text" {
    // The positive control. Everything below is about the numbers that are not
    // this one.
    var memory: [128]u8 = @splat(0);
    @memcpy(memory[64..][0..5], "hello");
    withAnswer(&memory, 16, @intFromEnum(Outcome.success), 64, 5);

    const answer = try readAnswer(&memory, 16);
    try testing.expectEqual(Outcome.success, answer.outcome);
    try testing.expectEqualStrings("hello", textOf(&memory, answer));
}

test "a text address past the end of the guest's memory is refused, not read" {
    // The fault this file exists for. Vulcan bounds checks nothing, so a guest
    // that names an address past its own memory would otherwise have the host
    // read whatever the allocator put after it.
    //
    // Mutation check: drop the `text_end > memory.len` test and `textOf`
    // slices past the end of the allocation.
    var memory: [128]u8 = @splat(0);
    withAnswer(&memory, 16, @intFromEnum(Outcome.success), 120, 64);
    try testing.expectError(error.TextOutOfBounds, readAnswer(&memory, 16));

    // And an address that is past the end on its own, with a zero length.
    withAnswer(&memory, 16, @intFromEnum(Outcome.success), 4096, 0);
    try testing.expectError(error.TextOutOfBounds, readAnswer(&memory, 16));
}

test "an address that wraps when the record is added to it is refused" {
    // The other way past a bound: a number so large that `address + 12`
    // overflows back into the memory. Checked arithmetic is what makes the
    // refusal happen rather than a read at a small address.
    //
    // Mutation check: write `address + Answer.len` unchecked and this test
    // reads the record at the start of memory instead of refusing.
    var memory: [128]u8 = @splat(0);
    try testing.expectError(
        error.AnswerOutOfBounds,
        readAnswer(&memory, std.math.maxInt(usize) - 4),
    );
    // And a text length that wraps the same way.
    withAnswer(&memory, 16, @intFromEnum(Outcome.success), std.math.maxInt(u32), 8);
    try testing.expectError(error.TextOutOfBounds, readAnswer(&memory, 16));
}

test "a record that does not fit inside the guest's memory is refused" {
    var memory: [128]u8 = @splat(0);
    try testing.expectError(error.AnswerOutOfBounds, readAnswer(&memory, 120));
    // One byte short of fitting, which is the boundary the check is on.
    try testing.expectError(error.AnswerOutOfBounds, readAnswer(&memory, 117));
    withAnswer(&memory, 116, @intFromEnum(Outcome.success), 0, 0);
    _ = try readAnswer(&memory, 116);
}

test "an outcome word this ABI does not have is refused rather than read as a failure" {
    // A guest whose answer cannot be read has not failed, it has misbehaved,
    // and the two read differently to the person looking at the session.
    var memory: [128]u8 = @splat(0);
    withAnswer(&memory, 16, 7, 0, 0);
    try testing.expectError(error.UnknownOutcome, readAnswer(&memory, 16));
}

test "a text longer than this ABI carries is refused before it is measured against memory" {
    // A guest with a large memory could otherwise name a length that is a
    // denial of service on its own: every byte is copied out and put in front
    // of the model.
    const memory = try testing.allocator.alloc(u8, (max_result_bytes * 2) + 64);
    defer testing.allocator.free(memory);
    @memset(memory, 0);
    withAnswer(memory, 16, @intFromEnum(Outcome.success), 64, max_result_bytes + 1);
    try testing.expectError(error.TextOutOfBounds, readAnswer(memory, 16));
}

test "what a guest writes is what a host reads" {
    // The two halves of the ABI, against each other. A record written by the
    // guest side and read by the host side must agree field for field, or the
    // outcome and the length swap places the first time one side changes.
    //
    // The address a guest writes is an address in its own linear memory, and
    // this test runs on the host, so the record is written here and then the
    // address field is set to where the text really is in this test's own
    // buffer. Everything else crosses unchanged.
    var memory: [256]u8 = @splat(0);
    @memcpy(memory[128..][0..5], "hi yo");

    var record: [Answer.len]u8 align(4) = @splat(0);
    writeAnswer(&record, .failure, memory[128..][0..5]);
    // The one field a host build cannot produce truthfully: a wasm32 guest
    // address. Every other field is the guest's own.
    std.mem.writeInt(u32, record[Answer.text_ptr_offset..][0..4], 128, .little);
    @memcpy(memory[16..][0..Answer.len], &record);

    const answer = try readAnswer(&memory, 16);
    try testing.expectEqual(Outcome.failure, answer.outcome);
    try testing.expectEqual(@as(u32, 5), answer.text_len);
    try testing.expectEqualStrings("hi yo", textOf(&memory, answer));
}

test "the record is three words and the offsets do not overlap" {
    // The layout is the ABI. A field that moved would make every plugin built
    // before the move answer nonsense, which is what the ABI version in
    // `chock_plugin_magic` is for.
    try testing.expectEqual(@as(usize, 12), Answer.len);
    try testing.expectEqual(@as(usize, 0), Answer.outcome_offset);
    try testing.expectEqual(@as(usize, 4), Answer.text_ptr_offset);
    try testing.expectEqual(@as(usize, 8), Answer.text_len_offset);
}
