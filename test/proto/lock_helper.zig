//! A real second process for the log lock test. test/proto/lock.zig starts this
//! program, and build.zig passes its path to that test. flock locks an open file
//! description and not a path, so only a second process can prove the lock holds.
//!
//! Protocol over the caller's pipes: take the lock, write one byte to standard
//! output, block on one byte from standard input, then close and exit 0. The
//! caller must not try its own lock before the ready byte arrives.
//!
//! Exit codes:
//!   0 - the lock was taken and later released in the order above.
//!   3 - opening the log failed.
//!   4 - taking the lock failed.
//!   5 - the ready byte could not be sent.

const std = @import("std");
const chock_proto = @import("chock-proto");

pub fn main(init: std.process.Init.Minimal) !u8 {
    // `Init.Minimal` carries no `Io`, so this process builds its own.
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.args.toSlice(arena);
    if (args.len != 2) {
        std.debug.print("usage: lock-helper <log-path>\n", .{});
        return 2;
    }
    const path = arena.dupeZ(u8, args[1]) catch |err| {
        std.debug.print("lock-helper: could not copy the path: {s}\n", .{@errorName(err)});
        return 3;
    };

    var log = chock_proto.log.Log.open(io, path, "01TESTSESSION") catch |err| {
        std.debug.print("lock-helper: open failed: {s}\n", .{@errorName(err)});
        return 3;
    };
    defer log.close(io);

    _ = log.lock(io) catch |err| {
        std.debug.print("lock-helper: lock failed: {s}\n", .{@errorName(err)});
        return 4;
    };

    // These must go through `std.Io`. A raw Linux syscall number reaches the
    // macOS kernel but names a different call there, so the ready byte never
    // arrives and the caller waits for ever.
    std.Io.File.stdout().writeStreamingAll(io, "r") catch |err| {
        std.debug.print("lock-helper: could not send the ready byte: {s}\n", .{@errorName(err)});
        return 5;
    };

    var release_byte: [1]u8 = undefined;
    while (true) {
        const count = std.Io.File.stdin().readStreaming(io, &.{&release_byte}) catch break;
        if (count != 0) break;
    }

    return 0;
}
