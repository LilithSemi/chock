//! A real second process for the log lock test. test/proto/lock.zig starts this
//! program and reads its result, the same pattern test/sandbox/escape.zig uses to
//! start test/sandbox/probe.zig. See build.zig for how this binary's path reaches
//! that test.
//!
//! This process opens the log at the path it is given, on the command line, and
//! takes the exclusive lock. Only a genuine second open file description, held by a
//! genuine second process, can prove that a session another process owns cannot be
//! taken. Two Log values inside one test binary would not prove it, because flock
//! locks an open file description, not a path.
//!
//! Protocol, over the pipes the caller sets up:
//!   1. This process opens the log and takes the lock.
//!   2. It writes one byte to standard output. The caller must not try its own lock
//!      before that byte arrives, or the attempt could race ahead of the lock.
//!   3. It blocks reading one byte from standard input. The caller sends that byte
//!      once its own lock attempt is done, so the release below never happens before
//!      the caller has actually tried and failed.
//!   4. It closes the log, which releases the lock, and exits 0.
//!
//! Exit codes:
//!   0 - the lock was taken and later released in the order above.
//!   3 - opening the log failed.
//!   4 - taking the lock failed. This should never happen: this process is always
//!       the first to reach the lock in the test that starts it.
//!   5 - the ready byte could not be sent. The caller then reads nothing and fails
//!       on its own, but this code tells the two apart in the exit status.

const std = @import("std");
const chock_proto = @import("chock-proto");

pub fn main(init: std.process.Init.Minimal) !u8 {
    // `Init.Minimal` carries no `Io`, only `Init` does, and this process has no
    // need for anything else `Init` adds. It builds its own `std.Io.Threaded`
    // instead of widening the parameter it accepts just to reach the one field
    // this file needs.
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

    // Both of these go through `std.Io`, not through a raw syscall. They used to
    // call `std.os.linux.write` and `std.os.linux.read`, which send a Linux syscall
    // number through the host's own trap instruction. On macOS the trap reaches the
    // kernel, but the number names a different call there, so the ready byte below
    // never reached standard output and the caller waited on a byte that was never
    // sent. See test/proto/lock.zig's own `readOneByte`.
    std.Io.File.stdout().writeStreamingAll(io, "r") catch |err| {
        std.debug.print("lock-helper: could not send the ready byte: {s}\n", .{@errorName(err)});
        return 5;
    };

    var release_byte: [1]u8 = undefined;
    while (true) {
        const count = std.Io.File.stdin().readStreaming(io, &.{&release_byte}) catch break;
        if (count != 0) break;
    }

    // log's own defer releases the lock through close, on the way out.
    return 0;
}
