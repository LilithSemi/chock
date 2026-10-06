//! A real second process for test/proto/lock.zig's log lock test.
//! It takes the lock, signals the caller over stdout, then waits for stdin before exiting.

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

    // These must go through `std.Io`, since a raw Linux syscall number names a different call on macOS.
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
