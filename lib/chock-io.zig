//! The layer for the small number of primitives `std.Io` does not have. Three
//! rules keep it from becoming a second standard library.
//!
//! **This module is temporary.** When `std.Io` gains one of the primitives below,
//! delete the function here. No caller changes: `Io.pipeCloseOnExec` and
//! `Io.growPipeBuffer` stay the call sites, only their bodies move. This file is a
//! layer that shrinks over time, never a parallel standard library that grows.
//!
//! **The admission rule.** A primitive belongs here only if all three hold: `std.Io`
//! does not have it, Chock genuinely needs it, and it has a real implementation on
//! every platform Chock supports, or an honest refusal on the platform that cannot
//! do it. Two primitives pass that test today. Do not add a third on the strength of
//! "it would be convenient here too": that is exactly the phrasing that turns a
//! portability layer into a place where anything can be put.
//!
//! **It holds exactly three primitives**, one function each, one implementation per
//! platform, chosen at compile time from `builtin.os.tag`, the same driver split
//! `chock-sandbox` and `chock-workspace` already use:
//!
//! 1. `pipeCloseOnExec`: a pipe whose ends close on exec. Correctness, not
//!    convenience. A descriptor that leaks across `execve` is a descriptor a
//!    sandboxed program inherits. Linux gets this atomically from `pipe2`. Darwin
//!    has no `pipe2`, so it is `pipe` then `fcntl` on both ends, with a window
//!    between the two calls in which a `fork` on another thread inherits a
//!    descriptor that does not yet carry the flag. See
//!    `chock-io/darwin/driver.zig`'s own doc comment for why that window is real
//!    and cannot be closed on this platform.
//! 2. `growPipeBuffer`: a request to make a pipe buffer larger, for throughput,
//!    never for correctness. It only changes how often a reading loop wakes up.
//!    Linux asks the kernel with `fcntl`/`F_SETPIPE_SZ`, best effort: a refusal is
//!    fine, and the caller carries on. Darwin has no equivalent at all, and the
//!    function does nothing there. That is an honest no-operation, not a stub that
//!    lies: the return type is `void` on every platform, so no caller can write
//!    code that depends on the request having worked, on any platform, including
//!    Linux. See `chock-io/darwin/driver.zig`.
//! 3. `freeBytes`: how much room is left on the filesystem a path sits on. It
//!    passes the admission rule above rather than being convenient. `std.Io` has
//!    no reading of a filesystem's free space at all, and neither does
//!    `std.posix`: `statfs` is not bound anywhere in the standard library, so
//!    both drivers write the kernel's own structure out by hand, the same way
//!    `chock-sandbox/linux/namespace.zig` already has to. Chock needs it because
//!    **the workspace is the one writable area no cap can bound**: it holds the
//!    agent's real work, so a tmpfs there would trade a disk that fills for work
//!    that cannot be recovered. A free space floor read before each call is the
//!    only treatment left, and it is weaker: see
//!    `chock-core/tools.zig`'s own `workspace_free_floor_bytes`. Both platforms
//!    have a real implementation, and both answer null rather than zero when the
//!    call refuses, so "no room" and "no answer" are never confused.
//!
//! **The interface is a vtable**, the shape `std.mem.Allocator` uses and this
//! repository's own `chock-proto/storage.zig` already follows: a pointer plus a
//! table of function pointers, not a comptime generic parameter. Two reasons.
//! First, porting: a new platform becomes a new implementation of the table,
//! rather than another arm threaded into every call site that needs a primitive.
//! Second, and the reason this indirection earns its keep: a test can swap in a
//! fake that returns an error a real pipe cannot be made to return on demand.
//! `lib/chock-core/tools.zig`'s own pipe creation failure path was never
//! exercised before this module existed, because reaching it for real means
//! exhausting the process's whole descriptor table. `Fake`, below, makes that
//! path an ordinary test: see this file's own tests, and
//! `lib/chock-core/tools.zig`'s "spawnCapturing reports a pipe creation failure"
//! test.
//!
//! **The default instance is chosen at compile time, never at run time.**
//! `default` switches on `builtin.os.tag`, the same way
//! `chock-sandbox/Sandbox.zig`'s own driver selection does: only the branch that
//! matches the build's real target is ever imported, so a Darwin build never
//! carries a Linux system call number, and a Linux build never references
//! `std.c`. The vtable exists so a caller can substitute a fake in a test, never
//! so the platform gets decided at run time.

const std = @import("std");
const builtin = @import("builtin");

/// The two ends of a pipe, as raw descriptors. A caller that wants a
/// `std.Io.File` wraps one of these fields itself, the same way
/// `lib/chock-core/tools.zig` already wraps a raw descriptor today.
pub const Pipe = struct {
    read_fd: std.posix.fd_t,
    write_fd: std.posix.fd_t,
};

/// The one way either primitive in this module can fail: the underlying call
/// refused, for a reason a caller cannot act on differently than by giving up.
/// `error.Unexpected` shares its name with `chock-sandbox/Sandbox.zig`'s own
/// `SpawnError.Unexpected`, on purpose: Zig's error tags are identified by name
/// across the whole program, so this coerces straight into a caller's own error
/// set with no translation step. `lib/chock-core/tools.zig` relies on exactly
/// that.
pub const PipeError = error{Unexpected};

/// The interface every driver below implements. See this file's own top comment
/// for why this is a vtable and not a comptime parameter.
pub const Io = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        pipeCloseOnExec: *const fn (ptr: *anyopaque) PipeError!Pipe,
        growPipeBuffer: *const fn (ptr: *anyopaque, write_fd: std.posix.fd_t, target_bytes: usize) void,
        freeBytes: *const fn (ptr: *anyopaque, path: []const u8) ?u64,
    };

    /// Open a pipe whose read and write ends both close on exec. See this
    /// file's own top comment, item 1.
    pub fn pipeCloseOnExec(self: Io) PipeError!Pipe {
        return self.vtable.pipeCloseOnExec(self.ptr);
    }

    /// Ask the pipe whose write end is `write_fd` to grow its kernel buffer to
    /// at least `target_bytes`, best effort. Returns nothing: a caller cannot
    /// tell, from this signature alone, whether the request took effect, on
    /// any platform, and so cannot write code that depends on it having. See
    /// this file's own top comment, item 2, and `chock-io/darwin/driver.zig`'s
    /// own doc comment for why Darwin's implementation does nothing at all.
    pub fn growPipeBuffer(self: Io, write_fd: std.posix.fd_t, target_bytes: usize) void {
        self.vtable.growPipeBuffer(self.ptr, write_fd, target_bytes);
    }

    /// How many bytes an unprivileged process may still write to the filesystem
    /// `path` sits on. Null when the answer cannot be read: a path that is not
    /// there, or a call the kernel refused. See this file's own top comment,
    /// item 3.
    ///
    /// **Free to a process without privilege, not free in total.** Both drivers
    /// read the "available" count and never the "free" one, because a
    /// filesystem keeps a reserve only the superuser may write into, and a
    /// harness that counted that reserve would let a call start with room only
    /// root could use.
    ///
    /// **The answer is stale the moment it is given.** Everything else on the
    /// machine is writing too. It bounds nothing; it only says whether starting
    /// is sensible.
    pub fn freeBytes(self: Io, path: []const u8) ?u64 {
        return self.vtable.freeBytes(self.ptr, path);
    }
};

/// Selected once, at compile time, from `builtin.os.tag`. Only the branch that
/// matches the real build target is ever imported: see this file's own top
/// comment on why that must never become a run time choice.
const driver_impl = switch (builtin.os.tag) {
    .linux => @import("chock-io/linux/driver.zig"),
    .macos => @import("chock-io/darwin/driver.zig"),
    else => @compileError("chock-io: no driver for target os " ++ @tagName(builtin.os.tag)),
};

/// The real driver for whichever platform this binary was built for.
pub fn default() Io {
    return driver_impl.driver();
}

/// A test only driver that fails `pipeCloseOnExec` every time, does nothing on
/// `growPipeBuffer`, and answers nothing on `freeBytes`, so a caller can drive
/// an error path a real pipe cannot be made to take on demand. See this file's
/// own top comment.
pub const Fake = struct {
    pub fn driver() Io {
        return .{ .ptr = undefined, .vtable = &vtable };
    }

    fn pipeCloseOnExecFn(ptr: *anyopaque) PipeError!Pipe {
        _ = ptr;
        return error.Unexpected;
    }

    fn growPipeBufferFn(ptr: *anyopaque, write_fd: std.posix.fd_t, target_bytes: usize) void {
        _ = ptr;
        _ = write_fd;
        _ = target_bytes;
    }

    /// Always null, which is "this cannot be read" and never "there is no
    /// room". A caller that treated the two the same would refuse every call on
    /// a machine whose `statfs` is unavailable.
    fn freeBytesFn(ptr: *anyopaque, path: []const u8) ?u64 {
        _ = ptr;
        _ = path;
        return null;
    }

    const vtable = Io.VTable{
        .pipeCloseOnExec = pipeCloseOnExecFn,
        .growPipeBuffer = growPipeBufferFn,
        .freeBytes = freeBytesFn,
    };
};

test "the fake driver always fails pipeCloseOnExec, so a caller's error path is reachable" {
    const driver = Fake.driver();
    try std.testing.expectError(error.Unexpected, driver.pipeCloseOnExec());
}

test "the real driver reads free space, and answers nothing for a path that is not there" {
    // **A real reading, not a plausible number.** The whole point of the floor
    // this feeds is to refuse a call before the disk fills, and a driver that
    // answered a constant would refuse nothing or refuse everything. The
    // temporary directory of whichever machine runs this is a real filesystem
    // with a real answer, and the assertion is only that it is a number: the
    // exact figure belongs to the machine and would be a wall clock style
    // assertion if it were pinned.
    const driver = default();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(std.testing.io, &path_buffer);
    const free = driver.freeBytes(path_buffer[0..path_len]);
    try std.testing.expect(free != null);
    // A filesystem with a test suite running on it has room on it. Zero here
    // would mean the call answered without reading anything.
    try std.testing.expect(free.? > 0);

    // Null, and never zero: a path that cannot be read is not a full disk, and
    // a caller that read the two the same way would refuse every call.
    try std.testing.expectEqual(@as(?u64, null), driver.freeBytes("/nonexistent-chock-free-space"));
    // A path too long to terminate is refused the same way rather than being
    // cut short, because a truncated path names a different filesystem.
    const too_long = [_]u8{'a'} ** (std.fs.max_path_bytes + 1);
    try std.testing.expectEqual(@as(?u64, null), driver.freeBytes(&too_long));
}

test "the fake driver answers nothing for free space, which is not the same as no room" {
    const driver = Fake.driver();
    try std.testing.expectEqual(@as(?u64, null), driver.freeBytes("/"));
}

test "the fake driver's growPipeBuffer takes no descriptor and reports nothing" {
    // Nothing to assert on a return value: growPipeBuffer is void on every
    // driver, including this one, by design. This only proves the call runs,
    // with no real descriptor, and does not crash.
    const driver = Fake.driver();
    driver.growPipeBuffer(-1, 1024);
}

test {
    std.testing.refAllDecls(@This());
}
