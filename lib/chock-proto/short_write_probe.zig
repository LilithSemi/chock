//! Scaffolding for one regression test in `log.zig`: make an already open
//! pipe nonblocking, and name a byte count larger than that pipe's kernel
//! buffer, so a single write returns a short count instead of blocking
//! forever with nobody there to read the other end.
//!
//! This file holds no platform call. It forwards to whichever driver
//! `builtin.os.tag` selects, the same split `chock-io`, `chock-sandbox` and
//! `chock-workspace` already use.
//!
//! Neither function belongs in `lib/chock-io`. A primitive goes there only
//! when Chock genuinely needs it. Production Chock needs neither a nonblocking
//! pipe nor a pipe buffer size: only this one test does, as a way to make the
//! kernel report a short write on demand.
//!
//! The property under test is not platform specific. `writeExact` must report
//! a short write and must never retry, because a partial line corrupts the
//! byte offset of every event after it, and those offsets are how Chock names
//! an event. Only the way this test reproduces a short write is platform
//! specific, which is why the reproduction lives behind a driver and the rule
//! it proves does not.

const std = @import("std");
const builtin = @import("builtin");

pub const Error = error{Unexpected};

/// Add `O_NONBLOCK` to `fd`, an already open descriptor. Read, change, write:
/// `F_SETFL` replaces the whole flag word, so each driver keeps the flags it
/// found and only adds this one.
pub fn setNonblocking(fd: std.posix.fd_t) Error!void {
    return driver.setNonblocking(fd);
}

/// A byte count larger than `fd`'s own kernel pipe buffer. A write of this
/// many bytes into an empty nonblocking pipe cannot be taken in full, so the
/// kernel takes what fits and reports that count.
///
/// **A wrong answer here fails the test, it never passes it.** If this count
/// were ever below the real buffer size, the write would complete, `writeExact`
/// would return without error, and the test would fail on the missing
/// `error.ShortWrite`. So a driver may answer with an upper bound and does not
/// have to read the exact size, and neither driver can go quietly wrong.
pub fn overCapacity(fd: std.posix.fd_t) Error!usize {
    return driver.overCapacity(fd);
}

const driver = switch (builtin.os.tag) {
    .linux => @import("linux/short_write_probe.zig"),
    .macos => @import("darwin/short_write_probe.zig"),
    else => @compileError("chock-proto: no short write probe for target os " ++ @tagName(builtin.os.tag)),
};

test {
    _ = driver;
}
