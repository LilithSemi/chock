//! The supervisor half of `SECCOMP_RET_USER_NOTIF`, and the handover that puts
//! the notification descriptor in the supervisor's hands without stopping
//! either process forever.
//!
//! Chock's log can say that an agent ran `run_command` with some argument
//! vector. It could not say what that program then opened. This file is what
//! answers that. A filter built with `seccomp.Options.traps` holds each call in
//! `seccomp.TrapCall`, the kernel tells the supervisor it happened, the
//! supervisor counts it, and the call then runs. **Nothing here refuses a
//! call.** The answer is always `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
//!
//! ## The handover, and why it cannot stop forever
//!
//! `linux/driver.zig` forks twice. A is the supervisor, and it already exists
//! and already waits. B is the process that runs the caller's program, and B is
//! the process the filter goes on. A is not subject to B's filter.
//!
//! **`execve` is in the trap set, so B's own `execve` is held.** If A does not
//! hold the notification descriptor by that moment, B waits for an answer that
//! can never come, and A waits for a B that can never end.
//!
//! So B does not run on after it installs the filter. B writes the descriptor
//! number to A over a socket pair, and then waits for A to answer. A takes the
//! descriptor with `pidfd_getfd`, and only then answers. Four rules make this
//! safe:
//!
//!   1. **B waits on calls that can never be trapped.** `write`, `read`, and
//!      `close` are named in `seccomp.bootstrap_calls`, and a compile time
//!      check in `seccomp.zig` stops the build if any of them ever becomes a
//!      member of `seccomp.TrapCall`.
//!   2. **A answers whichever way the take went.** `takeListener` writes the
//!      answer byte on both roads. An A that said nothing would leave B in
//!      `read` while A waited for B to end.
//!   3. **A "no" is fatal for B.** B that ran on with no supervisor would meet
//!      `ENOSYS` on its first held call, because the kernel answers that way
//!      for a filter whose listener nobody holds. A setup failure is the
//!      honest outcome, and the caller reads which step it was.
//!   4. **The death of either process ends the wait of the other.** The socket
//!      pair closes when a process dies, so a blocked `read` on either side
//!      reads end of file rather than waiting.
//!
//! ## What the descriptor number is worth
//!
//! B sends a number, and A takes whatever descriptor sits on it. B is this
//! project's own code at that moment, before `execve`, so there is nothing
//! hostile about the number. A wrong number would make the first `ioctl` fail,
//! A would report a fault, and the call would end. It cannot make A count
//! something that did not happen.

const std = @import("std");
const linux = std.os.linux;
const seccomp = @import("seccomp.zig");
const SECCOMP = linux.SECCOMP;

/// How many members `seccomp.TrapCall` has. `Counts` is indexed by the tag
/// value of a member, so the two cannot drift apart.
pub const call_count = @typeInfo(seccomp.TrapCall).@"enum".fields.len;

/// One count for each member of `seccomp.TrapCall`, indexed by its tag value.
///
/// **A histogram and not a line for each call.** A session makes thousands of
/// tool calls and a tool call makes thousands of opens. A record for each one
/// would grow the session log without bound, which is a fault this project has
/// already paid for once.
pub const Counts = [call_count]u64;

/// A histogram with nothing counted yet.
pub const empty_counts: Counts = @splat(0);

/// The byte A sends when it holds the notification descriptor.
const ack_holding: u8 = 1;
/// The byte A sends when it does not. B must not run on after reading this.
const ack_none: u8 = 0;

/// How the serve loop ended.
pub const Outcome = enum {
    /// The observed process ended. Anything it left behind that still carries
    /// the filter stops being observed from here.
    child_ended,
    /// Every process that carried the filter ended, so the kernel released the
    /// listener.
    listener_ended,
    /// The kernel answered something this loop cannot carry on from. The
    /// caller must end the observed process rather than wait for it: a process
    /// held in a call nobody will answer never ends on its own.
    fault,
};

/// B's half of the handover, in the order it has to run.
///
/// Give the descriptor number to A, wait for A's answer, and then give up
/// every descriptor this process holds for the handover. True when A holds the
/// listener and this process may run on.
///
/// **The listener is closed here whichever way the answer went.** A process
/// that kept it could answer its own notifications, which would make the count
/// worth nothing.
pub fn handOver(handshake_fd: i32, listener: i32) bool {
    var number: [4]u8 = undefined;
    std.mem.writeInt(i32, &number, listener, .little);
    const announced = writeAll(handshake_fd, &number);

    var answer: [1]u8 = undefined;
    const heard = announced and readAll(handshake_fd, &answer);

    _ = linux.close(listener);
    _ = linux.close(handshake_fd);
    return heard and answer[0] == ack_holding;
}

/// A's half of the handover. Gives back the notification descriptor, or -1
/// when there is none to take.
///
/// `child_pidfd` is a descriptor on the observed process. -1 is allowed and
/// reads as a process that could not be named, which fails the take the same
/// way a refused take does.
///
/// **The answer goes back on both roads, and that is the rule that stops a
/// deadlock.** B waits for this byte. An A that took nothing and said nothing
/// would leave B in `read` while A waited for B to end.
///
/// **This has to run before the supervisor drops its own capabilities.**
/// `pidfd_getfd` needs ptrace level access to the target. The observed process
/// already dropped every capability of its own, and the kernel makes a process
/// undumpable when a credential change takes a capability away, so from that
/// moment the take is permitted only for a process holding `CAP_SYS_PTRACE` in
/// the target's user namespace. The supervisor still holds that here, and
/// `restrictMiddle` in `linux/driver.zig` is where it gives it up.
pub fn takeListener(handshake_fd: i32, child_pidfd: i32) i32 {
    const listener = take(handshake_fd, child_pidfd);
    const answer = [1]u8{if (listener >= 0) ack_holding else ack_none};
    _ = writeAll(handshake_fd, &answer);
    return listener;
}

fn take(handshake_fd: i32, child_pidfd: i32) i32 {
    if (child_pidfd < 0) return -1;

    var number: [4]u8 = undefined;
    if (!readAll(handshake_fd, &number)) return -1;
    const child_fd = std.mem.readInt(i32, &number, .little);
    if (child_fd < 0) return -1;

    const got = linux.pidfd_getfd(child_pidfd, child_fd, 0);
    if (linux.errno(got) != .SUCCESS) return -1;
    return @intCast(got);
}

/// Answer notifications and count them, until the observed process ends or
/// something goes wrong.
///
/// `child_pidfd` is what ends the loop when the observed process ends while a
/// process it left behind still carries the filter. Without it this would wait
/// for that process too, and a tool call that started a daemon would hold the
/// session.
///
/// **Belt as well as braces, and said plainly.** `linux/driver.zig` runs the
/// observed process as process 1 of a pid namespace of its own, and the kernel
/// kills every other member of such a namespace the moment process 1 exits, so
/// the leftover process is already gone today and this descriptor never
/// decides anything. Measured on 2026-09-11: taking it out of the poll set
/// changes no test. It is here so that this function is correct by itself,
/// rather than through a fact that belongs to another file and could change
/// there.
///
/// The caller owns both descriptors and closes them.
pub fn serve(listener: i32, child_pidfd: i32, counts: *Counts) Outcome {
    var watched = [2]linux.pollfd{
        .{ .fd = listener, .events = linux.POLL.IN, .revents = 0 },
        .{ .fd = child_pidfd, .events = linux.POLL.IN, .revents = 0 },
    };

    while (true) {
        watched[0].revents = 0;
        watched[1].revents = 0;
        const rc = linux.poll(&watched, watched.len, -1);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            // A signal caught while waiting. Not a fault, and not the end.
            .INTR => continue,
            else => return .fault,
        }

        // The listener first. A notification that is already waiting is
        // answered even when the observed process has ended in the same
        // moment, so nothing is lost between the two reads.
        if (watched[0].revents & linux.POLL.IN != 0) {
            switch (answerOne(listener, counts)) {
                .served => continue,
                .fault => return .fault,
            }
        }
        // Any other state on the listener means the kernel released it,
        // because every process that carried the filter has ended.
        if (watched[0].revents != 0) return .listener_ended;
        if (watched[1].revents != 0) return .child_ended;
    }
}

/// What one turn of the serve loop came to.
const Answered = enum { served, fault };

fn answerOne(listener: i32, counts: *Counts) Answered {
    var note: SECCOMP.notif = undefined;
    @memset(std.mem.asBytes(&note), 0);
    const rc = linux.ioctl(listener, SECCOMP.IOCTL_NOTIF.RECV, @intFromPtr(&note));
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        // A signal, or a caller that died between the poll and this read.
        // Neither is the end: the poll above decides that.
        .INTR, .NOENT => return .served,
        else => return .fault,
    }

    // **The number came from the kernel inside the notification.** The
    // observed process cannot change it after the filter read it, so this
    // count cannot be forged. A number no member holds is dropped rather than
    // counted against the first member.
    if (seccomp.TrapCall.fromNumber(note.data.nr)) |call| {
        counts[@intFromEnum(call)] += 1;
    }

    // **Continue, and never a spoofed answer.** This loop counts. It decides
    // nothing, so it must not stand between the program and the kernel. The
    // kernel's own manual page says a supervisor cannot use this flag to make
    // a security decision, because the arguments can change after the check.
    // Counting by call number is not a decision and reads nothing the program
    // owns.
    var response: SECCOMP.notif_resp = .{
        .id = note.id,
        .val = 0,
        .@"error" = 0,
        .flags = SECCOMP.USER_NOTIF_FLAG_CONTINUE,
    };
    const sent = linux.ioctl(listener, SECCOMP.IOCTL_NOTIF.SEND, @intFromPtr(&response));
    return switch (linux.errno(sent)) {
        // ENOENT means the caller went away before the answer landed. The
        // kernel already released it, so there is nothing left to answer.
        .SUCCESS, .NOENT => .served,
        else => .fault,
    };
}

/// Write every byte to the handshake socket, retrying a short write and a
/// signal. False when the other end has gone.
///
/// **`sendto` with `MSG_NOSIGNAL`, and not `write`.** The other end of this
/// socket is a process that can die at any moment, and a plain write to a
/// socket with no reader raises `SIGPIPE`. The supervisor puts every signal
/// back to its default action before it forks the observed process, so that
/// signal would end the supervisor, and the caller would read the whole tool
/// call as a program killed by `SIGPIPE`. The flag turns the death into a
/// plain `EPIPE`, which is a fact this function can give back.
///
/// `sendto` is named in `seccomp.bootstrap_calls` for the same reason `write`
/// is: the observed process makes this call while no supervisor holds the
/// notification descriptor yet.
fn writeAll(fd: i32, bytes: []const u8) bool {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = linux.sendto(
            fd,
            bytes[sent..].ptr,
            bytes.len - sent,
            linux.MSG.NOSIGNAL,
            null,
            0,
        );
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return false,
        }
        if (rc == 0) return false;
        sent += rc;
    }
    return true;
}

/// Read every byte, retrying a short read and a signal. False on end of file,
/// which is what the death of the other process leaves behind.
fn readAll(fd: i32, bytes: []u8) bool {
    var filled: usize = 0;
    while (filled < bytes.len) {
        const rc = linux.read(fd, bytes[filled..].ptr, bytes.len - filled);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return false,
        }
        if (rc == 0) return false;
        filled += rc;
    }
    return true;
}

test "a histogram has one slot for each call a policy can observe" {
    // `Counts` is indexed by the tag value of a `seccomp.TrapCall`. A member
    // added there with no slot here would write past the end of the array.
    try std.testing.expectEqual(call_count, empty_counts.len);
    inline for (@typeInfo(seccomp.TrapCall).@"enum".fields) |field| {
        try std.testing.expect(field.value < call_count);
    }
    for (empty_counts) |count| try std.testing.expectEqual(@as(u64, 0), count);
}

test "the handover answers a supervisor that took nothing, so the other side is never left waiting" {
    // **The deadlock this whole file is written around.** B waits for the
    // answer byte. A that took no descriptor and wrote nothing would leave B
    // in `read` while A waited for B to end, and the tool call would never
    // finish.
    //
    // A pair of sockets stands in for the two processes. `child_pidfd` is -1,
    // which is the shape of a supervisor that could not name the observed
    // process at all, so the take must fail.
    //
    // Mutation check: move the `writeAll` in `takeListener` inside an
    // `if (listener >= 0)` and the read below fails with end of file.
    var pair: [2]i32 = undefined;
    try std.testing.expectEqual(
        .SUCCESS,
        linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)),
    );
    defer _ = linux.close(pair[1]);

    // The side standing in for B says which descriptor it is on.
    var number: [4]u8 = undefined;
    std.mem.writeInt(i32, &number, 7, .little);
    try std.testing.expect(writeAll(pair[1], &number));

    try std.testing.expectEqual(@as(i32, -1), takeListener(pair[0], -1));

    // **The supervisor's end goes away before the read below.** A test that
    // left it open would wait forever for a byte the mutation stops being
    // written, and a test that hangs when the code it guards is broken is
    // worth no more than a test that skips. Bytes already sent survive this
    // close, so the read still finds them.
    _ = linux.close(pair[0]);

    var answer: [1]u8 = undefined;
    try std.testing.expect(readAll(pair[1], &answer));
    try std.testing.expectEqual(ack_none, answer[0]);
}

test "a supervisor that says no stops the observed process rather than letting it run on" {
    // The other half of the same rule. B that ran on with no supervisor would
    // meet ENOSYS on its first held call, because that is how the kernel
    // answers a filter whose listener nobody holds.
    //
    // Mutation check: make `handOver` return true whatever the byte said, and
    // this expectation fails.
    var pair: [2]i32 = undefined;
    try std.testing.expectEqual(
        .SUCCESS,
        linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)),
    );
    defer _ = linux.close(pair[0]);

    // A descriptor of this process's own, so the close inside `handOver` has
    // something real to close and cannot be mistaken for a close of the pair.
    const spare = linux.dup(pair[0]);
    try std.testing.expectEqual(.SUCCESS, linux.errno(spare));

    const refusal = [1]u8{ack_none};
    try std.testing.expect(writeAll(pair[0], &refusal));
    try std.testing.expect(!handOver(pair[1], @intCast(spare)));
}

test "the observed side does not wait when the supervisor has already gone" {
    // Case two of the deadlock argument: A dies before it ever answers. The
    // socket pair is what turns that into a refused call rather than a wait
    // with no end. The send fails with EPIPE, and `MSG_NOSIGNAL` is what keeps
    // that a value this code reads instead of a signal that ends the process.
    //
    // Mutation check: drop `MSG_NOSIGNAL` from `writeAll` and this test dies
    // from SIGPIPE rather than reporting anything.
    var pair: [2]i32 = undefined;
    try std.testing.expectEqual(
        .SUCCESS,
        linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)),
    );
    const spare = linux.dup(pair[1]);
    try std.testing.expectEqual(.SUCCESS, linux.errno(spare));

    // The supervisor's end goes away before it ever answers.
    _ = linux.close(pair[0]);
    try std.testing.expect(!handOver(pair[1], @intCast(spare)));
}

test "a read that ends early is a failure, and never a half filled answer" {
    // **The one line the case above cannot reach.** There the send fails
    // first, so the read never runs. This drives the read itself: the other
    // end shuts down its writing half after two bytes, so a four byte read
    // ends early. A `readAll` that called that success would hand the
    // handover an answer byte nobody ever wrote, and the observed process
    // would run on into a call nothing can answer.
    //
    // Mutation check: make `readAll` treat a zero length read as success and
    // this expectation fails.
    var pair: [2]i32 = undefined;
    try std.testing.expectEqual(
        .SUCCESS,
        linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)),
    );
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try std.testing.expect(writeAll(pair[0], &[2]u8{ 1, 2 }));
    // SHUT_WR is 1. The reading half of this end stays open, so this is an end
    // of file for the reader and not a closed socket.
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.shutdown(pair[0], 1)));

    var four: [4]u8 = undefined;
    try std.testing.expect(!readAll(pair[1], &four));
}
