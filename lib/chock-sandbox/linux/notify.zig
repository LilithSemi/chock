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
//! A is the supervisor. It forks a pid namespace keeper before B. B runs the
//! caller's program and gets the notification filter. A is not subject to B's
//! filter.
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
//! ## The path reader, and why it is a third process
//!
//! Counting says `openat` happened 14,434 times. It does not say what was
//! opened. Reading the path means reading a string out of the observed
//! process's memory, and the only call that does that is `process_vm_readv`.
//!
//! **A cannot make that call, measured twice.** `process_vm_readv` is a member
//! of `seccomp.blocked_calls`, and `linux/driver.zig`'s `restrictMiddle` puts
//! that same filter on A: measured on 2026-09-11, A dies of `SIGSYS` on the
//! call. A also puts a Landlock ruleset with no rule in it on itself, so A
//! cannot open `/proc/PID/mem` either: measured the same day, `EACCES`.
//!
//! So the read happens in a third process, R, and R is forked by A **after**
//! B, which puts R inside B's pid namespace. That placement is the whole
//! safety argument, and it is the kernel that enforces it:
//!
//!   * `process_vm_readv` names a **pid**, and the kernel resolves a pid in
//!     the pid namespace of the caller. R is a member of B's namespace, so
//!     every number R can write down resolves to B, to a child of B, or to R
//!     itself. There is no number R can pass that reaches `ssh-agent`, a
//!     password manager, or any other process on the host.
//!   * Measured on 2026-09-11: a process inside a fresh pid namespace asked to
//!     read its own parent's memory by that parent's host pid number and was
//!     answered `ESRCH`. Asked again for every number from 1 to 63, exactly
//!     one answered, and that one was the reader itself.
//!   * R does not choose the number at all. It uses `pid` out of the
//!     notification, which the kernel fills in relative to the reader's own
//!     namespace.
//!
//! ## Killing the auditor breaks your own opens
//!
//! R holds the notification descriptor, and **A closes its own copy the moment
//! R exists**. That is a rule and not tidiness. A filter whose listener nobody
//! holds makes the kernel answer every trapped call with `ENOSYS`, so a B that
//! killed its own reader would find that `openat` had stopped working.
//!
//! Measured on 2026-09-11, including the hard case: a target held inside a
//! trapped `openat` whose only listener holder was killed was answered
//! `ENOSYS` at the instant of the kill, and did not wait. The same measurement
//! with a second holder still open showed the target waiting forever, which is
//! why the rule above is written as a rule.
//!
//! ## The record is telemetry and never evidence
//!
//! The answer to a notification is `CONTINUE`, so the kernel runs the call
//! with the arguments it finds **after** R has read them. A process that wants
//! to lie about a filename can write one string, wait to be let go, and then
//! open another. So a path here is what the process **said**, and
//! `seccomp.TrapCall.pathArg` names the argument rather than a number written
//! at the read site. Two things carry that caveat outward: the field is called
//! `unverified_paths`, and the event carries `paths_verified: false` as a
//! machine readable fact a later mode can flip. See `lib/chock-proto/event.zig`.
//!
//! The counts are a different thing and stay unforgeable: the call number
//! comes from the kernel inside the notification.
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
const grants = @import("../grants.zig");
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

/// How many bytes of a path the reader copies out of the observed process.
///
/// **Measured, and the reason for the number.** A read of up to 4 KB costs
/// about 3.5 microseconds. Clamping the read to 256 bytes costs about 0.9
/// microseconds, against the 11 microseconds the notification itself costs. A
/// path longer than this is recorded as far as it was read and counted as
/// truncated, so a long name is short in the record and never a silent lie.
pub const path_read_clamp = 256;

/// How many distinct paths outside every grant one record names.
///
/// **A cap, and the overflow is counted rather than dropped in silence.** A
/// clean `zig build` opens 14,434 files. Naming each one would grow the
/// session log without bound, which is a cost this project has already paid
/// once. Eight names of 64 bytes is 512 bytes of text, which keeps the whole
/// record small enough to write once for a whole session: measured on
/// 2026-09-11, a full record with every counter saturated is one line of 1,503
/// bytes and a real one that named three paths is 743 bytes. **The size does
/// not grow with the number of opens**, which is the fault this cap exists to
/// stop.
///
/// **Eight is enough because the split is on the grant and not on the
/// workspace.** A healthy run names nothing at all: measured on 2026-09-11, a
/// real `git status` inside a sandbox that granted the toolchain tree made 115
/// opens and named none of them. The same run split on the workspace named 9
/// paths, of which 8 were the dynamic loader's own.
pub const kept_path_cap = 8;

/// How many bytes of one kept path the record holds. See `kept_path_cap`.
///
/// **A name longer than this is kept as its first bytes**, and the `truncated`
/// count is about the read clamp rather than about this. A reader of the log
/// knows this width, because it is the same for every record a build writes.
/// The paths worth reading outside every grant are short ones such as
/// `/etc/shadow` or `/home/someone/.ssh/id_ed25519`. The long ones are
/// toolchain paths, which are under a granted tree and are never named.
pub const kept_path_bytes = 64;

/// What the reader saw, in memory both the reader and the caller of `spawn`
/// can reach.
///
/// **Shared memory, and not the middle pipe.** The reader writes while it
/// serves notifications. The caller reads the page after it reaps the reader.
///
/// **The observed process never holds this mapping when it can write to it.**
/// `spawn` makes the mapping before it forks, so B inherits it, and B gives it
/// up in `applyLayers` before it applies a single layer. B is this project's
/// own code until that point. `execve` would take the mapping away in any
/// case, because it replaces the whole address space, but the give up is
/// written down rather than left to that.
///
/// **A count and not a line for each call.** See `kept_path_cap`, and
/// `SandboxSyscalls` in `lib/chock-proto/event.zig` for the same argument
/// about the log.
pub const PathRecord = extern struct {
    /// One when the reader finished confining itself and reached its loop.
    /// **Zero is the fact an audit reads**: the reader never ran, so every
    /// number below is short.
    ready: u32 = 0,
    /// One when the reader's own loop returned rather than being killed.
    ///
    /// **Leaving its own loop is the ordinary end**, because the reader
    /// watches the observed program's process descriptor as well as the
    /// notification descriptor, so that program's end wakes it. The keeper is
    /// process 1 of their namespace. The program's exit does not kill R.
    ended: u32 = 0,
    /// Set by the supervisor after it has reaped the reader. One means the
    /// reader never wrote `ended`, so **it did not report that it saw the
    /// observed program end**.
    ///
    /// A healthy reader reports before A closes the keeper. A program can
    /// still kill its reader. That closes the last listener and makes trapped
    /// calls answer `ENOSYS`. This field records that missing report.
    reader_unreported: u32 = 0,
    /// How many slots of `names` hold a path.
    kept: u32 = 0,
    /// The histogram, the same one `serve` fills in. Read by the supervisor
    /// after the observed process has ended, and reported the way an
    /// unobserved run is reported.
    counts: Counts = empty_counts,
    /// Calls whose path was at or below something the caller's own config
    /// puts inside the sandbox. **Counted and never named**: this is the
    /// numerous half, and it holds every open the dynamic loader makes.
    granted: Counts = empty_counts,
    /// Calls whose path was at or below none of them. **These are the few a
    /// reader wants**, so they are named below until the cap is reached.
    ungranted: Counts = empty_counts,
    /// Calls whose path was ungranted and is **not** among the names below.
    /// The explicit overflow count.
    ungranted_unnamed: Counts = empty_counts,
    /// Calls whose path had no leading separator, so it resolves against a
    /// directory the reader cannot see.
    ///
    /// **Its own count, because neither side would be true.** `openat` with a
    /// descriptor takes a relative name, and the reader is given the name and
    /// not the descriptor. Counting these as granted would claim a boundary
    /// nothing checked, and naming them would fill the cap with ordinary work.
    relative: Counts = empty_counts,
    /// Calls whose path could not be read out of the observed process at all.
    unread: Counts = empty_counts,
    /// Calls whose path was longer than `path_read_clamp`, or ran off the end
    /// of the pages the reader could reach. The name kept for such a call is a
    /// prefix of the real one.
    truncated: Counts = empty_counts,
    /// Which call each kept name belongs to, by `seccomp.TrapCall` tag value.
    name_call: [kept_path_cap]u32 = @splat(0),
    /// How many calls each kept name stands for.
    ///
    /// **Not written to the log, and it is here for the sum.** One record is
    /// merged into another when a session adds up its tool calls, and a name
    /// the second set has no room for has to add its own calls to
    /// `ungranted_unnamed`. Without this the merge would add one, and a name
    /// that stood for five hundred opens would read as one.
    name_hits: [kept_path_cap]u64 = @splat(0),
    /// How many bytes of each kept name are real.
    name_len: [kept_path_cap]u32 = @splat(0),
    /// The kept names themselves, not terminated and not trusted.
    names: [kept_path_cap][kept_path_bytes]u8 = @splat(@splat(0)),

    /// The bytes of slot `slot`, or an empty slice for a slot nothing filled.
    pub fn name(self: *const PathRecord, slot: usize) []const u8 {
        if (slot >= self.kept or slot >= kept_path_cap) return &.{};
        // **Clamped, and never trusted as it stands.** This length was written
        // by another process into shared memory. A caller that indexed with it
        // straight would read past the slot the day anything wrote a wrong
        // number there.
        const len = @min(self.name_len[slot], kept_path_bytes);
        return self.names[slot][0..len];
    }
};

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
/// The pidfd is load bearing. The keeper stays alive after the observed
/// process exits. A process left behind can still hold the listener. The pidfd
/// ends this loop at B's exit rather than at the last filtered process's exit.
///
/// The caller owns both descriptors and closes them.
pub fn serve(listener: i32, child_pidfd: i32, counts: *Counts) Outcome {
    return loop(listener, child_pidfd, counts, null);
}

/// The same loop, in a process that may also read the path each call names.
///
/// **Only the path reader may call this**, because the read it adds is
/// `process_vm_readv`, and every other process this project starts is killed
/// for making that call. See this file's own top comment for where the reader
/// lives and why the kernel bounds what it can name. `record` is the shared
/// page the reader writes and the caller of `spawn` reads.
///
/// `granted` is every path inside the sandbox that the caller's own config
/// puts something at, which `Sandbox.grantPrefixes` builds. A path at or below
/// one of them is counted and never named. See `classify`.
pub fn serveRecording(
    listener: i32,
    child_pidfd: i32,
    record: *PathRecord,
    granted: []const []const u8,
) Outcome {
    return loop(listener, child_pidfd, &record.counts, .{
        .record = record,
        .granted = granted,
    });
}

/// What the loop needs to turn one notification into a path in the record.
const Recorder = struct {
    record: *PathRecord,
    granted: []const []const u8,
};

fn loop(listener: i32, child_pidfd: i32, counts: *Counts, recorder: ?Recorder) Outcome {
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
            switch (answerOne(listener, counts, recorder)) {
                .served => {
                    // Do not let a busy orphan starve B's exit. One pending
                    // call is complete. The pidfd now takes priority.
                    if (watched[1].revents != 0) return .child_ended;
                    continue;
                },
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

fn answerOne(listener: i32, counts: *Counts, recorder: ?Recorder) Answered {
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
        // **Before the answer below, and that order is the whole point.** The
        // observed process is held inside the call until this loop answers, so
        // this is the one moment its argument is still the one the kernel will
        // use. It can still be changed afterwards, which is why the record
        // says `unverified`. Reading after the answer would make it not even
        // that.
        if (recorder) |r| readAndNote(r, call, &note);
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

/// Read the path one notification names, and put it in the record.
///
/// **Nothing here refuses, spoils or delays the call.** A read that fails is
/// counted and the call still runs.
fn readAndNote(recorder: Recorder, call: seccomp.TrapCall, note: *const SECCOMP.notif) void {
    const slot = @intFromEnum(call);
    const arg = call.pathArg() orelse return;
    const address = argAt(&note.data, arg);

    var buffer: [path_read_clamp]u8 = undefined;
    // **The pid comes from the kernel, inside the notification, and the kernel
    // wrote it in this process's own pid namespace.** So this number cannot
    // name a process outside the namespace the reader shares with the observed
    // program, whatever the observed program does. See this file's own top
    // comment for the measurement.
    const read = readPath(@intCast(note.pid), address, &buffer) orelse {
        recorder.record.unread[slot] +|= 1;
        return;
    };
    if (read.truncated) recorder.record.truncated[slot] +|= 1;
    countPath(recorder.record, call, read.path, recorder.granted);
}

/// One argument of a held call, by index. A switch and not an array index,
/// because the kernel's own structure names each argument one at a time. Four
/// of them, which is every index `seccomp.TrapCall.pathArg` can give back.
fn argAt(data: *const SECCOMP.data, index: u2) u64 {
    return switch (index) {
        0 => data.arg0,
        1 => data.arg1,
        2 => data.arg2,
        3 => data.arg3,
    };
}

/// What one path read came back with.
const PathRead = struct {
    path: []const u8,
    /// True when no terminator was found in what was read, so the path is
    /// longer than this or runs into a page the reader could not reach.
    truncated: bool,
};

/// Copy a path out of the observed process, clamped.
///
/// **Two remote pieces and one call.** A read that ran into an unmapped page
/// would give back nothing at all, so the first piece stops at the end of the
/// page the string starts in. The second piece carries the rest of the clamp.
/// The kernel reads the pieces in order and gives back what it managed, so a
/// string that ends inside the first page costs the same one call as one that
/// does not.
///
/// Null when nothing at all could be read. That is the ordinary answer for a
/// call whose argument is not a pointer to readable memory, and for a process
/// the reader may not read at all.
fn readPath(target: linux.pid_t, address: u64, buffer: *[path_read_clamp]u8) ?PathRead {
    if (address == 0) return null;

    const page: u64 = 4096;
    const to_page_end = page - (address & (page - 1));
    const want: u64 = buffer.len;
    const first = @min(to_page_end, want);

    const local: [1]std.posix.iovec = .{.{ .base = buffer, .len = @intCast(want) }};
    var remote: [2]std.posix.iovec_const = .{
        .{ .base = @ptrFromInt(address), .len = @intCast(first) },
        .{ .base = @ptrFromInt(address + first), .len = @intCast(want - first) },
    };
    const pieces: usize = if (want > first) 2 else 1;

    const rc = linux.process_vm_readv(target, &local, remote[0..pieces], 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    if (rc == 0) return null;

    const got = buffer[0..@min(rc, buffer.len)];
    const end = std.mem.indexOfScalar(u8, got, 0) orelse
        return .{ .path = got, .truncated = true };
    return .{ .path = got[0..end], .truncated = false };
}

/// Which of the record's three buckets one path a program named belongs in.
pub const Side = enum {
    /// At or below a path the caller's own config puts something at.
    granted,
    /// At or below none of them. This is the anomaly, and it is named.
    ungranted,
    /// No leading separator, so it resolves against a directory the reader
    /// cannot see. See `PathRecord.relative`.
    relative,
};

/// Which side of the grant set `path` falls on.
///
/// **The split is on the grant and not on the workspace, and that is the whole
/// value of the record.** Measured on 2026-09-11: a plain `git status` inside
/// a sandbox made 115 opens. Split on the workspace it named 9 distinct paths,
/// and 8 of them were Nix store paths the caller granted on purpose. The
/// loader's opens come first, so a set of eight names holds eight toolchain
/// paths and nothing a reader would act on. Split on the grant, the same run
/// counted 17 granted opens, 98 relative ones, and named nothing at all.
///
/// An empty grant set puts every absolute path on the `ungranted` side, which
/// is the honest answer for a config that granted nothing.
///
/// This is a decision about a **string the observed process wrote**, and never
/// about a file. It says nothing about where the kernel then went. See this
/// file's own top comment.
pub fn classify(path: []const u8, granted: []const []const u8) Side {
    if (path.len == 0 or path[0] != '/') return .relative;
    // `grants.holds` is the same comparison `Sandbox.firstGap` makes against
    // this same mount set. A second spelling of it here is how the two would
    // quietly stop agreeing.
    return if (grants.setHolds(granted, path)) .granted else .ungranted;
}

/// Count one path, and name it when the caller granted nothing that holds it
/// and the record still has room.
fn countPath(
    record: *PathRecord,
    call: seccomp.TrapCall,
    path: []const u8,
    granted: []const []const u8,
) void {
    const slot = @intFromEnum(call);
    switch (classify(path, granted)) {
        .granted => record.granted[slot] +|= 1,
        .relative => record.relative[slot] +|= 1,
        .ungranted => {
            record.ungranted[slot] +|= 1;
            keepName(record, @intCast(slot), path, 1);
        },
    }
}

/// Put one name in the record's capped set, or count it as one the set had no
/// room for.
///
/// `call_tag` is a `seccomp.TrapCall` tag value. **A tag no member holds is
/// dropped and never counted against the first member**, because this is also
/// the function that merges one process's record into another's, and the
/// record it reads from was written by a process that could have written
/// anything there.
///
/// `hits` is how many calls this name stands for. One for a call as it
/// happens, and the source name's own total when one record is merged into
/// another. See `name_hits`.
pub fn keepName(record: *PathRecord, call_tag: u32, path: []const u8, hits: u64) void {
    if (call_tag >= call_count) return;

    const kept = @min(record.kept, kept_path_cap);
    const text = path[0..@min(path.len, kept_path_bytes)];
    var slot_index: u32 = 0;
    while (slot_index < kept) : (slot_index += 1) {
        if (record.name_call[slot_index] != call_tag) continue;
        if (std.mem.eql(u8, record.name(slot_index), text)) {
            record.name_hits[slot_index] +|= hits;
            return;
        }
    }
    if (kept >= kept_path_cap) {
        // **The overflow is a number and never a silent drop**, and it counts
        // calls rather than names. See `kept_path_cap` and `name_hits`.
        record.ungranted_unnamed[call_tag] +|= hits;
        return;
    }
    @memcpy(record.names[kept][0..text.len], text);
    record.name_len[kept] = @intCast(text.len);
    record.name_call[kept] = call_tag;
    record.name_hits[kept] = hits;
    record.kept = kept + 1;
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
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

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
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

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
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

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
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

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

/// The grant set of an ordinary tool call: the toolchain tree, the project's
/// own workspace, and a scratch area. Written once here, because every test
/// below is about which side of it a path falls on.
const test_grants = [_][]const u8{ "/nix/store", "/work", "/run/chock/scratch" };

test "a path the config granted is granted, and a name that only starts the same way is not" {
    // **The boundary is what the caller granted, and not the workspace.** The
    // whole toolchain tree is a mount the caller declared, so every open under
    // it is the numerous half and never the interesting one.
    //
    // Mutation check: make `classify` give back `.ungranted` for a path
    // `grants.setHolds` accepts and the first expectation fails.
    try std.testing.expectEqual(Side.granted, classify("/work/src/main.zig", &test_grants));
    try std.testing.expectEqual(
        Side.granted,
        classify("/nix/store/abc-glibc-2.40/lib/libc.so.6", &test_grants),
    );
    try std.testing.expectEqual(Side.granted, classify("/work", &test_grants));
    try std.testing.expectEqual(Side.ungranted, classify("/etc/passwd", &test_grants));
    // `/work` must not swallow `/work-of-someone-else`. This is the one
    // direction the record must not fail in, and `grants.holds` is where the
    // separator check lives.
    try std.testing.expectEqual(
        Side.ungranted,
        classify("/work-of-someone-else/key", &test_grants),
    );
    // A config that granted nothing put every absolute path outside.
    try std.testing.expectEqual(Side.ungranted, classify("/anything", &.{}));
}

test "a relative name is neither granted nor ungranted, because the reader cannot resolve it" {
    // **`openat` with a descriptor takes a relative name.** The reader is
    // given the name and never the descriptor, so it cannot say which
    // directory the name resolves against. Calling it granted would claim a
    // boundary nothing checked; naming it would fill the cap with ordinary
    // work.
    //
    // Mutation check: make `classify` give back `.granted` for a name with no
    // leading separator and the `relative` count below reads 0 while
    // `granted` reads 2.
    try std.testing.expectEqual(Side.relative, classify("src/main.zig", &test_grants));
    try std.testing.expectEqual(Side.relative, classify("", &test_grants));

    var record: PathRecord = .{};
    countPath(&record, .openat, "src/main.zig", &test_grants);
    countPath(&record, .openat, "build.zig", &test_grants);

    const slot = @intFromEnum(seccomp.TrapCall.openat);
    try std.testing.expectEqual(@as(u64, 2), record.relative[slot]);
    try std.testing.expectEqual(@as(u64, 0), record.granted[slot]);
    try std.testing.expectEqual(@as(u64, 0), record.ungranted[slot]);
    try std.testing.expectEqual(@as(u32, 0), record.kept);
}

test "the loader's opens are counted and never named, so the cap is left for the anomaly" {
    // **The defect this split exists to fix.** A dynamically linked program's
    // first opens are the loader's, and every one of them is under the
    // toolchain mount the caller declared. Split on the workspace, those eight
    // slots are full before the program has run a line of its own, and the one
    // path nobody granted lands in the overflow count with no name at all.
    //
    // Mutation check: pass a grant set of `&.{}` to `countPath` below and
    // `kept` reads 8 with the planted name nowhere in the set.
    var record: PathRecord = .{};
    var made: usize = 0;
    while (made < 12) : (made += 1) {
        var buffer: [64]u8 = undefined;
        const path = std.fmt.bufPrint(
            &buffer,
            "/nix/store/aaaaaaaaaaaa{d}-glibc-2.40/lib/libc.so.6",
            .{made},
        ) catch unreachable;
        countPath(&record, .openat, path, &test_grants);
    }
    countPath(&record, .openat, "/etc/chock-probe-secret", &test_grants);

    const slot = @intFromEnum(seccomp.TrapCall.openat);
    try std.testing.expectEqual(@as(u64, 12), record.granted[slot]);
    try std.testing.expectEqual(@as(u64, 1), record.ungranted[slot]);
    try std.testing.expectEqual(@as(u64, 0), record.ungranted_unnamed[slot]);
    try std.testing.expectEqual(@as(u32, 1), record.kept);
    try std.testing.expectEqualStrings("/etc/chock-probe-secret", record.name(0));
}

test "an open the config granted is counted and never named" {
    // The numerous and boring half. A record that named these would be
    // thousands of lines for one tool call.
    //
    // Mutation check: make `countPath` fall through to the naming code for a
    // granted path and the `kept` expectation below fails.
    var record: PathRecord = .{};
    countPath(&record, .openat, "/work/src/main.zig", &test_grants);
    countPath(&record, .openat, "/work/build.zig", &test_grants);

    try std.testing.expectEqual(@as(u64, 2), record.granted[@intFromEnum(seccomp.TrapCall.openat)]);
    try std.testing.expectEqual(@as(u64, 0), record.ungranted[@intFromEnum(seccomp.TrapCall.openat)]);
    try std.testing.expectEqual(@as(u32, 0), record.kept);
}

test "an open the config granted nothing for is named once, and a repeat adds no second name" {
    // Mutation check: take the `std.mem.eql` check out of `keepName`'s scan and
    // `kept` below becomes 2.
    var record: PathRecord = .{};
    countPath(&record, .openat, "/etc/passwd", &test_grants);
    countPath(&record, .openat, "/etc/passwd", &test_grants);

    try std.testing.expectEqual(@as(u64, 2), record.ungranted[@intFromEnum(seccomp.TrapCall.openat)]);
    try std.testing.expectEqual(@as(u32, 1), record.kept);
    try std.testing.expectEqualStrings("/etc/passwd", record.name(0));
    try std.testing.expectEqual(
        @as(u32, @intFromEnum(seccomp.TrapCall.openat)),
        record.name_call[0],
    );
}

test "the same path under two calls is named for each of them" {
    // The names are read back one call at a time, so a name kept under
    // `openat` must not answer for `execve`.
    //
    // Mutation check: drop the `name_call` comparison from `keepName`'s scan and
    // `kept` below becomes 1, so the `execve` row loses its only name.
    var record: PathRecord = .{};
    countPath(&record, .openat, "/bin/sh", &test_grants);
    countPath(&record, .execve, "/bin/sh", &test_grants);

    try std.testing.expectEqual(@as(u32, 2), record.kept);
    try std.testing.expectEqual(
        @as(u32, @intFromEnum(seccomp.TrapCall.openat)),
        record.name_call[0],
    );
    try std.testing.expectEqual(
        @as(u32, @intFromEnum(seccomp.TrapCall.execve)),
        record.name_call[1],
    );
}

test "a record that is full counts what it cannot name rather than dropping it" {
    // **The cap is the reason this record stays in the hundreds of bytes**,
    // and the overflow count is what stops a reader mistaking a full record
    // for the whole truth. See `kept_path_cap`.
    //
    // Mutation check: make `keepName` return early when the record is full
    // without touching `ungranted_unnamed` and the last expectation fails.
    var record: PathRecord = .{};
    var made: usize = 0;
    while (made < kept_path_cap + 5) : (made += 1) {
        var buffer: [32]u8 = undefined;
        const path = std.fmt.bufPrint(&buffer, "/etc/thing-{d}", .{made}) catch unreachable;
        countPath(&record, .openat, path, &test_grants);
    }

    const slot = @intFromEnum(seccomp.TrapCall.openat);
    try std.testing.expectEqual(@as(u32, kept_path_cap), record.kept);
    try std.testing.expectEqual(@as(u64, kept_path_cap + 5), record.ungranted[slot]);
    try std.testing.expectEqual(@as(u64, 5), record.ungranted_unnamed[slot]);
}

test "a name longer than a slot is kept as its first bytes and never past the slot" {
    // Mutation check: take the `@min` out of the `text` line in `keepName` and
    // the `@memcpy` there writes past the slot, which the safety check in a
    // test build turns into a panic.
    var record: PathRecord = .{};
    var long: [kept_path_bytes * 2]u8 = @splat('a');
    long[0] = '/';
    countPath(&record, .openat, &long, &test_grants);

    try std.testing.expectEqual(@as(u32, 1), record.kept);
    try std.testing.expectEqual(@as(usize, kept_path_bytes), record.name(0).len);
    try std.testing.expectEqualStrings(long[0..kept_path_bytes], record.name(0));
}

test "a name length written past the end of a slot is clamped rather than believed" {
    // `PathRecord` lives in memory another process writes, so a length read
    // back from it is untrusted input and never a fact. See `PathRecord.name`.
    //
    // Mutation check: take the `@min` out of `PathRecord.name` and this test
    // reads past the slot, which the safety check turns into a panic.
    var record: PathRecord = .{};
    record.kept = 1;
    record.name_len[0] = kept_path_bytes * 4;
    try std.testing.expectEqual(@as(usize, kept_path_bytes), record.name(0).len);
}

test "the whole record stays in the hundreds of bytes" {
    // **The size is the requirement and not an accident.** A session log with
    // one of these for each tool call is what the cap exists to bound. See
    // `kept_path_cap`.
    //
    // Mutation check: raise `kept_path_cap` to 64 and this fails.
    try std.testing.expect(@sizeOf(PathRecord) <= 2048);
}

test "only a call that names a path has an argument to read" {
    // **The argument index belongs to the call and not to the read site.** A
    // number written where the memory is read would be wrong for one call the
    // day the trap set grows. See `seccomp.TrapCall.pathArg`.
    //
    // Mutation check: give `connect` a `pathArg` of 1 and the third
    // expectation fails.
    try std.testing.expectEqual(@as(?u2, 1), seccomp.TrapCall.openat.pathArg());
    try std.testing.expectEqual(@as(?u2, 0), seccomp.TrapCall.execve.pathArg());
    try std.testing.expectEqual(@as(?u2, null), seccomp.TrapCall.connect.pathArg());
    try std.testing.expectEqual(@as(?u2, null), seccomp.TrapCall.getdents64.pathArg());
}

test "the reader reads a path out of another process and stops at the clamp" {
    // **The one call this whole design is built around**, run against a real
    // process. A child holds two strings and waits. This process reads them
    // both by that child's pid.
    //
    // Mutation check: make `readPath` report `truncated = false` always and
    // the truncation expectation fails. Make it give back the whole buffer
    // rather than stopping at the terminator and the first string comparison
    // fails.
    //
    // **Raising `path_read_clamp` is not a mutation this can catch, and that
    // is on purpose.** The clamp is the size of the buffer the read fills, so
    // no value of it can make the read run past what was asked for. What this
    // pins is that the read stops at whatever the clamp is, rather than
    // following the string to its end.
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    // Held in this process, and read back through the kernel rather than by
    // pointer, so nothing here can pass by reading its own memory: the read
    // below names the child's pid, and the child is a fork with its own copy.
    var short: [16]u8 = @splat(0);
    @memcpy(short[0.."/etc/passwd".len], "/etc/passwd");
    var long: [path_read_clamp * 2]u8 = @splat('b');
    long[long.len - 1] = 0;

    var pair: [2]i32 = undefined;
    try std.testing.expectEqual(
        .SUCCESS,
        linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)),
    );
    const forked = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(forked));
    if (forked == 0) {
        // The child touches both strings so the pages are its own, then waits
        // for the parent to finish reading.
        short[short.len - 1] = 0;
        long[0] = 'b';
        _ = linux.close(pair[0]);
        var wait: [1]u8 = undefined;
        _ = linux.read(pair[1], &wait, 1);
        linux.exit(0);
    }
    const child: linux.pid_t = @intCast(forked);
    defer {
        _ = linux.close(pair[0]);
        var status: u32 = 0;
        _ = linux.wait4(child, &status, 0, null);
    }
    _ = linux.close(pair[1]);

    var buffer: [path_read_clamp]u8 = undefined;
    const near = readPath(child, @intFromPtr(&short), &buffer) orelse {
        // A kernel or a policy that refuses the read at all is not this test
        // failing, and it must not read as a pass either.
        return error.SkipZigTest;
    };
    try std.testing.expectEqualStrings("/etc/passwd", near.path);
    try std.testing.expect(!near.truncated);

    const far = readPath(child, @intFromPtr(&long), &buffer).?;
    try std.testing.expectEqual(@as(usize, path_read_clamp), far.path.len);
    try std.testing.expect(far.truncated);
}

test "a path the reader cannot reach is counted and never guessed at" {
    // Mutation check: make `readPath` give back an empty path instead of null
    // on a failed read and `unread` below stays zero while a name nobody ever
    // opened appears in the record.
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    var buffer: [path_read_clamp]u8 = undefined;
    // Address zero is the argument a program passes when it has nothing. No
    // process maps it.
    try std.testing.expectEqual(@as(?PathRead, null), readPath(linux.getpid(), 0, &buffer));
}

test "the reader's own filter permits the one call the sandbox kills, and nothing the sandbox needs" {
    // **The reader is a process of its own exactly because of this call.** A
    // build in which the reader's filter and the sandbox's filter agreed about
    // `process_vm_readv` would mean the separation had quietly been undone.
    //
    // Mutation check: take `.process_vm_readv` out of `seccomp.reader_calls`
    // and the build stops at the `comptime` block beside it.
    var reads_memory = false;
    var writes_memory = false;
    var opens = false;
    for (seccomp.reader_calls) |call| {
        if (call == .process_vm_readv) reads_memory = true;
        if (call == .process_vm_writev) writes_memory = true;
        if (call == .openat) opens = true;
    }
    try std.testing.expect(reads_memory);
    // The reader reads. A reader that could write into the observed process
    // would be able to change the very call it is recording.
    try std.testing.expect(!writes_memory);
    // Nothing the reader does needs a path, and it holds an empty Landlock
    // ruleset in any case.
    try std.testing.expect(!opens);

    var blocked_and_allowed: usize = 0;
    for (seccomp.reader_calls) |call| {
        for (seccomp.blocked_calls) |killed| {
            if (call == killed) blocked_and_allowed += 1;
        }
    }
    // Exactly one: `process_vm_readv`, and no second call has quietly joined
    // it.
    try std.testing.expectEqual(@as(usize, 1), blocked_and_allowed);
}
