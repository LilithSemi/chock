//! Counts the syscalls a sandboxed process makes under SECCOMP_RET_USER_NOTIF, hands the
//! notification descriptor from the forked child to the supervisor, and reads the path each
//! held call names.

const std = @import("std");
const linux = std.os.linux;
const seccomp = @import("seccomp.zig");
const grants = @import("../grants.zig");
const SECCOMP = linux.SECCOMP;

pub const call_count = @typeInfo(seccomp.TrapCall).@"enum".fields.len;

pub const Counts = [call_count]u64;

pub const empty_counts: Counts = @splat(0);

pub const path_read_clamp = 256;

pub const kept_path_cap = 8;

pub const kept_path_bytes = 64;

pub const PathRecord = extern struct {
    ready: u32 = 0,
    ended: u32 = 0,
    reader_unreported: u32 = 0,
    kept: u32 = 0,
    counts: Counts = empty_counts,
    granted: Counts = empty_counts,
    ungranted: Counts = empty_counts,
    ungranted_unnamed: Counts = empty_counts,
    relative: Counts = empty_counts,
    unread: Counts = empty_counts,
    truncated: Counts = empty_counts,
    name_call: [kept_path_cap]u32 = @splat(0),
    name_hits: [kept_path_cap]u64 = @splat(0),
    name_len: [kept_path_cap]u32 = @splat(0),
    names: [kept_path_cap][kept_path_bytes]u8 = @splat(@splat(0)),

    pub fn name(self: *const PathRecord, slot: usize) []const u8 {
        if (slot >= self.kept or slot >= kept_path_cap) return &.{};
        const len = @min(self.name_len[slot], kept_path_bytes);
        return self.names[slot][0..len];
    }
};

const ack_holding: u8 = 1;
const ack_none: u8 = 0;

pub const Outcome = enum {
    child_ended,
    listener_ended,
    fault,
};

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

    // Must run before the supervisor drops capabilities: pidfd_getfd needs ptrace access.
    const got = linux.pidfd_getfd(child_pidfd, child_fd, 0);
    if (linux.errno(got) != .SUCCESS) return -1;
    return @intCast(got);
}

pub fn serve(listener: i32, child_pidfd: i32, counts: *Counts) Outcome {
    return loop(listener, child_pidfd, counts, null);
}

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
            .INTR => continue,
            else => return .fault,
        }

        if (watched[0].revents & linux.POLL.IN != 0) {
            switch (answerOne(listener, counts, recorder)) {
                .served => {
                    if (watched[1].revents != 0) return .child_ended;
                    continue;
                },
                .fault => return .fault,
            }
        }
        if (watched[0].revents != 0) return .listener_ended;
        if (watched[1].revents != 0) return .child_ended;
    }
}

const Answered = enum { served, fault };

fn answerOne(listener: i32, counts: *Counts, recorder: ?Recorder) Answered {
    var note: SECCOMP.notif = undefined;
    @memset(std.mem.asBytes(&note), 0);
    const rc = linux.ioctl(listener, SECCOMP.IOCTL_NOTIF.RECV, @intFromPtr(&note));
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .INTR, .NOENT => return .served,
        else => return .fault,
    }

    if (seccomp.TrapCall.fromNumber(note.data.nr)) |call| {
        counts[@intFromEnum(call)] += 1;
        if (recorder) |r| readAndNote(r, call, &note);
    }

    // CONTINUE decides nothing; the kernel refuses to treat this flag as a security check
    // because the arguments can still change after this point.
    var response: SECCOMP.notif_resp = .{
        .id = note.id,
        .val = 0,
        .@"error" = 0,
        .flags = SECCOMP.USER_NOTIF_FLAG_CONTINUE,
    };
    const sent = linux.ioctl(listener, SECCOMP.IOCTL_NOTIF.SEND, @intFromPtr(&response));
    return switch (linux.errno(sent)) {
        .SUCCESS, .NOENT => .served,
        else => .fault,
    };
}

fn readAndNote(recorder: Recorder, call: seccomp.TrapCall, note: *const SECCOMP.notif) void {
    const slot = @intFromEnum(call);
    const arg = call.pathArg() orelse return;
    const address = argAt(&note.data, arg);

    var buffer: [path_read_clamp]u8 = undefined;
    const read = readPath(@intCast(note.pid), address, &buffer) orelse {
        recorder.record.unread[slot] +|= 1;
        return;
    };
    if (read.truncated) recorder.record.truncated[slot] +|= 1;
    countPath(recorder.record, call, read.path, recorder.granted);
}

fn argAt(data: *const SECCOMP.data, index: u2) u64 {
    return switch (index) {
        0 => data.arg0,
        1 => data.arg1,
        2 => data.arg2,
        3 => data.arg3,
    };
}

const PathRead = struct {
    path: []const u8,
    truncated: bool,
};

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

pub const Side = enum {
    granted,
    ungranted,
    relative,
};

pub fn classify(path: []const u8, granted: []const []const u8) Side {
    if (path.len == 0 or path[0] != '/') return .relative;
    return if (grants.setHolds(granted, path)) .granted else .ungranted;
}

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
        record.ungranted_unnamed[call_tag] +|= hits;
        return;
    }
    @memcpy(record.names[kept][0..text.len], text);
    record.name_len[kept] = @intCast(text.len);
    record.name_call[kept] = call_tag;
    record.name_hits[kept] = hits;
    record.kept = kept + 1;
}

// sendto with MSG_NOSIGNAL, not write: the other end can die at any moment, and a plain write
// to a dead socket raises SIGPIPE instead of giving back EPIPE.
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
    try std.testing.expectEqual(call_count, empty_counts.len);
    inline for (@typeInfo(seccomp.TrapCall).@"enum".fields) |field| {
        try std.testing.expect(field.value < call_count);
    }
    for (empty_counts) |count| try std.testing.expectEqual(@as(u64, 0), count);
}

test "the handover answers a supervisor that took nothing, so the other side is never left waiting" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    var pair: [2]i32 = undefined;
    try std.testing.expectEqual(
        .SUCCESS,
        linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)),
    );
    defer _ = linux.close(pair[1]);

    var number: [4]u8 = undefined;
    std.mem.writeInt(i32, &number, 7, .little);
    try std.testing.expect(writeAll(pair[1], &number));

    try std.testing.expectEqual(@as(i32, -1), takeListener(pair[0], -1));

    _ = linux.close(pair[0]);

    var answer: [1]u8 = undefined;
    try std.testing.expect(readAll(pair[1], &answer));
    try std.testing.expectEqual(ack_none, answer[0]);
}

test "a supervisor that says no stops the observed process rather than letting it run on" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    var pair: [2]i32 = undefined;
    try std.testing.expectEqual(
        .SUCCESS,
        linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)),
    );
    defer _ = linux.close(pair[0]);

    const spare = linux.dup(pair[0]);
    try std.testing.expectEqual(.SUCCESS, linux.errno(spare));

    const refusal = [1]u8{ack_none};
    try std.testing.expect(writeAll(pair[0], &refusal));
    try std.testing.expect(!handOver(pair[1], @intCast(spare)));
}

test "the observed side does not wait when the supervisor has already gone" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    var pair: [2]i32 = undefined;
    try std.testing.expectEqual(
        .SUCCESS,
        linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)),
    );
    const spare = linux.dup(pair[1]);
    try std.testing.expectEqual(.SUCCESS, linux.errno(spare));

    _ = linux.close(pair[0]);
    try std.testing.expect(!handOver(pair[1], @intCast(spare)));
}

test "a read that ends early is a failure, and never a half filled answer" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    var pair: [2]i32 = undefined;
    try std.testing.expectEqual(
        .SUCCESS,
        linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)),
    );
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try std.testing.expect(writeAll(pair[0], &[2]u8{ 1, 2 }));
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.shutdown(pair[0], 1)));

    var four: [4]u8 = undefined;
    try std.testing.expect(!readAll(pair[1], &four));
}

const test_grants = [_][]const u8{ "/nix/store", "/work", "/run/chock/scratch" };

test "a path the config granted is granted, and a name that only starts the same way is not" {
    try std.testing.expectEqual(Side.granted, classify("/work/src/main.zig", &test_grants));
    try std.testing.expectEqual(
        Side.granted,
        classify("/nix/store/abc-glibc-2.40/lib/libc.so.6", &test_grants),
    );
    try std.testing.expectEqual(Side.granted, classify("/work", &test_grants));
    try std.testing.expectEqual(Side.ungranted, classify("/etc/passwd", &test_grants));
    try std.testing.expectEqual(
        Side.ungranted,
        classify("/work-of-someone-else/key", &test_grants),
    );
    try std.testing.expectEqual(Side.ungranted, classify("/anything", &.{}));
}

test "a relative name is neither granted nor ungranted, because the reader cannot resolve it" {
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
    var record: PathRecord = .{};
    countPath(&record, .openat, "/work/src/main.zig", &test_grants);
    countPath(&record, .openat, "/work/build.zig", &test_grants);

    try std.testing.expectEqual(@as(u64, 2), record.granted[@intFromEnum(seccomp.TrapCall.openat)]);
    try std.testing.expectEqual(@as(u64, 0), record.ungranted[@intFromEnum(seccomp.TrapCall.openat)]);
    try std.testing.expectEqual(@as(u32, 0), record.kept);
}

test "an open the config granted nothing for is named once, and a repeat adds no second name" {
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
    var record: PathRecord = .{};
    var long: [kept_path_bytes * 2]u8 = @splat('a');
    long[0] = '/';
    countPath(&record, .openat, &long, &test_grants);

    try std.testing.expectEqual(@as(u32, 1), record.kept);
    try std.testing.expectEqual(@as(usize, kept_path_bytes), record.name(0).len);
    try std.testing.expectEqualStrings(long[0..kept_path_bytes], record.name(0));
}

test "a name length written past the end of a slot is clamped rather than believed" {
    var record: PathRecord = .{};
    record.kept = 1;
    record.name_len[0] = kept_path_bytes * 4;
    try std.testing.expectEqual(@as(usize, kept_path_bytes), record.name(0).len);
}

test "the whole record stays in the hundreds of bytes" {
    try std.testing.expect(@sizeOf(PathRecord) <= 2048);
}

test "only a call that names a path has an argument to read" {
    try std.testing.expectEqual(@as(?u2, 1), seccomp.TrapCall.openat.pathArg());
    try std.testing.expectEqual(@as(?u2, 0), seccomp.TrapCall.execve.pathArg());
    try std.testing.expectEqual(@as(?u2, null), seccomp.TrapCall.connect.pathArg());
    try std.testing.expectEqual(@as(?u2, null), seccomp.TrapCall.getdents64.pathArg());
}

test "the reader reads a path out of another process and stops at the clamp" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

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
        return error.SkipZigTest;
    };
    try std.testing.expectEqualStrings("/etc/passwd", near.path);
    try std.testing.expect(!near.truncated);

    const far = readPath(child, @intFromPtr(&long), &buffer).?;
    try std.testing.expectEqual(@as(usize, path_read_clamp), far.path.len);
    try std.testing.expect(far.truncated);
}

test "a path the reader cannot reach is counted and never guessed at" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    var buffer: [path_read_clamp]u8 = undefined;
    try std.testing.expectEqual(@as(?PathRead, null), readPath(linux.getpid(), 0, &buffer));
}

test "the reader's own filter permits the one call the sandbox kills, and nothing the sandbox needs" {
    var reads_memory = false;
    var writes_memory = false;
    var opens = false;
    for (seccomp.reader_calls) |call| {
        if (call == .process_vm_readv) reads_memory = true;
        if (call == .process_vm_writev) writes_memory = true;
        if (call == .openat) opens = true;
    }
    try std.testing.expect(reads_memory);
    try std.testing.expect(!writes_memory);
    try std.testing.expect(!opens);

    var blocked_and_allowed: usize = 0;
    for (seccomp.reader_calls) |call| {
        for (seccomp.blocked_calls) |killed| {
            if (call == killed) blocked_and_allowed += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), blocked_and_allowed);
}
