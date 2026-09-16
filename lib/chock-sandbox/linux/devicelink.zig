//! The channel a device passthrough uses to cross the sandbox boundary: one
//! descriptor, one destination, and nothing else.
//!
//! ## What this is for
//!
//! Giving a sandboxed program a USB device or a serial adapter needs work on
//! both sides of the boundary. **Outside**, a process that is not sandboxed
//! decides which device is permitted and opens it: that decision needs the
//! real device tree, which the sandbox never sees. **Inside**, a helper puts
//! the open descriptor where a program can find it, at a path inside the
//! sandbox's own filesystem view. This file is the wire between those two: a
//! fixed size message that carries one open descriptor and the path it goes
//! to, over `SCM_RIGHTS`, the same way `netbroker.zig` and `routerlink.zig`
//! carry a descriptor across the same boundary for a connection.
//!
//! ## Authority is the descriptor, never the path
//!
//! `Place.path` says where the node goes **inside** the sandbox. It is never
//! a source: the inside half never resolves it against a filesystem, never
//! opens it, and never reads it as a name for anything the outside holds.
//! What the outside decided is already an open descriptor by the time it
//! reaches this wire, and the descriptor is what the receiving end places.
//!
//! This is what keeps a path race from handing over a device nobody
//! permitted. A check of the shape "is this path allowed, then open it" has a
//! gap between the two steps that a symlink can widen. There is no such gap
//! here, because there is no open by name on this side of the boundary at
//! all: the path only says where the already open descriptor is put.
//!
//! ## `Place` and `Drop`, and why they are not a request and a reply
//!
//! Every other channel in this library asks a question and reads one answer:
//! `netbroker.Request`/`Reply` and `routerlink.Request`/`Reply` both cross the
//! boundary from the sandboxed side outward and come back once. This one runs
//! the other way. The outside decides on its own schedule, with no question
//! from the inside to answer: a device becomes available, so it sends
//! `Place`, and a device goes away, so it sends `Drop`. Nothing here waits for
//! either to be asked for, and nothing answers back across the wire: what
//! `serveOne` did is `Outcome`, read by the loop that called it, not sent
//! anywhere.
//!
//! `request_magic` and `reply_magic` are still the names for the two magics,
//! the same as every other channel in this library, so a message read with
//! the wrong one of the two structures is refused the same way a reply read
//! as a request is. `Place` carries `request_magic` because it is the
//! message that starts something, and `Drop` carries `reply_magic` because it
//! ends what a `Place` started.
//!
//! ## `fd_number` is 4, not 3
//!
//! `routerlink.fd_number` already owns 3, and a `.filtered` call installs at
//! most one of `net_broker` or `net_router` at a time: see
//! `Sandbox.Config.net_router`. A device passthrough is not exclusive with
//! either, so its own descriptor needs a number neither of them uses.
//!
//! ## Linux only, and why the file is here
//!
//! `SCM_RIGHTS` exists on Darwin too, but `Sandbox.spawn` refuses a
//! `.filtered` call there, so there is no channel to serve. The file sits
//! under `linux/` with the rest of the mechanism, for the same reason
//! `netbroker.zig` and `routerlink.zig` do. It compiles for Darwin, and every
//! test in it that opens a socket answers `error.SkipZigTest` there.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const netbroker = @import("netbroker.zig");

/// The descriptor number the in-sandbox helper finds its channel on. **Not
/// `routerlink.fd_number`**: see this file's own top comment for why the two
/// numbers must differ.
pub const fd_number: i32 = 4;

/// The bytes "CDV1", so a message that is not one of ours is refused rather
/// than read as a `Place`. Carried by `Place`. See this file's own top
/// comment for why this channel has no request and reply in the usual sense,
/// and `netbroker.request_magic` for why a pair with exactly two ends carries
/// a magic anyway.
pub const request_magic: u32 = 0x31564443;

/// The bytes "CDR1". Carried by `Drop`. See `request_magic`.
pub const reply_magic: u32 = 0x31524443;

/// The longest destination path one message may carry. `sun_path` on an
/// `AF_UNIX` address is 108 bytes on Linux, including the trailing nul, and a
/// device node's destination is a plain filesystem path of the same practical
/// length as the one Chock already binds a device special file to.
pub const max_path_bytes: usize = 108;

/// Told to the in-sandbox helper: put `handle` at `path`, which names where
/// the node goes **inside** the sandbox. Fixed size, so `serveOne` can refuse
/// a message of the wrong length outright rather than parsing whatever
/// arrived. One descriptor rides with this in `SCM_RIGHTS`, and that
/// descriptor is `handle`: nothing in the structure itself names it.
pub const Place = extern struct {
    magic: u32 = request_magic,
    /// Which kind of node `path` should become. Opaque to this file: the
    /// helper that implements `DeviceSeam.place` is the one that reads it.
    /// Left as a plain byte, and not an enum, because this file never
    /// branches on it and has no set of values to be authoritative about.
    kind: u8 = 0,
    /// Always zero. Present so the structure has no padding the compiler
    /// chose, which would otherwise send this process's own memory across
    /// the boundary in the gap.
    _pad: [3]u8 = @splat(0),
    /// How many bytes of `path` are the destination. Bounded by `serveOne`
    /// before it is used.
    path_len: u32 = 0,
    path: [max_path_bytes]u8 = @splat(0),
};

/// Told to the in-sandbox helper: take the node at `path` back out. No
/// descriptor rides with this one: removing a node needs no authority beyond
/// naming which node, unlike putting one there.
pub const Drop = extern struct {
    magic: u32 = reply_magic,
    path_len: u32 = 0,
    path: [max_path_bytes]u8 = @splat(0),
};

/// Who does the real work once a message has been read and bounded. The
/// in-sandbox helper implements this. `serveOne` only ever hands it a path
/// and, for a `place`, a descriptor already known to be open. **Which paths
/// may be written and how a node is made there is the seam's question**, the
/// same division `netbroker.NetBroker` draws between the wire and the policy
/// behind it.
pub const DeviceSeam = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    /// What one call to `place` or `drop` did.
    ///
    /// **Two answers, and nothing beyond them.** A mount can fail, a name can
    /// already be taken, a permission can be missing, or `kind` can be a byte
    /// the seam does not implement. None of that is this file's business:
    /// `netbroker.NetBroker.Grant` and `NetRouter.Resolution`, the two seams
    /// this one is modelled on, both stop at "it worked" or "it did not" and
    /// leave the reason to the implementation's own log. `Result` keeps the
    /// same line: a caller that wants to count a fault, write a log entry, or
    /// raise a status flag has what it needs from `serveOne`'s `Outcome`
    /// below, and this type never grows a taxonomy of reasons nobody outside
    /// the seam could act on anyway.
    ///
    /// **Not a plain `bool`.** A `place` that returns `true` reads as "placed
    /// this" only if the reader already remembers what the call was; `.done`
    /// reads the same at every call site, which is the whole point of naming
    /// the two states instead of leaving them as `1` and `0`.
    pub const Result = enum {
        /// The seam did what was asked. `handle` is now reachable at `path`,
        /// or the node at `path` is gone, depending on which call this
        /// answers.
        done,
        /// It could not. The seam still owns whatever it was given: see
        /// `VTable.place`.
        failed,
    };

    pub const VTable = struct {
        /// Put `handle` at `path`. **The seam owns `handle` from here**: it
        /// closes it, or moves it somewhere a program can reach, and
        /// `serveOne` never touches it again either way, whether this
        /// answers `.done` or `.failed`.
        place: *const fn (ptr: *anyopaque, kind: u8, path: []const u8, handle: i32) Result,
        /// Take the node at `path` back out.
        drop: *const fn (ptr: *anyopaque, path: []const u8) Result,
    };

    pub fn place(self: DeviceSeam, kind: u8, path: []const u8, handle: i32) Result {
        return self.vtable.place(self.ptr, kind, path, handle);
    }

    pub fn drop(self: DeviceSeam, path: []const u8) Result {
        return self.vtable.drop(self.ptr, path);
    }
};

/// What one `serveOne` did, for the caller that drives the helper's loop.
pub const Outcome = enum {
    /// A `Place` was read and the seam placed it.
    placed,
    /// A `Place` was read and handed to the seam, and the seam answered
    /// `.failed`. **Carried outward and not absorbed**: a caller that never
    /// saw this could not increment a fault counter, write a log entry, or
    /// raise a status flag for it, which is what a silent failure here would
    /// otherwise be.
    place_failed,
    /// A `Drop` was read and the seam removed it.
    dropped,
    /// A `Drop` was read and handed to the seam, and the seam answered
    /// `.failed`. See `place_failed`.
    drop_failed,
    /// The far end is gone, so the loop is over.
    peer_gone,
    /// Nothing was there after all, a signal interrupted the read, or what
    /// arrived was not a `Place` or a `Drop` this file recognises. **Refused
    /// the same way whichever of those it was**: a caller that only wants to
    /// know whether to keep looping never needs to tell them apart, and the
    /// seam is never called for any of them.
    nothing,
};

// ---------------------------------------------------------------------------
// The inside half: the in-sandbox helper reads here.
// ---------------------------------------------------------------------------

/// Read one message and hand it to `seam`. **This is the inside half**,
/// called by the helper that runs inside the sandbox on the end of the pair
/// that crossed in.
///
/// Call it only when the descriptor is readable. It does one `recvmsg` and
/// never waits for anything else.
///
/// ## What is checked here, and what is not
///
/// The shape, and only the shape: exactly one `Place` with our magic and
/// exactly one descriptor, or exactly one `Drop` with our magic and no
/// descriptor at all, and for either a `path_len` that fits in `path`.
/// **Which paths the seam will actually write is its question**, and this
/// file must never grow a second answer to it: the same division
/// `netbroker.serveOne` and `routerlink.serveOne` draw against their own
/// seams.
///
/// A `Place` with no descriptor, or a `Drop` with one, is refused outright
/// rather than handed to the seam anyway: `handle` is the one thing `Place`
/// exists to carry, and a `Drop` that carried a descriptor would be a far end
/// that is not the one this file expects, since removing a node needs no
/// authority to hand over.
pub fn serveOne(fd: i32, seam: DeviceSeam) Outcome {
    // Sized for the larger of the two messages. A `Drop`, which is shorter,
    // still lands whole in it: `SOCK_SEQPACKET` keeps message boundaries, so
    // a short message is a short `recvmsg` and never a fragment of a longer
    // one still to come.
    var buffer: [@sizeOf(Place)]u8 align(@alignOf(Place)) = undefined;
    var iov = [1]std.posix.iovec{.{ .base = &buffer, .len = buffer.len }};
    var control: [control_bytes]u8 align(@alignOf(linux.cmsghdr)) = undefined;
    var message = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };

    // `MSG_CMSG_CLOEXEC` so a descriptor that arrives is close-on-exec. The
    // helper never runs another program with it before `place` has had the
    // chance to move it, and the safe default is the one that does not leak
    // a device into a process nobody meant to give it to.
    const rc = linux.recvmsg(fd, &message, linux.MSG.CMSG_CLOEXEC);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .AGAIN, .INTR => return .nothing,
        else => return .peer_gone,
    }
    // Zero is the end of the stream: the far end closed.
    if (rc == 0) return .peer_gone;

    const received = netbroker.firstReceivedFd(&message, &control);
    const truncated = (message.flags & linux.MSG.TRUNC) != 0;

    if (rc == @sizeOf(Place) and !truncated) {
        const place: *const Place = @ptrCast(@alignCast(&buffer));
        if (place.magic == request_magic and
            std.mem.allEqual(u8, &place._pad, 0) and
            place.path_len > 0 and place.path_len <= max_path_bytes)
        {
            if (received) |handle| {
                return switch (seam.place(place.kind, place.path[0..place.path_len], handle)) {
                    .done => .placed,
                    .failed => .place_failed,
                };
            }
        }
    } else if (rc == @sizeOf(Drop) and !truncated) {
        const drop: *const Drop = @ptrCast(@alignCast(buffer[0..@sizeOf(Drop)]));
        if (drop.magic == reply_magic and received == null and
            drop.path_len > 0 and drop.path_len <= max_path_bytes)
        {
            return switch (seam.drop(drop.path[0..drop.path_len])) {
                .done => .dropped,
                .failed => .drop_failed,
            };
        }
    }

    // Whatever this was, it is not a message this file understood. A
    // descriptor that rode with it is not handed to the seam: closing it
    // here is the only way it is not simply leaked.
    if (received) |handle| _ = linux.close(handle);
    return .nothing;
}

// ---------------------------------------------------------------------------
// The outside half: the process that opened the device sends here.
// ---------------------------------------------------------------------------

/// Why a send did not go out. Both members are the same fact a caller of
/// `netbroker.ask` already reads as `error.BrokerGone`: the far end is not
/// there to carry the message, whichever step noticed it first.
pub const SendError = error{
    /// `path` is empty or longer than `max_path_bytes`.
    PathUnusable,
    /// The far end has gone, or would not take the message.
    PeerGone,
};

/// Send a `Place` naming `handle` and `path`. **This is the outside half**,
/// called by the process that opened the device, on the end of the pair that
/// stayed outside the sandbox.
///
/// `handle` still belongs to this call's caller once it returns: sending a
/// descriptor with `SCM_RIGHTS` duplicates it into the receiving process, and
/// closing it here is left to the caller, the same as `netbroker.zig`'s own
/// grant leaves its handle to whoever passed it in.
pub fn sendPlace(fd: i32, kind: u8, path: []const u8, handle: i32) SendError!void {
    if (path.len == 0 or path.len > max_path_bytes) return error.PathUnusable;

    var place = Place{ .kind = kind, .path_len = @intCast(path.len) };
    @memcpy(place.path[0..path.len], path);

    var iov = [1]std.posix.iovec_const{.{ .base = @ptrCast(&place), .len = @sizeOf(Place) }};
    var control: [control_bytes]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const header: *linux.cmsghdr = @ptrCast(@alignCast(&control));
    header.* = .{ .len = cmsg_len, .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS };
    // `@memcpy` and not a pointer store, because the payload of a control
    // message has the alignment of the buffer and not of an `i32`: see
    // `netbroker.grant`, whose own comment this reasoning is copied from.
    @memcpy(control[cmsg_data_offset..][0..@sizeOf(i32)], std.mem.asBytes(&handle));

    var message = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    // `MSG_NOSIGNAL` so a peer that has already gone answers `EPIPE` here
    // instead of raising `SIGPIPE` at this whole process. See `netbroker.ask`
    // for the measurement behind the same flag on the same socket type.
    const rc = linux.sendmsg(fd, &message, linux.MSG.NOSIGNAL);
    if (linux.errno(rc) != .SUCCESS or rc != @sizeOf(Place)) return error.PeerGone;
}

/// Send a `Drop` naming `path`. No descriptor rides with it: see `Drop`'s own
/// doc comment for why removing a node needs none.
pub fn sendDrop(fd: i32, path: []const u8) SendError!void {
    if (path.len == 0 or path.len > max_path_bytes) return error.PathUnusable;

    var drop = Drop{ .path_len = @intCast(path.len) };
    @memcpy(drop.path[0..path.len], path);

    const sent = linux.sendto(fd, @ptrCast(&drop), @sizeOf(Drop), linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(sent) != .SUCCESS or sent != @sizeOf(Drop)) return error.PeerGone;
}

const cmsg_data_offset: usize = netbroker.cmsg_data_offset;
const cmsg_len: usize = netbroker.cmsg_len;
const control_bytes: usize = netbroker.control_bytes;

/// Make the pair one device passthrough uses. `[0]` stays outside the
/// sandbox and `[1]` crosses into it, the same split `routerlink.makePair`
/// and `netbroker.makePair` use.
///
/// Both ends are close-on-exec. The driver clears the flag on the child's end
/// in the last step before the in-sandbox helper runs, and nowhere earlier,
/// so a sandbox that failed to come up never hands a program a channel out.
pub fn makePair() error{SocketFailed}![2]i32 {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &fds);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    return fds;
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Linux only, the same rule the rest of this library follows: a test that
/// opens a socket makes a Linux system call, and this file compiles for
/// Darwin so that `chock-sandbox.zig` can name it there.
fn linuxOnly() !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
}

/// A device number: the pair `statx` answers `dev_major`/`dev_minor` as, and
/// what proves two descriptors name the same inode when paired with `ino`.
/// `st_dev` on an ordinary `fstat` is this same pair packed into one integer,
/// and `statx` hands the two halves over unpacked instead.
const Identity = struct {
    dev_major: u32,
    dev_minor: u32,
    ino: u64,

    fn of(fd: i32) !Identity {
        var stx: linux.Statx = undefined;
        const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, linux.STATX.BASIC_STATS, &stx);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
        return .{ .dev_major = stx.dev_major, .dev_minor = stx.dev_minor, .ino = stx.ino };
    }
};

/// A temporary file with no name in the directory tree: `O_TMPFILE` makes an
/// inode that exists only through the descriptor this opens, so nothing else
/// on the machine can hand a test the same identity by accident.
fn openTempFile() !i32 {
    const rc = linux.open("/tmp", .{ .ACCMODE = .RDWR, .DIRECTORY = true, .TMPFILE = true, .CLOEXEC = true }, 0o600);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    return @intCast(rc);
}

/// How many descriptors this process holds, read out of `/proc/self/fd`. The
/// same helper `netbroker.zig` uses for its own "a descriptor a sandboxed
/// process sends across is never received" test, copied here rather than made
/// public there: it reads process state and takes no part of either wire.
fn openDescriptorCount() usize {
    const rc = linux.open("/proc/self/fd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return 0;
    const dir: i32 = @intCast(rc);
    defer _ = linux.close(dir);

    var count: usize = 0;
    var buffer: [4096]u8 = undefined;
    while (true) {
        const nread = linux.getdents64(dir, &buffer, buffer.len);
        if (linux.errno(nread) != .SUCCESS or nread == 0) break;
        var offset: usize = 0;
        while (offset < nread) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            count += 1;
            offset += entry.reclen;
        }
    }
    return count;
}

/// A seam that records what it was asked, and hands back the paths and the
/// descriptor identity it saw. A test reads these rather than trusting that
/// `serveOne` called it correctly.
const StubSeam = struct {
    places: usize = 0,
    drops: usize = 0,
    place_kind: u8 = 0,
    place_path: [max_path_bytes]u8 = @splat(0),
    place_path_len: usize = 0,
    place_identity: ?Identity = null,
    drop_path: [max_path_bytes]u8 = @splat(0),
    drop_path_len: usize = 0,
    /// What `placeFn` answers. A test that wants to see `.place_failed` carry
    /// out through `serveOne` sets this to `.failed` first.
    place_result: DeviceSeam.Result = .done,
    /// What `dropFn` answers. See `place_result`.
    drop_result: DeviceSeam.Result = .done,

    fn seam(self: *StubSeam) DeviceSeam {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = DeviceSeam.VTable{ .place = placeFn, .drop = dropFn };

    fn placeFn(ptr: *anyopaque, kind: u8, path: []const u8, handle: i32) DeviceSeam.Result {
        const self: *StubSeam = @ptrCast(@alignCast(ptr));
        self.places += 1;
        self.place_kind = kind;
        @memcpy(self.place_path[0..path.len], path);
        self.place_path_len = path.len;
        self.place_identity = Identity.of(handle) catch null;
        _ = linux.close(handle);
        return self.place_result;
    }

    fn dropFn(ptr: *anyopaque, path: []const u8) DeviceSeam.Result {
        const self: *StubSeam = @ptrCast(@alignCast(ptr));
        self.drops += 1;
        @memcpy(self.drop_path[0..path.len], path);
        self.drop_path_len = path.len;
        return self.drop_result;
    }

    fn sawPlacePath(self: *const StubSeam) []const u8 {
        return self.place_path[0..self.place_path_len];
    }

    fn sawDropPath(self: *const StubSeam) []const u8 {
        return self.drop_path[0..self.drop_path_len];
    }
};

test "both wire structures are a fixed size with no padding a compiler chose" {
    // **The size is the framing.** `serveOne` tells a `Place` from a `Drop`
    // by the byte count `recvmsg` reports, which is only a fact both ends
    // agree on while the size is written out and not left to the compiler.
    try testing.expectEqual(@as(usize, 4 + 1 + 3 + 4 + max_path_bytes), @sizeOf(Place));
    try testing.expectEqual(@as(usize, 4 + 4 + max_path_bytes), @sizeOf(Drop));
    try testing.expect(@sizeOf(Place) != @sizeOf(Drop));
    try testing.expect(request_magic != reply_magic);
}

test "a placement carries a descriptor and a destination, and nothing else" {
    try linuxOnly();
    // Authority is the descriptor. The far side never resolves a host path,
    // so a path race cannot hand it a file nobody permitted: there is no
    // path to race. See this file's own top comment.
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const given = try openTempFile();
    defer _ = linux.close(given);
    const sent_identity = try Identity.of(given);

    try sendPlace(pair[0], 7, "/dev/chock-widget0", given);

    var stub = StubSeam{};
    try testing.expectEqual(Outcome.placed, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 1), stub.places);
    try testing.expectEqual(@as(usize, 0), stub.drops);
    try testing.expectEqual(@as(u8, 7), stub.place_kind);
    try testing.expectEqualStrings("/dev/chock-widget0", stub.sawPlacePath());

    // **The proof a descriptor crossed, and not merely that one arrived.** A
    // send that carried the wrong number, or a fresh descriptor with nothing
    // behind it, would still make `serveOne` answer `.placed`; only the
    // identity comparison catches that.
    const got_identity = stub.place_identity orelse return error.NoIdentityRead;
    try testing.expectEqual(sent_identity.dev_major, got_identity.dev_major);
    try testing.expectEqual(sent_identity.dev_minor, got_identity.dev_minor);
    try testing.expectEqual(sent_identity.ino, got_identity.ino);
}

test "a message of the wrong length is refused outright" {
    try linuxOnly();
    // The same rule `netbroker.serveOne` keeps: a fixed size structure lets a
    // reader refuse a short or long message rather than parse whatever
    // arrived.
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const short = [_]u8{0} ** 8;
    const rc = linux.sendto(pair[0], &short, short.len, linux.MSG.NOSIGNAL, null, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));

    var stub = StubSeam{};
    try testing.expectEqual(Outcome.nothing, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 0), stub.places);
    try testing.expectEqual(@as(usize, 0), stub.drops);

    // A long message, past even `Place`, is the one a length check alone
    // cannot see: the kernel copies what fits and reports the size of the
    // buffer, so this would otherwise read as a well formed `Place` with a
    // tail nobody saw. `MSG_TRUNC` in the answered flags is the only sign of
    // it.
    var oversize: [@sizeOf(Place) + 64]u8 = @splat(0);
    var place = Place{ .path_len = 3 };
    @memcpy(place.path[0..3], "abc");
    @memcpy(oversize[0..@sizeOf(Place)], std.mem.asBytes(&place));
    const long_rc = linux.sendto(pair[0], &oversize, oversize.len, linux.MSG.NOSIGNAL, null, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(long_rc));
    try testing.expectEqual(Outcome.nothing, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 0), stub.places);
}

test "a drop names no descriptor, and one is closed rather than handed over" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try sendDrop(pair[0], "/dev/chock-widget0");

    var stub = StubSeam{};
    try testing.expectEqual(Outcome.dropped, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 1), stub.drops);
    try testing.expectEqualStrings("/dev/chock-widget0", stub.sawDropPath());

    // A `Drop` sent with a descriptor riding along anyway, as `sendDrop`
    // itself never does but a hostile or broken sender might. **Refused
    // outright, and the seam is never asked**: removing a node needs no
    // authority to hand over, so a descriptor here names a sender this file
    // does not expect.
    const given = try openTempFile();
    defer _ = linux.close(given);

    var drop = Drop{ .path_len = 3 };
    @memcpy(drop.path[0..3], "abc");
    var iov = [1]std.posix.iovec_const{.{ .base = @ptrCast(&drop), .len = @sizeOf(Drop) }};
    var control: [control_bytes]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const header: *linux.cmsghdr = @ptrCast(@alignCast(&control));
    header.* = .{ .len = cmsg_len, .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS };
    @memcpy(control[cmsg_data_offset..][0..@sizeOf(i32)], std.mem.asBytes(&given));
    var message = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.sendmsg(pair[0], &message, 0)));
    try testing.expectEqual(Outcome.nothing, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 1), stub.drops);
}

test "a seam that cannot place or drop is carried outward, not swallowed" {
    try linuxOnly();
    // Before this file grew `DeviceSeam.Result`, a failed mount, an EEXIST, a
    // permission denial, or a bad `kind` all vanished at `place` and `drop`:
    // `serveOne` answered `.placed` or `.dropped` either way, because there
    // was nothing else it could answer. This is the test that pins the fix: a
    // seam that answers `.failed` must turn into an `Outcome` a caller can
    // count, log, or raise a status flag over, and never into the same
    // `Outcome` a real success gives.
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const given = try openTempFile();
    defer _ = linux.close(given);
    try sendPlace(pair[0], 1, "/dev/chock-widget0", given);

    var stub = StubSeam{ .place_result = .failed };
    try testing.expectEqual(Outcome.place_failed, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 1), stub.places);

    try sendDrop(pair[0], "/dev/chock-widget0");
    stub.drop_result = .failed;
    try testing.expectEqual(Outcome.drop_failed, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 1), stub.drops);
}

test "a message this file refuses does not leak the descriptor that rode with it" {
    try linuxOnly();
    // The property is descriptor hygiene by reading, not by a test: the last
    // lines of `serveOne` close `handle` when nothing else claimed it. This
    // is the same proof `netbroker.zig`'s own "a descriptor a sandboxed
    // process sends across is never received" uses: both ends of the pair are
    // in this one process, so a descriptor that crossed and was not closed
    // shows up as a higher `openDescriptorCount()` afterward, and one that was
    // closed does not.
    //
    // Mutation check: delete the `if (received) |handle| _ = linux.close(handle);`
    // line at the end of `serveOne` and this test fails, because the copy of
    // `given` that crossed to `pair[1]` stays open on a fresh number.
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const given = try openTempFile();
    defer _ = linux.close(given);

    const before = openDescriptorCount();

    // A magic that is not ours, so `serveOne` falls through past both the
    // `Place` and the `Drop` branches to the final, catch-all close. `given`
    // still rides along in `SCM_RIGHTS`.
    var place = Place{ .magic = 0xdeadbeef, .path_len = 3 };
    @memcpy(place.path[0..3], "abc");
    var iov = [1]std.posix.iovec_const{.{ .base = @ptrCast(&place), .len = @sizeOf(Place) }};
    var control: [control_bytes]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const header: *linux.cmsghdr = @ptrCast(@alignCast(&control));
    header.* = .{ .len = cmsg_len, .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS };
    @memcpy(control[cmsg_data_offset..][0..@sizeOf(i32)], std.mem.asBytes(&given));
    var message = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.sendmsg(pair[0], &message, 0)));

    var stub = StubSeam{};
    try testing.expectEqual(Outcome.nothing, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 0), stub.places);

    try testing.expectEqual(before, openDescriptorCount());
}

test "a placement with no descriptor is refused rather than handed to the seam" {
    try linuxOnly();
    // `sendPlace` never sends one of these, so this is a far end that is not
    // the one this file expects: the same shape check `netbroker.serveOne`
    // keeps against a message that is well formed but missing what makes it
    // usable.
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    var place = Place{ .path_len = 3 };
    @memcpy(place.path[0..3], "abc");
    const rc = linux.sendto(pair[0], @ptrCast(&place), @sizeOf(Place), linux.MSG.NOSIGNAL, null, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));

    var stub = StubSeam{};
    try testing.expectEqual(Outcome.nothing, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 0), stub.places);
}

test "a magic that is not ours, a reserved byte, or a path of no length is refused" {
    try linuxOnly();
    // Every one of these is refused without the seam being asked anything,
    // which is what makes the shape check a boundary and not a parser. See
    // `routerlink`'s own test of the same name for the pattern.
    const cases = [_]struct { name: []const u8, place: Place }{
        .{ .name = "a magic that is not ours", .place = blk: {
            var one = Place{ .magic = 0xdeadbeef, .path_len = 3 };
            @memcpy(one.path[0..3], "abc");
            break :blk one;
        } },
        .{ .name = "a reserved byte that is not zero", .place = blk: {
            var one = Place{ .path_len = 3, ._pad = .{ 1, 0, 0 } };
            @memcpy(one.path[0..3], "abc");
            break :blk one;
        } },
        .{ .name = "a path of no length", .place = Place{ .path_len = 0 } },
        .{ .name = "a path longer than the buffer", .place = Place{ .path_len = max_path_bytes + 1 } },
    };

    var got_through: std.ArrayList(u8) = .empty;
    defer got_through.deinit(testing.allocator);

    for (cases) |case| {
        const pair = try makePair();
        defer _ = linux.close(pair[0]);
        defer _ = linux.close(pair[1]);

        const given = try openTempFile();
        defer _ = linux.close(given);

        var place = case.place;
        var iov = [1]std.posix.iovec_const{.{ .base = @ptrCast(&place), .len = @sizeOf(Place) }};
        var control: [control_bytes]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
        const header: *linux.cmsghdr = @ptrCast(@alignCast(&control));
        header.* = .{ .len = cmsg_len, .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS };
        @memcpy(control[cmsg_data_offset..][0..@sizeOf(i32)], std.mem.asBytes(&given));
        var message = linux.msghdr_const{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &control,
            .controllen = control.len,
            .flags = 0,
        };
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.sendmsg(pair[0], &message, 0)));

        var stub = StubSeam{};
        const outcome = serveOne(pair[1], stub.seam());
        if (outcome != .nothing) {
            try got_through.print(testing.allocator, "{s} answered {t}\n", .{ case.name, outcome });
        }
        if (stub.places + stub.drops != 0) {
            try got_through.print(testing.allocator, "{s} reached the seam\n", .{case.name});
        }
    }

    try testing.expectEqualStrings("", got_through.items);
}

test "the far side is gone once its peer has closed" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[1]);
    _ = linux.close(pair[0]);

    var stub = StubSeam{};
    try testing.expectEqual(Outcome.peer_gone, serveOne(pair[1], stub.seam()));
}

test "sendPlace and sendDrop refuse a path they could not put in a message" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const given = try openTempFile();
    defer _ = linux.close(given);

    try testing.expectError(error.PathUnusable, sendPlace(pair[0], 0, "", given));
    try testing.expectError(error.PathUnusable, sendPlace(pair[0], 0, "a" ** (max_path_bytes + 1), given));
    try testing.expectError(error.PathUnusable, sendDrop(pair[0], ""));
    try testing.expectError(error.PathUnusable, sendDrop(pair[0], "a" ** (max_path_bytes + 1)));
}

test "a channel that has gone answers PeerGone rather than waiting" {
    try linuxOnly();
    const pair = try makePair();
    _ = linux.close(pair[1]);
    defer _ = linux.close(pair[0]);

    const given = try openTempFile();
    defer _ = linux.close(given);

    try testing.expectError(error.PeerGone, sendPlace(pair[0], 0, "/dev/chock-widget0", given));
    try testing.expectError(error.PeerGone, sendDrop(pair[0], "/dev/chock-widget0"));
}
