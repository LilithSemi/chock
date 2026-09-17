//! The channel a device passthrough uses to cross the sandbox boundary: two
//! paths and nothing else.
//!
//! ## What this is for
//!
//! Giving a sandboxed program a USB device or a serial adapter needs work on
//! both sides of the boundary. **Outside**, a process that is not sandboxed
//! decides which device is permitted, by Chock's own policy, and names it as
//! a path relative to the one host directory that policy already chose: see
//! `Sandbox.Config.device_tree`. **Inside**, a helper resolves that path
//! against a hidden copy of that directory, bound into the sandbox's own
//! root before anything pivots, and binds the node it finds there to a path
//! a program can open. This file is the wire between those two: a fixed
//! size message that carries the two paths, over an ordinary
//! `SOCK_SEQPACKET` pair, the same kind of pair `netbroker.zig` and
//! `routerlink.zig` use for their own channels.
//!
//! ## Authority is a path Chock chose, out of a tree the program cannot read
//!
//! **This channel used to carry an open descriptor, and this file used to
//! claim that authority was the descriptor and never a path. That claim no
//! longer holds, and it must not be repeated.** A descriptor opened on the
//! host and sent across `SCM_RIGHTS` cannot become a mount inside the
//! in-sandbox helper's own mount namespace: a bind mount can only be made
//! from a filesystem that belongs to the caller's *own current* mount
//! namespace, and a descriptor opened before the helper's own `unshare`
//! never does, whichever of `open_tree` or plain `mount` does the binding.
//! Measured directly against this project's own kernel; see
//! `.superpowers/sdd/task-4b-report.md` for both dead ends.
//!
//! The guarantee this channel gives instead is narrower, and has to be
//! stated as what it really is: **the helper binds a path Chock's host side
//! chose, after asking its own policy, out of a tree the sandboxed program
//! cannot read.** `Place.source` is a path, and the inside half really does
//! resolve it, against `Sandbox.Config.device_tree.host`, bound into the
//! sandbox's own root at `device_tree.inside` before anything pivots and
//! never granted through Landlock. The sandboxed program cannot open that
//! directory by name, list it, or resolve any path under it. Only Chock's
//! own host side decides what `device_tree.host` names, and only Chock's
//! own host side ever holds the writing end of this pair, so the caller of
//! `sendPlace` controls both what the hidden tree is and what `source` may
//! be relative to it. A sandboxed process controls neither. That is
//! equivalent in practice to what the descriptor gave, even though it is
//! not the same mechanism: an agent inside the sandbox has no path to the
//! hidden tree at all, and the one path it does control, `target`, is
//! merely where the node lands, checked the same way it always was.
//!
//! **`serveOne` still refuses nothing about `source` beyond its length.**
//! The one check that stops a `source` from climbing back out of the hidden
//! tree, no leading `/`, no `..` component, no empty component, lives in
//! `driver.zig`'s own `buildDeviceSource`, not here: the same division this
//! file already keeps between the wire's shape and the seam's own policy
//! over what a path may resolve to. See `serveOne`'s own doc comment.
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
//! Bind mounts exist on Darwin too, but `Sandbox.spawn` refuses a
//! `.filtered` call there, so there is no channel to serve. The file sits
//! under `linux/` with the rest of the mechanism, for the same reason
//! `netbroker.zig` and `routerlink.zig` do. It compiles for Darwin, and every
//! test in it that opens a socket answers `error.SkipZigTest` there.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

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

/// The longest `source` or `target` one message may carry. Generous over a
/// real device path: `bus/usb/001/005` and `/dev/bus/usb/001/005` are both
/// far short of it, and it is the same bound this file has always used for a
/// device node's own destination.
pub const max_path_bytes: usize = 108;

/// Told to the in-sandbox helper: bind the node at `source`, relative to
/// `Sandbox.Config.device_tree.host`, at `target`, an absolute path inside
/// the sandbox. Fixed size, so `serveOne` can refuse a message of the wrong
/// length outright rather than parsing whatever arrived.
pub const Place = extern struct {
    magic: u32 = request_magic,
    /// Which kind of node `target` should become. Opaque to this file: the
    /// helper that implements `DeviceSeam.place` is the one that reads it.
    /// Left as a plain byte, and not an enum, because this file never
    /// branches on it and has no set of values to be authoritative about.
    kind: u8 = 0,
    /// Always zero. Present so the structure has no padding the compiler
    /// chose, which would otherwise send this process's own memory across
    /// the boundary in the gap.
    _pad: [3]u8 = @splat(0),
    /// How many bytes of `source` are the path. Bounded by `serveOne` before
    /// it is used.
    source_len: u32 = 0,
    /// A path relative to the hidden device tree. **Never resolved here.**
    /// This file only bounds its length; whether it climbs back out of the
    /// tree it is relative to is `driver.zig`'s own `buildDeviceSource`
    /// question, the same as it always was for `target` below.
    source: [max_path_bytes]u8 = @splat(0),
    /// How many bytes of `target` are the path. Bounded by `serveOne` before
    /// it is used.
    target_len: u32 = 0,
    /// The destination, inside the sandbox.
    target: [max_path_bytes]u8 = @splat(0),
};

/// Told to the in-sandbox helper: take the node at `path` back out. `path`
/// names the same destination `Place.target` would have named: there is no
/// `source` to carry, since removing a node needs no authority beyond
/// naming which one.
pub const Drop = extern struct {
    magic: u32 = reply_magic,
    path_len: u32 = 0,
    path: [max_path_bytes]u8 = @splat(0),
};

/// Who does the real work once a message has been read and bounded. The
/// in-sandbox helper implements this. `serveOne` only ever hands it the two
/// paths a `Place` carried, or the one path a `Drop` carried. **Which paths
/// may be resolved and how a node is made there is the seam's question**,
/// the same division `netbroker.NetBroker` draws between the wire and the
/// policy behind it.
pub const DeviceSeam = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    /// What one call to `place` or `drop` did.
    ///
    /// **Two answers, and nothing beyond them.** A mount can fail, a name can
    /// already be taken, a permission can be missing, a `source` can climb
    /// back out of the tree it is relative to, or `kind` can be a byte the
    /// seam does not implement. None of that is this file's business:
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
        /// The seam did what was asked. The node is now reachable at
        /// `target`, or the node at `path` is gone, depending on which call
        /// this answers.
        done,
        /// It could not.
        failed,
    };

    pub const VTable = struct {
        /// Bind the node at `source`, relative to the seam's own hidden
        /// tree, at `target`, inside the sandbox.
        place: *const fn (ptr: *anyopaque, kind: u8, source: []const u8, target: []const u8) Result,
        /// Take the node at `path` back out.
        drop: *const fn (ptr: *anyopaque, path: []const u8) Result,
    };

    pub fn place(self: DeviceSeam, kind: u8, source: []const u8, target: []const u8) Result {
        return self.vtable.place(self.ptr, kind, source, target);
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
/// The shape, and only the shape: exactly one `Place` with our magic and a
/// `source_len` and `target_len` that each fit in their own buffer, or
/// exactly one `Drop` with our magic and a `path_len` that fits. **Whether
/// `source` may resolve to anything, or where `target` may land, is the
/// seam's own question**, and this file must never grow a second answer to
/// it: the same division `netbroker.serveOne` and `routerlink.serveOne` draw
/// against their own seams.
pub fn serveOne(fd: i32, seam: DeviceSeam) Outcome {
    // Sized for the larger of the two messages. A `Drop`, which is shorter,
    // still lands whole in it: `SOCK_SEQPACKET` keeps message boundaries, so
    // a short message is a short `recvmsg` and never a fragment of a longer
    // one still to come.
    var buffer: [@sizeOf(Place)]u8 align(@alignOf(Place)) = undefined;
    var iov = [1]std.posix.iovec{.{ .base = &buffer, .len = buffer.len }};
    var message = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const rc = linux.recvmsg(fd, &message, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .AGAIN, .INTR => return .nothing,
        else => return .peer_gone,
    }
    // Zero is the end of the stream: the far end closed.
    if (rc == 0) return .peer_gone;

    const truncated = (message.flags & linux.MSG.TRUNC) != 0;

    if (rc == @sizeOf(Place) and !truncated) {
        const place: *const Place = @ptrCast(@alignCast(&buffer));
        if (place.magic == request_magic and
            std.mem.allEqual(u8, &place._pad, 0) and
            place.source_len > 0 and place.source_len <= max_path_bytes and
            place.target_len > 0 and place.target_len <= max_path_bytes)
        {
            return switch (seam.place(
                place.kind,
                place.source[0..place.source_len],
                place.target[0..place.target_len],
            )) {
                .done => .placed,
                .failed => .place_failed,
            };
        }
    } else if (rc == @sizeOf(Drop) and !truncated) {
        const drop: *const Drop = @ptrCast(@alignCast(buffer[0..@sizeOf(Drop)]));
        if (drop.magic == reply_magic and drop.path_len > 0 and drop.path_len <= max_path_bytes) {
            return switch (seam.drop(drop.path[0..drop.path_len])) {
                .done => .dropped,
                .failed => .drop_failed,
            };
        }
    }

    // Whatever this was, it is not a message this file understood.
    return .nothing;
}

// ---------------------------------------------------------------------------
// The outside half: the process that named the device sends here.
// ---------------------------------------------------------------------------

/// Why a send did not go out. Both members are the same fact a caller of
/// `netbroker.ask` already reads as `error.BrokerGone`: the far end is not
/// there to carry the message, whichever step noticed it first.
pub const SendError = error{
    /// `source` or `target` is empty or longer than `max_path_bytes`.
    PathUnusable,
    /// The far end has gone, or would not take the message.
    PeerGone,
};

/// Send a `Place` naming `kind`, `source`, and `target`. **This is the
/// outside half**, called by the process that named the device, on the end
/// of the pair that stayed outside the sandbox.
pub fn sendPlace(fd: i32, kind: u8, source: []const u8, target: []const u8) SendError!void {
    if (source.len == 0 or source.len > max_path_bytes) return error.PathUnusable;
    if (target.len == 0 or target.len > max_path_bytes) return error.PathUnusable;

    var place = Place{ .kind = kind, .source_len = @intCast(source.len), .target_len = @intCast(target.len) };
    @memcpy(place.source[0..source.len], source);
    @memcpy(place.target[0..target.len], target);

    // `MSG_NOSIGNAL` so a peer that has already gone answers `EPIPE` here
    // instead of raising `SIGPIPE` at this whole process. See `netbroker.ask`
    // for the measurement behind the same flag on the same socket type.
    const rc = linux.sendto(fd, @ptrCast(&place), @sizeOf(Place), linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(rc) != .SUCCESS or rc != @sizeOf(Place)) return error.PeerGone;
}

/// Send a `Drop` naming `path`. No `source` rides with it: see `Drop`'s own
/// doc comment for why removing a node needs none.
pub fn sendDrop(fd: i32, path: []const u8) SendError!void {
    if (path.len == 0 or path.len > max_path_bytes) return error.PathUnusable;

    var drop = Drop{ .path_len = @intCast(path.len) };
    @memcpy(drop.path[0..path.len], path);

    const sent = linux.sendto(fd, @ptrCast(&drop), @sizeOf(Drop), linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(sent) != .SUCCESS or sent != @sizeOf(Drop)) return error.PeerGone;
}

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

/// A seam that records what it was asked. A test reads these rather than
/// trusting that `serveOne` called it correctly.
const StubSeam = struct {
    places: usize = 0,
    drops: usize = 0,
    place_kind: u8 = 0,
    place_source: [max_path_bytes]u8 = @splat(0),
    place_source_len: usize = 0,
    place_target: [max_path_bytes]u8 = @splat(0),
    place_target_len: usize = 0,
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

    fn placeFn(ptr: *anyopaque, kind: u8, source: []const u8, target: []const u8) DeviceSeam.Result {
        const self: *StubSeam = @ptrCast(@alignCast(ptr));
        self.places += 1;
        self.place_kind = kind;
        @memcpy(self.place_source[0..source.len], source);
        self.place_source_len = source.len;
        @memcpy(self.place_target[0..target.len], target);
        self.place_target_len = target.len;
        return self.place_result;
    }

    fn dropFn(ptr: *anyopaque, path: []const u8) DeviceSeam.Result {
        const self: *StubSeam = @ptrCast(@alignCast(ptr));
        self.drops += 1;
        @memcpy(self.drop_path[0..path.len], path);
        self.drop_path_len = path.len;
        return self.drop_result;
    }

    fn sawPlaceSource(self: *const StubSeam) []const u8 {
        return self.place_source[0..self.place_source_len];
    }

    fn sawPlaceTarget(self: *const StubSeam) []const u8 {
        return self.place_target[0..self.place_target_len];
    }

    fn sawDropPath(self: *const StubSeam) []const u8 {
        return self.drop_path[0..self.drop_path_len];
    }
};

test "both wire structures are a fixed size with no padding a compiler chose" {
    // **The size is the framing.** `serveOne` tells a `Place` from a `Drop`
    // by the byte count `recvmsg` reports, which is only a fact both ends
    // agree on while the size is written out and not left to the compiler.
    try testing.expectEqual(
        @as(usize, 4 + 1 + 3 + 4 + max_path_bytes + 4 + max_path_bytes),
        @sizeOf(Place),
    );
    try testing.expectEqual(@as(usize, 4 + 4 + max_path_bytes), @sizeOf(Drop));
    try testing.expect(@sizeOf(Place) != @sizeOf(Drop));
    try testing.expect(request_magic != reply_magic);
}

test "a placement carries a source and a target, and nothing else" {
    try linuxOnly();
    // Authority is a path Chock chose, out of a tree the program cannot
    // read. See this file's own top comment.
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try sendPlace(pair[0], 7, "bus/usb/001/005", "/dev/chock-widget0");

    var stub = StubSeam{};
    try testing.expectEqual(Outcome.placed, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 1), stub.places);
    try testing.expectEqual(@as(usize, 0), stub.drops);
    try testing.expectEqual(@as(u8, 7), stub.place_kind);
    try testing.expectEqualStrings("bus/usb/001/005", stub.sawPlaceSource());
    try testing.expectEqualStrings("/dev/chock-widget0", stub.sawPlaceTarget());
}

test "a removal carries a target and nothing else" {
    try linuxOnly();
    const pair = try makePair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    try sendDrop(pair[0], "/dev/chock-widget0");

    var stub = StubSeam{};
    try testing.expectEqual(Outcome.dropped, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 0), stub.places);
    try testing.expectEqual(@as(usize, 1), stub.drops);
    try testing.expectEqualStrings("/dev/chock-widget0", stub.sawDropPath());
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
    var place = Place{ .source_len = 3, .target_len = 3 };
    @memcpy(place.source[0..3], "abc");
    @memcpy(place.target[0..3], "abc");
    @memcpy(oversize[0..@sizeOf(Place)], std.mem.asBytes(&place));
    const long_rc = linux.sendto(pair[0], &oversize, oversize.len, linux.MSG.NOSIGNAL, null, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(long_rc));
    try testing.expectEqual(Outcome.nothing, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 0), stub.places);
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

    try sendPlace(pair[0], 1, "bus/usb/001/005", "/dev/chock-widget0");

    var stub = StubSeam{ .place_result = .failed };
    try testing.expectEqual(Outcome.place_failed, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 1), stub.places);

    try sendDrop(pair[0], "/dev/chock-widget0");
    stub.drop_result = .failed;
    try testing.expectEqual(Outcome.drop_failed, serveOne(pair[1], stub.seam()));
    try testing.expectEqual(@as(usize, 1), stub.drops);
}

test "a magic that is not ours, a reserved byte, or a path of no length is refused" {
    try linuxOnly();
    // Every one of these is refused without the seam being asked anything,
    // which is what makes the shape check a boundary and not a parser. See
    // `routerlink`'s own test of the same name for the pattern.
    const cases = [_]struct { name: []const u8, place: Place }{
        .{ .name = "a magic that is not ours", .place = blk: {
            var one = Place{ .magic = 0xdeadbeef, .source_len = 3, .target_len = 3 };
            @memcpy(one.source[0..3], "abc");
            @memcpy(one.target[0..3], "abc");
            break :blk one;
        } },
        .{ .name = "a reserved byte that is not zero", .place = blk: {
            var one = Place{ .source_len = 3, .target_len = 3, ._pad = .{ 1, 0, 0 } };
            @memcpy(one.source[0..3], "abc");
            @memcpy(one.target[0..3], "abc");
            break :blk one;
        } },
        .{ .name = "a source of no length", .place = Place{ .source_len = 0, .target_len = 3 } },
        .{ .name = "a source longer than the buffer", .place = Place{ .source_len = max_path_bytes + 1, .target_len = 3 } },
        .{ .name = "a target of no length", .place = Place{ .source_len = 3, .target_len = 0 } },
        .{ .name = "a target longer than the buffer", .place = Place{ .source_len = 3, .target_len = max_path_bytes + 1 } },
    };

    var got_through: std.ArrayList(u8) = .empty;
    defer got_through.deinit(testing.allocator);

    for (cases) |case| {
        const pair = try makePair();
        defer _ = linux.close(pair[0]);
        defer _ = linux.close(pair[1]);

        const rc = linux.sendto(pair[0], @ptrCast(&case.place), @sizeOf(Place), linux.MSG.NOSIGNAL, null, 0);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));

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

    try testing.expectError(error.PathUnusable, sendPlace(pair[0], 0, "", "/dev/chock-widget0"));
    try testing.expectError(error.PathUnusable, sendPlace(pair[0], 0, "a" ** (max_path_bytes + 1), "/dev/chock-widget0"));
    try testing.expectError(error.PathUnusable, sendPlace(pair[0], 0, "bus/usb/001/005", ""));
    try testing.expectError(error.PathUnusable, sendPlace(pair[0], 0, "bus/usb/001/005", "a" ** (max_path_bytes + 1)));
    try testing.expectError(error.PathUnusable, sendDrop(pair[0], ""));
    try testing.expectError(error.PathUnusable, sendDrop(pair[0], "a" ** (max_path_bytes + 1)));
}

test "a channel that has gone answers PeerGone rather than waiting" {
    try linuxOnly();
    const pair = try makePair();
    _ = linux.close(pair[1]);
    defer _ = linux.close(pair[0]);

    try testing.expectError(error.PeerGone, sendPlace(pair[0], 0, "bus/usb/001/005", "/dev/chock-widget0"));
    try testing.expectError(error.PeerGone, sendDrop(pair[0], "/dev/chock-widget0"));
}
