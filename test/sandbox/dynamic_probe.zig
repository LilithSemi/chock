//! A dynamically linked program, for the two things `test/sandbox/probe.zig`
//! cannot be.
//!
//! **The probe is statically linked, so it never runs a dynamic loader.** That
//! is a blind spot and not a clean result: the loader's opens come first, and
//! there are dozens of them, so a path record that names every open outside
//! the workspace is full of toolchain paths before the program has run a line
//! of its own. A record split on what the sandbox's own configuration granted
//! counts those and keeps the names for the paths nobody granted. This program
//! is what makes that difference measurable through a real `Sandbox.spawn`.
//!
//! **And the probe is not glibc, which is the only thing that reads
//! `/etc/resolv.conf`, `/etc/nsswitch.conf` and the nscd socket.** A resolver
//! written by hand proves the router answers a query. It cannot prove that a
//! real program finds the router at all, and finding it is where three silent
//! failures live: a sandbox with no `/etc`, an `nsswitch.conf` that returns
//! before it reaches `dns`, and an nscd socket that answers from the host's
//! own view of the network. The second mode below is what measures those.
//!
//! It links libc, which is what makes it dynamic. The interpreter and every
//! library it then opens are under the toolchain tree, and that tree is a
//! mount the sandbox configuration declares, so a correct split names none of
//! them.
//!
//! With no argument it opens one path the configuration grants nothing for.
//! That open is the only name the record should hold. **The open does not have
//! to succeed**: the kernel tells the reader about the call before it runs it,
//! so a path that is not there is recorded exactly as one that is.

const std = @import("std");
const linux = std.os.linux;
const c = std.c;

/// The one path nothing in the sandbox configuration grants. The same spelling
/// as `probe.zig`'s own `named_ungranted`, because the caller looks for it by
/// name in the record.
const named_ungranted = "/etc/chock-probe-secret";

/// `getaddrinfo` found nothing.
const not_resolved: u8 = 20;
/// `getaddrinfo` found an address, and it is not the one the caller named.
const wrong_address: u8 = 21;
/// The arguments do not name an operation this program has.
const bad_arguments: u8 = 22;

pub fn main(init: std.process.Init.Minimal) u8 {
    var buffer: [4096]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&buffer);
    const args = init.args.toSlice(fixed.allocator()) catch return bad_arguments;

    // No argument at all: the path audit mode, which is what this program was
    // written for and what the caller that passes nothing still gets.
    if (args.len < 2) {
        const rc = linux.openat(linux.AT.FDCWD, named_ungranted, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(rc) == .SUCCESS) _ = linux.close(@intCast(rc));
        return 0;
    }

    // `resolve <name> <a.b.c.d>`: look the name up **through libc**, and
    // require the answer to be the address the caller named.
    //
    // **The address is the test and not the success.** A lookup that answered
    // from the host's own view of the network would succeed too, and it would
    // succeed with a different address, so comparing is what tells the
    // sandbox's own resolver apart from somebody else's.
    if (args.len == 4 and std.mem.eql(u8, args[1], "resolve")) {
        const name = fixed.allocator().dupeZ(u8, args[2]) catch return bad_arguments;
        const wanted = parseDotted(args[3]) orelse return bad_arguments;

        var hints: c.addrinfo = std.mem.zeroes(c.addrinfo);
        hints.family = c.AF.INET;
        hints.socktype = c.SOCK.STREAM;
        var found: ?*c.addrinfo = null;
        if (c.getaddrinfo(name.ptr, null, &hints, &found) != @as(c.EAI, @enumFromInt(0)))
            return not_resolved;
        const first = found orelse return not_resolved;
        defer c.freeaddrinfo(first);

        const address = first.addr orelse return not_resolved;
        const ip4: *const c.sockaddr.in = @ptrCast(@alignCast(address));
        const bytes: [4]u8 = @bitCast(ip4.addr);
        if (!std.mem.eql(u8, &bytes, &wanted)) return wrong_address;
        return 0;
    }

    return bad_arguments;
}

fn parseDotted(text: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, text, '.');
    for (&out) |*slot| {
        const part = parts.next() orelse return null;
        slot.* = std.fmt.parseInt(u8, part, 10) catch return null;
    }
    if (parts.next() != null) return null;
    return out;
}
