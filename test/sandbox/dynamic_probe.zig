//! A dynamically linked program, for the two things `test/sandbox/probe.zig`
//! cannot be: it runs a dynamic loader, and it resolves through glibc, which is
//! the only thing that reads `/etc/resolv.conf`, `/etc/nsswitch.conf` and the
//! nscd socket.

const std = @import("std");
const linux = std.os.linux;
const c = std.c;

/// The one path nothing in the sandbox configuration grants. `probe.zig` uses the same spelling.
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

    // The kernel reports the open before it runs, so a missing path is recorded like any other.
    if (args.len < 2) {
        const rc = linux.openat(linux.AT.FDCWD, named_ungranted, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(rc) == .SUCCESS) _ = linux.close(@intCast(rc));
        return 0;
    }

    // The address is the test and not the success. A lookup answered from the host's own view
    // of the network would succeed too, with a different address.
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
