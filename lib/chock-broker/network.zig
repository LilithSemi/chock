//! The network broker: who answers when a sandboxed process asks to reach a
//! host. The mechanism is in `lib/chock-sandbox/linux/netbroker.zig`, and the
//! decision is here.

const std = @import("std");

const chock_policy = @import("chock-policy");
const chock_sandbox = @import("chock-sandbox");
const chock_proto = @import("chock-proto");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;

const Broker = @import("Broker.zig");
const event = chock_proto.event;

const table = chock_policy.table;
const NetBroker = chock_sandbox.NetBroker;
const NetRouter = chock_sandbox.NetRouter;

/// `chock_proto.storage.Locked` is not `pub`, so this reaches the same type
/// through the return type of `Storage.lock`.
pub const Locked = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

pub const action_prefix = "net.connect";

pub const max_host_bytes = chock_sandbox.net_broker.max_host_bytes;

pub const request_source = "the sandbox";

pub const nix_action_prefix = "nix.net";

const longest_prefix = @max(action_prefix.len, NixPhase.build.prefix().len);

pub const max_action_bytes = longest_prefix + 1 + max_host_bytes + 1 + 5;

/// Labels are reversed: `api.anthropic.com:443` becomes
/// `net.connect.com.anthropic.api.443`, so a chosen name cannot widen a class rule.
pub fn actionInto(buffer: []u8, host: []const u8, port: u16) ?[]const u8 {
    return portedActionInto(buffer, action_prefix, host, port);
}

/// The phase word sits where a reversed host's last label sits, so a host under
/// a top level domain named `build` or `eval` shares a name with that phase.
pub const NixPhase = enum {
    eval,
    build,

    pub fn prefix(self: NixPhase) []const u8 {
        return switch (self) {
            .eval => nix_action_prefix ++ ".eval",
            .build => nix_action_prefix ++ ".build",
        };
    }
};

pub const NixActions = struct {
    phase: []const u8,
    either_phase: []const u8,
};

/// The table matches a name against itself or a trailing `.*` and nothing else,
/// so `nix.net.*.com.github.443` is a parse error and needs two names.
pub fn nixActionsInto(
    phase_buffer: []u8,
    either_buffer: []u8,
    phase: NixPhase,
    host: []const u8,
    port: u16,
) ?NixActions {
    return .{
        .phase = portedActionInto(phase_buffer, phase.prefix(), host, port) orelse return null,
        .either_phase = portedActionInto(
            either_buffer,
            nix_action_prefix,
            host,
            port,
        ) orelse return null,
    };
}

pub const nix_opaque_action = nix_action_prefix ++ ".build.opaque";

pub const nix_mirrors_prefix = nix_action_prefix ++ ".build.mirrors";

pub const max_site_bytes = 64;

const digest_bytes = 64;

pub const max_mirror_action_bytes =
    nix_mirrors_prefix.len + 1 + max_site_bytes + 1 + digest_bytes;

pub fn mirrorActionInto(buffer: []u8, site: []const u8, digest: []const u8) ?[]const u8 {
    if (buffer.len < max_mirror_action_bytes) return null;
    if (site.len == 0 or site.len > max_site_bytes) return null;
    for (site) |character| {
        if (!std.ascii.isAlphanumeric(character)) return null;
    }
    if (digest.len != digest_bytes) return null;
    for (digest) |character| {
        if (!std.ascii.isHex(character) or std.ascii.isUpper(character)) return null;
    }
    return std.fmt.bufPrint(
        buffer,
        nix_mirrors_prefix ++ ".{s}.{s}",
        .{ site, digest },
    ) catch null;
}

fn portedActionInto(
    buffer: []u8,
    prefix: []const u8,
    host: []const u8,
    port: u16,
) ?[]const u8 {
    const written = hostActionInto(buffer, prefix, host) orelse return null;
    const tail = std.fmt.bufPrint(buffer[written..], ".{d}", .{port}) catch return null;
    return buffer[0 .. written + tail.len];
}

pub fn classActionInto(buffer: []u8, host: []const u8) ?[]const u8 {
    const written = hostActionInto(buffer, action_prefix, host) orelse return null;
    return buffer[0..written];
}

fn hostActionInto(buffer: []u8, prefix: []const u8, host: []const u8) ?usize {
    if (buffer.len < max_action_bytes) return null;
    if (!chock_sandbox.net_broker.hostBytesAreUsable(host)) return null;

    var written: usize = 0;
    @memcpy(buffer[0..prefix.len], prefix);
    written += prefix.len;

    var end = host.len;
    while (end > 0) {
        const start = if (std.mem.lastIndexOfScalar(u8, host[0..end], '.')) |dot| dot + 1 else 0;
        const label = host[start..end];
        buffer[written] = '.';
        written += 1;
        // A host name is not case sensitive and a policy key is.
        for (label, buffer[written..][0..label.len]) |from, *to| to.* = std.ascii.toLower(from);
        written += label.len;
        end = if (start == 0) 0 else start - 1;
    }

    return written;
}

pub const Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Address = std.Io.net.IpAddress;

    pub const LookupError = error{
        NotResolved,
    };

    pub const DialError = error{
        NotConnected,
    };

    pub const VTable = struct {
        lookup: *const fn (ptr: *anyopaque, io: std.Io, host: []const u8, port: u16) LookupError!Address,
        /// The caller owns the descriptor and closes it after the send.
        dial: *const fn (ptr: *anyopaque, io: std.Io, address: Address) DialError!std.posix.fd_t,
    };

    pub fn lookup(self: Transport, io: std.Io, host: []const u8, port: u16) LookupError!Address {
        return self.vtable.lookup(self.ptr, io, host, port);
    }

    pub fn dial(self: Transport, io: std.Io, address: Address) DialError!std.posix.fd_t {
        return self.vtable.dial(self.ptr, io, address);
    }
};

/// The host policy already said yes. This asks only whether the name resolved
/// onto this machine. Refused: loopback, link local (`169.254.169.254` is the
/// cloud metadata service on the large providers), unspecified, multicast,
/// broadcast, the NAT64 wrapped form of those, `fd00:ec2::254` and
/// `100.100.100.200`. The private IPv4 ranges, `fc00::/7` and `100.64.0.0/10`
/// stay permitted: a company network or a Tailscale network lives in them.
pub fn addressIsReachable(address: Transport.Address) bool {
    switch (address) {
        .ip4 => |ip4| return ip4BytesAreReachable(ip4.bytes),
        .ip6 => |ip6| {
            // An IPv4 address written as an IPv6 one gets the IPv4 rules.
            if (std.Io.net.Ip4Address.fromIp6(ip6)) |ip4| return ip4BytesAreReachable(ip4.bytes);
            // `fromIp6` knows `::ffff:/96` and no other prefix.
            if (std.mem.startsWith(u8, &ip6.bytes, &nat64_well_known_prefix))
                return ip4BytesAreReachable(ip6.bytes[12..16].*);
            if (std.mem.eql(u8, &ip6.bytes, &ec2_metadata_ip6)) return false;
            if (ip6.isLoopBack() or ip6.isLinkLocal() or ip6.isMultiCast()) return false;
            for (ip6.bytes) |byte| {
                if (byte != 0) return true;
            }
            return false;
        },
    }
}

/// `64:ff9b::/96`, the NAT64 well-known prefix of RFC 6052 section 2.1.
const nat64_well_known_prefix = [_]u8{ 0x00, 0x64, 0xff, 0x9b } ++ [_]u8{0} ** 8;

const ec2_metadata_ip6 = [_]u8{ 0xfd, 0x00, 0x0e, 0xc2 } ++ [_]u8{0} ** 10 ++ [_]u8{ 0x02, 0x54 };

fn ip4BytesAreReachable(bytes: [4]u8) bool {
    if (bytes[0] == 127) return false;
    if (bytes[0] == 169 and bytes[1] == 254) return false;
    if (bytes[0] == 0) return false;
    // `224.0.0.0/4` is multicast, and above it is reserved or broadcast.
    if (bytes[0] >= 224) return false;
    if (std.mem.eql(u8, &bytes, &alibaba_metadata_ip4)) return false;
    return true;
}

const alibaba_metadata_ip4 = [_]u8{ 100, 100, 100, 200 };

/// `broker.policy` must be the same table as `Network.table`. Nothing checks it.
pub const Asker = struct {
    broker: *const Broker,
    storage: chock_proto.storage.Storage,
    locked: *Locked,
    /// Bumped before `askPermits` waits and corrected when the wait ends, so a
    /// tool call's own deadline can grow while a person is asked.
    approval_wait_ns: ?*std.atomic.Value(u64) = null,
};

const max_chain_parents = 32;

pub const Network = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    table: *const table.Table,
    chain: []const []const u8,
    agent_kind: []const u8,
    model: []const u8,
    tool: []const u8,
    transport: Transport,
    /// Null where there is no `Locked` handle to give, which refuses `ask`.
    asker: ?Asker = null,

    self_policy: []const chock_policy.ratchet.Restriction = &.{},

    /// An empty id makes the red team log scan report a gap, not an answer.
    tool_call_id: []const u8 = "",

    handed_out: HandedOut = .{},

    granted: usize = 0,
    refused: usize = 0,
    /// The first refusal and not the last. The caller releases it.
    diagnostic: ?Diagnostic = null,

    pub fn netBroker(self: *Network) NetBroker {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = NetBroker.VTable{ .connect = connectFn };

    fn connectFn(ptr: *anyopaque, host: []const u8, port: u16) NetBroker.Grant {
        const self: *Network = @ptrCast(@alignCast(ptr));
        return self.answer(host, port);
    }

    pub fn netRouter(self: *Network) NetRouter {
        return .{ .ptr = self, .vtable = &router_vtable };
    }

    const router_vtable = NetRouter.VTable{ .resolve = resolveFn, .open = openFn };

    fn resolveFn(ptr: *anyopaque, host: []const u8, want: NetRouter.Family) NetRouter.Resolution {
        const self: *Network = @ptrCast(@alignCast(ptr));
        return self.resolveName(host, want);
    }

    fn openFn(ptr: *anyopaque, address: NetRouter.Address, port: u16) NetBroker.Grant {
        const self: *Network = @ptrCast(@alignCast(ptr));
        return self.openAddress(address, port);
    }

    /// `ceilingChain` and not `evaluateChain`: a query is a resource question,
    /// so a project whose only rule names a port still resolves the bare host.
    /// An address handed out is not a connection granted.
    pub fn resolveName(self: *Network, host: []const u8, want: NetRouter.Family) NetRouter.Resolution {
        var buffer: [max_action_bytes]u8 = undefined;
        const action = classActionInto(&buffer, host) orelse {
            _ = self.refuse(.{ .net_host_not_a_name = .{ .host = "", .port = 0 } });
            return .refused;
        };

        const key = table.Key{
            .agent_kind = self.agent_kind,
            .model = self.model,
            .tool = self.tool,
            .action = action,
        };

        // Two readings: the ceiling says if the host is forbidden outright, and
        // `permitsSomethingUnder` says if anybody wrote a rule that reaches it.
        var fault: ?table.ChainFault = null;
        const ceiling = chock_policy.ratchet.ceilingFor(self.self_policy, action)
            .intersect(chock_policy.ratchet.ceilingFor(self.self_policy, action_prefix))
            .intersect(self.table.ceilingChain(self.chain, key, &fault));
        if (ceiling != .allow or !self.table.permitsSomethingUnder(key)) {
            _ = self.refuse(.{ .net_host_not_permitted = .{
                .host = self.copy(host),
                .port = 0,
                .decision = if (ceiling == .allow) .ask else ceiling,
            } });
            return .refused;
        }

        const found = self.transport.lookup(self.io, host, 0) catch return .unresolved;

        // glibc asks for both widths, one after the other. An IPv4 address
        // given back as an `AAAA` answer is four bytes where sixteen belong.
        const address: NetRouter.Address = switch (found) {
            .ip4 => |ip4| if (want == .ipv4) .{ .ipv4 = ip4.bytes } else return .unresolved,
            .ip6 => |ip6| if (want == .ipv6) .{ .ipv6 = ip6.bytes } else return .unresolved,
        };

        if (!addressIsReachable(found)) {
            _ = self.refuse(.{ .net_address_not_permitted = self.about(host, 0) });
            return .refused;
        }

        self.handed_out.remember(address, host);
        return .{ .granted = address };
    }

    /// This dials the address it resolved and does not look the name up again.
    /// A second answer opens the window a rebinding attack needs.
    pub fn openAddress(self: *Network, address: NetRouter.Address, port: u16) NetBroker.Grant {
        var name: [max_host_bytes]u8 = undefined;
        const found = self.handed_out.nameFor(address) orelse {
            return self.refuse(.{ .net_address_not_permitted = .{ .host = "", .port = port } });
        };
        @memcpy(name[0..found.len], found);

        return self.answerWith(name[0..found.len], port, addressWithPort(address, port));
    }

    pub fn answer(self: *Network, host: []const u8, port: u16) NetBroker.Grant {
        return self.answerWith(host, port, null);
    }

    fn answerWith(
        self: *Network,
        host: []const u8,
        port: u16,
        known: ?Transport.Address,
    ) NetBroker.Grant {
        // The policy first: nothing below runs for a host the table refuses.
        var buffer: [max_action_bytes]u8 = undefined;
        // The name failed the shape rule, so it is not kept for a diagnostic.
        const action = actionInto(&buffer, host, port) orelse
            return self.refuse(.{ .net_host_not_a_name = .{ .host = "", .port = port } });

        var fault: ?table.ChainFault = null;
        // The session's own promises fold in here too, because an `allow` never
        // reaches the broker.
        const decision = chock_policy.ratchet.narrow(
            self.table.evaluateChain(self.chain, .{
                .agent_kind = self.agent_kind,
                .model = self.model,
                .tool = self.tool,
                .action = action,
            }, &fault),
            self.self_policy,
            action,
        ).intersect(chock_policy.ratchet.ceilingFor(self.self_policy, action_prefix));
        if (decision != .allow) {
            // Only `ask` is sent on. The other three refuse right here.
            if (decision == .ask) {
                if (self.asker) |asker| {
                    if (self.askPermits(asker, action, host, port)) return self.finishConnect(host, port, known);
                    return .refused;
                }
            }
            return self.refuse(.{ .net_host_not_permitted = .{
                .host = self.copy(host),
                .port = port,
                .decision = decision,
            } });
        }

        return self.finishConnect(host, port, known);
    }

    fn askPermits(self: *Network, asker: Asker, action: []const u8, host: []const u8, port: u16) bool {
        const parents = self.chain[0 .. self.chain.len - 1];
        if (parents.len > max_chain_parents) {
            _ = self.refuse(.{ .net_host_not_permitted = .{
                .host = self.copy(host),
                .port = port,
                .decision = .ask,
            } });
            return false;
        }
        var links: [max_chain_parents]event.SpawnLink = undefined;
        for (parents, links[0..parents.len]) |kind, *slot| slot.* = .{ .agent_kind = kind, .reason = "" };

        var summary_buf: [max_host_bytes + 40]u8 = undefined;
        const summary = std.fmt.bufPrint(&summary_buf, "reach {s} on port {d}", .{ host, port }) catch
            "reach a host this session asked for";

        // Read `self.io` only inside this `if`. A probe that calls
        // `Sandbox.spawn` keeps no working `Io` and no counter either, so a
        // read outside this branch crashes the reentrant escape tests.
        var asked_at: std.Io.Clock.Timestamp = undefined;
        if (asker.approval_wait_ns) |counter| {
            asked_at = std.Io.Clock.Timestamp.now(self.io, .awake);
            counter.store(@as(u64, @intCast(Broker.default_timeout_ms)) * std.time.ns_per_ms, .monotonic);
        }
        defer if (asker.approval_wait_ns) |counter| {
            const elapsed = asked_at.untilNow(self.io).raw.toNanoseconds();
            counter.store(if (elapsed > 0) @intCast(elapsed) else 0, .monotonic);
        };

        const outcome = asker.broker.request(self.gpa, self.io, asker.storage, asker.locked, .{
            .action = action,
            .summary = summary,
            .detail = summary,
            .reason = "",
            .agent_kind = self.agent_kind,
            .model_alias = self.model,
            .tool = self.tool,
            .tool_call_id = self.tool_call_id,
            .source = request_source,
            .spawn_chain = links[0..parents.len],
            .self_policy = self.self_policy,
        }, null) catch {
            _ = self.refuse(.{ .net_host_not_permitted = .{
                .host = self.copy(host),
                .port = port,
                .decision = .ask,
            } });
            return false;
        };

        if (outcome.permits()) return true;
        _ = self.refuse(.{ .net_host_not_permitted = .{
            .host = self.copy(host),
            .port = port,
            .decision = .ask,
        } });
        return false;
    }

    fn finishConnect(
        self: *Network,
        host: []const u8,
        port: u16,
        known: ?Transport.Address,
    ) NetBroker.Grant {
        const address = known orelse (self.transport.lookup(self.io, host, port) catch
            return self.refuse(.{ .net_host_not_resolved = self.about(host, port) }));

        if (!addressIsReachable(address))
            return self.refuse(.{ .net_address_not_permitted = self.about(host, port) });

        const handle = self.transport.dial(self.io, address) catch
            return self.refuse(.{ .net_not_connected = self.about(host, port) });

        self.granted += 1;
        return .{ .granted = handle };
    }

    fn refuse(self: *Network, reason: Diagnostic) NetBroker.Grant {
        self.refused += 1;
        var owned = reason;
        if (!diagnostic.note(&self.diagnostic, owned)) owned.deinit(self.gpa);
        return .refused;
    }

    fn about(self: *Network, host: []const u8, port: u16) Diagnostic.NetHost {
        return .{ .host = self.copy(host), .port = port };
    }

    /// The name points into the driver's request buffer, gone when this returns.
    fn copy(self: *Network, host: []const u8) []const u8 {
        return self.gpa.dupe(u8, host) catch "";
    }
};

fn addressWithPort(address: NetRouter.Address, port: u16) Transport.Address {
    return switch (address) {
        .ipv4 => |bytes| .{ .ip4 = .{ .bytes = bytes, .port = port } },
        .ipv6 => |bytes| .{ .ip6 = .{ .bytes = bytes, .port = port } },
    };
}

pub const handed_out_capacity: usize = 64;

const HandedOut = struct {
    entries: [handed_out_capacity]Entry = @splat(.{}),
    next: usize = 0,

    const Entry = struct {
        address: NetRouter.Address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
        host: [max_host_bytes]u8 = @splat(0),
        host_len: usize = 0,
        live: bool = false,
    };

    fn remember(self: *HandedOut, address: NetRouter.Address, host: []const u8) void {
        std.debug.assert(host.len > 0 and host.len <= max_host_bytes);

        const slot = self.slotFor(address);
        slot.address = address;
        slot.host_len = host.len;
        @memcpy(slot.host[0..host.len], host);
        slot.live = true;
    }

    fn nameFor(self: *const HandedOut, address: NetRouter.Address) ?[]const u8 {
        for (&self.entries) |*entry| {
            if (!entry.live) continue;
            if (!addressesEqual(entry.address, address)) continue;
            return entry.host[0..entry.host_len];
        }
        return null;
    }

    fn slotFor(self: *HandedOut, address: NetRouter.Address) *Entry {
        for (&self.entries) |*entry| {
            if (entry.live and addressesEqual(entry.address, address)) return entry;
        }
        for (&self.entries) |*entry| {
            if (!entry.live) return entry;
        }
        const taken = &self.entries[self.next];
        self.next = (self.next + 1) % handed_out_capacity;
        return taken;
    }
};

fn addressesEqual(a: NetRouter.Address, b: NetRouter.Address) bool {
    return switch (a) {
        .ipv4 => |left| switch (b) {
            .ipv4 => |right| std.mem.eql(u8, &left, &right),
            .ipv6 => false,
        },
        .ipv6 => |left| switch (b) {
            .ipv4 => false,
            .ipv6 => |right| std.mem.eql(u8, &left, &right),
        },
    };
}

/// The lookup has no deadline of its own. A resolver that never answers holds
/// the driver's serve loop until the call's own deadline ends it.
pub const System = struct {
    /// Nothing reads this today. It is the value a dial bound wants.
    timeout_ms: u64 = 10_000,

    pub fn transport(self: *System) Transport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Transport.VTable{ .lookup = lookupFn, .dial = dialFn };

    fn lookupFn(
        ptr: *anyopaque,
        io: std.Io,
        host: []const u8,
        port: u16,
    ) Transport.LookupError!Transport.Address {
        _ = ptr;
        // A literal address parses here and resolves to itself.
        if (std.Io.net.IpAddress.parse(host, port)) |parsed| return parsed else |_| {}

        const name = std.Io.net.HostName.init(host) catch return error.NotResolved;
        var results: [16]std.Io.net.HostName.LookupResult = undefined;
        var queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&results);

        var future = io.async(std.Io.net.HostName.lookup, .{ name, io, &queue, .{ .port = port } });
        defer future.cancel(io) catch {};

        var found: ?Transport.Address = null;
        while (queue.getOne(io)) |result| {
            switch (result) {
                .address => |address| {
                    if (found == null) found = address;
                },
                .canonical_name => {},
            }
        } else |_| {}

        return found orelse error.NotResolved;
    }

    /// No deadline on this connect. In Zig 0.16 `netConnectIpPosix` with a
    /// timeout is a `@panic`, which killed a real session with `SIGABRT`.
    /// `std.Io` cannot await a future with a deadline, and `std.posix` no
    /// longer carries `socket`, `connect` or `fcntl`, so the kernel's own SYN
    /// retry, over two minutes, is the only bound today.
    fn dialFn(ptr: *anyopaque, io: std.Io, address: Transport.Address) Transport.DialError!std.posix.fd_t {
        _ = ptr;
        const stream = address.connect(io, .{ .mode = .stream }) catch return error.NotConnected;
        return stream.socket.handle;
    }
};

const testing = std.testing;

const FakeTransport = struct {
    answers: []const Answer,
    lookups: usize = 0,
    dials: usize = 0,
    last_lookup: [max_host_bytes]u8 = @splat(0),
    last_lookup_len: usize = 0,
    handed: std.ArrayList(std.Io.File) = .empty,
    gpa: std.mem.Allocator,

    const Answer = struct {
        host: []const u8,
        address: Transport.Address,
    };

    fn transport(self: *FakeTransport) Transport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Transport.VTable{ .lookup = lookupFn, .dial = dialFn };

    fn lookupFn(
        ptr: *anyopaque,
        io: std.Io,
        host: []const u8,
        port: u16,
    ) Transport.LookupError!Transport.Address {
        _ = io;
        const self: *FakeTransport = @ptrCast(@alignCast(ptr));
        self.lookups += 1;
        @memcpy(self.last_lookup[0..host.len], host);
        self.last_lookup_len = host.len;
        for (self.answers) |one| {
            if (!std.mem.eql(u8, one.host, host)) continue;
            var address = one.address;
            address.setPort(port);
            return address;
        }
        return error.NotResolved;
    }

    fn dialFn(ptr: *anyopaque, io: std.Io, address: Transport.Address) Transport.DialError!std.posix.fd_t {
        _ = address;
        const self: *FakeTransport = @ptrCast(@alignCast(ptr));
        self.dials += 1;
        // A file and not a socket, because these tests build for Darwin too.
        const file = std.Io.Dir.cwd().openFile(io, "/dev/null", .{}) catch return error.NotConnected;
        self.handed.append(self.gpa, file) catch {
            file.close(io);
            return error.NotConnected;
        };
        return file.handle;
    }

    fn askedFor(self: *const FakeTransport) []const u8 {
        return self.last_lookup[0..self.last_lookup_len];
    }

    fn deinit(self: *FakeTransport, io: std.Io) void {
        for (self.handed.items) |file| file.close(io);
        self.handed.deinit(self.gpa);
    }
};

fn tableFrom(gpa: std.mem.Allocator, source: [:0]const u8) !*const table.Table {
    return table.Table.parse(gpa, source, null);
}

const Bench = struct {
    gpa: std.mem.Allocator,
    policy: *const table.Table,
    fake: FakeTransport,
    network: Network = undefined,

    fn init(gpa: std.mem.Allocator, source: [:0]const u8, answers: []const FakeTransport.Answer) !Bench {
        return .{
            .gpa = gpa,
            .policy = try tableFrom(gpa, source),
            .fake = .{ .answers = answers, .gpa = gpa },
        };
    }

    fn ready(self: *Bench, chain: []const []const u8) *Network {
        self.network = .{
            .gpa = self.gpa,
            .io = testing.io,
            .table = self.policy,
            .chain = chain,
            .agent_kind = chain[chain.len - 1],
            .model = "main",
            .tool = "mcp",
            .transport = self.fake.transport(),
        };
        return &self.network;
    }

    fn deinit(self: *Bench) void {
        if (self.network.diagnostic) |*one| one.deinit(self.gpa);
        self.fake.deinit(testing.io);
        table.Table.destroy(self.gpa, self.policy);
    }
};

const allow_anthropic: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.connect.com.anthropic.*", .decision = .allow },
    \\        },
    \\    },
    \\}
;

test "each Nix phase builds its own name, through the same reversal net.connect uses" {
    var scoped: [max_action_bytes]u8 = undefined;
    var either: [max_action_bytes]u8 = undefined;

    const evaluating = nixActionsInto(&scoped, &either, .eval, "api.github.com", 443).?;
    try testing.expectEqualStrings("nix.net.eval.com.github.api.443", evaluating.phase);
    try testing.expectEqualStrings("nix.net.com.github.api.443", evaluating.either_phase);

    const building = nixActionsInto(&scoped, &either, .build, "API.GitHub.com", 443).?;
    try testing.expectEqualStrings("nix.net.build.com.github.api.443", building.phase);
    try testing.expectEqualStrings("nix.net.com.github.api.443", building.either_phase);

    var connect: [max_action_bytes]u8 = undefined;
    try testing.expect(!std.mem.eql(
        u8,
        actionInto(&connect, "api.github.com", 443).?,
        building.phase,
    ));

    const hostile = nixActionsInto(&scoped, &either, .build, "evil.com.github.api", 443).?;
    try testing.expectEqualStrings("nix.net.build.api.github.com.evil.443", hostile.phase);

    const daemon = nixActionsInto(&scoped, &either, .build, "sourceware.org", 9418).?;
    try testing.expectEqualStrings("nix.net.build.org.sourceware.9418", daemon.phase);
    try testing.expectEqualStrings("nix.net.org.sourceware.9418", daemon.either_phase);

    try testing.expect(nixActionsInto(&scoped, &either, .eval, "a b.com", 443) == null);
    try testing.expect(nixActionsInto(&scoped, &either, .eval, "", 443) == null);
}

test "known limitation: a host under a build or eval top level domain shares a phase name" {
    var scoped: [max_action_bytes]u8 = undefined;
    var either: [max_action_bytes]u8 = undefined;
    var other: [max_action_bytes]u8 = undefined;
    var spare: [max_action_bytes]u8 = undefined;

    for ([_][]const u8{ "build", "eval" }) |label| {
        var host_buffer: [64]u8 = undefined;
        const suffixed = try std.fmt.bufPrint(&host_buffer, "example.{s}", .{label});
        const phase: NixPhase = if (std.mem.eql(u8, label, "build")) .build else .eval;

        const under_the_domain = nixActionsInto(&scoped, &either, phase, suffixed, 443).?;
        const ordinary = nixActionsInto(&other, &spare, phase, "example", 443).?;
        try testing.expectEqualStrings(ordinary.phase, under_the_domain.either_phase);
    }

    const longer = nixActionsInto(&scoped, &either, .build, "example.build", 443).?;
    const shorter = nixActionsInto(&other, &spare, .build, "example", 443).?;
    try testing.expect(!std.mem.eql(u8, longer.phase, shorter.phase));
}

test "a mirror set is named by its site and the hash of that site's list" {
    var buffer: [max_mirror_action_bytes]u8 = undefined;
    const digest = "a" ** 64;

    try testing.expectEqualStrings(
        "nix.net.build.mirrors.gnu." ++ digest,
        mirrorActionInto(&buffer, "gnu", digest).?,
    );

    try testing.expect(mirrorActionInto(&buffer, "gnu.evil", digest) == null);
    try testing.expect(mirrorActionInto(&buffer, "", digest) == null);
    try testing.expect(mirrorActionInto(&buffer, "gnu", "a" ** 63) == null);
    try testing.expect(mirrorActionInto(&buffer, "gnu", "A" ** 64) == null);
    try testing.expect(mirrorActionInto(&buffer, "gnu", "z" ** 64) == null);

    var small: [8]u8 = undefined;
    try testing.expect(mirrorActionInto(&small, "gnu", digest) == null);
}

test "a host name becomes an action whose labels run the other way" {
    var buffer: [max_action_bytes]u8 = undefined;

    try testing.expectEqualStrings(
        "net.connect.com.anthropic.api.443",
        actionInto(&buffer, "api.anthropic.com", 443).?,
    );
    try testing.expectEqualStrings(
        "net.connect.localhost.8080",
        actionInto(&buffer, "localhost", 8080).?,
    );
    try testing.expectEqualStrings(
        "net.connect.com.anthropic.api.443",
        actionInto(&buffer, "API.Anthropic.COM", 443).?,
    );

    try testing.expect(actionInto(&buffer, "", 443) == null);
    try testing.expect(actionInto(&buffer, "a..b.com", 443) == null);
    try testing.expect(actionInto(&buffer, "a*b.com", 443) == null);
    try testing.expect(actionInto(&buffer, ".a.com", 443) == null);
    try testing.expect(actionInto(&buffer, "a.com.", 443) == null);
    try testing.expect(actionInto(&buffer, "a b.com", 443) == null);

    var small: [8]u8 = undefined;
    try testing.expect(actionInto(&small, "api.anthropic.com", 443) == null);

    try testing.expectEqualStrings(
        "net.connect.34.216.184.93.443",
        actionInto(&buffer, "93.184.216.34", 443).?,
    );
}

test "a class rule covers what is under the host and nothing that only looks like it" {
    var buffer: [max_action_bytes]u8 = undefined;
    const class = "net.connect.com.anthropic.*";

    const outside = [_][]const u8{
        "evil.com.anthropic.api",
        "anthropic.com.evil.test",
        "api.anthropic.com.evil.test",
        "anthropiccom",
        "notanthropic.com",
        "com.anthropic",
    };
    for (outside) |host| {
        const action = actionInto(&buffer, host, 443).?;
        try testing.expect(!table.patternMatches(class, action));
    }

    const inside = [_][]const u8{ "api.anthropic.com", "a.b.c.anthropic.com" };
    for (inside) |host| {
        const action = actionInto(&buffer, host, 443).?;
        try testing.expect(table.patternMatches(class, action));
    }
}

test "a permitted host is looked up, dialled, and the descriptor is handed back" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    const grant = network.answer("api.anthropic.com", 443);
    switch (grant) {
        .granted => |fd| try testing.expect(fd >= 0),
        .refused => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 1), network.granted);
    try testing.expectEqual(@as(usize, 0), network.refused);
    try testing.expectEqual(@as(usize, 1), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 1), bench.fake.dials);
    try testing.expectEqualStrings("api.anthropic.com", bench.fake.askedFor());
}

test "a host the table does not permit is never looked up at all" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "secret.evil.test", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    try testing.expectEqual(NetBroker.Grant.refused, network.answer("secret.evil.test", 443));
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 0), bench.fake.dials);
    try testing.expectEqual(@as(usize, 1), network.refused);

    try testing.expectEqual(NetBroker.Grant.refused, network.answer("a..b.evil.test", 443));
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
}

test "only allow permits, and every other decision is a refusal" {
    const gpa = testing.allocator;

    const sources = [_][:0]const u8{
        \\.{ .policy = .{ .rules = .{} } }
        ,
        \\.{ .policy = .{ .rules = .{ .{ .action = "net.connect.*", .decision = .ask } } } }
        ,
        \\.{ .policy = .{ .rules = .{ .{ .action = "net.connect.*", .decision = .deny } } } }
        ,
        \\.{ .policy = .{ .rules = .{ .{ .action = "net.connect.*", .decision = .agent_review } } } }
        ,
        \\.{ .policy = .{ .rules = .{ .{ .action = "net.connect.*", .decision = .agent_then_human } } } }
        ,
    };

    for (sources) |source| {
        var bench = try Bench.init(gpa, source, &.{
            .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
        });
        defer bench.deinit();
        const network = bench.ready(&.{"main"});
        try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
        try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    }

    var permitted = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer permitted.deinit();
    const network = permitted.ready(&.{"main"});
    try testing.expect(network.answer("api.anthropic.com", 443) == .granted);
}

test "a subagent cannot reach a host its parent could not" {
    const gpa = testing.allocator;
    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "net.connect.com.anthropic.*", .decision = .deny },
        \\            .{ .agent_kind = "fetcher", .action = "net.connect.com.anthropic.*", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const answers = [_]FakeTransport.Answer{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    };

    {
        var bench = try Bench.init(gpa, source, &answers);
        defer bench.deinit();
        const network = bench.ready(&.{"fetcher"});
        try testing.expect(network.answer("api.anthropic.com", 443) == .granted);
    }

    {
        var bench = try Bench.init(gpa, source, &answers);
        defer bench.deinit();
        const network = bench.ready(&.{ "main", "fetcher" });
        try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
        try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    }
}

test "a permitted name that resolves onto this machine is still refused" {
    const gpa = testing.allocator;

    const refused = [_]Transport.Address{
        .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 127, 9, 9, 9 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 169, 254, 169, 254 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 239, 1, 1, 1 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 255, 255, 255, 255 }, .port = 0 } },
        .{ .ip6 = .loopback(0) },
        .{ .ip6 = .unspecified(0) },
        .{ .ip6 = .{ .bytes = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 0 } },
        .{ .ip6 = .{ .bytes = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 0 } },
        .{ .ip6 = .fromIp4(.{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 }) },
        .{ .ip6 = .fromIp4(.{ .bytes = .{ 169, 254, 169, 254 }, .port = 0 }) },
        .{ .ip6 = .{ .bytes = nat64_well_known_prefix ++ [_]u8{ 169, 254, 169, 254 }, .port = 0 } },
        .{ .ip6 = .{ .bytes = nat64_well_known_prefix ++ [_]u8{ 127, 0, 0, 1 }, .port = 0 } },
        .{ .ip6 = .{ .bytes = nat64_well_known_prefix ++ [_]u8{ 0, 0, 0, 0 }, .port = 0 } },
        .{ .ip6 = .{ .bytes = ec2_metadata_ip6, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 100, 100, 100, 200 }, .port = 0 } },
        .{ .ip6 = .fromIp4(.{ .bytes = .{ 100, 100, 100, 200 }, .port = 0 }) },
        .{ .ip6 = .{ .bytes = nat64_well_known_prefix ++ [_]u8{ 100, 100, 100, 200 }, .port = 0 } },
    };

    for (refused) |address| {
        const answers = [_]FakeTransport.Answer{
            .{ .host = "api.anthropic.com", .address = address },
        };
        var bench = try Bench.init(gpa, allow_anthropic, &answers);
        defer bench.deinit();
        const network = bench.ready(&.{"main"});
        try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
        try testing.expectEqual(@as(usize, 1), bench.fake.lookups);
        try testing.expectEqual(@as(usize, 0), bench.fake.dials);
    }

    const permitted = [_]Transport.Address{
        .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 5 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 172, 16, 3, 4 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 192, 168, 1, 20 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } },
        .{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1}, .port = 0 } },
        .{ .ip6 = .{ .bytes = .{ 0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a } ++ [_]u8{0} ** 9 ++ [_]u8{1}, .port = 0 } },
        .{ .ip6 = .{ .bytes = nat64_well_known_prefix ++ [_]u8{ 93, 184, 216, 34 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 100, 64, 0, 1 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 100, 100, 100, 1 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 100, 127, 255, 254 }, .port = 0 } },
    };
    for (permitted) |address| {
        const answers = [_]FakeTransport.Answer{
            .{ .host = "api.anthropic.com", .address = address },
        };
        var bench = try Bench.init(gpa, allow_anthropic, &answers);
        defer bench.deinit();
        const network = bench.ready(&.{"main"});
        try testing.expect(network.answer("api.anthropic.com", 443) == .granted);
    }
}

test "a name that does not resolve, and a connection that does not open, are refusals and not faults" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{});
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
    try testing.expectEqual(@as(usize, 1), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 0), bench.fake.dials);
    try testing.expectEqual(@as(usize, 1), network.refused);

    try testing.expect(network.diagnostic != null);
    try testing.expectEqual(
        std.meta.Tag(Diagnostic).net_host_not_resolved,
        std.meta.activeTag(network.diagnostic.?),
    );
}

test "the first refusal is the one kept, and it names the host it was about" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{});
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    _ = network.answer("first.evil.test", 443);
    _ = network.answer("second.evil.test", 443);
    try testing.expectEqual(@as(usize, 2), network.refused);

    const kept = network.diagnostic orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("first.evil.test", kept.net_host_not_permitted.host);
    try testing.expectEqual(@as(u16, 443), kept.net_host_not_permitted.port);
    try testing.expectEqual(table.Decision.ask, kept.net_host_not_permitted.decision);
}

test "the broker answers through the interface the sandbox calls, and not only directly" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    const broker = network.netBroker();
    try testing.expect(broker.connect("api.anthropic.com", 443) == .granted);
    try testing.expectEqual(NetBroker.Grant.refused, broker.connect("api.evil.test", 443));
    try testing.expectEqual(@as(usize, 1), network.granted);
    try testing.expectEqual(@as(usize, 1), network.refused);
}

test "a port is part of the key, so a rule about one port is not a rule about every port" {
    const gpa = testing.allocator;
    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "net.connect.com.anthropic.api.443", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const answers = [_]FakeTransport.Answer{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    };

    var bench = try Bench.init(gpa, source, &answers);
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    try testing.expect(network.answer("api.anthropic.com", 443) == .granted);
    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 80));
    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 4433));
}

test "a permitted host resolves, and the address is remembered for the connection that follows" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    const resolved = network.resolveName("api.anthropic.com", .ipv4);
    try testing.expectEqual(@as(usize, 1), bench.fake.lookups);
    switch (resolved) {
        .granted => |address| try testing.expectEqualSlices(u8, &.{ 93, 184, 216, 34 }, &address.ipv4),
        else => return error.TestUnexpectedResult,
    }

    const grant = network.openAddress(.{ .ipv4 = .{ 93, 184, 216, 34 } }, 443);
    try testing.expect(grant == .granted);
    try testing.expectEqual(@as(usize, 1), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 1), bench.fake.dials);
    try testing.expectEqual(@as(usize, 1), network.granted);
}

test "a host the table names nothing about is refused, and is never looked up" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "secret.evil.test", .address = .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 7 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    try testing.expect(network.resolveName("secret.evil.test", .ipv4) == .refused);
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 1), network.refused);
}

test "a host named by a rule about one port still resolves, and only that port connects" {
    const gpa = testing.allocator;
    const one_port: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "net.connect.com.anthropic.api.443", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    var bench = try Bench.init(gpa, one_port, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    try testing.expect(network.resolveName("api.anthropic.com", .ipv4) == .granted);

    try testing.expect(network.openAddress(.{ .ipv4 = .{ 93, 184, 216, 34 } }, 443) == .granted);
    try testing.expect(network.openAddress(.{ .ipv4 = .{ 93, 184, 216, 34 } }, 80) == .refused);
}

test "an address this call never handed out is refused, whatever the policy says about the host" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    try testing.expect(network.openAddress(.{ .ipv4 = .{ 93, 184, 216, 34 } }, 443) == .refused);
    try testing.expectEqual(@as(usize, 0), bench.fake.dials);
}

test "a query answers about the width it asked about and never about the other one" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    try testing.expect(network.resolveName("api.anthropic.com", .ipv6) == .unresolved);
    try testing.expect(network.resolveName("api.anthropic.com", .ipv4) == .granted);
}

test "a permitted name that resolves onto this machine hands out no address at all" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .{ .host = "meta.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 169, 254, 169, 254 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    try testing.expect(network.resolveName("api.anthropic.com", .ipv4) == .refused);
    try testing.expect(network.resolveName("meta.anthropic.com", .ipv4) == .refused);
    try testing.expectEqual(@as(usize, 2), bench.fake.lookups);
}

test "a subagent resolves nothing its parent could not" {
    const gpa = testing.allocator;
    const deny_parent: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "net.connect.com.anthropic.*", .decision = .deny },
        \\            .{ .agent_kind = "fetcher", .action = "net.connect.com.anthropic.*", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const answers = [_]FakeTransport.Answer{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    };

    var alone = try Bench.init(gpa, deny_parent, &answers);
    defer alone.deinit();
    try testing.expect(alone.ready(&.{"fetcher"}).resolveName("api.anthropic.com", .ipv4) == .granted);

    var under_main = try Bench.init(gpa, deny_parent, &answers);
    defer under_main.deinit();
    const network = under_main.ready(&.{ "main", "fetcher" });
    try testing.expect(network.resolveName("api.anthropic.com", .ipv4) == .refused);
    try testing.expectEqual(@as(usize, 0), under_main.fake.lookups);
}

test "the router seam and the direct calls are the same code" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const seam = bench.ready(&.{"main"}).netRouter();

    switch (seam.resolve("api.anthropic.com", .ipv4)) {
        .granted => |address| try testing.expectEqualSlices(u8, &.{ 93, 184, 216, 34 }, &address.ipv4),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(seam.open(.{ .ipv4 = .{ 93, 184, 216, 34 } }, 443) == .granted);
}

test "a name that is not a name is refused before anything reads it" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{});
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    try testing.expect(network.resolveName("api anthropic com", .ipv4) == .refused);
    try testing.expect(network.resolveName("", .ipv4) == .refused);
    try testing.expect(network.resolveName("api.anthropic.com/../evil", .ipv4) == .refused);
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
}

const ask_anthropic: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.connect.com.anthropic.*", .decision = .ask },
    \\        },
    \\    },
    \\}
;

const deny_anthropic: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.connect.com.anthropic.*", .decision = .deny },
    \\        },
    \\    },
    \\}
;

const AnswerOnWait = struct {
    gpa: std.mem.Allocator,
    store: chock_proto.storage.Storage,
    locked: *Locked,
    decision: event.ApprovalDecision,
    now_ms: i64 = 1_700_000_000_000,
    waits: usize = 0,
    answered: bool = false,
    counter: ?*std.atomic.Value(u64) = null,
    seen_on_first_wait: ?u64 = null,

    fn waiter(self: *AnswerOnWait) Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = io;
        const self: *AnswerOnWait = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        const self: *AnswerOnWait = @ptrCast(@alignCast(ptr));
        self.waits += 1;
        if (self.seen_on_first_wait == null) {
            if (self.counter) |counter| self.seen_on_first_wait = counter.load(.monotonic);
        }
        if (!self.answered) {
            self.answered = true;
            if (Broker.openRequest(self.gpa, io, self.store) catch null) |id| {
                // `SessionGrants.apply` keys on the action a response names.
                if (requestActionFor(self.gpa, io, self.store, id) catch null) |owned_action| {
                    defer self.gpa.free(owned_action);
                    _ = self.locked.append(self.gpa, io, .{ .approval_response = .{
                        .request_id = id,
                        .decision = self.decision,
                        .responder = "tester",
                        .action = owned_action,
                    } }, self.now_ms) catch {};
                }
            }
        }
        self.now_ms += @intCast(budget_ms);
        return .slept;
    }
};

fn requestActionFor(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    id: u64,
) !?[]u8 {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.id != id) continue;
        if (parsed.value.event != .approval_request) continue;
        return try gpa.dupe(u8, parsed.value.event.approval_request.action);
    }
    return null;
}

fn countKind(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    kind: event.Kind,
) !usize {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    var count: usize = 0;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (std.meta.activeTag(parsed.value.event) == kind) count += 1;
    }
    return count;
}

test "an allow decision still grants with nobody asked and no question written, even when the network could ask" {
    const gpa = testing.allocator;
    const io = testing.io;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETASK1");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = AnswerOnWait{ .gpa = gpa, .store = store, .locked = &locked, .decision = .approved_by_user };
    const broker = Broker{ .policy = bench.policy, .waiter = waiter.waiter() };
    network.asker = .{ .broker = &broker, .storage = store, .locked = &locked };

    try testing.expect(network.answer("api.anthropic.com", 443) == .granted);
    try testing.expectEqual(@as(usize, 0), waiter.waits);
    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
}

test "ask with a broker that permits grants the connection" {
    const gpa = testing.allocator;
    const io = testing.io;
    var bench = try Bench.init(gpa, ask_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETASK2");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = AnswerOnWait{ .gpa = gpa, .store = store, .locked = &locked, .decision = .approved_by_user };
    const broker = Broker{ .policy = bench.policy, .waiter = waiter.waiter() };
    network.asker = .{ .broker = &broker, .storage = store, .locked = &locked };

    const grant = network.answer("api.anthropic.com", 443);
    switch (grant) {
        .granted => |fd| try testing.expect(fd >= 0),
        .refused => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 1), network.granted);
    try testing.expectEqual(@as(usize, 1), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 1), waiter.waits);
    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_request));
}

test "a live counter is bumped before the wait starts and corrected once it ends" {
    const gpa = testing.allocator;
    const io = testing.io;
    var bench = try Bench.init(gpa, ask_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETASK5");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var counter: std.atomic.Value(u64) = .init(0);
    var waiter = AnswerOnWait{
        .gpa = gpa,
        .store = store,
        .locked = &locked,
        .decision = .approved_by_user,
        .counter = &counter,
    };
    const broker = Broker{ .policy = bench.policy, .waiter = waiter.waiter() };
    network.asker = .{ .broker = &broker, .storage = store, .locked = &locked, .approval_wait_ns = &counter };

    try testing.expectEqual(@as(u64, 0), counter.load(.monotonic));

    try testing.expect(network.answer("api.anthropic.com", 443) == .granted);

    try testing.expectEqual(
        @as(u64, @intCast(Broker.default_timeout_ms)) * std.time.ns_per_ms,
        waiter.seen_on_first_wait.?,
    );

    try testing.expect(counter.load(.monotonic) < @as(u64, @intCast(Broker.default_timeout_ms)) * std.time.ns_per_ms);
}

test "ask with a broker that refuses does not connect, and the name is never resolved" {
    const gpa = testing.allocator;
    const io = testing.io;
    var bench = try Bench.init(gpa, ask_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETASK3");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = AnswerOnWait{ .gpa = gpa, .store = store, .locked = &locked, .decision = .refused_by_user };
    const broker = Broker{ .policy = bench.policy, .waiter = waiter.waiter() };
    network.asker = .{ .broker = &broker, .storage = store, .locked = &locked };

    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 0), bench.fake.dials);
    try testing.expectEqual(@as(usize, 1), network.refused);
}

test "a second connection to the same host and port is answered from the session's own memory, with no second question" {
    const gpa = testing.allocator;
    const io = testing.io;
    var bench = try Bench.init(gpa, ask_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETASK4");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = AnswerOnWait{
        .gpa = gpa,
        .store = store,
        .locked = &locked,
        .decision = .approved_by_user_for_session,
    };
    var grants: chock_proto.state.SessionGrants = .{};
    defer {
        var it = grants.granted.keyIterator();
        while (it.next()) |key| gpa.free(key.*);
        grants.granted.deinit(gpa);
    }
    const broker = Broker{
        .policy = bench.policy,
        .waiter = waiter.waiter(),
        .grants = .{ .memory = &grants, .allocator = gpa },
    };
    network.asker = .{ .broker = &broker, .storage = store, .locked = &locked };

    const first = network.answer("api.anthropic.com", 443);
    try testing.expect(first == .granted);
    try testing.expectEqual(@as(usize, 1), waiter.waits);

    const second = network.answer("api.anthropic.com", 443);
    try testing.expect(second == .granted);
    try testing.expectEqual(@as(usize, 1), waiter.waits);
    try testing.expectEqual(@as(usize, 2), network.granted);
    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_request));
}

test "a deny decision never reaches the broker's question path at all" {
    const gpa = testing.allocator;
    const io = testing.io;
    var bench = try Bench.init(gpa, deny_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETASK5");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = AnswerOnWait{ .gpa = gpa, .store = store, .locked = &locked, .decision = .approved_by_user };
    const broker = Broker{ .policy = bench.policy, .waiter = waiter.waiter() };
    network.asker = .{ .broker = &broker, .storage = store, .locked = &locked };

    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
    try testing.expectEqual(@as(usize, 0), waiter.waits);
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
}

test "a network built with no asker refuses ask exactly as it always has, because the MCP startup path has no locked handle to give it" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, ask_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 1), network.refused);
}

test "a session's own promise narrows an allow the table gives on its own, so an allow row is ratcheted too" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    const promised = [_]chock_policy.ratchet.Restriction{
        .{ .action = "net.*", .ceiling = .deny },
    };
    network.self_policy = &promised;

    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 1), network.refused);
}

test "a session's own promise narrows an ask the table gives, with nobody asked at all" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, ask_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    const promised = [_]chock_policy.ratchet.Restriction{
        .{ .action = "net.*", .ceiling = .deny },
    };
    network.self_policy = &promised;

    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
}

test "askPermits carries this session's own promise into the broker's own decision, so a person is never asked" {
    const gpa = testing.allocator;
    const io = testing.io;
    var bench = try Bench.init(gpa, ask_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    const promised = [_]chock_policy.ratchet.Restriction{
        .{ .action = "net.*", .ceiling = .deny },
    };
    network.self_policy = &promised;

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETASK6");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = AnswerOnWait{ .gpa = gpa, .store = store, .locked = &locked, .decision = .approved_by_user };
    const broker = Broker{ .policy = bench.policy, .waiter = waiter.waiter() };
    network.asker = .{ .broker = &broker, .storage = store, .locked = &locked };

    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
    try testing.expectEqual(@as(usize, 0), waiter.waits);
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
}

test "askPermits writes the real tool call id, not an empty one, into the request it asks about" {
    const gpa = testing.allocator;
    const io = testing.io;
    var bench = try Bench.init(gpa, ask_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});
    network.tool_call_id = "call_123";

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETASK7");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = AnswerOnWait{ .gpa = gpa, .store = store, .locked = &locked, .decision = .approved_by_user };
    const broker = Broker{ .policy = bench.policy, .waiter = waiter.waiter() };
    network.asker = .{ .broker = &broker, .storage = store, .locked = &locked };

    try testing.expect(network.answer("api.anthropic.com", 443) == .granted);

    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    var found_request = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .approval_request) continue;
        found_request = true;
        try testing.expectEqualStrings("call_123", parsed.value.event.approval_request.tool_call_id);
        try testing.expectEqualStrings(
            request_source,
            parsed.value.event.approval_request.source,
        );
    }
    try testing.expect(found_request);
}
