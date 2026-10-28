//! The links a confined call reaches the host through, and the paths, names and
//! files that belong to this project.

const std = @import("std");
const builtin = @import("builtin");
const palisade = @import("palisade");
const nftables = @import("linux/nftables.zig");
const netns = @import("linux/netns.zig");

const namespace = palisade.linux.namespace;
const seccomp = palisade.linux.seccomp;
const Config = palisade.Sandbox.Config;
const Limits = palisade.Sandbox.Limits;

/// No mount uses this path. The kernel keeps only the last match at a spot, which would hide what is below it.
pub const runtime_prefix = "/run/chock";

pub const trust_store_inside = runtime_prefix ++ "/ca-bundle.crt";

/// The prefix every cgroup Chock makes carries, so a stray one is known by its name.
pub const cgroup_name_prefix = "chock.";

pub const deny_notice = "chock: this file is denied by the project. Its bytes are not in this sandbox.\n";

pub const NetBroker = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Grant = union(enum) {
        granted: std.posix.fd_t,
        /// No reason crosses the boundary: a reason would tell a process which hosts exist.
        refused,
    };

    pub const VTable = struct {
        /// `host` borrows the driver's own buffer and is invalid after this returns.
        connect: *const fn (ptr: *anyopaque, host: []const u8, port: u16) Grant,
    };

    pub fn connect(self: NetBroker, host: []const u8, port: u16) Grant {
        return self.vtable.connect(self.ptr, host, port);
    }
};

/// The address is the identity, not the name: two hosts on one content network can share a name.
pub const NetRouter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Address = nftables.Address;

    pub const Family = @typeInfo(Address).@"union".tag_type.?;

    pub const Resolution = union(enum) {
        granted: Address,
        refused,
        unresolved,
    };

    pub const VTable = struct {
        resolve: *const fn (ptr: *anyopaque, host: []const u8, want: Family) Resolution,
        open: *const fn (ptr: *anyopaque, address: Address, port: u16) NetBroker.Grant,
    };

    pub fn resolve(self: NetRouter, host: []const u8, want: Family) Resolution {
        return self.vtable.resolve(self.ptr, host, want);
    }

    pub fn open(self: NetRouter, address: Address, port: u16) NetBroker.Grant {
        return self.vtable.open(self.ptr, address, port);
    }
};

pub const DeviceSource = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        wakeup: *const fn (ptr: *anyopaque) i32,
        next: *const fn (ptr: *anyopaque) ?Change,
    };

    pub const Change = union(enum) {
        /// No descriptor rides with this: it cannot become a mount inside the helper's own namespace, so a path crosses and is checked on the far side.
        place: struct { kind: u8, source: []const u8, target: []const u8 },
        drop: struct { target: []const u8 },
    };
};

/// The host side of the inbound path: the ports a project published, and the
/// connections they accepted. The descriptor rides with each one, because a
/// connection cannot be named the way a device path can.
pub const ServeSource = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Inbound = struct {
        /// The port inside the sandbox the connection is for. Never zero.
        port: u16,
        /// The accepted connection. The receiver owns it and closes it.
        handle: std.posix.fd_t,
    };

    pub const VTable = struct {
        /// One descriptor that is readable when any published port has a
        /// connection waiting. Palisade polls it.
        wakeup: *const fn (ptr: *anyopaque) i32,
        next: *const fn (ptr: *anyopaque) ?Inbound,
    };
};

pub const DeviceTree = struct {
    host: []const u8,
    inside: []const u8,
};

/// What a call reaches the host through. Palisade's Config carries opaque
/// channels, so these travel beside it and Chock lowers them into channels and
/// helpers for the driver that needs them.
pub const Set = struct {
    net_broker: ?NetBroker = null,
    net_router: ?NetRouter = null,
    device_source: ?DeviceSource = null,
    device_tree: ?DeviceTree = null,
    serve_source: ?ServeSource = null,
};

/// What Chock hands a driver for one call: palisade's config, the links the call
/// reaches the host through, and where the driver writes its reports. Palisade's
/// Config carries opaque channels and no report slots, so these travel beside it.
pub const Call = struct {
    config: Config,
    links: Set = .{},
    reports: palisade.Sandbox.Reports = .{},
};

/// What a kernel without these has to load before a sandbox can have its own filtered network.
pub const network_modules: []const u8 = switch (builtin.os.tag) {
    .linux => netns.kernel_module,
    else => "",
};

pub const filter_modules: []const u8 = switch (builtin.os.tag) {
    .linux => "nf_tables nf_nat nft_chain_nat nft_redir nft_reject nf_conntrack",
    else => "",
};

pub const missing_module_notice =
    "sandbox: this host cannot give a sandbox its own filtered network.\n" ++
    "sandbox: a kernel module it needs is not loaded, and a sandbox cannot load one.\n" ++
    "sandbox: load these on the host and run again:\n" ++
    "sandbox:   modprobe " ++ network_modules ++ " " ++ filter_modules ++ "\n";

const resolv_conf =
    "# Written by chock. The resolver is the sandbox's own.\n" ++
    "nameserver 10.99.0.1\n" ++
    "options timeout:1 attempts:2\n";

comptime {
    const bytes = netns.address4;
    var rendered: [40]u8 = undefined;
    const text = std.fmt.bufPrint(&rendered, "nameserver {d}.{d}.{d}.{d}\n", .{
        bytes[0], bytes[1], bytes[2], bytes[3],
    }) catch @compileError("sandbox: the resolver address does not fit a resolv.conf line");
    if (std.mem.indexOf(u8, resolv_conf, text) == null) @compileError(
        "sandbox: resolv.conf must name the address the router binds. See netns.address4.",
    );
}

const nsswitch_conf =
    "# Written by chock. The sandbox asks its own resolver and nothing else.\n" ++
    "hosts: files dns\n" ++
    "passwd: files\n" ++
    "group: files\n" ++
    "shadow: files\n" ++
    "services: files\n" ++
    "protocols: files\n" ++
    "networks: files\n";

const hosts_file =
    "127.0.0.1\tlocalhost\n" ++
    "::1\tlocalhost ip6-localhost ip6-loopback\n";

const trust_store_link_target = "/etc/ssl/certs/ca-certificates.crt";

/// What a routed sandbox gets in place of the host's resolver files. Pass these
/// as `Config.substitutions`, with `owned_etc` in `Config.owned_directories`.
pub const resolver_substitutions = [_]namespace.Substitution{
    .{ .text = .{ .target = "/etc/resolv.conf", .contents = resolv_conf } },
    .{ .text = .{ .target = "/etc/nsswitch.conf", .contents = nsswitch_conf } },
    .{ .text = .{ .target = "/etc/hosts", .contents = hosts_file } },
    .{ .link = .{ .target = trust_store_link_target, .link_to = trust_store_inside } },
    .{ .hide = "/run/nscd" },
    .{ .hide = "/var/run/nscd" },
};

/// Every resolver file a program has to be able to read. Palisade applies the
/// substitution; without a Landlock rule beside it the program is handed a file
/// it cannot open, which reads as a permission error and not as a missing one.
///
/// The link is left out on purpose: a rule on it would resolve to the trust
/// store inside, which a call that was given no trust store does not have, and
/// a rule naming an absent path fails the whole ruleset.
pub const resolver_reads = resolver_text_targets;

const resolver_text_targets = blk: {
    var targets: []const []const u8 = &.{};
    for (resolver_substitutions) |one| switch (one) {
        .text => |text| targets = targets ++ [_][]const u8{text.target},
        .link => {},
        .hide => {},
    };
    break :blk targets;
};

/// A routed sandbox writes its own resolver files, so it takes /etc for itself
/// first: the host's copy is read only, and a write to it would reach the host.
pub const owned_etc = namespace.OwnedDirectory{
    .target = "/etc",
    .remove = resolver_text_targets,
};

comptime {
    for (resolver_substitutions) |one| {
        const target = switch (one) {
            .text => |text| text.target,
            .link => |link| link.target,
            .hide => continue,
        };
        if (!std.mem.startsWith(u8, target, owned_etc.target ++ "/")) @compileError(
            "sandbox: every resolver substitution has to sit inside the directory a routed " ++
                "sandbox takes for itself. See owned_etc.",
        );
    }
}

/// Feeds the length before the bytes, so two fields cannot blur into one reading.
fn feedText(hash: *std.crypto.hash.sha2.Sha256, text: []const u8) void {
    feedCount(hash, text.len);
    hash.update(text);
}

fn feedCount(hash: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    hash.update(&bytes);
}

/// Hashes everything that bounds what a call can reach. The environment and this process's own fields are left out on purpose.
pub fn shapeHash(config: Config) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    // Versions this function's own reading, so a hash from an older Chock over fewer fields never compares equal.
    feedText(&hash, "chock sandbox shape 2");

    feedText(&hash, config.root);
    feedText(&hash, config.cwd);

    feedCount(&hash, config.mounts.len);
    for (config.mounts) |mount| switch (mount) {
        .bind => |one| {
            feedText(&hash, "bind");
            feedText(&hash, one.source);
            feedText(&hash, one.target);
            feedCount(&hash, @intFromBool(one.read_only));
        },
        .overlay => |one| {
            feedText(&hash, "overlay");
            feedText(&hash, one.lower);
            feedText(&hash, one.upper);
            feedText(&hash, one.work);
            feedText(&hash, one.target);
        },
        .proc => |one| {
            feedText(&hash, "proc");
            feedText(&hash, one.target);
        },
        .deny => |one| {
            feedText(&hash, "deny");
            feedText(&hash, one.target);
        },
    };

    feedCount(&hash, config.rules.len);
    for (config.rules) |rule| {
        feedText(&hash, rule.path);
        feedCount(&hash, rule.access.bits());
    }

    feedCount(&hash, config.scratch.len);
    for (config.scratch) |area| feedText(&hash, area.target);

    feedCount(&hash, config.substitutions.len);
    for (config.substitutions) |one| switch (one) {
        .text => |text| {
            feedText(&hash, "text");
            feedText(&hash, text.target);
            feedText(&hash, text.contents);
        },
        .link => |link| {
            feedText(&hash, "link");
            feedText(&hash, link.target);
            feedText(&hash, link.link_to);
        },
        .hide => |target| {
            feedText(&hash, "hide");
            feedText(&hash, target);
        },
    };

    feedText(&hash, config.deny_notice);

    inline for (@typeInfo(Limits).@"struct".field_names, @typeInfo(Limits).@"struct".field_types) |field_name, _| {
        const value = @field(config.limits, field_name);
        feedText(&hash, field_name);
        if (value) |set| feedCount(&hash, set) else feedText(&hash, "none");
    }

    feedText(&hash, @tagName(config.network));
    feedText(&hash, @tagName(config.containment));
    // The targets a channel or a helper reaches are this process's own, so only
    // how many of each bound the call is readable from here.
    feedCount(&hash, config.channels.len);
    for (config.channels) |channel| {
        feedCount(&hash, @intFromBool(channel.hands_host_descriptor));
        feedCount(&hash, @intFromBool(channel.serve != null));
        feedCount(&hash, @intFromBool(channel.wakeup != null));
        if (channel.serve) |serve| feedCount(&hash, serve.max_requests);
    }
    feedCount(&hash, config.helpers.len);
    for (config.helpers) |helper| {
        feedCount(&hash, helper.allowed.len);
        feedCount(&hash, helper.keep_fds.len);
        if (helper.keep_capability) |capability| feedCount(&hash, capability);
    }

    inline for (@typeInfo(seccomp.Options).@"struct".field_names, @typeInfo(seccomp.Options).@"struct".field_types) |field_name, _| {
        feedText(&hash, field_name);
        const value = @field(config.seccomp_options, field_name);
        switch (@typeInfo(@TypeOf(value))) {
            .bool => feedCount(&hash, @intFromBool(value)),
            .@"enum" => feedText(&hash, @tagName(value)),
            else => feedText(&hash, "unread"),
        }
    }

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hash.final(&digest);
    return digest;
}
