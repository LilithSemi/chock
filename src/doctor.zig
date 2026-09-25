//! `chock doctor`: ask, before a session starts, whether this machine can
//! contain one, with no session, no workspace and no provider call. It is the
//! one producer of `src/ui.zig`'s `Layer.State.unavailable`, which a running
//! session never has because the Linux driver refuses to spawn rather than
//! degrade.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_broker = @import("chock-broker");
const chock_container = @import("chock-container");
const chock_core = @import("chock-core");
const chock_io = @import("chock-io");
const chock_nix = @import("chock-nix");
const chock_pcsc = @import("chock-pcsc");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");
const sandbox = @import("chock-sandbox");

const session_paths = @import("session.zig");
const run = @import("run.zig");
const Exit = @import("main.zig").Exit;
const version_line = @import("main.zig").version_line;
const tty = @import("tty.zig");
const ui = @import("ui.zig");

const linux = std.os.linux;

const usage_text =
    \\Usage: chock doctor [options]
    \\
    \\Says whether a session can start on this machine, one layer at a time,
    \\and what to do about a row that is not on.
    \\
    \\Exits 0 when a first run can work here, and 2 when it cannot. A machine
    \\that works with a layer missing still exits 0 and says which layer, so a
    \\script gets one answer and a person gets the whole report.
    \\
    \\A row that is on is a glyph, a name and OK. A row that is not on also says
    \\what is lost and what to do about it. With --verbose every row that is on
    \\says what it gives as well, and the report says what redaction is not.
    \\
    \\Options:
    \\  --project <dir>   The project. Defaults to the current directory.
    \\
++ tty.options_text;

const Options = struct {
    project: ?[]const u8 = null,
};

pub const Probe = union(enum) {
    ok,
    absent: []const u8,
    refused: []const u8,

    pub fn state(self: Probe) ui.Layer.State {
        return switch (self) {
            .ok => .on,
            .absent => .unsupported,
            .refused => .unavailable,
        };
    }

    pub fn why(self: Probe) []const u8 {
        return switch (self) {
            .ok => "",
            .absent, .refused => |text| text,
        };
    }
};

pub const CgroupSupport = @FieldType(sandbox.Sandbox.LimitsReport, "cgroup");

pub const CgroupVantage = sandbox.cgroup.Vantage;

pub const DevShellState = union(enum) {
    no_flake,
    read: bool,
    failed: []const u8,
    no_nix,
};

pub const ContainerState = union(enum) {
    not_installed,
    unreachable_runtime: []const u8,
    ready: Ready,

    pub const Ready = struct {
        kind: chock_container.Runtime.Kind,
        program: []const u8,
        trust: chock_container.Runtime.Trust,
    };
};

pub const ToolchainState = union(enum) {
    dev_shell,
    image: []const u8,
    image_unusable: []const u8,
    host: usize,
    none,
};

pub const ResolverFiles = union(enum) {
    not_read,
    made_inside,
    owned,
    from_image: []const u8,
};

pub const SinkProbe = struct {
    kind: chock_policy.org.RequiredSink.Kind,
    path: []const u8,
    reached: Probe,
};

pub const CredentialState = union(enum) {
    found: []const u8,
    not_needed,
    missing: []const u8,
    unconfigured: []const u8,
    unreadable: []const u8,
};

pub const LayerFamily = enum {
    none,
    namespaces,
    seatbelt,

    pub fn forDriver(given: sandbox.Sandbox.Guarantees) LayerFamily {
        if (given.count() == 0) return .none;
        return if (given.contains(.workspace_mounted)) .namespaces else .seatbelt;
    }
};

pub const Measured = struct {
    driver: sandbox.Sandbox.Guarantees = sandbox.Sandbox.guarantees,
    family: LayerFamily = LayerFamily.forDriver(sandbox.Sandbox.guarantees),

    seatbelt: Probe = .{ .absent = layer_not_measured },
    rlimits: Probe = .{ .absent = layer_not_measured },
    tool_call_refused: ?[]const u8 = null,

    user_namespace: Probe = .{ .absent = driver_gives_nothing },
    mount_namespace: Probe = .{ .absent = driver_gives_nothing },
    pid_namespace: Probe = .{ .absent = driver_gives_nothing },
    ipc_namespace: Probe = .{ .absent = driver_gives_nothing },
    network_namespace: Probe = .{ .absent = driver_gives_nothing },
    router_network: Probe = .{ .absent = layer_not_measured },
    router_filter: Probe = .{ .absent = layer_not_measured },
    resolver_files: ResolverFiles = .not_read,
    landlock: Probe = .{ .absent = driver_gives_nothing },
    landlock_abi: ?i32 = null,
    seccomp: Probe = .{ .absent = driver_gives_nothing },
    write_execute: chock_policy.hardening.WriteExecute = .strict,
    cgroup: ?CgroupSupport = null,
    cgroup_vantage: ?CgroupVantage = null,
    overlayfs: Probe = .{ .absent = driver_gives_nothing },
    pidfd: Probe = .{ .absent = driver_gives_nothing },
    tmpfs: Probe = .{ .absent = driver_gives_nothing },

    device_passthrough: bool = sandbox.Sandbox.expresses.device_passthrough,

    git_program: ?[]const u8 = null,
    nix_program: ?[]const u8 = null,
    dev_shell: DevShellState = .no_flake,
    container: ContainerState = .not_installed,
    toolchain: ToolchainState = .none,
    credential: CredentialState = .{ .unconfigured = "the configuration was not read" },
    cache: Probe = .{ .refused = "the toolchain cache was not read" },
    free_bytes: ?u64 = null,

    card_seal: Probe = .{ .absent = "the PC/SC transport was not read" },
    card_readers: ?usize = null,

    required_sinks: []const SinkProbe = &.{},
    org_ceilings: []const []const u8 = &.{},
};

pub const driver_gives_nothing =
    "this build's sandbox driver applies no layer, so it refuses to run a tool call at all";

pub const layer_not_measured = "this build's sandbox driver was never asked about it";

pub const Row = struct {
    name: []const u8,
    state: ui.Layer.State,
    means: []const u8,
    why: []const u8 = "",
    fix: []const u8 = "",
    blocks: bool = false,
};

pub const layers_heading = "Sandbox layers";
pub const first_run_heading = "Before a first run";

pub const refuses_outright =
    "chock doctor: no session can start with this build. Its sandbox driver applies no layer, " ++
    "and Sandbox.spawn refuses before it forks rather than run a tool call unprotected. " ++
    "This is a build for a target Chock has no sandbox driver for. There is nothing to " ++
    "configure and no layer below to turn on.";

pub const Verdict = enum {
    ready,
    degraded,
    blocked,
};

pub fn verdictFor(rows: []const Row) Verdict {
    var verdict: Verdict = .ready;
    for (rows) |row| {
        if (row.state == .on) continue;
        if (row.blocks) return .blocked;
        verdict = .degraded;
    }
    return verdict;
}

pub fn exitFor(verdict: Verdict) Exit {
    return switch (verdict) {
        .ready, .degraded => .finished,
        .blocked => .faulted,
    };
}

pub fn wordFor(row: Row) []const u8 {
    if (row.state == .on) return "OK";
    if (row.blocks) return "BLOCKED";
    return switch (row.state) {
        .on => unreachable,
        .off, .unsupported => row.state.word(),
        .unavailable => "DEGRADED",
    };
}

pub fn rowsFor(arena: std.mem.Allocator, m: Measured) std.mem.Allocator.Error![]const Row {
    var rows: std.ArrayList(Row) = .empty;

    if (m.family == .seatbelt) try appendSeatbeltRows(arena, m, &rows);
    if (m.family == .namespaces) {
        try rows.append(arena, .{
            .name = "user namespace",
            .state = m.user_namespace.state(),
            .means = if (m.user_namespace == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "a tool call would keep your own user id: {s}", .{
                    m.user_namespace.why(),
                }),
            .why = "this process can make one, so a tool call runs as a user id of its own",
            .fix = if (m.user_namespace == .ok) "" else
            // The one setting an administrator can change, named exactly.
            "Every other layer is built on this one. Set kernel.unprivileged_userns_clone to 1, " ++
                "or remove the container or policy that turns it off.",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "mount namespace",
            .state = m.mount_namespace.state(),
            .means = if (m.mount_namespace == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "the workspace cannot be mounted: {s}", .{
                    m.mount_namespace.why(),
                }),
            .why = "the workspace can appear at the project's own path and nothing else can",
            .fix = if (m.mount_namespace == .ok) "" else "This is the layer Sandbox.spawn is named after. Without it there is no sandbox.",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "pid namespace",
            .state = m.pid_namespace.state(),
            .means = if (m.pid_namespace == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "a tool call could signal any process you own: {s}", .{
                    m.pid_namespace.why(),
                }),
            .why = "a tool call sees its own processes and can signal no other",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "ipc namespace",
            .state = m.ipc_namespace.state(),
            .means = if (m.ipc_namespace == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "shared memory would cross the boundary: {s}", .{
                    m.ipc_namespace.why(),
                }),
            .why = "shared memory and message queues do not cross the boundary",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "net namespace",
            .state = m.network_namespace.state(),
            .means = if (m.network_namespace == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "a tool call would reach the network freely: {s}", .{
                    m.network_namespace.why(),
                }),
            .why = "a tool call reaches no host unless a policy brokers the connection",
            .blocks = true,
        });

        if (m.driver.contains(.network_isolated)) {
            try rows.append(arena, try routerRow(
                arena,
                "router network",
                m.router_network,
                "the sandbox has a network of its own: loopback, one blackhole device, an address, and a default route through it",
                router_network_fix,
            ));
            try rows.append(arena, try routerRow(
                arena,
                "router filter",
                m.router_filter,
                "the kernel itself filters that network, so a connection reaches only an address a policy let out",
                router_filter_fix,
            ));
            try rows.append(arena, try resolverFilesRow(arena, m.resolver_files, m.overlayfs));
        }

        try rows.append(arena, .{
            .name = "landlock",
            .state = m.landlock.state(),
            .means = if (m.landlock == .ok)
                (if (m.landlock_abi) |abi| try std.fmt.allocPrint(arena, "ABI {d}", .{abi}) else "")
            else
                try std.fmt.allocPrint(arena, "no path restriction at all: {s}", .{
                    m.landlock.why(),
                }),
            .why = "the paths a tool call may open are named by the kernel itself",
            .fix = if (m.landlock == .ok) "" else "Landlock needs kernel 5.13 or later and lsm=landlock on the kernel command line. " ++
                "Sandbox.spawn refuses without it rather than run with one layer missing.",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "seccomp",
            .state = m.seccomp.state(),
            .means = if (m.seccomp == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "no system call filter: {s}", .{m.seccomp.why()}),
            .why = "the system calls a tool call may make are filtered",
            .fix = if (m.seccomp == .ok) "" else "The filter needs CONFIG_SECCOMP_FILTER and no_new_privs. Sandbox.spawn refuses without it.",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "write^execute",
            .state = switch (m.write_execute) {
                .strict => .on,
                .relaxed => .off,
            },
            .means = switch (m.write_execute) {
                .strict => "",
                .relaxed => try std.fmt.allocPrint(
                    arena,
                    "this project's policy answers allow for {s}, so a page can be writable and " ++
                        "executable at the same time",
                    .{chock_policy.hardening.jit_action},
                ),
            },
            .why = "a page cannot be writable and executable at the same time, which raises the cost of running injected code",
            .fix = switch (m.write_execute) {
                .strict => "",
                .relaxed => "A run time with a just in time compiler needs this. Every other layer is " ++
                    "unchanged, and an organisation can refuse it with one rule in its policy bundle.",
            },
            .blocks = false,
        });

        try rows.append(arena, .{
            .name = "pidfd",
            .state = m.pidfd.state(),
            .means = if (m.pidfd == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "a call could not be cancelled safely: {s}", .{
                    m.pidfd.why(),
                }),
            .why = "a cancelled tool call is signalled by handle, so a late cancel reaches nothing rather than a stranger",
            .fix = if (m.pidfd == .ok) "" else "pidfd_open needs kernel 5.3 or later. Any kernel with Landlock already has it, " ++
                "so a machine that fails only here is unusual and worth reporting.",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "disk cap tmpfs",
            .state = m.tmpfs.state(),
            .means = if (m.tmpfs == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "no capped writable area: {s}", .{m.tmpfs.why()}),
            .why = "the sandbox's own writable areas are held in memory with a hard cap on each",
            .fix = if (m.tmpfs == .ok) "" else "A tmpfs is the only capacity limit an unprivileged process can put on a filesystem, " ++
                "and Sandbox.spawn refuses rather than give an uncapped directory instead.",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "overlayfs",
            .state = m.overlayfs.state(),
            .means = if (m.overlayfs == .ok)
                ""
            else
                try std.fmt.allocPrint(
                    arena,
                    "a project with no git of its own has no workspace: {s}",
                    .{m.overlayfs.why()},
                ),
            .why = "a project with no git of its own still gets a workspace, and a routed sandbox " ++
                "takes a host /etc for itself",
            .fix = if (m.overlayfs == .ok) "" else "A git project is unaffected: it gets a worktree. " ++
                "Rootless overlayfs needs kernel 5.11 or later.",
            .blocks = false,
        });

        try rows.append(arena, try cgroupRow(arena, m.cgroup, m.cgroup_vantage));
    }

    if (m.device_passthrough) try rows.append(arena, deviceRow());

    try rows.append(arena, gitRow(m));
    try rows.append(arena, nixRow(m));
    try rows.append(arena, try devShellRow(arena, m.dev_shell));
    if (try containerRow(arena, m.container, m.toolchain)) |row| try rows.append(arena, row);
    try rows.append(arena, try toolchainRow(arena, m.toolchain));
    try rows.append(arena, try credentialRow(arena, m.credential));
    try rows.append(arena, try cacheRow(arena, m.cache));
    try rows.append(arena, try freeSpaceRow(arena, m.free_bytes));
    try rows.append(arena, try cardSealRow(arena, m.card_seal, m.card_readers));
    for (m.required_sinks) |one| try rows.append(arena, try requiredSinkRow(arena, one));
    for (m.org_ceilings) |means| try rows.append(arena, .{
        .name = org_ceiling_name,
        .state = .on,
        .means = means,
        .why = "an organisation can cap what a project of this installation does, and these are " ++
            "the caps it set. A project's own chock.zon may narrow them and can never widen one",
    });

    return rows.toOwnedSlice(arena);
}

fn routerRow(
    arena: std.mem.Allocator,
    name: []const u8,
    probe: Probe,
    why: []const u8,
    absent_fix: []const u8,
) std.mem.Allocator.Error!Row {
    return .{
        .name = name,
        .state = probe.state(),
        .means = if (probe == .ok)
            ""
        else
            try std.fmt.allocPrint(arena, "no foreground tool call can start: {s}", .{probe.why()}),
        .why = why,
        .fix = switch (probe) {
            .ok => "",
            .absent => absent_fix,
            .refused => router_refusal_fix,
        },
        .blocks = true,
    };
}

const router_network_fix = "Load it on the host and run again: modprobe " ++ sandbox.Sandbox.network_modules ++
    ". A sandbox cannot make the kernel load a module, and every foreground tool call takes a " ++
    "filtered network, so no tool call runs until this is loaded.";

const router_filter_fix = "Load them on the host and run again: modprobe " ++ sandbox.Sandbox.filter_modules ++
    ". A sandbox with a network and no ruleset on it would reach whatever the host can reach, " ++
    "so Chock refuses to start rather than run without the filter.";

const router_refusal_fix = "The sandbox builds this inside a network namespace of its own, where it holds " ++
    "CAP_NET_ADMIN, so a refusal here is a fault in Chock and not a setting on this machine. " ++
    "It is worth reporting.";

fn resolverFilesRow(
    arena: std.mem.Allocator,
    files: ResolverFiles,
    overlayfs: Probe,
) std.mem.Allocator.Error!Row {
    const why = "the sandbox writes its own resolv.conf, nsswitch.conf and hosts, so a program in it " ++
        "asks the sandbox's own resolver and no other";
    return switch (files) {
        .not_read => .{
            .name = resolver_files_name,
            .state = .unsupported,
            .means = layer_not_measured,
        },
        .made_inside => .{
            .name = resolver_files_name,
            .state = .on,
            .means = "",
            .why = why,
        },
        .owned => if (overlayfs == .ok) .{
            .name = resolver_files_name,
            .state = .on,
            .means = "this host's own /etc is bound into the sandbox, and a routed call takes that " ++
                "directory for itself with an overlay, so what the host keeps there does not matter",
            .why = why,
        } else .{
            .name = resolver_files_name,
            .state = .unavailable,
            .means = try std.fmt.allocPrint(
                arena,
                "no foreground tool call can start: this host's own /etc is bound into the sandbox, " ++
                    "and the overlay a routed call takes it with was refused ({s})",
                .{overlayfs.why()},
            ),
            .why = why,
            .fix = "Rootless overlayfs needs kernel 5.11 or later. " ++ resolver_files_fix,
            .blocks = true,
        },
        .from_image => |reference| .{
            .name = resolver_files_name,
            .state = .on,
            .means = try std.fmt.allocPrint(
                arena,
                "the /etc a routed sandbox holds comes from the image {s}, so this host's own says " ++
                    "nothing about it, and nothing here unpacked one to read it",
                .{reference},
            ),
            .why = why,
        },
    };
}

const resolver_files_fix = "The other answer is to give this project a flake.nix dev shell or a " ++
    "chock.zon container image, and the sandbox holds no host /etc at all.";

pub const resolver_files_name = "resolver files";

pub const tool_call_name = "tool call";

fn appendSeatbeltRows(
    arena: std.mem.Allocator,
    m: Measured,
    rows: *std.ArrayList(Row),
) std.mem.Allocator.Error!void {
    try rows.append(arena, .{
        .name = "seatbelt",
        .state = m.seatbelt.state(),
        .means = if (m.seatbelt == .ok)
            ""
        else
            try std.fmt.allocPrint(arena, "no path restriction at all: {s}", .{m.seatbelt.why()}),
        .why = "the paths a tool call may open are named by the kernel itself, and a descriptor it never opened is no way in",
        .fix = if (m.seatbelt == .ok) "" else "sandbox_init is in libSystem on every macOS. A refusal here is a fault in Chock's own " ++
            "profile, not a setting, so it is worth reporting.",
        .blocks = true,
    });

    try rows.append(arena, .{
        .name = "network",
        .state = m.seatbelt.state(),
        .means = if (m.seatbelt == .ok) "" else "the profile that closes it did not go on",
        .why = "a tool call reaches no host, and no unix socket on this machine either",
        .blocks = true,
    });
    try rows.append(arena, .{
        .name = "signal reach",
        .state = m.seatbelt.state(),
        .means = if (m.seatbelt == .ok) "" else "the profile that closes it did not go on",
        .why = "a tool call can signal its own processes and no other process you own",
        .blocks = true,
    });
    try rows.append(arena, .{
        .name = "ipc",
        .state = m.seatbelt.state(),
        .means = if (m.seatbelt == .ok) "" else "the profile that closes it did not go on",
        .why = "shared memory and message queues do not cross the boundary",
        .blocks = true,
    });

    try rows.append(arena, .{
        .name = "rlimit floor",
        .state = m.rlimits.state(),
        .means = if (m.rlimits == .ok)
            "cpu time, size of one file and open files"
        else
            try std.fmt.allocPrint(arena, "no bound on what a tool call takes: {s}", .{m.rlimits.why()}),
        .why = "a runaway tool call is ended by the kernel rather than by a person watching it",
        .blocks = true,
    });

    try rows.append(arena, .{
        .name = "memory ceiling",
        .state = .unsupported,
        .means = "macos has no cgroup, so nothing bounds how much memory a tool call takes",
    });
    try rows.append(arena, .{
        .name = "mapped memory",
        .state = .unsupported,
        .means = "setrlimit answers EINVAL for both RLIMIT_AS and RLIMIT_DATA, and a 512 MiB mapping still succeeded",
    });
    try rows.append(arena, .{
        .name = "process count",
        .state = .unsupported,
        .means = "RLIMIT_NPROC counts every process of the user, not this sandbox, so setting it would bound you and not the agent",
    });
    try rows.append(arena, .{
        .name = "disk cap tmpfs",
        .state = .unsupported,
        .means = "an ordinary user on macos cannot mount a filesystem, so there is no capped writable area to give",
    });

    try rows.append(arena, .{
        .name = "syscall filter",
        .state = .unsupported,
        .means = "a per call denial compiles and applies and does nothing: ptrace still returned 0. " ++
            "The only form with any effect stops execve as well",
    });
    try rows.append(arena, .{
        .name = "process list",
        .state = .unsupported,
        .means = "a tool call reads the whole host process table through sysctl, and taking that away stops ordinary software starting. " ++
            "It can act on none of them: see the signal reach row",
    });
    try rows.append(arena, .{
        .name = "workspace mount",
        .state = .unsupported,
        .means = "macos has no bind mount, so the workspace cannot appear at the project's own path. " ++
            "It appears at its own, and a tool call works there",
        .fix = "This gap is permanent. An absolute path a tool call writes into a file " ++
            "names the workspace, which is deleted when the session ends.",
    });

    try rows.append(arena, toolCallRow(m));
}

fn toolCallRow(m: Measured) Row {
    if (m.tool_call_refused) |why| return .{
        .name = tool_call_name,
        .state = .unavailable,
        .means = why,
        .fix = "Every layer above is on. What is missing is that a tool call still asks for a path to appear " ++
            "somewhere else, and Sandbox.spawn refuses rather than run one unprotected.",
        .blocks = true,
    };
    return .{
        .name = tool_call_name,
        .state = .on,
        .means = "",
        .why = "a tool call really runs here, inside the profile every row above measured",
    };
}

pub const required_sink_name = "audit sink";

pub const org_ceiling_name = "org ceiling";

fn deviceRow() Row {
    return .{
        .name = "device passthrough",
        .state = .on,
        .means = "this build can bind a USB or serial device node into a sandbox, for a device " ++
            "a project names in its devices block and a policy rule allows",
        .why = "a device node reaches a kernel driver directly. Chock binds it under the same " ++
            "uid and mode the person already has, so a session reaches only what that account " ++
            "could already open, and never a narrower slice of one device",
        .blocks = false,
    };
}

fn requiredSinkRow(arena: std.mem.Allocator, one: SinkProbe) std.mem.Allocator.Error!Row {
    const what = switch (one.kind) {
        .directory => "directory",
        .syslog => "syslog socket",
    };
    if (one.reached == .ok) return .{
        .name = required_sink_name,
        .state = .on,
        .means = try std.fmt.allocPrint(
            arena,
            "this installation requires the {s} {s}, and it was reached",
            .{ what, one.path },
        ),
    };
    return .{
        .name = required_sink_name,
        .state = one.reached.state(),
        .means = try std.fmt.allocPrint(
            arena,
            "this installation requires the {s} {s}, and it could not be reached: {s}. " ++
                "A session still starts and the log keeps every line the sink missed, and it " ++
                "exits {d} when that tail is still on this machine at the end",
            .{ what, one.path, one.reached.why(), Exit.audit_gap.code() },
        ),
        .fix = "Nobody typed this sink: an org policy bundle requires it. Start the collector " ++
            "that reads it, or ask whoever installed this Chock.",
        .blocks = false,
    };
}

fn cgroupRow(
    arena: std.mem.Allocator,
    support: ?CgroupSupport,
    vantage: ?CgroupVantage,
) std.mem.Allocator.Error!Row {
    const found = support orelse return .{
        .name = "cgroup v2",
        .state = .unsupported,
        .means = "no memory or process bound was asked for: " ++ driver_gives_nothing,
    };
    const view = vantageNote(vantage);
    return .{
        .name = "cgroup v2",
        .state = switch (found) {
            .ok, .supplied => .on,
            .off => .off,
            .unsupported => .unsupported,
            .unavailable => .unavailable,
        },
        .means = switch (found) {
            .ok => "",
            else => try std.fmt.allocPrint(arena, "{f}. The rlimit floor still applies{s}", .{ found, view.means }),
        },
        .why = "the memory and pids controllers are delegated, so a tool call has a resident memory bound and a process count bound",
        .fix = switch (found) {
            .ok, .off, .supplied => "",
            .unsupported, .unavailable => view.fix orelse fixFor(found),
        },
        .blocks = false,
    };
}

const cgroup_floor = "A tool call still gets the rlimit floor, so a session runs. What it loses is the " ++
    "resident memory bound and the per sandbox process count. ";

const VantageNote = struct {
    means: []const u8,
    fix: ?[]const u8,
};

fn vantageNote(vantage: ?CgroupVantage) VantageNote {
    const ask_here = cgroup_floor ++ "This chock is inside the container, so the controllers have to be " ++
        "delegated there. Run chock doctor outside it to measure the machine itself.";

    const known = vantage orelse return .{ .means = "", .fix = null };
    return switch (known) {
        .own, .none => .{ .means = "", .fix = null },
        .foreign => .{
            .means = ". This process is in a cgroup namespace, so that is the answer for the " ++
                "cgroup tree it can see and not for the machine outside it",
            .fix = ask_here,
        },
        .not_mounted => .{
            .means = ". The kernel has a cgroup v2 hierarchy and this process can see no tree " ++
                "mounted, so that is the answer for this view and not for the machine outside it",
            .fix = ask_here,
        },
        .unknown => .{
            .means = ". Which cgroup holds this process could not be read, so the answer may be " ++
                "for its own view and not for the machine",
            .fix = null,
        },
    };
}

fn fixFor(found: CgroupSupport) []const u8 {
    const ask_init = cgroup_floor ++ "Ask the machine's init system to delegate the controllers to your user slice.";
    const ask_where = cgroup_floor ++ "The controllers are already delegated above this process and no directory " ++
        "could be made under them, so this is about which cgroup chock was started in. Start it from a session " ++
        "your own user manager owns.";

    return switch (found) {
        .ok, .off, .supplied => "",
        .unsupported, .unavailable => |reason| switch (reason) {
            .no_cgroup2_tree,
            .no_cgroup2_mount,
            .not_in_unified_hierarchy,
            .cgroup_path_too_long,
            .no_delegated_parent,
            .write_refused,
            => ask_init,
            .create_refused => ask_where,
        },
    };
}

fn gitRow(m: Measured) Row {
    if (m.git_program) |path| return .{
        .name = "git",
        .state = .on,
        .means = path,
        .why = "the session works in a worktree of your project, so your own tree is never edited",
    };
    return .{
        .name = "git",
        .state = .unavailable,
        .means = "not on this machine's PATH, so no session can build a workspace and no session can start",
        .fix = "Install git. Chock runs it to make the worktree a session works in and to apply the work back.",
        .blocks = true,
    };
}

fn nixRow(m: Measured) Row {
    if (m.nix_program) |path| return .{
        .name = "nix",
        .state = .on,
        .means = path,
    };
    return .{
        .name = "nix",
        .state = .off,
        .means = "not on this machine's PATH, so a project's dev shell cannot be read and no program can be provisioned",
        .fix = "Only a project with a flake.nix needs it. Install nix, or run chock from a shell that has it.",
        .blocks = false,
    };
}

fn devShellRow(arena: std.mem.Allocator, state: DevShellState) std.mem.Allocator.Error!Row {
    return switch (state) {
        .no_flake => .{
            .name = "dev shell",
            .state = .off,
            .means = "this project states no flake.nix, so tool calls do not get a toolchain of the project's own",
            .fix = "Write a flake.nix with a dev shell to narrow what a session mounts.",
        },
        .read => |evaluated| .{
            .name = "dev shell",
            .state = .on,
            .means = if (evaluated) "evaluated with nix" else "read from the cache",
            .why = "every tool call gets this project's own toolchain",
        },
        .failed => |reason| .{
            .name = "dev shell",
            .state = .unavailable,
            .means = try std.fmt.allocPrint(arena, "nix could not read it: {s}", .{reason}),
            .fix = "A session still runs. The toolchain row says what it mounts instead.",
        },
        .no_nix => .{
            .name = "dev shell",
            .state = .unavailable,
            .means = "this project has a flake.nix and this machine has no nix to read it with",
            .fix = "A session still runs on the host toolchain. Install nix to get this project's own.",
        },
    };
}

fn containerRow(
    arena: std.mem.Allocator,
    state: ContainerState,
    toolchain: ToolchainState,
) std.mem.Allocator.Error!?Row {
    const wanted = switch (toolchain) {
        .image, .image_unusable => true,
        .dev_shell, .host, .none => false,
    };

    return switch (state) {
        .not_installed => if (!wanted) null else .{
            .name = "container runtime",
            .state = .off,
            .means = "none is on this machine's PATH, and this project names a container image",
            .fix = "Install podman, which needs no daemon and unpacks an image with your own " ++
                "privilege, or install docker, whose daemon runs as root by default.",
        },
        .unreachable_runtime => |text| if (!wanted) null else .{
            .name = "container runtime",
            .state = .unavailable,
            .means = try std.fmt.allocPrint(arena, "it is installed and did not answer: {s}", .{text}),
            .fix = "Start the runtime's daemon, or install podman, which has none.",
        },
        .ready => |ready| .{
            .name = "container runtime",
            .state = .on,
            .means = try std.fmt.allocPrint(arena, "{s}", .{ready.kind.displayName()}),
            .why = "a project with no Nix can name a container image, and its files become the toolchain",
            .fix = if (ready.trust.isPrivileged())
                try std.fmt.allocPrint(
                    arena,
                    "Warning: {s}. The sandbox a tool call runs in is unchanged. Podman rootless " ++
                        "is the stronger position.",
                    .{ready.trust.text()},
                )
            else
                "",
        },
    };
}

fn toolchainRow(arena: std.mem.Allocator, state: ToolchainState) std.mem.Allocator.Error!Row {
    return switch (state) {
        .dev_shell => .{
            .name = "toolchain",
            .state = .on,
            .means = "this project's own dev shell",
            .why = "a tool call runs the project's own programs and the sandbox mounts that closure and no more",
        },
        .image => |reference| .{
            .name = "toolchain",
            .state = .on,
            .means = try std.fmt.allocPrint(arena, "the image {s}, already on this machine", .{reference}),
            .why = "a tool call runs the image's own programs. The image is a source of files and " ++
                "nothing runs in a container",
        },
        .image_unusable => |why| .{
            .name = "toolchain",
            .state = .unavailable,
            .means = try std.fmt.allocPrint(arena, "no session can start: {s}", .{why}),
            .fix = "Chock reads the image before the session starts and never during one, because " ++
                "a tool call has no network and no daemon socket.",
            .blocks = true,
        },
        .host => |count| .{
            .name = "toolchain",
            .state = .on,
            .means = try std.fmt.allocPrint(
                arena,
                "this machine's own programs, with {d} system directories mounted read only",
                .{count},
            ),
            .why = "a tool call can run what this machine has",
            .fix = "This is the widest answer. Narrow it with a flake.nix dev shell, or with " ++
                ".container = .{ .image = \"...\" } in chock.zon.",
        },
        .none => .{
            .name = "toolchain",
            .state = .unavailable,
            .means = "no session can start: there is nothing for a tool call to run a program from",
            .fix = "This project states no dev shell and no container image, and none of the usual " ++
                "system directories is on this machine either. Give the project a flake.nix with a " ++
                "dev shell, or a chock.zon holding .container = .{ .image = \"...\" }.",
            .blocks = true,
        },
    };
}

fn credentialRow(arena: std.mem.Allocator, state: CredentialState) std.mem.Allocator.Error!Row {
    return switch (state) {
        .found => |source| .{
            .name = "credential",
            .state = .on,
            .means = try std.fmt.allocPrint(arena, "found: {s}", .{source}),
        },
        .not_needed => .{
            .name = "credential",
            .state = .off,
            .means = "this provider asks for none, which is what a local endpoint is",
        },
        .missing => |reason| .{
            .name = "credential",
            .state = .unavailable,
            .means = try std.fmt.allocPrint(arena, "no session can be started: {s}", .{reason}),
            .fix = "Run chock login for this provider instance.",
            .blocks = true,
        },
        .unconfigured => |reason| .{
            .name = "credential",
            .state = .unavailable,
            .means = try std.fmt.allocPrint(arena, "no session can be started: {s}", .{reason}),
            .fix = "Write a provider and a model into config.zon, then run chock login.",
            .blocks = true,
        },
        .unreadable => |reason| .{
            .name = "credential",
            .state = .unavailable,
            .means = try std.fmt.allocPrint(arena, "the credential could not be read: {s}", .{reason}),
            .fix = "Run chock login for this provider instance.",
            .blocks = true,
        },
    };
}

fn cacheRow(arena: std.mem.Allocator, probe: Probe) std.mem.Allocator.Error!Row {
    return .{
        .name = "toolchain cache",
        .state = probe.state(),
        .means = if (probe == .ok)
            ""
        else
            try std.fmt.allocPrint(arena, "it could not be made: {s}", .{probe.why()}),
        .why = "the directory a compiler writes into is there and writable",
        .fix = if (probe == .ok) "" else "A session still runs. A compiler in it has nowhere but the workspace to write, " ++
            "so every session recompiles from nothing.",
        .blocks = false,
    };
}

fn cardSealRow(
    arena: std.mem.Allocator,
    probe: Probe,
    readers: ?usize,
) std.mem.Allocator.Error!Row {
    return .{
        .name = "card seal",
        .state = probe.state(),
        .means = if (probe == .ok) try std.fmt.allocPrint(
            arena,
            "a PC/SC daemon answered and named {d} reader(s)",
            .{readers orelse 0},
        ) else try std.fmt.allocPrint(arena, "no card key on this machine: {s}", .{probe.why()}),
        .why = "a card key can be tried, so a seal can reach level 2 or level 1",
        .fix = if (probe == .ok) "" else "A session still runs and `chock sessions seal` still signs, with a software key, " ++
            "and the level it used is inside the bytes the signature covers.",
        .blocks = false,
    };
}

fn freeSpaceRow(arena: std.mem.Allocator, free: ?u64) std.mem.Allocator.Error!Row {
    const floor = chock_core.tools.default_workspace_free_floor_bytes;
    const bytes = free orelse return .{
        .name = "workspace space",
        .state = .unavailable,
        .means = "the free space could not be read, which is not the same as no room",
        .fix = "A session still runs. A writing tool call is refused only when the reading works and answers too little.",
        .blocks = false,
    };
    if (bytes >= floor) return .{
        .name = "workspace space",
        .state = .on,
        .means = try std.fmt.allocPrint(arena, "{d} MiB free, over the {d} MiB floor", .{
            bytes / (1024 * 1024),
            floor / (1024 * 1024),
        }),
    };
    return .{
        .name = "workspace space",
        .state = .unavailable,
        .means = try std.fmt.allocPrint(arena, "{d} MiB free, under the {d} MiB floor", .{
            bytes / (1024 * 1024),
            floor / (1024 * 1024),
        }),
        .fix = "Every writing tool call is refused under the floor, so a session starts and gets nothing done. Free some space.",
        .blocks = true,
    };
}

const name_width = 17;

fn printReport(project_root: []const u8, m: Measured, rows: []const Row, verdict: Verdict) void {
    tty.out(.plain, "{s}\n", .{version_line});

    tty.detail("{s}\n", .{project_root});
    tty.out(.plain, "\n", .{});

    if (m.family == .none) {
        tty.print(.err, "{s}\n\n", .{refuses_outright});
    } else {
        tty.out(.plain, "{s}\n", .{layers_heading});
        for (rows) |row| {
            if (isFirstRunRow(row)) continue;
            printRow(row);
        }
        tty.out(.plain, "\n", .{});
    }

    tty.out(.plain, "{s}\n", .{first_run_heading});
    for (rows) |row| {
        if (!isFirstRunRow(row)) continue;
        printRow(row);
    }
    tty.out(.plain, "\n", .{});

    if (tty.verbose()) tty.out(.plain, "{s}\n\n", .{chock_core.redact.not_a_boundary});

    switch (verdict) {
        .ready => tty.out(.plain, "chock doctor: a session can start here, with every row on.\n", .{}),
        .degraded => tty.out(
            .plain,
            "chock doctor: a session can start here. Rows that are not on: {d} of {d}. None of them stops a first run.\n",
            .{ countNotOn(rows), rows.len },
        ),
        .blocked => tty.print(
            .err,
            "chock doctor: a session cannot start here. Rows that stop a first run: {d} of {d}.\n",
            .{ countBlocking(rows), rows.len },
        ),
    }
}

fn isFirstRunRow(row: Row) bool {
    for ([_][]const u8{
        "git",
        "nix",
        "dev shell",
        "container runtime",
        "toolchain",
        "credential",
        "toolchain cache",
        "workspace space",
        "card seal",
        required_sink_name,
    }) |name| {
        if (std.mem.eql(u8, row.name, name)) return true;
    }
    return false;
}

fn printRow(row: Row) void {
    if (row.means.len == 0) {
        tty.out(.plain, "  {s} {s: <17}  {s}\n", .{
            row.state.glyph(),
            row.name,
            wordFor(row),
        });
    } else {
        tty.out(.plain, "  {s} {s: <17}  {s: <8}  {s}\n", .{
            row.state.glyph(),
            row.name,
            wordFor(row),
            row.means,
        });
    }
    if (row.state == .on and row.why.len != 0 and tty.verbose()) {
        tty.out(.dim, "      {s}\n", .{row.why});
    }
    if (row.fix.len != 0) tty.out(.plain, "      {s}\n", .{row.fix});
}

fn countNotOn(rows: []const Row) usize {
    var count: usize = 0;
    for (rows) |row| {
        if (row.state != .on) count += 1;
    }
    return count;
}

fn countBlocking(rows: []const Row) usize {
    var count: usize = 0;
    for (rows) |row| {
        if (row.state != .on and row.blocks) count += 1;
    }
    return count;
}

fn measure(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) Measured {
    var m = Measured{};
    // Comptime, so a branch this build's driver never takes is never analysed:
    // the two measure functions name mechanisms of different targets.
    switch (comptime LayerFamily.forDriver(sandbox.Sandbox.guarantees)) {
        .none => {},
        .namespaces => measureLayers(arena, io, env, project_root, &m),
        .seatbelt => measureSeatbelt(arena, io, env, project_root, &m),
    }
    measureHost(arena, gpa, io, env, project_root, &m);
    return m;
}

fn measureHost(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    m: *Measured,
) void {
    m.git_program = chock_nix.proc.resolve(arena, io, env, "git") catch null;
    m.nix_program = chock_nix.proc.resolve(arena, io, env, "nix") catch null;
    m.dev_shell = measureDevShell(arena, gpa, io, env, project_root, m.nix_program != null);
    m.container = measureContainer(arena, io, env);
    m.toolchain = measureToolchain(arena, io, env, project_root, m.dev_shell, m.container);
    m.credential = measureCredential(arena, io, env);

    m.cache = cache: {
        const dir = session_paths.cacheDir(arena, env, project_root) catch |err| break :cache .{
            .refused = @errorName(err),
        };
        _ = session_paths.createCacheDir(io, dir, null) catch |err| break :cache .{ .refused = @errorName(err) };
        break :cache .ok;
    };

    if (session_paths.projectDir(arena, env, project_root) catch null) |dir| {
        m.free_bytes = freeBytesNear(dir);
    }

    measureCardSeal(arena, io, m);

    m.required_sinks = measureRequiredSinks(arena, io, env);
    m.org_ceilings = measureOrgCeilings(arena, io, env);

    m.write_execute = measureHardening(arena, io, env, project_root, defaultModel(arena, io, env));

    if (m.driver.contains(.network_isolated)) {
        m.resolver_files = measureResolverFiles(io, m.toolchain, "");
    }
}

fn measureResolverFiles(io: std.Io, toolchain: ToolchainState, host_root: []const u8) ResolverFiles {
    switch (toolchain) {
        .image => |reference| return .{ .from_image = reference },
        .dev_shell, .image_unusable, .none => return .made_inside,
        .host => {},
    }

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (under(&buffer, host_root, run.host_toolchain_candidates[0])) |store| {
        if (pathIsDirectory(io, store)) return .made_inside;
    }

    for (sandbox.Sandbox.resolver_substitutions) |one| {
        const target = switch (one) {
            .text => |text| text.target,
            .link => continue,
            .hide => continue,
        };
        const parent = std.fs.path.dirname(target) orelse continue;
        const parent_path = under(&buffer, host_root, parent) orelse continue;
        if (pathIsDirectory(io, parent_path)) return .owned;
    }

    return .made_inside;
}

fn pathIsDirectory(io: std.Io, path: []const u8) bool {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return stat.kind == .directory;
}

fn under(buffer: []u8, root: []const u8, path: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ root, path }) catch null;
}

fn measureHardening(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    model: []const u8,
) chock_policy.hardening.WriteExecute {
    const org_rules: []const chock_policy.table.Rule = rules: {
        const data_dir = chock_auth.paths.dataDir(arena, env) catch break :rules &.{};
        const path = std.fs.path.join(arena, &.{ data_dir, chock_policy.org.file_name }) catch
            break :rules &.{};
        const bundle = chock_policy.org.load(arena, io, path, null) catch break :rules &.{};
        break :rules bundle.rules;
    };

    const policy = chock_policy.table.Table.loadUnder(
        arena,
        io,
        project_root,
        org_rules,
        null,
    ) catch return .strict;

    return chock_policy.hardening.writeExecuteFor(policy.evaluateChain(&.{doctor_agent_kind}, .{
        .agent_kind = doctor_agent_kind,
        .model = model,
        .tool = chock_broker.actions.self_asked_tool,
        .action = chock_policy.hardening.jit_action,
    }, null));
}

const doctor_agent_kind = "main";

const no_default_model = "(no default model)";

fn defaultModel(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
) []const u8 {
    const config_dir = chock_auth.paths.configDir(arena, env) catch return no_default_model;
    const config = chock_auth.config.load(arena, io, config_dir, null) catch return no_default_model;
    const named = config.default_model orelse return no_default_model;
    return if (named.len == 0) no_default_model else named;
}

fn measureCardSeal(arena: std.mem.Allocator, io: std.Io, m: *Measured) void {
    if (comptime !@hasDecl(chock_pcsc.platform, "Failure")) {
        m.card_seal = .{ .absent = "this build has no PC/SC transport: macOS reaches a card " ++
            "through a framework that has to be linked, and Chock links no platform library" };
        return;
    } else {
        var driver = chock_pcsc.default(io);
        defer driver.deinit();

        driver.establish() catch |err| {
            const why = if (driver.failure) |failure|
                std.fmt.allocPrint(arena, "{f}", .{failure}) catch @errorName(err)
            else
                @errorName(err);
            m.card_seal = switch (err) {
                error.NotAuthorized, error.ProtocolMismatch => .{ .refused = why },
                else => .{ .absent = why },
            };
            return;
        };

        var names: [4096]u8 = undefined;
        const written = driver.pcsc().listReaders(&names) catch |err| {
            m.card_seal = .{ .absent = @errorName(err) };
            return;
        };

        var list = chock_pcsc.ReaderList.init(names[0..written]);
        var counted: usize = 0;
        while (list.next()) |_| counted += 1;
        m.card_readers = counted;

        m.card_seal = if (counted == 0)
            .{ .absent = "a PC/SC daemon answered and no reader is attached" }
        else
            .ok;
    }
}

const probe_drop_name = ".chock-doctor.probe";

fn measureOrgCeilings(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
) []const []const u8 {
    const data_dir = chock_auth.paths.dataDir(arena, env) catch return &.{};
    const path = std.fs.path.join(arena, &.{ data_dir, chock_policy.org.file_name }) catch return &.{};
    const bundle = chock_policy.org.load(arena, io, path, null) catch return &.{};

    var found: std.ArrayList([]const u8) = .empty;

    if (bundle.budget) |ceiling| {
        const currency = if (ceiling.currency.len != 0) ceiling.currency else "USD";
        const line = std.fmt.allocPrint(
            arena,
            "a session of this installation may spend at most {d} {s}, and a project that asks " ++
                "for more is refused when it starts",
            .{ ceiling.max_cost, currency },
        ) catch return found.items;
        found.append(arena, line) catch return found.items;
    }

    if (bundle.subagents) |ceiling| {
        const line = if (ceiling.max_depth != null and ceiling.max_width != null)
            std.fmt.allocPrint(
                arena,
                "a spawn tree of this installation reaches at most {d} deep and {d} wide",
                .{ ceiling.max_depth.?, ceiling.max_width.? },
            ) catch return found.items
        else if (ceiling.max_width) |width|
            std.fmt.allocPrint(
                arena,
                "an agent of this installation may start at most {d} subagents",
                .{width},
            ) catch return found.items
        else
            std.fmt.allocPrint(
                arena,
                "a spawn tree of this installation reaches at most {d} deep",
                .{ceiling.max_depth.?},
            ) catch return found.items;
        found.append(arena, line) catch return found.items;
    }

    if (bundle.deny_read.len != 0) {
        const line = std.fmt.allocPrint(
            arena,
            "{d} {s} named by this installation are kept out of every sandbox, whatever a " ++
                "project's own deny_read says",
            .{ bundle.deny_read.len, if (bundle.deny_read.len == 1) "path" else "paths" },
        ) catch return found.items;
        found.append(arena, line) catch return found.items;
    }

    if (bundle.limits) |ceiling| limits: {
        const machine = chock_policy.limits.Machine.read() catch break :limits;
        const processes = resolveCeilingField(ceiling.processes, machine.cpu_count);
        const memory_mib = if (resolveCeilingField(ceiling.memory, machine.memory_bytes)) |bytes|
            bytes / (1024 * 1024)
        else
            null;

        const line = if (processes != null and memory_mib != null)
            std.fmt.allocPrint(
                arena,
                "a sandboxed program of this installation may use at most {d} processes and " ++
                    "threads and {d} MiB of memory, and a project that asks for more is held to " ++
                    "that number",
                .{ processes.?, memory_mib.? },
            ) catch break :limits
        else if (memory_mib) |mib|
            std.fmt.allocPrint(
                arena,
                "a sandboxed program of this installation may use at most {d} MiB of memory, and " ++
                    "a project that asks for more is held to that number",
                .{mib},
            ) catch break :limits
        else
            std.fmt.allocPrint(
                arena,
                "a sandboxed program of this installation may use at most {d} processes and " ++
                    "threads, and a project that asks for more is held to that number",
                .{processes.?},
            ) catch break :limits;
        found.append(arena, line) catch return found.items;
    }

    return found.items;
}

fn resolveCeilingField(text: ?[]const u8, basis: u64) ?u64 {
    const setting = chock_policy.limits.parseSetting(text orelse return null) catch return null;
    return setting.resolve(basis);
}

fn measureRequiredSinks(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
) []const SinkProbe {
    const data_dir = chock_auth.paths.dataDir(arena, env) catch return &.{};
    const path = std.fs.path.join(arena, &.{ data_dir, chock_policy.org.file_name }) catch return &.{};
    const bundle = chock_policy.org.load(arena, io, path, null) catch return &.{};
    if (bundle.sinks.len == 0) return &.{};

    const probes = arena.alloc(SinkProbe, bundle.sinks.len) catch return &.{};
    for (bundle.sinks, probes) |required, *slot| {
        slot.* = .{
            .kind = required.kind,
            .path = required.path,
            .reached = reachSink(arena, io, required),
        };
    }
    return probes;
}

fn reachSink(
    arena: std.mem.Allocator,
    io: std.Io,
    required: chock_policy.org.RequiredSink,
) Probe {
    switch (required.kind) {
        .syslog => {
            var syslog = chock_proto.ship.Syslog{ .path = required.path };
            defer syslog.close();
            syslog.sink().reach(io) catch |err| return .{ .refused = @errorName(err) };
            return .ok;
        },
        .directory => {
            makeDirAll(io, required.path) catch {};
            const path = std.fs.path.join(arena, &.{ required.path, probe_drop_name }) catch
                return .{ .refused = "the probe path could not be built" };
            var drop = chock_proto.ship.FileDrop{ .path = path };
            defer std.Io.Dir.cwd().deleteFile(io, path) catch {};
            defer drop.close(io);
            drop.sink().reach(io) catch |err| return .{ .refused = @errorName(err) };
            return .ok;
        },
    }
}

fn freeBytesNear(path: []const u8) ?u64 {
    const driver = chock_io.default();
    var here: []const u8 = path;
    while (here.len != 0) {
        if (driver.freeBytes(here)) |bytes| return bytes;
        here = std.fs.path.dirname(here) orelse return null;
    }
    return null;
}

fn measureDevShell(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    has_nix: bool,
) DevShellState {
    const dir = session_paths.devShellDir(arena, env, project_root) catch return .no_flake;
    session_paths.createDevShellDir(io, dir) catch return .no_flake;

    // The same attribute `chock run` reads. A doctor that reads `default`
    // while the session reads another one answers about a shell nobody runs.
    const block = chock_policy.nix.load(arena, io, project_root, null) catch
        chock_policy.nix.Nix{};

    var diag: ?chock_nix.Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    const loaded = chock_nix.DevShell.load(gpa, io, .{
        .project_root = project_root,
        .cache_dir = dir,
        .shell_name = block.dev_shell,
        .host_env = env,
        .diag = &diag,
    }) catch |err| {
        if (!has_nix) return .no_nix;
        if (diag) |*fault| return .{
            .failed = std.fmt.allocPrint(arena, "{f}", .{fault}) catch @errorName(err),
        };
        return .{ .failed = @errorName(err) };
    };
    var shell = loaded orelse return .no_flake;
    defer shell.deinit();
    return .{ .read = shell.evaluated };
}

fn measureContainer(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
) ContainerState {
    const answer = chock_container.Runtime.detect(arena, io, env, null) catch return .not_installed;
    return switch (answer) {
        .not_installed => .not_installed,
        .refused => |refusal| .{ .unreachable_runtime = refusal.text },
        .ready => |found| .{ .ready = .{
            .kind = found.kind,
            .program = found.program,
            .trust = found.trust,
        } },
    };
}

fn measureToolchain(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    dev_shell: DevShellState,
    container: ContainerState,
) ToolchainState {
    const named: ?[]const u8 = switch (chock_container.config.load(arena, io, project_root) catch |err| {
        return .{ .image_unusable = std.fmt.allocPrint(
            arena,
            "the container block of this project's chock.zon could not be read ({t})",
            .{err},
        ) catch "the container block of this project's chock.zon could not be read" };
    }) {
        .none => null,
        .refused => |text| return .{ .image_unusable = text },
        .named => |reference| reference,
    };

    if (named) |reference| {
        const ready = switch (container) {
            .ready => |value| value,
            .not_installed => return .{ .image_unusable = std.fmt.allocPrint(
                arena,
                "this project names the image {s} and no container runtime is installed",
                .{reference},
            ) catch "this project names an image and no container runtime is installed" },
            .unreachable_runtime => |text| return .{ .image_unusable = text },
        };

        // The resolved path and never the bare name. `proc.run` asserts that
        // `argv[0]` is absolute, and a bare name aborted the whole command in a
        // debug build against a real podman.
        var host = chock_container.Runtime.Host{
            .program = ready.program,
            .env = env,
        };
        const present = chock_container.Image.present(arena, io, .{
            .reference = reference,
            .cache_dir = project_root,
            .kind = ready.kind,
            .trust = ready.trust,
            .runner = host.runner(),
        }) catch false;

        if (!present) return .{ .image_unusable = std.fmt.allocPrint(
            arena,
            "this project names the image {s} and it is not on this machine. Run `{s} pull {s}` first",
            .{ reference, ready.kind.program(), reference },
        ) catch "this project names an image that is not on this machine" };

        return .{ .image = reference };
    }

    if (dev_shell == .read) return .dev_shell;

    var count: usize = 0;
    for (run.host_toolchain_candidates) |path| {
        const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch continue;
        if (stat.kind != .directory) continue;
        if (std.mem.eql(u8, path, run.host_toolchain_candidates[0])) return .{ .host = 1 };
        count += 1;
    }
    if (count == 0) return .none;
    return .{ .host = count };
}

fn measureCredential(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
) CredentialState {
    const config_dir = chock_auth.paths.configDir(arena, env) catch |err| return .{
        .unconfigured = @errorName(err),
    };
    const data_dir = chock_auth.paths.dataDir(arena, env) catch |err| return .{
        .unconfigured = @errorName(err),
    };

    var config_diag: ?chock_auth.config.Diagnostic = null;
    defer if (config_diag) |*d| d.deinit(arena);
    var config = chock_auth.config.load(arena, io, config_dir, &config_diag) catch |err| {
        if (err == error.NoConfigFile) return .{
            .unconfigured = std.fmt.allocPrint(arena, "there is no configuration at {s}/{s}", .{
                config_dir,
                chock_auth.config.file_name,
            }) catch "there is no configuration",
        };
        if (config_diag) |*d| return .{
            .unconfigured = std.fmt.allocPrint(arena, "{f}", .{d}) catch @errorName(err),
        };
        return .{ .unconfigured = @errorName(err) };
    };

    const instance = config.defaultInstance() orelse return .{
        .unconfigured = std.fmt.allocPrint(
            arena,
            "the configuration names {d} providers and no default",
            .{config.instances.len},
        ) catch "the configuration names no default provider",
    };
    if (config.default_model == null) return .{
        .unconfigured = "the configuration names no default model",
    };

    const driver = chock_auth.store.Driver{
        .data_dir = data_dir,
        .store = config.credential_store,
        .env = env,
    };
    const store = chock_auth.store.Store{ .data_dir = data_dir, .secrets = driver.secrets() };
    var lookup_diag: ?chock_auth.lookup.Diagnostic = null;
    defer if (lookup_diag) |*d| d.deinit(arena);
    const resolved = chock_auth.lookup.resolve(
        arena,
        io,
        instance,
        config_dir,
        store,
        &lookup_diag,
    ) catch |err| {
        if (lookup_diag) |*d| return .{
            .unreadable = std.fmt.allocPrint(arena, "{f}", .{d}) catch @errorName(err),
        };
        return .{ .unreadable = @errorName(err) };
    };
    if (chock_auth.lookup.credentialIsMissing(instance, resolved.source)) return .{
        .missing = std.fmt.allocPrint(
            arena,
            "the provider {s} talks to {s} and no credential was found",
            .{ instance.name, instance.base_url },
        ) catch "the default provider needs a credential and none was found",
    };
    if (resolved.source == .none) return .not_needed;
    return .{ .found = resolved.source.describe() };
}

const Step = enum(u8) {
    namespaces = 1,
    tmpfs = 2,
    overlayfs = 3,
    seccomp = 4,
    router_network = 5,
    router_filter = 6,
};

const Answer = enum(u8) {
    ok = 0,
    absent = 1,
    refused = 2,
    refused_id_map = 3,
};

const record_bytes = 3;

const Plan = struct {
    network: sandbox.namespace.Network,
    mount: bool,
    filesystems: bool,
    seccomp: bool,
    router: bool,
};

const ChildReport = struct {
    namespaces: ?Answer = null,
    tmpfs: ?Answer = null,
    overlayfs: ?Answer = null,
    seccomp: ?Answer = null,
    router_network: ?Answer = null,
    router_network_step: u8 = 0,
    router_filter: ?Answer = null,
    router_filter_step: u8 = 0,
    crashed: bool = false,
};

const probe_tmpfs_bytes: u64 = 1 << 20;

const probe_dir_prefix = "doctor.probe";

fn probeDirName(buffer: []u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, probe_dir_prefix ++ "-{d}", .{std.posix.system.getpid()});
}

fn removeDeadProbeRoots(
    arena: std.mem.Allocator,
    io: std.Io,
    project_dir: []const u8,
    comptime remove: fn (std.mem.Allocator, std.Io, []const u8) void,
) void {
    var dir = std.Io.Dir.openDirAbsolute(io, project_dir, .{ .iterate = true }) catch return;
    defer dir.close(io);

    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (!std.mem.startsWith(u8, entry.name, probe_dir_prefix ++ "-")) continue;
        const digits = entry.name[probe_dir_prefix.len + 1 ..];
        const pid = std.fmt.parseInt(std.posix.pid_t, digits, 10) catch continue;
        // Signal 0 is not a member of `std.posix.SIG` and the enum is open, so
        // it is written this way.
        std.posix.kill(pid, @enumFromInt(0)) catch |err| switch (err) {
            error.ProcessNotFound => {
                const path = std.fs.path.join(arena, &.{ project_dir, entry.name }) catch continue;
                remove(arena, io, path);
            },
            else => {},
        };
    }
}

fn removeSeatbeltProbeRoot(arena: std.mem.Allocator, io: std.Io, root: []const u8) void {
    _ = arena;
    std.Io.Dir.cwd().deleteTree(io, root) catch {};
}

fn measureLayers(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    m: *Measured,
) void {
    if (sandbox.landlock.probeAbi()) |abi| {
        m.landlock = .ok;
        m.landlock_abi = abi;
    } else |err| {
        m.landlock = switch (err) {
            error.NotSupported => .{ .absent = "the kernel answered that it has no Landlock" },
            error.Unexpected => .{ .refused = "the kernel refused the Landlock version call" },
        };
    }

    m.pidfd = probePidfd();
    m.cgroup_vantage = sandbox.cgroup.readVantage();
    m.cgroup = probeCgroup();

    const probe_root = probeRoot(arena, io, env, project_root);
    defer if (probe_root) |root| removeProbeRoot(arena, io, root);

    const filter = sandbox.seccomp.build(arena, .{}) catch null;

    const whole = runChild(.{
        .network = .none,
        .mount = true,
        .filesystems = probe_root != null,
        .seccomp = filter != null,
        .router = true,
    }, probe_root, filter);

    applySeccomp(m, whole, filter);
    applyFilesystems(m, whole, probe_root);
    applyRouter(arena, m, whole);

    if (whole.namespaces == .ok) {
        m.user_namespace = .ok;
        m.mount_namespace = .ok;
        m.pid_namespace = .ok;
        m.ipc_namespace = .ok;
        m.network_namespace = .ok;
        return;
    }

    narrowNamespaces(arena, m, whole, filter);
}

const seatbelt_inside_name = "inside.txt";
const seatbelt_outside_name = "outside.txt";

fn measureSeatbelt(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    m: *Measured,
) void {
    // Not `probeRoot`: `removeProbeRoot` chmods a work directory the kernel
    // leaves behind with mode 0, through a Linux only call. Nothing here mounts
    // anything, so the tree is one directory.
    const root = seatbeltProbeRoot(arena, io, env, project_root) orelse {
        m.seatbelt = .{ .refused = "no directory could be made to measure it in" };
        m.rlimits = .{ .refused = "no directory could be made to measure it in" };
        return;
    };
    defer std.Io.Dir.cwd().deleteTree(io, root) catch {};

    const inside_dir = std.fs.path.join(arena, &.{ root, "inside" }) catch return;
    makeDirAll(io, inside_dir) catch {
        m.seatbelt = .{ .refused = "no directory could be made to measure it in" };
        m.rlimits = .{ .refused = "no directory could be made to measure it in" };
        return;
    };
    const inside = std.fs.path.join(arena, &.{ inside_dir, seatbelt_inside_name }) catch return;
    const outside = std.fs.path.join(arena, &.{ root, seatbelt_outside_name }) catch return;
    for ([_][]const u8{ inside, outside }) |path| {
        var file = std.Io.Dir.createFileAbsolute(io, path, .{}) catch {
            m.seatbelt = .{ .refused = "the probe files could not be written" };
            m.rlimits = .{ .refused = "the probe files could not be written" };
            return;
        };
        defer file.close(io);
        file.writeStreamingAll(io, "probe\n") catch {};
    }

    const mounts = [_]sandbox.namespace.Mount{.{ .bind = .{
        .source = inside_dir,
        .target = inside_dir,
        .read_only = true,
    } }};
    const rules = [_]sandbox.Config.Rule{.{
        .path = inside_dir,
        .access = sandbox.landlock.AccessFs.read_only,
    }};

    const quiet = std.Io.Dir.openFileAbsolute(io, "/dev/null", .{ .mode = .read_write }) catch {
        m.seatbelt = .{ .refused = "/dev/null could not be opened" };
        m.rlimits = .{ .refused = "/dev/null could not be opened" };
        return;
    };
    defer quiet.close(io);

    // Null is never a refusal, on either call. A program the system killed says
    // nothing about the boundary.
    const permitted = seatbeltProbeRan(arena, &mounts, &rules, inside_dir, inside, quiet.handle) orelse {
        m.seatbelt = .{ .refused = "a sandboxed program could not be started at all" };
        m.rlimits = .{ .refused = "a sandboxed program could not be started at all" };
        return;
    };
    m.rlimits = .ok;

    const reached_outside = seatbeltProbeRan(arena, &mounts, &rules, inside_dir, outside, quiet.handle) orelse {
        m.seatbelt = .{ .refused = "the program that should have been refused answered nothing at all" };
        return;
    };

    if (!permitted) {
        m.seatbelt = .{ .refused = "a path the profile permits could not be read, so the profile is wrong" };
    } else if (reached_outside) {
        m.seatbelt = .{ .refused = "a path the profile does not permit was read anyway" };
    } else {
        m.seatbelt = .ok;
    }

    m.tool_call_refused = seatbeltToolCallRefusal(arena, root);
}

fn seatbeltProbeRoot(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) ?[]const u8 {
    const project_dir = session_paths.projectDir(arena, env, project_root) catch return null;
    var name_buffer: [64]u8 = undefined;
    const name = probeDirName(&name_buffer) catch return null;
    const root = std.fs.path.join(arena, &.{ project_dir, name }) catch return null;
    makeDirAll(io, root) catch return null;
    removeDeadProbeRoots(arena, io, project_dir, removeSeatbeltProbeRoot);
    return root;
}

fn seatbeltProbeRan(
    arena: std.mem.Allocator,
    mounts: []const sandbox.namespace.Mount,
    rules: []const sandbox.Config.Rule,
    cwd: []const u8,
    target: []const u8,
    quiet_fd: std.posix.fd_t,
) ?bool {
    const argv = [_][]const u8{ "/bin/cat", target };
    const term = sandbox.spawn(arena, .{
        .root = "/",
        .mounts = mounts,
        .rules = rules,
        .cwd = cwd,
        .env = &.{},
        .stdout_fd = quiet_fd,
        .stderr_fd = quiet_fd,
    }, &argv, null, null) catch return null;
    return switch (term) {
        .exited => |code| code == 0,
        // Killed by a signal says nothing about the boundary, and must never be
        // read as a refusal the sandbox made.
        else => null,
    };
}

fn seatbeltToolCallRefusal(arena: std.mem.Allocator, root: []const u8) ?[]const u8 {
    const also_mounted = [_][]const u8{
        chock_core.scratchpad.sandboxDirFor(root),
        chock_core.cache.sandboxDirFor(root),
        chock_core.tasks.sandboxDirFor(root),
    };
    for (also_mounted) |target| {
        const config = sandbox.Config{
            .root = "/",
            .mounts = &.{.{ .bind = .{ .source = root, .target = target, .read_only = false } }},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
        };
        const why = sandbox.darwin_driver_for_testing.expressibleOn(config) orelse continue;
        return std.fmt.allocPrint(arena, "a tool call needs {s}, for {s}", .{ why.text(), target }) catch
            "a tool call needs a path to appear somewhere else, and macos has no bind mount";
    }
    return null;
}

fn narrowNamespaces(
    arena: std.mem.Allocator,
    m: *Measured,
    whole: ChildReport,
    filter: ?[]sandbox.bpf.Insn,
) void {
    const failed = whole.namespaces orelse Answer.refused;
    const bare = runChild(.{
        .network = .host,
        .mount = false,
        .filesystems = false,
        .seccomp = whole.seccomp == null and filter != null,
        .router = false,
    }, null, filter);
    applySeccomp(m, bare, filter);

    if (bare.namespaces != Answer.ok) {
        const why = whyFor(failed, namespaceRefusalText(arena, failed));
        m.user_namespace = why;
        m.pid_namespace = why;
        m.ipc_namespace = why;
        m.mount_namespace = .{ .refused = "the user namespace it is built on was refused" };
        m.network_namespace = .{ .refused = "the user namespace it is built on was refused" };
        return;
    }

    m.user_namespace = .ok;
    m.pid_namespace = .ok;
    m.ipc_namespace = .ok;

    const with_mount = runChild(.{
        .network = .host,
        .mount = true,
        .filesystems = false,
        .seccomp = false,
        .router = false,
    }, null, null);
    if (with_mount.namespaces == Answer.ok) {
        m.mount_namespace = .ok;
        m.network_namespace = whyFor(failed, "the kernel refused a network namespace to this process");
        return;
    }
    m.mount_namespace = whyFor(with_mount.namespaces orelse Answer.refused, "the kernel refused a mount namespace to this process");
    m.network_namespace = .{ .refused = "the mount namespace beside it was refused, so this was never reached" };
}

fn applySeccomp(m: *Measured, report: ChildReport, filter: ?[]sandbox.bpf.Insn) void {
    if (filter == null) {
        m.seccomp = .{ .refused = "the filter could not be built, which is chock's own fault and not this machine's" };
        return;
    }
    const answer = report.seccomp orelse return;
    m.seccomp = whyFor(answer, "the kernel refused a seccomp filter to this process");
}

fn applyFilesystems(m: *Measured, report: ChildReport, probe_root: ?[]const u8) void {
    if (probe_root == null) {
        const why = Probe{ .refused = "chock's own session directory could not be made, so nothing could be mounted to find out" };
        m.tmpfs = why;
        m.overlayfs = why;
        return;
    }
    if (report.tmpfs) |answer| {
        m.tmpfs = whyFor(answer, "the kernel refused a tmpfs to this process");
    } else {
        m.tmpfs = .{ .refused = "the mount namespace it needs was refused" };
    }
    if (report.overlayfs) |answer| {
        m.overlayfs = whyFor(answer, "the kernel refused an overlay mount to this process");
    } else {
        m.overlayfs = .{ .refused = "the mount namespace it needs was refused" };
    }
}

fn applyRouter(arena: std.mem.Allocator, m: *Measured, report: ChildReport) void {
    const network = report.router_network orelse {
        m.router_network = .{ .refused = router_not_reached };
        m.router_filter = .{ .refused = router_not_reached };
        return;
    };
    m.router_network = routerProbe(
        arena,
        network,
        routerStepName(sandbox.netns.Step, report.router_network_step),
    );

    const filter = report.router_filter orelse {
        m.router_filter = .{ .refused = "the network it filters did not come up, so this was never reached" };
        return;
    };
    m.router_filter = routerProbe(
        arena,
        filter,
        routerStepName(sandbox.nftables.Step, report.router_filter_step),
    );
}

const router_not_reached = "the sandbox's own namespaces did not come up, so nothing asked the kernel for a network";

fn routerProbe(arena: std.mem.Allocator, answer: Answer, step: ?[]const u8) Probe {
    return switch (answer) {
        .ok => .ok,
        .absent => .{ .absent = if (step) |named| std.fmt.allocPrint(
            arena,
            "the {s} step needs a kernel module that is not loaded, and a sandbox cannot make " ++
                "the kernel load one",
            .{named},
        ) catch router_absent_text else router_absent_text },
        .refused, .refused_id_map => .{ .refused = if (step) |named| std.fmt.allocPrint(
            arena,
            "the kernel refused the {s} step",
            .{named},
        ) catch router_refused_text else router_refused_text },
    };
}

const router_absent_text = "a kernel module it needs is not loaded, and a sandbox cannot make the kernel load one";
const router_refused_text = "the kernel refused it";

fn routerStepName(comptime Named: type, byte: u8) ?[]const u8 {
    if (byte == 0) return null;
    const step = std.enums.fromInt(Named, byte - 1) orelse return null;
    return @tagName(step);
}

fn whyFor(answer: Answer, refused_text: []const u8) Probe {
    return switch (answer) {
        .ok => .ok,
        .absent => .{ .absent = "the kernel answered that it does not have it" },
        .refused, .refused_id_map => .{ .refused = refused_text },
    };
}

fn namespaceRefusalText(arena: std.mem.Allocator, answer: Answer) []const u8 {
    const measured = switch (answer) {
        .refused_id_map => "the kernel made the user namespace and refused the id map write inside it",
        .ok, .absent, .refused => "the kernel refused a user namespace to this process",
    };
    const detail = sandbox.namespace.probeAvailability();
    if (detail != .unavailable) return measured;
    return std.fmt.allocPrint(arena, "{s}, and {f}", .{ measured, detail.unavailable }) catch measured;
}

fn probePidfd() Probe {
    const rc = linux.pidfd_open(linux.getpid(), 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => {
            _ = linux.close(@intCast(rc));
            return .ok;
        },
        .NOSYS => .{ .absent = "this kernel has no pidfd_open" },
        else => .{ .refused = "the kernel refused a handle on this process" },
    };
}

fn probeCgroup() CgroupSupport {
    const limits = sandbox.Sandbox.Limits{};
    // `create` asserts that at least one bound is asked for, so the defaults are
    // read from the same type a session uses.
    var made = sandbox.cgroup.Cgroup.create(
        limits.memory_bytes orelse probe_tmpfs_bytes,
        limits.processes orelse 1,
        0,
    );
    defer made.destroy();
    return made.support;
}

fn probeRoot(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) ?[]const u8 {
    const project_dir = session_paths.projectDir(arena, env, project_root) catch return null;
    var name_buffer: [64]u8 = undefined;
    const name = probeDirName(&name_buffer) catch return null;
    const root = std.fs.path.join(arena, &.{ project_dir, name }) catch return null;
    for ([_][]const u8{ "lower", "upper", "work", "merged" }) |leaf| {
        const path = std.fs.path.join(arena, &.{ root, leaf }) catch return null;
        makeDirAll(io, path) catch return null;
    }
    removeDeadProbeRoots(arena, io, project_dir, removeProbeRoot);
    return root;
}

fn removeProbeRoot(arena: std.mem.Allocator, io: std.Io, root: []const u8) void {
    if (std.fmt.allocPrintSentinel(arena, "{s}/work/work", .{root}, 0)) |path| {
        _ = linux.fchmodat(linux.AT.FDCWD, path.ptr, 0o755);
    } else |_| {}
    std.Io.Dir.cwd().deleteTree(io, root) catch {};
}

fn makeDirAll(io: std.Io, path: []const u8) !void {
    if (path.len == 0) return;
    std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse return err;
            try makeDirAll(io, parent);
            std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |second| switch (second) {
                error.PathAlreadyExists => return,
                else => return second,
            };
        },
        else => return err,
    };
}

fn runChild(plan: Plan, probe_root: ?[]const u8, filter: ?[]sandbox.bpf.Insn) ChildReport {
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return .{};

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return .{};
    }

    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        runProbes(plan, fds[1], probe_root, filter);
        // Never a return: this is a forked child of a program with an arena,
        // open files and a terminal, and none of that is this process's to
        // unwind.
        std.process.exit(0);
    }

    _ = linux.close(fds[1]);
    var report = readReport(fds[0]);
    _ = linux.close(fds[0]);

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);

    report.crashed = status != 0;
    return report;
}

fn readReport(read_fd: i32) ChildReport {
    var report = ChildReport{};
    var buffer: [record_bytes * 8]u8 = undefined;
    var held: usize = 0;

    while (held + record_bytes <= buffer.len) {
        const rc = linux.read(read_fd, buffer[held..].ptr, buffer.len - held);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => break,
        }
        if (rc == 0) break;
        held += rc;
    }

    var index: usize = 0;
    while (index + record_bytes <= held) : (index += record_bytes) {
        // The bytes came over a pipe, so they are read with `fromInt` and never
        // with `@enumFromInt`, which is undefined behaviour on an invalid tag.
        const step = std.enums.fromInt(Step, buffer[index]) orelse continue;
        const answer = std.enums.fromInt(Answer, buffer[index + 1]) orelse continue;
        switch (step) {
            .namespaces => report.namespaces = answer,
            .tmpfs => report.tmpfs = answer,
            .overlayfs => report.overlayfs = answer,
            .seccomp => report.seccomp = answer,
            .router_network => {
                report.router_network = answer;
                report.router_network_step = buffer[index + 2];
            },
            .router_filter => {
                report.router_filter = answer;
                report.router_filter_step = buffer[index + 2];
            },
        }
    }
    return report;
}

fn runProbes(plan: Plan, write_fd: i32, probe_root: ?[]const u8, filter: ?[]sandbox.bpf.Insn) void {
    const entered = sandbox.namespace.enter(.{ .network = plan.network, .mount = plan.mount }, null);
    if (entered) |_| {
        say(write_fd, .namespaces, .ok);
    } else |err| {
        say(write_fd, .namespaces, switch (err) {
            error.MapFailed => .refused_id_map,
            error.NotPermitted, error.MultiThreaded, error.Unexpected => .refused,
        });
        if (plan.seccomp) sayFilter(write_fd, filter);
        return;
    }

    // Before the mounts, so a mount fault cannot hide a network fault.
    if (plan.router) probeNetwork(write_fd);

    if (plan.filesystems and plan.mount) {
        if (probe_root) |root| {
            probeMounts(write_fd, root);
        }
    }

    if (plan.seccomp) sayFilter(write_fd, filter);
}

fn probeNetwork(write_fd: i32) void {
    var route_diag: ?sandbox.netns.Diagnostic = null;
    var route = sandbox.netns.Session.open(&route_diag) catch |err| {
        sayDetail(write_fd, .router_network, networkAnswer(err), netnsStepByte(route_diag));
        return;
    };
    defer route.close();
    _ = route.configure(&route_diag) catch |err| {
        sayDetail(write_fd, .router_network, networkAnswer(err), netnsStepByte(route_diag));
        return;
    };
    say(write_fd, .router_network, .ok);

    var table_diag: ?sandbox.nftables.Diagnostic = null;
    const table = sandbox.nftables.Session.open(&table_diag) catch |err| {
        sayDetail(write_fd, .router_filter, filterAnswer(err), nftablesStepByte(table_diag));
        return;
    };
    defer table.close();
    table.install(&table_diag) catch |err| {
        sayDetail(write_fd, .router_filter, filterAnswer(err), nftablesStepByte(table_diag));
        return;
    };
    say(write_fd, .router_filter, .ok);
}

fn networkAnswer(err: sandbox.netns.Error) Answer {
    return switch (err) {
        error.KernelModuleMissing => .absent,
        error.NotPermitted, error.Refused, error.ExchangeFailed => .refused,
    };
}

fn filterAnswer(err: sandbox.nftables.Error) Answer {
    return switch (err) {
        error.KernelModuleMissing => .absent,
        error.NotPermitted, error.Refused, error.ExchangeFailed => .refused,
    };
}

fn netnsStepByte(diag: ?sandbox.netns.Diagnostic) u8 {
    const one = diag orelse return 0;
    return @intFromEnum(one.step) + 1;
}

fn nftablesStepByte(diag: ?sandbox.nftables.Diagnostic) u8 {
    const one = diag orelse return 0;
    return @intFromEnum(one.step) + 1;
}

fn probeMounts(write_fd: i32, root: []const u8) void {
    const scratch = sandbox.namespace.mountScratch(root, "cap", probe_tmpfs_bytes, null);
    if (scratch) |fd| {
        _ = linux.close(fd);
        say(write_fd, .tmpfs, .ok);
    } else |err| {
        say(write_fd, .tmpfs, mountAnswer(err));
    }

    var scratch_bytes: [6 * std.fs.max_path_bytes]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch_bytes);

    var lower_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var upper_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var work_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var merged_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const lower = joinLeaf(&lower_buffer, root, "lower") orelse return;
    const upper = joinLeaf(&upper_buffer, root, "upper") orelse return;
    const work = joinLeaf(&work_buffer, root, "work") orelse return;
    const merged = joinLeaf(&merged_buffer, root, "merged") orelse return;

    if (sandbox.namespace.mountOverlay(fba.allocator(), .{
        .lower = lower,
        .upper = upper,
        .work = work,
        .target = merged,
    }, null)) {
        say(write_fd, .overlayfs, .ok);
    } else |err| {
        say(write_fd, .overlayfs, mountAnswer(err));
    }
}

fn mountAnswer(err: sandbox.namespace.MountError) Answer {
    return switch (err) {
        // The two the kernel answers when the filesystem is not there at all.
        error.OverlayNotSupported, error.KernelTooOld => .absent,
        error.NotPermitted,
        error.SourceMissing,
        error.OutOfMemory,
        error.DenyTargetIsDirectory,
        error.DenyTargetIsSymlink,
        error.BindSourceIsSymlink,
        error.BindTargetIsSymlink,
        error.Unexpected,
        => .refused,
    };
}

fn joinLeaf(buffer: []u8, a: []const u8, b: []const u8) ?[]const u8 {
    if (a.len + 1 + b.len > buffer.len) return null;
    @memcpy(buffer[0..a.len], a);
    buffer[a.len] = '/';
    @memcpy(buffer[a.len + 1 ..][0..b.len], b);
    return buffer[0 .. a.len + 1 + b.len];
}

fn sayFilter(write_fd: i32, filter: ?[]sandbox.bpf.Insn) void {
    const insns = filter orelse return;
    if (sandbox.seccomp.install(sandbox.bpf.Prog.init(insns))) {
        say(write_fd, .seccomp, .ok);
    } else |err| {
        say(write_fd, .seccomp, switch (err) {
            error.NotSupported => .absent,
            error.NoNewPrivsRefused, error.NotPermitted, error.Rejected, error.Unexpected => .refused,
        });
    }
}

fn say(write_fd: i32, step: Step, answer: Answer) void {
    sayDetail(write_fd, step, answer, 0);
}

fn sayDetail(write_fd: i32, step: Step, answer: Answer, detail: u8) void {
    const record = [record_bytes]u8{ @intFromEnum(step), @intFromEnum(answer), detail };
    _ = linux.write(write_fd, &record, record.len);
}

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = exe_path;

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    var env = try environ.createMap(arena);
    defer env.deinit();

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        else => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    const project_root = try resolveProject(arena, io, options.project);

    const measured = measure(arena, gpa, io, &env, project_root);
    const rows = try rowsFor(arena, measured);
    const verdict = verdictFor(rows);
    printReport(project_root, measured, rows, verdict);
    return exitFor(verdict).code();
}

const ParseError = error{ HelpWanted, BadArguments };

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;
        if (std.mem.eql(u8, argument, "--project")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.project = args[index];
            continue;
        }
        return error.BadArguments;
    }
    return options;
}

fn resolveProject(arena: std.mem.Allocator, io: std.Io, given: ?[]const u8) ![]const u8 {
    if (given) |path| {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return arena.dupe(u8, path);
        defer dir.close(io);
        const len = dir.realPath(io, &buffer) catch return arena.dupe(u8, path);
        return arena.dupe(u8, buffer[0..len]);
    }
    return std.process.currentPathAlloc(io, arena);
}

const testing = std.testing;

fn healthy() Measured {
    return .{
        .driver = sandbox.Sandbox.Guarantees.initFull(),
        .family = .namespaces,
        .user_namespace = .ok,
        .mount_namespace = .ok,
        .pid_namespace = .ok,
        .ipc_namespace = .ok,
        .network_namespace = .ok,
        .router_network = .ok,
        .router_filter = .ok,
        .resolver_files = .made_inside,
        .landlock = .ok,
        .landlock_abi = 6,
        .seccomp = .ok,
        .cgroup = .ok,
        .cgroup_vantage = .own,
        .overlayfs = .ok,
        .pidfd = .ok,
        .tmpfs = .ok,
        .device_passthrough = true,
        .git_program = "/run/current-system/sw/bin/git",
        .nix_program = "/run/current-system/sw/bin/nix",
        .dev_shell = .{ .read = false },
        .container = .not_installed,
        .toolchain = .dev_shell,
        .credential = .{ .found = "chock login" },
        .cache = .ok,
        .free_bytes = 8 * 1024 * 1024 * 1024,
        .card_seal = .ok,
        .card_readers = 1,
    };
}

fn rowNamed(rows: []const Row, name: []const u8) ?Row {
    for (rows) |row| {
        if (std.mem.eql(u8, row.name, name)) return row;
    }
    return null;
}

test "a layer this machine has is still reported absent when the measurement says absent" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.landlock = .{ .absent = "the kernel answered that it has no Landlock" };
    m.landlock_abi = null;
    m.overlayfs = .{ .absent = "the kernel answered that it does not have it" };
    m.tmpfs = .{ .absent = "the kernel answered that it does not have it" };

    const rows = try rowsFor(arena, m);

    try testing.expectEqual(ui.Layer.State.unsupported, rowNamed(rows, "landlock").?.state);
    try testing.expectEqual(ui.Layer.State.unsupported, rowNamed(rows, "overlayfs").?.state);
    try testing.expectEqual(ui.Layer.State.unsupported, rowNamed(rows, "disk cap tmpfs").?.state);

    try testing.expectEqual(ui.Layer.State.on, rowNamed(rows, "user namespace").?.state);
    try testing.expectEqual(ui.Layer.State.on, rowNamed(rows, "seccomp").?.state);
}

test "a layer the machine has and this process may not use is BLOCKED, not NONE" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.user_namespace = .{ .refused = "the kernel refused a user namespace to this process" };
    const rows = try rowsFor(arena, m);

    const row = rowNamed(rows, "user namespace").?;
    try testing.expectEqual(ui.Layer.State.unavailable, row.state);
    try testing.expect(row.blocks);
    try testing.expectEqualStrings("BLOCKED", wordFor(row));
    try testing.expect(row.state != .unsupported);
    try testing.expect(std.mem.indexOf(u8, row.fix, "unprivileged_userns_clone") != null);
}

test "a project that gave up the write and execute rule does not read like one that kept it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const strict_rows = try rowsFor(arena, healthy());
    const strict = rowNamed(strict_rows, "write^execute").?;
    try testing.expectEqual(ui.Layer.State.on, strict.state);
    try testing.expectEqualStrings("OK", wordFor(strict));

    var m = healthy();
    m.write_execute = .relaxed;
    const relaxed_rows = try rowsFor(arena, m);
    const relaxed = rowNamed(relaxed_rows, "write^execute").?;
    try testing.expectEqual(ui.Layer.State.off, relaxed.state);
    try testing.expectEqualStrings("OFF", wordFor(relaxed));

    try testing.expect(relaxed.state != .unsupported);
    try testing.expect(relaxed.state != .unavailable);

    try testing.expect(std.mem.indexOf(u8, relaxed.means, chock_policy.hardening.jit_action) != null);

    try testing.expect(!strict.blocks);
    try testing.expect(!relaxed.blocks);
}

test "the report reads the same rules a session reads, and an org bundle can take the row back" {
    const allocator = testing.allocator;
    const source =
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "sandbox.jit", .decision = .allow },
        \\} } }
    ;
    const key: chock_policy.table.Key = .{
        .agent_kind = doctor_agent_kind,
        .model = no_default_model,
        .tool = chock_broker.actions.self_asked_tool,
        .action = chock_policy.hardening.jit_action,
    };

    const alone = try chock_policy.table.Table.parse(allocator, source, null);
    defer chock_policy.table.Table.destroy(allocator, alone);
    try testing.expectEqual(
        chock_policy.hardening.WriteExecute.relaxed,
        chock_policy.hardening.writeExecuteFor(alone.evaluateChain(&.{doctor_agent_kind}, key, null)),
    );

    const org_rules = [_]chock_policy.table.Rule{
        .{ .action = chock_policy.hardening.jit_action, .decision = .deny },
    };
    const under_org = try chock_policy.table.Table.parseUnder(allocator, source, &org_rules, null);
    defer chock_policy.table.Table.destroy(allocator, under_org);
    try testing.expectEqual(
        chock_policy.hardening.WriteExecute.strict,
        chock_policy.hardening.writeExecuteFor(under_org.evaluateChain(&.{doctor_agent_kind}, key, null)),
    );
}

test "a cgroup refusal measured inside a namespace says so, and never blames a working init system" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.cgroup = .{ .unavailable = .no_delegated_parent };

    m.cgroup_vantage = .own;
    const on_the_machine = rowNamed(try rowsFor(arena, m), "cgroup v2").?;
    try testing.expect(std.mem.indexOf(u8, on_the_machine.means, "namespace") == null);
    try testing.expect(std.mem.indexOf(u8, on_the_machine.fix, "init system") != null);

    m.cgroup_vantage = .foreign;
    const in_a_container = rowNamed(try rowsFor(arena, m), "cgroup v2").?;
    try testing.expect(std.mem.indexOf(u8, in_a_container.means, "cgroup namespace") != null);
    try testing.expect(std.mem.indexOf(u8, in_a_container.means, "not for the machine outside it") != null);
    try testing.expect(std.mem.indexOf(u8, in_a_container.fix, "init system") == null);
    try testing.expect(std.mem.indexOf(u8, in_a_container.fix, "outside it") != null);
    try testing.expect(!std.mem.eql(u8, on_the_machine.means, in_a_container.means));

    m.cgroup = .{ .unavailable = .no_cgroup2_mount };
    m.cgroup_vantage = .not_mounted;
    const hidden = rowNamed(try rowsFor(arena, m), "cgroup v2").?;
    try testing.expectEqual(ui.Layer.State.unavailable, hidden.state);
    try testing.expect(!hidden.blocks);
    try testing.expectEqualStrings("DEGRADED", wordFor(hidden));
    try testing.expect(std.mem.indexOf(u8, hidden.means, "not for the machine outside it") != null);

    m.cgroup = .{ .unavailable = .no_delegated_parent };
    m.cgroup_vantage = .unknown;
    const unproven = rowNamed(try rowsFor(arena, m), "cgroup v2").?;
    try testing.expect(std.mem.indexOf(u8, unproven.means, "may be") != null);
    try testing.expect(!std.mem.eql(u8, unproven.means, on_the_machine.means));

    m.cgroup = .{ .unavailable = .create_refused };
    m.cgroup_vantage = .own;
    const refused = rowNamed(try rowsFor(arena, m), "cgroup v2").?;
    try testing.expect(std.mem.indexOf(u8, refused.fix, "init system") == null);
    try testing.expect(std.mem.indexOf(u8, refused.fix, "already delegated") != null);
    try testing.expect(!std.mem.eql(u8, refused.fix, on_the_machine.fix));
}

test "the report is readable with no colour: every row carries a glyph, a word, and a sentence when something is wrong" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.cgroup = .{ .unavailable = .no_delegated_parent };
    m.seccomp = .{ .refused = "the kernel refused a seccomp filter to this process" };
    m.dev_shell = .no_flake;
    const rows = try rowsFor(arena, m);

    try testing.expect(rows.len > 0);
    var not_on: usize = 0;
    for (rows) |row| {
        try testing.expect(row.name.len != 0);
        try testing.expect(row.state.glyph().len != 0);
        try testing.expect(wordFor(row).len != 0);
        if (row.state == .on) {
            try testing.expect(row.means.len != 0 or row.why.len != 0);
            continue;
        }
        not_on += 1;
        try testing.expect(row.means.len != 0);
    }
    try testing.expect(not_on >= 2);

    const stated: Row = .{ .name = "stated", .state = .on, .means = "" };
    try testing.expectEqualStrings("OK", wordFor(stated));
    try testing.expectEqualStrings("OFF", wordFor(.{ .name = "x", .state = .off, .means = "y" }));
    try testing.expectEqualStrings("NONE", wordFor(.{ .name = "x", .state = .unsupported, .means = "y" }));
    try testing.expectEqualStrings("DEGRADED", wordFor(.{ .name = "x", .state = .unavailable, .means = "y" }));
    for ([_]ui.Layer.State{ .off, .unsupported, .unavailable }) |state| {
        try testing.expectEqualStrings("BLOCKED", wordFor(.{
            .name = "x",
            .state = state,
            .means = "y",
            .blocks = true,
        }));
    }

    const cgroup_row = rowNamed(rows, "cgroup v2").?;
    try testing.expect(cgroup_row.fix.len != 0);
    try testing.expect(std.mem.indexOf(u8, cgroup_row.means, "rlimit floor") != null);
}

test "the word BLOCKED stands beside exactly the rows the footer counts" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.dev_shell = .{ .failed = "nix could not evaluate it" };
    m.credential = .{ .unconfigured = "no provider is named in config.zon" };
    const rows = try rowsFor(arena, m);

    var said: usize = 0;
    for (rows) |row| {
        const says_blocked = std.mem.eql(u8, wordFor(row), "BLOCKED");
        try testing.expectEqual(row.state != .on and row.blocks, says_blocked);
        if (says_blocked) said += 1;
    }
    try testing.expectEqual(countBlocking(rows), said);
    try testing.expectEqual(@as(usize, 1), said);

    const dev = rowNamed(rows, "dev shell").?;
    try testing.expectEqual(ui.Layer.State.unavailable, dev.state);
    try testing.expect(!dev.blocks);
    try testing.expectEqualStrings("DEGRADED", wordFor(dev));
    try testing.expectEqualStrings("BLOCKED", wordFor(rowNamed(rows, "credential").?));

    var no_landlock = healthy();
    no_landlock.landlock = .{ .absent = "the kernel answered that it has no Landlock" };
    no_landlock.landlock_abi = null;
    const kernel_rows = try rowsFor(arena, no_landlock);
    const landlock = rowNamed(kernel_rows, "landlock").?;
    try testing.expectEqual(ui.Layer.State.unsupported, landlock.state);
    try testing.expect(landlock.blocks);
    try testing.expectEqualStrings("BLOCKED", wordFor(landlock));
}

test "the printed report says BLOCKED as many times as its own footer counts" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = Measured{
        .driver = sandbox.darwin_driver_for_testing.guarantees,
        .family = .seatbelt,
        .seatbelt = .ok,
        .rlimits = .ok,
    };
    m.git_program = "/usr/bin/git";
    m.nix_program = "/run/current-system/sw/bin/nix";
    m.toolchain = .{ .host = 4 };
    m.cache = .ok;
    m.free_bytes = 8 * 1024 * 1024 * 1024;
    m.dev_shell = .{ .failed = "nix could not evaluate it" };
    m.credential = .{ .unconfigured = "no provider is named in config.zon" };

    const rows = try rowsFor(arena, m);
    const verdict = verdictFor(rows);
    try testing.expectEqual(Verdict.blocked, verdict);

    tty.configure(.{});
    defer tty.configure(.{});

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    printReport("/some/project", m, rows, verdict);
    tty.flushOut();

    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, said.out(), "BLOCKED"));
    try testing.expectEqual(countBlocking(rows), std.mem.count(u8, said.out(), "BLOCKED"));
    try testing.expect(std.mem.indexOf(u8, said.err(), "Rows that stop a first run: 1 of") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "DEGRADED") != null);
}

test "a machine where no tool call could work does not read as a machine a session can start on" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.toolchain = .none;
    const rows = try rowsFor(arena, m);
    try testing.expect(rowNamed(rows, "toolchain").?.blocks);
    try testing.expectEqual(Verdict.blocked, verdictFor(rows));

    m.toolchain = .{ .host = 6 };
    const wide = try rowsFor(arena, m);
    const row = rowNamed(wide, "toolchain").?;
    try testing.expectEqual(ui.Layer.State.on, row.state);
    try testing.expect(!row.blocks);
    try testing.expect(std.mem.indexOf(u8, row.fix, "flake.nix") != null);
    try testing.expectEqual(Verdict.ready, verdictFor(wide));

    m.toolchain = .{ .image_unusable = "run `docker pull debian:stable-slim` first" };
    const missing = try rowsFor(arena, m);
    try testing.expect(rowNamed(missing, "toolchain").?.blocks);
    try testing.expectEqual(Verdict.blocked, verdictFor(missing));
}

test "the container row appears only where it matters, and its trust position is never a layer" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.container = .{ .ready = .{ .kind = .docker, .program = "/usr/bin/docker", .trust = .root_daemon } };
    const with_docker = try rowsFor(arena, m);
    const row = rowNamed(with_docker, "container runtime").?;
    try testing.expectEqual(ui.Layer.State.on, row.state);
    try testing.expect(!row.blocks);
    try testing.expect(std.mem.indexOf(u8, row.fix, "Warning") != null);
    try testing.expectEqual(Verdict.ready, verdictFor(with_docker));
    try testing.expectEqual(healthy().family, LayerFamily.forDriver(healthy().driver));

    m.container = .{ .ready = .{ .kind = .podman, .program = "/usr/bin/podman", .trust = .user_only } };
    const rootless = try rowsFor(arena, m);
    try testing.expectEqual(@as(usize, 0), rowNamed(rootless, "container runtime").?.fix.len);

    m.container = .not_installed;
    const quiet = try rowsFor(arena, m);
    try testing.expectEqual(@as(?Row, null), rowNamed(quiet, "container runtime"));

    m.container = .{ .unreachable_runtime = "the daemon is not running" };
    const silent = try rowsFor(arena, m);
    try testing.expectEqual(@as(?Row, null), rowNamed(silent, "container runtime"));

    m.toolchain = .{ .image_unusable = "no container runtime is installed" };
    m.container = .not_installed;
    const wanted = try rowsFor(arena, m);
    try testing.expectEqual(ui.Layer.State.off, rowNamed(wanted, "container runtime").?.state);
    try testing.expect(!rowNamed(wanted, "container runtime").?.blocks);
    try testing.expect(rowNamed(wanted, "toolchain").?.blocks);
}

test "a build whose driver applies no layer gets one sentence and no layer rows" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = Measured{ .driver = sandbox.Sandbox.Guarantees.initEmpty(), .family = .none };
    m.credential = .{ .found = "chock login" };
    m.cache = .ok;
    m.free_bytes = 8 * 1024 * 1024 * 1024;
    m.dev_shell = .no_flake;

    const rows = try rowsFor(arena, m);

    for ([_][]const u8{
        "user namespace",
        "mount namespace",
        "pid namespace",
        "ipc namespace",
        "net namespace",
        "router network",
        "router filter",
        resolver_files_name,
        "landlock",
        "seccomp",
        "pidfd",
        "disk cap tmpfs",
        "overlayfs",
        "cgroup v2",
    }) |name| {
        try testing.expectEqual(@as(?Row, null), rowNamed(rows, name));
    }

    try testing.expect(rowNamed(rows, "credential") != null);
    try testing.expect(rowNamed(rows, "workspace space") != null);

    try testing.expect(std.mem.indexOf(u8, refuses_outright, "Sandbox.spawn refuses") != null);
    try testing.expect(std.mem.indexOf(u8, refuses_outright, "no sandbox driver") != null);
    try testing.expect(std.mem.indexOf(u8, refuses_outright, "nothing to configure") != null);
}

test "the real Darwin driver gives four layers, and still refuses a root of its own" {
    const darwin = sandbox.darwin_driver_for_testing;
    try testing.expectEqual(@as(usize, 4), darwin.guarantees.count());
    for ([_]sandbox.Sandbox.Guarantee{ .network_isolated, .signal_isolated, .ipc_isolated, .path_restricted }) |one| {
        try testing.expect(darwin.guarantees.contains(one));
    }
    try testing.expect(!darwin.guarantees.contains(.syscall_restricted));
    try testing.expect(!darwin.guarantees.contains(.workspace_mounted));

    try testing.expectError(error.NoMountNamespace, darwin.spawn(
        testing.allocator,
        .{ .root = "/nonexistent", .mounts = &.{}, .rules = &.{}, .cwd = "/", .env = &.{} },
        &.{"true"},
        null,
        null,
    ));

    try testing.expectEqual(LayerFamily.seatbelt, LayerFamily.forDriver(darwin.guarantees));
}

test "a seatbelt build gets darwin's own rows, and none of the eleven linux ones" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = Measured{
        .driver = sandbox.darwin_driver_for_testing.guarantees,
        .family = .seatbelt,
        .seatbelt = .ok,
        .rlimits = .ok,
    };
    m.credential = .{ .found = "chock login" };
    m.cache = .ok;
    m.free_bytes = 8 * 1024 * 1024 * 1024;
    m.dev_shell = .no_flake;
    m.git_program = "/usr/bin/git";
    m.toolchain = .{ .host = 4 };
    m.tool_call_refused = "a tool call needs a path to appear somewhere else";

    const rows = try rowsFor(arena, m);

    for ([_][]const u8{ "user namespace", "mount namespace", "landlock", "seccomp", "pidfd", "cgroup v2", "overlayfs" }) |name| {
        try testing.expectEqual(@as(?Row, null), rowNamed(rows, name));
    }
    for ([_][]const u8{ "seatbelt", "network", "signal reach", "ipc" }) |name| {
        try testing.expectEqual(ui.Layer.State.on, rowNamed(rows, name).?.state);
    }
    for ([_][]const u8{ "memory ceiling", "mapped memory", "process count", "disk cap tmpfs" }) |name| {
        const row = rowNamed(rows, name).?;
        try testing.expectEqual(ui.Layer.State.unsupported, row.state);
        try testing.expect(!row.blocks);
        try testing.expect(row.means.len != 0);
    }
    try testing.expectEqual(ui.Layer.State.on, rowNamed(rows, "rlimit floor").?.state);

    const tool_call = rowNamed(rows, tool_call_name).?;
    try testing.expect(tool_call.blocks);
    try testing.expectEqual(Verdict.blocked, verdictFor(rows));

    m.tool_call_refused = null;
    const runs = try rowsFor(arena, m);
    try testing.expectEqual(ui.Layer.State.on, rowNamed(runs, tool_call_name).?.state);
    try testing.expectEqual(Verdict.degraded, verdictFor(runs));
}

test "the tool call row asks the libraries where they really put their paths" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = "/some/session/scratch";
    if (sandbox.expresses.moved_paths) {
        const why = seatbeltToolCallRefusal(arena, root).?;
        try testing.expect(std.mem.indexOf(u8, why, "bind mount") != null);
        try testing.expect(std.mem.indexOf(u8, why, chock_core.scratchpad.sandbox_dir) != null);
    } else {
        try testing.expectEqual(@as(?[]const u8, null), seatbeltToolCallRefusal(arena, root));
        for ([_][]const u8{
            chock_core.scratchpad.sandboxDirFor(root),
            chock_core.cache.sandboxDirFor(root),
            chock_core.tasks.sandboxDirFor(root),
        }) |target| try testing.expectEqualStrings(root, target);
    }

    try testing.expectEqual(
        @as(?sandbox.darwin_driver_for_testing.Inexpressible, null),
        sandbox.darwin_driver_for_testing.expressibleOn(.{
            .root = "/",
            .mounts = &.{.{ .bind = .{ .source = "/x", .target = "/x", .read_only = true } }},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
        }),
    );
    try testing.expectEqual(
        @as(?sandbox.darwin_driver_for_testing.Inexpressible, .bind_moves_a_path),
        sandbox.darwin_driver_for_testing.expressibleOn(.{
            .root = "/",
            .mounts = &.{.{ .bind = .{ .source = "/x", .target = "/y", .read_only = true } }},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
        }),
    );
}

test "the exit code says whether a first run can work here, and degraded is not a failure" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ready = try rowsFor(arena, healthy());
    try testing.expectEqual(Verdict.ready, verdictFor(ready));
    try testing.expectEqual(@as(u8, 0), exitFor(verdictFor(ready)).code());

    var degraded = healthy();
    degraded.cgroup = .{ .unavailable = .no_delegated_parent };
    degraded.overlayfs = .{ .absent = "the kernel answered that it does not have it" };
    degraded.nix_program = null;
    const degraded_rows = try rowsFor(arena, degraded);
    try testing.expectEqual(Verdict.degraded, verdictFor(degraded_rows));
    try testing.expectEqual(@as(u8, 0), exitFor(verdictFor(degraded_rows)).code());

    var blocked = healthy();
    blocked.landlock = .{ .absent = "the kernel answered that it has no Landlock" };
    blocked.landlock_abi = null;
    const blocked_rows = try rowsFor(arena, blocked);
    try testing.expectEqual(Verdict.blocked, verdictFor(blocked_rows));
    try testing.expectEqual(Exit.faulted, exitFor(verdictFor(blocked_rows)));
    try testing.expect(exitFor(verdictFor(blocked_rows)).code() != 0);
    try testing.expect(exitFor(verdictFor(blocked_rows)) != .usage);
}

fn broken() Measured {
    var m = healthy();
    const refused = Probe{ .refused = "the kernel refused it to this process" };
    m.user_namespace = refused;
    m.mount_namespace = refused;
    m.pid_namespace = refused;
    m.ipc_namespace = refused;
    m.network_namespace = refused;
    m.router_network = .{ .absent = "the dummy_create step needs a kernel module that is not loaded" };
    m.router_filter = .{ .absent = "the batch_begin step needs a kernel module that is not loaded" };
    m.resolver_files = .owned;
    m.landlock = .{ .absent = "the kernel answered that it has no Landlock" };
    m.landlock_abi = null;
    m.seccomp = refused;
    m.cgroup = .{ .unavailable = .no_delegated_parent };
    m.overlayfs = .{ .absent = "the kernel answered that it does not have it" };
    m.pidfd = refused;
    m.tmpfs = refused;
    m.git_program = null;
    m.nix_program = null;
    m.dev_shell = .{ .failed = "flake.nix does not evaluate" };
    m.container = .{ .unreachable_runtime = "the daemon is not running" };
    m.toolchain = .none;
    m.credential = .{ .unconfigured = "there is no configuration" };
    m.cache = .{ .refused = "CacheDirectoryUnwritable" };
    m.free_bytes = 1024;
    m.card_seal = .{ .absent = "there is no pcscd socket at /run/pcscd/pcscd.comm" };
    m.card_readers = null;
    m.write_execute = .relaxed;
    m.device_passthrough = false;
    return m;
}

test "every row that stops a first run is one Sandbox.spawn or chock run really refuses on" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rows = try rowsFor(arena, broken());
    for (rows) |row| try testing.expect(row.state != .on);

    const blocking = [_][]const u8{
        "user namespace",
        "mount namespace",
        "pid namespace",
        "ipc namespace",
        "net namespace",
        "router network",
        "router filter",
        resolver_files_name,
        "landlock",
        "seccomp",
        "pidfd",
        "disk cap tmpfs",
        "credential",
        "git",
        "toolchain",
        "workspace space",
    };
    const not_blocking = [_][]const u8{
        "overlayfs",
        "cgroup v2",
        "nix",
        "dev shell",
        "toolchain cache",
        "card seal",
        "write^execute",
    };
    for (blocking) |name| try testing.expect(rowNamed(rows, name).?.blocks);
    for (not_blocking) |name| try testing.expect(!rowNamed(rows, name).?.blocks);
    try testing.expectEqual(blocking.len + not_blocking.len, rows.len);
}

test "a provider that asks for no credential is not a machine that cannot run" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.credential = .not_needed;
    const rows = try rowsFor(arena, m);
    try testing.expect(!rowNamed(rows, "credential").?.blocks);
    try testing.expectEqual(Verdict.degraded, verdictFor(rows));
    try testing.expectEqual(@as(u8, 0), exitFor(verdictFor(rows)).code());
}

test "free space that could not be read is never reported as no room" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var unknown = healthy();
    unknown.free_bytes = null;
    const unknown_rows = try rowsFor(arena, unknown);
    const unknown_row = rowNamed(unknown_rows, "workspace space").?;
    try testing.expect(!unknown_row.blocks);
    try testing.expect(std.mem.indexOf(u8, unknown_row.means, "not the same as no room") != null);

    var full = healthy();
    full.free_bytes = 1024;
    const full_rows = try rowsFor(arena, full);
    try testing.expect(rowNamed(full_rows, "workspace space").?.blocks);
    try testing.expectEqual(Verdict.blocked, verdictFor(full_rows));
}

test "an audit sink this installation requires and cannot reach is reported and stops nothing" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.required_sinks = &.{.{
        .kind = .directory,
        .path = "/var/audit/chock",
        .reached = .{ .refused = "AccessDenied" },
    }};
    const rows = try rowsFor(arena, m);

    const row = rowNamed(rows, required_sink_name).?;
    try testing.expect(!row.blocks);
    try testing.expectEqual(ui.Layer.State.unavailable, row.state);
    try testing.expect(std.mem.indexOf(u8, row.means, "/var/audit/chock") != null);
    try testing.expect(std.mem.indexOf(u8, row.means, "AccessDenied") != null);
    try testing.expect(std.mem.indexOf(u8, row.means, "still starts") != null);
    const code = try std.fmt.allocPrint(arena, "exits {d}", .{Exit.audit_gap.code()});
    try testing.expect(std.mem.indexOf(u8, row.means, code) != null);
    try testing.expect(std.mem.indexOf(u8, row.fix, "org policy bundle") != null);

    try testing.expectEqual(Verdict.degraded, verdictFor(rows));
    try testing.expectEqual(@as(u8, 0), exitFor(verdictFor(rows)).code());

    try testing.expect(isFirstRunRow(row));
}

test "a required sink that was reached says so, and an installation with no bundle adds no row" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var reached = healthy();
    reached.required_sinks = &.{
        .{ .kind = .directory, .path = "/var/audit/chock", .reached = .ok },
        .{ .kind = .syslog, .path = "/dev/log", .reached = .ok },
    };
    const reached_rows = try rowsFor(arena, reached);

    var found: usize = 0;
    for (reached_rows) |row| {
        if (!std.mem.eql(u8, row.name, required_sink_name)) continue;
        try testing.expectEqual(ui.Layer.State.on, row.state);
        try testing.expectEqualStrings("", row.fix);
        found += 1;
    }
    try testing.expectEqual(@as(usize, 2), found);
    try testing.expect(std.mem.indexOf(u8, reached_rows[reached_rows.len - 2].means, "/var/audit/chock") != null);
    try testing.expect(std.mem.indexOf(u8, reached_rows[reached_rows.len - 1].means, "/dev/log") != null);
    try testing.expectEqual(Verdict.ready, verdictFor(reached_rows));

    const plain = try rowsFor(arena, healthy());
    try testing.expectEqual(@as(?Row, null), rowNamed(plain, required_sink_name));
    try testing.expectEqual(reached_rows.len - 2, plain.len);
}

test "a daemon that refused is DEGRADED and a machine with no reader is NONE" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var refused = healthy();
    refused.card_seal = .{ .refused = "pcscd accepted the connection and closed it without answering" };
    refused.card_readers = null;
    const refused_rows = try rowsFor(arena, refused);
    const refused_row = rowNamed(refused_rows, "card seal").?;
    try testing.expectEqual(ui.Layer.State.unavailable, refused_row.state);
    try testing.expect(std.mem.indexOf(u8, refused_row.means, "closed it without answering") != null);
    try testing.expectEqualStrings("DEGRADED", wordFor(refused_row));

    var empty = healthy();
    empty.card_seal = .{ .absent = "a PC/SC daemon answered and no reader is attached" };
    empty.card_readers = 0;
    const empty_rows = try rowsFor(arena, empty);
    const empty_row = rowNamed(empty_rows, "card seal").?;
    try testing.expectEqual(ui.Layer.State.unsupported, empty_row.state);
    try testing.expectEqualStrings("NONE", wordFor(empty_row));

    try testing.expect(!refused_row.blocks);
    try testing.expect(!empty_row.blocks);
    try testing.expectEqual(Verdict.degraded, verdictFor(refused_rows));
    try testing.expectEqual(@as(u8, 0), exitFor(verdictFor(refused_rows)).code());
}

test "a card seal row that is on says how many readers were named" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var three = healthy();
    three.card_readers = 3;
    const rows = try rowsFor(arena, three);
    const row = rowNamed(rows, "card seal").?;
    try testing.expectEqual(ui.Layer.State.on, row.state);
    try testing.expect(std.mem.indexOf(u8, row.means, "3 reader") != null);
    try testing.expectEqualStrings("", row.fix);
}

test "the card seal is reported before a first run, not as a sandbox layer" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rows = try rowsFor(arena, healthy());
    try testing.expect(isFirstRunRow(rowNamed(rows, "card seal").?));
}

test "the report opens with the version, on an ordinary run and not only with --verbose" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const m = healthy();
    const rows = try rowsFor(arena, m);

    tty.configure(.{});
    defer tty.configure(.{});

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    printReport("/some/project", m, rows, verdictFor(rows));
    tty.flushOut();

    const first = std.mem.sliceTo(said.out(), '\n');
    try testing.expectEqualStrings(version_line, first);
    try testing.expect(std.mem.indexOf(u8, said.err(), version_line) == null);
    try testing.expect(std.mem.indexOf(u8, said.out(), first_run_heading).? > first.len);
}

test "the report says what redaction is not, with --verbose, in the words the module argued for" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const m = healthy();
    const rows = try rowsFor(arena, m);

    {
        tty.configure(.{});
        defer tty.configure(.{});

        var quiet: tty.Capture = undefined;
        quiet.start(testing.io, testing.allocator);
        defer quiet.stop(testing.io);

        printReport("/some/project", m, rows, verdictFor(rows));
        tty.flushOut();

        try testing.expect(std.mem.indexOf(u8, quiet.out(), "Redaction") == null);
    }

    tty.configure(.{ .verbose = true });
    defer tty.configure(.{});

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    printReport("/some/project", m, rows, verdictFor(rows));
    tty.flushOut();

    try testing.expect(std.mem.indexOf(u8, said.out(), chock_core.redact.not_a_boundary) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "/some/project") != null);
    const at = std.mem.indexOf(u8, said.out(), chock_core.redact.not_a_boundary).?;
    try testing.expect(at > std.mem.indexOf(u8, said.out(), layers_heading).?);
    try testing.expect(at > std.mem.indexOf(u8, said.out(), first_run_heading).?);
    try testing.expect(std.mem.indexOf(u8, said.out(), "redaction   ") == null);
}

test "a required sink is reached through the shipper's own transport, and the probe is removed" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = buffer[0..len];

    const drop_dir = try std.fmt.allocPrint(arena, "{s}/audit", .{root});
    const reached = reachSink(arena, testing.io, .{ .kind = .directory, .path = drop_dir });
    try testing.expectEqual(ui.Layer.State.on, reached.state());

    var opened = try std.Io.Dir.openDirAbsolute(testing.io, drop_dir, .{ .iterate = true });
    defer opened.close(testing.io);
    var it = opened.iterate();
    try testing.expectEqual(@as(?std.Io.Dir.Entry, null), try it.next(testing.io));

    const missing = try std.fmt.allocPrint(arena, "{s}/no-such-socket", .{root});
    const down = reachSink(arena, testing.io, .{ .kind = .syslog, .path = missing });
    try testing.expectEqual(ui.Layer.State.unavailable, down.state());
    try testing.expect(down.why().len != 0);
}

test "the command line takes a project and nothing else" {
    try testing.expectEqual(@as(?[]const u8, null), (try parseOptions(&.{})).project);
    try testing.expectEqualStrings("/somewhere", (try parseOptions(&.{ "--project", "/somewhere" })).project.?);
    try testing.expectError(error.BadArguments, parseOptions(&.{"--project"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"list"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"-h"}));
}

test "the probe answers map to the three states and never invent a fourth" {
    try testing.expectEqual(ui.Layer.State.on, whyFor(.ok, "x").state());
    try testing.expectEqual(ui.Layer.State.unsupported, whyFor(.absent, "x").state());
    try testing.expectEqual(ui.Layer.State.unavailable, whyFor(.refused, "x").state());
    try testing.expectEqualStrings("x", whyFor(.refused, "x").why());
    try testing.expectEqualStrings("", whyFor(.ok, "x").why());
}

test "the router rows are built by really building a network and really filtering it" {
    switch (comptime LayerFamily.forDriver(sandbox.Sandbox.guarantees)) {
        .none, .seatbelt => return error.SkipZigTest,
        .namespaces => {},
    }

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const report = runChild(.{
        .network = .none,
        .mount = true,
        .filesystems = false,
        .seccomp = false,
        .router = true,
    }, null, null);

    try testing.expect(!report.crashed);

    if (report.namespaces != Answer.ok) return error.SkipZigTest;

    const network = report.router_network orelse return error.TestUnexpectedResult;
    if (network != Answer.ok) {
        try testing.expect(routerStepName(sandbox.netns.Step, report.router_network_step) != null);
        return;
    }

    const filter = report.router_filter orelse return error.TestUnexpectedResult;
    if (filter != Answer.ok) {
        try testing.expect(routerStepName(sandbox.nftables.Step, report.router_filter_step) != null);
        return;
    }

    var m = healthy();
    m.router_network = .{ .absent = "stated, and overwritten by the measurement below" };
    m.router_filter = .{ .absent = "stated, and overwritten by the measurement below" };
    applyRouter(arena, &m, report);
    const rows = try rowsFor(arena, m);
    try testing.expectEqual(ui.Layer.State.on, rowNamed(rows, "router network").?.state);
    try testing.expectEqual(ui.Layer.State.on, rowNamed(rows, "router filter").?.state);
}

test "a plan that asks for no network builds none, so nothing is ever made on the machine a person is using" {
    switch (comptime LayerFamily.forDriver(sandbox.Sandbox.guarantees)) {
        .none, .seatbelt => return error.SkipZigTest,
        .namespaces => {},
    }

    const quiet = runChild(.{
        .network = .host,
        .mount = false,
        .filesystems = false,
        .seccomp = false,
        .router = false,
    }, null, null);
    try testing.expect(!quiet.crashed);
    try testing.expectEqual(@as(?Answer, null), quiet.router_network);
    try testing.expectEqual(@as(?Answer, null), quiet.router_filter);

    const asked = runChild(.{
        .network = .none,
        .mount = true,
        .filesystems = false,
        .seccomp = false,
        .router = true,
    }, null, null);
    try testing.expect(!asked.crashed);
    if (asked.namespaces != Answer.ok) return error.SkipZigTest;
    try testing.expect(asked.router_network != null);
}

test "a kernel that has no module names the call and the modprobe line, and one that refused does not" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqual(Answer.absent, networkAnswer(error.KernelModuleMissing));
    try testing.expectEqual(Answer.absent, filterAnswer(error.KernelModuleMissing));
    for ([_]sandbox.netns.Error{ error.NotPermitted, error.Refused, error.ExchangeFailed }) |err| {
        try testing.expectEqual(Answer.refused, networkAnswer(err));
    }
    for ([_]sandbox.nftables.Error{ error.NotPermitted, error.Refused, error.ExchangeFailed }) |err| {
        try testing.expectEqual(Answer.refused, filterAnswer(err));
    }

    var m = healthy();
    applyRouter(arena, &m, .{
        .namespaces = .ok,
        .router_network = .ok,
        .router_filter = .absent,
        .router_filter_step = @intFromEnum(sandbox.nftables.Step.relay_rule) + 1,
    });
    const rows = try rowsFor(arena, m);

    const filter = rowNamed(rows, "router filter").?;
    try testing.expectEqual(ui.Layer.State.unsupported, filter.state);
    try testing.expectEqualStrings("BLOCKED", wordFor(filter));
    try testing.expect(filter.blocks);
    try testing.expect(std.mem.indexOf(u8, filter.means, "relay_rule") != null);
    if (sandbox.Sandbox.filter_modules.len != 0) {
        try testing.expect(std.mem.indexOf(u8, filter.fix, "modprobe") != null);
        try testing.expect(std.mem.indexOf(u8, filter.fix, sandbox.Sandbox.filter_modules) != null);
        for ([_][]const u8{
            "nf_tables",
            "nf_nat",
            "nft_chain_nat",
            "nft_redir",
            "nft_reject",
            "nf_conntrack",
        }) |module| {
            try testing.expect(std.mem.indexOf(u8, filter.fix, module) != null);
        }
    }
    try testing.expectEqual(ui.Layer.State.on, rowNamed(rows, "router network").?.state);

    var no_dummy = healthy();
    applyRouter(arena, &no_dummy, .{
        .namespaces = .ok,
        .router_network = .absent,
        .router_network_step = @intFromEnum(sandbox.netns.Step.dummy_create) + 1,
    });
    const dummy_rows = try rowsFor(arena, no_dummy);
    const network = rowNamed(dummy_rows, "router network").?;
    try testing.expect(std.mem.indexOf(u8, network.means, "dummy_create") != null);
    if (sandbox.Sandbox.network_modules.len != 0) {
        try testing.expect(std.mem.indexOf(u8, network.fix, "modprobe") != null);
        try testing.expect(std.mem.indexOf(
            u8,
            network.fix,
            sandbox.Sandbox.network_modules,
        ) != null);
        try testing.expect(std.mem.indexOf(u8, network.fix, "nft_redir") == null);
    }
    const never = rowNamed(dummy_rows, "router filter").?;
    try testing.expect(std.mem.indexOf(u8, never.means, "did not come up") != null);
    try testing.expect(std.mem.indexOf(u8, never.fix, "modprobe") == null);

    var refused = healthy();
    applyRouter(arena, &refused, .{
        .namespaces = .ok,
        .router_network = .refused,
        .router_network_step = @intFromEnum(sandbox.netns.Step.route4_add) + 1,
    });
    const refused_rows = try rowsFor(arena, refused);
    const row = rowNamed(refused_rows, "router network").?;
    try testing.expectEqual(ui.Layer.State.unavailable, row.state);
    try testing.expect(std.mem.indexOf(u8, row.means, "route4_add") != null);
    try testing.expect(std.mem.indexOf(u8, row.fix, "modprobe") == null);
    try testing.expect(std.mem.indexOf(u8, row.fix, "worth reporting") != null);
}

test "a child that never reached the network says so, and is never read as a kernel that answered no" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    applyRouter(arena, &m, .{});
    try testing.expectEqualStrings(router_not_reached, m.router_network.why());
    try testing.expectEqualStrings(router_not_reached, m.router_filter.why());
    try testing.expect(std.mem.indexOf(u8, router_not_reached, "namespaces") != null);

    try testing.expectEqual(@as(?[]const u8, null), routerStepName(sandbox.netns.Step, 0));
    try testing.expectEqualStrings(
        "open_socket",
        routerStepName(sandbox.netns.Step, @intFromEnum(sandbox.netns.Step.open_socket) + 1).?,
    );
    try testing.expectEqualStrings(
        "open_socket",
        routerStepName(sandbox.nftables.Step, @intFromEnum(sandbox.nftables.Step.open_socket) + 1).?,
    );
    try testing.expectEqual(@as(?[]const u8, null), routerStepName(sandbox.netns.Step, 250));

    var unnamed = healthy();
    applyRouter(arena, &unnamed, .{ .namespaces = .ok, .router_network = .absent });
    try testing.expectEqualStrings(router_absent_text, unnamed.router_network.why());
}

test "a host whose resolv.conf is a link starts a routed sandbox, and the row says the sandbox owns /etc" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0..try tmp.dir.realPath(testing.io, &root_buffer)];

    try testing.expectEqual(
        ResolverFiles.made_inside,
        measureResolverFiles(testing.io, .{ .host = 9 }, root),
    );

    try tmp.dir.createDir(testing.io, "etc", .default_dir);
    try tmp.dir.symLink(
        testing.io,
        "../run/systemd/resolve/stub-resolv.conf",
        "etc/resolv.conf",
        .{},
    );
    try testing.expectEqual(
        if (sandbox.Sandbox.resolver_substitutions.len != 0)
            ResolverFiles.owned
        else
            ResolverFiles.made_inside,
        measureResolverFiles(testing.io, .{ .host = 9 }, root),
    );

    var linked = healthy();
    linked.toolchain = .{ .host = 9 };
    linked.resolver_files = .owned;
    const row = rowNamed(try rowsFor(arena, linked), resolver_files_name).?;
    try testing.expectEqual(ui.Layer.State.on, row.state);
    try testing.expect(!row.blocks);
    try testing.expect(std.mem.indexOf(u8, row.means, "overlay") != null);

    try tmp.dir.deleteFile(testing.io, "etc/resolv.conf");
    try testing.expectEqual(
        if (sandbox.Sandbox.resolver_substitutions.len != 0)
            ResolverFiles.owned
        else
            ResolverFiles.made_inside,
        measureResolverFiles(testing.io, .{ .host = 9 }, root),
    );

    const refused = rowNamed(try rowsFor(arena, noOverlayHost()), resolver_files_name).?;
    try testing.expectEqual(ui.Layer.State.unavailable, refused.state);
    try testing.expect(refused.blocks);
    try testing.expectEqualStrings("BLOCKED", wordFor(refused));
    try testing.expect(std.mem.indexOf(u8, refused.means, "overlay") != null);
    try testing.expect(std.mem.indexOf(u8, refused.fix, "5.11") != null);
    try testing.expect(std.mem.indexOf(u8, refused.fix, "dev shell") != null);
    try testing.expect(std.mem.indexOf(u8, refused.fix, "container image") != null);

    try tmp.dir.symLink(testing.io, "../run/systemd/resolve/stub-resolv.conf", "etc/resolv.conf", .{});
    try tmp.dir.createDir(testing.io, "nix", .default_dir);
    try tmp.dir.createDir(testing.io, "nix/store", .default_dir);
    try testing.expectEqual(
        ResolverFiles.made_inside,
        measureResolverFiles(testing.io, .{ .host = 9 }, root),
    );
}

test "a toolchain that puts no host /etc in the sandbox is never blocked by the host's own" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0..try tmp.dir.realPath(testing.io, &root_buffer)];
    try tmp.dir.createDir(testing.io, "etc", .default_dir);
    try tmp.dir.symLink(testing.io, "../run/systemd/resolve/stub-resolv.conf", "etc/resolv.conf", .{});

    try testing.expectEqual(
        ResolverFiles.made_inside,
        measureResolverFiles(testing.io, .dev_shell, root),
    );
    try testing.expectEqual(
        ResolverFiles.made_inside,
        measureResolverFiles(testing.io, .none, root),
    );

    const measured = measureResolverFiles(testing.io, .{ .image = "docker.io/library/alpine:3.20" }, root);
    try testing.expectEqualStrings("docker.io/library/alpine:3.20", measured.from_image);

    var m = healthy();
    m.resolver_files = measured;
    const rows = try rowsFor(arena, m);
    const row = rowNamed(rows, resolver_files_name).?;
    try testing.expectEqual(ui.Layer.State.on, row.state);
    try testing.expect(!row.blocks);
    try testing.expect(std.mem.indexOf(u8, row.means, "alpine:3.20") != null);
    try testing.expect(std.mem.indexOf(u8, row.means, "nothing here unpacked one") != null);
}

test "a build whose driver isolates no network gets none of the three router rows" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    try testing.expect(rowNamed(try rowsFor(arena, m), "router network") != null);

    m.driver.remove(.network_isolated);
    const rows = try rowsFor(arena, m);
    for ([_][]const u8{ "router network", "router filter", resolver_files_name }) |name| {
        try testing.expectEqual(@as(?Row, null), rowNamed(rows, name));
    }
    try testing.expect(rowNamed(rows, "landlock") != null);
    try testing.expect(rowNamed(rows, "net namespace") != null);
}

fn noOverlayHost() Measured {
    var m = healthy();
    m.toolchain = .{ .host = 9 };
    m.resolver_files = .owned;
    m.overlayfs = .{ .absent = "the kernel answered that it does not have it" };
    return m;
}

test "a machine that cannot route says so in its exit code, because every tool call takes a filtered network" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var no_modules = healthy();
    applyRouter(arena, &no_modules, .{
        .namespaces = .ok,
        .router_network = .ok,
        .router_filter = .absent,
        .router_filter_step = @intFromEnum(sandbox.nftables.Step.batch_begin) + 1,
    });
    const rows = try rowsFor(arena, no_modules);
    try testing.expectEqual(Verdict.blocked, verdictFor(rows));
    try testing.expectEqual(@as(u8, 2), exitFor(verdictFor(rows)).code());
    try testing.expectEqual(@as(usize, 1), countBlocking(rows));

    const linked_rows = try rowsFor(arena, noOverlayHost());
    try testing.expectEqual(Verdict.blocked, verdictFor(linked_rows));
    try testing.expectEqual(@as(u8, 2), exitFor(verdictFor(linked_rows)).code());

    try testing.expectEqual(Verdict.ready, verdictFor(try rowsFor(arena, healthy())));
    try testing.expectEqual(@as(u8, 0), exitFor(.ready).code());
}

test "the three router rows are sandbox layers and are printed under that heading" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rows = try rowsFor(arena, healthy());
    for ([_][]const u8{ "router network", "router filter", resolver_files_name }) |name| {
        try testing.expect(!isFirstRunRow(rowNamed(rows, name).?));
    }

    var seen: usize = 0;
    var net_namespace: usize = 0;
    var landlock: usize = 0;
    var first_router: usize = 0;
    for (rows, 0..) |row, index| {
        if (std.mem.eql(u8, row.name, "net namespace")) net_namespace = index;
        if (std.mem.eql(u8, row.name, "landlock")) landlock = index;
        if (std.mem.eql(u8, row.name, "router network")) {
            first_router = index;
            seen += 1;
        }
        if (std.mem.eql(u8, row.name, "router filter")) seen += 1;
        if (std.mem.eql(u8, row.name, resolver_files_name)) seen += 1;
    }
    try testing.expectEqual(@as(usize, 3), seen);
    try testing.expectEqual(net_namespace + 1, first_router);
    try testing.expectEqual(first_router + 3, landlock);
}

test "a record from the probe pipe with a byte that names no step is dropped" {
    try testing.expectEqual(@as(?Step, null), std.enums.fromInt(Step, 0));
    try testing.expectEqual(@as(?Step, null), std.enums.fromInt(Step, 200));
    try testing.expectEqual(Step.namespaces, std.enums.fromInt(Step, 1).?);
    try testing.expectEqual(@as(?Answer, null), std.enums.fromInt(Answer, 9));
    try testing.expectEqual(Answer.ok, std.enums.fromInt(Answer, 0).?);
}

test "an org ceiling is reported, and an installation with no bundle adds no row" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var capped = healthy();
    capped.org_ceilings = &.{
        "a session of this installation may spend at most 5 USD",
        "a spawn tree of this installation reaches at most 3 deep and 2 wide",
    };
    const rows = try rowsFor(arena, capped);

    var found: usize = 0;
    for (rows) |row| {
        if (!std.mem.eql(u8, row.name, org_ceiling_name)) continue;
        try testing.expectEqual(ui.Layer.State.on, row.state);
        try testing.expectEqualStrings("", row.fix);
        try testing.expect(!row.blocks);
        found += 1;
    }
    try testing.expectEqual(@as(usize, 2), found);
    try testing.expectEqual(Verdict.ready, verdictFor(rows));

    const plain = try rowsFor(arena, healthy());
    for (plain) |row| {
        try testing.expect(!std.mem.eql(u8, row.name, org_ceiling_name));
    }
}

test "device passthrough is a fact this build's driver can act on, and a build with none gets no row" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var on = healthy();
    on.device_passthrough = true;
    const rows_on = try rowsFor(arena, on);
    const row = rowNamed(rows_on, "device passthrough").?;
    try testing.expectEqual(ui.Layer.State.on, row.state);
    try testing.expectEqualStrings("", row.fix);
    try testing.expect(!row.blocks);
    try testing.expectEqual(Verdict.ready, verdictFor(rows_on));

    var off = healthy();
    off.device_passthrough = false;
    const rows_off = try rowsFor(arena, off);
    try testing.expectEqual(@as(?Row, null), rowNamed(rows_off, "device passthrough"));
}
