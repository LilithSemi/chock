//! The public interface of chock-sandbox: one driver per way of sandboxing,
//! chosen at compile time from `builtin.os.tag`.

const std = @import("std");
const builtin = @import("builtin");
const landlock = @import("linux/landlock.zig");
const namespace = @import("linux/namespace.zig");
const seccomp = @import("linux/seccomp.zig");
const notify = @import("linux/notify.zig");
const rlimits = @import("linux/rlimits.zig");
const cgroup = @import("linux/cgroup.zig");
const nftables = @import("linux/nftables.zig");
const grants = @import("grants.zig");

/// The one directory inside a sandbox root that belongs to Chock. Nothing
/// mounts this path: the kernel takes the last matching mount and not the
/// longest prefix, so a mount here would hide everything below it.
pub const runtime_prefix = "/run/chock";

pub const trust_store_inside = runtime_prefix ++ "/ca-bundle.crt";

pub const expresses = struct {
    pub const moved_paths = builtin.os.tag != .macos;

    pub const scratch_area = builtin.os.tag == .linux;

    pub const procfs = builtin.os.tag == .linux;

    pub const cgroup_placement = builtin.os.tag == .linux;

    pub const device_passthrough = builtin.os.tag == .linux;
};

/// macOS reaches `$TMPDIR` below `/var`, a link to `/private/var`, so a rule
/// written on the unresolved spelling matches nothing. `buffer` holds the answer.
/// Length first, so two fields cannot run together into one reading: a mount
/// of `/ab` at `/c` and one of `/a` at `/bc` are different sandboxes.
fn feedText(hash: *std.crypto.hash.sha2.Sha256, text: []const u8) void {
    feedCount(hash, text.len);
    hash.update(text);
}

fn feedCount(hash: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    hash.update(&bytes);
}

pub fn resolvedPath(io: std.Io, path: []const u8, buffer: []u8) []const u8 {
    if (expresses.moved_paths) return path;
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{}) catch return path;
    defer dir.close(io);
    const length = dir.realPath(io, buffer) catch return path;
    return buffer[0..length];
}

pub const Config = struct {
    root: []const u8,
    /// A `Mount.deny` entry is applied last whatever its place in this list.
    mounts: []const namespace.Mount,
    rules: []const Rule,
    cwd: []const u8,
    env: []const []const u8,
    seccomp_options: seccomp.Options = .{},
    network: namespace.Network = .none,
    stdout_fd: std.posix.fd_t = std.posix.STDOUT_FILENO,
    /// Also carries every setup failure, so `/dev/null` here makes a failed sandbox quiet.
    stderr_fd: std.posix.fd_t = std.posix.STDERR_FILENO,
    /// Null for `/dev/null`, which is what every tool call gets. A pipe here is not
    /// a terminal, so the kernel answers `ENOTTY` to `TIOCSTI` on it.
    stdin_fd: ?std.posix.fd_t = null,
    limits: Limits = .{},
    containment: Containment = .best_effort,
    /// A tmpfs with a hard cap is the only capacity limit an unprivileged process
    /// can put on a filesystem: `RLIMIT_FSIZE` bounds one file, and ten thousand one
    /// byte files still fill a disk.
    scratch: []const namespace.Scratch = &.{},
    /// Required when `network` is `.filtered`, and refused otherwise.
    net_broker: ?NetBroker = null,
    /// A caller names this or `net_broker`, never both: the seccomp rule that stops
    /// a handed over descriptor being re-aimed also stops the router's own program connecting.
    net_router: ?NetRouter = null,
    device_source: ?DeviceSource = null,
    /// `inside` is never granted through `Config.rules`: a rule for it would hand
    /// the sandboxed program the reach only the device helper may have.
    device_tree: ?DeviceTree = null,
    limits_report: ?*LimitsReport = null,
    supervisor_audit: ?*SupervisorAudit = null,
    syscall_audit: ?*SyscallAudit = null,
    /// Telemetry and never evidence: the kernel runs the call after the reader has
    /// read the argument, so a program can write one name and then open another.
    path_audit: bool = false,

    pub const Rule = struct {
        path: []const u8,
        access: landlock.AccessFs,
    };

    /// SHA-256 over what this sandbox lets a tool call reach: every mount with
    /// its kind and paths, every rule with its access bits, the scratch areas,
    /// the limits, the network mode and the device tree.
    ///
    /// A resumed session runs a sandbox built again from the files and flags of
    /// that run, so a change to any of them changes this. That is what it is
    /// for: the log holds one of these per run, and two runs of one session
    /// that differ here were not the same sandbox.
    ///
    /// The environment is left out on purpose. It decides what a program does
    /// and not what it may reach, and it carries a path that moves between
    /// machines, which would make every hash differ for no reason worth
    /// reporting. `stdout_fd` and the report pointers are left out for the
    /// same reason: they are this process's own, not the sandbox's shape.
    pub fn shapeHash(self: Config) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        // A version of this function's own reading. A hash written by an older
        // Chock, over fewer fields, must not compare equal to one written now.
        feedText(&hash, "chock sandbox shape 1");

        feedText(&hash, self.root);
        feedText(&hash, self.cwd);

        feedCount(&hash, self.mounts.len);
        for (self.mounts) |mount| switch (mount) {
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

        feedCount(&hash, self.rules.len);
        for (self.rules) |rule| {
            feedText(&hash, rule.path);
            feedCount(&hash, @as(u64, @intCast(@as(u64, @bitCast(rule.access)))));
        }

        feedCount(&hash, self.scratch.len);
        for (self.scratch) |area| feedText(&hash, area.target);

        inline for (@typeInfo(Limits).@"struct".fields) |field| {
            const value = @field(self.limits, field.name);
            feedText(&hash, field.name);
            if (value) |set| feedCount(&hash, set) else feedText(&hash, "none");
        }

        feedText(&hash, @tagName(self.network));
        feedText(&hash, @tagName(self.containment));
        feedCount(&hash, @intFromBool(self.net_broker != null));
        feedCount(&hash, @intFromBool(self.net_router != null));
        feedCount(&hash, @intFromBool(self.device_source != null));
        if (self.device_tree) |tree| {
            feedText(&hash, tree.host);
            feedText(&hash, tree.inside);
        } else feedText(&hash, "no devices");

        inline for (@typeInfo(seccomp.Options).@"struct".fields) |field| {
            feedText(&hash, field.name);
            const value = @field(self.seccomp_options, field.name);
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

    pub const DeviceTree = struct {
        host: []const u8,
        inside: []const u8,
    };

    /// A copy sharing no memory with the original. A field added below is copied
    /// here on the day it is added, or by nobody.
    pub fn copy(self: Config, allocator: std.mem.Allocator) std.mem.Allocator.Error!Config {
        var out = self;
        out.root = try allocator.dupe(u8, self.root);
        out.cwd = try allocator.dupe(u8, self.cwd);
        out.env = try copyStrings(allocator, self.env);

        if (self.device_tree) |tree| out.device_tree = .{
            .host = try allocator.dupe(u8, tree.host),
            .inside = try allocator.dupe(u8, tree.inside),
        };

        const mounts = try allocator.alloc(namespace.Mount, self.mounts.len);
        for (self.mounts, mounts) |from, *to| {
            to.* = switch (from) {
                .bind => |bind| .{ .bind = .{
                    .source = try allocator.dupe(u8, bind.source),
                    .target = try allocator.dupe(u8, bind.target),
                    .read_only = bind.read_only,
                } },
                .overlay => |overlay| .{ .overlay = .{
                    .lower = try allocator.dupe(u8, overlay.lower),
                    .upper = try allocator.dupe(u8, overlay.upper),
                    .work = try allocator.dupe(u8, overlay.work),
                    .target = try allocator.dupe(u8, overlay.target),
                } },
                .proc => |proc| .{ .proc = .{ .target = try allocator.dupe(u8, proc.target) } },
                .deny => |deny| .{ .deny = .{ .target = try allocator.dupe(u8, deny.target) } },
            };
        }
        out.mounts = mounts;

        const rules = try allocator.alloc(Rule, self.rules.len);
        for (self.rules, rules) |from, *to| {
            to.* = .{ .path = try allocator.dupe(u8, from.path), .access = from.access };
        }
        out.rules = rules;

        const scratch = try allocator.alloc(namespace.Scratch, self.scratch.len);
        for (self.scratch, scratch) |from, *to| {
            to.* = .{ .target = try allocator.dupe(u8, from.target) };
        }
        out.scratch = scratch;
        return out;
    }
};

/// Where a `Config`'s mount list and its Landlock rule list disagree. A rule
/// above a mount target is outside the mount set, because Landlock rights
/// accumulate downwards.
pub const LayerGap = union(enum) {
    rule_outside_mounts: []const u8,
    mount_without_rule: []const u8,

    pub fn path(self: LayerGap) []const u8 {
        return switch (self) {
            .rule_outside_mounts, .mount_without_rule => |value| value,
        };
    }

    pub fn format(self: LayerGap, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        return switch (self) {
            .rule_outside_mounts => |value| writer.print(
                "landlock rule {s} names a path the mount set does not hold",
                .{value},
            ),
            .mount_without_rule => |value| writer.print(
                "mount {s} has no landlock rule, so it is present and unreachable",
                .{value},
            ),
        };
    }
};

/// The root is a real gap this cannot see: `namespace.buildRoot` binds
/// `config.root` over itself read write, so only Landlock refuses `/`.
pub fn firstGap(config: Config) ?LayerGap {
    for (config.rules) |rule| {
        if (!mountSetHolds(config, rule.path)) return .{ .rule_outside_mounts = rule.path };
    }
    for (config.mounts) |mount| {
        const target = mountTarget(mount) orelse continue;
        if (!ruleSetHolds(config, target)) return .{ .mount_without_rule = target };
    }
    for (config.scratch) |area| {
        if (!ruleSetHolds(config, area.target)) return .{ .mount_without_rule = area.target };
    }
    return null;
}

fn mountTarget(mount: namespace.Mount) ?[]const u8 {
    return switch (mount) {
        .bind => |bind| bind.target,
        .overlay => |overlay| overlay.target,
        .proc => |proc| proc.target,
        .deny => null,
    };
}

fn mountSetHolds(config: Config, target_path: []const u8) bool {
    for (config.mounts) |mount| {
        const target = mountTarget(mount) orelse continue;
        if (grants.holds(target, target_path)) return true;
    }
    for (config.scratch) |area| {
        if (grants.holds(area.target, target_path)) return true;
    }
    return false;
}

fn ruleSetHolds(config: Config, target_path: []const u8) bool {
    for (config.rules) |rule| {
        if (grants.holds(rule.path, target_path)) return true;
    }
    return false;
}

/// A `Mount.deny` target is not in the set, so a denial below a granted tree
/// still reads as granted.
pub fn grantPrefixes(
    allocator: std.mem.Allocator,
    config: Config,
) std.mem.Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(allocator);
    try out.ensureTotalCapacityPrecise(allocator, config.mounts.len + config.scratch.len);
    for (config.mounts) |mount| {
        const target = mountTarget(mount) orelse continue;
        out.appendAssumeCapacity(target);
    }
    for (config.scratch) |area| out.appendAssumeCapacity(area.target);
    return out.toOwnedSlice(allocator);
}

pub fn copyStrings(
    allocator: std.mem.Allocator,
    from: []const []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    const to = try allocator.alloc([]const u8, from.len);
    for (from, to) |one, *slot| slot.* = try allocator.dupe(u8, one);
    return to;
}

/// A granted descriptor outlives the check, and a connected TCP socket can be
/// re-aimed with `connect`, so the Linux driver refuses `connect` for a filtered
/// process.
pub const NetBroker = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Grant = union(enum) {
        /// The implementation gives up ownership. The driver closes it either way.
        granted: std.posix.fd_t,
        /// No reason crosses the boundary: a reason tells a process which hosts exist.
        refused,
    };

    pub const VTable = struct {
        /// `host` borrows the driver's own buffer and is not valid after this returns.
        connect: *const fn (ptr: *anyopaque, host: []const u8, port: u16) Grant,
    };

    pub fn connect(self: NetBroker, host: []const u8, port: u16) Grant {
        return self.vtable.connect(self.ptr, host, port);
    }
};

/// On `open` the address is the identity and the name is not: two hosts on one
/// content network share a name, so the implementation maps the address back to
/// the name it handed out.
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
        /// The source owns this descriptor and the driver never closes it.
        wakeup: *const fn (ptr: *anyopaque) i32,
        next: *const fn (ptr: *anyopaque) ?Change,
    };

    pub const Change = union(enum) {
        /// No descriptor rides with this: a descriptor cannot become a mount inside the
        /// helper's own mount namespace, so a path crosses and is checked on the far side.
        place: struct { kind: u8, source: []const u8, target: []const u8 },
        drop: struct { target: []const u8 },
    };
};

/// A fall back from `supplied` to a post fork write must not happen: a process
/// that runs even briefly outside its cgroup can fork faster than the write that
/// would contain it.
pub const Containment = union(enum) {
    best_effort,
    supplied: Supplied,

    pub const Supplied = struct {
        /// A descriptor and not a path: the kernel resolves no name for
        /// `CLONE_INTO_CGROUP`, so a directory renamed between the caller's check and
        /// the clone cannot make the child land elsewhere.
        fd: std.posix.fd_t,
    };
};

pub const Limits = rlimits.Limits;

/// `memory.max` kills with a bare `SIGKILL`, the same thing a caller sees when a
/// person cancels a call, so the outcome has to be named.
pub const LimitsReport = struct {
    limits: Limits = .{},
    cgroup: cgroup.Support = .off,
    /// Whether `RLIMIT_NPROC` went on. False on a kernel older than 5.14, where it
    /// counts the user's own processes on the host and not the sandbox's.
    nproc_applied: bool = false,
    events: cgroup.Events = .{},
    /// Read from the filesystem itself: nothing in the kernel counts a full tmpfs.
    scratch_full: bool = false,
    /// `scratch_space` is inferred and not counted: the kernel answers `ENOSPC` and
    /// keeps no record, so a full area plus a bad end reads as the area ending it.
    killed_by: ?rlimits.Diagnostic.Which = null,

    pub fn killedText(self: LimitsReport, buffer: []u8) ?[]const u8 {
        const which = self.killed_by orelse return null;

        // A program that fills a scratch area prints "No space left on device", so the
        // sentence has to say the machine's own disk is not the thing that filled.
        if (which == .scratch_space) {
            if (self.limits.scratch_bytes) |number| {
                return std.fmt.bufPrint(
                    buffer,
                    "the program filled the sandbox's own scratch area, which chock caps at {d} bytes. The machine's own disk is not full",
                    .{number},
                ) catch null;
            }
            return std.fmt.bufPrint(
                buffer,
                "the program filled the sandbox's own scratch area. The machine's own disk is not full",
                .{},
            ) catch null;
        }

        const value: ?u64 = switch (which) {
            .memory => self.limits.memory_bytes,
            .mapped_memory => self.limits.mapped_memory_bytes,
            .cpu_time => self.limits.cpu_seconds,
            .file_size => self.limits.file_size_bytes,
            .processes => self.limits.processes,
            .open_files => self.limits.open_files,
            .core_dump, .scratch_space => null,
        };
        const unit: []const u8 = switch (which) {
            .memory, .mapped_memory, .file_size => " bytes",
            .cpu_time => " seconds",
            else => "",
        };
        if (value) |number| {
            return std.fmt.bufPrint(
                buffer,
                "the program was stopped by the limit on {s}, which is {d}{s}",
                .{ which.text(), number, unit },
            ) catch null;
        }
        return std.fmt.bufPrint(
            buffer,
            "the program was stopped by the limit on {s}",
            .{which.text()},
        ) catch null;
    }
};

pub const LayerProcess = enum {
    sandboxed,
    /// The process that waits, which holds this program's own memory including the credential.
    supervisor,

    pub fn wireName(self: LayerProcess) []const u8 {
        return switch (self) {
            .sandboxed => "sandboxed",
            .supervisor => "supervisor",
        };
    }
};

pub const LayerName = enum {
    mount_tree,
    pivot_root,
    capabilities,
    landlock,
    session_keyring,
    seccomp,

    pub fn wireName(self: LayerName) []const u8 {
        return switch (self) {
            .mount_tree => "mount_tree",
            .pivot_root => "pivot_root",
            .capabilities => "capabilities",
            .landlock => "landlock",
            .session_keyring => "session_keyring",
            .seccomp => "seccomp",
        };
    }
};

pub const FailMode = enum {
    closed,
    open,
};

/// What happens to `process` when `layer` will not go on, or null when that
/// process never puts it on. `linux/driver.zig` reads this table at compile time
/// and `applyLayers` refuses to compile if it says one of its layers may be
/// skipped, so an edit here is an edit to the behaviour.
pub fn failModeFor(process: LayerProcess, layer: LayerName) ?FailMode {
    return switch (process) {
        .sandboxed => .closed,
        .supervisor => switch (layer) {
            .capabilities, .landlock, .seccomp => .open,
            .mount_tree, .pivot_root, .session_keyring => null,
        },
    };
}

/// Whether the supervisor process could confine itself. That install stays best
/// effort, and the terminal line it prints dies with the terminal.
pub const SupervisorAudit = struct {
    pub const process_name = LayerProcess.supervisor.wireName();

    layers: std.EnumArray(LayerName, Counters) = .initFill(.{}),

    pub const Counters = struct {
        confined: std.atomic.Value(u64) = .init(0),
        unconfined: std.atomic.Value(u64) = .init(0),
        /// A cancelled call kills the supervisor before it confines itself, so there is
        /// no answer to record and a count of zero would be a claim.
        unreported: std.atomic.Value(u64) = .init(0),
        first_fault: std.atomic.Value(u8) = .init(0),
    };

    pub const Fault = enum(u8) {
        /// The sandboxed process puts the same layer on from the same inputs and that
        /// install is fatal, so this arriving means the kernel answered two processes differently.
        not_supported = 1,
        no_new_privs_refused = 2,
        not_permitted = 3,
        rejected = 4,
        unexpected = 5,
    };

    pub const Outcome = union(enum) {
        on,
        off: Fault,
        unsaid,
    };

    pub fn record(self: *SupervisorAudit, layer: LayerName, outcome: Outcome) void {
        const slot = self.layers.getPtr(layer);
        switch (outcome) {
            .on => _ = slot.confined.fetchAdd(1, .monotonic),
            .unsaid => _ = slot.unreported.fetchAdd(1, .monotonic),
            .off => |fault| {
                _ = slot.unconfined.fetchAdd(1, .monotonic);
                _ = slot.first_fault.cmpxchgStrong(0, @intFromEnum(fault), .monotonic, .monotonic);
            },
        }
    }

    pub fn counts(self: *const SupervisorAudit, layer: LayerName) Counts {
        const slot = self.layers.getPtrConst(layer);
        const raw = slot.first_fault.load(.monotonic);
        return .{
            .confined = slot.confined.load(.monotonic),
            .unconfined = slot.unconfined.load(.monotonic),
            .unreported = slot.unreported.load(.monotonic),
            .first_fault = std.enums.fromInt(Fault, raw),
        };
    }

    pub const Counts = struct {
        confined: u64,
        unconfined: u64,
        unreported: u64,
        first_fault: ?Fault,
    };
};

/// What the sandboxed program asked the kernel for, at the one level a program
/// cannot talk its way around. `observed` and `unobserved` are what make a
/// histogram of zeros readable.
pub const SyscallAudit = struct {
    pub const mechanism_name = "seccomp_user_notif";

    observed: std.atomic.Value(u64) = .init(0),
    unobserved: std.atomic.Value(u64) = .init(0),
    calls: [notify.call_count]std.atomic.Value(u64) = @splat(.init(0)),

    paths: PathTotals = .{},

    pub const PathTotals = struct {
        lock: Lock = .{},
        /// The ordinary pid namespace teardown and a program that kills its own reader
        /// are identical at the reap, so this counts both.
        readers_unreported: u64 = 0,
        readers_absent: u64 = 0,
        seen: notify.PathRecord = .{},
    };

    pub const Outcome = union(enum) {
        observed: notify.Counts,
        unobserved,
    };

    pub fn record(self: *SyscallAudit, outcome: Outcome) void {
        switch (outcome) {
            .unobserved => _ = self.unobserved.fetchAdd(1, .monotonic),
            .observed => |made| {
                _ = self.observed.fetchAdd(1, .monotonic);
                for (made, &self.calls) |count, *total| {
                    _ = total.fetchAdd(count, .monotonic);
                }
            },
        }
    }

    /// Plain atomics and a yield: `std.Io.Mutex.lock` needs an `Io` and `spawn` has
    /// none to give. Never held across a system call.
    pub const Lock = struct {
        held: std.atomic.Value(bool) = .init(false),

        fn lock(self: *Lock) void {
            while (self.held.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
                std.Thread.yield() catch std.atomic.spinLoopHint();
            }
        }

        fn unlock(self: *Lock) void {
            self.held.store(false, .release);
        }
    };

    /// Everything read out of `seen` is untrusted input: the reader process wrote it.
    pub fn recordPaths(self: *SyscallAudit, seen: *const notify.PathRecord) void {
        self.paths.lock.lock();
        defer self.paths.lock.unlock();

        if (seen.reader_unreported != 0) self.paths.readers_unreported +|= 1;
        if (seen.ready == 0) self.paths.readers_absent +|= 1;

        const into = &self.paths.seen;
        for (0..notify.call_count) |slot| {
            into.granted[slot] +|= seen.granted[slot];
            into.ungranted[slot] +|= seen.ungranted[slot];
            into.ungranted_unnamed[slot] +|= seen.ungranted_unnamed[slot];
            into.relative[slot] +|= seen.relative[slot];
            into.unread[slot] +|= seen.unread[slot];
            into.truncated[slot] +|= seen.truncated[slot];
        }

        var slot: u32 = 0;
        while (slot < @min(seen.kept, notify.kept_path_cap)) : (slot += 1) {
            notify.keepName(into, seen.name_call[slot], seen.name(slot), seen.name_hits[slot]);
        }
    }

    pub fn counts(self: *const SyscallAudit) Counts {
        var out: Counts = .{
            .observed = self.observed.load(.monotonic),
            .unobserved = self.unobserved.load(.monotonic),
            .calls = notify.empty_counts,
        };
        for (&self.calls, &out.calls) |*total, *slot| slot.* = total.load(.monotonic);
        return out;
    }

    pub const Counts = struct {
        observed: u64,
        unobserved: u64,
        calls: notify.Counts,
    };

    pub const name_cap = notify.kept_path_cap;

    /// The names point into this audit's own storage, and a call in flight can add one.
    pub fn pathCounts(self: *SyscallAudit) PathCounts {
        self.paths.lock.lock();
        defer self.paths.lock.unlock();

        const seen = &self.paths.seen;
        var out: PathCounts = .{
            .readers_unreported = self.paths.readers_unreported,
            .readers_absent = self.paths.readers_absent,
            .granted = seen.granted,
            .ungranted = seen.ungranted,
            .ungranted_unnamed = seen.ungranted_unnamed,
            .relative = seen.relative,
            .unread = seen.unread,
            .truncated = seen.truncated,
            .kept = @min(seen.kept, name_cap),
            .name_call = seen.name_call,
            .names = @splat(&.{}),
        };
        for (&out.names, 0..) |*slot, index| slot.* = seen.name(index);
        return out;
    }

    pub const PathCounts = struct {
        readers_unreported: u64,
        readers_absent: u64,
        granted: notify.Counts,
        ungranted: notify.Counts,
        ungranted_unnamed: notify.Counts,
        relative: notify.Counts,
        unread: notify.Counts,
        truncated: notify.Counts,
        kept: u32,
        name_call: [name_cap]u32,
        names: [name_cap][]const u8,

        pub fn empty(self: PathCounts) bool {
            if (self.kept != 0) return false;
            if (self.readers_unreported != 0 or self.readers_absent != 0) return false;
            for (0..notify.call_count) |slot| {
                if (self.granted[slot] != 0 or self.ungranted[slot] != 0) return false;
                if (self.ungranted_unnamed[slot] != 0 or self.relative[slot] != 0) return false;
                if (self.unread[slot] != 0 or self.truncated[slot] != 0) return false;
            }
            return true;
        }
    };
};

/// The guarantees a driver can give. Nothing compares against this set yet.
pub const Guarantee = enum {
    network_isolated,
    /// A PID namespace alone does not give this: `kill(0, sig)` names the caller's
    /// own process group, which the kernel holds as an object and not as a number,
    /// and from a fresh namespace it still reached a process outside.
    signal_isolated,
    ipc_isolated,
    path_restricted,
    syscall_restricted,
    /// Darwin has none of this, and the gap is permanent: macOS has no bind mount.
    workspace_mounted,
};

pub const Guarantees = std.EnumSet(Guarantee);

pub const SetupError = error{
    StdinRedirectFailed,
    NetRouterUnavailable,
    DeviceHelperFailed,
    ProcessGroupFailed,
    CgroupJoinFailed,
    ResourceLimitFailed,
    CloseFdsFailed,
    NamespaceFailed,
    ScratchMountFailed,
    MountTreeFailed,
    PivotFailed,
    CapabilitiesFailed,
    LandlockInitFailed,
    LandlockRuleFailed,
    LandlockRestrictFailed,
    SessionKeyringFailed,
    SeccompInstallFailed,
    NotifyHandoverFailed,
    ForkFailed,
    PdeathsigSetupFailed,
    ExecFailed,
};

pub const SpawnError = error{
    LandlockUnavailable,
    UntrustedSetupReport,
    Unexpected,
    NoMountNamespace,
    NetBrokerMissing,
    NetBrokerNotFiltered,
    NetBrokerSocketFailed,
    NetRouterNotFiltered,
    NetRouterAndBroker,
    DeviceSourceSocketFailed,
    DeviceSourceNeedsTree,
    /// Refused and never degraded: writing `cgroup.procs` after the fork leaves a
    /// window in which the child is outside the cgroup the caller asked for.
    CgroupPlacementUnsupported,
    CgroupPlacementRefused,
} || SetupError || std.mem.Allocator.Error;

/// The Landlock ruleset masks a right out of every rule when the running
/// kernel's ABI has not got it, with no error and no other signal.
pub const LandlockReport = struct {
    abi: i32,
    features: landlock.Features,
};

/// `spawn` reaps the process it forked before it returns, so a `kill` by number
/// after that reaches whatever started next: one teardown path sent `SIGKILL` to
/// a process group holding an unrelated build. Signal through `fd`, never `pid`.
pub const Middle = struct {
    /// For reporting and never for signalling.
    pid: std.posix.pid_t = 0,
    fd: std.posix.fd_t = -1,
};

pub const SignalError = error{
    Gone,
    NoHandle,
    Unexpected,
};

const driver = switch (builtin.os.tag) {
    .linux => @import("linux/driver.zig"),
    .macos => @import("darwin/driver.zig"),
    else => @compileError("chock-sandbox: no driver for target os " ++ @tagName(builtin.os.tag)),
};

pub const guarantees: Guarantees = driver.guarantees;

pub const network_modules: []const u8 = switch (builtin.os.tag) {
    .linux => driver.network_modules,
    else => "",
};
pub const filter_modules: []const u8 = switch (builtin.os.tag) {
    .linux => driver.filter_modules,
    else => "",
};

/// `namespace.substitute` refuses a `text` target that is a symbolic link rather
/// than following it, which is what `chock doctor` reads this list to check.
pub const resolver_substitutions: []const namespace.Substitution = switch (builtin.os.tag) {
    .linux => &driver.resolver_substitutions,
    else => &.{},
};

pub fn spawn(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    landlock_report: ?*LandlockReport,
    middle: ?*Middle,
) SpawnError!std.process.Child.Term {
    return driver.spawn(allocator, config, argv, landlock_report, middle);
}

/// Safe to call from a signal handler: one syscall over a descriptor already held.
pub fn signalMiddle(fd: std.posix.fd_t, sig: std.posix.SIG) SignalError!void {
    return driver.signalMiddle(fd, sig);
}

/// Call it only after the `spawn` that filled the handle in has returned.
pub fn closeMiddle(middle: *Middle) void {
    driver.closeMiddle(middle);
}

pub const joinFreshSessionKeyring = driver.joinFreshSessionKeyring;

test "the audit counts each of the three answers apart, and keeps the first fault" {
    var audit: SupervisorAudit = .{};
    try std.testing.expectEqual(@as(?SupervisorAudit.Fault, null), audit.counts(.seccomp).first_fault);

    audit.record(.seccomp, .on);
    audit.record(.seccomp, .on);
    audit.record(.seccomp, .unsaid);
    audit.record(.seccomp, .{ .off = .not_supported });
    audit.record(.seccomp, .{ .off = .rejected });

    const counts = audit.counts(.seccomp);
    try std.testing.expectEqual(@as(u64, 2), counts.confined);
    try std.testing.expectEqual(@as(u64, 2), counts.unconfined);
    try std.testing.expectEqual(@as(u64, 1), counts.unreported);
    try std.testing.expectEqual(
        @as(?SupervisorAudit.Fault, .not_supported),
        counts.first_fault,
    );

    const paths = audit.counts(.landlock);
    try std.testing.expectEqual(@as(u64, 0), paths.confined);
    try std.testing.expectEqual(@as(u64, 0), paths.unconfined);
    try std.testing.expectEqual(@as(u64, 0), paths.unreported);
    try std.testing.expectEqual(@as(?SupervisorAudit.Fault, null), paths.first_fault);

    audit.record(.landlock, .{ .off = .rejected });
    try std.testing.expectEqual(@as(u64, 1), audit.counts(.landlock).unconfined);
    try std.testing.expectEqual(@as(u64, 2), audit.counts(.seccomp).unconfined);
}

test "a fresh audit claims nothing, so an absent answer is never a confined one" {
    const audit: SupervisorAudit = .{};
    for (std.enums.values(LayerName)) |layer| {
        const counts = audit.counts(layer);
        try std.testing.expectEqual(@as(u64, 0), counts.confined);
        try std.testing.expectEqual(@as(u64, 0), counts.unconfined);
        try std.testing.expectEqual(@as(u64, 0), counts.unreported);
        try std.testing.expectEqual(@as(?SupervisorAudit.Fault, null), counts.first_fault);
    }
}

test "the grant set is every mount target and every scratch area, and no denial" {
    const config = Config{
        .root = "/tmp/root",
        .mounts = &.{
            .{ .bind = .{ .source = "/host/work", .target = "/work" } },
            .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } },
            .{ .proc = .{ .target = "/proc" } },
            .{ .deny = .{ .target = "/work/.ssh" } },
        },
        .rules = &.{},
        .scratch = &.{.{ .target = "/run/chock/scratch" }},
        .cwd = "/work",
        .env = &.{},
    };

    const set = try grantPrefixes(std.testing.allocator, config);
    defer std.testing.allocator.free(set);

    try std.testing.expectEqual(@as(usize, 4), set.len);
    try std.testing.expectEqualStrings("/work", set[0]);
    try std.testing.expectEqualStrings("/nix/store", set[1]);
    try std.testing.expectEqualStrings("/proc", set[2]);
    try std.testing.expectEqualStrings("/run/chock/scratch", set[3]);

    try std.testing.expect(grants.setHolds(set, "/nix/store/abc-glibc/lib/libc.so.6"));
    try std.testing.expect(!grants.setHolds(set, "/etc/shadow"));
}

test "a copied config shares no memory with the original, scratch areas included" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const original = Config{
        .root = "/tmp/root",
        .mounts = &.{.{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } }},
        .rules = &.{.{ .path = "/work", .access = .{ .read_file = true } }},
        .scratch = &.{ .{ .target = "/run/chock/scratch" }, .{ .target = "/run/chock/tasks" } },
        .cwd = "/",
        .env = &.{"PATH=/bin"},
        .path_audit = true,
        .device_tree = .{ .host = "/tmp/chock-devices", .inside = "/.chock-device-tree" },
    };

    const copied = try original.copy(arena);

    try std.testing.expectEqual(original.scratch.len, copied.scratch.len);
    for (original.scratch, copied.scratch) |from, to| {
        try std.testing.expectEqualStrings(from.target, to.target);
        try std.testing.expect(from.target.ptr != to.target.ptr);
    }
    try std.testing.expect(original.scratch.ptr != copied.scratch.ptr);

    try std.testing.expectEqual(true, copied.path_audit);

    try std.testing.expect(original.root.ptr != copied.root.ptr);
    try std.testing.expect(original.cwd.ptr != copied.cwd.ptr);
    try std.testing.expect(original.env.ptr != copied.env.ptr);
    try std.testing.expect(original.mounts.ptr != copied.mounts.ptr);
    try std.testing.expect(original.rules.ptr != copied.rules.ptr);

    const original_tree = original.device_tree orelse return error.TestUnexpectedResult;
    const copied_tree = copied.device_tree orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(original_tree.host, copied_tree.host);
    try std.testing.expect(original_tree.host.ptr != copied_tree.host.ptr);
    try std.testing.expectEqualStrings(original_tree.inside, copied_tree.inside);
    try std.testing.expect(original_tree.inside.ptr != copied_tree.inside.ptr);

    try std.testing.expectEqual(original.limits, copied.limits);
    try std.testing.expectEqual(original.containment, copied.containment);
    const supplied = try (Config{
        .root = "/tmp/root",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .containment = .{ .supplied = .{ .fd = 11 } },
    }).copy(arena);
    try std.testing.expectEqual(@as(std.posix.fd_t, 11), switch (supplied.containment) {
        .supplied => |one| one.fd,
        .best_effort => @as(std.posix.fd_t, -1),
    });

    try std.testing.expectEqual(original.net_broker, copied.net_broker);

    var stub: StubRouter = .{};
    const routed = try (Config{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .network = .filtered,
        .net_router = stub.netRouter(),
    }).copy(arena);
    try std.testing.expectEqual(
        @as(?*anyopaque, &stub),
        if (routed.net_router) |one| one.ptr else null,
    );

    var device_stub: StubDevice = .{};
    const with_device = try (Config{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .device_source = device_stub.deviceSource(),
    }).copy(arena);
    try std.testing.expectEqual(
        @as(?*anyopaque, &device_stub),
        if (with_device.device_source) |one| one.ptr else null,
    );
}

const StubDevice = struct {
    fn deviceSource(self: *StubDevice) DeviceSource {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = DeviceSource.VTable{ .wakeup = wakeupFn, .next = nextFn };

    fn wakeupFn(_: *anyopaque) i32 {
        return -1;
    }

    fn nextFn(_: *anyopaque) ?DeviceSource.Change {
        return null;
    }
};

const StubRouter = struct {
    fn netRouter(self: *StubRouter) NetRouter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = NetRouter.VTable{ .resolve = resolveFn, .open = openFn };

    fn resolveFn(_: *anyopaque, _: []const u8, _: NetRouter.Family) NetRouter.Resolution {
        return .refused;
    }

    fn openFn(_: *anyopaque, _: NetRouter.Address, _: u16) NetBroker.Grant {
        return .refused;
    }
};

test "the linux driver and the darwin driver expose the same public shape" {
    if (builtin.os.tag != .linux) return;

    const linux_driver = @import("linux/driver.zig");
    const darwin_driver = @import("darwin/driver.zig");

    // Add a name here whenever the dispatch above reads a new driver declaration.
    const shape = .{ "spawn", "guarantees", "joinFreshSessionKeyring", "signalMiddle", "closeMiddle" };
    inline for (shape) |name| {
        if (!@hasDecl(linux_driver, name)) @compileError("linux driver is missing " ++ name);
        if (!@hasDecl(darwin_driver, name)) @compileError("darwin driver is missing " ++ name);
    }
}

test "a path a rule will name is resolved where a mount cannot be" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try tmp.dir.realPath(std.testing.io, &real_buffer);
    const real = real_buffer[0..real_length];

    const through_link = try std.fmt.allocPrint(std.testing.allocator, "{s}/link", .{real});
    defer std.testing.allocator.free(through_link);
    try tmp.dir.symLink(std.testing.io, real, "link", .{ .is_directory = true });

    var answer_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const answered = resolvedPath(std.testing.io, through_link, &answer_buffer);

    if (expresses.moved_paths) {
        try std.testing.expectEqualStrings(through_link, answered);
    } else {
        try std.testing.expectEqualStrings(real, answered);
    }

    var missing_buffer: [std.fs.max_path_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/no/such/directory/here",
        resolvedPath(std.testing.io, "/no/such/directory/here", &missing_buffer),
    );
}

test "a rule below a mount agrees, and a rule beside one does not" {
    const agreeing = Config{
        .root = "/root",
        .mounts = &.{.{ .bind = .{ .source = "/host/work", .target = "/work" } }},
        .rules = &.{
            .{ .path = "/work", .access = landlock.AccessFs.read_write },
            .{ .path = "/work/build.zig", .access = landlock.AccessFs.read_only_file },
        },
        .cwd = "/work",
        .env = &.{},
    };
    try std.testing.expectEqual(@as(?LayerGap, null), firstGap(agreeing));

    const extra_rule = Config{
        .root = "/root",
        .mounts = &.{.{ .bind = .{ .source = "/host/work", .target = "/work" } }},
        .rules = &.{
            .{ .path = "/work", .access = landlock.AccessFs.read_write },
            .{ .path = "/etc", .access = landlock.AccessFs.read_only },
        },
        .cwd = "/work",
        .env = &.{},
    };
    const gap = firstGap(extra_rule) orelse return error.TestExpectedGap;
    try std.testing.expectEqual(std.meta.Tag(LayerGap).rule_outside_mounts, std.meta.activeTag(gap));
    try std.testing.expectEqualStrings("/etc", gap.path());
}

test "a rule above every mount is a gap, because landlock rights reach downwards" {
    const too_wide = Config{
        .root = "/root",
        .mounts = &.{.{ .bind = .{ .source = "/host/work", .target = "/work" } }},
        .rules = &.{.{ .path = "/", .access = landlock.AccessFs.read_write }},
        .cwd = "/work",
        .env = &.{},
    };
    const gap = firstGap(too_wide) orelse return error.TestExpectedGap;
    try std.testing.expectEqualStrings("/", gap.path());

    const neighbour = Config{
        .root = "/root",
        .mounts = &.{.{ .bind = .{ .source = "/host/work", .target = "/work" } }},
        .rules = &.{.{ .path = "/workshop", .access = landlock.AccessFs.read_write }},
        .cwd = "/work",
        .env = &.{},
    };
    const neighbour_gap = firstGap(neighbour) orelse return error.TestExpectedGap;
    try std.testing.expectEqualStrings("/workshop", neighbour_gap.path());
}

test "a mount with no rule is a gap, and a denied path is not" {
    const unreachable_mount = Config{
        .root = "/root",
        .mounts = &.{
            .{ .bind = .{ .source = "/host/work", .target = "/work" } },
            .{ .bind = .{ .source = "/host/tool", .target = "/run/chock/bin", .read_only = true } },
        },
        .rules = &.{.{ .path = "/work", .access = landlock.AccessFs.read_write }},
        .cwd = "/work",
        .env = &.{},
    };
    const gap = firstGap(unreachable_mount) orelse return error.TestExpectedGap;
    try std.testing.expectEqual(std.meta.Tag(LayerGap).mount_without_rule, std.meta.activeTag(gap));
    try std.testing.expectEqualStrings("/run/chock/bin", gap.path());

    const denied = Config{
        .root = "/root",
        .mounts = &.{
            .{ .bind = .{ .source = "/host/work", .target = "/work" } },
            .{ .deny = .{ .target = "/work/.env" } },
        },
        .rules = &.{.{ .path = "/work", .access = landlock.AccessFs.read_write }},
        .cwd = "/work",
        .env = &.{},
    };
    try std.testing.expectEqual(@as(?LayerGap, null), firstGap(denied));
}

test "a capped scratch area is a mount the sandbox makes, and it needs a rule of its own" {
    const with_rule = Config{
        .root = "/root",
        .mounts = &.{.{ .bind = .{ .source = "/host/work", .target = "/work" } }},
        .rules = &.{
            .{ .path = "/work", .access = landlock.AccessFs.read_write },
            .{ .path = "/run/chock/tmp", .access = landlock.AccessFs.read_write },
        },
        .scratch = &.{.{ .target = "/run/chock/tmp" }},
        .cwd = "/work",
        .env = &.{},
    };
    try std.testing.expectEqual(@as(?LayerGap, null), firstGap(with_rule));

    const without_rule = Config{
        .root = "/root",
        .mounts = &.{.{ .bind = .{ .source = "/host/work", .target = "/work" } }},
        .rules = &.{.{ .path = "/work", .access = landlock.AccessFs.read_write }},
        .scratch = &.{.{ .target = "/run/chock/tmp" }},
        .cwd = "/work",
        .env = &.{},
    };
    const gap = firstGap(without_rule) orelse return error.TestExpectedGap;
    try std.testing.expectEqualStrings("/run/chock/tmp", gap.path());
}

test "a gap names the path and says which of the two lists is short" {
    var buffer: [160]u8 = undefined;
    try std.testing.expectEqualStrings(
        "landlock rule /etc names a path the mount set does not hold",
        try std.fmt.bufPrint(&buffer, "{f}", .{LayerGap{ .rule_outside_mounts = "/etc" }}),
    );
    try std.testing.expectEqualStrings(
        "mount /proc has no landlock rule, so it is present and unreachable",
        try std.fmt.bufPrint(&buffer, "{f}", .{LayerGap{ .mount_without_rule = "/proc" }}),
    );
}

test "one tool call's paths are added to the session's own, and a name with no room keeps its count" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const openat = @intFromEnum(seccomp.TrapCall.openat);

    var audit: SyscallAudit = .{};

    var first: notify.PathRecord = .{ .ready = 1 };
    var made: u32 = 0;
    while (made < notify.kept_path_cap) : (made += 1) {
        var buffer: [32]u8 = undefined;
        const path = try std.fmt.bufPrint(&buffer, "/etc/thing-{d}", .{made});
        first.ungranted[openat] += 1;
        notify.keepName(&first, openat, path, 1);
    }
    audit.recordPaths(&first);

    var second: notify.PathRecord = .{ .ready = 1 };
    second.ungranted[openat] = 500;
    second.relative[openat] = 7;
    second.granted[openat] = 11;
    notify.keepName(&second, openat, "/home/someone/.ssh/id_ed25519", 500);
    audit.recordPaths(&second);

    const counted = audit.pathCounts();
    try std.testing.expectEqual(@as(u32, notify.kept_path_cap), counted.kept);
    try std.testing.expectEqual(
        @as(u64, notify.kept_path_cap + 500),
        counted.ungranted[openat],
    );
    try std.testing.expectEqual(@as(u64, 500), counted.ungranted_unnamed[openat]);
    try std.testing.expectEqual(@as(u64, 7), counted.relative[openat]);
    try std.testing.expectEqual(@as(u64, 11), counted.granted[openat]);
    try std.testing.expectEqual(@as(u64, 0), counted.readers_unreported);
    try std.testing.expectEqual(@as(u64, 0), counted.readers_absent);
}

test "a reader that never started, and one that never reported, are counted apart" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var audit: SyscallAudit = .{};

    var never_started: notify.PathRecord = .{ .ready = 0 };
    audit.recordPaths(&never_started);
    var no_report: notify.PathRecord = .{ .ready = 1, .reader_unreported = 1 };
    audit.recordPaths(&no_report);
    var whole_way: notify.PathRecord = .{ .ready = 1, .ended = 1 };
    audit.recordPaths(&whole_way);

    const counted = audit.pathCounts();
    try std.testing.expectEqual(@as(u64, 1), counted.readers_absent);
    try std.testing.expectEqual(@as(u64, 1), counted.readers_unreported);
}

test "the shape hash changes when the sandbox lets through anything different" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const mounts = [_]namespace.Mount{
        .{ .bind = .{ .source = "/nix/store/a", .target = "/nix/store/a", .read_only = true } },
        .{ .proc = .{} },
    };
    const base = Config{
        .root = "/state/root",
        .mounts = &mounts,
        .rules = &.{},
        .cwd = "/project",
        .env = &.{},
    };
    const first = base.shapeHash();

    // The same configuration hashes the same, or one run of one session could
    // never be compared with the next.
    try std.testing.expectEqualSlices(u8, &first, &base.shapeHash());

    // A bind that became writable is the alteration this has to catch.
    const widened = [_]namespace.Mount{
        .{ .bind = .{ .source = "/nix/store/a", .target = "/nix/store/a", .read_only = false } },
        .{ .proc = .{} },
    };
    var changed = base;
    changed.mounts = &widened;
    try std.testing.expect(!std.mem.eql(u8, &first, &changed.shapeHash()));

    // One more mount, a wider limit, and a network where there was none.
    const added = [_]namespace.Mount{
        .{ .bind = .{ .source = "/nix/store/a", .target = "/nix/store/a", .read_only = true } },
        .{ .proc = .{} },
        .{ .bind = .{ .source = "/home/me/.ssh", .target = "/home/me/.ssh", .read_only = true } },
    };
    var more = base;
    more.mounts = &added;
    try std.testing.expect(!std.mem.eql(u8, &first, &more.shapeHash()));

    var looser = base;
    looser.limits = .{ .memory_bytes = (base.limits.memory_bytes orelse 0) * 2 };
    try std.testing.expect(!std.mem.eql(u8, &first, &looser.shapeHash()));

    var networked = base;
    networked.network = .filtered;
    try std.testing.expect(!std.mem.eql(u8, &first, &networked.shapeHash()));

    // A rule with more access, at the same path.
    const narrow = [_]Config.Rule{.{ .path = "/project", .access = .{ .read_file = true } }};
    const wide = [_]Config.Rule{.{ .path = "/project", .access = .{ .read_file = true, .write_file = true } }};
    var reading = base;
    reading.rules = &narrow;
    var writing = base;
    writing.rules = &wide;
    try std.testing.expect(!std.mem.eql(u8, &reading.shapeHash(), &writing.shapeHash()));
}

test "two paths that run together are told apart by the length before each" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const left = [_]namespace.Mount{
        .{ .bind = .{ .source = "/ab", .target = "/c" } },
    };
    const right = [_]namespace.Mount{
        .{ .bind = .{ .source = "/a", .target = "/bc" } },
    };
    var one = Config{ .root = "/r", .mounts = &left, .rules = &.{}, .cwd = "/", .env = &.{} };
    var two = one;
    two.mounts = &right;
    try std.testing.expect(!std.mem.eql(u8, &one.shapeHash(), &two.shapeHash()));
}
