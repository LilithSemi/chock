//! What crosses between the host and a guest: one sandbox request, one answer.
//!
//! A guest has a kernel of its own, so the driver that already exists runs in
//! there unchanged. What the host cannot do is hand it a `Sandbox.Config`: that
//! type holds descriptors and seams, which are host things and do not travel. So
//! a `Request` is the part of a `Config` that is geometry, and the guest builds a
//! `Config` back out of it.
//!
//! ## What does not cross, and why none of it is a gap
//!
//! `Config`'s other fields are all one of three kinds.
//!
//! * **A seam.** `net_broker`, `net_router` and `device_source` are function
//!   tables in the host's own address space. A guest reaches the network by
//!   naming a host, which crosses as Mirage's own `reaching` message and is
//!   decided on the host by the same policy path as before: see
//!   `lib/chock-broker/network.zig`. **A guest must not grow a second copy of
//!   `addressIsReachable`.**
//! * **A descriptor.** `stdout_fd`, `stderr_fd`, `stdin_fd` and
//!   `Containment.supplied.fd` name open files of the host. The streams are
//!   carried by the channel the request arrived on; a supplied cgroup is
//!   refused, because a guest places a call in a cgroup of its own.
//! * **A report.** `landlock_report`, `limits_report`, `supervisor_audit` and
//!   `syscall_audit` are pointers the host reads after the call. Their contents
//!   come back in the `Answer` instead.
//!
//! `everyConfigFieldIsAccountedFor` below is what keeps that list honest: a
//! field added to `Config` and forgotten here fails a test rather than silently
//! not crossing.
//!
//! ## Framing
//!
//! One JSON object a line, and the message and its newline go out in one write.
//! The same rule `lib/chock-acp/jsonrpc.zig` states, for the same reason: a
//! reader that saw half a line would act on half a request.

const std = @import("std");

const iface = @import("../Sandbox.zig");
const landlock = @import("../linux/landlock.zig");
const namespace = @import("../linux/namespace.zig");
const rlimits = @import("../linux/rlimits.zig");
const seccomp = @import("../linux/seccomp.zig");

/// The most one message may be. A request carries every mount and every rule of
/// one tool call, and a rule is a path; past this the sender refuses rather than
/// writing a line the reader will not take.
pub const max_message_bytes: usize = 1 << 20;

/// One bind, as it crosses. The same three fields `namespace.Mount.Bind` has.
pub const Bind = struct {
    source: []const u8,
    target: []const u8,
    read_only: bool = false,
};

pub const Overlay = struct {
    lower: []const u8,
    upper: []const u8,
    work: []const u8,
    target: []const u8,
};

/// A mount, tagged by name rather than by position, so a guest of another build
/// reads a kind it knows and refuses one it does not.
pub const Mount = union(enum) {
    bind: Bind,
    overlay: Overlay,
    proc: Proc,
    deny: Deny,

    pub const Proc = struct {
        target: []const u8,
    };

    pub const Deny = struct {
        target: []const u8,
    };
};

pub const Rule = struct {
    path: []const u8,
    /// The access bits as the number Landlock itself takes, so a bit this build
    /// has no name for still crosses.
    access: u64,
};

pub const Scratch = struct {
    target: []const u8,
};

/// The seccomp options, with the trap set as names.
///
/// **`seccomp.Options` itself does not cross.** Its `traps` is a
/// `std.EnumSet`, whose shape is a bit mask of this build's own member order, and
/// two builds that disagree about that order would agree about the number. Names
/// cannot do that: a name the reader has no member for is refused, which is the
/// same rule `chock migrate` follows for an action it did not invent.
pub const Seccomp = struct {
    strict_wx: bool = true,
    block_connect: bool = false,
    traps: []const []const u8 = &.{},
};

/// One tool call's whole sandbox, as geometry.
pub const Request = struct {
    root: []const u8,
    mounts: []const Mount,
    rules: []const Rule,
    scratch: []const Scratch = &.{},
    cwd: []const u8,
    env: []const []const u8,
    argv: []const []const u8,
    limits: rlimits.Limits = .{},
    seccomp_options: Seccomp = .{},
    network: namespace.Network = .none,
    path_audit: bool = false,
};

/// How a call ended, and what the host would have read out of its report
/// pointers had the call been in this process.
pub const Answer = struct {
    /// Exactly one of these. A guest that could not run the call at all says so
    /// in `refusal` and never reports an exit code it did not see.
    ended: ?Ended = null,
    refusal: ?[]const u8 = null,
    landlock: ?Landlock = null,

    /// The same four shapes `std.process.Child.Term` has. A signal crosses as
    /// its own number, because a guest kernel may name one this build does not.
    pub const Ended = union(enum) {
        exited: u8,
        signalled: u32,
        stopped: u32,
        unknown: u32,
    };

    pub const Landlock = struct {
        applied: bool,
        abi: i64 = 0,
    };
};

/// The part of `Config` this module does not carry, each with the reason it
/// stays on the host. Read the top comment before adding a name here.
const host_only = [_][]const u8{
    "stdout_fd",
    "stderr_fd",
    "stdin_fd",
    "containment",
    "net_broker",
    "net_router",
    "device_source",
    "device_tree",
    "limits_report",
    "supervisor_audit",
    "syscall_audit",
};

/// A `Request` for `config` and `argv`, or null when the config holds something
/// a guest cannot be asked for.
///
/// **A refusal and never a quiet drop.** A supplied cgroup is the one case: the
/// descriptor names a directory of the host's, and a guest that ignored it would
/// run the call with no containment while the caller believed otherwise.
pub fn requestFor(
    allocator: std.mem.Allocator,
    config: iface.Config,
    argv: []const []const u8,
) std.mem.Allocator.Error!?Request {
    if (config.containment == .supplied) return null;
    if (config.device_tree != null) return null;

    const mounts = try allocator.alloc(Mount, config.mounts.len);
    for (config.mounts, mounts) |from, *into| into.* = switch (from) {
        .bind => |one| .{ .bind = .{
            .source = one.source,
            .target = one.target,
            .read_only = one.read_only,
        } },
        .overlay => |one| .{ .overlay = .{
            .lower = one.lower,
            .upper = one.upper,
            .work = one.work,
            .target = one.target,
        } },
        .proc => |one| .{ .proc = .{ .target = one.target } },
        .deny => |one| .{ .deny = .{ .target = one.target } },
    };

    const rules = try allocator.alloc(Rule, config.rules.len);
    for (config.rules, rules) |from, *into| into.* = .{
        .path = from.path,
        .access = @as(u64, @bitCast(from.access)),
    };

    const scratch = try allocator.alloc(Scratch, config.scratch.len);
    for (config.scratch, scratch) |from, *into| into.* = .{ .target = from.target };

    var traps: std.ArrayList([]const u8) = .empty;
    errdefer traps.deinit(allocator);
    var asked = config.seccomp_options.traps.iterator();
    while (asked.next()) |one| try traps.append(allocator, @tagName(one));

    return .{
        .root = config.root,
        .mounts = mounts,
        .rules = rules,
        .scratch = scratch,
        .cwd = config.cwd,
        .env = config.env,
        .argv = argv,
        .limits = config.limits,
        .seccomp_options = .{
            .strict_wx = config.seccomp_options.strict_wx,
            .block_connect = config.seccomp_options.block_connect,
            .traps = try traps.toOwnedSlice(allocator),
        },
        .network = config.network,
        .path_audit = config.path_audit,
    };
}

pub const ConfigError = std.mem.Allocator.Error || error{
    /// The request named a trap this build has no member for. A refusal, because
    /// running the call with a smaller trap set than the host asked for would be
    /// a weaker boundary than the caller believes it has.
    UnknownTrap,
};

/// The `Config` a guest builds back out of a request. Every descriptor field
/// keeps its own default, which is what the guest's own streams are.
pub fn configFor(
    allocator: std.mem.Allocator,
    request: Request,
) ConfigError!iface.Config {
    const mounts = try allocator.alloc(namespace.Mount, request.mounts.len);
    for (request.mounts, mounts) |from, *into| into.* = switch (from) {
        .bind => |one| .{ .bind = .{
            .source = one.source,
            .target = one.target,
            .read_only = one.read_only,
        } },
        .overlay => |one| .{ .overlay = .{
            .lower = one.lower,
            .upper = one.upper,
            .work = one.work,
            .target = one.target,
        } },
        .proc => |one| .{ .proc = .{ .target = one.target } },
        .deny => |one| .{ .deny = .{ .target = one.target } },
    };

    const rules = try allocator.alloc(iface.Config.Rule, request.rules.len);
    for (request.rules, rules) |from, *into| into.* = .{
        .path = from.path,
        .access = @as(landlock.AccessFs, @bitCast(from.access)),
    };

    const scratch = try allocator.alloc(namespace.Scratch, request.scratch.len);
    for (request.scratch, scratch) |from, *into| into.* = .{ .target = from.target };

    var traps: seccomp.TrapSet = .initEmpty();
    for (request.seccomp_options.traps) |name| {
        const one = std.meta.stringToEnum(seccomp.TrapCall, name) orelse return error.UnknownTrap;
        traps.insert(one);
    }

    return .{
        .root = request.root,
        .mounts = mounts,
        .rules = rules,
        .scratch = scratch,
        .cwd = request.cwd,
        .env = request.env,
        .limits = request.limits,
        .seccomp_options = .{
            .strict_wx = request.seccomp_options.strict_wx,
            .block_connect = request.seccomp_options.block_connect,
            .traps = traps,
        },
        .network = request.network,
        .path_audit = request.path_audit,
    };
}

/// Write one message and its newline in one call, so a reader never sees half.
pub fn write(writer: *std.Io.Writer, value: anytype) std.Io.Writer.Error!void {
    try writer.print("{f}\n", .{std.json.fmt(value, .{})});
    try writer.flush();
}

pub const ReadError = error{
    /// The line was longer than `max_message_bytes`, so it was not read.
    TooLong,
    /// The other end is gone.
    Ended,
    /// The line is not this message.
    Unreadable,
};

/// Read one message. The result owns its memory and is freed with `deinit`.
///
/// **`takeDelimiterInclusive` and not the exclusive one.** The exclusive call
/// leaves the newline in the buffer, so the next call finds a delimiter at the
/// front, answers an empty slice and tosses nothing: a loop that reads messages
/// with it never ends. The newline is taken here and trimmed off.
pub fn read(
    comptime T: type,
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
) (ReadError || std.mem.Allocator.Error)!std.json.Parsed(T) {
    const line = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.StreamTooLong => return error.TooLong,
        error.EndOfStream => return error.Ended,
        else => return error.Ended,
    };
    if (line.len > max_message_bytes) return error.TooLong;

    return std.json.parseFromSlice(T, allocator, std.mem.trim(u8, line, " \t\r\n"), .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Unreadable,
    };
}

const testing = std.testing;

test "every field of Config either crosses or is named host only, with a reason" {
    // The guard this file exists to keep. A field added to `Config` and
    // forgotten here would silently not reach a guest, and a tool call would run
    // with less of a boundary than its caller asked for.
    inline for (@typeInfo(iface.Config).@"struct".fields) |field| {
        const crosses = @hasField(Request, field.name);
        var named = false;
        for (host_only) |one| {
            if (std.mem.eql(u8, one, field.name)) named = true;
        }
        if (!crosses and !named) {
            // The failure prints the field, so a reader sees which one.
            try testing.expectEqualStrings("a field that crosses or is host only", field.name);
            return error.ConfigFieldIsNeither;
        }
        // And never both, which would be a field said to stay and to travel.
        try testing.expect(!(crosses and named));
    }

    // Every host only name is a real field, so a rename leaves no dead entry.
    for (host_only) |one| {
        var found = false;
        inline for (@typeInfo(iface.Config).@"struct".fields) |field| {
            if (std.mem.eql(u8, one, field.name)) found = true;
        }
        if (!found) {
            try testing.expectEqualStrings("a field of Config", one);
            return error.HostOnlyNamesNothing;
        }
    }
}

test "a config's geometry survives the round trip, bit for bit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const access: landlock.AccessFs = .{ .read_file = true, .read_dir = true };
    const config = iface.Config{
        .root = "/sandbox",
        .mounts = &.{
            .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } },
            .{ .bind = .{ .source = "/work", .target = "/project" } },
            .{ .overlay = .{
                .lower = "/lower",
                .upper = "/upper",
                .work = "/work-dir",
                .target = "/project",
            } },
            .{ .proc = .{ .target = "/proc" } },
            .{ .deny = .{ .target = "/project/.env" } },
        },
        .rules = &.{.{ .path = "/project", .access = access }},
        .scratch = &.{.{ .target = "/tmp" }},
        .cwd = "/project",
        .env = &.{ "PATH=/bin", "HOME=/project" },
        .limits = .{ .processes = 17, .open_files = 64 },
        .seccomp_options = .{
            .strict_wx = false,
            .block_connect = true,
            .traps = .initMany(&.{ .openat, .connect }),
        },
        .network = .filtered,
        .path_audit = true,
    };

    const request = (try requestFor(arena, config, &.{ "/bin/zig", "build" })).?;
    const back = try configFor(arena, request);

    // `shapeHash` is a hash of what the sandbox lets a tool call reach: every
    // mount with its kind and paths, every rule with its access bits, the areas,
    // the limits and the network mode. Comparing it compares the whole boundary
    // at once, so a field this module carried wrongly cannot pass here.
    try testing.expectEqualSlices(u8, &config.shapeHash(), &back.shapeHash());

    try testing.expectEqualStrings(config.root, back.root);
    try testing.expectEqualStrings(config.cwd, back.cwd);
    try testing.expectEqual(config.network, back.network);
    try testing.expectEqual(config.path_audit, back.path_audit);
    try testing.expectEqual(config.limits, back.limits);
    try testing.expectEqual(config.seccomp_options, back.seccomp_options);
    try testing.expectEqual(access, back.rules[0].access);
    try testing.expectEqual(@as(usize, 2), request.argv.len);
}

test "a config a guest cannot be asked for is refused rather than narrowed" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const base = iface.Config{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    };

    // A cgroup the host opened names a directory of the host's, and a guest that
    // ran the call anyway would have no containment while the caller believed it
    // had one.
    var supplied = base;
    supplied.containment = .{ .supplied = .{ .fd = 7 } };
    try testing.expectEqual(
        @as(?Request, null),
        try requestFor(arena, supplied, &.{"/bin/true"}),
    );

    try testing.expect(try requestFor(arena, base, &.{"/bin/true"}) != null);
}

test "the trap set crosses by name, and a name this build has no member for is refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const base = iface.Config{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .seccomp_options = .{ .traps = .initMany(&.{ .execve, .getdents64 }) },
    };

    const request = (try requestFor(arena, base, &.{"/bin/true"})).?;
    try testing.expectEqual(@as(usize, 2), request.seccomp_options.traps.len);

    const back = try configFor(arena, request);
    try testing.expect(back.seccomp_options.traps.contains(.execve));
    try testing.expect(back.seccomp_options.traps.contains(.getdents64));
    try testing.expect(!back.seccomp_options.traps.contains(.openat));
    try testing.expect(!back.seccomp_options.traps.contains(.connect));

    // A trap a newer build asked for is a refusal. Silently leaving it out would
    // run the call with a smaller trap set than the host believes it asked for.
    var newer = request;
    newer.seccomp_options.traps = &.{ "execve", "a-call-this-build-cannot-trap" };
    try testing.expectError(error.UnknownTrap, configFor(arena, newer));

    // Every member this build has round trips, so a member added to `TrapCall`
    // needs nothing written here.
    var all: seccomp.TrapSet = .initEmpty();
    inline for (@typeInfo(seccomp.TrapCall).@"enum".fields) |field| {
        all.insert(@field(seccomp.TrapCall, field.name));
    }
    var every = base;
    every.seccomp_options = .{ .traps = all };
    const whole = (try requestFor(arena, every, &.{"/bin/true"})).?;
    const rebuilt = try configFor(arena, whole);
    try testing.expectEqual(all, rebuilt.seccomp_options.traps);
}
