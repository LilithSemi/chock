//! What crosses between the host and a guest: one sandbox request, one answer.

const std = @import("std");

const iface = @import("../Sandbox.zig");
const landlock = @import("../linux/landlock.zig");
const namespace = @import("../linux/namespace.zig");
const rlimits = @import("../linux/rlimits.zig");
const seccomp = @import("../linux/seccomp.zig");

pub const max_message_bytes: usize = 1 << 20;

pub const guest_root = "/run/chock/sandbox";

pub const guest_output = "/run/chock/output";
pub const guest_output_err = "/run/chock/output-err";

pub const max_output_bytes: u64 = 8 << 20;

pub const reaching_v4 = "v4.";
pub const reaching_v6 = "v6.";

pub const max_reaching_text: usize = reaching_v6.len + 32;

pub fn writeAddress(into: []u8, address: iface.NetRouter.Address) []const u8 {
    return switch (address) {
        .ipv4 => |bytes| std.fmt.bufPrint(into, reaching_v4 ++ "{x}", .{bytes}) catch unreachable,
        .ipv6 => |bytes| std.fmt.bufPrint(into, reaching_v6 ++ "{x}", .{bytes}) catch unreachable,
    };
}

pub fn addressIn(text: []const u8) ?iface.NetRouter.Address {
    if (std.mem.startsWith(u8, text, reaching_v4)) {
        var bytes: [4]u8 = undefined;
        const digits = text[reaching_v4.len..];
        if (digits.len != bytes.len * 2) return null;
        _ = std.fmt.hexToBytes(&bytes, digits) catch return null;
        return .{ .ipv4 = bytes };
    }
    if (std.mem.startsWith(u8, text, reaching_v6)) {
        var bytes: [16]u8 = undefined;
        const digits = text[reaching_v6.len..];
        if (digits.len != bytes.len * 2) return null;
        _ = std.fmt.hexToBytes(&bytes, digits) catch return null;
        return .{ .ipv6 = bytes };
    }
    return null;
}

pub const Resolve = struct {
    resolve: []const u8,
    ipv6: bool = false,
};

pub const Resolved = struct {
    address: ?[]const u8 = null,
    refused: bool = false,
};

pub fn resolveIn(allocator: std.mem.Allocator, line: []const u8) ?std.json.Parsed(Resolve) {
    return std.json.parseFromSlice(
        Resolve,
        allocator,
        std.mem.trim(u8, line, " \t\r\n"),
        .{ .ignore_unknown_fields = true },
    ) catch null;
}

pub const Hello = struct {
    hello: u32,
};

pub const hello_line = "{\"hello\":1}\n";

pub fn helloIn(line: []const u8) bool {
    const said = std.mem.trim(u8, line, " \t\r\n");
    return std.mem.eql(u8, said, std.mem.trim(u8, hello_line, "\n"));
}

pub const Output = struct {
    output: u64,
    err: bool = false,
};

pub const cancel_terminate = "{\"cancel\":15}\n";
pub const cancel_kill = "{\"cancel\":9}\n";

pub fn cancelAtStart(text: []const u8) ?struct { signal: u32, bytes: usize } {
    if (std.mem.startsWith(u8, text, cancel_kill)) {
        return .{ .signal = 9, .bytes = cancel_kill.len };
    }
    if (std.mem.startsWith(u8, text, cancel_terminate)) {
        return .{ .signal = 15, .bytes = cancel_terminate.len };
    }
    return null;
}

pub fn cancelIn(line: []const u8) ?u32 {
    const said = std.mem.trim(u8, line, " \t\r\n");
    if (std.mem.eql(u8, said, std.mem.trim(u8, cancel_terminate, "\n"))) return 15;
    if (std.mem.eql(u8, said, std.mem.trim(u8, cancel_kill, "\n"))) return 9;
    return null;
}

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
    access: u64,
};

pub const Scratch = struct {
    target: []const u8,
};

pub const Seccomp = struct {
    strict_wx: bool = true,
    block_connect: bool = false,
    traps: []const []const u8 = &.{},
};

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
    now_ns: i64 = 0,
};

pub const Answer = struct {
    ended: ?Ended = null,
    refusal: ?[]const u8 = null,
    landlock: ?Landlock = null,

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
    "hide_helpers",
};

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
        .root = guest_root,
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
    UnknownTrap,
};

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

pub fn write(writer: *std.Io.Writer, value: anytype) std.Io.Writer.Error!void {
    try writer.print("{f}\n", .{std.json.fmt(value, .{})});
    try writer.flush();
}

pub const ReadError = error{
    TooLong,
    Ended,
    Broke,
    Unreadable,
};

pub fn readLine(reader: *std.Io.Reader) ReadError![]const u8 {
    const line = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.StreamTooLong => return error.TooLong,
        error.EndOfStream => return error.Ended,
        else => return error.Broke,
    };
    if (line.len > max_message_bytes) return error.TooLong;
    return line;
}

pub fn frameIn(allocator: std.mem.Allocator, line: []const u8) ?Output {
    const parsed = std.json.parseFromSlice(
        Output,
        allocator,
        std.mem.trim(u8, line, " \t\r\n"),
        .{ .ignore_unknown_fields = true },
    ) catch return null;
    defer parsed.deinit();
    return parsed.value;
}

pub fn parseLine(
    comptime T: type,
    allocator: std.mem.Allocator,
    line: []const u8,
) (ReadError || std.mem.Allocator.Error)!std.json.Parsed(T) {
    return std.json.parseFromSlice(T, allocator, std.mem.trim(u8, line, " \t\r\n"), .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Unreadable,
    };
}

pub fn read(
    comptime T: type,
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
) (ReadError || std.mem.Allocator.Error)!std.json.Parsed(T) {
    return parseLine(T, allocator, try readLine(reader));
}

const testing = std.testing;

test "every field of Config either crosses or is named host only, with a reason" {
    inline for (@typeInfo(iface.Config).@"struct".fields) |field| {
        const crosses = @hasField(Request, field.name);
        var named = false;
        for (host_only) |one| {
            if (std.mem.eql(u8, one, field.name)) named = true;
        }
        if (!crosses and !named) {
            try testing.expectEqualStrings("a field that crosses or is host only", field.name);
            return error.ConfigFieldIsNeither;
        }
        try testing.expect(!(crosses and named));
    }

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

    var as_guest = config;
    as_guest.root = guest_root;
    try testing.expectEqualSlices(u8, &as_guest.shapeHash(), &back.shapeHash());

    try testing.expectEqualStrings(guest_root, back.root);
    try testing.expect(!std.mem.eql(u8, config.root, back.root));
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

    var newer = request;
    newer.seccomp_options.traps = &.{ "execve", "a-call-this-build-cannot-trap" };
    try testing.expectError(error.UnknownTrap, configFor(arena, newer));

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

test "a cancel line is read back as the signal it asks for, and nothing else is" {
    try testing.expectEqual(@as(?u32, 15), cancelIn(cancel_terminate));
    try testing.expectEqual(@as(?u32, 9), cancelIn(cancel_kill));
    try testing.expectEqual(@as(?u32, null), cancelIn("{\"root\":\"/\"}\n"));
    try testing.expectEqual(@as(?u32, null), cancelIn(""));

    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, cancel_terminate, "\n"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, cancel_kill, "\n"));
}

test "an address goes out as bytes and comes back as the same bytes" {
    var room: [max_reaching_text]u8 = undefined;

    const four: iface.NetRouter.Address = .{ .ipv4 = .{ 127, 0, 0, 1 } };
    try testing.expectEqualStrings("v4.7f000001", writeAddress(&room, four));
    try testing.expectEqual(four, addressIn(writeAddress(&room, four)).?);

    const six: iface.NetRouter.Address = .{ .ipv6 = .{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    } };
    try testing.expectEqual(six, addressIn(writeAddress(&room, six)).?);

    try testing.expectEqual(@as(?iface.NetRouter.Address, null), addressIn("127.0.0.1"));
    try testing.expectEqual(@as(?iface.NetRouter.Address, null), addressIn("v4.7f0000"));
    try testing.expectEqual(@as(?iface.NetRouter.Address, null), addressIn("v4.zzzzzzzz"));
    try testing.expectEqual(@as(?iface.NetRouter.Address, null), addressIn(""));
}

test "a cancel is taken from the front, and a request behind it is left alone" {
    const kill = cancelAtStart(cancel_kill).?;
    try testing.expectEqual(@as(u32, 9), kill.signal);
    try testing.expectEqual(cancel_kill.len, kill.bytes);

    const both = cancel_terminate ++ "{\"root\":\"/\",\"argv\":[]}\n";
    const taken = cancelAtStart(both).?;
    try testing.expectEqual(@as(u32, 15), taken.signal);
    try testing.expectEqual(cancel_terminate.len, taken.bytes);
    try testing.expectEqualStrings("{\"root\":\"/\",\"argv\":[]}\n", both[taken.bytes..]);

    try testing.expectEqual(
        @as(?@TypeOf(kill), null),
        cancelAtStart("{\"root\":\"/\"}\n"),
    );
    try testing.expectEqual(@as(?@TypeOf(kill), null), cancelAtStart(""));
}
