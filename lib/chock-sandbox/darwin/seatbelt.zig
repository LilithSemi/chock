//! Seatbelt sandbox profile compiler for Darwin confinement.

const std = @import("std");
const builtin = @import("builtin");

extern "c" fn sandbox_init(profile: [*:0]const u8, flags: u64, errorbuf: *?[*:0]u8) c_int;
extern "c" fn sandbox_free_error(errorbuf: [*:0]u8) void;
extern "c" fn sandbox_check(pid: std.c.pid_t, operation: ?[*:0]const u8, filter_type: c_int, ...) c_int;

pub const Support = union(enum) {
    ok,
    off,
    unsupported: Reason,
    unavailable: Reason,

    pub const Reason = enum {
        not_darwin,
        profile_refused,
        /// sandbox_init may be called exactly once per process. A second call is refused whether it widens or narrows the profile.
        already_sandboxed,
        profile_too_long,
        path_not_resolvable,

        pub fn text(self: Reason) []const u8 {
            return switch (self) {
                .not_darwin => "this build is not for macOS, so there is no seatbelt",
                .profile_refused => "the sandbox profile was refused",
                .already_sandboxed => "this process already has a sandbox profile",
                .profile_too_long => "the sandbox profile is longer than the buffer it is built in",
                .path_not_resolvable => "a path in the profile could not be resolved",
            };
        }
    };

    pub fn applied(self: Support) bool {
        return self == .ok;
    }

    pub fn format(self: Support, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .ok => try writer.writeAll("seatbelt applied"),
            .off => try writer.writeAll("no seatbelt profile was asked for"),
            .unsupported => |reason| try writer.print("no seatbelt: {s}", .{reason.text()}),
            .unavailable => |reason| try writer.print("no seatbelt: {s}", .{reason.text()}),
        }
    }
};

pub const Access = struct {
    read: bool = false,
    write: bool = false,

    pub const read_only: Access = .{ .read = true };
    pub const read_write: Access = .{ .read = true, .write = true };
};

pub const Reach = enum {
    subpath,
    literal,
};

pub const Verb = enum { allow, deny };

pub const Rule = struct {
    path: []const u8,
    access: Access,
    reach: Reach = .subpath,
    verb: Verb = .allow,
};

pub const Options = struct {
    rules: []const Rule = &.{},
    deny: []const Rule = &.{},
    allow_exec: bool = true,
    allow_fork: bool = true,
    allow_network: bool = false,
    allow_sysctl_read: bool = true,
    allow_metadata: bool = true,
    allow_signal_same_sandbox: bool = true,
    mach_services: []const []const u8 = &.{},
    mach_services_network: []const []const u8 = &.{},
};

pub const default_mach_services: []const []const u8 = &.{
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership",
    "com.apple.system.DirectoryService.libinfo_v1",
    "com.apple.bsd.dirhelper",
    "com.apple.cfprefsd.daemon",
    "com.apple.cfprefsd.agent",
    "com.apple.logd",
    "com.apple.logd.events",
    "com.apple.system.logger",
    "com.apple.diagnosticd",
    "com.apple.system.notification_center",
    "com.apple.analyticsd",
    "com.apple.analyticsd.messagetracer",
    "com.apple.PowerManagement.control",
    "com.apple.dt.automationmode.reader",
};

pub const network_mach_services: []const []const u8 = &.{
    "com.apple.SecurityServer",
    "com.apple.trustd",
    "com.apple.SystemConfiguration.configd",
    "com.apple.SystemConfiguration.DNSConfiguration",
    "com.apple.networkd",
    "com.apple.ocspd",
};

/// Without this rule, execve succeeds and the new program is killed by SIGABRT with no diagnostic.
const dyld_root_rule = "(allow file-read* (literal \"/\"))\n";

pub const PathFault = enum {
    empty,
    not_absolute,
    not_normalised,
    /// A NUL or control byte would end the profile text early. A `"` or `\` is not a fault, since both are escaped.
    bad_byte,
    too_long,

    pub fn text(self: PathFault) []const u8 {
        return switch (self) {
            .empty => "is empty",
            .not_absolute => "is not absolute",
            .not_normalised => "holds a . or .. component",
            .bad_byte => "holds a byte that cannot be in a sandbox profile",
            .too_long => "is longer than a path this code may hold",
        };
    }
};

pub const max_path_bytes = 1024;

pub fn checkPath(path: []const u8) ?PathFault {
    if (path.len == 0) return .empty;
    if (path.len > max_path_bytes) return .too_long;
    if (path[0] != '/') return .not_absolute;
    if (hasBadByte(path)) return .bad_byte;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return .not_normalised;
    }
    return null;
}

fn hasBadByte(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte == 0 or byte < 0x20 or byte == 0x7f) return true;
    }
    return false;
}

pub fn checkMachServiceName(name: []const u8) ?PathFault {
    if (name.len == 0) return .empty;
    if (hasBadByte(name)) return .bad_byte;
    return null;
}

/// Builds into a caller's buffer instead of allocating, so it is safe to use between fork and execve.
pub const Builder = struct {
    buffer: []u8,
    len: usize = 0,
    fault: ?struct { text: []const u8, fault: PathFault } = null,
    overflowed: bool = false,

    pub fn init(buffer: []u8) Builder {
        return .{ .buffer = buffer };
    }

    fn write(self: *Builder, bytes: []const u8) void {
        if (self.overflowed) return;
        if (bytes.len > self.buffer.len - self.len) {
            self.overflowed = true;
            return;
        }
        @memcpy(self.buffer[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    /// Escapes `"` and `\` so a path cannot close the string and inject profile text.
    fn writeQuoted(self: *Builder, path: []const u8) void {
        self.write("\"");
        var start: usize = 0;
        for (path, 0..) |byte, index| {
            if (byte != '"' and byte != '\\') continue;
            self.write(path[start..index]);
            self.write(if (byte == '"') "\\\"" else "\\\\");
            start = index + 1;
        }
        self.write(path[start..]);
        self.write("\"");
    }

    fn writeRule(self: *Builder, verb: Verb, rule: Rule) void {
        if (checkPath(rule.path)) |fault| {
            if (self.fault == null) self.fault = .{ .text = rule.path, .fault = fault };
            return;
        }
        if (!rule.access.read and !rule.access.write) return;
        self.write("(");
        self.write(@tagName(verb));
        if (rule.access.read) self.write(" file-read*");
        if (rule.access.write) self.write(" file-write*");
        self.write(" (");
        self.write(@tagName(rule.reach));
        self.write(" ");
        self.writeQuoted(rule.path);
        self.write("))\n");
    }

    /// Must go through writeQuoted: a second, unquoted writer here would reopen the injection hole for a Mach service name.
    fn writeMachService(self: *Builder, name: []const u8) void {
        if (checkMachServiceName(name)) |fault| {
            if (self.fault == null) self.fault = .{ .text = name, .fault = fault };
            return;
        }
        self.write("(allow mach-lookup (global-name ");
        self.writeQuoted(name);
        self.write("))\n");
    }

    /// The order of the sections is the contract: the base rule first, then options.rules, then options.deny last, since the later of two rules on one path wins.
    pub fn finish(self: *Builder, options: Options) error{ ProfileTooLong, BadPath }![:0]u8 {
        self.len = 0;
        self.fault = null;
        self.overflowed = false;

        self.write("(version 1)\n(deny default)\n");
        self.write(dyld_root_rule);
        if (options.allow_fork) self.write("(allow process-fork)\n");
        if (options.allow_exec) self.write("(allow process-exec*)\n");
        if (options.allow_sysctl_read) self.write("(allow sysctl-read)\n");
        if (options.allow_metadata) self.write("(allow file-read-metadata)\n");

        for (options.rules) |rule| self.writeRule(rule.verb, rule);

        // The allow line is what opens the network; the denial alone still blocks it even with this line removed.
        if (options.allow_network) {
            self.write("(allow network*)\n");
        } else {
            self.write("(deny network*)\n");
        }
        self.write("(deny signal)\n");
        if (options.allow_signal_same_sandbox) self.write("(allow signal (target same-sandbox))\n");

        // launchd and LaunchServices are deliberately left off this list: reaching them starts a process outside this profile.
        self.write("(deny mach-lookup)\n");
        for (options.mach_services) |name| self.writeMachService(name);
        if (options.allow_network) {
            for (options.mach_services_network) |name| self.writeMachService(name);
        }

        for (options.deny) |rule| self.writeRule(.deny, rule);

        // Written through write, not appended directly, so a full buffer overflows here instead of truncating the last denial.
        self.write("\x00");
        if (self.overflowed) return error.ProfileTooLong;
        if (self.fault != null) return error.BadPath;
        return self.buffer[0 .. self.len - 1 :0];
    }
};

/// Confinement survives fork and exec: a second sandbox_init is refused with EPERM. This never prints or allocates, so it is safe between fork and execve.
pub fn apply(profile: [:0]const u8) Support {
    if (builtin.os.tag == .macos) {
        var message: ?[*:0]u8 = null;
        const rc = sandbox_init(profile.ptr, 0, &message);
        if (message) |text| sandbox_free_error(text);
        if (rc == 0) return .ok;
        return .{ .unavailable = .profile_refused };
    } else {
        return .{ .unsupported = .not_darwin };
    }
}

pub const Nesting = enum {
    free,
    confined,
    /// A test must not skip on this: the fault is in this code or the machine, and a skip would report it as a pass.
    trial_rejected,
};

const trial_options: Options = .{ .rules = &.{.{ .path = "/", .access = .read_write }} };

pub fn confinedAlready() bool {
    return nesting() == .confined;
}

/// EPERM tells an outer profile's refusal apart from a bad profile text; neither the return value nor the message alone does.
pub fn nesting() Nesting {
    if (builtin.os.tag != .macos) return .free;

    if (sandbox_check(std.c.getpid(), null, 0) != 1) return .free;

    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const trial = builder.finish(trial_options) catch return .trial_rejected;
    return applyInChild(trial);
}

fn applyInChild(profile: [:0]const u8) Nesting {
    if (builtin.os.tag != .macos) return .free;

    const pid = std.c.fork();
    if (pid < 0) return .trial_rejected;
    if (pid == 0) {
        // libsandbox prints its own refusal on stderr, which would flag the build log, so the child silences it.
        const quiet = std.c.open("/dev/null", .{ .ACCMODE = .WRONLY });
        if (quiet >= 0) _ = std.c.dup2(quiet, 2);
        var message: ?[*:0]u8 = null;
        std.c._errno().* = 0;
        const rc = sandbox_init(profile.ptr, 0, &message);
        const failure = std.c._errno().*;
        if (message) |text| sandbox_free_error(text);
        if (rc == 0) std.c._exit(0);
        std.c._exit(if (failure == @intFromEnum(std.c.E.PERM)) 1 else 2);
    }

    var status: c_int = 0;
    while (std.c.waitpid(pid, &status, 0) < 0) {
        if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) return .trial_rejected;
    }
    if (!std.c.W.IFEXITED(@bitCast(status))) return .trial_rejected;
    return switch (std.c.W.EXITSTATUS(@bitCast(status))) {
        0 => .free,
        1 => .confined,
        else => .trial_rejected,
    };
}

test "a profile puts every denial after every allowance" {
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const profile = try builder.finish(.{
        .rules = &.{.{ .path = "/work", .access = .read_write }},
        .deny = &.{.{ .path = "/work/secret.env", .access = .read_write, .reach = .literal }},
    });
    const allow_at = std.mem.indexOf(u8, profile, "(allow file-read* file-write* (subpath \"/work\"))").?;
    const deny_at = std.mem.indexOf(u8, profile, "(deny file-read* file-write* (literal \"/work/secret.env\"))").?;
    try std.testing.expect(deny_at > allow_at);
}

test "a path that would not match anything is refused rather than written" {
    try std.testing.expectEqual(PathFault.empty, checkPath("").?);
    try std.testing.expectEqual(PathFault.not_absolute, checkPath("work/tree").?);
    try std.testing.expectEqual(PathFault.not_normalised, checkPath("/work/../work").?);
    try std.testing.expectEqual(PathFault.not_normalised, checkPath("/work/./tree").?);
    try std.testing.expectEqual(PathFault.bad_byte, checkPath("/work/a\nb").?);
    try std.testing.expectEqual(PathFault.bad_byte, checkPath("/work/a\x00b").?);
    try std.testing.expectEqual(@as(?PathFault, null), checkPath("/work/tree"));
    try std.testing.expectEqual(@as(?PathFault, null), checkPath("/work/"));

    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    try std.testing.expectError(error.BadPath, builder.finish(.{
        .deny = &.{.{ .path = "relative/path", .access = .read_write }},
    }));
}

test "a quote in a path is escaped, so a path cannot become a rule" {
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const profile = try builder.finish(.{
        .rules = &.{.{ .path = "/work/x\") (allow file-read* (subpath \"/", .access = .read_only }},
    });
    var rules: usize = 0;
    var lines = std.mem.splitScalar(u8, profile, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "(allow file-read*")) rules += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), rules);
    try std.testing.expect(std.mem.indexOf(u8, profile, "\\\"") != null);
    var second = Builder.init(&buffer);
    const with_slash = try second.finish(.{
        .rules = &.{.{ .path = "/work/back\\", .access = .read_only }},
    });
    try std.testing.expect(std.mem.indexOf(u8, with_slash, "\"/work/back\\\\\"") != null);
}

test "a profile that does not fit is refused, never truncated" {
    var buffer: [64]u8 = undefined;
    var builder = Builder.init(&buffer);
    try std.testing.expectError(error.ProfileTooLong, builder.finish(.{
        .rules = &.{.{ .path = "/a/reasonably/long/path/that/will/not/fit", .access = .read_write }},
    }));
}

test "the network and the signal rules are what the measurements say" {
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const closed = try builder.finish(.{});
    try std.testing.expect(std.mem.indexOf(u8, closed, "(deny network*)") != null);
    const deny_signal_at = std.mem.indexOf(u8, closed, "(deny signal)").?;
    const allow_same_at = std.mem.indexOf(u8, closed, "(allow signal (target same-sandbox))").?;
    try std.testing.expect(allow_same_at > deny_signal_at);

    var open_builder = Builder.init(&buffer);
    const opened = try open_builder.finish(.{ .allow_network = true });
    try std.testing.expect(std.mem.indexOf(u8, opened, "(deny network*)") == null);
    try std.testing.expect(std.mem.indexOf(u8, opened, "(allow network*)") != null);
    try std.testing.expect(std.mem.indexOf(u8, opened, "(deny signal)") != null);
}

test "every profile denies mach-lookup by default" {
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const profile = try builder.finish(.{});
    try std.testing.expect(std.mem.indexOf(u8, profile, "(deny mach-lookup)") != null);
}

test "the mach-lookup denial comes before every mach-lookup allowance" {
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const profile = try builder.finish(.{
        .mach_services = default_mach_services,
        .allow_network = true,
        .mach_services_network = network_mach_services,
    });
    const deny_at = std.mem.indexOf(u8, profile, "(deny mach-lookup)").?;
    const needle = "(allow mach-lookup (global-name ";
    var checked: usize = 0;
    var search_at: usize = 0;
    while (std.mem.indexOfPos(u8, profile, search_at, needle)) |allow_at| {
        try std.testing.expect(allow_at > deny_at);
        checked += 1;
        search_at = allow_at + needle.len;
    }
    try std.testing.expect(checked > 0);
}

test "the network mach services are absent without allow_network and present with it" {
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const closed = try builder.finish(.{
        .mach_services = default_mach_services,
        .mach_services_network = network_mach_services,
    });
    for (network_mach_services) |name| {
        try std.testing.expect(std.mem.indexOf(u8, closed, name) == null);
    }
    for (default_mach_services) |name| {
        try std.testing.expect(std.mem.indexOf(u8, closed, name) != null);
    }

    var open_builder = Builder.init(&buffer);
    const opened = try open_builder.finish(.{
        .mach_services = default_mach_services,
        .allow_network = true,
        .mach_services_network = network_mach_services,
    });
    for (network_mach_services) |name| {
        try std.testing.expect(std.mem.indexOf(u8, opened, name) != null);
    }
}

test "no configuration ever names launchd or its lookup service" {
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const profile = try builder.finish(.{
        .mach_services = default_mach_services,
        .allow_network = true,
        .mach_services_network = network_mach_services,
    });
    try std.testing.expect(std.mem.indexOf(u8, profile, "com.apple.lsd") == null);
    try std.testing.expect(std.mem.indexOf(u8, profile, "com.apple.launchd") == null);
}

test "a mach service name holding a control byte is refused" {
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    try std.testing.expectError(error.BadPath, builder.finish(.{
        .mach_services = &.{"com.apple.bad\x00name"},
    }));
}

test "a quote in a mach service name is escaped, not refused" {
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const profile = try builder.finish(.{
        .mach_services = &.{"com.apple.\"injected\""},
    });
    var rules: usize = 0;
    var lines = std.mem.splitScalar(u8, profile, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "(allow mach-lookup")) rules += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), rules);
    try std.testing.expect(std.mem.indexOf(u8, profile, "\\\"") != null);
}

test "every profile carries the root rule dyld needs" {
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const profile = try builder.finish(.{});
    try std.testing.expect(std.mem.indexOf(u8, profile, "(allow file-read* (literal \"/\"))") != null);
    try std.testing.expect(std.mem.startsWith(u8, profile, "(version 1)\n(deny default)\n"));
}

test "apply answers unsupported on a build that is not for macOS" {
    if (builtin.os.tag == .macos) return;
    const support = apply("(version 1)(deny default)");
    try std.testing.expect(!support.applied());
    try std.testing.expectEqual(Support.Reason.not_darwin, support.unsupported);
}

test "a profile refused for its own reason is never read as a profile above" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (sandbox_check(std.c.getpid(), null, 0) == 1) return error.SkipZigTest;
    try std.testing.expectEqual(Nesting.trial_rejected, applyInChild("(version 1) this is not sbpl ((("));
}

test "the trial profile this file measures with really compiles" {
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const trial = try builder.finish(trial_options);
    try std.testing.expect(std.mem.startsWith(u8, trial, "(version 1)\n(deny default)\n"));
    try std.testing.expect(std.mem.indexOf(u8, trial, "(deny network*)") != null);
    try std.testing.expect(std.mem.indexOf(u8, trial, "(deny signal)") != null);
    if (builtin.os.tag != .macos) return;
    try std.testing.expect(applyInChild(trial) != .trial_rejected);
}

test "a process that already has a profile is told from one that has not" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    const pid = std.c.fork();
    try std.testing.expect(pid >= 0);
    if (pid == 0) {
        const quiet = std.c.open("/dev/null", .{ .ACCMODE = .WRONLY });
        if (quiet >= 0) _ = std.c.dup2(quiet, 2);
        _ = apply("(version 1)(allow default)");
        std.c._exit(if (confinedAlready()) 0 else 1);
    }
    var status: c_int = 0;
    while (std.c.waitpid(pid, &status, 0) < 0) {
        if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) return error.ChildNotReaped;
    }
    try std.testing.expectEqual(@as(c_int, 0), status);
}
