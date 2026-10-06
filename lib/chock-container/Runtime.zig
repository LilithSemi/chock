//! Which container runtime this machine has, and what privilege it holds.
//! Podman is tried first. A refused runtime is never skipped for another.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const proc = @import("proc.zig");

pub const Error = std.mem.Allocator.Error || error{
    /// Distinct from `Answer.refused`.
    RunnerFailed,
};

pub const Kind = enum {
    podman,
    docker,

    pub fn program(self: Kind) []const u8 {
        return switch (self) {
            .podman => "podman",
            .docker => "docker",
        };
    }

    pub fn displayName(self: Kind) []const u8 {
        return switch (self) {
            .podman => "Podman",
            .docker => "Docker",
        };
    }
};

pub const order: []const Kind = &.{ .podman, .docker };

/// Not a sandbox guarantee.
pub const Trust = enum {
    user_only,
    /// Socket group membership equals root.
    root_daemon,
    /// The runtime did not say.
    unknown,

    /// `unknown` answers true.
    pub fn isPrivileged(self: Trust) bool {
        return switch (self) {
            .user_only => false,
            .root_daemon, .unknown => true,
        };
    }

    pub fn text(self: Trust) []const u8 {
        return switch (self) {
            .user_only => "the runtime unpacks an image with your own privilege and no more",
            .root_daemon => "a daemon running as root unpacks the image, so membership of its " ++
                "group is equal to root on this machine",
            .unknown => "the runtime did not say whether it is rootless, so it is treated as a " ++
                "daemon running as root",
        };
    }
};

pub const Found = struct {
    kind: Kind,
    /// From `proc.resolve`, owned by `detect`'s allocator.
    program: []const u8,
    trust: Trust,

    /// `env`/`diag` are the caller's own.
    pub fn host(self: *const Found, env: *const std.process.Environ.Map, diag: ?diagnostic.Sink) Host {
        return .{ .program = self.program, .env = env, .diag = diag };
    }
};

pub const Refusal = struct {
    kind: Kind,
    /// Owned by `detect`'s allocator.
    text: []const u8,
};

pub const Answer = union(enum) {
    /// Never a silent fallback to unconfined.
    not_installed,
    refused: Refusal,
    ready: Found,
};

/// Give this an arena.
pub fn detect(
    allocator: std.mem.Allocator,
    io: std.Io,
    host_env: *const std.process.Environ.Map,
    diag: ?*?Diagnostic,
) Error!Answer {
    const sink = diagnostic.sinkOf(allocator, diag);
    for (order) |kind| {
        const program = proc.resolve(allocator, io, host_env, kind.program()) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => continue,
        };

        var output = proc.run(allocator, io, .{
            .argv = &.{ program, "info", "--format", infoTemplate(kind) },
            .env = host_env,
            .max_output_bytes = 1024 * 1024,
            .diag = sink,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                _ = diagnostic.note(sink, .{ .runtime_not_runnable = err });
                return error.RunnerFailed;
            },
        };
        defer output.deinit(allocator);

        if (!output.succeeded()) {
            return .{ .refused = .{
                .kind = kind,
                .text = try unreachableText(allocator, kind, output.stderr),
            } };
        }

        return .{ .ready = .{
            .kind = kind,
            .program = program,
            .trust = trustFrom(kind, output.stdout),
        } };
    }

    return .not_installed;
}

/// The caller owns the result.
pub fn notInstalledText(allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
    return allocator.dupe(
        u8,
        "no container runtime is installed. Install podman, which needs no daemon and " ++
            "unpacks an image with your own privilege, or install docker, whose daemon runs " ++
            "as root by default.",
    );
}

fn infoTemplate(kind: Kind) []const u8 {
    return switch (kind) {
        .podman => "{{.Host.Security.Rootless}}",
        .docker => "{{.SecurityOptions}}",
    };
}

fn trustFrom(kind: Kind, stdout: []const u8) Trust {
    const answer = std.mem.trim(u8, stdout, " \t\r\n");
    return switch (kind) {
        .podman => podmanTrust(answer),
        .docker => dockerTrust(answer),
    };
}

fn podmanTrust(answer: []const u8) Trust {
    if (std.mem.eql(u8, answer, "true")) return .user_only;
    if (std.mem.eql(u8, answer, "false")) return .root_daemon;
    return .unknown;
}

/// A Go slice printed in brackets.
fn dockerTrust(answer: []const u8) Trust {
    if (answer.len < 2) return .unknown;
    if (answer[0] != '[' or answer[answer.len - 1] != ']') return .unknown;
    if (std.mem.indexOf(u8, answer, "name=rootless") != null) return .user_only;
    return .root_daemon;
}

/// The caller owns the result.
fn unreachableText(
    allocator: std.mem.Allocator,
    kind: Kind,
    stderr: []const u8,
) std.mem.Allocator.Error![]u8 {
    const said = std.mem.trim(u8, stderr, " \t\r\n");
    const tail = if (said.len > max_said_bytes) said[said.len - max_said_bytes ..] else said;
    return std.fmt.allocPrint(
        allocator,
        "{s} is installed and did not answer: {s}",
        .{ kind.displayName(), tail },
    );
}

const max_said_bytes: usize = 512;

pub const Runner = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Output owned by `allocator`.
        run: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            args: []const []const u8,
        ) Error!proc.Output,
    };

    pub fn run(
        self: Runner,
        allocator: std.mem.Allocator,
        io: std.Io,
        args: []const []const u8,
    ) Error!proc.Output {
        return self.vtable.run(self.ptr, allocator, io, args);
    }
};

/// Never inside the sandbox.
pub const Host = struct {
    program: []const u8,
    /// The host's own.
    env: *const std.process.Environ.Map,
    diag: ?diagnostic.Sink = null,

    pub fn runner(self: *const Host) Runner {
        return .{ .ptr = @constCast(self), .vtable = &vtable };
    }

    const vtable = Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        args: []const []const u8,
    ) Error!proc.Output {
        const self: *Host = @ptrCast(@alignCast(ptr));

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(allocator);
        try argv.append(allocator, self.program);
        try argv.appendSlice(allocator, args);

        return proc.run(allocator, io, .{
            .argv = argv.items,
            .env = self.env,
            .max_output_bytes = 8 * 1024 * 1024,
            .diag = self.diag,
        }) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => {
                _ = diagnostic.note(self.diag, .{ .runtime_not_runnable = err });
                return error.RunnerFailed;
            },
        };
    }
};

const testing = std.testing;

test "an unknown trust reads as privileged, so the good answer needs a measurement" {
    try testing.expect(!Trust.user_only.isPrivileged());
    try testing.expect(Trust.root_daemon.isPrivileged());
    try testing.expect(Trust.unknown.isPrivileged());
}

test "docker's real security options on a root daemon read as a root daemon" {
    try testing.expectEqual(
        Trust.root_daemon,
        trustFrom(.docker, "[name=seccomp,profile=builtin name=cgroupns]\n"),
    );
}

test "docker in rootless mode reads as user only" {
    try testing.expectEqual(
        Trust.user_only,
        trustFrom(.docker, "[name=seccomp,profile=builtin name=rootless name=cgroupns]\n"),
    );
}

test "a docker answer that is not a list says nothing, so it reads as unknown" {
    for ([_][]const u8{ "", "\n", "   ", "name=rootless", "[", "]", "<no value>" }) |answer| {
        try testing.expectEqual(Trust.unknown, trustFrom(.docker, answer));
    }
}

test "podman states rootlessness directly, and anything else reads as unknown" {
    try testing.expectEqual(Trust.user_only, trustFrom(.podman, "true\n"));
    try testing.expectEqual(Trust.root_daemon, trustFrom(.podman, "false\n"));
    for ([_][]const u8{ "", "yes", "<no value>", "True" }) |answer| {
        try testing.expectEqual(Trust.unknown, trustFrom(.podman, answer));
    }
}

test "podman is tried before docker" {
    try testing.expectEqual(@as(usize, 2), order.len);
    try testing.expectEqual(Kind.podman, order[0]);
    try testing.expectEqual(Kind.docker, order[1]);
}

test "a machine with no runtime is a named refusal that says what to install" {
    const allocator = testing.allocator;

    var env = std.process.Environ.Map.init(allocator);
    defer env.deinit();
    try env.put("PATH", "/chock-no-such-directory");

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const answer = try detect(arena_state.allocator(), testing.io, &env, null);
    try testing.expectEqual(Answer.not_installed, answer);

    const text = try notInstalledText(allocator);
    defer allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "podman") != null);
    try testing.expect(std.mem.indexOf(u8, text, "docker") != null);
}

test "a runtime that is installed and did not answer names itself and what it said" {
    const allocator = testing.allocator;
    const text = try unreachableText(allocator, .docker, "\nCannot connect to the Docker daemon\n");
    defer allocator.free(text);
    try testing.expectEqualStrings(
        "Docker is installed and did not answer: Cannot connect to the Docker daemon",
        text,
    );
}

test "a runtime name is the program name a person types" {
    try testing.expectEqualStrings("podman", Kind.podman.program());
    try testing.expectEqualStrings("docker", Kind.docker.program());
    try testing.expectEqualStrings("Podman", Kind.podman.displayName());
    try testing.expectEqualStrings("Docker", Kind.docker.displayName());
}

test "each trust position says something different to a person" {
    const positions: []const Trust = &.{ .user_only, .root_daemon, .unknown };
    for (positions, 0..) |position, i| {
        try testing.expect(position.text().len > 0);
        for (positions[i + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, position.text(), other.text()));
        }
    }
    try testing.expect(std.mem.indexOf(u8, Trust.root_daemon.text(), "root") != null);
}
