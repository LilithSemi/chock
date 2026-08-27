//! Which container runtime this machine has, and what privilege it holds.
//!
//! ## Rootless Podman first, Docker second
//!
//! Podman is tried first because it fits a sandbox-first tool. A rootless
//! Podman needs no daemon at all, and the process that unpacks an image is the
//! user's own process with the user's own privilege.
//!
//! ## An installed runtime is never skipped
//!
//! `detect` answers about the first runtime it finds installed, whatever that
//! runtime then says. A Podman that is installed and refuses is reported as a
//! refusal. It is **not** replaced by a Docker that happens to work.
//!
//! Falling through would change which program unpacks the image, and would
//! change the trust position from a user process to a root daemon, without
//! anybody choosing it. That is the silent fallback this project refuses. A
//! person who wants Docker instead removes Podman or says so in the project's
//! own configuration.
//!
//! ## What is measured, and what is not
//!
//! The Docker path here was measured on 2026-08-25, on Linux 6.18.42, aarch64,
//! against Docker 29.7.2. Its `info` output is the exact text `dockerTrust`
//! is tested against.
//!
//! **The Podman path has never run.** No Podman is installed on the machine
//! this was written on. `podmanTrust` is tested against the two strings the
//! `{{.Host.Security.Rootless}}` template is documented to produce, and that
//! is a weaker thing than a measurement. The surface which is unverified is
//! kept as small as it can be: the program name and this one template. Every
//! other step, which is the image inspection, the export, the extraction and
//! the mount set, is one shared path that the Docker measurement exercises in
//! full. See `Image`.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const proc = @import("proc.zig");

pub const Error = std.mem.Allocator.Error || error{
    /// The runtime could not be run at all. Distinct from a runtime that ran
    /// and refused, which is an `Answer.refused` a person reads.
    RunnerFailed,
};

/// Which runtime, in the order `detect` tries them.
pub const Kind = enum {
    podman,
    docker,

    /// The program name on the host's own `PATH`.
    pub fn program(self: Kind) []const u8 {
        return switch (self) {
            .podman => "podman",
            .docker => "docker",
        };
    }

    /// The name a person reads.
    pub fn displayName(self: Kind) []const u8 {
        return switch (self) {
            .podman => "Podman",
            .docker => "Docker",
        };
    }
};

/// Every kind, in the order `detect` tries them. Podman first: see this file's
/// own top comment.
pub const order: []const Kind = &.{ .podman, .docker };

/// What privilege the program that unpacks an image holds.
///
/// **This is not a sandbox guarantee and must never be read as one.** Nothing
/// in this library changes what `chock_sandbox.guarantees` states. A tool call
/// gets the same boundary whether its files came from a Nix closure, from a
/// rootless Podman, or from a root Docker daemon. What changes is who put the
/// files there, and that is what this says.
pub const Trust = enum {
    /// The runtime needs no privileged helper. A rootless Podman, or a Docker
    /// running in its rootless mode. The process that unpacked the image had
    /// the user's own privilege and no more.
    user_only,
    /// A daemon running as root unpacked the image. On such a machine,
    /// membership of the group that may write the daemon's socket is equal to
    /// root, because that socket accepts a request to bind the host root
    /// filesystem into a container.
    root_daemon,
    /// The runtime did not say. **Read as `root_daemon` by every caller**, and
    /// `isPrivileged` is what makes that automatic rather than a rule each
    /// caller has to remember.
    unknown,

    /// True when a caller must treat this as a root daemon.
    ///
    /// **`unknown` answers true.** A guarantee that was not measured must not
    /// read as the good answer. That is the same rule
    /// `lib/chock-sandbox/darwin/driver.zig` states for a sandbox layer, and
    /// it is put in the type here so that a caller cannot reach the good
    /// answer by failing to measure.
    pub fn isPrivileged(self: Trust) bool {
        return switch (self) {
            .user_only => false,
            .root_daemon, .unknown => true,
        };
    }

    /// One sentence for a person, saying what this means for them.
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

/// A runtime that is installed and answered.
pub const Found = struct {
    kind: Kind,
    /// The absolute path of the program, from `proc.resolve`. Owned by the
    /// allocator `detect` was given.
    program: []const u8,
    trust: Trust,

    /// A `Runner` that runs this runtime on the host.
    ///
    /// `env` and `diag` are the caller's own, because a `Found` is a fact
    /// about the machine and holds neither. **`diag` is a `Sink`**, so the
    /// allocator that owns the message travels with the slot: see
    /// `chock-container/diagnostic.zig`.
    pub fn host(self: *const Found, env: *const std.process.Environ.Map, diag: ?diagnostic.Sink) Host {
        return .{ .program = self.program, .env = env, .diag = diag };
    }
};

/// A runtime that is installed and did not answer.
pub const Refusal = struct {
    kind: Kind,
    /// One sentence for a person. Owned by the allocator `detect` was given.
    text: []const u8,
};

/// What `detect` found.
pub const Answer = union(enum) {
    /// No runtime is installed. **A clean refusal with a reason, and never a
    /// silent fall back to running unconfined.**
    not_installed,
    /// A runtime is installed and did not answer.
    refused: Refusal,
    ready: Found,
};

/// The first installed runtime, and what it said. See this file's own top
/// comment for why an installed runtime is never skipped.
///
/// **Give this an arena.** Every string of the answer comes from `allocator`.
pub fn detect(
    allocator: std.mem.Allocator,
    io: std.Io,
    host_env: *const std.process.Environ.Map,
    diag: ?*?Diagnostic,
) Error!Answer {
    // Every string of the answer comes from `allocator` and so does every
    // string of the message, which is what makes this the right owner here:
    // `detect` has one allocator and it is the caller's own.
    const sink = diagnostic.sinkOf(allocator, diag);
    for (order) |kind| {
        const program = proc.resolve(allocator, io, host_env, kind.program()) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // Not installed. Try the next one. This is the only reason to go
            // on to another runtime.
            else => continue,
        };

        var output = proc.run(allocator, io, .{
            .argv = &.{ program, "info", "--format", infoTemplate(kind) },
            .env = host_env,
            // An `info` answer is one line under this template. This bounds a
            // runtime that writes without end.
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

/// One sentence saying that no runtime is installed, and what to do next. The
/// caller owns the result.
pub fn notInstalledText(allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
    return allocator.dupe(
        u8,
        "no container runtime is installed. Install podman, which needs no daemon and " ++
            "unpacks an image with your own privilege, or install docker, whose daemon runs " ++
            "as root by default.",
    );
}

/// The `info` template that answers whether this runtime is rootless.
fn infoTemplate(kind: Kind) []const u8 {
    return switch (kind) {
        // Podman states it directly. Documented, and never measured here: see
        // this file's own top comment.
        .podman => "{{.Host.Security.Rootless}}",
        // Docker has no such field. It lists `name=rootless` among its
        // security options when it runs rootless, and lists the options
        // without it when it does not. Measured on 2026-08-25.
        .docker => "{{.SecurityOptions}}",
    };
}

/// What `info` said, as a trust position.
fn trustFrom(kind: Kind, stdout: []const u8) Trust {
    const answer = std.mem.trim(u8, stdout, " \t\r\n");
    return switch (kind) {
        .podman => podmanTrust(answer),
        .docker => dockerTrust(answer),
    };
}

/// Podman's own `{{.Host.Security.Rootless}}`, which is `true` or `false`.
/// Anything else is `unknown`.
fn podmanTrust(answer: []const u8) Trust {
    if (std.mem.eql(u8, answer, "true")) return .user_only;
    if (std.mem.eql(u8, answer, "false")) return .root_daemon;
    return .unknown;
}

/// Docker's own `{{.SecurityOptions}}`, which is a Go slice printed in
/// brackets, such as `[name=seccomp,profile=builtin name=cgroupns]`.
///
/// **The absence of `name=rootless` only means a root daemon once a real list
/// was seen.** An empty answer, or one that is not a list, says nothing about
/// this machine, so it answers `unknown` rather than the worse of the two
/// named positions. A negative reading of a reply that never arrived is a
/// guess, and a guess is what this project refuses.
fn dockerTrust(answer: []const u8) Trust {
    if (answer.len < 2) return .unknown;
    if (answer[0] != '[' or answer[answer.len - 1] != ']') return .unknown;
    if (std.mem.indexOf(u8, answer, "name=rootless") != null) return .user_only;
    return .root_daemon;
}

/// One sentence for a runtime that is installed and did not answer. The caller
/// owns the result.
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

/// How much of a refusal a person is shown. A daemon that is not running
/// answers in one line, and a longer answer is a trace whose tail is the part
/// to act on.
const max_said_bytes: usize = 512;

/// What runs a container runtime.
///
/// **A seam, because the thing on the other side of it is a container
/// runtime.** `run` is given the arguments after the program, so the argument
/// vector `Image` builds is the value a test reads. The same shape
/// `lib/chock-nix/provision.zig` gives its own `Runner`, and for the same
/// reason.
pub const Runner = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Run the runtime with these arguments and answer what it produced.
        /// The output is owned by `allocator`.
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

/// The `Runner` that really runs a container runtime, on the host, outside
/// every sandbox.
///
/// **Never inside the sandbox.** The sandbox has no network and no daemon
/// socket, so a runtime call there fails. This runs in `src/run.zig`'s phase
/// 1, which holds an `std.Io` able to spawn a process.
pub const Host = struct {
    /// The absolute path of the runtime, from `proc.resolve`.
    program: []const u8,
    /// The environment the runtime itself runs with. The host's own, so the
    /// runtime reads the user's own configuration and the user's own
    /// `DOCKER_HOST` or `CONTAINER_HOST`.
    env: *const std.process.Environ.Map,
    /// Where a fault past what `Error` can say is left, and who owns what it
    /// carries. A field of the host and not a parameter, because
    /// `Runner.VTable` is the seam a test replaces and a diagnostic is this
    /// one implementation's business.
    ///
    /// **A `Sink` and not a slot.** `runFn` is given the allocator of
    /// whichever call is running, and in `Image.load` that is a private arena
    /// which is destroyed on the error path. The message must not come from
    /// it: see `chock-container/diagnostic.zig`.
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
            // One image inspection is a few kilobytes. A root filesystem never
            // comes through here: see `proc.Options.max_output_bytes`.
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
    // The rule this whole file is built on. A driver that reports a guarantee
    // it does not enforce is worse than one that refuses, so an answer nobody
    // measured must never be the good answer.
    try testing.expect(!Trust.user_only.isPrivileged());
    try testing.expect(Trust.root_daemon.isPrivileged());
    try testing.expect(Trust.unknown.isPrivileged());
}

test "docker's real security options on a root daemon read as a root daemon" {
    // The exact text this machine's Docker 29.7.2 answered on 2026-08-25.
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
    // **The point of `dockerTrust`'s own guard.** Reading "no rootless here"
    // out of an empty reply would turn a reply that never arrived into a
    // claim about this machine.
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
    // The order is the whole of the runtime choice, and it is a decision this
    // file states rather than a property of a loop somebody may reorder.
    try testing.expectEqual(@as(usize, 2), order.len);
    try testing.expectEqual(Kind.podman, order[0]);
    try testing.expectEqual(Kind.docker, order[1]);
}

test "a machine with no runtime is a named refusal that says what to install" {
    const allocator = testing.allocator;

    // A PATH with nothing on it, which is the shortest way to a machine that
    // has neither runtime. The answer must be `not_installed` and must reach
    // no child process at all.
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
    // The root daemon sentence has to name the thing a person acts on, which
    // is that the group is equal to root.
    try testing.expect(std.mem.indexOf(u8, Trust.root_daemon.text(), "root") != null);
}
