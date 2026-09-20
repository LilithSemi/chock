//! On macOS, a tool call must not write the project's own
//! `.git/worktrees/<id>`, and `git status`, `git add` and `git commit` must
//! keep working while it cannot. Every test here drives a real sandbox.

const std = @import("std");
const builtin = @import("builtin");

const chock_workspace = @import("chock-workspace");
const sandbox = @import("chock-sandbox");
const Workspace = chock_workspace.Workspace;
const git = chock_workspace.git;

// Zig 0.16 has no argv a test can read, and the default test runner panics on
// argv it does not know, so build.zig embeds the probe path at build time.
const probe_path = @import("darwin_workspace_probe_path").probe_path;

const succeeded: u8 = 0;
const refused: u8 = 1;

/// The read only system paths the real git needs under `(deny default)`. A real
/// session gets this set from the Nix dev shell closure and this suite has no
/// dev shell, so it carries its own. None of them covers the project, the
/// scratch directory, or the copy.
const system_paths = [_]struct { path: []const u8, read_only: bool = true }{
    .{ .path = "/nix/store" },
    .{ .path = "/usr" },
    .{ .path = "/bin" },
    .{ .path = "/etc" },
    .{ .path = "/System" },
    .{ .path = "/Library" },
    .{ .path = "/private/var/db" },
    .{ .path = "/private/var/select" },
    // git opens `/dev/null` for reading and writing before it does anything
    // else, and fails outright without it.
    .{ .path = "/dev", .read_only = false },
};

/// The absolute, resolved path of an open descriptor, through `F_GETPATH`.
/// Seatbelt matches the path the kernel resolved, so a rule naming `/tmp/x`,
/// where `/tmp` is a link to `/private/tmp`, matches nothing, and a relative
/// path such as the `.zig-cache/tmp` one `tmpDir` hands back matches nothing.
fn resolvedPath(handle: std.posix.fd_t, buffer: *[std.fs.max_path_bytes]u8) ![]const u8 {
    if (std.c.fcntl(handle, std.c.F.GETPATH, @as([*]u8, buffer)) != 0) return error.PathNotResolvable;
    return std.mem.sliceTo(buffer, 0);
}

/// The absolute, resolved path of `path`. Null when it cannot be opened. Every
/// `git` on a Nix `PATH` is a link into the store, and a link in a rule matches
/// nothing.
fn resolveOnDisk(allocator: std.mem.Allocator, path: []const u8) !?[]u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (path.len >= buffer.len) return null;
    @memcpy(buffer[0..path.len], path);
    buffer[path.len] = 0;
    const zero_terminated: [*:0]const u8 = @ptrCast(&buffer);

    const handle = std.c.open(zero_terminated, .{ .ACCMODE = .RDONLY });
    if (handle < 0) return null;
    defer _ = std.c.close(handle);

    var resolved: [std.fs.max_path_bytes]u8 = undefined;
    const real = resolvedPath(handle, &resolved) catch return null;
    return try allocator.dupe(u8, real);
}

/// The absolute path of the real git, found on `PATH` and then resolved.
/// Answers null when there is no git, and the caller skips.
fn findGit(allocator: std.mem.Allocator, env: *const std.process.Environ.Map) !?[]u8 {
    const path_value = env.get("PATH") orelse return null;
    var entries = std.mem.splitScalar(u8, path_value, ':');
    while (entries.next()) |entry| {
        if (entry.len == 0) continue;
        const candidate = try std.fs.path.join(allocator, &.{ entry, "git" });
        defer allocator.free(candidate);
        if (try resolveOnDisk(allocator, candidate)) |real| return real;
    }
    return null;
}

/// A fresh project and a scratch directory with one commit already made.
/// `test/workspace/escape.zig` builds the same shape but reads `/proc/self/fd`,
/// so it cannot be shared.
const TestProject = struct {
    allocator: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    root_path: []u8,
    scratch_path: []u8,
    env: std.process.Environ.Map,

    fn init(allocator: std.mem.Allocator) !TestProject {
        const io = std.testing.io;
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tmp_path = try resolvedPath(tmp.dir.handle, &buffer);

        const root_path = try std.fs.path.join(allocator, &.{ tmp_path, "project" });
        errdefer allocator.free(root_path);
        const scratch_path = try std.fs.path.join(allocator, &.{ tmp_path, "scratch" });
        errdefer allocator.free(scratch_path);

        try tmp.dir.createDirPath(io, "project");
        try tmp.dir.createDirPath(io, "scratch");

        var env = try std.testing.environ.createMap(allocator);
        errdefer env.deinit();
        // `tmpDir` puts its directory inside this project's own checkout, so
        // git's upward search would otherwise find the real repository.
        try env.put("GIT_CEILING_DIRECTORIES", tmp_path);

        var project: TestProject = .{
            .allocator = allocator,
            .tmp = tmp,
            .root_path = root_path,
            .scratch_path = scratch_path,
            .env = env,
        };

        try project.git(&.{"init"});
        try project.git(&.{ "config", "user.email", "test@example.com" });
        try project.git(&.{ "config", "user.name", "Test" });

        try tmp.dir.writeFile(io, .{ .sub_path = "project/tracked.txt", .data = "hello\n" });
        try project.git(&.{ "add", "tracked.txt" });
        try project.git(&.{ "commit", "-m", "first commit" });

        return project;
    }

    fn git(self: *TestProject, argv: []const []const u8) !void {
        var output = try chock_workspace.git.run(self.allocator, std.testing.io, &self.env, self.root_path, argv, null);
        defer output.deinit(self.allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    }

    fn deinit(self: *TestProject) void {
        self.allocator.free(self.root_path);
        self.allocator.free(self.scratch_path);
        self.env.deinit();
        self.tmp.cleanup();
    }
};

fn serializeMounts(allocator: std.mem.Allocator, mounts: []const sandbox.namespace.Mount) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (system_paths) |entry| {
        const line = try std.fmt.allocPrint(
            allocator,
            "bind\x01{s}\x01{s}\x01{d}\n",
            .{ entry.path, entry.path, @intFromBool(entry.read_only) },
        );
        defer allocator.free(line);
        try out.appendSlice(allocator, line);
    }
    for (mounts) |entry| {
        const line = switch (entry) {
            .bind => |b| try std.fmt.allocPrint(
                allocator,
                "bind\x01{s}\x01{s}\x01{d}\n",
                .{ b.source, b.target, @intFromBool(b.read_only) },
            ),
            .deny => |d| try std.fmt.allocPrint(allocator, "deny\x01{s}\n", .{d.target}),
            .overlay, .proc => return error.NotExpressibleOnDarwin,
        };
        defer allocator.free(line);
        try out.appendSlice(allocator, line);
    }
    return out.toOwnedSlice(allocator);
}

fn serializeRules(allocator: std.mem.Allocator, rules: []const sandbox.Config.Rule) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (rules) |rule| {
        const line = try std.fmt.allocPrint(allocator, "{s}\x01{d}\n", .{ rule.path, rule.access.bits() });
        defer allocator.free(line);
        try out.appendSlice(allocator, line);
    }
    return out.toOwnedSlice(allocator);
}

fn serializeLines(allocator: std.mem.Allocator, lines: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (lines) |line| {
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

fn runProbe(
    allocator: std.mem.Allocator,
    workspace: *const Workspace,
    operation: []const u8,
    args: []const []const u8,
) !std.process.Child.Term {
    const config = try workspace.sandboxConfig(allocator, "/");
    defer allocator.free(config.mounts);
    defer allocator.free(config.rules);
    defer allocator.free(config.env);

    const mounts_blob = try serializeMounts(allocator, config.mounts);
    defer allocator.free(mounts_blob);
    const rules_blob = try serializeRules(allocator, config.rules);
    defer allocator.free(rules_blob);
    const env_blob = try serializeLines(allocator, config.env);
    defer allocator.free(env_blob);
    const args_blob = try serializeLines(allocator, args);
    defer allocator.free(args_blob);

    const absolute_probe = (try resolveOnDisk(allocator, probe_path)) orelse return error.ProbeNotOnDisk;
    defer allocator.free(absolute_probe);

    // git writes to standard error on a commit here, because it tries to pack
    // the project's refs and the read only rule refuses. The commit still
    // succeeds, and the exit status is the whole answer.
    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ absolute_probe, operation, config.cwd, mounts_blob, rules_blob, env_blob, args_blob },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    return child.wait(std.testing.io);
}

/// A Seatbelt profile cannot be layered, so a process that already carries one
/// would answer for the outer profile and not for the one the driver built.
fn requireOwnProfile() !void {
    if (sandbox.darwin_driver_for_testing.confinedAlready()) return error.SkipZigTest;
}

test "finding 4 on macos: a tool call writes the worktree metadata directory and the user's own repository never sees it" {
    // The third path is the root of the directory, which no read only rule can
    // cover: `git add` creates `index.lock` there and renames it over `index`.
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    try requireOwnProfile();

    const allocator = std.testing.allocator;
    var project = try TestProject.init(allocator);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;

    const probes = [_][]const u8{
        "logs/probe-from-session",
        "refs/pwn-test",
        "probe-from-session",
    };

    for (probes) |relative| {
        const in_sandbox = try std.fs.path.join(allocator, &.{ wt.worktree_meta_target, relative });
        defer allocator.free(in_sandbox);

        try std.testing.expectEqual(
            std.process.Child.Term{ .exited = succeeded },
            try runProbe(allocator, &workspace, "write", &.{in_sandbox}),
        );

        const in_project = try std.fs.path.join(allocator, &.{ wt.worktree_meta_source, relative });
        defer allocator.free(in_project);
        try std.testing.expectError(
            error.FileNotFound,
            std.Io.Dir.cwd().statFile(std.testing.io, in_project, .{}),
        );

        const in_copy = try std.fs.path.join(allocator, &.{ wt.worktree_meta_bind_source, relative });
        defer allocator.free(in_copy);
        _ = try std.Io.Dir.cwd().statFile(std.testing.io, in_copy, .{});
    }
}

test "finding 4 on macos: the project's own metadata directory refuses a write from inside the sandbox" {
    // macOS moves no path, so the project's own metadata directory really is
    // reachable inside the sandbox and the rule is what refuses it.
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    try requireOwnProfile();

    const allocator = std.testing.allocator;
    var project = try TestProject.init(allocator);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;

    const direct = try std.fs.path.join(allocator, &.{ wt.worktree_meta_source, "logs/direct-probe" });
    defer allocator.free(direct);

    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = refused },
        try runProbe(allocator, &workspace, "write", &.{direct}),
    );
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(std.testing.io, direct, .{}),
    );
}

test "finding 4 on macos: git status, git add, and git commit still work inside the sandbox" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    try requireOwnProfile();

    const allocator = std.testing.allocator;
    var project = try TestProject.init(allocator);
    defer project.deinit();

    const git_path = (try findGit(allocator, &project.env)) orelse return error.SkipZigTest;
    defer allocator.free(git_path);

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;

    const head_before = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, wt.worktree_head_source, allocator, .limited(1 << 16));
    defer allocator.free(head_before);

    const agent_path = try std.fs.path.join(allocator, &.{ wt.path, "written-by-the-agent.txt" });
    defer allocator.free(agent_path);
    {
        var file = try std.Io.Dir.createFileAbsolute(std.testing.io, agent_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "the agent wrote this inside the sandbox\n");
    }

    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = succeeded },
        try runProbe(allocator, &workspace, "run", &.{ git_path, "status", "--short" }),
    );
    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = succeeded },
        try runProbe(allocator, &workspace, "run", &.{ git_path, "add", "written-by-the-agent.txt" }),
    );
    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = succeeded },
        try runProbe(allocator, &workspace, "run", &.{
            git_path, "-c",               "user.email=agent@example.com",
            "-c",     "user.name=Agent",  "commit",
            "-m",     "from the sandbox",
        }),
    );

    const moved = (try wt.headMoved(allocator, std.testing.io, &project.env, null)) orelse
        return error.TheSessionsOwnCommitWasNotVisible;
    defer allocator.free(moved);
    try std.testing.expect(!std.mem.eql(u8, moved, wt.base_commit));

    const head_after = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, wt.worktree_head_source, allocator, .limited(1 << 16));
    defer allocator.free(head_after);
    try std.testing.expectEqualSlices(u8, head_before, head_after);
}
