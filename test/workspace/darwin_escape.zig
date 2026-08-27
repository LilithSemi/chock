//! Finding 4 on macOS: a tool call must not be able to write the project's own
//! `.git/worktrees/<id>`, and `git status`, `git add` and `git commit` must
//! keep working while it cannot.
//!
//! **Every test here drives a real `chock_sandbox.spawn` on a real Mac.** The
//! Linux half of this proof lives in `test/workspace/escape.zig` and shares no
//! code with it, because the two share no mechanism: `Layout.remapped` moves
//! the copy to the path git looks for, and `Layout.in_place` cannot move a path
//! at all. A test that only read the Seatbelt profile would pass against a
//! profile that denies nothing, so nothing here reads one.
//!
//! **The system paths this suite adds are its own, not the workspace's.** A
//! real `chock` session gets its readable system set from the Nix dev shell's
//! own closure, and this suite has no dev shell. So it adds a
//! generous read only set of its own for `/nix/store`, `/usr` and the rest, so
//! that the real git can run at all. **None of them covers the project, the
//! scratch directory, or the copy**, which is what keeps the boundary these
//! tests measure the workspace's own and not this file's.

const std = @import("std");
const builtin = @import("builtin");

const chock_workspace = @import("chock-workspace");
const sandbox = @import("chock-sandbox");
const Workspace = chock_workspace.Workspace;
const git = chock_workspace.git;

// Zig 0.16 removed std.process.argsWithAllocator and the default test runner
// panics on any argv it does not recognize, so the probe's path cannot come in
// as a CLI argument. build.zig embeds it as a build time constant instead.
const probe_path = @import("darwin_workspace_probe_path").probe_path;

const succeeded: u8 = 0;
const refused: u8 = 1;

/// The read only system paths the real git needs to run under `(deny
/// default)`. See this file's own top comment for why the suite carries them
/// and the workspace does not.
const system_paths = [_]struct { path: []const u8, read_only: bool = true }{
    .{ .path = "/nix/store" },
    .{ .path = "/usr" },
    .{ .path = "/bin" },
    .{ .path = "/etc" },
    .{ .path = "/System" },
    .{ .path = "/Library" },
    .{ .path = "/private/var/db" },
    .{ .path = "/private/var/select" },
    // Read write, and only this one: git opens `/dev/null` for reading and
    // writing before it does anything else, and answers
    // "fatal: could not open '/dev/null' for reading and writing" without it.
    // Measured on macOS 15.7.9 on 2026-08-26.
    .{ .path = "/dev", .read_only = false },
};

/// The absolute, resolved path of an open descriptor, through `F_GETPATH`.
///
/// **Resolved, and not merely absolute.** Seatbelt matches the path the kernel
/// resolved. Measured on 2026-08-25 in `test/sandbox/darwin_escape.zig`: a rule
/// naming `/tmp/x`, where `/tmp` is a link to `/private/tmp`, matches nothing.
/// `std.testing.tmpDir` hands back a directory under `.zig-cache/tmp` reached
/// by a relative path, which in a rule matches nothing at all.
fn resolvedPath(handle: std.posix.fd_t, buffer: *[std.fs.max_path_bytes]u8) ![]const u8 {
    if (std.c.fcntl(handle, std.c.F.GETPATH, @as([*]u8, buffer)) != 0) return error.PathNotResolvable;
    return std.mem.sliceTo(buffer, 0);
}

/// The absolute, resolved path of `path`, through `F_GETPATH` on a descriptor
/// opened for it. Answers null when the path cannot be opened at all.
///
/// **A relative path in a rule matches nothing**, and build.zig hands the test
/// a probe path under `.zig-cache`, relative to the build root. A link matches
/// nothing either, and every `git` on a Nix `PATH` is a link into the store.
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

/// A fresh project and a scratch directory, both under one resolved temporary
/// directory, with one commit already made. The same shape
/// `test/workspace/escape.zig`'s own `TestProject` builds, written again here
/// because that one reads `/proc/self/fd` to find its own path.
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
        // This project's own checkout is a git repository and `tmpDir` makes
        // its scratch directory underneath it, so git's upward search would
        // otherwise walk past the fresh repository and find the real one.
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

/// Run one probe operation against a sandbox built from `workspace`'s own
/// `Sandbox.Config`, and answer what the probe exited with.
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

    // The probe's own path must be absolute and resolved for the same reason
    // every other path here must be. See `resolveOnDisk`.
    const absolute_probe = (try resolveOnDisk(allocator, probe_path)) orelse return error.ProbeNotOnDisk;
    defer allocator.free(absolute_probe);

    // **Nothing of the probe's output is kept**, and the exit status is the
    // whole answer. git writes to standard error on a commit here, because it
    // tries to pack the project's own refs and the read only rule over the
    // whole of `.git` refuses: the commit itself still succeeds. A passing
    // test that wrote that line would read in the build log like a failure.
    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ absolute_probe, operation, config.cwd, mounts_blob, rules_blob, env_blob, args_blob },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    return child.wait(std.testing.io);
}

/// Refuse to run at all when this process already carries a Seatbelt profile.
/// A profile cannot be layered, so every answer below would be the outer
/// profile's and not the one the driver built.
fn requireOwnProfile() !void {
    if (sandbox.darwin_driver_for_testing.confinedAlready()) return error.SkipZigTest;
}

test "finding 4 on macos: a tool call writes the worktree metadata directory and the user's own repository never sees it" {
    // **The red team's own three paths.** A live run by `moonshotai/kimi-k3`
    // wrote `logs/probe-from-session` and `refs/pwn-test` into the project's
    // own `.git/worktrees/<id>`, and both files were still there when the
    // session ended. The root of the same directory is the third, because no
    // read only rule can ever cover it: `git add` creates `index.lock` there
    // and renames it over `index`.
    //
    // Each write must succeed, because a refusal is a workspace that cannot
    // commit, and each one must land in the session's own copy and never in
    // the project.
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

        // The user's own repository never saw it, which is the whole finding.
        const in_project = try std.fs.path.join(allocator, &.{ wt.worktree_meta_source, relative });
        defer allocator.free(in_project);
        try std.testing.expectError(
            error.FileNotFound,
            std.Io.Dir.cwd().statFile(std.testing.io, in_project, .{}),
        );

        // And it really was written, in the session's own copy. Without this
        // the line above would hold for a sandbox that refused the write,
        // which is a broken workspace and not a fix.
        const in_copy = try std.fs.path.join(allocator, &.{ wt.worktree_meta_bind_source, relative });
        defer allocator.free(in_copy);
        _ = try std.Io.Dir.cwd().statFile(std.testing.io, in_copy, .{});
    }
}

test "finding 4 on macos: the project's own metadata directory refuses a write from inside the sandbox" {
    // The other side of the same boundary, and the one that says the rule is
    // real rather than a redirection nobody checks. A tool call that names the
    // project's own `.git/worktrees/<id>` by its real path, which is a path
    // that exists inside this sandbox because macOS moves nothing, must be
    // refused.
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
    // A workspace that refuses the writes above and also refuses `git commit`
    // has closed nothing worth having. This drives a real add and a real
    // commit through a real Seatbelt profile, then reads the commit back the
    // way `Worktree.headAfterSession` does, and requires the project's own
    // `HEAD` for this worktree not to have moved one byte.
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

    // The file the agent adds and commits, written into the checkout on the
    // host before any sandbox runs.
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
